//! The node update runner and its trust (docs/design/fleet-updates.md, D57, "The update runner" and "Interfaces").
//!
//! `update-run` runs as root (LocalSystem on Windows) in a job of its own: a launchd `WatchPaths` daemon on macOS, a
//! systemd `.path` unit on Linux, a detached copy the elevated helper starts on Windows. The state machine is oarbank-core's
//! fleet.rs; this is the OS's side of it: the package tools, the pinned native signatures, and the agent's `current`
//! (`install` in main.rs). `update-trust` pins what the runner verifies against.
//!
//! The runner's state directory is root's: `trust.json`, `journal.json`, `packages/` and `logs/` are owner-only. The
//! directory itself is 0711 with one world-readable file, `available` (`{format, mode, fleet_id, owner_version,
//! pinned_at}`, written with the trust), which is how the agent, which may not read the rest, knows the runner can
//! verify an update here (its `install.updater` fact).

use crate::Home;
use anyhow::{bail, Context, Result};
use oarbank_core::fleet::{self, InstallOutcome, Installer, Ran, Runner, Spool, SystemClock, Trust};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// How long a held dpkg or rpm lock is waited for before the install counts as busy.
const LOCK_WAIT: Duration = Duration::from_secs(20 * 60);
/// The Developer ID Installer team a macOS pkg must be signed by, when the build pins one.
const TEAM_ID: Option<&str> = option_env!("OARBANK_TEAM_ID");
/// The Authenticode subject an MSI must be signed by, when the build pins one.
const AUTHENTICODE_SUBJECT: Option<&str> = option_env!("OARBANK_AUTHENTICODE_SUBJECT");

pub const USAGE_RUN: &str = "usage: oarbank-launcher update-run [--agent-home P] [--state P] [--prefix P] [--probation-s N] [--pin-wait-s N] [--once]";
/// How long a runner started with a pin pending waits for the agent's owner keys: a join the owner approves by hand
/// can take minutes. It holds nothing up: without a trust no update can come.
const PIN_WAIT: Duration = Duration::from_secs(15 * 60);
pub const USAGE_TRUST: &str = "usage: oarbank-launcher update-trust (--from-agent | --unsigned | --keys K1,K2 [--fleet F] [--owner-version N]) \
                               [--agent-home P] [--state P]";

fn flag(opts: &[String], name: &str) -> Option<String> {
    opts.iter().position(|o| o == name).and_then(|i| opts.get(i + 1)).cloned()
}

fn has(opts: &[String], name: &str) -> bool {
    opts.iter().any(|o| o == name)
}

pub fn default_state() -> PathBuf {
    crate::setup::system_data().join("update")
}

pub fn default_agent_home() -> PathBuf {
    crate::setup::system_data().join("agent")
}

/// Where the `tar` format installs (`<prefix>/versions/<release>/`).
pub fn default_prefix() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files")).join("Oarbank")
    } else {
        PathBuf::from("/opt/oarbank")
    }
}

/// Where each package format installs the node's agent (oarbank-core's `fleet::package_agent`).
pub fn package_agent(format: &str) -> Option<PathBuf> {
    fleet::package_agent(format)
}

/// How this machine's node package was installed: macOS pkg, Windows MSI, a deb or rpm (the package database owns the
/// agent), else a tarball.
pub fn detect_format() -> String {
    if cfg!(target_os = "macos") {
        return "pkg".into();
    }
    if cfg!(windows) {
        return "msi".into();
    }
    let agent = package_agent("deb").expect("known");
    let owned = |argv: &[&str]| Command::new(argv[0]).args(&argv[1..]).arg(&agent).output().is_ok_and(|o| o.status.success());
    if agent.exists() && owned(&["dpkg", "-S"]) {
        "deb".into()
    } else if agent.exists() && owned(&["rpm", "-qf"]) {
        "rpm".into()
    } else {
        "tar".into()
    }
}

/// The agent binary a tarball (or its single top directory) carries.
fn find_agent(dir: &Path) -> Option<PathBuf> {
    let name = format!("oarbank-agent{}", std::env::consts::EXE_SUFFIX);
    let at = |d: &Path| [d.join(&name), d.join("bin").join(&name)].into_iter().find(|p| p.is_file());
    at(dir).or_else(|| {
        let subdirs: Vec<PathBuf> = std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
        match subdirs.as_slice() {
            [one] => at(one),
            _ => None,
        }
    })
}

/// Run a command, its output appended to `log`; (exit code, the output's last lines).
fn run_logged(cmd: &mut Command, log: &Path) -> (Option<i32>, String) {
    let out = cmd.output();
    let (code, text) = match out {
        Ok(o) => (o.status.code(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))),
        Err(e) => (None, format!("could not run {:?}: {e}", cmd.get_program())),
    };
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
        let _ = writeln!(f, "$ {:?} {:?}\n{text}\n(exit {code:?})", cmd.get_program(), cmd.get_args().collect::<Vec<_>>());
    }
    let tail: Vec<&str> = text.lines().rev().take(5).collect();
    (code, tail.into_iter().rev().collect::<Vec<_>>().join("\n"))
}

/// macOS package tools require a `.pkg` filename. The runner keeps packages under their verified digest, so give
/// those tools a hard link in the same owner-only directory: exactly the verified bytes, removed after use.
struct PkgPath {
    path: PathBuf,
    linked: bool,
}

impl PkgPath {
    fn new(package: &Path) -> std::io::Result<Self> {
        if !std::fs::symlink_metadata(package)?.is_file() {
            return Err(std::io::Error::other("the verified package is not a regular file"));
        }
        if package.extension() == Some(std::ffi::OsStr::new("pkg")) {
            return Ok(Self { path: package.to_path_buf(), linked: false });
        }
        let path = package.with_extension("pkg");
        // A runner interrupted during the package tool can leave its link; replace it from the verified cache.
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        std::fs::hard_link(package, &path)?;
        Ok(Self { path, linked: true })
    }
}

impl Drop for PkgPath {
    fn drop(&mut self) {
        if self.linked {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// The OS's package tools, and the agent home's `current`.
pub struct OsInstaller {
    pub home: Home,
    pub prefix: PathBuf,
    pub logs: PathBuf,
    pub format: String,
}

impl OsInstaller {
    fn log(&self, what: &str, release: &str) -> PathBuf {
        let _ = std::fs::create_dir_all(&self.logs);
        self.logs.join(format!("{what}-{release}.log"))
    }

    /// Unpack into `<prefix>/versions/<release>/`, through a temporary directory renamed into place (again on a resume).
    fn unpack(&self, package: &Path, release: &str) -> Result<()> {
        let versions = self.prefix.join("versions");
        std::fs::create_dir_all(&versions)?;
        let dir = versions.join(release);
        let tmp = versions.join(format!(".{release}.tmp"));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        let unpacked = (|| -> Result<()> {
            let f = std::fs::File::open(package)?;
            // entries are unpacked inside `tmp` only: tar's unpack skips `..` and absolute paths
            tar::Archive::new(flate2::read::GzDecoder::new(f)).unpack(&tmp).context("unpacking the tarball")?;
            if find_agent(&tmp).is_none() {
                bail!("the tarball has no oarbank-agent");
            }
            Ok(())
        })();
        if let Err(e) = unpacked {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(e);
        }
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::rename(&tmp, &dir)?;
        Ok(())
    }

    /// Install with dpkg or rpm, waiting while another installer holds the lock (20 min).
    fn package_tool(&self, argv: Vec<String>, package: &Path, release: &str) -> InstallOutcome {
        let log = self.log(&argv[0], release);
        let until = Instant::now() + LOCK_WAIT;
        let mut configured = false;
        loop {
            let mut cmd = Command::new(&argv[0]);
            cmd.args(&argv[1..]).arg(package).env("DEBIAN_FRONTEND", "noninteractive");
            let (code, tail) = run_logged(&mut cmd, &log);
            if code == Some(0) {
                return InstallOutcome::Installed { reboot_pending: false };
            }
            let low = tail.to_lowercase();
            if low.contains("lock") && (low.contains("dpkg") || low.contains("transaction") || low.contains("rpm")) {
                if Instant::now() < until {
                    std::thread::sleep(Duration::from_secs(10));
                    continue;
                }
                return InstallOutcome::Busy(format!("{} is locked by another installer", argv[0]));
            }
            // a package left half-configured (an earlier install was cut): configure what is pending, once, and retry
            if argv[0] == "dpkg" && !configured {
                configured = true;
                let _ = run_logged(Command::new("dpkg").args(["--configure", "-a"]).env("DEBIAN_FRONTEND", "noninteractive"), &log);
                continue;
            }
            return InstallOutcome::Failed { error: format!("{} failed ({}): {tail}", argv[0], code.map_or("killed".into(), |c| c.to_string())),
                                            restored: false };
        }
    }
}

impl Installer for OsInstaller {
    fn format(&self) -> String {
        self.format.clone()
    }

    fn check_native(&mut self, format: &str, package: &Path) -> Result<(), String> {
        match (format, TEAM_ID, AUTHENTICODE_SUBJECT) {
            ("pkg", Some(team), _) if !team.is_empty() => {
                let pkg = PkgPath::new(package).map_err(|e| e.to_string())?;
                let o = Command::new("pkgutil").arg("--check-signature").arg(&pkg.path).output().map_err(|e| e.to_string())?;
                let text = String::from_utf8_lossy(&o.stdout);
                if !o.status.success() || !text.contains("Developer ID Installer:") || !text.contains(&format!("({team})")) {
                    return Err(format!("the package is not signed by the pinned Developer ID Installer team {team}"));
                }
                Ok(())
            }
            ("msi", _, Some(subject)) if !subject.is_empty() => {
                let p = package.display().to_string().replace('\'', "''");
                let script = format!("$s = Get-AuthenticodeSignature -LiteralPath '{p}'; \"$($s.Status)|$($s.SignerCertificate.Subject)\"");
                let o = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]).output().map_err(|e| e.to_string())?;
                let got = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if got != format!("Valid|{subject}") {
                    return Err(format!("the package's Authenticode signature is not the pinned subject's ({got})"));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn install(&mut self, format: &str, package: &Path, release: &str, rollback: bool) -> InstallOutcome {
        match format {
            "tar" => match self.unpack(package, release) {
                Ok(()) => InstallOutcome::Installed { reboot_pending: false },
                Err(e) => InstallOutcome::Failed { error: format!("{e:#}"), restored: false },
            },
            "deb" => self.package_tool(vec!["dpkg".into(), "-i".into()], package, release),
            "rpm" => {
                let mut argv: Vec<String> = vec!["rpm".into(), "-U".into(), "--replacepkgs".into()];
                if rollback {
                    argv.push("--oldpackage".into());
                }
                self.package_tool(argv, package, release)
            }
            "pkg" => {
                let pkg = match PkgPath::new(package) {
                    Ok(pkg) => pkg,
                    Err(e) => return InstallOutcome::Failed { error: format!("preparing the verified pkg: {e}"), restored: true },
                };
                let (code, tail) = run_logged(Command::new("installer").arg("-pkg").arg(&pkg.path).args(["-target", "/"]), &self.log("installer", release));
                if code == Some(0) { InstallOutcome::Installed { reboot_pending: false } }
                else { InstallOutcome::Failed { error: format!("installer failed: {tail}"), restored: false } }
            }
            "msi" => {
                // this release's package is installed already (its agent, which only the MSI writes, is the release):
                // nothing to install. Running the same MSI again from another path is a repair, and Windows
                // Installer's secure repair refuses a package whose source moved (1603)
                if package_agent("msi").and_then(|a| std::fs::read(a).ok())
                    .is_some_and(|d| crate::marker(&d, b"oarbank-agent-version:").as_deref() == Some(release)) {
                    return InstallOutcome::Installed { reboot_pending: false };
                }
                let log = self.log("msiexec", release);
                let code = Command::new("msiexec").arg("/i").arg(package).args(["/qn", "/norestart", "/L*v"]).arg(&log).status()
                    .ok().and_then(|s| s.code());
                match code {
                    Some(c) => match fleet::msi_outcome(c) {
                        InstallOutcome::Failed { error, restored } => InstallOutcome::Failed { error: format!("{error} (log: {})", log.display()), restored },
                        o => o,
                    },
                    None => InstallOutcome::Failed { error: "msiexec could not run".into(), restored: true },
                }
            }
            f => InstallOutcome::Failed { error: format!("no installer for {f}"), restored: true },
        }
    }

    fn point_agent(&mut self, format: &str, release: &str) -> Result<(), String> {
        let bin = match format {
            "tar" => find_agent(&self.prefix.join("versions").join(release)).ok_or("the unpacked release has no oarbank-agent")?,
            f => package_agent(f).ok_or(format!("no agent path for {f}"))?,
        };
        let data = std::fs::read(&bin).map_err(|e| format!("{}: {e}", bin.display()))?;
        let v = crate::marker(&data, b"oarbank-agent-version:");
        if v.as_deref() != Some(release) {
            return Err(format!("{} is version {}, not {release}", bin.display(), v.unwrap_or_else(|| "unknown".into())));
        }
        crate::make_current(&self.home, &bin, &data, crate::install)
    }

    fn current_agent(&self) -> Option<String> {
        self.home.current_target()
    }

    fn point_back(&mut self, previous: &str) -> Result<(), String> {
        self.home.point(previous).map_err(|e| e.to_string())
    }
}

/// The state directory: root's, traversable (its `available` marker is the one file others may read).
fn ensure_state(state: &Path) -> Result<()> {
    std::fs::create_dir_all(state.join("logs"))?;
    std::fs::create_dir_all(state.join("packages"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o711))?;
        for d in ["logs", "packages"] {
            std::fs::set_permissions(state.join(d), std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(windows)]
    {
        // SYSTEM and administrators only, users may read (nothing here is secret; the agent reads `available`): the
        // default ProgramData rights would let any account create files in it
        let _ = Command::new("icacls").arg(state).args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F",
                                                         "*S-1-5-32-545:(OI)(CI)RX"]).output();
    }
    Ok(())
}

/// One runner at a time: a lock held for the process's life (a second runner exits at once).
struct Lock(#[allow(dead_code)] std::fs::File);

fn lock(state: &Path) -> Result<Option<Lock>> {
    let p = state.join("lock");
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&p)?;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Ok(None);
        }
        Ok(Some(Lock(f)))
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new().create(true).truncate(false).write(true).share_mode(0).open(&p) {
            Ok(f) => Ok(Some(Lock(f))),
            Err(e) if e.raw_os_error() == Some(32) => Ok(None),     // ERROR_SHARING_VIOLATION: another runner has it
            Err(e) => Err(e.into()),
        }
    }
}

/// `update-run`: resume the journal's update, else take the spool's request; `--once` handles at most one and exits,
/// without it the runner watches the spool (tests).
pub fn update_run(opts: &[String]) -> Result<i32> {
    let agent_home = flag(opts, "--agent-home").map(PathBuf::from).unwrap_or_else(default_agent_home);
    let state = flag(opts, "--state").map(PathBuf::from).unwrap_or_else(default_state);
    let explicit_prefix = flag(opts, "--prefix").map(PathBuf::from);
    let probation_s = match flag(opts, "--probation-s") {
        Some(s) => s.parse::<f64>().ok().filter(|p| *p > 0.0).context(USAGE_RUN)?,
        None => fleet::PROBATION_S,
    };
    let once = has(opts, "--once");
    let pin_wait = match flag(opts, "--pin-wait-s") {
        Some(s) => Duration::from_secs(s.parse().ok().context(USAGE_RUN)?),
        None => PIN_WAIT,
    };
    ensure_state(&state)?;
    let Some(_lock) = lock(&state)? else {
        eprintln!("oarbank-launcher: another update runner is running");
        return Ok(0);
    };
    crate::handle_stop_requests();
    // an administrator's install or join left a pin pending (the agent had no owner keys yet): pin them once it has
    if pending(&state) {
        match settle(&agent_home, &state, pin_wait) {
            Ok(FromAgent::Pinned(t)) => eprintln!("oarbank-launcher: update trust pinned from the agent: owner key set version {}{}",
                                                  t.owner_version, t.fleet_id.as_deref().map(|f| format!(" of {f}")).unwrap_or_default()),
            Ok(FromAgent::Already(_)) => {}
            Ok(FromAgent::NotYet) => eprintln!("oarbank-launcher: the agent has no owner keys yet; the update trust stays pending"),
            Err(e) => eprintln!("oarbank-launcher: pinning the update trust from the agent failed: {e:#}"),
        }
    }
    // an explicit prefix is a tarball install (Linux /opt/oarbank, and the tests)
    let format = if explicit_prefix.is_some() { "tar".to_string() } else { detect_format() };
    let installer = OsInstaller { home: Home(agent_home.clone()), prefix: explicit_prefix.unwrap_or_else(default_prefix),
                                  logs: state.join("logs"), format };
    let mut runner = Runner::new(Spool::new(&agent_home, &state), installer, SystemClock);
    runner.probation_s = probation_s;
    loop {
        match runner.run_once() {
            Ok(Ran::Idle) => {
                if once {
                    return Ok(0);
                }
            }
            Ok(ran) => {
                eprintln!("oarbank-launcher: update runner: {ran:?}");
                if once {
                    return Ok(0);
                }
            }
            Err(e) => {
                // the journal holds the step: the next start (the trigger, a reboot) resumes it
                eprintln!("oarbank-launcher: update runner stopped: {e}");
                if once {
                    return Ok(1);
                }
                crate::pause(Duration::from_secs(5));
            }
        }
        if crate::STOP.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(0);
        }
        crate::pause(Duration::from_secs(1));
    }
}

fn now() -> f64 {
    crate::now()
}

/// Who pinned: the administrator sudo names, else the account.
fn pinned_by(how: &str) -> String {
    let who = ["SUDO_USER", "USER", "USERNAME"].iter().find_map(|k| std::env::var(k).ok()).unwrap_or_else(|| "root".into());
    format!("{how} ({who})")
}

/// A key's fingerprint, to read out against the coordinator's (`oarbank update trust`).
fn fingerprint(k: &str) -> String {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.decode(k).unwrap_or_default();
    let h = fleet::sha256_hex(&raw);
    h.as_bytes()[..32].chunks(4).map(|c| String::from_utf8_lossy(c).to_string()).collect::<Vec<_>>().join(" ")
}

/// Write the trust and the readable marker beside it.
pub fn pin(state: &Path, t: &Trust) -> Result<()> {
    ensure_state(state)?;
    let spool = Spool::new(Path::new("."), state);
    spool.write_trust(t)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(spool.trust(), std::fs::Permissions::from_mode(0o600))?;
    }
    let marker = state.join("available");
    let mode = if t.mode == fleet::Mode::Signed { "signed" } else { "unsigned" };
    fleet::write_durable(&marker, json!({"format": 1, "mode": mode, "fleet_id": t.fleet_id, "owner_version": t.owner_version,
                                         "pinned_at": t.pinned_at}).to_string().as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(())
}

/// The file an administrator's install or join leaves in the runner's state directory while the agent has no owner
/// keys to pin yet (a fresh install: the package installs before the node joins): root's runner pins them as soon as
/// the agent has them, and deletes it (docs/design/fleet-updates.md, "Trust").
const PENDING: &str = "pin-pending";

/// What pinning from the agent came to.
#[derive(Debug, PartialEq)]
pub enum FromAgent {
    /// pinned now: the trust written
    Pinned(Trust),
    /// a trust was pinned already (by an earlier pin, `--keys` or `--unsigned`): left as it is
    Already(Trust),
    /// the agent has pinned no owner keys yet (not joined yet, or a fleet that is not in signing mode)
    NotYet,
}

/// The owner keys the agent pinned (D35's trust on first use), as a trust to pin: None while it has none.
fn agent_trust(agent_home: &Path, how: &str) -> Option<Trust> {
    let cfg: Value = serde_json::from_slice(&std::fs::read(agent_home.join("agent.json")).ok()?).ok()?;
    let ct = &cfg["coordinator_trust"];
    let keys: Vec<String> = ct["owner_keys"].as_array().into_iter().flatten().filter_map(|k| k.as_str().map(str::to_string)).collect();
    (!keys.is_empty()).then(|| Trust::signed(ct["fleet_id"].as_str().map(str::to_string), ct["owner_version"].as_i64().unwrap_or(1),
                                             keys, now(), &pinned_by(how)))
}

/// Pin the owner keys the agent pinned, unless a trust is pinned already; a pin, or one found, settles a pending pin.
pub fn pin_from_agent(agent_home: &Path, state: &Path, how: &str) -> Result<FromAgent> {
    let r = if let Some(t) = Spool::new(agent_home, state).read_trust() {
        FromAgent::Already(t)
    } else if let Some(t) = agent_trust(agent_home, how) {
        pin(state, &t)?;
        FromAgent::Pinned(t)
    } else {
        return Ok(FromAgent::NotYet);
    };
    let _ = std::fs::remove_file(state.join(PENDING));
    Ok(r)
}

/// Leave a pending pin (an administrator's install or join, before the agent has owner keys): root's runner pins them
/// once the agent has them. Nothing when a trust is pinned already.
pub fn arm(agent_home: &Path, state: &Path, how: &str) -> Result<()> {
    if Spool::new(agent_home, state).read_trust().is_some() {
        return Ok(());
    }
    ensure_state(state)?;
    let p = state.join(PENDING);
    fleet::write_durable(&p, json!({"format": 1, "armed_at": now(), "by": pinned_by(how)}).to_string().as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn pending(state: &Path) -> bool {
    state.join(PENDING).is_file()
}

/// A pending pin, settled: the agent's owner keys pinned as soon as it has them, polled for up to `wait`. Nothing
/// (NotYet) when no pin is pending.
pub fn settle(agent_home: &Path, state: &Path, wait: Duration) -> Result<FromAgent> {
    let started = Instant::now();
    loop {
        if !pending(state) {
            return Ok(FromAgent::NotYet);
        }
        match pin_from_agent(agent_home, state, "an administrator's install or join, pinned by the update runner")? {
            FromAgent::NotYet if started.elapsed() < wait && !crate::STOP.load(std::sync::atomic::Ordering::SeqCst) => {
                std::thread::sleep(Duration::from_millis(500).min(wait));
            }
            r => return Ok(r),
        }
    }
}

/// Start root's update runner now, so it settles a pending pin as soon as the node joins (setup, after it staged a
/// code or an address at system scope): macOS's launchd job, Linux's oneshot unit (not waited for). Windows' elevated
/// helper looks for a pending pin itself (`watch_spool`). Best effort: the runner also settles it when it next starts.
pub fn kick_runner() {
    let quiet = |c: &mut Command| { let _ = c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null())
                                             .stderr(std::process::Stdio::null()).status(); };
    if cfg!(target_os = "macos") {
        if Path::new(&format!("/Library/LaunchDaemons/{RUNNER}.plist")).is_file() {
            // never `-k`: a running runner may be installing a package
            quiet(Command::new("/bin/launchctl").args(["kickstart", &format!("system/{RUNNER}")]));
        }
    } else if cfg!(target_os = "linux") && Path::new("/run/systemd/system").is_dir() {
        quiet(Command::new("systemctl").args(["start", "--no-block", &format!("{RUNNER}.service")]));
    }
}

pub use fleet::TRUST_REMEDY;

/// The runner's job: the launchd label, the systemd unit's name.
const RUNNER: &str = "dev.codonic.oarbank.agent.update";

/// `update-trust`: pin the owner keys the runner verifies releases against (first pin from the agent's own TOFU pin,
/// at an administrator's install or join), explicit keys, or `unsigned` (test fleets; an administrator's explicit
/// choice). `--from-agent` before the agent has owner keys leaves the pin pending: the runner makes it once it has.
pub fn update_trust(opts: &[String]) -> Result<()> {
    let agent_home = flag(opts, "--agent-home").map(PathBuf::from).unwrap_or_else(default_agent_home);
    let state = flag(opts, "--state").map(PathBuf::from).unwrap_or_else(default_state);
    let t = if has(opts, "--from-agent") {
        match pin_from_agent(&agent_home, &state, "update-trust --from-agent")? {
            FromAgent::Already(t) => {
                println!("update trust already pinned ({}, {} keys); unchanged", t.pinned_by, t.owner_keys.len());
                return Ok(());
            }
            FromAgent::Pinned(t) => t,
            FromAgent::NotYet => {
                arm(&agent_home, &state, "update-trust --from-agent")?;
                bail!("the agent has pinned no owner keys yet: the update runner pins them once the node has joined and its \
                       agent has them. A fleet that is not in signing mode has none: pin with --keys, or --unsigned for a test fleet");
            }
        }
    } else if has(opts, "--unsigned") {
        Trust::unsigned(now(), &pinned_by("update-trust --unsigned"))
    } else if let Some(k) = flag(opts, "--keys") {
        let keys: Vec<String> = k.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        for key in &keys {
            use base64::Engine;
            if base64::engine::general_purpose::STANDARD.decode(key).map(|b| b.len()) != Ok(32) {
                bail!("{key:?} is not a base64 Ed25519 public key");
            }
        }
        if keys.is_empty() {
            bail!("{USAGE_TRUST}");
        }
        let version = match flag(opts, "--owner-version") {
            Some(v) => v.parse().ok().filter(|v: &i64| *v >= 1).context("--owner-version is the key set's version (1 or more)")?,
            None => 1,
        };
        Trust::signed(flag(opts, "--fleet"), version, keys, now(), &pinned_by("update-trust --keys"))
    } else {
        bail!("{USAGE_TRUST}");
    };
    pin(&state, &t)?;
    match t.mode {
        fleet::Mode::Unsigned => println!("update trust: unsigned (any release the coordinator offers installs here)"),
        fleet::Mode::Signed => {
            println!("update trust: owner key set version {}{}", t.owner_version, t.fleet_id.as_deref().map(|f| format!(" of {f}")).unwrap_or_default());
            for k in &t.owner_keys {
                println!("  {}", fingerprint(k));
            }
        }
    }
    Ok(())
}

/// Windows: the elevated helper (LocalSystem) settles a pending pin, and watches the agent's spool and starts the runner
/// for a request, or for an update the journal says is in progress (after a reboot), from a copy of the launcher in the runner's own
/// directory, detached and out of the helper's job: the MSI it runs replaces the launcher and restarts the helper.
#[cfg(windows)]
pub fn watch_spool() {
    let (spool, journal) = (default_agent_home().join("updates").join("request.json"), default_state().join("journal.json"));
    let mut started: Option<Instant> = None;
    while !crate::STOP.load(std::sync::atomic::Ordering::SeqCst) {
        // an administrator's install or join left a pin pending: the agent's owner keys, pinned once it has them
        if pending(&default_state()) {
            if let Err(e) = pin_from_agent(&default_agent_home(), &default_state(), "an administrator's install or join, pinned by the helper") {
                eprintln!("oarbank-launcher: pinning the update trust from the agent failed: {e:#}");
            }
        }
        let active = std::fs::read(&journal).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).is_some_and(|j| !j["active"].is_null());
        if (spool.exists() || active) && started.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
            match start_detached() {
                Ok(()) => started = Some(Instant::now()),
                Err(e) => eprintln!("oarbank-launcher: could not start the update runner: {e:#}"),
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(windows)]
fn start_detached() -> Result<()> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let dir = default_state().join("runner");
    std::fs::create_dir_all(&dir)?;
    let copy = dir.join("oarbank-launcher.exe");
    // a copy still running (another runner) is locked: it is the same launcher, start it as it is
    if let Err(e) = std::fs::copy(std::env::current_exe()?, &copy) {
        if !copy.exists() {
            return Err(e.into());
        }
    }
    let flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    let spawn = |f: u32| Command::new(&copy).args(["update-run", "--once"]).current_dir(&dir).creation_flags(f).spawn();
    // breaking away needs the job's permission; without it the runner still outlives the helper's process
    spawn(flags | CREATE_BREAKAWAY_FROM_JOB).or_else(|_| spawn(flags))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkg_tools_get_the_verified_bytes_with_a_suffix_and_no_leftover_link() {
        let tmp = tempfile::Builder::new().prefix("oarbank-launcher-pkg-").tempdir().unwrap();
        for name in ["verified-digest", ".incoming", "already.pkg"] {
            let cache = tmp.path().join(name);
            std::fs::write(&cache, b"verified package").unwrap();
            let view = cache.with_extension("pkg");
            if view != cache {
                std::fs::write(&view, b"stale interrupted runner link").unwrap();
            }
            {
                let pkg = PkgPath::new(&cache).unwrap();
                assert_eq!(pkg.path.extension().unwrap(), "pkg");
                assert_eq!(std::fs::read(&pkg.path).unwrap(), b"verified package");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let (a, b) = (std::fs::metadata(&cache).unwrap(), std::fs::metadata(&pkg.path).unwrap());
                    assert_eq!((a.dev(), a.ino(), a.uid(), a.mode()), (b.dev(), b.ino(), b.uid(), b.mode()));
                }
            }
            assert_eq!(std::fs::read(&cache).unwrap(), b"verified package");
            assert_eq!(view.exists(), view == cache);
        }
        assert!(PkgPath::new(&tmp.path().join("missing")).is_err());
        assert!(PkgPath::new(tmp.path()).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_installer_accepts_a_cached_pkg_through_its_suffixed_view() {
        let tmp = tempfile::Builder::new().prefix("oarbank-launcher-pkg-info-").tempdir().unwrap();
        let original = tmp.path().join("fixture.pkg");
        let built = Command::new("/usr/bin/pkgbuild").args(["--nopayload", "--identifier", "dev.codonic.oarbank.test.pkg-path",
            "--version", "1.0.0"]).arg(&original).output().unwrap();
        assert!(built.status.success(), "{}", String::from_utf8_lossy(&built.stderr));
        let cache = tmp.path().join(fleet::sha256_hex(&std::fs::read(&original).unwrap()));
        std::fs::rename(&original, &cache).unwrap();
        let info = |path: &Path| Command::new("/usr/sbin/installer").args(["-pkginfo", "-pkg"]).arg(path).output().unwrap();
        assert!(!info(&cache).status.success());
        {
            let pkg = PkgPath::new(&cache).unwrap();
            let result = info(&pkg.path); // package metadata only: no install, service or administrator access
            assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stdout));
        }
        assert!(cache.is_file() && !cache.with_extension("pkg").exists());
    }

    /// A tarball unpacks into `<prefix>/versions/<release>/` (again on a resume), and its agent becomes current.
    #[test]
    fn a_tarball_installs_side_by_side_and_its_agent_becomes_current() {
        let tmp = tempfile::Builder::new().prefix("oarbank-launcher-tar-").tempdir().unwrap();
        let (home, prefix) = (tmp.path().join("agent"), tmp.path().join("prefix"));
        std::fs::create_dir_all(&home).unwrap();
        let agent = [&b"\x7fELF"[..], b"....oarbank-agent-version:2.10.0\0rest"].concat();
        let tgz = tmp.path().join("r.tar.gz");
        {
            let mut b = tar::Builder::new(flate2::write::GzEncoder::new(std::fs::File::create(&tgz).unwrap(), flate2::Compression::fast()));
            let mut h = tar::Header::new_gnu();
            h.set_size(agent.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            // the agent's name on this OS (`oarbank-agent.exe` on Windows), as a release's tarball for it would hold
            let name = format!("oarbank-agent-2.10.0/oarbank-agent{}", std::env::consts::EXE_SUFFIX);
            b.append_data(&mut h, &name, &agent[..]).unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        let mut i = OsInstaller { home: Home(home.clone()), prefix: prefix.clone(), logs: tmp.path().join("logs"), format: "tar".into() };
        for _ in 0..2 {
            assert_eq!(i.install("tar", &tgz, "2.10.0", false), InstallOutcome::Installed { reboot_pending: false });
        }
        assert!(prefix.join(format!("versions/2.10.0/oarbank-agent-2.10.0/oarbank-agent{}", std::env::consts::EXE_SUFFIX)).is_file());
        assert!(i.point_agent("tar", "2.9.0").unwrap_err().contains("no oarbank-agent"), "2.9.0 was never unpacked");
        // an agent-only update staged before the package came: the package's agent wins
        std::fs::create_dir_all(home.join("state")).unwrap();
        std::fs::write(home.join("state/upgrade.json"), json!({"state": "staged", "target": "versions/x/oarbank-agent"}).to_string()).unwrap();
        i.point_agent("tar", "2.10.0").unwrap();
        assert!(!home.join("state/upgrade.json").exists());
        let cur = i.current_agent().unwrap();
        assert!(cur.starts_with("versions/2.10.0-"), "{cur}");
        assert_eq!(std::fs::read(home.join(&cur)).unwrap(), agent);
        i.point_back("versions/old/oarbank-agent").unwrap();
        assert_eq!(i.current_agent().as_deref(), Some("versions/old/oarbank-agent"));
        // not a tarball
        std::fs::write(&tgz, b"junk").unwrap();
        assert!(matches!(i.install("tar", &tgz, "2.11.0", false), InstallOutcome::Failed { .. }));
        assert!(!prefix.join("versions/2.11.0").exists() && !prefix.join("versions/.2.11.0.tmp").exists());
    }

    /// `update-trust`: from the agent's own pin only when none exists yet, explicit keys, unsigned; the marker the agent
    /// reads goes beside it.
    #[test]
    fn trust_is_pinned_from_the_agent_once() {
        let tmp = tempfile::Builder::new().prefix("oarbank-launcher-trust-").tempdir().unwrap();
        let (home, state) = (tmp.path().join("agent"), tmp.path().join("update"));
        std::fs::create_dir_all(&home).unwrap();
        let args = |a: &[&str]| -> Vec<String> {
            a.iter().map(|s| s.to_string()).chain(["--agent-home".into(), home.display().to_string(), "--state".into(), state.display().to_string()]).collect()
        };
        assert!(update_trust(&args(&["--from-agent"])).is_err(), "no agent.json");
        assert!(pending(&state), "a pin from the agent before it has keys is left pending");
        std::fs::write(home.join("agent.json"), json!({"coordinator_trust": {"owner_keys": [], "owner_version": 0}}).to_string()).unwrap();
        assert!(update_trust(&args(&["--from-agent"])).is_err(), "no owner keys");
        assert!(!state.join("trust.json").exists() && !state.join("available").exists());
        let k = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
        std::fs::write(home.join("agent.json"), json!({"coordinator_trust": {"owner_keys": [k], "owner_version": 3, "fleet_id": "fleet_a"}}).to_string()).unwrap();
        update_trust(&args(&["--from-agent"])).unwrap();
        assert!(!pending(&state), "pinning settles the pending pin");
        let t = Spool::new(&home, &state).read_trust().unwrap();
        assert_eq!((t.mode, t.owner_version, t.owner_keys.clone(), t.fleet_id.as_deref()), (fleet::Mode::Signed, 3, vec![k.to_string()], Some("fleet_a")));
        let marker: Value = serde_json::from_slice(&std::fs::read(state.join("available")).unwrap()).unwrap();
        assert_eq!((marker["mode"].as_str(), marker["owner_version"].as_i64()), (Some("signed"), Some(3)));
        // a second --from-agent leaves the pin alone
        std::fs::write(home.join("agent.json"), json!({"coordinator_trust": {"owner_keys": [k], "owner_version": 9}}).to_string()).unwrap();
        update_trust(&args(&["--from-agent"])).unwrap();
        assert_eq!(Spool::new(&home, &state).read_trust().unwrap().owner_version, 3);
        assert!(update_trust(&args(&["--keys", "nope"])).is_err());
        update_trust(&args(&["--keys", k, "--fleet", "fleet_b"])).unwrap();
        assert_eq!(Spool::new(&home, &state).read_trust().unwrap().fleet_id.as_deref(), Some("fleet_b"));
        update_trust(&args(&["--unsigned"])).unwrap();
        assert_eq!(Spool::new(&home, &state).read_trust().unwrap().mode, fleet::Mode::Unsigned);
        assert!(update_trust(&args(&[])).is_err());
    }

    /// A fresh install: the package's pin runs before the node joined, so it is left pending; root's runner (or the
    /// join itself) pins the agent's owner keys as soon as the agent has them, once, and only when a pin is pending.
    #[test]
    fn a_pending_pin_is_made_once_the_agent_has_owner_keys() {
        let tmp = tempfile::Builder::new().prefix("oarbank-launcher-pending-").tempdir().unwrap();
        let (home, state) = (tmp.path().join("agent"), tmp.path().join("update"));
        std::fs::create_dir_all(&home).unwrap();
        // nothing pending: the runner pins nothing, whatever the agent has
        let k = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
        let keys = json!({"coordinator_trust": {"owner_keys": [k], "owner_version": 1, "fleet_id": "fleet_a"}}).to_string();
        std::fs::write(home.join("agent.json"), &keys).unwrap();
        assert_eq!(settle(&home, &state, Duration::ZERO).unwrap(), FromAgent::NotYet);
        assert!(Spool::new(&home, &state).read_trust().is_none());
        std::fs::remove_file(home.join("agent.json")).unwrap();
        // the package's install (or a join) before the node joined: pending, root's alone
        arm(&home, &state, "test").unwrap();
        assert!(pending(&state));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(state.join(PENDING)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(settle(&home, &state, Duration::from_millis(300)).unwrap(), FromAgent::NotYet);
        assert!(pending(&state), "still pending until the agent has keys");
        // the node joins: the first directive brings the owner key set while the runner waits
        let writer = {
            let (home, keys) = (home.clone(), keys.clone());
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(700));
                std::fs::write(home.join("agent.json"), keys).unwrap();
            })
        };
        let r = settle(&home, &state, Duration::from_secs(30)).unwrap();
        writer.join().unwrap();
        let FromAgent::Pinned(t) = r else { panic!("{r:?}") };
        assert_eq!((t.mode, t.owner_version, t.owner_keys.clone(), t.fleet_id.as_deref()), (fleet::Mode::Signed, 1, vec![k.to_string()], Some("fleet_a")));
        assert_eq!(Spool::new(&home, &state).read_trust(), Some(t));
        let marker: Value = serde_json::from_slice(&std::fs::read(state.join("available")).unwrap()).unwrap();
        assert_eq!((marker["mode"].as_str(), marker["fleet_id"].as_str()), (Some("signed"), Some("fleet_a")));
        assert!(!pending(&state), "settled");
        // pinned: arming again leaves nothing pending, and a later key set never replaces the pin from here
        arm(&home, &state, "test").unwrap();
        assert!(!pending(&state));
        std::fs::write(home.join("agent.json"), json!({"coordinator_trust": {"owner_keys": [k], "owner_version": 7}}).to_string()).unwrap();
        assert!(matches!(pin_from_agent(&home, &state, "test").unwrap(), FromAgent::Already(t) if t.owner_version == 1));
        // a trust an administrator pinned some other way (--unsigned) settles a pending pin without changing it
        std::fs::remove_file(state.join("trust.json")).unwrap();
        arm(&home, &state, "test").unwrap();
        update_trust(&["--unsigned".into(), "--agent-home".into(), home.display().to_string(), "--state".into(), state.display().to_string()]).unwrap();
        assert!(matches!(settle(&home, &state, Duration::ZERO).unwrap(), FromAgent::Already(t) if t.mode == fleet::Mode::Unsigned));
        assert!(!pending(&state));
    }

    /// The runner started with a pin pending (setup started it as the node joined) pins the agent's keys, then runs.
    #[test]
    fn the_runner_settles_a_pending_pin() {
        let tmp = tempfile::Builder::new().prefix("oarbank-launcher-runner-pin-").tempdir().unwrap();
        let (home, state) = (tmp.path().join("agent"), tmp.path().join("update"));
        std::fs::create_dir_all(&home).unwrap();
        arm(&home, &state, "test").unwrap();
        let k = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
        std::fs::write(home.join("agent.json"), json!({"coordinator_trust": {"owner_keys": [k], "owner_version": 2}}).to_string()).unwrap();
        let run = |extra: &[&str]| update_run(&["--agent-home", &home.display().to_string(), "--state", &state.display().to_string(),
                                               "--prefix", &tmp.path().join("prefix").display().to_string(), "--once"]
                                              .iter().chain(extra).map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert_eq!(run(&["--pin-wait-s", "5"]), 0);
        assert_eq!(Spool::new(&home, &state).read_trust().map(|t| t.owner_version), Some(2));
        assert!(!pending(&state));
    }
}
