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

pub const USAGE_RUN: &str = "usage: oarbank-launcher update-run [--agent-home P] [--state P] [--prefix P] [--probation-s N] [--once]";
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

/// Where each package format installs the node's agent (scripts/package-*.sh, deploy/windows/oarbank-agent.wxs).
pub fn package_agent(format: &str) -> Option<PathBuf> {
    match format {
        "pkg" => Some(PathBuf::from("/Library/Oarbank/bin/oarbank-agent")),
        "deb" | "rpm" => Some(PathBuf::from("/usr/lib/oarbank/oarbank-agent")),
        "msi" => Some(default_prefix().join("oarbank-agent.exe")),
        _ => None,
    }
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
                let o = Command::new("pkgutil").arg("--check-signature").arg(package).output().map_err(|e| e.to_string())?;
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
                let (code, tail) = run_logged(Command::new("installer").arg("-pkg").arg(package).args(["-target", "/"]), &self.log("installer", release));
                if code == Some(0) { InstallOutcome::Installed { reboot_pending: false } }
                else { InstallOutcome::Failed { error: format!("installer failed: {tail}"), restored: false } }
            }
            "msi" => {
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
        crate::install(&self.home, &bin).map(|_| ()).map_err(|e| format!("{e:#}"))
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
    ensure_state(&state)?;
    let Some(_lock) = lock(&state)? else {
        eprintln!("oarbank-launcher: another update runner is running");
        return Ok(0);
    };
    // an explicit prefix is a tarball install (Linux /opt/oarbank, and the tests)
    let format = if explicit_prefix.is_some() { "tar".to_string() } else { detect_format() };
    let installer = OsInstaller { home: Home(agent_home.clone()), prefix: explicit_prefix.unwrap_or_else(default_prefix),
                                  logs: state.join("logs"), format };
    let mut runner = Runner::new(Spool::new(&agent_home, &state), installer, SystemClock);
    runner.probation_s = probation_s;
    crate::handle_stop_requests();
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

/// `update-trust`: pin the owner keys the runner verifies releases against (first pin from the agent's own TOFU pin,
/// at an administrator's install), explicit keys, or `unsigned` (test fleets; an administrator's explicit choice).
pub fn update_trust(opts: &[String]) -> Result<()> {
    let agent_home = flag(opts, "--agent-home").map(PathBuf::from).unwrap_or_else(default_agent_home);
    let state = flag(opts, "--state").map(PathBuf::from).unwrap_or_else(default_state);
    let t = if has(opts, "--from-agent") {
        if let Some(t) = Spool::new(&agent_home, &state).read_trust() {
            println!("update trust already pinned ({}, {} keys); unchanged", t.pinned_by, t.owner_keys.len());
            return Ok(());
        }
        let cfg: Value = serde_json::from_slice(&std::fs::read(agent_home.join("agent.json"))
            .with_context(|| format!("no agent.json in {}: join the node first", agent_home.display()))?)?;
        let ct = &cfg["coordinator_trust"];
        let keys: Vec<String> = ct["owner_keys"].as_array().into_iter().flatten().filter_map(|k| k.as_str().map(str::to_string)).collect();
        if keys.is_empty() {
            bail!("the agent has pinned no owner keys (the fleet is not in signing mode): pin with --keys, or --unsigned for a test fleet");
        }
        Trust::signed(ct["fleet_id"].as_str().map(str::to_string), ct["owner_version"].as_i64().unwrap_or(1), keys, now(),
                      &pinned_by("update-trust --from-agent"))
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

/// Windows: the elevated helper (LocalSystem) watches the agent's spool and starts the runner for a request, or for
/// an update the journal says is in progress (after a reboot), from a copy of the launcher in the runner's own
/// directory, detached and out of the helper's job: the MSI it runs replaces the launcher and restarts the helper.
#[cfg(windows)]
pub fn watch_spool() {
    let (spool, journal) = (default_agent_home().join("updates").join("request.json"), default_state().join("journal.json"));
    let mut started: Option<Instant> = None;
    while !crate::STOP.load(std::sync::atomic::Ordering::SeqCst) {
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
        std::fs::write(home.join("agent.json"), json!({"coordinator_trust": {"owner_keys": [], "owner_version": 0}}).to_string()).unwrap();
        assert!(update_trust(&args(&["--from-agent"])).is_err(), "no owner keys");
        let k = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=";
        std::fs::write(home.join("agent.json"), json!({"coordinator_trust": {"owner_keys": [k], "owner_version": 3, "fleet_id": "fleet_a"}}).to_string()).unwrap();
        update_trust(&args(&["--from-agent"])).unwrap();
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
}
