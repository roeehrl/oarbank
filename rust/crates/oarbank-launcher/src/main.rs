//! oarbank-launcher: keeps the agent running and owns which version runs (docs/design/architecture.md, "Updates and
//! trust").
//!
//! Versions live side by side in `<home>/versions/<version>-<sha12>/oarbank-agent`; `<home>/current` points at one.
//! The agent never replaces a running binary. To update, it stages the new version and records
//! `state/upgrade.json {state: "staged", target}`, then exits 75. The launcher then flips `current` to the target and
//! starts it on trial: it must confirm itself (after its first hello and heartbeat it writes `state: "confirmed"`)
//! within 10 minutes and within three starts, or the launcher flips back to the previous version and records
//! `rolled_back` with the reason, which the old agent reports. Updates never replace the launcher.

#[cfg_attr(not(windows), allow(dead_code))]
mod container_support;
mod node;
mod setup;
mod update;
#[cfg_attr(target_os = "macos", path = "svc_launchd.rs")]
#[cfg_attr(windows, path = "svc_windows.rs")]
#[cfg_attr(all(unix, not(target_os = "macos")), path = "svc_systemd.rs")]
mod svc;
#[cfg_attr(not(windows), allow(dead_code))]
mod helper_sessions;
#[cfg(windows)]
mod helper_windows;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TRIAL_STARTS: i64 = 3;
const TRIAL_S: f64 = 600.0;
const SWAP: i32 = 75;

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

struct Home(PathBuf);

impl Home {
    fn current(&self) -> PathBuf { self.0.join("current") }
    /// The agent `current` points at (a symlink on Unix, a pointer file naming it on Windows).
    fn current_bin(&self) -> PathBuf {
        if cfg!(unix) { self.current() } else { self.current_target().map(|t| self.0.join(t)).unwrap_or_else(|| self.current()) }
    }
    fn upgrade(&self) -> PathBuf { self.0.join("state").join("upgrade.json") }

    fn current_target(&self) -> Option<String> {
        if let Ok(p) = std::fs::read_link(self.current()) {
            return Some(p.to_string_lossy().to_string());
        }
        std::fs::read_to_string(self.current()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
    }

    /// Point `current` at `rel` (a path relative to the home) atomically. Idempotent: `current` already naming `rel`
    /// (before, or after a rename that failed: the launcher and the update runner both point it) is success.
    fn point(&self, rel: &str) -> Result<()> {
        if self.current_target().as_deref() == Some(rel) {
            return Ok(());
        }
        let tmp = self.0.join(".current.tmp");
        let _ = std::fs::remove_file(&tmp);
        #[cfg(unix)]
        std::os::unix::fs::symlink(rel, &tmp)?;
        #[cfg(not(unix))]
        std::fs::write(&tmp, rel)?;
        match rename(&tmp, &self.current()) {
            Err(_) if self.current_target().as_deref() == Some(rel) => {
                let _ = std::fs::remove_file(&tmp);
                Ok(())
            }
            r => Ok(r?),
        }
    }

    fn read_upgrade(&self) -> Option<Value> {
        serde_json::from_slice(&std::fs::read(self.upgrade()).ok()?).ok()
    }

    fn write_upgrade(&self, v: &Value) -> Result<()> {
        let p = self.upgrade();
        std::fs::create_dir_all(p.parent().unwrap())?;
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(v)?)?;
        std::fs::rename(tmp, p)?;
        Ok(())
    }
}

/// How long a rename that Windows refuses for a moment is retried: another process (an antivirus scan, a reader) has the
/// file open without FILE_SHARE_DELETE, or a lock on it, until it closes it.
const RENAME_RETRY: Duration = Duration::from_secs(30);

/// ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION: what a rename on Windows fails with while
/// another process has the file open. Nothing is transient elsewhere.
fn transient(e: &std::io::Error) -> bool {
    cfg!(windows) && matches!(e.raw_os_error(), Some(5 | 32 | 33))
}

/// `op`, again after a transient error (backing off from 100 ms to 5 s) until `budget` has been slept.
fn retrying<T>(budget: Duration, mut op: impl FnMut() -> std::io::Result<T>, transient: impl Fn(&std::io::Error) -> bool,
               mut sleep: impl FnMut(Duration)) -> std::io::Result<T> {
    let (mut slept, mut delay) = (Duration::ZERO, Duration::from_millis(100));
    loop {
        match op() {
            Err(e) if transient(&e) && slept < budget => {
                let d = delay.min(budget - slept);
                sleep(d);
                slept += d;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            r => return r,
        }
    }
}

/// Rename `from` over `to`, retrying what Windows refuses for a moment.
fn rename(from: &Path, to: &Path) -> std::io::Result<()> {
    retrying(RENAME_RETRY, || std::fs::rename(from, to), transient, std::thread::sleep)
}

/// Where `install` puts the agent `data` (relative to the home): `versions/<version>-<sha12>/oarbank-agent`.
fn install_path(data: &[u8]) -> Option<String> {
    let version = marker(data, b"oarbank-agent-version:")?;
    Some(format!("versions/{version}-{}/oarbank-agent{}", &sha256_hex(data)[..12], std::env::consts::EXE_SUFFIX))
}

/// Install a binary as a version and make it current (first install, or by hand). Idempotent: a version already
/// installed is not written again. On Windows it could not be: that version's agent may be running, and Windows refuses
/// to replace a running program's file (ERROR_ACCESS_DENIED), as when the update runner makes the package's agent
/// current after the package's setup and the launcher have already started it.
fn install(home: &Home, binary: &Path) -> Result<String> {
    let data = std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    let target = install_path(&data).context("the binary embeds no oarbank-agent version")?;
    let (rel, name) = target.rsplit_once('/').expect("versions/<v>/<name>");
    let dir = home.0.join(rel);
    std::fs::create_dir_all(&dir)?;
    let dst = dir.join(name);
    if std::fs::read(&dst).ok().as_deref() != Some(&data[..]) {
        let tmp = dir.join(".oarbank-agent.tmp");
        std::fs::write(&tmp, &data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }
        rename(&tmp, &dst)?;
    }
    home.point(&target)?;
    let rel = rel.to_string();
    // an agent-only self-update staged or on trial would put its own build back over this one at the next start
    // (before_start): the installed agent wins, and the coordinator offers that update again if it still applies
    if home.read_upgrade().is_some_and(|u| matches!(u["state"].as_str(), Some("staged" | "trial"))) {
        let _ = std::fs::remove_file(home.upgrade());
    }
    Ok(rel)
}

/// The update runner's step: make the package's agent `bin` (its content `data`) current with `install`. Installing
/// failing while `current` already names this very build (the package's setup, or the launcher at its start, made it
/// current) is success: the node runs the release, and the rollout must not count a failure or roll it back.
fn make_current(home: &Home, bin: &Path, data: &[u8], install: impl FnOnce(&Home, &Path) -> Result<String>)
                -> std::result::Result<(), String> {
    match install(home, bin) {
        Ok(_) => Ok(()),
        Err(e) if install_path(data).is_some_and(|t| home.current_target().as_deref() == Some(t.as_str())) => {
            eprintln!("oarbank-launcher: current already names {}: {e:#}", bin.display());
            Ok(())
        }
        Err(e) => Err(format!("{e:#}")),
    }
}

fn marker(data: &[u8], p: &[u8]) -> Option<String> {
    // the prefix also appears as a plain literal (the code that looks for it): take the occurrence a version follows
    let mut from = 0;
    while let Some(i) = data[from..].windows(p.len()).position(|w| w == p) {
        let rest = &data[from + i + p.len()..];
        if let Some(end) = rest.iter().take(64).position(|&b| b == 0) {
            let v = &rest[..end];
            if !v.is_empty() && v[0].is_ascii_digit() && v.iter().all(|c| c.is_ascii_alphanumeric() || b".+-".contains(c)) {
                return String::from_utf8(v.to_vec()).ok();
            }
        }
        from += i + 1;
    }
    None
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// The version of the agent `rel` (a path relative to the home) names: `versions/<version>-<sha12>/oarbank-agent`, as
/// `install` and the agent's staging name it; else the version its binary embeds.
fn version_at(home: &Home, rel: &str) -> Option<String> {
    let named = Path::new(rel).parent().and_then(|d| d.file_name()).map(|n| n.to_string_lossy().to_string())
        .and_then(|n| n.rsplit_once('-').filter(|(_, h)| h.len() == 12 && h.bytes().all(|b| b.is_ascii_hexdigit()))
                         .map(|(v, _)| v.to_string()))
        .filter(|v| oarbank_core::fleet::version_key(v).is_some());
    named.or_else(|| std::fs::read(home.0.join(rel)).ok().and_then(|d| oarbank_core::fleet::agent_version_of(&d)))
}

/// The installed package's agent: beside this launcher when the launcher is a package's own (fleet.rs
/// `package_agent_beside`); none for a development or tarball launcher.
fn package_agent() -> Option<PathBuf> {
    let me = std::env::current_exe().ok()?;
    let me = if cfg!(windows) { me } else { std::fs::canonicalize(me).ok()? };
    oarbank_core::fleet::package_agent_beside(&me)
}

/// The installed package supersedes every older agent-only build (docs/protocol.md, "Agent self-update"; a fleet release
/// or a manual package install is the unit, D57): a staged agent-only update to a version older than the package's
/// agent is refused (`failed`: the agent reports it and never retries that build), and when `current` names an older
/// version than the package's agent (a channel build from before the package was installed, whose postinstall could
/// not move `current`) the package's agent becomes current. A trial in progress is left to finish first.
fn supersede(home: &Home, package: Option<&Path>) -> Result<()> {
    let Some(pkg) = package else { return Ok(()) };
    let Some(pv) = std::fs::read(pkg).ok().and_then(|d| oarbank_core::fleet::agent_version_of(&d)) else { return Ok(()) };
    let mut up = home.read_upgrade();
    if let Some(u) = up.as_mut().filter(|u| u["state"] == "staged") {
        let target = u["target"].as_str().unwrap_or("").to_string();
        let tv = u["version"].as_str().map(str::to_string).or_else(|| version_at(home, &target));
        if let Some(tv) = tv.filter(|tv| oarbank_core::fleet::newer(&pv, tv)) {
            u["state"] = json!("failed");
            u["error"] = json!(format!("agent build {tv} is older than the installed package's agent {pv}: the package supersedes it"));
            home.write_upgrade(u)?;
            eprintln!("oarbank-launcher: refused the staged agent {tv}: the installed package's agent is {pv}");
        }
    }
    if up.as_ref().is_some_and(|u| matches!(u["state"].as_str(), Some("staged" | "trial"))) {
        return Ok(());
    }
    let cv = home.current_target().and_then(|t| version_at(home, &t));
    if cv.as_deref().is_some_and(|cv| oarbank_core::fleet::newer(&pv, cv)) {
        let rel = install(home, pkg)?;
        eprintln!("oarbank-launcher: current ran agent {} older than the installed package's {pv}: current -> {rel}",
                  cv.unwrap_or_default());
    }
    Ok(())
}

/// Before each start: the installed package supersedes older agent-only builds, then apply a staged update, and decide
/// whether a trial has failed.
fn before_start(home: &Home) -> Result<()> {
    before_start_with(home, package_agent().as_deref())
}

fn before_start_with(home: &Home, package: Option<&Path>) -> Result<()> {
    if let Err(e) = supersede(home, package) {
        eprintln!("oarbank-launcher: could not compare the agent with the installed package's: {e:#}");
    }
    let Some(mut up) = home.read_upgrade() else { return Ok(()) };
    match up["state"].as_str() {
        Some("staged") => {
            let target = up["target"].as_str().context("staged update without a target")?.to_string();
            if !home.0.join(&target).is_file() {
                up["state"] = json!("failed");
                up["error"] = json!("the staged binary is missing");
                return home.write_upgrade(&up);
            }
            up["previous"] = json!(home.current_target());
            home.point(&target)?;
            up["state"] = json!("trial");
            up["starts"] = json!(0);
            up["trial_since"] = json!(now());
            home.write_upgrade(&up)
        }
        Some("trial") => {
            let starts = up["starts"].as_i64().unwrap_or(0);
            let since = up["trial_since"].as_f64().unwrap_or_else(now);
            let failed = if starts >= TRIAL_STARTS { Some(format!("the new version failed to start {starts} times")) }
                         else if now() - since > TRIAL_S { Some("the new version did not confirm within 600 s".into()) }
                         else { None };
            if let Some(reason) = failed {
                if let Some(prev) = up["previous"].as_str() {
                    home.point(prev)?;
                }
                up["state"] = json!("rolled_back");
                up["error"] = json!(reason);
                up["rolled_back_at"] = json!(now());
            } else {
                up["starts"] = json!(starts + 1);
            }
            home.write_upgrade(&up)
        }
        _ => Ok(()),
    }
}

static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CHILD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Stop: no new start, and ask the running agent to stop. On Unix that is SIGTERM, and the launcher waits for the agent
/// as long as it takes (the service manager's stop timeout, `AGENT_STOP_TIMEOUT_S`, bounds it). On Windows, where a
/// console control or the service manager's stop arrives here and a process has no SIGTERM, the launcher sets the
/// agent's stop event and ends the agent only if it has not stopped within that timeout (its runners' Job Objects
/// then end with it).
fn stop_now() {
    STOP.store(true, std::sync::atomic::Ordering::SeqCst);
    let c = CHILD.load(std::sync::atomic::Ordering::SeqCst);
    if c > 0 {
        #[cfg(unix)]
        unsafe { libc::kill(c, libc::SIGTERM) };
        #[cfg(windows)]
        {
            stop_event::set();
            std::thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(oarbank_core::service::AGENT_STOP_TIMEOUT_S as u64 - 5);
                while Instant::now() < until && CHILD.load(std::sync::atomic::Ordering::SeqCst) == c {
                    std::thread::sleep(Duration::from_millis(200));
                }
                if CHILD.load(std::sync::atomic::Ordering::SeqCst) == c {
                    eprintln!("oarbank-launcher: the agent did not stop in time; ending it");
                    unsafe {
                        use windows_sys::Win32::Foundation::CloseHandle;
                        use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
                        let h = OpenProcess(PROCESS_TERMINATE, 0, c as u32);
                        if !h.is_null() {
                            TerminateProcess(h, 0);
                            CloseHandle(h);
                        }
                    }
                }
            });
        }
    }
}

/// Windows: the event that asks the agent this launcher started to stop (the agent's sys.rs `launcher_stop_event`),
/// named after this launcher's pid; created before the first agent starts.
#[cfg(windows)]
mod stop_event {
    use std::sync::OnceLock;
    static EVENT: OnceLock<usize> = OnceLock::new();

    pub fn create() {
        use windows_sys::Win32::System::Threading::CreateEventW;
        let name: Vec<u16> = format!("Local\\oarbank-agent-stop-{}", std::process::id()).encode_utf16().chain([0]).collect();
        // manual reset: it stays set for whichever agent opens it later
        let h = unsafe { CreateEventW(std::ptr::null(), 1, 0, name.as_ptr()) };
        if !h.is_null() {
            let _ = EVENT.set(h as usize);
        }
    }

    pub fn set() {
        if let Some(h) = EVENT.get() {
            unsafe { windows_sys::Win32::System::Threading::SetEvent(*h as _) };
        }
    }
}

#[cfg(unix)]
extern "C" fn on_term(_: i32) {
    stop_now();
}

#[cfg(windows)]
unsafe extern "system" fn on_ctrl(_kind: u32) -> i32 {
    stop_now();
    1
}

fn handle_stop_requests() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGTERM, on_term as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_term as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_term as *const () as libc::sighandler_t);
    }
    #[cfg(windows)]
    {
        stop_event::create();
        unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    }
}

/// The node runtime the packages ship beside the launcher (`runtime/`: CPython 3.12 with the module SDK, and uv),
/// for the agent unless its environment already names one.
fn runtime_env() -> Vec<(&'static str, PathBuf)> {
    // canonicalize follows a symlinked launcher on Unix; on Windows it would add a \\?\ prefix, which the
    // runtime's python then carries into sys.executable.
    let exe = std::env::current_exe().ok().and_then(|e| if cfg!(windows) { Some(e) } else { std::fs::canonicalize(e).ok() });
    let Some(dir) = exe.and_then(|e| e.parent().map(|p| p.join("runtime"))) else { return vec![] };
    let (py, uv) = if cfg!(windows) { (dir.join("python.exe"), dir.join("uv.exe")) }
                   else { (dir.join("bin").join("python3"), dir.join("bin").join("uv")) };
    let mut out = vec![];
    if py.is_file() && std::env::var_os("OARBANK_RUNTIME_PYTHON").is_none() {
        out.push(("OARBANK_RUNTIME_PYTHON", py));
    }
    if uv.is_file() && std::env::var_os("OARBANK_UV").is_none() {
        out.push(("OARBANK_UV", uv));
    }
    out
}

/// Sleep for `d`, or less once a stop is requested.
fn pause(d: Duration) {
    let until = Instant::now() + d;
    while !STOP.load(std::sync::atomic::Ordering::SeqCst) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(250).min(until - Instant::now()));
    }
}

/// Apply a staged update or a rollback, then run the current agent until it exits.
fn run_once(home: &Home, args: &[String]) -> Result<std::process::ExitStatus> {
    before_start(home)?;
    let mut cmd = Command::new(home.current_bin());
    cmd.arg("--home").arg(&home.0).args(args)
        .env("OARBANK_LAUNCHER", "1").env("OARBANK_LAUNCHER_PID", std::process::id().to_string());
    for (k, v) in runtime_env() {
        cmd.env(k, v);
    }
    // the installed package's agent, which the agent reports and never self-updates below (nodeupdate.rs)
    if let Some(p) = package_agent() {
        cmd.env("OARBANK_PACKAGE_AGENT", p);
    }
    let mut child = cmd.spawn()?;
    CHILD.store(child.id() as i32, std::sync::atomic::Ordering::SeqCst);
    let st = child.wait();
    CHILD.store(0, std::sync::atomic::Ordering::SeqCst);
    Ok(st?)
}

fn run(home: &Home, args: &[String]) -> Result<()> {
    handle_stop_requests();
    let bin = home.current_bin();
    if !bin.exists() {
        bail!("{} points at nothing: install a version first (oarbank-launcher install <binary>)", bin.display());
    }
    let mut backoff = Duration::from_secs(1);
    loop {
        if STOP.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        let started = Instant::now();
        // the agent exiting, and failing to start at all (a file still locked or a disk not ready at boot), are both
        // retried: the launcher keeps the service up rather than stopping before the machine is ready
        let outcome = run_once(home, args);
        if STOP.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(60) || outcome.as_ref().is_ok_and(|st| st.code() == Some(SWAP)) {
            backoff = Duration::from_secs(1);
        }
        match outcome {
            Ok(st) if st.code() == Some(SWAP) => continue,    // a staged update, or a rollback by the agent itself
            Ok(st) => eprintln!("oarbank-launcher: the agent exited ({st}); restarting in {} s", backoff.as_secs()),
            Err(e) => eprintln!("oarbank-launcher: could not start the agent: {e:#}; retrying in {} s", backoff.as_secs()),
        }
        pause(backoff);
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

const LABEL: &str = "dev.codonic.oarbank.agent";

fn flag(opts: &[String], name: &str) -> Option<String> {
    opts.iter().position(|o| o == name).and_then(|i| opts.get(i + 1)).cloned()
}

/// `service install|uninstall|status`: the service manager of this OS (svc_*.rs).
fn service(home: &Home, rest: &[String]) -> Result<()> {
    svc::service(home, rest)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut home: Option<PathBuf> = std::env::var_os("OARBANK_AGENT_HOME").map(PathBuf::from);
    let mut rest = vec![];
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--home" {
            home = it.next().map(PathBuf::from);
        } else {
            rest.push(a);
        }
    }
    // `oarbank-node`: the launcher under its second name; its commands also work as `oarbank-launcher join` etc.
    let invoked = std::env::args().next().map(|a| Path::new(&a).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()).unwrap_or_default();
    if invoked == "oarbank-node" && rest.is_empty() {
        eprintln!("{}", node::USAGE);
        std::process::exit(2);
    }
    match rest.first().map(String::as_str) {
        Some("join" | "check" | "status" | "leave" | "doctor" | "policy-apply") => {
            let code = node::main(home.as_deref(), &rest)?;
            std::process::exit(code);
        }
        Some("setup") => return setup::setup(home.as_deref(), &rest),
        // Windows: container support after the installer (container_support.rs; the MSI and its task run it)
        Some("container-support") => {
            let code = container_support::main(&rest)?;
            std::process::exit(code);
        }
        Some("remove") => return setup::remove(home.as_deref(), &rest),
        // the node update runner and its trust (update.rs; docs/design/fleet-updates.md, D57)
        Some("update-run") => {
            let code = update::update_run(&rest[1..])?;
            std::process::exit(code);
        }
        Some("update-trust") => return update::update_trust(&rest[1..]),
        // an upgrade's postinstall: the installed service definition, rendered again (it names its own home)
        Some("service") if rest.get(1).map(String::as_str) == Some("refresh") => return svc::refresh(&rest[2..]),
        #[cfg(windows)]
        Some("helper-main") => return svc::helper_main(),
        #[cfg(windows)]
        Some("helper-config") => return svc::helper_config(&rest),
        #[cfg(windows)]
        Some("helper-clear") => return helper_windows::helper_clear(),
        Some("--version") => {
            println!("oarbank-launcher {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }
    let home = Home(home.context("--home <agent home> (or OARBANK_AGENT_HOME)")?);
    match rest.first().map(String::as_str) {
        Some("install") => {
            let rel = install(&home, Path::new(rest.get(1).context("oarbank-launcher install <binary>")?))?;
            println!("{rel}");
            Ok(())
        }
        Some("current") => {
            println!("{}", home.current_target().unwrap_or_default());
            Ok(())
        }
        Some("run") => run(&home, &rest),
        Some("service") => service(&home, &rest),
        // what the Windows service manager starts (svc_windows.rs); elsewhere the service runs `run`
        #[cfg(windows)]
        Some("service-main") => svc::service_main(home, rest[1..].to_vec()),
        _ => bail!("usage: oarbank-launcher --home <dir> install <binary> | current | run [agent args...] | service ... | setup ... | remove ..."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(version: &str) -> Vec<u8> {
        [&b"\x7fELF...."[..], format!("oarbank-agent-version:{version}\0").as_bytes(), b"rest"].concat()
    }

    /// An agent home whose `current` runs `version` (installed as `install` names it), and a package's agent beside.
    fn world(current: &str, package: &str) -> (tempfile::TempDir, Home, PathBuf) {
        let tmp = tempfile::Builder::new().prefix("oarbank-launcher-supersede-").tempdir().unwrap();
        let home = Home(tmp.path().join("agent"));
        std::fs::create_dir_all(&home.0).unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("channel-agent"), [agent(current), b"channel".to_vec()].concat()).unwrap();      // another sha
        install(&home, &bin.join("channel-agent")).unwrap();
        let pkg = bin.join("oarbank-agent");
        std::fs::write(&pkg, agent(package)).unwrap();
        (tmp, home, pkg)
    }

    fn running(home: &Home) -> String {
        version_at(home, &home.current_target().unwrap()).unwrap()
    }

    /// The live 2.10.3 -> 2.10.4 case: a channel build from before the fleet release keeps `current`; the launcher's next
    /// start runs the package's agent instead.
    #[test]
    fn an_older_channel_build_in_current_gives_way_to_the_packages_agent() {
        let (_t, home, pkg) = world("2.10.3", "2.10.4");
        assert_eq!(running(&home), "2.10.3");
        before_start_with(&home, Some(&pkg)).unwrap();
        assert_eq!(running(&home), "2.10.4");
        assert_eq!(std::fs::read(home.current_bin()).unwrap(), agent("2.10.4"));
        before_start_with(&home, Some(&pkg)).unwrap();                  // and stays
        assert_eq!(running(&home), "2.10.4");
    }

    #[test]
    fn a_staged_build_older_than_the_package_is_refused_and_never_started() {
        let (_t, home, pkg) = world("2.10.4", "2.10.4");
        let old = install(&home, &{
            let p = home.0.join("old");
            std::fs::write(&p, agent("2.10.3")).unwrap();
            p
        }).unwrap();
        install(&home, &pkg).unwrap();
        home.write_upgrade(&json!({"state": "staged", "target": format!("{old}/oarbank-agent{}", std::env::consts::EXE_SUFFIX),
                                   "sha256": "ab", "version": "2.10.3"})).unwrap();
        before_start_with(&home, Some(&pkg)).unwrap();
        let up = home.read_upgrade().unwrap();
        assert_eq!(up["state"], "failed");
        assert!(up["error"].as_str().unwrap().contains("older than the installed package's agent 2.10.4"), "{up}");
        assert_eq!(running(&home), "2.10.4");
    }

    /// A channel build newer than the package (promoted after it) still updates the node, on trial as before.
    #[test]
    fn a_newer_channel_build_still_updates_and_an_equal_one_is_left_alone() {
        let (_t, home, pkg) = world("2.10.4", "2.10.4");
        let newer = install(&home, &{
            let p = home.0.join("new");
            std::fs::write(&p, agent("2.10.5")).unwrap();
            p
        }).unwrap();
        install(&home, &pkg).unwrap();
        home.write_upgrade(&json!({"state": "staged", "target": format!("{newer}/oarbank-agent{}", std::env::consts::EXE_SUFFIX),
                                   "sha256": "cd", "version": "2.10.5"})).unwrap();
        before_start_with(&home, Some(&pkg)).unwrap();
        assert_eq!(home.read_upgrade().unwrap()["state"], "trial");
        assert_eq!(running(&home), "2.10.5");
        before_start_with(&home, Some(&pkg)).unwrap();                  // on trial: the package does not interrupt it
        assert_eq!(running(&home), "2.10.5");
        // a channel build of the package's own version (another sha) is not replaced either
        let (_t2, home2, pkg2) = world("2.10.4", "2.10.4");
        let before = home2.current_target();
        before_start_with(&home2, Some(&pkg2)).unwrap();
        assert_eq!(home2.current_target(), before);
    }

    fn denied() -> std::io::Error {
        std::io::Error::from_raw_os_error(5)
    }

    #[test]
    fn a_transient_error_is_retried_with_backoff_and_then_succeeds() {
        let (mut calls, mut slept) = (0, vec![]);
        let r = retrying(RENAME_RETRY, || { calls += 1; if calls <= 3 { Err(denied()) } else { Ok(calls) } },
                         |_| true, |d| slept.push(d));
        assert_eq!(r.unwrap(), 4);
        assert_eq!(slept, [100, 200, 400].map(Duration::from_millis));
    }

    #[test]
    fn retrying_is_bounded_and_leaves_other_errors_alone() {
        let (mut calls, mut slept) = (0, Duration::ZERO);
        let r: std::io::Result<()> = retrying(RENAME_RETRY, || { calls += 1; Err(denied()) }, |_| true, |d| slept += d);
        assert_eq!(r.unwrap_err().raw_os_error(), Some(5));
        assert_eq!(slept, RENAME_RETRY);
        assert!(calls > 5 && calls < 20, "{calls}");
        let mut calls = 0;
        let r: std::io::Result<()> = retrying(RENAME_RETRY, || { calls += 1; Err(denied()) }, |_| false, |_| panic!("slept"));
        assert!(r.is_err());
        assert_eq!(calls, 1);
        // only Windows' access denied, sharing and lock violations are transient (errno 5 is EIO on Unix)
        assert_eq!(transient(&denied()), cfg!(windows));
        assert!(!transient(&std::io::Error::from(std::io::ErrorKind::NotFound)));
    }

    /// The live 2.11.0 fleet update on Windows: the package's setup and the launcher had made the package's agent current
    /// and started it, and the update runner's own install then failed to replace the running agent's file (Access is
    /// denied). Installing the same build again writes nothing and leaves `current` as it is.
    #[test]
    fn installing_the_current_build_again_writes_nothing() {
        let (_t, home, pkg) = world("2.10.4", "2.11.0");
        let rel = install(&home, &pkg).unwrap();
        let target = home.current_target().unwrap();
        assert_eq!(target, install_path(&agent("2.11.0")).unwrap());
        #[cfg(unix)]
        {
            // the version directory and the home refuse writes, as Windows refuses to replace a running program
            use std::os::unix::fs::PermissionsExt;
            for d in [home.0.join(&rel), home.0.clone()] {
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();
            }
        }
        let again = install(&home, &pkg);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for d in [home.0.clone(), home.0.join(&rel)] {
                std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        assert_eq!(again.unwrap(), rel);
        assert_eq!(home.current_target().unwrap(), target);
        assert!(!home.0.join(&rel).join(".oarbank-agent.tmp").exists());
    }

    #[test]
    fn pointing_where_current_already_points_is_success() {
        let (_t, home, _pkg) = world("2.10.4", "2.11.0");
        let target = home.current_target().unwrap();
        home.point(&target).unwrap();
        assert!(!home.0.join(".current.tmp").exists());
        assert_eq!(home.current_target().unwrap(), target);
    }

    /// The runner's step is idempotent: a failed install while `current` already names the package's build is success,
    /// and a failure while it names anything else is still a failure.
    #[test]
    fn making_the_packages_agent_current_succeeds_when_it_already_is() {
        let (_t, home, pkg) = world("2.10.4", "2.11.0");
        let data = std::fs::read(&pkg).unwrap();
        let failing = |_: &Home, _: &Path| -> Result<String> { Err(anyhow::anyhow!("Access is denied. (os error 5)")) };
        let err = make_current(&home, &pkg, &data, failing).unwrap_err();
        assert!(err.contains("Access is denied"), "{err}");
        assert_eq!(running(&home), "2.10.4");
        install(&home, &pkg).unwrap();                                  // the launcher at its start
        make_current(&home, &pkg, &data, failing).unwrap();
        assert_eq!(running(&home), "2.11.0");
        make_current(&home, &pkg, &data, install).unwrap();
        assert_eq!(running(&home), "2.11.0");
    }

    #[test]
    fn without_a_package_agent_nothing_changes() {
        let (_t, home, pkg) = world("2.10.3", "2.10.4");
        before_start_with(&home, None).unwrap();
        assert_eq!(running(&home), "2.10.3");
        std::fs::write(&pkg, b"not an agent").unwrap();
        before_start_with(&home, Some(&pkg)).unwrap();
        assert_eq!(running(&home), "2.10.3");
    }
}
