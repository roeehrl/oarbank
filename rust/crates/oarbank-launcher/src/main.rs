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

    /// Point `current` at `rel` (a path relative to the home) atomically.
    fn point(&self, rel: &str) -> Result<()> {
        let tmp = self.0.join(".current.tmp");
        let _ = std::fs::remove_file(&tmp);
        #[cfg(unix)]
        std::os::unix::fs::symlink(rel, &tmp)?;
        #[cfg(not(unix))]
        std::fs::write(&tmp, rel)?;
        std::fs::rename(&tmp, self.current())?;
        Ok(())
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

/// Install a binary as a version and make it current (first install, or by hand).
fn install(home: &Home, binary: &Path) -> Result<String> {
    let data = std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    let version = marker(&data, b"oarbank-agent-version:").context("the binary embeds no oarbank-agent version")?;
    let sha = sha256_hex(&data);
    let rel = format!("versions/{version}-{}", &sha[..12]);
    let dir = home.0.join(&rel);
    std::fs::create_dir_all(&dir)?;
    let name = format!("oarbank-agent{}", std::env::consts::EXE_SUFFIX);
    let dst = dir.join(&name);
    let tmp = dir.join(".oarbank-agent.tmp");
    std::fs::write(&tmp, &data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, &dst)?;
    home.point(&format!("{rel}/{name}"))?;
    Ok(rel)
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

/// Before each start: apply a staged update, and decide whether a trial has failed.
fn before_start(home: &Home) -> Result<()> {
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

/// Stop: no new start, and ask the running agent to stop (SIGTERM on Unix; terminated on Windows, where a console
/// control or the service manager's stop arrives here).
fn stop_now() {
    STOP.store(true, std::sync::atomic::Ordering::SeqCst);
    let c = CHILD.load(std::sync::atomic::Ordering::SeqCst);
    if c > 0 {
        #[cfg(unix)]
        unsafe { libc::kill(c, libc::SIGTERM) };
        #[cfg(windows)]
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
    }
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1);
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
