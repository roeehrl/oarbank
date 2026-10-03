//! The launcher under the Windows service manager (docs/design/architecture.md, "Host interfaces": the launcher
//! is the service). The system scope is a service run by its virtual account (`NT SERVICE\<name>`), started at boot
//! (delayed) and restarted by the service manager's recovery actions; the personal scope is a scheduled task at
//! the user's logon. The service manager starts `oarbank-launcher --home H service-main <agent args>`.

use crate::{flag, Home, LABEL};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::process::Command;
use std::sync::OnceLock;

fn sc(args: &[String], dry: bool) -> Result<std::process::Output> {
    if dry {
        println!("sc.exe {}", args.join(" "));
        return Ok(std::process::Output { status: Default::default(), stdout: vec![], stderr: vec![] });
    }
    Ok(Command::new("sc.exe").args(args).output()?)
}

fn icacls(args: &[String], dry: bool) -> Result<std::process::Output> {
    if dry {
        println!("icacls.exe {}", args.join(" "));
        return Ok(std::process::Output { status: Default::default(), stdout: vec![], stderr: vec![] });
    }
    Ok(Command::new("icacls.exe").args(args).output()?)
}

fn schtasks(args: &[String], dry: bool) -> Result<std::process::Output> {
    if dry {
        println!("schtasks.exe {}", args.join(" "));
        return Ok(std::process::Output { status: Default::default(), stdout: vec![], stderr: vec![] });
    }
    Ok(Command::new("schtasks.exe").args(args).output()?)
}

fn ok(o: &std::process::Output, what: &str) -> Result<()> {
    if !o.status.success() {
        bail!("{what} failed: {}{}", String::from_utf8_lossy(&o.stdout).trim(), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(())
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// The service manager restarts the service when it crashes and also when it stops itself with an error
/// (`failureflag`): after 10 s, 10 s, then every 60 s, the count reset after a day.
fn recovery(name: &str, dry: bool) -> Result<()> {
    ok(&sc(&s(&["failure", name, "reset=", "86400", "actions=", "restart/10000/restart/10000/restart/60000"]), dry)?, "sc failure")?;
    ok(&sc(&s(&["failureflag", name, "1"]), dry)?, "sc failureflag")
}

/// `helper-config [--dry-run]` (the MSI runs it once the helper's service exists): start it at boot, delayed, and
/// with the agent's recovery actions.
pub fn helper_config(opts: &[String]) -> Result<()> {
    let dry = opts.iter().any(|o| o == "--dry-run");
    ok(&sc(&s(&["config", crate::helper_windows::SERVICE, "start=", "delayed-auto"]), dry)?, "sc config")?;
    recovery(crate::helper_windows::SERVICE, dry)
}

/// `service install|uninstall|status [--system [--user ACCOUNT]] [--label NAME] [--dry-run] [-- agent args...]`
pub fn service(home: &Home, rest: &[String]) -> Result<()> {
    let split = rest.iter().position(|a| a == "--").unwrap_or(rest.len());
    let (opts, agent_args) = (&rest[..split], rest.get(split + 1..).unwrap_or(&[]));
    let dry = opts.iter().any(|o| o == "--dry-run");
    let system = opts.iter().any(|o| o == "--system");
    let name = flag(opts, "--label").unwrap_or_else(|| LABEL.to_string());
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)) {
        bail!("bad label {name:?}");
    }
    let task = format!("Oarbank\\{name}");
    match opts.get(1).map(String::as_str) {
        Some("install") => {
            let exe = std::env::current_exe()?;
            let home_dir = std::path::absolute(&home.0)?;
            if !dry && !home.current_bin().exists() {
                bail!("install a version first (oarbank-launcher install <binary>)");
            }
            if system {
                let mut program = vec![exe.display().to_string(), "--home".into(), home_dir.display().to_string(), "service-main".into()];
                program.extend(agent_args.iter().cloned());
                let _ = sc(&s(&["stop", &name]), dry);
                let _ = sc(&s(&["delete", &name]), dry);
                ok(&sc(&oarbank_core::service::sc_create_args(&name, "Oarbank agent", &program, flag(opts, "--user").as_deref()), dry)?, "sc create")?;
                // its virtual account exists now: the home becomes its own before the service first starts
                ok(&icacls(&oarbank_core::service::icacls_home_args(&name, &home_dir.display().to_string()), dry)?, "icacls")?;
                ok(&sc(&s(&["description", &name, "Runs Oarbank jobs on this machine for its coordinator"]), dry)?, "sc description")?;
                recovery(&name, dry)?;
                ok(&sc(&s(&["start", &name]), dry)?, "sc start")?;
                println!("installed service {name}");
            } else {
                let mut tr = format!("\"{}\" --home \"{}\" run", exe.display(), home_dir.display());
                for a in agent_args {
                    tr += &format!(" \"{a}\"");
                }
                ok(&schtasks(&s(&["/Create", "/F", "/TN", &task, "/SC", "ONLOGON", "/RL", "LIMITED", "/TR", &tr]), dry)?, "schtasks create")?;
                ok(&schtasks(&s(&["/Run", "/TN", &task]), dry)?, "schtasks run")?;
                println!("installed task {task}");
            }
            Ok(())
        }
        Some("uninstall") => {
            if system {
                let _ = sc(&s(&["stop", &name]), dry)?;
                ok(&sc(&s(&["delete", &name]), dry)?, "sc delete")?;
            } else {
                let _ = schtasks(&s(&["/End", "/TN", &task]), dry);
                ok(&schtasks(&s(&["/Delete", "/F", "/TN", &task]), dry)?, "schtasks delete")?;
            }
            println!("uninstalled {name}");
            Ok(())
        }
        Some("status") => {
            let st = if system {
                let o = sc(&s(&["queryex", &name]), dry)?;
                let t = String::from_utf8_lossy(&o.stdout).to_string();
                let field = |k: &str| t.lines().map(str::trim).find_map(|l| l.strip_prefix(k).map(|v| v.trim_start_matches([' ', ':']).trim().to_string()));
                json!({"label": name, "installed": o.status.success(), "state": field("STATE"),
                       "pid": field("PID").and_then(|p| p.parse::<i64>().ok()), "current": home.current_target()})
            } else {
                let o = schtasks(&s(&["/Query", "/TN", &task, "/FO", "LIST"]), dry)?;
                json!({"label": task, "installed": o.status.success(), "detail": String::from_utf8_lossy(&o.stdout).trim(),
                       "current": home.current_target()})
            };
            println!("{}", serde_json::to_string_pretty(&st)?);
            Ok(())
        }
        _ => bail!("usage: oarbank-launcher --home <dir> service install|uninstall|status [--system [--user ACCOUNT]] [--label NAME] [--dry-run] [-- agent args]"),
    }
}

// MARK: the service manager's entry point

use windows_sys::Win32::Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
use windows_sys::Win32::System::Services::{RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
                                           SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
                                           SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
                                           SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS};

/// What the service manager starts this process for: the agent's supervisor, or the elevated helper.
enum Mode {
    Agent(Home, Vec<String>),
    Helper,
}

static START: OnceLock<Mode> = OnceLock::new();
static HANDLE: OnceLock<usize> = OnceLock::new();

/// Report a state; a nonzero `exit` is a service-specific error code (the service manager then runs the recovery
/// actions, `sc failureflag`).
fn report(state: u32, exit: u32) {
    let Some(h) = HANDLE.get() else { return };
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS, dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 },
        dwWin32ExitCode: if exit == 0 { NO_ERROR } else { ERROR_SERVICE_SPECIFIC_ERROR }, dwServiceSpecificExitCode: exit,
        dwCheckPoint: 0, dwWaitHint: if state == SERVICE_STOP_PENDING { 30_000 } else { 0 },
    };
    unsafe { SetServiceStatus(*h as SERVICE_STATUS_HANDLE, &st) };
}

unsafe extern "system" fn control(code: u32, _event: u32, _data: *mut core::ffi::c_void, _ctx: *mut core::ffi::c_void) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        report(SERVICE_STOP_PENDING, 0);
        crate::stop_now();
        // the helper waits in ConnectNamedPipe: a connection of our own wakes it to see the stop
        if matches!(START.get(), Some(Mode::Helper)) {
            let _ = std::fs::OpenOptions::new().read(true).write(true).open(crate::helper_windows::PIPE);
        }
    }
    NO_ERROR
}

unsafe extern "system" fn main_fn(_argc: u32, _argv: *mut *mut u16) {
    let Some(mode) = START.get() else { return };
    let name: Vec<u16> = "OarbankAgent\0".encode_utf16().collect();          // ignored for an own-process service
    let h = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), std::ptr::null_mut()) };
    if h.is_null() {
        return;
    }
    let _ = HANDLE.set(h as usize);
    report(SERVICE_RUNNING, 0);
    let r = match mode {
        Mode::Agent(home, args) => {
            log_to_file(home);
            let mut run_args = vec!["run".to_string()];
            run_args.extend(args.iter().cloned());
            crate::run(home, &run_args)
        }
        Mode::Helper => crate::helper_windows::serve(),
    };
    if let Err(e) = &r {
        eprintln!("oarbank-launcher: {e:#}");
    }
    report(SERVICE_STOPPED, if r.is_ok() { 0 } else { 1 });
}

/// A service has no console: the launcher's and the agent's output go to `<home>\logs\launcher.log` (as launchd's
/// StandardOutPath does on macOS), set aside as `launcher.log.1` once it passes 16 MB.
fn log_to_file(home: &Home) {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
    let dir = home.0.join("logs");
    let path = dir.join("launcher.log");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if std::fs::metadata(&path).map(|m| m.len() > 16 << 20).unwrap_or(false) {
        let _ = std::fs::rename(&path, dir.join("launcher.log.1"));
    }
    let open = || std::fs::OpenOptions::new().create(true).append(true).open(&path);
    if let (Ok(out), Ok(err)) = (open(), open()) {
        unsafe {
            SetStdHandle(STD_OUTPUT_HANDLE, out.into_raw_handle() as _);
            SetStdHandle(STD_ERROR_HANDLE, err.into_raw_handle() as _);
        }
    }
}

/// `service-main <agent args>`: hand the process to the service manager, which calls back into main_fn.
pub fn service_main(home: Home, args: Vec<String>) -> Result<()> {
    START.set(Mode::Agent(home, args)).ok().context("service-main ran twice")?;
    dispatch()
}

/// `helper-main`: the elevated helper's service (helper_windows.rs).
pub fn helper_main() -> Result<()> {
    START.set(Mode::Helper).ok().context("helper-main ran twice")?;
    dispatch()
}

fn dispatch() -> Result<()> {
    let mut name: Vec<u16> = "OarbankAgent\0".encode_utf16().collect();
    let table = [SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(main_fn) },
                 SERVICE_TABLE_ENTRYW { lpServiceName: std::ptr::null_mut(), lpServiceProc: None }];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        bail!("not started by the service manager: {}", std::io::Error::last_os_error());
    }
    Ok(())
}
