//! The launcher under launchd (macOS): a LaunchAgent in the user's GUI session, or with `--system` a LaunchDaemon
//! run as a named account. A system install also puts the session helper, which tells the agent's host protection
//! what the service's account may not read, in every GUI login (`/Library/LaunchAgents/<label>.session.plist`,
//! started now in the sessions logged in), and runs the agent with `--session-hub`, serving them in a directory of
//! the account's that everyone may enter.

use crate::{flag, Home, LABEL};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where a system install's agent serves session helpers (oarbank-protection's platform/macos/session.rs).
const SESSION_DIR: &str = "/Library/Application Support/Oarbank/run";

/// Where the service's definition lives and the launchctl domain it loads into: a LaunchAgent in the user's GUI
/// session, or with `--system` a LaunchDaemon (run as `--user`, or root).
struct ServiceTarget {
    label: String,
    plist: PathBuf,
    domain: String,
}

fn service_target(opts: &[String]) -> Result<ServiceTarget> {
    let label = flag(opts, "--label").unwrap_or_else(|| LABEL.to_string());
    if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)) {
        bail!("bad label {label:?}");
    }
    if opts.iter().any(|o| o == "--system") {
        return Ok(ServiceTarget { plist: PathBuf::from(format!("/Library/LaunchDaemons/{label}.plist")), domain: "system".into(), label });
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).context("HOME is not set")?;
    let uid = unsafe { libc::getuid() };
    Ok(ServiceTarget { plist: home.join("Library/LaunchAgents").join(format!("{label}.plist")), domain: format!("gui/{uid}"), label })
}

/// The accounts logged in at a GUI session (utmpx's console logins, one per fast-user-switched session).
fn gui_uids() -> Vec<u32> {
    let mut uids = vec![];
    // SAFETY: the utmpx database is read start to end on this thread; each entry is copied before the next call.
    unsafe {
        libc::setutxent();
        loop {
            let e = libc::getutxent();
            if e.is_null() {
                break;
            }
            let line = CStr::from_ptr((*e).ut_line.as_ptr()).to_bytes();
            if (*e).ut_type != libc::USER_PROCESS || line != b"console" {
                continue;
            }
            let pw = libc::getpwnam((*e).ut_user.as_ptr());
            if !pw.is_null() && !uids.contains(&(*pw).pw_uid) {
                uids.push((*pw).pw_uid);
            }
        }
        libc::endutxent();
    }
    uids
}

/// The account's uid and primary group.
fn account_ids(name: &str) -> Result<(u32, u32)> {
    let c = CString::new(name)?;
    // SAFETY: a NUL-terminated name; the entry is read before any other getpw* call.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        bail!("no account {name:?}");
    }
    Ok(unsafe { ((*pw).pw_uid, (*pw).pw_gid) })
}

/// The session helpers' socket directory, the account's, that everyone may enter (only the account creates in it).
fn session_dir(account: &str, dry: bool) -> Result<()> {
    if dry {
        println!("mkdir -m 755 {SESSION_DIR} && chown {account} {SESSION_DIR}");
        return Ok(());
    }
    use std::os::unix::fs::PermissionsExt;
    let (uid, gid) = account_ids(account)?;
    std::fs::create_dir_all(SESSION_DIR)?;
    std::os::unix::fs::chown(SESSION_DIR, Some(uid), Some(gid))?;
    std::fs::set_permissions(SESSION_DIR, std::fs::Permissions::from_mode(0o755))?;
    Ok(())
}

/// Start (`plist`) or stop (None) the session helper in every GUI session logged in now; later logins load it
/// from /Library/LaunchAgents themselves.
fn helpers_in_gui_sessions(label: &str, plist: Option<&Path>, dry: bool) -> Result<()> {
    for uid in gui_uids() {
        let _ = launchctl(&["bootout", &format!("gui/{uid}/{label}")], dry);
        if let Some(p) = plist {
            let out = launchctl(&["bootstrap", &format!("gui/{uid}"), &p.display().to_string()], dry)?;
            if !out.status.success() {
                bail!("launchctl bootstrap gui/{uid} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
            }
        }
    }
    Ok(())
}

fn launchctl(args: &[&str], dry: bool) -> Result<std::process::Output> {
    if dry {
        println!("launchctl {}", args.join(" "));
        return Ok(std::process::Output { status: std::process::ExitStatus::default(), stdout: vec![], stderr: vec![] });
    }
    Ok(Command::new("/bin/launchctl").args(args).output()?)
}

/// `service install|uninstall|status [--system [--user NAME]] [--label L] [--dry-run] [-- agent args...]`: run the
/// launcher (and so the agent) under launchd, started at login (or boot) and kept alive.
pub fn service(home: &Home, rest: &[String]) -> Result<()> {
    let split = rest.iter().position(|a| a == "--").unwrap_or(rest.len());
    let (opts, agent_args) = (&rest[..split], rest.get(split + 1..).unwrap_or(&[]));
    let dry = opts.iter().any(|o| o == "--dry-run");
    let t = service_target(opts)?;
    let target = format!("{}/{}", t.domain, t.label);
    let helper_label = format!("{}.session", t.label);
    let helper_plist = PathBuf::from("/Library/LaunchAgents").join(format!("{helper_label}.plist"));
    match opts.get(1).map(String::as_str) {
        Some("install") => {
            let exe = std::fs::canonicalize(std::env::current_exe()?)?;
            let home_dir = std::path::absolute(&home.0)?;
            let logs = home_dir.join("logs");
            let mut program = vec![exe.display().to_string(), "--home".into(), home_dir.display().to_string(), "run".into()];
            program.extend(agent_args.iter().cloned());
            let account = if t.domain == "system" { flag(opts, "--user") } else { None };
            if account.is_some() {
                program.push("--session-hub".into());
            }
            let spec = oarbank_core::service::ServiceSpec {
                label: t.label.clone(), program,
                env: vec![("OARBANK_LOG".into(), "info".into()),
                          ("PATH".into(), "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into())],
                working_dir: Some(home_dir.display().to_string()),
                stdout: Some(logs.join("launcher.log").display().to_string()),
                stderr: Some(logs.join("launcher.log").display().to_string()),
                user: account.clone(),
                keep_alive: true,
                restart_on_failure: false,
            };
            let plist = oarbank_core::service::launchd_plist(&spec);
            if dry {
                println!("# {}\n{plist}", t.plist.display());
            } else {
                if !home.current_bin().exists() {
                    bail!("install a version first (oarbank-launcher install <binary>)");
                }
                std::fs::create_dir_all(&logs)?;
                std::fs::create_dir_all(t.plist.parent().unwrap())?;
                let _ = launchctl(&["bootout", &target], false);          // a previous definition, if loaded
                let tmp = t.plist.with_extension("plist.tmp");
                std::fs::write(&tmp, &plist)?;
                std::fs::rename(&tmp, &t.plist)?;
            }
            if let Some(a) = &account {
                session_dir(a, dry)?;
            }
            let out = launchctl(&["bootstrap", &t.domain, &t.plist.display().to_string()], dry)?;
            if !out.status.success() {
                bail!("launchctl bootstrap failed: {}", String::from_utf8_lossy(&out.stderr).trim());
            }
            // the agent binary installed beside the launcher (root's), never the service account's current version
            let helper_agent = exe.with_file_name("oarbank-agent");
            if account.is_some() && helper_agent.exists() {
                let text = oarbank_core::service::session_helper_plist(&helper_label, &helper_agent.display().to_string());
                if dry {
                    println!("# {}\n{text}", helper_plist.display());
                } else {
                    std::fs::write(&helper_plist, text)?;
                }
                helpers_in_gui_sessions(&helper_label, Some(&helper_plist), dry)?;
            } else if account.is_some() {
                eprintln!("no agent binary beside the launcher ({}): no session helpers; the people's processes stay unseen \
                           by host protection", helper_agent.display());
            }
            println!("installed {target}");
            Ok(())
        }
        Some("uninstall") => {
            let _ = launchctl(&["bootout", &target], dry)?;
            if dry {
                println!("rm {}", t.plist.display());
            } else if t.plist.exists() {
                std::fs::remove_file(&t.plist)?;
            }
            if t.domain == "system" && (dry || helper_plist.exists()) {
                helpers_in_gui_sessions(&helper_label, None, dry)?;
                if dry {
                    println!("rm {} && rm -r {SESSION_DIR}", helper_plist.display());
                } else {
                    std::fs::remove_file(&helper_plist)?;
                    let _ = std::fs::remove_dir_all(SESSION_DIR);
                }
            }
            println!("uninstalled {target}");
            Ok(())
        }
        Some("status") => {
            let out = launchctl(&["print", &target], dry)?;
            let text = String::from_utf8_lossy(&out.stdout);
            let field = |k: &str| text.lines().map(str::trim).find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string()));
            let st = if dry { json!({"label": t.label}) } else {
                json!({"label": t.label, "plist": t.plist, "installed": t.plist.exists(), "loaded": out.status.success(),
                       "state": field("state = "), "pid": field("pid = ").and_then(|p| p.parse::<i64>().ok()),
                       "last_exit": field("last exit code = "), "current": home.current_target()})
            };
            println!("{}", serde_json::to_string_pretty(&st)?);
            Ok(())
        }
        _ => bail!("usage: oarbank-launcher --home <dir> service install|uninstall|status [--system [--user NAME]] [--label L] [--dry-run] [-- agent args]"),
    }
}

