//! The launcher under launchd (macOS): a LaunchAgent in the user's GUI session, or with `--system` a LaunchDaemon
//! run as a named account.

use crate::{flag, Home, LABEL};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;

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
    match opts.get(1).map(String::as_str) {
        Some("install") => {
            let exe = std::fs::canonicalize(std::env::current_exe()?)?;
            let home_dir = std::path::absolute(&home.0)?;
            let logs = home_dir.join("logs");
            let mut program = vec![exe.display().to_string(), "--home".into(), home_dir.display().to_string(), "run".into()];
            program.extend(agent_args.iter().cloned());
            let spec = oarbank_core::service::ServiceSpec {
                label: t.label.clone(), program,
                env: vec![("OARBANK_LOG".into(), "info".into()),
                          ("PATH".into(), "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into())],
                working_dir: Some(home_dir.display().to_string()),
                stdout: Some(logs.join("launcher.log").display().to_string()),
                stderr: Some(logs.join("launcher.log").display().to_string()),
                user: if t.domain == "system" { flag(opts, "--user") } else { None },
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
            let out = launchctl(&["bootstrap", &t.domain, &t.plist.display().to_string()], dry)?;
            if !out.status.success() {
                bail!("launchctl bootstrap failed: {}", String::from_utf8_lossy(&out.stderr).trim());
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

