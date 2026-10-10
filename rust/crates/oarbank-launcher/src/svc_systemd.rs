//! The launcher under systemd (Linux): a user unit in `~/.config/systemd/user`, or with `--system` a system unit in
//! `/etc/systemd/system` run as a named account. The unit restarts the launcher on any exit (the launcher itself
//! handles the agent's exit 75) and delegates its cgroup, so the agent can put jobs in cgroups of their own. A system
//! install also enables, for every person's user manager, the session helper that tells the agent's host protection
//! what the service's account may not read (`/etc/systemd/user/<label>.session.service`), and runs the agent with
//! `--session-hub`.

use crate::{flag, Home, LABEL};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;

fn systemctl(user: bool, args: &[&str], dry: bool) -> Result<std::process::Output> {
    let mut all: Vec<&str> = if user { vec!["--user"] } else { vec![] };
    all.extend_from_slice(args);
    if dry {
        println!("systemctl {}", all.join(" "));
        return Ok(std::process::Output { status: Default::default(), stdout: vec![], stderr: vec![] });
    }
    Ok(Command::new("systemctl").args(&all).output()?)
}

/// `service install|uninstall|status [--system [--user NAME]] [--label L] [--dry-run] [-- agent args...]`
pub fn service(home: &Home, rest: &[String]) -> Result<()> {
    let split = rest.iter().position(|a| a == "--").unwrap_or(rest.len());
    let (opts, agent_args) = (&rest[..split], rest.get(split + 1..).unwrap_or(&[]));
    let dry = opts.iter().any(|o| o == "--dry-run");
    let system = opts.iter().any(|o| o == "--system");
    let label = flag(opts, "--label").unwrap_or_else(|| LABEL.to_string());
    if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c)) {
        bail!("bad label {label:?}");
    }
    let unit = format!("{label}.service");
    let helper_unit = format!("{label}.session.service");
    let helper_path = PathBuf::from("/etc/systemd/user").join(&helper_unit);
    let path = if system { PathBuf::from("/etc/systemd/system").join(&unit) } else {
        let base = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))).context("HOME is not set")?;
        base.join("systemd/user").join(&unit)
    };
    match opts.get(1).map(String::as_str) {
        Some("install") => {
            let exe = std::fs::canonicalize(std::env::current_exe()?)?;
            let home_dir = std::path::absolute(&home.0)?;
            let mut program = vec![exe.display().to_string(), "--home".into(), home_dir.display().to_string(), "run".into()];
            program.extend(agent_args.iter().cloned());
            let account = if system { flag(opts, "--user") } else { None };
            if account.is_some() {
                program.push("--session-hub".into());
            }
            // the agent binary installed beside the launcher (root's), never the service account's current version
            let helper_agent = exe.with_file_name("oarbank-agent");
            let spec = oarbank_core::service::ServiceSpec {
                label: label.clone(), program, env: vec![("OARBANK_LOG".into(), "info".into())],
                working_dir: Some(home_dir.display().to_string()), stdout: None, stderr: None,
                user: account.clone(), keep_alive: true, restart_on_failure: false, associated_bundle: None,
                stop_timeout_s: Some(oarbank_core::service::AGENT_STOP_TIMEOUT_S),
            };
            let text = oarbank_core::service::systemd_unit(&spec, "Oarbank agent", system);
            if dry {
                println!("# {}\n{text}", path.display());
            } else {
                if !home.current_bin().exists() {
                    bail!("install a version first (oarbank-launcher install <binary>)");
                }
                std::fs::create_dir_all(path.parent().unwrap())?;
                let tmp = path.with_extension("service.tmp");
                std::fs::write(&tmp, &text)?;
                std::fs::rename(&tmp, &path)?;
            }
            if let (Some(a), true) = (&account, helper_agent.exists()) {
                let text = oarbank_core::service::session_helper_unit(&helper_agent.display().to_string(), a);
                if dry {
                    println!("# {}\n{text}", helper_path.display());
                } else {
                    std::fs::write(&helper_path, text)?;
                }
                // started in each person's user manager at their next login
                let o = systemctl(false, &["--global", "enable", &helper_unit], dry)?;
                if !o.status.success() {
                    bail!("systemctl --global enable failed: {}", String::from_utf8_lossy(&o.stderr).trim());
                }
            } else if account.is_some() {
                eprintln!("no agent binary beside the launcher ({}): no session helpers; other accounts' paths, arguments \
                           and displays stay unreadable to host protection", helper_agent.display());
            }
            systemctl(!system, &["daemon-reload"], dry)?;
            let o = systemctl(!system, &["enable", "--now", &unit], dry)?;
            if !o.status.success() {
                bail!("systemctl enable failed: {}", String::from_utf8_lossy(&o.stderr).trim());
            }
            println!("installed {unit}");
            Ok(())
        }
        Some("uninstall") => {
            let _ = systemctl(!system, &["disable", "--now", &unit], dry)?;
            if dry {
                println!("rm {}", path.display());
            } else if path.exists() {
                std::fs::remove_file(&path)?;
            }
            if system && (dry || helper_path.exists()) {
                let _ = systemctl(false, &["--global", "disable", &helper_unit], dry)?;
                if dry {
                    println!("rm {}", helper_path.display());
                } else {
                    std::fs::remove_file(&helper_path)?;
                }
            }
            systemctl(!system, &["daemon-reload"], dry)?;
            println!("uninstalled {unit}");
            Ok(())
        }
        Some("status") => {
            let o = systemctl(!system, &["show", &unit, "-p", "ActiveState", "-p", "MainPID", "-p", "ExecMainStatus"], dry)?;
            let t = String::from_utf8_lossy(&o.stdout).to_string();
            let field = |k: &str| t.lines().find_map(|l| l.strip_prefix(&format!("{k}=")).map(str::to_string));
            println!("{}", serde_json::to_string_pretty(&json!({
                "label": unit, "unit": path, "installed": path.exists(), "state": field("ActiveState"),
                "pid": field("MainPID").and_then(|p| p.parse::<i64>().ok()).filter(|p| *p > 0),
                "last_exit": field("ExecMainStatus"), "current": home.current_target()}))?);
            Ok(())
        }
        _ => bail!("usage: oarbank-launcher --home <dir> service install|uninstall|status [--system [--user NAME]] [--label L] [--dry-run] [-- agent args]"),
    }
}
