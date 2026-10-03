//! `setup` and `remove`: the declarative install plan (deploy/install-plan.json; docs/design/architecture.md,
//! "Packaging and CI") rendered for this OS. The plan names the scopes (personal: the user's LaunchAgent; system: a
//! LaunchDaemon run as a dedicated account), the home and its directories with their modes, where a join code goes, and
//! what a purge removes. Installers (the pkg's postinstall, MDM) and people run the same command; `--dry-run` prints
//! every step.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const PLAN: &str = include_str!("../../../../deploy/install-plan.json");

pub struct Step {
    dry: bool,
}

impl Step {
    fn run(&self, what: &str, f: impl FnOnce() -> Result<()>) -> Result<()> {
        if self.dry {
            println!("{what}");
            return Ok(());
        }
        f().with_context(|| what.to_string())
    }
}

pub fn plan() -> Value {
    serde_json::from_str(PLAN).expect("the embedded install plan is JSON")
}

fn user_data() -> Result<PathBuf> {
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Oarbank")).context("LOCALAPPDATA is not set");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).context("HOME is not set")?;
    Ok(if cfg!(target_os = "macos") { home.join("Library/Application Support/Oarbank") } else {
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".local/share")).join("oarbank")
    })
}

fn system_data() -> PathBuf {
    if cfg!(windows) {
        return std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("Oarbank");
    }
    PathBuf::from(if cfg!(target_os = "macos") { "/Library/Application Support/Oarbank" } else { "/var/lib/oarbank" })
}

/// Whether this process may install a system service: root on Unix, an elevated administrator on Windows.
fn privileged() -> bool {
    #[cfg(unix)]
    return unsafe { libc::geteuid() } == 0;
    #[cfg(windows)]
    return unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } != 0;
}

/// The scope's home from the plan, unless `--home` named one.
pub fn scope_home(scope: &str, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(h) = explicit {
        return Ok(h.to_path_buf());
    }
    let p = plan();
    let tpl = p["scopes"][scope]["home"].as_str().with_context(|| format!("unknown scope {scope:?} (personal or system)"))?;
    let s = tpl.replace("{user_data}", &user_data()?.display().to_string()).replace("{system_data}", &system_data().display().to_string());
    Ok(PathBuf::from(s))
}

fn flag(opts: &[String], name: &str) -> Option<String> {
    opts.iter().position(|o| o == name).and_then(|i| opts.get(i + 1)).cloned()
}

#[cfg(not(unix))]
fn chmod(_p: &Path, _mode: u32) -> Result<()> {
    Ok(())                                  // profile and ProgramData ACLs; the system scope adds its account below
}

#[cfg(unix)]
fn chmod(p: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))?)
}

fn sh(argv: &[&str]) -> Result<String> {
    let o = Command::new(argv[0]).args(&argv[1..]).output()?;
    if !o.status.success() {
        bail!("{}: {}", argv.join(" "), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}

/// The dedicated account a system install runs as: hidden, no shell, its home the system data directory.
fn ensure_account(name: &str, home: &Path, st: &Step) -> Result<()> {
    if !cfg!(target_os = "macos") {
        return st.run(&format!("useradd --system --home-dir {} --shell /usr/sbin/nologin {name}", home.display()), || {
            if sh(&["id", "-u", name]).is_err() {
                sh(&["useradd", "--system", "--home-dir", &home.display().to_string(), "--shell", "/usr/sbin/nologin", name])?;
            }
            Ok(())
        });
    }
    if !st.dry && sh(&["/usr/bin/dscl", ".", "-read", &format!("/Users/{name}")]).is_ok() {
        return Ok(());
    }
    // a free id below 500 (system accounts), from the existing ones
    let uid = if st.dry { 450 } else {
        let used: Vec<i64> = sh(&["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"])?.lines()
            .filter_map(|l| l.split_whitespace().nth(1)?.parse().ok()).collect();
        (400..500).rev().find(|u| !used.contains(u)).context("no free system user id below 500")?
    };
    let u = format!("/Users/{name}");
    let g = format!("/Groups/{name}");
    let steps: Vec<Vec<String>> = vec![
        vec!["-create".into(), g.clone()],
        vec!["-create".into(), g.clone(), "PrimaryGroupID".into(), uid.to_string()],
        vec!["-create".into(), u.clone()],
        vec!["-create".into(), u.clone(), "UniqueID".into(), uid.to_string()],
        vec!["-create".into(), u.clone(), "PrimaryGroupID".into(), uid.to_string()],
        vec!["-create".into(), u.clone(), "UserShell".into(), "/usr/bin/false".into()],
        vec!["-create".into(), u.clone(), "NFSHomeDirectory".into(), home.display().to_string()],
        vec!["-create".into(), u.clone(), "RealName".into(), "Oarbank agent".into()],
        vec!["-create".into(), u.clone(), "IsHidden".into(), "1".into()],
    ];
    for s in steps {
        let mut argv = vec!["/usr/bin/dscl", "."];
        argv.extend(s.iter().map(String::as_str));
        st.run(&argv.join(" "), || sh(&argv).map(|_| ()))?;
    }
    Ok(())
}

/// `setup [--scope personal|system] [--join-code-file F | --join-code C] [--coordinator URL] [--agent PATH]
/// [--no-service] [--dry-run]`; `--no-service` lays out the home and prints the agent arguments without loading a
/// service (image builds, tests).
pub fn setup(explicit_home: Option<&Path>, opts: &[String]) -> Result<()> {
    let st = Step { dry: opts.iter().any(|o| o == "--dry-run") };
    let scope = flag(opts, "--scope").unwrap_or_else(|| "personal".into());
    let p = plan();
    let sc = &p["scopes"][&scope];
    if sc.is_null() {
        bail!("unknown scope {scope:?} (personal or system)");
    }
    let system = sc["service"] == "system";
    if system && !st.dry && !privileged() {
        bail!("a system install needs root (sudo) or an elevated administrator");
    }
    let code = match (flag(opts, "--join-code"), flag(opts, "--join-code-file")) {
        (Some(c), _) => Some(c),
        (None, Some(f)) => Some(std::fs::read_to_string(&f).with_context(|| format!("reading {f}"))?.trim().to_string()),
        _ => None,
    };
    if code.as_ref().is_some_and(|c| !c.starts_with("OB1-")) {
        bail!("that is not an Oarbank join code (they start with OB1-)");
    }
    let home = scope_home(&scope, explicit_home)?;
    // the dedicated account, per OS (Windows: the service's virtual account, nothing to create)
    let os = if cfg!(target_os = "macos") { "darwin" } else if cfg!(windows) { "windows" } else { "linux" };
    let account = sc["account"].as_str().or_else(|| sc["account"][os].as_str());
    if let (true, Some(a), false) = (system, account, cfg!(windows)) {
        ensure_account(a, home.parent().unwrap_or(&home), &st)?;
    }
    for d in p["dirs"].as_array().cloned().unwrap_or_default() {
        let dir = home.join(d["path"].as_str().unwrap_or(""));
        let mode = u32::from_str_radix(d["mode"].as_str().unwrap_or("0700").trim_start_matches('0'), 8).unwrap_or(0o700);
        st.run(&format!("mkdir -m {mode:o} {}", dir.display()), || {
            std::fs::create_dir_all(&dir)?;
            chmod(&dir, mode)
        })?;
    }
    let me = std::fs::canonicalize(std::env::current_exe()?)?;
    let agent = flag(opts, "--agent").map(PathBuf::from)
        .unwrap_or_else(|| me.with_file_name(format!("oarbank-agent{}", std::env::consts::EXE_SUFFIX)));
    st.run(&format!("install {} as the current version", agent.display()), || {
        crate::install(&crate::Home(home.clone()), &agent).map(|rel| println!("current -> {rel}"))
    })?;
    let mut agent_args: Vec<String> = vec![];
    let jc = &p["join_code"];
    let join_to = home.join(jc["to"].as_str().unwrap_or("state/join-code"));
    if let Some(code) = code {
        st.run(&format!("write the join code to {} (0600)", join_to.display()), || {
            std::fs::write(&join_to, &code)?;
            chmod(&join_to, 0o600)
        })?;
        agent_args.extend(["--join-file".into(), join_to.display().to_string()]);
    }
    if let Some(url) = flag(opts, "--coordinator") {
        agent_args.extend(["--coordinator".into(), url]);
    }
    if agent_args.is_empty() && !home.join("agent.json").exists() {
        bail!("give --join-code-file, --join-code or --coordinator: this node does not know its coordinator yet");
    }
    // Windows names no account: the service's virtual account gets the home when the service is created (svc_windows.rs)
    if let (true, Some(a)) = (system, account) {
        st.run(&format!("chown -R {a} {}", home.display()), || sh(&["chown", "-R", &format!("{a}:{a}"), &home.display().to_string()]).map(|_| ()))?;
        if cfg!(target_os = "linux") {
            // rootless containers need the account's runtime directory, which only lingering keeps without a login
            st.run(&format!("loginctl enable-linger {a}"), || { let _ = sh(&["loginctl", "enable-linger", a]); Ok(()) })?;
        }
    }
    if opts.iter().any(|o| o == "--no-service") {
        println!("agent arguments: run {}", agent_args.join(" "));
        return Ok(());
    }
    let mut svc: Vec<String> = vec!["service".into(), "install".into(), "--label".into(), p["label"].as_str().unwrap_or(crate::LABEL).into()];
    if system {
        svc.push("--system".into());
        if let (Some(a), false) = (account, cfg!(windows)) {          // Windows: the service's virtual account
            svc.extend(["--user".into(), a.into()]);
        }
    }
    if st.dry {
        svc.push("--dry-run".into());
    }
    svc.push("--".into());
    svc.extend(agent_args);
    crate::service(&crate::Home(home), &svc)
}

/// `remove [--scope personal|system] [--purge] [--dry-run]`: unload and delete the service; `--purge` also deletes
/// what the plan lists (the agent's home: its keys, certificate, caches and logs).
pub fn remove(explicit_home: Option<&Path>, opts: &[String]) -> Result<()> {
    let st = Step { dry: opts.iter().any(|o| o == "--dry-run") };
    let scope = flag(opts, "--scope").unwrap_or_else(|| "personal".into());
    let p = plan();
    let home = scope_home(&scope, explicit_home)?;
    let mut svc: Vec<String> = vec!["service".into(), "uninstall".into(), "--label".into(), p["label"].as_str().unwrap_or(crate::LABEL).into()];
    if p["scopes"][&scope]["service"] == "system" {
        svc.push("--system".into());
    }
    if st.dry {
        svc.push("--dry-run".into());
    }
    crate::service(&crate::Home(home.clone()), &svc)?;
    if opts.iter().any(|o| o == "--purge") {
        for rel in p["purge"].as_array().cloned().unwrap_or_default() {
            let path = home.join(rel.as_str().unwrap_or("-"));
            if path.exists() || st.dry {
                st.run(&format!("rm -r {}", path.display()), || Ok(std::fs::remove_dir_all(&path)?))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_plan_parses_and_names_both_scopes() {
        let p = super::plan();
        assert_eq!(p["format"], 1);
        assert!(p["scopes"]["personal"]["home"].as_str().unwrap().contains("{user_data}"));
        assert_eq!(p["scopes"]["system"]["account"]["darwin"], "_oarbank");
        assert_eq!(p["scopes"]["system"]["account"]["linux"], "oarbank");
    }
}
