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
pub fn privileged() -> bool {
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

/// A path the plan names (`/`-separated, relative to the home) in this OS's spelling.
fn plan_path(home: &Path, rel: &str) -> PathBuf {
    rel.split('/').filter(|c| !c.is_empty()).fold(home.to_path_buf(), |p, c| p.join(c))
}

/// Where the agent keeps its status document (node-enrollment.md): `status/node.json` in the scope's data directory,
/// beside the (private) home, readable by everyone.
pub fn status_file(home: &Path) -> PathBuf {
    home.parent().unwrap_or(home).join("status").join("node.json")
}

/// What `setup` needs, from flags or from `oarbank-node join`.
#[derive(Default)]
pub struct SetupOpts {
    pub scope: String,
    pub code: Option<String>,
    pub coordinator: Option<String>,
    pub name: Option<String>,
    pub agent: Option<PathBuf>,
    pub no_service: bool,
    pub dry: bool,
}

/// `setup [--scope personal|system] [--join-code-file F | --join-code-stdin | --join-code C] [--coordinator URL]
/// [--name NAME] [--agent PATH] [--no-service] [--dry-run]`. Without a code or a coordinator the service starts and
/// waits for one (`oarbank-node join` stages it later, or managed policy names it). `--no-service` lays out the home and
/// prints the agent arguments without loading a service (image builds, tests). `--join-code` is for the Windows
/// installer's elevated custom action, whose command line only administrators can read.
pub fn setup(explicit_home: Option<&Path>, opts: &[String]) -> Result<()> {
    let code = match (flag(opts, "--join-code"), flag(opts, "--join-code-file"), opts.iter().any(|o| o == "--join-code-stdin")) {
        (Some(c), _, _) => Some(c),
        (None, Some(f), _) => Some(std::fs::read_to_string(&f).with_context(|| format!("reading {f}"))?),
        (None, None, true) => {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
            Some(s)
        }
        _ => None,
    };
    let o = SetupOpts { scope: flag(opts, "--scope").unwrap_or_else(|| "personal".into()), code: code.map(|c| c.trim().to_string()),
                        coordinator: flag(opts, "--coordinator"), name: flag(opts, "--name"), agent: flag(opts, "--agent").map(PathBuf::from),
                        no_service: opts.iter().any(|o| o == "--no-service"), dry: opts.iter().any(|o| o == "--dry-run") };
    setup_with(explicit_home, &o).map(|_| ())
}

/// The install plan for `o`; returns the home.
pub fn setup_with(explicit_home: Option<&Path>, o: &SetupOpts) -> Result<PathBuf> {
    let st = Step { dry: o.dry };
    let scope = o.scope.clone();
    let p = plan();
    let sc = &p["scopes"][&scope];
    if sc.is_null() {
        bail!("unknown scope {scope:?} (personal or system)");
    }
    let system = sc["service"] == "system";
    if system && !st.dry && !privileged() {
        bail!("a system install needs root (sudo) or an elevated administrator");
    }
    if let Some(c) = &o.code {
        oarbank_core::joincode::decode(c).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    let home = scope_home(&scope, explicit_home)?;
    // the dedicated account, per OS (Windows: the service's virtual account, nothing to create)
    let os = if cfg!(target_os = "macos") { "darwin" } else if cfg!(windows) { "windows" } else { "linux" };
    let account = sc["account"].as_str().or_else(|| sc["account"][os].as_str());
    if let (true, Some(a), false) = (system, account, cfg!(windows)) {
        ensure_account(a, home.parent().unwrap_or(&home), &st)?;
    }
    for d in p["dirs"].as_array().cloned().unwrap_or_default() {
        let dir = plan_path(&home, d["path"].as_str().unwrap_or(""));
        let mode = u32::from_str_radix(d["mode"].as_str().unwrap_or("0700").trim_start_matches('0'), 8).unwrap_or(0o700);
        st.run(&format!("mkdir -m {mode:o} {}", dir.display()), || {
            std::fs::create_dir_all(&dir)?;
            chmod(&dir, mode)
        })?;
    }
    let status = status_file(&home);
    let status_dir = status.parent().unwrap().to_path_buf();
    st.run(&format!("mkdir -m 755 {}", status_dir.display()), || {
        std::fs::create_dir_all(&status_dir)?;
        chmod(&status_dir, 0o755)
    })?;
    let me = std::fs::canonicalize(std::env::current_exe()?)?;
    let agent = o.agent.clone().unwrap_or_else(|| me.with_file_name(format!("oarbank-agent{}", std::env::consts::EXE_SUFFIX)));
    st.run(&format!("install {} as the current version", agent.display()), || {
        crate::install(&crate::Home(home.clone()), &agent).map(|rel| println!("current -> {rel}"))
    })?;
    let jc = &p["join_code"];
    let join_to = plan_path(&home, jc["to"].as_str().unwrap_or("state/join-code"));
    if let Some(code) = &o.code {
        st.run(&format!("stage the join code in {} (0600)", join_to.display()), || {
            write_owner_only(&join_to, code.as_bytes())
        })?;
    }
    // the agent always knows where a code is staged, where to report, and to read managed policy while not joined
    let mut agent_args: Vec<String> = vec!["--join-file".into(), join_to.display().to_string(),
                                           "--status-file".into(), status.display().to_string(), "--policy".into()];
    if let Some(url) = &o.coordinator {
        agent_args.extend(["--coordinator".into(), url.clone()]);
    }
    if let Some(n) = o.name.as_ref().filter(|n| !n.trim().is_empty()) {
        agent_args.extend(["--name".into(), n.trim().to_string()]);
    }
    // Windows names no account: the service's virtual account gets the home when the service is created (svc_windows.rs)
    if let (true, Some(a)) = (system, account) {
        st.run(&format!("chown -R {a} {}", home.display()), || sh(&["chown", "-R", &format!("{a}:{a}"), &home.display().to_string()]).map(|_| ()))?;
        st.run(&format!("chown {a} {}", status_dir.display()), || sh(&["chown", "-R", &format!("{a}:{a}"), &status_dir.display().to_string()]).map(|_| ()))?;
        if cfg!(target_os = "linux") {
            // rootless containers need the account's runtime directory, which only lingering keeps without a login
            st.run(&format!("loginctl enable-linger {a}"), || { let _ = sh(&["loginctl", "enable-linger", a]); Ok(()) })?;
        }
    }
    // OARBANK_SETUP_NO_SERVICE: the same without loading a service, for `oarbank-node join` in tests and image builds
    if o.no_service || std::env::var_os("OARBANK_SETUP_NO_SERVICE").is_some() {
        println!("agent arguments: run {}", agent_args.join(" "));
        return Ok(home);
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
    crate::service(&crate::Home(home.clone()), &svc)?;
    Ok(home)
}

/// Write `data` owner-only from the first byte (the staged join code).
fn write_owner_only(p: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let _ = std::fs::remove_file(p);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p)?.write_all(data)?;
    Ok(())
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
    // Windows: the agent's WSL containers session and its storage (up to the session's disk cap) go with the node; its
    // images are a cache, never the node's identity (docs/design/windows-containers.md, "Packaging")
    if cfg!(windows) {
        let agent = crate::Home(home.clone()).current_bin();
        if agent.exists() || st.dry {
            st.run(&format!("{} --home {} containers remove", agent.display(), home.display()), || {
                let out = std::process::Command::new(&agent).arg("--home").arg(&home).args(["containers", "remove"]).output()?;
                if !out.status.success() {
                    eprintln!("containers remove: {}", String::from_utf8_lossy(&out.stderr).trim());
                }
                Ok(())
            })?;
        }
    }
    if opts.iter().any(|o| o == "--purge") {
        for rel in p["purge"].as_array().cloned().unwrap_or_default() {
            let path = plan_path(&home, rel.as_str().unwrap_or("-"));
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
