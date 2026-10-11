//! `install_coordinator`: this node becomes the standby coordinator of a move (coordinator-move.md, "B pairs with A
//! instead of using SSH"; docs/protocol.md, "Coordinator identity and moves").
//!
//! The directive names a coordinator bundle. In signing mode it is a coordinator build for this platform, signed by
//! the owner key set (its statement names the build's sha256, version and platform); with signing off it may be the
//! old coordinator's checkout (`dev-checkout`), never when a release key is pinned. The agent downloads the bundle
//! (sha256 and size checked), unpacks it under `oarbank-coordinator/<sha12>` (absolute or `..` member paths are
//! refused), and installs the standby as the system service every coordinator is (docs/design/coordinator-system-service.md,
//! decision 11): the build's own installer, `install-oarbankd.sh --build <bundle> ... --pair <code> --from <url>
//! --from-ca <pin>`, run as root, writes the launchd daemons or systemd system units run by the coordinator's account.
//! Only root may create system services, and a node's agent never runs as root (`_oarbank`, `oarbank`, a person's
//! account; on Windows an unprivileged virtual account): an agent that is not root refuses the install with the one
//! command the owner runs on this machine instead, naming the bundle it already verified (on Windows,
//! deploy\oarbankd\install-oarbankd.ps1 with the pairing code; docs/design/windows-coordinator.md). It reports
//! `coordinator_install {plan_id, state: installing|installed|failed, error}`; the final state is sent once.

use crate::api::Api;
use crate::config::Trust;
use crate::signing::Signing;
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};

const MAX_BUNDLE: u64 = 1024 * 1024 * 1024;

#[derive(Default)]
pub struct CoordInstall {
    state: Arc<Mutex<Value>>,
    /// Plans this agent already tried (each is installed at most once).
    tried: Vec<String>,
}

fn now() -> f64 {
    crate::doctor::now()
}

/// Where coordinator bundles are unpacked: `OARBANK_COORDINATOR_INSTALL_DIR`, else `~/oarbank-coordinator`.
fn install_root() -> PathBuf {
    std::env::var_os("OARBANK_COORDINATOR_INSTALL_DIR").map(PathBuf::from).unwrap_or_else(|| {
        std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/")).join("oarbank-coordinator")
    })
}

impl CoordInstall {
    /// For the heartbeat: the install in progress, or its final state once.
    pub fn report(&self) -> Value {
        let mut st = self.state.lock().unwrap();
        if st.is_null() {
            return json!({});
        }
        let out = json!({"coordinator_install": st.clone()});
        if st["state"] != "installing" {
            *st = Value::Null;
        }
        out
    }

    pub fn handle(&mut self, api: &Arc<Api>, d: &Value, signing: &Signing, trust: &Trust) {
        let Some(plan) = d["plan_id"].as_str() else { return };
        if self.tried.iter().any(|p| p == plan) {
            return;
        }
        self.tried.push(plan.to_string());
        *self.state.lock().unwrap() = json!({"plan_id": plan, "state": "installing", "at": now()});
        warn!(plan_id = %plan, from = d["from_url"].as_str().unwrap_or(""), "installing a standby coordinator for a move");
        let (api, d, signing, trust, state) = (api.clone(), d.clone(), signing.clone(), trust.clone(), self.state.clone());
        tokio::spawn(async move {
            let plan = d["plan_id"].as_str().unwrap_or("").to_string();
            let r = install(&api, &d, &signing, &trust).await;
            let error = r.as_ref().err().map(|e| format!("{e:#}"));
            match &error {
                None => info!(plan_id = %plan, "standby coordinator installed; it pairs with the old coordinator now"),
                Some(e) => error!(plan_id = %plan, error = %e, "standby coordinator install failed"),
            }
            *state.lock().unwrap() = json!({"plan_id": plan, "state": if error.is_none() { "installed" } else { "failed" },
                                            "error": error, "at": now()});
        });
    }
}

/// The signed statement for a coordinator build, checked against the pinned release key and the owner key set.
pub fn check_build(d: &Value, signing: &Signing, trust: &Trust, platform: &str) -> Result<()> {
    let stmt = d["statement"].as_str().context("unsigned coordinator build refused")?;
    let sig = d["signature"].as_str().context("unsigned coordinator build refused")?;
    let keys: Vec<&String> = signing.pinned_key.iter().chain(trust.owner_keys.iter()).collect();
    if keys.is_empty() {
        bail!("no owner key is pinned to verify the coordinator build with");
    }
    if !keys.iter().any(|k| crate::identity::verify_ed25519(k, stmt.as_bytes(), sig).is_ok()) {
        bail!("the coordinator build signature does not verify with an owner key");
    }
    let s: Value = serde_json::from_str(stmt)?;
    if s["coordinator_sha256"] != d["bundle_sha256"] || s["version"] != d["version"] {
        bail!("the coordinator build statement names another build");
    }
    if s["platform"].as_str() != Some(platform) {
        bail!("the coordinator build is for {}, not {platform}", s["platform"]);
    }
    Ok(())
}

async fn install(api: &Api, d: &Value, signing: &Signing, trust: &Trust) -> Result<()> {
    if cfg!(windows) && std::env::var("OARBANK_SERVICE_HOST").as_deref() != Ok("process") {
        bail!("this node's agent runs under an unprivileged service account, which cannot install services: prepare the \
               move with this machine's URL and install the standby here with deploy\\oarbankd\\install-oarbankd.ps1 -Pair");
    }
    let s = |k: &str| d[k].as_str().filter(|v| !v.is_empty()).with_context(|| format!("install_coordinator without {k}"));
    let (code, from, bind, sha, url) = (s("pair_code")?, s("from_url")?, s("bind")?, s("bundle_sha256")?, s("bundle_url")?);
    if sha.len() != 64 || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("bad bundle sha256");
    }
    if !url.starts_with("/v1/move/bundle/") {
        bail!("the bundle must come from the coordinator's move endpoint");
    }
    let port = d["agent_port"].as_u64().unwrap_or(7443);
    let kind = d["kind"].as_str().unwrap_or("dev-checkout");
    match kind {
        "build" => check_build(d, signing, trust, &crate::facts::platform_token())?,
        "dev-checkout" if signing.pinned_key.is_some() || !trust.owner_keys.is_empty() => {
            bail!("an unsigned checkout bundle is refused: this node is in signing mode")
        }
        "dev-checkout" => {}
        k => bail!("unknown coordinator bundle kind {k:?}"),
    }
    let dir = install_root().join(&sha[..12]);
    crate::fsutil::private_dir(&dir)?;
    let tgz = dir.join("bundle.tar.gz");
    let r = api.download(url, 0).await?;
    let mut f = tokio::fs::File::create(&tgz).await?;
    let (mut h, mut n) = (Sha256::new(), 0u64);
    let mut body = r.bytes_stream();
    while let Some(c) = body.next().await {
        let c = c?;
        n += c.len() as u64;
        if n > MAX_BUNDLE {
            bail!("the coordinator bundle is over {} MB", MAX_BUNDLE >> 20);
        }
        h.update(&c);
        f.write_all(&c).await?;
    }
    f.sync_all().await?;
    if hex::encode(h.finalize()) != sha {
        bail!("coordinator bundle sha256 mismatch");
    }
    if d["bundle_size"].as_u64().is_some_and(|sz| sz != n) {
        bail!("the coordinator bundle has the wrong size");
    }
    let root = dir.join("unpacked");
    let (d2, root2, tgz2) = (d.clone(), root.clone(), tgz.clone());
    let kind = kind.to_string();
    let (from, code, bind) = (from.to_string(), code.to_string(), bind.to_string());
    tokio::task::spawn_blocking(move || -> Result<()> {
        unpack(&tgz2, &root2)?;
        let coordinator_home = std::env::var_os("OARBANK_COORDINATOR_HOME").map(PathBuf::from);
        let existing = coordinator_home.clone().unwrap_or_else(default_coordinator_home);
        let standby = Standby {
            url: format!("https://{bind}:{port}"), bind, port, code, from,
            from_ca: d2["from_ca"].as_str().filter(|c| !c.is_empty()).map(str::to_string),
            archive_home: existing.join("oarbank.sqlite3").exists(),
        };
        if std::env::var("OARBANK_SERVICE_HOST").as_deref() == Ok("process") {
            let (program, _console) = programs(&kind, &root2)?;
            let mut args = program;
            args.extend(standby.oarbankd_args());
            return start_process(&root2, args, coordinator_home);
        }
        install_system(&kind, &root2, &tgz2, &standby)
    }).await.context("install task")??;
    Ok(())
}

/// What makes the coordinator a move's standby (coordinator-move.md): its agent address, the pairing with the old one.
struct Standby {
    bind: String,
    port: u64,
    url: String,
    code: String,
    from: String,
    from_ca: Option<String>,
    archive_home: bool,
}

impl Standby {
    /// oarbankd's standby arguments.
    fn oarbankd_args(&self) -> Vec<String> {
        let mut a = vec!["--agent-bind".into(), self.bind.clone(), "--agent-port".into(), self.port.to_string(), "--standby".into(),
                         "--pair".into(), self.code.clone(), "--from".into(), self.from.clone(), "--url".into(), self.url.clone()];
        if let Some(ca) = &self.from_ca {
            a.extend(["--from-ca".into(), ca.clone()]);
        }
        if self.archive_home {
            a.push("--archive-home".into());
        }
        a
    }

    /// The build installer's arguments for this standby (deploy/oarbankd/install-oarbankd.sh); `code` stands for the
    /// pairing code (the real one, or a placeholder in the owner's instructions).
    fn installer_args(&self, bundle: &Path, code: &str) -> Vec<String> {
        let mut a = vec!["--build".into(), bundle.display().to_string(), "--agent-bind".into(), self.bind.clone(),
                         "--agent-port".into(), self.port.to_string(), "--url".into(), self.url.clone(), "--pair".into(),
                         code.into(), "--from".into(), self.from.clone()];
        if let Some(ca) = &self.from_ca {
            a.extend(["--from-ca".into(), ca.clone()]);
        }
        if self.archive_home {
            a.push("--archive-home".into());
        }
        a
    }
}

/// The coordinator's home on this machine: the system service's (paths.coordinator_home in the coordinator).
fn default_coordinator_home() -> PathBuf {
    if cfg!(windows) {
        return std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("Oarbank").join("coordinator");
    }
    PathBuf::from(if cfg!(target_os = "macos") { "/Library/Application Support/Oarbank/coordinator" } else { "/var/lib/oarbank/coordinator" })
}

/// The standby as the system service: the build's own installer, as root. An agent that is not root (every node's
/// agent) refuses with the command the owner runs on this machine, naming the bundle it verified.
fn install_system(kind: &str, root: &Path, bundle: &Path, standby: &Standby) -> Result<()> {
    let installer = root.join("install-oarbankd.sh");
    if kind != "build" || !installer.is_file() {
        bail!("a checkout bundle runs only under OARBANK_SERVICE_HOST=process; install a signed coordinator build");
    }
    #[cfg(unix)]
    let is_root = crate::sys::uid() == 0;
    #[cfg(not(unix))]
    let is_root = false;
    if !is_root {
        let args = standby.installer_args(bundle, "<the pairing code>");
        bail!("creating the standby's system services needs root, and this node's agent is unprivileged: on this machine, \
               run `sudo bash {} {}` with the pairing code `oarbank coordinator prepare` printed",
              shell_quote(&installer.display().to_string()), args.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" "));
    }
    let o = std::process::Command::new("/bin/bash").arg(&installer).args(standby.installer_args(bundle, &standby.code))
        .current_dir(root).stdin(std::process::Stdio::null()).output()?;
    if !o.status.success() {
        let e = String::from_utf8_lossy(&o.stderr);
        bail!("install-oarbankd.sh failed: {}", &e[e.len().saturating_sub(400)..]);
    }
    Ok(())
}

fn shell_quote(a: &str) -> String {
    if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c)) {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', "'\\''"))
    }
}

/// The system's tar: bsdtar on macOS and Windows (System32\tar.exe since Windows 10 1803), GNU tar on Linux.
fn tar() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        return root.join("System32").join("tar.exe");
    }
    PathBuf::from("/usr/bin/tar")
}

/// Unpack with the system tar after listing the members: nothing absolute, nothing above the root.
fn unpack(tgz: &Path, root: &Path) -> Result<()> {
    let list = std::process::Command::new(tar()).arg("-t").arg("-z").arg("-f").arg(tgz).output()?;
    if !list.status.success() {
        bail!("not a gzipped tar: {}", String::from_utf8_lossy(&list.stderr).trim());
    }
    for m in String::from_utf8_lossy(&list.stdout).lines() {
        let p = Path::new(m);
        if p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir)) {
            bail!("the coordinator bundle has an unsafe member {m:?}");
        }
    }
    if root.exists() {
        let aside = root.with_file_name(format!("unpacked-{}", now() as u64));
        std::fs::rename(root, aside)?;
    }
    std::fs::create_dir_all(root)?;
    let x = std::process::Command::new(tar()).arg("-x").arg("-z").arg("-f").arg(tgz).arg("-C").arg(root)
        .arg("--no-same-owner").output()?;
    if !x.status.success() {
        bail!("unpack failed: {}", String::from_utf8_lossy(&x.stderr).trim());
    }
    Ok(())
}

/// The coordinator's and the console's argv: a build's manifest `exec`/`console` (paths inside the archive), or a
/// checkout's virtualenv after `uv sync --frozen`.
fn programs(kind: &str, root: &Path) -> Result<(Vec<String>, Option<Vec<String>>)> {
    if kind == "build" {
        let m: Value = serde_json::from_slice(&std::fs::read(root.join("oarbank-coordinator.json"))
            .context("the build has no oarbank-coordinator.json")?)?;
        let argv = |k: &str| -> Result<Option<Vec<String>>> {
            let Some(a) = m[k].as_array() else { return Ok(None) };
            let mut v: Vec<String> = a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
            let first = v.first().context("empty argv")?;
            let p = root.join(first);
            if Path::new(first).is_absolute() || Path::new(first).components().any(|c| matches!(c, Component::ParentDir))
                || !std::fs::canonicalize(&p)?.starts_with(std::fs::canonicalize(root)?) {
                bail!("{k}[0] must be a path inside the build");
            }
            v[0] = p.display().to_string();
            Ok(Some(v))
        };
        let exec = argv("exec")?.unwrap_or_else(|| vec![root.join("bin/oarbankd").display().to_string()]);
        return Ok((exec, argv("console")?));
    }
    let checkout = root.join("oarbank");
    let uv = which("uv").context("uv not found (the checkout bundle needs it)")?;
    let venv = checkout.join(".venv");
    let mut sync = std::process::Command::new(uv);
    sync.args(["sync", "--frozen", "-q"]).current_dir(&checkout).env("UV_PROJECT_ENVIRONMENT", &venv);
    if cfg!(windows) {
        // copies, not hard links into uv's cache: a linked file keeps the cache's protected DACL, so the module
        // sandbox's grant on site-packages never reaches it, and a module process could not read the editable
        // SDK's .pth (it would not even find oarbank_sdk)
        sync.env("UV_LINK_MODE", "copy");
    }
    let s = sync.output()?;
    if !s.status.success() {
        let e = String::from_utf8_lossy(&s.stderr);
        bail!("uv sync failed: {}", &e[e.len().saturating_sub(400)..]);
    }
    let (bin, exe) = if cfg!(windows) { ("Scripts", ".exe") } else { ("bin", "") };
    Ok((vec![venv.join(bin).join(format!("oarbankd{exe}")).display().to_string()],
        Some(vec![venv.join(bin).join(format!("python{exe}")).display().to_string(), "-m".into(), "oarbank.console".into()])))
}

fn which(name: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("OARBANK_UV").filter(|_| name == "uv").map(PathBuf::from).filter(|p| p.exists()) {
        return Some(p);
    }
    let name = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let path = std::env::var_os("PATH").unwrap_or_default();
    let found = std::env::split_paths(&path).chain(["/opt/homebrew/bin", "/usr/local/bin"].map(PathBuf::from))
        .map(|d| d.join(&name)).find(|p| p.exists());
    found
}

/// The standby as a supervised child of the agent (`OARBANK_SERVICE_HOST=process`, the tests): restarted after a failed
/// exit, its pid in `<install>/standby.pid`.
fn start_process(root: &Path, args: Vec<String>, home: Option<PathBuf>) -> Result<()> {
    let mut env = if cfg!(windows) {
        // what a Windows program needs to start, from the agent's own environment
        ["SystemRoot", "windir", "SystemDrive", "ComSpec", "PATHEXT", "PATH", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA",
         "APPDATA", "ProgramData", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"].iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v))).collect()
    } else {
        vec![("PATH".to_string(), "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".to_string())]
    };
    if let Some(h) = &home {
        env.push(("OARBANKD_HOME".into(), h.display().to_string()));
    }
    let logs = home.clone().unwrap_or_else(default_coordinator_home).join("logs");
    std::fs::create_dir_all(&logs)?;
    for (k, v) in std::env::vars() {
        let knob = k.starts_with("OARBANKD_") || ["OARBANK_RELEASE_SIGNING", "OARBANK_SECRET_STORE", "OARBANK_SANDBOX_EXEC"]
            .contains(&k.as_str());
        if knob && !env.iter().any(|(e, _)| *e == k) {
            env.push((k, v));                                     // test knobs: the move time lock, the module launcher
        }
    }
    supervise(root, args, env, &logs.join("oarbankd.log"))
}

fn supervise(root: &Path, args: Vec<String>, env: Vec<(String, String)>, log: &Path) -> Result<()> {
    let pidfile = root.parent().unwrap_or(root).join("standby.pid");
    let (root, log) = (root.to_path_buf(), log.to_path_buf());
    let spawn = move || -> std::io::Result<std::process::Child> {
        let out = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
        let mut cmd = std::process::Command::new(&args[0]);
        cmd.args(&args[1..]).env_clear().envs(env.clone()).current_dir(&root).stdin(std::process::Stdio::null())
            .stdout(out.try_clone()?).stderr(out);
        let child = cmd.spawn()?;
        std::fs::write(&pidfile, child.id().to_string())?;
        Ok(child)
    };
    let mut child = spawn()?;
    std::thread::spawn(move || loop {
        match child.wait() {
            Ok(st) if st.success() => return,
            Ok(st) => warn!(status = %st, "the standby coordinator exited; restarting it"),
            Err(e) => return warn!(error = %e, "waiting for the standby coordinator"),
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        match spawn() {
            Ok(c) => child = c,
            Err(e) => return warn!(error = %e, "restarting the standby coordinator"),
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> tempfile::TempDir {
        crate::scratch("coordinstall")
    }

    fn tgz(dir: &Path, members: &[(&str, &str)]) -> PathBuf {
        let src = dir.join("src");
        for (name, body) in members {
            let p = src.join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        let out = dir.join("b.tar.gz");
        assert!(std::process::Command::new(tar()).arg("-c").arg("-z").arg("-f").arg(&out).arg("-C").arg(&src)
            .args(members.iter().map(|m| m.0)).status().unwrap().success());
        out
    }

    #[test]
    fn a_build_runs_its_manifest_exec_inside_the_archive() {
        let t = scratch();
        let b = tgz(t.path(), &[("oarbank-coordinator.json", r#"{"format":1,"version":"1.0.0","platform":"darwin-arm64","exec":["bin/run","x"]}"#),
                                ("bin/run", "#!/bin/sh\n")]);
        let root = t.path().join("u");
        unpack(&b, &root).unwrap();
        let (exec, console) = programs("build", &root).unwrap();
        assert_eq!(exec, vec![root.join("bin/run").display().to_string(), "x".into()]);
        assert!(console.is_none());
        std::fs::write(root.join("oarbank-coordinator.json"), r#"{"exec":["../../etc/x"]}"#).unwrap();
        assert!(programs("build", &root).is_err());
    }

    #[test]
    fn an_unprivileged_agent_refuses_with_the_owner_s_command_and_never_shows_the_code() {
        let t = scratch();
        let root = t.path().join("unpacked");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("install-oarbankd.sh"), "#!/bin/bash\nexit 0\n").unwrap();
        let s = Standby { bind: "100.64.0.9".into(), port: 7443, url: "https://100.64.0.9:7443".into(), code: "SECRET-CODE".into(),
                          from: "https://100.64.0.1:7443".into(), from_ca: Some("abc".into()), archive_home: true };
        assert_eq!(s.installer_args(Path::new("/b/bundle.tar.gz"), "X"),
                   ["--build", "/b/bundle.tar.gz", "--agent-bind", "100.64.0.9", "--agent-port", "7443", "--url",
                    "https://100.64.0.9:7443", "--pair", "X", "--from", "https://100.64.0.1:7443", "--from-ca", "abc", "--archive-home"]);
        assert!(s.oarbankd_args().windows(2).any(|w| w == ["--pair", "SECRET-CODE"]));
        if cfg!(unix) && crate::sys::uid() == 0 {
            return;                                   // as root it would run the installer
        }
        let e = format!("{:#}", install_system("build", &root, Path::new("/b/bundle.tar.gz"), &s).unwrap_err());
        assert!(e.contains("needs root") && e.contains("sudo bash") && e.contains("install-oarbankd.sh") && e.contains("--build /b/bundle.tar.gz"), "{e}");
        assert!(e.contains("'<the pairing code>'") && !e.contains("SECRET-CODE"), "{e}");
        assert!(install_system("dev-checkout", &root, Path::new("/b"), &s).is_err());
    }

    #[test]
    fn statements_must_verify_and_name_this_build() {
        use ed25519_dalek::Signer;
        use base64::Engine;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let sha = "ab".repeat(32);
        let stmt = json!({"coordinator_sha256": sha, "version": "1.2.3", "platform": "darwin-arm64", "seq": 1}).to_string();
        let d = json!({"bundle_sha256": sha, "version": "1.2.3", "statement": stmt, "signature": b64(&key.sign(stmt.as_bytes()).to_bytes())});
        let trust = Trust { owner_keys: vec![b64(key.verifying_key().as_bytes())], ..Default::default() };
        let none = Signing::default();
        check_build(&d, &none, &trust, "darwin-arm64").unwrap();
        assert!(check_build(&d, &none, &trust, "linux-amd64").is_err());
        assert!(check_build(&d, &none, &Trust::default(), "darwin-arm64").is_err());
        let mut other = d.clone();
        other["bundle_sha256"] = json!("cd".repeat(32));
        assert!(check_build(&other, &none, &trust, "darwin-arm64").is_err());
    }
}
