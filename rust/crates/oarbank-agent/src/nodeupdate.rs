//! Whole-package node updates, the agent's part (docs/design/fleet-updates.md, D57, "The directive and the agent's
//! part"; the "Interfaces" section is the contract).
//!
//! The agent never installs anything. On a `node_update` directive it downloads the package into
//! `<home>/updates/incoming/` (under a site transfer lease, uplink.rs), checks its size and sha256, that the manifest
//! (its exact text) names this artifact for this platform and install format, and the owner's signature when owner keys
//! are pinned: `staged`. On `go` it drains (no new claims; running attempts finish, services stay for the next agent
//! to adopt), then moves the package to `<home>/updates/package` and writes `request.json` through a rename, which
//! starts the root update runner (oarbank-launcher `update-run`): `installing`. A drain that outlasts
//! `drain_timeout_s` is `deferred`, and the node claims again.
//!
//! The runner says how it went in `result.json`. `installed`: the agent `current` points at now is the release's, so
//! an agent of another version exits 75 and the launcher starts the new one (a tarball install has nothing else that
//! restarts it; a package's own restart may come before `current` moved). The new agent confirms after its first
//! hello and heartbeat (`updates/confirmed`) and reports `confirming`, then `done` once the runner committed.
//! `rolled_back`, `failed` and `refused` are reported with the runner's reason; an agent of the release that was rolled
//! back exits 75 once so the launcher starts the previous one again.
//!
//! A directive that failed verification is not retried until the coordinator re-issues it (a null directive in
//! between). The install facts (`install: {format, scope, updater, why}`) say whether this node can be updated so.

use crate::api::Api;
use crate::config::Trust;
use crate::paths::Layout;
use futures_util::StreamExt;
use oarbank_core::fleet::{self, Manifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

/// How often the install facts are read again (they run dpkg, rpm or pkgutil).
const FACTS_EVERY: Duration = Duration::from_secs(600);
/// A download that failed (cut, coordinator unreachable, not enough disk) is tried again after this long.
const RETRY_S: f64 = 30.0;
const DISK_RETRY_S: f64 = 600.0;
/// A request no runner took within this long is withdrawn (and the node claims again).
const UNTAKEN_S: f64 = 1800.0;
/// Package formats and the agent's spool states (fleet-updates.md, "Interfaces").
pub const SWAP_EXIT: i32 = crate::selfupdate::SWAP_EXIT;

fn now() -> f64 {
    crate::doctor::now()
}

/// What survives a restart: the request handed to the runner, directives that failed verification, and the requests
/// this agent already exited for.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Persist {
    request: Option<Value>,
    failed: Vec<String>,
    swapped: Vec<String>,
    report: Value,
}

/// A verified package in `incoming/`, waiting for `go`.
#[derive(Debug, Clone)]
pub struct Staged {
    key: String,
    request: Value,
    path: PathBuf,
}

/// A staging failure: `Refuse` is final for this directive; `Retry` is tried again later (reported as `state`).
#[derive(Debug, Clone, PartialEq)]
pub enum StageError {
    Refuse(String),
    Retry { state: &'static str, error: String, after: f64 },
}

type Slot = Arc<Mutex<Option<Result<Staged, StageError>>>>;

pub struct NodeUpdate {
    home: PathBuf,
    p: Persist,
    install: Value,
    install_read: Option<Instant>,
    /// The download in progress: the directive's key and where its outcome lands.
    staging: Option<(String, Slot)>,
    staged: Option<Staged>,
    retry_at: f64,
    go: bool,
    drain_since: Option<f64>,
    drain_timeout_s: f64,
    /// Deferred: the next drain waits for the coordinator to give the slot again (`go` false, then true).
    deferred: bool,
    /// This agent is the release the runner installed and waits for: it confirms after its first hello and heartbeat.
    confirming: Option<Value>,
}

/// The directive's identity: a re-issue of the same release is a new directive only after a null one.
fn key_of(d: &Value) -> String {
    format!("{}:{}:{}", d["release"].as_str().unwrap_or(""), d["seq"].as_i64().unwrap_or(-1), d["artifact"]["sha256"].as_str().unwrap_or(""))
}

impl NodeUpdate {
    pub fn open(l: &Layout) -> NodeUpdate {
        let mut n = NodeUpdate { home: l.home.clone(), p: Persist::default(), install: Value::Null, install_read: None, staging: None,
                                 staged: None, retry_at: 0.0, go: false, drain_since: None, drain_timeout_s: 1800.0, deferred: false,
                                 confirming: None };
        n.p = std::fs::read(n.persist_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        if n.p.report.is_null() {
            n.p.report = json!({"state": "idle", "release": null, "seq": null, "error": null, "at": now()});
        }
        // the runner installed this agent's release and waits for it
        if let (Some(req), Some(r)) = (n.p.request.clone(), n.read_result()) {
            if r["id"] == req["id"] && r["state"] == "installed" && r["release"].as_str() == Some(crate::VERSION) {
                n.confirming = Some(req);
            }
        }
        n
    }

    pub fn spool(&self) -> PathBuf {
        self.home.join("updates")
    }

    fn persist_path(&self) -> PathBuf {
        self.home.join("state").join("node-update.json")
    }

    fn save(&self) {
        if let Err(e) = crate::fsutil::write_private(&self.persist_path(), &serde_json::to_vec_pretty(&self.p).unwrap_or_default()) {
            warn!(error = %e, "cannot keep the node update state");
        }
    }

    fn read_result(&self) -> Option<Value> {
        serde_json::from_slice(&std::fs::read(self.spool().join("result.json")).ok()?).ok()
    }

    fn set(&mut self, state: &str, release: &Value, seq: &Value, error: Option<String>) {
        let changed = self.p.report["state"] != state || self.p.report["release"] != *release || self.p.report["error"] != json!(error);
        self.p.report = json!({"state": state, "release": release, "seq": seq, "error": error, "at": now()});
        if changed {
            match &error {
                Some(e) => warn!(state, release = %release, error = %e, "node update"),
                None => info!(state, release = %release, "node update"),
            }
            self.save();
        }
    }

    pub fn state(&self) -> &str {
        self.p.report["state"].as_str().unwrap_or("idle")
    }

    /// Between staging and the runner's outcome: the legacy agent self-update waits.
    pub fn busy(&self) -> bool {
        self.staging.is_some() || self.staged.is_some() || self.p.request.is_some()
    }

    /// No new claims: draining for the install, or the runner has it.
    pub fn draining(&self) -> bool {
        self.drain_since.is_some() || self.p.request.is_some()
    }

    /// `node_update` and `install` for hello and heartbeat.
    pub fn report(&mut self) -> Value {
        if self.install_read.is_none_or(|t| t.elapsed() >= FACTS_EVERY) {
            self.install = install_facts(&self.home);
            self.install_read = Some(Instant::now());
        }
        json!({"node_update": self.p.report, "install": self.install})
    }

    /// The status document's `update` (menu bar and tray): the version it is going to, or the one it is back on.
    pub fn status(&self) -> Value {
        let r = &self.p.report;
        let state = self.state();
        let version = match state {
            "idle" | "unsupported" => return Value::Null,
            "rolled_back" | "failed" | "refused" => json!(crate::VERSION),
            _ => r["release"].clone(),
        };
        json!({"state": state, "version": version, "error": r["error"], "at": r["at"]})
    }

    /// Act on the heartbeat's `node_update` directive (null: nothing to do). `trust`: the owner keys this agent pinned;
    /// `self_updating`: an agent-only update is staged, which goes first.
    pub fn handle(&mut self, api: &Arc<Api>, d: &Value, trust: &Trust, self_updating: bool) {
        if self.p.request.is_some() {
            return;                                  // the runner has it
        }
        if !d.is_object() {
            if self.staging.is_some() || self.staged.is_some() || self.drain_since.is_some() {
                self.abandon();
                self.set("idle", &Value::Null, &Value::Null, None);
            }
            if !self.p.failed.is_empty() {
                self.p.failed.clear();               // a later directive for it is a re-issue
                self.save();
            }
            return;
        }
        let key = key_of(d);
        if self.p.failed.contains(&key) {
            return;
        }
        if self.install.is_null() {
            self.report();
        }
        if self.install["updater"] != true {
            let why = self.install["why"].as_str().map(str::to_string);
            self.set("unsupported", &d["release"], &d["seq"], why);
            return;
        }
        if self_updating {
            return;
        }
        if self.staged.as_ref().is_some_and(|s| s.key != key) || self.staging.as_ref().is_some_and(|s| s.0 != key) {
            self.abandon();                          // the assignment changed: another release now
        }
        self.go = d["go"].as_bool() == Some(true);
        self.drain_timeout_s = d["drain_timeout_s"].as_f64().filter(|t| *t > 0.0).unwrap_or(1800.0);
        if !self.go {
            self.deferred = false;
        }
        self.collect();
        if self.staged.is_none() && self.staging.is_none() && now() >= self.retry_at {
            let slot: Slot = Arc::new(Mutex::new(None));
            self.staging = Some((key.clone(), slot.clone()));
            self.set("staging", &d["release"], &d["seq"], None);
            let (api, d, home) = (api.clone(), d.clone(), self.home.clone());
            let (keys, format) = (owner_keys(&d, trust), self.install["format"].as_str().unwrap_or("").to_string());
            tokio::spawn(async move {
                let out = stage(&api, &home, &d, &keys, &crate::facts::platform_token(), &format).await;
                *slot.lock().unwrap() = Some(out);
            });
        }
        if let Some(s) = &self.staged {
            if self.go && !self.deferred && self.drain_since.is_none() {
                self.drain_since = Some(now());
                let r = s.request.clone();
                self.set("draining", &r["release"], &r["seq"], None);
            }
        }
    }

    /// A finished download: staged, refused for good, or to be tried again.
    fn collect(&mut self) {
        let Some((key, slot)) = &self.staging else { return };
        let Some(out) = slot.lock().unwrap().take() else { return };
        let key = key.clone();
        self.staging = None;
        let (release, seq) = key.split_once(':').map(|(r, rest)| (json!(r), json!(rest.split(':').next().and_then(|s| s.parse::<i64>().ok())))).unwrap_or_default();
        match out {
            Ok(s) => {
                self.set("staged", &s.request["release"], &s.request["seq"], None);
                self.staged = Some(s);
            }
            Err(StageError::Refuse(e)) => {
                self.p.failed.push(key);
                self.set("failed", &release, &seq, Some(e));
            }
            Err(StageError::Retry { state, error, after }) => {
                self.retry_at = now() + after;
                self.set(state, &release, &seq, Some(error));
            }
        }
    }

    fn abandon(&mut self) {
        self.staging = None;
        if let Some(s) = self.staged.take() {
            let _ = std::fs::remove_file(&s.path);
        }
        self.drain_since = None;
        self.deferred = false;
    }

    /// Every round: a drained node hands over, a drain that took too long defers, and the runner's result is read.
    /// Some(75): exit so the launcher starts `current`.
    pub fn tick(&mut self, idle: bool) -> Option<i32> {
        self.collect();
        if let (Some(since), Some(s)) = (self.drain_since, self.staged.clone()) {
            if idle {
                self.drain_since = None;
                self.staged = None;
                match self.hand_over(&s) {
                    Ok(id) => {
                        info!(id, release = %s.request["release"], "drained: the update runner takes over");
                        self.set("installing", &s.request["release"], &s.request["seq"], None);
                    }
                    Err(e) => {
                        self.retry_at = now() + RETRY_S;
                        self.set("failed", &s.request["release"], &s.request["seq"], Some(format!("handing the package to the runner: {e:#}")));
                    }
                }
            } else if now() - since > self.drain_timeout_s {
                self.drain_since = None;
                self.deferred = true;
                let r = s.request.clone();
                self.set("deferred", &r["release"], &r["seq"], Some(format!("running work outlasted the {} s drain", self.drain_timeout_s)));
            }
        }
        let req = self.p.request.clone()?;
        let result = self.read_result().filter(|r| r["id"] == req["id"]);
        // no runner took the request (its trigger is missing or broken): withdraw it rather than stay drained
        if result.is_none() && now() - req["at"].as_f64().unwrap_or(f64::MAX) > UNTAKEN_S && self.spool().join("request.json").exists() {
            let _ = std::fs::remove_file(self.spool().join("request.json"));
            self.finish();
            if let Some(k) = req["key"].as_str() {
                self.p.failed.push(k.to_string());
            }
            self.set("failed", &req["release"], &req["seq"], Some(format!("no update runner took the request within {UNTAKEN_S} s")));
            return None;
        }
        let r = result?;
        let id = req["id"].as_str().unwrap_or("").to_string();
        let release = r["release"].as_str().unwrap_or("").to_string();
        match r["state"].as_str().unwrap_or("") {
            // this agent is the release (a package's own restart started it before the runner said so): it confirms
            // after its next heartbeat
            "installed" if release == crate::VERSION && self.confirming.is_none() && self.state() != "confirming" => {
                self.confirming = Some(req);
            }
            "installed" if release != crate::VERSION && self.confirming.is_none() => {
                if !self.p.swapped.contains(&id) {
                    self.p.swapped.push(id);
                    self.save();
                    info!(release, "the runner installed the release: restarting on it");
                    return Some(SWAP_EXIT);
                }
            }
            "done" => {
                self.finish();
                self.set("done", &json!(release), &req["seq"], None);
            }
            s @ ("rolled_back" | "failed" | "refused") => {
                self.finish();
                let error = r["error"].as_str().map(str::to_string);
                self.set(s, &json!(release), &req["seq"], error);
                // this is the agent that was rolled back: the launcher starts the one `current` points at again
                let back = format!("{id}:back");
                if release == crate::VERSION && s != "refused" && !self.p.swapped.contains(&back) {
                    self.p.swapped.push(back);
                    self.save();
                    return Some(SWAP_EXIT);
                }
            }
            _ => {}
        }
        None
    }

    fn finish(&mut self) {
        self.p.request = None;
        self.confirming = None;
        for f in ["package", "confirmed"] {
            let _ = std::fs::remove_file(self.spool().join(f));
        }
        let n = self.p.swapped.len();
        if n > 16 {
            self.p.swapped.drain(..n - 16);
        }
    }

    /// The package to `updates/package`, then `request.json` through a rename (its appearance starts the runner).
    fn hand_over(&mut self, s: &Staged) -> anyhow::Result<String> {
        let spool = self.spool();
        let package = spool.join("package");
        let _ = std::fs::remove_file(&package);
        std::fs::rename(&s.path, &package)?;
        for f in ["confirmed", "result.json"] {
            let _ = std::fs::remove_file(spool.join(f));
        }
        let id = format!("nu-{}-{}", s.request["seq"].as_i64().unwrap_or(0), &crate::identity::new_nonce()[..12]);
        let mut req = s.request.clone();
        req["id"] = json!(id);
        req["requested_at"] = json!(now());
        crate::fsutil::write_private(&spool.join("request.json"), &serde_json::to_vec(&req)?)?;
        self.p.request = Some(json!({"id": id, "release": req["release"], "seq": req["seq"], "key": s.key, "at": now()}));
        self.save();
        Ok(id)
    }

    /// After the first hello and heartbeat on the release the runner installed: tell it this agent runs.
    pub fn confirm(&mut self) {
        let Some(req) = self.confirming.take() else { return };
        let doc = json!({"id": req["id"], "release": req["release"], "agent_version": crate::VERSION, "at": now()});
        match crate::fsutil::write_private(&self.spool().join("confirmed"), doc.to_string().as_bytes()) {
            Ok(()) => self.set("confirming", &req["release"], &req["seq"], None),
            Err(e) => {
                warn!(error = %e, "cannot confirm the update");
                self.confirming = Some(req);
            }
        }
    }
}

/// The keys to verify with: the pinned set, or the newer set the directive relays when the pinned one signed it.
fn owner_keys(d: &Value, trust: &Trust) -> Vec<String> {
    if d["owner_anchors"].is_object() {
        if let Ok(set) = crate::moves::check_owner_anchors(&d["owner_anchors"], trust) {
            return set.keys;
        }
    }
    trust.owner_keys.clone()
}

/// The directive checked before any download: the manifest names exactly its artifact for this platform and install
/// format, and the owner signed the manifest (when owner keys are pinned). The request the runner gets, less its id.
pub fn check(d: &Value, keys: &[String], platform: &str, format: &str) -> Result<Value, String> {
    let a = &d["artifact"];
    let (Some(release), Some(seq), Some(sha), Some(size), Some(text)) =
        (d["release"].as_str(), d["seq"].as_i64(), a["sha256"].as_str(), a["size"].as_u64(), d["manifest"].as_str()) else {
        return Err("the directive is malformed".into());
    };
    if a["format"].as_str() != Some(format) {
        return Err(format!("the directive's package is {}, this node is installed as {format}", a["format"]));
    }
    let m = Manifest::parse(text).map_err(|e| e.0)?;
    if m.version != release || m.seq != seq {
        return Err("the directive names another release than its manifest".into());
    }
    let art = m.node_artifact(platform, format).ok_or_else(|| format!("the manifest names no {format} package for {platform}"))?;
    if art.sha256 != sha || art.size != size || a["name"].as_str() != Some(art.name.as_str()) {
        return Err("the directive's package is not the one the manifest names".into());
    }
    if m.expires.is_some_and(|e| now() > e) {
        return Err(format!("release {release} expired"));
    }
    if !keys.is_empty() {
        fleet::verify_release(&d["signature"], text, &m, keys).map_err(|e| e.0)?;
    }
    Ok(json!({"release": release, "seq": seq, "format": format, "sha256": sha, "size": size, "manifest": text,
              "signature": d["signature"], "owner_anchors": d["owner_anchors"], "rollback": d["rollback"].as_bool() == Some(true)}))
}

/// Check, download and verify the directive's package into `incoming/<sha256>`.
async fn stage(api: &Api, home: &Path, d: &Value, keys: &[String], platform: &str, format: &str) -> Result<Staged, StageError> {
    let request = check(d, keys, platform, format).map_err(StageError::Refuse)?;
    let (sha, size) = (request["sha256"].as_str().unwrap_or("").to_string(), request["size"].as_u64().unwrap_or(0));
    let incoming = home.join("updates").join("incoming");
    crate::fsutil::private_dir(&incoming).map_err(|e| StageError::Refuse(format!("{}: {e}", incoming.display())))?;
    let dst = incoming.join(&sha);
    let staged = Staged { key: key_of(d), request, path: dst.clone() };
    if crate::fsutil::sha256_file(&dst).ok().as_deref() == Some(sha.as_str()) {
        return Ok(staged);                         // staged before this agent restarted
    }
    // other packages left here (an abandoned release) go
    for e in std::fs::read_dir(&incoming).into_iter().flatten().flatten() {
        let _ = std::fs::remove_file(e.path());
    }
    if crate::facts::disk_free_gb(home).is_some_and(|gb| gb * 1e9 < 2.0 * size as f64) {
        return Err(StageError::Retry { state: "failed", error: format!("disk: {:.1} GB free, the update needs {:.1} GB",
                                       crate::facts::disk_free_gb(home).unwrap_or(0.0), 2.0 * size as f64 / 1e9), after: DISK_RETRY_S });
    }
    let retry = |e: String| StageError::Retry { state: "staging", error: e, after: RETRY_S };
    let url = d["artifact"]["url"].as_str().ok_or_else(|| StageError::Refuse("the directive names no url".into()))?;
    let partial = incoming.join(format!("{sha}.partial"));
    let got = async {
        // a bulk download waits for the site's uplink and holds a transfer lease there (docs/design/sites.md)
        let mut tr = crate::uplink::global().begin("node_update", crate::uplink::Dir::Down, Some(size)).await;
        let r = api.download(url, 0).await.map_err(|e| format!("downloading the package: {e}"))?;
        let mut f = tokio::fs::File::create(&partial).await.map_err(|e| e.to_string())?;
        let (mut h, mut n, mut s) = (Sha256::new(), 0u64, r.bytes_stream());
        while let Some(c) = s.next().await {
            let c = c.map_err(|e| format!("the download was cut: {e}"))?;
            tr.pace(c.len()).await;
            n += c.len() as u64;
            if n > size {
                return Err("the download is larger than the package".to_string());
            }
            h.update(&c);
            f.write_all(&c).await.map_err(|e| e.to_string())?;
        }
        f.sync_all().await.map_err(|e| e.to_string())?;
        Ok::<(String, u64), String>((hex::encode(h.finalize()), n))
    }.await;
    match got {
        Ok((h, n)) if h == sha && n == size => {
            std::fs::rename(&partial, &dst).map_err(|e| retry(e.to_string()))?;
            Ok(staged)
        }
        Ok((_, n)) if n < size => {
            let _ = std::fs::remove_file(&partial);
            Err(retry("the download was cut short".into()))
        }
        Ok(_) => {
            let _ = std::fs::remove_file(&partial);
            Err(StageError::Refuse("the downloaded package does not match its sha256".into()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&partial);
            Err(retry(e))
        }
    }
}

/// The agent home a system install uses (`<system data>/agent`; fleet-updates.md, "Paths").
pub fn system_data() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData")).join("Oarbank")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/Oarbank")
    } else {
        PathBuf::from("/var/lib/oarbank")
    }
}

/// How this node was installed. `OARBANK_INSTALL_FORMAT` names it outright (tests, image builds); else the package
/// database owns the packaged agent (dpkg, rpm), the macOS pkg's receipt, the MSI's install folder, a launcher running
/// from a tarball's `versions/<release>/`, or `dev`.
pub fn detect_format() -> String {
    if let Ok(f) = std::env::var("OARBANK_INSTALL_FORMAT") {
        if fleet::FORMATS.contains(&f.as_str()) || f == "dev" {
            return f;
        }
    }
    let ok = |argv: &[&str]| std::process::Command::new(argv[0]).args(&argv[1..]).stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success());
    if cfg!(target_os = "macos") {
        if Path::new("/Library/Oarbank/bin/oarbank-launcher").is_file() && ok(&["pkgutil", "--pkg-info", "dev.codonic.oarbank.agent"]) {
            return "pkg".into();
        }
    } else if cfg!(windows) {
        let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
        if pf.join("Oarbank").join("oarbank-launcher.exe").is_file() {
            return "msi".into();
        }
    } else {
        let agent = "/usr/lib/oarbank/oarbank-agent";
        if Path::new(agent).is_file() {
            if ok(&["dpkg", "-S", agent]) {
                return "deb".into();
            }
            if ok(&["rpm", "-qf", agent]) {
                return "rpm".into();
            }
        }
        // the launcher that started this agent, unpacked from a tarball into <prefix>/versions/<release>/
        let launcher = std::env::var("OARBANK_LAUNCHER_PID").ok().and_then(|p| std::fs::read_link(format!("/proc/{p}/exe")).ok());
        if launcher.is_some_and(|l| l.ancestors().any(|a| a.file_name().is_some_and(|n| n == "versions"))) {
            return "tar".into();
        }
    }
    "dev".into()
}

/// Whether the root runner's trigger is installed: the launchd daemon, the systemd path unit, the elevated helper.
/// `OARBANK_UPDATE_TRIGGER=external`: something else runs `update-run` (tests).
fn trigger_installed() -> bool {
    if std::env::var("OARBANK_UPDATE_TRIGGER").as_deref() == Ok("external") {
        return true;
    }
    if cfg!(target_os = "macos") {
        Path::new("/Library/LaunchDaemons/dev.codonic.oarbank.agent.update.plist").is_file()
    } else if cfg!(windows) {
        std::process::Command::new("sc.exe").args(["query", "OarbankHelper"]).stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
    } else {
        ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"].iter()
            .any(|d| Path::new(d).join("dev.codonic.oarbank.agent.update.path").is_file())
    }
}

/// The version of the installed package's agent: the binary the launcher names in `OARBANK_PACKAGE_AGENT` (a package's
/// launcher names the agent its package installed beside it; a development or tarball launcher names none). It is read
/// again only when the file changed. The package supersedes every older agent-only build (docs/protocol.md, "Agent
/// self-update"): the coordinator never assigns one, and this agent refuses one.
pub fn package_version() -> Option<String> {
    package_version_at(Path::new(&std::env::var_os("OARBANK_PACKAGE_AGENT")?))
}

fn package_version_at(path: &Path) -> Option<String> {
    type Seen = Option<(PathBuf, u64, Option<std::time::SystemTime>, Option<String>)>;
    static SEEN: Mutex<Seen> = Mutex::new(None);
    let path = path.to_path_buf();
    let meta = std::fs::metadata(&path).ok()?;
    let (len, mtime) = (meta.len(), meta.modified().ok());
    let mut seen = SEEN.lock().unwrap();
    if let Some((p, l, m, v)) = seen.as_ref() {
        if *p == path && *l == len && *m == mtime {
            return v.clone();
        }
    }
    let v = std::fs::read(&path).ok().and_then(|d| fleet::agent_version_of(&d));
    *seen = Some((path, len, mtime, v.clone()));
    v
}

/// `install: {format, scope, updater, why, trust, package_version}`: the runner can update this node when the node is a
/// system install, its trigger is in place and its trust is pinned (`<data root>/update/available`, which `update-trust`
/// writes readable); `trust` is what the agent found there ([`Marker`]); `package_version` is the installed package's
/// agent ([`package_version`]), which may differ from the build this agent runs.
pub fn install_facts(home: &Path) -> Value {
    let format = detect_format();
    let system = home == system_data().join("agent");
    let external = std::env::var("OARBANK_UPDATE_TRIGGER").as_deref() == Ok("external");
    let marker = home.parent().map(|p| marker_at(&p.join("update").join("available"))).unwrap_or(Marker::Missing);
    let why = why_no_updater(&format, system || external, || trigger_installed(), marker);
    json!({"format": format, "scope": if system { "system" } else { "personal" }, "updater": why.is_none(), "why": why,
           "trust": marker.name(), "package_version": package_version()})
}

/// What the agent finds of the runner's trust marker.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Marker {
    Pinned,
    /// no marker (or not one this agent reads): no trust is pinned
    Missing,
    /// the state directory or the marker is closed to the agent: a trust may be pinned behind it (2.10's macOS pkg made
    /// the directory owner-only on every install)
    Unreadable,
}

impl Marker {
    fn name(self) -> &'static str {
        match self {
            Marker::Pinned => "pinned",
            Marker::Missing => "missing",
            Marker::Unreadable => "unreadable",
        }
    }
}

fn marker_at(p: &Path) -> Marker {
    match std::fs::read(p) {
        Ok(b) if serde_json::from_slice::<Value>(&b).is_ok_and(|v| v["format"] == 1) => Marker::Pinned,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Marker::Unreadable,
        _ => Marker::Missing,
    }
}

/// Why the runner cannot update this node, with what fixes it (the coordinator's update plan shows it): None when it can.
fn why_no_updater(format: &str, system: bool, trigger: impl FnOnce() -> bool, marker: Marker) -> Option<String> {
    if format == "dev" {
        Some("a development build: no package to update (agent-only self-update)".into())
    } else if !system {
        Some("a personal install: only a system install has the update runner".into())
    } else if !trigger() {
        Some("the update runner's trigger is not installed: reinstall the node package".into())
    } else if marker == Marker::Unreadable {
        Some(format!("the update runner's state directory is not readable by the agent, so it cannot see whether update trust \
                      is pinned: {}", oarbank_core::fleet::TRUST_REMEDY))
    } else if marker == Marker::Missing {
        Some(format!("no update trust is pinned: {}", oarbank_core::fleet::TRUST_REMEDY))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    fn package() -> Vec<u8> {
        b"a node package".repeat(100)
    }

    fn directive(go: bool, owner: Option<&SigningKey>) -> Value {
        let p = package();
        let sha = oarbank_core::fleet::sha256_hex(&p);
        let manifest = serde_json::to_string(&json!({"type": "oarbank-fleet-release", "format": 1, "version": "9.1.0", "seq": 91,
            "expires": null, "agent_min": "2.9.0", "stops": [], "artifacts": [
                {"name": "oarbank-agent-9.1.0-linux-amd64.tar.gz", "role": "node", "platform": "linux-amd64", "format": "tar",
                 "sha256": sha, "size": p.len(), "agent_version": "9.1.0"}]})).unwrap();
        let signature = owner.map(|k| {
            let stmt = serde_json::to_string(&json!({"manifest_sha256": oarbank_core::fleet::manifest_sha256(&manifest), "seq": 91,
                                                      "signed_at": 1, "type": "oarbank.fleet-release/v1", "version": "9.1.0"})).unwrap();
            json!({"statement": stmt, "signature": B64.encode(k.sign(stmt.as_bytes()).to_bytes())})
        });
        json!({"release": "9.1.0", "seq": 91, "go": go, "rollback": false, "drain_timeout_s": 1800,
               "artifact": {"name": "oarbank-agent-9.1.0-linux-amd64.tar.gz", "format": "tar", "sha256": sha, "size": p.len(),
                            "url": format!("/v1/updates/artifacts/{sha}")},
               "manifest": manifest, "signature": signature, "owner_anchors": null})
    }

    /// The plan's hint for a node without update trust is the command that pins it, `--from-agent` included (a bare
    /// `update-trust` only prints its usage).
    #[test]
    fn a_node_without_update_trust_says_the_command_that_pins_it() {
        let why = why_no_updater("pkg", true, || true, Marker::Missing).unwrap();
        assert!(why.starts_with("no update trust is pinned: ") && why.contains("update-trust --from-agent"), "{why}");
        if cfg!(target_os = "macos") {
            assert!(why.ends_with(": sudo /Library/Oarbank/bin/oarbank-launcher update-trust --from-agent"), "{why}");
        }
        assert_eq!(why_no_updater("pkg", true, || true, Marker::Pinned), None);
        assert!(why_no_updater("pkg", true, || false, Marker::Missing).unwrap().contains("trigger is not installed"));
        assert!(why_no_updater("deb", false, || panic!("not asked"), Marker::Missing).unwrap().starts_with("a personal install"));
        assert!(why_no_updater("dev", true, || true, Marker::Pinned).unwrap().starts_with("a development build"));
        // a marker the agent may not read is not "no trust": the same command repairs the directory
        let why = why_no_updater("pkg", true, || true, Marker::Unreadable).unwrap();
        assert!(why.starts_with("the update runner's state directory is not readable by the agent") && why.contains("update-trust --from-agent"),
                "{why}");
    }

    /// The marker: pinned, missing (or not one this agent reads), or closed to the agent (a directory it may not traverse).
    #[cfg(unix)]
    #[test]
    fn the_marker_is_pinned_missing_or_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = crate::scratch("nodeupdate-marker");
        let state = tmp.path().join("update");
        std::fs::create_dir_all(&state).unwrap();
        let marker = state.join("available");
        assert_eq!(marker_at(&marker), Marker::Missing);
        std::fs::write(&marker, b"{\"format\": 2}").unwrap();
        assert_eq!(marker_at(&marker), Marker::Missing);
        std::fs::write(&marker, b"{\"format\": 1, \"mode\": \"signed\"}").unwrap();
        assert_eq!(marker_at(&marker), Marker::Pinned);
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        // root reads through any mode: only an account the mode binds sees it closed
        let closed = std::fs::read(&marker).is_err();
        if closed {
            assert_eq!(marker_at(&marker), Marker::Unreadable);
        }
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o711)).unwrap();
        assert_eq!(marker_at(&marker), Marker::Pinned);
    }

    #[test]
    fn a_directive_is_checked_against_its_manifest_and_the_owner() {
        let owner = SigningKey::from_bytes(&[3; 32]);
        let pk = B64.encode(owner.verifying_key().to_bytes());
        let d = directive(false, Some(&owner));
        let req = check(&d, std::slice::from_ref(&pk), "linux-amd64", "tar").unwrap();
        assert_eq!((req["release"].as_str(), req["format"].as_str(), req["rollback"].as_bool()), (Some("9.1.0"), Some("tar"), Some(false)));
        check(&directive(false, None), &[], "linux-amd64", "tar").unwrap();        // no owner keys pinned: unsigned is fine
        let refused = |d: &Value, keys: &[String], platform: &str, format: &str, why: &str| {
            let e = check(d, keys, platform, format).unwrap_err();
            assert!(e.contains(why), "{e} does not say {why:?}");
        };
        refused(&directive(false, None), std::slice::from_ref(&pk), "linux-amd64", "tar", "not signed by the owner");
        refused(&directive(false, Some(&SigningKey::from_bytes(&[4; 32]))), std::slice::from_ref(&pk), "linux-amd64", "tar", "no pinned owner key");
        refused(&d, &[], "linux-amd64", "deb", "installed as deb");
        refused(&d, &[], "darwin-arm64", "tar", "no tar package for darwin-arm64");
        let mut other = d.clone();
        other["artifact"]["sha256"] = json!("b".repeat(64));
        refused(&other, &[], "linux-amd64", "tar", "not the one the manifest names");
        let mut other = d.clone();
        other["artifact"]["name"] = json!("evil.tar.gz");
        refused(&other, &[], "linux-amd64", "tar", "not the one the manifest names");
        let mut other = d.clone();
        other["seq"] = json!(92);
        refused(&other, &[], "linux-amd64", "tar", "another release than its manifest");
        refused(&json!({"release": "9.1.0"}), &[], "linux-amd64", "tar", "malformed");
    }

    fn node(tmp: &Path) -> NodeUpdate {
        let mut n = NodeUpdate::open(&Layout::new(tmp.to_path_buf()));
        n.install = json!({"format": "tar", "scope": "personal", "updater": true, "why": null});
        n.install_read = Some(Instant::now());
        n
    }

    fn stage_now(n: &mut NodeUpdate, d: &Value) {
        let req = check(d, &[], "linux-amd64", "tar").unwrap();
        let path = n.spool().join("incoming").join(req["sha256"].as_str().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, package()).unwrap();
        n.staged = Some(Staged { key: key_of(d), request: req, path });
        n.set("staged", &d["release"], &d["seq"], None);
    }

    fn api() -> Arc<Api> {
        Arc::new(Api::new("http://127.0.0.1:9", crate::rescue::client().unwrap(), 0))
    }

    #[tokio::test]
    async fn go_drains_hands_over_and_follows_the_runners_result() {
        let tmp = crate::scratch("nodeupdate-go");
        let mut n = node(tmp.path());
        let d = directive(true, None);
        stage_now(&mut n, &d);
        n.handle(&api(), &d, &Trust::default(), false);
        assert_eq!((n.state(), n.draining()), ("draining", true));
        assert_eq!(n.tick(false), None);                                      // a job still runs
        assert_eq!(n.tick(true), None);
        assert_eq!(n.state(), "installing");
        let req: Value = serde_json::from_slice(&std::fs::read(n.spool().join("request.json")).unwrap()).unwrap();
        assert_eq!(std::fs::read(n.spool().join("package")).unwrap(), package());
        assert_eq!((req["release"].as_str(), req["seq"].as_i64(), req["format"].as_str()), (Some("9.1.0"), Some(91), Some("tar")));
        assert!(req["manifest"].as_str().unwrap() == d["manifest"].as_str().unwrap() && req["id"].as_str().unwrap().starts_with("nu-91-"));
        assert!(n.busy() && n.draining());
        // the runner installed it: this agent (another version) exits once for the launcher
        let id = req["id"].clone();
        let result = |state: &str, release: &str| std::fs::write(n_spool(tmp.path()).join("result.json"),
            json!({"id": id, "release": release, "state": state, "error": if state == "rolled_back" { json!("did not confirm") } else { Value::Null }}).to_string()).unwrap();
        result("installing", "9.1.0");
        assert_eq!(n.tick(true), None);
        result("installed", "9.1.0");
        assert_eq!(n.tick(true), Some(SWAP_EXIT));
        assert_eq!(n.tick(true), None, "once");
        // the new agent: confirms after its first hello and heartbeat, then done
        let mut new = NodeUpdate::open(&Layout::new(tmp.path().to_path_buf()));
        if crate::VERSION == "9.1.0" {
            new.confirm();
            assert_eq!(new.state(), "confirming");
        }
        result("done", "9.1.0");
        assert_eq!(new.tick(true), None);
        assert_eq!((new.state(), new.busy(), new.draining()), ("done", false, false));
        assert!(!n_spool(tmp.path()).join("package").exists());
        assert_eq!(new.status()["version"], "9.1.0");
    }

    #[tokio::test]
    async fn a_request_no_runner_takes_is_withdrawn() {
        let tmp = crate::scratch("nodeupdate-untaken");
        let mut n = node(tmp.path());
        let d = directive(true, None);
        stage_now(&mut n, &d);
        n.handle(&api(), &d, &Trust::default(), false);
        assert_eq!(n.tick(true), None);
        assert!(n.draining());
        n.p.request.as_mut().unwrap()["at"] = json!(now() - UNTAKEN_S - 1.0);
        assert_eq!(n.tick(true), None);
        assert_eq!((n.state(), n.draining(), n.spool().join("request.json").exists()), ("failed", false, false));
        n.handle(&api(), &d, &Trust::default(), false);
        assert!(!n.busy(), "not retried until re-issued");
    }

    /// The release's agent started before the runner said `installed` (a package's own restart): it confirms once it is.
    #[tokio::test]
    async fn an_agent_started_early_confirms_once_the_runner_says_installed() {
        let tmp = crate::scratch("nodeupdate-early");
        let mut n = node(tmp.path());
        std::fs::create_dir_all(n.spool()).unwrap();
        n.p.request = Some(json!({"id": "nu-1", "release": crate::VERSION, "seq": 1, "at": now()}));
        std::fs::write(n.spool().join("result.json"), json!({"id": "nu-1", "release": crate::VERSION, "state": "installing"}).to_string()).unwrap();
        assert_eq!(n.tick(true), None);
        n.confirm();
        assert!(!n.spool().join("confirmed").exists());
        std::fs::write(n.spool().join("result.json"), json!({"id": "nu-1", "release": crate::VERSION, "state": "installed"}).to_string()).unwrap();
        assert_eq!(n.tick(true), None, "no restart: this is the release");
        n.confirm();
        let c: Value = serde_json::from_slice(&std::fs::read(n.spool().join("confirmed")).unwrap()).unwrap();
        assert_eq!((c["id"].as_str(), c["agent_version"].as_str(), n.state()), (Some("nu-1"), Some(crate::VERSION), "confirming"));
    }

    fn n_spool(home: &Path) -> PathBuf {
        home.join("updates")
    }

    #[tokio::test]
    async fn a_rollback_is_reported_and_a_long_drain_defers() {
        let tmp = crate::scratch("nodeupdate-back");
        let mut n = node(tmp.path());
        let d = directive(true, None);
        stage_now(&mut n, &d);
        n.handle(&api(), &d, &Trust::default(), false);
        n.drain_timeout_s = 0.0;
        n.drain_since = Some(now() - 1.0);
        assert_eq!(n.tick(false), None);
        assert_eq!((n.state(), n.draining()), ("deferred", false));
        n.handle(&api(), &d, &Trust::default(), false);
        assert_eq!(n.state(), "deferred", "go stays: no second drain until the coordinator gives the slot again");
        let mut idle = d.clone();
        idle["go"] = json!(false);
        n.handle(&api(), &idle, &Trust::default(), false);
        n.handle(&api(), &d, &Trust::default(), false);
        assert_eq!(n.state(), "draining");
        assert_eq!(n.tick(true), None);
        let id = n.p.request.as_ref().unwrap()["id"].clone();
        std::fs::write(n.spool().join("result.json"), json!({"id": id, "release": "9.1.0", "state": "rolled_back",
                                                             "error": "release 9.1.0's agent did not confirm within 600 s"}).to_string()).unwrap();
        // the old agent, running again
        let mut old = NodeUpdate::open(&Layout::new(tmp.path().to_path_buf()));
        assert_eq!(old.tick(true), None);
        assert_eq!((old.state(), old.p.report["error"].as_str().unwrap().contains("did not confirm")), ("rolled_back", true));
        assert_eq!(old.status()["version"], crate::VERSION);
        assert!(!old.busy());
    }

    #[tokio::test]
    async fn a_node_without_an_updater_or_a_refused_directive_does_nothing() {
        let tmp = crate::scratch("nodeupdate-none");
        let mut n = node(tmp.path());
        n.install = json!({"format": "dev", "scope": "personal", "updater": false, "why": "a development build"});
        let d = directive(true, None);
        n.handle(&api(), &d, &Trust::default(), false);
        assert_eq!((n.state(), n.busy()), ("unsupported", false));
        n.install["updater"] = json!(true);
        n.p.failed.push(key_of(&d));
        n.handle(&api(), &d, &Trust::default(), false);
        assert!(!n.busy(), "a failed directive is not retried");
        n.handle(&api(), &Value::Null, &Trust::default(), false);
        assert!(n.p.failed.is_empty(), "until the coordinator re-issues it");
        // an agent-only update goes first
        n.handle(&api(), &d, &Trust::default(), true);
        assert!(!n.busy());
    }

    /// The download: under the uplink, checked against the directive; a tampered package is refused for good.
    #[tokio::test]
    async fn the_package_is_downloaded_and_checked() {
        let tmp = crate::scratch("nodeupdate-stage");
        let d = directive(false, None);
        let sha = d["artifact"]["sha256"].as_str().unwrap().to_string();
        let path: &'static str = Box::leak(format!("/v1/updates/artifacts/{sha}").into_boxed_str());
        let body = String::from_utf8(package()).unwrap();
        let base = crate::rescue::tests::serve(vec![(path, 200, "", body.clone())]).await;
        let api = Api::new(&base, crate::rescue::client().unwrap(), 0);
        let s = stage(&api, tmp.path(), &d, &[], "linux-amd64", "tar").await.unwrap();
        assert_eq!(std::fs::read(&s.path).unwrap(), package());
        let tampered = crate::rescue::tests::serve(vec![(path, 200, "", body.replace('a', "b"))]).await;
        std::fs::remove_file(&s.path).unwrap();
        let api = Api::new(&tampered, crate::rescue::client().unwrap(), 0);
        assert!(matches!(stage(&api, tmp.path(), &d, &[], "linux-amd64", "tar").await, Err(StageError::Refuse(_))));
        let gone = crate::rescue::tests::serve(vec![]).await;
        let api = Api::new(&gone, crate::rescue::client().unwrap(), 0);
        assert!(matches!(stage(&api, tmp.path(), &d, &[], "linux-amd64", "tar").await, Err(StageError::Retry { .. })));
    }

    #[test]
    fn the_package_version_is_read_from_the_packages_agent_and_again_when_it_changes() {
        let tmp = crate::scratch("nodeupdate-package");
        let p = tmp.path().join("oarbank-agent");
        assert_eq!(package_version_at(&p), None);
        std::fs::write(&p, b"..oarbank-agent-version:2.10.4\0..").unwrap();
        assert_eq!(package_version_at(&p).as_deref(), Some("2.10.4"));
        std::fs::write(&p, b"....oarbank-agent-version:2.10.5\0....").unwrap();
        assert_eq!(package_version_at(&p).as_deref(), Some("2.10.5"));
    }

    #[test]
    fn install_facts_say_why_a_node_has_no_updater() {
        let tmp = crate::scratch("nodeupdate-facts");
        let f = install_facts(&tmp.path().join("agent"));
        assert_eq!(f["updater"], false);
        assert!(f["why"].is_string());
        assert_eq!(f["trust"], "missing");
        assert_eq!(f["scope"], "personal");
    }
}
