//! The runner over a fake machine: every refusal, every step's failure, crash and resume, and RunnerSafe as a property.

use super::*;
use crate::owner::tests::{key, owner_set, sign};
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::rc::Rc;

const PLATFORM: &str = "linux-amd64";

/// The machine the runner updates: what the OS has installed, what `current` points at, and an agent that confirms
/// itself after its start when its release is healthy.
struct Machine {
    now: f64,
    pointed: String,
    installed: Option<String>,
    installs: Vec<(String, String, bool)>,
    script: VecDeque<InstallOutcome>,
    point_fails: bool,
    native_fails: bool,
    healthy: BTreeSet<String>,
    confirm_after: f64,
    seen: HashMap<String, f64>,
    confirmations: Vec<String>,
    crash_at: BTreeSet<usize>,
    checkpoints: usize,
    agent_spool: PathBuf,
}

type M = Rc<RefCell<Machine>>;

struct FakeInstaller(M, &'static str);

impl Installer for FakeInstaller {
    fn format(&self) -> String {
        self.1.into()
    }
    fn check_native(&mut self, _: &str, _: &Path) -> Result<(), String> {
        if self.0.borrow().native_fails { Err("the package is not signed by the pinned team".into()) } else { Ok(()) }
    }
    fn install(&mut self, _format: &str, package: &Path, release: &str, rollback: bool) -> InstallOutcome {
        let sha = sha256_hex(&std::fs::read(package).expect("the runner installs its own kept copy"));
        let mut m = self.0.borrow_mut();
        m.installs.push((sha, release.to_string(), rollback));
        let out = m.script.pop_front().unwrap_or(InstallOutcome::Installed { reboot_pending: false });
        if matches!(out, InstallOutcome::Installed { .. }) {
            m.installed = Some(release.to_string());
        }
        out
    }
    fn point_agent(&mut self, _format: &str, release: &str) -> Result<(), String> {
        let mut m = self.0.borrow_mut();
        if m.point_fails {
            return Err("no agent in the package".into());
        }
        if m.installed.as_deref() != Some(release) {
            return Err(format!("{release} is not installed"));
        }
        m.pointed = format!("versions/{release}");
        Ok(())
    }
    fn current_agent(&self) -> Option<String> {
        Some(self.0.borrow().pointed.clone())
    }
    fn point_back(&mut self, previous: &str) -> Result<(), String> {
        self.0.borrow_mut().pointed = previous.to_string();
        Ok(())
    }
}

struct FakeClock(M);

impl Clock for FakeClock {
    fn now(&mut self) -> f64 {
        self.0.borrow().now
    }
    fn sleep(&mut self, secs: f64) {
        let mut m = self.0.borrow_mut();
        m.now += secs.max(0.1);
        // the agent `current` points at: once started on an installed release, it confirms (when healthy)
        let Some(r) = std::fs::read(m.agent_spool.join("result.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { return };
        let (Some(id), Some(release)) = (r["id"].as_str(), r["release"].as_str()) else { return };
        if r["state"] != "installed" || m.pointed != format!("versions/{release}") || !m.healthy.contains(release) {
            return;
        }
        let now = m.now;
        let first = *m.seen.entry(id.to_string()).or_insert(now);
        if now - first >= m.confirm_after && !m.confirmations.iter().any(|c| c == id) {
            let doc = json!({"id": id, "release": release, "agent_version": release, "at": now});
            std::fs::write(m.agent_spool.join("confirmed"), doc.to_string()).unwrap();
            m.confirmations.push(id.to_string());
        }
    }
    fn checkpoint(&mut self, at: &str) -> Result<(), Halt> {
        let mut m = self.0.borrow_mut();
        let n = m.checkpoints;
        m.checkpoints += 1;
        if m.crash_at.contains(&n) { Err(Halt(format!("crash at {at}"))) } else { Ok(()) }
    }
}

struct World {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    state: PathBuf,
    m: M,
    format: &'static str,
    owner: Option<(ed25519_dalek::SigningKey, String)>,
}

/// A release as CI publishes it, and the agent's request for it.
#[derive(Clone)]
struct Rel {
    version: String,
    seq: i64,
    package: Vec<u8>,
    manifest: String,
}

impl Rel {
    fn sha(&self) -> String {
        sha256_hex(&self.package)
    }
}

fn manifest_text(version: &str, seq: i64, artifacts: Value, expires: Value) -> String {
    serde_json::to_string(&json!({"type": MANIFEST_TYPE, "format": 1, "version": version, "seq": seq, "released_at": "2026-10-20T00:00:00Z",
                                  "expires": expires, "agent_min": "2.9.0", "stops": [], "artifacts": artifacts})).unwrap()
}

fn rel(version: &str, seq: i64, format: &str) -> Rel {
    let package = format!("the {version} {format} package").repeat(10).into_bytes();
    let art = json!([{"name": format!("oarbank-agent-{version}.{format}"), "role": "node", "platform": PLATFORM, "format": format,
                      "sha256": sha256_hex(&package), "size": package.len(), "agent_version": version},
                     {"name": format!("oarbank-agent-{version}-darwin-arm64.pkg"), "role": "node", "platform": "darwin-arm64",
                      "format": "pkg", "sha256": "0".repeat(64), "size": 1}]);
    Rel { version: version.into(), seq, manifest: manifest_text(version, seq, art, Value::Null), package }
}

impl World {
    fn new(format: &'static str, signed: bool) -> World {
        let tmp = tempfile::Builder::new().prefix("oarbank-fleet-").tempdir().unwrap();
        let home = tmp.path().join("agent");
        let state = tmp.path().join("update");
        std::fs::create_dir_all(home.join("updates")).unwrap();
        let m = Rc::new(RefCell::new(Machine {
            now: 1_000_000.0, pointed: "versions/1.0.0".into(), installed: Some("1.0.0".into()), installs: vec![], script: VecDeque::new(),
            point_fails: false, native_fails: false, healthy: BTreeSet::new(), confirm_after: 5.0, seen: HashMap::new(),
            confirmations: vec![], crash_at: BTreeSet::new(), checkpoints: 0, agent_spool: home.join("updates") }));
        let owner = signed.then(|| key(7));
        let w = World { _tmp: tmp, home, state, m, format, owner };
        let trust = match &w.owner {
            Some(o) => Trust::signed(Some("fleet_a".into()), 1, vec![o.1.clone()], 0.0, "test"),
            None => Trust::unsigned(0.0, "test"),
        };
        w.spool().write_trust(&trust).unwrap();
        w
    }

    fn spool(&self) -> Spool {
        Spool::new(&self.home, &self.state)
    }

    fn runner(&self) -> Runner<FakeInstaller, FakeClock> {
        let mut r = Runner::new(self.spool(), FakeInstaller(self.m.clone(), self.format), FakeClock(self.m.clone()));
        r.platform = PLATFORM.into();
        r.probation_s = 600.0;
        r
    }

    fn signature(&self, r: &Rel) -> Value {
        match &self.owner {
            Some((sk, _)) => {
                let stmt = serde_json::to_string(&json!({"manifest_sha256": manifest_sha256(&r.manifest), "seq": r.seq, "signed_at": 1,
                                                          "type": STATEMENT_TYPE, "version": r.version})).unwrap();
                json!({"statement": stmt, "signature": sign(sk, &stmt)})
            }
            None => Value::Null,
        }
    }

    fn request(&self, id: &str, r: &Rel, rollback: bool) -> Value {
        json!({"id": id, "release": r.version, "seq": r.seq, "format": self.format, "sha256": r.sha(), "size": r.package.len(),
               "manifest": r.manifest, "signature": self.signature(r), "owner_anchors": null, "rollback": rollback,
               "requested_at": 1.0})
    }

    /// The agent's part: the package, then the request.
    fn submit(&self, req: &Value, package: &[u8]) {
        std::fs::write(self.spool().package(), package).unwrap();
        std::fs::write(self.spool().request(), req.to_string()).unwrap();
    }

    /// Run until the runner is idle again, restarting it after every crash.
    fn run(&self) -> Ran {
        for _ in 0..1000 {
            match self.runner().run_once() {
                Ok(r) => return r,
                Err(_) => continue,
            }
        }
        panic!("the runner never finished");
    }

    fn result(&self) -> Value {
        self.spool().read_result().unwrap_or(Value::Null)
    }

    fn journal(&self) -> Journal {
        self.spool().read_journal().unwrap()
    }

    fn healthy(&self, v: &str) {
        self.m.borrow_mut().healthy.insert(v.into());
    }

    fn pointed(&self) -> String {
        self.m.borrow().pointed.clone()
    }
}

fn finished(state: &str, id: &str) -> Ran {
    Ran::Finished { id: id.into(), state: state.into() }
}

fn refused_with(w: &World, req: Value, package: &[u8], why: &str) {
    w.submit(&req, package);
    let id = req["id"].as_str().unwrap_or("").to_string();
    assert_eq!(w.run(), finished("refused", &id), "{why}");
    let r = w.result();
    assert_eq!(r["state"], "refused");
    assert!(r["error"].as_str().unwrap().contains(why), "{} does not say {why:?}", r["error"]);
    assert!(!w.spool().request().exists() && !w.spool().incoming().exists());
    assert!(w.m.borrow().installs.is_empty(), "a refused request installs nothing");
    assert_eq!(w.pointed(), "versions/1.0.0");
}

#[test]
fn versions_order_as_the_coordinator_orders_them() {
    assert!(newer("2.10.4", "2.10.3") && newer("2.10.10", "2.10.9") && newer("3.0.0", "2.99.99"));
    assert!(newer("2.10.4", "2.10.4-rc.1") && !newer("2.10.4-rc.1", "2.10.4"));
    assert!(!newer("2.10.4", "2.10.4") && !newer("2.10.4+build.7", "2.10.4"));
    assert!(!newer("x", "1.0.0") && !newer("1.0.0", "") && !newer("1.0", "0.9.0") && !newer("1.2.3-", "0.1.0"));
    assert_eq!(agent_version_of(b"..oarbank-agent-version:\0..oarbank-agent-version:2.10.4\0.."), Some("2.10.4".into()));
    assert_eq!(agent_version_of(b"no marker"), None);
}

#[test]
fn a_package_agent_is_found_only_beside_a_packages_launcher() {
    let dir = std::env::temp_dir();
    assert_eq!(package_agent_beside(&dir.join("oarbank-launcher")), None);
    assert_eq!(package_agent_beside(Path::new("oarbank-launcher")), None);
    assert!(package_agent("tar").is_none() && package_agent("pkg").is_some());
}

#[test]
fn an_update_installs_confirms_and_commits() {
    let w = World::new("deb", true);
    let r2 = rel("2.0.0", 20, "deb");
    w.healthy("2.0.0");
    w.submit(&w.request("u1", &r2, false), &r2.package);
    assert_eq!(w.run(), finished("done", "u1"));
    let j = w.journal();
    assert_eq!((j.committed_seq, j.committed_release.as_deref(), j.active.is_none()), (20, Some("2.0.0"), true));
    assert_eq!(j.current.as_ref().map(|p| p.sha256.clone()), Some(r2.sha()));
    assert_eq!(j.previous, None);
    assert_eq!(w.pointed(), "versions/2.0.0");
    assert_eq!(w.result()["state"], "done");
    assert!(w.spool().kept(&r2.sha()).is_file() && !w.spool().request().exists() && !w.spool().confirmed().exists());
    // a second release keeps two packages; the first is the previous one now
    let r3 = rel("3.0.0", 30, "deb");
    w.healthy("3.0.0");
    w.submit(&w.request("u2", &r3, false), &r3.package);
    assert_eq!(w.run(), finished("done", "u2"));
    let r4 = rel("4.0.0", 40, "deb");
    w.healthy("4.0.0");
    w.submit(&w.request("u3", &r4, false), &r4.package);
    assert_eq!(w.run(), finished("done", "u3"));
    let j = w.journal();
    assert_eq!((j.current.unwrap().release, j.previous.unwrap().release), ("4.0.0".to_string(), "3.0.0".to_string()));
    let kept: BTreeSet<String> = std::fs::read_dir(w.spool().packages()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
    assert_eq!(kept, [r3.sha(), r4.sha()].into_iter().collect());
}

#[test]
fn every_refusal_installs_nothing() {
    let r2 = rel("2.0.0", 20, "deb");
    let w = World::new("deb", true);
    let mut req = w.request("x1", &r2, false);
    req["format"] = json!("rpm");
    refused_with(&w, req, &r2.package, "this node's package is deb");

    let w = World::new("deb", true);
    let mut req = w.request("x2", &r2, false);
    req["manifest"] = json!("{\"type\": \"something else\"}");
    refused_with(&w, req, &r2.package, "not a fleet release manifest");

    let w = World::new("deb", true);
    let mut req = w.request("x3", &r2, false);
    req["release"] = json!("2.0.1");
    refused_with(&w, req, &r2.package, "another release than its manifest");

    let w = World::new("deb", true);
    let mut req = w.request("x4", &r2, false);
    req["seq"] = json!(21);
    refused_with(&w, req, &r2.package, "another release than its manifest");

    let w = World::new("msi", true);
    let mut req = w.request("x5", &r2, false);
    req["format"] = json!("msi");
    refused_with(&w, req, &r2.package, "names no msi package for linux-amd64");

    let w = World::new("deb", true);
    let mut req = w.request("x6", &r2, false);
    req["sha256"] = json!("a".repeat(64));
    refused_with(&w, req, &r2.package, "not the one the manifest names");

    let w = World::new("deb", true);
    let mut req = w.request("x7", &r2, false);
    req["size"] = json!(3);
    refused_with(&w, req, &r2.package, "not the one the manifest names");

    // tampered bytes in the spool: the copy is checked, never the agent's file
    let w = World::new("deb", true);
    let mut bad = r2.package.clone();
    bad[0] ^= 1;
    refused_with(&w, w.request("x8", &r2, false), &bad, "does not match the manifest's sha256");
    let w = World::new("deb", true);
    let mut long = r2.package.clone();
    long.push(0);
    refused_with(&w, w.request("x9", &r2, false), &long, "does not match the manifest's sha256");

    // the owner's signature: missing, by another key, over another manifest
    let w = World::new("deb", true);
    let mut req = w.request("s1", &r2, false);
    req["signature"] = Value::Null;
    refused_with(&w, req, &r2.package, "not signed by the owner");
    let w = World::new("deb", true);
    let mut req = w.request("s2", &r2, false);
    let stmt = req["signature"]["statement"].as_str().unwrap().to_string();
    req["signature"]["signature"] = json!(sign(&key(9).0, &stmt));
    refused_with(&w, req, &r2.package, "verifies with no pinned owner key");
    let w = World::new("deb", true);
    let r2b = rel("2.0.0", 20, "deb");
    let mut req = w.request("s3", &r2b, false);
    let other = manifest_text("2.0.0", 20, json!([{"name": "x.deb", "role": "node", "platform": PLATFORM, "format": "deb",
                                                     "sha256": r2.sha(), "size": r2.package.len()}]), json!(null));
    req["manifest"] = json!(other);                 // a manifest naming the same package, which the owner never signed
    refused_with(&w, req, &r2.package, "names another manifest");

    // no trust pinned at all
    let w = World::new("deb", true);
    std::fs::remove_file(w.spool().trust()).unwrap();
    refused_with(&w, w.request("t1", &r2, false), &r2.package, "no update trust is pinned");

    // an expired release
    let w = World::new("deb", false);
    let mut old = rel("2.0.0", 20, "deb");
    let art = serde_json::from_str::<Value>(&old.manifest).unwrap()["artifacts"].clone();
    old.manifest = manifest_text("2.0.0", 20, art, json!("2026-01-01T00:00:00Z"));
    w.m.borrow_mut().now = rfc3339("2026-01-02T00:00:00Z").unwrap();
    refused_with(&w, w.request("e1", &old, false), &old.package, "expired");

    // a native signature that is not the pinned one
    let w = World::new("deb", false);
    w.m.borrow_mut().native_fails = true;
    refused_with(&w, w.request("n1", &r2, false), &r2.package, "not signed by the pinned team");

    // not a request at all, or one that is not a file
    let w = World::new("deb", false);
    std::fs::write(w.spool().request(), b"{not json").unwrap();
    assert_eq!(w.run(), finished("refused", ""));
    assert_eq!(w.result()["state"], "refused");
    assert!(!w.spool().request().exists());
    // one it cannot even delete is moved aside: a request left in place would start the runner again and again
    std::fs::create_dir(w.spool().request()).unwrap();
    assert_eq!(w.run(), finished("refused", ""));
    assert!(!w.spool().request().exists());
    assert!(std::fs::read_dir(&w.spool().agent).unwrap().flatten().any(|e| e.file_name().to_string_lossy().starts_with("request.rejected-")));
    assert_eq!(w.run(), Ran::Idle);
    #[cfg(unix)]
    {
        let w = World::new("deb", false);
        std::os::unix::fs::symlink(w.home.join("elsewhere"), w.spool().package()).unwrap();
        std::fs::write(w.home.join("elsewhere"), &r2.package).unwrap();
        std::fs::write(w.spool().request(), w.request("l1", &r2, false).to_string()).unwrap();
        assert_eq!(w.run(), finished("refused", "l1"));
        assert!(w.result()["error"].as_str().unwrap().contains("not a regular file"));
    }
}

#[test]
fn an_older_seq_is_refused_unless_it_rolls_back_to_the_kept_package() {
    let w = World::new("rpm", true);
    let (r2, r3) = (rel("2.0.0", 20, "rpm"), rel("3.0.0", 30, "rpm"));
    w.healthy("2.0.0");
    w.healthy("3.0.0");
    for (id, r) in [("a", &r2), ("b", &r3)] {
        w.submit(&w.request(id, r, false), &r.package);
        assert_eq!(w.run(), finished("done", id));
    }
    // a replay of 2.0.0 as an ordinary update: below the committed seq
    w.submit(&w.request("c", &r2, false), &r2.package);
    assert_eq!(w.run(), finished("refused", "c"));
    assert!(w.result()["error"].as_str().unwrap().contains("below the committed 30"));
    // an older release the runner did not keep, even as a rollback
    let r1 = rel("1.5.0", 15, "rpm");
    w.submit(&w.request("d", &r1, true), &r1.package);
    assert_eq!(w.run(), finished("refused", "d"));
    // the kept previous package, as a rollback: installed, and the committed seq goes down with it
    w.submit(&w.request("e", &r2, true), &r2.package);
    assert_eq!(w.run(), finished("done", "e"));
    assert_eq!((w.journal().committed_seq, w.pointed()), (20, "versions/2.0.0".to_string()));
    assert_eq!(w.m.borrow().installs.last().map(|i| i.1.clone()), Some("2.0.0".into()));
}

#[test]
fn a_finished_request_is_never_run_again() {
    let w = World::new("deb", false);
    let r2 = rel("2.0.0", 20, "deb");
    w.healthy("2.0.0");
    w.submit(&w.request("same", &r2, false), &r2.package);
    assert_eq!(w.run(), finished("done", "same"));
    let installs = w.m.borrow().installs.len();
    w.submit(&w.request("same", &r2, false), &r2.package);
    assert_eq!(w.run(), Ran::Ignored("same".into()));
    assert_eq!((w.m.borrow().installs.len(), w.spool().request().exists()), (installs, false));
    assert_eq!(w.result()["state"], "done");
    // a refused id too
    let mut bad = w.request("bad", &r2, false);
    bad["format"] = json!("rpm");
    w.submit(&bad, &r2.package);
    assert_eq!(w.run(), finished("refused", "bad"));
    w.submit(&w.request("bad", &r2, false), &r2.package);
    assert_eq!(w.run(), Ran::Ignored("bad".into()));
    assert_eq!(w.run(), Ran::Idle);
}

#[test]
fn a_busy_installer_is_retried_later_then_fails_with_nothing_changed() {
    let w = World::new("msi", false);
    let mut r2 = rel("2.0.0", 20, "msi");
    let art = json!([{"name": "a.msi", "role": "node", "platform": PLATFORM, "format": "msi", "sha256": r2.sha(), "size": r2.package.len()}]);
    r2.manifest = manifest_text("2.0.0", 20, art, Value::Null);
    w.healthy("2.0.0");
    w.m.borrow_mut().script = [msi_outcome(1618), msi_outcome(3010)].into_iter().collect();
    let t0 = w.m.borrow().now;
    w.submit(&w.request("b1", &r2, false), &r2.package);
    assert_eq!(w.run(), finished("done", "b1"));
    assert!(w.m.borrow().now - t0 >= BUSY_RETRY_S[0]);
    assert_eq!(w.result()["reboot_pending"], true);

    let w = World::new("msi", false);
    w.m.borrow_mut().script = std::iter::repeat_n(msi_outcome(1618), 4).collect();
    w.submit(&w.request("b2", &r2, false), &r2.package);
    assert_eq!(w.run(), finished("failed", "b2"));
    assert_eq!(w.m.borrow().installs.len(), 4);
    assert!(w.result()["error"].as_str().unwrap().starts_with("busy:"));
    assert_eq!((w.pointed(), w.journal().committed_seq), ("versions/1.0.0".to_string(), 0));
}

#[test]
fn a_failed_install_puts_back_the_kept_package_unless_the_os_did() {
    let w = World::new("deb", false);
    let (r2, r3) = (rel("2.0.0", 20, "deb"), rel("3.0.0", 30, "deb"));
    w.healthy("2.0.0");
    w.submit(&w.request("a", &r2, false), &r2.package);
    assert_eq!(w.run(), finished("done", "a"));
    w.m.borrow_mut().script = [InstallOutcome::Failed { error: "dpkg: error processing".into(), restored: false }].into_iter().collect();
    w.submit(&w.request("b", &r3, false), &r3.package);
    assert_eq!(w.run(), finished("failed", "b"));
    let last = w.m.borrow().installs.last().cloned().unwrap();
    assert_eq!((last.1.as_str(), last.2), ("2.0.0", true), "the kept package went back on");
    assert_eq!((w.pointed(), w.result()["partial"].clone()), ("versions/2.0.0".to_string(), json!(false)));
    assert!(!w.spool().kept(&r3.sha()).exists());
    assert_eq!(w.journal().committed_seq, 20);

    // MSI 1603: Windows restored the product, nothing is reinstalled
    let w = World::new("msi", false);
    let mut r2 = rel("2.0.0", 20, "msi");
    let art = json!([{"name": "a.msi", "role": "node", "platform": PLATFORM, "format": "msi", "sha256": r2.sha(), "size": r2.package.len()}]);
    r2.manifest = manifest_text("2.0.0", 20, art, Value::Null);
    w.m.borrow_mut().script = [msi_outcome(1603)].into_iter().collect();
    w.submit(&w.request("m", &r2, false), &r2.package);
    assert_eq!(w.run(), finished("failed", "m"));
    assert_eq!(w.m.borrow().installs.len(), 1);
    assert!(w.result()["error"].as_str().unwrap().contains("1603"));
}

#[test]
fn a_package_without_its_agent_rolls_back() {
    let w = World::new("tar", false);
    let r2 = rel("2.0.0", 20, "tar");
    w.m.borrow_mut().point_fails = true;
    w.submit(&w.request("p", &r2, false), &r2.package);
    assert_eq!(w.run(), finished("failed", "p"));
    let r = w.result();
    assert!(r["error"].as_str().unwrap().contains("could not be made current"));
    assert_eq!((r["partial"].clone(), w.pointed()), (json!(true), "versions/1.0.0".to_string()));
}

#[test]
fn an_agent_that_never_confirms_is_rolled_back() {
    // with a kept package: it is reinstalled and the agent pointed back
    let w = World::new("deb", false);
    let (r2, r3) = (rel("2.0.0", 20, "deb"), rel("3.0.0", 30, "deb"));
    w.healthy("2.0.0");
    w.submit(&w.request("a", &r2, false), &r2.package);
    assert_eq!(w.run(), finished("done", "a"));
    let t0 = w.m.borrow().now;
    w.submit(&w.request("b", &r3, false), &r3.package);
    assert_eq!(w.run(), finished("rolled_back", "b"));
    assert!(w.m.borrow().now - t0 >= 600.0);
    let r = w.result();
    assert!(r["error"].as_str().unwrap().contains("did not confirm within 600 s"));
    assert_eq!((r["partial"].clone(), w.pointed()), (json!(false), "versions/2.0.0".to_string()));
    assert_eq!(w.m.borrow().installed.as_deref(), Some("2.0.0"));
    assert_eq!((w.journal().committed_seq, w.journal().current.unwrap().release), (20, "2.0.0".to_string()));

    // the first fleet update of a node installed by hand: only the agent goes back
    let w = World::new("deb", false);
    w.submit(&w.request("c", &r3, false), &r3.package);
    assert_eq!(w.run(), finished("rolled_back", "c"));
    assert_eq!((w.result()["partial"].clone(), w.pointed()), (json!(true), "versions/1.0.0".to_string()));

    // a forged confirmation (another id, or another version's agent) gains nothing
    let w = World::new("deb", false);
    std::fs::write(w.spool().confirmed(), json!({"id": "other", "release": "3.0.0", "agent_version": "3.0.0"}).to_string()).unwrap();
    w.submit(&w.request("d", &r3, false), &r3.package);
    assert_eq!(w.run(), finished("rolled_back", "d"));
}

#[test]
fn a_crash_at_any_step_resumes_to_the_same_end() {
    for good in [true, false] {
        let mut n = 0;
        loop {
            let w = World::new("deb", true);
            let (r2, r3) = (rel("2.0.0", 20, "deb"), rel("3.0.0", 30, "deb"));
            w.healthy("2.0.0");
            w.submit(&w.request("a", &r2, false), &r2.package);
            assert_eq!(w.run(), finished("done", "a"));
            if good {
                w.healthy("3.0.0");
            }
            let base = w.m.borrow().checkpoints;
            w.m.borrow_mut().crash_at = [base + n].into_iter().collect();
            w.submit(&w.request("b", &r3, false), &r3.package);
            let end = w.run();
            let crashed = w.m.borrow().checkpoints > base + n;
            assert_eq!(end, finished(if good { "done" } else { "rolled_back" }, "b"), "crash at checkpoint {n}");
            assert_eq!(w.pointed(), if good { "versions/3.0.0" } else { "versions/2.0.0" });
            assert_eq!(w.result()["state"], if good { "done" } else { "rolled_back" });
            if !crashed {
                break;
            }
            n += 1;
        }
        assert!(n >= 8, "every step was crashed at ({n})");
    }
}

#[test]
fn a_newer_owner_key_set_in_the_request_rotates_the_runners_keys() {
    let w = World::new("deb", true);
    let o1 = w.owner.clone().unwrap();
    let o2 = key(8);
    let r2 = rel("2.0.0", 20, "deb");
    w.healthy("2.0.0");
    let stmt = serde_json::to_string(&json!({"manifest_sha256": manifest_sha256(&r2.manifest), "seq": 20, "signed_at": 1,
                                              "type": STATEMENT_TYPE, "version": "2.0.0"})).unwrap();
    let mut req = w.request("r", &r2, false);
    req["signature"] = json!({"statement": stmt, "signature": sign(&o2.0, &stmt)});
    req["owner_anchors"] = owner_set(2, &[&o2], &[&o1, &o2]);
    w.submit(&req, &r2.package);
    assert_eq!(w.run(), finished("done", "r"));
    let t = w.spool().read_trust().unwrap();
    assert_eq!((t.owner_version, t.owner_keys), (2, vec![o2.1.clone()]));
    // a set the pinned keys never signed changes nothing
    let o3 = key(10);
    let r3 = rel("3.0.0", 30, "deb");
    let mut req = w.request("s", &r3, false);
    let stmt = req["signature"]["statement"].as_str().unwrap().to_string();
    req["signature"]["signature"] = json!(sign(&o3.0, &stmt));
    req["owner_anchors"] = owner_set(3, &[&o3], &[&o3]);
    w.submit(&req, &r3.package);
    assert_eq!(w.run(), finished("refused", "s"));
    assert_eq!(w.spool().read_trust().unwrap().owner_keys, vec![o2.1]);
}

#[test]
fn manifests_and_requests_are_parsed_as_untrusted_data() {
    let r = rel("2.10.0", 21000, "deb");
    let m = Manifest::parse(&r.manifest).unwrap();
    assert_eq!((m.version.as_str(), m.seq, m.agent_min.as_deref(), m.expires), ("2.10.0", 21000, Some("2.9.0"), None));
    assert_eq!(m.node_artifact(PLATFORM, "deb").unwrap().sha256, r.sha());
    assert!(m.node_artifact(PLATFORM, "rpm").is_none());
    let bad = |a: Value| Manifest::parse(&manifest_text("2.0.0", 1, a, Value::Null)).is_err();
    assert!(bad(json!([{"name": "../x", "role": "node", "platform": "p", "format": "deb", "sha256": "0".repeat(64), "size": 1}])));
    assert!(bad(json!([{"name": "x", "role": "node", "platform": "p", "format": "deb", "sha256": "0".repeat(63), "size": 1}])));
    assert!(bad(json!([{"name": "x", "role": "node", "platform": "p", "format": "deb", "sha256": "0".repeat(64), "size": -1}])));
    assert!(bad(json!({})));
    assert!(Manifest::parse(&manifest_text("v2", 1, json!([]), Value::Null)).is_err());
    assert!(Manifest::parse(&manifest_text("2.0.0", 1, json!([]), json!("tomorrow"))).is_err());
    assert_eq!(Manifest::parse(&manifest_text("2.0.0", 1, json!([]), json!(5))).unwrap().expires, Some(5.0));
    assert_eq!(rfc3339("1970-01-01T00:00:00Z"), Some(0.0));
    assert_eq!(rfc3339("2026-10-20T00:00:00Z"), Some(1_792_454_400.0));
    assert_eq!(rfc3339("2026-10-20T02:00:00.5+02:00"), Some(1_792_454_400.5));
    assert_eq!(rfc3339("2026-13-20T00:00:00Z"), None);
    assert_eq!(manifest_sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    let ok = json!({"id": "u_1", "release": "2.0.0", "seq": 1, "format": "deb", "sha256": "a".repeat(64), "size": 1, "manifest": "{}",
                    "signature": null, "rollback": false});
    assert!(Request::parse(ok.to_string().as_bytes()).is_ok());
    for (k, v) in [("id", json!("../../etc")), ("id", json!("")), ("release", json!("2.0.0; rm")), ("format", json!("exe")),
                   ("sha256", json!("A".repeat(64))), ("size", json!(-1)), ("seq", json!("1")), ("manifest", json!(1)),
                   ("signature", json!("sig"))] {
        let mut r = ok.clone();
        r[k] = v;
        assert!(Request::parse(r.to_string().as_bytes()).is_err(), "{k}");
    }
    assert_eq!(Request::id_of(b"{\"id\": \"u_2\", \"seq\": \"x\"}"), Some("u_2".into()));
}

#[test]
fn msi_exit_codes() {
    assert_eq!(msi_outcome(0), InstallOutcome::Installed { reboot_pending: false });
    assert_eq!(msi_outcome(3010), InstallOutcome::Installed { reboot_pending: true });
    assert_eq!(msi_outcome(1641), InstallOutcome::Installed { reboot_pending: true });
    assert!(matches!(msi_outcome(1618), InstallOutcome::Busy(_)));
    assert!(matches!(msi_outcome(1603), InstallOutcome::Failed { restored: true, .. }));
}

mod runner_safe {
    use super::*;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Ask {
        /// The next release, healthy or not.
        Update { healthy: bool },
        /// The same request id again.
        Replay,
        /// A request tampered with: 0 bytes, 1 sha, 2 signature, 3 format.
        Tampered(u8),
        /// Back to the package the runner kept.
        Rollback,
    }

    fn ask() -> impl Strategy<Value = Ask> {
        prop_oneof![
            4 => any::<bool>().prop_map(|healthy| Ask::Update { healthy }),
            1 => Just(Ask::Replay),
            2 => (0u8..4).prop_map(Ask::Tampered),
            1 => Just(Ask::Rollback),
        ]
    }

    fn outcome() -> impl Strategy<Value = InstallOutcome> {
        prop_oneof![
            6 => any::<bool>().prop_map(|reboot_pending| InstallOutcome::Installed { reboot_pending }),
            2 => Just(InstallOutcome::Busy("locked".into())),
            1 => any::<bool>().prop_map(|restored| InstallOutcome::Failed { error: "broken".into(), restored }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

        /// RunnerSafe: whenever the runner is idle again, the node runs the new release confirmed (committed) or the
        /// one it ran before, never a package that did not verify; committed_seq never goes down but by an explicit
        /// rollback, and a finished request id is never run again.
        #[test]
        fn runner_safe(asks in proptest::collection::vec(ask(), 1..7),
                       outcomes in proptest::collection::vec(outcome(), 0..12),
                       crashes in proptest::collection::btree_set(0usize..120, 0..6),
                       confirm_after in 0.0f64..900.0,
                       signed in any::<bool>(), point_fails in any::<bool>()) {
            let w = World::new("deb", signed);
            {
                let mut m = w.m.borrow_mut();
                m.script = outcomes.into_iter().collect();
                m.crash_at = crashes;
                m.confirm_after = confirm_after;
            }
            let mut next = 2;
            let mut last: Option<(String, Rel)> = None;
            let mut verified: BTreeSet<String> = BTreeSet::new();
            for (i, a) in asks.into_iter().enumerate() {
                let id = format!("req{i}");
                let before = (w.pointed(), w.journal());
                let installs_before = w.m.borrow().installs.len();
                let result_before = w.result();
                // a point failure now and then (a package whose agent is missing)
                w.m.borrow_mut().point_fails = point_fails && i % 3 == 2;
                let (req, package, valid, rollback) = match &a {
                    Ask::Update { healthy } => {
                        let r = rel(&format!("{next}.0.0"), next * 10, "deb");
                        next += 1;
                        if *healthy {
                            w.healthy(&r.version);
                        }
                        let req = w.request(&id, &r, false);
                        last = Some((id.clone(), r.clone()));
                        (req, r.package.clone(), Some(r), false)
                    }
                    Ask::Replay => match &last {
                        Some((lid, r)) => (w.request(lid, r, false), r.package.clone(), None, false),
                        None => continue,
                    },
                    Ask::Tampered(how) => {
                        let r = rel(&format!("{next}.0.0"), next * 10, "deb");
                        next += 1;
                        w.healthy(&r.version);
                        let mut req = w.request(&id, &r, false);
                        let mut package = r.package.clone();
                        match how {
                            0 => package[3] ^= 0x20,
                            1 => req["sha256"] = json!(sha256_hex(b"other")),
                            2 => req["signature"] = json!({"statement": "{}", "signature": sign(&key(11).0, "{}")}),
                            _ => req["format"] = json!("rpm"),
                        }
                        // unsigned trust takes any signature: that tampering is no tampering there
                        let still_valid = *how == 2 && !signed;
                        (req, package, still_valid.then_some(r), false)
                    }
                    Ask::Rollback => {
                        let Some(prev) = before.1.previous.clone() else { continue };
                        let v: i64 = prev.release.split('.').next().unwrap().parse().unwrap();
                        let r = rel(&prev.release, v * 10, "deb");
                        (w.request(&id, &r, true), r.package.clone(), Some(r), true)
                    }
                };
                if let Some(r) = &valid {
                    verified.insert(r.sha());
                }
                w.submit(&req, &package);
                let ran = w.run();
                let after = (w.pointed(), w.journal());
                // idle again: nothing in progress, the request taken
                prop_assert!(after.1.active.is_none());
                prop_assert!(!w.spool().request().exists());
                // only verified packages were ever installed
                for (sha, _, _) in &w.m.borrow().installs {
                    prop_assert!(verified.contains(sha), "installed an unverified package");
                }
                match &ran {
                    Ran::Ignored(_) => {
                        prop_assert!(matches!(a, Ask::Replay));
                        prop_assert_eq!(w.m.borrow().installs.len(), installs_before, "a finished id ran again");
                        prop_assert_eq!(&w.result(), &result_before);
                        prop_assert_eq!(&after.0, &before.0);
                    }
                    Ran::Finished { state, .. } if state == "done" => {
                        let r = valid.clone().expect("only a verified request commits");
                        prop_assert_eq!(&after.0, &format!("versions/{}", r.version));
                        prop_assert!(w.m.borrow().confirmations.contains(&req["id"].as_str().unwrap().to_string()), "committed unconfirmed");
                        prop_assert_eq!(after.1.committed_release.clone(), Some(r.version.clone()));
                        if rollback {
                            prop_assert_eq!(after.1.committed_seq, r.seq);
                        } else {
                            prop_assert!(after.1.committed_seq >= before.1.committed_seq);
                        }
                    }
                    Ran::Finished { state, .. } => {
                        prop_assert!(["refused", "rolled_back", "failed"].contains(&state.as_str()), "{}", state);
                        prop_assert_eq!(&after.0, &before.0, "not committed, yet the agent moved");
                        prop_assert_eq!(after.1.committed_seq, before.1.committed_seq);
                        prop_assert_eq!(&after.1.current, &before.1.current);
                        if state == "refused" {
                            prop_assert_eq!(w.m.borrow().installs.len(), installs_before);
                        }
                    }
                    Ran::Idle => prop_assert!(false, "a request was left untaken"),
                }
                prop_assert_eq!(w.run(), Ran::Idle);
            }
        }
    }
}
