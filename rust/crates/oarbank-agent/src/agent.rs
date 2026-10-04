//! The agent's session with its coordinator: prove the coordinator's identity, enroll with a CSR, then hello and
//! heartbeat, acting on directives (docs/protocol.md, "Session").

use crate::api::{Api, ApiError};
use crate::config::Config;
use crate::paths::Layout;
use crate::release::Release;
use crate::runtime::Runtime;
use crate::signing::Signing;
use crate::jobs::{JobState, Stop, Table};
use crate::{doctor, facts, identity, jobs, keys, outbox, release, staging, tls};
use std::sync::Arc;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{info, warn};

pub const VERSION: &str = crate::VERSION;

pub struct Agent {
    pub layout: Layout,
    pub cfg: Config,
    pub api: Option<Arc<Api>>,
    pub boot_id: String,
    pub seq: u64,
    pub node_id: Option<String>,
    pub directives: Value,
    pub hooks: Box<dyn Hooks + Send>,
    pub runtime: Option<Runtime>,
    pub release: Option<Release>,
    /// The latest doctor report, sent with the next heartbeat.
    pub doctor: Option<Value>,
    pub signing: Signing,
    pub last_release_error: Option<String>,
    /// Send hello instead of the next heartbeat (a new release is installed: the coordinator records it at hello).
    pub need_hello: bool,
    pub table: Table,
    /// Modules whose doctor passed in the current release (offered in claims).
    pub healthy: Vec<String>,
    pub draining: bool,
    pub prot: Option<crate::prot::Protection>,
    /// Serve session helpers (`run --session-hub`: a system install's service).
    pub session_hub: bool,
    facts: Value,
    pub update: crate::selfupdate::SelfUpdate,
    /// What happened to the pending coordinator move, for the heartbeat (`coordinator_move_state`).
    pub move_state: Value,
    /// When to read the owner's rescue locations (rescue.rs).
    pub rescue: crate::rescue::RescueWatch,
    /// The coordinator's clock as of its last answer: moves' time locks and expiries are in its time (clock.rs).
    pub coord_clock: crate::clock::CoordClock,
    #[cfg(unix)]
    pub containers: Option<Arc<dyn crate::container_runtime::ContainerRuntime>>,
    /// Verifies container set images for every attempt (verified digests are remembered for the agent's lifetime).
    #[cfg(unix)]
    images: Option<Arc<crate::imageset::Verifier>>,
    /// Module services and probes (service protocol 1), created with the first release.
    pub services: Option<Arc<std::sync::Mutex<crate::services::ServiceManager>>>,
    /// What the services were last configured with: release id, policy, limits.
    services_seen: (String, Value, Value),
    /// Capabilities services and probes provide; a change re-runs the doctors (modules' `requires`).
    services_caps: Vec<String>,
    rerun_doctors: bool,
    pub coord_install: crate::coordinstall::CoordInstall,
    /// Services were stopped because the node is not active and has no work (a drain); resumed when it is again.
    services_halted: bool,
}

/// What the session asks of the rest of the agent each round (releases, jobs, protection), so the session logic can
/// be tested without them.
pub trait Hooks {
    fn hello_extra(&mut self) -> Value { json!({}) }
    fn heartbeat_extra(&mut self) -> Value { json!({}) }
    fn on_directives(&mut self, _d: &Value) {}
}

pub struct NoHooks;
impl Hooks for NoHooks {}

impl Agent {
    pub fn open(layout: Layout, coordinator: Option<&str>) -> Result<Agent> {
        layout.ensure()?;
        let cfg = match (Config::load(&layout.config())?, coordinator) {
            (Some(mut c), Some(url)) if c.coordinator != url.trim_end_matches('/') => {
                c.coordinator = url.trim_end_matches('/').to_string();
                c
            }
            (Some(c), _) => c,
            (None, Some(url)) => Config::new(url),
            (None, None) => bail!("no agent.json yet: pass --coordinator https://<host>:7443"),
        };
        cfg.save(&layout.config())?;
        let release = release::current(&layout);
        let signing = Signing { pinned_key: cfg.release_pubkey.clone(), release_seq: cfg.release_seq, agent_seq: cfg.agent_seq };
        Ok(Agent { node_id: cfg.node_id.clone(), cfg, api: None, boot_id: identity::new_nonce(), seq: 0,
                   directives: Value::Null, hooks: Box::new(NoHooks), runtime: None, release, doctor: None, signing,
                   last_release_error: None, need_hello: false, table: Table::default(), healthy: vec![],
                   draining: false, prot: None, session_hub: false, facts: Value::Null, update: crate::selfupdate::SelfUpdate::open(&layout), move_state: Value::Null,
                   rescue: Default::default(), coord_clock: Default::default(),
                   #[cfg(unix)]
                   containers: None,
                   #[cfg(unix)]
                   images: None,
                   services: None, services_seen: Default::default(), services_caps: vec![],
            rerun_doctors: true,                 // a release installed before a restart: its doctors run again before any claim
            services_halted: false, coord_install: Default::default(), layout })
    }

    /// Open with a join code: the first of its addresses whose coordinator proves its identity with the pinned CA.
    pub async fn open_with_join(layout: Layout, code: &str) -> Result<Agent> {
        let j = crate::join::decode(code)?;
        let mut last = None;
        for url in &j.urls {
            let mut a = Agent::open(Layout::new(layout.home.clone()), Some(url))?;
            a.cfg.coordinator_trust.ca_spki_sha256 = Some(j.ca_spki.clone());
            match a.prove_identity().await {
                Ok(_) => {
                    a.cfg.join_secret = Some(j.secret.clone());
                    a.cfg.save(&a.layout.config())?;
                    return Ok(a);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no coordinator address answered")))
    }

    /// Fetch and check the identity proof; on first use pin the key, fleet and CA. Returns the CA PEM it vouches for.
    pub async fn prove_identity(&mut self) -> Result<String> {
        let nonce = identity::new_nonce();
        let boot = tls::bootstrap_client()?;
        let url = format!("{}/v1/identity?nonce={nonce}", self.cfg.coordinator);
        let ans: Value = boot.get(&url).send().await.context("identity: coordinator unreachable")?
            .error_for_status()?.json().await?;
        let proof = identity::check(&ans, &nonce, &self.cfg.coordinator_trust)?;
        if proof.role == "handed_off" {
            self.catch_up_move(&boot).await;
        }
        if proof.role != "active" {
            bail!("identity: the coordinator is {}, not active", proof.role);
        }
        let pin = proof.ca_spki_sha256.clone().context("identity: the coordinator names no TLS CA pin")?;
        if let Some(pre) = &self.cfg.coordinator_trust.ca_spki_sha256 {
            // pinned beforehand (a join code, or an earlier session): the coordinator must name exactly that CA
            if pre != &pin && proof.ca_next_spki_sha256.as_deref() != Some(pre.as_str())
                && self.cfg.coordinator_trust.ca_next_spki_sha256.as_deref() != Some(pin.as_str()) {
                bail!("identity: the coordinator's CA is not the pinned one");
            }
        }
        let ca_pem = ans["ca_pem"].as_str().context("identity: no CA certificate offered")?.to_string();
        let ca_der = tls::certs_from_pem(&ca_pem)?.remove(0);
        let got = tls::spki_sha256(&ca_der)?;
        if got != pin && proof.ca_next_spki_sha256.as_deref() != Some(got.as_str()) {
            bail!("identity: the offered CA does not match the signed pin");
        }
        identity::apply(&mut self.cfg.coordinator_trust, &proof);
        self.cfg.save(&self.layout.config())?;
        Ok(ca_pem)
    }

    /// The coordinator this node trusts proved it handed off, and no move is pending here: the node missed the statement
    /// (it was away through the time lock, or the cutover froze the coordinator before a heartbeat carried it). Read
    /// the committed chain there and record the next move, which the session loop then follows; the statement is
    /// verified like one from a directive, so the unpinned client is enough.
    async fn catch_up_move(&mut self, client: &reqwest::Client) {
        if self.cfg.coordinator_trust.pending_move.is_some() {
            return;
        }
        let url = format!("{}/v1/coordinator/moves?since_epoch={}", self.cfg.coordinator, self.cfg.coordinator_trust.max_epoch);
        match async { client.get(&url).send().await?.error_for_status()?.json::<Value>().await }.await {
            Ok(c) => match c["moves"].get(0) {
                Some(next) => self.observe_moves(&json!({"coordinator_move": next})),
                None => warn!("the coordinator handed off but lists no move after this node's epoch"),
            },
            Err(e) => warn!(error = %e, "the coordinator handed off; its move chain is unreadable"),
        }
    }

    fn mtls(&self) -> Result<Arc<Api>> {
        let ca = std::fs::read_to_string(self.layout.ca_cert())?;
        let cert = std::fs::read_to_string(self.layout.node_cert())?;
        let key = std::fs::read_to_string(self.layout.node_key())?;
        let client = tls::pinned_client(&ca, &identity::pins(&self.cfg.coordinator_trust), Some((&cert, &key)))?;
        Ok(Arc::new(Api::new(&self.cfg.coordinator, client, self.cfg.coordinator_trust.max_epoch)))
    }

    /// Enroll: a CSR for the node's own key; wait for the owner's approval; store the certificate.
    pub async fn enroll(&mut self, poll: Duration, max_wait: Option<Duration>) -> Result<()> {
        let ca_pem = self.prove_identity().await?;
        let key = keys::ensure_key(&self.layout)?;
        let pins = identity::pins(&self.cfg.coordinator_trust);
        let anon = Api::new(&self.cfg.coordinator, tls::pinned_client(&ca_pem, &pins, None)?, self.cfg.coordinator_trust.max_epoch);
        let eid = match &self.cfg.enrollment_id {
            Some(e) => e.clone(),
            None => {
                let body = json!({"hostname": facts::hostname(), "facts": facts::collect(&self.layout.home),
                                  "csr": keys::csr_pem(&key, &facts::hostname())?, "join": self.cfg.join_secret.take()});
                let r = anon.post("/v1/agent/enroll", &body).await?;
                let e = r["enrollment_id"].as_str().context("enroll: no enrollment id")?.to_string();
                self.cfg.enrollment_id = Some(e.clone());
                self.cfg.save(&self.layout.config())?;
                info!(enrollment = %e, "enrollment requested: approve it on the coordinator (oarbank node approve {e})");
                e
            }
        };
        let started = std::time::Instant::now();
        loop {
            let st = anon.get(&format!("/v1/agent/enroll/{eid}")).await?;
            match st["status"].as_str() {
                Some("approved") => {
                    let cert = st["cert_pem"].as_str().context("enroll: approved without a certificate")?;
                    let ca = st["ca_pem"].as_str().unwrap_or(&ca_pem);
                    keys::store_cert(&self.layout, cert, ca, None)?;
                    self.cfg.node_id = st["node_id"].as_str().map(str::to_string);
                    self.node_id = self.cfg.node_id.clone();
                    self.cfg.enrollment_id = None;
                    self.cfg.save(&self.layout.config())?;
                    info!(node = ?self.node_id, "enrolled");
                    return Ok(());
                }
                Some("rejected") => {
                    self.cfg.enrollment_id = None;
                    self.cfg.save(&self.layout.config())?;
                    bail!("the owner rejected this node's enrollment");
                }
                Some("claimed") => {
                    self.cfg.enrollment_id = None;
                    self.cfg.save(&self.layout.config())?;
                    bail!("this enrollment's certificate was already collected; enroll again");
                }
                _ => {}
            }
            if max_wait.is_some_and(|m| started.elapsed() > m) {
                bail!("enrollment {eid} is still pending");
            }
            tokio::time::sleep(poll).await;
        }
    }

    pub async fn connect(&mut self) -> Result<()> {
        self.prove_identity().await?;
        self.api = Some(self.mtls()?);
        Ok(())
    }

    fn api(&self) -> Result<&Api> {
        self.api.as_deref().context("not connected")
    }

    pub async fn hello(&mut self) -> Result<Value, ApiError> {
        let mut body = json!({"agent_version": VERSION, "boot_id": self.boot_id, "facts": facts::collect(&self.layout.home),
                              "ready_datasets": staging::ready(&self.layout),
                              "live_attempts": self.table.lock().unwrap().keys().cloned().collect::<Vec<_>>(),
                              "release_id": self.release.as_ref().map(|r| r.id.clone()), "clock": doctor::now()});
        merge(&mut body, self.hooks.hello_extra());
        merge(&mut body, self.update.report());
        merge(&mut body, self.trust_report());
        let d = self.api().map_err(io_err)?.post("/v1/agent/hello", &body).await?;
        self.rescue.contact(doctor::now());
        self.after_directives(&d).await;
        Ok(d)
    }

    pub async fn heartbeat(&mut self) -> Result<Value, ApiError> {
        self.seq += 1;
        let (capacity, telemetry, journal, processes) = match self.prot.as_mut() {
            Some(p) => (p.capacity.as_ref().map(|c| c.to_json()), p.telemetry.clone(), p.journal_out(), p.processes(&self.table)),
            None => (None, json!({}), json!([]), None),
        };
        let mut body = json!({"seq": self.seq, "attempts": jobs::attempts(&self.table), "doctor": self.doctor.take(),
                              "capacity": capacity, "telemetry": telemetry, "journal": journal, "processes": processes,
                              "ready_datasets": staging::ready(&self.layout),
                              "release_id": self.release.as_ref().map(|r| r.id.clone()), "clock": doctor::now()});
        merge(&mut body, self.hooks.heartbeat_extra());
        merge(&mut body, self.coord_install.report());
        merge(&mut body, self.update.report());
        merge(&mut body, self.trust_report());
        let d = self.api().map_err(io_err)?.post("/v1/agent/heartbeat", &body).await?;
        self.rescue.contact(doctor::now());
        self.after_directives(&d).await;
        Ok(d)
    }

    async fn after_directives(&mut self, d: &Value) {
        if let Some(n) = d["node_id"].as_str() {
            self.node_id = Some(n.to_string());
        }
        if let Some(s) = d["heartbeat_s"].as_f64() {
            self.cfg.heartbeat_s = s.clamp(1.0, 300.0);
        }
        if let Some(p) = &self.prot {
            p.ack(d);
        }
        self.observe_moves(d);
        if let Err(e) = self.signing.observe_key(d["release_pubkey"].as_str()) {
            warn!(error = %e, "release key");
        }
        if self.signing.pinned_key.is_some() && self.cfg.release_pubkey != self.signing.pinned_key {
            self.cfg.release_pubkey = self.signing.pinned_key.clone();
            let _ = self.cfg.save(&self.layout.config());
        }
        if d["release"].is_object() {
            self.install_release(&d["release"].clone()).await;
        }
        for (key, stop) in [("cancel", Stop::Cancel), ("revoke", Stop::Revoke), ("kill", Stop::Revoke)] {
            for aid in d[key].as_array().cloned().unwrap_or_default().iter().filter_map(Value::as_i64) {
                if let Some(j) = self.table.lock().unwrap().get_mut(&aid) {
                    j.stop.get_or_insert(stop.clone());
                    j.wake.notify_one();
                }
            }
        }
        if let (Some(api), Some(list)) = (self.api.clone(), d["prefetch"].as_array()) {
            let ready = staging::ready(&self.layout);
            for did in list.iter().filter_map(Value::as_str).filter(|x| !ready.iter().any(|r| r == x)).take(4) {
                let (api, l, did) = (api.clone(), Layout::new(self.layout.home.clone()), did.to_string());
                tokio::spawn(async move {
                    if let Err(e) = staging::stage(&api, &l, &did).await {
                        warn!(dataset = %did, error = %e, "prefetch failed");
                    }
                });
            }
        }
        if d["run_doctor"].as_bool() == Some(true) && self.doctor.is_none() {
            self.run_doctors(&d["policy"].clone()).await;
        }
        if d["agent_update"].is_object() {
            if let Some(api) = self.api.clone() {
                let l = Layout::new(self.layout.home.clone());
                if self.update.handle(&api, &l, &d["agent_update"], &self.signing).await {
                    self.draining = true;
                }
            }
        } else if self.update.staged.is_some() && d.get("agent_update").is_some() {
            self.update.staged = None;                     // the assignment changed before the swap: abandon it
            self.update.state = json!({"state": "idle"});
            self.draining = false;
        }
        if d["install_coordinator"].is_object() {
            if let Some(api) = self.api.clone() {
                self.coord_install.handle(&api, &d["install_coordinator"], &self.signing, &self.cfg.coordinator_trust);
            }
        }
        if d["renew_cert"].as_bool() == Some(true) {
            if let Err(e) = self.renew_cert().await {
                warn!(error = %e, "certificate renewal failed; retrying on the next heartbeat");
            }
        }
        self.hooks.on_directives(d);
        self.directives = d.clone();
        self.sync_services();
    }

    /// Create the service manager with the first release; reconfigure it on a new release or policy, and hand it
    /// new limits.
    fn sync_services(&mut self) {
        let Some(rel) = self.release.clone() else { return };
        if self.services.is_none() {
            let Ok(rt) = self.runtime() else { return };
            let hub = self.session_hub;
            let registry = self.prot.get_or_insert_with(|| crate::prot::Protection::new(&self.layout, hub)).registry.clone();
            self.services = Some(Arc::new(std::sync::Mutex::new(crate::services::ServiceManager::new(
                Layout::new(self.layout.home.clone()), rt, Some(registry), self.cfg.manage_services))));
        }
        let svc = self.services.clone().expect("set above");
        let mut s = svc.lock().unwrap();
        let (policy, limits) = (&self.directives["policy"], &self.directives["limits"]);
        if self.services_seen.0 != rel.id || self.services_seen.1 != *policy {
            s.configure(&rel, policy, self.node_id.as_deref());
            self.services_seen.0 = rel.id.clone();
            self.services_seen.1 = policy.clone();
        }
        if self.services_seen.2 != *limits {
            s.set_limits(limits);
            self.services_seen.2 = limits.clone();
        }
    }

    fn runtime(&mut self) -> Result<Runtime> {
        if self.runtime.is_none() {
            self.runtime = Some(Runtime::discover(None, None)?);
        }
        Ok(self.runtime.clone().expect("set above"))
    }

    async fn install_release(&mut self, d: &Value) {
        let id = d["release_id"].as_str().unwrap_or("").to_string();
        if self.release.as_ref().is_some_and(|r| r.id == id) {
            return;
        }
        let result = async {
            let rt = self.runtime()?;
            release::install(self.api()?, &self.layout, &rt, d, &self.signing).await
        }.await;
        match result {
            Ok(rel) => {
                info!(release = %rel.id, modules = rel.modules.len(), "release installed");
                self.signing.accept_release(d);
                self.cfg.release_seq = self.signing.release_seq;
                let _ = self.cfg.save(&self.layout.config());
                self.release = Some(rel);
                self.last_release_error = None;
                self.need_hello = true;
                self.sync_services();
                let policy = self.directives["policy"].clone();
                self.run_doctors(&policy).await;
            }
            Err(e) => {
                warn!(release = %id, error = %e, "release install refused");
                self.last_release_error = Some(format!("{e:#}"));
                self.doctor = Some(json!({"at": doctor::now(), "release_id": id, "modules": {},
                                          "release_install": {"ok": false, "error": format!("{e:#}")}}));
            }
        }
    }

    async fn run_doctors(&mut self, policy: &Value) {
        let (Some(rel), Ok(rt)) = (self.release.clone(), self.runtime()) else { return };
        let (l, p) = (Layout::new(self.layout.home.clone()), policy.clone());
        match tokio::task::spawn_blocking(move || doctor::run_all(&l, &rt, &rel, &p)).await {
            Ok(mut rep) => {
                self.fold_requires(&mut rep);
                info!(report = %rep["modules"], "doctors ran");
                self.healthy = rep["modules"].as_object().map(|m| m.iter().filter(|(_, v)| v["health"] == "healthy")
                    .map(|(k, _)| k.clone()).collect()).unwrap_or_default();
                self.doctor = Some(rep);
            }
            Err(e) => warn!(error = %e, "doctor task failed"),
        }
    }

    /// A module whose `requires` (capabilities its stages all need) nothing on this node provides is not healthy:
    /// its own doctor's capabilities and those of the node's services and probes count.
    /// The node's capabilities (what its offered services and healthy probes provide) go into the report, where the
    /// coordinator checks stages' `requires.capabilities`; a module whose `requires` nothing provides is unhealthy.
    fn fold_requires(&self, rep: &mut Value) {
        let node: Vec<String> = self.services.as_ref().map(|s| s.lock().unwrap().capabilities()).unwrap_or_default();
        rep["capabilities"] = json!(node);
        let (Some(rel), Some(mods)) = (self.release.as_ref(), rep["modules"].as_object_mut()) else { return };
        for m in &rel.modules {
            let Some(r) = m["name"].as_str().and_then(|n| mods.get_mut(n)) else { continue };
            let own: Vec<String> = r["capabilities"].as_array().cloned().unwrap_or_default().iter()
                .filter_map(|c| c.as_str().map(str::to_string)).collect();
            let missing: Vec<&str> = m["requires"].as_array().map(Vec::as_slice).unwrap_or(&[]).iter().filter_map(Value::as_str)
                .filter(|c| !own.iter().chain(node.iter()).any(|x| x == c)).collect();
            if missing.is_empty() {
                continue;
            }
            let check = json!({"name": "requires", "ok": false, "detail": format!("no service or probe provides {}", missing.join(", "))});
            r["health"] = json!("unhealthy");
            match r["checks"].as_array_mut() {
                Some(c) => c.push(check),
                None => r["checks"] = json!([check]),
            }
        }
    }

    fn trust_report(&self) -> Value {
        use sha2::Digest;
        let fp = self.cfg.coordinator_trust.cik.as_deref()
            .and_then(|k| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, k).ok())
            .map(|raw| hex::encode(sha2::Sha256::digest(raw)));
        json!({"cik_pinned": fp, "coordinator_move_state": self.move_state})
    }

    /// Owner key sets and move statements in a directive (or a 410's body): verify, then pin or record.
    pub fn observe_moves(&mut self, d: &Value) {
        let now = doctor::now();
        self.coord_clock.observe(d, now);              // every directive and 410 body carries the coordinator's `now`
        if d["owner_anchors"].is_object() {
            match crate::moves::check_owner_anchors(&d["owner_anchors"], &self.cfg.coordinator_trust) {
                Ok(set) => {
                    let t = &mut self.cfg.coordinator_trust;
                    (t.owner_version, t.owner_keys, t.owner_rescue) = (set.version, set.keys, set.rescue);
                    let _ = self.cfg.save(&self.layout.config());
                    info!(version = set.version, rescue_locations = self.cfg.coordinator_trust.owner_rescue.len(), "owner key set pinned");
                }
                // the set this node already pinned (or an older one), sent again with every directive: nothing to do
                Err(_) if self.cfg.coordinator_trust.owner_version > 0 && d["owner_anchors"]["statement"].as_str()
                    .and_then(|st| serde_json::from_str::<Value>(st).ok()).and_then(|doc| doc["version"].as_i64())
                    .is_some_and(|v| v <= self.cfg.coordinator_trust.owner_version) => {}
                Err(e) => warn!(error = %e, "owner key set refused"),
            }
        }
        let trust = &self.cfg.coordinator_trust;
        if let Some(pending) = trust.pending_move.as_ref().and_then(|p| crate::moves::Statement::parse(p).ok()) {
            if d["coordinator_move_cancel"].is_object()
                && crate::moves::check_cancel(&d["coordinator_move_cancel"], trust, &pending).is_ok() {
                info!(move_id = %pending.move_id, "coordinator move cancelled");
                self.cfg.coordinator_trust.pending_move = None;
                self.move_state = json!({"move_id": pending.move_id, "state": "cancelled", "at": now});
                let _ = self.cfg.save(&self.layout.config());
                return;
            }
        }
        if !d["coordinator_move"].is_object() || self.cfg.coordinator_trust.pending_move.is_some() {
            return;
        }
        match crate::moves::Statement::parse(&d["coordinator_move"])
            .and_then(|s| s.verify(&self.cfg.coordinator_trust, self.coord_clock.now(now), true).map(|_| s)) {
            Ok(s) => self.record_move(&s, now),
            Err(e) => {
                if self.move_state["error"].as_str() != Some(&format!("{e:#}")) {
                    warn!(error = %e, "coordinator move refused");
                }
                self.move_state = json!({"state": "refused", "error": format!("{e:#}"), "at": now});
            }
        }
    }

    /// Pin a verified move statement as the pending move.
    fn record_move(&mut self, s: &crate::moves::Statement, now: f64) {
        info!(move_id = %s.move_id, to = %s.to_url, not_before = s.not_before, rescue = s.rescue, "coordinator move recorded");
        self.cfg.coordinator_trust.pending_move = Some(s.json());
        self.move_state = json!({"move_id": s.move_id, "state": "pending", "epoch": s.epoch, "at": now});
        let _ = self.cfg.save(&self.layout.config());
    }

    /// Signing mode: read the owner key set's rescue locations when they are due (rescue.rs) and record the first move
    /// there that verifies. `unreachable`: the coordinator did not answer this round.
    pub async fn rescue_check(&mut self, unreachable: bool) {
        let now = doctor::now();
        let t = &self.cfg.coordinator_trust;
        if t.pending_move.is_some() || t.owner_keys.is_empty() || t.owner_rescue.is_empty() || !self.rescue.due(now, unreachable) {
            return;
        }
        let client = match crate::rescue::client() {
            Ok(c) => c,
            Err(e) => return warn!(error = %e, "rescue locations: no HTTP client"),
        };
        if let Some((location, s)) = crate::rescue::find(&client, &self.cfg.coordinator_trust, self.coord_clock.now(now)).await {
            warn!(location = %location, move_id = %s.move_id, to = %s.to_url, "rescue move found at a rescue location");
            self.record_move(&s, now);
        }
    }

    /// Follow a recorded move once its time lock passed: tailnet identity, the target's proof, a hello; then commit.
    /// A target that is not ready is retried; nothing here ever goes back to the old coordinator.
    pub async fn follow_move(&mut self) -> Result<bool> {
        let Some(s) = self.cfg.coordinator_trust.pending_move.as_ref().and_then(|p| crate::moves::Statement::parse(p).ok()) else {
            return Ok(false);
        };
        if self.coord_clock.now(doctor::now()) < s.not_before {
            return Ok(false);
        }
        self.move_state = json!({"move_id": s.move_id, "state": "following", "at": doctor::now()});
        let host = reqwest::Url::parse(&s.to_url)?.host_str().unwrap_or("").to_string();
        if let Some(want) = &s.to_stable_id {
            if crate::moves::tailnet_address(&host) && crate::moves::tailnet_stable_id(&host).as_deref() != Some(want.as_str()) {
                bail!("move: the target address is not the tailnet node the statement names");
            }
        }
        let nonce = identity::new_nonce();
        let ans: Value = tls::bootstrap_client()?.get(format!("{}/v1/identity?nonce={nonce}", s.to_url.trim_end_matches('/')))
            .send().await?.error_for_status()?.json().await?;
        let mut expect = self.cfg.coordinator_trust.clone();
        expect.cik = Some(s.to_cik.clone());
        expect.max_epoch = s.epoch;
        let proof = identity::check(&ans, &nonce, &expect)?;
        if proof.role != "active" || proof.epoch != s.epoch {
            bail!("move: the target is {} at epoch {}, not active at {} yet", proof.role, proof.epoch, s.epoch);
        }
        let mut trust = self.cfg.coordinator_trust.clone();
        identity::apply(&mut trust, &proof);
        let ca = std::fs::read_to_string(self.layout.ca_cert())?;
        let cert = std::fs::read_to_string(self.layout.node_cert())?;
        let key = std::fs::read_to_string(self.layout.node_key())?;
        let ca_pem = ans["ca_pem"].as_str().map(str::to_string).unwrap_or(ca);
        let api = Api::new(&s.to_url, tls::pinned_client(&ca_pem, &identity::pins(&trust), Some((&cert, &key)))?, s.epoch);
        let mut body = json!({"agent_version": VERSION, "boot_id": self.boot_id, "facts": facts::collect(&self.layout.home),
                              "live_attempts": [], "ready_datasets": staging::ready(&self.layout),
                              "release_id": self.release.as_ref().map(|r| r.id.clone())});
        merge(&mut body, self.update.report());
        api.post("/v1/agent/hello", &body).await?;
        let mut coordinator = self.cfg.coordinator.clone();
        crate::moves::commit(&mut self.cfg.coordinator_trust, &mut coordinator, &s);
        self.cfg.coordinator_trust.ca_spki_sha256 = trust.ca_spki_sha256;
        self.cfg.coordinator_trust.ca_next_spki_sha256 = trust.ca_next_spki_sha256;
        self.cfg.coordinator = coordinator;
        std::fs::write(self.layout.ca_cert(), ca_pem)?;
        self.cfg.save(&self.layout.config())?;
        self.move_state = json!({"move_id": s.move_id, "state": "committed", "epoch": s.epoch, "at": doctor::now()});
        info!(to = %s.to_url, epoch = s.epoch, "followed the coordinator move");
        self.api = Some(self.mtls()?);
        Ok(true)
    }

    /// The container runtime, once a release has a module approved for containers and the runtime exists here (none
    /// on Windows yet: an agent-owned WSL2 distribution comes later).
    #[cfg(unix)]
    fn container_runtime(&mut self) -> Option<Arc<dyn crate::container_runtime::ContainerRuntime>> {
        let wants = self.release.as_ref().is_some_and(|r| r.modules.iter()
            .any(|m| ["containers", "container_sets"].iter().any(|k| m["sandbox"][k].as_array().is_some_and(|c| !c.is_empty()))));
        if !wants {
            return None;
        }
        if self.containers.is_none() {
            self.containers = crate::container_runtime::for_node(&self.layout);
        }
        self.containers.clone()
    }

    /// The container set verifier, made once (its index seqs live in the agent's home).
    #[cfg(unix)]
    fn image_verifier(&mut self) -> anyhow::Result<Arc<crate::imageset::Verifier>> {
        if self.images.is_none() {
            self.images = Some(Arc::new(crate::imageset::Verifier::new(self.layout.home.join("image-sets.json"))?));
        }
        Ok(self.images.clone().expect("made above"))
    }

    /// At start no attempt is live, so a container still carrying the attempt label was left by an earlier run of the
    /// agent (one that crashed or was killed while a job ran a container): remove it before any new work starts.
    #[cfg(unix)]
    async fn reap_containers(&mut self) {
        let Some(rt) = self.container_runtime() else { return };
        let _ = tokio::task::spawn_blocking(move || {
            let removed = rt.reap();
            if !removed.is_empty() {
                info!(containers = ?removed, "removed containers left by an earlier run");
            }
        }).await;
    }

    /// One protection tick: sample, decide, actuate, recompute capacity.
    pub fn protect(&mut self) {
        if self.facts.is_null() {
            self.facts = facts::collect(&self.layout.home);
        }
        let l = Layout::new(self.layout.home.clone());
        #[cfg(unix)]
        // the runtime's `containers` pool, and the `gpu` pool where containers can get the node's GPUs (CDI)
        let mut pools: std::collections::BTreeMap<String, i64> = self.container_runtime().map(|rt| {
            let gpu = rt.gpu_device().is_some();
            [("containers".to_string(), rt.pool_tokens() as i64)].into_iter().chain(gpu.then(|| ("gpu".to_string(), 1)))
                .collect()
        }).unwrap_or_default();
        #[cfg(windows)]
        let mut pools = std::collections::BTreeMap::<String, i64>::new();
        let (mut reserved, mut running) = (0.0, vec![]);
        if let Some(svc) = self.services.clone() {
            let (need, live) = {
                let t = self.table.lock().unwrap();
                let mut need = std::collections::BTreeMap::<String, i64>::new();
                for n in t.values().flat_map(|j| j.needs.iter()) {
                    *need.entry(n.clone()).or_default() += 1;
                }
                (need, t.keys().copied().collect::<Vec<_>>())
            };
            let soft = self.prot.as_ref().and_then(|p| p.telemetry["guard"].as_str()).is_some_and(|g| g != "clear");
            let mut s = svc.lock().unwrap();
            s.tick(&need, &live, soft);
            for (k, v) in s.pools() {
                *pools.entry(k).or_default() += v;
            }
            reserved = s.reserved_mem_gb();
            running = s.running();
            let caps = s.capabilities();
            if caps != self.services_caps {
                self.services_caps = caps;
                self.rerun_doctors = true;
            }
        }
        let hub = self.session_hub;
        let p = self.prot.get_or_insert_with(|| crate::prot::Protection::new(&l, hub));
        p.service_pools = pools;
        p.service_reserved_mem_gb = reserved;
        p.tick(&self.directives, &self.table, &self.facts);
        p.telemetry["services_running"] = json!(running);
        p.telemetry["services_reserved_gb"] = json!((reserved * 10.0).round() / 10.0);
    }

    /// Services stop when the node is not active and has no work left (a drain), and may start again once it is.
    async fn drain_services(&mut self) {
        let Some(svc) = self.services.clone() else { return };
        let idle = self.directives["desired_state"].as_str().is_some_and(|s| s != "active") && self.table.lock().unwrap().is_empty();
        if idle && !self.services_halted {
            self.services_halted = true;
            info!("not active and idle: stopping module services");
            let _ = tokio::task::spawn_blocking(move || svc.lock().unwrap().stop_all()).await;
        } else if !idle && self.services_halted && self.directives["desired_state"].as_str() == Some("active") {
            self.services_halted = false;
            svc.lock().unwrap().resume();
        }
    }

    /// What this node can still take: CPU slots and memory after its running jobs, from host protection's capacity
    /// when it has run, else a plain estimate.
    pub fn free(&self) -> (f64, f64) {
        if let Some(c) = self.prot.as_ref().and_then(|p| p.capacity.as_ref()) {
            return if c.admit { (c.free_cpu.floor(), c.mem_gb_free) } else { (0.0, 0.0) };
        }
        let f = facts::collect(&self.layout.home);
        let cores = f["cpu"]["logical"].as_f64().unwrap_or(1.0);
        let mem = f["memory_gb"].as_f64().unwrap_or(8.0);
        let reserve_mem = self.directives["policy"]["os_reserve_gb"].as_f64().unwrap_or(4.0);
        let t = self.table.lock().unwrap();
        let used_cpu: f64 = t.values().map(|j| j.cpu).sum();
        let used_mem: f64 = t.values().map(|j| j.mem_gb).sum();
        let mut cpu = (cores - 1.0 - used_cpu).max(0.0);
        if let Some(cap) = self.directives["limits"]["cpu_cores"].as_f64() {
            cpu = cpu.min((cap - used_cpu).max(0.0));
        }
        if let Some(cap) = self.directives["limits"]["jobs"].as_f64() {
            if t.len() as f64 >= cap {
                cpu = 0.0;
            }
        }
        let mut free_mem = (mem - reserve_mem - used_mem).max(0.0);
        if let Some(cap) = self.directives["limits"]["mem_gb"].as_f64() {
            free_mem = free_mem.min((cap - used_mem).max(0.0));
        }
        (cpu.floor(), free_mem)
    }

    /// Claim work when the node is ready and has room, and start each grant.
    pub async fn claim(&mut self) -> Result<usize, ApiError> {
        let d = &self.directives;
        if self.draining || d["desired_state"].as_str() != Some("active") || d["lifecycle"].as_str() != Some("ready")
            || self.release.is_none() || self.healthy.is_empty() || self.need_hello {
            return Ok(0);
        }
        let (cpu, mem) = self.free();
        if cpu < 1.0 {
            if let Some(c) = self.prot.as_ref().and_then(|p| p.capacity.as_ref()) {
                if self.seq.is_multiple_of(6) {
                    info!(binding = %c.binding_limit, why = ?c.not_admitting_because, slots = c.slots, "not admitting work");
                }
            }
            return Ok(0);
        }
        let rel = self.release.clone().expect("checked");
        let cap = self.prot.as_ref().and_then(|p| p.capacity.as_ref());
        let body = json!({"free_cpu": cpu, "free_mem_gb": mem, "modules": self.healthy, "release_id": rel.id,
                          "ready_datasets": staging::ready(&self.layout), "pool_jobs_only": cap.is_some_and(|c| c.pool_jobs_only),
                          "gpu_jobs": cap.and_then(|c| c.gpu_jobs)});
        let r = self.api().map_err(io_err)?.post("/v1/agent/claim", &body).await?;
        let received = std::time::Instant::now();
        let grants = r["grants"].as_array().cloned().unwrap_or_default();
        if grants.is_empty() {
            return Ok(0);
        }
        let rt = self.runtime().map_err(io_err)?;
        let ctx = Arc::new(jobs::Ctx { api: self.api.clone().expect("connected"), layout: Layout::new(self.layout.home.clone()),
                                       runtime: rt, release: rel.clone(), policy: self.directives["policy"].clone(),
                                       table: self.table.clone(), registry: self.prot.as_ref().map(|p| p.registry.clone()),
                                       #[cfg(unix)]
                                       containers: self.container_runtime(),
                                       #[cfg(unix)]
                                       images: self.image_verifier().map_err(io_err)?,
                                       services: self.services.clone() });
        for g in &grants {
            let aid = g["attempt_id"].as_i64().unwrap_or(0);
            let res = &g["spec"]["resources"];
            let module = g["module"].as_str().unwrap_or("");
            let runner = rel.module(module).map(|e| e["runner"].clone()).unwrap_or(Value::Null);
            self.table.lock().unwrap().insert(aid, JobState {
                attempt_id: aid, phase: "staging".into(), cpu: res["cpu"].as_f64().unwrap_or(1.0), mem_gb: res["mem_gb"].as_f64().unwrap_or(1.0),
                gpu: runner["gpu"]["use"].as_str().is_some_and(|u| u != "none"), pgid: None, stop: None, pause: false,
                usage: Default::default(), log_bytes: 0, started_at: doctor::now(),
                caps: runner["capabilities"].as_array().cloned().unwrap_or_default().iter().filter_map(|c| c.as_str().map(str::to_string)).collect(),
                bandwidth: runner["bandwidth_class"].as_str().map(str::to_string), threads: None,
                needs: jobs::needs_of(res), wake: Default::default() });
            info!(attempt = aid, kind = g["kind"].as_str().unwrap_or(""), module = g["module"].as_str().unwrap_or(""), "granted");
            tokio::spawn(jobs::run(ctx.clone(), g.clone(), crate::clock::local_deadline(g, received)));
        }
        Ok(grants.len())
    }

    /// A new key and certificate; the old pair keeps working until the new one is first used.
    pub async fn renew_cert(&mut self) -> Result<()> {
        let key = keys::new_key()?;
        let r = self.api()?.post("/v1/agent/cert", &json!({"csr": keys::csr_pem(&key, &facts::hostname())?})).await?;
        let cert = r["cert_pem"].as_str().context("renewal: no certificate")?;
        let ca = r["ca_pem"].as_str().map(str::to_string).unwrap_or(std::fs::read_to_string(self.layout.ca_cert())?);
        keys::store_cert(&self.layout, cert, &ca, Some(&key))?;
        self.api = Some(self.mtls()?);
        info!("client certificate renewed");
        Ok(())
    }

    /// The session loop: connect (enrolling first if needed), hello, then heartbeats; errors back off. Returns the
    /// process exit code: 0 stopped, 75 a staged update or a rollback for the launcher.
    pub async fn run(&mut self, stop: tokio::sync::watch::Receiver<bool>) -> Result<i32> {
        staging::sweep_partials(&self.layout);
        jobs::clear_workdirs(&self.layout);
        #[cfg(unix)]
        self.reap_containers().await;
        let mut backoff = Duration::from_secs(2);
        loop {
            if *stop.borrow() {
                return Ok(0);
            }
            if !keys::have_cert(&self.layout) {
                if let Err(e) = self.enroll(Duration::from_secs(10), None).await {
                    warn!(error = %e, "enrollment failed");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(300));
                    continue;
                }
            }
            let round = async {
                self.connect().await.map_err(|e| ApiError::Http { status: 0, code: "identity".into(), detail: e.to_string(),
                                                                  retry_after: None, body: Box::default() })?;
                self.hello().await?;
                if let Some(api) = self.api.clone() {
                    outbox::flush(&api, &self.layout).await;
                }
                loop {
                    // protection ticks every 2 s between heartbeats
                    let until = std::time::Instant::now() + Duration::from_secs_f64(self.cfg.heartbeat_s);
                    while std::time::Instant::now() < until {
                        self.protect();
                        tokio::time::sleep(Duration::from_secs(2).min(until.saturating_duration_since(std::time::Instant::now()))).await;
                    }
                    if *stop.borrow() {
                        return Ok::<i32, ApiError>(0);
                    }
                    if std::mem::take(&mut self.need_hello) {
                        self.hello().await?;
                    } else {
                        self.heartbeat().await?;
                        self.update.confirm(&self.layout);          // a hello and a heartbeat succeeded on this build
                    }
                    self.rescue_check(false).await;
                    match self.follow_move().await {
                        Ok(true) => {
                            self.hello().await?;
                            continue;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(error = %e, "coordinator move not followed yet");
                            self.move_state["error"] = json!(format!("{e:#}"));
                        }
                    }
                    if self.update.should_give_up() {
                        warn!("this version was not confirmed within 600 s: back to the previous one");
                        return Ok::<i32, ApiError>(crate::selfupdate::SWAP_EXIT);
                    }
                    if self.draining && self.update.staged.is_some() && self.table.lock().unwrap().is_empty() {
                        self.update.hand_over(&self.layout).map_err(io_err)?;
                        let _ = self.heartbeat().await;                // report "restarting"
                        info!("drained: restarting on the new version");
                        return Ok(crate::selfupdate::SWAP_EXIT);
                    }
                    self.drain_services().await;
                    if std::mem::take(&mut self.rerun_doctors) && self.release.is_some() {
                        let policy = self.directives["policy"].clone();
                        self.run_doctors(&policy).await;
                    }
                    self.claim().await?;
                }
            };
            match round.await {
                Ok(code) => return Ok(code),
                Err(e) => {
                    match e.code() {
                        "node_retired" => bail!("this node was retired"),
                        "coordinator_moved" => {
                            if let ApiError::Http { body, .. } = &e {
                                self.observe_moves(body);
                            }
                        }
                        "unauthorized" | "client_certificate_required" => {
                            warn!("the coordinator no longer knows this node's certificate: enrolling again");
                            let _ = std::fs::remove_file(self.layout.node_cert());
                        }
                        _ => {
                            warn!(error = %e, "session lost");
                            self.rescue_check(true).await;
                        }
                    }
                    // the coordinator is gone (moved, or unreachable with a rescue move found): follow a pending move
                    if self.cfg.coordinator_trust.pending_move.is_some() {
                        match self.follow_move().await {
                            Ok(true) => {
                                backoff = Duration::from_secs(2);
                                continue;
                            }
                            Ok(false) => warn!("a coordinator move is pending; its time lock has not passed"),
                            Err(err) => {
                                warn!(error = %err, "coordinator move not followed yet");
                                self.move_state["error"] = json!(format!("{err:#}"));
                            }
                        }
                    }
                    let wait = e.retry_after().unwrap_or(backoff);
                    tokio::time::sleep(wait).await;
                    backoff = (backoff * 2).min(Duration::from_secs(120));
                }
            }
        }
    }
}

fn io_err(e: anyhow::Error) -> ApiError {
    ApiError::Http { status: 0, code: "local".into(), detail: e.to_string(), retry_after: None, body: Box::default() }
}

fn merge(into: &mut Value, extra: Value) {
    if let (Some(a), Value::Object(b)) = (into.as_object_mut(), extra) {
        for (k, v) in b {
            a.insert(k, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rescue::tests::{key, rescue_file, serve};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::Signer;

    /// The owner key set a directive carries pins its rescue locations; a rescue move published there is recorded as
    /// The doctor report always names the node's capabilities, even before a release: the coordinator grants stages
    /// whose `requires.capabilities` only on nodes that report them.
    #[test]
    fn the_doctor_report_names_the_nodes_capabilities() {
        let home = std::env::temp_dir().join(format!("oarbank-agent-caps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let agent = Agent::open(Layout::new(home.clone()), Some("https://127.0.0.1:9")).unwrap();
        let mut rep = json!({"modules": {}});
        agent.fold_requires(&mut rep);
        assert_eq!(rep["capabilities"], json!([]));
        let _ = std::fs::remove_dir_all(&home);
    }

    /// the pending move (and survives a restart in agent.json).
    #[tokio::test]
    async fn a_rescue_move_at_a_pinned_rescue_location_becomes_the_pending_move() {
        let home = std::env::temp_dir().join(format!("oarbank-agent-rescue-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let (a, b, owner) = (key(1), key(2), key(3));
        let base = serve(vec![("/fleet_a.json", 200, "", rescue_file(&a.1, &b, &owner.0, 2, "https://b:7443").to_string())]).await;
        let mut agent = Agent::open(Layout::new(home.clone()), Some("https://127.0.0.1:9")).unwrap();
        let t = &mut agent.cfg.coordinator_trust;
        (t.cik, t.fleet_id, t.max_epoch) = (Some(a.1.clone()), Some("fleet_a".into()), 1);
        agent.rescue_check(true).await;
        assert!(agent.cfg.coordinator_trust.pending_move.is_none(), "no owner keys pinned: no rescue");

        let set = serde_json::to_string(&json!({"type": "oarbank.owner-anchors/v1", "fleet_id": "fleet_a", "version": 1,
            "threshold": 1, "keys": [owner.1], "rescue": [format!("{base}/fleet_a.json")], "signed_at": 1})).unwrap();
        let sig = B64.encode(owner.0.sign(set.as_bytes()).to_bytes());
        agent.observe_moves(&json!({"owner_anchors": {"statement": set, "signatures": [{"key": owner.1, "sig": sig}]}}));
        assert_eq!(agent.cfg.coordinator_trust.owner_rescue, [format!("{base}/fleet_a.json")]);
        agent.rescue_check(true).await;
        let pending = crate::moves::Statement::parse(agent.cfg.coordinator_trust.pending_move.as_ref().expect("recorded")).unwrap();
        assert_eq!((pending.epoch, pending.to_cik.as_str(), pending.rescue), (2, b.1.as_str(), true));
        assert_eq!(agent.move_state["state"], "pending");
        let saved = Config::load(&agent.layout.config()).unwrap().unwrap();
        assert!(saved.coordinator_trust.pending_move.is_some() && saved.coordinator_trust.owner_rescue.len() == 1);
        let _ = std::fs::remove_dir_all(home);
    }
}
