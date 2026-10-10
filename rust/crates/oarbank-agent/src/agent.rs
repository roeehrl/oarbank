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

/// An enrollment that cannot go on (the code was refused, the owner declined the machine): the agent goes back to
/// waiting for a code. `.0` is the status error code.
#[derive(Debug)]
pub struct EnrollmentEnded(pub &'static str, pub String);

impl std::fmt::Display for EnrollmentEnded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

impl std::error::Error for EnrollmentEnded {}

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
    /// Modules whose runner started in the current release: their doctor printed a DoctorOutput, healthy or not (offered
    /// in claims; the coordinator decides which of their stages run here: docs/design/stage-gating.md).
    pub offered: Vec<String>,
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
    pub containers: Option<crate::container_runtime::Containers>,
    /// Verifies container set images for every attempt (verified digests are remembered for the agent's lifetime).
    images: Option<Arc<crate::imageset::Verifier>>,
    /// The node statement this node applies (folders and added tool paths), and what it found for each folder (folders.rs).
    pub folders: crate::folders::Folders,
    /// Module services and probes (service protocol 1), created with the first release.
    pub services: Option<Arc<std::sync::Mutex<crate::services::ServiceManager>>>,
    /// What the services were last configured with: release id, policy, limits.
    services_seen: (String, Value, Value),
    /// Capabilities services and probes provide; a change re-runs the doctors (modules' `requires`).
    services_caps: Vec<String>,
    rerun_doctors: bool,
    /// The GPU APIs this node provides, from the latest probe (gpuapi.rs): `{host, containers, evidence}`.
    gpu_apis: Value,
    pub coord_install: crate::coordinstall::CoordInstall,
    /// Services were stopped because the node is not active and has no work (a drain); resumed when it is again.
    services_halted: bool,
    /// The status document (status.rs): joining, pending, connected, and errors with their codes.
    pub status: crate::status::Status,
    /// The host tools this node detected (tools.rs), reported in hello and every heartbeat; Null before the first run.
    pub tools: Value,
    /// The `tool_pins` directive: paths chosen among what this node found, per module (tools.rs `granted`).
    tool_pins: Value,
    /// Detect again at the next chance: asked by the coordinator, a new statement, or never yet.
    detect_due: bool,
    detected: Option<std::time::Instant>,
    /// The coordinator's settings revision this agent applied and the keys it refused (`settings` in heartbeats).
    pub settings_report: Value,
    /// The `policy` and `limits` as applied from the coordinator (or the table's defaults), before this machine's
    /// managed settings tighten them: what a refused or missing key keeps, and what a change of managed policy re-applies to.
    settings_base: Value,
    /// This machine's managed settings (policy.rs `Settings`), raw, and who manages it (`ManagedByOrganizationName`).
    pub managed: serde_json::Map<String, Value>,
    pub managed_by: Option<String>,
    /// When the managed policy was last read: at most once a minute, since a read runs plutil or reg.
    managed_read: Option<std::time::Instant>,
}

/// Directives before the coordinator's first answer: the settings table's defaults, nothing else.
pub fn initial_directives() -> Value {
    use oarbank_protection::settings::{defaults, Section};
    json!({"policy": defaults(Section::Policy), "limits": defaults(Section::Limits)})
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
        let mut a = Agent { node_id: cfg.node_id.clone(), cfg, api: None, boot_id: identity::new_nonce(), seq: 0,
                   directives: initial_directives(), hooks: Box::new(NoHooks), runtime: None, release, doctor: None, signing,
                   last_release_error: None, need_hello: false, table: Table::default(), offered: vec![],
                   draining: false, prot: None, session_hub: false, facts: Value::Null, update: crate::selfupdate::SelfUpdate::open(&layout), move_state: Value::Null,
                   rescue: Default::default(), coord_clock: Default::default(),
                   containers: None, images: None,
                   services: None, services_seen: Default::default(), services_caps: vec![], gpu_apis: Value::Null,
                   folders: crate::folders::Folders::load(&layout.state().join("folders.json")),
            rerun_doctors: true,                 // a release installed before a restart: its doctors run again before any claim
            services_halted: false, coord_install: Default::default(), status: Default::default(), layout,
            tools: Value::Null, tool_pins: json!({}), detect_due: true, detected: None, settings_report: Value::Null,
            settings_base: initial_directives(), managed: Default::default(), managed_by: None, managed_read: None };
        a.refresh_managed();                    // the defaults the agent starts from are tightened, too
        // macOS: the container runtime's report of an earlier run is stale (its VM may be gone); until a release wants
        // containers the facts show what the agent finds now
        #[cfg(target_os = "macos")]
        let _ = std::fs::remove_file(crate::colima::report_file(&a.layout.home));
        // folder entries a statement or a release no longer grants are removed when the agent starts, too
        #[cfg(windows)]
        crate::sandbox_windows::reconcile_folder_grants(&a.layout, a.release.as_ref(), &a.folders);
        Ok(a)
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

    /// Ask for enrollment: prove the coordinator's identity, then send a CSR for the node's own key with the join code's
    /// secret (kept until the coordinator answers, so a request lost on the way is sent again with it) or, joining by
    /// address, the device code this node shows its person. A code the coordinator refuses is final.
    pub async fn request_enrollment(&mut self) -> std::result::Result<Value, crate::join::EnrollError> {
        use crate::join::EnrollError;
        use crate::status::{JOINING, PENDING, ERROR};
        let ca_pem = self.prove_identity().await?;
        let key = keys::ensure_key(&self.layout)?;
        let pins = identity::pins(&self.cfg.coordinator_trust);
        let anon = Api::new(&self.cfg.coordinator, tls::pinned_client(&ca_pem, &pins, None)?, self.cfg.coordinator_trust.max_epoch);
        if self.cfg.join_secret.is_none() && self.cfg.user_code.is_none() {
            self.cfg.user_code = Some(crate::join::new_user_code());
        }
        let user_code = if self.cfg.join_secret.is_some() { None } else { self.cfg.user_code.clone() };
        let body = json!({"hostname": facts::hostname(), "facts": facts::collect(&self.layout.home),
                          "csr": keys::csr_pem(&key, &facts::hostname())?, "join": self.cfg.join_secret,
                          "name": self.cfg.name, "user_code": user_code});
        let r = anon.post("/v1/agent/enroll", &body).await.map_err(|e| EnrollError::Other(anyhow::anyhow!("{e}")))?;
        self.cfg.join_secret = None;
        if r["join"] == "refused" {
            self.cfg.save(&self.layout.config())?;
            let f = crate::join::refusal(r["join_error"].as_str().unwrap_or(""));
            self.status.fail(ERROR, f.code, &f.message, json!({}));
            return Err(EnrollError::Refused(f));
        }
        let e = r["enrollment_id"].as_str().context("enroll: no enrollment id")?.to_string();
        self.cfg.enrollment_id = Some(e.clone());
        self.cfg.save(&self.layout.config())?;
        let approved = r["status"] == "approved";
        self.status.set(if approved { JOINING } else { PENDING }, json!({
            "coordinator": self.cfg.coordinator, "enrollment_id": e, "key_fingerprint": keys::fingerprint(&key),
            "user_code": user_code, "name": self.cfg.name,
            "fingerprint": self.cfg.coordinator_trust.ca_spki_sha256.as_deref().map(|p| &p[..16.min(p.len())])}));
        if !approved {
            info!(enrollment = %e, "enrollment requested: approve it on the coordinator{}",
                  user_code.map(|c| format!(" (Fleet, Approve a machine by its code: {c})")).unwrap_or_default());
        }
        Ok(r)
    }

    /// Enroll: request it if not done yet, wait for the owner's approval, store the certificate.
    pub async fn enroll(&mut self, poll: Duration, max_wait: Option<Duration>) -> Result<()> {
        if self.cfg.enrollment_id.is_none() {
            match self.request_enrollment().await {
                Ok(_) => {}
                Err(crate::join::EnrollError::Refused(f)) => bail!(EnrollmentEnded(f.code, f.message)),
                Err(crate::join::EnrollError::Other(e)) => return Err(e),
            }
        }
        let ca_pem = self.prove_identity().await?;
        let pins = identity::pins(&self.cfg.coordinator_trust);
        let anon = Api::new(&self.cfg.coordinator, tls::pinned_client(&ca_pem, &pins, None)?, self.cfg.coordinator_trust.max_epoch);
        let eid = self.cfg.enrollment_id.clone().context("no enrollment")?;
        let started = std::time::Instant::now();
        loop {
            let st = match anon.get(&format!("/v1/agent/enroll/{eid}")).await {
                Ok(st) => st,
                Err(e) if e.code() == "not_found" => {
                    // the coordinator lost the request (restored from a backup, or another coordinator): ask again
                    self.cfg.enrollment_id = None;
                    self.cfg.save(&self.layout.config())?;
                    bail!("the coordinator no longer knows enrollment {eid}: requesting again");
                }
                Err(e) => return Err(anyhow::anyhow!("{e}")),
            };
            match st["status"].as_str() {
                Some("approved") => {
                    let cert = st["cert_pem"].as_str().context("enroll: approved without a certificate")?;
                    let ca = st["ca_pem"].as_str().unwrap_or(&ca_pem);
                    keys::store_cert(&self.layout, cert, ca, None)?;
                    self.cfg.node_id = st["node_id"].as_str().map(str::to_string);
                    self.node_id = self.cfg.node_id.clone();
                    self.cfg.enrollment_id = None;
                    self.cfg.user_code = None;
                    self.cfg.save(&self.layout.config())?;
                    self.status.set(crate::status::JOINED, json!({"node_id": self.node_id, "enrollment_id": null,
                                                                  "user_code": null, "coordinator": self.cfg.coordinator}));
                    info!(node = ?self.node_id, "enrolled");
                    return Ok(());
                }
                Some("rejected") => {
                    self.cfg.enrollment_id = None;
                    self.cfg.save(&self.layout.config())?;
                    let m = "The owner declined this machine in the console.";
                    self.status.fail(crate::status::ERROR, "E_APPROVAL_DENIED", m, json!({"enrollment_id": null}));
                    bail!(EnrollmentEnded("E_APPROVAL_DENIED", m.into()));
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
                              "ready_datasets": staging::ready(&self.layout), "tools": self.tools,
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
                              "ready_datasets": staging::ready(&self.layout), "folders": self.folders.report(), "tools": self.tools,
                              "release_id": self.release.as_ref().map(|r| r.id.clone()), "clock": doctor::now()});
        if let Some(svc) = &self.services {
            merge(&mut body, svc.lock().unwrap().report());              // `services` and `probes`
        }
        if !self.settings_report.is_null() {
            body["settings"] = self.settings_report.clone();
        }
        merge(&mut body, self.hooks.heartbeat_extra());
        merge(&mut body, self.coord_install.report());
        merge(&mut body, self.update.report());
        merge(&mut body, self.trust_report());
        let d = self.api().map_err(io_err)?.post("/v1/agent/heartbeat", &body).await?;
        self.rescue.contact(doctor::now());
        self.after_directives(&d).await;
        Ok(d)
    }

    /// Read this machine's managed policy again when a minute has passed since the last read.
    fn refresh_managed(&mut self) {
        if self.managed_read.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
            return;
        }
        self.managed_read = Some(std::time::Instant::now());
        let p = crate::policy::read();
        self.set_managed(p.settings, p.managed_by);
    }

    /// Take new managed settings; they tighten the directives in force at once (and every directive after).
    pub fn set_managed(&mut self, settings: serde_json::Map<String, Value>, by: Option<String>) {
        if settings == self.managed && by == self.managed_by {
            return;
        }
        let (_, _, _, refused) = self.with_managed();
        let before: Vec<String> = refused.into_iter().map(|r| r.key).collect();
        self.managed = settings;
        self.managed_by = by;
        let (policy, limits, _, refused) = self.with_managed();
        let keys: Vec<String> = refused.into_iter().map(|r| r.key).collect();
        if !keys.is_empty() && keys != before {
            // the keys only: values stay out of logs (policy.rs)
            warn!(keys = %keys.join(", "), "this machine's managed policy sets settings it may not set, or invalid values; they are ignored");
        }
        if self.directives.is_object() {
            self.directives["policy"] = policy;
            self.directives["limits"] = limits;
        }
    }

    /// The settings in force: the coordinator's (`settings_base`) with this machine's managed settings laid over, each
    /// only tightening. (policy, limits, the managed keys, the managed keys refused.)
    fn with_managed(&self) -> (Value, Value, Vec<oarbank_protection::settings::Managed>, Vec<oarbank_protection::settings::Rejected>) {
        use oarbank_protection::settings::{apply_managed, unknown_managed, Section};
        let (policy, mut set, mut refused) = apply_managed(Section::Policy, &self.settings_base["policy"], &self.managed);
        let (limits, more_set, more_refused) = apply_managed(Section::Limits, &self.settings_base["limits"], &self.managed);
        set.extend(more_set);
        refused.extend(more_refused);
        refused.extend(unknown_managed(&self.managed));
        (policy, limits, set, refused)
    }

    /// The directive's `policy` and `limits` checked against the settings table (docs/design/settings.md): a refused
    /// or missing key keeps the value it had and is reported, with the revision, in the next heartbeat. This machine's
    /// managed settings then tighten them ("Managed on this machine"), reported only when the policy sets any.
    fn apply_settings(&mut self, d: &Value) -> Value {
        use oarbank_protection::settings::{validate, Section};
        let mut out = d.clone();
        if !d.is_object() || (d.get("policy").is_none() && d.get("limits").is_none()) {
            return out;
        }
        let (policy, mut rejected) = validate(Section::Policy, &d["policy"], &self.settings_base["policy"]);
        let (limits, more) = validate(Section::Limits, &d["limits"], &self.settings_base["limits"]);
        rejected.extend(more);
        for r in &rejected {
            warn!(key = %r.key, reason = %r.reason, "a setting from the coordinator was refused; the node keeps its previous value");
        }
        self.settings_base = json!({"policy": policy, "limits": limits});
        let (policy, limits, set, refused) = self.with_managed();
        out["policy"] = policy;
        out["limits"] = limits;
        if let Some(rev) = d["settings_rev"].as_i64() {
            let mut rep = json!({"applied_rev": rev,
                "rejected": rejected.iter().map(|r| json!({"key": r.key, "reason": r.reason})).collect::<Vec<_>>()});
            if !self.managed.is_empty() {
                rep["managed"] = set.iter().map(|m| json!({"key": m.key, "value": m.value, "binding": m.binding})).collect();
                if !refused.is_empty() {
                    rep["managed_refused"] = refused.iter().map(|r| json!({"key": r.key, "reason": r.reason})).collect();
                }
                if let Some(by) = &self.managed_by {
                    rep["managed_by"] = json!(by);
                }
            }
            self.settings_report = rep;
        }
        out
    }

    async fn after_directives(&mut self, d: &Value) {
        self.refresh_managed();
        let applied = self.apply_settings(d);
        let d = &applied;
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
        if !d["tool_pins"].is_null() && d["tool_pins"] != self.tool_pins {
            self.tool_pins = d["tool_pins"].clone();
            self.rerun_doctors = true;                          // the tools files change with the pins
        }
        if d["detect_tools"].as_bool() == Some(true) {
            self.detect_due = true;
        }
        if d["statement"].is_object() {
            self.observe_statement(&d["statement"].clone());
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
            let policy = self.with_grants(&d["policy"]);
            self.run_doctors(&policy).await;
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
        s.set_gpu_apis(crate::gpuapi::host(&self.gpu_apis));
        let limits = &self.directives["limits"];
        // a module the coordinator disabled (its kill switch) has every service disabled here: stopped, never offered
        let mut policy = self.with_grants(&self.directives["policy"]);
        let off: Vec<&str> = self.directives["modules_disabled"].as_array().into_iter().flatten().filter_map(|m| m.as_str()).collect();
        if !off.is_empty() {
            let mut disabled: Vec<Value> = policy["disabled_services"].as_array().cloned().unwrap_or_default();
            for e in rel.modules.iter().filter(|e| e["name"].as_str().is_some_and(|n| off.contains(&n))) {
                for sv in e["services"].as_array().into_iter().flatten() {
                    disabled.push(json!(format!("{}/{}", e["name"].as_str().unwrap_or(""), sv["name"].as_str().unwrap_or(""))));
                }
            }
            policy["disabled_services"] = Value::Array(disabled);
        }
        if self.services_seen.0 != rel.id || self.services_seen.1 != policy {
            s.configure(&rel, &policy, self.node_id.as_deref());
            self.services_seen.0 = rel.id.clone();
            self.services_seen.1 = policy;
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
        // a service the previous release dropped is stopped with that release's files, which this install may prune
        self.settle_services().await;
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
                #[cfg(windows)]
                crate::sandbox_windows::reconcile_folder_grants(&self.layout, self.release.as_ref(), &self.folders);
                self.detect_tools().await;                      // the release carries the fleet's tool definitions
                self.sync_services();
                let policy = self.with_grants(&self.directives["policy"]);
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

    /// Probe the node's GPU APIs again (in a child: gpuapi::probe) and hand the host's to the services.
    async fn probe_gpu_apis(&mut self) {
        let home = self.layout.home.clone();
        match tokio::task::spawn_blocking(move || crate::gpuapi::probe(std::path::Path::new(&crate::sandbox::me()), &home)).await {
            Ok(r) => {
                if r != self.gpu_apis {
                    info!(host = %r["host"], containers = %r["containers"], "GPU APIs");
                }
                self.gpu_apis = r;
                if let Some(s) = &self.services {
                    s.lock().unwrap().set_gpu_apis(crate::gpuapi::host(&self.gpu_apis));
                }
            }
            Err(e) => warn!(error = %e, "GPU probe task failed"),
        }
    }

    async fn run_doctors(&mut self, policy: &Value) {
        self.probe_gpu_apis().await;
        let (Some(rel), Ok(rt)) = (self.release.clone(), self.runtime()) else { return };
        let (l, p) = (Layout::new(self.layout.home.clone()), policy.clone());
        match tokio::task::spawn_blocking(move || doctor::run_all(&l, &rt, &rel, &p)).await {
            Ok(mut rep) => {
                self.fold_requires(&mut rep);
                self.fold_gpu_apis(&mut rep);
                info!(report = %rep["modules"], "doctors ran");
                self.offered = doctor::offered(&rep);
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

    /// The node's GPU APIs go into the report, where the coordinator checks stages' GPU needs; a module whose runner
    /// (the release entry's, already for this platform) needs a GPU API the host lacks cannot run here: `undetected`.
    fn fold_gpu_apis(&self, rep: &mut Value) {
        rep["gpu_apis"] = if self.gpu_apis.is_null() { json!({"host": [], "containers": [], "evidence": {}}) } else { self.gpu_apis.clone() };
        let host = crate::gpuapi::host(&self.gpu_apis);
        let (Some(rel), Some(mods)) = (self.release.as_ref(), rep["modules"].as_object_mut()) else { return };
        for m in &rel.modules {
            let Some(r) = m["name"].as_str().and_then(|n| mods.get_mut(n)) else { continue };
            let g = &m["runner"]["gpu"];
            let apis: Vec<String> = g["apis_any"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
            if g["use"].as_str().is_none_or(|u| u == "none") || g["in_container"].as_bool() == Some(true) || crate::gpuapi::fits(&apis, &host) {
                continue;
            }
            let have = if host.is_empty() { "no GPU API".to_string() } else { host.join(", ") };
            let check = json!({"name": "gpu_apis", "ok": false,
                               "detail": format!("needs one of {} on the host; this node provides {have}", apis.join(", "))});
            r["health"] = json!("undetected");
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

    /// The node's statement in a directive (folders.rs): verified against the pinned release key, its folders checked one
    /// by one and applied; on Windows the folder entries no applied statement or current release grants any more are
    /// removed. Tool paths it adds are detected again (tools.rs checks and verifies them).
    fn observe_statement(&mut self, d: &Value) {
        match crate::folders::apply(&self.folders, d, self.node_id.as_deref().unwrap_or(""),
                                    self.cfg.coordinator_trust.fleet_id.as_deref(), self.signing.pinned_key.as_deref(),
                                    &data_root(&self.layout.home)) {
            Ok(Some(f)) => {
                info!(seq = f.seq, folders = %f.report(), tools = f.tools.len(), "statement applied");
                if let Err(e) = f.save(&self.layout.state().join("folders.json")) {
                    warn!(error = %e, "cannot keep the statement");
                }
                if f.tools != self.folders.tools {
                    self.detect_due = true;
                }
                self.folders = f;
                #[cfg(windows)]
                crate::sandbox_windows::reconcile_folder_grants(&self.layout, self.release.as_ref(), &self.folders);
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "statement refused (the last applied one stays)"),
        }
    }

    /// Detect the host tools now (tools.rs): the built-in ones, the release's definitions, the hints file and the
    /// statement's added paths. A change re-runs the doctors (their tools files change) and reconfigures the services.
    pub async fn detect_tools(&mut self) {
        let defs = crate::tools::defs(self.release.as_ref().map(|r| &r.tools).unwrap_or(&Value::Null));
        let (home, added) = (self.layout.home.clone(), self.folders.tools.clone());
        let found = tokio::task::spawn_blocking(move || {
            let run = crate::tools::sandboxed_runner(&home);
            crate::tools::detect(&defs, &crate::tools::hints(&home), &added, &data_root(&home), &run)
        }).await;
        self.detect_due = false;
        self.detected = Some(std::time::Instant::now());
        match found {
            Ok(rep) => {
                if !crate::tools::same(&rep, &self.tools) {
                    info!(tools = %rep["tools"], "host tools detected");
                    if !self.tools.is_null() && self.release.is_some() {
                        self.rerun_doctors = true;
                    }
                }
                self.tools = rep;
            }
            Err(e) => warn!(error = %e, "tool detection task failed"),
        }
    }

    /// Whether detection is due: asked for, never run, or the slow timer ran out.
    fn detection_due(&self) -> bool {
        self.detect_due || self.detected.is_none_or(|t| t.elapsed() >= crate::tools::REDETECT_EVERY)
    }

    /// The policy the agent hands doctors, services and runners: the coordinator's, with this node's resolution of each
    /// module's tool requests (`tool_grants`, tools.rs `grants`), which grant_files reads.
    fn with_grants(&self, policy: &Value) -> Value {
        let mut p = if policy.is_object() { policy.clone() } else { json!({}) };
        let defs = crate::tools::defs(self.release.as_ref().map(|r| &r.tools).unwrap_or(&Value::Null));
        p["tool_grants"] = crate::tools::grants(&self.tools, self.release.as_ref().map(|r| r.modules.as_slice()).unwrap_or(&[]),
                                                &self.tool_pins, &defs);
        p
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

    /// The container runtimes, once a release has a module approved for containers and a runtime exists here (on
    /// Windows and macOS it always does: it reports what is missing itself).
    fn container_runtime(&mut self) -> Option<crate::container_runtime::Containers> {
        let wants = self.release.as_ref().is_some_and(|r| r.modules.iter()
            .any(|m| ["containers", "container_sets"].iter().any(|k| m["sandbox"][k].as_array().is_some_and(|c| !c.is_empty()))));
        if !wants {
            return None;
        }
        if self.containers.is_none() {
            #[cfg(target_os = "macos")]
            {
                // the agent's own runtime publishes its report (the facts' `containers`) and comes up now, in the
                // background (docs/design/macos-containers.md, "Bring-up")
                self.containers = crate::container_runtime::for_node_mac(&self.layout, true);
                if let Some(rts) = &self.containers {
                    rts.all().iter().for_each(|rt| rt.recheck());
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                self.containers = crate::container_runtime::for_node(&self.layout);
            }
        }
        self.containers.clone()
    }

    /// The container set verifier, made once (its index seqs live in the agent's home).
    fn image_verifier(&mut self) -> anyhow::Result<Arc<crate::imageset::Verifier>> {
        if self.images.is_none() {
            self.images = Some(Arc::new(crate::imageset::Verifier::new(self.layout.home.join("image-sets.json"))?));
        }
        Ok(self.images.clone().expect("made above"))
    }

    /// At start no attempt is live, so a container still carrying the attempt label was left by an earlier run of the
    /// agent (one that crashed or was killed while a job ran a container): remove it before any new work starts.
    async fn reap_containers(&mut self) {
        let Some(rts) = self.container_runtime() else { return };
        let _ = tokio::task::spawn_blocking(move || {
            let removed: Vec<String> = rts.all().iter().flat_map(|rt| rt.reap()).collect();
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
        // the runtime's `containers` pool (only while it can run containers), and the `gpu` pool where containers can get
        // the node's GPUs (CDI on Linux and Windows, the krunkit VM on macOS)
        let rts = self.container_runtime();
        let mut pools = container_pools(rts.as_ref());
        // a runtime that keeps its own report (Windows) changed state: the facts go out again, and the doctors (with the
        // GPU APIs in containers) run again
        if let Some(report) = rts.as_ref().and_then(|r| r.cpu.report()) {
            if self.facts["containers"] != report && !self.facts.is_null() {
                self.facts = facts::collect(&self.layout.home);
                self.need_hello = true;
                self.rerun_doctors = true;
            }
        }
        let (mut reserved, mut running) = (0.0, vec![]);
        if let Some(svc) = self.services.clone() {
            let (need, live) = self.service_demand();
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
        p.services = self.services.as_ref().map(|s| s.lock().unwrap().fleet_view()).unwrap_or_default();
        p.tick(&self.directives, &self.table, &self.facts);
        // the services protection stops are held down until it lets them go (their users were released by the tick)
        let stops: std::collections::BTreeMap<String, String> = p.last.as_ref()
            .map(|r| r.service_stops.iter().map(|s| (s.key.clone(), s.reason.clone())).collect()).unwrap_or_default();
        let mut held = std::collections::BTreeMap::new();
        let demand = self.service_demand();
        let p = self.prot.as_mut().expect("made above");
        if let Some(svc) = self.services.clone() {
            let mut s = svc.lock().unwrap();
            if s.held() != stops {
                s.set_held(&stops);
                let soft = p.telemetry["guard"].as_str().is_some_and(|g| g != "clear");
                s.tick(&demand.0, &demand.1, soft);                          // stopped now, not on the next tick
            }
            held = s.held();
        }
        p.telemetry["services_running"] = json!(running);
        p.telemetry["services_reserved_gb"] = json!((reserved * 10.0).round() / 10.0);
        p.telemetry["services_held"] = json!(held);
    }

    /// What the services' tick needs: the jobs needing each pool, and the live attempts.
    fn service_demand(&self) -> (std::collections::BTreeMap<String, i64>, Vec<i64>) {
        let t = self.table.lock().unwrap();
        let mut need = std::collections::BTreeMap::<String, i64>::new();
        for n in t.values().flat_map(|j| j.needs.iter()) {
            *need.entry(n.clone()).or_default() += 1;
        }
        (need, t.keys().copied().collect())
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
        let reserve_mem = self.directives["policy"]["os_reserve_gb"].as_f64().unwrap_or(oarbank_protection::settings_table::OS_RESERVE_GB);
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
            || self.release.is_none() || self.offered.is_empty() || self.need_hello {
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
        let body = json!({"free_cpu": cpu, "free_mem_gb": mem, "modules": self.offered, "release_id": rel.id,
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
                                       runtime: rt, release: rel.clone(), policy: self.with_grants(&self.directives["policy"]),
                                       table: self.table.clone(), registry: self.prot.as_ref().map(|p| p.registry.clone()),
                                       containers: self.container_runtime(),
                                       images: self.image_verifier().map_err(io_err)?,
                                       services: self.services.clone(), folders: self.folders.clone() });
        for g in &grants {
            let aid = g["attempt_id"].as_i64().unwrap_or(0);
            let res = &g["spec"]["resources"];
            let module = g["module"].as_str().unwrap_or("");
            let runner = rel.module(module).map(|e| e["runner"].clone()).unwrap_or(Value::Null);
            let needs = jobs::needs_of(res);
            // a GPU job: its runner uses a GPU, or it uses a service that does
            let gpu_pools = self.services.as_ref().map(|s| s.lock().unwrap().gpu_pools(module)).unwrap_or_default();
            let gpu = runner["gpu"]["use"].as_str().is_some_and(|u| u != "none") || needs.iter().any(|n| gpu_pools.contains(n));
            self.table.lock().unwrap().insert(aid, JobState {
                attempt_id: aid, module: module.to_string(), phase: "staging".into(), cpu: res["cpu"].as_f64().unwrap_or(1.0),
                mem_gb: res["mem_gb"].as_f64().unwrap_or(1.0), gpu, pgid: None, stop: None, pause: false,
                usage: Default::default(), log_bytes: 0, started_at: doctor::now(),
                caps: runner["capabilities"].as_array().cloned().unwrap_or_default().iter().filter_map(|c| c.as_str().map(str::to_string)).collect(),
                bandwidth: runner["bandwidth_class"].as_str().map(str::to_string), threads: None,
                needs, wake: Default::default() });
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
    /// The agent's life: its rounds with the coordinator until a stop, a swap or a fatal error, and then the stops of
    /// services a release dropped, which the process's exit would cut short.
    pub async fn run(&mut self, stop: tokio::sync::watch::Receiver<bool>) -> Result<i32> {
        let r = self.rounds(stop).await;
        self.settle_services().await;
        r
    }

    /// Wait for the stops of services a release no longer has (services.rs `Stops`).
    async fn settle_services(&self) {
        let Some(svc) = &self.services else { return };
        let stops = svc.lock().unwrap().stops();
        let _ = tokio::task::spawn_blocking(move || stops.wait()).await;
    }

    async fn rounds(&mut self, stop: tokio::sync::watch::Receiver<bool>) -> Result<i32> {
        staging::sweep_partials(&self.layout);
        jobs::clear_workdirs(&self.layout);
        self.reap_containers().await;
        self.probe_gpu_apis().await;                // before any service is offered: a GPU service waits for it
        self.detect_tools().await;                  // hello reports them
        let mut backoff = Duration::from_secs(2);
        loop {
            if *stop.borrow() {
                return Ok(0);
            }
            if !keys::have_cert(&self.layout) {
                if let Err(e) = self.enroll(Duration::from_secs(10), None).await {
                    if e.downcast_ref::<EnrollmentEnded>().is_some() {
                        return Err(e);                  // refused or declined: main goes back to waiting for a code
                    }
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
                if self.status.state() != crate::status::CONNECTED {
                    self.status.set(crate::status::CONNECTED, json!({"node_id": self.node_id, "coordinator": self.cfg.coordinator,
                                                                     "enrollment_id": null, "user_code": null}));
                }
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
                    if self.detection_due() {
                        self.detect_tools().await;
                        self.sync_services();
                    }
                    if std::mem::take(&mut self.rerun_doctors) && self.release.is_some() {
                        // the container runtime checks again too (Windows: what it missed may be installed by now)
                        if let Some(rts) = self.container_runtime() {
                            rts.all().iter().for_each(|rt| rt.recheck());
                        }
                        let policy = self.with_grants(&self.directives["policy"]);
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
                            self.status.fail(crate::status::OFFLINE, "E_TCP", &format!("The session with the coordinator was lost: {e}"), json!({}));
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

/// Oarbank's data: the agent's home, and the Oarbank directory it sits in by default (beside a coordinator's). No folder
/// or tool path may lie in or around it.
pub fn data_root(home: &std::path::Path) -> std::path::PathBuf {
    match home.parent() {
        Some(p) if p.file_name().is_some_and(|n| n == "Oarbank") => p.to_path_buf(),
        _ => home.to_path_buf(),
    }
}

/// The agent's own pools from its container runtimes: `containers` while the runtime can run containers (one that is not
/// ready offers none: its node is not offered container work), and `gpu` (one token) where containers get the node's
/// GPUs.
fn container_pools(rts: Option<&crate::container_runtime::Containers>) -> std::collections::BTreeMap<String, i64> {
    let mut pools = std::collections::BTreeMap::new();
    if let Some(rts) = rts {
        let tokens = rts.cpu.pool_tokens() as i64;
        if tokens > 0 {
            pools.insert("containers".to_string(), tokens);
            if rts.gpu.as_ref().is_some_and(|g| g.gpu_device().is_some()) {
                pools.insert("gpu".to_string(), 1);
            }
        }
    }
    pools
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
pub mod tests {
    use super::*;
    use crate::rescue::tests::{key, rescue_file, serve};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::Signer;

    struct PoolRuntime {
        tokens: u32,
        gpu: Option<String>,
    }

    impl crate::container_runtime::ContainerRuntime for PoolRuntime {
        fn status(&self) -> Result<crate::container_runtime::RuntimeStatus, String> {
            Err("unused".into())
        }
        fn ensure_started(&self) -> Result<(), String> {
            Ok(())
        }
        fn pull(&self, _: &str, _: &str) -> Result<(), String> {
            Ok(())
        }
        fn run(&self, _: &crate::container_runtime::RunSpec, _: &std::sync::atomic::AtomicBool)
               -> Result<crate::container_runtime::RunResult, String> {
            Err("unused".into())
        }
        fn images(&self) -> Vec<String> {
            vec![]
        }
        fn reap(&self) -> Vec<String> {
            vec![]
        }
        fn remove_attempt(&self, _: i64) -> Vec<String> {
            vec![]
        }
        fn pool_tokens(&self) -> u32 {
            self.tokens
        }
        fn gpu_device(&self) -> Option<String> {
            self.gpu.clone()
        }
    }

    /// The pools a runtime gives the node, as the agent holds it (Windows: one runtime for both kinds of job; the live
    /// GPU test checks its real runtime with it).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn pools_of(rt: Arc<dyn crate::container_runtime::ContainerRuntime>) -> std::collections::BTreeMap<String, i64> {
        container_pools(Some(&crate::container_runtime::Containers { cpu: rt.clone(), gpu: Some(rt) }))
    }

    /// A runtime that cannot run containers yet (Windows: its session is missing a prerequisite or still starting)
    /// offers no pool at all, so the node is not offered container work; a ready one offers `containers`, and `gpu`
    /// beside it where containers get the GPU.
    #[test]
    fn container_pools_only_from_a_runtime_that_can_run_them() {
        let both = |tokens, gpu: Option<&str>| {
            let rt: Arc<dyn crate::container_runtime::ContainerRuntime> = Arc::new(PoolRuntime { tokens, gpu: gpu.map(str::to_string) });
            container_pools(Some(&crate::container_runtime::Containers { cpu: rt.clone(), gpu: Some(rt) })).into_iter().collect::<Vec<_>>()
        };
        assert!(container_pools(None).is_empty());
        assert!(both(0, Some("microsoft.com/wslc=gpu")).is_empty());
        assert_eq!(both(4, None), [("containers".to_string(), 4)]);
        assert_eq!(both(4, Some("microsoft.com/wslc=gpu")), [("containers".to_string(), 4), ("gpu".to_string(), 1)]);
        let cpu: Arc<dyn crate::container_runtime::ContainerRuntime> = Arc::new(PoolRuntime { tokens: 4, gpu: None });
        assert_eq!(container_pools(Some(&crate::container_runtime::Containers { cpu, gpu: None })).len(), 1);
    }

    /// The owner key set a directive carries pins its rescue locations; a rescue move published there is recorded as
    /// The coordinator's settings: a section is checked key by key against the generated table; a refused key keeps
    /// its last value and is reported with the revision (docs/design/settings.md), nothing falls back silently.
    #[test]
    fn settings_from_the_coordinator_are_checked_and_reported() {
        use oarbank_protection::settings::{defaults, Section};
        let tmp = crate::scratch("agent-settings");
        let home = tmp.path().join("agent");
        let mut agent = Agent::open(Layout::new(home), Some("https://127.0.0.1:9")).unwrap();
        agent.set_managed(Default::default(), None);                          // whatever this machine's own policy sets
        assert_eq!(agent.directives["policy"]["job_mem_gb"], json!(1.5));      // before the first heartbeat: the table's defaults
        let mut policy = defaults(Section::Policy);
        policy["job_mem_gb"] = json!(2.5);
        let d = agent.apply_settings(&json!({"policy": policy, "limits": defaults(Section::Limits), "settings_rev": 7}));
        assert_eq!(d["policy"]["job_mem_gb"], json!(2.5));
        assert_eq!(agent.settings_report, json!({"applied_rev": 7, "rejected": []}));
        agent.directives = d;
        let mut bad = defaults(Section::Policy);
        bad["job_mem_gb"] = json!("abc");
        let d = agent.apply_settings(&json!({"policy": bad, "limits": defaults(Section::Limits), "settings_rev": 8}));
        assert_eq!(d["policy"]["job_mem_gb"], json!(2.5));                      // the last applied value, not a default
        assert_eq!(agent.settings_report["applied_rev"], json!(8));
        assert_eq!(agent.settings_report["rejected"][0]["key"], json!("job_mem_gb"));
    }

    /// A machine's managed settings only tighten what the coordinator sends, from before the first heartbeat on, and
    /// are reported with who manages it; a key managed policy may not set is refused and reported, not applied.
    #[test]
    fn managed_settings_only_tighten_the_coordinators() {
        use oarbank_protection::settings::{defaults, Section};
        let tmp = crate::scratch("agent-managed");
        let mut agent = Agent::open(Layout::new(tmp.path().join("agent")), Some("https://127.0.0.1:9")).unwrap();
        let managed = json!({"run_on_battery": false, "jobs": 4, "job_mem_gb": 3, "os_reserve_gb": "6", "enforce": "hard"});
        agent.set_managed(managed.as_object().unwrap().clone(), Some("Example".into()));
        // before the first heartbeat: the table's defaults, tightened
        assert_eq!((&agent.directives["policy"]["os_reserve_gb"], &agent.directives["limits"]["enforce"]), (&json!(6), &json!("hard")));
        assert_eq!((&agent.directives["limits"]["jobs"], &agent.directives["policy"]["job_mem_gb"]), (&json!(4), &json!(1.5)));
        let mut policy = defaults(Section::Policy);
        policy["run_on_battery"] = json!(true);
        policy["os_reserve_gb"] = json!(10);
        let mut limits = defaults(Section::Limits);
        limits["jobs"] = json!(2);
        let d = agent.apply_settings(&json!({"policy": policy, "limits": limits, "settings_rev": 3}));
        assert_eq!(d["policy"]["run_on_battery"], json!(false));                // managed off holds
        assert_eq!(d["limits"]["jobs"], json!(2));                              // managed 4 does not loosen 2
        assert_eq!(d["policy"]["os_reserve_gb"], json!(10));
        assert_eq!(d["limits"]["enforce"], json!("hard"));
        assert_eq!(d["policy"]["job_mem_gb"], json!(1.5));                      // refused: not managed
        assert_eq!(agent.settings_report, json!({"applied_rev": 3, "rejected": [],
            "managed": [{"key": "run_on_battery", "value": false, "binding": true},
                        {"key": "os_reserve_gb", "value": 6, "binding": false},
                        {"key": "jobs", "value": 4, "binding": false},
                        {"key": "enforce", "value": "hard", "binding": true}],
            "managed_refused": [{"key": "job_mem_gb", "reason": "not a setting managed policy may set"}],
            "managed_by": "Example"}));
        agent.directives = d;
        // the managed policy goes away: the coordinator's values apply at once, and the report is as without one
        agent.set_managed(Default::default(), None);
        assert_eq!((&agent.directives["policy"]["run_on_battery"], &agent.directives["limits"]["enforce"]), (&json!(true), &json!("soft")));
        agent.apply_settings(&json!({"policy": defaults(Section::Policy), "limits": defaults(Section::Limits), "settings_rev": 4}));
        assert_eq!(agent.settings_report, json!({"applied_rev": 4, "rejected": []}));
    }

    /// The doctor report always names the node's capabilities, even before a release: the coordinator grants stages
    /// whose `requires.capabilities` only on nodes that report them.
    #[test]
    fn the_doctor_report_names_the_nodes_capabilities() {
        let tmp = crate::scratch("agent-caps");
        let home = tmp.path().to_path_buf();
        let agent = Agent::open(Layout::new(home.clone()), Some("https://127.0.0.1:9")).unwrap();
        let mut rep = json!({"modules": {}});
        agent.fold_requires(&mut rep);
        assert_eq!(rep["capabilities"], json!([]));
    }

    /// The doctor report carries the GPU probe; a module whose runner needs an API this host lacks is `undetected`
    /// (never certified here; the coordinator keeps its jobs off by GPU_API_MISSING), one that needs it in containers or
    /// names none is left to its own doctor.
    #[test]
    fn the_doctor_report_names_the_gpu_apis_and_a_module_needing_another_is_undetected() {
        let tmp = crate::scratch("agent-gpuapis");
        let home = tmp.path().to_path_buf();
        let mut agent = Agent::open(Layout::new(home.clone()), Some("https://127.0.0.1:9")).unwrap();
        let mut rep = json!({"modules": {}});
        agent.fold_gpu_apis(&mut rep);
        assert_eq!(rep["gpu_apis"], json!({"host": [], "containers": [], "evidence": {}}), "not probed yet: nothing provided");
        agent.gpu_apis = json!({"host": ["metal", "opencl"], "containers": ["vulkan"], "evidence": {"metal": "Apple M4 Max"}});
        let entry = |name: &str, gpu: Value| json!({"name": name, "runner": {"gpu": gpu}});
        agent.release = Some(crate::release::Release { id: "r1".into(), dir: home.clone(), modules: vec![
            entry("cuda", json!({"use": "shared", "apis_any": ["cuda"]})),
            entry("metal", json!({"use": "exclusive", "apis_any": ["metal", "cuda"]})),
            entry("boxed", json!({"use": "exclusive", "apis_any": ["cuda"], "in_container": true})),
            entry("cpu", json!({"use": "none", "apis_any": []}))], tools: Value::Null });
        let ok = json!({"health": "healthy", "checks": []});
        let mut rep = json!({"modules": {"cuda": ok, "metal": ok, "boxed": ok, "cpu": ok}});
        agent.fold_gpu_apis(&mut rep);
        assert_eq!(rep["gpu_apis"]["host"], json!(["metal", "opencl"]));
        assert_eq!(rep["modules"]["cuda"]["health"], "undetected");
        assert_eq!(rep["modules"]["cuda"]["checks"][0],
                   json!({"name": "gpu_apis", "ok": false, "detail": "needs one of cuda on the host; this node provides metal, opencl"}));
        for m in ["metal", "boxed", "cpu"] {
            assert_eq!(rep["modules"][m], ok, "{m}");
        }
    }

    /// the pending move (and survives a restart in agent.json).
    #[tokio::test]
    async fn a_rescue_move_at_a_pinned_rescue_location_becomes_the_pending_move() {
        let tmp = crate::scratch("agent-rescue");
        let home = tmp.path().to_path_buf();
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
    }
}
