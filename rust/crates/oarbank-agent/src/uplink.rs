//! The site uplink (docs/design/sites.md, PLAN D55): nodes that share one internet line hold network-heavy fleet work
//! together while a protected process at their site is in an `uplink` phase, and keep to their site's budget otherwise.
//!
//! Every bulk transfer the agent makes (dataset staging from origins and the coordinator, result and checkpoint uploads,
//! releases and agent updates) goes through [`Uplink::begin`] and [`Transfer::pace`]:
//!
//! - **Held** while this node's own protected process is in a phase tagged `uplink` (seen at once through the
//!   protection crate's phase listener, never looser: an unreadable phase counts as on), while a protection rule caps
//!   staging at 0, or while the coordinator says the node's site holds (heartbeat `uplink.site`, every lease renewal).
//!   A held transfer stops between chunks (its connection idles; a resumable one picks up where it stopped) and goes on
//!   when the hold ends.
//! - **Leased** at a site: the coordinator grants at most the site's `max_transfers` leases, each paced at the site's
//!   rate share; the agent renews every `poll_s` while it holds one, and treats a lease it could not renew for
//!   `lease_ttl_s - 5` seconds (counted from when it sent the last successful renewal) as gone, so it has stopped before
//!   the coordinator frees the slot. A lease it stops using (revoked, held, gone stale) it gives back once it has
//!   stopped: a revoked lease keeps its slot on the coordinator until then (specs/OarbankSiteUplink.tla).
//! - **Paced** at the smallest of the lease's rate, the node's `staging_mbps` cap and a protection rule's staging cap.
//!
//! Transfers under [`HEAVY_MIN_BYTES`] (manifests, small results) are none of this's business. A tagged phase changing
//! on this node also asks the agent for a heartbeat at once, so the rest of the site hears of it within the bound
//! (SITE_HOLD_BOUND_S on the coordinator). The agent also reports a keyed fingerprint of its default gateway's hardware
//! address (salted with the fleet's salt from the coordinator; never the address), the evidence site suggestions use.

use crate::api::Api;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Transfers this small need no lease and are never held.
pub const HEAVY_MIN_BYTES: u64 = 8 << 20;
/// The phase tag that holds a site.
pub const TAG: &str = "uplink";
/// A lease is treated as gone this long before the coordinator's TTL runs out (by the agent's own clock).
const LEASE_MARGIN_S: f64 = 5.0;
/// How often the network fingerprint is read and reported.
const NETWORK_EVERY: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Dir {
    Up,
    Down,
}

impl Dir {
    fn as_str(self) -> &'static str {
        match self {
            Dir::Up => "up",
            Dir::Down => "down",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Site {
    id: String,
    name: String,
    hold: bool,
    why: Option<String>,
    ttl_s: f64,
    poll_s: f64,
}

struct Lease {
    mbps: Option<f64>,
    /// When the request that last granted or renewed it was sent.
    ok_sent: Instant,
    revoked: bool,
}

struct Xfer {
    kind: String,
    dir: Dir,
    total: Option<u64>,
    done: u64,
    paused: Option<String>,
}

#[derive(Default)]
struct State {
    site: Option<Site>,
    salt: Option<String>,
    /// This node's `uplink` phases that are on (or unreadable), by key.
    local: BTreeSet<String>,
    /// A protection rule caps staging at 0 now (why).
    cap_zero: Option<String>,
    /// The smallest positive staging cap (the node's `staging_mbps`, a protection rule's).
    cap_mbps: Option<f64>,
    leases: HashMap<String, Lease>,
    transfers: BTreeMap<u64, Xfer>,
    next: u64,
    /// Attempts of network-heavy stages running here.
    heavy: BTreeSet<i64>,
    /// A network-heavy workload runs here (the poller then follows the site's hold too).
    heavy_workloads: bool,
}

/// Why a transfer may not move now.
#[derive(Debug, PartialEq)]
enum Block {
    Held(String),
    NeedLease,
}

pub struct Uplink {
    st: Mutex<State>,
    wake: tokio::sync::Notify,
    /// A tagged phase changed here: the agent's loop sends a heartbeat now.
    report_now: AtomicBool,
    pub heartbeat_wake: tokio::sync::Notify,
    api: Mutex<Option<Arc<Api>>>,
    journal: Mutex<Option<Arc<oarbank_protection::DecisionJournal>>>,
    poller: AtomicBool,
}

static GLOBAL: OnceLock<Arc<Uplink>> = OnceLock::new();

/// The agent's one uplink gate (every transfer of the process goes through it).
pub fn global() -> &'static Arc<Uplink> {
    GLOBAL.get_or_init(|| Arc::new(Uplink::new()))
}

fn wall() -> f64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

impl Default for Uplink {
    fn default() -> Self {
        Self::new()
    }
}

impl Uplink {
    pub fn new() -> Self {
        Uplink { st: Mutex::new(State::default()), wake: tokio::sync::Notify::new(), report_now: AtomicBool::new(false),
                 heartbeat_wake: tokio::sync::Notify::new(), api: Mutex::new(None), journal: Mutex::new(None),
                 poller: AtomicBool::new(false) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The agent connected: transfers may ask for leases, and the poller (renewals, the network report) runs.
    pub fn set_api(self: &Arc<Self>, api: Arc<Api>) {
        *self.api.lock().unwrap_or_else(|e| e.into_inner()) = Some(api);
        if !self.poller.swap(true, Ordering::SeqCst) && tokio::runtime::Handle::try_current().is_ok() {
            let me = self.clone();
            tokio::spawn(async move { me.poll_loop().await });
        }
    }

    pub fn set_journal(&self, j: Arc<oarbank_protection::DecisionJournal>) {
        *self.journal.lock().unwrap_or_else(|e| e.into_inner()) = Some(j);
    }

    fn api(&self) -> Option<Arc<Api>> {
        self.api.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn journal(&self, kind: &str, reason: &str, detail: Value) {
        if let Some(j) = self.journal.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            j.record(kind, reason, None, detail.as_object().cloned().unwrap_or_default());
        }
    }

    /// The heartbeat reply's `uplink`: the node's site (or none) and the fleet's gateway salt.
    pub fn apply_directive(&self, d: &Value) {
        let u = &d["uplink"];
        if u.is_null() {
            return;
        }
        let mut st = self.lock();
        st.site = site_of(&u["site"]);
        if let Some(s) = u["salt"].as_str() {
            st.salt = Some(s.to_string());
        }
        if st.site.is_none() {
            st.leases.clear();
        }
        drop(st);
        self.wake.notify_waiters();
    }

    /// From each protection tick: this node's uplink phases that are on or unreadable, a protection rule's staging cap
    /// (0: held) and the node's own `staging_mbps` cap.
    pub fn set_local(&self, keys: BTreeSet<String>, rule_cap: Option<f64>, node_cap: Option<f64>) {
        let mut st = self.lock();
        let was = st.local.is_empty();
        st.local = keys;
        st.cap_zero = rule_cap.filter(|c| *c <= 0.0).map(|_| "a protection rule caps staging at 0".to_string());
        st.cap_mbps = [rule_cap, node_cap].into_iter().flatten().filter(|c| *c > 0.0).reduce(f64::min);
        let changed = was != st.local.is_empty();
        drop(st);
        if changed {
            self.report_now.store(true, Ordering::SeqCst);
            self.heartbeat_wake.notify_one();
        }
        self.wake.notify_waiters();
    }

    /// A network-heavy job started (its spec's `resources.network`), or the set of running attempts to keep.
    pub fn mark_heavy(&self, aid: i64) {
        self.lock().heavy.insert(aid);
    }

    pub fn retain_heavy(&self, live: &BTreeSet<i64>) {
        self.lock().heavy.retain(|a| live.contains(a));
    }

    pub fn set_heavy_workloads(&self, any: bool) {
        self.lock().heavy_workloads = any;
    }

    pub fn heavy(&self) -> BTreeSet<i64> {
        self.lock().heavy.clone()
    }

    /// Why this node's network-heavy jobs pause now (its own uplink phase, or its site's hold), if they do.
    pub fn jobs_held(&self) -> Option<String> {
        let st = self.lock();
        held_by(&st)
    }

    /// A tagged phase changed since the last heartbeat (the agent sends one now); clears the flag.
    pub fn take_report_now(&self) -> bool {
        self.report_now.swap(false, Ordering::SeqCst)
    }

    /// The heartbeat telemetry's `uplink`.
    pub fn report(&self) -> Value {
        let st = self.lock();
        json!({
            "site": st.site.as_ref().map(|s| s.name.clone()), "site_id": st.site.as_ref().map(|s| s.id.clone()),
            "held": held_by(&st).or_else(|| st.cap_zero.clone()),
            "local_phases": st.local.iter().collect::<Vec<_>>(),
            "cap_mbps": st.cap_mbps,
            "leases": st.leases.values().filter(|l| !l.revoked).count(),
            "heavy_jobs": st.heavy.iter().collect::<Vec<_>>(),
            "active": st.transfers.values().map(|x| json!({"kind": x.kind, "dir": x.dir.as_str(), "done": x.done,
                                                            "total": x.total, "paused": x.paused.is_some(), "why": x.paused}))
                .collect::<Vec<_>>(),
        })
    }

    fn blocked(&self, lease: Option<&str>) -> Option<Block> {
        let st = self.lock();
        if let Some(w) = held_by(&st).or_else(|| st.cap_zero.clone()) {
            return Some(Block::Held(w));
        }
        let site = st.site.as_ref()?;
        let fresh = |l: &Lease| !l.revoked && l.ok_sent.elapsed().as_secs_f64() < (site.ttl_s - LEASE_MARGIN_S).max(1.0);
        match lease.and_then(|id| st.leases.get(id)) {
            Some(l) if fresh(l) => None,
            _ => Some(Block::NeedLease),
        }
    }

    /// The pace for a transfer holding `lease` (bytes per second; None: unpaced).
    fn rate(&self, lease: Option<&str>) -> Option<f64> {
        let st = self.lock();
        let lease_mbps = lease.and_then(|id| st.leases.get(id)).and_then(|l| l.mbps);
        [lease_mbps, st.cap_mbps].into_iter().flatten().filter(|m| *m > 0.0).reduce(f64::min).map(|m| m * 1e6 / 8.0)
    }

    /// Whether transfers here are gated at all (a site or a cap): uploads then go in small chunks, so a hold stops one
    /// within a fraction of a second.
    pub fn gated(&self) -> bool {
        let st = self.lock();
        st.site.is_some() || st.cap_mbps.is_some() || st.cap_zero.is_some() || !st.local.is_empty()
    }

    /// Start a bulk transfer: waits while held, takes a lease at a site. `bytes`: its size when known (under
    /// HEAVY_MIN_BYTES it is never held).
    pub async fn begin(self: &Arc<Self>, kind: &str, dir: Dir, bytes: Option<u64>) -> Transfer {
        let light = bytes.is_some_and(|b| b < HEAVY_MIN_BYTES);
        let id = {
            let mut st = self.lock();
            st.next += 1;
            let id = st.next;
            if !light {
                st.transfers.insert(id, Xfer { kind: kind.into(), dir, total: bytes, done: 0, paused: None });
            }
            id
        };
        let mut t = Transfer { up: self.clone(), id, kind: kind.into(), dir, total: bytes, light, lease: None, done: 0,
                               started: Instant::now(), pace_from: None, paced_bytes: 0, paced_rate: None,
                               paused_at: None, was_paced: false };
        if !light {
            t.gate().await;
        }
        t
    }

    async fn ask_lease(&self, kind: &str, dir: Dir, bytes: Option<u64>) -> Result<(String, Option<f64>), Duration> {
        let Some(api) = self.api() else { return Err(Duration::from_secs(2)) };
        let sent = Instant::now();
        match api.post("/v1/agent/uplink/lease", &json!({"kind": kind, "dir": dir.as_str(), "bytes": bytes})).await {
            Ok(r) => {
                self.lock().site = site_of(&r["site"]);
                if r["granted"].as_bool() == Some(true) {
                    let Some(id) = r["lease_id"].as_str() else { return Ok((String::new(), None)) };
                    let mbps = r["mbps"].as_f64();
                    self.lock().leases.insert(id.to_string(), Lease { mbps, ok_sent: sent, revoked: false });
                    return Ok((id.to_string(), mbps));
                }
                Err(Duration::from_secs_f64(r["retry_s"].as_f64().unwrap_or(2.0).clamp(0.5, 30.0)))
            }
            Err(_) => Err(Duration::from_secs(2)),
        }
    }

    async fn wait(&self, d: Duration) {
        let _ = tokio::time::timeout(d, self.wake.notified()).await;
    }

    /// Renew the leases, learn the site's state, and report the network now and then (runs once per agent).
    async fn poll_loop(self: Arc<Self>) {
        let mut last_net: Option<Instant> = None;
        loop {
            let (poll, ids, need) = {
                let st = self.lock();
                let poll = st.site.as_ref().map(|s| s.poll_s).unwrap_or(2.0).clamp(0.5, 10.0);
                let ids: Vec<String> = st.leases.iter().filter(|(_, l)| !l.revoked).map(|(k, _)| k.clone()).collect();
                (poll, ids.clone(), st.site.is_some() && (!ids.is_empty() || !st.heavy.is_empty() || st.heavy_workloads
                                                         || !st.transfers.is_empty()))
            };
            if need {
                self.renew(ids).await;
            }
            if last_net.is_none_or(|t| t.elapsed() >= NETWORK_EVERY) {
                let salt = self.lock().salt.clone();
                if let (Some(salt), Some(api)) = (salt, self.api()) {
                    last_net = Some(Instant::now());
                    let mac = tokio::task::spawn_blocking(gateway_mac).await.ok().flatten();
                    let body = match mac {
                        Some(m) => json!({"gateway_fp": gateway_fp(&salt, &m)}),
                        None => json!({}),
                    };
                    let _ = api.post("/v1/agent/uplink/network", &body).await;
                }
            }
            tokio::time::sleep(Duration::from_secs_f64(poll)).await;
        }
    }

    async fn renew(&self, ids: Vec<String>) {
        let Some(api) = self.api() else { return };
        let sent = Instant::now();
        if let Ok(r) = api.post("/v1/agent/uplink/renew", &json!({"leases": ids})).await {
            let mut st = self.lock();
            st.site = site_of(&r["site"]);
            for (id, v) in r["leases"].as_object().into_iter().flatten() {
                if let Some(l) = st.leases.get_mut(id) {
                    if v == "ok" {
                        l.ok_sent = sent;
                    } else {
                        l.revoked = true;
                    }
                }
            }
            drop(st);
            self.wake.notify_waiters();
        }
    }
}

fn site_of(v: &Value) -> Option<Site> {
    let id = v["id"].as_str()?;
    Some(Site { id: id.into(), name: v["name"].as_str().unwrap_or(id).into(), hold: v["hold"].as_bool() == Some(true),
                why: v["why"].as_str().map(str::to_string), ttl_s: v["lease_ttl_s"].as_f64().unwrap_or(20.0),
                poll_s: v["poll_s"].as_f64().unwrap_or(2.0) })
}

fn held_by(st: &State) -> Option<String> {
    if !st.local.is_empty() {
        return Some(format!("this node's protected process is in an upload phase ({})",
                            st.local.iter().cloned().collect::<Vec<_>>().join(", ")));
    }
    st.site.as_ref().filter(|s| s.hold).map(|s| format!("site {}: {}", s.name, s.why.as_deref().unwrap_or("an uplink phase")))
}

/// One bulk transfer: call [`Transfer::pace`] before each chunk; dropping it gives its lease back.
pub struct Transfer {
    up: Arc<Uplink>,
    id: u64,
    kind: String,
    dir: Dir,
    total: Option<u64>,
    light: bool,
    lease: Option<String>,
    done: u64,
    started: Instant,
    pace_from: Option<Instant>,
    paced_bytes: u64,
    paced_rate: Option<f64>,
    paused_at: Option<(Instant, f64)>,
    was_paced: bool,
}

impl Transfer {
    /// Wait until the transfer may move: no hold, and a live lease at a site.
    async fn gate(&mut self) {
        loop {
            match self.up.blocked(self.lease.as_deref()) {
                None => break,
                Some(Block::Held(why)) => {
                    self.mark_paused(&why);
                    self.drop_lease();
                    self.up.wait(Duration::from_millis(500)).await;
                }
                Some(Block::NeedLease) => {
                    if self.lease.is_some() && self.done > 0 {
                        self.mark_paused("its transfer lease was revoked or could not be renewed");
                    }
                    self.drop_lease();
                    match self.up.ask_lease(&self.kind, self.dir, self.total).await {
                        Ok((id, _)) if id.is_empty() => break,               // the node is at no site any more
                        Ok((id, _)) => self.lease = Some(id),
                        Err(retry) => {
                            if self.done > 0 && self.paused_at.is_none() {
                                self.mark_paused("waiting for a transfer lease");
                            }
                            self.up.wait(retry).await;
                        }
                    }
                }
            }
        }
        if let Some((at, wall_at)) = self.paused_at.take() {
            let s = (at.elapsed().as_secs_f64() * 10.0).round() / 10.0;
            self.up.journal("transfer_resumed", "TRANSFER_RESUMED", json!({"transfer": self.kind, "dir": self.dir.as_str(),
                "paused_s": s, "paused_at": wall_at, "done": self.done}));
            if let Some(x) = self.up.lock().transfers.get_mut(&self.id) {
                x.paused = None;
            }
            self.pace_from = None;
        }
    }

    fn mark_paused(&mut self, why: &str) {
        if self.paused_at.is_some() {
            return;
        }
        let t = wall();
        self.paused_at = Some((Instant::now(), t));
        if let Some(x) = self.up.lock().transfers.get_mut(&self.id) {
            x.paused = Some(why.to_string());
        }
        tracing::info!(kind = %self.kind, why, "transfer paused");
        self.up.journal("transfer_paused", "TRANSFER_PAUSED", json!({"transfer": self.kind, "dir": self.dir.as_str(), "why": why,
                                                                     "done": self.done, "paused_at": t}));
    }

    /// Stop using the lease (between chunks: nothing moves now) and give it back, so a revoked lease's slot frees as
    /// soon as the coordinator hears it; a lost give-back costs the slot until the lease expires.
    fn drop_lease(&mut self) {
        if let Some(id) = self.lease.take() {
            self.up.lock().leases.remove(&id);
            if let (Some(api), Ok(h)) = (self.up.api(), tokio::runtime::Handle::try_current()) {
                h.spawn(async move {
                    let _ = api.post("/v1/agent/uplink/release", &json!({"lease_id": id})).await;
                });
            }
        }
    }

    /// Before sending or writing `n` more bytes: wait out a hold or a lost lease, then keep to the pace.
    pub async fn pace(&mut self, n: usize) {
        if self.light {
            return;
        }
        self.gate().await;
        let rate = self.up.rate(self.lease.as_deref());
        if rate != self.paced_rate || self.pace_from.is_none() {
            self.paced_rate = rate;
            self.pace_from = Some(Instant::now());
            self.paced_bytes = 0;
        }
        if let (Some(r), Some(from)) = (rate, self.pace_from) {
            self.was_paced = true;
            self.paced_bytes += n as u64;
            loop {
                let due = Duration::from_secs_f64(self.paced_bytes as f64 / r);
                let el = from.elapsed();
                if due <= el {
                    break;
                }
                tokio::time::sleep((due - el).min(Duration::from_millis(200))).await;
                if self.up.blocked(self.lease.as_deref()).is_some() {
                    self.gate().await;
                    self.pace_from = Some(Instant::now());
                    self.paced_bytes = n as u64;
                    break;
                }
            }
        }
        self.done += n as u64;
        if let Some(x) = self.up.lock().transfers.get_mut(&self.id) {
            x.done = self.done;
        }
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        let mut st = self.up.lock();
        st.transfers.remove(&self.id);
        let lease = self.lease.take();
        if let Some(id) = &lease {
            st.leases.remove(id);
        }
        drop(st);
        if let (Some(id), Some(api), Ok(h)) = (lease, self.up.api(), tokio::runtime::Handle::try_current()) {
            let body = json!({"lease_id": id, "kind": self.kind, "dir": self.dir.as_str(), "bytes": self.done,
                              "seconds": self.started.elapsed().as_secs_f64(), "paced": self.was_paced});
            h.spawn(async move {
                let _ = api.post("/v1/agent/uplink/release", &body).await;
            });
        }
        self.up.wake.notify_waiters();
    }
}

/// The protection crate's phase listener: an `uplink` phase turning on holds this node's transfers at once and asks
/// for a heartbeat now, so the coordinator holds the rest of the site.
pub struct Listener(pub Arc<Uplink>);

impl oarbank_protection::PhaseListener for Listener {
    fn phase_changed(&self, key: &str, on: bool, tags: &[String], _event_t: f64) {
        if !tags.iter().any(|t| t == TAG) {
            return;
        }
        let mut st = self.0.lock();
        if on {
            st.local.insert(key.to_string());
        } else {
            st.local.remove(key);
        }
        drop(st);
        self.0.report_now.store(true, Ordering::SeqCst);
        self.0.heartbeat_wake.notify_one();
        self.0.wake.notify_waiters();
    }
}

// ---------------------------------------------------------------------------- the network fingerprint

/// HMAC-SHA256 (RFC 2104) over `msg` with `key`.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let (mut inner, mut outer) = (Sha256::new(), Sha256::new());
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// The fingerprint the node reports for its default gateway: keyed with the fleet's salt, so nodes behind one gateway
/// agree and nobody outside the fleet can match it against a hardware address.
pub fn gateway_fp(salt: &str, mac: &str) -> String {
    hex::encode(&hmac_sha256(salt.as_bytes(), format!("gateway:{mac}").as_bytes())[..16])
}

/// A hardware address in one form: six lower-case two-digit octets joined by colons (`0:1b:...` and `00-1B-...` agree).
fn norm_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let octets: Option<Vec<u8>> = parts.iter().map(|p| u8::from_str_radix(p, 16).ok()).collect();
    let o = octets?;
    if o.iter().all(|b| *b == 0) || o.iter().all(|b| *b == 0xff) {
        return None;
    }
    Some(o.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

/// `route -n get default` (macOS): the gateway's address.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_route_get(out: &str) -> Option<String> {
    out.lines().find_map(|l| l.trim().strip_prefix("gateway:").map(|g| g.trim().to_string())).filter(|g| !g.is_empty())
}

/// `arp -n <ip>` (macOS) or `arp -a <ip>` (Windows): the hardware address on the line naming `ip`.
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn parse_arp(out: &str, ip: &str) -> Option<String> {
    out.lines().filter(|l| l.split(|c: char| c.is_whitespace() || c == '(' || c == ')').any(|w| w == ip))
        .flat_map(|l| l.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        .find_map(|w| norm_mac(&w))
}

/// /proc/net/route (Linux): the default route's gateway (hex, little-endian).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_route(text: &str) -> Option<String> {
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 2 && f[1] == "00000000" && f[2] != "00000000" {
            let v = u32::from_str_radix(f[2], 16).ok()?;
            Some(std::net::Ipv4Addr::from(v.to_le_bytes()).to_string())
        } else {
            None
        }
    })
}

/// /proc/net/arp (Linux): `IP HWtype Flags HWaddress Mask Device`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_arp(text: &str, ip: &str) -> Option<String> {
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 3 && f[0] == ip).then(|| norm_mac(f[3])).flatten()
    })
}

/// `route print -4 0.0.0.0` (Windows): the first default route's gateway (its numeric table is the same in every
/// language; an on-link route has none).
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_route_print(out: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() >= 5 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" && f[2].parse::<std::net::Ipv4Addr>().is_ok())
            .then(|| f[2].to_string())
    })
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn run(prog: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(prog).args(args).stdin(std::process::Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The default gateway's hardware address, read from the OS's route and neighbour tables (nothing is sent anywhere).
pub fn gateway_mac() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let gw = parse_route_get(&run("/sbin/route", &["-n", "get", "default"])?)?;
        parse_arp(&run("/usr/sbin/arp", &["-n", &gw])?, &gw)
    }
    #[cfg(target_os = "linux")]
    {
        let gw = parse_proc_route(&std::fs::read_to_string("/proc/net/route").ok()?)?;
        parse_proc_arp(&std::fs::read_to_string("/proc/net/arp").ok()?, &gw)
    }
    #[cfg(windows)]
    {
        let gw = parse_route_print(&run("route.exe", &["print", "-4", "0.0.0.0"])?)?;
        parse_arp(&run("arp.exe", &["-a", &gw])?, &gw)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        assert_eq!(hex::encode(hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
                   "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn the_gateway_is_read_from_each_os_table() {
        let mac_route = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.7.1\n  interface: en0\n";
        assert_eq!(parse_route_get(mac_route).as_deref(), Some("192.168.7.1"));
        let mac_arp = "? (192.168.7.1) at 4:d9:f5:a:b:c on en0 ifscope [ethernet]\n";
        assert_eq!(parse_arp(mac_arp, "192.168.7.1").as_deref(), Some("04:d9:f5:0a:0b:0c"));
        assert_eq!(parse_arp("? (192.168.7.1) at (incomplete) on en0 ifscope [ethernet]\n", "192.168.7.1"), None);
        let route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\nwlan0\t00000000\t0107A8C0\t0003\t0\t0\t600\t00000000\nwlan0\t0007A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n";
        assert_eq!(parse_proc_route(route).as_deref(), Some("192.168.7.1"));
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n192.168.7.1      0x1         0x2         04:D9:F5:0A:0B:0C     *        wlan0\n";
        assert_eq!(parse_proc_arp(arp, "192.168.7.1").as_deref(), Some("04:d9:f5:0a:0b:0c"));
        let print = "IPv4 Route Table\n===\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.7.1    192.168.7.20     25\n";
        assert_eq!(parse_route_print(print).as_deref(), Some("192.168.7.1"));
        let win_arp = "\nInterface: 192.168.7.20 --- 0x5\n  Internet Address      Physical Address      Type\n  192.168.7.1           04-d9-f5-0a-0b-0c     dynamic\n";
        assert_eq!(parse_arp(win_arp, "192.168.7.1").as_deref(), Some("04:d9:f5:0a:0b:0c"));
        // one gateway, one fingerprint, whatever the notation; another salt, another fingerprint
        assert_eq!(gateway_fp("s", "04:d9:f5:0a:0b:0c"), gateway_fp("s", &norm_mac("04-D9-F5-0A-0B-0C").unwrap()));
        assert_ne!(gateway_fp("s", "04:d9:f5:0a:0b:0c"), gateway_fp("t", "04:d9:f5:0a:0b:0c"));
        assert_eq!(gateway_fp("s", "04:d9:f5:0a:0b:0c").len(), 32);
    }

    fn site(hold: bool) -> Value {
        json!({"uplink": {"site": {"id": "site_1", "name": "home", "hold": hold, "why": "mini's rule t is in an upload phase",
                                   "lease_ttl_s": 20.0, "poll_s": 2.0}, "salt": "x"}})
    }

    #[tokio::test]
    async fn a_local_phase_holds_a_transfer_until_it_ends_and_small_ones_never_wait() {
        let up = Arc::new(Uplink::new());
        up.set_local(BTreeSet::from(["t#0".to_string()]), None, None);
        assert!(up.take_report_now(), "a tagged phase asks for a heartbeat at once");
        // a small transfer is never held
        let small = tokio::time::timeout(Duration::from_millis(200), up.begin("staging", Dir::Down, Some(1024))).await;
        assert!(small.is_ok());
        let up2 = up.clone();
        let big = tokio::spawn(async move {
            let mut t = up2.begin("staging", Dir::Down, Some(64 << 20)).await;
            t.pace(1 << 20).await;
            Instant::now()
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!big.is_finished(), "held while the phase is on");
        assert!(up.report()["active"][0]["paused"].as_bool().unwrap());
        let off = Instant::now();
        up.set_local(BTreeSet::new(), None, None);
        let went = tokio::time::timeout(Duration::from_secs(5), big).await.unwrap().unwrap();
        assert!(went >= off);
        assert_eq!(up.report()["active"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn a_site_without_a_lease_waits_and_a_hold_names_the_site() {
        let up = Arc::new(Uplink::new());
        up.apply_directive(&site(true));
        assert!(up.jobs_held().unwrap().contains("site home"));
        assert_eq!(up.blocked(None), Some(Block::Held("site home: mini's rule t is in an upload phase".into())));
        up.apply_directive(&site(false));
        assert_eq!(up.jobs_held(), None);
        assert_eq!(up.blocked(None), Some(Block::NeedLease), "at a site every bulk transfer needs a lease");
        up.lock().leases.insert("l".into(), Lease { mbps: Some(8.0), ok_sent: Instant::now(), revoked: false });
        assert_eq!(up.blocked(Some("l")), None);
        assert_eq!(up.rate(Some("l")), Some(1e6));
        up.lock().leases.get_mut("l").unwrap().ok_sent = Instant::now() - Duration::from_secs(16);
        assert_eq!(up.blocked(Some("l")), Some(Block::NeedLease), "a lease not renewed for TTL - 5 s is gone");
        up.apply_directive(&json!({"uplink": {"site": null, "salt": "x"}}));
        assert_eq!(up.blocked(None), None);
    }

    #[tokio::test]
    async fn a_cap_paces_and_a_zero_cap_holds() {
        let up = Arc::new(Uplink::new());
        up.set_local(BTreeSet::new(), Some(0.0), Some(100.0));
        assert!(matches!(up.blocked(None), Some(Block::Held(_))));
        up.set_local(BTreeSet::new(), Some(16.0), Some(100.0));
        assert_eq!(up.rate(None), Some(2e6));
        let mut t = up.begin("upload", Dir::Up, None).await;
        let t0 = Instant::now();
        for _ in 0..4 {
            t.pace(250_000).await;                       // 1 MB at 2 MB/s
        }
        let el = t0.elapsed().as_secs_f64();
        assert!((0.35..3.0).contains(&el), "{el}");
    }
}
