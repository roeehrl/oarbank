//! The mapping lifecycle (docs/design/inbound-listeners.md, "Port mapping"): one lifecycle per listener and address
//! family, driven by `Manager::step`, against a `Router` (the real protocol clients, or a model in the property tests).
//!
//! ```text
//!   Idle ─► (discover) ─► request ─► Mapped ─► renew / verify ─► Mapped
//!                           │  │        └ verify fails / epoch reset / expired ─► Idle (request again at once)
//!                           │  ├ conflict ─► next port (next_free) | PortTaken (refuse) | router's choice
//!                           │  └ refused ─► next protocol | Unmappable (retried with a backoff)
//!   not wanted any more / agent stop ─► release (journaled `releasing`, then removed)
//! ```
//!
//! The rules the TLA+ model (`specs/OarbankPortmap.tla`) and the property tests check:
//! - every request is journaled before it is sent (`Journal::put` before `Router::map`; a failed write sends nothing);
//! - a journal entry nobody owns is released, and a release deletes only this node's own mapping (the router's
//!   read-back for UPnP; NAT-PMP and PCP are keyed by this host's own address, and PCP by the nonce), or it waits for
//!   the lease to run out; an entry that names the same router mapping as a live lease is simply dropped;
//! - a mapping is reported (and so announced) only while its lease runs and its last verification is recent; a failed
//!   verification, an epoch reset or an expired lease makes it lost at once.

use crate::journal::{self, Entry, Journal, State};
use crate::types::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};

/// A router mapping as the router lists it, for the owner's list of mappings (UPnP only can list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterMapping {
    pub external_port: u16,
    pub internal: String,
    pub description: String,
    /// It carries this node's description prefix.
    pub ours: bool,
}

/// What the lifecycle needs from a router (the real clients in `router.rs`; a model in the property tests).
pub trait Router: Send {
    /// Which protocols answer for `family` on the current network.
    fn discover(&mut self, family: Family) -> impl Future<Output = Discovery> + Send;
    /// Create or renew a mapping (or, for IPv6 over UPnP, a pinhole: `req.pinhole` renews one).
    fn map(&mut self, proto: Proto, req: &MapReq) -> impl Future<Output = Result<Granted, MapErr>> + Send;
    /// Is the mapping still there, as ours.
    fn verify(&mut self, lease: &Lease) -> impl Future<Output = Result<Verified, MapErr>> + Send;
    /// Delete the journaled mapping if, and only if, it is this node's own. `own` is this node's current address for
    /// the entry's family (NAT-PMP and PCP can only delete from the address that made the mapping).
    fn release(&mut self, e: &Entry, own: Option<IpAddr>) -> impl Future<Output = Released> + Send;
    /// Mappings the router lists for `internal` (empty when it cannot list).
    fn list(&mut self, internal: IpAddr) -> impl Future<Output = Vec<RouterMapping>> + Send;
}

/// A mapping the router granted, as the lifecycle holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct Lease {
    pub entry_id: String,
    pub proto: Proto,
    pub family: Family,
    pub gateway: IpAddr,
    pub internal: SocketAddr,
    pub external_port: u16,
    pub external_ip: Option<IpAddr>,
    pub lifetime: u32,
    pub permanent: bool,
    pub granted_at: f64,
    pub expires_at: f64,
    pub renew_at: f64,
    pub verified_at: f64,
    pub verify_at: f64,
    pub pinhole: Option<u16>,
    pub description: String,
    /// The port the router gave is outside what the listener's fallback allows: it is asked for the next one, or
    /// released.
    pub acceptable: bool,
}

impl Lease {
    /// The same router mapping as a journal entry: NAT-PMP and PCP key mappings by the internal address and port, UPnP
    /// by the external port (a pinhole by its id).
    pub fn same_mapping(&self, e: &Entry) -> bool {
        self.proto == e.protocol && self.gateway == e.gateway && self.family == e.family && match (self.proto, self.family) {
            (Proto::Upnp, Family::Ipv4) => self.external_port == e.external_port,
            (Proto::Upnp, Family::Ipv6) => self.pinhole.is_some() && self.pinhole == e.pinhole,
            _ => self.internal == e.internal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmappable {
    /// No default gateway, or nothing answered.
    NoGateway,
    /// The gateway answers no mapping protocol.
    NoProtocol,
    /// Every protocol that answered refused.
    Refused,
    /// IPv6: the router has a firewall but no way to open it from here.
    NoPinhole,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Phase {
    Idle { at: f64 },
    Mapped(Lease),
    PortTaken { at: f64 },
    Unmappable { at: f64, why: Unmappable },
    Manual,
    NotNeeded,
}

#[derive(Debug, Clone)]
pub struct Lifecycle {
    pub want: Want,
    pub nonce: [u8; 12],
    pub phase: Phase,
    port_idx: usize,
    refused: BTreeSet<Proto>,
    attempts: u32,
    /// A journal entry this lifecycle took over from before a restart (an unanswered request): its id is reused.
    adopted: Option<String>,
    pub error: Option<String>,
    pub holder: Option<String>,
    /// The router requires the external port to equal the internal one (UPnP 724): the listener should bind it.
    pub same_port_required: bool,
    /// Bumped whenever the mapped external address or port changes (announcements, probes).
    pub changes: u64,
}

impl Lifecycle {
    fn new(want: Want, now: f64) -> Lifecycle {
        let phase = match want.mode {
            Mode::Manual => Phase::Manual,
            Mode::None => Phase::NotNeeded,
            _ => Phase::Idle { at: now },
        };
        Lifecycle { want, nonce: rand::random(), phase, port_idx: 0, refused: BTreeSet::new(), attempts: 0,
                    adopted: None, error: None, holder: None, same_port_required: false, changes: 0 }
    }

    pub fn lease(&self) -> Option<&Lease> {
        match &self.phase {
            Phase::Mapped(l) => Some(l),
            _ => None,
        }
    }

    fn due(&self) -> f64 {
        match &self.phase {
            Phase::Idle { at } | Phase::PortTaken { at } | Phase::Unmappable { at, .. } => *at,
            Phase::Mapped(l) if !l.acceptable => f64::NEG_INFINITY,
            Phase::Mapped(l) => l.renew_at.min(l.verify_at).min(l.expires_at),
            Phase::Manual | Phase::NotNeeded => f64::INFINITY,
        }
    }
}

/// What the agent reports and announces for one mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub key: String,
    pub family: Family,
    /// mapped, requesting, port_taken, unmappable, manual, not_needed.
    pub state: &'static str,
    pub protocol: Option<Proto>,
    pub gateway: Option<IpAddr>,
    pub external: Option<SocketAddr>,
    pub internal: SocketAddr,
    pub lease_s: Option<u32>,
    pub expires_at: Option<f64>,
    pub verified_at: Option<f64>,
    pub permanent: bool,
    /// The mapping is held and was verified within two verify intervals: announceable.
    pub fresh: bool,
    pub error: Option<String>,
    pub holder: Option<String>,
    pub unmappable: Option<Unmappable>,
    pub changes: u64,
}

/// One event of the lifecycle's own account (for logs and tests).
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Requested { key: String, proto: Proto, port: u16 },
    Mapped { key: String, proto: Proto, port: u16 },
    Renewed { key: String },
    Lost { key: String, why: String },
    EpochReset { proto: Proto, gateway: IpAddr },
    Released { id: String, how: Released },
    Conflict { key: String, port: u16 },
}

pub struct Manager<R: Router> {
    pub router: R,
    pub journal: Journal,
    pub timing: Timing,
    lcs: BTreeMap<(String, Family), Lifecycle>,
    disc: BTreeMap<Family, (Discovery, f64)>,
    epochs: HashMap<(Proto, IpAddr), (u32, f64)>,
    release_at: HashMap<String, f64>,
    /// This node's current address per family (NAT-PMP and PCP deletes must come from it).
    own: BTreeMap<Family, IpAddr>,
    gateway: BTreeMap<Family, Option<IpAddr>>,
    /// UPnP: the router's listing was searched for this node's stale mappings on this gateway.
    swept: BTreeSet<IpAddr>,
    /// Another mapping the router lists for this node's address (the owner's list), refreshed every 10 minutes.
    pub others: Vec<RouterMapping>,
    others_at: f64,
    pub permanent_seen: bool,
    pub node_prefix: String,
    pub events: Vec<Event>,
}

/// RFC 6887 section 8.5: the router's epoch against the client's own clock since the last answer. False: the router
/// restarted (or its clock jumped) and lost its mappings.
pub fn epoch_ok(prev: (u32, f64), cur: u32, now: f64) -> bool {
    let (e0, t0) = prev;
    if (cur as f64) + 1.0 < e0 as f64 {
        return false;
    }
    let cd = (now - t0).max(0.0);
    let sd = cur as f64 - e0 as f64;
    !(cd + 2.0 < sd - sd / 16.0 || sd + 2.0 < cd - cd / 16.0)
}

impl<R: Router> Manager<R> {
    pub fn new(router: R, journal: Journal, timing: Timing, node_prefix: &str) -> Manager<R> {
        Manager { router, journal, timing, lcs: BTreeMap::new(), disc: BTreeMap::new(), epochs: HashMap::new(),
                  release_at: HashMap::new(), own: BTreeMap::new(), gateway: BTreeMap::new(), swept: BTreeSet::new(),
                  others: vec![], others_at: f64::NEG_INFINITY, permanent_seen: false, node_prefix: node_prefix.to_string(),
                  events: vec![] }
    }

    fn event(&mut self, e: Event) {
        tracing::debug!(event = ?e, "portmap");
        self.events.push(e);
        if self.events.len() > 1000 {
            self.events.drain(..500);
        }
    }

    pub fn lifecycles(&self) -> impl Iterator<Item = &Lifecycle> {
        self.lcs.values()
    }

    pub fn discovery(&self, family: Family) -> Option<&Discovery> {
        self.disc.get(&family).map(|(d, _)| d)
    }

    /// The network as the agent sees it now: this node's address and gateway per family. A changed gateway makes every
    /// lease on the old one an orphan (released if the old gateway still answers, else left to expire) and forgets
    /// what was discovered; a changed address is a changed want (`set_wants`).
    pub fn set_network(&mut self, family: Family, own: Option<IpAddr>, gateway: Option<IpAddr>, now: f64) {
        match own {
            Some(ip) => {
                self.own.insert(family, ip);
            }
            None => {
                self.own.remove(&family);
            }
        }
        let prev = self.gateway.insert(family, gateway);
        if prev.is_some() && prev != Some(gateway) {
            self.disc.remove(&family);
            for lc in self.lcs.values_mut().filter(|l| l.want.family == family) {
                if let Phase::Mapped(l) = &lc.phase {
                    if Some(l.gateway) != gateway {
                        self.release_at.insert(l.entry_id.clone(), now);
                        lc.phase = Phase::Idle { at: now };
                        lc.refused.clear();
                        lc.port_idx = 0;
                    }
                }
            }
        }
    }

    /// The node woke from sleep (or the network changed under it): forget discoveries and verify every lease now.
    pub fn wake(&mut self, now: f64) {
        self.disc.clear();
        self.swept.clear();
        for lc in self.lcs.values_mut() {
            match &mut lc.phase {
                Phase::Mapped(l) => l.verify_at = now,
                Phase::Idle { at } | Phase::PortTaken { at } | Phase::Unmappable { at, .. } => *at = at.min(now),
                _ => {}
            }
        }
    }

    /// A NAT-PMP announcement (UDP 5350): the router's epoch and its external address.
    pub fn announcement(&mut self, gateway: IpAddr, epoch: u32, external: IpAddr, now: f64) {
        if !self.observe_epoch(Proto::Natpmp, gateway, epoch, now) {
            return;
        }
        for lc in self.lcs.values_mut() {
            if let Phase::Mapped(l) = &mut lc.phase {
                if l.gateway == gateway && l.family == Family::Ipv4 && l.external_ip != Some(external) {
                    l.external_ip = Some(external);
                    lc.changes += 1;
                }
                if l.proto == Proto::Upnp {
                    l.verify_at = now;
                }
            }
        }
    }

    /// The listeners' wanted mappings now. A want that went away (or moved to another address, or changed its
    /// protocol) leaves its lease as an orphan to release; a new want first takes over what the journal holds for it
    /// from before a restart.
    pub fn set_wants(&mut self, wants: Vec<Want>, now: f64) {
        let wanted: BTreeMap<(String, Family), Want> = wants.into_iter().map(|w| ((w.key.clone(), w.family), w)).collect();
        let gone: Vec<(String, Family)> = self.lcs.keys().filter(|k| !wanted.contains_key(*k)).cloned().collect();
        for k in gone {
            if let Some(lc) = self.lcs.remove(&k) {
                self.orphan(&lc, now);
            }
        }
        for (k, w) in wanted {
            match self.lcs.get_mut(&k) {
                Some(lc) if lc.want == w => {}
                Some(lc) => {
                    let keep = lc.lease().is_some_and(|l| l.internal == w.internal && l.description == w.description
                        && w.mode != Mode::Manual && w.mode != Mode::None
                        && (w.mode == Mode::Auto || w.mode == Mode::Only(l.proto))
                        && (l.family == Family::Ipv6 || w.fallback.accepts(w.external_port, l.external_port)));
                    if keep {
                        lc.want = w;
                    } else {
                        let old = lc.clone();
                        let nonce = lc.nonce;
                        *lc = Lifecycle::new(w, now);
                        lc.nonce = nonce;
                        self.orphan(&old, now);
                    }
                }
                None => {
                    let mut lc = Lifecycle::new(w, now);
                    self.adopt(&mut lc, now);
                    self.lcs.insert(k, lc);
                }
            }
        }
    }

    fn orphan(&mut self, lc: &Lifecycle, now: f64) {
        if let Some(l) = lc.lease() {
            self.release_at.insert(l.entry_id.clone(), now);
        }
        if let Some(id) = &lc.adopted {
            self.release_at.insert(id.clone(), now);
        }
    }

    fn owned_ids(&self) -> BTreeSet<String> {
        let mut s = BTreeSet::new();
        for lc in self.lcs.values() {
            if let Some(l) = lc.lease() {
                s.insert(l.entry_id.clone());
            }
            if let Some(a) = &lc.adopted {
                s.insert(a.clone());
            }
        }
        s
    }

    /// Take over the journal's entries for this want from before a restart: a held, unexpired lease is adopted (and
    /// renewed at once, which confirms it); an unanswered request lends its nonce (PCP refuses a second nonce for one
    /// mapping) and its id.
    fn adopt(&mut self, lc: &mut Lifecycle, now: f64) {
        if matches!(lc.phase, Phase::Manual | Phase::NotNeeded) {
            return;
        }
        let owned = self.owned_ids();
        let mine: Vec<Entry> = self.journal.entries().iter()
            .filter(|e| !owned.contains(&e.id) && e.key == lc.want.key && e.family == lc.want.family && e.internal == lc.want.internal
                    && e.description == lc.want.description)
            .cloned().collect();
        if let Some(e) = mine.first() {
            lc.nonce = e.nonce_bytes();
        }
        let held = mine.iter().find(|e| e.state == State::Held && e.expires_at.is_none_or(|t| t > now)
                                     && lc.want.fallback.accepts(lc.want.external_port, e.external_port));
        if let Some(e) = held {
            lc.phase = Phase::Mapped(Lease {
                entry_id: e.id.clone(), proto: e.protocol, family: e.family, gateway: e.gateway, internal: e.internal,
                external_port: e.external_port, external_ip: e.external_ip, lifetime: e.lifetime, permanent: e.permanent,
                granted_at: e.written_at, expires_at: e.expires_at.unwrap_or(f64::INFINITY), renew_at: now, verified_at: f64::NEG_INFINITY,
                verify_at: now, pinhole: e.pinhole, description: e.description.clone(), acceptable: true });
        } else if let Some(e) = mine.iter().find(|e| e.state == State::Intended) {
            // ask for the journaled port again under the same entry (TLA+ finding g)
            if let Some(i) = lc.want.fallback.ports(lc.want.external_port).iter().position(|p| *p == e.external_port) {
                lc.port_idx = i;
            }
            lc.adopted = Some(e.id.clone());
        }
    }

    /// The journal entries no lifecycle owns: to be released.
    pub fn orphans(&self) -> Vec<Entry> {
        let owned = self.owned_ids();
        self.journal.entries().iter().filter(|e| !owned.contains(&e.id)).cloned().collect()
    }

    /// Do everything that is due; returns when the next thing is due.
    pub async fn step(&mut self, now: f64) -> f64 {
        self.release_orphans(now).await;
        self.sweep(now).await;
        let keys: Vec<(String, Family)> = self.lcs.keys().cloned().collect();
        for k in keys {
            // a few rounds per lifecycle: a conflict walks to the next port, a refusal to the next protocol, at once
            for _ in 0..8 {
                let Some(lc) = self.lcs.get(&k) else { break };
                if lc.due() > now {
                    break;
                }
                let before = lc.phase.clone();
                self.act(&k, now).await;
                if self.lcs.get(&k).is_none_or(|l| l.phase == before) {
                    break;
                }
            }
        }
        self.next_due(now)
    }

    /// When something is next due (at most a minute away, so the orphans and the router's listing are looked at).
    pub fn next_due(&self, now: f64) -> f64 {
        let mut t = now + 60.0;
        for lc in self.lcs.values() {
            t = t.min(lc.due());
        }
        for (id, at) in &self.release_at {
            if self.journal.get(id).is_some() {
                t = t.min(*at);
            }
        }
        for e in self.orphans() {
            if let Some(g) = e.gone_by() {
                t = t.min(g);
            }
        }
        t.max(now)
    }

    async fn act(&mut self, k: &(String, Family), now: f64) {
        let Some(lc) = self.lcs.get(k) else { return };
        match lc.phase.clone() {
            Phase::Mapped(l) if !l.acceptable => {
                // NAT-PMP and PCP substitute a port instead of refusing: when the wanted port is held by this node's own
                // mapping from a previous address, a stable-port listener waits for it as for a conflict (above)
                let wanted = lc.want.fallback.ports(lc.want.external_port).get(lc.port_idx).copied().unwrap_or(lc.want.external_port);
                let own_old = self.journal.entries().iter().filter(|e| e.id != l.entry_id && e.external_port == wanted
                                                                       && e.description == l.description && e.internal != l.internal)
                    .filter_map(|e| e.gone_by()).fold(None::<f64>, |a, t| Some(a.map_or(t, |a| a.min(t))));
                if let (Some(until), Fallback::Refuse) = (own_old, lc.want.fallback) {
                    self.release_at.insert(l.entry_id.clone(), now);
                    let lc = self.lcs.get_mut(k).expect("present");
                    lc.error = Some(format!("port {wanted} is still held by this node's mapping from its previous address; it expires on its own"));
                    lc.phase = Phase::Idle { at: until.min(now + self.timing.port_taken_retry_s).max(now + 1.0) };
                    return;
                }
                let lc = self.lcs.get_mut(k).expect("present");
                lc.port_idx += 1;
                if lc.port_idx < lc.want.fallback.ports(lc.want.external_port).len() {
                    lc.phase = Phase::Idle { at: now };
                    // NAT-PMP and PCP: the next request names the same mapping (internal port): it replaces it; UPnP never
                    // substitutes outside AddAnyPortMapping, which accepts any port
                    if l.proto == Proto::Upnp {
                        self.release_at.insert(l.entry_id.clone(), now);
                    } else {
                        lc.adopted = Some(l.entry_id.clone());
                    }
                } else {
                    lc.phase = Phase::PortTaken { at: now + self.timing.port_taken_retry_s };
                    self.release_at.insert(l.entry_id.clone(), now);
                }
            }
            Phase::Mapped(l) if now >= l.expires_at => {
                self.lost(k, "the lease ran out before it could be renewed", now, false);
            }
            Phase::Mapped(l) if now >= l.renew_at => self.renew(k, l, now).await,
            // NAT-PMP and PCP verify by refreshing: a refresh is as cheap as a probe, re-creates a mapping the router
            // lost (a reboot too close to the last answer for the epoch to show it), and checks the epoch on the way
            Phase::Mapped(l) if now >= l.verify_at && l.proto != Proto::Upnp => self.renew(k, l, now).await,
            Phase::Mapped(l) if now >= l.verify_at => self.verify(k, l, now).await,
            Phase::Idle { .. } | Phase::PortTaken { .. } | Phase::Unmappable { .. } => self.request(k, now).await,
            _ => {}
        }
    }

    /// The mapping is gone from the router (or cannot be counted on): forget the lease and request again at once, under
    /// the same journal entry (its port, id and nonce): an entry is removed only on a delete's or a conflict's answer,
    /// never by inference, so a renewal whose answer was lost can never leave an unjournaled mapping behind (TLA+
    /// finding g). `_router_says`: the router itself said so (an epoch reset, the read-back), as opposed to a lease that
    /// ran out unrenewed.
    fn lost(&mut self, k: &(String, Family), why: &str, now: f64, _router_says: bool) {
        let Some(lc) = self.lcs.get_mut(k) else { return };
        if let Phase::Mapped(l) = &lc.phase {
            let id = l.entry_id.clone();
            lc.phase = Phase::Idle { at: now };
            lc.adopted = Some(id);
            lc.changes += 1;
            lc.error = Some(why.to_string());
            self.event(Event::Lost { key: k.0.clone(), why: why.to_string() });
        }
    }

    async fn discover(&mut self, family: Family, now: f64) -> Discovery {
        if let Some((d, at)) = self.disc.get(&family) {
            if d.any() && now - at < self.timing.discovery_ttl_s {
                return d.clone();
            }
        }
        let d = self.router.discover(family).await;
        if let Some((p, e)) = d.epoch {
            if let Some(g) = d.gateway {
                self.observe_epoch(p, g, e, now);
            }
        }
        self.disc.insert(family, (d.clone(), now));
        d
    }

    /// Record an epoch; false (and every lease on that gateway and protocol lost) when it shows a router restart.
    fn observe_epoch(&mut self, proto: Proto, gateway: IpAddr, epoch: u32, now: f64) -> bool {
        let ok = self.epochs.get(&(proto, gateway)).is_none_or(|prev| epoch_ok(*prev, epoch, now));
        self.epochs.insert((proto, gateway), (epoch, now));
        if !ok {
            self.event(Event::EpochReset { proto, gateway });
            let keys: Vec<(String, Family)> = self.lcs.iter()
                .filter(|(_, lc)| lc.lease().is_some_and(|l| l.gateway == gateway && l.proto == proto))
                .map(|(k, _)| k.clone()).collect();
            for k in keys {
                self.lost(&k, "the router restarted and lost its mappings", now, true);
            }
        }
        ok
    }

    async fn request(&mut self, k: &(String, Family), now: f64) {
        let Some(lc) = self.lcs.get(k) else { return };
        let (family, mode) = (lc.want.family, lc.want.mode);
        let d = self.discover(family, now).await;
        let lc = self.lcs.get_mut(k).expect("present");
        if family == Family::Ipv6 && d.firewall.is_some_and(|(on, _)| !on) && !d.pcp {
            lc.phase = Phase::NotNeeded;
            return;
        }
        let order: Vec<Proto> = match mode {
            Mode::Only(p) => vec![p],
            _ => vec![Proto::Pcp, Proto::Natpmp, Proto::Upnp],
        };
        let cands: Vec<Proto> = order.into_iter().filter(|p| d.has(*p) && !lc.refused.contains(p))
            .filter(|p| family == Family::Ipv4 || *p != Proto::Natpmp).collect();
        let Some(&proto) = cands.first() else {
            let why = if d.gateway.is_none() && !d.any() { Unmappable::NoGateway }
                      else if !lc.refused.is_empty() { Unmappable::Refused }
                      else if family == Family::Ipv6 { Unmappable::NoPinhole }
                      else { Unmappable::NoProtocol };
            let at = now + self.timing.backoff(lc.attempts);
            lc.attempts += 1;
            lc.refused.clear();                       // the next try starts over with every protocol
            lc.phase = Phase::Unmappable { at, why };
            self.disc.remove(&family);
            return;
        };
        // never ask for a port another listener of this node holds: a UPnP router lets one client overwrite its own
        // mapping, so two listeners on one port would silently take it from each other
        let mine: BTreeMap<u16, String> = self.lcs.iter().filter(|(kk, _)| *kk != k && kk.1 == family)
            .flat_map(|(kk, l)| l.lease().map(|x| x.external_port).into_iter()
                      .chain(l.adopted.as_ref().and_then(|a| self.journal.get(a)).map(|e| e.external_port)).map(move |p| (p, kk.0.clone())))
            .collect();
        let lc = self.lcs.get_mut(k).expect("present");
        let ports = lc.want.fallback.ports(lc.want.external_port);
        while lc.port_idx < ports.len() && mine.contains_key(&ports[lc.port_idx]) && lc.want.fallback != Fallback::Refuse {
            lc.port_idx += 1;
        }
        if lc.port_idx >= ports.len() {
            lc.phase = Phase::PortTaken { at: now + self.timing.port_taken_retry_s };
            lc.port_idx = 0;
            return;
        }
        let port = ports[lc.port_idx];
        if let Some(other) = mine.get(&port) {
            lc.holder = Some(format!("this node's listener {other}"));
            lc.error = Some(format!("port {port} is held by this node's listener {other}"));
            lc.phase = Phase::PortTaken { at: now + self.timing.port_taken_retry_s };
            return;
        }
        let lifetime = self.timing.lease(proto, family);
        let gateway = d.gateway.unwrap_or(lc.want.internal.ip());
        // an entry taken over names one router mapping: for UPnP that is its external port, so a request for another
        // port (or by another protocol) gets an entry of its own and the old one is released (read back first)
        if let Some(a) = lc.adopted.clone() {
            if self.journal.get(&a).is_some_and(|e| e.protocol != proto || (proto == Proto::Upnp && e.external_port != port)) {
                lc.adopted = None;
                self.release_at.insert(a, now);
            }
        }
        let lc = self.lcs.get_mut(k).expect("present");
        let id = lc.adopted.clone().unwrap_or_else(journal::new_id);
        let fresh_entry = lc.adopted.is_none();
        let req = MapReq { family, internal: lc.want.internal, external_port: port, any: false,
                           prefer_failure: lc.want.fallback == Fallback::Refuse, lifetime, nonce: lc.nonce,
                           description: lc.want.description.clone(), pinhole: None };
        let entry = Entry { id: id.clone(), key: k.0.clone(), family, protocol: proto, state: State::Intended, gateway,
                            internal: req.internal, external_port: port, external_ip: None, lifetime, permanent: false,
                            expires_at: None, nonce: hex::encode(req.nonce), description: req.description.clone(), pinhole: None,
                            written_at: now };
        if let Err(e) = self.journal.put(entry) {
            let lc = self.lcs.get_mut(k).expect("present");
            lc.error = Some(e);
            lc.phase = Phase::Idle { at: now + self.timing.backoff(lc.attempts) };
            lc.attempts += 1;
            return;                                   // never sent unjournaled
        }
        self.lcs.get_mut(k).expect("present").adopted = Some(id.clone());
        self.event(Event::Requested { key: k.0.clone(), proto, port });
        let r = self.router.map(proto, &req).await;
        let lc = self.lcs.get_mut(k).expect("present");
        lc.adopted = None;
        match r {
            Ok(g) if g.not_needed => {
                lc.phase = Phase::NotNeeded;
                let _ = self.journal.remove(&id);
            }
            Ok(g) => {
                let acceptable = lc.want.fallback.accepts(port, g.external_port);
                let lease = self.lease_from(&id, proto, &req, &g, now, acceptable);
                let lc = self.lcs.get_mut(k).expect("present");
                lc.phase = Phase::Mapped(lease.clone());
                lc.attempts = 0;
                lc.error = None;
                lc.holder = None;
                lc.refused.clear();
                lc.changes += 1;
                if g.permanent {
                    self.permanent_seen = true;
                }
                self.put_held(&lease, now);
                // older entries naming the same router mapping (an unanswered request before) are this one now
                let dup: Vec<String> = self.journal.entries().iter().filter(|e| e.id != id && lease.same_mapping(e))
                    .map(|e| e.id.clone()).collect();
                for d in dup {
                    let _ = self.journal.remove(&d);
                }
                if let Some(e) = g.epoch {
                    self.observe_epoch(proto, g.gateway, e, now);
                }
                self.event(Event::Mapped { key: k.0.clone(), proto, port: g.external_port });
            }
            Err(MapErr::Conflict { holder }) => {
                if fresh_entry {
                    let _ = self.journal.remove(&id);  // nothing was made
                } else {
                    self.release_at.insert(id.clone(), now);
                }
                // the port is held by this node's own older mapping, made from an address it no longer has (Wi-Fi to
                // Ethernet), which a router that deletes only for the mapping's own client will not let it delete
                // (NAT-PMP, PCP, UPnP in secure mode): a listener whose port must not change waits for that lease to
                // run out rather than reporting its own port taken; a `next_free` one walks on as for any conflict
                // (TLA+ findings d, f)
                let own_old = self.journal.entries().iter().filter(|e| e.id != id && e.protocol == proto && e.external_port == port
                                                                       && e.description == req.description && e.internal != req.internal)
                    .filter_map(|e| e.gone_by()).fold(None::<f64>, |a, t| Some(a.map_or(t, |a| a.min(t))));
                if let (Some(until), Fallback::Refuse) = (own_old, self.lcs[k].want.fallback) {
                    let lc = self.lcs.get_mut(k).expect("present");
                    lc.error = Some(format!("port {port} is still held by this node's mapping from its previous address; it expires on its own"));
                    lc.phase = Phase::Idle { at: until.min(now + self.timing.port_taken_retry_s).max(now + 1.0) };
                    self.event(Event::Conflict { key: k.0.clone(), port });
                    return;
                }
                let lc = self.lcs.get_mut(k).expect("present");
                lc.holder = holder;
                match lc.want.fallback {
                    Fallback::Refuse => {
                        lc.phase = Phase::PortTaken { at: now + self.timing.port_taken_retry_s };
                        lc.error = Some(format!("port {port} is taken on the router"));
                    }
                    Fallback::NextFree { .. } | Fallback::RouterChoice => {
                        lc.port_idx += 1;
                        lc.phase = if lc.port_idx < ports.len() { Phase::Idle { at: now } }
                                   else { Phase::PortTaken { at: now + self.timing.port_taken_retry_s } };
                        if lc.port_idx >= ports.len() {
                            lc.port_idx = 0;
                            lc.error = Some("every port of the fallback range is taken on the router".into());
                        }
                    }
                }
                self.event(Event::Conflict { key: k.0.clone(), port });
            }
            Err(MapErr::Refused(msg)) => {
                if fresh_entry {
                    let _ = self.journal.remove(&id);
                } else {
                    self.release_at.insert(id.clone(), now);
                }
                let lc = self.lcs.get_mut(k).expect("present");
                if msg.contains("same external and internal port") {
                    lc.same_port_required = true;
                }
                lc.refused.insert(proto);
                lc.error = Some(format!("{}: {msg}", proto.label()));
                lc.phase = Phase::Idle { at: now };
            }
            Err(e @ (MapErr::NoAnswer(_) | MapErr::Failed(_))) => {
                // the request may have been applied: its entry stays, and the next request reuses it (the same id and
                // nonce); released (read back first) if the listener goes away meanwhile
                lc.adopted = Some(id.clone());
                lc.error = Some(e.to_string());
                lc.phase = Phase::Idle { at: now + self.timing.backoff(lc.attempts) };
                lc.attempts += 1;
                self.disc.remove(&family);
            }
        }
    }

    fn lease_from(&self, id: &str, proto: Proto, req: &MapReq, g: &Granted, now: f64, acceptable: bool) -> Lease {
        let life = if g.permanent { 0 } else { g.lifetime.max(1) };
        let expires_at = if g.permanent { f64::INFINITY } else { now + life as f64 };
        // renew at half life (PCP: a random point between 1/2 and 5/8); a permanent mapping is only verified
        let frac = if proto == Proto::Pcp { 0.5 + 0.125 * rand::random::<f64>() } else { 0.5 };
        let renew_at = if g.permanent { f64::INFINITY } else { now + life as f64 * frac };
        Lease { entry_id: id.to_string(), proto, family: req.family, gateway: g.gateway, internal: req.internal,
                external_port: g.external_port, external_ip: g.external_ip, lifetime: life, permanent: g.permanent, granted_at: now,
                expires_at, renew_at, verified_at: now, verify_at: now + self.timing.verify_s.min(life as f64 / 2.0).max(1.0),
                pinhole: g.pinhole, description: req.description.clone(), acceptable }
    }

    fn put_held(&mut self, l: &Lease, now: f64) {
        let prev = self.journal.get(&l.entry_id).cloned();
        let e = Entry { id: l.entry_id.clone(), key: prev.as_ref().map(|p| p.key.clone()).unwrap_or_default(), family: l.family,
                        protocol: l.proto, state: State::Held, gateway: l.gateway, internal: l.internal, external_port: l.external_port,
                        external_ip: l.external_ip, lifetime: l.lifetime, permanent: l.permanent,
                        expires_at: l.expires_at.is_finite().then_some(l.expires_at),
                        nonce: prev.as_ref().map(|p| p.nonce.clone()).unwrap_or_default(), description: l.description.clone(),
                        pinhole: l.pinhole, written_at: now };
        let _ = self.journal.put(e);
    }

    async fn renew(&mut self, k: &(String, Family), l: Lease, now: f64) {
        let Some(lc) = self.lcs.get(k) else { return };
        let req = MapReq { family: l.family, internal: l.internal, external_port: l.external_port, any: false,
                           prefer_failure: lc.want.fallback == Fallback::Refuse, lifetime: self.timing.lease(l.proto, l.family),
                           nonce: lc.nonce, description: l.description.clone(), pinhole: l.pinhole };
        let r = self.router.map(l.proto, &req).await;
        match r {
            Ok(g) => {
                if let Some(e) = g.epoch {
                    // a restarted router: this answer re-created the mapping (NAT-PMP and PCP map on renewal), so it is
                    // held again below; the other leases on that router are marked lost and request again
                    self.observe_epoch(l.proto, g.gateway, e, now);
                }
                let Some(lc) = self.lcs.get_mut(k) else { return };
                let acceptable = lc.want.fallback.accepts(lc.want.external_port, g.external_port)
                    || lc.want.fallback == Fallback::RouterChoice || g.external_port == l.external_port;
                let mut lease = self.lease_from(&l.entry_id, l.proto, &req, &g, now, acceptable);
                if lease.external_ip.is_none() {
                    lease.external_ip = l.external_ip;
                }
                let lc = self.lcs.get_mut(k).expect("present");
                if lease.external_port != l.external_port || lease.external_ip != l.external_ip {
                    lc.changes += 1;
                }
                lc.phase = Phase::Mapped(lease.clone());
                lc.adopted = None;
                lc.error = None;
                if self.journal.get(&lease.entry_id).is_none() {
                    // lost meanwhile (an epoch reset removed it): journal it again before relying on it
                    let e = Entry { id: lease.entry_id.clone(), key: k.0.clone(), family: lease.family, protocol: lease.proto,
                                    state: State::Held, gateway: lease.gateway, internal: lease.internal,
                                    external_port: lease.external_port, external_ip: lease.external_ip, lifetime: lease.lifetime,
                                    permanent: lease.permanent, expires_at: lease.expires_at.is_finite().then_some(lease.expires_at),
                                    nonce: hex::encode(req.nonce), description: lease.description.clone(), pinhole: lease.pinhole,
                                    written_at: now };
                    let _ = self.journal.put(e);
                } else {
                    self.put_held(&lease, now);
                }
                self.event(Event::Renewed { key: k.0.clone() });
            }
            Err(MapErr::Conflict { holder }) => {
                // someone else holds the port now (the router restarted and another device took it)
                self.lost(k, "the router gave the port to another device", now, true);
                if let Some(lc) = self.lcs.get_mut(k) {
                    lc.holder = holder;
                }
            }
            Err(e) => {
                let lc = self.lcs.get_mut(k).expect("present");
                lc.error = Some(e.to_string());
                if let Phase::Mapped(m) = &mut lc.phase {
                    let wait = self.timing.backoff(lc.attempts).min((m.expires_at - now) / 2.0).max(1.0);
                    m.renew_at = now + wait;
                    lc.attempts += 1;
                }
            }
        }
    }

    async fn verify(&mut self, k: &(String, Family), l: Lease, now: f64) {
        match self.router.verify(&l).await {
            Ok(v) => {
                if let Some(e) = v.epoch {
                    if !self.observe_epoch(l.proto, l.gateway, e, now) {
                        return;
                    }
                }
                if !v.present {
                    self.lost(k, "the router no longer holds the mapping", now, true);
                    return;
                }
                let Some(lc) = self.lcs.get_mut(k) else { return };
                if let Phase::Mapped(m) = &mut lc.phase {
                    m.verified_at = now;
                    m.verify_at = now + self.timing.verify_s;
                    if v.external_ip.is_some() && v.external_ip != m.external_ip {
                        m.external_ip = v.external_ip;
                        lc.changes += 1;
                    }
                }
            }
            Err(e) => {
                let Some(lc) = self.lcs.get_mut(k) else { return };
                lc.error = Some(format!("verify: {e}"));
                if let Phase::Mapped(m) = &mut lc.phase {
                    m.verify_at = now + (self.timing.verify_s / 5.0).max(1.0);
                }
            }
        }
    }

    /// Release every orphan that is due, and forget those the router has certainly forgotten.
    async fn release_orphans(&mut self, now: f64) {
        let live: Vec<Lease> = self.lcs.values().filter_map(|l| l.lease().cloned()).collect();
        for e in self.orphans() {
            if e.gone_by().is_some_and(|t| t <= now) {
                let _ = self.journal.remove(&e.id);
                self.release_at.remove(&e.id);
                continue;
            }
            if live.iter().any(|l| l.same_mapping(&e)) {
                let _ = self.journal.remove(&e.id);   // the same router mapping a lease holds: nothing to delete
                self.release_at.remove(&e.id);
                continue;
            }
            if self.release_at.get(&e.id).is_some_and(|t| *t > now) {
                continue;
            }
            // a lease about to run out is left to expire: a UPnP read-back and delete are two calls, and a router that
            // drops the lease between them could give the port to another device just in time to lose it (TLA+ finding e)
            if e.protocol == Proto::Upnp && e.gone_by().is_some_and(|t| t - now < (2.0 * self.timing.release_retry_s).min(60.0)) {
                self.release_at.insert(e.id.clone(), e.gone_by().unwrap_or(now));
                continue;
            }
            let _ = self.journal.put(Entry { state: State::Releasing, ..e.clone() });
            let own = self.own.get(&e.family).copied();
            let how = self.router.release(&e, own).await;
            self.event(Event::Released { id: e.id.clone(), how });
            match how {
                Released::Deleted | Released::Absent | Released::NotOurs => {
                    let _ = self.journal.remove(&e.id);
                    self.release_at.remove(&e.id);
                }
                Released::Unreachable => {
                    self.release_at.insert(e.id.clone(), now + self.timing.release_retry_s);
                }
            }
        }
    }

    /// UPnP: once per gateway, search the router's listing for this node's own stale mappings (its description prefix
    /// and its own address) that nothing holds, and release them (read back first, like every release); also keep
    /// the owner's list of the router's other mappings for this address fresh.
    async fn sweep(&mut self, now: f64) {
        let Some((d, _)) = self.disc.get(&Family::Ipv4) else { return };
        let (Some(gw), Some(_)) = (d.gateway, d.upnp.clone()) else { return };
        let Some(own) = self.own.get(&Family::Ipv4).copied() else { return };
        let due_list = now - self.others_at >= 600.0;
        if self.swept.contains(&gw) && !due_list {
            return;
        }
        let prefix = format!("oarbank:{}:", self.node_prefix);
        let list: Vec<RouterMapping> = self.router.list(own).await.into_iter()
            .map(|mut m| { m.ours = m.description.starts_with(&prefix); m }).collect();
        self.others_at = now;
        if !self.swept.contains(&gw) {
            self.swept.insert(gw);
            // any port this node holds or journaled, by any protocol (a router may list NAT-PMP and PCP mappings too)
            let held: Vec<u16> = self.lcs.values().filter_map(|l| l.lease()).filter(|l| l.family == Family::Ipv4)
                .map(|l| l.external_port).collect();
            let journaled: Vec<u16> = self.journal.entries().iter().filter(|e| e.family == Family::Ipv4).map(|e| e.external_port).collect();
            for m in list.iter().filter(|m| m.ours) {
                if held.contains(&m.external_port) || journaled.contains(&m.external_port) {
                    continue;
                }
                // journal it as found, then release it like any orphan (the release reads it back)
                let e = Entry { id: journal::new_id(), key: m.description.trim_start_matches(&prefix).to_string(), family: Family::Ipv4,
                                protocol: Proto::Upnp, state: State::Intended, gateway: gw,
                                internal: SocketAddr::new(own, 0), external_port: m.external_port, external_ip: None, lifetime: 0,
                                permanent: true, expires_at: None, nonce: hex::encode([0u8; 12]), description: m.description.clone(),
                                pinhole: None, written_at: now };
                self.release_at.insert(e.id.clone(), now);
                let _ = self.journal.put(e);
            }
        }
        self.others = list;
    }

    /// Delete everything this node holds or journaled (agent stop, uninstall, retirement). Returns what happened to
    /// each entry; entries the router could not be asked about stay journaled for the next start.
    pub async fn release_all(&mut self, now: f64) -> Vec<(Entry, Released)> {
        let lcs = std::mem::take(&mut self.lcs);
        drop(lcs);
        let mut out = vec![];
        for e in self.journal.entries().to_vec() {
            if e.gone_by().is_some_and(|t| t <= now) {
                let _ = self.journal.remove(&e.id);
                continue;
            }
            let _ = self.journal.put(Entry { state: State::Releasing, ..e.clone() });
            let own = self.own.get(&e.family).copied();
            let how = self.router.release(&e, own).await;
            if how != Released::Unreachable {
                let _ = self.journal.remove(&e.id);
            }
            out.push((e, how));
        }
        out
    }

    /// The reports of every lifecycle.
    pub fn statuses(&self, now: f64) -> Vec<Status> {
        self.lcs.values().map(|lc| self.status_of(lc, now)).collect()
    }

    pub fn status(&self, key: &str, family: Family, now: f64) -> Option<Status> {
        self.lcs.get(&(key.to_string(), family)).map(|lc| self.status_of(lc, now))
    }

    fn status_of(&self, lc: &Lifecycle, now: f64) -> Status {
        let mut s = Status { key: lc.want.key.clone(), family: lc.want.family, state: "requesting", protocol: None, gateway: None,
                             external: None, internal: lc.want.internal, lease_s: None, expires_at: None, verified_at: None,
                             permanent: false, fresh: false, error: lc.error.clone(), holder: lc.holder.clone(), unmappable: None,
                             changes: lc.changes };
        match &lc.phase {
            Phase::Mapped(l) => {
                s.state = "mapped";
                s.protocol = Some(l.proto);
                s.gateway = Some(l.gateway);
                s.external = match (l.family, l.external_ip) {
                    (Family::Ipv6, _) => Some(SocketAddr::new(l.internal.ip(), l.internal.port())),
                    (_, Some(ip)) => Some(SocketAddr::new(ip, l.external_port)),
                    (_, None) => None,
                };
                s.lease_s = Some(l.lifetime);
                s.expires_at = l.expires_at.is_finite().then_some(l.expires_at);
                s.verified_at = l.verified_at.is_finite().then_some(l.verified_at);
                s.permanent = l.permanent;
                s.fresh = l.acceptable && now < l.expires_at && now - l.verified_at <= 2.0 * self.timing.verify_s;
            }
            Phase::Idle { .. } => {}
            Phase::PortTaken { .. } => s.state = "port_taken",
            Phase::Unmappable { why, .. } => {
                s.state = "unmappable";
                s.unmappable = Some(*why);
            }
            Phase::Manual => s.state = "manual",
            Phase::NotNeeded => s.state = "not_needed",
        }
        s
    }
}
