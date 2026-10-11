//! Property tests of the lifecycle against a model router, in virtual time: random sequences of steps, router
//! reboots, agent crashes and restarts from the journal, lost answers, a router that goes silent, foreign mappings on the
//! wanted ports, network changes, external address changes and listeners coming and going. After every action the
//! TLA+ model's properties (specs/OarbankPortmap.tla) are checked on the trace:
//!
//! - NoForeignDelete: no mapping made by another device is ever deleted;
//! - AnnouncedImpliesMapped: a mapping reported fresh (announceable) is on the router, or was lost less than two verify
//!   intervals ago;
//! - AtMostOneExternalPortPerListener: the router never holds two mappings of one listener for its current address;
//! - EventuallyClean: once nothing is wanted and the router answers, the router soon holds nothing of this node and
//!   the journal is empty.
//!
//! The same model runs a 72-hour soak in virtual time.

use crate::journal::{Entry, Journal};
use crate::manager::{Lease, Manager, RouterMapping, Router};
use crate::types::*;
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

const GW: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

#[derive(Debug, Clone)]
struct M {
    proto: Proto,
    ext: u16,
    internal: SocketAddr,
    desc: String,
    expires: f64,
    nonce: [u8; 12],
    foreign: bool,
}

#[derive(Debug, Default)]
struct MState {
    now: f64,
    maps: Vec<M>,
    epoch_start: f64,
    pcp: bool,
    natpmp: bool,
    upnp: bool,
    permanent_only: bool,
    silent: bool,
    lose_next: bool,
    foreign_deleted: u32,
    ext_ip: u8,
}

impl MState {
    fn expire(&mut self) {
        let now = self.now;
        self.maps.retain(|m| m.expires > now);
    }

    fn epoch(&self) -> u32 {
        (self.now - self.epoch_start).max(0.0) as u32 + 100
    }

    fn ext(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, self.ext_ip.max(1)))
    }

    fn delete(&mut self, f: impl Fn(&M) -> bool) {
        let before = self.maps.len();
        let foreign = self.maps.iter().filter(|m| f(m) && m.foreign).count() as u32;
        self.foreign_deleted += foreign;
        self.maps.retain(|m| !f(m));
        let _ = before;
    }

    fn free(&self, from: u16, me: &dyn Fn(&M) -> bool) -> u16 {
        (from..u16::MAX).find(|p| !self.maps.iter().any(|m| m.ext == *p && !me(m))).unwrap_or(0)
    }
}

#[derive(Clone)]
struct ModelRouter(Arc<Mutex<MState>>);

impl ModelRouter {
    fn s(&self) -> std::sync::MutexGuard<'_, MState> {
        self.0.lock().unwrap()
    }
}

impl Router for ModelRouter {
    async fn discover(&mut self, family: Family) -> Discovery {
        let s = self.s();
        if s.silent || family == Family::Ipv6 {
            return Discovery { gateway: Some(GW), ..Default::default() };
        }
        Discovery { gateway: Some(GW), pcp: s.pcp, natpmp: s.natpmp, upnp: s.upnp.then(|| "IGD:2".into()), external_ip: Some(s.ext()),
                    epoch: (s.pcp || s.natpmp).then(|| (if s.pcp { Proto::Pcp } else { Proto::Natpmp }, s.epoch())), firewall: None }
    }

    async fn map(&mut self, proto: Proto, req: &MapReq) -> Result<Granted, MapErr> {
        let mut s = self.s();
        s.expire();
        if s.silent {
            return Err(MapErr::NoAnswer("silent".into()));
        }
        let now = s.now;
        let epoch = s.epoch();
        let ext_ip = s.ext();
        let r = match proto {
            Proto::Natpmp | Proto::Pcp => {
                let me = |m: &M| m.proto == proto && m.internal == req.internal;
                if let Some(i) = s.maps.iter().position(|m| me(m)) {
                    if proto == Proto::Pcp && s.maps[i].nonce != req.nonce {
                        return Err(MapErr::Refused("NotAuthorized".into()));
                    }
                    s.maps[i].expires = now + req.lifetime as f64;
                    let ext = s.maps[i].ext;
                    Ok(Granted { gateway: GW, external_port: ext, external_ip: Some(ext_ip), lifetime: req.lifetime, permanent: false,
                                 epoch: Some(epoch), pinhole: None, not_needed: false })
                } else {
                    let taken = s.maps.iter().any(|m| m.ext == req.external_port && !me(m));
                    if taken && proto == Proto::Pcp && req.prefer_failure {
                        return Err(MapErr::Conflict { holder: None });
                    }
                    let port = if taken { s.free(req.external_port, &me) } else { req.external_port };
                    s.maps.push(M { proto, ext: port, internal: req.internal, desc: req.description.clone(), expires: now + req.lifetime as f64,
                                    nonce: req.nonce, foreign: false });
                    Ok(Granted { gateway: GW, external_port: port, external_ip: Some(ext_ip), lifetime: req.lifetime, permanent: false,
                                 epoch: Some(epoch), pinhole: None, not_needed: false })
                }
            }
            Proto::Upnp => {
                let me = |m: &M| m.proto == Proto::Upnp && m.internal.ip() == req.internal.ip();
                let port = if req.any { s.free(req.external_port, &me) } else { req.external_port };
                if !req.any && s.maps.iter().any(|m| m.ext == port && !me(m)) {
                    return Err(MapErr::Conflict { holder: Some("someone".into()) });
                }
                let permanent = s.permanent_only;
                s.maps.retain(|m| !(m.ext == port && me(m)));
                s.maps.push(M { proto, ext: port, internal: req.internal, desc: req.description.clone(),
                                expires: if permanent { f64::INFINITY } else { now + req.lifetime as f64 }, nonce: req.nonce, foreign: false });
                Ok(Granted { gateway: GW, external_port: port, external_ip: Some(ext_ip), lifetime: if permanent { 0 } else { req.lifetime },
                             permanent, epoch: None, pinhole: None, not_needed: false })
            }
        };
        if std::mem::take(&mut s.lose_next) {
            return Err(MapErr::NoAnswer("lost answer".into()));
        }
        r
    }

    async fn verify(&mut self, l: &Lease) -> Result<Verified, MapErr> {
        let mut s = self.s();
        s.expire();
        if s.silent {
            return Err(MapErr::NoAnswer("silent".into()));
        }
        match l.proto {
            Proto::Upnp => {
                let present = s.maps.iter().any(|m| m.ext == l.external_port && m.internal.ip() == l.internal.ip() && m.desc == l.description);
                Ok(Verified { present, external_ip: Some(s.ext()), epoch: None })
            }
            _ => Ok(Verified { present: true, external_ip: Some(s.ext()), epoch: Some(s.epoch()) }),
        }
    }

    async fn release(&mut self, e: &Entry, own: Option<IpAddr>) -> Released {
        let mut s = self.s();
        s.expire();
        if s.silent {
            return Released::Unreachable;
        }
        match e.protocol {
            Proto::Upnp => match s.maps.iter().find(|m| m.ext == e.external_port).cloned() {
                None => Released::Absent,
                Some(m) if m.internal.ip() != e.internal.ip() || m.desc != e.description => Released::NotOurs,
                Some(_) => {
                    let p = e.external_port;
                    s.delete(|m| m.ext == p);
                    Released::Deleted
                }
            },
            p => {
                if own != Some(e.internal.ip()) {
                    return Released::Unreachable;
                }
                let n = e.nonce_bytes();
                match s.maps.iter().find(|m| m.proto == p && m.internal == e.internal).cloned() {
                    None => Released::Absent,
                    Some(m) if p == Proto::Pcp && m.nonce != n => Released::NotOurs,
                    Some(_) => {
                        let i = e.internal;
                        s.delete(|m| m.proto == p && m.internal == i);
                        Released::Deleted
                    }
                }
            }
        }
    }

    async fn list(&mut self, internal: IpAddr) -> Vec<RouterMapping> {
        let mut s = self.s();
        s.expire();
        if s.silent || !s.upnp {
            return vec![];
        }
        s.maps.iter().filter(|m| m.internal.ip() == internal)
            .map(|m| RouterMapping { external_port: m.ext, internal: m.internal.to_string(), description: m.desc.clone(), ours: false }).collect()
    }
}

fn timing() -> Timing {
    Timing { lease_pcp: 7200, lease_natpmp: 7200, lease_upnp: 3600, lease_pinhole: 3600, verify_s: 300.0, discovery_ttl_s: 600.0,
             retry_min_s: 5.0, retry_max_s: 600.0, port_taken_retry_s: 600.0, release_retry_s: 30.0 }
}

#[derive(Debug, Clone)]
enum Act {
    Step(u32),
    Reboot,
    Crash,
    Toggle(usize),
    Rebind(u8),
    Foreign(u16),
    DropForeign,
    LoseNext,
    Silent(bool),
    ExtIp(u8),
}

fn act() -> impl Strategy<Value = Act> {
    prop_oneof![
        6 => (1u32..900).prop_map(Act::Step),
        1 => Just(Act::Reboot),
        1 => Just(Act::Crash),
        2 => (0usize..3).prop_map(Act::Toggle),
        1 => (20u8..23).prop_map(Act::Rebind),
        1 => (9000u16..9004).prop_map(Act::Foreign),
        1 => Just(Act::DropForeign),
        1 => Just(Act::LoseNext),
        1 => any::<bool>().prop_map(Act::Silent),
        1 => (1u8..4).prop_map(Act::ExtIp),
    ]
}

struct World {
    state: Arc<Mutex<MState>>,
    m: Manager<ModelRouter>,
    wanted: [bool; 3],
    host: u8,
    absent_since: std::collections::HashMap<String, f64>,
    max_dt: f64,
}

const KEYS: [&str; 3] = ["mod/a", "mod/b", "mod/c"];

impl World {
    fn new(pcp: bool, natpmp: bool, upnp: bool, permanent_only: bool) -> World {
        let state = Arc::new(Mutex::new(MState { now: 1_000_000.0, epoch_start: 1_000_000.0 - 500.0, pcp, natpmp, upnp, permanent_only,
                                                 ext_ip: 1, ..Default::default() }));
        let m = Manager::new(ModelRouter(state.clone()), Journal::memory(), timing(), "n1model");
        let mut w = World { state, m, wanted: [true, true, false], host: 20, absent_since: Default::default(), max_dt: 900.0 };
        w.apply_wants();
        w
    }

    fn now(&self) -> f64 {
        self.state.lock().unwrap().now
    }

    fn own(&self) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, self.host))
    }

    fn wants(&self) -> Vec<Want> {
        let fb = [Fallback::Refuse, Fallback::NextFree { lo: 9001, hi: 9004 }, Fallback::RouterChoice];
        KEYS.iter().enumerate().filter(|(i, _)| self.wanted[*i]).map(|(i, k)| Want {
            key: k.to_string(), family: Family::Ipv4, internal: SocketAddr::new(self.own(), 41000 + i as u16), external_port: 9000 + i as u16,
            fallback: fb[i], mode: Mode::Auto, description: description("n1model", k) }).collect()
    }

    fn apply_wants(&mut self) {
        let now = self.now();
        self.m.set_network(Family::Ipv4, Some(self.own()), Some(GW), now);
        let w = self.wants();
        self.m.set_wants(w, now);
    }

    async fn step(&mut self, dt: f64) {
        let now = { let mut s = self.state.lock().unwrap(); s.now += dt; s.now };
        self.m.step(now).await;
    }

    async fn apply(&mut self, a: &Act) {
        match a {
            Act::Step(dt) => self.step(*dt as f64).await,
            Act::Reboot => {
                let mut s = self.state.lock().unwrap();
                s.maps.retain(|m| m.foreign);
                s.epoch_start = s.now;
            }
            Act::Crash => {
                let j = self.m.journal.clone();
                self.m = Manager::new(ModelRouter(self.state.clone()), j, timing(), "n1model");
                self.apply_wants();
            }
            Act::Toggle(i) => {
                self.wanted[*i] = !self.wanted[*i];
                self.apply_wants();
            }
            Act::Rebind(h) => {
                self.host = *h;
                self.apply_wants();
            }
            Act::Foreign(p) => {
                let mut s = self.state.lock().unwrap();
                let now = s.now;
                if !s.maps.iter().any(|m| m.ext == *p) {
                    s.maps.push(M { proto: Proto::Upnp, ext: *p, internal: "192.168.1.99:5000".parse().unwrap(), desc: "another device".into(),
                                    expires: now + 5000.0, nonce: [0; 12], foreign: true });
                }
            }
            Act::DropForeign => self.state.lock().unwrap().maps.retain(|m| !m.foreign),
            Act::LoseNext => self.state.lock().unwrap().lose_next = true,
            Act::Silent(b) => self.state.lock().unwrap().silent = *b,
            Act::ExtIp(x) => self.state.lock().unwrap().ext_ip = *x,
        }
        self.check();
    }

    fn check(&mut self) {
        let s = self.state.lock().unwrap();
        let now = s.now;
        // NoForeignDelete
        assert_eq!(s.foreign_deleted, 0, "a foreign mapping was deleted");
        // AtMostOneExternalPortPerListener (for the listener's current address)
        for w in self.wants() {
            let n = s.maps.iter().filter(|m| !m.foreign && m.expires > now && m.desc == w.description && m.internal == w.internal).count();
            assert!(n <= 1, "{} mappings of {} for {}: {:?}", n, w.key, w.internal, s.maps);
        }
        // AnnouncedImpliesMapped (bounded): fresh means on the router, or lost less than two verify intervals ago
        let statuses = self.m.statuses(now);
        let bound = 2.0 * timing().verify_s + self.max_dt;
        for st in statuses.iter().filter(|st| st.fresh) {
            let ext = st.external.map(|e| e.port());
            let present = s.maps.iter().any(|m| !m.foreign && m.expires > now && Some(m.ext) == ext && m.internal == st.internal);
            if present {
                self.absent_since.remove(&st.key);
            } else {
                let since = *self.absent_since.entry(st.key.clone()).or_insert(now);
                assert!(now - since <= bound, "{} announced {}s after the router lost it: {st:?} router {:?}", st.key, now - since, s.maps);
            }
        }
        for st in statuses.iter().filter(|st| !st.fresh) {
            self.absent_since.remove(&st.key);
        }
    }

    /// EventuallyClean: nothing wanted, the router answering: soon nothing of ours on it and an empty journal (a
    /// permanent mapping made from an address the node no longer has is the documented exception for NAT-PMP and PCP,
    /// which have no permanent mappings; UPnP can always delete its own).
    async fn drain(&mut self) {
        self.wanted = [false; 3];
        self.state.lock().unwrap().silent = false;
        self.apply_wants();
        for _ in 0..400 {
            self.step(60.0).await;
            self.check();
        }
        let s = self.state.lock().unwrap();
        let now = s.now;
        let left: Vec<&M> = s.maps.iter().filter(|m| !m.foreign && m.expires > now).collect();
        assert!(left.is_empty(), "stale mappings: {left:?}");
        drop(s);
        assert!(self.m.journal.entries().is_empty(), "journal: {:?}", self.m.journal.entries());
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, max_shrink_iters: 2000, ..ProptestConfig::default() })]

    #[test]
    fn the_lifecycle_keeps_its_promises(pcp in any::<bool>(), natpmp in any::<bool>(), upnp in any::<bool>(),
                                        permanent_only in any::<bool>(), acts in prop::collection::vec(act(), 1..80)) {
        rt().block_on(async {
            let mut w = World::new(pcp, natpmp, upnp, permanent_only);
            for a in &acts {
                w.apply(a).await;
            }
            w.drain().await;
        });
    }
}

#[test]
fn a_72_hour_soak_in_virtual_time() {
    rt().block_on(async {
        for (pcp, natpmp, upnp, perm) in [(true, true, true, false), (false, true, false, false), (false, false, true, false), (false, false, true, true)] {
            let mut w = World::new(pcp, natpmp, upnp, perm);
            w.max_dt = 60.0;
            let mut t = 0u64;
            let mut held = 0u64;
            let mut samples = 0u64;
            while t < 72 * 3600 {
                w.step(60.0).await;
                t += 60;
                match t % (5 * 3600) {
                    3600 => w.apply(&Act::Reboot).await,
                    7200 => w.apply(&Act::ExtIp((t / 3600 % 200) as u8 + 1)).await,
                    10800 => w.apply(&Act::Rebind(20 + (t / 10800 % 3) as u8)).await,
                    14400 => w.apply(&Act::Crash).await,
                    _ => w.check(),
                }
                samples += 1;
                // fresh, or by design waiting for its own old mapping from a previous address to run out (a stable
                // port behind a router that deletes only for the mapping's own address)
                held += w.m.statuses(w.now()).iter()
                    .filter(|s| s.fresh || s.error.as_deref().is_some_and(|e| e.contains("previous address"))).count() as u64;
            }
            // two listeners wanted: they are fresh nearly all the time (outages last at most a verify interval or two)
            let share = held as f64 / (2 * samples) as f64;
            assert!(share > 0.95, "{pcp} {natpmp} {upnp} {perm}: fresh {share}");
            w.drain().await;
        }
    });
}

#[test]
fn an_epoch_check_follows_rfc_6887() {
    use crate::manager::epoch_ok;
    assert!(epoch_ok((1000, 0.0), 1600, 600.0));
    assert!(epoch_ok((1000, 0.0), 1003, 4.0));
    assert!(!epoch_ok((1000, 0.0), 10, 600.0), "went back: the router restarted");
    assert!(!epoch_ok((1000, 0.0), 1100, 600.0), "advanced far less than the client's clock");
    assert!(!epoch_ok((1000, 0.0), 5000, 600.0), "advanced far more");
}
