//! Inbound listeners (docs/design/inbound-listeners.md; PLAN D47-D49): the agent accepts TCP connections on the node
//! for a module and relays each one to the module's endpoint service, maps the port on the router, keeps it mapped,
//! answers dial-back probes and says what is going on in the owner's words.
//!
//! - A listener exists only for a statement entry (the owner's, signed) whose module version in the release requests
//!   that `inbound` listener (approved by digest, or it would not be in the release), served by an enabled endpoint
//!   service of the module, with no kill switch, no managed policy against it and a node not in `strict_yield`.
//! - The data path: bind the node's address on the default route (never the wildcard), then for each connection the
//!   kill switch, the allowlist (the owner's intersected with the module's), the per-address token bucket and cap, the
//!   listener's cap; a dial-back probe is answered here and never reaches the module; anything else goes to the service
//!   on its endpoint channel (or, `listen_fd`, to the listening unix socket it inherited) and the agent relays the
//!   bytes, with the idle timeout, the byte-rate cap and, when asked, a PROXY v2 header first.
//! - The mapping: `oarbank_portmap::Manager` on its own task (PCP, NAT-PMP, UPnP; the journal in
//!   `state/portmaps.json`), told about network changes (checked every 5 s) and wakes from sleep.
//! - Announcements: `OARBANK_LISTENERS_FILE` and `{"op": "listener", ...}` on the service's channel on every change.
//!
//! Tests never reach a real router: `Env::from_env` names fake gateways when `OARBANK_PORTMAP_GATEWAY` or
//! `OARBANK_PORTMAP_SSDP` is set, and a test build refuses the system's gateway.

use crate::endpoints::{self, Channel};
use crate::paths::Layout;
use crate::release::Release;
use crate::services::{ListenerTarget, ServiceManager};
use crate::workloads::WorkloadManager;
use oarbank_portmap::addr::{self, Cidr};
use oarbank_portmap::classify::{self, Dialback};
use oarbank_portmap::journal::Journal;
use oarbank_portmap::manager::{Manager, RouterMapping};
use oarbank_portmap::netinfo::NetSnapshot;
use oarbank_portmap::router::{NetRouter, Target};
use oarbank_portmap::{probe, Discovery, Fallback, Family, Mode, Status, Timing, Want};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{info, warn};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now() -> f64 {
    oarbank_portmap::now()
}

// MARK: where the routers are

/// Which router the agent maps on, and the lifecycle's constants.
#[derive(Debug, Clone)]
pub struct Env {
    pub target: Target,
    pub timing: Timing,
    /// Treat probes from loopback and private addresses as coming from outside (tests on one machine).
    pub allow_local_probes: bool,
    /// Where NAT-PMP announcements are listened for (production: 0.0.0.0:5350, multicast 224.0.0.1).
    pub announce: Option<SocketAddr>,
}

impl Env {
    /// Production: the default gateway. `OARBANK_PORTMAP_GATEWAY` (NAT-PMP and PCP), `OARBANK_PORTMAP_SSDP` and
    /// `OARBANK_PORTMAP_PCP6` name fake gateways instead (tests), `OARBANK_PORTMAP_TIMING=fast` compresses the leases,
    /// `OARBANK_LISTENER_PROBE_ALLOW_LOCAL=1` accepts probes from this machine.
    pub fn from_env() -> Env {
        let addr = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<SocketAddr>().ok());
        let (pmp, ssdp, pcp6) = (addr("OARBANK_PORTMAP_GATEWAY"), addr("OARBANK_PORTMAP_SSDP"), addr("OARBANK_PORTMAP_PCP6"));
        let fixed = pmp.is_some() || ssdp.is_some();
        let target = if fixed { Target::Fixed { pmp, ssdp, pcp_v6: pcp6 } } else { Target::System };
        let timing = if std::env::var("OARBANK_PORTMAP_TIMING").as_deref() == Ok("fast") {
            Timing { lease_pcp: 20, lease_natpmp: 20, lease_upnp: 20, lease_pinhole: 20, verify_s: 2.0, discovery_ttl_s: 60.0,
                     retry_min_s: 0.5, retry_max_s: 5.0, port_taken_retry_s: 10.0, release_retry_s: 2.0 }
        } else {
            Timing::default()
        };
        let announce = if fixed { addr("OARBANK_PORTMAP_ANNOUNCE") } else { Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 5350))) };
        Env { target, timing, allow_local_probes: std::env::var("OARBANK_LISTENER_PROBE_ALLOW_LOCAL").as_deref() == Ok("1"), announce }
    }

    fn snapshot(&self) -> NetSnapshot {
        match &self.target {
            Target::System => {
                #[cfg(test)]
                panic!("a test must name a fake gateway (listeners::Env)");
                #[cfg(not(test))]
                NetSnapshot::system()
            }
            Target::Fixed { pmp, ssdp, .. } => pmp.or(*ssdp).map(NetSnapshot::fixed).unwrap_or_default(),
        }
    }
}

// MARK: what the module asks for, what the owner set

/// A manifest `[sandbox].net.inbound` entry, from the release.
#[derive(Debug, Clone, PartialEq)]
pub struct Spec {
    pub name: String,
    pub port_hint: Option<u16>,
    pub stable: bool,
    pub listen_fd: bool,
    pub proxy: bool,
    pub max_conns: usize,
    pub max_conns_per_ip: usize,
    pub rate_per_ip: f64,
    pub idle: Duration,
    pub bytes_per_s: Option<f64>,
}

impl Spec {
    pub fn parse(v: &Value) -> Option<Spec> {
        let listen_fd = v["handover"].as_str() == Some("listen_fd");
        Some(Spec {
            name: v["name"].as_str()?.to_string(),
            port_hint: v["port_hint"].as_u64().filter(|p| (1024..=65535).contains(p)).map(|p| p as u16),
            stable: v["port_policy"].as_str() != Some("flexible"),
            listen_fd,
            proxy: v["proxy_protocol"].as_bool().unwrap_or(listen_fd),
            max_conns: v["max_conns"].as_u64().unwrap_or(256).clamp(1, 65535) as usize,
            max_conns_per_ip: v["max_conns_per_ip"].as_u64().unwrap_or(16).clamp(1, 65535) as usize,
            rate_per_ip: v["new_conns_per_ip_per_s"].as_f64().filter(|r| *r > 0.0).unwrap_or(4.0),
            idle: Duration::from_secs_f64(v["idle_timeout_s"].as_f64().unwrap_or(120.0).clamp(1.0, 86400.0)),
            bytes_per_s: v["max_bytes_per_s"].as_f64().filter(|b| *b > 0.0),
        })
    }

    /// The owner's per-node limits: each may only lower the module's.
    fn lowered(&self, limits: &Value) -> Spec {
        let mut s = self.clone();
        let low = |k: &str| limits[k].as_f64().filter(|v| *v > 0.0);
        if let Some(v) = low("max_conns") { s.max_conns = s.max_conns.min(v as usize).max(1); }
        if let Some(v) = low("max_conns_per_ip") { s.max_conns_per_ip = s.max_conns_per_ip.min(v as usize).max(1); }
        if let Some(v) = low("new_conns_per_ip_per_s") { s.rate_per_ip = s.rate_per_ip.min(v); }
        if let Some(v) = low("idle_timeout_s") { s.idle = s.idle.min(Duration::from_secs_f64(v)); }
        if let Some(v) = low("max_bytes_per_s") { s.bytes_per_s = Some(s.bytes_per_s.map_or(v, |b| b.min(v))); }
        s
    }
}

/// The owner's statement entry for one listener on this node.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub external_port: Option<u16>,
    pub fallback: Fallback,
    pub mode: Mode,
    pub ipv6: bool,
    /// None: the address on the default route.
    pub bind: Option<IpAddr>,
    pub internal_port: Option<u16>,
    pub limits: Value,
    pub allow: Vec<Cidr>,
}

impl Entry {
    pub fn parse(v: &Value, spec: &Spec) -> Result<Entry, String> {
        let port = |k: &str| v[k].as_u64().filter(|p| (1024..=65535).contains(p)).map(|p| p as u16);
        let external_port = port("external_port").or(spec.port_hint);
        let fallback = match v["fallback"].as_str() {
            Some(f) => Fallback::parse(f).ok_or_else(|| format!("fallback {f:?} is not refuse, next_free:<a>-<b> or router_choice"))?,
            None if spec.stable => Fallback::Refuse,
            None => match external_port {
                Some(p) => Fallback::NextFree { lo: p, hi: p.saturating_add(15) },
                None => Fallback::RouterChoice,
            },
        };
        let mode = match v["mapping"].as_str() {
            Some(m) => Mode::parse(m).ok_or_else(|| format!("mapping {m:?} is not auto, pcp, natpmp, upnp, manual or none"))?,
            None => Mode::Auto,
        };
        let bind = match v["bind"].as_str() {
            None | Some("default_route") => None,
            Some(b) => Some(b.parse::<IpAddr>().map_err(|_| format!("bind {b:?} is not default_route or an address"))?)
                .filter(|ip| !ip.is_unspecified()),
        };
        let allow = v["allow"].as_array().into_iter().flatten().filter_map(Value::as_str)
            .map(|c| Cidr::parse(c).ok_or_else(|| format!("allow {c:?} is not a CIDR"))).collect::<Result<Vec<_>, _>>()?;
        Ok(Entry { external_port, fallback, mode, ipv6: v["ipv6"].as_str() != Some("off"), bind, internal_port: port("internal_port"),
                   limits: v["limits"].clone(), allow })
    }
}

/// Why a statement entry gives no listener (the heartbeat's `refused`).
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    pub code: &'static str,
    pub detail: String,
}

/// What the agent should run: each statement key, a listener to run or why not.
#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    Run { module: String, service: String, spec: Spec, entry: Entry },
    Refuse(Refused),
}

/// The inputs `plan` reads from the directives and the node's state.
pub struct Inputs<'a> {
    pub release: Option<&'a Release>,
    pub statement: &'a Map<String, Value>,
    pub policy: &'a Value,
    pub modules_disabled: &'a [String],
    pub listeners_disabled: bool,
    pub windows: bool,
}

/// Every statement entry, planned (pure: the gates of D47).
pub fn plan(i: &Inputs) -> BTreeMap<String, Plan> {
    let mut out = BTreeMap::new();
    let refuse = |code: &'static str, detail: String| Plan::Refuse(Refused { code, detail });
    let disabled_services: Vec<&str> = i.policy["disabled_services"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let strict = i.policy["protection"]["node"]["mode"].as_str() == Some("strict_yield")
        || i.policy["protection"]["mode"].as_str() == Some("strict_yield");
    for (key, v) in i.statement {
        let Some((module, listener)) = key.split_once('/') else {
            out.insert(key.clone(), refuse("LISTENER_NOT_GRANTED", format!("{key} is not <module>/<listener>")));
            continue;
        };
        let p = (|| {
            if i.listeners_disabled {
                return refuse("LISTENERS_DISABLED", "the listeners kill switch is engaged (listeners.disable)".into());
            }
            if i.policy["inbound_listeners"].as_bool() == Some(false) {
                return refuse("LISTENERS_FORBIDDEN", "this machine's settings forbid inbound listeners (inbound_listeners)".into());
            }
            if strict {
                return refuse("LISTENER_STRICT_YIELD", "this node yields completely to its owner (strict_yield): no listener runs here".into());
            }
            let Some(entry) = i.release.and_then(|r| r.modules.iter().find(|e| e["name"].as_str() == Some(module))) else {
                return refuse("LISTENER_NOT_GRANTED", format!("{module} is not in this node's release"));
            };
            let Some(spec) = entry["sandbox"]["net"]["inbound"].as_array().into_iter().flatten()
                .find(|x| x["name"].as_str() == Some(listener)).and_then(Spec::parse) else {
                return refuse("LISTENER_NOT_GRANTED", format!("{module}'s version here has no approved inbound listener {listener}"));
            };
            if i.modules_disabled.iter().any(|m| m == module) {
                return refuse("MODULE_DISABLED", format!("{module} is disabled on this node"));
            }
            let lists = |p: &&Value| p["listeners"].as_array().is_some_and(|l| l.iter().any(|x| x.as_str() == Some(listener)));
            let svc = entry["services"].as_array().into_iter().flatten()
                .find(|s| s["endpoint"].as_bool() == Some(true) && lists(s));
            // a workload may serve it instead (docs/design/workloads.md): connections reach it while it runs here
            let wl = entry["workloads"].as_array().into_iter().flatten().find(lists);
            let Some(target) = svc.or(wl) else {
                return refuse("LISTENER_NO_TARGET", format!("no endpoint service or workload of {module} serves {listener}"));
            };
            let service = target["name"].as_str().unwrap_or("").to_string();
            if svc.is_some() && disabled_services.contains(&format!("{module}/{service}").as_str()) {
                return refuse("LISTENER_NO_TARGET", format!("{module}/{service} does not run on this node"));
            }
            if svc.is_none() && spec.listen_fd {
                return refuse("LISTENER_HANDOVER_UNSUPPORTED", "a workload is handed its connections, never a listening socket".into());
            }
            if spec.listen_fd && i.windows {
                return refuse("LISTENER_HANDOVER_UNSUPPORTED", "a listen_fd listener cannot run on Windows".into());
            }
            match Entry::parse(v, &spec) {
                Ok(entry) => Plan::Run { module: module.to_string(), service, spec: spec.lowered(&entry.limits), entry },
                Err(e) => refuse("LISTENER_NOT_GRANTED", e),
            }
        })();
        out.insert(key.clone(), p);
    }
    out
}

/// The process serving a listener now: the module's endpoint service that lists it, else its workload that does.
fn target_of(svc: &Option<Arc<Mutex<ServiceManager>>>, wl: &Option<Arc<Mutex<WorkloadManager>>>, module: &str, listener: &str)
             -> Option<ListenerTarget> {
    svc.as_ref().and_then(|s| lock(s).listener_target(module, listener))
        .or_else(|| wl.as_ref().and_then(|w| lock(w).listener_target(module, listener)))
}

/// The internal port for a listener: derived from its key in the node's range (the same on every start while free).
pub fn internal_port_for(key: &str, range: (u16, u16), taken: impl Fn(u16) -> bool) -> Option<u16> {
    use sha2::Digest;
    let (lo, hi) = range;
    let size = (hi as u32).saturating_sub(lo as u32) + 1;
    let h = sha2::Sha256::digest(key.as_bytes());
    let start = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % size;
    (0..size).map(|i| lo + ((start + i) % size) as u16).find(|p| !taken(*p))
}

pub fn port_range(policy: &Value) -> (u16, u16) {
    policy["listener_port_range"].as_str().and_then(|r| r.split_once('-'))
        .and_then(|(a, b)| Some((a.trim().parse::<u16>().ok()?, b.trim().parse::<u16>().ok()?)))
        .filter(|(a, b)| *a >= 1024 && a <= b).unwrap_or((41000, 41999))
}

// MARK: the data path

/// A token bucket.
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn take(&mut self, rate: f64, burst: f64) -> bool {
        let n = Instant::now();
        self.tokens = (self.tokens + n.duration_since(self.at).as_secs_f64() * rate).min(burst);
        self.at = n;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct PerIp {
    open: usize,
    bucket: Option<Bucket>,
}

#[derive(Debug, Clone, Default)]
struct Talker {
    conns: u64,
    refused: u64,
    last: f64,
}

#[derive(Default)]
pub struct Counters {
    pub accepted: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub rate: AtomicU64,
    pub cap: AtomicU64,
    pub per_ip: AtomicU64,
    pub allow: AtomicU64,
    pub held: AtomicU64,
    pub disabled: AtomicU64,
    pub probes: AtomicU64,
}

/// What finds the listener's service now: its endpoint channel while it accepts, else why not.
pub type Lookup = Arc<dyn Fn() -> (Option<Arc<Channel>>, Option<String>) + Send + Sync>;

/// One listener's runtime, shared with its accept and relay tasks.
pub struct Rt {
    pub key: String,
    pub name: String,
    pub spec: Spec,
    pub owner_allow: Vec<Cidr>,
    pub disabled: AtomicBool,
    pub open: AtomicUsize,
    pub counters: Counters,
    per_ip: Mutex<HashMap<IpAddr, PerIp>>,
    talkers: Mutex<HashMap<IpAddr, Talker>>,
    bytes: Mutex<Option<(f64, Instant)>>,
    /// Expected dial-backs: probe id -> nonce.
    pub probes: Mutex<HashMap<String, String>>,
    /// The node's external address, for telling a probe from the node's own network.
    pub external_ip: Mutex<Option<IpAddr>>,
    pub allow_local_probes: bool,
    pub lookup: Lookup,
    #[cfg_attr(not(unix), allow(dead_code))]
    pub listen_path: Option<PathBuf>,
}

impl Rt {
    pub fn new(key: &str, spec: Spec, owner_allow: Vec<Cidr>, lookup: Lookup, listen_path: Option<PathBuf>, allow_local_probes: bool) -> Rt {
        Rt { key: key.into(), name: spec.name.clone(), spec, owner_allow, disabled: AtomicBool::new(false), open: AtomicUsize::new(0),
             counters: Counters::default(), per_ip: Mutex::default(), talkers: Mutex::default(), bytes: Mutex::new(None),
             probes: Mutex::default(), external_ip: Mutex::new(None), allow_local_probes, lookup, listen_path }
    }

    fn talk(&self, ip: IpAddr, refused: bool) {
        let mut t = lock(&self.talkers);
        let e = t.entry(addr::limit_key(ip)).or_default();
        if refused { e.refused += 1 } else { e.conns += 1 }
        e.last = now();
        if t.len() > 4096 {
            let cut = now() - 86400.0;
            t.retain(|_, v| v.last > cut);
            if t.len() > 4096 {
                let mut v: Vec<(IpAddr, u64)> = t.iter().map(|(k, x)| (*k, x.conns)).collect();
                v.sort_by_key(|x| std::cmp::Reverse(x.1));
                let keep: std::collections::HashSet<IpAddr> = v.into_iter().take(1024).map(|x| x.0).collect();
                t.retain(|k, _| keep.contains(k));
            }
        }
    }

    /// The 24-hour top client addresses (at most 20), for the owner only when asked.
    pub fn talkers(&self) -> Value {
        let cut = now() - 86400.0;
        let mut v: Vec<(IpAddr, Talker)> = lock(&self.talkers).iter().filter(|(_, t)| t.last > cut).map(|(k, t)| (*k, t.clone())).collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.1.conns + x.1.refused));
        Value::Array(v.into_iter().take(20).map(|(a, t)| json!({"addr": a.to_string(), "conns": t.conns, "refused": t.refused,
                                                                  "last": t.last})).collect())
    }

    /// Admission of a new connection: the kill switch, the allowlists, the per-address bucket and cap, the listener cap.
    /// Ok: admitted (the caller must `release`); Err: the counter it was refused under.
    fn admit(&self, peer: IpAddr, module_allow: Option<&[Cidr]>) -> Result<(), &'static str> {
        if self.disabled.load(Ordering::SeqCst) {
            self.counters.disabled.fetch_add(1, Ordering::Relaxed);
            return Err("disabled");
        }
        if !addr::allowed(peer, &self.owner_allow, module_allow) {
            self.counters.allow.fetch_add(1, Ordering::Relaxed);
            return Err("allow");
        }
        let k = addr::limit_key(peer);
        let mut m = lock(&self.per_ip);
        let e = m.entry(k).or_default();
        let rate = self.spec.rate_per_ip;
        let b = e.bucket.get_or_insert(Bucket { tokens: rate * 2.0, at: Instant::now() });
        if !b.take(rate, rate * 2.0) {
            self.counters.rate.fetch_add(1, Ordering::Relaxed);
            return Err("rate");
        }
        if e.open >= self.spec.max_conns_per_ip {
            self.counters.per_ip.fetch_add(1, Ordering::Relaxed);
            return Err("per_ip");
        }
        if self.open.load(Ordering::SeqCst) >= self.spec.max_conns {
            self.counters.cap.fetch_add(1, Ordering::Relaxed);
            return Err("cap");
        }
        e.open += 1;
        self.open.fetch_add(1, Ordering::SeqCst);
        if m.len() > 8192 {
            m.retain(|_, v| v.open > 0);
        }
        Ok(())
    }

    fn release(&self, peer: IpAddr) {
        let k = addr::limit_key(peer);
        if let Some(e) = lock(&self.per_ip).get_mut(&k) {
            e.open = e.open.saturating_sub(1);
        }
        self.open.fetch_sub(1, Ordering::SeqCst);
    }

    /// The byte-rate cap: how long to wait before `n` more bytes may pass.
    fn wait_bytes(&self, n: usize) -> Option<Duration> {
        let rate = self.spec.bytes_per_s?;
        let mut b = lock(&self.bytes);
        let n_ = Instant::now();
        let (tokens, at) = b.get_or_insert((rate, n_));
        *tokens = (*tokens + n_.duration_since(*at).as_secs_f64() * rate).min(rate);
        *at = n_;
        *tokens -= n as f64;
        (*tokens < 0.0).then(|| Duration::from_secs_f64(-*tokens / rate))
    }
}

/// A PROXY protocol v2 header (the client's address and the address the agent accepted on).
pub fn proxy_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut v = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    v.push(0x21);
    let as6 = |a: SocketAddr| match a.ip() {
        IpAddr::V4(x) => x.to_ipv6_mapped(),
        IpAddr::V6(x) => x,
    };
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            v.push(0x11);
            v.extend_from_slice(&12u16.to_be_bytes());
            v.extend_from_slice(&s.octets());
            v.extend_from_slice(&d.octets());
        }
        _ => {
            v.push(0x21);
            v.extend_from_slice(&36u16.to_be_bytes());
            v.extend_from_slice(&as6(src).octets());
            v.extend_from_slice(&as6(dst).octets());
        }
    }
    v.extend_from_slice(&src.port().to_be_bytes());
    v.extend_from_slice(&dst.port().to_be_bytes());
    v
}

/// Copy one direction, counting bytes and honouring the byte-rate cap; shuts the writer down at end of file.
async fn copy_dir<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut r: R, mut w: W, rt: &Rt, inbound: bool, last: &AtomicU64,
                                                                start: Instant) {
    let mut buf = vec![0u8; 16384];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if let Some(d) = rt.wait_bytes(n) {
            tokio::time::sleep(d.min(Duration::from_secs(5))).await;
        }
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
        last.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
        if inbound { &rt.counters.bytes_in } else { &rt.counters.bytes_out }.fetch_add(n as u64, Ordering::Relaxed);
    }
    let _ = w.shutdown().await;
}

/// Relay a TCP connection and the module's end until both directions end or the connection stays idle.
async fn relay<A, B>(tcp: A, module: B, rt: &Rt)
where A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin {
    let (tr, tw) = tokio::io::split(tcp);
    let (mr, mw) = tokio::io::split(module);
    let start = Instant::now();
    let last = AtomicU64::new(0);
    let idle = rt.spec.idle;
    let watchdog = async {
        loop {
            tokio::time::sleep((idle / 4).max(Duration::from_millis(50))).await;
            let quiet = start.elapsed().saturating_sub(Duration::from_millis(last.load(Ordering::Relaxed)));
            if quiet >= idle {
                return;
            }
        }
    };
    tokio::select! {
        _ = async { tokio::join!(copy_dir(tr, mw, rt, true, &last, start), copy_dir(mr, tw, rt, false, &last, start)) } => {}
        _ = watchdog => {}
    }
}

/// One accepted connection, from admission to the end of its relay.
async fn serve(rt: Arc<Rt>, mut tcp: tokio::net::TcpStream, peer: SocketAddr, local: SocketAddr) {
    let (channel, why) = (rt.lookup)();
    let module_allow: Option<Vec<Cidr>> = channel.as_ref().and_then(|c| c.allow_list(&rt.name))
        .map(|l| l.iter().filter_map(|c| Cidr::parse(c)).collect());
    if let Err(_why) = rt.admit(peer.ip(), module_allow.as_deref()) {
        rt.talk(peer.ip(), true);
        return;
    }
    let _guard = scopeguard(rt.clone(), peer.ip());
    // a dial-back probe is answered here, never by the module
    let mut prefix = Vec::new();
    let expecting = !lock(&rt.probes).is_empty();
    if expecting {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut b = [0u8; 128];
        loop {
            match probe::classify_first(&prefix) {
                probe::First::Partial => {}
                probe::First::NotProbe => break,
                probe::First::Probe(id) => {
                    rt.counters.probes.fetch_add(1, Ordering::Relaxed);
                    let nonce = lock(&rt.probes).get(&id).cloned();
                    if let Some(n) = nonce {
                        let same = !rt.allow_local_probes
                            && (addr::is_local_network(peer.ip()) || *lock(&rt.external_ip) == Some(peer.ip()));
                        let _ = tcp.write_all(&probe::answer(&n, same)).await;
                        info!(listener = %rt.key, peer = %peer, same_network = same, "answered a dial-back probe");
                    }
                    let _ = tcp.shutdown().await;
                    return;
                }
            }
            if prefix.len() >= 128 {
                break;
            }
            match tokio::time::timeout_at(deadline, tcp.read(&mut b)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return,
                Ok(Ok(n)) => prefix.extend_from_slice(&b[..n]),
                Err(_) => break,                                    // a client that waits for the server to speak
            }
        }
    }
    let Some(channel) = channel else {
        rt.counters.held.fetch_add(1, Ordering::Relaxed);
        rt.talk(peer.ip(), true);
        let _ = why;
        return;
    };
    rt.counters.accepted.fetch_add(1, Ordering::Relaxed);
    rt.talk(peer.ip(), false);
    let mut first = Vec::new();
    if rt.spec.proxy {
        first.extend(proxy_v2(peer, local));
    }
    first.extend(prefix);
    #[cfg(unix)]
    if let Some(path) = &rt.listen_path {
        let Ok(mut m) = tokio::net::UnixStream::connect(path).await else {
            rt.counters.held.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if m.write_all(&first).await.is_ok() {
            relay(tcp, m, &rt).await;
        }
        return;
    }
    let end = match channel.hand_listener(&rt.name, &peer.to_string()) {
        Ok(e) => e,
        Err(_) => {
            rt.counters.held.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };
    let Ok(mut m) = endpoints::into_async(end) else { return };
    if !first.is_empty() && m.write_all(&first).await.is_err() {
        return;
    }
    relay(tcp, m, &rt).await;
}

struct Guard(Arc<Rt>, IpAddr);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.release(self.1);
    }
}

fn scopeguard(rt: Arc<Rt>, ip: IpAddr) -> Guard {
    Guard(rt, ip)
}

/// Accept on `l` until the task is aborted.
pub fn spawn_accept(rt: Arc<Rt>, l: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match l.accept().await {
                Ok((s, peer)) => {
                    let _ = s.set_nodelay(true);
                    let local = s.local_addr().unwrap_or(peer);
                    tokio::spawn(serve(rt.clone(), s, peer, local));
                }
                Err(e) => {
                    warn!(listener = %rt.key, error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    })
}

/// Bind a TCP listener (std, then tokio), never the wildcard.
fn bind(at: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let l = std::net::TcpListener::bind(at)?;
    l.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(l)
}

// MARK: the hub

enum MapCmd {
    Wants(Vec<Want>),
    Network(NetSnapshot),
    Wake,
    Announcement(IpAddr, u32, IpAddr),
    ReleaseAll(tokio::sync::oneshot::Sender<usize>),
}

/// The port-mapping task's published view.
#[derive(Default, Clone)]
struct MapView {
    statuses: Vec<Status>,
    same_port: Vec<String>,
    discovery: Option<Discovery>,
    others: Vec<RouterMapping>,
    permanent_seen: bool,
    journal_error: Option<String>,
}

struct Listener {
    module: String,
    service: String,
    spec: Spec,
    entry: Entry,
    rt: Arc<Rt>,
    bind: SocketAddr,
    bind_v6: Option<SocketAddr>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    data: Option<PathBuf>,
    announced: Option<Value>,
    channel_seen: Option<usize>,
    since: f64,
    last_external: Option<String>,
    probe_wanted_at: f64,
    probed_endpoint: Option<String>,
    endpoint_probe_at: f64,
}

impl Drop for Listener {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub struct Hub {
    layout: Layout,
    env: Env,
    listeners: BTreeMap<String, Listener>,
    refused: BTreeMap<String, Refused>,
    services: Option<Arc<Mutex<ServiceManager>>>,
    /// Workloads may serve listeners too (docs/design/workloads.md): a listener no service lists is a workload's.
    workloads: Option<Arc<Mutex<WorkloadManager>>>,
    map_tx: Option<tokio::sync::mpsc::UnboundedSender<MapCmd>>,
    view: Arc<Mutex<MapView>>,
    net: NetSnapshot,
    net_at: Option<Instant>,
    clock: Option<(Instant, f64)>,
    node_prefix: String,
    statement_seq: i64,
    policy: Value,
    reach: Map<String, Value>,
    observed: Option<IpAddr>,
    stun_observed: Arc<Mutex<Option<(IpAddr, f64)>>>,
    stun_at: f64,
    probe_results: Arc<Mutex<Vec<Value>>>,
    dialed: BTreeMap<String, f64>,
    send_talkers: bool,
    firewall: Arc<Mutex<Option<crate::firewall::State>>>,
    firewall_at: Option<Instant>,
    history: Vec<(String, f64)>,
    /// listen_fd sockets, by "<module>/<listener>": the listener the hub made and its path.
    #[cfg(unix)]
    listen_socks: BTreeMap<String, (std::os::unix::net::UnixListener, PathBuf, String)>,
    /// Local reachability from the owner's probe endpoint (when no fleet prober is available).
    endpoint_reach: Arc<Mutex<BTreeMap<String, Value>>>,
    started: bool,
}

impl Hub {
    pub fn new(layout: Layout, env: Env) -> Hub {
        let history = std::fs::read(layout.state().join("listener-addresses.json")).ok()
            .and_then(|b| serde_json::from_slice::<Vec<(String, f64)>>(&b).ok()).unwrap_or_default();
        Hub { layout, env, listeners: BTreeMap::new(), refused: BTreeMap::new(), services: None, workloads: None, map_tx: None, view: Arc::default(),
              net: NetSnapshot::default(), net_at: None, clock: None, node_prefix: "node".into(), statement_seq: 0, policy: json!({}),
              reach: Map::new(), observed: None, stun_observed: Arc::default(), stun_at: 0.0, probe_results: Arc::default(),
              dialed: BTreeMap::new(), send_talkers: false, firewall: Arc::default(), firewall_at: None, history,
              #[cfg(unix)]
              listen_socks: BTreeMap::new(),
              endpoint_reach: Arc::default(), started: false }
    }

    /// The facts' `listeners`: this agent runs listeners and can be a prober.
    pub fn facts() -> Value {
        json!({"version": 1, "probe": true})
    }

    fn start_mapper(&mut self) {
        if self.map_tx.is_some() {
            return;
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<MapCmd>();
        let journal = Journal::load(&self.layout.state().join("portmaps.json"));
        let router = NetRouter::new(self.env.target.clone());
        let mut m = Manager::new(router, journal, self.env.timing.clone(), &self.node_prefix);
        let view = self.view.clone();
        let snap = self.net.clone();
        tokio::spawn(async move {
            m.set_network(Family::Ipv4, snap.local_v4.map(IpAddr::V4), snap.gateway_v4.map(IpAddr::V4), now());
            m.set_network(Family::Ipv6, snap.global_v6.map(IpAddr::V6), snap.gateway_v6.map(IpAddr::V6), now());
            let mut have_wants = false;
            loop {
                let next = m.next_due(now());
                let wait = Duration::from_secs_f64((next - now()).clamp(0.05, 60.0));
                let cmd = if have_wants {
                    tokio::select! { c = rx.recv() => c.map(Some), _ = tokio::time::sleep(wait) => Some(None) }
                } else {
                    rx.recv().await.map(Some)
                };
                let Some(cmd) = cmd else {
                    break;                                            // the hub is gone
                };
                match cmd {
                    Some(MapCmd::Wants(w)) => {
                        have_wants = true;
                        m.set_wants(w, now());
                    }
                    Some(MapCmd::Network(s)) => {
                        m.router.refresh();
                        m.set_network(Family::Ipv4, s.local_v4.map(IpAddr::V4), s.gateway_v4.map(IpAddr::V4), now());
                        m.set_network(Family::Ipv6, s.global_v6.map(IpAddr::V6), s.gateway_v6.map(IpAddr::V6), now());
                        m.wake(now());
                    }
                    Some(MapCmd::Wake) => m.wake(now()),
                    Some(MapCmd::Announcement(g, e, x)) => m.announcement(g, e, x, now()),
                    Some(MapCmd::ReleaseAll(done)) => {
                        let r = m.release_all(now()).await;
                        have_wants = false;
                        let _ = done.send(r.len());
                        continue;
                    }
                    None => {}
                }
                m.step(now()).await;
                let mut v = lock(&view);
                v.statuses = m.statuses(now());
                v.same_port = m.lifecycles().filter(|l| l.same_port_required).map(|l| l.want.key.clone()).collect();
                v.discovery = m.discovery(Family::Ipv4).cloned();
                v.others = m.others.clone();
                v.permanent_seen = m.permanent_seen;
                v.journal_error = m.journal.write_error.clone();
            }
        });
        self.map_tx = Some(tx.clone());
        // NAT-PMP announcements (UDP 5350): the router's new external address, or its restart
        if let Some(at) = self.env.announce {
            tokio::spawn(async move {
                let sock = match announce_socket(at) {
                    Ok(s) => s,
                    Err(e) => {
                        info!(error = %e, "NAT-PMP announcements are not listened for");
                        return;
                    }
                };
                let mut b = [0u8; 64];
                while let Ok((n, from)) = sock.recv_from(&mut b).await {
                    if let Some(a) = oarbank_portmap::natpmp::parse_external(&b[..n]) {
                        let _ = tx.send(MapCmd::Announcement(from.ip(), a.epoch, IpAddr::V4(a.external)));
                    }
                }
            });
        }
    }

    /// The directives changed (or the release, the statement, the services): plan every listener again and make it so.
    pub fn configure(&mut self, release: Option<&Release>, folders: &crate::folders::Folders, d: &Value,
                     services: Option<Arc<Mutex<ServiceManager>>>, node_id: Option<&str>) {
        if let Some(n) = node_id {
            self.node_prefix = oarbank_portmap::node_prefix(n);
        }
        self.services = services;
        self.statement_seq = folders.seq;
        self.policy = d["policy"].clone();
        self.reach = d["listener_reachability"].as_object().cloned().unwrap_or_default();
        self.observed = d["observed_addr"].as_str().and_then(|s| s.parse().ok()).filter(|ip| addr::is_global(*ip));
        if d["send_listener_talkers"].as_bool() == Some(true) {
            self.send_talkers = true;
        }
        let off: Vec<String> = d["modules_disabled"].as_array().into_iter().flatten().filter_map(|m| m.as_str().map(str::to_string)).collect();
        let plans = plan(&Inputs { release, statement: &folders.listeners, policy: &self.policy, modules_disabled: &off,
                                   listeners_disabled: d["listeners_disabled"].as_bool() == Some(true), windows: cfg!(windows) });
        self.sync_listen_socks(release);
        self.apply(plans);
        self.expect_probes(d);
        self.dial(d);
    }

    /// listen_fd: a listening unix socket for every such inbound listener of the release (made before the service
    /// starts, so its first `start` inherits it), published to the service manager by service key.
    fn sync_listen_socks(&mut self, release: Option<&Release>) {
        #[cfg(unix)]
        {
            let mut want: BTreeMap<String, String> = BTreeMap::new();
            for e in release.map(|r| r.modules.as_slice()).unwrap_or_default() {
                let Some(m) = e["name"].as_str() else { continue };
                for l in e["sandbox"]["net"]["inbound"].as_array().into_iter().flatten() {
                    let (Some(name), true) = (l["name"].as_str(), l["handover"].as_str() == Some("listen_fd")) else { continue };
                    if let Some(svc) = e["services"].as_array().into_iter().flatten()
                        .find(|s| s["listeners"].as_array().is_some_and(|x| x.iter().any(|y| y.as_str() == Some(name)))) {
                        want.insert(format!("{m}/{name}"), format!("{m}/{}", svc["name"].as_str().unwrap_or("")));
                    }
                }
            }
            self.listen_socks.retain(|k, v| {
                let keep = want.get(k) == Some(&v.2);
                if !keep {
                    let _ = std::fs::remove_file(&v.1);
                }
                keep
            });
            for (k, svc) in &want {
                if self.listen_socks.contains_key(k) {
                    continue;
                }
                let dir = self.layout.run().join("listen");
                if crate::fsutil::private_dir(&dir).is_err() {
                    continue;
                }
                let path = dir.join(format!("{}.sock", hex::encode(&k.as_bytes()[..k.len().min(40)])));
                let _ = std::fs::remove_file(&path);
                match std::os::unix::net::UnixListener::bind(&path) {
                    Ok(l) => {
                        use std::os::fd::AsRawFd;
                        unsafe { libc::fcntl(l.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
                        self.listen_socks.insert(k.clone(), (l, path, svc.clone()));
                    }
                    Err(e) => warn!(listener = %k, error = %e, "cannot make the listen_fd socket"),
                }
            }
            if let Some(s) = &self.services {
                use std::os::fd::AsRawFd;
                let fds = lock(s).listen_fds();
                let mut g = lock(&fds);
                g.clear();
                for (k, (l, _, svc)) in &self.listen_socks {
                    let name = k.split_once('/').map(|x| x.1).unwrap_or(k).to_string();
                    g.entry(svc.clone()).or_default().push((name, l.as_raw_fd() as i64));
                }
            }
        }
        #[cfg(not(unix))]
        let _ = release;
    }

    /// The workloads, whose listeners the hub relays to as it does to services' (the agent sets them once).
    pub fn set_workloads(&mut self, w: Arc<Mutex<WorkloadManager>>) {
        self.workloads = Some(w);
    }

    fn lookup_for(&self, module: &str, listener: &str) -> Lookup {
        let (svc, wl) = (self.services.clone(), self.workloads.clone());
        let (m, l) = (module.to_string(), listener.to_string());
        Arc::new(move || match target_of(&svc, &wl, &m, &l) {
            Some(t) => (t.channel, t.why),
            None if svc.is_none() && wl.is_none() => (None, Some("no services yet".into())),
            None => (None, Some("no service or workload serves it".into())),
        })
    }

    fn apply(&mut self, plans: BTreeMap<String, Plan>) {
        let range = port_range(&self.policy);
        self.refused.clear();
        let mut keep = vec![];
        for (key, p) in plans {
            match p {
                Plan::Refuse(r) => {
                    self.refused.insert(key, r);
                }
                Plan::Run { module, service, spec, entry } => {
                    let bind_ip = entry.bind.or_else(|| self.local_v4().map(IpAddr::V4));
                    let same = self.listeners.get(&key).is_some_and(|l| l.spec == spec && l.entry == entry && l.service == service
                                                                          && Some(l.bind.ip()) == bind_ip);
                    keep.push(key.clone());
                    if same {
                        continue;
                    }
                    self.listeners.remove(&key);
                    let Some(ip) = bind_ip else {
                        self.refused.insert(key, Refused { code: "LISTENER_BIND_FAILED", detail: "this node has no address on the default route".into() });
                        continue;
                    };
                    match self.open(&key, &module, &service, spec, entry, ip, range) {
                        Ok(l) => {
                            info!(listener = %key, bind = %l.bind, "listening");
                            self.listeners.insert(key, l);
                        }
                        Err(e) => {
                            self.refused.insert(key, Refused { code: "LISTENER_BIND_FAILED", detail: e });
                        }
                    }
                }
            }
        }
        self.listeners.retain(|k, _| keep.contains(k));
        self.push_wants();
    }

    fn local_v4(&mut self) -> Option<Ipv4Addr> {
        if self.net_at.is_none() {
            self.net = self.env.snapshot();
            self.net_at = Some(Instant::now());
        }
        self.net.local_v4
    }

    #[allow(clippy::too_many_arguments)]
    fn open(&mut self, key: &str, module: &str, service: &str, spec: Spec, entry: Entry, ip: IpAddr, range: (u16, u16)) -> Result<Listener, String> {
        let free = |p: u16| std::net::TcpListener::bind(SocketAddr::new(ip, p)).is_err();
        let port = match (entry.mode, entry.internal_port) {
            (_, Some(p)) => p,
            (Mode::None, None) => entry.external_port.unwrap_or_else(|| internal_port_for(key, range, free).unwrap_or(0)),
            _ => internal_port_for(key, range, free).ok_or("no free port in the internal range")?,
        };
        let at = SocketAddr::new(ip, port);
        let l = bind(at).map_err(|e| format!("cannot listen on {at}: {e}"))?;
        let listen_path = {
            #[cfg(unix)]
            { self.listen_socks.get(key).map(|s| s.1.clone()) }
            #[cfg(not(unix))]
            { None }
        };
        if spec.listen_fd && listen_path.is_none() {
            return Err("the listen_fd socket could not be made".into());
        }
        let rt = Arc::new(Rt::new(key, spec.clone(), entry.allow.clone(), self.lookup_for(module, &spec.name), listen_path,
                                  self.env.allow_local_probes));
        let mut tasks = vec![spawn_accept(rt.clone(), l)];
        let mut bind_v6 = None;
        if entry.ipv6 && entry.bind.is_none() {
            if let Some(v6) = self.net.global_v6 {
                let ext = entry.external_port.unwrap_or(port);
                for p in [ext, port] {
                    if let Ok(l6) = bind(SocketAddr::new(IpAddr::V6(v6), p)) {
                        bind_v6 = Some(SocketAddr::new(IpAddr::V6(v6), p));
                        tasks.push(spawn_accept(rt.clone(), l6));
                        break;
                    }
                }
            }
        }
        #[cfg(windows)]
        {
            // the elevated helper opens Defender Firewall for the agent on this port (no first-listen prompt)
            for p in [Some(port), bind_v6.map(|b| b.port())].into_iter().flatten() {
                if let Err(e) = crate::sandbox_windows::helper(&json!({"op": "firewall_allow", "port": p})) {
                    info!(error = %e, port = p, "no firewall rule for the listener");
                }
            }
        }
        let data = target_of(&self.services, &self.workloads, module, &spec.name).map(|t| t.data);
        Ok(Listener { module: module.into(), service: service.into(), spec, entry, rt, bind: at, bind_v6, tasks, data, announced: None,
                      channel_seen: None, since: now(), last_external: None, probe_wanted_at: 0.0, probed_endpoint: None,
                      endpoint_probe_at: 0.0 })
    }

    fn wants(&self) -> Vec<Want> {
        let mut out = vec![];
        for (k, l) in &self.listeners {
            let ext = l.entry.external_port.unwrap_or(l.bind.port());
            let d = oarbank_portmap::description(&self.node_prefix, k);
            out.push(Want { key: k.clone(), family: Family::Ipv4, internal: l.bind, external_port: ext, fallback: l.entry.fallback,
                            mode: l.entry.mode, description: d.clone() });
            if let Some(b6) = l.bind_v6 {
                out.push(Want { key: k.clone(), family: Family::Ipv6, internal: b6, external_port: b6.port(), fallback: Fallback::Refuse,
                                mode: if matches!(l.entry.mode, Mode::Manual | Mode::None) { l.entry.mode } else { Mode::Auto }, description: d });
            }
        }
        out
    }

    fn push_wants(&mut self) {
        let w = self.wants();
        if w.is_empty() && self.map_tx.is_none() && !self.layout.state().join("portmaps.json").exists() {
            return;                                                  // nothing wanted, nothing journaled: no router is asked
        }
        self.start_mapper();
        if let Some(tx) = &self.map_tx {
            let _ = tx.send(MapCmd::Wants(w));
        }
    }

    fn expect_probes(&mut self, d: &Value) {
        let mut by_key: BTreeMap<String, HashMap<String, String>> = BTreeMap::new();
        for p in d["listener_probes"].as_array().into_iter().flatten() {
            let (Some(id), Some(k), Some(n)) = (p["probe_id"].as_str(), p["key"].as_str(), p["nonce"].as_str()) else { continue };
            if probe::valid_token(id) && probe::valid_token(n) {
                by_key.entry(k.to_string()).or_default().insert(id.to_string(), n.to_string());
            }
        }
        for (k, l) in &self.listeners {
            let mut g = lock(&l.rt.probes);
            g.retain(|id, _| id.starts_with("local-"));
            g.extend(by_key.remove(k).unwrap_or_default());
        }
    }

    /// `dial_probes`: dial-backs this node makes for other nodes (once each).
    fn dial(&mut self, d: &Value) {
        let cut = now() - 600.0;
        self.dialed.retain(|_, t| *t > cut);
        for p in d["dial_probes"].as_array().into_iter().flatten() {
            let (Some(id), Some(host), Some(port), Some(nonce)) = (p["probe_id"].as_str(), p["host"].as_str(), p["port"].as_u64(), p["nonce"].as_str())
                else { continue };
            if self.dialed.contains_key(id) || !probe::valid_token(id) || !probe::valid_token(nonce) {
                continue;
            }
            let Ok(ip) = host.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>() else { continue };
            if !(1024..=65535).contains(&port) || (!addr::is_global(ip) && !self.env.allow_local_probes) {
                continue;                                            // a prober dials only public addresses, at listener ports
            }
            self.dialed.insert(id.to_string(), now());
            let (id, nonce, out) = (id.to_string(), nonce.to_string(), self.probe_results.clone());
            tokio::spawn(async move {
                let r = probe::dial(SocketAddr::new(ip, port as u16), &id, &nonce, Duration::from_secs(5)).await;
                let rtt = match r { probe::Outcome::Ok { rtt_ms } => Some(rtt_ms), _ => None };
                lock(&out).push(json!({"probe_id": id, "ok": r.ok(), "detail": r.detail(), "rtt_ms": rtt}));
            });
        }
    }

    /// Every protection tick: the network and the clock, announcements, the 724 rule, the owner's probe endpoint, the
    /// STUN check and the firewall.
    pub fn tick(&mut self) {
        if self.listeners.is_empty() && self.map_tx.is_none() {
            return;
        }
        let (mono, wall) = (Instant::now(), now());
        if let Some((m0, w0)) = self.clock {
            if (wall - w0) - mono.duration_since(m0).as_secs_f64() > 30.0 {
                info!("woke from sleep: verifying every mapping");
                self.net_at = None;
                if let Some(tx) = &self.map_tx {
                    let _ = tx.send(MapCmd::Wake);
                }
            }
        }
        self.clock = Some((mono, wall));
        if self.net_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(5)) {
            let s = self.env.snapshot();
            self.net_at = Some(Instant::now());
            if s != self.net {
                info!(gateway = ?s.gateway_v4, local = ?s.local_v4, "the network changed");
                self.net = s.clone();
                if let Some(tx) = &self.map_tx {
                    let _ = tx.send(MapCmd::Network(s));
                }
                // listeners on the default route move with it
                let moved: Vec<String> = self.listeners.iter().filter(|(_, l)| l.entry.bind.is_none() && Some(l.bind.ip()) != self.net.local_v4.map(IpAddr::V4))
                    .map(|(k, _)| k.clone()).collect();
                for k in moved {
                    if let Some(l) = self.listeners.remove(&k) {
                        let (m, svc, spec, entry) = (l.module.clone(), l.service.clone(), l.spec.clone(), l.entry.clone());
                        drop(l);
                        if let Some(ip) = self.net.local_v4 {
                            match self.open(&k, &m, &svc, spec, entry, IpAddr::V4(ip), port_range(&self.policy)) {
                                Ok(l) => {
                                    self.listeners.insert(k, l);
                                }
                                Err(e) => {
                                    self.refused.insert(k, Refused { code: "LISTENER_BIND_FAILED", detail: e });
                                }
                            }
                        }
                    }
                }
                self.push_wants();
            }
        }
        // UPnP 724: the router wants the external and the internal port equal: bind the external port itself
        let same: Vec<String> = lock(&self.view).same_port.clone();
        let mut rebind = false;
        for k in same {
            if let Some(l) = self.listeners.get_mut(&k) {
                let ext = l.entry.external_port.unwrap_or(l.bind.port());
                if l.entry.internal_port != Some(ext) {
                    l.entry.internal_port = Some(ext);
                    let (m, svc, spec, entry, ip) = (l.module.clone(), l.service.clone(), l.spec.clone(), l.entry.clone(), l.bind.ip());
                    self.listeners.remove(&k);
                    if let Ok(l) = self.open(&k, &m, &svc, spec, entry, ip, port_range(&self.policy)) {
                        self.listeners.insert(k, l);
                    }
                    rebind = true;
                }
            }
        }
        if rebind {
            self.push_wants();
        }
        self.announce();
        self.stun();
        self.endpoint_probes();
        if self.firewall_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(600)) {
            self.firewall_at = Some(Instant::now());
            let fw = self.firewall.clone();
            tokio::task::spawn_blocking(move || *lock(&fw) = Some(crate::firewall::status()));
        }
    }

    fn status_of(&self, key: &str, family: Family) -> Option<Status> {
        lock(&self.view).statuses.iter().find(|s| s.key == key && s.family == family).cloned()
    }

    /// The external endpoint of a listener now, and whether the router holds it (or the owner forwards it).
    fn external(&self, key: &str, l: &Listener) -> (Option<SocketAddr>, bool) {
        let s = self.status_of(key, Family::Ipv4);
        match l.entry.mode {
            Mode::None => (Some(l.bind), true),
            Mode::Manual => {
                let ip = self.observed.or(lock(&self.stun_observed).map(|x| x.0)).or(self.gateway_external());
                (ip.map(|ip| SocketAddr::new(ip, l.entry.external_port.unwrap_or(l.bind.port()))), true)
            }
            _ => match s {
                Some(s) if s.state == "mapped" => (s.external, s.fresh),
                _ => (None, false),
            },
        }
    }

    fn gateway_external(&self) -> Option<IpAddr> {
        lock(&self.view).discovery.as_ref().and_then(|d| d.external_ip)
    }

    fn reachability_state(&self, key: &str, ext: Option<&str>) -> Option<(String, f64, String, Option<String>)> {
        let r = self.reach.get(key).cloned().or_else(|| lock(&self.endpoint_reach).get(key).cloned())?;
        let state = r["state"].as_str()?.to_string();
        let _ = ext;
        Some((state, r["at"].as_f64().unwrap_or(0.0), r["via"].as_str().unwrap_or("").to_string(), r["detail"].as_str().map(str::to_string)))
    }

    /// Announce each listener's state to its service when it changes (and to every new run of the service).
    fn announce(&mut self) {
        let gx = self.gateway_external();
        let keys: Vec<String> = self.listeners.keys().cloned().collect();
        for k in keys {
            let l = &self.listeners[&k];
            *lock(&l.rt.external_ip) = gx;
            let (ext, held) = self.external(&k, l);
            let ext_s = ext.map(|e| e.to_string());
            let v6 = self.status_of(&k, Family::Ipv6).filter(|s| s.state == "mapped" || s.state == "not_needed")
                .and_then(|_| l.bind_v6.map(|b| b.to_string()));
            let state = if ext.is_none() || !held {
                "unmapped"
            } else {
                match self.reachability_state(&k, ext_s.as_deref()) {
                    Some((s, at, _, _)) if s == "reachable" && at + 1.0 >= l.since_ext() => "reachable",
                    Some((s, at, _, _)) if s == "unreachable" && at + 1.0 >= l.since_ext() => "unreachable",
                    _ => "mapped_unverified",
                }
            };
            let (channel, _) = (l.rt.lookup)();
            let chan_id = channel.as_ref().map(|c| Arc::as_ptr(c) as usize);
            let l = self.listeners.get_mut(&k).expect("present");
            if l.last_external != ext_s {
                l.last_external = ext_s.clone();
                l.since = now();
                if let Some(e) = ext_s.as_ref().and_then(|e| e.parse::<SocketAddr>().ok()) {
                    let ip = e.ip().to_string();
                    if self.history.last().is_none_or(|h| h.0 != ip) {
                        self.history.push((ip, now()));
                        let cut = now() - 30.0 * 86400.0;
                        self.history.retain(|h| h.1 > cut);
                        let _ = crate::fsutil::write_private(&self.layout.state().join("listener-addresses.json"),
                                                             &serde_json::to_vec(&self.history).unwrap_or_default());
                    }
                }
            }
            let msg = json!({"op": "listener", "name": l.spec.name, "external": ext_s, "external_v6": v6, "state": state, "since": l.since});
            if l.announced.as_ref() != Some(&msg) || l.channel_seen != chan_id {
                if let Some(dir) = &l.data {
                    let file = crate::services::listeners_file(dir, &l.service);
                    let mut doc: Map<String, Value> = std::fs::read(&file).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
                    doc.insert(l.spec.name.clone(), json!({"external": msg["external"], "external_v6": msg["external_v6"],
                                                            "state": state, "since": l.since}));
                    let _ = oarbank_portmap::journal::write_atomic(&file, &serde_json::to_vec(&doc).unwrap_or_default());
                }
                if let Some(c) = &channel {
                    c.notify(&msg);
                    l.channel_seen = chan_id;
                }
                l.announced = Some(msg);
            }
        }
    }

    /// The owner's STUN server, when named: the address the internet sees, every 30 minutes.
    fn stun(&mut self) {
        let Some(server) = self.policy["listener_stun_server"].as_str().map(str::to_string) else { return };
        if now() - self.stun_at < 1800.0 {
            return;
        }
        self.stun_at = now();
        let (out, local) = (self.stun_observed.clone(), self.net.local_v4.map(IpAddr::V4));
        tokio::spawn(async move {
            match oarbank_portmap::stun::binding(&server, local, Duration::from_secs(3)).await {
                Ok(a) => *lock(&out) = Some((a.ip(), now())),
                Err(e) => info!(error = %e, "STUN check failed"),
            }
        });
    }

    /// No fleet prober: the owner's own probe endpoint, when set, dials back (every 30 minutes and after a change).
    fn endpoint_probes(&mut self) {
        let Some(url) = self.policy["listener_probe_endpoint"].as_str().filter(|u| u.starts_with("https://")).map(str::to_string)
            else { return };
        let keys: Vec<String> = self.listeners.keys().cloned().collect();
        for k in keys {
            let no_prober = self.reach.get(&k).and_then(|r| r["state"].as_str()) == Some("no_prober");
            let l = &self.listeners[&k];
            let (ext, held) = self.external(&k, l);
            let Some(ext) = ext.filter(|_| held && no_prober) else { continue };
            let changed = l.probed_endpoint.as_deref() != Some(&ext.to_string());
            if !changed && now() - l.endpoint_probe_at < 1800.0 {
                continue;
            }
            let l = self.listeners.get_mut(&k).expect("present");
            l.endpoint_probe_at = now();
            l.probed_endpoint = Some(ext.to_string());
            let (id, nonce) = (probe::token(), probe::token());
            lock(&l.rt.probes).insert(format!("local-{id}"), nonce.clone());
            lock(&l.rt.probes).insert(id.clone(), nonce.clone());
            let (out, key, url) = (self.endpoint_reach.clone(), k.clone(), url.clone());
            tokio::spawn(async move {
                let r = endpoint_probe(&url, ext, &id, &nonce).await;
                lock(&out).insert(key, json!({"state": if r.ok() { "reachable" } else { "unreachable" }, "at": now(), "via": "endpoint",
                                              "detail": r.detail()}));
            });
        }
    }

    /// The heartbeat's `listeners`, `portmaps`, `network`, `probe_results` and (when asked) `listener_talkers`.
    pub fn report(&mut self) -> Value {
        if self.listeners.is_empty() && self.refused.is_empty() && self.map_tx.is_none() && lock(&self.probe_results).is_empty() {
            return json!({});
        }
        let view = lock(&self.view).clone();
        let fw = lock(&self.firewall).clone();
        let gx = view.discovery.as_ref().and_then(|d| d.external_ip);
        let observed = self.observed.or(lock(&self.stun_observed).map(|x| x.0));
        let mut listeners = vec![];
        for (k, l) in &self.listeners {
            let s4 = self.status_of(k, Family::Ipv4);
            let s6 = self.status_of(k, Family::Ipv6);
            let (ext, held) = self.external(k, l);
            let reach = self.reachability_state(k, None);
            let dialback = match &reach {
                Some((s, at, via, _)) if s == "reachable" && *at + 1.0 >= l.since_ext() => Some(Dialback::Reachable { via: via.clone(), at: *at }),
                Some((s, at, via, d)) if s == "unreachable" && *at + 1.0 >= l.since_ext() =>
                    Some(Dialback::Unreachable { via: via.clone(), at: *at, detail: d.clone() }),
                Some((s, ..)) if s == "no_prober" => Some(Dialback::NoProber),
                _ => None,
            };
            let changed_ago = self.history.len().ge(&2).then(|| self.history.last().map(|h| now() - h.1)).flatten();
            let inputs = classify::Inputs {
                mode: Some(l.entry.mode), port: ext.map(|e| e.port()).unwrap_or(l.entry.external_port.unwrap_or(l.bind.port())),
                internal: Some(l.bind), interface_public: addr::is_global(l.bind.ip()),
                map_state: s4.as_ref().map(|s| s.state.to_string()).unwrap_or_else(|| match l.entry.mode {
                    Mode::Manual => "manual".into(), Mode::None => "not_needed".into(), _ => "requesting".into() }),
                protocol: s4.as_ref().and_then(|s| s.protocol), unmappable: s4.as_ref().and_then(|s| s.unmappable),
                holder: s4.as_ref().and_then(|s| s.holder.clone()), gateway_external: gx, observed, external: ext, dialback,
                firewall_blocks: fw.as_ref().and_then(|f| f.blocks()), address_changed_ago_s: changed_ago,
                permanent_only_router: view.permanent_seen,
                renewed_ago_s: s4.as_ref().and_then(|s| s.expires_at.zip(s.lease_s)).map(|(e, ls)| now() - (e - ls as f64)),
                v6: l.bind_v6.map(|b| classify::V6 { address: b, state: s6.as_ref().map(|s| s.state.to_string()).unwrap_or_default(),
                                                     reachable: None }),
            };
            let out = classify::classify(&inputs);
            let probe_wanted = ext.is_some() && held && (l.probe_wanted_at == 0.0 || now() - l.probe_wanted_at > 1800.0
                || reach.as_ref().is_none_or(|r| r.1 + 1.0 < l.since_ext()));
            let state = if l.rt.disabled.load(Ordering::SeqCst) { "closed" }
                        else if (l.rt.lookup)().0.is_some() { "listening" } else { "held" };
            let c = &l.rt.counters;
            let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
            listeners.push(json!({
                "key": k, "service": format!("{}/{}", l.module, l.service), "state": state, "refused": null, "detail": null,
                "statement_seq": self.statement_seq, "bind": l.bind.to_string(), "bind_v6": l.bind_v6.map(|b| b.to_string()),
                "external": ext.map(|e| e.to_string()), "external_v6": l.bind_v6.filter(|_| s6.as_ref().is_some_and(|s| s.state == "mapped" || s.state == "not_needed")).map(|b| b.to_string()),
                "announced": l.announced.as_ref().map(|a| a["state"].clone()), "since": l.since, "handover": if l.spec.listen_fd { "listen_fd" } else { "connections" },
                "reachability": {"result": out.result, "flags": out.flags, "text": out.text, "fix": out.fix,
                                 "via": reach.as_ref().map(|r| r.2.clone()), "at": reach.as_ref().map(|r| r.1)},
                "conns": {"open": l.rt.open.load(Ordering::SeqCst), "accepted": g(&c.accepted), "bytes_in": g(&c.bytes_in), "bytes_out": g(&c.bytes_out),
                          "probes": g(&c.probes),
                          "refused": {"rate": g(&c.rate), "cap": g(&c.cap), "per_ip": g(&c.per_ip), "allow": g(&c.allow), "held": g(&c.held),
                                      "disabled": g(&c.disabled)}},
                "probe_wanted": probe_wanted}));
        }
        let wanted: Vec<String> = listeners.iter().filter(|l| l["probe_wanted"] == true).filter_map(|l| l["key"].as_str().map(str::to_string)).collect();
        for k in wanted {
            if let Some(l) = self.listeners.get_mut(&k) {
                if now() - l.probe_wanted_at > 60.0 {
                    l.probe_wanted_at = now();
                }
            }
        }
        for (k, r) in &self.refused {
            listeners.push(json!({"key": k, "state": "refused", "refused": r.code, "detail": r.detail, "statement_seq": self.statement_seq}));
        }
        let portmaps: Vec<Value> = view.statuses.iter().map(|s| json!({
            "key": s.key, "family": s.family.name(), "protocol": s.protocol.map(|p| p.name()), "gateway": s.gateway.map(|g| g.to_string()),
            "external": s.external.map(|e| e.to_string()), "internal": s.internal.to_string(), "lease_s": s.lease_s, "expires_at": s.expires_at,
            "verified_at": s.verified_at, "permanent": s.permanent, "state": s.state, "error": s.error, "holder": s.holder})).collect();
        let d = view.discovery.clone().unwrap_or_default();
        let network = json!({
            "gateway": self.net.gateway_v4.map(|g| g.to_string()), "local": self.net.local_v4.map(|a| a.to_string()),
            "local_v6": self.net.global_v6.map(|a| a.to_string()), "gateway_external": gx.map(|g| g.to_string()),
            "observed": observed.map(|o| o.to_string()),
            "protocols": {"pcp": d.pcp, "natpmp": d.natpmp, "upnp": d.upnp},
            "router_mappings": view.others.iter().map(|m| json!({"protocol": "TCP", "external_port": m.external_port, "internal": m.internal,
                                                                  "description": m.description, "ours": m.ours})).collect::<Vec<_>>(),
            "firewall": fw.map(|f| f.to_json()), "journal_error": view.journal_error});
        let mut out = json!({"listeners": listeners, "portmaps": portmaps, "network": network,
                             "probe_results": std::mem::take(&mut *lock(&self.probe_results))});
        if std::mem::take(&mut self.send_talkers) {
            out["listener_talkers"] = Value::Object(self.listeners.iter().map(|(k, l)| (k.clone(), l.rt.talkers())).collect());
        }
        out
    }

    /// Close every listener and delete every mapping (agent stop, node retired, uninstall). Returns how many journal
    /// entries were released.
    pub async fn shutdown(&mut self) -> usize {
        self.listeners.clear();
        if !self.started && self.map_tx.is_none() {
            return 0;
        }
        let Some(tx) = self.map_tx.take() else { return 0 };
        let (done, wait) = tokio::sync::oneshot::channel();
        if tx.send(MapCmd::ReleaseAll(done)).is_err() {
            return 0;
        }
        tokio::time::timeout(Duration::from_secs(20), wait).await.ok().and_then(|r| r.ok()).unwrap_or(0)
    }
}

impl Listener {
    /// Since when the current external endpoint holds (a dial-back older than that says nothing about it).
    fn since_ext(&self) -> f64 {
        self.since
    }
}

/// The NAT-PMP announcement socket: production binds UDP 5350 shared with other listeners and joins 224.0.0.1.
fn announce_socket(at: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    #[cfg(unix)]
    s.set_reuse_port(true)?;
    s.bind(&at.into())?;
    if at.ip().is_unspecified() {
        s.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 1), &Ipv4Addr::UNSPECIFIED)?;
    }
    s.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(s.into())
}

/// The owner's probe endpoint: `POST <url> {"host", "port", "probe_id"}` answered `{"ok", "line"}`.
async fn endpoint_probe(url: &str, ext: SocketAddr, id: &str, nonce: &str) -> probe::Outcome {
    let client = match crate::staging::origin_client() {
        Ok(c) => c,
        Err(e) => return probe::Outcome::Error(e.to_string()),
    };
    let r = client.post(url).json(&json!({"host": ext.ip().to_string(), "port": ext.port(), "probe_id": id})).send().await;
    match r {
        Ok(r) => match r.json::<Value>().await {
            Ok(v) => probe::check(v["line"].as_str().unwrap_or(""), nonce, Duration::ZERO),
            Err(e) => probe::Outcome::Error(e.to_string()),
        },
        Err(e) => probe::Outcome::Error(e.to_string()),
    }
}

/// `oarbank-agent probe-endpoint`: the owner-run dial-back endpoint (on a machine on another network).
pub async fn serve_probe_endpoint(bind_at: SocketAddr) -> anyhow::Result<()> {
    let l = tokio::net::TcpListener::bind(bind_at).await?;
    info!(at = %bind_at, "probe endpoint listening (POST {{host, port, probe_id}})");
    loop {
        let (mut s, _) = l.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut n = 0;
            while n < buf.len() {
                match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf[n..])).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(k)) => n += k,
                }
                if let Some(i) = buf[..n].windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                    let len = head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                    if n >= i + 4 + len {
                        break;
                    }
                }
            }
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
            let req: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let answer = match (req["host"].as_str().and_then(|h| h.parse::<IpAddr>().ok()), req["port"].as_u64(), req["probe_id"].as_str()) {
                (Some(ip), Some(p), Some(id)) if (1024..=65535).contains(&p) && probe::valid_token(id) => {
                    let line = async {
                        let mut c = tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(SocketAddr::new(ip, p as u16))).await.ok()?.ok()?;
                        c.write_all(&probe::request(id)).await.ok()?;
                        let l = tokio::time::timeout(Duration::from_secs(5), probe::read_line(&mut c)).await.ok()?.ok()?;
                        Some(String::from_utf8_lossy(&l).trim().to_string())
                    }.await;
                    json!({"ok": line.is_some(), "line": line})
                }
                _ => json!({"ok": false, "error": "bad request"}),
            };
            let b = answer.to_string();
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).as_bytes()).await;
        });
    }
}

/// `oarbank-agent portmap status`: the journal, and what the router says about each entry now.
pub async fn portmap_status(layout: &Layout) -> Value {
    let j = Journal::load(&layout.state().join("portmaps.json"));
    let entries: Vec<Value> = j.entries().iter().map(|e| serde_json::to_value(e).unwrap_or(Value::Null)).collect();
    json!({"journal": layout.state().join("portmaps.json").display().to_string(), "entries": entries})
}

/// `oarbank-agent portmap release-all`: delete every journaled mapping (the launcher's uninstall step). Entries the
/// router cannot be asked about stay journaled.
pub async fn portmap_release_all(layout: &Layout, env: &Env) -> Value {
    let path = layout.state().join("portmaps.json");
    let j = Journal::load(&path);
    if j.entries().is_empty() {
        return json!({"released": 0, "left": 0});
    }
    let snap = env.snapshot();
    let mut m = Manager::new(NetRouter::new(env.target.clone()), j, env.timing.clone(), "node");
    m.set_network(Family::Ipv4, snap.local_v4.map(IpAddr::V4), snap.gateway_v4.map(IpAddr::V4), now());
    m.set_network(Family::Ipv6, snap.global_v6.map(IpAddr::V6), snap.gateway_v6.map(IpAddr::V6), now());
    let r = m.release_all(now()).await;
    let released = r.iter().filter(|x| x.1 != oarbank_portmap::Released::Unreachable).count();
    json!({"released": released, "left": m.journal.entries().len(),
           "entries": r.iter().map(|(e, how)| json!({"key": e.key, "protocol": e.protocol.name(), "external_port": e.external_port,
                                                     "outcome": format!("{how:?}")})).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn release(services: Value, inbound: Value) -> Release {
        Release { id: "r1".into(), dir: PathBuf::from("/nonexistent"), tools: Value::Null,
                  modules: vec![json!({"name": "mod", "services": services, "sandbox": {"net": {"mode": "none", "inbound": inbound}}})] }
    }

    fn svc() -> Value {
        json!([{"name": "node", "endpoint": true, "lifecycle": "always", "listeners": ["peer"]}])
    }

    fn inbound() -> Value {
        json!([{"name": "peer", "protocol": "tcp", "port_hint": 9000, "port_policy": "stable", "handover": "connections",
                "proxy_protocol": false, "max_conns": 256, "max_conns_per_ip": 16, "new_conns_per_ip_per_s": 4.0, "idle_timeout_s": 120}])
    }

    fn plan_one(rel: Option<&Release>, entry: Value, policy: Value, off: &[String], disabled: bool) -> Plan {
        let st: Map<String, Value> = [("mod/peer".to_string(), entry)].into_iter().collect();
        plan(&Inputs { release: rel, statement: &st, policy: &policy, modules_disabled: off, listeners_disabled: disabled, windows: false })
            .remove("mod/peer").unwrap()
    }

    fn code(p: &Plan) -> &'static str {
        match p {
            Plan::Refuse(r) => r.code,
            Plan::Run { .. } => "run",
        }
    }

    /// A workload may serve a listener (docs/design/workloads.md): planned as a service's is, with the workload's name;
    /// a listen_fd listener is never a workload's.
    #[test]
    fn a_workload_serves_a_listener_no_service_lists() {
        let mut rel = release(json!([]), inbound());
        rel.modules[0]["workloads"] = json!([{"name": "worker", "listeners": ["peer"]}]);
        let p = plan_one(Some(&rel), json!({}), json!({}), &[], false);
        let Plan::Run { service, .. } = &p else { panic!("{p:?}") };
        assert_eq!(service, "worker");
        // a disabled service of the same name does not stop a workload's listener
        assert_eq!(code(&plan_one(Some(&rel), json!({}), json!({"disabled_services": ["mod/worker"]}), &[], false)), "run");
        let mut fd = inbound();
        fd[0]["handover"] = json!("listen_fd");
        let mut rel_fd = release(json!([]), fd);
        rel_fd.modules[0]["workloads"] = json!([{"name": "worker", "listeners": ["peer"]}]);
        assert_eq!(code(&plan_one(Some(&rel_fd), json!({}), json!({}), &[], false)), "LISTENER_HANDOVER_UNSUPPORTED");
    }

    #[test]
    fn every_gate_of_d47() {
        let rel = release(svc(), inbound());
        let ok = plan_one(Some(&rel), json!({}), json!({}), &[], false);
        let Plan::Run { spec, entry, service, .. } = &ok else { panic!("{ok:?}") };
        assert_eq!((service.as_str(), entry.external_port, entry.fallback, entry.mode), ("node", Some(9000), Fallback::Refuse, Mode::Auto));
        assert_eq!(spec.max_conns, 256);
        assert_eq!(code(&plan_one(None, json!({}), json!({}), &[], false)), "LISTENER_NOT_GRANTED");
        assert_eq!(code(&plan_one(Some(&release(svc(), json!([]))), json!({}), json!({}), &[], false)), "LISTENER_NOT_GRANTED");
        assert_eq!(code(&plan_one(Some(&release(json!([]), inbound())), json!({}), json!({}), &[], false)), "LISTENER_NO_TARGET");
        assert_eq!(code(&plan_one(Some(&rel), json!({}), json!({"disabled_services": ["mod/node"]}), &[], false)), "LISTENER_NO_TARGET");
        assert_eq!(code(&plan_one(Some(&rel), json!({}), json!({}), &["mod".into()], false)), "MODULE_DISABLED");
        assert_eq!(code(&plan_one(Some(&rel), json!({}), json!({}), &[], true)), "LISTENERS_DISABLED");
        assert_eq!(code(&plan_one(Some(&rel), json!({}), json!({"inbound_listeners": false}), &[], false)), "LISTENERS_FORBIDDEN");
        assert_eq!(code(&plan_one(Some(&rel), json!({}), json!({"protection": {"node": {"mode": "strict_yield"}}}), &[], false)),
                   "LISTENER_STRICT_YIELD");
        assert_eq!(code(&plan_one(Some(&rel), json!({"fallback": "sometimes"}), json!({}), &[], false)), "LISTENER_NOT_GRANTED");
        let fd = release(svc(), json!([{"name": "peer", "handover": "listen_fd"}]));
        let st: Map<String, Value> = [("mod/peer".to_string(), json!({}))].into_iter().collect();
        let p = plan(&Inputs { release: Some(&fd), statement: &st, policy: &json!({}), modules_disabled: &[], listeners_disabled: false, windows: true });
        assert_eq!(code(&p["mod/peer"]), "LISTENER_HANDOVER_UNSUPPORTED");
    }

    #[test]
    fn the_owner_can_only_lower_limits_and_flexible_ports_walk() {
        let s = Spec::parse(&inbound()[0]).unwrap();
        let l = s.lowered(&json!({"max_conns": 64, "max_conns_per_ip": 99, "idle_timeout_s": 10, "max_bytes_per_s": 1000}));
        assert_eq!((l.max_conns, l.max_conns_per_ip, l.idle, l.bytes_per_s), (64, 16, Duration::from_secs(10), Some(1000.0)));
        let flex = Spec { stable: false, ..s.clone() };
        assert_eq!(Entry::parse(&json!({}), &flex).unwrap().fallback, Fallback::NextFree { lo: 9000, hi: 9015 });
        let e = Entry::parse(&json!({"external_port": 9100, "mapping": "manual", "ipv6": "off", "bind": "127.0.0.1",
                                     "allow": ["198.51.100.0/24"], "internal_port": 41500}), &s).unwrap();
        assert_eq!((e.external_port, e.mode, e.ipv6, e.internal_port), (Some(9100), Mode::Manual, false, Some(41500)));
        assert_eq!(e.bind, Some("127.0.0.1".parse().unwrap()));
        assert!(Entry::parse(&json!({"allow": ["nope"]}), &s).is_err());
        let fd = Spec::parse(&json!({"name": "x", "handover": "listen_fd"})).unwrap();
        assert!(fd.listen_fd && fd.proxy, "listen_fd defaults to the PROXY header");
    }

    #[test]
    fn internal_ports_are_deterministic_and_skip_taken_ones() {
        let a = internal_port_for("mod/peer", (41000, 41999), |_| false).unwrap();
        assert_eq!(Some(a), internal_port_for("mod/peer", (41000, 41999), |_| false));
        assert!((41000..=41999).contains(&a));
        assert_eq!(internal_port_for("mod/peer", (41000, 41999), |p| p == a), Some(if a == 41999 { 41000 } else { a + 1 }));
        assert_eq!(internal_port_for("x", (41000, 41000), |_| true), None);
        assert_eq!(port_range(&json!({"listener_port_range": "42000-42010"})), (42000, 42010));
        assert_eq!(port_range(&json!({"listener_port_range": "80-90"})), (41000, 41999));
    }

    #[test]
    fn proxy_v2_headers_follow_the_spec() {
        let h = proxy_v2("203.0.113.5:51000".parse().unwrap(), "192.0.2.10:41000".parse().unwrap());
        assert_eq!(&h[..12], b"\r\n\r\n\0\r\nQUIT\n");
        assert_eq!((h[12], h[13], u16::from_be_bytes([h[14], h[15]])), (0x21, 0x11, 12));
        assert_eq!(&h[16..20], &[203, 0, 113, 5]);
        assert_eq!(u16::from_be_bytes([h[24], h[25]]), 51000);
        assert_eq!(h.len(), 28);
        let h6 = proxy_v2("[2001:db8::5]:51000".parse().unwrap(), "192.0.2.10:41000".parse().unwrap());
        assert_eq!((h6[13], h6.len()), (0x21, 16 + 36));
    }

    fn rt(spec: Spec, allow: Vec<Cidr>) -> Arc<Rt> {
        Arc::new(Rt::new("mod/peer", spec, allow, Arc::new(|| (None, Some("down".into()))), None, false))
    }

    #[test]
    fn admission_caps_buckets_and_allowlists() {
        let base = Spec::parse(&inbound()[0]).unwrap();
        let r = rt(Spec { max_conns: 3, max_conns_per_ip: 2, rate_per_ip: 100.0, ..base.clone() }, vec![]);
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        assert!(r.admit(a, None).is_ok() && r.admit(a, None).is_ok());
        assert_eq!(r.admit(a, None), Err("per_ip"));
        assert!(r.admit(b, None).is_ok());
        assert_eq!(r.admit("198.51.100.3".parse().unwrap(), None), Err("cap"));
        r.release(a);
        assert!(r.admit(a, None).is_ok(), "a slot frees when a connection ends");
        // the token bucket: a burst of twice the rate, then the rate
        let r = rt(Spec { rate_per_ip: 2.0, ..base.clone() }, vec![]);
        let ok = (0..10).filter(|_| r.admit(a, None).map(|_| r.release(a)).is_ok()).count();
        assert_eq!(ok, 4);
        assert_eq!(r.counters.rate.load(Ordering::Relaxed), 6);
        // the owner's list and the module's narrowing
        let r = rt(base.clone(), vec![Cidr::parse("198.51.0.0/16").unwrap()]);
        assert_eq!(r.admit("203.0.113.1".parse().unwrap(), None), Err("allow"));
        let narrow = [Cidr::parse("203.0.113.0/24").unwrap()];
        assert_eq!(r.admit(a, Some(&narrow)), Err("allow"), "the module can only narrow");
        r.disabled.store(true, Ordering::SeqCst);
        assert_eq!(r.admit(a, None), Err("disabled"));
    }

    #[tokio::test]
    async fn a_probe_is_answered_by_the_agent_and_a_held_service_closes_connections() {
        let r = rt(Spec::parse(&inbound()[0]).unwrap(), vec![]);
        let (id, nonce) = (probe::token(), probe::token());
        lock(&r.probes).insert(id.clone(), nonce.clone());
        let l = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let at = l.local_addr().unwrap();
        let _t = spawn_accept(r.clone(), l);
        // from loopback: the node's own network
        assert_eq!(probe::dial(at, &id, &nonce, Duration::from_secs(5)).await, probe::Outcome::SameNetwork);
        let r2 = Arc::new(Rt::new("mod/peer", Spec::parse(&inbound()[0]).unwrap(), vec![], Arc::new(|| (None, None)), None, true));
        lock(&r2.probes).insert(id.clone(), nonce.clone());
        let l2 = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let at2 = l2.local_addr().unwrap();
        let _t2 = spawn_accept(r2.clone(), l2);
        assert!(probe::dial(at2, &id, &nonce, Duration::from_secs(5)).await.ok());
        assert_eq!(probe::dial(at2, &probe::token(), &nonce, Duration::from_secs(5)).await, probe::Outcome::WrongAnswer, "unknown probe id");
        // a real client while the service is down: closed at once, counted as held
        let mut c = tokio::net::TcpStream::connect(at2).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut b = [0u8; 8];
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), c.read(&mut b)).await.unwrap().unwrap_or(0), 0);
        assert_eq!(r2.counters.held.load(Ordering::Relaxed), 1);
        assert_eq!(r2.open.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_relay_copies_both_ways_counts_and_ends_idle_connections() {
        let r = rt(Spec { idle: Duration::from_millis(400), bytes_per_s: Some(1_000_000.0), ..Spec::parse(&inbound()[0]).unwrap() }, vec![]);
        let (client, tcp_side) = tokio::io::duplex(4096);
        let (module_side, module) = tokio::io::duplex(4096);
        let r2 = r.clone();
        let task = tokio::spawn(async move { relay(tcp_side, module_side, &r2).await });
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut mr, mut mw) = tokio::io::split(module);
        cw.write_all(b"hello").await.unwrap();
        let mut b = [0u8; 5];
        mr.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"hello");
        mw.write_all(b"world!").await.unwrap();
        let mut b = [0u8; 6];
        cr.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"world!");
        tokio::time::timeout(Duration::from_secs(5), task).await.expect("idle connections end").unwrap();
        assert_eq!((r.counters.bytes_in.load(Ordering::Relaxed), r.counters.bytes_out.load(Ordering::Relaxed)), (5, 6));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_owners_probe_endpoint_dials_back() {
        let r = Arc::new(Rt::new("mod/peer", Spec::parse(&inbound()[0]).unwrap(), vec![], Arc::new(|| (None, None)), None, true));
        let (id, nonce) = (probe::token(), probe::token());
        lock(&r.probes).insert(id.clone(), nonce.clone());
        let l = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let target = l.local_addr().unwrap();
        let _t = spawn_accept(r, l);
        let ep = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ep_at = ep.local_addr().unwrap();
        drop(ep);
        tokio::spawn(serve_probe_endpoint(ep_at));
        tokio::time::sleep(Duration::from_millis(200)).await;
        let body = json!({"host": "127.0.0.1", "port": target.port(), "probe_id": id}).to_string();
        let mut s = tokio::net::TcpStream::connect(ep_at).await.unwrap();
        s.write_all(format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        let v: Value = serde_json::from_str(out.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert!(probe::check(v["line"].as_str().unwrap(), &nonce, Duration::ZERO).ok(), "{v}");
    }
}
