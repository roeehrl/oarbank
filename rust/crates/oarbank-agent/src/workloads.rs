//! Workloads (docs/design/workloads.md; the SDK's spec/workload-protocol.md): supervised long-running processes that
//! are the work itself. The owner assigns a workload to the node; the coordinator's directives say what to run, with a
//! seat lease for a workload whose identity belongs to one node (D46). The agent runs `<exec> run` as one long-running
//! process in the module sandbox, in a lasting container of its own, gives it its secrets, the runner control document,
//! a per-run home and an event file, restarts it with backoff and full jitter, and withdraws it after `max_failures`.
//!
//! Containers (`sys::spawn_workload`): the leader's process group on macOS, plus every process of the agent's account
//! whose sandbox profile is the workload's own (a process cannot drop the profile it inherited, so a daemon that calls
//! `setsid` and forks twice is still found: `escapees`); the delegated cgroup leaf on Linux (without one, workloads are
//! not offered); a named Job Object on Windows. Every signal goes through the spawn registry (S16).
//!
//! A workload outlives its agent: a graceful stop of the agent leaves it running, and the next agent adopts it from
//! its record (`<home>/state/workloads/<module>.<name>.json`) while its lease still runs on the boot clock and its
//! leader is the recorded process.
//!
//! The agent's tick (every 2 s) reads state and hands out work; a start (which waits for the sandbox launcher), a stop
//! (which waits up to `stop_timeout_s`) and a health check run on threads of their own.

use crate::doctor::{base_env, grant_files, resolve_exec};
use crate::endpoints::{self, Channel, Refusal};
use crate::jobs::ControlFile;
use crate::paths::Layout;
use crate::procs;
use crate::release::Release;
use crate::runtime::Runtime;
use oarbank_protection::{FleetWorkloadView, SpawnRegistry, WorkloadAction};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// The workload protocol major this agent speaks.
pub const PROTOCOL: u32 = 1;
/// A workload's log is kept under this size; the older part moves to `.1`.
const LOG_MAX: u64 = 4 << 20;
/// What a heartbeat carries of a workload's log.
const LOG_TAIL: usize = 2048;
/// A report event's data, as JSON, at most; reports a minute per workload; reports queued.
pub const REPORT_MAX_BYTES: usize = 4096;
pub const REPORTS_PER_MIN: u32 = 60;
const REPORTS_QUEUED: usize = 200;
/// How often the records follow a lease that moved.
const RECORD_LEASE_STEP_S: f64 = 30.0;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A clock that runs while the machine sleeps, so a lease that ran out during a sleep has run out on waking: macOS
/// `CLOCK_MONOTONIC` (it counts sleep on Darwin), Linux `CLOCK_BOOTTIME`, Windows `GetTickCount64`. Never the wall clock
/// (it can be set) and never Rust's `Instant` (it stops during sleep on macOS and Linux).
pub mod boot {
    /// Seconds since an arbitrary point in this boot.
    pub fn now_s() -> f64 {
        #[cfg(unix)]
        {
            #[cfg(target_os = "linux")]
            let clock = libc::CLOCK_BOOTTIME;
            #[cfg(not(target_os = "linux"))]
            let clock = libc::CLOCK_MONOTONIC;
            let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            unsafe { libc::clock_gettime(clock, &mut ts) };
            ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
        }
        #[cfg(windows)]
        {
            (unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }) as f64 / 1000.0
        }
    }

    /// This boot's identity: a record from another boot names processes that are gone.
    pub fn id() -> String {
        #[cfg(target_os = "macos")]
        {
            let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
            let mut len = std::mem::size_of::<libc::timeval>();
            let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
            let r = unsafe { libc::sysctl(mib.as_mut_ptr(), 2, &mut tv as *mut _ as *mut _, &mut len, std::ptr::null_mut(), 0) };
            if r == 0 { format!("darwin-{}.{}", tv.tv_sec, tv.tv_usec) } else { "darwin-unknown".into() }
        }
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()).unwrap_or_default()
        }
        #[cfg(windows)]
        {
            // the boot's wall time, to a minute (the tick count and the wall clock are read a moment apart)
            let boot = crate::doctor::now() - now_s();
            format!("windows-{}", (boot / 60.0).round() as i64)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            String::new()
        }
    }
}

fn secs(v: &Value, default: f64, min: f64) -> f64 {
    v.as_f64().filter(|x| x.is_finite()).unwrap_or(default).max(min)
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// A release entry's `workloads[]` item, with the manifest's defaults (the coordinator sends this platform's only).
#[derive(Debug, Clone, PartialEq)]
pub struct Decl {
    pub module: String,
    pub name: String,
    exec: Vec<Value>,
    per_node: bool,
    secrets: Vec<String>,
    listeners: Vec<String>,
    cpu_cores: f64,
    mem_gb: f64,
    gpu: bool,
    apis_any: Vec<String>,
    freeze_ok: bool,
    coop_pause: bool,
    coop_throttle: bool,
    pause_tolerance_s: f64,
    stop_timeout: Duration,
    backoff_initial_s: f64,
    backoff_max_s: f64,
    max_failures: u32,
    jitter: bool,
    health: Option<(Duration, Duration, u32)>,
    reports: bool,
}

impl Decl {
    pub fn parse(module: &str, v: &Value) -> Option<Decl> {
        let name = v["name"].as_str()?.to_string();
        let exec = v["exec"].as_array()?.clone();
        let plats = strings(&v["platforms"]);
        if exec.is_empty() || !(plats.is_empty() || plats.contains(&crate::facts::platform_token())) {
            return None;
        }
        let control = strings(&v["control"]);
        let has = |c: &str| control.iter().any(|x| x == c);
        let pausable = has("cooperative_pause") || has("freeze_ok");
        let r = &v["restart"];
        let initial = secs(&r["backoff_initial_s"], 10.0, 0.01);
        let gpu = v["gpu"]["use"].as_str().is_some_and(|u| u != "none");
        let h = &v["health"];
        Some(Decl {
            module: module.to_string(),
            name,
            exec,
            per_node: v["identity"].as_str() == Some("per_node"),
            secrets: strings(&v["secrets"]),
            listeners: strings(&v["listeners"]),
            cpu_cores: secs(&v["resources"]["cpu_cores"], 1.0, 0.0),
            mem_gb: secs(&v["resources"]["mem_gb"], 0.5, 0.0),
            gpu,
            apis_any: if gpu { strings(&v["gpu"]["apis_any"]) } else { vec![] },
            freeze_ok: has("freeze_ok"),
            coop_pause: has("cooperative_pause"),
            coop_throttle: has("cooperative_throttle"),
            pause_tolerance_s: if pausable { secs(&v["pause_tolerance_s"], 20.0, 0.0).min(600.0) } else { 0.0 },
            stop_timeout: Duration::from_secs_f64(secs(&v["stop_timeout_s"], 30.0, 0.5).min(600.0)),
            backoff_initial_s: initial,
            backoff_max_s: secs(&r["backoff_max_s"], 600.0, initial),
            max_failures: r["max_failures"].as_u64().unwrap_or(5).clamp(1, 1000) as u32,
            jitter: r["jitter"].as_str() != Some("none"),
            health: h.is_object().then(|| (Duration::from_secs_f64(secs(&h["period_s"], 15.0, 1.0)),
                                            Duration::from_secs_f64(secs(&h["timeout_s"], 5.0, 0.5)),
                                            h["failures"].as_u64().unwrap_or(3).clamp(1, 100) as u32)),
            reports: v["reports"].as_bool() == Some(true),
        })
    }

    fn key(&self) -> String {
        format!("{}/{}", self.module, self.name)
    }

    /// The backoff after `n` consecutive failures: exponential, capped, and with full jitter a uniform draw below it.
    pub fn backoff(&self, n: u32, draw: f64) -> f64 {
        let d = (self.backoff_initial_s * 2f64.powi(n.saturating_sub(1).min(60) as i32)).min(self.backoff_max_s);
        if self.jitter { d * draw.clamp(0.0, 1.0) } else { d }
    }
}

type ProxySlot = Arc<Mutex<Option<crate::proxy::Proxy>>>;

/// What running one module's workloads needs: its paths, settings, tool grants and network grant.
struct Ctx {
    module: String,
    module_id: String,
    bundle: PathBuf,
    python: PathBuf,
    venv: Option<PathBuf>,
    data: PathBuf,
    roots: Vec<String>,
    net: String,
    gpu_device: bool,
    exec_rw: bool,
    node_id: String,
    settings: Value,
    tool_grants: Value,
    entry: Value,
    proxy: Option<ProxySlot>,
}

impl Ctx {
    fn proxy_port(&self) -> Option<u16> {
        let slot = self.proxy.as_ref()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(p) = lock(slot).as_ref() {
                return Some(p.port);
            }
            if Instant::now() > deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// What the directives want of one workload.
#[derive(Debug, Clone, Default, PartialEq)]
struct Want {
    running: bool,
    seat: Option<String>,
    fence: i64,
    /// The lease's end on the boot clock (None: no identity, no lease).
    deadline: Option<f64>,
    restart_seq: i64,
    reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Starting,
    Running,
    Stopping,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Idle => "stopped",
            Phase::Starting => "starting",
            Phase::Running => "running",
            Phase::Stopping => "stopping",
        }
    }
}

/// What protection asked of the run and what was applied.
#[derive(Debug, Clone, Default, PartialEq)]
struct Applied {
    frozen: bool,
    coop_paused: bool,
    lowered: bool,
    threads: Option<i64>,
    cpu_cap: Option<f64>,
}

/// One live run of a workload.
struct Run {
    n: u64,
    leader: i32,
    start_us: u64,
    child: Option<std::process::Child>,
    control: Option<ControlFile>,
    private: PathBuf,
    run_dir: PathBuf,
    seat: Option<String>,
    fence: i64,
    deadline: Option<f64>,
    /// Processes of the workload outside its process group (macOS: found by sandbox identity), pid and start time.
    members: Vec<(i32, u64)>,
    channel: Option<Arc<Channel>>,
    channel_lost: Arc<AtomicBool>,
    adopted: bool,
    started_wall: f64,
    applied: Applied,
    /// The control document's fields as last written.
    doc: Value,
    record_deadline: Option<f64>,
    record_members: usize,
    job_name: String,
    secret_values: Vec<(String, Value)>,
}

#[derive(Debug, Default)]
struct HealthSt {
    fails: u32,
    last: Option<Instant>,
    busy: bool,
    healthy: Option<bool>,
    detail: String,
}

#[derive(Debug, Default)]
struct EventsSt {
    offset: u64,
    partial: String,
    progress: BTreeMap<String, u64>,
    queue: VecDeque<Value>,
    next_seq: u64,
    window: Option<(Instant, u32)>,
    dropped: u64,
    last_error: Option<String>,
}

/// One workload's state on this node.
struct Wl {
    decl: Decl,
    want: Want,
    phase: Phase,
    run: Option<Run>,
    /// Why it is not offered here (a reason code and the detail).
    blocked: Option<(&'static str, String)>,
    failures: u32,
    withdrawn: bool,
    next_try: Option<Instant>,
    last_error: Option<String>,
    restart_seq: i64,
    restarts: u64,
    /// Protection's hold (the release reason and the journal code) and whether it admits a start.
    hold: Option<(String, &'static str)>,
    admit: bool,
    plan: WorkloadAction,
    secrets: Option<(Option<String>, i64, Map<String, Value>)>,
    secrets_error: Option<String>,
    health: HealthSt,
    events: EventsSt,
    /// The seat and fence of the last run (the report says it stopped with them).
    last_seat: Option<(Option<String>, i64)>,
    /// The seat may go to another node (its lease lapsed here, it was withdrawn, or it cannot run here).
    release: bool,
    usage: procs::Usage,
    started_at: f64,
}

impl Wl {
    fn new(decl: Decl) -> Wl {
        Wl { decl, want: Want::default(), phase: Phase::Idle, run: None, blocked: None, failures: 0, withdrawn: false,
             next_try: None, last_error: None, restart_seq: 0, restarts: 0, hold: None, admit: true,
             plan: WorkloadAction { admit: true, ..Default::default() }, secrets: None, secrets_error: None,
             health: HealthSt::default(), events: EventsSt::default(), last_seat: None, release: false,
             usage: Default::default(), started_at: 0.0 }
    }

    fn key(&self) -> String {
        self.decl.key()
    }

    /// The run failed: back off (full jitter), withdraw after `max_failures`.
    fn failed(&mut self, why: &str) {
        self.failures += 1;
        let draw: f64 = rand::random::<f64>();
        let delay = self.decl.backoff(self.failures, draw);
        self.next_try = Some(Instant::now() + Duration::from_secs_f64(delay));
        self.last_error = Some(format!("{why} ({} in a row); retry in {delay:.0} s", self.failures));
        if self.failures >= self.decl.max_failures && !self.withdrawn {
            self.withdrawn = true;
            self.release = true;
            warn!(workload = %self.key(), failures = self.failures, "workload withdrawn after repeated failures");
        } else {
            warn!(workload = %self.key(), why, "workload run failed");
        }
    }
}

/// Wakes what waits for a workload's channel (`listener_lookup`).
#[derive(Default)]
struct Changed {
    seq: Mutex<u64>,
    cv: Condvar,
}

impl Changed {
    fn bump(&self) {
        *lock(&self.seq) += 1;
        self.cv.notify_all();
    }

    fn wait_for<T>(&self, deadline: Instant, mut f: impl FnMut() -> Option<T>) -> Option<T> {
        loop {
            let seen = *lock(&self.seq);
            if let Some(v) = f() {
                return Some(v);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let g = lock(&self.seq);
            if *g == seen {
                let _ = self.cv.wait_timeout(g, deadline - now);
            }
        }
    }
}

impl endpoints::Waker for Changed {
    fn changed(&self) {
        self.bump();
    }
}

#[derive(Default)]
struct Shared {
    w: BTreeMap<String, Wl>,
}

type SharedRef = Arc<Mutex<Shared>>;

impl Clone for Env {
    fn clone(&self) -> Env {
        Env { layout: Layout::new(self.layout.home.clone()), registry: self.registry.clone(), shared: self.shared.clone(),
              changed: self.changed.clone() }
    }
}

/// What a start or stop thread needs.
struct Env {
    layout: Layout,
    registry: Option<Arc<SpawnRegistry>>,
    shared: SharedRef,
    changed: Arc<Changed>,
}

pub struct WorkloadManager {
    layout: Layout,
    runtime: Runtime,
    registry: Option<Arc<SpawnRegistry>>,
    shared: SharedRef,
    changed: Arc<Changed>,
    ctxs: BTreeMap<String, Arc<Ctx>>,
    proxies: HashMap<String, (Vec<String>, ProxySlot)>,
    node_id: String,
    /// The node's `workloads` setting (a machine's managed policy may force it off).
    allowed: bool,
    gpu_apis: Vec<String>,
    disabled_modules: BTreeSet<String>,
    limits: Value,
    last_scan: Option<Instant>,
}

/// A workload's record file.
fn record_path(layout: &Layout, key: &str) -> PathBuf {
    layout.state().join("workloads").join(format!("{}.json", key.replace('/', ".")))
}

/// The name of a workload's Windows Job Object: per home and workload, so two agents never share one.
fn job_name(layout: &Layout, key: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("{}\0{key}", layout.home.display()).as_bytes());
    format!("Local\\oarbank-workload-{}", &hex::encode(h)[..16])
}

/// A workload's private directory: the control document, the secrets file, its grants and sandbox profile. Only its own
/// profile grants reading it (the macOS identity check reads exactly this).
fn private_dir(layout: &Layout, decl: &Decl) -> PathBuf {
    layout.run().join("workloads").join(&decl.module).join(&decl.name)
}

/// A file beside the workload's private directory that no module's profile grants (a sibling, so any profile that
/// grants reading that whole area grants it too): the denied half of the identity check. It must exist: some
/// profiles allow reading existing files of an area and deny the rest.
fn canary_of(private: &Path) -> PathBuf {
    let mut p = private.as_os_str().to_owned();
    p.push(".canary");
    PathBuf::from(p)
}

/// Make the canary beside a private directory (idempotent).
fn ensure_canary(private: &Path) {
    let c = canary_of(private);
    if !c.exists() {
        let _ = std::fs::write(&c, b"not granted to any module process\n");
    }
}

/// Whether this node can contain a workload (macOS: always; Linux: with a delegated cgroup; Windows: Job Objects).
fn containment() -> Result<(), String> {
    if !crate::sandbox::available() {
        return Err("this node has no module sandbox".into());
    }
    #[cfg(target_os = "linux")]
    if crate::cgroup::root().is_none() {
        return Err("Linux contains a workload in a delegated cgroup, and the agent's cgroup is not delegated (run it as a \
                    systemd unit with Delegate=yes)".into());
    }
    Ok(())
}

impl WorkloadManager {
    pub fn new(layout: Layout, runtime: Runtime, registry: Option<Arc<SpawnRegistry>>) -> Self {
        let _ = std::fs::create_dir_all(layout.state().join("workloads"));
        WorkloadManager { layout, runtime, registry, shared: SharedRef::default(), changed: Arc::default(), ctxs: BTreeMap::new(),
                          proxies: HashMap::new(), node_id: String::new(), allowed: true, gpu_apis: vec![],
                          disabled_modules: BTreeSet::new(), limits: json!({}), last_scan: None }
    }

    fn env(&self) -> Env {
        Env { layout: Layout::new(self.layout.home.clone()), registry: self.registry.clone(), shared: self.shared.clone(),
              changed: self.changed.clone() }
    }

    /// Adopt the workloads an earlier agent left running (call once, before the first hello, so hello reports them and
    /// the coordinator renews their leases). A record whose leader still has its start time, from this boot, whose
    /// lease still runs (or that has none) and that serves no listener is adopted; anything else it names is ended.
    pub fn adopt(&mut self, release: Option<&Release>) {
        let dir = self.layout.state().join("workloads");
        let boot_now = boot::now_s();
        let this_boot = boot::id();
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = e.path();
            if path.extension().is_none_or(|x| x != "json") {
                continue;
            }
            let Some(rec) = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else {
                let _ = std::fs::remove_file(&path);
                continue;
            };
            let key = rec["key"].as_str().unwrap_or("").to_string();
            let leader = rec["leader"].as_i64().unwrap_or(0) as i32;
            let start: u64 = rec["start_us"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
            let alive = leader > 1 && procs::start_time_us(leader) == Some(start);
            let same_boot = rec["boot"].as_str() == Some(this_boot.as_str());
            let lease_ok = rec["deadline"].as_f64().is_none_or(|d| d > boot_now);
            let decl = release.and_then(|r| {
                let (m, n) = key.split_once('/')?;
                r.module(m)?["workloads"].as_array()?.iter().filter_map(|w| Decl::parse(m, w)).find(|d| d.name == n)
            });
            let listens = rec["listeners"].as_bool() == Some(true);
            let why = if !alive {
                Some("its process has ended")
            } else if !same_boot {
                Some("it is from another boot")
            } else if !lease_ok {
                Some("its seat lease has run out")
            } else if listens {
                Some("it serves listeners, whose channel ended with the earlier agent")
            } else if decl.is_none() {
                Some("this node's release no longer declares it")
            } else {
                None
            };
            if let Some(why) = why {
                info!(workload = %key, why, "not adopting a workload an earlier agent ran: ending what its record names");
                end_recorded(&self.layout, &rec);
                let _ = std::fs::remove_file(&path);
                continue;
            }
            let decl = decl.expect("checked");
            let name = rec["job"].as_str().unwrap_or("").to_string();
            if !crate::sys::adopt_workload(leader, &name) {
                warn!(workload = %key, "could not take over the workload's container: ending it");
                end_recorded(&self.layout, &rec);
                let _ = std::fs::remove_file(&path);
                continue;
            }
            if let Some(r) = &self.registry {
                if !r.register_workload(leader, &key, Some(start)) {
                    end_recorded(&self.layout, &rec);
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
            }
            let private = PathBuf::from(rec["private"].as_str().unwrap_or(""));
            let members: Vec<(i32, u64)> = rec["members"].as_array().into_iter().flatten().filter_map(|m| {
                let (p, s) = (m[0].as_i64()? as i32, m[1].as_str()?.parse::<u64>().ok()?);
                (procs::start_time_us(p) == Some(s)).then_some((p, s))
            }).collect();
            let control = ControlFile::resume(&private, leader).ok();
            let seat = rec["seat"].as_str().map(str::to_string);
            let fence = rec["fence"].as_i64().unwrap_or(0);
            let deadline = rec["deadline"].as_f64();
            info!(workload = %key, leader, "adopted a workload an earlier agent started");
            let run = Run { n: rec["run"].as_u64().unwrap_or(0), leader, start_us: start, child: None, control,
                            private, run_dir: PathBuf::from(rec["run_dir"].as_str().unwrap_or("")), seat: seat.clone(), fence,
                            deadline, members, channel: None, channel_lost: Arc::default(), adopted: true,
                            started_wall: rec["started_at"].as_f64().unwrap_or(0.0), applied: Applied::default(),
                            doc: json!({}), record_deadline: deadline, record_members: 0, job_name: name, secret_values: vec![] };
            let mut w = Wl::new(decl);
            w.phase = Phase::Running;
            w.want = Want { running: true, seat, fence, deadline, ..Default::default() };
            w.started_at = run.started_wall;
            w.events.offset = std::fs::metadata(run.run_dir.join("events.ndjson")).map(|m| m.len()).unwrap_or(0);
            let mut run = run;
            write_record(&self.layout, &key, &mut run);           // now this agent's (an earlier watchdog lets it be)
            w.run = Some(run);
            lock(&self.shared).w.insert(key, w);
        }
    }

    /// The GPU APIs the host provides: a GPU workload whose `apis_any` they do not meet is not offered here.
    pub fn set_gpu_apis(&mut self, host: Vec<String>) {
        self.gpu_apis = host;
    }

    /// The node's `workloads` setting (the effective policy, after this machine's managed policy).
    pub fn set_allowed(&mut self, on: bool) {
        if on != self.allowed {
            info!(allowed = on, "workloads setting changed");
        }
        self.allowed = on;
    }

    /// The owner's caps, passed to workloads as OARBANK_LIMITS_FILE.
    pub fn set_limits(&mut self, limits: &Value) {
        self.limits = limits.clone();
    }

    fn proxy_for(&mut self, module: &str, allow: Vec<String>) -> ProxySlot {
        if let Some((a, slot)) = self.proxies.get(module) {
            if *a == allow {
                return slot.clone();
            }
        }
        let slot = ProxySlot::default();
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                let (s2, a2, m) = (slot.clone(), allow.clone(), module.to_string());
                h.spawn(async move {
                    match crate::proxy::start(a2).await {
                        Ok(p) => *lock(&s2) = Some(p),
                        Err(e) => warn!(module = %m, error = %e, "cannot start the workloads' egress proxy"),
                    }
                });
            }
            Err(_) => warn!(module, "no async runtime for the egress proxy: workloads run without network"),
        }
        self.proxies.insert(module.to_string(), (allow, slot.clone()));
        slot
    }

    /// A new release or policy: read the workloads from the release's module entries. State carries over for
    /// workloads that stay; one the release no longer has is stopped.
    pub fn configure(&mut self, release: &Release, policy: &Value, node_id: Option<&str>, modules_disabled: &[String]) {
        if let Some(n) = node_id {
            self.node_id = n.to_string();
        }
        self.disabled_modules = modules_disabled.iter().cloned().collect();
        let mut ctxs = BTreeMap::new();
        let mut decls = vec![];
        for entry in &release.modules {
            let Some(name) = entry["name"].as_str().map(str::to_string) else { continue };
            let ds: Vec<Decl> = entry["workloads"].as_array().into_iter().flatten().filter_map(|w| Decl::parse(&name, w)).collect();
            if ds.is_empty() {
                continue;
            }
            let net = entry["sandbox"]["net"]["mode"].as_str().unwrap_or("none").to_string();
            let proxy = (net == "egress-allowlist").then(|| self.proxy_for(&name, strings(&entry["sandbox"]["net"]["allow"])));
            let mut settings = policy["module_settings"][&name].clone();
            if settings.is_null() {
                settings = json!({});
            }
            ctxs.insert(name.clone(), Arc::new(Ctx {
                module_id: entry["module_id"].as_str().unwrap_or(&name).to_string(),
                bundle: release.bundle(entry),
                python: self.runtime.module_python(&release.dir, &name),
                venv: Some(release.dir.join("venvs").join(&name)).filter(|v| v.exists()),
                data: self.layout.module_data().join(&name),
                roots: self.runtime.roots.clone(),
                net,
                gpu_device: entry["sandbox"]["devices"]["gpu"].as_str().is_some_and(|g| g != "none"),
                exec_rw: entry["sandbox"]["exec_writable"].as_bool() == Some(true),
                node_id: self.node_id.clone(),
                settings,
                tool_grants: policy["tool_grants"][&name].clone(),
                entry: entry.clone(),
                proxy,
                module: name.clone(),
            }));
            decls.extend(ds);
        }
        self.proxies.retain(|m, _| ctxs.get(m).is_some_and(|c: &Arc<Ctx>| c.proxy.is_some()));
        self.ctxs = ctxs;
        let mut sh = lock(&self.shared);
        let keys: BTreeSet<String> = decls.iter().map(Decl::key).collect();
        for d in decls {
            let key = d.key();
            match sh.w.get_mut(&key) {
                Some(w) => {
                    if w.decl != d {
                        // a new version of the module: a fresh start (a withdrawal ends)
                        w.withdrawn = false;
                        w.failures = 0;
                        w.next_try = None;
                    }
                    w.decl = d;
                }
                None => {
                    sh.w.insert(key, Wl::new(d));
                }
            }
        }
        for (k, w) in sh.w.iter_mut().filter(|(k, _)| !keys.contains(*k)) {
            if w.want.running {
                info!(workload = %k, "this node's release no longer declares the workload: stopping it");
            }
            w.want.running = false;
            w.blocked = Some(("WORKLOAD_NOT_OFFERED", "this node's release no longer declares it".into()));
        }
    }

    /// The directives' `workloads` (docs/protocol.md, "Workloads"): what to run, with each seat's fence and lease.
    /// `sent_boot`: the boot clock when the request this answers was sent (a lease ends no later than the coordinator's
    /// own end). Absent (an older coordinator, or none yet): nothing changes.
    pub fn set_wanted(&mut self, list: &Value, sent_boot: f64) {
        let Some(items) = list.as_array() else { return };
        let mut seen = BTreeSet::new();
        let mut sh = lock(&self.shared);
        for it in items {
            let Some(key) = it["key"].as_str() else { continue };
            seen.insert(key.to_string());
            let Some(w) = sh.w.get_mut(key) else { continue };
            let running = it["desired"].as_str() == Some("running");
            let seat = it["seat_id"].as_str().map(str::to_string);
            let fence = it["fence"].as_i64().unwrap_or(0);
            let deadline = it["lease_s"].as_f64().map(|l| sent_boot + l.max(0.0));
            let restart_seq = it["restart_seq"].as_i64().unwrap_or(0);
            if restart_seq > w.restart_seq && w.withdrawn {
                w.withdrawn = false;                              // a restart operation lifts a withdrawal
                w.failures = 0;
                w.next_try = None;
            }
            // a renewal never shortens a lease already granted for the same seat and fence (a reply to an older request)
            let deadline = match (deadline, w.want.deadline) {
                (Some(d), Some(old)) if w.want.seat == seat && w.want.fence == fence => Some(d.max(old)),
                (d, _) => d,
            };
            w.want = Want { running, seat, fence, deadline, restart_seq, reason: it["reason"].as_str().map(str::to_string) };
            // told to stop, this node gives the seat up once nothing of it runs (the coordinator frees a seat only on such a
            // release with the current fence: specs/OarbankSeat.tla, finding F1)
            w.release = !running;
        }
        for (k, w) in sh.w.iter_mut().filter(|(k, _)| !seen.contains(*k)) {
            if w.want.running {
                info!(workload = %k, "not assigned to this node any more: stopping it");
            }
            w.want.running = false;
            w.want.reason = Some("WORKLOAD_UNASSIGNED".into());
            w.release = true;
        }
    }

    /// Workloads waiting for their secrets for a seat and fence: `(key, seat, fence)`. The agent fetches them
    /// (`POST /v1/agent/workloads/secrets`) and hands them back with `provide_secrets`.
    pub fn needs_secrets(&self) -> Vec<(String, Option<String>, i64)> {
        let sh = lock(&self.shared);
        sh.w.iter().filter(|(_, w)| {
            w.phase == Phase::Idle && w.want.running && !w.decl.secrets.is_empty() && w.blocked.is_none() && !w.withdrawn
                && w.secrets.as_ref().is_none_or(|(s, f, _)| *s != w.want.seat || *f != w.want.fence)
                && w.next_try.is_none_or(|t| Instant::now() >= t)
        }).map(|(k, w)| (k.clone(), w.want.seat.clone(), w.want.fence)).collect()
    }

    pub fn provide_secrets(&mut self, key: &str, seat: Option<String>, fence: i64, got: Result<Map<String, Value>, String>) {
        let mut sh = lock(&self.shared);
        let Some(w) = sh.w.get_mut(key) else { return };
        match got {
            Ok(m) => {
                w.secrets = Some((seat, fence, m));
                w.secrets_error = None;
            }
            Err(e) => {
                w.secrets_error = Some(e.clone());
                w.next_try = Some(Instant::now() + Duration::from_secs(30));
            }
        }
    }

    /// Every protection tick: ended runs, lease ends, the sandbox-identity scan, health checks, events, logs, records,
    /// and what to start or stop.
    pub fn tick(&mut self) {
        let now_boot = boot::now_s();
        let env = self.env();
        let contain = containment();
        let mut stops: Vec<(String, &'static str)> = vec![];
        let mut starts: Vec<String> = vec![];
        let mut ended: Vec<(String, Run, Option<String>)> = vec![];
        let mut health: Vec<String> = vec![];
        {
            let mut sh = lock(&self.shared);
            for (k, w) in sh.w.iter_mut() {
                // what keeps it from running here at all
                let ctx = self.ctxs.get(&w.decl.module);
                w.blocked = if ctx.is_none() {
                    Some(("WORKLOAD_NOT_OFFERED", "this node's release does not have it".to_string()))
                } else if self.disabled_modules.contains(&w.decl.module) {
                    Some(("WORKLOAD_NOT_OFFERED", "its module is disabled".to_string()))
                } else if !self.allowed {
                    Some(("WORKLOAD_POLICY_OFF", "this node's workloads setting is off".to_string()))
                } else if let Err(e) = &contain {
                    Some(("WORKLOAD_NO_CONTAINMENT", e.clone()))
                } else if cfg!(target_os = "linux") && ctx.is_some_and(|c| c.net == "egress-any") {
                    Some(("WORKLOAD_NOT_OFFERED", "Linux cannot enforce the egress-any network mode".to_string()))
                } else if w.decl.gpu && !crate::gpuapi::fits(&w.decl.apis_any, &self.gpu_apis) {
                    Some(("WORKLOAD_NOT_OFFERED", format!("it needs one of {} on the host", w.decl.apis_any.join(", "))))
                } else {
                    None
                };
                if w.blocked.is_some() && w.phase == Phase::Idle {
                    w.release = true;
                }
                let Some(run) = w.run.as_mut() else { continue };
                // the run ended: its leader exited (or the workload closed its endpoint channel)
                let exit = match run.child.as_mut() {
                    Some(c) => match c.try_wait() {
                        Ok(Some(st)) => Some(Some(format!("exited {}", st.code().map(|c| c.to_string())
                            .unwrap_or_else(|| "on a signal".into())))),
                        Ok(None) => None,
                        Err(e) => Some(Some(format!("cannot wait for it: {e}"))),
                    },
                    None => (procs::start_time_us(run.leader) != Some(run.start_us)).then(|| Some("its process ended".into())),
                };
                let exit = exit.or_else(|| run.channel_lost.load(Ordering::SeqCst)
                    .then(|| Some("it closed its endpoint channel".to_string())));
                if let Some(why) = exit {
                    let r = w.run.take().expect("present");
                    w.phase = Phase::Stopping;
                    ended.push((k.clone(), r, why));
                    continue;
                }
                // a renewed lease reaches the run (and its record)
                if w.want.seat == run.seat && w.want.fence == run.fence {
                    run.deadline = match (run.deadline, w.want.deadline) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                }
                // the lease ran out on the boot clock: stopped, and the seat goes back
                if w.decl.per_node && run.deadline.is_none_or(|d| d <= now_boot) && w.phase == Phase::Running {
                    info!(workload = %k, "its seat lease ran out: stopping it");
                    w.release = true;
                    w.want.running = false;
                    w.want.reason = Some("WORKLOAD_SEAT_LEASE_EXPIRED".into());
                    stops.push((k.clone(), "WORKLOAD_SEAT_LEASE_EXPIRED"));
                    continue;
                }
                if let Some(h) = w.decl.health {
                    // never while protection holds it paused: a frozen workload cannot answer (spec/workload-protocol.md)
                    let paused = run.applied.frozen || run.applied.coop_paused;
                    if w.phase == Phase::Running && !paused && !w.health.busy && w.health.last.is_none_or(|t| t.elapsed() >= h.0) {
                        w.health.busy = true;
                        w.health.last = Some(Instant::now());
                        health.push(k.clone());
                    }
                }
            }
            // what to stop and start
            let decided: BTreeSet<String> = stops.iter().map(|s| s.0.clone()).collect();
            for (k, w) in sh.w.iter_mut().filter(|(k, _)| !decided.contains(*k)) {
                let seat_ok = !w.decl.per_node || w.want.deadline.is_some_and(|d| d > now_boot);
                let should = w.want.running && seat_ok && w.blocked.is_none() && w.hold.is_none() && !w.withdrawn;
                match w.phase {
                    Phase::Running => {
                        let Some(run) = w.run.as_ref() else { continue };
                        let moved = w.decl.per_node && (w.want.seat != run.seat || w.want.fence != run.fence);
                        let restart = w.want.restart_seq > w.restart_seq;
                        if !should || moved || restart {
                            let why = if restart { "WORKLOAD_RESTART" } else if moved { "WORKLOAD_SEAT_ELSEWHERE" }
                                else if w.hold.is_some() { "WORKLOAD_HELD" } else if w.withdrawn { "WORKLOAD_WITHDRAWN" }
                                else if w.blocked.is_some() { w.blocked.as_ref().map(|b| b.0).unwrap_or("WORKLOAD_NOT_OFFERED") }
                                else { "WORKLOAD_UNASSIGNED" };
                            if restart {
                                w.restart_seq = w.want.restart_seq;
                            }
                            stops.push((k.clone(), why));
                        }
                    }
                    Phase::Idle => {
                        if w.want.restart_seq > w.restart_seq {
                            w.restart_seq = w.want.restart_seq;
                        }
                        let secrets_ready = w.decl.secrets.is_empty()
                            || w.secrets.as_ref().is_some_and(|(s, f, _)| *s == w.want.seat && *f == w.want.fence);
                        if should && w.admit && secrets_ready && w.next_try.is_none_or(|t| Instant::now() >= t) {
                            starts.push(k.clone());
                        }
                    }
                    Phase::Starting | Phase::Stopping => {}
                }
            }
            for (k, _) in &stops {
                if let Some(w) = sh.w.get_mut(k) {
                    w.phase = Phase::Stopping;
                }
            }
            for k in &starts {
                if let Some(w) = sh.w.get_mut(k) {
                    w.phase = Phase::Starting;
                    w.release = false;
                }
            }
        }
        for (k, run, why) in ended {
            let e = env.clone();
            spawn_named(format!("wl end {k}"), move || finish_run(&e, &k, run, why));
        }
        for (k, why) in stops {
            let taken = lock(&self.shared).w.get_mut(&k).and_then(|w| w.run.take().map(|r| (r, w.decl.stop_timeout)));
            match taken {
                Some((run, timeout)) => {
                    let e = env.clone();
                    spawn_named(format!("wl stop {k}"), move || stop_run(&e, &k, run, timeout, why));
                }
                None => {
                    if let Some(w) = lock(&self.shared).w.get_mut(&k) {
                        w.phase = Phase::Idle;
                    }
                }
            }
        }
        for k in starts {
            let job = {
                let mut sh = lock(&self.shared);
                let Some(w) = sh.w.get_mut(&k) else { continue };
                let Some(ctx) = self.ctxs.get(&w.decl.module).cloned() else {
                    w.phase = Phase::Idle;
                    continue;
                };
                w.restarts += 1;
                let secrets = w.secrets.as_ref().map(|s| s.2.clone()).unwrap_or_default();
                (ctx, w.decl.clone(), w.want.clone(), secrets, w.restarts, self.limits.clone())
            };
            let e = env.clone();
            spawn_named(format!("wl start {k}"), move || start_run(&e, job.0, job.1, job.2, job.3, job.4, &job.5));
        }
        for k in health {
            let job = {
                let sh = lock(&self.shared);
                let Some(w) = sh.w.get(&k) else { continue };
                let (Some(ctx), Some(run)) = (self.ctxs.get(&w.decl.module).cloned(), w.run.as_ref()) else { continue };
                (ctx, w.decl.clone(), run.private.clone(), run.run_dir.clone(), run.seat.clone(), run.fence)
            };
            let e = env.clone();
            spawn_named(format!("wl health {k}"), move || health_check(&e, &k, job.0, job.1, &job.2, &job.3, job.4, job.5));
        }
        self.scan_escapees();
        self.follow_runs();
    }

    /// macOS: find the processes of each running workload that left its process group, by sandbox identity (a
    /// process of the agent's account whose profile grants reading the workload's private directory and does not grant
    /// the canary). A member that is found joins the run; protection's current actions reach it at once.
    fn scan_escapees(&mut self) {
        #[cfg(target_os = "macos")]
        {
            if self.last_scan.is_some_and(|t| t.elapsed() < Duration::from_millis(1500)) {
                return;
            }
            self.last_scan = Some(Instant::now());
            let c = |p: PathBuf| std::ffi::CString::new(p.display().to_string()).ok();
            let markers: Vec<Marker> = lock(&self.shared).w.iter()
                .filter_map(|(k, w)| w.run.as_ref().map(|r| (k.clone(), r)))
                .filter_map(|(k, r)| {
                    ensure_canary(&r.private);
                    Some(Marker { key: k, leader: r.leader, born: r.start_us, control: c(r.private.join("control.json"))?,
                                  canary: c(canary_of(&r.private))?, events: c(r.run_dir.join("events.ndjson"))? })
                })
                .collect();
            if markers.is_empty() {
                return;
            }
            let me = std::process::id() as i32;
            // the agent's own containers (jobs, services, workloads, health checks) are accounted for already
            let known: BTreeSet<i32> = self.registry.as_ref().map(|r| r.all().iter().map(|m| m.pid).collect()).unwrap_or_default();
            let mut found: Vec<(String, i32, u64)> = vec![];
            for pid in own_pids() {
                if pid == me || pid <= 1 {
                    continue;
                }
                let pgid = unsafe { libc::getpgid(pid) };
                if markers.iter().any(|m| m.leader == pgid) || known.contains(&pgid) {
                    continue;                                     // in a container of the agent's: accounted for
                }
                let Some(born) = procs::start_time_us(pid) else { continue };
                if !crate::seatbelt::is_sandboxed(pid as u32) {
                    continue;
                }
                if let Some(m) = markers.iter().find(|m| runs_with_profile(pid as u32, born, m)) {
                    found.push((m.key.clone(), pid, born));
                }
            }
            let mut sh = lock(&self.shared);
            for (k, pid, start) in found {
                let Some(run) = sh.w.get_mut(&k).and_then(|w| w.run.as_mut()) else { continue };
                if run.members.iter().any(|m| m.0 == pid) {
                    continue;
                }
                info!(workload = %k, pid, "a process of the workload left its process group: tracked by its sandbox identity");
                run.members.push((pid, start));
                if let Some(r) = &self.registry {
                    if run.applied.frozen {
                        let _ = r.signal_member(run.leader, pid, start, oarbank_protection::Signal::Stop, "WORKLOAD_PAUSE");
                    }
                    if run.applied.lowered {
                        let _ = r.set_background_member(run.leader, pid, start, true, "WORKLOAD_LOWER");
                    }
                }
            }
            for w in sh.w.values_mut() {
                if let Some(run) = w.run.as_mut() {
                    run.members.retain(|(p, s)| procs::start_time_us(*p) == Some(*s));
                }
            }
        }
    }

    /// Per running workload: usage, new events, the log's size, and its record when the lease or members changed.
    fn follow_runs(&mut self) {
        let layout = Layout::new(self.layout.home.clone());
        let mut sh = lock(&self.shared);
        for (k, w) in sh.w.iter_mut() {
            let Some(run) = w.run.as_mut() else { continue };
            let mut u = procs::group_usage(run.leader);
            #[cfg(target_os = "macos")]
            for (pid, _) in &run.members {
                let m = member_usage(*pid);
                u.cpu_s += m.cpu_s;
                u.footprint_gb += m.footprint_gb;
                u.procs += 1;
            }
            w.usage = u;
            read_events(&run.run_dir.join("events.ndjson"), &mut w.events, w.decl.reports);
            rotate_log(&log_path(&layout, k));
            let moved = match (run.deadline, run.record_deadline) {
                (Some(a), Some(b)) => (a - b).abs() >= RECORD_LEASE_STEP_S,
                (a, b) => a.is_some() != b.is_some(),
            };
            if moved || run.members.len() != run.record_members {
                write_record(&layout, k, run);
            }
        }
    }

    /// Workloads as host protection sees them: each that runs, and each that is wanted here but not running (so a hold
    /// can end and a start can be admitted).
    pub fn views(&self) -> Vec<FleetWorkloadView> {
        let hard_cap = crate::sys::can_cap_cpu();
        lock(&self.shared).w.iter().filter(|(_, w)| w.run.is_some() || (w.want.running && w.blocked.is_none()))
            .map(|(k, w)| FleetWorkloadView {
                key: k.clone(),
                running: w.run.is_some() && w.phase == Phase::Running,
                footprint_gb: w.usage.footprint_gb,
                started_at: w.started_at,
                cpu_cores: w.decl.cpu_cores,
                pause_tolerance_s: w.decl.pause_tolerance_s,
                pausable: w.decl.freeze_ok || w.decl.coop_pause,
                cooperative_throttle: w.decl.coop_throttle,
                hard_cap,
                gpu: w.decl.gpu,
            }).collect()
    }

    /// Every process of every running workload (fleet work: never protected, and its memory is the fleet's).
    pub fn fleet_pids(&self) -> Vec<i32> {
        let sh = lock(&self.shared);
        let mut out = vec![];
        for run in sh.w.values().filter_map(|w| w.run.as_ref()) {
            out.push(run.leader);
            out.extend(procs::group_pids(run.leader));
            out.extend(run.members.iter().map(|m| m.0));
        }
        out
    }

    /// What running workloads hold of the node: their declared cores and memory.
    pub fn reserved(&self) -> (f64, f64) {
        lock(&self.shared).w.values().filter(|w| w.run.is_some())
            .fold((0.0, 0.0), |(c, m), w| (c + w.decl.cpu_cores, m + w.decl.mem_gb))
    }

    /// Apply this tick's protection plans: holds (a stop now, kept while they last), pause (a freeze or the control
    /// document), lowering, and throttle (the `threads` hint and the hard CPU cap).
    pub fn apply(&mut self, plans: &BTreeMap<String, WorkloadAction>) {
        let reg = self.registry.clone();
        let mut stop_now = vec![];
        {
            let mut sh = lock(&self.shared);
            for (k, w) in sh.w.iter_mut() {
                let plan = plans.get(k).cloned().unwrap_or(WorkloadAction { admit: true, ..Default::default() });
                let hold = plan.hold.as_ref().map(|h| (h.reason.clone(), h.code));
                if hold.is_some() && w.hold.is_none() {
                    info!(workload = %k, reason = ?hold, "held down by host protection");
                    if w.phase == Phase::Running {
                        stop_now.push(k.clone());
                    }
                }
                w.hold = hold;
                w.admit = plan.admit;
                w.plan = plan.clone();
                let Some(run) = w.run.as_mut() else { continue };
                if w.phase != Phase::Running || w.hold.is_some() {
                    continue;
                }
                let want = Applied {
                    frozen: plan.paused && w.decl.freeze_ok,
                    coop_paused: plan.paused && !w.decl.freeze_ok && w.decl.coop_pause,
                    lowered: plan.lowered,
                    threads: plan.threads.filter(|_| w.decl.coop_throttle),
                    cpu_cap: plan.cpu_cap,
                };
                apply_to_run(reg.as_deref(), k, run, &want);
            }
        }
        if !stop_now.is_empty() {
            self.tick();                                          // stopped now, not on the next tick
        }
    }

    /// Thaw every frozen workload (the agent is going away: a frozen workload it leaves behind could not act on
    /// anything; the next agent applies protection again).
    pub fn thaw_all(&mut self) {
        let reg = self.registry.clone();
        let mut sh = lock(&self.shared);
        for (k, w) in sh.w.iter_mut() {
            if let Some(run) = w.run.as_mut() {
                if run.applied.frozen || run.applied.coop_paused {
                    let want = Applied { frozen: false, coop_paused: false, ..run.applied.clone() };
                    apply_to_run(reg.as_deref(), k, run, &want);
                }
            }
        }
    }

    /// The heartbeat's `workloads` (docs/protocol.md, "Workloads").
    pub fn report(&self) -> Value {
        let layout = Layout::new(self.layout.home.clone());
        let now_boot = boot::now_s();
        let sh = lock(&self.shared);
        let rows: Vec<Value> = sh.w.iter().map(|(k, w)| {
            let run = w.run.as_ref();
            let (seat, fence) = match run {
                Some(r) => (r.seat.clone(), r.fence),
                None => w.last_seat.clone().unwrap_or((w.want.seat.clone(), w.want.fence)),
            };
            let active = matches!(w.phase, Phase::Starting | Phase::Running | Phase::Stopping) || run.is_some();
            let lease_left = run.and_then(|r| r.deadline).or(w.want.deadline).map(|d| ((d - now_boot).max(0.0)).round());
            let secrets = run.map(|r| r.secret_values.clone()).unwrap_or_default();
            let tail = crate::jobs::redact(&crate::doctor::tail(&read_tail(&log_path(&layout, k), LOG_TAIL), LOG_TAIL), &secrets);
            json!({
                "key": k, "state": if w.withdrawn && !active { "withdrawn" } else if w.hold.is_some() && !active { "held" }
                    else { w.phase.as_str() },
                "running": active, "seat_id": seat, "fence": fence, "release": w.release && !active,
                "pid": run.map(|r| r.leader), "started_at": run.map(|r| r.started_wall), "run": run.map(|r| r.n),
                "adopted": run.is_some_and(|r| r.adopted), "members": run.map(|r| r.members.len()).unwrap_or(0),
                "restarts": w.restarts, "failures": w.failures, "withdrawn": w.withdrawn, "error": w.last_error
                    .clone().or_else(|| w.events.last_error.clone()),
                "blocked": w.blocked.as_ref().map(|b| b.0), "blocked_detail": w.blocked.as_ref().map(|b| b.1.clone()),
                "held": w.hold.as_ref().map(|h| h.0.clone()), "held_code": w.hold.as_ref().map(|h| h.1),
                "paused": run.is_some_and(|r| r.applied.frozen || r.applied.coop_paused),
                "lowered": run.is_some_and(|r| r.applied.lowered), "threads": run.and_then(|r| r.applied.threads),
                "cpu_cap": run.and_then(|r| r.applied.cpu_cap), "admit": w.admit,
                "health": w.health.healthy.map(|h| if h { "healthy" } else { "unhealthy" }).unwrap_or("unknown"),
                "health_detail": w.health.detail, "lease_left_s": lease_left, "want": w.want.running,
                "reason": w.want.reason, "secrets_error": w.secrets_error,
                "cpu_s": (w.usage.cpu_s * 10.0).round() / 10.0, "footprint_gb": (w.usage.footprint_gb * 100.0).round() / 100.0,
                "progress": w.events.progress, "reports_dropped": w.events.dropped, "log_tail": tail,
            })
        }).collect();
        Value::Array(rows)
    }

    /// The report events waiting for the coordinator: `[{key, seat_id, fence, events: [{seq, t, data}]}]`.
    pub fn reports_out(&self) -> Value {
        let sh = lock(&self.shared);
        Value::Array(sh.w.iter().filter(|(_, w)| !w.events.queue.is_empty()).map(|(k, w)| {
            let (seat, fence) = w.run.as_ref().map(|r| (r.seat.clone(), r.fence))
                .or_else(|| w.last_seat.clone()).unwrap_or((None, 0));
            json!({"key": k, "seat_id": seat, "fence": fence, "events": w.events.queue.iter().take(60).collect::<Vec<_>>()})
        }).collect())
    }

    /// The coordinator stored report events up to these sequence numbers (`workload_reports_ack: {key: seq}`).
    pub fn ack_reports(&mut self, ack: &Value) {
        let Some(m) = ack.as_object() else { return };
        let mut sh = lock(&self.shared);
        for (k, seq) in m {
            let (Some(w), Some(upto)) = (sh.w.get_mut(k), seq.as_u64()) else { continue };
            while w.events.queue.front().is_some_and(|e| e["seq"].as_u64().is_some_and(|s| s <= upto)) {
                w.events.queue.pop_front();
            }
        }
    }

    /// For the inbound listener (inbound-listeners.md; built beside this): how to reach the running workload of `module` that serves
    /// `listener`, as a connector's lookup (wait up to its limit for one that is starting, refuse at once when none
    /// will come). None when no workload of the module lists it.
    #[allow(dead_code)]
    pub fn listener_lookup(&self, module: &str, listener: &str) -> Option<endpoints::Lookup> {
        let key = lock(&self.shared).w.iter()
            .find(|(_, w)| w.decl.module == module && w.decl.listeners.iter().any(|l| l == listener)).map(|(k, _)| k.clone())?;
        let (sh, changed) = (self.shared.clone(), self.changed.clone());
        Some(Arc::new(move |limit: Duration| {
            let mut why = String::new();
            changed.wait_for(Instant::now() + limit, || {
                let g = lock(&sh);
                let Some(w) = g.w.get(&key) else {
                    why = format!("{key} is not in this node's release");
                    return Some(None);
                };
                if !w.want.running || w.blocked.is_some() || w.hold.is_some() || w.withdrawn {
                    why = format!("{key} does not run here now");
                    return Some(None);
                }
                match w.run.as_ref().and_then(|r| r.channel.clone()) {
                    Some(c) if c.accepting() => Some(Some(c)),
                    _ => {
                        why = format!("{key} did not come up in time");
                        None
                    }
                }
            }).flatten().ok_or_else(|| Refusal::new("workload_unavailable", why))
        }))
    }

    /// The keys of workloads running now (tests and the status page).
    #[allow(dead_code)]
    pub fn running(&self) -> Vec<String> {
        lock(&self.shared).w.iter().filter(|(_, w)| w.run.is_some()).map(|(k, _)| k.clone()).collect()
    }
}

fn spawn_named(name: String, f: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().name(name.clone()).spawn(f) {
        warn!(thread = %name, error = %e, "cannot start a workload thread");
    }
}

fn log_path(layout: &Layout, key: &str) -> PathBuf {
    layout.logs().join("workloads").join(format!("{}.log", key.replace('/', ".")))
}

fn read_tail(p: &Path, n: usize) -> String {
    let Ok(mut f) = std::fs::File::open(p) else { return String::new() };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(n as u64 * 2)));
    let mut b = vec![];
    let _ = f.read_to_end(&mut b);
    String::from_utf8_lossy(&b).to_string()
}

/// Keep a log the workload appends to under LOG_MAX: copy its last part to `.1` and truncate it in place (the
/// workload's descriptor is in append mode, so it keeps writing at the new end).
fn rotate_log(p: &Path) {
    let Ok(m) = std::fs::metadata(p) else { return };
    if m.len() < LOG_MAX {
        return;
    }
    let keep = read_tail(p, (LOG_MAX / 4) as usize);
    let _ = std::fs::write(p.with_extension("log.1"), keep);
    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(p) {
        let _ = f.set_len(0);
    }
}

/// New complete lines of the events file: progress counts, the last error, and report events (bounded).
fn read_events(path: &Path, st: &mut EventsSt, reports: bool) {
    let Ok(mut f) = std::fs::File::open(path) else { return };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if len < st.offset {
        st.offset = 0;                                            // replaced or truncated: read it again from the start
        st.partial.clear();
    }
    if len == st.offset || f.seek(SeekFrom::Start(st.offset)).is_err() {
        return;
    }
    let mut buf = vec![];
    if f.take(1 << 20).read_to_end(&mut buf).is_err() {
        return;
    }
    st.offset += buf.len() as u64;
    st.partial.push_str(&String::from_utf8_lossy(&buf));
    let text = std::mem::take(&mut st.partial);
    let mut lines: Vec<&str> = text.split('\n').collect();
    let rest = lines.pop().unwrap_or("").to_string();
    for line in lines {
        let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
        match v["type"].as_str() {
            Some("progress") => {
                let e = v["event"].as_str().unwrap_or("unit").chars().take(64).collect::<String>();
                *st.progress.entry(e).or_default() += v["n"].as_u64().unwrap_or(1).min(1_000_000);
            }
            Some("error") => st.last_error = v["message"].as_str().map(|m| m.chars().take(300).collect()),
            Some("report") if reports => {
                let data = v["data"].clone();
                let size = serde_json::to_vec(&data).map(|b| b.len()).unwrap_or(usize::MAX);
                let now = Instant::now();
                let (start, n) = st.window.filter(|(t, _)| now.duration_since(*t) < Duration::from_secs(60)).unwrap_or((now, 0));
                if size > REPORT_MAX_BYTES || n >= REPORTS_PER_MIN || !data.is_object() {
                    st.dropped += 1;
                    continue;
                }
                st.window = Some((start, n + 1));
                let ms = (crate::doctor::now() * 1000.0) as u64;
                st.next_seq = st.next_seq.max(ms) + 1;               // rising across agent restarts while the clock is sane
                st.queue.push_back(json!({"seq": st.next_seq, "t": v["t"].as_f64().unwrap_or_else(crate::doctor::now),
                                           "data": data}));
                while st.queue.len() > REPORTS_QUEUED {
                    st.queue.pop_front();
                    st.dropped += 1;
                }
            }
            _ => {}
        }
    }
    st.partial = rest;
}

/// The record a later agent adopts the run from (written atomically).
fn write_record(layout: &Layout, key: &str, run: &mut Run) {
    let rec = json!({
        "key": key, "run": run.n, "leader": run.leader, "start_us": run.start_us.to_string(),
        "members": run.members.iter().map(|(p, s)| json!([p, s.to_string()])).collect::<Vec<_>>(),
        "seat": run.seat, "fence": run.fence, "deadline": run.deadline, "boot": boot::id(),
        "private": run.private.display().to_string(), "run_dir": run.run_dir.display().to_string(),
        "listeners": run.channel.is_some(), "job": run.job_name, "started_at": run.started_wall,
        "agent_pid": std::process::id(),
    });
    let p = record_path(layout, key);
    let tmp = p.with_extension("tmp");
    if std::fs::write(&tmp, rec.to_string()).and_then(|_| std::fs::rename(&tmp, &p)).is_ok() {
        run.record_deadline = run.deadline;
        run.record_members = run.members.len();
    }
}

/// End what a record names that still runs (each process only while it has its recorded start time).
fn end_recorded(layout: &Layout, rec: &Value) {
    let leader = rec["leader"].as_i64().unwrap_or(0) as i32;
    let start: u64 = rec["start_us"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
    let key = rec["key"].as_str().unwrap_or("");
    if leader > 1 && procs::start_time_us(leader) == Some(start) {
        let _ = crate::sys::adopt_workload(leader, rec["job"].as_str().unwrap_or(""));
        procs::signal_group(leader, procs::Sig::Kill);
        crate::sys::release(leader);
    }
    for m in rec["members"].as_array().into_iter().flatten() {
        let (Some(p), Some(s)) = (m[0].as_i64(), m[1].as_str().and_then(|s| s.parse::<u64>().ok())) else { continue };
        if procs::start_time_us(p as i32) == Some(s) {
            crate::sys::signal_process(p as i32, procs::Sig::Kill);
        }
    }
    // the secrets of a run that is over go with it
    if let Some(p) = rec["private"].as_str() {
        let _ = std::fs::remove_file(Path::new(p).join("secrets.json"));
    }
    let _ = layout;
    let _ = key;
}

/// The sandbox policy of a workload's processes: the module's grants plus its private directory, read-only.
fn policy(ctx: &Ctx, private: &Path, tool_paths: &[String], exe: &str) -> oarbank_core::sandbox::Policy {
    let mut pol = oarbank_core::sandbox::Policy::new(ctx.module_id.clone());
    pol.ro = vec![ctx.bundle.display().to_string(), ctx.python.display().to_string(), private.display().to_string()];
    if let Some(v) = &ctx.venv {
        pol.ro.push(v.display().to_string());
    }
    pol.ro.extend(ctx.roots.iter().cloned());
    pol.ro.extend(tool_paths.iter().cloned());
    pol.rw = vec![ctx.data.display().to_string()];
    pol.gpu = ctx.gpu_device;
    pol.exec_rw = ctx.exec_rw;
    pol.kind = "workload".into();
    pol.exe = Some(exe.to_string());
    pol
}

/// The environment of a workload's processes (`run` and `status`).
fn workload_env(ctx: &Ctx, decl: &Decl, private: &Path, run_dir: &Path, seat: &Option<String>, fence: i64,
                files: &(PathBuf, PathBuf), secrets: bool) -> Vec<(String, String)> {
    let mut env = base_env(&ctx.module, run_dir, &run_dir.join("tmp"));
    env.extend([("OARBANK_WORKLOAD".into(), decl.name.clone()), ("OARBANK_WORKLOAD_PROTOCOL".into(), PROTOCOL.to_string()),
                ("OARBANK_WORKLOAD_RUN".into(), run_dir.display().to_string()),
                ("OARBANK_MODULE_DATA".into(), ctx.data.display().to_string()),
                ("OARBANK_CONTROL_FILE".into(), private.join("control.json").display().to_string()),
                ("OARBANK_EVENTS_FILE".into(), run_dir.join("events.ndjson").display().to_string()),
                ("OARBANK_SETTINGS_FILE".into(), files.1.display().to_string()),
                ("OARBANK_TOOLS_FILE".into(), files.0.display().to_string()),
                ("OARBANK_LIMITS_FILE".into(), private.join("limits.json").display().to_string()),
                ("OARBANK_NODE_ID".into(), ctx.node_id.clone()),
                ("OARBANK_SEAT_ID".into(), seat.clone().unwrap_or_default()),
                ("OARBANK_SEAT_FENCE".into(), fence.to_string())]);
    if secrets {
        env.push(("OARBANK_SECRETS_FILE".into(), private.join("secrets.json").display().to_string()));
    }
    env
}

/// Network grant and proxy for the module.
fn net_of(ctx: &Ctx, pol: &mut oarbank_core::sandbox::Policy, env: &mut Vec<(String, String)>) {
    let port = if ctx.net == "egress-allowlist" { ctx.proxy_port() } else { None };
    pol.net = match ctx.net.as_str() {
        "egress-any" => "egress-any".into(),
        "egress-allowlist" if port.is_some() => "egress-allowlist".into(),
        _ => "none".into(),
    };
    pol.proxy_port = if pol.net == "egress-allowlist" { port } else { None };
    if let Some(p) = pol.proxy_port {
        let url = format!("http://127.0.0.1:{p}");
        for k in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"] {
            env.push((k.into(), url.clone()));
        }
    }
}

/// Start a run on its own thread: the private directory, the secrets file, a fresh run directory, the control
/// document, the sandboxed leader in its lasting container, its registration and record.
fn start_run(e: &Env, ctx: Arc<Ctx>, decl: Decl, want: Want, secrets: Map<String, Value>, n: u64, limits: &Value) {
    let key = decl.key();
    let r = start_inner(e, &ctx, &decl, &want, &secrets, n, limits);
    let mut sh = lock(&e.shared);
    let Some(w) = sh.w.get_mut(&key) else {
        drop(sh);
        if let Ok(run) = r {
            kill_run(e, &key, run);
        }
        return;
    };
    match r {
        Ok(mut run) => {
            // unwanted meanwhile: stopped at once by the next tick
            info!(workload = %key, leader = run.leader, run = n, "workload started");
            write_record(&e.layout, &key, &mut run);
            w.started_at = run.started_wall;
            w.last_seat = Some((run.seat.clone(), run.fence));
            w.health = HealthSt::default();
            w.events.offset = 0;
            w.events.partial.clear();
            w.run = Some(run);
            w.phase = Phase::Running;
        }
        Err(why) => {
            w.phase = Phase::Idle;
            w.failed(&format!("start failed: {why}"));
        }
    }
    drop(sh);
    e.changed.bump();
}

fn start_inner(e: &Env, ctx: &Ctx, decl: &Decl, want: &Want, secrets: &Map<String, Value>, n: u64, limits: &Value)
               -> Result<Run, String> {
    let key = decl.key();
    let private = private_dir(&e.layout, decl);
    crate::fsutil::private_dir(&private).map_err(|x| format!("private directory: {x}"))?;
    ensure_canary(&private);
    let _ = std::fs::remove_file(private.join("secrets.json"));
    let (tools_file, settings_file, tool_paths) = grant_files(&private, &ctx.entry, &ctx.settings, &ctx.tool_grants)
        .map_err(|x| format!("grants: {x}"))?;
    crate::fsutil::write_if_changed(&private.join("limits.json"), limits.to_string().as_bytes())
        .map_err(|x| format!("limits file: {x}"))?;
    let secret_values: Vec<(String, Value)> = secrets.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    if !decl.secrets.is_empty() {
        let missing: Vec<&String> = decl.secrets.iter().filter(|s| !secrets.contains_key(*s)).collect();
        if !missing.is_empty() {
            return Err(format!("secrets {missing:?} did not arrive"));
        }
        crate::fsutil::write_private(&private.join("secrets.json"), &serde_json::to_vec(secrets).map_err(|x| x.to_string())?)
            .map_err(|x| format!("secrets file: {x}"))?;
    }
    // a fresh run directory; earlier runs' directories go
    let parent = ctx.data.join("workloads").join(&decl.name);
    for d in std::fs::read_dir(&parent).into_iter().flatten().flatten() {
        if d.file_name().to_string_lossy().starts_with("run-") {
            let _ = std::fs::remove_dir_all(d.path());
        }
    }
    let run_dir = parent.join(format!("run-{n}"));
    crate::fsutil::private_dir(&run_dir.join("tmp")).map_err(|x| format!("run directory: {x}"))?;
    std::fs::write(run_dir.join("events.ndjson"), b"").map_err(|x| format!("events file: {x}"))?;
    let mut control = ControlFile::create(&private).map_err(|x| format!("control document: {x}"))?;
    let mut argv = resolve_exec(&decl.exec, &ctx.bundle, &ctx.python);
    if argv.is_empty() || !Path::new(&argv[0]).is_absolute() {
        return Err("the exec does not resolve to an absolute path".into());
    }
    argv.push("run".into());
    let mut env = workload_env(ctx, decl, &private, &run_dir, &want.seat, want.fence, &(tools_file, settings_file),
                               !decl.secrets.is_empty());
    let mut pol = policy(ctx, &private, &tool_paths, &argv[0]);
    net_of(ctx, &mut pol, &mut env);
    let channel_lost: Arc<AtomicBool> = Arc::default();
    let channel = if decl.listeners.is_empty() {
        None
    } else {
        let lost = channel_lost.clone();
        let ch = Channel::new(&key, e.changed.clone(), Box::new(move || lost.store(true, Ordering::SeqCst)))
            .map_err(|x| format!("endpoint channel: {x}"))?;
        env.push((endpoints::CHANNEL_ENV.into(), ch.child_value()));
        Some(ch)
    };
    let sandboxed = crate::sandbox::available();
    if sandboxed {
        argv = crate::sandbox::wrap(&pol, &private.join("workload.sb"), &argv)?;
    }
    let log = log_path(&e.layout, &key);
    let _ = std::fs::create_dir_all(log.parent().unwrap_or(Path::new(".")));
    let out = std::fs::OpenOptions::new().create(true).append(true).open(&log).map_err(|x| format!("log: {x}"))?;
    let err = out.try_clone().map_err(|x| format!("log: {x}"))?;
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]).env_clear().envs(env).current_dir(&run_dir).stdin(std::process::Stdio::null())
        .stdout(out).stderr(err);
    control.prepare(&mut cmd);
    let signal = sandboxed.then(crate::sandbox::ConfinedSignal::new).transpose().map_err(|x| format!("confinement signal: {x}"))?;
    if let Some(s) = &signal {
        s.prepare(&mut cmd);
    }
    if let Some(ch) = &channel {
        ch.prepare(&mut cmd);
    }
    let name = job_name(&e.layout, &key);
    let mut child = match crate::sys::spawn_workload(&mut cmd, &name) {
        Ok(c) => c,
        Err(x) => {
            if let Some(ch) = &channel {
                ch.spawned(None);
            }
            return Err(format!("spawn: {x}"));
        }
    };
    let leader = child.id() as i32;
    if let Some(ch) = &channel {
        ch.spawned(Some(leader));
    }
    control.started(leader);
    if let Some(r) = &e.registry {
        r.register_workload(leader, &key, None);                 // only registered containers may be signalled (S16)
    }
    let start_us = procs::start_time_us(leader).unwrap_or(0);
    if let Some(s) = signal {
        use crate::sandbox::Came;
        let fault = match s.wait(leader as u32, crate::sandbox::CONFINE_GUARD) {
            Came::Confined if crate::sandbox::holds(leader) || matches!(child.try_wait(), Ok(Some(_))) => None,
            Came::Confined => Some("sandbox_missing: the launcher said it was confined, but the process is not"),
            Came::Ended => None,
            Came::Hung => Some("sandbox_hung: the launcher did not confine itself within the guard"),
        };
        if let Some(f) = fault {
            procs::signal_group(leader, procs::Sig::Kill);
            let _ = child.wait();
            if let Some(r) = &e.registry {
                r.unregister(leader);
            }
            crate::sys::release(leader);
            let _ = std::fs::remove_file(private.join("secrets.json"));
            warn!(workload = %key, "{f}; killed");
            return Err("the process did not come up sandboxed".into());
        }
    }
    Ok(Run { n, leader, start_us, child: Some(child), control: Some(control), private, run_dir, seat: want.seat.clone(),
             fence: want.fence, deadline: want.deadline, members: vec![], channel, channel_lost, adopted: false,
             started_wall: crate::doctor::now(), applied: Applied::default(), doc: json!({}), record_deadline: None,
             record_members: 0, job_name: name, secret_values })
}

/// Whether anything of the run still runs: its leader (as the recorded process), its container, a tracked member.
fn run_alive(run: &mut Run) -> bool {
    let leader = match run.child.as_mut() {
        Some(c) => matches!(c.try_wait(), Ok(None)),
        None => procs::start_time_us(run.leader) == Some(run.start_us),
    };
    leader || crate::sys::group_alive(run.leader) || run.members.iter().any(|(p, s)| procs::start_time_us(*p) == Some(*s))
}

/// Kill the whole run now: its container and every tracked member (through the spawn registry while the container is
/// registered), then forget the container.
fn kill_run(e: &Env, key: &str, mut run: Run) {
    let reg = e.registry.as_deref();
    let via_registry = reg.is_some_and(|r| r.signal(run.leader, oarbank_protection::Signal::Kill, "WORKLOAD_STOP").is_ok());
    if !via_registry {
        procs::signal_group(run.leader, procs::Sig::Kill);
    }
    for (p, s) in run.members.clone() {
        if let Some(r) = reg {
            if r.signal_member(run.leader, p, s, oarbank_protection::Signal::Kill, "WORKLOAD_STOP").is_ok() {
                continue;
            }
        }
        if procs::start_time_us(p) == Some(s) {
            crate::sys::signal_process(p, procs::Sig::Kill);
        }
    }
    if let Some(c) = run.child.as_mut() {
        let _ = c.wait();
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while run_alive(&mut run) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    cleanup(e, key, run);
}

/// What a finished run leaves: the registration, the container, the secrets file, the channel, the record.
fn cleanup(e: &Env, key: &str, run: Run) {
    if let Some(r) = &e.registry {
        r.unregister(run.leader);
    }
    crate::sys::release(run.leader);
    let _ = std::fs::remove_file(run.private.join("secrets.json"));
    if let Some(c) = &run.channel {
        c.close();
    }
    let _ = std::fs::remove_file(record_path(&e.layout, key));
}

/// The run ended on its own (its leader exited): end whatever is left of it; unless the agent was stopping it, that
/// is a failure, and the restart policy applies.
fn finish_run(e: &Env, key: &str, run: Run, why: Option<String>) {
    let why = why.unwrap_or_else(|| "it ended".into());
    info!(workload = %key, why = %why, "workload run ended");
    let tail: String = crate::doctor::tail(&read_tail(&log_path(&e.layout, key), 400), 300);
    let secrets = run.secret_values.clone();
    kill_run(e, key, run);
    let mut sh = lock(&e.shared);
    if let Some(w) = sh.w.get_mut(key) {
        w.phase = Phase::Idle;
        w.secrets = None;
        if w.want.running && w.hold.is_none() {
            let tail = crate::jobs::redact(tail.trim(), &secrets);
            w.failed(&if tail.is_empty() { why } else { format!("{why}: {tail}") });
        }
    }
    drop(sh);
    e.changed.bump();
}

/// Stop a run on its own thread: the stop request in the control document (a frozen run is thawed first, so it can
/// act on it), then the kill after `timeout`.
fn stop_run(e: &Env, key: &str, mut run: Run, timeout: Duration, why: &'static str) {
    info!(workload = %key, why, "stopping workload");
    if run.applied.frozen {
        let want = Applied { frozen: false, ..run.applied.clone() };
        apply_to_run(e.registry.as_deref(), key, &mut run, &want);
    }
    let mut doc = run.doc.clone();
    doc["stop"] = json!(true);
    doc["pause"] = json!(false);
    doc["reason"] = json!(why);
    if let Some(c) = run.control.as_mut() {
        let _ = c.write(doc);
    }
    #[cfg(unix)]
    {
        // a POSIX workload also gets SIGTERM, as a runner does
        if let Some(r) = &e.registry {
            let _ = r.signal(run.leader, oarbank_protection::Signal::Term, why);
        } else {
            procs::signal_group(run.leader, procs::Sig::Term);
        }
    }
    let deadline = Instant::now() + timeout;
    loop {
        let leader_alive = match run.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => procs::start_time_us(run.leader) == Some(run.start_us),
        };
        if !leader_alive || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    kill_run(e, key, run);
    let mut sh = lock(&e.shared);
    if let Some(w) = sh.w.get_mut(key) {
        w.phase = Phase::Idle;
        w.secrets = None;
        if why == "WORKLOAD_HELD" {
            // a hold is no failure; it starts again after the initial backoff once the cause clears
            w.next_try = Some(Instant::now() + Duration::from_secs_f64(w.decl.backoff_initial_s));
        }
    }
    drop(sh);
    e.changed.bump();
}

/// Bring the run to what protection asks: freeze or thaw (registry), the control document (pause, threads), lowering,
/// and the hard CPU cap.
fn apply_to_run(reg: Option<&SpawnRegistry>, key: &str, run: &mut Run, want: &Applied) {
    use oarbank_protection::Signal;
    let have = run.applied.clone();
    if want.frozen != have.frozen {
        let (sig, why) = if want.frozen { (Signal::Stop, "WORKLOAD_PAUSE") } else { (Signal::Cont, "WORKLOAD_RESUME") };
        match reg {
            Some(r) => {
                let _ = r.signal(run.leader, sig, why);
                for (p, s) in &run.members {
                    let _ = r.signal_member(run.leader, *p, *s, sig, why);
                }
            }
            None => {
                #[cfg(not(target_os = "macos"))]
                procs::signal_group(run.leader, if want.frozen { procs::Sig::Stop } else { procs::Sig::Cont });
            }
        }
    }
    if want.lowered != have.lowered {
        let why = if want.lowered { "WORKLOAD_LOWER" } else { "WORKLOAD_RESTORE" };
        if let Some(r) = reg {
            let _ = r.set_background(run.leader, want.lowered, why);
            for (p, s) in &run.members {
                let _ = r.set_background_member(run.leader, *p, *s, want.lowered, why);
            }
        }
    }
    if want.cpu_cap != have.cpu_cap {
        crate::sys::cpu_cap(run.leader, want.cpu_cap);
    }
    if (want.coop_paused, want.threads) != (have.coop_paused, have.threads) {
        let mut doc = run.doc.clone();
        doc["pause"] = json!(want.coop_paused);
        doc["threads"] = want.threads.map_or(Value::Null, Value::from);
        if let Some(c) = run.control.as_mut() {
            match c.write(doc.clone()) {
                Ok(()) => run.doc = doc,
                Err(x) => warn!(workload = %key, error = %x, "cannot write the control document"),
            }
        }
    }
    run.applied = want.clone();
}

/// The health check: `<exec> status`, sandboxed, with the run's environment; it prints `{"healthy": bool, ...}`.
#[allow(clippy::too_many_arguments)]
fn health_check(e: &Env, key: &str, ctx: Arc<Ctx>, decl: Decl, private: &Path, run_dir: &Path, seat: Option<String>, fence: i64) {
    let (_, timeout, limit) = decl.health.unwrap_or((Duration::from_secs(15), Duration::from_secs(5), 3));
    let r = status_op(e, &ctx, &decl, private, run_dir, &seat, fence, timeout);
    let taken = {
        let mut sh = lock(&e.shared);
        let Some(w) = sh.w.get_mut(key) else { return };
        w.health.busy = false;
        match r {
            Ok((true, d)) => {
                w.health.fails = 0;
                w.health.healthy = Some(true);
                w.health.detail = d;
                w.failures = 0;                                   // a healthy run is past its earlier failures
                None
            }
            Ok((false, d)) | Err(d) => {
                w.health.fails += 1;
                w.health.healthy = Some(false);
                w.health.detail = d;
                if w.health.fails >= limit && w.phase == Phase::Running {
                    w.health.fails = 0;
                    let detail = w.health.detail.clone();
                    w.run.take().map(|run| {
                        w.phase = Phase::Stopping;
                        (run, detail)
                    })
                } else {
                    None
                }
            }
        }
    };
    if let Some((run, detail)) = taken {
        kill_run(e, key, run);
        if let Some(w) = lock(&e.shared).w.get_mut(key) {
            w.phase = Phase::Idle;
            w.failed(&format!("unhealthy {limit} times in a row: {detail}"));
        }
    }
    e.changed.bump();
}

#[allow(clippy::too_many_arguments)]
fn status_op(e: &Env, ctx: &Ctx, decl: &Decl, private: &Path, run_dir: &Path, seat: &Option<String>, fence: i64,
             timeout: Duration) -> Result<(bool, String), String> {
    let mut argv = resolve_exec(&decl.exec, &ctx.bundle, &ctx.python);
    if argv.is_empty() {
        return Err("no exec".into());
    }
    argv.push("status".into());
    let files = (private.join("tools.json"), private.join("settings.json"));
    let mut env = workload_env(ctx, decl, private, run_dir, seat, fence, &files, !decl.secrets.is_empty());
    let mut pol = policy(ctx, private, &[], &argv[0]);
    net_of(ctx, &mut pol, &mut env);
    if crate::sandbox::available() {
        argv = crate::sandbox::wrap(&pol, &private.join("status.sb"), &argv)?;
    }
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]).env_clear().envs(env).current_dir(run_dir).stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
    let mut child = crate::sys::spawn_contained(&mut cmd, false).map_err(|x| format!("spawn: {x}"))?;
    let pid = child.id() as i32;
    if let Some(r) = &e.registry {
        r.register(pid, None, Some(&format!("{}/status", decl.key())));
    }
    let mut out = child.stdout.take();
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if Instant::now() >= deadline => break None,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => break None,
        }
    };
    procs::signal_group(pid, procs::Sig::Kill);
    let _ = child.wait();
    if let Some(r) = &e.registry {
        r.unregister(pid);
    }
    crate::sys::release(pid);
    let Some(status) = status else { return Err(format!("status timed out after {:.0} s", timeout.as_secs_f64())) };
    let mut text = String::new();
    if let Some(o) = out.as_mut() {
        let _ = o.take(1 << 16).read_to_string(&mut text);
    }
    if !status.success() {
        return Err(format!("status exited {}", status.code().unwrap_or(-1)));
    }
    let doc = text.lines().rev().find_map(|l| serde_json::from_str::<Value>(l.trim()).ok().filter(Value::is_object))
        .ok_or("status printed no JSON object")?;
    Ok((doc["healthy"].as_bool() == Some(true), doc["detail"].as_str().unwrap_or("").chars().take(300).collect()))
}

/// What tells one workload's processes from every other process of the agent's account (macOS).
#[cfg(target_os = "macos")]
struct Marker {
    key: String,
    leader: i32,
    /// The leader's start time: a process of the run was born after it.
    born: u64,
    control: std::ffi::CString,
    canary: std::ffi::CString,
    events: std::ffi::CString,
}

/// Whether a sandboxed process runs with this workload's own profile: born after the run's leader, allowed to read the
/// workload's control document but not the canary beside its private directory (a profile that grants that whole
/// area, as some system services' do, grants both), allowed to write the run's events file but not the control
/// document. Only the workload's generated profile answers all four so.
#[cfg(target_os = "macos")]
fn runs_with_profile(pid: u32, born: u64, m: &Marker) -> bool {
    use crate::seatbelt::{allows_read, allows_write};
    born >= m.born
        && allows_read(pid, &m.control) == Some(true)
        && allows_read(pid, &m.canary) == Some(false)
        && allows_write(pid, &m.events) == Some(true)
        && allows_write(pid, &m.control) == Some(false)
}

/// macOS: the processes of the agent's account.
#[cfg(target_os = "macos")]
fn own_pids() -> Vec<i32> {
    const PROC_UID_ONLY: u32 = 4;
    let uid = unsafe { libc::getuid() };
    unsafe {
        let n = libc::proc_listpids(PROC_UID_ONLY, uid, std::ptr::null_mut(), 0);
        if n <= 0 {
            return vec![];
        }
        let mut buf = vec![0i32; (n as usize) / 4 + 64];
        let got = libc::proc_listpids(PROC_UID_ONLY, uid, buf.as_mut_ptr() as *mut _, (buf.len() * 4) as i32);
        buf.truncate(got.max(0) as usize / 4);
        buf.retain(|p| *p > 0);
        buf
    }
}

/// macOS: one process's CPU time and footprint.
#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn member_usage(pid: i32) -> procs::Usage {
    let mut u = procs::Usage::default();
    unsafe {
        let mut ri: libc::rusage_info_v2 = std::mem::zeroed();
        if libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V2, &mut ri as *mut _ as *mut _) == 0 {
            let mut tb = libc::mach_timebase_info { numer: 0, denom: 0 };
            libc::mach_timebase_info(&mut tb);
            let scale = if tb.denom > 0 { tb.numer as f64 / tb.denom as f64 } else { 1.0 };
            u.cpu_s = (ri.ri_user_time + ri.ri_system_time) as f64 * scale / 1e9;
            u.footprint_gb = ri.ri_phys_footprint as f64 / 1073741824.0;
        }
    }
    u
}

/// The watchdog of an agent that has ended (runners.rs) keeps the seat leases of the workloads it left: each one still
/// named by that agent's record when its lease runs out on the boot clock is ended, unless a newer agent adopted it
/// meanwhile (its record names that agent then). Returns when no record of that agent with a lease is left.
/// (specs/OarbankSeat.tla: without it an agent that stays down past a lease would leave its workload running after the
/// seat moved.)
#[cfg(unix)]
pub fn guard_leases(layout: &Layout, agent_pid: u32) {
    loop {
        let mut next: Option<f64> = None;
        let now = boot::now_s();
        let this_boot = boot::id();
        for e in std::fs::read_dir(layout.state().join("workloads")).into_iter().flatten().flatten() {
            let p = e.path();
            if p.extension().is_none_or(|x| x != "json") {
                continue;
            }
            let Some(rec) = std::fs::read(&p).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { continue };
            if rec["agent_pid"].as_u64() != Some(agent_pid as u64) || rec["boot"].as_str() != Some(this_boot.as_str()) {
                continue;
            }
            let Some(d) = rec["deadline"].as_f64() else { continue };
            if d <= now {
                info!(workload = rec["key"].as_str().unwrap_or("?"), "its agent is gone and its seat lease ran out: ended");
                end_recorded(layout, &rec);
                let _ = std::fs::remove_file(&p);
            } else {
                next = Some(next.map_or(d, |n: f64| n.min(d)));
            }
        }
        let Some(n) = next else { return };
        std::thread::sleep(Duration::from_secs_f64((n - now).clamp(0.5, 30.0)));
    }
}

/// `oarbank-agent stop-workloads`: end every workload this home's records name (an uninstall, a node that leaves
/// its fleet). Only processes that still have their recorded start times are signalled.
pub fn stop_all_recorded(layout: &Layout) -> Vec<String> {
    let mut out = vec![];
    for e in std::fs::read_dir(layout.state().join("workloads")).into_iter().flatten().flatten() {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "json") {
            continue;
        }
        if let Some(rec) = std::fs::read(&p).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
            end_recorded(layout, &rec);
            out.push(rec["key"].as_str().unwrap_or("?").to_string());
        }
        let _ = std::fs::remove_file(&p);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl(extra: Value) -> Decl {
        let mut v = json!({"name": "w", "exec": ["python", "{bundle}/w.py"]});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        Decl::parse("m", &v).unwrap()
    }

    #[test]
    fn a_declaration_reads_with_the_manifests_defaults() {
        let d = decl(json!({}));
        assert_eq!((d.pause_tolerance_s, d.stop_timeout, d.max_failures, d.jitter, d.per_node),
                   (0.0, Duration::from_secs(30), 5, true, false));
        let d = decl(json!({"control": ["freeze_ok"], "identity": "per_node", "secrets": ["k"],
                            "health": {"period_s": 15}, "restart": {"jitter": "none", "backoff_initial_s": 2, "backoff_max_s": 10}}));
        assert_eq!((d.pause_tolerance_s, d.freeze_ok, d.per_node, d.health.map(|h| h.2)), (20.0, true, true, Some(3)));
        assert_eq!((d.backoff(1, 0.3), d.backoff(2, 0.3), d.backoff(9, 0.3)), (2.0, 4.0, 10.0), "no jitter: the plain backoff");
        let j = decl(json!({"restart": {"backoff_initial_s": 10, "backoff_max_s": 600}}));
        assert_eq!(j.backoff(3, 0.5), 20.0, "full jitter: a uniform draw below the exponential");
        assert_eq!(j.backoff(30, 1.0), 600.0);
        assert!(Decl::parse("m", &json!({"name": "w", "exec": ["x"], "platforms": ["plan9-amd64"]})).is_none());
    }

    #[test]
    fn the_boot_clock_moves_and_the_boot_has_an_identity() {
        let a = boot::now_s();
        std::thread::sleep(Duration::from_millis(20));
        assert!(boot::now_s() - a >= 0.015);
        assert!(!boot::id().is_empty());
        assert_eq!(boot::id(), boot::id());
    }

    #[test]
    fn report_events_are_bounded_and_progress_is_counted() {
        let tmp = crate::scratch("wl-events");
        let p = tmp.path().join("events.ndjson");
        let mut lines = String::new();
        lines.push_str("{\"type\":\"progress\",\"event\":\"unit\",\"n\":2}\n");
        lines.push_str("{\"type\":\"error\",\"message\":\"peer gone\"}\n");
        for i in 0..70 {
            lines.push_str(&format!("{{\"type\":\"report\",\"t\":1,\"data\":{{\"i\":{i}}}}}\n"));
        }
        lines.push_str(&format!("{{\"type\":\"report\",\"data\":{{\"big\":\"{}\"}}}}\n", "x".repeat(5000)));
        lines.push_str("{\"type\":\"progress\",\"event\":\"un"); // a partial line waits for its end
        std::fs::write(&p, &lines).unwrap();
        let mut st = EventsSt::default();
        read_events(&p, &mut st, true);
        assert_eq!(st.progress.get("unit"), Some(&2));
        assert_eq!(st.last_error.as_deref(), Some("peer gone"));
        assert_eq!(st.queue.len(), REPORTS_PER_MIN as usize, "60 a minute");
        assert_eq!(st.dropped, 11, "ten over the minute's budget and one too large");
        let seqs: Vec<u64> = st.queue.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
        assert!(seqs.windows(2).all(|w| w[1] > w[0]));
        use std::io::Write;
        std::fs::OpenOptions::new().append(true).open(&p).unwrap().write_all(b"it\"}\n").unwrap();
        read_events(&p, &mut st, true);
        assert_eq!(st.progress.get("unit"), Some(&3), "the partial line completed");
        // not a reporting workload: reports are ignored
        let mut st2 = EventsSt::default();
        read_events(&p, &mut st2, false);
        assert!(st2.queue.is_empty());
    }

    /// A fake release with one module, `mod`, whose workload `w` is the synthetic double-forking daemon.
    #[cfg(unix)]
    struct Fx {
        root: PathBuf,
        release: Release,
        _tmp: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl Fx {
        fn new(tag: &str, workload: Value) -> Fx {
            let tmp = crate::scratch(&format!("wl-{tag}"));
            let root = std::fs::canonicalize(tmp.path()).unwrap();
            let dir = root.join("releases/r_test");
            let bundle = dir.join("modules/mod");
            std::fs::create_dir_all(&bundle).unwrap();
            let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/workloads/wl.sh");
            std::fs::copy(&src, bundle.join("wl.sh")).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(bundle.join("wl.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
            let entry = json!({"name": "mod", "module_id": "dev.test.mod", "bundle": "modules/mod", "workloads": [workload],
                               "sandbox": {"contract": 1, "net": {"mode": "none"}, "tools": [], "devices": {"gpu": "none"},
                                           "exec_writable": false}});
            let release = Release { id: "r_test".into(), dir, modules: vec![entry], tools: Value::Null };
            Fx { root, release, _tmp: tmp }
        }

        fn layout(&self) -> Layout {
            let l = Layout::new(self.root.join("home"));
            l.ensure().unwrap();
            l
        }

        fn manager(&self, registry: Option<Arc<SpawnRegistry>>) -> WorkloadManager {
            let rt = Runtime { python: PathBuf::from("/usr/bin/python3"), uv: None, site_dirs: vec![], roots: vec![], host_provided: None };
            let mut m = WorkloadManager::new(self.layout(), rt, registry);
            m.adopt(Some(&self.release));
            m.configure(&self.release, &json!({}), Some("node-1"), &[]);
            m
        }

        fn run_file(&self, name: &str) -> Option<String> {
            let base = self.root.join("home/modules-data/mod/workloads/w");
            std::fs::read_dir(&base).ok()?.flatten().find(|e| e.file_name().to_string_lossy().starts_with("run-"))
                .and_then(|e| std::fs::read_to_string(e.path().join(name)).ok())
        }
    }

    #[cfg(unix)]
    fn until(secs: f64, mut f: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs_f64(secs);
        while Instant::now() < deadline {
            if f() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        f()
    }

    #[cfg(unix)]
    fn state(pid: i32) -> String {
        let o = std::process::Command::new("/bin/ps").args(["-o", "stat=", "-p", &pid.to_string()]).output().unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    }

    /// The whole life of a workload on this OS, through the agent's own code: started sandboxed in its container when
    /// the directives want it; its daemon, which calls setsid and forks twice, still belongs to it (macOS: tracked by its
    /// sandbox identity; Linux: its cgroup); a protection pause freezes the daemon too; the sandbox refuses to let it
    /// listen; a new agent adopts it (the same leader, the daemon found again); unassigned, everything of it ends.
    #[cfg(unix)]
    #[test]
    fn a_double_forking_workload_is_contained_paused_adopted_and_stopped() {
        #[cfg(target_os = "linux")]
        if crate::cgroup::root().is_none() {
            assert!(!crate::cgroup::required_in_tests(), "no delegated cgroup, and OARBANK_TEST_CGROUPS=required");
            eprintln!("skipped: no delegated cgroup (workloads are not offered here)");
            return;
        }
        let fx = Fx::new("life", json!({"name": "w", "exec": ["{bundle}/wl.sh"], "control": ["freeze_ok"],
                                         "pause_tolerance_s": 60, "stop_timeout_s": 2, "health": {"period_s": 1}}));
        let reg = crate::prot::Protection::new(&fx.layout(), false).registry.clone();
        let mut m = fx.manager(Some(reg.clone()));
        let want = json!([{"key": "mod/w", "desired": "running", "restart_seq": 0}]);
        m.set_wanted(&want, boot::now_s());
        assert!(until(60.0, || {
            m.tick();
            fx.run_file("daemon.pid").is_some() && !m.running().is_empty()
        }), "never started: {}", m.report());
        let daemon: i32 = fx.run_file("daemon.pid").unwrap().trim().parse().unwrap();
        let leader = m.report()[0]["pid"].as_i64().unwrap() as i32;
        assert_ne!(unsafe { libc::getpgid(daemon) }, leader, "the daemon left the leader's group");
        // it is the workload's: in its fleet pids (macOS once the scan finds it)
        assert!(until(20.0, || {
            m.tick();
            m.fleet_pids().contains(&daemon)
        }), "the daemon was not tracked: {}", m.report());
        assert!(fx.run_file("listen.txt").unwrap_or_default().starts_with("refused"), "{:?}", fx.run_file("listen.txt"));
        // nothing but the workload's own processes is ever taken for a member (every other process of this account,
        // sandboxed apps and system services among them, fails the identity check)
        for _ in 0..5 {
            m.tick();
            std::thread::sleep(Duration::from_millis(300));
        }
        let sh = lock(&m.shared);
        for (p, _) in &sh.w["mod/w"].run.as_ref().unwrap().members {
            let o = std::process::Command::new("/bin/ps").args(["-o", "command=", "-p", &p.to_string()]).output().unwrap();
            let cmd = String::from_utf8_lossy(&o.stdout).to_string();
            assert!(*p == daemon || cmd.contains("perl") || cmd.contains("wl.sh") || cmd.trim().is_empty(),
                    "a process that is not the workload's was tracked: {p} {cmd}");
        }
        drop(sh);
        // protection pauses it: the leader and the daemon are frozen; resumed, both run again
        let mut plans = BTreeMap::new();
        plans.insert("mod/w".to_string(), WorkloadAction { admit: true, paused: true, ..Default::default() });
        m.apply(&plans);
        assert!(until(10.0, || state(daemon).starts_with('T') && state(leader).starts_with('T')),
                "not frozen: daemon {} leader {}", state(daemon), state(leader));
        plans.insert("mod/w".to_string(), WorkloadAction { admit: true, ..Default::default() });
        m.apply(&plans);
        assert!(until(10.0, || !state(daemon).starts_with('T')));
        // the health check answers
        assert!(until(20.0, || {
            m.tick();
            m.report()[0]["health"] == "healthy"
        }), "{}", m.report());
        // a new agent: the old one's manager goes, the workload stays and is adopted with its daemon
        drop(m);
        assert!(crate::sys::group_alive(leader));
        let mut m2 = fx.manager(Some(reg.clone()));
        let r = m2.report();
        assert_eq!((r[0]["pid"].as_i64(), r[0]["adopted"].as_bool()), (Some(leader as i64), Some(true)), "{r}");
        m2.set_wanted(&want, boot::now_s());
        assert!(until(20.0, || {
            m2.tick();
            m2.fleet_pids().contains(&daemon)
        }), "the adopted workload's daemon was not found again");
        // unassigned: everything of it ends
        m2.set_wanted(&json!([]), boot::now_s());
        assert!(until(30.0, || {
            m2.tick();
            // the leader was this test's child (the first manager's): reap it, as init does for an agent that is gone
            unsafe { libc::waitpid(leader, std::ptr::null_mut(), libc::WNOHANG) };
            m2.running().is_empty() && !crate::sys::group_alive(leader) && procs::start_time_us(daemon).is_none()
                && m2.report()[0]["state"] == "stopped"
        }), "still running: leader {} daemon {}: {}", crate::sys::group_alive(leader), procs::start_time_us(daemon).is_some(),
            m2.report());
        assert!(!record_path(&fx.layout(), "mod/w").exists(), "its record goes with it");
        assert!(!fx.root.join("home/run/workloads/mod/w/secrets.json").exists());
    }

    /// A per-node identity: the workload waits for its secrets for its seat and fence, runs with them in an owner-only
    /// file, and stops when its lease runs out on the boot clock (the report then gives the seat back); a renewal keeps
    /// it running.
    #[cfg(unix)]
    #[test]
    fn a_seat_lease_gates_the_run_and_its_end_stops_it() {
        #[cfg(target_os = "linux")]
        if crate::cgroup::root().is_none() {
            return;
        }
        let fx = Fx::new("lease", json!({"name": "w", "exec": ["{bundle}/wl.sh"], "identity": "per_node",
                                          "secrets": ["key"], "stop_timeout_s": 2}));
        let mut m = fx.manager(None);
        let want = |lease: f64| json!([{"key": "mod/w", "desired": "running", "seat_id": "s_1", "fence": 3, "lease_s": lease}]);
        m.set_wanted(&want(6.0), boot::now_s());
        m.tick();
        assert!(m.running().is_empty(), "no secrets yet");
        assert_eq!(m.needs_secrets(), vec![("mod/w".to_string(), Some("s_1".to_string()), 3)]);
        let mut sec = Map::new();
        sec.insert("key".into(), json!("value-one"));
        m.provide_secrets("mod/w", Some("s_1".into()), 3, Ok(sec));
        assert!(until(30.0, || {
            m.tick();
            !m.running().is_empty()
        }));
        let secrets = fx.root.join("home/run/workloads/mod/w/secrets.json");
        assert_eq!(std::fs::read_to_string(&secrets).unwrap(), r#"{"key":"value-one"}"#);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&secrets).unwrap().permissions().mode() & 0o777, 0o600);
        // renewed: still running past the first lease's end
        std::thread::sleep(Duration::from_secs(4));
        m.set_wanted(&want(6.0), boot::now_s());
        std::thread::sleep(Duration::from_secs(3));
        m.tick();
        assert!(!m.running().is_empty(), "a renewal keeps it running");
        // not renewed: stopped at the end, the seat given back with its fence, the secrets gone
        assert!(until(20.0, || {
            m.tick();
            m.report()[0]["state"] == "stopped"
        }), "{}", m.report());
        let r = m.report();
        assert_eq!((r[0]["release"].as_bool(), r[0]["fence"].as_i64(), r[0]["reason"].as_str()),
                   (Some(true), Some(3), Some("WORKLOAD_SEAT_LEASE_EXPIRED")), "{r}");
        assert!(!secrets.exists());
    }

    /// A workload that keeps exiting backs off and is withdrawn after max_failures; a restart operation lifts it.
    #[cfg(unix)]
    #[test]
    fn a_crash_loop_backs_off_then_withdraws_until_a_restart() {
        #[cfg(target_os = "linux")]
        if crate::cgroup::root().is_none() {
            return;
        }
        let fx = Fx::new("crash", json!({"name": "w", "exec": ["/usr/bin/false"],
                                          "restart": {"backoff_initial_s": 0.2, "backoff_max_s": 0.4, "max_failures": 3, "jitter": "none"}}));
        let mut m = fx.manager(None);
        m.set_wanted(&json!([{"key": "mod/w", "desired": "running", "restart_seq": 0}]), boot::now_s());
        assert!(until(60.0, || {
            m.tick();
            m.report()[0]["withdrawn"] == true
        }), "{}", m.report());
        let r = m.report();
        assert_eq!((r[0]["failures"].as_u64(), r[0]["state"].as_str(), r[0]["release"].as_bool()), (Some(3), Some("withdrawn"), Some(true)));
        assert!(r[0]["error"].as_str().unwrap_or("").contains("exited"), "{r}");
        m.set_wanted(&json!([{"key": "mod/w", "desired": "running", "restart_seq": 1}]), boot::now_s());
        let r = m.report();
        assert_eq!((r[0]["withdrawn"].as_bool(), r[0]["failures"].as_u64()), (Some(false), Some(0)));
    }

    /// The watchdog of an agent that died ends the workloads its records name when their leases run out, but not one a
    /// newer agent adopted (its record names that agent).
    #[cfg(unix)]
    #[test]
    fn a_dead_agents_watchdog_ends_its_workloads_at_their_lease_end() {
        let tmp = crate::scratch("wl-guard");
        let layout = Layout::new(tmp.path().to_path_buf());
        layout.ensure().unwrap();
        std::fs::create_dir_all(layout.state().join("workloads")).unwrap();
        let spawn = || {
            let mut c = std::process::Command::new("/bin/sleep");
            c.arg("300");
            crate::sys::spawn_contained(&mut c, true).unwrap()
        };
        let (mut a, mut b) = (spawn(), spawn());
        let rec = |child: &std::process::Child, key: &str, agent: u32| {
            let pid = child.id() as i32;
            json!({"key": key, "leader": pid, "start_us": procs::start_time_us(pid).unwrap().to_string(), "members": [],
                   "deadline": boot::now_s() + 1.0, "boot": boot::id(), "agent_pid": agent, "job": ""})
        };
        std::fs::write(record_path(&layout, "m/a"), rec(&a, "m/a", 4_000_000).to_string()).unwrap();
        std::fs::write(record_path(&layout, "m/b"), rec(&b, "m/b", 4_000_001).to_string()).unwrap();
        guard_leases(&layout, 4_000_000);
        assert!(a.wait().is_ok() && !record_path(&layout, "m/a").exists(), "ended at its lease's end");
        assert!(b.try_wait().unwrap().is_none(), "another agent's workload is left alone");
        let _ = b.kill();
        let _ = b.wait();
    }
}
