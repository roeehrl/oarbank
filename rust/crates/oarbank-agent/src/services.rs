//! Module services and probes (service protocol 1: the SDK's spec/service-protocol.md; docs/protocol.md, "Services
//! and probes"). A service is a bundle executable answering `fingerprint | start | stop | status | ready | list_owned |
//! destroy`, a probe one answering `fingerprint`; the agent knows nothing about what either manages.
//!
//! Every op runs as its own process group under the module sandbox, with the protocol's environment and cwd the
//! bundle root, on a worker thread: the agent's tick only reads state and hands out work, so a `start` that waits up
//! to `start_timeout_s` for `ready` never holds it up. On-demand services are reference-counted by the pools and
//! capabilities admitted jobs need, gated on `ready`, and stopped after `idle_timeout_s`; failures back off and then
//! withdraw the service; a service found running is adopted, never started twice; objects owned by attempts that no
//! longer exist are reaped through `list_owned` and `destroy`.
//!
//! An endpoint service (`endpoint = true`) gets its endpoint channel at `start` (endpoints.rs); it is ready only once it
//! has said hello on it, it is never adopted (a channel ends with the agent that made it, so one found running is stopped
//! and started again), and a channel the service closes is its failure. Host protection may hold a yieldable service
//! down (`set_held`). Every change of state wakes the waiters on `changed`, so nothing that waits for a service polls.

use crate::doctor::{base_env, grant_files, resolve_exec};
use crate::endpoints::{self, Channel, Connector, Refusal};
use crate::paths::Layout;
use crate::procs;
use crate::release::Release;
use crate::runtime::Runtime;
use oarbank_protection::SpawnRegistry;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// The protocol's default timeouts for the ops that have no manifest field.
const FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(5);
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const LIST_TIMEOUT: Duration = Duration::from_secs(5);
const DESTROY_TIMEOUT: Duration = Duration::from_secs(60);
/// Between `ready` polls while a service comes up.
const READY_POLL: Duration = Duration::from_secs(1);
/// SIGTERM to SIGKILL for a process group the agent ends.
const TERM_GRACE: Duration = Duration::from_secs(3);
/// The shortest probe period honoured (the manifest's floor is 10 s; this only stops a hot loop).
const MIN_PROBE_PERIOD: Duration = Duration::from_secs(1);
/// A probe that could not be run at all (timeout, spawn) is tried again this soon, not a whole period later.
const PROBE_RETRY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    OnDemand,
    Always,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Not fingerprinted yet.
    Unknown,
    Healthy,
    /// Offered at zero capacity; the agent tries to heal it.
    Unhealthy,
    /// Not offered, no alert.
    Undetected,
}

impl Health {
    fn parse(s: Option<&str>) -> Health {
        match s {
            Some("healthy") => Health::Healthy,
            Some("undetected") => Health::Undetected,
            _ => Health::Unhealthy,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Health::Unknown => "unknown",
            Health::Healthy => "healthy",
            Health::Unhealthy => "unhealthy",
            Health::Undetected => "undetected",
        }
    }
}

/// A release entry's `services[]` item, with the manifest's defaults.
#[derive(Debug, Clone)]
struct ServiceDecl {
    name: String,
    exec: Vec<Value>,
    lifecycle: Lifecycle,
    idle_timeout: Duration,
    start_timeout: Duration,
    stop_timeout: Duration,
    backoff_initial_s: f64,
    backoff_max_s: f64,
    max_failures: u32,
    capabilities: Vec<String>,
    pools: Vec<String>,
    reserves_host_memory: bool,
    yieldable: bool,
    /// Jobs reach it through the agent (spec/service-protocol.md, "Endpoints").
    endpoint: bool,
    /// `gpu.use` is not none: GPU-resident fleet work while it runs.
    gpu: bool,
}

fn secs(v: &Value, default: f64, min: f64) -> f64 {
    v.as_f64().filter(|x| x.is_finite()).unwrap_or(default).max(min)
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// Whether a `platforms` list admits this node (empty: every platform).
fn on_this_platform(v: &Value) -> bool {
    let p = strings(v);
    p.is_empty() || p.contains(&crate::facts::platform_token())
}

impl ServiceDecl {
    fn parse(v: &Value) -> Option<ServiceDecl> {
        let name = v["name"].as_str()?.to_string();
        let exec = v["exec"].as_array()?.clone();
        if exec.is_empty() || !on_this_platform(&v["platforms"]) {
            return None;
        }
        let lifecycle = match v["lifecycle"].as_str() {
            Some("always") => Lifecycle::Always,
            Some("manual") => Lifecycle::Manual,
            _ => Lifecycle::OnDemand,
        };
        let r = &v["restart"];
        let initial = secs(&r["backoff_initial_s"], 10.0, 0.01);
        Some(ServiceDecl {
            name,
            exec,
            lifecycle,
            idle_timeout: Duration::from_secs_f64(secs(&v["idle_timeout_s"], 900.0, 0.0)),
            start_timeout: Duration::from_secs_f64(secs(&v["start_timeout_s"], 120.0, 1.0)),
            stop_timeout: Duration::from_secs_f64(secs(&v["stop_timeout_s"], 120.0, 1.0)),
            backoff_initial_s: initial,
            backoff_max_s: secs(&r["backoff_max_s"], 600.0, initial),
            max_failures: r["max_failures"].as_u64().unwrap_or(5).clamp(1, 1000) as u32,
            capabilities: strings(&v["provides"]["capabilities"]),
            pools: strings(&v["provides"]["pools"]),
            reserves_host_memory: v["reserves_host_memory"].as_bool() == Some(true),
            yieldable: v["yieldable"].as_bool() != Some(false),
            endpoint: v["endpoint"].as_bool() == Some(true),
            gpu: v["gpu"]["use"].as_str().is_some_and(|u| u != "none"),
        })
    }

    /// Jobs that need this service: the most demanded of the pools and capabilities it provides (a job needing two
    /// of them counts once).
    fn users(&self, need: &BTreeMap<String, i64>) -> i64 {
        self.pools.iter().chain(self.capabilities.iter()).filter_map(|n| need.get(n)).copied().max().unwrap_or(0).max(0)
    }

    fn provides(&self, name: &str) -> bool {
        self.pools.iter().any(|p| p == name) || self.capabilities.iter().any(|c| c == name)
    }
}

#[derive(Debug, Clone)]
struct ProbeDecl {
    name: String,
    exec: Vec<Value>,
    period: Duration,
}

impl ProbeDecl {
    fn parse(v: &Value) -> Option<ProbeDecl> {
        let name = v["name"].as_str()?.to_string();
        let exec = v["exec"].as_array()?.clone();
        if exec.is_empty() || !on_this_platform(&v["platforms"]) {
            return None;
        }
        let period = Duration::from_secs_f64(secs(&v["period_s"], 3600.0, 0.0)).max(MIN_PROBE_PERIOD);
        Some(ProbeDecl { name, exec, period })
    }
}

/// What running one module's executables needs: its paths, the files the protocol passes by path, its grants.
struct ModCtx {
    module: String,
    module_id: String,
    bundle: PathBuf,
    python: PathBuf,
    venv: Option<PathBuf>,
    data: PathBuf,
    grants: PathBuf,
    tools_file: PathBuf,
    settings_file: PathBuf,
    limits_file: PathBuf,
    tool_paths: Vec<String>,
    roots: Vec<String>,
    node_id: String,
    net: String,
    gpu: bool,
    exec_rw: bool,
    /// `egress-allowlist`: the module's proxy, kept for as long as the module keeps the same allow list (a running
    /// service's sandbox names its port).
    proxy: Option<ProxySlot>,
}

type ProxySlot = Arc<Mutex<Option<crate::proxy::Proxy>>>;

impl ModCtx {
    /// The proxy's port, waiting briefly for a proxy still starting.
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

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The result of one op.
struct OpOut {
    ok: bool,
    doc: Option<Value>,
    detail: String,
    /// `start` only: the op's process group, while processes it left behind still hold it.
    pgid: Option<i32>,
}

impl OpOut {
    fn failed(detail: String) -> OpOut {
        OpOut { ok: false, doc: None, detail, pgid: None }
    }
}

/// One service's or probe's executable, ready to run an op.
#[derive(Clone)]
struct Exec {
    ctx: Arc<ModCtx>,
    name: String,
    kind: &'static str,
    exec: Vec<Value>,
    registry: Option<Arc<SpawnRegistry>>,
}

/// Whether a process container still has members.
fn group_alive(pgid: i32) -> bool {
    crate::sys::group_alive(pgid)
}

/// SIGTERM a process group, then SIGKILL whatever is left after the grace.
fn end_group(pgid: i32) {
    if !group_alive(pgid) {
        return;
    }
    procs::signal_group(pgid, procs::Sig::Term);
    let deadline = Instant::now() + TERM_GRACE;
    while group_alive(pgid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    procs::signal_group(pgid, procs::Sig::Kill);
}

#[cfg(unix)]
fn set_nonblocking(fd: &impl std::os::fd::AsRawFd) {
    unsafe {
        let fl = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if fl >= 0 {
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
        }
    }
}

/// How many bytes a pipe holds now (Windows pipes cannot be made non-blocking: peek first, read only that).
#[cfg(windows)]
fn pending(r: &impl std::os::windows::io::AsRawHandle) -> usize {
    let mut avail = 0u32;
    let ok = unsafe {
        windows_sys::Win32::System::Pipes::PeekNamedPipe(r.as_raw_handle() as _, std::ptr::null_mut(), 0, std::ptr::null_mut(),
                                                         &mut avail, std::ptr::null_mut())
    };
    if ok != 0 { avail as usize } else { 0 }
}

/// Read what a pipe holds now without blocking, keeping at most `cap` bytes (the tail).
#[cfg(unix)]
fn drain(r: &mut Option<impl Read>, buf: &mut Vec<u8>, cap: usize) {
    drain_some(r, buf, cap, usize::MAX)
}

#[cfg(windows)]
fn drain(r: &mut Option<impl Read + std::os::windows::io::AsRawHandle>, buf: &mut Vec<u8>, cap: usize) {
    let n = r.as_ref().map(pending).unwrap_or(0);
    if n > 0 {
        drain_some(r, buf, cap, n)
    }
}

fn drain_some(r: &mut Option<impl Read>, buf: &mut Vec<u8>, cap: usize, mut budget: usize) {
    let Some(r) = r.as_mut() else { return };
    let mut chunk = [0u8; 8192];
    while budget > 0 {
        let want = chunk.len().min(budget);
        match r.read(&mut chunk[..want]) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                budget -= n;
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > cap {
                    buf.drain(..buf.len() - cap);
                }
            }
        }
    }
}

/// The op's JSON document: all of stdout, else its last line that is an object.
fn parse_doc(out: &[u8]) -> Option<Value> {
    let s = String::from_utf8_lossy(out);
    serde_json::from_str::<Value>(s.trim()).ok().filter(Value::is_object).or_else(|| {
        s.lines().rev().find(|l| l.trim_start().starts_with('{')).and_then(|l| serde_json::from_str(l).ok())
    })
}

impl Exec {
    fn label(&self) -> String {
        format!("{}/{}", self.ctx.module, self.name)
    }

    /// The module sandbox for this op (spec/service-protocol.md, "Sandbox"): read-only bundle, interpreter, runtime
    /// and approved tools; read-write the module's data directory; the module's network grant; never the broker.
    fn confine(&self, argv: &[String], port: Option<u16>) -> Result<Vec<String>, String> {
        let exe = argv[0].as_str();
        let c = &self.ctx;
        let mut pol = oarbank_core::sandbox::Policy::new(c.module_id.clone());
        pol.ro = vec![c.bundle.display().to_string(), c.python.display().to_string(), c.grants.display().to_string()];
        if let Some(v) = &c.venv {
            pol.ro.push(v.display().to_string());
        }
        pol.ro.extend(c.roots.iter().cloned());
        pol.ro.extend(c.tool_paths.iter().cloned());
        pol.rw = vec![c.data.display().to_string()];
        pol.net = match c.net.as_str() {
            "egress-any" => "egress-any".into(),
            "egress-allowlist" if port.is_some() => "egress-allowlist".into(),
            _ => "none".into(),                                    // no proxy (or an unknown mode): no network
        };
        pol.proxy_port = if pol.net == "egress-allowlist" { port } else { None };
        pol.gpu = c.gpu;
        pol.exec_rw = c.exec_rw;
        pol.kind = self.kind.into();
        pol.exe = Some(exe.to_string());
        crate::sandbox::wrap(&pol, &c.grants.join(format!("{}-{}.sb", self.kind, self.name)), argv)
    }

    /// Run `<exec> <args...>` and wait for it (killing its group after `timeout`). `keep_group`: processes the op
    /// leaves behind are the service itself (`start`), so its group is kept and returned; any other op leaves nothing.
    fn run(&self, args: &[&str], timeout: Duration, keep_group: bool) -> OpOut {
        self.run_with(args, timeout, keep_group, None)
    }

    /// `run`, handing `channel`'s service end to the op (`start` of an endpoint service) and to what it leaves running.
    fn run_with(&self, args: &[&str], timeout: Duration, keep_group: bool, channel: Option<&Channel>) -> OpOut {
        let c = &self.ctx;
        let mut argv = resolve_exec(&self.exec, &c.bundle, &c.python);
        if argv.is_empty() || !Path::new(&argv[0]).is_absolute() {
            return OpOut::failed("the exec does not resolve to an absolute path".into());
        }
        argv.extend(args.iter().map(|a| a.to_string()));
        if let Err(e) = crate::fsutil::private_dir(&c.data.join("tmp")) {
            return OpOut::failed(format!("data directory: {e}"));
        }
        let port = if c.net == "egress-allowlist" { c.proxy_port() } else { None };
        let mut env = base_env(&c.module, &c.data, &c.data.join("tmp"));
        env.extend([("OARBANK_MODULE_DATA".into(), c.data.display().to_string()),
                    ("OARBANK_SERVICE".into(), self.name.clone()),
                    ("OARBANK_NODE_ID".into(), c.node_id.clone()),
                    ("OARBANK_SETTINGS_FILE".into(), c.settings_file.display().to_string()),
                    ("OARBANK_TOOLS_FILE".into(), c.tools_file.display().to_string()),
                    ("OARBANK_LIMITS_FILE".into(), c.limits_file.display().to_string())]);
        if let Some(ch) = channel {
            env.push((endpoints::CHANNEL_ENV.into(), ch.child_value()));
        }
        if let Some(p) = port {
            let url = format!("http://127.0.0.1:{p}");
            for k in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"] {
                env.push((k.into(), url.clone()));
            }
        }
        let sandboxed = crate::sandbox::available();
        if sandboxed {
            match self.confine(&argv, port) {
                Ok(a) => argv = a,
                Err(e) => return OpOut::failed(e),
            }
        }
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]).env_clear().envs(env).current_dir(&c.bundle).stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let signal = match sandboxed.then(crate::sandbox::ConfinedSignal::new).transpose() {
            Ok(s) => s,
            Err(e) => return OpOut::failed(format!("confinement signal: {e}")),
        };
        if let Some(s) = &signal {
            s.prepare(&mut cmd);
        }
        if let Some(ch) = channel {
            ch.prepare(&mut cmd);
        }
        let mut child = match crate::sys::spawn_contained(&mut cmd, keep_group) {
            Ok(ch) => ch,
            Err(e) => {
                if let Some(ch) = channel {
                    ch.spawned(None);
                }
                return OpOut::failed(format!("spawn: {e}"));
            }
        };
        let pid = child.id() as i32;
        if let Some(ch) = channel {
            ch.spawned(Some(pid));
        }
        if let Some(r) = &self.registry {
            r.register(pid, None, Some(&self.label()));          // only registered groups may ever be signalled (S16)
        }
        let unregister = |pid: i32| {
            if let Some(r) = &self.registry {
                r.unregister(pid);
            }
        };
        let (mut stdout, mut stderr) = (child.stdout.take(), child.stderr.take());
        // a service's daemon may inherit these pipes and hold them open: read without blocking, never to EOF
        #[cfg(unix)]
        {
            if let Some(s) = &stdout {
                set_nonblocking(s);
            }
            if let Some(s) = &stderr {
                set_nonblocking(s);
            }
        }
        // the launcher says when its sandbox holds, just before the module runs: a process that does not come up
        // confined is killed, never left running
        if let Some(s) = signal {
            use crate::sandbox::Came;
            let fault = match s.wait(pid as u32, crate::sandbox::CONFINE_GUARD) {
                Came::Confined if crate::sandbox::holds(pid) || matches!(child.try_wait(), Ok(Some(_))) => None,
                Came::Confined => Some("sandbox_missing: the launcher said it was confined, but the process is not"),
                Came::Ended => None,                           // it could not confine itself: its exit says why
                Came::Hung => Some("sandbox_hung: the launcher did not confine itself within the guard"),
            };
            if let Some(f) = fault {
                procs::signal_group(pid, procs::Sig::Kill);
                let _ = child.wait();
                unregister(pid);
                warn!(service = %self.label(), "{f}; killed");
                return OpOut::failed("the process did not come up sandboxed".into());
            }
        }
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let deadline = Instant::now() + timeout;
        let status = loop {
            drain(&mut stdout, &mut out, 1 << 20);
            drain(&mut stderr, &mut err, 8 << 10);
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if Instant::now() >= deadline => {
                    end_group(pid);
                    let _ = child.wait();
                    break None;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(15)),
                Err(_) => break None,
            }
        };
        drain(&mut stdout, &mut out, 1 << 20);
        drain(&mut stderr, &mut err, 8 << 10);
        let ok = status.is_some_and(|s| s.success());
        let keep = keep_group && ok && group_alive(pid);
        if !keep {
            procs::signal_group(pid, procs::Sig::Kill);              // nothing outlives an op but a started service
            unregister(pid);
        }
        let err_tail: String = String::from_utf8_lossy(&err).trim().chars().rev().take(300).collect::<Vec<_>>()
            .into_iter().rev().collect();
        let detail = match status {
            None => format!("{} timed out after {:.0} s", args.first().unwrap_or(&"?"), timeout.as_secs_f64()),
            Some(s) if !s.success() => format!("{} exited {}: {err_tail}", args.first().unwrap_or(&"?"),
                                               s.code().map(|c| c.to_string()).unwrap_or_else(|| "on a signal".into())),
            Some(_) => String::new(),
        };
        OpOut { ok, doc: parse_doc(&out), detail, pgid: keep.then_some(pid) }
    }
}

/// One service's runtime state.
#[derive(Debug, Clone)]
struct Svc {
    module: String,
    decl: ServiceDecl,
    health: Health,
    running: bool,
    ready: bool,
    pools: BTreeMap<String, i64>,
    reserve_mem_gb: f64,
    disabled: bool,
    /// A lifecycle op (fingerprint, start, stop, ready) is in flight; one at a time per service.
    busy: bool,
    reaping: bool,
    failures: u32,
    next_try: Option<Instant>,
    last_fingerprint: Option<Instant>,
    idle_since: Option<Instant>,
    users: i64,
    /// After `restart.max_failures` consecutive failures, until a later fingerprint is healthy.
    withdrawn: bool,
    last_error: Option<String>,
    /// The process group `start` left the service in (signalled after `stop` so nothing outlives it).
    pgid: Option<i32>,
    last_reap: Option<Instant>,
    /// An endpoint service's channel, from its `start` until it stops.
    channel: Option<Arc<Channel>>,
    /// Host protection holds it down, with the release reason (`set_held`).
    held: Option<String>,
    /// Unix time this agent started it (0: adopted).
    started_at: f64,
}

impl Svc {
    fn new(module: &str, decl: ServiceDecl) -> Svc {
        Svc { module: module.into(), decl, health: Health::Unknown, running: false, ready: false, pools: BTreeMap::new(),
              reserve_mem_gb: 0.0, disabled: false, busy: false, reaping: false, failures: 0, next_try: None,
              last_fingerprint: None, idle_since: None, users: 0, withdrawn: false, last_error: None, pgid: None,
              last_reap: None, channel: None, held: None, started_at: 0.0 }
    }

    /// Offered to the coordinator: healthy, enabled, not withdrawn.
    fn offered(&self) -> bool {
        self.health == Health::Healthy && !self.disabled && !self.withdrawn
    }

    /// An endpoint service has said hello on its channel (any other service: always).
    fn accepting(&self) -> bool {
        !self.decl.endpoint || self.channel.as_ref().is_some_and(|c| c.accepting())
    }

    /// A failed op: back off exponentially, withdraw after `max_failures`.
    fn failed(&mut self, key: &str, op: &str, detail: &str) {
        self.failures += 1;
        let d = &self.decl;
        let delay = (d.backoff_initial_s * 2f64.powi(self.failures.saturating_sub(1).min(60) as i32)).min(d.backoff_max_s);
        self.next_try = Some(Instant::now() + Duration::from_secs_f64(delay));
        self.last_error = Some(format!("{op} failed ({}): {detail}; retry in {delay:.0} s", self.failures));
        if self.failures >= d.max_failures && !self.withdrawn {
            self.withdrawn = true;
            warn!(service = key, failures = self.failures, "service withdrawn after repeated failures");
        } else {
            warn!(service = key, op, detail, "service op failed");
        }
        self.last_fingerprint = None;
    }
}

#[derive(Debug, Clone)]
struct ProbeSt {
    module: String,
    decl: ProbeDecl,
    health: Health,
    attrs: Value,
    busy: bool,
    last_run: Option<Instant>,
}

#[derive(Default)]
struct Shared {
    services: BTreeMap<String, Svc>,
    probes: BTreeMap<String, ProbeSt>,
    /// After `stop_all`: nothing starts until `resume`.
    halted: bool,
    changed: Arc<Changed>,
}

/// Wakes everything that waits on the services' state: the readiness gate (async, `notify`) and connectors (threads).
#[derive(Default)]
pub struct Changed {
    seq: Mutex<u64>,
    cv: Condvar,
    pub notify: tokio::sync::Notify,
}

impl Changed {
    pub fn bump(&self) {
        *lock(&self.seq) += 1;
        self.cv.notify_all();
        self.notify.notify_waiters();
    }

    /// `f` once it answers, waiting for changes in between (never past `deadline`).
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

type SharedRef = Arc<Mutex<Shared>>;

enum Job {
    Fingerprint,
    Start,
    Stop(Option<i32>),
    Ready,
    Reap(BTreeSet<i64>),
    Probe,
}

/// A running service for host protection: its process group, whether it uses a GPU, whether protection may stop it,
/// and the pools it provides (the jobs reserving them are its users, released with it).
pub struct ServiceView {
    pub key: String,
    pub module: String,
    pub pgid: Option<i32>,
    pub started_at: f64,
    pub gpu: bool,
    pub yieldable: bool,
    pub pools: Vec<String>,
}

pub struct ServiceManager {
    layout: Layout,
    runtime: Runtime,
    registry: Option<Arc<SpawnRegistry>>,
    manage: bool,
    node_id: String,
    limits: Value,
    modules: BTreeMap<String, Arc<ModCtx>>,
    proxies: HashMap<String, (Vec<String>, ProxySlot)>,
    shared: SharedRef,
    last_live: BTreeSet<i64>,
    fingerprint_every: Duration,
    reap_every: Duration,
}

impl ServiceManager {
    pub fn new(layout: Layout, runtime: Runtime, registry: Option<Arc<SpawnRegistry>>, manage_services: bool) -> Self {
        ServiceManager { layout, runtime, registry, manage: manage_services, node_id: String::new(), limits: json!({}),
                         modules: BTreeMap::new(), proxies: HashMap::new(), shared: SharedRef::default(),
                         last_live: BTreeSet::new(), fingerprint_every: Duration::from_secs(20),
                         reap_every: Duration::from_secs(60) }
    }

    /// The owner's caps (the directives' `limits`), passed to services as OARBANK_LIMITS_FILE.
    pub fn set_limits(&mut self, limits: &Value) {
        self.limits = if limits.is_object() { limits.clone() } else { json!({}) };
        for c in self.modules.values() {
            if let Err(e) = std::fs::write(&c.limits_file, self.limits.to_string()) {
                warn!(module = %c.module, error = %e, "cannot write the limits file");
            }
        }
    }

    /// The module's egress proxy, reused while its allow list stays the same.
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
                        Err(e) => warn!(module = %m, error = %e, "cannot start the services' egress proxy"),
                    }
                });
            }
            Err(_) => warn!(module, "no async runtime for the egress proxy: services run without network"),
        }
        self.proxies.insert(module.to_string(), (allow, slot.clone()));
        slot
    }

    fn module_ctx(&mut self, release: &Release, entry: &Value, policy: &Value) -> std::io::Result<ModCtx> {
        let name = entry["name"].as_str().unwrap_or("").to_string();
        let bundle = release.bundle(entry);
        let python = self.runtime.module_python(&release.dir, &name);
        let venv = Some(release.dir.join("venvs").join(&name)).filter(|v| v.exists());
        let data = self.layout.module_data().join(&name);
        crate::fsutil::private_dir(&data.join("tmp"))?;
        let grants = self.layout.run().join("services").join(&name);
        let mut settings = policy["module_settings"][&name].clone();
        if settings.is_null() {
            settings = json!({});
        }
        let (tools_file, settings_file, tool_paths) = grant_files(&grants, entry, &settings)?;
        let limits_file = grants.join("limits.json");
        std::fs::write(&limits_file, self.limits.to_string())?;
        let net = entry["sandbox"]["net"]["mode"].as_str().unwrap_or("none").to_string();
        let proxy = (net == "egress-allowlist").then(|| self.proxy_for(&name, strings(&entry["sandbox"]["net"]["allow"])));
        Ok(ModCtx { module_id: entry["module_id"].as_str().unwrap_or(&name).to_string(), module: name, bundle, python, venv,
                    data, grants, tools_file, settings_file, limits_file, tool_paths, roots: self.runtime.roots.clone(),
                    node_id: self.node_id.clone(), net, gpu: entry["sandbox"]["devices"]["gpu"].as_str().is_some_and(|g| g != "none"),
                    exec_rw: entry["sandbox"]["exec_writable"].as_bool() == Some(true), proxy })
    }

    /// A new release or policy: (re)read services/probes from the release's module entries, honour disabled_services
    /// and module_settings. Runtime state (running, failures, adoption) carries over for services that stay; a running
    /// service the release no longer has is stopped with its old executable.
    pub fn configure(&mut self, release: &Release, policy: &Value, node_id: Option<&str>) {
        if let Some(n) = node_id {
            self.node_id = n.to_string();
        }
        let disabled: BTreeSet<String> = strings(&policy["disabled_services"]).into_iter().collect();
        // the files first (contexts, grants), away from the shared state
        let mut modules = BTreeMap::new();
        let mut decls: Vec<(String, Vec<ServiceDecl>, Vec<ProbeDecl>)> = Vec::new();
        for entry in &release.modules {
            let Some(name) = entry["name"].as_str().map(str::to_string) else { continue };
            let sd: Vec<ServiceDecl> = entry["services"].as_array().into_iter().flatten().filter_map(ServiceDecl::parse).collect();
            let pd: Vec<ProbeDecl> = entry["probes"].as_array().into_iter().flatten().filter_map(ProbeDecl::parse).collect();
            if sd.is_empty() && pd.is_empty() {
                continue;
            }
            match self.module_ctx(release, entry, policy) {
                Ok(c) => {
                    modules.insert(name.clone(), Arc::new(c));
                    decls.push((name, sd, pd));
                }
                Err(e) => warn!(module = %name, error = %e, "cannot prepare the module's services"),
            }
        }
        // then the new state in one hold of the lock: an op that finishes meanwhile writes into the state that stays
        let old_services = {
            let mut sh = lock(&self.shared);
            let mut old_services = std::mem::take(&mut sh.services);
            let mut old_probes = std::mem::take(&mut sh.probes);
            for (name, sd, pd) in decls {
                for d in sd {
                    let key = format!("{name}/{}", d.name);
                    let mut st = old_services.remove(&key).unwrap_or_else(|| Svc::new(&name, d.clone()));
                    st.decl = d;
                    st.disabled = disabled.contains(&key);
                    sh.services.insert(key, st);
                }
                for d in pd {
                    let key = format!("{name}/{}", d.name);
                    let mut st = old_probes.remove(&key).unwrap_or_else(|| ProbeSt { module: name.clone(), decl: d.clone(),
                        health: Health::Unknown, attrs: Value::Null, busy: false, last_run: None });
                    st.decl = d;
                    sh.probes.insert(key, st);
                }
            }
            old_services
        };
        let old_modules = std::mem::replace(&mut self.modules, modules);
        self.proxies.retain(|m, _| self.modules.get(m).is_some_and(|c| c.proxy.is_some()));
        for (key, s) in old_services {
            if !(self.manage && s.running && s.decl.lifecycle != Lifecycle::Manual) {
                continue;
            }
            if let Some(ctx) = old_modules.get(&s.module) {
                info!(service = %key, "stopping a service the release no longer has");
                let x = Exec { ctx: ctx.clone(), name: s.decl.name.clone(), kind: "service", exec: s.decl.exec.clone(),
                               registry: self.registry.clone() };
                let (timeout, pgid, reg, channel) = (s.decl.stop_timeout, s.pgid, self.registry.clone(), s.channel);
                std::thread::spawn(move || {
                    let _ = x.run(&["stop"], timeout, false);
                    if let Some(c) = channel {
                        c.close();
                    }
                    if let Some(g) = pgid {
                        end_group(g);
                        if let Some(r) = reg {
                            r.unregister(g);
                        }
                    }
                });
            }
        }
    }

    /// Fingerprint every service and run every probe on the next tick (after a doctor-triggering event).
    #[cfg(all(test, unix))]
    pub fn refresh_now(&mut self) {
        let mut sh = lock(&self.shared);
        sh.services.values_mut().for_each(|s| s.last_fingerprint = None);
        sh.probes.values_mut().for_each(|p| p.last_run = None);
    }

    /// Every agent tick: start/stop on demand, idle timeouts, probe periods, backoff, adoption, reaping. `jobs_need`:
    /// pools (and capabilities) needed by admitted/running jobs, with the number of jobs needing each; `live_attempts`
    /// for reaping; `memory_soft`: the memory guard is soft or hard (stop idle yieldable services).
    pub fn tick(&mut self, jobs_need: &BTreeMap<String, i64>, live_attempts: &[i64], memory_soft: bool) {
        let now = Instant::now();
        let live: BTreeSet<i64> = live_attempts.iter().copied().collect();
        let ended = self.last_live.difference(&live).next().is_some();        // an attempt ended: reap now
        self.last_live = live.clone();
        let mut todo: Vec<(String, Job)> = Vec::new();
        let mut sh = lock(&self.shared);
        let halted = sh.halted;
        for (k, p) in sh.probes.iter_mut() {
            if !p.busy && p.last_run.is_none_or(|t| now.duration_since(t) >= p.decl.period) {
                p.busy = true;
                todo.push((k.clone(), Job::Probe));
            }
        }
        let sandboxed = crate::sandbox::available();
        for (k, s) in sh.services.iter_mut() {
            if let Some(g) = s.pgid.filter(|g| !group_alive(*g)) {
                s.pgid = None;                                    // the service's processes are gone
                if let Some(r) = &self.registry {
                    r.unregister(g);
                }
            }
            // for as long as it runs, nothing of it may run outside the sandbox: ended at once, a failure of the service
            if let Some((g, e)) = s.pgid.filter(|_| sandboxed).and_then(|g| crate::sandbox::escape(g).map(|e| (g, e))) {
                warn!(service = %k, "sandbox_escape: {e}; ended");
                procs::signal_group(g, procs::Sig::Kill);
                if let Some(r) = &self.registry {
                    r.unregister(g);
                }
                s.pgid = None;
                s.running = false;
                s.ready = false;
                s.failed(k, "sandbox", &format!("sandbox_escape: {e}"));
            }
            s.users = s.decl.users(jobs_need);
            if s.users > 0 {
                s.idle_since = None;
            } else if s.idle_since.is_none() {
                s.idle_since = Some(now);
            }
            if s.busy {
                continue;
            }
            if s.last_fingerprint.is_none_or(|t| now.duration_since(t) >= self.fingerprint_every) {
                s.busy = true;
                todo.push((k.clone(), Job::Fingerprint));
                continue;
            }
            if self.manage && s.running && !s.reaping && !halted
                && (ended || s.last_reap.is_none_or(|t| now.duration_since(t) >= self.reap_every)) {
                s.reaping = true;
                todo.push((k.clone(), Job::Reap(live.clone())));
            }
            if s.health == Health::Undetected {
                continue;
            }
            let may_try = !s.withdrawn && s.next_try.is_none_or(|t| now >= t);
            match want(s, now, memory_soft, halted) {
                Some(true) if !s.running => {
                    if self.manage && may_try {
                        s.busy = true;
                        todo.push((k.clone(), Job::Start));
                    }
                }
                Some(false) if s.running => {
                    if self.manage {
                        s.busy = true;
                        todo.push((k.clone(), Job::Stop(s.pgid)));
                    }
                }
                _ => {
                    // the readiness gate for one already up (adopted, started elsewhere, or not ready in time)
                    let wanted = s.users > 0 || (self.manage && s.decl.lifecycle == Lifecycle::Always);
                    if s.running && !s.ready && !s.disabled && !halted && wanted && may_try {
                        s.busy = true;
                        todo.push((k.clone(), Job::Ready));
                    }
                }
            }
        }
        drop(sh);
        for (k, job) in todo {
            self.spawn(k, job);
        }
    }

    /// Run one job on a worker thread; it writes its outcome back into the shared state.
    fn spawn(&self, key: String, job: Job) {
        let sh = self.shared.clone();
        let exec = {
            let g = lock(&sh);
            let (module, name, kind, exec) = match &job {
                Job::Probe => match g.probes.get(&key) {
                    Some(p) => (p.module.clone(), p.decl.name.clone(), "probe", p.decl.exec.clone()),
                    None => return,
                },
                _ => match g.services.get(&key) {
                    Some(s) => (s.module.clone(), s.decl.name.clone(), "service", s.decl.exec.clone()),
                    None => return,
                },
            };
            self.modules.get(&module).map(|ctx| Exec { ctx: ctx.clone(), name, kind, exec, registry: self.registry.clone() })
        };
        let Some(x) = exec else {
            let mut g = lock(&sh);
            if let Some(p) = g.probes.get_mut(&key) {
                p.busy = false;
            }
            if let Some(s) = g.services.get_mut(&key) {
                s.busy = false;
                s.reaping = false;
            }
            return;
        };
        let (reg, sh2, key2) = (self.registry.clone(), sh.clone(), key.clone());
        let spawned = std::thread::Builder::new().name(format!("svc {key}")).spawn(move || match job {
            Job::Probe => probe_job(&x, &sh, &key),
            Job::Fingerprint => fingerprint_job(&x, &sh, &key),
            Job::Start => start_job(&x, &sh, &key),
            Job::Ready => {
                let timeout = lock(&sh).services.get(&key).map(|s| s.decl.start_timeout).unwrap_or(Duration::from_secs(120));
                wait_ready(&x, &sh, &key, Instant::now() + timeout);
            }
            Job::Stop(pgid) => stop_job(&x, &sh, &key, pgid, reg.as_deref()),
            Job::Reap(live) => reap_job(&x, &sh, &key, &live),
        });
        if spawned.is_err() {
            warn!(service = %key2, "cannot start a service worker thread");
            let mut g = lock(&sh2);
            if let Some(p) = g.probes.get_mut(&key2) {
                p.busy = false;
            }
            if let Some(s) = g.services.get_mut(&key2) {
                s.busy = false;
                s.reaping = false;
            }
        }
    }

    /// Pools available now: each declared pool's tokens from the fingerprints of offered services (healthy, enabled,
    /// not withdrawn; 0 otherwise). An on-demand service need not be running to offer them: a job that needs them
    /// is what starts it, and `ready_for` gates that job's runner.
    pub fn pools(&self) -> BTreeMap<String, i64> {
        let mut out = BTreeMap::new();
        for s in lock(&self.shared).services.values() {
            for p in &s.decl.pools {
                let n = if s.offered() { s.pools.get(p).copied().unwrap_or(0).max(0) } else { 0 };
                *out.entry(p.clone()).or_insert(0) += n;
            }
        }
        out
    }

    /// Capabilities offered services and healthy probes provide.
    pub fn capabilities(&self) -> Vec<String> {
        let sh = lock(&self.shared);
        let mut c: BTreeSet<String> = sh.services.values().filter(|s| s.offered())
            .flat_map(|s| s.decl.capabilities.iter().cloned()).collect();
        c.extend(sh.probes.values().filter(|p| p.health == Health::Healthy).map(|p| p.decl.name.clone()));
        c.into_iter().collect()
    }

    /// The readiness gate: whether every named pool or capability that services provide has an offered service that
    /// is running and has answered `ready`. Names no service provides (probes' capabilities) do not hold it shut.
    pub fn ready_for(&self, needs: &[String]) -> bool {
        let sh = lock(&self.shared);
        needs.iter().all(|n| {
            let mut providers = sh.services.values().filter(|s| s.decl.provides(n)).peekable();
            providers.peek().is_none() || providers.any(|s| s.offered() && s.running && s.ready && s.accepting())
        })
    }

    /// What wakes a waiter when any service changes (the readiness gate waits on it, never on a timer).
    pub fn changed(&self) -> Arc<Changed> {
        lock(&self.shared).changed.clone()
    }

    /// The connectors an attempt of `module` gets: one per endpoint service of the module that provides a pool the
    /// attempt reserves (`requires.pools`; `needs_pools` gives none). Each connect waits up to the service's
    /// `start_timeout_s` for a service that is (re)starting.
    pub fn connectors(&self, module: &str, reserved: &[String], attempt: i64) -> std::io::Result<Vec<Connector>> {
        let wanted: Vec<(String, String, Duration)> = lock(&self.shared).services.iter()
            .filter(|(_, s)| s.module == module && s.decl.endpoint && s.decl.pools.iter().any(|p| reserved.contains(p)))
            .map(|(k, s)| (k.clone(), s.decl.name.clone(), s.decl.start_timeout)).collect();
        let mut out = Vec::new();
        for (key, name, wait) in wanted {
            let (sh, k2) = (self.shared.clone(), key.clone());
            let lookup: endpoints::Lookup = Arc::new(move |limit| channel_for(&sh, &k2, limit));
            out.push(Connector::new(&name, attempt, lookup, wait)?);
        }
        Ok(out)
    }

    /// The services host protection holds down this tick (`module/service` → release reason); every other service is
    /// free again. A held service is stopped and not started while the hold lasts.
    pub fn set_held(&mut self, held: &BTreeMap<String, String>) {
        let changed = {
            let mut sh = lock(&self.shared);
            for (k, s) in sh.services.iter_mut() {
                let h = held.get(k).cloned();
                if h != s.held {
                    if let Some(r) = &h {
                        info!(service = %k, reason = %r, "held down by host protection");
                    }
                    s.held = h;
                }
            }
            sh.changed.clone()
        };
        changed.bump();
    }

    /// Running services as host protection sees them.
    pub fn fleet_view(&self) -> Vec<ServiceView> {
        lock(&self.shared).services.iter().filter(|(_, s)| s.running)
            .map(|(k, s)| ServiceView { key: k.clone(), module: s.module.clone(), pgid: s.pgid, started_at: s.started_at,
                                        gpu: s.decl.gpu, yieldable: s.decl.yieldable, pools: s.decl.pools.clone() }).collect()
    }

    /// The pools GPU services provide, by module (a job reserving one is a GPU job).
    pub fn gpu_pools(&self, module: &str) -> Vec<String> {
        lock(&self.shared).services.values().filter(|s| s.module == module && s.decl.gpu)
            .flat_map(|s| s.decl.pools.iter().cloned()).collect()
    }

    /// For the heartbeat telemetry: the services held down, with why.
    pub fn held(&self) -> BTreeMap<String, String> {
        lock(&self.shared).services.iter().filter_map(|(k, s)| s.held.clone().map(|r| (k.clone(), r))).collect()
    }

    /// Host memory reserved by running services (reserves_host_memory), for capacity.
    pub fn reserved_mem_gb(&self) -> f64 {
        lock(&self.shared).services.values().filter(|s| s.running && s.decl.reserves_host_memory)
            .map(|s| s.reserve_mem_gb.max(0.0)).sum()
    }

    /// For the heartbeat telemetry: ["module/service", ...] running.
    pub fn running(&self) -> Vec<String> {
        lock(&self.shared).services.iter().filter(|(_, s)| s.running).map(|(k, _)| k.clone()).collect()
    }

    /// Every service's and probe's state (what the tests assert on).
    #[cfg(test)]
    pub fn report(&self) -> Value {
        let sh = lock(&self.shared);
        let services: Vec<Value> = sh.services.iter().map(|(k, s)| json!({
            "service": k, "health": s.health.as_str(), "running": s.running, "ready": s.ready, "pools": s.pools,
            "reserve_mem_gb": (s.reserve_mem_gb * 100.0).round() / 100.0, "disabled": s.disabled, "users": s.users,
            "failures": s.failures, "withdrawn": s.withdrawn, "error": s.last_error, "held": s.held, "busy": s.busy,
            "accepting": s.decl.endpoint && s.accepting(),
            "lifecycle": match s.decl.lifecycle { Lifecycle::OnDemand => "on_demand", Lifecycle::Always => "always",
                                                  Lifecycle::Manual => "manual" }})).collect();
        let probes: Vec<Value> = sh.probes.iter().map(|(k, p)| json!({"probe": k, "health": p.health.as_str(), "attrs": p.attrs}))
            .collect();
        drop(sh);
        json!({"services": services, "probes": probes, "capabilities": self.capabilities()})
    }

    /// Stop everything (agent shutdown/drain): waits for ops in flight, then stops every running service the agent
    /// may stop, in parallel, each bounded by its `stop_timeout_s`. Blocks: call it from a blocking context. Nothing
    /// starts again until `resume`. With manage_services off it stops nothing.
    pub fn stop_all(&mut self) {
        let wait = {
            let mut sh = lock(&self.shared);
            sh.halted = true;
            sh.services.values().map(|s| s.decl.start_timeout).max().unwrap_or_default() + Duration::from_secs(10)
        };
        if !self.manage {
            return;
        }
        let deadline = Instant::now() + wait;
        while lock(&self.shared).services.values().any(|s| s.busy) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut handles = Vec::new();
        let todo: Vec<(String, Option<i32>)> = {
            let mut sh = lock(&self.shared);
            sh.services.iter_mut().filter(|(_, s)| s.running && !s.busy && s.decl.lifecycle != Lifecycle::Manual)
                .map(|(k, s)| {
                    s.busy = true;
                    (k.clone(), s.pgid)
                }).collect()
        };
        for (key, pgid) in todo {
            let x = {
                let sh = lock(&self.shared);
                let s = &sh.services[&key];
                self.modules.get(&s.module).map(|ctx| Exec { ctx: ctx.clone(), name: s.decl.name.clone(), kind: "service",
                                                              exec: s.decl.exec.clone(), registry: self.registry.clone() })
            };
            let Some(x) = x else { continue };
            let (sh, reg) = (self.shared.clone(), self.registry.clone());
            handles.push(std::thread::spawn(move || stop_job(&x, &sh, &key, pgid, reg.as_deref())));
        }
        for h in handles {
            let _ = h.join();
        }
    }

    /// Undo `stop_all` (a drain ended): services start again as their lifecycle says.
    pub fn resume(&mut self) {
        lock(&self.shared).halted = false;
    }
}

/// What a service should be (`Some(true)` up, `Some(false)` down, `None` leave it), from its lifecycle, its users and
/// its idle time; idle yieldable services go down under memory pressure and stay down until it ends.
fn want(s: &Svc, now: Instant, memory_soft: bool, halted: bool) -> Option<bool> {
    let d = &s.decl;
    if d.lifecycle == Lifecycle::Manual {
        return None;
    }
    if halted || s.held.is_some() {
        return s.running.then_some(false);                         // down, and not started while it lasts
    }
    if d.endpoint && s.running && s.channel.is_none() {
        return Some(false);                // found running without a channel (an earlier agent's): stopped, then started anew
    }
    let mut w = None;
    if s.disabled {
        if s.running && s.users == 0 {
            w = Some(false);
        }
    } else if d.lifecycle == Lifecycle::Always || s.users > 0 {
        w = Some(true);
    } else if s.running && s.idle_since.is_some_and(|i| now.duration_since(i) >= d.idle_timeout) {
        w = Some(false);
    }
    if memory_soft && s.users == 0 && d.yieldable {
        w = s.running.then_some(false);                          // down, and not started again while it lasts
    }
    w
}

fn with_svc(sh: &SharedRef, key: &str, f: impl FnOnce(&mut Svc)) {
    let changed = {
        let mut g = lock(sh);
        if let Some(s) = g.services.get_mut(key) {
            f(s);
        }
        g.changed.clone()
    };
    changed.bump();
}

fn probe_job(x: &Exec, sh: &SharedRef, key: &str) {
    let r = x.run(&["fingerprint"], FINGERPRINT_TIMEOUT, false);
    let health = if r.ok { Health::parse(r.doc.as_ref().and_then(|d| d["health"].as_str())) } else { Health::Unhealthy };
    if let Some(p) = lock(sh).probes.get_mut(key) {
        if p.health != health && p.health != Health::Unknown {
            info!(probe = key, health = health.as_str(), "probe health changed");
        }
        p.health = health;
        p.attrs = r.doc.as_ref().map(|d| d["attrs"].clone()).unwrap_or(Value::Null);
        p.busy = false;
        let now = Instant::now();
        p.last_run = Some(if r.ok || r.doc.is_some() { now } else {
            now.checked_sub(p.decl.period.saturating_sub(PROBE_RETRY)).unwrap_or(now)
        });
    }
}

/// `fingerprint`, and `status` when the fingerprint does not say whether the service runs (adoption).
fn fingerprint_job(x: &Exec, sh: &SharedRef, key: &str) {
    let fp = x.run(&["fingerprint"], FINGERPRINT_TIMEOUT, false);
    let reported = fp.doc.as_ref().and_then(|d| d["running"].as_bool());
    let status = (fp.ok && reported.is_none()).then(|| x.run(&["status"], STATUS_TIMEOUT, false)).filter(|s| s.ok)
        .and_then(|s| s.doc);
    with_svc(sh, key, |s| {
        s.busy = false;
        s.last_fingerprint = Some(Instant::now());
        let Some(d) = fp.doc.as_ref().filter(|_| fp.ok) else {
            s.health = Health::Unhealthy;
            s.last_error = Some(format!("fingerprint failed: {}", fp.detail));
            return;
        };
        s.health = Health::parse(d["health"].as_str());
        s.pools = d["pools"].as_object().map(|o| o.iter().filter_map(|(k, v)| {
            v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)).map(|n| (k.clone(), n))
        }).collect()).unwrap_or_default();
        s.reserve_mem_gb = d["reserve"]["mem_gb"].as_f64().unwrap_or(0.0);
        let running = reported.or_else(|| status.as_ref().and_then(|st| st["running"].as_bool()));
        if let Some(r) = running {
            if r && !s.running {
                info!(service = key, "adopted a running service");
            }
            s.running = r;
            if !r {
                s.ready = false;
            } else if status.as_ref().and_then(|st| st["ready"].as_bool()) == Some(true) {
                s.ready = true;
            }
        }
        if s.health == Health::Healthy && s.withdrawn && s.next_try.is_none_or(|t| Instant::now() >= t) {
            s.withdrawn = false;
            s.failures = 0;
            info!(service = key, "service healthy again; offered");
        }
    });
}

/// The channel of a service that accepts connections, waiting for one that is (re)starting until `limit`; refused at once
/// when it will not come (gone, disabled, withdrawn, held down, the agent halted).
fn channel_for(sh: &SharedRef, key: &str, limit: Duration) -> Result<Arc<Channel>, Refusal> {
    let changed = lock(sh).changed.clone();
    let mut why = String::new();
    changed.wait_for(Instant::now() + limit, || {
        let g = lock(sh);
        let Some(s) = g.services.get(key) else {
            why = format!("{key} is not in this node's release");
            return Some(None);
        };
        if g.halted || !s.offered() || s.held.is_some() {
            why = format!("{key} is not offered here now");
            return Some(None);
        }
        match &s.channel {
            Some(c) if s.running && s.ready && c.accepting() => Some(Some(c.clone())),
            _ => {
                why = format!("{key} did not come up within its start timeout");
                None
            }
        }
    }).flatten().ok_or_else(|| Refusal::new("service_unavailable", why))
}

/// Whether the job should keep waiting for this service (still wanted, not halted, still configured).
fn still_wanted(sh: &SharedRef, key: &str) -> bool {
    let g = lock(sh);
    !g.halted && g.services.get(key).is_some_and(|s| !s.disabled)
}

/// `start`, then the readiness gate.
fn start_job(x: &Exec, sh: &SharedRef, key: &str) {
    let Some((timeout, stale)) = lock(sh).services.get_mut(key).map(|s| (s.decl.start_timeout, s.pgid.take())) else { return };
    if let Some(g) = stale {
        end_group(g);                                             // left by an earlier start of a service now down
        if let Some(r) = &x.registry {
            r.unregister(g);
        }
    }
    let deadline = Instant::now() + timeout;
    info!(service = key, "starting");
    let endpoint = lock(sh).services.get(key).is_some_and(|s| s.decl.endpoint);
    let channel = if endpoint {
        match new_channel(x, sh, key) {
            Ok(c) => Some(c),
            Err(e) => {
                with_svc(sh, key, |s| {
                    s.busy = false;
                    s.failed(key, "start", &format!("endpoint channel: {e}"));
                });
                return;
            }
        }
    } else {
        None
    };
    let r = x.run_with(&["start"], timeout, true, channel.as_deref());
    if !r.ok {
        if let Some(c) = &channel {
            c.close();
        }
        with_svc(sh, key, |s| {
            s.busy = false;
            s.failed(key, "start", &r.detail);
        });
        return;
    }
    with_svc(sh, key, |s| {
        s.running = true;
        s.ready = false;
        s.pgid = r.pgid;
        s.channel = channel;
        s.started_at = crate::doctor::now();
    });
    wait_ready(x, sh, key, deadline);
}

/// An endpoint service's channel for its next run. If the service closes it first (it died, or exited), that is its
/// failure: whatever is left of its process group is ended and the restart policy applies.
fn new_channel(x: &Exec, sh: &SharedRef, key: &str) -> std::io::Result<Arc<Channel>> {
    let changed = lock(sh).changed.clone();
    let slot: Arc<Mutex<Option<std::sync::Weak<Channel>>>> = Arc::default();
    let (sh2, key2, slot2, reg) = (sh.clone(), key.to_string(), slot.clone(), x.registry.clone());
    let lost = Box::new(move || {
        let Some(me) = lock(&slot2).as_ref().and_then(|w| w.upgrade()) else { return };
        let mut ended = None;
        with_svc(&sh2, &key2, |s| {
            if !s.channel.as_ref().is_some_and(|c| Arc::ptr_eq(c, &me)) {
                return;                                           // not this run's (it is stopping, or already gone)
            }
            s.channel = None;
            s.running = false;
            s.ready = false;
            ended = s.pgid.take();
            s.failed(&key2, "endpoint", "the service closed its endpoint channel");
        });
        if let Some(g) = ended {
            end_group(g);
            if let Some(r) = reg {
                r.unregister(g);
            }
        }
    });
    let ch = Channel::new(key, changed, lost)?;
    *lock(&slot) = Some(Arc::downgrade(&ch));
    Ok(ch)
}

/// Poll `ready` until it answers true or the deadline passes (a failure, with backoff).
fn wait_ready(x: &Exec, sh: &SharedRef, key: &str, deadline: Instant) {
    loop {
        let q = x.run(&["ready"], STATUS_TIMEOUT, false);
        if q.ok && q.doc.as_ref().and_then(|d| d["ready"].as_bool()) == Some(true) {
            with_svc(sh, key, |s| {
                s.busy = false;
                s.ready = true;
                s.failures = 0;
                s.last_error = None;
                s.last_fingerprint = None;                         // re-fingerprint: pools and reserve while running
            });
            info!(service = key, "ready");
            return;
        }
        if !still_wanted(sh, key) {
            with_svc(sh, key, |s| {
                s.busy = false;
                s.last_fingerprint = None;
            });
            return;
        }
        let now = Instant::now();
        if now >= deadline {
            with_svc(sh, key, |s| {
                s.busy = false;
                s.failed(key, "ready", "not ready in time");
            });
            return;
        }
        std::thread::sleep(READY_POLL.min(deadline - now));
    }
}

/// `stop`, then end whatever the service left in its process group.
fn stop_job(x: &Exec, sh: &SharedRef, key: &str, pgid: Option<i32>, reg: Option<&SpawnRegistry>) {
    let Some(timeout) = lock(sh).services.get(key).map(|s| s.decl.stop_timeout) else { return };
    info!(service = key, "stopping");
    let r = x.run(&["stop"], timeout, false);
    if r.ok {
        let channel = lock(sh).services.get_mut(key).and_then(|s| s.channel.take());
        if let Some(c) = channel {
            c.close();                                            // the service exits on the end of its channel
        }
        if let Some(g) = pgid {
            end_group(g);
            if let Some(reg) = reg {
                reg.unregister(g);
            }
        }
    }
    with_svc(sh, key, |s| {
        s.busy = false;
        if r.ok {
            s.running = false;
            s.ready = false;
            s.failures = 0;
            s.last_error = None;
            s.idle_since = None;
            if s.pgid == pgid {
                s.pgid = None;
            }
            s.last_fingerprint = None;
        } else {
            s.failed(key, "stop", &r.detail);
        }
    });
}

/// Label-scoped reaping: destroy the objects a service lists as owned whose attempt is no longer live. Objects
/// without the `oarbank.attempt_id` label, or labelled for another node, are never touched.
fn reap_job(x: &Exec, sh: &SharedRef, key: &str, live: &BTreeSet<i64>) {
    let r = x.run(&["list_owned"], LIST_TIMEOUT, false);
    let objs = r.doc.as_ref().filter(|_| r.ok).and_then(|d| d["objects"].as_array().cloned()).unwrap_or_default();
    for o in objs {
        let Some(id) = o["id"].as_str() else { continue };
        let labels = &o["labels"];
        let aid = match &labels["oarbank.attempt_id"] {
            Value::String(s) => s.trim().parse::<i64>().ok(),
            v => v.as_i64(),
        };
        let Some(aid) = aid else { continue };
        if live.contains(&aid) || labels["oarbank.node"].as_str().is_some_and(|n| !x.ctx.node_id.is_empty() && n != x.ctx.node_id) {
            continue;
        }
        let d = x.run(&["destroy", id, "--force"], DESTROY_TIMEOUT, false);
        if d.ok {
            info!(service = key, object = id, attempt = aid, "reaped an object of an attempt that no longer exists");
        } else {
            warn!(service = key, object = id, detail = %d.detail, "destroy failed");
        }
    }
    with_svc(sh, key, |s| {
        s.reaping = false;
        s.last_reap = Some(Instant::now());
    });
}

/// Unit tests run their sandboxed children through this test binary (`launch_argv` names the current executable):
/// answer the launcher's `sandbox-exec` the way the agent's `main` does, before the test harness starts.
#[cfg(all(test, target_os = "macos"))]
#[used]
#[link_section = "__DATA,__mod_init_func"]
static SANDBOX_LAUNCHER_FOR_TESTS: extern "C" fn() = {
    extern "C" fn launcher() {
        let raw: Vec<String> = std::env::args().collect();
        if raw.get(1).map(String::as_str) == Some("sandbox-exec") {
            crate::seatbelt::exec(&raw[2..]);
        }
    }
    launcher
};

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::path::Path;

    /// A fake release with one module, `mod`, whose bundle holds the fixture service and probe.
    struct Fx {
        root: PathBuf,
        release: Release,
    }

    impl Fx {
        fn new(tag: &str, services: Value, probes: Value) -> Fx {
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
            let root = std::env::temp_dir().join(format!("oarbank-svc-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&root).unwrap();
            let root = std::fs::canonicalize(&root).unwrap();
            let dir = root.join("releases/r_test");
            let bundle = dir.join("modules/mod");
            std::fs::create_dir_all(&bundle).unwrap();
            let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/services");
            for f in ["svc.sh", "probe.sh"] {
                std::fs::copy(fixtures.join(f), bundle.join(f)).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(bundle.join(f), std::fs::Permissions::from_mode(0o755)).unwrap();
                }
            }
            let entry = json!({"name": "mod", "module_id": "dev.test.mod", "bundle": "modules/mod", "services": services,
                               "probes": probes, "sandbox": {"contract": 1, "net": {"mode": "none"}, "tools": [],
                                                            "devices": {"gpu": "none"}, "exec_writable": false}});
            let release = Release { id: "r_test".into(), dir, modules: vec![entry] };
            Fx { root, release }
        }

        fn layout(&self) -> Layout {
            let l = Layout::new(self.root.join("home"));
            l.ensure().unwrap();
            l
        }

        fn manager(&self, policy: Value, manage: bool) -> ServiceManager {
            let rt = Runtime { python: PathBuf::from("/usr/bin/python3"), uv: None, site_dirs: vec![], roots: vec![], host_provided: None };
            let mut m = ServiceManager::new(self.layout(), rt, None, manage);
            m.fingerprint_every = Duration::from_millis(300);
            m.configure(&self.release, &policy, Some("node-1"));
            m
        }

        fn data(&self) -> PathBuf {
            self.root.join("home/modules-data/mod")
        }

        fn file(&self, name: &str) -> String {
            std::fs::read_to_string(self.data().join(name)).unwrap_or_default()
        }

        fn calls(&self, svc: &str, op: &str) -> usize {
            self.file(&format!("{svc}.calls")).lines().filter(|l| *l == op).count()
        }

        fn touch(&self, name: &str, text: &str) {
            std::fs::create_dir_all(self.data()).unwrap();
            std::fs::write(self.data().join(name), text).unwrap();
        }
    }

    impl Drop for Fx {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn need(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    /// Tick every 100 ms until `cond` holds; false after `secs`.
    fn tick_until(m: &mut ServiceManager, n: &BTreeMap<String, i64>, live: &[i64], soft: bool, secs: f64,
                  mut cond: impl FnMut(&ServiceManager) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs_f64(secs);
        while Instant::now() < deadline {
            m.tick(n, live, soft);
            if cond(m) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn tick_for(m: &mut ServiceManager, n: &BTreeMap<String, i64>, live: &[i64], soft: bool, secs: f64) {
        tick_until(m, n, live, soft, secs, |_| false);
    }

    fn svc(name: &str, extra: Value) -> Value {
        let mut v = json!({"name": name, "exec": ["{bundle}/svc.sh"], "lifecycle": "on_demand", "idle_timeout_s": 1,
                           "start_timeout_s": 20, "stop_timeout_s": 10,
                           "provides": {"pools": ["vmpool"], "capabilities": ["amd64"]}, "reserves_host_memory": true});
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    }

    /// Every service fingerprinted healthy (a first op can be slow on a loaded machine: wait for it, not one try).
    fn fingerprinted(m: &ServiceManager) -> bool {
        lock(&m.shared).services.values().all(|s| s.health == Health::Healthy && !s.busy)
    }

    fn pid_alive(pid: i32) -> bool {
        crate::sys::alive(pid)
    }

    #[test]
    fn on_demand_starts_gated_on_ready_refcounted_and_stops_when_idle() {
        let fx = Fx::new("ondemand", json!([svc("vm", json!({}))]), json!([]));
        let mut m = fx.manager(json!({"module_settings": {"mod": {"vm_mem_gb": 12}}}), true);
        assert!(tick_until(&mut m, &need(&[]), &[], false, 20.0, fingerprinted));
        assert_eq!(m.pools(), need(&[("vmpool", 4)]), "{}", m.report());   // offered before it runs: demand starts it
        assert!(m.capabilities().contains(&"amd64".to_string()));
        assert!(m.running().is_empty());
        assert_eq!(m.reserved_mem_gb(), 0.0);
        assert_eq!(fx.calls("vm", "start"), 0);
        m.set_limits(&json!({"vm_mem_gb": 8}));

        // a job needs the pool: start, then the gate stays shut until `ready` says so
        let one = need(&[("vmpool", 1)]);
        let mut saw_gate_shut = false;
        let up = tick_until(&mut m, &one, &[], false, 25.0, |m| {
            let open = m.ready_for(&["vmpool".to_string()]);
            if open {
                assert!(fx.data().join("vm.ready").exists(), "the gate opened before the service was ready");
            } else if m.running() == ["mod/vm"] {
                saw_gate_shut = true;
            }
            open
        });
        assert!(up && saw_gate_shut);
        assert_eq!(fx.calls("vm", "start"), 1);
        assert!(tick_until(&mut m, &one, &[], false, 20.0, |m| m.reserved_mem_gb() == 8.0));
        let env = fx.file("vm.env");
        assert!(env.contains("service=vm") && env.contains("node=node-1") && env.contains("module=mod"), "{env}");
        assert!(env.contains(&format!("cwd={}", fx.release.dir.join("modules/mod").display())), "{env}");
        assert!(env.contains(r#"settings={"vm_mem_gb":12}"#) && env.contains(r#"limits={"vm_mem_gb":8}"#), "{env}");

        // more users, then fewer: still one start, still running
        tick_for(&mut m, &need(&[("vmpool", 2)]), &[], false, 1.5);
        tick_for(&mut m, &one, &[], false, 1.5);
        assert_eq!(m.running(), ["mod/vm"]);
        assert_eq!(fx.calls("vm", "start"), 1);
        assert_eq!(fx.calls("vm", "stop"), 0);

        // no users: stopped after the idle timeout, its process group ended
        let daemon: i32 = fx.file("vm.pid").trim().parse().unwrap();
        assert!(tick_until(&mut m, &need(&[]), &[], false, 20.0, |m| m.running().is_empty()));
        assert_eq!(fx.calls("vm", "stop"), 1);
        assert!(!m.ready_for(&["vmpool".to_string()]));
        let deadline = Instant::now() + Duration::from_secs(5);
        while pid_alive(daemon) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!pid_alive(daemon));
        assert_eq!(m.reserved_mem_gb(), 0.0);
    }

    #[test]
    fn probes_run_on_their_period_and_provide_capabilities() {
        let fx = Fx::new("probe", json!([]), json!([{"name": "java17", "exec": ["{bundle}/probe.sh"], "period_s": 1}]));
        let mut m = fx.manager(json!({}), true);
        assert!(tick_until(&mut m, &need(&[]), &[], false, 20.0, |m| m.capabilities() == ["java17"]));
        let t0 = Instant::now();
        let first = fx.file("java17.calls").lines().count();
        tick_for(&mut m, &need(&[]), &[], false, 3.2);
        let runs = fx.file("java17.calls").lines().count() - first;
        assert!((1..=5).contains(&runs), "{runs} runs in {:?}", t0.elapsed());   // every 1 s, not every tick
        assert_eq!(m.report()["probes"][0]["attrs"]["version"], "17");
        fx.touch("java17.health", "unhealthy");
        assert!(tick_until(&mut m, &need(&[]), &[], false, 5.0, |m| m.capabilities().is_empty()));

        // a long period: run once, then again only when a doctor-triggering event asks
        let fx = Fx::new("probe-event", json!([]), json!([{"name": "java17", "exec": ["{bundle}/probe.sh"], "period_s": 3600}]));
        let mut m = fx.manager(json!({}), true);
        assert!(tick_until(&mut m, &need(&[]), &[], false, 20.0, |m| m.capabilities() == ["java17"]));
        tick_for(&mut m, &need(&[]), &[], false, 1.0);
        assert_eq!(fx.file("java17.calls").lines().count(), 1);
        m.refresh_now();
        assert!(tick_until(&mut m, &need(&[]), &[], false, 5.0, |_| fx.file("java17.calls").lines().count() == 2));
    }

    #[test]
    fn failures_back_off_then_withdraw_the_service() {
        let fx = Fx::new("backoff", json!([svc("vm", json!({
            "restart": {"backoff_initial_s": 0.2, "backoff_max_s": 0.4, "max_failures": 3}}))]), json!([]));
        fx.touch("vm.fail_start", "");
        let mut m = fx.manager(json!({}), true);
        m.fingerprint_every = Duration::from_secs(600);         // only the first fingerprint: no healthy re-offer
        let one = need(&[("vmpool", 1)]);
        let t0 = Instant::now();
        assert!(tick_until(&mut m, &one, &[], false, 20.0, |m| lock(&m.shared).services["mod/vm"].withdrawn));
        assert!(t0.elapsed() >= Duration::from_millis(600));   // 0.2 s, then 0.4 s between the three tries
        tick_for(&mut m, &one, &[], false, 1.5);
        assert_eq!(fx.calls("vm", "start"), 3);
        assert_eq!(m.pools(), need(&[("vmpool", 0)]));
        assert!(!m.capabilities().contains(&"amd64".to_string()));
        assert!(m.running().is_empty());
        let r = m.report();
        assert_eq!(r["services"][0]["failures"], 3);
        assert!(r["services"][0]["error"].as_str().unwrap().contains("start refused"), "{r}");
    }

    #[test]
    fn a_running_service_is_adopted_after_a_restart() {
        let fx = Fx::new("adopt", json!([svc("vm", json!({}))]), json!([]));
        let one = need(&[("vmpool", 1)]);
        {
            let mut m1 = fx.manager(json!({}), true);
            assert!(tick_until(&mut m1, &one, &[], false, 25.0, |m| m.ready_for(&["vmpool".to_string()])));
        }                                                         // the agent exits without stopping it
        assert_eq!(fx.calls("vm", "start"), 1);
        fx.touch("vm.no_running", "");                           // fingerprint is silent: `status` answers
        let mut m2 = fx.manager(json!({}), true);
        assert!(tick_until(&mut m2, &need(&[]), &[], false, 20.0, |m| m.running() == ["mod/vm"]));
        assert!(fx.calls("vm", "status") >= 1);
        assert!(tick_until(&mut m2, &one, &[], false, 20.0, |m| m.ready_for(&["vmpool".to_string()])));
        assert_eq!(fx.calls("vm", "start"), 1);                  // never a second one
        let daemon: i32 = fx.file("vm.pid").trim().parse().unwrap();
        m2.stop_all();
        assert!(m2.running().is_empty());
        assert_eq!(fx.calls("vm", "stop"), 1);
        assert!(!fx.data().join("vm.up").exists());
        let deadline = Instant::now() + Duration::from_secs(5);
        while pid_alive(daemon) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!pid_alive(daemon));
        // halted: nothing starts until resume
        tick_for(&mut m2, &one, &[], false, 1.0);
        assert_eq!(fx.calls("vm", "start"), 1);
        m2.resume();
        assert!(tick_until(&mut m2, &one, &[], false, 25.0, |m| m.ready_for(&["vmpool".to_string()])));
        m2.stop_all();
    }

    #[test]
    fn objects_of_dead_attempts_are_reaped_by_label() {
        let fx = Fx::new("reap", json!([svc("vm", json!({"lifecycle": "always"}))]), json!([]));
        fx.touch("vm.owned", &json!({"objects": [
            {"id": "c1", "labels": {"oarbank.attempt_id": "7", "oarbank.node": "node-1", "oarbank.service": "vm"}},
            {"id": "c2", "labels": {"oarbank.attempt_id": "8", "oarbank.node": "node-1", "oarbank.service": "vm"}},
            {"id": "c3", "labels": {}},
            {"id": "c4", "labels": {"oarbank.attempt_id": "9", "oarbank.node": "node-2", "oarbank.service": "vm"}}]})
            .to_string());
        let mut m = fx.manager(json!({}), true);
        m.reap_every = Duration::from_millis(500);
        assert!(tick_until(&mut m, &need(&[]), &[8], false, 25.0, |_| fx.file("vm.destroyed").contains("c1")));
        tick_for(&mut m, &need(&[]), &[8], false, 1.5);
        let destroyed = fx.file("vm.destroyed");
        assert!(destroyed.lines().all(|l| l == "c1"), "{destroyed}");  // never the live, unlabelled or foreign ones
        assert!(fx.calls("vm", "destroy c1 --force") >= 1);
        m.stop_all();
    }

    #[test]
    fn disabled_services_are_neither_offered_nor_started_and_are_stopped() {
        let fx = Fx::new("disabled", json!([svc("vm", json!({}))]), json!([]));
        let off = json!({"disabled_services": ["mod/vm"]});
        let mut m = fx.manager(off.clone(), true);
        let one = need(&[("vmpool", 1)]);
        tick_for(&mut m, &one, &[], false, 2.0);
        assert_eq!(fx.calls("vm", "start"), 0);
        assert_eq!(m.pools(), need(&[("vmpool", 0)]));
        assert!(!m.capabilities().contains(&"amd64".to_string()));

        m.configure(&fx.release, &json!({}), None);
        assert!(tick_until(&mut m, &one, &[], false, 25.0, |m| m.ready_for(&["vmpool".to_string()])));
        m.configure(&fx.release, &off, None);                    // disabled while running and idle: stopped
        assert!(tick_until(&mut m, &need(&[]), &[], false, 20.0, |m| m.running().is_empty()));
        assert_eq!(fx.calls("vm", "stop"), 1);
    }

    #[test]
    fn an_op_that_finishes_during_a_reconfigure_is_kept() {
        // configure replaces the service table while ops run on their threads; an op's outcome written meanwhile must
        // land in the table that stays (it once went to a table being rebuilt, and the service stayed busy for good:
        // never started or stopped again)
        let fx = Fx::new("reconfigure", json!([svc("vm", json!({}))]), json!([]));
        let mut m = fx.manager(json!({}), true);
        let busy = |m: &ServiceManager| lock(&m.shared).services["mod/vm"].busy;
        for round in 0..5 {
            m.refresh_now();
            m.tick(&need(&[]), &[], false);                       // a fingerprint op on its way
            assert!(busy(&m));
            let deadline = Instant::now() + Duration::from_secs(20);
            while busy(&m) && Instant::now() < deadline {
                m.configure(&fx.release, &json!({}), None);
            }
            assert!(!busy(&m), "round {round}: the fingerprint's outcome was lost: {}", m.report());
            assert_eq!(m.report()["services"][0]["health"], "healthy");
        }
    }

    #[test]
    fn with_manage_services_off_nothing_starts_or_stops() {
        let fx = Fx::new("unmanaged", json!([svc("vm", json!({"lifecycle": "always"}))]),
                         json!([{"name": "java17", "exec": ["{bundle}/probe.sh"], "period_s": 1}]));
        let mut m = fx.manager(json!({}), false);
        assert!(tick_until(&mut m, &need(&[("vmpool", 1)]), &[], false, 20.0,
                           |m| fingerprinted(m) && m.capabilities().contains(&"java17".to_string())));
        tick_for(&mut m, &need(&[("vmpool", 1)]), &[], false, 1.5);
        assert_eq!(fx.calls("vm", "start"), 0);
        assert_eq!(m.pools(), need(&[("vmpool", 4)]), "{}", m.report()); // fingerprints are read-only: still offered

        fx.touch("vm.up", "");                                    // started by someone else
        assert!(tick_until(&mut m, &need(&[]), &[], true, 20.0, |m| m.running() == ["mod/vm"]));
        tick_for(&mut m, &need(&[]), &[], true, 1.0);
        m.stop_all();
        assert_eq!(fx.calls("vm", "stop"), 0);
        assert_eq!(m.running(), ["mod/vm"]);
    }

    #[test]
    fn idle_yieldable_services_stop_under_memory_pressure() {
        let fx = Fx::new("yield", json!([svc("vm", json!({"lifecycle": "always"})),
                                         svc("db", json!({"lifecycle": "always", "yieldable": false,
                                                          "provides": {"pools": [], "capabilities": []}}))]), json!([]));
        let mut m = fx.manager(json!({}), true);
        let both = |m: &ServiceManager| m.running() == ["mod/db", "mod/vm"] && m.ready_for(&["vmpool".to_string()]);
        assert!(tick_until(&mut m, &need(&[]), &[], false, 25.0, both));
        assert!(tick_until(&mut m, &need(&[]), &[], true, 20.0, |m| m.running() == ["mod/db"]));
        tick_for(&mut m, &need(&[]), &[], true, 4.0);            // and it stays down while the pressure lasts
        assert_eq!(m.running(), ["mod/db"]);
        assert_eq!(fx.calls("vm", "start"), 1);
        assert_eq!(fx.calls("vm", "stop"), 1);
        assert_eq!(fx.calls("db", "stop"), 0);
        // a user keeps a yieldable service up under pressure
        assert!(tick_until(&mut m, &need(&[("vmpool", 1)]), &[], true, 25.0, both));
        assert_eq!(fx.calls("vm", "start"), 2);
        m.stop_all();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn services_and_their_processes_run_sandboxed() {
        let fx = Fx::new("sandbox", json!([svc("vm", json!({"lifecycle": "always"}))]), json!([]));
        let mut m = fx.manager(json!({}), true);
        assert!(tick_until(&mut m, &need(&[]), &[], false, 25.0, |m| m.ready_for(&["vmpool".to_string()])));
        let daemon: u32 = fx.file("vm.pid").trim().parse().unwrap();
        assert!(crate::seatbelt::is_sandboxed(daemon));
        // the sandbox holds: the service could not write into its (read-only) bundle
        assert!(fx.file("vm.escape").contains("denied"), "{}", fx.file("vm.escape"));
        assert!(!fx.release.dir.join("modules/mod/escaped").exists());
        m.stop_all();
    }
}
