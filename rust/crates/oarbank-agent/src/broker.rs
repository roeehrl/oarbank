//! The per-attempt container broker (spec/sandbox.md, "Containers: the agent's broker"; the SDK's `broker` module is
//! the client). A job whose module is approved for containers gets a unix socket, `OARBANK_BROKER=unix:/path`, the
//! only IPC its sandbox allows. One JSON request per connection, one JSON answer line. Ops: `container.run`,
//! `container.pull`, `status`. Every run is validated against the module's approved images, its directories and its
//! reservation, runs on the agent's own runtime with a fixed argument shape, and dies with the attempt.

use crate::container_runtime::{image_key, ContainerRuntime, Mount, RunResult, RunSpec};
use serde_json::{json, Value};
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, FileExt, PermissionsExt};
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{info, warn};

pub const MIN_CPUS: f64 = 0.1;
pub const MIN_MEM_GB: f64 = 0.25;
pub const DEFAULT_TIMEOUT_S: f64 = 3600.0;
const TAIL_BYTES: usize = 4096;
const MAX_REQUEST: usize = 1 << 20;
/// macOS `sun_path` holds 104 bytes with the NUL.
const MAX_SOCKET_PATH: usize = 103;

/// What one attempt's broker may do: the module's approved images, its directories and its reservation.
#[derive(Debug, Clone)]
pub struct BrokerGrant {
    pub attempt_id: i64,
    pub module: String,
    /// (image reference with an `@sha256:` digest, OCI platform such as `linux/amd64`).
    pub approved_images: Vec<(String, String)>,
    pub workdir: PathBuf,
    pub module_data: PathBuf,
    pub network_granted: bool,
    /// The attempt's reservation: every container is clamped to it.
    pub cpus: f64,
    pub mem_gb: f64,
}

/// A refused request: `{ok: false, error, detail}`.
#[derive(Debug, Clone, PartialEq)]
pub struct Refusal {
    pub code: String,
    pub detail: String,
}

impl Refusal {
    pub fn new(code: &str, detail: impl Into<String>) -> Self {
        Refusal { code: code.into(), detail: detail.into() }
    }
    fn bad_request(d: impl Into<String>) -> Self {
        Self::new("bad_request", d)
    }
    fn bad_mount(d: impl Into<String>) -> Self {
        Self::new("bad_mount", d)
    }
    pub fn json(&self) -> Value {
        json!({"ok": false, "error": self.code, "detail": self.detail})
    }
}

/// The grant with its two directories resolved once (realpath), which every mount must stay inside.
#[derive(Debug, Clone)]
pub struct Scope {
    pub grant: BrokerGrant,
    pub work: PathBuf,
    pub data: PathBuf,
}

impl Scope {
    pub fn new(grant: BrokerGrant) -> std::io::Result<Scope> {
        std::fs::create_dir_all(&grant.module_data)?;
        let work = std::fs::canonicalize(&grant.workdir)?;
        let data = std::fs::canonicalize(&grant.module_data)?;
        Ok(Scope { grant, work, data })
    }
}

// MARK: validation

fn opt_str(v: &Value, name: &str) -> Result<Option<String>, Refusal> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) if !s.contains('\0') => Ok(Some(s.clone())),
        _ => Err(Refusal::bad_request(format!("{name} must be a string"))),
    }
}

fn opt_num(v: &Value, name: &str) -> Result<Option<f64>, Refusal> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => n.as_f64().filter(|d| d.is_finite()).map(Some).ok_or_else(|| Refusal::bad_request(format!("{name} must be a number"))),
        _ => Err(Refusal::bad_request(format!("{name} must be a number"))),
    }
}

fn opt_bool(v: &Value, name: &str, code: &str) -> Result<bool, Refusal> {
    match v {
        Value::Null => Ok(false),
        Value::Bool(b) => Ok(*b),
        _ => Err(Refusal::new(code, format!("{name} must be true or false"))),
    }
}

/// `^[A-Za-z_][A-Za-z0-9_]*$`
pub fn is_env_key(k: &str) -> bool {
    let mut b = k.bytes();
    matches!(b.next(), Some(c) if c == b'_' || c.is_ascii_alphabetic()) && b.all(|c| c == b'_' || c.is_ascii_alphanumeric())
}

/// The image must exactly equal an approved entry's reference, and the platform that entry's platform.
pub fn approved(image: Option<&str>, platform: Option<&str>, g: &BrokerGrant) -> Result<(), Refusal> {
    let image = image.filter(|i| !i.is_empty()).ok_or_else(|| Refusal::bad_request("image is required"))?;
    let platforms: Vec<&str> = g.approved_images.iter().filter(|(i, _)| i == image).map(|(_, p)| p.as_str()).collect();
    if platforms.is_empty() {
        return Err(Refusal::new("image_not_approved", format!("{image} is not an approved image of this module")));
    }
    match platform {
        Some(p) if platforms.contains(&p) => Ok(()),
        p => Err(Refusal::new("image_not_approved",
                              format!("{image} is approved for {}, not {}", platforms.join(", "), p.unwrap_or("(none)")))),
    }
}

/// An absolute POSIX path inside the container, without `..`, `:`, newline or NUL.
fn container_path(p: &str, what: &str) -> Result<String, Refusal> {
    if !p.starts_with('/') || p.contains(['\0', ':', '\n']) || p.split('/').any(|s| s == "..") {
        return Err(Refusal::bad_mount(format!("{what} must be an absolute path without '..' or ':', got {p:?}")));
    }
    Ok(p.to_string())
}

/// `base/rel` with every existing component resolved (symlinks followed) and the missing tail appended as is: the
/// path the mount would really name.
fn resolve_existing(base: &Path, rel: &str) -> Result<PathBuf, String> {
    let full = if rel == "." { base.to_path_buf() } else { base.join(rel) };
    for anc in full.ancestors() {
        if std::fs::symlink_metadata(anc).is_ok() {
            let real = std::fs::canonicalize(anc).map_err(|e| format!("{}: {e}", anc.display()))?;
            let rest = full.strip_prefix(anc).map_err(|e| e.to_string())?;
            return Ok(if rest.as_os_str().is_empty() { real } else { real.join(rest) });
        }
    }
    Err("nothing of the path exists".into())
}

/// `src` is a PortablePath inside the work directory (`.` for all of it), or `data:<path>` inside the module-data
/// directory. Resolved without letting a symlink lead out of that directory; a missing directory is created.
pub fn resolve_mount_source(src: &str, s: &Scope) -> Result<PathBuf, Refusal> {
    let (rel, base, what) = match src.strip_prefix("data:") {
        Some(r) => (r, &s.data, "data"),
        None => (src, &s.work, "work"),
    };
    if rel != "." {
        oarbank_core::portable::check_portable_path(rel, true).map_err(|e| Refusal::bad_mount(
            format!("mount source must be a relative PortablePath inside the work directory, or data:<path> ({})", e.0)))?;
    }
    let outside = || Refusal::bad_mount(format!("mount source {src:?} resolves outside the {what} directory"));
    let resolved = resolve_existing(base, rel).map_err(|_| outside())?;
    if !resolved.starts_with(base) {
        return Err(outside());
    }
    let text = resolved.to_str().ok_or_else(|| Refusal::bad_mount(format!("mount source {src:?} is not UTF-8")))?;
    if text.contains([':', ',', '\n', '\0']) {
        return Err(Refusal::bad_mount(format!("mount source {src:?} has an unusable character")));
    }
    match std::fs::symlink_metadata(&resolved) {
        Ok(m) if m.is_dir() || m.is_file() => {}
        Ok(m) if m.file_type().is_socket() => return Err(Refusal::bad_mount(format!("mount source {src:?} is a socket"))),
        Ok(_) => return Err(Refusal::bad_mount(format!("mount source {src:?} is not a file or directory"))),
        Err(_) => {
            std::fs::create_dir_all(&resolved)
                .map_err(|_| Refusal::bad_mount(format!("mount source {src:?} does not exist and cannot be created")))?;
            // a symlink planted while the directories were created would show here
            if std::fs::canonicalize(&resolved).ok().as_deref() != Some(resolved.as_path()) {
                return Err(outside());
            }
        }
    }
    Ok(resolved)
}

/// Validate a `container.run` request into the exact run (output files not yet attached).
pub fn plan(req: &Value, s: &Scope) -> Result<RunSpec, Refusal> {
    let g = &s.grant;
    if !req.is_object() {
        return Err(Refusal::bad_request("request must be a JSON object"));
    }
    let image = opt_str(&req["image"], "image")?;
    let platform = opt_str(&req["platform"], "platform")?;
    approved(image.as_deref(), platform.as_deref(), g)?;
    let mut args = Vec::new();
    match &req["args"] {
        Value::Null => {}
        Value::Array(a) => {
            for x in a {
                match x {
                    Value::String(v) if !v.contains('\0') => args.push(v.clone()),
                    _ => return Err(Refusal::bad_request("args must be a list of strings")),
                }
            }
        }
        _ => return Err(Refusal::bad_request("args must be a list of strings")),
    }
    let network = opt_bool(&req["network"], "network", "bad_request")?;
    if network && !g.network_granted {
        return Err(Refusal::new("network_not_granted", "this module is not approved for network egress"));
    }
    let mut mounts = Vec::new();
    match &req["mounts"] {
        Value::Null => {}
        Value::Array(a) => {
            for m in a {
                let (Some(src), Some(dst)) = (m["src"].as_str(), m["dst"].as_str()) else {
                    return Err(Refusal::bad_mount("each mount needs string src and dst"));
                };
                let ro = opt_bool(&m["ro"], "mount ro", "bad_mount")?;
                let host = resolve_mount_source(src, s)?;
                mounts.push(Mount { host, dst: container_path(dst, "mount dst")?, ro });
            }
        }
        _ => return Err(Refusal::bad_request("mounts must be a list of {src, dst, ro}")),
    }
    let mut env = Vec::new();
    match &req["env"] {
        Value::Null => {}
        Value::Object(o) => {
            for (k, v) in o {
                if !is_env_key(k) {
                    return Err(Refusal::bad_request(format!("env key {k:?} is not ^[A-Za-z_][A-Za-z0-9_]*$")));
                }
                match v {
                    Value::String(v) if !v.contains('\0') => env.push((k.clone(), v.clone())),
                    _ => return Err(Refusal::bad_request(format!("env {k} must be a string"))),
                }
            }
            env.sort();
        }
        _ => return Err(Refusal::bad_request("env must be an object of strings")),
    }
    let workdir = opt_str(&req["workdir"], "workdir")?.map(|w| container_path(&w, "workdir")).transpose()?;
    let entrypoint = opt_str(&req["entrypoint"], "entrypoint")?;
    if entrypoint.as_deref() == Some("") {
        return Err(Refusal::bad_request("entrypoint must not be empty"));
    }
    let (max_cpus, max_mem) = (g.cpus.max(MIN_CPUS), g.mem_gb.max(MIN_MEM_GB));
    let cpus = opt_num(&req["cpus"], "cpus")?.unwrap_or(max_cpus).clamp(MIN_CPUS, max_cpus);
    let mem_gb = opt_num(&req["mem_gb"], "mem_gb")?.unwrap_or(max_mem).clamp(MIN_MEM_GB, max_mem);
    let timeout = opt_num(&req["timeout_s"], "timeout_s")?.filter(|t| *t > 0.0).unwrap_or(DEFAULT_TIMEOUT_S);
    Ok(RunSpec {
        image: image.unwrap_or_default(), platform: platform.unwrap_or_default(), args, entrypoint, mounts, env, workdir, network,
        cpus, mem_gb, attempt_id: g.attempt_id, module: g.module.clone(), timeout_s: timeout.max(1.0), stdout: None, stderr: None,
    })
}

// MARK: the broker

struct Shared {
    scope: Scope,
    runtime: Arc<dyn ContainerRuntime>,
    /// Set when the attempt ends: refuses new requests and cancels the running container.
    closed: AtomicBool,
    inflight: AtomicUsize,
    counter: AtomicU64,
    /// A container was started at least once (only then is there anything to remove).
    ran: AtomicBool,
    /// One run at a time: each is clamped to the attempt's whole reservation, so concurrent runs would oversubscribe
    /// it (and a timed-out run is then the only container to remove).
    gate: tokio::sync::Mutex<()>,
}

struct Inflight<'a>(&'a Shared);

impl<'a> Inflight<'a> {
    fn new(s: &'a Shared) -> Self {
        s.inflight.fetch_add(1, Ordering::SeqCst);
        Inflight(s)
    }
}

impl Drop for Inflight<'_> {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

fn cancelled() -> Value {
    Refusal::new("cancelled", "the attempt has ended").json()
}

async fn blocking<T: Send + 'static>(sh: &Arc<Shared>, f: impl FnOnce(&Shared) -> T + Send + 'static) -> Result<T, Refusal> {
    let s = sh.clone();
    tokio::task::spawn_blocking(move || f(&s)).await.map_err(|e| Refusal::new("runtime_unavailable", e.to_string()))
}

/// The runtime is running (started on demand) and can run `platform`.
async fn ready(sh: &Arc<Shared>, platform: &str) -> Result<(), Refusal> {
    let unavailable = |d: String| Refusal::new("runtime_unavailable", format!("the agent's container runtime is not available: {d}"));
    let st = blocking(sh, |s| s.runtime.status()).await?.map_err(unavailable)?;
    if !st.platforms.iter().any(|p| p == platform) {
        return Err(Refusal::new("platform_unavailable",
                                format!("this node's container runtime runs {}, not {platform}", st.platforms.join(", "))));
    }
    if !st.running {
        blocking(sh, |s| s.runtime.ensure_started()).await?.map_err(unavailable)?;
    }
    Ok(())
}

/// Answer one request.
async fn handle(sh: &Arc<Shared>, req: &Value) -> Value {
    if sh.closed.load(Ordering::SeqCst) {
        return cancelled();
    }
    let _g = Inflight::new(sh);
    match req["op"].as_str().unwrap_or("") {
        "status" => status(sh).await,
        "container.pull" => pull(sh, req).await.unwrap_or_else(|r| r.json()),
        "container.run" => run(sh, req).await.unwrap_or_else(|r| r.json()),
        _ => Refusal::bad_request(format!("unknown op {}", req["op"])).json(),
    }
}

/// `{ok, running, images[]}`: the approved images already present.
async fn status(sh: &Arc<Shared>) -> Value {
    let r = blocking(sh, |s| {
        let running = s.runtime.status().is_ok_and(|st| st.running);
        let present: Vec<(String, String)> = if running { s.runtime.images().iter().map(|i| image_key(i)).collect() } else { vec![] };
        let mut images: Vec<String> = Vec::new();
        for (i, _) in &s.scope.grant.approved_images {
            if present.contains(&image_key(i)) && !images.contains(i) {
                images.push(i.clone());
            }
        }
        (running, images)
    }).await;
    match r {
        Ok((running, images)) => json!({"ok": true, "running": running, "images": images}),
        Err(r) => r.json(),
    }
}

async fn pull(sh: &Arc<Shared>, req: &Value) -> Result<Value, Refusal> {
    let image = opt_str(&req["image"], "image")?;
    let platform = opt_str(&req["platform"], "platform")?;
    approved(image.as_deref(), platform.as_deref(), &sh.scope.grant)?;
    let (image, platform) = (image.unwrap_or_default(), platform.unwrap_or_default());
    ready(sh, &platform).await?;
    let p2 = platform.clone();
    match blocking(sh, move |s| s.runtime.pull(&image, &p2)).await? {
        Ok(()) => Ok(json!({"ok": true})),
        Err(e) if e.contains("no matching manifest") => Err(Refusal::new("platform_unavailable", e)),
        Err(e) => Err(Refusal::new("pull_failed", e)),
    }
}

/// `broker/<n>.stdout` and `.stderr` in the work directory, created by the agent itself and never through a symlink.
fn open_outputs(sh: &Shared) -> std::io::Result<(u64, std::fs::File, std::fs::File)> {
    let dir = sh.scope.work.join("broker");
    if std::fs::symlink_metadata(&dir).is_err() {
        std::fs::create_dir(&dir)?;
    }
    let cdir = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())?;
    let dfd = unsafe { libc::open(cdir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if dfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dir_fd = unsafe { std::fs::File::from_raw_fd(dfd) };
    let open = |name: String| -> std::io::Result<std::fs::File> {
        use std::os::unix::io::AsRawFd;
        let c = std::ffi::CString::new(name)?;
        let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(dir_fd.as_raw_fd(), c.as_ptr(), flags, 0o644 as libc::c_uint) };
        if fd < 0 { Err(std::io::Error::last_os_error()) } else { Ok(unsafe { std::fs::File::from_raw_fd(fd) }) }
    };
    for _ in 0..1000 {
        let n = sh.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let out = match open(format!("{n}.stdout")) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        match open(format!("{n}.stderr")) {
            Ok(err) => return Ok((n, out, err)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("no free output name"))
}

/// The last 4 KB written, decoded without a partial leading UTF-8 sequence.
fn tail(f: Option<&std::fs::File>) -> String {
    let Some(f) = f else { return String::new() };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let n = (TAIL_BYTES as u64).min(size) as usize;
    let mut buf = vec![0u8; n];
    let Ok(got) = f.read_at(&mut buf, size - n as u64) else { return String::new() };
    let start = buf[..got].iter().take_while(|b| (**b & 0xC0) == 0x80).count();
    String::from_utf8_lossy(&buf[start..got]).to_string()
}

async fn run(sh: &Arc<Shared>, req: &Value) -> Result<Value, Refusal> {
    let mut spec = plan(req, &sh.scope)?;
    ready(sh, &spec.platform).await?;
    let _gate = sh.gate.lock().await;
    if sh.closed.load(Ordering::SeqCst) {
        return Ok(cancelled());
    }
    let (n, out, err) = open_outputs(sh).map_err(|e| Refusal::bad_request(format!("cannot create the output files in broker/: {e}")))?;
    (spec.stdout, spec.stderr) = (Some(out), Some(err));
    let timeout = spec.timeout_s;
    sh.ran.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    let (spec, r): (RunSpec, Result<RunResult, String>) = blocking(sh, move |s| {
        let r = s.runtime.run(&spec, &s.closed);
        (spec, r)
    }).await?;
    let dur = t0.elapsed().as_secs_f64();
    let r = r.map_err(|e| Refusal::new("runtime_unavailable", e))?;
    if r.timed_out || r.cancelled {
        // runs are serialized: the attempt's only container is this run's
        let aid = sh.scope.grant.attempt_id;
        let _ = blocking(sh, move |s| s.runtime.remove_attempt(aid)).await;
    }
    let mut o = json!({
        "stdout_tail": tail(spec.stdout.as_ref()), "stderr_tail": tail(spec.stderr.as_ref()),
        "stdout_path": format!("broker/{n}.stdout"), "stderr_path": format!("broker/{n}.stderr"),
        "duration_s": (dur * 1000.0).round() / 1000.0,
    });
    if r.timed_out {
        o["ok"] = json!(false);
        o["error"] = json!("timeout");
        o["detail"] = json!(format!("the container ran longer than timeout_s={} and was removed", timeout as i64));
    } else if r.cancelled {
        o["ok"] = json!(false);
        o["error"] = json!("cancelled");
        o["detail"] = json!("the attempt ended");
    } else {
        o["ok"] = json!(true);
        o["exit_code"] = json!(r.exit_code);
    }
    Ok(o)
}

/// Read one line (at most 1 MiB, 30 s), answer it, close.
async fn serve(mut c: UnixStream, sh: Arc<Shared>) {
    if c.peer_cred().map(|p| p.uid()).ok() != Some(unsafe { libc::geteuid() }) {
        return;
    }
    let mut buf = Vec::new();
    let read = async {
        let mut chunk = vec![0u8; 65536];
        while !buf.contains(&b'\n') && buf.len() < MAX_REQUEST {
            match c.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(30), read).await;
    let line = buf.split(|b| *b == b'\n').next().unwrap_or(&[]);
    let resp = match serde_json::from_slice::<Value>(line) {
        Ok(req) if req.is_object() => handle(&sh, &req).await,
        _ => Refusal::bad_request("one JSON object per line").json(),
    };
    let mut out = serde_json::to_vec(&resp).unwrap_or_default();
    out.push(b'\n');
    let _ = c.write_all(&out).await;
    let _ = c.shutdown().await;
}

/// One attempt's broker: serves its socket until dropped.
pub struct Broker {
    socket: PathBuf,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Broker {
    /// Bind a fresh socket at `socket_path` (mode 0600, parent dir private) and serve requests for this grant until
    /// dropped. Also creates the work directory's `broker/` output directory.
    pub async fn start(socket_path: PathBuf, grant: BrokerGrant, runtime: Arc<dyn ContainerRuntime>) -> std::io::Result<Broker> {
        if socket_path.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(std::io::Error::new(ErrorKind::InvalidInput,
                                           format!("broker socket path too long ({} bytes): {}", socket_path.as_os_str().len(), socket_path.display())));
        }
        let dir = socket_path.parent().ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "socket path has no directory"))?;
        crate::fsutil::private_dir(dir)?;
        let scope = Scope::new(grant)?;
        let out = scope.work.join("broker");
        if std::fs::symlink_metadata(&out).is_ok_and(|m| !m.is_dir()) {
            std::fs::remove_file(&out)?;
        }
        std::fs::create_dir_all(&out)?;
        if std::fs::symlink_metadata(&socket_path).is_ok_and(|m| !m.is_dir()) {
            std::fs::remove_file(&socket_path)?;
        }
        let listener = UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;
        let shared = Arc::new(Shared {
            scope, runtime, closed: AtomicBool::new(false), inflight: AtomicUsize::new(0), counter: AtomicU64::new(0),
            ran: AtomicBool::new(false), gate: tokio::sync::Mutex::new(()),
        });
        let sh = shared.clone();
        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((c, _)) => {
                        tokio::spawn(serve(c, sh.clone()));
                    }
                    Err(e) => {
                        warn!(error = %e, "broker accept failed");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
        Ok(Broker { socket: socket_path, shared, task })
    }

    /// The job's `OARBANK_BROKER`.
    pub fn endpoint(&self) -> String {
        format!("unix:{}", self.socket.display())
    }
}

impl Drop for Broker {
    /// Stop serving, cancel the running container, remove the socket; then, on a thread of its own so dropping never
    /// blocks the async runtime, wait for in-flight requests (their containers are being stopped) and remove every
    /// container labelled with the attempt.
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket);
        let sh = self.shared.clone();
        std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(13);
            while sh.inflight.load(Ordering::SeqCst) > 0 && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(50));
            }
            if sh.ran.load(Ordering::SeqCst) {
                let aid = sh.scope.grant.attempt_id;
                let removed = sh.runtime.remove_attempt(aid);
                if !removed.is_empty() {
                    info!(attempt = aid, containers = ?removed, "broker: containers of the ended attempt removed");
                }
            }
        });
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::container_runtime::RuntimeStatus;
    use std::io::Write;
    use std::sync::Mutex;

    const IMAGE: &str = "docker.io/org/tool:1.2@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct Tmp(PathBuf);

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmp() -> Tmp {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!("obk-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("work/inputs")).unwrap();
        std::fs::create_dir_all(d.join("data/cache")).unwrap();
        Tmp(d)
    }

    fn grant(base: &Path, egress: bool) -> BrokerGrant {
        BrokerGrant {
            attempt_id: 42, module: "toy".into(), approved_images: vec![(IMAGE.into(), "linux/amd64".into())],
            workdir: base.join("work"), module_data: base.join("data"), network_granted: egress, cpus: 4.0, mem_gb: 8.0,
        }
    }

    fn scope(base: &Path, egress: bool) -> Scope {
        Scope::new(grant(base, egress)).unwrap()
    }

    fn req(extra: Value) -> Value {
        let mut o = json!({"op": "container.run", "image": IMAGE, "platform": "linux/amd64"});
        for (k, v) in extra.as_object().unwrap() {
            o[k] = v.clone();
        }
        o
    }

    fn code(r: Result<RunSpec, Refusal>) -> Option<String> {
        r.err().map(|e| e.code)
    }

    #[test]
    fn builds_exactly_the_allowed_docker_arguments() {
        let t = tmp();
        let s = scope(&t.0, true);
        let r = req(json!({"args": ["tool", "--in", "/w/x"], "entrypoint": "/bin/tool", "workdir": "/w",
                           "mounts": [{"src": "inputs", "dst": "/w", "ro": true}, {"src": "data:cache", "dst": "/cache"}, {"src": "out", "dst": "/out"}],
                           "env": {"B": "2", "A_1": "x y"}, "network": true, "timeout_s": 100, "cpus": 16, "mem_gb": 2.5}));
        let p = plan(&r, &s).unwrap();
        let (w, d) = (s.work.to_string_lossy().to_string(), s.data.to_string_lossy().to_string());
        assert_eq!(p.docker_args(), [
            "run", "--rm", "--platform", "linux/amd64", "--network", "bridge", "--cpus", "4", "--memory", "2.5g",
            "--label", "oarbank.attempt_id=42", "--label", "oarbank.module=toy",
            "-v", &format!("{w}/inputs:/w:ro"), "-v", &format!("{d}/cache:/cache"), "-v", &format!("{w}/out:/out"),
            "--workdir", "/w", "--entrypoint", "/bin/tool", "-e", "A_1=x y", "-e", "B=2", IMAGE, "tool", "--in", "/w/x",
        ]);
        assert_eq!(p.timeout_s, 100.0);
        assert!(s.work.join("out").is_dir());                      // created inside the work dir
        // defaults: no network, the whole reservation, the SDK's nulls
        let minimal = req(json!({"args": [], "entrypoint": null, "workdir": null, "cpus": null, "mem_gb": null, "mounts": [], "env": {},
                                 "network": false, "timeout_s": 3600}));
        assert_eq!(plan(&minimal, &s).unwrap().docker_args(),
                   ["run", "--rm", "--platform", "linux/amd64", "--network", "none", "--cpus", "4", "--memory", "8g",
                    "--label", "oarbank.attempt_id=42", "--label", "oarbank.module=toy", IMAGE]);
    }

    #[test]
    fn refuses_unapproved_images_and_platforms() {
        let t = tmp();
        let s = scope(&t.0, false);
        let r = |i: &str, p: &str| code(plan(&json!({"op": "container.run", "image": i, "platform": p, "args": []}), &s));
        assert_eq!(r(IMAGE, "linux/amd64"), None);
        assert_eq!(r(IMAGE, "linux/arm64").as_deref(), Some("image_not_approved"));
        assert_eq!(r("docker.io/org/tool:1.2", "linux/amd64").as_deref(), Some("image_not_approved"));
        assert_eq!(r(&format!("{IMAGE} "), "linux/amd64").as_deref(), Some("image_not_approved"));
        assert_eq!(r("org/tool@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "linux/amd64").as_deref(),
                   Some("image_not_approved"));                    // the exact approved spelling only
        assert_eq!(code(plan(&json!({"op": "container.run", "platform": "linux/amd64"}), &s)).as_deref(), Some("bad_request"));
        assert_eq!(code(plan(&json!({"op": "container.run", "image": IMAGE}), &s)).as_deref(), Some("image_not_approved"));
        assert_eq!(code(plan(&json!({"op": "container.run", "image": 7, "platform": "linux/amd64"}), &s)).as_deref(), Some("bad_request"));
    }

    #[test]
    fn refuses_bad_mounts_including_symlink_escapes() {
        let t = tmp();
        let s = scope(&t.0, false);
        let base = std::fs::canonicalize(&t.0).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        std::os::unix::fs::symlink(base.join("outside"), s.work.join("escape")).unwrap();
        std::os::unix::fs::symlink("../..", s.work.join("inputs/up")).unwrap();
        std::os::unix::fs::symlink(&s.work, s.data.join("esc")).unwrap();
        std::os::unix::fs::symlink("/nonexistent/x", s.work.join("dangling")).unwrap();
        std::os::unix::fs::symlink("cache", s.data.join("inner")).unwrap();
        std::os::unix::net::UnixListener::bind(s.work.join("sock")).unwrap();
        std::fs::write(s.work.join("inputs/a.txt"), "x").unwrap();
        let m = |src: &str, dst: &str| code(plan(&req(json!({"mounts": [{"src": src, "dst": dst}]})), &s));
        let ok = |src: &str| m(src, "/m");
        assert_eq!(ok("inputs"), None);
        assert_eq!(ok("."), None);
        assert_eq!(ok("data:."), None);
        assert_eq!(ok("data:cache"), None);
        assert_eq!(ok("data:new/dir"), None);                      // created inside the data dir
        assert!(s.data.join("new/dir").is_dir());
        assert_eq!(ok("data:inner"), None);                        // a symlink that stays inside
        assert_eq!(ok("inputs/a.txt"), None);                      // a file
        for bad in ["/etc", "../outside", "inputs/../../outside", "escape", "escape/sub", "inputs/up", "inputs/up/outside",
                    "dangling", "dangling/sub", "data:esc", "data:../work", "data:/etc", "data:", "", "sock", "a\\b", "c:x", "./inputs"] {
            assert_eq!(ok(bad).as_deref(), Some("bad_mount"), "{bad:?}");
        }
        for dst in ["relative", "/a/../etc", "/w:rw", "", "/a\nb"] {
            assert_eq!(m("inputs", dst).as_deref(), Some("bad_mount"), "{dst:?}");
        }
        assert_eq!(code(plan(&req(json!({"mounts": [{"src": "inputs"}]})), &s)).as_deref(), Some("bad_mount"));
        assert_eq!(code(plan(&req(json!({"mounts": [{"src": "inputs", "dst": "/m", "ro": "yes"}]})), &s)).as_deref(), Some("bad_mount"));
        assert_eq!(code(plan(&req(json!({"mounts": "inputs:/m"})), &s)).as_deref(), Some("bad_request"));
        assert!(!base.join("outside/sub").exists());
    }

    #[test]
    fn refuses_network_without_grant_and_bad_fields_and_clamps_resources() {
        let t = tmp();
        let s = scope(&t.0, false);
        let r = |extra: Value| code(plan(&req(extra), &s));
        assert_eq!(r(json!({"network": true})).as_deref(), Some("network_not_granted"));
        assert_eq!(r(json!({"network": false})), None);
        assert_eq!(r(json!({"network": "host"})).as_deref(), Some("bad_request"));
        assert_eq!(r(json!({"env": {"1BAD": "x"}})).as_deref(), Some("bad_request"));
        assert_eq!(r(json!({"env": {"BAD-KEY": "x"}})).as_deref(), Some("bad_request"));
        assert_eq!(r(json!({"env": {"GOOD": 3}})).as_deref(), Some("bad_request"));
        assert_eq!(r(json!({"env": {"_ok9": "x"}})), None);
        assert_eq!(r(json!({"args": ["a", 1]})).as_deref(), Some("bad_request"));
        assert_eq!(r(json!({"args": "a b"})).as_deref(), Some("bad_request"));
        assert_eq!(r(json!({"workdir": "rel"})).as_deref(), Some("bad_mount"));
        assert_eq!(r(json!({"entrypoint": ""})).as_deref(), Some("bad_request"));
        assert_eq!(r(json!({"cpus": "lots"})).as_deref(), Some("bad_request"));
        let p = plan(&req(json!({"cpus": 0, "mem_gb": 0, "timeout_s": -5})), &s).unwrap();
        let a = p.docker_args();
        assert!(a.contains(&"0.1".to_string()) && a.contains(&"0.25g".to_string()), "{a:?}");
        assert_eq!(p.timeout_s, DEFAULT_TIMEOUT_S);
        assert_eq!(plan(&req(json!({"timeout_s": 0.2})), &s).unwrap().timeout_s, 1.0);
        let net = scope(&t.0, true);
        assert!(plan(&req(json!({"network": true})), &net).unwrap().docker_args().windows(2).any(|w| w == ["--network", "bridge"]));
    }

    #[test]
    fn never_privileged_host_network_or_another_mount() {
        let t = tmp();
        let s = scope(&t.0, true);
        let base = req(json!({"mounts": [{"src": "inputs", "dst": "/w"}], "args": ["--privileged", "-v", "/:/host"]}));
        let mut hostile = base.clone();
        for (k, v) in [("privileged", json!(true)), ("network_mode", json!("host")), ("net", json!("host")), ("pid", json!("host")),
                       ("volumes", json!(["/var/run/docker.sock:/var/run/docker.sock"])), ("devices", json!(["/dev/kvm"])),
                       ("cap_add", json!(["ALL"])), ("security_opt", json!(["seccomp=unconfined"])), ("user", json!("0")),
                       ("ipc", json!("host")), ("runtime", json!("runc")), ("extra_args", json!(["--privileged"]))] {
            hostile[k] = v;
        }
        let a = plan(&hostile, &s).unwrap().docker_args();
        assert_eq!(a, plan(&base, &s).unwrap().docker_args());    // unknown keys never reach the command
        let image_at = a.iter().position(|x| x == IMAGE).unwrap();
        let flags = &a[..image_at];
        assert!(!flags.iter().any(|x| x.contains("privileged") || x.contains("host") || x.contains("docker.sock")
                                  || x.starts_with("--cap") || x.starts_with("--security") || x.starts_with("--device")), "{flags:?}");
        let vols: Vec<&String> = flags.iter().zip(flags.iter().skip(1)).filter(|(f, _)| *f == "-v").map(|(_, v)| v).collect();
        assert_eq!(vols, [&format!("{}/inputs:/w", s.work.display())]);
        assert_eq!(flags[..2], ["run", "--rm"]);
        // the container's own arguments come after the image, where docker passes them to the container
        assert_eq!(a[image_at + 1..], ["--privileged", "-v", "/:/host"]);
    }

    // MARK: the broker over its socket

    #[derive(Default)]
    struct FakeState {
        running: bool,
        start_fails: bool,
        starts: usize,
        runs: Vec<(Vec<String>, f64)>,
        pulls: Vec<(String, String)>,
        removed: Vec<i64>,
        time_out: bool,
        block: bool,
        exit_code: i32,
        images: Vec<String>,
    }

    #[derive(Default)]
    struct Fake(Mutex<FakeState>);

    impl Fake {
        fn running() -> Arc<Fake> {
            let f = Fake::default();
            f.0.lock().unwrap().running = true;
            Arc::new(f)
        }
        fn with<T>(&self, f: impl FnOnce(&mut FakeState) -> T) -> T {
            f(&mut self.0.lock().unwrap())
        }
    }

    impl ContainerRuntime for Fake {
        fn status(&self) -> Result<RuntimeStatus, String> {
            Ok(RuntimeStatus { running: self.with(|s| s.running), mem_gb: None,
                               platforms: vec!["linux/arm64".into(), "linux/amd64".into()], detail: None })
        }
        fn ensure_started(&self) -> Result<(), String> {
            self.with(|s| {
                s.starts += 1;
                if s.start_fails { Err("colima start failed".into()) } else { s.running = true; Ok(()) }
            })
        }
        fn pull(&self, image: &str, platform: &str) -> Result<(), String> {
            self.with(|s| s.pulls.push((image.into(), platform.into())));
            Ok(())
        }
        fn run(&self, spec: &RunSpec, cancel: &AtomicBool) -> Result<RunResult, String> {
            let (block, time_out, exit_code) = self.with(|s| {
                s.runs.push((spec.docker_args(), spec.timeout_s));
                (s.block, s.time_out, s.exit_code)
            });
            let _ = spec.stdout.as_ref().unwrap().write_all(b"hello from the container\n");
            let _ = spec.stderr.as_ref().unwrap().write_all(b"a warning\n");
            if block {
                while !cancel.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(10));
                }
                return Ok(RunResult { exit_code: 143, timed_out: false, cancelled: true });
            }
            Ok(RunResult { exit_code: if time_out { 143 } else { exit_code }, timed_out: time_out, cancelled: false })
        }
        fn images(&self) -> Vec<String> {
            self.with(|s| s.images.clone())
        }
        fn reap(&self) -> Vec<String> {
            vec![]
        }
        fn remove_attempt(&self, attempt_id: i64) -> Vec<String> {
            self.with(|s| s.removed.push(attempt_id));
            vec!["c1".into()]
        }
    }

    async fn ask(endpoint: &str, line: &str) -> Value {
        let mut c = UnixStream::connect(endpoint.strip_prefix("unix:").unwrap()).await.unwrap();
        c.write_all(format!("{line}\n").as_bytes()).await.unwrap();
        let mut b = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut b)).await.unwrap().unwrap();
        assert!(b.ends_with(b"\n"), "one answer line");
        serde_json::from_slice(&b).unwrap()
    }

    async fn eventually(what: &str, f: impl Fn() -> bool) {
        for _ in 0..500 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn round_trip_over_the_socket_then_close_removes_containers() {
        let t = tmp();
        let rt = Fake::running();
        let sock = t.0.join("b/42.sock");
        let b = Broker::start(sock.clone(), grant(&t.0, false), rt.clone()).await.unwrap();
        let ep = b.endpoint();
        assert_eq!(ep, format!("unix:{}", sock.display()));
        let m = std::fs::symlink_metadata(&sock).unwrap();
        assert!(m.file_type().is_socket() && m.permissions().mode() & 0o777 == 0o600);
        assert_eq!(std::fs::metadata(t.0.join("b")).unwrap().permissions().mode() & 0o777, 0o700);

        let r = ask(&ep, &req(json!({"args": ["echo"], "mounts": [{"src": "inputs", "dst": "/w", "ro": true}]})).to_string()).await;
        assert_eq!((r["ok"].as_bool(), r["exit_code"].as_i64()), (Some(true), Some(0)), "{r}");
        assert_eq!(r["stdout_tail"], "hello from the container\n");
        assert_eq!(r["stderr_tail"], "a warning\n");
        assert_eq!(r["stdout_path"], "broker/1.stdout");
        assert!(r["duration_s"].is_number());
        let work = std::fs::canonicalize(t.0.join("work")).unwrap();
        assert_eq!(std::fs::read_to_string(work.join("broker/1.stdout")).unwrap(), "hello from the container\n");
        let (args, timeout) = rt.with(|s| s.runs[0].clone());
        assert_eq!(timeout, DEFAULT_TIMEOUT_S);
        assert!(args.contains(&format!("{}/inputs:/w:ro", work.display())) && args.contains(&"--rm".to_string()));

        // a pre-planted symlink is never written through: the next run takes another number
        std::os::unix::fs::symlink("/tmp/nope", work.join("broker/2.stdout")).unwrap();
        let r2 = ask(&ep, &req(json!({})).to_string()).await;
        assert_eq!(r2["stdout_path"], "broker/3.stdout");
        rt.with(|s| s.exit_code = 3);
        assert_eq!(ask(&ep, &req(json!({})).to_string()).await["exit_code"], 3);

        let refused = ask(&ep, r#"{"op": "container.run", "image": "evil:latest", "platform": "linux/amd64"}"#).await;
        assert_eq!((refused["ok"].as_bool(), refused["error"].as_str()), (Some(false), Some("image_not_approved")));
        assert!(refused["detail"].is_string());
        assert_eq!(ask(&ep, &req(json!({"network": true})).to_string()).await["error"], "network_not_granted");
        assert_eq!(ask(&ep, &req(json!({"mounts": [{"src": "/Users", "dst": "/u"}]})).to_string()).await["error"], "bad_mount");
        assert_eq!(ask(&ep, "not json").await["error"], "bad_request");
        assert_eq!(ask(&ep, "[1]").await["error"], "bad_request");
        assert_eq!(ask(&ep, r#"{"op": "rm -rf"}"#).await["error"], "bad_request");

        rt.with(|s| s.images = vec!["org/tool@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(), "alpine@sha256:00".into()]);
        let st = ask(&ep, r#"{"op": "status"}"#).await;
        assert_eq!(st, json!({"ok": true, "running": true, "images": [IMAGE]}));
        assert_eq!(ask(&ep, &json!({"op": "container.pull", "image": IMAGE, "platform": "linux/amd64"}).to_string()).await, json!({"ok": true}));
        assert_eq!(ask(&ep, &json!({"op": "container.pull", "image": IMAGE, "platform": "linux/arm64"}).to_string()).await["error"],
                   "image_not_approved");
        assert_eq!(rt.with(|s| s.pulls.clone()), [(IMAGE.to_string(), "linux/amd64".to_string())]);

        // a stopped runtime is started on demand; one that cannot start is unavailable
        rt.with(|s| s.running = false);
        assert_eq!(ask(&ep, &req(json!({})).to_string()).await["ok"], true);
        assert_eq!(rt.with(|s| s.starts), 1);
        rt.with(|s| (s.running, s.start_fails) = (false, true));
        let un = ask(&ep, &req(json!({})).to_string()).await;
        assert_eq!(un["error"], "runtime_unavailable");
        assert_eq!(ask(&ep, r#"{"op": "status"}"#).await, json!({"ok": true, "running": false, "images": []}));
        rt.with(|s| (s.running, s.start_fails) = (true, false));

        let sh = b.shared.clone();
        drop(b);
        assert!(!sock.exists());
        for _ in 0..100 {
            if !rt.with(|s| s.removed.is_empty()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(rt.with(|s| s.removed.clone()), [42]);
        assert_eq!(handle(&sh, &json!({"op": "status"})).await["error"], "cancelled");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_platform_the_runtime_cannot_run_is_unavailable() {
        let t = tmp();
        let rt = Fake::running();
        let mut g = grant(&t.0, false);
        g.approved_images.push((IMAGE.into(), "linux/riscv64".into()));
        let b = Broker::start(t.0.join("p.sock"), g, rt.clone()).await.unwrap();
        let r = ask(&b.endpoint(), &json!({"op": "container.run", "image": IMAGE, "platform": "linux/riscv64"}).to_string()).await;
        assert_eq!(r["error"], "platform_unavailable");
        assert!(rt.with(|s| s.runs.is_empty()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_out_run_removes_its_container() {
        let t = tmp();
        let rt = Fake::running();
        rt.with(|s| s.time_out = true);
        let b = Broker::start(t.0.join("t.sock"), grant(&t.0, false), rt.clone()).await.unwrap();
        let r = ask(&b.endpoint(), &req(json!({"timeout_s": 1})).to_string()).await;
        assert_eq!((r["ok"].as_bool(), r["error"].as_str()), (Some(false), Some("timeout")), "{r}");
        assert_eq!(r["stdout_tail"], "hello from the container\n");
        assert_eq!(rt.with(|s| (s.removed.clone(), s.runs[0].1)), (vec![42], 1.0));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_the_broker_cancels_the_running_container_and_removes_it() {
        let t = tmp();
        let rt = Fake::running();
        rt.with(|s| s.block = true);
        let sock = t.0.join("d.sock");
        let b = Broker::start(sock.clone(), grant(&t.0, false), rt.clone()).await.unwrap();
        let ep = b.endpoint();
        let pending = tokio::spawn(async move { ask(&ep, &req(json!({})).to_string()).await });
        eventually("the run to start", || rt.with(|s| !s.runs.is_empty())).await;
        drop(b);
        assert!(!sock.exists());
        let r = pending.await.unwrap();
        assert_eq!(r["error"], "cancelled", "{r}");
        eventually("the attempt's containers to be removed", || rt.with(|s| s.removed.contains(&42))).await;
    }

    /// The SDK's Python client against this broker (needs uv and the oarbank checkout).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn sdk_python_client_round_trip() {
        let t = tmp();
        let rt = Fake::running();
        let b = Broker::start(t.0.join("py.sock"), grant(&t.0, false), rt.clone()).await.unwrap();
        let script = format!(r#"
import json
from oarbank_sdk import broker
r = broker.run("{IMAGE}", ["echo", "hi"], mounts=[broker.Mount("inputs", "/w", ro=True), broker.Mount("data:cache", "/c")],
               platform="linux/amd64", env={{"A": "1"}}, timeout_s=50)
out = {{"exit_code": r.exit_code, "stdout_tail": r.stdout_tail, "stdout_path": r.stdout_path, "status": broker.status()}}
try:
    broker.run("evil:latest", [], platform="linux/amd64")
except broker.BrokerError as e:
    out["refused"] = e.code
try:
    broker.run("{IMAGE}", [], platform="linux/amd64", network=True)
except broker.BrokerError as e:
    out["network"] = e.code
print(json.dumps(out))
"#);
        let repo = std::env::var_os("OARBANK_REPO").map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.."));
        let o = tokio::process::Command::new("uv").args(["run", "--quiet", "python", "-c", &script]).current_dir(&repo)
            .env("OARBANK_BROKER", b.endpoint()).output().await.expect("uv");
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let v: Value = serde_json::from_slice(&o.stdout).unwrap();
        assert_eq!(v["exit_code"], 0);
        assert_eq!(v["stdout_tail"], "hello from the container\n");
        assert_eq!(v["stdout_path"], "broker/1.stdout");
        assert_eq!(v["status"]["running"], true);
        assert_eq!(v["refused"], "image_not_approved");
        assert_eq!(v["network"], "network_not_granted");
        let (args, timeout) = rt.with(|s| s.runs[0].clone());
        assert_eq!(timeout, 50.0);
        let data = std::fs::canonicalize(t.0.join("data")).unwrap();
        assert!(args.contains(&format!("{}/cache:/c", data.display())) && args.contains(&"A=1".to_string()), "{args:?}");
        assert_eq!(args[args.len() - 3..], [IMAGE, "echo", "hi"]);
    }
}
