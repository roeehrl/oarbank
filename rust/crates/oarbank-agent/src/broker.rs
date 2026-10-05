//! The per-attempt container broker (spec/sandbox.md, "Containers: the agent's broker"; the SDK's `broker` module is
//! the client). A job whose module is approved for containers gets an endpoint, the only IPC its sandbox allows: a unix
//! socket, `OARBANK_BROKER=unix:/path`, or on Windows a named pipe, `OARBANK_BROKER=npipe://./pipe/<name>`, that only
//! the agent's account and the module's AppContainer may open. One JSON request per connection, one JSON answer line.
//! Ops: `container.run`, `container.pull`, `status`. Every run is validated against the module's approved images (its static `containers`, or
//! an image of one of its `container_sets` that the job lists, whose signature the agent verifies before pulling), its
//! directories and its reservation (the GPU only for a job that reserved the agent's `gpu` pool), runs on the agent's own
//! runtime with a fixed argument shape, and dies with the attempt.

use crate::container_runtime::{image_key, ContainerRuntime, Mount, RunResult, RunSpec};
use crate::imageset::Verifier;
use oarbank_core::images::ContainerSet;
use serde_json::{json, Value};
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixListener;
use tracing::{info, warn};

pub const MIN_CPUS: f64 = 0.1;
pub const MIN_MEM_GB: f64 = 0.25;
pub const DEFAULT_TIMEOUT_S: f64 = 3600.0;
const TAIL_BYTES: usize = 4096;
const MAX_REQUEST: usize = 1 << 20;
/// macOS `sun_path` holds 104 bytes with the NUL.
#[cfg(unix)]
const MAX_SOCKET_PATH: usize = 103;

/// Where a broker listens: a socket path, or on Windows a pipe name (`\\.\pipe\<name>`).
#[cfg(unix)]
pub type Bind = PathBuf;
#[cfg(windows)]
pub type Bind = String;

/// The endpoint of attempt `aid`'s broker: a socket in the agent's run directory, or a pipe name nobody can guess (the
/// first instance is created exclusively, so a name taken by another process fails the start instead of being shared).
pub fn bind_for(home: &Path, aid: i64) -> std::io::Result<Bind> {
    #[cfg(unix)]
    return crate::paths::socket_path(home, &format!("broker-{aid}.sock"));
    #[cfg(windows)]
    {
        let _ = home;
        Ok(format!("oarbank-broker-{aid}-{}", hex::encode(rand::random::<[u8; 12]>())))
    }
}

/// What one attempt's broker may do: the module's approved images, its directories and its reservation.
#[derive(Debug, Clone)]
pub struct BrokerGrant {
    pub attempt_id: i64,
    pub module: String,
    /// (image reference with an `@sha256:` digest, OCI platform such as `linux/amd64`).
    pub approved_images: Vec<(String, String)>,
    /// The module's image sets, and the set images this job listed (jobs.enqueue `images`): only those may run.
    pub sets: Vec<ContainerSet>,
    pub job_images: Vec<String>,
    /// The job reserved the agent's `gpu` pool: its containers may get every GPU (`gpus = "all"`).
    pub gpu: bool,
    pub workdir: PathBuf,
    pub module_data: PathBuf,
    pub network_granted: bool,
    /// The module's sandbox identity (its `module_id`): on Windows the AppContainer whose SID may open the pipe.
    #[cfg(windows)]
    pub sandbox_id: String,
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

/// Which approval an image falls under: a static entry (None), or a set (Some) whose signature the agent must still
/// verify. A static image must exactly equal an approved entry's reference with that entry's platform; a set image lies
/// under the set's prefix with its platform and is listed by the job.
pub fn approved<'a>(image: Option<&str>, platform: Option<&str>, g: &'a BrokerGrant) -> Result<Option<&'a ContainerSet>, Refusal> {
    let image = image.filter(|i| !i.is_empty()).ok_or_else(|| Refusal::bad_request("image is required"))?;
    let platforms: Vec<&str> = g.approved_images.iter().filter(|(i, _)| i == image).map(|(_, p)| p.as_str()).collect();
    if platforms.contains(&platform.unwrap_or("")) {
        return Ok(None);
    }
    let norm = oarbank_core::images::normalize(image).ok();
    let set = norm.as_ref().filter(|n| n.digest.is_some())
        .and_then(|n| g.sets.iter().find(|s| Some(s.platform.as_str()) == platform && s.covers(&n.repository)));
    if let (Some(set), Some(n)) = (set, &norm) {
        let listed = g.job_images.iter().any(|j| oarbank_core::images::normalize(j).ok()
            .is_some_and(|m| m.repository == n.repository && m.digest == n.digest));
        if !listed {
            return Err(Refusal::new("image_not_approved", format!("{image} is in set {} but this job does not list it \
                                                                   (jobs.enqueue images)", set.name)));
        }
        return Ok(Some(set));
    }
    if platforms.is_empty() {
        return Err(Refusal::new("image_not_approved", format!("{image} is not an approved image of this module")));
    }
    Err(Refusal::new("image_not_approved", format!("{image} is approved for {}, not {}", platforms.join(", "),
                                                   platform.unwrap_or("(none)"))))
}

/// `gpus`: "none" (or absent) or "all"; a count comes later. "all" needs the job's `gpu` pool reservation.
fn gpus(v: &Value, g: &BrokerGrant) -> Result<bool, Refusal> {
    match v {
        Value::Null => Ok(false),
        Value::String(s) if s == "none" => Ok(false),
        Value::String(s) if s == "all" && g.gpu => Ok(true),
        Value::String(s) if s == "all" => Err(Refusal::new("gpu_not_granted", "this job did not reserve the gpu pool \
                                                            (stages[].requires.pools gpu = 1)")),
        Value::Number(_) => Err(Refusal::bad_request("gpus is \"none\" or \"all\"; a GPU count is not supported yet")),
        _ => Err(Refusal::bad_request("gpus is \"none\" or \"all\"")),
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
    // component by component: a verbatim Windows path (`\\?\C:\...`, what canonicalize returns) takes no `/`
    let full = if rel == "." { base.to_path_buf() } else { rel.split('/').fold(base.to_path_buf(), |p, c| p.join(c)) };
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
    // the part a container flag carries as is: the whole path where the runtime mounts host paths unchanged, the part
    // below the directory where it translates them (WSL: a drive letter's colon is the runtime's to spell)
    let carried = if cfg!(windows) { resolved.strip_prefix(base).unwrap_or(&resolved) } else { resolved.as_path() };
    let text = carried.to_str().ok_or_else(|| Refusal::bad_mount(format!("mount source {src:?} is not UTF-8")))?;
    if text.contains([':', ',', '\n', '\0']) {
        return Err(Refusal::bad_mount(format!("mount source {src:?} has an unusable character")));
    }
    match std::fs::symlink_metadata(&resolved) {
        Ok(m) if m.is_dir() || m.is_file() => {}
        #[cfg(unix)]
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

/// Validate a `container.run` request into the exact run (output files not yet attached), and the set whose signature
/// must still be verified (none for a static image).
pub fn plan<'a>(req: &Value, s: &'a Scope) -> Result<(RunSpec, Option<&'a ContainerSet>), Refusal> {
    let g = &s.grant;
    if !req.is_object() {
        return Err(Refusal::bad_request("request must be a JSON object"));
    }
    let image = opt_str(&req["image"], "image")?;
    let platform = opt_str(&req["platform"], "platform")?;
    let set = approved(image.as_deref(), platform.as_deref(), g)?;
    let gpus = gpus(&req["gpus"], g)?;
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
    Ok((RunSpec {
        image: image.unwrap_or_default(), platform: platform.unwrap_or_default(), args, entrypoint, mounts, env, workdir, network,
        cpus, mem_gb, attempt_id: g.attempt_id, module: g.module.clone(), timeout_s: timeout.max(1.0), stdout: None, stderr: None,
        gpu_device: gpus.then(String::new),
    }, set))
}

// MARK: the broker

struct Shared {
    scope: Scope,
    runtime: Arc<dyn ContainerRuntime>,
    verifier: Arc<Verifier>,
    /// The set images this attempt ran, `{set, image}`, for its report (the coordinator audits each first run).
    ran_images: std::sync::Mutex<Vec<Value>>,
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

/// The set image's signature (or index membership), checked before anything is pulled.
async fn verified(sh: &Arc<Shared>, set: Option<&ContainerSet>, image: &str, platform: &str) -> Result<(), Refusal> {
    match set {
        None => Ok(()),
        Some(s) => sh.verifier.verify(s, image, platform).await.map_err(|r| Refusal::new(r.code, r.detail)),
    }
}

/// `{ok, running, images[], gpus}`: the approved images already present, and whether this job's containers may get the
/// GPU (it reserved the `gpu` pool and the runtime passes GPUs through).
async fn status(sh: &Arc<Shared>) -> Value {
    let gpus = if sh.scope.grant.gpu && sh.runtime.gpu_device().is_some() { "all" } else { "none" };
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
        Ok((running, images)) => json!({"ok": true, "running": running, "images": images, "gpus": gpus}),
        Err(r) => r.json(),
    }
}

async fn pull(sh: &Arc<Shared>, req: &Value) -> Result<Value, Refusal> {
    let image = opt_str(&req["image"], "image")?;
    let platform = opt_str(&req["platform"], "platform")?;
    let set = approved(image.as_deref(), platform.as_deref(), &sh.scope.grant)?;
    let (image, platform) = (image.unwrap_or_default(), platform.unwrap_or_default());
    verified(sh, set, &image, &platform).await?;
    ready(sh, &platform).await?;
    let p2 = platform.clone();
    match blocking(sh, move |s| s.runtime.pull(&image, &p2)).await? {
        Ok(()) => Ok(json!({"ok": true})),
        Err(e) if e.contains("no matching manifest") => Err(Refusal::new("platform_unavailable", e)),
        Err(e) => Err(Refusal::new("pull_failed", e)),
    }
}

/// `broker/<n>.stdout` and `.stderr` in the work directory, created by the agent itself and never through a symlink.
#[cfg(unix)]
fn open_outputs(sh: &Shared) -> std::io::Result<(u64, std::fs::File, std::fs::File)> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
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
    numbered_outputs(sh, |name| {
        let c = std::ffi::CString::new(name)?;
        let flags = libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(dir_fd.as_raw_fd(), c.as_ptr(), flags, 0o644 as libc::c_uint) };
        if fd < 0 { Err(std::io::Error::last_os_error()) } else { Ok(unsafe { std::fs::File::from_raw_fd(fd) }) }
    })
}

/// Windows: the directory must be a real one (no junction or symlink), and the broker holds it open without sharing
/// delete for its whole life (`Broker::_out_dir`), so it can be neither renamed nor replaced; each file is created new,
/// never opened through an existing name or a reparse point.
#[cfg(windows)]
fn open_outputs(sh: &Shared) -> std::io::Result<(u64, std::fs::File, std::fs::File)> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let dir = sh.scope.work.join("broker");
    numbered_outputs(sh, |name| {
        std::fs::OpenOptions::new().read(true).write(true).create_new(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(dir.join(name))
    })
}

/// The first free `<n>.stdout`/`<n>.stderr` pair `open` creates.
fn numbered_outputs(sh: &Shared, open: impl Fn(String) -> std::io::Result<std::fs::File>) -> std::io::Result<(u64, std::fs::File, std::fs::File)> {
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

/// The broker's output directory, opened as a directory without following a reparse point and without
/// FILE_SHARE_DELETE: while the handle lives nobody can rename, delete or replace it. A junction or symlink is refused.
#[cfg(windows)]
fn hold_dir(dir: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ_WRITE: u32 = 0x1 | 0x2;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let f = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(dir)?;
    let m = f.metadata()?;
    if !m.is_dir() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::other(format!("{} is not a plain directory", dir.display())));
    }
    Ok(f)
}

/// The last 4 KB written, decoded without a partial leading UTF-8 sequence.
fn tail(f: Option<&std::fs::File>) -> String {
    let Some(f) = f else { return String::new() };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let n = (TAIL_BYTES as u64).min(size) as usize;
    let mut buf = vec![0u8; n];
    #[cfg(unix)]
    let got = std::os::unix::fs::FileExt::read_at(f, &mut buf, size - n as u64);
    #[cfg(windows)]
    let got = std::os::windows::fs::FileExt::seek_read(f, &mut buf, size - n as u64);
    let Ok(got) = got else { return String::new() };
    let start = buf[..got].iter().take_while(|b| (**b & 0xC0) == 0x80).count();
    String::from_utf8_lossy(&buf[start..got]).to_string()
}

async fn run(sh: &Arc<Shared>, req: &Value) -> Result<Value, Refusal> {
    let (mut spec, set) = plan(req, &sh.scope)?;
    if spec.gpu_device.is_some() {
        spec.gpu_device = Some(sh.runtime.gpu_device().ok_or_else(|| Refusal::new("gpu_unavailable",
            "this node's container runtime cannot pass a GPU through (Linux: no CDI spec; macOS: krunkit is not installed)"))?);
    }
    verified(sh, set, &spec.image, &spec.platform).await?;
    if let Some(s) = set {
        let rec = json!({"set": s.name, "image": spec.image});
        let mut ran = sh.ran_images.lock().unwrap();
        if !ran.contains(&rec) {
            ran.push(rec);
        }
    }
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
async fn serve<C: AsyncRead + AsyncWrite + Unpin>(mut c: C, sh: Arc<Shared>) {
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

/// One attempt's broker: serves its endpoint until dropped.
pub struct Broker {
    bind: Bind,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
    /// Windows: the `broker/` output directory, held open so it cannot be swapped (open_outputs), and closed with the
    /// broker: the attempt's processes are gone by then, and the work directory is removed next, which an open handle
    /// would stop (the shared state lives on a moment, in the aborted accept task and the cleanup thread).
    #[cfg(windows)]
    _out_dir: std::fs::File,
}

impl Broker {
    /// Serve requests for this grant at `bind` until dropped: on Unix a fresh socket (mode 0600, parent dir private), on
    /// Windows a named pipe whose only allowed clients are the agent's account and the module's AppContainer. Also
    /// creates the work directory's `broker/` output directory.
    pub async fn start(bind: Bind, grant: BrokerGrant, runtime: Arc<dyn ContainerRuntime>,
                       verifier: Arc<Verifier>) -> std::io::Result<Broker> {
        let scope = Scope::new(grant)?;
        let out = scope.work.join("broker");
        if std::fs::symlink_metadata(&out).is_ok_and(|m| !m.is_dir()) {
            std::fs::remove_file(&out)?;
        }
        std::fs::create_dir_all(&out)?;
        #[cfg(windows)]
        let out_dir = hold_dir(&out)?;
        let listener = listen(&bind, &scope.grant)?;
        let shared = Arc::new(Shared {
            scope, runtime, verifier, ran_images: std::sync::Mutex::new(Vec::new()), closed: AtomicBool::new(false), inflight: AtomicUsize::new(0), counter: AtomicU64::new(0),
            ran: AtomicBool::new(false), gate: tokio::sync::Mutex::new(()),
        });
        let task = tokio::spawn(accept(listener, shared.clone()));
        Ok(Broker { bind, shared, task, #[cfg(windows)] _out_dir: out_dir })
    }

    /// The job's `OARBANK_BROKER`.
    pub fn endpoint(&self) -> String {
        #[cfg(unix)]
        return format!("unix:{}", self.bind.display());
        #[cfg(windows)]
        return format!("npipe://./pipe/{}", self.bind);
    }

    /// The set images the attempt ran so far, `[{set, image}]`.
    pub fn ran_images(&self) -> Vec<Value> {
        self.shared.ran_images.lock().unwrap().clone()
    }
}

#[cfg(unix)]
fn listen(socket_path: &Path, _grant: &BrokerGrant) -> std::io::Result<UnixListener> {
    if socket_path.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(std::io::Error::new(ErrorKind::InvalidInput,
                                       format!("broker socket path too long ({} bytes): {}", socket_path.as_os_str().len(), socket_path.display())));
    }
    let dir = socket_path.parent().ok_or_else(|| std::io::Error::new(ErrorKind::InvalidInput, "socket path has no directory"))?;
    crate::fsutil::private_dir(dir)?;
    if std::fs::symlink_metadata(socket_path).is_ok_and(|m| !m.is_dir()) {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Only the agent's own account may ask (the socket is 0600; this checks the peer too).
#[cfg(unix)]
async fn accept(listener: UnixListener, sh: Arc<Shared>) {
    loop {
        match listener.accept().await {
            Ok((c, _)) => {
                if c.peer_cred().map(|p| p.uid()).ok() == Some(unsafe { libc::geteuid() }) {
                    tokio::spawn(serve(c, sh.clone()));
                }
            }
            Err(e) => {
                warn!(error = %e, "broker accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// The pipe's first instance, created exclusively with the broker's security descriptor (sandbox_windows.rs).
#[cfg(windows)]
struct PipeListener {
    name: String,
    sd: crate::sandbox_windows::PipeSecurity,
    next: tokio::net::windows::named_pipe::NamedPipeServer,
}

#[cfg(windows)]
fn pipe_instance(name: &str, sd: &crate::sandbox_windows::PipeSecurity, first: bool)
                 -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let mut sa = sd.attributes();
    unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new().first_pipe_instance(first).reject_remote_clients(true)
            .create_with_security_attributes_raw(format!(r"\\.\pipe\{name}"), &mut sa as *mut _ as *mut std::ffi::c_void)
    }
}

#[cfg(windows)]
fn listen(name: &str, grant: &BrokerGrant) -> std::io::Result<PipeListener> {
    let sd = crate::sandbox_windows::PipeSecurity::for_module(&grant.sandbox_id).map_err(std::io::Error::other)?;
    let next = pipe_instance(name, &sd, true)?;
    Ok(PipeListener { name: name.to_string(), sd, next })
}

/// The pipe's DACL decides who may connect (the agent's account and the module's AppContainer: the same peers the
/// Unix socket admits); each connected instance is served while the next one waits.
#[cfg(windows)]
async fn accept(mut l: PipeListener, sh: Arc<Shared>) {
    loop {
        match l.next.connect().await {
            Ok(()) => match pipe_instance(&l.name, &l.sd, false) {
                Ok(fresh) => {
                    let c = std::mem::replace(&mut l.next, fresh);
                    tokio::spawn(serve(c, sh.clone()));
                }
                Err(e) => {
                    warn!(error = %e, "broker pipe instance failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            },
            Err(e) => {
                warn!(error = %e, "broker accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

impl Drop for Broker {
    /// Stop serving, cancel the running container, remove the socket; then, on a thread of its own so dropping never
    /// blocks the async runtime, wait for in-flight requests (their containers are being stopped) and remove every
    /// container labelled with the attempt.
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.task.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.bind);
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

#[cfg(test)]
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
            sets: vec![], job_images: vec![], gpu: false,
            workdir: base.join("work"), module_data: base.join("data"), network_granted: egress, cpus: 4.0, mem_gb: 8.0,
            #[cfg(windows)]
            sandbox_id: "dev.test.toy".into(),
        }
    }

    /// A fresh endpoint for one test broker: a socket in the test's directory, or a pipe name of its own.
    fn bind(t: &Tmp, name: &str) -> Bind {
        #[cfg(unix)]
        return t.0.join(name);
        #[cfg(windows)]
        return format!("oarbank-test-{}-{name}", t.0.file_name().unwrap().to_string_lossy());
    }

    /// A host path as the docker arguments spell it (the work and data directories are canonical, so verbatim on
    /// Windows).
    fn hp(p: &Path) -> String {
        p.to_string_lossy().to_string()
    }

    fn plan_spec(req: &Value, s: &Scope) -> Result<RunSpec, Refusal> {
        plan(req, s).map(|(spec, _)| spec)
    }

    fn verifier(base: &Path) -> Arc<Verifier> {
        Arc::new(Verifier::new(base.join("image-sets.json")).unwrap())
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
        let p = plan_spec(&r, &s).unwrap();
        assert_eq!(p.docker_args(), [
            "run", "--rm", "--platform", "linux/amd64", "--network", "bridge", "--cpus", "4", "--memory", "2.5g",
            "--label", "oarbank.attempt_id=42", "--label", "oarbank.module=toy",
            "-v", &format!("{}:/w:ro", hp(&s.work.join("inputs"))), "-v", &format!("{}:/cache", hp(&s.data.join("cache"))),
            "-v", &format!("{}:/out", hp(&s.work.join("out"))),
            "--workdir", "/w", "--entrypoint", "/bin/tool", "-e", "A_1=x y", "-e", "B=2", IMAGE, "tool", "--in", "/w/x",
        ]);
        assert_eq!(p.timeout_s, 100.0);
        assert!(s.work.join("out").is_dir());                      // created inside the work dir
        // defaults: no network, the whole reservation, the SDK's nulls
        let minimal = req(json!({"args": [], "entrypoint": null, "workdir": null, "cpus": null, "mem_gb": null, "mounts": [], "env": {},
                                 "network": false, "timeout_s": 3600}));
        assert_eq!(plan_spec(&minimal, &s).unwrap().docker_args(),
                   ["run", "--rm", "--platform", "linux/amd64", "--network", "none", "--cpus", "4", "--memory", "8g",
                    "--label", "oarbank.attempt_id=42", "--label", "oarbank.module=toy", IMAGE]);
    }

    #[test]
    fn refuses_unapproved_images_and_platforms() {
        let t = tmp();
        let s = scope(&t.0, false);
        let r = |i: &str, p: &str| code(plan_spec(&json!({"op": "container.run", "image": i, "platform": p, "args": []}), &s));
        assert_eq!(r(IMAGE, "linux/amd64"), None);
        assert_eq!(r(IMAGE, "linux/arm64").as_deref(), Some("image_not_approved"));
        assert_eq!(r("docker.io/org/tool:1.2", "linux/amd64").as_deref(), Some("image_not_approved"));
        assert_eq!(r(&format!("{IMAGE} "), "linux/amd64").as_deref(), Some("image_not_approved"));
        assert_eq!(r("org/tool@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "linux/amd64").as_deref(),
                   Some("image_not_approved"));                    // the exact approved spelling only
        assert_eq!(code(plan_spec(&json!({"op": "container.run", "platform": "linux/amd64"}), &s)).as_deref(), Some("bad_request"));
        assert_eq!(code(plan_spec(&json!({"op": "container.run", "image": IMAGE}), &s)).as_deref(), Some("image_not_approved"));
        assert_eq!(code(plan_spec(&json!({"op": "container.run", "image": 7, "platform": "linux/amd64"}), &s)).as_deref(), Some("bad_request"));
    }

    #[test]
    #[cfg(unix)]
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
        let m = |src: &str, dst: &str| code(plan_spec(&req(json!({"mounts": [{"src": src, "dst": dst}]})), &s));
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
        assert_eq!(code(plan_spec(&req(json!({"mounts": [{"src": "inputs"}]})), &s)).as_deref(), Some("bad_mount"));
        assert_eq!(code(plan_spec(&req(json!({"mounts": [{"src": "inputs", "dst": "/m", "ro": "yes"}]})), &s)).as_deref(), Some("bad_mount"));
        assert_eq!(code(plan_spec(&req(json!({"mounts": "inputs:/m"})), &s)).as_deref(), Some("bad_request"));
        assert!(!base.join("outside/sub").exists());
    }

    /// Windows: a junction (which any user may create) or a symlink out of the work or data directory leads nowhere,
    /// and the verbatim paths canonicalize returns compare correctly; mounts inside stay usable.
    #[test]
    #[cfg(windows)]
    fn refuses_junction_escapes_on_windows() {
        let t = tmp();
        let s = scope(&t.0, false);
        let base = std::fs::canonicalize(&t.0).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        let junction = |link: &Path, target: &Path| {
            let out = std::process::Command::new("cmd").args(["/c", "mklink", "/J"]).arg(link).arg(crate::wslc::host_path(target))
                .output().unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
        };
        junction(&s.work.join("escape"), &base.join("outside"));
        junction(&s.data.join("esc"), &s.work);
        junction(&s.data.join("inner"), &s.data.join("cache"));
        std::fs::write(s.work.join("inputs").join("a.txt"), "x").unwrap();
        let ok = |src: &str| code(plan_spec(&req(json!({"mounts": [{"src": src, "dst": "/m"}]})), &s));
        for good in ["inputs", ".", "data:cache", "data:inner", "inputs/a.txt", "data:new/dir"] {
            assert_eq!(ok(good), None, "{good}");
        }
        for bad in ["escape", "escape/sub", "data:esc", "../outside", r"inputs\..\..\outside", "C:/Windows", "c:x", "data:C:/x"] {
            assert_eq!(ok(bad).as_deref(), Some("bad_mount"), "{bad:?}");
        }
        assert!(!base.join("outside").join("sub").exists());
        let p = plan_spec(&req(json!({"mounts": [{"src": "inputs", "dst": "/m", "ro": true}]})), &s).unwrap();
        assert_eq!(p.mounts[0].host, s.work.join("inputs"));
    }

    #[test]
    fn refuses_network_without_grant_and_bad_fields_and_clamps_resources() {
        let t = tmp();
        let s = scope(&t.0, false);
        let r = |extra: Value| code(plan_spec(&req(extra), &s));
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
        let p = plan_spec(&req(json!({"cpus": 0, "mem_gb": 0, "timeout_s": -5})), &s).unwrap();
        let a = p.docker_args();
        assert!(a.contains(&"0.1".to_string()) && a.contains(&"0.25g".to_string()), "{a:?}");
        assert_eq!(p.timeout_s, DEFAULT_TIMEOUT_S);
        assert_eq!(plan_spec(&req(json!({"timeout_s": 0.2})), &s).unwrap().timeout_s, 1.0);
        let net = scope(&t.0, true);
        assert!(plan_spec(&req(json!({"network": true})), &net).unwrap().docker_args().windows(2).any(|w| w == ["--network", "bridge"]));
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
        let a = plan_spec(&hostile, &s).unwrap().docker_args();
        assert_eq!(a, plan_spec(&base, &s).unwrap().docker_args());    // unknown keys never reach the command
        let image_at = a.iter().position(|x| x == IMAGE).unwrap();
        let flags = &a[..image_at];
        assert!(!flags.iter().any(|x| x.contains("privileged") || x.contains("host") || x.contains("docker.sock")
                                  || x.starts_with("--cap") || x.starts_with("--security") || x.starts_with("--device")), "{flags:?}");
        let vols: Vec<&String> = flags.iter().zip(flags.iter().skip(1)).filter(|(f, _)| *f == "-v").map(|(_, v)| v).collect();
        assert_eq!(vols, [&format!("{}:/w", hp(&s.work.join("inputs")))]);
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
        gpu: Option<String>,
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
        fn gpu_device(&self) -> Option<String> {
            self.with(|s| s.gpu.clone())
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
        #[cfg(unix)]
        let mut c = tokio::net::UnixStream::connect(endpoint.strip_prefix("unix:").unwrap()).await.unwrap();
        #[cfg(windows)]
        let mut c = {
            let name = format!(r"\\.\pipe\{}", endpoint.strip_prefix("npipe://./pipe/").unwrap());
            // every instance busy: wait for the next one, as the SDK's client does
            loop {
                match tokio::net::windows::named_pipe::ClientOptions::new().open(&name) {
                    Ok(c) => break c,
                    Err(e) if e.raw_os_error() == Some(231) => tokio::time::sleep(Duration::from_millis(20)).await,
                    Err(e) => panic!("{name}: {e}"),
                }
            }
        };
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
        #[cfg(unix)]
        let sock = t.0.join("b/42.sock");
        #[cfg(windows)]
        let sock = bind(&t, "42");
        let b = Broker::start(sock.clone(), grant(&t.0, false), rt.clone(), verifier(&t.0)).await.unwrap();
        let ep = b.endpoint();
        #[cfg(unix)]
        {
            assert_eq!(ep, format!("unix:{}", sock.display()));
            let m = std::fs::symlink_metadata(&sock).unwrap();
            assert!(m.file_type().is_socket() && m.permissions().mode() & 0o777 == 0o600);
            assert_eq!(std::fs::metadata(t.0.join("b")).unwrap().permissions().mode() & 0o777, 0o700);
        }
        #[cfg(windows)]
        {
            assert_eq!(ep, format!("npipe://./pipe/{sock}"));
            // the name is taken: a second broker (or anyone else) cannot create the pipe's first instance
            assert!(Broker::start(sock.clone(), grant(&t.0, false), rt.clone(), verifier(&t.0)).await.is_err());
        }

        let r = ask(&ep, &req(json!({"args": ["echo"], "mounts": [{"src": "inputs", "dst": "/w", "ro": true}]})).to_string()).await;
        assert_eq!((r["ok"].as_bool(), r["exit_code"].as_i64()), (Some(true), Some(0)), "{r}");
        assert_eq!(r["stdout_tail"], "hello from the container\n");
        assert_eq!(r["stderr_tail"], "a warning\n");
        assert_eq!(r["stdout_path"], "broker/1.stdout");
        assert!(r["duration_s"].is_number());
        let work = std::fs::canonicalize(t.0.join("work")).unwrap();
        assert_eq!(std::fs::read_to_string(work.join("broker").join("1.stdout")).unwrap(), "hello from the container\n");
        let (args, timeout) = rt.with(|s| s.runs[0].clone());
        assert_eq!(timeout, DEFAULT_TIMEOUT_S);
        assert!(args.contains(&format!("{}:/w:ro", hp(&work.join("inputs")))) && args.contains(&"--rm".to_string()));

        // a pre-planted file or symlink is never written through: the next run takes another number
        #[cfg(unix)]
        std::os::unix::fs::symlink("/tmp/nope", work.join("broker/2.stdout")).unwrap();
        #[cfg(windows)]
        std::fs::write(work.join("broker").join("2.stdout"), "planted").unwrap();
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
        assert_eq!(st, json!({"ok": true, "running": true, "images": [IMAGE], "gpus": "none"}));
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
        assert_eq!(ask(&ep, r#"{"op": "status"}"#).await, json!({"ok": true, "running": false, "images": [], "gpus": "none"}));
        rt.with(|s| (s.running, s.start_fails) = (true, false));

        let sh = b.shared.clone();
        drop(b);
        #[cfg(unix)]
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

    /// Many clients at once, each closing as soon as its answer is read while the broker closes its end: on Windows the
    /// broker's pipe and the clients' are mio named pipes, whose reads failing right after they were submitted freed
    /// memory still in use before mio 1.2.4 (tokio-rs/mio#2014; the agent's tests died with STATUS_HEAP_CORRUPTION).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_broker_survives_many_clients_closing_at_once() {
        let t = tmp();
        let rt = Fake::running();
        let b = Broker::start(bind(&t, "many"), grant(&t.0, false), rt.clone(), verifier(&t.0)).await.unwrap();
        let ep = b.endpoint();
        let tasks: Vec<_> = (0..32).map(|_| {
            let ep = ep.clone();
            tokio::spawn(async move {
                for _ in 0..40 {
                    assert_eq!(ask(&ep, r#"{"op": "status"}"#).await["ok"], true);
                }
            })
        }).collect();
        for task in tasks {
            task.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_platform_the_runtime_cannot_run_is_unavailable() {
        let t = tmp();
        let rt = Fake::running();
        let mut g = grant(&t.0, false);
        g.approved_images.push((IMAGE.into(), "linux/riscv64".into()));
        let b = Broker::start(bind(&t, "p.sock"), g, rt.clone(), verifier(&t.0)).await.unwrap();
        let r = ask(&b.endpoint(), &json!({"op": "container.run", "image": IMAGE, "platform": "linux/riscv64"}).to_string()).await;
        assert_eq!(r["error"], "platform_unavailable");
        assert!(rt.with(|s| s.runs.is_empty()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_out_run_removes_its_container() {
        let t = tmp();
        let rt = Fake::running();
        rt.with(|s| s.time_out = true);
        let b = Broker::start(bind(&t, "t.sock"), grant(&t.0, false), rt.clone(), verifier(&t.0)).await.unwrap();
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
        let sock = bind(&t, "d.sock");
        let b = Broker::start(sock.clone(), grant(&t.0, false), rt.clone(), verifier(&t.0)).await.unwrap();
        let ep = b.endpoint();
        let pending = tokio::spawn(async move { ask(&ep, &req(json!({})).to_string()).await });
        eventually("the run to start", || rt.with(|s| !s.runs.is_empty())).await;
        drop(b);
        #[cfg(unix)]
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
        let b = Broker::start(bind(&t, "py.sock"), grant(&t.0, false), rt.clone(), verifier(&t.0)).await.unwrap();
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
        assert!(args.contains(&format!("{}:/c", hp(&data.join("cache")))) && args.contains(&"A=1".to_string()), "{args:?}");
        assert_eq!(args[args.len() - 3..], [IMAGE, "echo", "hi"]);
    }

    /// One approval (a set: prefix and key) covers any number of signed images: 500 distinct ones run through one
    /// broker, each verified against the local registry once, each reported for the coordinator's audit; an unsigned
    /// image, one outside the set and one the job did not list are refused with image_not_approved.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn five_hundred_signed_images_run_under_one_set_and_the_rest_are_refused() {
        use crate::imageset::tests::{serve, set, Key, Store};
        let t = tmp();
        let key = Key::new();
        let store = Arc::new(Mutex::new(Store { referrers_api: true, ..Default::default() }));
        let reg = serve(store.clone()).await;
        let mut images = vec![];
        {
            let mut s = store.lock().unwrap();
            for i in 0..500 {
                let path = format!("org/tasks/task-{i}");
                let d = s.image(&path, format!("task {i}").as_bytes());
                s.sign(&key, &reg, &path, &d, i % 2 == 1);         // both cosign formats
                images.push(format!("{reg}/{path}@{d}"));
            }
        }
        let unsigned = { store.lock().unwrap().image("org/tasks/unsigned", b"u") };
        let outside = { store.lock().unwrap().image("org/elsewhere", b"o") };
        let (unsigned, outside) = (format!("{reg}/org/tasks/unsigned@{unsigned}"), format!("{reg}/org/elsewhere@{outside}"));
        let not_listed = images.pop().unwrap();
        let mut g = grant(&t.0, false);
        g.sets = vec![set(&reg, &key, None)];
        g.job_images = images.iter().cloned().chain([unsigned.clone(), outside.clone()]).collect();
        let rt = Fake::running();
        let b = Broker::start(bind(&t, "s.sock"), g, rt.clone(), verifier(&t.0)).await.unwrap();
        let ep = b.endpoint();
        let run = |image: &str| json!({"op": "container.run", "image": image, "platform": "linux/amd64"}).to_string();
        for i in &images {
            let r = ask(&ep, &run(i)).await;
            assert_eq!(r["ok"], true, "{i}: {r}");
        }
        assert_eq!(rt.with(|s| s.runs.len()), 499);
        assert_eq!(b.ran_images().len(), 499);
        assert_eq!(b.ran_images()[0], json!({"set": "tasks", "image": images[0]}));
        for (img, why) in [(&unsigned, "no cosign signature"), (&outside, "not an approved image"), (&not_listed, "does not list it")] {
            let r = ask(&ep, &run(img)).await;
            assert_eq!(r["error"], "image_not_approved", "{img}: {r}");
            assert!(r["detail"].as_str().unwrap().contains(why), "{r}");
        }
        // verified once: running them all again asks the registry nothing
        let hits = store.lock().unwrap().hits;
        for i in images.iter().take(20) {
            assert_eq!(ask(&ep, &run(i)).await["ok"], true);
        }
        assert_eq!(store.lock().unwrap().hits, hits);
        assert_eq!(b.ran_images().len(), 499, "each image is reported once");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gpus_need_the_gpu_pool_and_a_runtime_that_passes_one_through() {
        let t = tmp();
        let rt = Fake::running();
        let b = Broker::start(bind(&t, "g.sock"), grant(&t.0, false), rt.clone(), verifier(&t.0)).await.unwrap();
        let ep = b.endpoint();
        assert_eq!(ask(&ep, &req(json!({"gpus": "all"})).to_string()).await["error"], "gpu_not_granted");
        assert_eq!(ask(&ep, &req(json!({"gpus": 1})).to_string()).await["error"], "bad_request");
        assert_eq!(ask(&ep, &req(json!({"gpus": "some"})).to_string()).await["error"], "bad_request");
        assert_eq!(ask(&ep, &req(json!({"gpus": "none"})).to_string()).await["ok"], true);
        drop(b);
        let mut g = grant(&t.0, false);
        g.gpu = true;
        let b = Broker::start(bind(&t, "g2.sock"), g, rt.clone(), verifier(&t.0)).await.unwrap();
        let ep = b.endpoint();
        assert_eq!(ask(&ep, &req(json!({"gpus": "all"})).to_string()).await["error"], "gpu_unavailable");
        rt.with(|s| s.gpu = Some("nvidia.com/gpu=all".into()));
        assert_eq!(ask(&ep, r#"{"op": "status"}"#).await["gpus"], "all");
        assert_eq!(ask(&ep, &req(json!({"gpus": "all"})).to_string()).await["ok"], true);
        let args = rt.with(|s| s.runs.last().unwrap().0.clone());
        assert!(args.windows(2).any(|w| w == ["--device", "nvidia.com/gpu=all"]), "{args:?}");
        drop(b);
        // a job that did not reserve the pool is told it cannot give its containers the GPU, on the same runtime
        let b = Broker::start(bind(&t, "g3.sock"), grant(&t.0, false), rt.clone(), verifier(&t.0)).await.unwrap();
        assert_eq!(ask(&b.endpoint(), r#"{"op": "status"}"#).await["gpus"], "none");
    }

    /// Plain HTTP/1.1 to a registry on 127.0.0.1 (the live test's pushes): (status, Location header).
    #[cfg(any(windows, target_os = "linux"))]
    async fn http(port: u16, method: &str, path: &str, ctype: &str, body: &[u8]) -> (u16, String) {
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\
                            Connection: close\r\n\r\n", body.len());
        c.write_all(head.as_bytes()).await.unwrap();
        c.write_all(body).await.unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out).await;
        let text = String::from_utf8_lossy(&out).to_string();
        let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let location = text.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.trim().to_string())).unwrap_or_default();
        (status, location)
    }

    /// The TCP ports listening on any or the loopback address in `/proc/net/tcp` and `/proc/net/tcp6` text.
    fn vm_listeners(text: &str) -> std::collections::HashSet<u16> {
        text.lines().filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (local, state) = (f.get(1)?, f.get(3)?);
            (*state == "0A").then_some(())?;
            u16::from_str_radix(local.rsplit(':').next()?, 16).ok()
        }).collect()
    }

    #[test]
    fn vm_listeners_read_proc_net_tcp() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                    0: 00000000:4E21 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n\
                    1: 0100007F:1F90 0100007F:D3C2 01 00000000:00000000 00:00000000 00000000     0        0 2 1\n\
                    0: 00000000000000000000000000000000:C350 00000000000000000000000000000000:0000 0A 0 0 0 0 0 3 1\n";
        assert_eq!(vm_listeners(text), [20001, 50000].into_iter().collect());
    }

    /// Push every blob and manifest of `store` into the real registry on `port` (the OCI distribution push: monolithic
    /// blob uploads, manifests by tag and by digest).
    #[cfg(any(windows, target_os = "linux"))]
    async fn push(store: &crate::imageset::tests::Store, port: u16, repos: &[&str]) {
        for repo in repos {
            for (digest, blob) in &store.blobs {
                let (st, loc) = http(port, "POST", &format!("/v2/{repo}/blobs/uploads/"), "application/octet-stream", b"").await;
                assert_eq!(st, 202, "upload start for {repo}");
                let loc = loc.strip_prefix(&format!("http://127.0.0.1:{port}")).unwrap_or(&loc).to_string();
                let sep = if loc.contains('?') { '&' } else { '?' };
                let (st, _) = http(port, "PUT", &format!("{loc}{sep}digest={digest}"), "application/octet-stream", blob).await;
                assert_eq!(st, 201, "blob {digest} into {repo}");
            }
        }
        for ((repo, reference), doc) in &store.manifests {
            let ctype = serde_json::from_slice::<Value>(doc).unwrap()["mediaType"].as_str().unwrap().to_string();
            let (st, _) = http(port, "PUT", &format!("/v2/{repo}/manifests/{reference}"), &ctype, doc).await;
            assert_eq!(st, 201, "manifest {repo}:{reference}");
        }
    }

    /// Windows with a GPU (OARBANK_LIVE_WSLC_GPU=1 besides the live test's variables): the session's VM has the GPU, the
    /// node offers the `gpu` pool, and a job that reserved it runs a `gpus = "all"` container (a glibc image) that sees
    /// the GPU-PV device and, on an NVIDIA host, CUDA's `nvidia-smi`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(windows)]
    #[ignore]
    async fn live_wslc_gives_a_gpu_container_the_gpu() {
        use crate::container_runtime::{ContainerRuntime, PROBE_GPU_IMAGE};
        use crate::wslc::WslcRuntime;
        if std::env::var("OARBANK_LIVE_WSLC_GPU").as_deref() != Ok("1") {
            eprintln!("set OARBANK_LIVE_WSLC_GPU=1 (and the live test's variables) on a machine with a GPU");
            return;
        }
        let sdk = PathBuf::from(std::env::var_os("OARBANK_WSLC_SDK").expect("OARBANK_WSLC_SDK names wslcsdk.dll"));
        let t = tmp();
        let rt = Arc::new(WslcRuntime::start_at(&t.0.join("agent"), sdk, 4.0, 2));
        let ready = { let r = rt.clone(); tokio::task::spawn_blocking(move || r.ensure_started()).await.unwrap() };
        assert!(ready.is_ok(), "the session is not ready: {ready:?}");
        let report = rt.snapshot().json();
        eprintln!("{report}");
        assert_eq!(rt.gpu_device().as_deref(), Some("microsoft.com/wslc=gpu"), "the session's VM has no GPU: {report}");
        assert_eq!(crate::agent::tests::pools_of(rt.clone()).get("gpu"), Some(&1));
        let (apis, evidence) = rt.snapshot().container_apis();
        eprintln!("GPU APIs in containers: {apis:?} ({evidence})");
        assert!(!apis.is_empty(), "{evidence}");
        let platform = rt.status().unwrap().platforms[0].clone();
        let mut g = grant(&t.0, false);
        g.approved_images = vec![(PROBE_GPU_IMAGE.into(), platform.clone())];
        g.gpu = true;
        let b = Broker::start(bind(&t, "gpu"), g, rt.clone(), verifier(&t.0)).await.unwrap();
        let script = "test -e /dev/dxg && echo dxg; if command -v nvidia-smi >/dev/null; then nvidia-smi -L; fi";
        let r = ask(&b.endpoint(), &json!({"op": "container.run", "image": PROBE_GPU_IMAGE, "platform": platform, "gpus": "all",
                                           "args": ["sh", "-c", script], "timeout_s": 600}).to_string()).await;
        assert_eq!((r["ok"].as_bool(), r["exit_code"].as_i64()), (Some(true), Some(0)), "{r}");
        let out = r["stdout_tail"].as_str().unwrap();
        assert!(out.contains("dxg"), "{r}");
        if apis.iter().any(|a| a == "cuda") {
            assert!(out.contains("GPU 0:"), "CUDA is listed, so nvidia-smi must name the GPU: {r}");
        }
    }

    /// Linux with an engine: the Windows live test's push helper against a real registry (`registry:3` in the engine,
    /// published on 127.0.0.1): what it pushes is there by digest, and a signed image verifies against it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[cfg(target_os = "linux")]
    async fn the_push_helper_fills_a_real_registry() {
        use crate::container_runtime::NativeRuntime;
        use crate::imageset::tests::{set, Key, Store};
        let t = tmp();
        let layout = crate::paths::Layout::new(t.0.join("agent"));
        let Some(rt) = NativeRuntime::detect(&layout, 16.0) else {
            eprintln!("no container engine here: skipped");
            return;
        };
        if !rt.status().is_ok_and(|s| s.running) {
            eprintln!("the engine is not running: skipped");
            return;
        }
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let name = format!("oarbank-push-test-{}", std::process::id());
        let image = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e";
        let cli = rt.cli.clone();
        let started = std::process::Command::new(&cli).env("HOME", &rt.home)
            .args(["run", "-d", "--rm", "--name", &name, "-p", &format!("127.0.0.1:{port}:5000"), image]).output().unwrap();
        assert!(started.status.success(), "{}", String::from_utf8_lossy(&started.stderr));
        for _ in 0..100 {
            if http(port, "GET", "/v2/", "text/plain", b"").await.0 == 200 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let reg = format!("127.0.0.1:{port}");
        let key = Key::new();
        let mut store = Store::default();
        let d = store.image("org/tasks/pushed", b"pushed layer");
        store.sign(&key, &reg, "org/tasks/pushed", &d, true);
        push(&store, port, &["org/tasks/pushed"]).await;
        let got = crate::imageset::Registry::new().unwrap().manifest(&format!("{reg}/org/tasks/pushed"), &d).await;
        let verified = verifier(&t.0).verify(&set(&reg, &key, None), &format!("{reg}/org/tasks/pushed@{d}"), "linux/amd64").await;
        let _ = std::process::Command::new(&cli).env("HOME", &rt.home).args(["rm", "-f", &name]).output();
        assert_eq!(got.unwrap().map(|(_, digest)| digest), Some(d));
        assert_eq!(verified, Ok(()));
    }

    /// Windows with WSL 2.9.3+ and the Virtual Machine Platform (OARBANK_LIVE_WSLC=1, OARBANK_WSLC_SDK=wslcsdk.dll; the
    /// account's %LOCALAPPDATA%\wslc\settings.yaml sets `session: hostLoopback: none`): the agent's own WSLc session in a
    /// scratch home runs a module's containers through the broker with Linux's semantics. A registry runs inside the
    /// session (host networking, so the Windows side and the session VM reach it at the same 127.0.0.1 port); a signed
    /// image of busybox's root filesystem is pushed to it, verified by the broker on the Windows side, pulled by digest by
    /// the session and run with a mount of the work directory, no network, the reservation's CPU and memory limits in
    /// its cgroup; an unsigned image in the same set and an unapproved one are refused before any pull; a granted
    /// network reaches the internet; the attempt's containers are gone once the broker is.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[cfg(windows)]
    #[ignore]
    async fn live_wslc_runs_a_signed_image_with_the_brokers_semantics() {
        use crate::container_runtime::{ContainerRuntime, PROBE_IMAGE};
        use crate::imageset::tests::{Key, Store};
        use crate::wslc::{decode, parse_ids, WslcRuntime};
        if std::env::var("OARBANK_LIVE_WSLC").as_deref() != Ok("1") {
            eprintln!("set OARBANK_LIVE_WSLC=1 and OARBANK_WSLC_SDK to run against the real WSL containers runtime");
            return;
        }
        let sdk = PathBuf::from(std::env::var_os("OARBANK_WSLC_SDK").expect("OARBANK_WSLC_SDK names wslcsdk.dll"));
        let t = tmp();
        let rt = Arc::new(WslcRuntime::start_at(&t.0.join("agent"), sdk, 4.0, 2));
        let ready = { let r = rt.clone(); tokio::task::spawn_blocking(move || r.ensure_started()).await.unwrap() };
        assert!(ready.is_ok(), "the session is not ready: {ready:?}\n{}", rt.snapshot().json());
        let platform = rt.status().unwrap().platforms.first().cloned().expect("the session's platform");
        let arch = platform.trim_start_matches("linux/").to_string();
        let cli = |args: Vec<String>| {
            let r = rt.clone();
            async move { tokio::task::spawn_blocking(move || r.cli(&args.iter().map(String::as_str).collect::<Vec<_>>(), 600)).await.unwrap().unwrap() }
        };
        // the registry, inside the session. A published port reaches the session VM on a port of WSLc's choosing, and the
        // session pulls from that one (its loopback is plain HTTP to the engine; WSLc has no host networking), so the
        // images are named after it and the test forwards the same port on Windows to the published one: the broker
        // verifies them on Windows and the session pulls them, both at one address
        let listeners = || {
            let r = rt.clone();
            async move {
                let out = tokio::task::spawn_blocking(move || r.cli(&["system", "session", "run", "/bin/sh", "-c", "cat /proc/net/tcp /proc/net/tcp6"], 120))
                    .await.unwrap().unwrap();
                vm_listeners(&decode(&out.stdout))
            }
        };
        let before = listeners().await;
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let registry = "docker.io/library/registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e";
        let r = cli(vec!["container".into(), "run".into(), "-d".into(), "--rm".into(), "-p".into(), format!("127.0.0.1:{port}:5000"),
                         "--label".into(), "oarbank.live-test=registry".into(), registry.into()]).await;
        assert!(r.ok(), "the registry: {}", decode(&r.stderr));
        for _ in 0..100 {
            if http(port, "GET", "/v2/", "text/plain", b"").await.0 == 200 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let new: Vec<u16> = listeners().await.difference(&before).copied().collect();
        let [vm_port] = new[..] else { panic!("the registry's port in the session VM: new listeners {new:?}") };
        let forward = tokio::net::TcpListener::bind(("127.0.0.1", vm_port)).await
            .unwrap_or_else(|e| panic!("127.0.0.1:{vm_port} on Windows (the session VM's port for the registry): {e}"));
        tokio::spawn(async move {
            while let Ok((mut c, _)) = forward.accept().await {
                tokio::spawn(async move {
                    if let Ok(mut up) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                    }
                });
            }
        });
        let (port, reg) = (vm_port, format!("127.0.0.1:{vm_port}"));
        // busybox's root filesystem for this platform, as a signed image of the set, and an unsigned one beside it
        let hub = crate::imageset::Registry::new().unwrap();
        let (index, _) = hub.manifest("docker.io/library/busybox", PROBE_IMAGE.split_once('@').unwrap().1).await.unwrap().unwrap();
        let index: Value = serde_json::from_slice(&index).unwrap();
        let m = index["manifests"].as_array().unwrap().iter().find(|m| m["platform"]["architecture"] == arch.as_str() && m["platform"]["os"] == "linux")
            .unwrap()["digest"].as_str().unwrap().to_string();
        let (manifest, _) = hub.manifest("docker.io/library/busybox", &m).await.unwrap().unwrap();
        let manifest: Value = serde_json::from_slice(&manifest).unwrap();
        let layer = hub.blob("docker.io/library/busybox", manifest["layers"][0]["digest"].as_str().unwrap()).await.unwrap();
        let mut tar = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&layer[..]), &mut tar).unwrap();
        let key = Key::new();
        let mut store = Store::default();
        let signed = store.rootfs_image("org/tasks/shell", &tar, &arch);
        store.sign(&key, &reg, "org/tasks/shell", &signed, true);
        let unsigned = store.image("org/tasks/unsigned", b"never pulled: refused before");
        push(&store, port, &["org/tasks/shell", "org/tasks/unsigned"]).await;
        let (signed, unsigned) = (format!("{reg}/org/tasks/shell@{signed}"), format!("{reg}/org/tasks/unsigned@{unsigned}"));
        let mut g = grant(&t.0, true);
        g.approved_images = vec![(PROBE_IMAGE.into(), platform.clone())];
        g.sets = vec![oarbank_core::images::ContainerSet { name: "tasks".into(), registry: reg.clone(), repository: "org/tasks/".into(),
                                                          platform: platform.clone(), key_pem: key.pem(), index: None }];
        g.job_images = vec![signed.clone(), unsigned.clone()];
        (g.cpus, g.mem_gb) = (1.0, 0.5);
        let b = Broker::start(bind(&t, "live"), g, rt.clone(), verifier(&t.0)).await.unwrap();
        let ep = b.endpoint();
        let script = "echo signed-ok > /w/written.txt; echo \"mem:$(cat /sys/fs/cgroup/memory.max)\"; echo \"cpu:$(cat /sys/fs/cgroup/cpu.max)\"; \
                      if wget -q -T 5 -O /dev/null http://example.com; then echo net:yes; else echo net:no; fi";
        let run = |image: &str, network: bool| json!({"op": "container.run", "image": image, "platform": platform, "args": ["sh", "-c", script],
                                                      "mounts": [{"src": "inputs", "dst": "/w"}], "network": network, "timeout_s": 600}).to_string();
        let r = ask(&ep, &run(&signed, false)).await;
        assert_eq!((r["ok"].as_bool(), r["exit_code"].as_i64()), (Some(true), Some(0)), "{r}");
        let out = r["stdout_tail"].as_str().unwrap();
        assert!(out.contains("mem:536870912") && out.contains("cpu:100000 100000") && out.contains("net:no"), "{r}");
        let work = std::fs::canonicalize(t.0.join("work")).unwrap();
        assert_eq!(std::fs::read_to_string(work.join("inputs").join("written.txt")).unwrap().trim(), "signed-ok");
        assert_eq!(b.ran_images(), vec![json!({"set": "tasks", "image": signed})]);
        // refusals, before anything is pulled
        assert_eq!(ask(&ep, &run(&unsigned, false)).await["error"], "image_not_approved");
        assert_eq!(ask(&ep, &run("docker.io/library/alpine:3.20", false)).await["error"], "image_not_approved");
        // the granted network, through the statically approved image
        let r = ask(&ep, &run(PROBE_IMAGE, true)).await;
        assert!(r["stdout_tail"].as_str().unwrap().contains("net:yes"), "{r}");
        drop(b);
        let gone = { let r = rt.clone(); tokio::task::spawn_blocking(move || {
            for _ in 0..100 {
                let ids = r.cli(&["container", "list", "--all", "--quiet", "--filter", "label=oarbank.attempt_id=42"], 60).unwrap();
                if parse_ids(&decode(&ids.stdout)).is_empty() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            false
        }).await.unwrap() };
        let ids = cli(vec!["container".into(), "list".into(), "--all".into(), "--quiet".into(), "--filter".into(), "label=oarbank.live-test".into()]).await;
        let regs = parse_ids(&decode(&ids.stdout));
        let _ = cli([vec!["container".to_string(), "rm".into(), "--force".into()], regs].concat()).await;
        assert!(gone, "the attempt's containers outlived the broker");
    }

    /// Linux with an engine: a signed image of the host's own shell, served by a local registry, verified by the broker
    /// and then pulled by digest and run by the real engine; an unsigned one in the same set is refused before any pull.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[cfg(target_os = "linux")]
    async fn a_signed_image_from_a_registry_is_verified_pulled_and_run_by_the_real_engine() {
        use crate::container_runtime::{tests::host_rootfs, NativeRuntime};
        use crate::imageset::tests::{serve, Key, Store};
        let t = tmp();
        let layout = crate::paths::Layout::new(t.0.join("agent"));
        let Some(mut rt) = NativeRuntime::detect(&layout, 16.0) else {
            eprintln!("no container engine here: skipped");
            return;
        };
        // a private engine home: its own storage and run state (the reset below removes only those), and the local
        // registry allowed over plain HTTP
        rt.home = t.0.join("engine-home");
        crate::container_runtime::tests::private_engine(&rt.home);
        let tar = t.0.join("rootfs.tar");
        host_rootfs(&tar);
        let key = Key::new();
        let store = Arc::new(Mutex::new(Store { referrers_api: true, ..Default::default() }));
        let reg = serve(store.clone()).await;
        std::fs::create_dir_all(rt.home.join(".config/containers")).unwrap();
        std::fs::write(rt.home.join(".config/containers/registries.conf"),
                       format!("[[registry]]\nlocation = \"{reg}\"\ninsecure = true\n")).unwrap();
        if !rt.status().is_ok_and(|s| s.running) {
            eprintln!("the engine is not running: skipped");
            return;
        }
        let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
        let platform = format!("linux/{arch}");
        let (signed, unsigned) = {
            let mut s = store.lock().unwrap();
            let bytes = std::fs::read(&tar).unwrap();
            let d = s.rootfs_image("org/tasks/shell", &bytes, arch);
            s.sign(&key, &reg, "org/tasks/shell", &d, false);
            let u = s.image("org/tasks/unsigned", b"never pulled: refused before");
            (format!("{reg}/org/tasks/shell@{d}"), format!("{reg}/org/tasks/unsigned@{u}"))
        };
        let (cli, engine_home) = (rt.cli.clone(), rt.home.clone());
        let mut g = grant(&t.0, false);
        g.approved_images = vec![];
        g.sets = vec![oarbank_core::images::ContainerSet { name: "tasks".into(), registry: reg.clone(), repository: "org/tasks/".into(),
                                                          platform: platform.clone(), key_pem: key.pem(), index: None }];
        g.job_images = vec![signed.clone(), unsigned.clone()];
        let b = Broker::start(t.0.join("live.sock"), g, Arc::new(rt), verifier(&t.0)).await.unwrap();
        let ep = b.endpoint();
        let r = ask(&ep, &json!({"op": "container.run", "image": signed, "platform": platform, "args": ["sh", "-c", "echo signed-ok"],
                                 "timeout_s": 120}).to_string()).await;
        assert_eq!(r["ok"], true, "{r}");
        assert_eq!(r["exit_code"], 0, "{r}");
        assert!(r["stdout_tail"].as_str().unwrap().contains("signed-ok"), "{r}");
        let r = ask(&ep, &json!({"op": "container.run", "image": unsigned, "platform": platform, "args": ["true"]}).to_string()).await;
        assert_eq!(r["error"], "image_not_approved", "{r}");
        assert_eq!(b.ran_images(), vec![json!({"set": "tasks", "image": signed})]);
        drop(b);
        // the broker removes the attempt's containers on a thread of its own: wait for them before the storage goes
        for _ in 0..100 {
            let left = std::process::Command::new(&cli).env("HOME", &engine_home).args(["ps", "-aq", "--filter", "label=oarbank.attempt_id=42"])
                .output().map(|o| o.stdout.is_empty()).unwrap_or(true);
            if left {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        crate::container_runtime::tests::remove_private_engine(&cli, &engine_home);
    }
}
