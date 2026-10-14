//! The agent's container runtime (spec/sandbox.md, "Containers"; docs/design/module-sandbox.md, decision 3). Modules
//! never reach Docker: the broker validates their requests and hands this runtime a finished `RunSpec`. On macOS the
//! runtime is an agent-owned Colima profile, `oarbank`, whose VM mounts only the agent's work and modules-data
//! directories (Colima's default profile mounts `$HOME` writable, so its socket is the whole home), and GPU containers
//! run in a second one, `oarbank-gpu`, on krunkit (docs/design/gpu-placement.md). Linux uses the host's engine; Windows
//! an agent-owned WSL containers session (wslc.rs, docs/design/windows-containers.md).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "macos")]
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The label carrying the attempt id on every container the broker starts: an attempt's containers are found, and
/// removed, by it.
pub const ATTEMPT_LABEL: &str = "oarbank.attempt_id";
pub const MODULE_LABEL: &str = "oarbank.module";

/// Whether the runtime can run containers now.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeStatus {
    pub running: bool,
    /// The VM's actual memory, when running.
    pub mem_gb: Option<f64>,
    /// OCI platforms the runtime can run (`linux/arm64`, and `linux/amd64` under Rosetta).
    pub platforms: Vec<String>,
    /// Why it is not running, when known.
    pub detail: Option<String>,
}

/// One validated bind mount: `host` is a resolved directory inside the work or module-data directory.
#[derive(Debug, Clone, PartialEq)]
pub struct Mount {
    pub host: PathBuf,
    pub dst: String,
    pub ro: bool,
}

/// A validated `container.run` (built only by the broker): everything `docker run` gets, and where its output goes.
#[derive(Debug)]
pub struct RunSpec {
    pub image: String,
    pub platform: String,
    pub args: Vec<String>,
    pub entrypoint: Option<String>,
    pub mounts: Vec<Mount>,
    /// Sorted by key.
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub network: bool,
    pub cpus: f64,
    pub mem_gb: f64,
    pub attempt_id: i64,
    pub module: String,
    pub timeout_s: f64,
    /// The full output, opened by the broker inside the work directory (None: discarded).
    pub stdout: Option<std::fs::File>,
    pub stderr: Option<std::fs::File>,
    /// Every GPU of the node, as the `--device` value the runtime passes them with (`nvidia.com/gpu=all`, `/dev/dri`).
    pub gpu_device: Option<String>,
}

/// `2.50` -> `2.5`, `4.00` -> `4`.
pub fn fmt_num(v: f64) -> String {
    let s = format!("{v:.2}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

impl RunSpec {
    /// Exactly: `run --rm --platform P --network none|bridge --cpus C --memory Mg --label oarbank.attempt_id=<id>
    /// --label oarbank.module=<name> [--device <gpu device>] [-v src:dst[:ro]]... [--workdir W] [--entrypoint E]
    /// [-e K=V]... image args...`.
    /// Nothing from the request reaches a flag position except through these fields.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn docker_args(&self) -> Vec<String> {
        self.docker_args_with(&self.image)
    }

    /// The same, naming the image as `image` (a runtime that needs it spelled differently: see [`qualified`]).
    pub fn docker_args_with(&self, image: &str) -> Vec<String> {
        let mut a: Vec<String> = vec![
            "run".into(), "--rm".into(), "--platform".into(), self.platform.clone(),
            "--network".into(), if self.network { "bridge" } else { "none" }.into(),
            "--cpus".into(), fmt_num(self.cpus), "--memory".into(), format!("{}g", fmt_num(self.mem_gb)),
            "--label".into(), format!("{ATTEMPT_LABEL}={}", self.attempt_id), "--label".into(), format!("{MODULE_LABEL}={}", self.module),
        ];
        if let Some(dev) = self.gpu_device.as_deref().filter(|k| !k.is_empty()) {
            a.extend(["--device".into(), dev.to_string()]);
        }
        for m in &self.mounts {
            a.push("-v".into());
            a.push(format!("{}:{}{}", m.host.to_string_lossy(), m.dst, if m.ro { ":ro" } else { "" }));
        }
        if let Some(w) = &self.workdir {
            a.extend(["--workdir".into(), w.clone()]);
        }
        if let Some(e) = &self.entrypoint {
            a.extend(["--entrypoint".into(), e.clone()]);
        }
        for (k, v) in &self.env {
            a.extend(["-e".into(), format!("{k}={v}")]);
        }
        a.push(image.to_string());
        a.extend(self.args.iter().cloned());
        a
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunResult {
    pub exit_code: i32,
    pub timed_out: bool,
    pub cancelled: bool,
}

/// What the broker needs from the agent's container runtime (a fake in tests). Calls block; the broker runs them
/// on blocking threads.
pub trait ContainerRuntime: Send + Sync {
    /// Whether the runtime is usable now (Err: it cannot be used on this node at all, and why).
    fn status(&self) -> Result<RuntimeStatus, String>;
    /// Start the runtime if it is not running.
    fn ensure_started(&self) -> Result<(), String>;
    /// Make sure `image` is present for `platform`.
    fn pull(&self, image: &str, platform: &str) -> Result<(), String>;
    /// Run to completion; the caller already validated everything. On timeout or `cancel` the container CLI gets
    /// SIGTERM (it forwards it to the container), then SIGKILL.
    fn run(&self, spec: &RunSpec, cancel: &AtomicBool) -> Result<RunResult, String>;
    /// Image references present on the runtime, as `repository@sha256:<digest>`.
    fn images(&self) -> Vec<String>;
    /// Remove every container carrying the attempt label (at agent start, when no attempt is live); the ids removed.
    fn reap(&self) -> Vec<String>;
    /// Remove every container labelled with this attempt; the ids removed.
    fn remove_attempt(&self, attempt_id: i64) -> Vec<String>;
    /// The `containers` pool this runtime offers.
    fn pool_tokens(&self) -> u32 {
        0
    }
    /// The `--device` value through which containers get every GPU of the node (None: no passthrough here).
    fn gpu_device(&self) -> Option<String> {
        None
    }
    /// The runtime's own report for the facts' `containers`, when it keeps one (Windows: its session's state). A change
    /// makes the agent send its facts again.
    fn report(&self) -> Option<serde_json::Value> {
        None
    }
    /// Check the runtime's prerequisites again when it is not ready (the agent's doctors run again: a release, a restart).
    /// A runtime that backs off after failed starts keeps its backoff here.
    fn recheck(&self) {}
    /// The owner asked for a fresh look (a `run_doctor` directive, Re-detect): as `recheck`, whatever backoff the runtime
    /// keeps after failed starts.
    fn retry(&self) {
        self.recheck()
    }
    /// The agent's periodic re-probe (`RUNTIME_REPROBE`): a runtime missing a prerequisite looks for it again, since the
    /// owner may have installed it since (2.10.3 looked only at a release or restart). Cheap: file checks.
    fn reprobe(&self) {
        if self.report().is_some_and(|r| r["state"] == "missing") {
            self.recheck()
        }
    }
    /// The agent is stopping: leave the runtime so the next agent can start it (macOS: stop the VMs, within `budget`).
    fn shutdown(&self, _budget: Duration) {}
}

/// How often the agent re-probes a runtime that is missing a prerequisite (or, on macOS, whose start failed and whose
/// backoff has run out): `ContainerRuntime::reprobe`.
pub const RUNTIME_REPROBE: Duration = Duration::from_secs(60);
/// What a stopping agent gives its VMs to stop (graceful, then forced), within the service managers' 60 s stop timeout
/// after the runners' STOP_GRACE and STOP_REPORT (agent.rs).
pub const VM_STOP_BUDGET: Duration = Duration::from_secs(25);

/// The node's container runtimes: `cpu` runs every container, `gpu` the containers of jobs that reserved the agent's
/// `gpu` pool (the same runtime on Linux, the krunkit VM on macOS; None where containers cannot get the GPU).
#[derive(Clone)]
pub struct Containers {
    pub cpu: std::sync::Arc<dyn ContainerRuntime>,
    pub gpu: Option<std::sync::Arc<dyn ContainerRuntime>>,
}

impl Containers {
    /// The runtime an attempt's broker uses: the GPU runtime for a job that reserved the `gpu` pool, when there is one.
    pub fn for_job(&self, gpu: bool) -> std::sync::Arc<dyn ContainerRuntime> {
        match (&self.gpu, gpu) {
            (Some(g), true) => g.clone(),
            _ => self.cpu.clone(),
        }
    }

    /// Each distinct runtime once (on Linux `gpu` is `cpu`).
    pub fn all(&self) -> Vec<std::sync::Arc<dyn ContainerRuntime>> {
        let mut v = vec![self.cpu.clone()];
        if let Some(g) = self.gpu.as_ref().filter(|g| !std::sync::Arc::ptr_eq(g, &self.cpu)) {
            v.push(g.clone());
        }
        v
    }
}

/// How containers on this node get the GPU (docs/design/gpu-placement.md): the facts' `containers.gpu`, the `--device`
/// value, and the GPU APIs a container then has (Linux; macOS reports it from its runtime's state, crate::colima).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq)]
pub struct Passthrough {
    /// `cdi:<kind>`.
    pub kind: String,
    pub device: String,
    pub apis: Vec<String>,
    /// What was found, for the doctor report's evidence.
    pub evidence: String,
}

/// A CDI spec with an `all` device: its kind and the GPU APIs a container given that device has.
#[derive(Debug, Clone, PartialEq)]
pub struct CdiSpec {
    pub kind: String,
    pub apis: Vec<String>,
}

/// The first spec in `dirs` (the directories in order, each one's files by name) that declares a device named `all`, as
/// `nvidia-ctk cdi generate` writes. JSON specs are parsed; YAML specs are read by their top-level `kind:` line, a device
/// `name: all` and their `path:`, `hostPath:` and `containerPath:` values (the only facts needed), without a YAML parser.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn cdi_spec(dirs: &[&Path]) -> Option<CdiSpec> {
    let files = dirs.iter().flat_map(|d| {
        let mut fs: Vec<PathBuf> = std::fs::read_dir(d).into_iter().flatten().flatten().map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json" || x == "yaml" || x == "yml")).collect();
        fs.sort();
        fs
    });
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        if f.extension().is_some_and(|x| x == "json") {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
            let all = v["devices"].as_array().is_some_and(|ds| ds.iter().any(|d| d["name"] == "all"));
            if let (true, Some(k)) = (all, v["kind"].as_str()) {
                let mut paths = vec![];
                json_paths(&v, &mut paths);
                return Some(CdiSpec { kind: k.to_string(), apis: cdi_apis(k, &paths) });
            }
            continue;
        }
        let unq = |s: &str| s.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
        let kind = text.lines().find_map(|l| l.strip_prefix("kind:")).map(unq);
        let field = |l: &str, k: &str| l.trim().trim_start_matches("- ").strip_prefix(k).map(unq);
        let all = text.lines().any(|l| field(l, "name:").is_some_and(|v| v == "all"));
        if let (true, Some(k)) = (all, kind.filter(|k| k.contains('/'))) {
            let paths: Vec<String> = text.lines()
                .filter_map(|l| field(l, "path:").or_else(|| field(l, "hostPath:")).or_else(|| field(l, "containerPath:"))).collect();
            return Some(CdiSpec { apis: cdi_apis(&k, &paths), kind: k });
        }
    }
    None
}

fn json_paths(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                match (k.as_str(), x.as_str()) {
                    ("path" | "hostPath" | "containerPath", Some(p)) => out.push(p.to_string()),
                    _ => json_paths(x, out),
                }
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| json_paths(x, out)),
        _ => {}
    }
}

/// The GPU APIs a container given a CDI spec's devices has (docs/design/gpu-placement.md, "In containers"): an NVIDIA
/// spec gives `cuda` when it mounts `libcuda.so` (also over WSL2's `/dev/dxg`), `vulkan` when it mounts the NVIDIA
/// Vulkan ICD and `opencl` when it mounts `libnvidia-opencl`; another kind gives `rocm` with `/dev/kfd` and `vulkan`
/// with a DRM render node (the image brings Mesa).
pub fn cdi_apis(kind: &str, paths: &[String]) -> Vec<String> {
    let any = |f: &dyn Fn(&str) -> bool| paths.iter().any(|p| f(p));
    let mut apis = vec![];
    if kind.starts_with("nvidia.com/") {
        if any(&|p| p.contains("libcuda.so")) {
            apis.push("cuda");
        }
        if any(&|p| p.contains("libnvidia-opencl")) {
            apis.push("opencl");
        }
        if any(&|p| p.ends_with("nvidia_icd.json")) {
            apis.push("vulkan");
        }
    } else {
        if any(&|p| p == "/dev/kfd") {
            apis.push("rocm");
        }
        if any(&|p| p.starts_with("/dev/dri/renderD")) {
            apis.push("vulkan");
        }
    }
    apis.into_iter().map(String::from).collect()
}

/// Where CDI specs live (the CDI specification's static and dynamic directories).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const CDI_DIRS: [&str; 2] = ["/etc/cdi", "/var/run/cdi"];

/// `docker.io/org/tool:1.2@sha256:x` and `org/tool@sha256:x` name the same image: (canonical repository, digest).
pub fn image_key(reference: &str) -> (String, String) {
    let (name, digest) = reference.split_once('@').unwrap_or((reference, ""));
    let last = name.rfind('/').map(|i| i + 1).unwrap_or(0);
    let repo = match name[last..].find(':') {
        Some(i) => &name[..last + i],
        None => name,
    };
    let repo = repo.strip_prefix("index.docker.io/").map(|r| format!("docker.io/{r}")).unwrap_or_else(|| repo.to_string());
    let first = repo.split('/').next().unwrap_or("");
    let registry = repo.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost");
    let repo = if registry {
        repo
    } else if repo.contains('/') {
        format!("docker.io/{repo}")
    } else {
        format!("docker.io/library/{repo}")
    };
    (repo, digest.to_string())
}

/// A reference with its registry spelled out as Docker resolves a short name (docker.io, and library/ for a one-part
/// name), its tag and digest kept. Modules approve images in Docker's form (`genonet/hap-py@sha256:…`), and Podman
/// refuses a short name unless the host configures unqualified-search registries, which a default install does not.
#[cfg(any(target_os = "linux", windows, test))]
pub fn qualified(reference: &str) -> String {
    let (name, digest) = match reference.split_once('@') {
        Some((n, d)) => (n, Some(d)),
        None => (reference, None),
    };
    let first = name.split('/').next().unwrap_or("");
    let has_registry = name.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost");
    let full = if has_registry {
        name.to_string()
    } else if name.contains('/') {
        format!("docker.io/{name}")
    } else {
        format!("docker.io/library/{name}")
    };
    match digest {
        Some(d) => format!("{full}@{d}"),
        None => full,
    }
}

// MARK: helper processes

/// Where a helper's output goes.
pub enum Out {
    Capture,
    File(std::fs::File),
    Null,
}

#[derive(Debug, Default)]
pub struct Exec {
    pub code: i32,
    pub timed_out: bool,
    pub cancelled: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Exec {
    pub fn ok(&self) -> bool {
        self.code == 0 && !self.timed_out && !self.cancelled
    }
    #[cfg_attr(windows, allow(dead_code))]
    pub fn stderr_tail(&self, n: usize) -> String {
        let s = String::from_utf8_lossy(&self.stderr);
        let t = s.trim_end();
        let mut i = t.len().saturating_sub(n);
        while !t.is_char_boundary(i) {
            i += 1;
        }
        t[i..].to_string()
    }
}

fn stdio(o: &Out) -> std::io::Result<Stdio> {
    Ok(match o {
        Out::Capture => Stdio::piped(),
        Out::File(f) => Stdio::from(f.try_clone()?),
        Out::Null => Stdio::null(),
    })
}

fn drain<R: Read + Send + 'static>(r: Option<R>) -> Option<std::thread::JoinHandle<Vec<u8>>> {
    r.map(|mut r| std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = r.read_to_end(&mut b);
        b
    }))
}

/// Run a helper in its own process group with exactly `env`. On timeout or cancel the group gets SIGTERM, then
/// SIGKILL `grace` later.
pub fn exec(argv: &[String], env: &[(String, String)], timeout: Duration, out: Out, err: Out, cancel: &AtomicBool,
            grace: Duration) -> Result<Exec, String> {
    use crate::sys::Sig;
    let (prog, rest) = argv.split_first().ok_or("empty argv")?;
    let mut cmd = Command::new(prog);
    // Windows: an empty pipe, closed at once, rather than NUL: NUL is a character device, which a console program
    // (wslc) takes for a console and fails to read (ERROR_INVALID_HANDLE)
    #[cfg(unix)]
    let input = Stdio::null();
    #[cfg(windows)]
    let input = Stdio::piped();
    cmd.args(rest).env_clear().envs(env.iter().map(|(k, v)| (k, v))).stdin(input)
        .stdout(stdio(&out).map_err(|e| e.to_string())?).stderr(stdio(&err).map_err(|e| e.to_string())?);
    let mut child = crate::sys::spawn_contained(&mut cmd, false).map_err(|e| format!("{prog}: {e}"))?;
    drop(child.stdin.take());
    let pid = child.id() as i32;
    let (ro, re) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let start = Instant::now();
    let mut r = Exec::default();
    let mut term_at: Option<Instant> = None;
    let status = loop {
        if let Ok(Some(s)) = child.try_wait() {
            break s;
        }
        if term_at.is_none() && (start.elapsed() > timeout || cancel.load(Ordering::SeqCst)) {
            r.timed_out = start.elapsed() > timeout;
            r.cancelled = !r.timed_out;
            crate::sys::signal_group(pid, Sig::Term);
            term_at = Some(Instant::now());
        }
        if term_at.is_some_and(|t| t.elapsed() > grace) {
            crate::sys::signal_group(pid, Sig::Kill);
            let _ = child.kill();
            match child.wait() {
                Ok(s) => break s,
                Err(e) => return Err(e.to_string()),
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    crate::sys::release(pid);
    #[cfg(unix)]
    {
        r.code = status.code().unwrap_or_else(|| 128 + crate::sys::exit_signal(&status).unwrap_or(0));
    }
    #[cfg(windows)]
    {
        r.code = status.code().unwrap_or(1);
    }
    r.stdout = ro.and_then(|h| h.join().ok()).unwrap_or_default();
    r.stderr = re.and_then(|h| h.join().ok()).unwrap_or_default();
    Ok(r)
}

pub fn quick(argv: &[String], env: &[(String, String)], timeout_s: u64) -> Result<Exec, String> {
    exec(argv, env, Duration::from_secs(timeout_s), Out::Capture, Out::Capture, &AtomicBool::new(false), Duration::from_secs(5))
}

/// Remove every container `ps` lists for `filter` (a label filter); the ids removed.
#[cfg(unix)]
fn remove_labelled(cli: impl Fn(&[&str], u64) -> Result<Exec, String>, filter: &str) -> Vec<String> {
    let Ok(r) = cli(&["ps", "-aq", "--filter", filter], 20) else { return vec![] };
    let ids: Vec<String> = String::from_utf8_lossy(&r.stdout).lines().map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('-')).map(str::to_string).collect();
    if !ids.is_empty() {
        let mut args = vec!["rm", "-f"];
        args.extend(ids.iter().map(String::as_str));
        let _ = cli(&args, 60);
    }
    ids
}

/// The container VM (or engine) memory budget by host RAM: <= 32 GB: 8, >= 96 GB: 32, else 12; the owner's cap
/// replaces it. CPUs: the owner's, else 8 on >= 96 GB and 6 otherwise. Tokens: floor((M - 1.5) / 2.5).
pub fn sizing(ram_gb: f64, vm_mem_gb: Option<f64>, vm_cpus: Option<u32>) -> (f64, u32, u32) {
    let def_mem = if ram_gb <= 32.0 { 8.0 } else if ram_gb >= 96.0 { 32.0 } else { 12.0 };
    let mem = vm_mem_gb.map(|m| m.max(0.0)).unwrap_or(def_mem);
    let cpus = vm_cpus.unwrap_or(if ram_gb >= 96.0 { 8 } else { 6 }).max(1);
    (mem, cpus, tokens(mem))
}

/// The `containers` pool a runtime with this much memory offers.
pub fn tokens(mem_gb: f64) -> u32 {
    ((mem_gb - 1.5) / 2.5).floor().max(0.0) as u32
}

#[cfg(unix)]
fn executable(p: &Path) -> bool {
    std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0)
}

/// Where a Linux container engine keeps its configuration and (rootless Podman) its storage: the account's own home
/// when this process may write it (the personal scope), else the agent's home. A system install's `oarbank` account has
/// the home /var/lib/oarbank, which is root's: rootless Podman cannot create its configuration there and every command
/// fails ("stat /var/lib/oarbank/.config: no such file or directory").
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn engine_home(account_home: Option<PathBuf>, agent_home: &Path) -> PathBuf {
    let writable = |p: &Path| p.is_dir() && std::ffi::CString::new(p.as_os_str().as_encoded_bytes())
        .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0);
    account_home.filter(|h| writable(h)).unwrap_or_else(|| agent_home.to_path_buf())
}

// MARK: Colima

/// Which of the agent's two Colima profiles: `oarbank` runs every container on Virtualization.framework (with Rosetta on
/// Apple silicon); `oarbank-gpu` runs the containers of GPU jobs on krunkit, whose virtio-gpu device gives them Vulkan on
/// the Mac's GPU (Mesa's Venus driver in the container, MoltenVK on the host; docs/design/gpu-placement.md).
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Cpu,
    Gpu,
}

#[cfg(target_os = "macos")]
impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Profile::Cpu => crate::colima::CPU_PROFILE,
            Profile::Gpu => crate::colima::GPU_PROFILE,
        }
    }
}

/// The report both profiles of one agent share (the facts' `containers`, crate::colima::Report), and the agent home
/// its state file lives in.
#[cfg(target_os = "macos")]
pub struct MacShared {
    report: Mutex<crate::colima::Report>,
    agent_home: PathBuf,
    /// Write the state file (the agent; a CLI's probe leaves the running agent's report alone).
    publish: bool,
    retry: Mutex<Retry>,
}

/// The CPU profile's failed starts since it was last ready: when the runtime tries by itself again
/// (crate::colima::retry_after), and how many stale instances it cleared (crate::colima::MAX_RECOVERIES).
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
struct Retry {
    failures: u32,
    not_before: Option<Instant>,
    recoveries: u32,
}

#[cfg(target_os = "macos")]
impl MacShared {
    fn snapshot(&self) -> crate::colima::Report {
        self.report.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn update(&self, f: impl FnOnce(&mut crate::colima::Report)) {
        let mut g = self.report.lock().unwrap_or_else(|e| e.into_inner());
        let before = g.clone();
        f(&mut g);
        if *g != before && self.publish {
            let _ = crate::fsutil::write_private(&crate::colima::report_file(&self.agent_home),
                                                 &serde_json::to_vec_pretty(&g.state_json()).unwrap_or_default());
        }
    }

    fn new(report: crate::colima::Report, agent_home: PathBuf, publish: bool) -> MacShared {
        MacShared { report: Mutex::new(report), agent_home, publish, retry: Mutex::new(Retry::default()) }
    }

    fn retry(&self) -> std::sync::MutexGuard<'_, Retry> {
        self.retry.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A start failed: the next one by itself waits longer. Returns that wait.
    fn failed(&self) -> Duration {
        let mut r = self.retry();
        r.failures += 1;
        let wait = crate::colima::retry_after(r.failures);
        r.not_before = Some(Instant::now() + wait);
        wait
    }

    /// The profile is ready, or the owner asked: no backoff, and stale instances may be cleared again.
    fn reset(&self) {
        *self.retry() = Retry::default();
    }

    /// Whether a failed profile may be started again by itself now.
    fn retry_due(&self) -> bool {
        self.retry().not_before.is_none_or(|t| Instant::now() >= t)
    }

    /// One more stale-instance recovery, unless MAX_RECOVERIES in a row were tried already.
    fn take_recovery(&self) -> Option<u32> {
        let mut r = self.retry();
        (r.recoveries < crate::colima::MAX_RECOVERIES).then(|| {
            r.recoveries += 1;
            r.recoveries
        })
    }
}

/// One of the agent-owned Colima profiles (docs/design/macos-containers.md). Only these profiles are ever started or
/// queried. Colima runs with an environment of its own: the helper `PATH` (Homebrew's directories whatever launchd's
/// PATH is), `HOME` and `COLIMA_HOME` where the agent's account may write (crate::colima::dirs: a system install's
/// account home belongs to root), and an empty `DOCKER_CONFIG` of the agent's own, so neither the user's current docker
/// context nor `~/.docker` (contexts, credential helpers that reach the keychain) is used.
#[cfg(target_os = "macos")]
#[derive(Clone)]
pub struct ColimaRuntime {
    pub profile: Profile,
    pub dirs: crate::colima::Dirs,
    /// The only two host directories the VM mounts.
    pub work: PathBuf,
    pub modules_data: PathBuf,
    pub docker_config: PathBuf,
    pub log: PathBuf,
    pub vm_cpus: u32,
    pub vm_mem_gb: f64,
    /// Apple silicon (Rosetta, krunkit).
    pub arm: bool,
    /// Where colima, docker, limactl and krunkit are looked up (Homebrew's directories, then PATH's; tests: a scratch
    /// directory of fakes), and the file whose presence means Rosetta 2 is installed.
    tools: Vec<PathBuf>,
    rosetta: PathBuf,
    start_lock: std::sync::Arc<Mutex<()>>,
    shared: std::sync::Arc<MacShared>,
}

/// The DRM render node a krunkit guest's virtio-gpu device appears as.
#[cfg(target_os = "macos")]
const RENDER_NODE: &str = "/dev/dri/renderD128";

#[cfg(target_os = "macos")]
fn realpath(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// What the agent finds on this Mac now, before it brings the runtime up (`absent`, or `missing` with each fix).
#[cfg(target_os = "macos")]
pub fn mac_report_now(agent_home: &Path) -> crate::colima::Report {
    crate::colima::Report::of(&crate::colima::detect(agent_home), crate::colima::State::Absent)
}

#[cfg(target_os = "macos")]
impl ColimaRuntime {
    /// One profile with a report of its own (tests, the live tests); `pair` shares one between both.
    #[cfg(test)]
    pub fn new(layout: &crate::paths::Layout, profile: Profile) -> Self {
        let host = crate::colima::detect(&layout.home);
        let shared = std::sync::Arc::new(MacShared::new(crate::colima::Report::of(&host, crate::colima::State::Absent), layout.home.clone(), false));
        Self::with(layout, profile, host.dirs, shared)
    }

    fn with(layout: &crate::paths::Layout, profile: Profile, dirs: crate::colima::Dirs, shared: std::sync::Arc<MacShared>) -> Self {
        let ram = crate::facts::sysctl_u64("hw.memsize").unwrap_or(0) as f64 / 1073741824.0;
        let logical = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
        // the budget the other runtimes get, within what the host has (half its memory, its processors)
        let (mem, cpus) = crate::wslc::session_size(ram, logical);
        ColimaRuntime {
            profile, dirs, work: layout.work(), modules_data: layout.module_data(), docker_config: layout.run().join("docker"),
            log: layout.logs().join(format!("colima-{}.log", profile.name())), vm_cpus: cpus, vm_mem_gb: mem,
            arm: cfg!(target_arch = "aarch64"), tools: crate::colima::search_dirs(std::env::var_os("PATH").as_deref()),
            rosetta: PathBuf::from(crate::colima::ROSETTA_RUNTIME), start_lock: std::sync::Arc::new(Mutex::new(())), shared,
        }
    }

    /// Both profiles of this agent with one report, which `publish` writes to the agent's state file.
    pub fn pair(layout: &crate::paths::Layout, publish: bool) -> (ColimaRuntime, ColimaRuntime) {
        let host = crate::colima::detect(&layout.home);
        let shared = std::sync::Arc::new(MacShared::new(crate::colima::Report::of(&host, crate::colima::State::Absent), layout.home.clone(), publish));
        (Self::with(layout, Profile::Cpu, host.dirs.clone(), shared.clone()), Self::with(layout, Profile::Gpu, host.dirs, shared))
    }

    /// This runtime's `containers` pool size, once ready.
    pub fn pool_tokens(&self) -> u32 {
        tokens(self.vm_mem_gb)
    }

    /// What this Mac has now (looked up again on every call: what was installed since counts).
    fn host(&self) -> crate::colima::Host {
        crate::colima::detect_in(self.dirs.clone(), &self.tools, &self.rosetta)
    }

    /// Replace the shared report (tests).
    #[cfg(test)]
    pub fn set_report(&self, r: crate::colima::Report) {
        self.shared.update(|x| *x = r);
    }

    /// colima, docker, krunkit as found now (installed since the agent started counts).
    fn tool(&self, name: &str) -> PathBuf {
        let found = crate::colima::find(name, &self.tools, &|p: &Path| executable(p));
        found.usable().map(Path::to_path_buf).unwrap_or_else(|| Path::new(crate::colima::BREW_DIRS[0]).join(name))
    }

    pub fn colima(&self) -> PathBuf {
        self.tool("colima")
    }

    pub fn docker(&self) -> PathBuf {
        self.tool("docker")
    }

    pub fn installed(&self) -> bool {
        executable(&self.colima()) && executable(&self.docker())
    }

    pub fn docker_socket(&self) -> PathBuf {
        self.dirs.config.join(self.profile.name()).join("docker.sock")
    }

    fn base_env(&self) -> Vec<(String, String)> {
        let h = self.host();
        let mut e = vec![("PATH".into(), crate::colima::helper_path(&[&h.colima, &h.limactl, &h.docker, &h.krunkit])),
                         ("HOME".into(), self.dirs.home.to_string_lossy().into()),
                         ("USER".into(), h.account.clone()), ("LOGNAME".into(), h.account.clone()),
                         ("DOCKER_CONFIG".into(), self.docker_config.to_string_lossy().into())];
        if let Some(c) = &self.dirs.colima_home {
            e.push(("COLIMA_HOME".into(), c.to_string_lossy().into()));
        }
        e
    }

    /// Colima's environment: its own `docker context` calls land in the agent's docker config, never the user's.
    pub fn colima_env(&self) -> Vec<(String, String)> {
        self.base_env()
    }

    pub fn docker_env(&self) -> Vec<(String, String)> {
        let mut e = self.base_env();
        e.push(("DOCKER_HOST".into(), format!("unix://{}", self.docker_socket().to_string_lossy())));
        e
    }

    pub fn start_args(&self) -> Vec<String> {
        let mounts = [realpath(&self.work).to_string_lossy().to_string(), realpath(&self.modules_data).to_string_lossy().to_string()];
        crate::colima::start_args(&self.colima().to_string_lossy(), self.profile == Profile::Gpu, self.arm, self.vm_cpus, self.vm_mem_gb, &mounts)
    }

    fn colima_cmd(&self, args: &[&str]) -> Vec<String> {
        let mut v = vec![self.colima().to_string_lossy().to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        v
    }

    fn cli(&self, args: &[&str], timeout_s: u64) -> Result<Exec, String> {
        crate::fsutil::private_dir(&self.docker_config).map_err(|e| format!("{}: {e}", self.docker_config.display()))?;
        let mut argv = vec![self.docker().to_string_lossy().to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        quick(&argv, &self.docker_env(), timeout_s)
    }

    fn running(&self) -> bool {
        self.status().is_ok_and(|s| s.running)
    }

    fn log_file(&self) -> Out {
        if let Some(d) = self.log.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        std::fs::OpenOptions::new().create(true).append(true).open(&self.log).map(Out::File).unwrap_or(Out::Null)
    }

    /// The end of the profile's Colima log: the report carries it (the agent's logs directory is its account's only).
    fn log_tail(&self) -> String {
        let text = std::fs::read(&self.log).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        let t = text.trim_end();
        let mut i = t.len().saturating_sub(600);
        while !t.is_char_boundary(i) {
            i += 1;
        }
        t[i..].to_string()
    }

    /// The GPU VM has its virtio-gpu device: the guest has a DRM render node.
    fn has_render_node(&self) -> Result<(), String> {
        let r = quick(&self.colima_cmd(&["--profile", self.profile.name(), "ssh", "--", "test", "-e", RENDER_NODE]),
                      &self.colima_env(), 60)?;
        if r.ok() {
            Ok(())
        } else {
            Err(format!("the {} VM has no GPU device ({RENDER_NODE} is missing); see {}", self.profile.name(), self.log.display()))
        }
    }

    /// `colima start <profile>` unless it runs (the first start downloads the VM image).
    fn start_profile(&self) -> Result<(), String> {
        if self.running() {
            return Ok(());
        }
        for d in [&self.work, &self.modules_data] {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        if let Some(c) = &self.dirs.colima_home {
            // Colima honours COLIMA_HOME only when the directory exists
            crate::fsutil::private_dir(c).map_err(|e| format!("{}: {e}", c.display()))?;
        }
        crate::fsutil::private_dir(&self.docker_config).map_err(|e| e.to_string())?;
        let Err((e, out)) = self.colima_start() else { return Ok(()) };
        // an instance an earlier VM left behind (its host agent was killed, e.g. with an agent restart): Colima cannot
        // inspect it and fails every start until it is force-stopped
        let instance = crate::colima::instance_dir(&self.dirs.config, self.profile.name());
        if !crate::colima::stale_instance(&out) && !crate::colima::stale_files(&instance) {
            return Err(e);
        }
        let Some(n) = self.shared.take_recovery() else {
            tracing::warn!(profile = self.profile.name(), "the Colima instance is stale again: not force-stopping it a {}th time in a row",
                           crate::colima::MAX_RECOVERIES + 1);
            return Err(format!("{e} (a stale instance: {} force stops in a row did not clear it)", crate::colima::MAX_RECOVERIES));
        };
        tracing::warn!(profile = self.profile.name(), attempt = n, of = crate::colima::MAX_RECOVERIES,
                       "colima start found a stale instance (an earlier VM was not shut down cleanly): force-stopping it and starting again");
        if let Err(stop) = self.colima_stop(true, Duration::from_secs(60)) {
            tracing::warn!(profile = self.profile.name(), error = %stop, "colima stop --force failed");
        }
        match self.colima_start() {
            Ok(()) => {
                tracing::info!(profile = self.profile.name(), "the stale Colima instance was cleared and the profile started");
                Ok(())
            }
            Err((e, _)) => Err(e),
        }
    }

    /// One `colima start <profile>` (600 s: the first downloads the VM image), its output in the profile's log. Err: why,
    /// and what this start wrote to the log.
    fn colima_start(&self) -> Result<(), (String, String)> {
        let from = std::fs::metadata(&self.log).map(|m| m.len()).unwrap_or(0);
        let (o, e) = (self.log_file(), self.log_file());
        let r = exec(&self.start_args(), &self.colima_env(), Duration::from_secs(600), o, e, &AtomicBool::new(false),
                     Duration::from_secs(10)).map_err(|e| (e, String::new()))?;
        if r.ok() {
            return Ok(());
        }
        let out = std::fs::read(&self.log).ok().and_then(|b| b.get(from as usize..).map(|b| String::from_utf8_lossy(b).into_owned()))
            .unwrap_or_default();
        Err((format!("colima start {} failed ({}{}); see {}: {}", self.profile.name(), r.code, if r.timed_out { ", timeout" } else { "" },
                     self.log.display(), self.log_tail()), out))
    }

    /// `colima stop [--force] <profile>` within `timeout`, its output in the profile's log. `--force` also clears what a
    /// killed host agent left (its pid files).
    fn colima_stop(&self, force: bool, timeout: Duration) -> Result<(), String> {
        let mut args = vec!["stop"];
        if force {
            args.push("--force");
        }
        args.push(self.profile.name());
        let (o, e) = (self.log_file(), self.log_file());
        let r = exec(&self.colima_cmd(&args), &self.colima_env(), timeout, o, e, &AtomicBool::new(false), Duration::from_secs(2))?;
        if r.ok() {
            Ok(())
        } else {
            Err(format!("colima {} failed ({}{})", args.join(" "), r.code, if r.timed_out { ", timeout" } else { "" }))
        }
    }

    /// Stop the profile's VM if it has one: gracefully within most of `budget`, else forced, so no stale instance is
    /// left for the next agent (a VM still up when the agent's service ends may be killed with it).
    fn stop_vm(&self, budget: Duration) {
        let instance = crate::colima::instance_dir(&self.dirs.config, self.profile.name());
        if !self.installed() || !crate::colima::instance_up(&instance) {
            return;
        }
        // each stop may take its timeout and exec's 2 s grace after it
        let force_s = Duration::from_secs(5).min(budget / 2);
        let t = Instant::now();
        tracing::info!(profile = self.profile.name(), "stopping the Colima VM");
        match self.colima_stop(false, budget.saturating_sub(force_s + Duration::from_secs(4))) {
            Ok(()) => tracing::info!(profile = self.profile.name(), secs = t.elapsed().as_secs_f64(), "the Colima VM stopped"),
            Err(e) => {
                tracing::warn!(profile = self.profile.name(), error = %e, "the Colima VM did not stop in time: forcing it");
                if let Err(e) = self.colima_stop(true, force_s) {
                    tracing::warn!(profile = self.profile.name(), error = %e, "colima stop --force failed");
                }
            }
        }
    }

    /// Bring the CPU profile up (docs/design/macos-containers.md, "Bring-up"): check the prerequisites (missing: the
    /// report says what, with each fix), start the profile, and report ready or failed.
    pub fn bring_up(&self) -> Result<(), String> {
        use crate::colima::{Report, State};
        let _g = self.start_lock.lock().unwrap_or_else(|e| e.into_inner());
        let host = self.host();
        let now = Report::of(&host, State::Starting);
        let keep_gpu = |r: &mut Report, n: &Report| {
            // a failed or running GPU profile keeps its state; its prerequisites are as found now
            r.gpu_missing = n.gpu_missing.clone();
            if !n.gpu_missing.is_empty() {
                r.gpu_state = crate::colima::GpuState::Unavailable;
            } else if r.gpu_state == crate::colima::GpuState::Unavailable {
                r.gpu_state = crate::colima::GpuState::OnDemand;
            }
        };
        if now.state == State::Missing {
            let line = now.doctor_line();
            self.shared.update(|r| {
                keep_gpu(r, &now);
                (r.state, r.missing, r.detail, r.platforms, r.colima_home) = (State::Missing, now.missing.clone(), None, vec![], now.colima_home.clone());
            });
            return Err(line);
        }
        self.shared.update(|r| {
            keep_gpu(r, &now);
            if r.state != State::Ready {
                (r.state, r.detail) = (State::Starting, None);
            }
            (r.missing, r.colima_home) = (vec![], now.colima_home.clone());
        });
        let started = self.start_profile();
        match &started {
            Ok(()) => self.shared.reset(),
            Err(_) => {
                let wait = self.shared.failed();
                tracing::warn!(profile = self.profile.name(), retry_in_s = wait.as_secs(), "colima start failed: trying again later by itself");
            }
        }
        self.shared.update(|r| match &started {
            Ok(()) => (r.state, r.detail, r.platforms) = (State::Ready, None, crate::colima::platforms(host.arm)),
            Err(e) => (r.state, r.detail, r.platforms) = (State::Failed, Some(e.clone()), vec![]),
        });
        started
    }

    fn start_gpu(&self) -> Result<(), String> {
        use crate::colima::GpuState;
        let _g = self.start_lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = crate::colima::gpu_missing(&self.host()).first() {
            let line = format!("{}: {} ({})", m.what, m.detail, m.fix);
            self.shared.update(|r| r.gpu_state = GpuState::Unavailable);
            return Err(line);
        }
        if self.running() {
            self.shared.update(|r| (r.gpu_state, r.gpu_detail) = (GpuState::Ready, None));
            return Ok(());
        }
        self.shared.update(|r| r.gpu_state = GpuState::Starting);
        let r = self.start_profile().and_then(|_| self.has_render_node());
        self.shared.update(|s| match &r {
            Ok(()) => (s.gpu_state, s.gpu_detail) = (GpuState::Ready, None),
            Err(e) => (s.gpu_state, s.gpu_detail) = (GpuState::Failed, Some(e.clone())),
        });
        r
    }
}

#[cfg(target_os = "macos")]
impl ContainerRuntime for ColimaRuntime {
    /// The CPU profile offers its pool only while ready (a node whose runtime cannot run containers is not offered
    /// container work).
    fn pool_tokens(&self) -> u32 {
        if self.shared.snapshot().ready() { ColimaRuntime::pool_tokens(self) } else { 0 }
    }

    /// `colima status <profile> --json`: running, and the VM's memory (colima 0.10 reports bytes). The GPU VM runs
    /// arm64 images only: krunkit has no Rosetta.
    fn status(&self) -> Result<RuntimeStatus, String> {
        if !self.installed() {
            let r = self.shared.snapshot();
            let why = if r.missing.is_empty() { format!("{} or {} missing", self.colima().display(), self.docker().display()) } else { r.doctor_line() };
            return Err(why);
        }
        let platforms = match self.profile {
            Profile::Cpu => crate::colima::platforms(self.arm),
            Profile::Gpu => vec!["linux/arm64".to_string()],
        };
        let r = quick(&self.colima_cmd(&["status", self.profile.name(), "--json"]), &self.colima_env(), 20)?;
        if !r.ok() {
            return Ok(RuntimeStatus { running: false, mem_gb: None, platforms, detail: Some(r.stderr_tail(300)) });
        }
        let j: serde_json::Value = serde_json::from_slice(&r.stdout).unwrap_or_default();
        let mem = j["memory"].as_f64().map(|m| if m > 1048576.0 { m / 1073741824.0 } else { m });
        Ok(RuntimeStatus { running: true, mem_gb: mem, platforms, detail: None })
    }

    fn ensure_started(&self) -> Result<(), String> {
        match self.profile {
            Profile::Cpu if self.shared.snapshot().ready() && self.running() => Ok(()),
            Profile::Cpu => self.bring_up(),
            Profile::Gpu => self.start_gpu(),
        }
    }

    fn pull(&self, image: &str, platform: &str) -> Result<(), String> {
        let r = self.cli(&["pull", "--platform", platform, image], 1800)?;
        if r.ok() { Ok(()) } else { Err(r.stderr_tail(1000)) }
    }

    fn run(&self, spec: &RunSpec, cancel: &AtomicBool) -> Result<RunResult, String> {
        crate::fsutil::private_dir(&self.docker_config).map_err(|e| e.to_string())?;
        let mut argv = vec![self.docker().to_string_lossy().to_string()];
        argv.extend(spec.docker_args());
        let file = |f: &Option<std::fs::File>| -> Result<Out, String> {
            Ok(match f {
                Some(f) => Out::File(f.try_clone().map_err(|e| e.to_string())?),
                None => Out::Null,
            })
        };
        let r = exec(&argv, &self.docker_env(), Duration::from_secs_f64(spec.timeout_s.max(1.0)), file(&spec.stdout)?,
                     file(&spec.stderr)?, cancel, Duration::from_secs(10))?;
        Ok(RunResult { exit_code: r.code, timed_out: r.timed_out, cancelled: r.cancelled })
    }

    fn images(&self) -> Vec<String> {
        let Ok(r) = self.cli(&["image", "ls", "--digests", "--format", "{{.Repository}}@{{.Digest}}"], 30) else { return vec![] };
        String::from_utf8_lossy(&r.stdout).lines().map(str::trim).filter(|l| !l.is_empty() && !l.contains("<none>"))
            .map(str::to_string).collect()
    }

    /// Only containers carrying the attempt label are ever listed, so only those are removed.
    fn reap(&self) -> Vec<String> {
        if !self.installed() || !self.running() {
            return vec![];
        }
        remove_labelled(|a, t| self.cli(a, t), &format!("label={ATTEMPT_LABEL}"))
    }

    fn remove_attempt(&self, attempt_id: i64) -> Vec<String> {
        if !self.installed() || !self.running() {
            return vec![];
        }
        remove_labelled(|a, t| self.cli(a, t), &format!("label={ATTEMPT_LABEL}={attempt_id}"))
    }

    /// The GPU VM's guest passes its render node through, offered while the report offers the GPU.
    fn gpu_device(&self) -> Option<String> {
        (self.profile == Profile::Gpu && self.shared.snapshot().gpu()).then(|| "/dev/dri".to_string())
    }

    /// The facts' `containers` (both profiles share it; the agent reads the CPU runtime's).
    fn report(&self) -> Option<serde_json::Value> {
        (self.profile == Profile::Cpu).then(|| self.shared.snapshot().json())
    }

    /// The CPU profile comes up when a release first wants containers (the agent calls this when it makes the runtime)
    /// and again after a release, a doctor run or a re-probe while it is not ready: in the background, so the agent's
    /// loop goes on. While `missing`, the prerequisites are looked at again here first (file checks): still missing,
    /// the report's pieces are brought up to date and nothing starts; all there, it comes up. A `failed` profile starts
    /// again once its backoff ran out (`retry` clears it). The GPU profile only checks krunkit again and forgets a
    /// failed start (its VM starts with the first GPU job).
    fn recheck(&self) {
        use crate::colima::{GpuState, Report, State};
        match self.profile {
            Profile::Cpu => {
                match self.shared.snapshot().state {
                    State::Ready | State::Starting => return,
                    State::Missing => {
                        let now = Report::of(&self.host(), State::Starting);
                        if now.state == State::Missing {
                            self.shared.update(|r| r.missing = now.missing.clone());
                            return;
                        }
                        tracing::info!(profile = self.profile.name(), "the container runtime's missing prerequisites are there now: bringing it up");
                    }
                    State::Failed if !self.shared.retry_due() => return,
                    State::Failed | State::Absent => {}
                }
                self.shared.update(|r| (r.state, r.detail) = (State::Starting, None));
                let me = self.clone();
                let _ = std::thread::Builder::new().name("colima-bring-up".into()).spawn(move || {
                    if let Err(e) = me.bring_up() {
                        tracing::warn!(error = %e, "the container runtime is not ready");
                    } else {
                        tracing::info!(profile = me.profile.name(), "the container runtime is ready");
                    }
                });
            }
            Profile::Gpu => {
                let ok = crate::colima::gpu_missing(&self.host()).is_empty();
                self.shared.update(|r| match (ok, r.gpu_state) {
                    (false, _) => r.gpu_state = GpuState::Unavailable,
                    (true, GpuState::Unavailable | GpuState::Failed) => (r.gpu_state, r.gpu_detail) = (GpuState::OnDemand, None),
                    _ => {}
                });
            }
        }
    }

    /// The owner asked: a failed CPU profile starts at once, and a stale instance may be cleared again.
    fn retry(&self) {
        if self.profile == Profile::Cpu {
            self.shared.reset();
        }
        self.recheck()
    }

    /// Every RUNTIME_REPROBE: the CPU profile looks for missing prerequisites again, or starts again once a failed
    /// start's backoff ran out; the GPU profile looks for krunkit again while it is unavailable (a failed GPU start
    /// stays failed until a release or a doctor run).
    fn reprobe(&self) {
        use crate::colima::{GpuState, State};
        let r = self.shared.snapshot();
        match self.profile {
            Profile::Cpu if matches!(r.state, State::Missing | State::Failed) => self.recheck(),
            Profile::Gpu if r.gpu_state == GpuState::Unavailable => self.recheck(),
            _ => {}
        }
    }

    fn shutdown(&self, budget: Duration) {
        self.stop_vm(budget)
    }
}

// MARK: Linux: the host's own engine

#[cfg(target_os = "linux")]
/// On Linux containers run on the host's engine, no VM: rootless Podman when installed, else Docker Engine. The agent
/// uses an empty `DOCKER_CONFIG` of its own (no credential helpers); Podman keeps the agent account's own storage.
/// Only `linux/<host arch>` runs, plus foreign platforms binfmt has an enabled handler for (QEMU's, or Rosetta's in a
/// macOS VM, under whatever name it was registered).
pub struct NativeRuntime {
    pub cli: PathBuf,
    pub home: PathBuf,
    pub docker_config: PathBuf,
    pub mem_gb: f64,
    /// The CDI spec through which containers get every GPU, when the host has one (GPU passthrough).
    pub gpu: Option<CdiSpec>,
}

#[cfg(target_os = "linux")]
impl NativeRuntime {
    /// The engine on PATH (or the usual places), when there is one.
    pub fn detect(layout: &crate::paths::Layout, ram_gb: f64) -> Option<NativeRuntime> {
        let find = |n: &str| ["/usr/bin", "/usr/local/bin", "/bin"].iter().map(|d| Path::new(d).join(n)).find(|p| executable(p));
        let cli = find("podman").or_else(|| find("docker"))?;
        let home = engine_home(std::env::var_os("HOME").map(PathBuf::from), &layout.home);
        // the same budget a Mac's VM would get
        let (mem_gb, _, _) = sizing(ram_gb, None, None);
        let gpu = cdi_spec(&CDI_DIRS.map(Path::new));
        Some(NativeRuntime { cli, home, docker_config: layout.run().join("docker"), mem_gb, gpu })
    }

    fn env(&self) -> Vec<(String, String)> {
        vec![("PATH".into(), "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into()), ("HOME".into(), self.home.to_string_lossy().into()),
             ("DOCKER_CONFIG".into(), self.docker_config.to_string_lossy().into())]
    }

    fn cli(&self, args: &[&str], timeout_s: u64) -> Result<Exec, String> {
        crate::fsutil::private_dir(&self.docker_config).map_err(|e| format!("{}: {e}", self.docker_config.display()))?;
        let mut argv = vec![self.cli.to_string_lossy().to_string()];
        argv.extend(args.iter().map(|s| s.to_string()));
        quick(&argv, &self.env(), timeout_s)
    }

    pub fn platforms() -> Vec<String> {
        let native = if cfg!(target_arch = "aarch64") { "linux/arm64" } else { "linux/amd64" };
        let dir = Path::new("/proc/sys/fs/binfmt_misc");
        let on = std::fs::read_to_string(dir.join("status")).is_ok_and(|s| s.trim() == "enabled");
        let mut foreign: Vec<&str> = if on {
            std::fs::read_dir(dir).into_iter().flatten().flatten()
                .filter(|e| !matches!(e.file_name().to_str(), Some("register" | "status")))
                .filter_map(|e| std::fs::read_to_string(e.path()).ok())
                .filter_map(|t| binfmt_platform(&t))
                .filter(|p| *p != native)
                .collect()
        } else {
            vec![]
        };
        foreign.sort();
        foreign.dedup();
        std::iter::once(native).chain(foreign).map(String::from).collect()
    }
}

/// The OCI platform a binfmt_misc handler (the text of `/proc/sys/fs/binfmt_misc/<name>`) runs: an enabled handler for
/// 64-bit little-endian ELF executables of x86-64 or AArch64 (the ELF machine field, bytes 18-19 of the magic), whatever
/// it is called: qemu-user-static's `qemu-x86_64`, Fedora's `x86_64`, Lima's and OrbStack's `rosetta`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn binfmt_platform(text: &str) -> Option<&'static str> {
    let mut lines = text.lines();
    if lines.next()?.trim() != "enabled" {
        return None;
    }
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).map(str::trim);
    if field("offset ").unwrap_or("0") != "0" {
        return None;
    }
    let magic = field("magic ")?.to_ascii_lowercase();
    if magic.len() < 40 || !magic.starts_with("7f454c460201") {     // \x7fELF, 64-bit, little-endian
        return None;
    }
    match &magic[36..40] {
        "3e00" => Some("linux/amd64"),
        "b700" => Some("linux/arm64"),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
impl ContainerRuntime for NativeRuntime {
    fn status(&self) -> Result<RuntimeStatus, String> {
        let r = self.cli(&["info", "--format", "{{json .}}"], 20)?;
        Ok(RuntimeStatus { running: r.ok(), mem_gb: Some(self.mem_gb), platforms: Self::platforms(),
                           detail: (!r.ok()).then(|| r.stderr_tail(300)) })
    }

    fn ensure_started(&self) -> Result<(), String> {
        match self.status()? {
            s if s.running => Ok(()),
            s => Err(format!("the container engine ({}) is not running: {}", self.cli.display(), s.detail.unwrap_or_default())),
        }
    }

    fn pull(&self, image: &str, platform: &str) -> Result<(), String> {
        let r = self.cli(&["pull", "--platform", platform, &qualified(image)], 1800)?;
        if r.ok() { Ok(()) } else { Err(r.stderr_tail(1000)) }
    }

    fn run(&self, spec: &RunSpec, cancel: &AtomicBool) -> Result<RunResult, String> {
        crate::fsutil::private_dir(&self.docker_config).map_err(|e| e.to_string())?;
        let mut argv = vec![self.cli.to_string_lossy().to_string()];
        argv.extend(spec.docker_args_with(&qualified(&spec.image)));
        let file = |f: &Option<std::fs::File>| -> Result<Out, String> {
            Ok(match f {
                Some(f) => Out::File(f.try_clone().map_err(|e| e.to_string())?),
                None => Out::Null,
            })
        };
        let r = exec(&argv, &self.env(), Duration::from_secs_f64(spec.timeout_s.max(1.0)), file(&spec.stdout)?, file(&spec.stderr)?,
                     cancel, Duration::from_secs(10))?;
        Ok(RunResult { exit_code: r.code, timed_out: r.timed_out, cancelled: r.cancelled })
    }

    fn images(&self) -> Vec<String> {
        let Ok(r) = self.cli(&["image", "ls", "--digests", "--format", "{{.Repository}}@{{.Digest}}"], 30) else { return vec![] };
        String::from_utf8_lossy(&r.stdout).lines().map(str::trim).filter(|l| !l.is_empty() && !l.contains("<none>"))
            .map(str::to_string).collect()
    }

    fn reap(&self) -> Vec<String> {
        remove_labelled(|a, t| self.cli(a, t), &format!("label={ATTEMPT_LABEL}"))
    }

    fn remove_attempt(&self, attempt_id: i64) -> Vec<String> {
        remove_labelled(|a, t| self.cli(a, t), &format!("label={ATTEMPT_LABEL}={attempt_id}"))
    }

    fn pool_tokens(&self) -> u32 {
        tokens(self.mem_gb)
    }

    fn gpu_device(&self) -> Option<String> {
        self.gpu.as_ref().map(|g| format!("{}=all", g.kind))
    }
}


/// Images the doctor's probe runs (digest-pinned multi-platform indexes): busybox for the runtime, and a glibc image for
/// the GPU (WSL 3.0.1's GPU hook runs the image's `ldconfig` and fails on musl, microsoft/WSL#41791).
pub const PROBE_IMAGE: &str = "docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";
pub const PROBE_GPU_IMAGE: &str = "docker.io/library/debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a";

/// `oarbank-agent containers doctor --probe [--gpu]`: run real containers through this node's runtime with the
/// broker's argument shape and check what a module relies on: the run, its output, a mount of the work directory, no
/// network, the CPU and memory limits inside the container, cleanup by label, and (`gpu`) the GPU device. Each check is
/// `{check, ok, detail}`.
pub fn probe(rts: &Containers, work: &Path, gpu: bool) -> Vec<serde_json::Value> {
    use serde_json::json;
    let rt = rts.cpu.as_ref();
    let mut checks = vec![];
    let mut check = |name: &str, ok: bool, detail: String| {
        checks.push(json!({"check": name, "ok": ok, "detail": detail}));
        ok
    };
    if !check("runtime", rt.ensure_started().is_ok(), rt.status().map(|s| s.detail.unwrap_or_default()).unwrap_or_else(|e| e)) {
        return checks;
    }
    let platform = rt.status().ok().and_then(|s| s.platforms.first().cloned()).unwrap_or_default();
    let pulled = rt.pull(PROBE_IMAGE, &platform);
    if !check("pull", pulled.is_ok(), pulled.err().unwrap_or_else(|| format!("{PROBE_IMAGE} for {platform}"))) {
        return checks;
    }
    let aid = -(std::process::id() as i64);
    let dir = work.join(format!("doctor-probe-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let host = std::fs::canonicalize(&dir).unwrap_or(dir.clone());
    let out = dir.join("stdout.txt");
    let spec = |image: &str, script: &str| RunSpec {
        image: image.into(), platform: platform.clone(), args: vec!["sh".into(), "-c".into(), script.into()], entrypoint: None,
        mounts: vec![Mount { host: host.clone(), dst: "/w".into(), ro: false }], env: vec![("PROBE".into(), "1".into())], workdir: Some("/w".into()),
        network: false, cpus: 1.0, mem_gb: 0.5, attempt_id: aid, module: "doctor".into(), timeout_s: 300.0,
        stdout: std::fs::File::create(&out).ok(), stderr: None, gpu_device: None,
    };
    let script = "echo probe > /w/written.txt; echo \"mem:$(cat /sys/fs/cgroup/memory.max)\"; echo \"cpu:$(cat /sys/fs/cgroup/cpu.max)\"; \
                  if wget -q -T 5 -O /dev/null http://example.com 2>/dev/null; then echo net:yes; else echo net:no; fi";
    let r = rt.run(&spec(PROBE_IMAGE, script), &AtomicBool::new(false));
    let text = std::fs::read_to_string(&out).unwrap_or_default();
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").trim().to_string();
    if check("run", r.as_ref().is_ok_and(|r| r.exit_code == 0), format!("{r:?}")) {
        let written = std::fs::read_to_string(dir.join("written.txt")).unwrap_or_default();
        check("mount", written.trim() == "probe", format!("{} holds {:?}", dir.join("written.txt").display(), written.trim()));
        check("memory_limit", field("mem:") == "536870912", format!("memory.max = {}", field("mem:")));
        check("cpu_limit", field("cpu:") == "100000 100000", format!("cpu.max = {}", field("cpu:")));
        check("no_network", field("net:") == "no", format!("network none: {}", field("net:")));
    }
    if gpu {
        // the GPU runtime (macOS: the krunkit VM; elsewhere the same one)
        let rt = rts.for_job(true);
        let rt = rt.as_ref();
        let kind = rt.gpu_device();
        if check("gpu_device", kind.is_some(), kind.clone().unwrap_or_else(|| "this runtime passes no GPU through".into()))
            && check("gpu_pull", rt.pull(PROBE_GPU_IMAGE, &platform).is_ok(), PROBE_GPU_IMAGE.into()) {
            let script = "if [ -e /dev/dxg ] || ls /dev/nvidia* >/dev/null 2>&1 || [ -e /dev/kfd ] || [ -d /dev/dri ]; then echo gpu:yes; else echo gpu:no; fi; \
                          if command -v nvidia-smi >/dev/null; then nvidia-smi -L; fi";
            let mut gspec = spec(PROBE_GPU_IMAGE, script);
            gspec.gpu_device = kind;
            let r = rt.run(&gspec, &AtomicBool::new(false));
            let _ = rt.remove_attempt(aid);
            let text = std::fs::read_to_string(&out).unwrap_or_default();
            check("gpu_run", r.as_ref().is_ok_and(|r| r.exit_code == 0) && text.contains("gpu:yes"), format!("{r:?}: {}", text.trim()));
        }
    }
    let left = rt.remove_attempt(aid);
    check("cleanup", true, format!("{} container(s) of the probe removed by label", left.len()));
    let _ = std::fs::remove_dir_all(&dir);
    checks
}

/// GPU passthrough on Linux: a container engine and a CDI spec with an `all` device.
#[cfg(target_os = "linux")]
pub fn gpu_passthrough() -> Option<Passthrough> {
    let engine = ["/usr/bin", "/usr/local/bin", "/bin"].iter()
        .find_map(|d| ["podman", "docker"].iter().map(|n| Path::new(d).join(n)).find(|p| executable(p)))?;
    let spec = cdi_spec(&CDI_DIRS.map(Path::new))?;
    Some(Passthrough { device: format!("{}=all", spec.kind), evidence: format!("cdi:{} ({})", spec.kind, engine.display()),
                       kind: format!("cdi:{}", spec.kind), apis: spec.apis })
}

/// The Linux host's container engine, when it has one (the facts' `containers.runtime`): Podman or Docker Engine
/// (`NativeRuntime::detect`'s). The node's `containers` pool and its GPU APIs in containers exist only with one.
#[cfg(target_os = "linux")]
pub fn runtime_name() -> Option<String> {
    ["podman", "docker"].iter().find(|n| ["/usr/bin", "/usr/local/bin", "/bin"].iter().any(|d| executable(&Path::new(d).join(n))))
        .map(|n| n.to_string())
}

/// This node's container runtimes, if it has any: the agent's Colima profiles on macOS (always: the report says what is
/// missing; the GPU one on Apple silicon, offered once krunkit is installed and the runtime is ready), the host's engine on Linux (also the GPU runtime where a CDI spec exists), the agent's WSL containers
/// session on Windows (one runtime for both; it reports what is missing itself, so it always exists there).
#[cfg(target_os = "macos")]
pub fn for_node(layout: &crate::paths::Layout) -> Option<Containers> {
    for_node_mac(layout, false)
}

/// The agent's runtimes on macOS: always (the report says what is missing), the GPU profile beside the CPU one on
/// Apple silicon; `publish` (the agent) writes the report to the state file the facts read.
#[cfg(target_os = "macos")]
pub fn for_node_mac(layout: &crate::paths::Layout, publish: bool) -> Option<Containers> {
    let (cpu, gpu) = ColimaRuntime::pair(layout, publish);
    let arm = cpu.arm;
    Some(Containers { cpu: std::sync::Arc::new(cpu), gpu: arm.then(|| std::sync::Arc::new(gpu) as std::sync::Arc<dyn ContainerRuntime>) })
}

#[cfg(target_os = "linux")]
pub fn for_node(layout: &crate::paths::Layout) -> Option<Containers> {
    let rt: std::sync::Arc<dyn ContainerRuntime> = std::sync::Arc::new(NativeRuntime::detect(layout, crate::host::memory().ram_gb)?);
    let gpu = rt.gpu_device().is_some().then(|| rt.clone());
    Some(Containers { cpu: rt, gpu })
}

#[cfg(windows)]
pub fn for_node(layout: &crate::paths::Layout) -> Option<Containers> {
    let rt: std::sync::Arc<dyn ContainerRuntime> = std::sync::Arc::new(crate::wslc::WslcRuntime::start(layout, crate::host::memory().ram_gb));
    Some(Containers { cpu: rt.clone(), gpu: Some(rt) })
}


#[cfg(test)]
pub mod tests {
    use super::*;

    /// The engine's home: the account's own when it may write it, else the agent's (a system install's account home is
    /// root's), and the agent's when there is no HOME at all.
    #[test]
    #[cfg(unix)]
    fn the_engine_keeps_its_state_where_the_agent_may_write() {
        use std::os::unix::fs::PermissionsExt;
        let ((_m, mine), (_a, agent), (_r, roots)) = (temp("eh-mine"), temp("eh-agent"), temp("eh-root"));
        std::fs::set_permissions(&roots, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert_eq!(engine_home(Some(mine.clone()), &agent), mine);
        assert_eq!(engine_home(None, &agent), agent);
        assert_eq!(engine_home(Some(mine.join("missing")), &agent), agent);
        if unsafe { libc::geteuid() } != 0 {                                    // root may write anything
            assert_eq!(engine_home(Some(roots.clone()), &agent), agent);
        }
        std::fs::set_permissions(&roots, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A foreign platform runs wherever binfmt has an enabled handler for its executables, whatever the handler is
    /// called: Rosetta in a Lima VM registers as `rosetta`, so looking only for `qemu-x86_64` offered amd64 images to no
    /// one there (the broker refused hap.py: "this node's container runtime runs linux/arm64, not linux/amd64").
    #[test]
    fn binfmt_handlers_name_the_platforms_they_run() {
        // Lima (vz, rosetta.binfmt), as /proc/sys/fs/binfmt_misc/rosetta reads
        let rosetta = "enabled\ninterpreter /mnt/lima-rosetta/rosetta\nflags: OCF\noffset 0\n\
                       magic 7f454c4602010100000000000000000002003e00\nmask fffffffffffefe00fffffffffffffffffeffffff\n";
        assert_eq!(binfmt_platform(rosetta), Some("linux/amd64"));
        // qemu-user-static's handlers
        let qemu_x86 = "enabled\ninterpreter /usr/libexec/qemu-binfmt/x86_64-binfmt-P\nflags: POCF\noffset 0\n\
                        magic 7f454c4602010100000000000000000002003e00\nmask fffffffffffefe00fffffffffffffffffeffffff\n";
        let qemu_arm = "enabled\ninterpreter /usr/libexec/qemu-binfmt/aarch64-binfmt-P\nflags: POCF\noffset 0\n\
                        magic 7f454c460201010000000000000000000200b700\nmask ffffffffffffff00fffffffffffffffffeffffff\n";
        assert_eq!(binfmt_platform(qemu_x86), Some("linux/amd64"));
        assert_eq!(binfmt_platform(qemu_arm), Some("linux/arm64"));
        // disabled, another file type (Python bytecode), 32-bit x86, and the register/status files are not platforms
        assert_eq!(binfmt_platform(&rosetta.replacen("enabled", "disabled", 1)), None);
        assert_eq!(binfmt_platform("enabled\ninterpreter /usr/bin/python3.14\nflags: \noffset 0\nmagic 2b0e0d0a\n"), None);
        assert_eq!(binfmt_platform("enabled\ninterpreter /usr/bin/qemu-i386\nflags: \noffset 0\n\
                                    magic 7f454c4601010100000000000000000002000300\n"), None);
        assert_eq!(binfmt_platform("enabled\n"), None);
    }

    /// Make `home` a rootless Podman home of its own: graph root, run root and temporary directory all inside it. A
    /// private HOME alone moves only the graph root: the run root and the temporary directory stay the account's
    /// (`$XDG_RUNTIME_DIR/containers`, `$XDG_RUNTIME_DIR/libpod/tmp`).
    #[cfg(target_os = "linux")]
    pub fn private_engine(home: &Path) {
        let conf = home.join(".config/containers");
        std::fs::create_dir_all(&conf).unwrap();
        std::fs::write(conf.join("storage.conf"), format!("[storage]\ndriver = \"overlay\"\ngraphroot = \"{}\"\nrunroot = \"{}\"\n",
                                                         home.join("storage").display(), home.join("run").display())).unwrap();
        std::fs::write(conf.join("containers.conf"), format!("[engine]\ntmp_dir = \"{}\"\n", home.join("tmp").display())).unwrap();
    }

    /// Delete a private engine's state. Its storage holds files of the user namespace's ids, which only a process in
    /// that namespace may remove (`podman unshare rm`); never `podman system reset`, which also deletes the account's
    /// own engine state under `$XDG_RUNTIME_DIR/libpod` whatever the configuration says (the run state of every other
    /// container the account runs, those of concurrent tests among them).
    #[cfg(target_os = "linux")]
    pub fn remove_private_engine(cli: &Path, home: &Path) {
        if cli.ends_with("podman") {
            let _ = Command::new(cli).env_clear().env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin").env("HOME", home)
                .args(["unshare", "rm", "-rf"]).args(["storage", "run", "tmp"].map(|d| home.join(d))).output();
        }
        let _ = std::fs::remove_dir_all(home);
    }

    /// A private engine works in its own roots, and removing it leaves the account's engine and its run state alone.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_private_engine_keeps_its_state_to_itself() {
        let (_home, home) = temp("private-engine");
        let layout = crate::paths::Layout::new(home.join("agent"));
        let Some(mut rt) = NativeRuntime::detect(&layout, 16.0) else {
            eprintln!("no container engine here: skipped");
            return;
        };
        if !rt.cli.ends_with("podman") || !rt.status().is_ok_and(|s| s.running) {
            eprintln!("no running rootless Podman here: skipped");
            return;
        }
        let shared = rt.cli(&["info", "--format", "{{.Store.RunRoot}}"], 30).unwrap();
        let shared_run = PathBuf::from(String::from_utf8_lossy(&shared.stdout).trim());
        let marker = shared_run.join(format!("oarbank-test-{}", std::process::id()));
        std::fs::write(&marker, "x").unwrap();
        let account_home = rt.home.clone();
        rt.home = home.join("engine-home");
        private_engine(&rt.home);
        let own = rt.cli(&["info", "--format", "{{.Store.RunRoot}} {{.Store.GraphRoot}}"], 60).unwrap();
        assert_eq!(String::from_utf8_lossy(&own.stdout).trim(),
                   format!("{} {}", rt.home.join("run").display(), rt.home.join("storage").display()), "{}", own.stderr_tail(500));
        remove_private_engine(&rt.cli, &rt.home);
        let kept = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert!(kept, "the account's run state ({}) was removed", shared_run.display());
        assert!(!rt.home.exists(), "the private engine's files are gone");
        rt.home = account_home;
        assert!(rt.status().is_ok_and(|s| s.running), "the account's engine still answers");
    }

    /// A root filesystem of this host's `sh` and `cat` with the libraries they load (`ldd`), as a tar to import: an
    /// image that needs no registry.
    #[cfg(target_os = "linux")]
    pub fn host_rootfs(tar: &Path) {
        let mut files: Vec<(String, PathBuf)> = vec![];
        for (name, bin) in [("bin/sh", "/bin/sh"), ("bin/cat", "/bin/cat")] {
            files.push((name.into(), PathBuf::from(bin)));
            let out = std::process::Command::new("ldd").arg(bin).output().unwrap();
            for lib in String::from_utf8_lossy(&out.stdout).split_whitespace().filter(|w| w.starts_with('/')) {
                files.push((lib.trim_start_matches('/').into(), PathBuf::from(lib)));
            }
        }
        let mut b = tar::Builder::new(std::fs::File::create(tar).unwrap());
        b.follow_symlinks(true);
        files.sort();
        files.dedup();
        for (name, path) in files {
            b.append_path_with_name(&path, &name).unwrap();
        }
        b.finish().unwrap();
    }

    /// Linux with an engine installed (Podman or Docker): import an image of the host's own shell (no registry) and run
    /// a real container of it through the native runtime, with the broker's argument shape, a mount and a label.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_native_runtime_runs_a_real_container() {
        let (_home, home) = temp("native");
        let layout = crate::paths::Layout::new(home.clone());
        let Some(rt) = NativeRuntime::detect(&layout, 16.0) else {
            eprintln!("no container engine here: skipped");
            return;
        };
        if !rt.status().is_ok_and(|s| s.running) {
            eprintln!("the engine is not running: skipped");
            return;
        }
        let image = format!("localhost/oarbank-crt-test:{}", std::process::id());
        let tar = home.join("rootfs.tar");
        host_rootfs(&tar);
        let imported = rt.cli(&["import", &tar.to_string_lossy(), &image], 120).unwrap();
        assert!(imported.ok(), "{}", imported.stderr_tail(500));
        let work = home.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let out = home.join("out.txt");
        let spec = RunSpec { image: image.clone(), platform: NativeRuntime::platforms()[0].clone(), args: vec!["sh".into(), "-c".into(),
            "echo hello > /w/hi.txt && cat /w/hi.txt".into()], entrypoint: None,
            mounts: vec![Mount { host: work.clone(), dst: "/w".into(), ro: false }], env: vec![], workdir: None, network: false,
            cpus: 1.0, mem_gb: 0.5, attempt_id: 424242, module: "test".into(), timeout_s: 120.0,
            stdout: Some(std::fs::File::create(&out).unwrap()), stderr: None, gpu_device: None };
        let r = rt.run(&spec, &AtomicBool::new(false));
        let _ = rt.cli(&["rmi", "-f", &image], 60);
        assert_eq!(r.unwrap().exit_code, 0);
        assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), "hello");
        assert_eq!(std::fs::read_to_string(work.join("hi.txt")).unwrap().trim(), "hello");
        assert!(rt.pool_tokens() > 0);
    }

    /// A scratch directory: (what removes it when dropped, its canonical path).
    fn temp(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let d = crate::scratch(&format!("crt-{tag}"));
        let p = std::fs::canonicalize(d.path()).unwrap();
        (d, p)
    }

    /// A runtime laid out as a system install's: Colima in `<agent home>/colima`.
    #[cfg(target_os = "macos")]
    fn colima_at(base: &Path, profile: Profile) -> ColimaRuntime {
        let l = crate::paths::Layout::new(base.join("agent"));
        let mut c = ColimaRuntime::new(&l, profile);
        c.dirs = crate::colima::dirs(&l.home, Some(Path::new("/Library/Application Support/Oarbank")));
        c
    }

    #[cfg(target_os = "macos")]
    fn ready_report(krunkit: bool) -> crate::colima::Report {
        use crate::colima::{Dirs, Found, Host, Report, State};
        let d = PathBuf::from("/a/colima");
        let h = Host { arm: true, colima: Found::Usable("/opt/homebrew/bin/colima".into()), docker: Found::Usable("/opt/homebrew/bin/docker".into()),
                       limactl: Found::Usable("/opt/homebrew/bin/limactl".into()),
                       krunkit: if krunkit { Found::Usable("/opt/homebrew/bin/krunkit".into()) } else { Found::Absent }, rosetta: true,
                       dirs: Dirs { home: d.clone(), config: d.clone(), colima_home: Some(d) }, config_writable: true, account: "_oarbank".into(),
                       owner: None };
        Report::of(&h, State::Ready)
    }

    #[test]
    fn sizing_follows_the_host_ram_unless_the_owner_caps_it() {
        assert_eq!(sizing(24.0, None, None), (8.0, 6, 2));
        assert_eq!(sizing(64.0, None, None), (12.0, 6, 4));
        assert_eq!(sizing(128.0, None, None), (32.0, 8, 12));
        assert_eq!(sizing(128.0, Some(6.5), Some(3)), (6.5, 3, 2));
        assert_eq!(tokens(1.0), 0);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn start_mounts_only_the_agent_directories_and_docker_never_uses_the_user_context() {
        let (_base, base) = temp("start");
        let mut c = colima_at(&base, Profile::Cpu);
        (c.vm_cpus, c.vm_mem_gb, c.arm) = (6, 10.0, true);
        std::fs::create_dir_all(&c.work).unwrap();
        std::fs::create_dir_all(&c.modules_data).unwrap();
        let a = c.start_args();
        let agent = base.join("agent").to_string_lossy().to_string();
        assert_eq!(a[1..], ["start", "oarbank", "--vm-type", "vz", "--vz-rosetta", "--arch", "aarch64", "--cpu", "6", "--memory",
                            "10", "--disk", "100", "--ssh-config=false", "--mount", &format!("{agent}/work:w"), "--mount", &format!("{agent}/modules-data:w")]);
        assert_eq!(a.iter().filter(|x| *x == "--mount").count(), 2);
        let env = c.docker_env();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        // Colima, Lima and their caches stay in the agent's own home, whatever HOME the agent was started with
        assert_eq!(get("DOCKER_HOST"), Some(format!("unix://{agent}/colima/oarbank/docker.sock")));
        assert_eq!(get("HOME"), Some(format!("{agent}/colima")));
        assert_eq!(get("COLIMA_HOME"), Some(format!("{agent}/colima")));
        assert_eq!(get("DOCKER_CONFIG"), Some(format!("{agent}/run/docker")));
        assert!(get("PATH").unwrap().split(':').any(|d| d == "/opt/homebrew/bin"), "Homebrew is on the helper PATH");
        assert!(get("DOCKER_CONTEXT").is_none());
        assert!(c.colima_env().iter().any(|(k, v)| k == "DOCKER_CONFIG" && *v == format!("{agent}/run/docker")));
        assert_eq!(c.gpu_device(), None);
        // an Intel Mac's VM is x86_64, without Rosetta
        c.arm = false;
        assert_eq!(c.start_args()[3..7], ["--vm-type", "vz", "--arch", "x86_64"]);
    }

    /// The GPU profile is a VM of its own on krunkit (no Rosetta, arm64 images only), with the same two mounts and its own
    /// socket and log, and its containers get `--device /dev/dri`, offered only while the shared report offers the GPU
    /// (a ready runtime with krunkit, whose GPU VM has not failed). A CPU job's containers never go there.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_gpu_profile_is_a_krunkit_vm_of_its_own() {
        let (_base, base) = temp("gpu");
        let l = crate::paths::Layout::new(base.join("agent"));
        let (mut cpu, mut g) = ColimaRuntime::pair(&l, false);
        for r in [&mut cpu, &mut g] {
            r.dirs = crate::colima::dirs(&l.home, None);
            (r.vm_cpus, r.vm_mem_gb, r.arm) = (6, 10.0, true);
        }
        let agent = base.join("agent").to_string_lossy().to_string();
        assert_eq!(g.start_args()[1..], ["start", "oarbank-gpu", "--vm-type", "krunkit", "--mount-type", "sshfs", "--arch", "aarch64", "--cpu", "6", "--memory",
                                          "10", "--disk", "100", "--ssh-config=false", "--mount", &format!("{agent}/work:w"),
                                          "--mount", &format!("{agent}/modules-data:w")]);
        assert_eq!(g.docker_socket(), PathBuf::from(format!("{agent}/colima/oarbank-gpu/docker.sock")));
        assert!(g.log.ends_with("logs/colima-oarbank-gpu.log"));
        cpu.set_report(crate::colima::Report { state: crate::colima::State::Starting, ..ready_report(true) });
        assert_eq!(g.gpu_device(), None, "no GPU while the runtime is not ready");
        g.set_report(ready_report(false));
        assert_eq!(g.gpu_device(), None, "no GPU without krunkit");
        cpu.set_report(ready_report(true));
        assert_eq!(g.gpu_device().as_deref(), Some("/dev/dri"), "one report for both profiles");
        assert_eq!((cpu.gpu_device(), g.report().is_none()), (None, true), "the CPU runtime reports for both");
        assert_eq!(cpu.report().unwrap()["gpu"], "virtio-gpu:venus");
        let spec = RunSpec { gpu_device: g.gpu_device(), ..spec("x@sha256:00") };
        assert!(spec.docker_args().windows(2).any(|w| w == ["--device", "/dev/dri"]));
        let cpu: std::sync::Arc<dyn ContainerRuntime> = std::sync::Arc::new(cpu);
        let both = Containers { cpu: cpu.clone(), gpu: Some(std::sync::Arc::new(g)) };
        assert!(std::sync::Arc::ptr_eq(&both.for_job(false), &cpu) && both.for_job(true).gpu_device().is_some());
        assert_eq!(both.all().len(), 2);
        let none = Containers { cpu: cpu.clone(), gpu: None };
        assert!(std::sync::Arc::ptr_eq(&none.for_job(true), &cpu) && none.all().len() == 1);
        let same = Containers { cpu: cpu.clone(), gpu: Some(cpu.clone()) };
        assert_eq!(same.all().len(), 1, "on Linux the GPU runtime is the CPU runtime: reaped once");
    }

    /// The `containers` pool is offered only while the runtime is ready, so a Mac whose runtime cannot run containers is
    /// not offered container work (2.8.0 offered it whenever colima and docker were installed).
    #[test]
    #[cfg(target_os = "macos")]
    fn the_pool_is_offered_only_by_a_ready_runtime() {
        let (_base, base) = temp("pool");
        let mut c = colima_at(&base, Profile::Cpu);
        assert!(c.vm_mem_gb <= (crate::facts::sysctl_u64("hw.memsize").unwrap() as f64 / 1073741824.0 / 2.0).max(1.0));
        c.vm_mem_gb = 8.0;                              // a VM with room for a slot, whatever this host has (a 7 GB runner has none)
        assert!(ColimaRuntime::pool_tokens(&c) > 0);
        c.set_report(crate::colima::Report { state: crate::colima::State::Starting, ..ready_report(false) });
        assert_eq!(ContainerRuntime::pool_tokens(&c), 0);
        c.set_report(ready_report(false));
        assert_eq!(ContainerRuntime::pool_tokens(&c), ColimaRuntime::pool_tokens(&c));
    }

    fn spec(image: &str) -> RunSpec {
        RunSpec { image: image.into(), platform: "linux/arm64".into(), args: vec![], entrypoint: None, mounts: vec![], env: vec![],
                  workdir: None, network: false, cpus: 1.0, mem_gb: 1.0, attempt_id: 1, module: "m".into(), timeout_s: 1.0,
                  stdout: None, stderr: None, gpu_device: None }
    }

    #[test]
    fn docker_args_have_a_fixed_shape() {
        let s = RunSpec {
            image: "x@sha256:00".into(), platform: "linux/arm64".into(), args: vec!["--privileged".into()], entrypoint: None,
            mounts: vec![Mount { host: "/w/in".into(), dst: "/in".into(), ro: true }], env: vec![("A".into(), "1".into())],
            workdir: Some("/in".into()), network: false, cpus: 2.0, mem_gb: 2.5, attempt_id: 7, module: "toy".into(),
            timeout_s: 10.0, stdout: None, stderr: None, gpu_device: None,
        };
        assert_eq!(s.docker_args(), ["run", "--rm", "--platform", "linux/arm64", "--network", "none", "--cpus", "2", "--memory", "2.5g",
                                     "--label", "oarbank.attempt_id=7", "--label", "oarbank.module=toy", "-v", "/w/in:/in:ro",
                                     "--workdir", "/in", "-e", "A=1", "x@sha256:00", "--privileged"]);
        let g = RunSpec { gpu_device: Some("nvidia.com/gpu=all".into()), ..s };
        assert_eq!(g.docker_args()[14..16], ["--device", "nvidia.com/gpu=all"]);
        assert_eq!(fmt_num(0.1), "0.1");
        assert_eq!(fmt_num(0.25), "0.25");
        assert_eq!(fmt_num(16.0), "16");
    }

    #[test]
    fn short_names_are_spelled_out_for_podman() {
        let d = "sha256:".to_string() + &"c".repeat(64);
        assert_eq!(qualified(&format!("genonet/hap-py@{d}")), format!("docker.io/genonet/hap-py@{d}"));
        assert_eq!(qualified("alpine:3.20"), "docker.io/library/alpine:3.20");
        for full in [format!("quay.io/biocontainers/bcftools:1.20--h8b25389_0@{d}"), format!("localhost:5000/x@{d}"),
                     format!("docker.io/org/tool@{d}"), "localhost/x".to_string()] {
            assert_eq!(qualified(&full), full);
        }
        for r in [format!("genonet/hap-py@{d}"), format!("alpine@{d}"), format!("ghcr.io/o/t:2@{d}")] {
            assert_eq!(image_key(&qualified(&r)), image_key(&r), "the broker's comparison is unchanged");
        }
        let s = RunSpec { platform: "linux/amd64".into(), ..spec(&format!("genonet/hap-py@{d}")) };
        assert_eq!(s.docker_args_with(&qualified(&s.image)).last().unwrap(), &format!("docker.io/genonet/hap-py@{d}"));
        assert_eq!(s.docker_args().last().unwrap(), &s.image);
    }

    #[test]
    fn cdi_specs_name_the_gpu_device_kind() {
        let kind = |dirs: &[&Path]| cdi_spec(dirs).map(|s| s.kind);
        let (_d, d) = temp("cdi");
        assert_eq!(kind(&[d.as_path()]), None);
        std::fs::write(d.join("readme.txt"), "kind: x/y\n- name: all\n").unwrap();
        assert_eq!(kind(&[d.as_path()]), None, "only .json, .yaml and .yml files are specs");
        std::fs::write(d.join("nvidia.yaml"), "---\ncdiVersion: 0.5.0\ncontainerEdits:\n  deviceNodes:\n  - path: /dev/nvidiactl\n\
            devices:\n- containerEdits:\n    deviceNodes:\n    - path: /dev/nvidia0\n  name: \"0\"\n- containerEdits:\n\
                deviceNodes:\n    - path: /dev/nvidia0\n  name: all\nkind: nvidia.com/gpu\n").unwrap();
        assert_eq!(kind(&[d.as_path()]).as_deref(), Some("nvidia.com/gpu"));
        let (_j, j) = temp("cdi-json");
        std::fs::write(j.join("amd.json"), r#"{"cdiVersion": "0.6.0", "kind": "amd.com/gpu", "devices": [{"name": "0"}]}"#).unwrap();
        assert_eq!(kind(&[j.as_path()]), None, "no `all` device");
        std::fs::write(j.join("amd.json"), r#"{"kind": "amd.com/gpu", "devices": [{"name": "0"}, {"name": "all"}]}"#).unwrap();
        assert_eq!(kind(&[j.as_path(), d.as_path()]).as_deref(), Some("amd.com/gpu"));
    }

    /// The APIs a container gets come from what the spec passes: recorded specs of `nvidia-ctk cdi generate` (a Linux
    /// host, and `--mode=wsl` over GPU-PV), and AMD's (`amd-ctk cdi generate`).
    #[test]
    fn cdi_specs_name_the_apis_a_container_gets() {
        let (_d, d) = temp("cdi-apis");
        std::fs::write(d.join("nvidia.yaml"), "---\ncdiVersion: 0.5.0\ncontainerEdits:\n  deviceNodes:\n  - path: /dev/nvidiactl\n\
            \x20 - path: /dev/nvidia-uvm\n  mounts:\n  - containerPath: /usr/lib/x86_64-linux-gnu/libcuda.so.570.86.15\n\
            \x20   hostPath: /usr/lib/x86_64-linux-gnu/libcuda.so.570.86.15\n    options: [ro, nosuid, nodev, bind]\n\
            \x20 - containerPath: /usr/lib/x86_64-linux-gnu/libnvidia-opencl.so.570.86.15\n\
            \x20   hostPath: /usr/lib/x86_64-linux-gnu/libnvidia-opencl.so.570.86.15\n\
            \x20 - containerPath: /etc/vulkan/icd.d/nvidia_icd.json\n    hostPath: /etc/vulkan/icd.d/nvidia_icd.json\n\
            devices:\n- containerEdits:\n    deviceNodes:\n    - path: /dev/nvidia0\n  name: all\nkind: nvidia.com/gpu\n").unwrap();
        assert_eq!(cdi_spec(&[d.as_path()]).unwrap().apis, ["cuda", "opencl", "vulkan"]);
        let (_w, w) = temp("cdi-wsl");
        std::fs::write(w.join("nvidia.json"), r#"{"cdiVersion": "0.5.0", "kind": "nvidia.com/gpu",
            "devices": [{"name": "all", "containerEdits": {"deviceNodes": [{"path": "/dev/dxg"}]}}],
            "containerEdits": {"mounts": [{"hostPath": "/usr/lib/wsl/lib/libcuda.so.1.1", "containerPath": "/usr/lib/wsl/lib/libcuda.so.1.1"},
                                          {"hostPath": "/usr/lib/wsl/lib/libd3d12.so", "containerPath": "/usr/lib/wsl/lib/libd3d12.so"}]}}"#).unwrap();
        assert_eq!(cdi_spec(&[w.as_path()]).unwrap().apis, ["cuda"]);
        let (_a, a) = temp("cdi-amd");
        std::fs::write(a.join("amd.json"), r#"{"cdiVersion": "0.6.0", "kind": "amd.com/gpu", "devices": [
            {"name": "0", "containerEdits": {"deviceNodes": [{"path": "/dev/dri/card1"}, {"path": "/dev/dri/renderD128"}]}},
            {"name": "all", "containerEdits": {"deviceNodes": [{"path": "/dev/kfd"}, {"path": "/dev/dri/card1"},
                                                                {"path": "/dev/dri/renderD128"}]}}]}"#).unwrap();
        assert_eq!(cdi_spec(&[a.as_path()]).unwrap().apis, ["rocm", "vulkan"]);
        assert!(cdi_apis("nvidia.com/gpu", &["/dev/dri/renderD128".into()]).is_empty(), "NVIDIA's Vulkan is its ICD, not Mesa");
        assert_eq!(cdi_apis("intel.com/gpu", &["/dev/dri/renderD129".into()]), ["vulkan"]);
    }

    #[test]
    fn image_keys_follow_docker_normalisation() {
        let d = "sha256:".to_string() + &"b".repeat(64);
        let k = ("docker.io/org/tool".to_string(), d.clone());
        assert_eq!(image_key(&format!("docker.io/org/tool:1.2@{d}")), k);
        assert_eq!(image_key(&format!("org/tool@{d}")), k);
        assert_eq!(image_key(&format!("index.docker.io/org/tool@{d}")), k);
        assert_eq!(image_key(&format!("alpine@{d}")).0, "docker.io/library/alpine");
        assert_eq!(image_key(&format!("ghcr.io/o/t:2@{d}")).0, "ghcr.io/o/t");
        assert_eq!(image_key(&format!("localhost:5000/t:2@{d}")).0, "localhost:5000/t");
        assert_ne!(image_key(&format!("org/other@{d}")), k);
    }

    #[test]
    #[cfg(unix)]
    fn exec_captures_times_out_and_cancels_the_whole_group() {
        let sh = |s: &str| vec!["/bin/sh".to_string(), "-c".into(), s.into()];
        let env = [("PATH".to_string(), "/usr/bin:/bin".to_string())];
        let never = AtomicBool::new(false);
        let r = exec(&sh("echo out; echo err >&2; exit 3"), &env, Duration::from_secs(10), Out::Capture, Out::Capture, &never,
                     Duration::from_secs(1)).unwrap();
        assert_eq!((r.code, r.stdout.as_slice(), r.stderr_tail(100).as_str()), (3, &b"out\n"[..], "err"));
        let t = Instant::now();
        // the grandchild sleeps too: the group is signalled, not only the shell
        let r = exec(&sh("sleep 30 & sleep 30; wait"), &env, Duration::from_millis(300), Out::Null, Out::Null, &never,
                     Duration::from_secs(2)).unwrap();
        assert!(r.timed_out && !r.cancelled && t.elapsed() < Duration::from_secs(5), "{r:?}");
        let cancel = AtomicBool::new(true);
        let r = exec(&sh("sleep 30"), &env, Duration::from_secs(30), Out::Null, Out::Null, &cancel, Duration::from_secs(2)).unwrap();
        assert!(r.cancelled && !r.ok());
        assert!(exec(&["/nonexistent/x".to_string()], &env, Duration::from_secs(1), Out::Null, Out::Null, &never,
                     Duration::from_secs(1)).is_err());
    }

    /// A runtime that cannot start says why, with the fix, and starts nothing: here Colima's directory is one the
    /// agent's account may not write (a system install whose account home belongs to root, in 2.8.0).
    #[test]
    #[cfg(target_os = "macos")]
    fn a_missing_piece_stops_the_bring_up_and_the_report_says_which() {
        let (_base, base) = temp("missing");
        let l = crate::paths::Layout::new(base.join("agent"));
        let (mut c, _) = ColimaRuntime::pair(&l, true);
        let root_owned = PathBuf::from("/oarbank-test-not-writable/colima");
        c.dirs = crate::colima::Dirs { home: root_owned.clone(), config: root_owned.clone(), colima_home: Some(root_owned) };
        if crate::colima::creatable(&c.dirs.config) {
            eprintln!("this account may write /: skipped");
            return;
        }
        let e = c.ensure_started().unwrap_err();
        let r = c.report().unwrap();
        assert_eq!((r["runtime"].as_str(), r["state"].as_str(), r["gpu"].as_str()), (Some("colima"), Some("missing"), Some("undetected")));
        let missing = r["missing"].as_array().unwrap();
        assert!(missing.iter().any(|m| m["what"] == "colima_home"));
        // the error names the first missing piece (`colima` itself, on a host without it)
        assert!(missing.iter().any(|m| e.starts_with(&format!("{}:", m["what"].as_str().unwrap()))), "{e}");
        assert_eq!(ContainerRuntime::pool_tokens(&c), 0);
        // the agent's runtime publishes the report the facts read
        assert_eq!(crate::colima::facts(&l.home, || unreachable!())["state"], "missing");
        assert_eq!(crate::facts::collect(&l.home)["containers"]["state"], "missing");
        c.recheck();                                    // in the background: missing again, nothing started
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(c.report().unwrap()["state"], "missing");
    }

    /// The trait's re-probe: a runtime that keeps its own report (Windows) checks again only while it is `missing`.
    #[test]
    fn the_default_reprobe_rechecks_only_a_missing_runtime() {
        struct R(&'static str, std::sync::atomic::AtomicUsize);
        impl ContainerRuntime for R {
            fn status(&self) -> Result<RuntimeStatus, String> { Err("unused".into()) }
            fn ensure_started(&self) -> Result<(), String> { Ok(()) }
            fn pull(&self, _: &str, _: &str) -> Result<(), String> { Ok(()) }
            fn run(&self, _: &RunSpec, _: &AtomicBool) -> Result<RunResult, String> { Err("unused".into()) }
            fn images(&self) -> Vec<String> { vec![] }
            fn reap(&self) -> Vec<String> { vec![] }
            fn remove_attempt(&self, _: i64) -> Vec<String> { vec![] }
            fn report(&self) -> Option<serde_json::Value> { Some(serde_json::json!({"state": self.0})) }
            fn recheck(&self) { self.1.fetch_add(1, Ordering::SeqCst); }
        }
        for (state, n) in [("missing", 1), ("ready", 0), ("starting", 0), ("failed", 0)] {
            let r = R(state, Default::default());
            r.reprobe();
            r.retry();
            assert_eq!(r.1.load(Ordering::SeqCst), n + 1, "{state}");
        }
    }

    /// A fake Colima (a shell script) in a short scratch directory, with docker and limactl beside it and the file
    /// that means Rosetta is installed: `calls` records each call; `vz.pid` without `ha.sock` in the instance makes
    /// `colima start` fail as a node did after an agent restart (`stale` keeps it failing so); `fail` fails every start.
    /// Nothing real is started: the runtime looks only in this directory.
    #[cfg(target_os = "macos")]
    struct FakeColima {
        _tmp: tempfile::TempDir,
        dir: PathBuf,
        rt: ColimaRuntime,
    }

    #[cfg(target_os = "macos")]
    const FAKE_COLIMA: &str = r#"#!/bin/sh
d=$(dirname "$0")
echo "$*" >> "$d/calls"
cmd=$1; shift
force=
if [ "$1" = "--force" ]; then force=1; shift; fi
p=$1
i="$COLIMA_HOME/_lima/colima-$p"
case "$cmd" in
status)
  if [ -e "$COLIMA_HOME/$p/running" ]; then echo '{"memory": 8589934592}'; exit 0; fi
  echo "colima $p is not running" >&2; exit 1;;
start)
  if [ -e "$d/stale" ] || { [ -e "$i/vz.pid" ] && [ ! -e "$i/ha.sock" ]; }; then
    echo "time=x level=fatal msg=\"errors inspecting instance: [failed to connect to $i/ha.sock: stat $i/ha.sock: no such file or directory]\"" >&2
    echo "error starting vm: error at 'starting': exit status 1" >&2
    exit 1
  fi
  if [ -e "$d/fail" ]; then echo "error starting vm: exit status 1" >&2; exit 1; fi
  mkdir -p "$i" "$COLIMA_HOME/$p" && echo 1 > "$i/vz.pid" && : > "$i/ha.sock" && : > "$COLIMA_HOME/$p/running"; exit 0;;
stop)
  if [ -z "$force" ] && [ -e "$d/hang" ]; then sleep 30; fi
  rm -f "$COLIMA_HOME/$p/running" "$i/ha.sock" "$i/vz.pid"; exit 0;;
esac
exit 2
"#;

    #[cfg(target_os = "macos")]
    impl FakeColima {
        /// Colima, docker and Rosetta present; `limactl` and Rosetta as asked.
        fn new(lima: bool, rosetta: bool) -> FakeColima {
            // Lima's sockets must fit in 104 bytes: a short directory, removed when the test ends
            let tmp = tempfile::Builder::new().prefix("oarbank-fc-").tempdir_in("/private/tmp").unwrap();
            let dir = tmp.path().to_path_buf();
            let tools = dir.join("bin");
            std::fs::create_dir_all(&tools).unwrap();
            let f = FakeColima { rt: Self::runtime(&dir, &tools), _tmp: tmp, dir };
            f.install("colima", FAKE_COLIMA);
            f.install("docker", "#!/bin/sh\nexit 0\n");
            if lima {
                f.install("limactl", "#!/bin/sh\nexit 0\n");
            }
            if rosetta {
                f.rosetta();
            }
            f.rt.set_report(crate::colima::Report::of(&f.rt.host(), crate::colima::State::Absent));
            f
        }

        fn runtime(dir: &Path, tools: &Path) -> ColimaRuntime {
            let l = crate::paths::Layout::new(dir.join("a"));
            let (mut c, _) = ColimaRuntime::pair(&l, true);
            c.dirs = crate::colima::dirs(&l.home, None);
            (c.tools, c.rosetta) = (vec![tools.to_path_buf()], dir.join("libRosettaRuntime"));
            c
        }

        fn install(&self, name: &str, script: &str) {
            use std::os::unix::fs::PermissionsExt;
            let p = self.dir.join("bin").join(name);
            std::fs::write(&p, script).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        fn rosetta(&self) {
            std::fs::write(&self.rt.rosetta, "").unwrap();
        }

        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.join("bin/calls")).unwrap_or_default().lines().map(str::to_string)
                .filter(|l| !l.starts_with("status")).collect()
        }

        fn instance(&self) -> PathBuf {
            crate::colima::instance_dir(&self.rt.dirs.config, crate::colima::CPU_PROFILE)
        }

        fn state(&self) -> String {
            self.rt.report().unwrap()["state"].as_str().unwrap().to_string()
        }

        /// The state once the background bring-up settled.
        fn settled(&self) -> String {
            let until = Instant::now() + Duration::from_secs(20);
            while self.state() == "starting" && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(20));
            }
            self.state()
        }
    }

    /// A prerequisite reported missing (Rosetta, as on a node; Lima too) and installed later is noticed without a
    /// restart: by the agent's periodic re-probe and by the owner's doctor run (`retry`), and the runtime then comes up.
    /// While it is still missing, a re-probe looks without starting anything and keeps the report as found now.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_prerequisite_installed_later_is_picked_up_by_the_reprobe_and_the_doctor_run() {
        let arm = cfg!(target_arch = "aarch64");
        let f = FakeColima::new(false, false);
        f.rt.recheck();                                         // a release wants containers
        assert_eq!(f.settled(), "missing");
        let whats = |f: &FakeColima| f.rt.report().unwrap()["missing"].as_array().unwrap().iter()
            .map(|m| m["what"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(whats(&f), if arm { vec!["lima", "rosetta"] } else { vec!["lima"] });
        assert_eq!(crate::colima::facts(&f.rt.shared.agent_home, || unreachable!())["state"], "missing");
        // Lima installed, Rosetta not yet: a re-probe sees it at once (no bring-up) and still reports what is missing
        f.install("limactl", "#!/bin/sh\nexit 0\n");
        f.rt.reprobe();
        if arm {
            assert_eq!((f.state(), whats(&f)), ("missing".to_string(), vec!["rosetta".to_string()]));
            assert!(f.calls().is_empty(), "nothing started while missing: {:?}", f.calls());
            f.rosetta();
            f.rt.reprobe();
        }
        assert_eq!(f.settled(), "ready");
        assert!(f.calls().iter().any(|c| c.starts_with("start oarbank --vm-type vz")), "{:?}", f.calls());
        assert_eq!(crate::colima::facts(&f.rt.shared.agent_home, || unreachable!())["state"], "ready");
        f.rt.reprobe();                                         // ready: nothing to do
        assert_eq!(f.calls().len(), 1);

        // the owner's doctor run after installing it
        let g = FakeColima::new(true, !arm);
        g.rt.recheck();
        if arm {
            assert_eq!(g.settled(), "missing");
            g.rosetta();
        }
        g.rt.retry();
        assert_eq!(g.settled(), "ready");
    }

    /// An agent restart that took the VM's host agent with it leaves an instance Colima cannot inspect (a `vz.pid`, no
    /// `ha.sock`): every `colima start` fails. The runtime clears it once per start (`colima stop --force`, then start
    /// again) and is ready, logging both; a stale instance that keeps coming back is cleared at most MAX_RECOVERIES times
    /// in a row, then the profile stays `failed`, and a failed start is retried by itself only after a backoff (2.10.3
    /// retried every ~10 s, forever), the owner's doctor run at once.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_stale_instance_is_force_stopped_once_and_started_again_with_bounded_retries() {
        use crate::colima::MAX_RECOVERIES;
        let f = FakeColima::new(true, true);
        std::fs::create_dir_all(f.instance()).unwrap();
        std::fs::write(f.instance().join("vz.pid"), "4242").unwrap();     // what the killed host agent left
        f.rt.recheck();
        assert_eq!(f.settled(), "ready");
        let calls = f.calls();
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert!(calls[0].starts_with("start oarbank ") && calls[2].starts_with("start oarbank "), "{calls:?}");
        assert_eq!(calls[1], "stop --force oarbank");

        // stale every time: one force stop per start, MAX_RECOVERIES in a row, then failed without another
        let forced = |g: &FakeColima| g.calls().iter().filter(|c| *c == "stop --force oarbank").count();
        let g2 = FakeColima::new(true, true);
        std::fs::write(g2.dir.join("bin/stale"), "").unwrap();
        g2.rt.recheck();
        assert_eq!(g2.settled(), "failed");
        let r = g2.rt.report().unwrap();
        assert!(r["detail"].as_str().unwrap().contains("colima start oarbank failed (1)"), "{r}");
        for _ in 0..MAX_RECOVERIES + 2 {
            g2.rt.shared.retry().not_before = None;            // the backoff ran out
            g2.rt.reprobe();
            assert_eq!(g2.settled(), "failed");
        }
        assert_eq!(forced(&g2), MAX_RECOVERIES as usize, "bounded: {:?}", g2.calls());
        assert!(g2.rt.report().unwrap()["detail"].as_str().unwrap().contains("force stops in a row did not clear it"));
        // the backoff: a failed profile is not started again by itself before it ran out
        let n = g2.calls().len();
        g2.rt.recheck();
        g2.rt.reprobe();
        assert_eq!((g2.state(), g2.calls().len()), ("failed".to_string(), n), "backing off");
        // the owner's doctor run tries at once, and may clear a stale instance again; fixed, it is ready
        std::fs::remove_file(g2.dir.join("bin/stale")).unwrap();
        g2.rt.retry();
        assert_eq!(g2.settled(), "ready");

        // a plain start failure is not a stale instance: no force stop
        let h = FakeColima::new(true, true);
        std::fs::write(h.dir.join("bin/fail"), "").unwrap();
        h.rt.recheck();
        assert_eq!(h.settled(), "failed");
        assert_eq!(h.calls().len(), 1, "{:?}", h.calls());
    }

    /// A stopping agent stops its VM (gracefully; forced when that takes longer than its budget) so no stale instance
    /// is left; a profile without a VM is left alone.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_stopping_agent_stops_its_vm_within_its_budget() {
        let f = FakeColima::new(true, true);
        f.rt.shutdown(Duration::from_secs(10));
        assert!(f.calls().is_empty(), "no VM, nothing to stop");
        f.rt.recheck();
        assert_eq!(f.settled(), "ready");
        f.rt.shutdown(Duration::from_secs(10));
        assert_eq!(f.calls()[1..], ["stop oarbank"]);
        assert!(!crate::colima::instance_up(&f.instance()));
        // a stop that hangs: forced within the budget
        let g = FakeColima::new(true, true);
        g.rt.recheck();
        assert_eq!(g.settled(), "ready");
        std::fs::write(g.dir.join("bin/hang"), "").unwrap();
        let t = Instant::now();
        g.rt.shutdown(Duration::from_secs(10));
        assert!(t.elapsed() < Duration::from_secs(11), "{:?}", t.elapsed());
        assert_eq!(g.calls()[1..], ["stop oarbank", "stop --force oarbank"]);
        assert!(!crate::colima::instance_up(&g.instance()));
    }

    /// A Mac with krunkit: starts (never stops) the agent's own `oarbank-gpu` profile, builds the Vulkan compute probe
    /// (tests/fixtures/vulkan-compute) in it and runs it as a GPU job's container runs (`--device /dev/dri`): the
    /// container sees the Mac's GPU through Venus and a compute shader's result is right. Opt-in twice: `--ignored` and
    /// OARBANK_LIVE_COLIMA=1.
    #[test]
    #[ignore]
    #[cfg(target_os = "macos")]
    fn live_colima_gpu_runs_vulkan_compute_on_the_apple_gpu() {
        if std::env::var("OARBANK_LIVE_COLIMA").as_deref() != Ok("1") {
            eprintln!("set OARBANK_LIVE_COLIMA=1 to start the oarbank-gpu Colima profile");
            return;
        }
        let layout = crate::paths::Layout::new(crate::paths::agent_home());
        let host = crate::colima::detect(&layout.home);
        if !crate::colima::missing(&host).is_empty() || !crate::colima::gpu_missing(&host).is_empty() {
            eprintln!("krunkit (or Colima or docker) is not installed: brew tap slp/krun && brew trust slp/krun && brew install krunkit");
            return;
        }
        let (cpu, mut g) = ColimaRuntime::pair(&layout, false);
        cpu.set_report(crate::colima::Report::of(&host, crate::colima::State::Ready));
        assert_eq!(g.gpu_device().as_deref(), Some("/dev/dri"));
        (g.vm_cpus, g.vm_mem_gb) = (4, 4.0);
        g.ensure_started().unwrap();
        let image = "localhost/oarbank-vkcompute-test:1";
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vulkan-compute");
        let built = g.cli(&["build", "-q", "-t", image, &fixture.to_string_lossy()], 1800).unwrap();
        assert!(built.ok(), "{}", built.stderr_tail(2000));
        let ws = layout.work().join(format!("livegpu-{}", std::process::id()));
        std::fs::create_dir_all(&ws).unwrap();
        let out = ws.join("stdout");
        let spec = RunSpec {
            image: image.into(), platform: "linux/arm64".into(),
            args: vec!["sh".into(), "-c".into(), "vulkaninfo --summary 2>/dev/null | grep -E 'deviceName|driverName'; vkcompute".into()],
            entrypoint: None, mounts: vec![], env: vec![], workdir: None, network: false, cpus: 2.0, mem_gb: 2.0,
            attempt_id: -4243, module: "livetest".into(), timeout_s: 600.0, stdout: Some(std::fs::File::create(&out).unwrap()),
            stderr: Some(std::fs::File::create(ws.join("stderr")).unwrap()), gpu_device: g.gpu_device(),
        };
        let r = g.run(&spec, &AtomicBool::new(false)).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let err = std::fs::read_to_string(ws.join("stderr")).unwrap_or_default();
        eprintln!("{text}{err}");
        assert_eq!(r.exit_code, 0, "{text}{err}");
        let device = text.lines().find(|l| l.starts_with("device: ")).expect("vkcompute names its device");
        assert!(device.contains("Venus") && device.contains("Apple"), "not the Mac's GPU through Venus: {device}");
        assert!(text.contains("compute: ok 65536"), "{text}");
        g.remove_attempt(-4243);
        let _ = std::fs::remove_dir_all(ws);
    }

    /// Starts (never stops) the agent's own `oarbank` profile with this agent's real directories and runs a tiny
    /// image through it. Opt-in twice: `--ignored` and OARBANK_LIVE_COLIMA=1.
    #[test]
    #[ignore]
    #[cfg(target_os = "macos")]
    fn live_colima_runs_a_tiny_container() {
        if std::env::var("OARBANK_LIVE_COLIMA").as_deref() != Ok("1") {
            eprintln!("set OARBANK_LIVE_COLIMA=1 to start the oarbank Colima profile");
            return;
        }
        let layout = crate::paths::Layout::new(crate::paths::agent_home());
        let mut c = ColimaRuntime::new(&layout, Profile::Cpu);
        (c.vm_cpus, c.vm_mem_gb) = (2, 2.0);
        c.ensure_started().unwrap();
        let image = "docker.io/library/alpine:3.20";
        c.pull(image, "linux/arm64").unwrap();
        let ws = layout.work().join(format!("livetest-{}", std::process::id()));
        std::fs::create_dir_all(ws.join("in")).unwrap();
        std::fs::write(ws.join("in/hello.txt"), "hello from the host\n").unwrap();
        let out = ws.join("stdout");
        let spec = RunSpec {
            image: image.into(), platform: "linux/arm64".into(), args: vec!["cat".into(), "/in/hello.txt".into()],
            entrypoint: None, mounts: vec![Mount { host: std::fs::canonicalize(ws.join("in")).unwrap(), dst: "/in".into(), ro: true }], env: vec![],
            workdir: None, network: false, cpus: 1.0, mem_gb: 0.5, attempt_id: -4242, module: "livetest".into(), timeout_s: 120.0,
            stdout: Some(std::fs::File::create(&out).unwrap()), stderr: None, gpu_device: None,
        };
        let r = c.run(&spec, &AtomicBool::new(false)).unwrap();
        assert_eq!(r.exit_code, 0);
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "hello from the host\n");
        assert!(c.images().iter().any(|i| image_key(i).0 == "docker.io/library/alpine"));
        c.remove_attempt(-4242);
        let _ = std::fs::remove_dir_all(ws);
    }
}

