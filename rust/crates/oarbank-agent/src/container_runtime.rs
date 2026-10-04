//! The agent's container runtime (spec/sandbox.md, "Containers"; docs/design/module-sandbox.md, decision 3). Modules
//! never reach Docker: the broker validates their requests and hands this runtime a finished `RunSpec`. On macOS the
//! runtime is an agent-owned Colima profile, `oarbank`, whose VM mounts only the agent's work and modules-data
//! directories (Colima's default profile mounts `$HOME` writable, so its socket is the whole home), and GPU containers
//! run in a second one, `oarbank-gpu`, on krunkit (docs/design/gpu-placement.md).

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
}

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
/// value, and the GPU APIs a container then has.
#[derive(Debug, Clone, PartialEq)]
pub struct Passthrough {
    /// `cdi:<kind>` or `virtio-gpu:venus`.
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
#[cfg(any(target_os = "linux", test))]
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
    cmd.args(rest).env_clear().envs(env.iter().map(|(k, v)| (k, v))).stdin(Stdio::null())
        .stdout(stdio(&out).map_err(|e| e.to_string())?).stderr(stdio(&err).map_err(|e| e.to_string())?);
    let mut child = crate::sys::spawn_contained(&mut cmd, false).map_err(|e| format!("{prog}: {e}"))?;
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
    r.code = status.code().unwrap_or_else(|| 128 + crate::sys::exit_signal(&status).unwrap_or(0));
    r.stdout = ro.and_then(|h| h.join().ok()).unwrap_or_default();
    r.stderr = re.and_then(|h| h.join().ok()).unwrap_or_default();
    Ok(r)
}

fn quick(argv: &[String], env: &[(String, String)], timeout_s: u64) -> Result<Exec, String> {
    exec(argv, env, Duration::from_secs(timeout_s), Out::Capture, Out::Capture, &AtomicBool::new(false), Duration::from_secs(5))
}

/// Remove every container `ps` lists for `filter` (a label filter); the ids removed.
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

fn executable(p: &Path) -> bool {
    std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0)
}

/// Where a Linux container engine keeps its configuration and (rootless Podman) its storage: the account's own home
/// when this process may write it (the personal scope), else the agent's home. A system install's `oarbank` account has
/// the home /var/lib/oarbank, which is root's: rootless Podman cannot create its configuration there and every command
/// fails ("stat /var/lib/oarbank/.config: no such file or directory").
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn engine_home(account_home: Option<PathBuf>, agent_home: &Path) -> PathBuf {
    let writable = |p: &Path| p.is_dir() && std::ffi::CString::new(p.as_os_str().as_encoded_bytes())
        .is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK) } == 0);
    account_home.filter(|h| writable(h)).unwrap_or_else(|| agent_home.to_path_buf())
}

// MARK: Colima

/// Which of the agent's two Colima profiles: `oarbank` runs every container on Virtualization.framework with Rosetta;
/// `oarbank-gpu` runs the containers of GPU jobs on krunkit, whose virtio-gpu device gives them Vulkan on the Mac's GPU
/// (Mesa's Venus driver in the container, MoltenVK on the host; docs/design/gpu-placement.md).
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
            Profile::Cpu => "oarbank",
            Profile::Gpu => "oarbank-gpu",
        }
    }
}

#[cfg(target_os = "macos")]
/// One of the agent-owned Colima profiles. Only these profiles are ever started or queried; the docker CLI is pointed at
/// the profile's socket through `DOCKER_HOST` with an empty `DOCKER_CONFIG` of the agent's own, so neither the user's
/// current context nor `~/.docker` (contexts, credential helpers that reach the keychain) is used.
pub struct ColimaRuntime {
    pub profile: Profile,
    /// The user's home: Colima keeps the profile in `~/.colima/<profile>`.
    pub home: PathBuf,
    pub colima: PathBuf,
    pub docker: PathBuf,
    /// The only two host directories the VM mounts.
    pub work: PathBuf,
    pub modules_data: PathBuf,
    pub docker_config: PathBuf,
    pub log: PathBuf,
    pub vm_cpus: u32,
    pub vm_mem_gb: f64,
    start_lock: Mutex<()>,
}

#[cfg(target_os = "macos")]
const HELPER_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// The DRM render node a krunkit guest's virtio-gpu device appears as.
#[cfg(target_os = "macos")]
const RENDER_NODE: &str = "/dev/dri/renderD128";

#[cfg(target_os = "macos")]
fn find_bin(name: &str) -> PathBuf {
    ["/opt/homebrew/bin", "/usr/local/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists())
        .unwrap_or_else(|| Path::new("/opt/homebrew/bin").join(name))
}

#[cfg(target_os = "macos")]
fn realpath(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// GPU passthrough on macOS: Colima, docker and krunkit installed (Colima finds krunkit on the helper `PATH`) on Apple
/// silicon. The krunkit VM gives containers Vulkan through `/dev/dri`.
#[cfg(target_os = "macos")]
pub fn gpu_passthrough() -> Option<Passthrough> {
    let krunkit = find_bin("krunkit");
    let ok = cfg!(target_arch = "aarch64") && executable(&find_bin("colima")) && executable(&find_bin("docker")) && executable(&krunkit);
    ok.then(|| Passthrough { kind: "virtio-gpu:venus".into(), device: "/dev/dri".into(), apis: vec!["vulkan".into()],
                             evidence: format!("virtio-gpu:venus (krunkit at {})", krunkit.display()) })
}

#[cfg(target_os = "macos")]
impl ColimaRuntime {
    /// The runtime for this agent's layout and one of its profiles, sized by the host's RAM.
    pub fn new(layout: &crate::paths::Layout, profile: Profile) -> Self {
        let ram = crate::facts::sysctl_u64("hw.memsize").unwrap_or(0) as f64 / 1073741824.0;
        let (mem, cpus, _) = sizing(ram, None, None);
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
        ColimaRuntime {
            profile, home, colima: find_bin("colima"), docker: find_bin("docker"), work: layout.work(), modules_data: layout.module_data(),
            docker_config: layout.run().join("docker"), log: layout.logs().join(format!("colima-{}.log", profile.name())),
            vm_cpus: cpus, vm_mem_gb: mem, start_lock: Mutex::new(()),
        }
    }

    /// This runtime's `containers` pool size.
    pub fn pool_tokens(&self) -> u32 {
        tokens(self.vm_mem_gb)
    }

    pub fn installed(&self) -> bool {
        executable(&self.colima) && executable(&self.docker)
    }

    pub fn docker_socket(&self) -> PathBuf {
        self.home.join(".colima").join(self.profile.name()).join("docker.sock")
    }

    fn base_env(&self) -> Vec<(String, String)> {
        vec![("PATH".into(), HELPER_PATH.into()), ("HOME".into(), self.home.to_string_lossy().into()),
             ("DOCKER_CONFIG".into(), self.docker_config.to_string_lossy().into())]
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

    fn fmt_gb(m: f64) -> String {
        if m == m.round() { format!("{}", m as i64) } else { format!("{m:.1}") }
    }

    /// The CPU profile on Virtualization.framework with Rosetta for amd64 images; the GPU profile on krunkit (no
    /// Rosetta). Both mount only the agent's work and modules-data directories.
    pub fn start_args(&self) -> Vec<String> {
        let c = self.colima.to_string_lossy().to_string();
        let mut a = vec![c, "start".into(), self.profile.name().into()];
        a.extend(match self.profile {
            Profile::Cpu => ["--vm-type", "vz", "--vz-rosetta"].as_slice(),
            Profile::Gpu => ["--vm-type", "krunkit"].as_slice(),
        }.iter().map(|s| s.to_string()));
        a.extend(["--arch".into(), "aarch64".into(), "--cpu".into(), self.vm_cpus.to_string(), "--memory".into(),
                  Self::fmt_gb(self.vm_mem_gb), "--disk".into(), "100".into(),
                  "--mount".into(), format!("{}:w", realpath(&self.work).to_string_lossy()),
                  "--mount".into(), format!("{}:w", realpath(&self.modules_data).to_string_lossy())]);
        a
    }

    fn colima_cmd(&self, args: &[&str]) -> Vec<String> {
        let mut v = vec![self.colima.to_string_lossy().to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        v
    }

    fn cli(&self, args: &[&str], timeout_s: u64) -> Result<Exec, String> {
        crate::fsutil::private_dir(&self.docker_config).map_err(|e| format!("{}: {e}", self.docker_config.display()))?;
        let mut argv = vec![self.docker.to_string_lossy().to_string()];
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
}

#[cfg(target_os = "macos")]
impl ContainerRuntime for ColimaRuntime {
    fn pool_tokens(&self) -> u32 {
        ColimaRuntime::pool_tokens(self)
    }

    /// `colima status <profile> --json`: running, and the VM's memory (colima 0.10 reports bytes). The GPU VM runs
    /// arm64 images only: krunkit has no Rosetta.
    fn status(&self) -> Result<RuntimeStatus, String> {
        if !self.installed() {
            return Err(format!("{} or {} missing", self.colima.display(), self.docker.display()));
        }
        let platforms = match self.profile {
            Profile::Cpu => vec!["linux/arm64".to_string(), "linux/amd64".to_string()],
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
        let _g = self.start_lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.status()?.running {
            return Ok(());
        }
        for d in [&self.work, &self.modules_data] {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        crate::fsutil::private_dir(&self.docker_config).map_err(|e| e.to_string())?;
        let (o, e) = (self.log_file(), self.log_file());
        // the first start downloads the VM image
        let r = exec(&self.start_args(), &self.colima_env(), Duration::from_secs(600), o, e, &AtomicBool::new(false),
                     Duration::from_secs(10))?;
        if !r.ok() {
            return Err(format!("colima start {} failed ({}{}); see {}", self.profile.name(), r.code,
                               if r.timed_out { ", timeout" } else { "" }, self.log.display()));
        }
        match self.profile {
            Profile::Cpu => Ok(()),
            Profile::Gpu => self.has_render_node(),
        }
    }

    fn pull(&self, image: &str, platform: &str) -> Result<(), String> {
        let r = self.cli(&["pull", "--platform", platform, image], 1800)?;
        if r.ok() { Ok(()) } else { Err(r.stderr_tail(1000)) }
    }

    fn run(&self, spec: &RunSpec, cancel: &AtomicBool) -> Result<RunResult, String> {
        crate::fsutil::private_dir(&self.docker_config).map_err(|e| e.to_string())?;
        let mut argv = vec![self.docker.to_string_lossy().to_string()];
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
        if !self.running() {
            return vec![];
        }
        remove_labelled(|a, t| self.cli(a, t), &format!("label={ATTEMPT_LABEL}"))
    }

    fn remove_attempt(&self, attempt_id: i64) -> Vec<String> {
        if !self.running() {
            return vec![];
        }
        remove_labelled(|a, t| self.cli(a, t), &format!("label={ATTEMPT_LABEL}={attempt_id}"))
    }

    /// The GPU VM's guest passes its render node through.
    fn gpu_device(&self) -> Option<String> {
        (self.profile == Profile::Gpu).then(|| "/dev/dri".to_string())
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


/// GPU passthrough on Linux: a container engine and a CDI spec with an `all` device.
#[cfg(target_os = "linux")]
pub fn gpu_passthrough() -> Option<Passthrough> {
    let engine = ["/usr/bin", "/usr/local/bin", "/bin"].iter()
        .find_map(|d| ["podman", "docker"].iter().map(|n| Path::new(d).join(n)).find(|p| executable(p)))?;
    let spec = cdi_spec(&CDI_DIRS.map(Path::new))?;
    Some(Passthrough { device: format!("{}=all", spec.kind), evidence: format!("cdi:{} ({})", spec.kind, engine.display()),
                       kind: format!("cdi:{}", spec.kind), apis: spec.apis })
}

/// This node's container runtimes, if it has any: the agent's Colima profiles on macOS (the GPU one where krunkit is
/// installed), the host's engine on Linux (also the GPU runtime where a CDI spec exists).
#[cfg(target_os = "macos")]
pub fn for_node(layout: &crate::paths::Layout) -> Option<Containers> {
    let cpu = ColimaRuntime::new(layout, Profile::Cpu);
    cpu.installed().then(|| Containers {
        cpu: std::sync::Arc::new(cpu),
        gpu: gpu_passthrough().map(|_| std::sync::Arc::new(ColimaRuntime::new(layout, Profile::Gpu)) as std::sync::Arc<dyn ContainerRuntime>),
    })
}

#[cfg(target_os = "linux")]
pub fn for_node(layout: &crate::paths::Layout) -> Option<Containers> {
    let rt: std::sync::Arc<dyn ContainerRuntime> = std::sync::Arc::new(NativeRuntime::detect(layout, crate::host::memory().ram_gb)?);
    let gpu = rt.gpu_device().is_some().then(|| rt.clone());
    Some(Containers { cpu: rt, gpu })
}


#[cfg(test)]
pub mod tests {
    use super::*;

    /// The engine's home: the account's own when it may write it, else the agent's (a system install's account home is
    /// root's), and the agent's when there is no HOME at all.
    #[test]
    fn the_engine_keeps_its_state_where_the_agent_may_write() {
        use std::os::unix::fs::PermissionsExt;
        let (mine, agent, roots) = (temp("eh-mine"), temp("eh-agent"), temp("eh-root"));
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
        let home = temp("native");
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
        let _ = std::fs::remove_dir_all(&home);
    }

    fn temp(tag: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!("oarbank-crt-{tag}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    #[cfg(target_os = "macos")]
    fn colima_at(base: &Path, profile: Profile) -> ColimaRuntime {
        let l = crate::paths::Layout::new(base.join("agent"));
        let mut c = ColimaRuntime::new(&l, profile);
        c.home = PathBuf::from("/Users/u");
        c
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
        let base = temp("start");
        let mut c = colima_at(&base, Profile::Cpu);
        (c.vm_cpus, c.vm_mem_gb) = (6, 10.0);
        std::fs::create_dir_all(&c.work).unwrap();
        std::fs::create_dir_all(&c.modules_data).unwrap();
        let a = c.start_args();
        let agent = base.join("agent").to_string_lossy().to_string();
        assert_eq!(a[1..], ["start", "oarbank", "--vm-type", "vz", "--vz-rosetta", "--arch", "aarch64", "--cpu", "6", "--memory",
                            "10", "--disk", "100", "--mount", &format!("{agent}/work:w"), "--mount", &format!("{agent}/modules-data:w")]);
        assert_eq!(a.iter().filter(|x| *x == "--mount").count(), 2);
        assert!(!a.iter().any(|x| x.starts_with("/Users/u")));
        let env = c.docker_env();
        let get = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert_eq!(get("DOCKER_HOST").as_deref(), Some("unix:///Users/u/.colima/oarbank/docker.sock"));
        assert_eq!(get("DOCKER_CONFIG"), Some(format!("{agent}/run/docker")));
        assert!(get("DOCKER_CONTEXT").is_none());
        assert!(c.colima_env().iter().any(|(k, v)| k == "DOCKER_CONFIG" && *v == format!("{agent}/run/docker")));
        assert_eq!(c.gpu_device(), None);
        let _ = std::fs::remove_dir_all(base);
    }

    /// The GPU profile is a VM of its own on krunkit (no Rosetta, arm64 images only), with the same two mounts and its own
    /// socket and log, and its containers get `--device /dev/dri`. A CPU job's containers never go there.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_gpu_profile_is_a_krunkit_vm_of_its_own() {
        let base = temp("gpu");
        let mut g = colima_at(&base, Profile::Gpu);
        (g.vm_cpus, g.vm_mem_gb) = (6, 10.0);
        let agent = base.join("agent").to_string_lossy().to_string();
        assert_eq!(g.start_args()[1..], ["start", "oarbank-gpu", "--vm-type", "krunkit", "--arch", "aarch64", "--cpu", "6", "--memory",
                                          "10", "--disk", "100", "--mount", &format!("{agent}/work:w"),
                                          "--mount", &format!("{agent}/modules-data:w")]);
        assert_eq!(g.docker_socket(), PathBuf::from("/Users/u/.colima/oarbank-gpu/docker.sock"));
        assert!(g.log.ends_with("logs/colima-oarbank-gpu.log"));
        assert_eq!(g.gpu_device().as_deref(), Some("/dev/dri"));
        let spec = RunSpec { gpu_device: g.gpu_device(), ..spec("x@sha256:00") };
        assert!(spec.docker_args().windows(2).any(|w| w == ["--device", "/dev/dri"]));
        let cpu: std::sync::Arc<dyn ContainerRuntime> = std::sync::Arc::new(colima_at(&base, Profile::Cpu));
        let both = Containers { cpu: cpu.clone(), gpu: Some(std::sync::Arc::new(g)) };
        assert!(std::sync::Arc::ptr_eq(&both.for_job(false), &cpu) && both.for_job(true).gpu_device().is_some());
        assert_eq!(both.all().len(), 2);
        let none = Containers { cpu: cpu.clone(), gpu: None };
        assert!(std::sync::Arc::ptr_eq(&none.for_job(true), &cpu) && none.all().len() == 1);
        let same = Containers { cpu: cpu.clone(), gpu: Some(cpu.clone()) };
        assert_eq!(same.all().len(), 1, "on Linux the GPU runtime is the CPU runtime: reaped once");
        let _ = std::fs::remove_dir_all(base);
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
        let s = RunSpec {
            image: format!("genonet/hap-py@{d}"), platform: "linux/amd64".into(), args: vec![], entrypoint: None, mounts: vec![],
            env: vec![], workdir: None, network: false, cpus: 1.0, mem_gb: 1.0, attempt_id: 1, module: "m".into(), timeout_s: 1.0,
            stdout: None, stderr: None, gpu_device: None,
        };
        assert_eq!(s.docker_args_with(&qualified(&s.image)).last().unwrap(), &format!("docker.io/genonet/hap-py@{d}"));
        assert_eq!(s.docker_args().last().unwrap(), &s.image);
    }

    #[test]
    fn cdi_specs_name_the_gpu_device_kind() {
        let kind = |dirs: &[&Path]| cdi_spec(dirs).map(|s| s.kind);
        let d = temp("cdi");
        assert_eq!(kind(&[d.as_path()]), None);
        std::fs::write(d.join("readme.txt"), "kind: x/y\n- name: all\n").unwrap();
        assert_eq!(kind(&[d.as_path()]), None, "only .json, .yaml and .yml files are specs");
        std::fs::write(d.join("nvidia.yaml"), "---\ncdiVersion: 0.5.0\ncontainerEdits:\n  deviceNodes:\n  - path: /dev/nvidiactl\n\
            devices:\n- containerEdits:\n    deviceNodes:\n    - path: /dev/nvidia0\n  name: \"0\"\n- containerEdits:\n\
                deviceNodes:\n    - path: /dev/nvidia0\n  name: all\nkind: nvidia.com/gpu\n").unwrap();
        assert_eq!(kind(&[d.as_path()]).as_deref(), Some("nvidia.com/gpu"));
        let j = temp("cdi-json");
        std::fs::write(j.join("amd.json"), r#"{"cdiVersion": "0.6.0", "kind": "amd.com/gpu", "devices": [{"name": "0"}]}"#).unwrap();
        assert_eq!(kind(&[j.as_path()]), None, "no `all` device");
        std::fs::write(j.join("amd.json"), r#"{"kind": "amd.com/gpu", "devices": [{"name": "0"}, {"name": "all"}]}"#).unwrap();
        assert_eq!(kind(&[j.as_path(), d.as_path()]).as_deref(), Some("amd.com/gpu"));
    }

    /// The APIs a container gets come from what the spec passes: recorded specs of `nvidia-ctk cdi generate` (a Linux
    /// host, and `--mode=wsl` over GPU-PV), and AMD's (`amd-ctk cdi generate`).
    #[test]
    fn cdi_specs_name_the_apis_a_container_gets() {
        let d = temp("cdi-apis");
        std::fs::write(d.join("nvidia.yaml"), "---\ncdiVersion: 0.5.0\ncontainerEdits:\n  deviceNodes:\n  - path: /dev/nvidiactl\n\
            \x20 - path: /dev/nvidia-uvm\n  mounts:\n  - containerPath: /usr/lib/x86_64-linux-gnu/libcuda.so.570.86.15\n\
            \x20   hostPath: /usr/lib/x86_64-linux-gnu/libcuda.so.570.86.15\n    options: [ro, nosuid, nodev, bind]\n\
            \x20 - containerPath: /usr/lib/x86_64-linux-gnu/libnvidia-opencl.so.570.86.15\n\
            \x20   hostPath: /usr/lib/x86_64-linux-gnu/libnvidia-opencl.so.570.86.15\n\
            \x20 - containerPath: /etc/vulkan/icd.d/nvidia_icd.json\n    hostPath: /etc/vulkan/icd.d/nvidia_icd.json\n\
            devices:\n- containerEdits:\n    deviceNodes:\n    - path: /dev/nvidia0\n  name: all\nkind: nvidia.com/gpu\n").unwrap();
        assert_eq!(cdi_spec(&[d.as_path()]).unwrap().apis, ["cuda", "opencl", "vulkan"]);
        let w = temp("cdi-wsl");
        std::fs::write(w.join("nvidia.json"), r#"{"cdiVersion": "0.5.0", "kind": "nvidia.com/gpu",
            "devices": [{"name": "all", "containerEdits": {"deviceNodes": [{"path": "/dev/dxg"}]}}],
            "containerEdits": {"mounts": [{"hostPath": "/usr/lib/wsl/lib/libcuda.so.1.1", "containerPath": "/usr/lib/wsl/lib/libcuda.so.1.1"},
                                          {"hostPath": "/usr/lib/wsl/lib/libd3d12.so", "containerPath": "/usr/lib/wsl/lib/libd3d12.so"}]}}"#).unwrap();
        assert_eq!(cdi_spec(&[w.as_path()]).unwrap().apis, ["cuda"]);
        let a = temp("cdi-amd");
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

    #[test]
    #[cfg(target_os = "macos")]
    fn a_missing_runtime_is_an_error_not_a_stopped_vm() {
        let base = temp("missing");
        let mut c = colima_at(&base, Profile::Cpu);
        c.colima = "/nonexistent/colima".into();
        assert!(c.status().unwrap_err().contains("missing"));
        assert!(c.ensure_started().is_err());
        assert!(c.remove_attempt(1).is_empty());
        let _ = std::fs::remove_dir_all(base);
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
        let Some(pass) = gpu_passthrough() else {
            eprintln!("krunkit (or Colima or docker) is not installed: brew tap slp/krun && brew install krunkit");
            return;
        };
        assert_eq!((pass.kind.as_str(), pass.device.as_str(), pass.apis.as_slice()), ("virtio-gpu:venus", "/dev/dri", ["vulkan".to_string()].as_slice()));
        let layout = crate::paths::Layout::new(crate::paths::agent_home());
        let containers = for_node(&layout).expect("Colima is installed");
        let rt = containers.for_job(true);
        assert_eq!(rt.gpu_device().as_deref(), Some("/dev/dri"));
        let mut g = ColimaRuntime::new(&layout, Profile::Gpu);
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

