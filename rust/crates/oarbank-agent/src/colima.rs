//! The macOS container runtime's prerequisites and report (docs/design/macos-containers.md). The runtime itself is the
//! agent's own Colima profiles (container_runtime.rs, `ColimaRuntime`); everything here is plain code tested on every
//! OS: where the tools are, where Colima keeps the profiles, what is missing and its fix, and the facts' `containers`.
//!
//! The agent of a system install runs as `_oarbank` under launchd. Its account's home (`/Library/Application
//! Support/Oarbank`) belongs to root, and launchd gives a daemon the PATH `/usr/bin:/bin:/usr/sbin:/sbin`, so nothing
//! may come from the environment: the tools are looked up in Homebrew's directories, and Colima's state lives in the
//! agent's own home.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Homebrew's `bin` directories: Apple silicon's, then Intel's. Searched whatever PATH the agent was started with.
pub const BREW_DIRS: [&str; 2] = ["/opt/homebrew/bin", "/usr/local/bin"];
/// The helper PATH every Colima and docker call gets (Colima runs `limactl`, and `krunkit` for the GPU profile, off it).
pub const BASE_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
/// Present once Rosetta 2 is installed (`softwareupdate --install-rosetta`); Lima's `--vz-rosetta` needs it.
pub const ROSETTA_RUNTIME: &str = "/Library/Apple/usr/libexec/oah/libRosettaRuntime";
/// macOS's limit on a socket path (`sockaddr_un.sun_path`, with its NUL).
pub const UNIX_PATH_MAX: usize = 104;
/// The longest socket Lima creates in an instance directory: ssh's control socket, to which ssh appends 16 random
/// characters while it creates it (Lima's `filenames.LongestSock`; `limactl create` refuses a longer path).
pub const LONGEST_SOCK: &str = "ssh.sock.1234567890123456";
/// The agent's two profiles (container_runtime.rs `Profile`).
pub const CPU_PROFILE: &str = "oarbank";
pub const GPU_PROFILE: &str = "oarbank-gpu";

/// Where a tool was found.
#[derive(Debug, Clone, PartialEq)]
pub enum Found {
    /// Present, and this process (the agent's account) may run it.
    Usable(PathBuf),
    /// Present, but this account may not run it (a Homebrew prefix in a person's home, a file without the x bit for
    /// others).
    NotRunnable(PathBuf),
    Absent,
}

impl Found {
    pub fn usable(&self) -> Option<&Path> {
        match self {
            Found::Usable(p) => Some(p),
            _ => None,
        }
    }
}

/// The directories a tool is looked up in: Homebrew's first, then PATH's absolute entries (a launchd daemon's PATH
/// holds neither Homebrew directory unless its property list sets one).
pub fn search_dirs(path_env: Option<&std::ffi::OsStr>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = BREW_DIRS.iter().map(PathBuf::from).collect();
    for d in path_env.map(std::env::split_paths).into_iter().flatten() {
        if d.is_absolute() && !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    dirs
}

/// The first `name` in `dirs`: usable when `runnable` says this account may run it; else the first one present.
pub fn find(name: &str, dirs: &[PathBuf], runnable: &dyn Fn(&Path) -> bool) -> Found {
    let mut seen = None;
    for p in dirs.iter().map(|d| d.join(name)) {
        if runnable(&p) {
            return Found::Usable(p);
        }
        if seen.is_none() && std::fs::symlink_metadata(&p).is_ok() {
            seen = Some(p);
        }
    }
    seen.map(Found::NotRunnable).unwrap_or(Found::Absent)
}

/// Where Colima keeps the agent's profiles, and the environment that puts them there.
#[derive(Debug, Clone, PartialEq)]
pub struct Dirs {
    /// `HOME` for every Colima, Lima and docker call (Lima's and Colima's caches go under `Library/Caches` in it).
    pub home: PathBuf,
    /// Colima's configuration directory: `<config>/<profile>/docker.sock`, `<config>/_lima/colima-<profile>/`.
    pub config: PathBuf,
    /// `COLIMA_HOME`, when the configuration directory is not `$HOME/.colima`.
    pub colima_home: Option<PathBuf>,
}

/// A personal install (the agent's home is `~/Library/Application Support/Oarbank/agent` of the person it runs as)
/// keeps Colima in that person's `~/.colima`, as Colima always does (its own profiles, never the default one); there the
/// agent's home is too long a prefix for Lima's sockets. Any other home, a system install's above all, keeps Colima in
/// `<agent home>/colima`, which the agent's account owns: `HOME` and `COLIMA_HOME` both point there.
pub fn dirs(agent_home: &Path, user_home: Option<&Path>) -> Dirs {
    match user_home.filter(|h| h.is_absolute() && *h != Path::new("/") && agent_home.starts_with(h.join("Library"))) {
        Some(h) => Dirs { home: h.to_path_buf(), config: h.join(".colima"), colima_home: None },
        None => {
            let d = agent_home.join("colima");
            Dirs { home: d.clone(), config: d.clone(), colima_home: Some(d) }
        }
    }
}

/// The longest socket path Lima would create for a profile (`<config>/_lima/colima-<profile>/ssh.sock.<16>`).
pub fn longest_socket(config: &Path, profile: &str) -> PathBuf {
    config.join("_lima").join(format!("colima-{profile}")).join(LONGEST_SOCK)
}

pub fn socket_fits(config: &Path, profile: &str) -> bool {
    longest_socket(config, profile).as_os_str().len() < UNIX_PATH_MAX
}

/// What the agent found on this Mac (`detect` on macOS; built by hand in tests).
#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    /// Apple silicon (Rosetta and krunkit exist only there).
    pub arm: bool,
    pub colima: Found,
    pub docker: Found,
    pub limactl: Found,
    pub krunkit: Found,
    pub rosetta: bool,
    pub dirs: Dirs,
    /// The agent's account may create or write Colima's configuration directory.
    pub config_writable: bool,
    /// The account this process runs as (for the report's fixes).
    pub account: String,
    /// The owner of the directory that holds Colima's (the agent's home in a system install): the agent's account.
    pub owner: Option<String>,
}

/// What stops the runtime (or the GPU profile): a code, what was seen, and what the owner does about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Missing {
    pub what: &'static str,
    pub detail: String,
    pub fix: String,
}

impl Missing {
    pub fn json(&self) -> Value {
        json!({"what": self.what, "detail": self.detail, "fix": self.fix})
    }
}

fn brew_fix(formula: &str) -> String {
    format!("install it with Homebrew (as the Mac's administrator user): `brew install {formula}`; the agent finds it in \
             /opt/homebrew/bin or /usr/local/bin, then picks it up on its next release or restart")
}

fn tool(what: &'static str, formula: &str, found: &Found, account: &str) -> Option<Missing> {
    match found {
        Found::Usable(_) => None,
        Found::Absent => Some(Missing { what, detail: format!("{formula} is not installed (looked in {})", BREW_DIRS.join(", ")),
                                        fix: brew_fix(formula) }),
        Found::NotRunnable(p) => Some(Missing {
            what: "account_access",
            detail: format!("{} exists but the agent's account ({account}) may not run it", p.display()),
            fix: format!("install {formula} with Homebrew in /opt/homebrew (Apple silicon) or /usr/local (Intel), whose files every \
                          account may run, rather than in a person's home; `chmod o+rx` on a custom prefix also works"),
        }),
    }
}

/// What the CPU profile (`oarbank`) cannot start without, each with its fix. Empty: it can start.
pub fn missing(h: &Host) -> Vec<Missing> {
    let mut m: Vec<Missing> = [tool("colima", "colima", &h.colima, &h.account), tool("docker", "docker", &h.docker, &h.account),
                               tool("lima", "lima", &h.limactl, &h.account)].into_iter().flatten().collect();
    if h.arm && !h.rosetta {
        m.push(Missing { what: "rosetta", detail: format!("Rosetta 2 is not installed ({ROSETTA_RUNTIME} is missing): linux/amd64 \
                                                          images run under it"),
                         fix: "install Rosetta 2 as an administrator: `softwareupdate --install-rosetta --agree-to-license`".into() });
    }
    let other = h.owner.as_ref().filter(|o| **o != h.account);
    if let Some(o) = other {
        // a doctor run by someone else sees that account's access, not the agent's
        m.push(Missing { what: "account", detail: format!("this runs as {}, but the agent's home belongs to {o}: what the agent's \
                                                          account may write and run is not what this account may", h.account),
                         fix: format!("run it as the agent's account: `sudo -u {o} /Library/Oarbank/bin/oarbank-agent --home <the agent's \
                                       home> containers doctor`") });
    } else if !h.config_writable {
        m.push(Missing { what: "colima_home", detail: format!("the agent's account ({}) may not write {}", h.account, h.dirs.config.display()),
                         fix: format!("give the agent's account its own home back: `sudo chown -R {} \"{}\"` (a system install's \
                                       home belongs to its account), or reinstall the agent", h.account,
                                      h.dirs.config.parent().unwrap_or(&h.dirs.config).display()) });
    }
    for p in [CPU_PROFILE, GPU_PROFILE] {
        if !socket_fits(&h.dirs.config, p) {
            let s = longest_socket(&h.dirs.config, p);
            m.push(Missing { what: "socket_path", detail: format!("{} is {} bytes; macOS allows a socket path of {} at most", s.display(),
                                                                  s.as_os_str().len(), UNIX_PATH_MAX - 1),
                             fix: "install the agent with a shorter home directory (Lima keeps its sockets in the profile's directory)".into() });
            break;
        }
    }
    m
}

/// What the GPU profile (`oarbank-gpu`, krunkit) needs beyond the CPU profile's. Empty: GPU containers can run here.
pub fn gpu_missing(h: &Host) -> Vec<Missing> {
    if !h.arm {
        return vec![Missing { what: "apple_silicon", detail: "krunkit's GPU passthrough needs Apple silicon".into(),
                              fix: "none on an Intel Mac: GPU containers run on Apple silicon Macs and Linux or Windows nodes".into() }];
    }
    match &h.krunkit {
        Found::Usable(_) => vec![],
        Found::Absent => vec![Missing { what: "krunkit", detail: "krunkit is not installed: containers get no GPU here".into(),
                                        fix: "`brew tap slp/krun && brew trust slp/krun && brew install krunkit` (Homebrew asks you to \
                                              trust the third-party tap)".into() }],
        f @ Found::NotRunnable(_) => tool("krunkit", "krunkit", f, &h.account).into_iter().collect(),
    }
}

/// The OCI platforms the CPU profile runs: arm64 and (Rosetta) amd64 on Apple silicon, amd64 on Intel.
pub fn platforms(arm: bool) -> Vec<String> {
    if arm { vec!["linux/arm64".into(), "linux/amd64".into()] } else { vec!["linux/amd64".into()] }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum State {
    /// No release wants containers yet: the agent has not brought the runtime up.
    #[default]
    Absent,
    Starting,
    Ready,
    /// A prerequisite is missing (`missing` says which, with its fix).
    Missing,
    /// `colima start` failed (`detail` says why; the Colima log is in the agent's logs).
    Failed,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Absent => "absent",
            State::Starting => "starting",
            State::Ready => "ready",
            State::Missing => "missing",
            State::Failed => "failed",
        }
    }
}

/// The GPU profile's state: it starts with the first job that reserved the `gpu` pool (a second VM is not kept running
/// for nothing), and its first start proves the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpuState {
    /// krunkit (or Apple silicon) is missing: `gpu_missing` says what.
    #[default]
    Unavailable,
    /// Its prerequisites are there; it starts with the first GPU job.
    OnDemand,
    Starting,
    Ready,
    /// Its last start failed: no GPU is offered until the agent checks again (a release, a restart).
    Failed,
}

impl GpuState {
    pub fn as_str(&self) -> &'static str {
        match self {
            GpuState::Unavailable => "unavailable",
            GpuState::OnDemand => "on_demand",
            GpuState::Starting => "starting",
            GpuState::Ready => "ready",
            GpuState::Failed => "failed",
        }
    }
}

/// The runtime's report: the facts' `containers` on macOS.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub state: State,
    pub platforms: Vec<String>,
    pub missing: Vec<Missing>,
    pub detail: Option<String>,
    pub gpu_state: GpuState,
    pub gpu_missing: Vec<Missing>,
    pub gpu_detail: Option<String>,
    /// Colima's configuration directory (where the profiles live).
    pub colima_home: String,
}

impl Report {
    /// The report of what the agent finds before (or while) it brings the runtime up.
    pub fn of(h: &Host, state: State) -> Report {
        let missing = missing(h);
        let gpu_missing = gpu_missing(h);
        let state = if missing.is_empty() { state } else { State::Missing };
        Report { state, platforms: if state == State::Ready { platforms(h.arm) } else { vec![] }, missing,
                 gpu_state: if gpu_missing.is_empty() { GpuState::OnDemand } else { GpuState::Unavailable }, gpu_missing,
                 colima_home: h.dirs.config.display().to_string(), ..Default::default() }
    }

    pub fn ready(&self) -> bool {
        self.state == State::Ready
    }

    /// GPU passthrough is offered only while the runtime is ready, krunkit is there and the GPU profile has not failed.
    pub fn gpu(&self) -> bool {
        self.ready() && self.gpu_missing.is_empty() && matches!(self.gpu_state, GpuState::OnDemand | GpuState::Starting | GpuState::Ready)
    }

    pub fn json(&self) -> Value {
        let mut gpu = json!({"profile": GPU_PROFILE, "state": self.gpu_state.as_str(),
                             "missing": self.gpu_missing.iter().map(Missing::json).collect::<Vec<_>>()});
        if let Some(d) = &self.gpu_detail {
            gpu["detail"] = json!(d);
        }
        let mut j = json!({
            "runtime": "colima", "state": self.state.as_str(), "profile": CPU_PROFILE, "colima_home": self.colima_home,
            "platforms": self.platforms, "gpu": if self.gpu() { "virtio-gpu:venus" } else { "undetected" },
            "missing": self.missing.iter().map(Missing::json).collect::<Vec<_>>(), "gpu_profile": gpu,
        });
        if let Some(d) = &self.detail {
            j["detail"] = json!(d);
        }
        j
    }

    /// The GPU APIs a `gpus = "all"` container gets, and why (the doctor report's `gpu_apis.containers` and evidence).
    pub fn container_apis(&self) -> (Vec<String>, String) {
        if self.gpu() {
            return (vec!["vulkan".into()], format!("virtio-gpu:venus (krunkit, Colima profile {GPU_PROFILE}: {})", self.gpu_state.as_str()));
        }
        let why = if !self.ready() {
            format!("the container runtime (Colima profile {CPU_PROFILE}) is {}", self.state.as_str())
        } else if let Some(m) = self.gpu_missing.first() {
            m.detail.clone()
        } else {
            format!("the GPU profile ({GPU_PROFILE}) failed to start: {}", self.gpu_detail.as_deref().unwrap_or("see its log"))
        };
        (vec![], format!("no GPU in containers: {why}"))
    }

    /// What the runtime writes for the facts and the GPU probe (a child process): the facts' `containers` and the GPU
    /// APIs in containers with their evidence.
    pub fn state_json(&self) -> Value {
        let (apis, evidence) = self.container_apis();
        json!({"containers": self.json(), "gpu_apis": apis, "evidence": evidence})
    }

    /// One line for a broker refusal or a log: the first missing piece with its fix, or the failure.
    pub fn doctor_line(&self) -> String {
        match (self.missing.first(), &self.detail) {
            (Some(m), _) => format!("{}: {} ({})", m.what, m.detail, m.fix),
            (None, Some(d)) => d.clone(),
            (None, None) => format!("the agent's Colima profile {CPU_PROFILE} is {}", self.state.as_str()),
        }
    }
}

/// Where the runtime keeps its last report (facts read it; `oarbank-agent containers doctor` prints it).
pub fn report_file(home: &Path) -> PathBuf {
    home.join("state").join("containers.json")
}

/// The runtime's last state as written (`state_json`), or, before any (no release wants containers yet, or a fresh
/// agent run), the absent report of what the agent finds now.
pub fn last_state(home: &Path, now: impl FnOnce() -> Report) -> Value {
    std::fs::read(report_file(home)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .filter(|v| v["containers"]["runtime"] == "colima")
        .unwrap_or_else(|| now().state_json())
}

/// The facts' `containers` on macOS.
pub fn facts(home: &Path, now: impl FnOnce() -> Report) -> Value {
    last_state(home, now)["containers"].clone()
}

/// The GPU APIs in containers and their evidence, for gpuapi.rs.
pub fn container_apis(home: &Path, now: impl FnOnce() -> Report) -> (Vec<String>, String) {
    let v = last_state(home, now);
    let apis = v["gpu_apis"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    (apis, v["evidence"].as_str().unwrap_or("").to_string())
}

/// `colima start` arguments for a profile: the CPU profile on Virtualization.framework (with Rosetta for amd64 images on
/// Apple silicon; an Intel Mac's VM is x86_64 itself), the GPU profile on krunkit (no Rosetta; `sshfs`, Colima's name
/// for reverse-sshfs: Lima's krunkit driver refuses 9p, which Colima 0.10.3 picks off `vz` for any other type,
/// abiosoft/colima#1607). Both mount only the agent's work and modules-data directories, and neither writes the account's
/// `~/.ssh/config` (`--ssh-config=false`).
pub fn start_args(colima: &str, gpu: bool, arm: bool, cpus: u32, mem_gb: f64, mounts: &[String]) -> Vec<String> {
    let mut a = vec![colima.to_string(), "start".into(), if gpu { GPU_PROFILE } else { CPU_PROFILE }.into()];
    let vm: &[&str] = match (gpu, arm) {
        (true, _) => &["--vm-type", "krunkit", "--mount-type", "sshfs"],
        (false, true) => &["--vm-type", "vz", "--vz-rosetta"],
        (false, false) => &["--vm-type", "vz"],
    };
    a.extend(vm.iter().map(|s| s.to_string()));
    let mem = if mem_gb == mem_gb.round() { format!("{}", mem_gb as i64) } else { format!("{mem_gb:.1}") };
    a.extend(["--arch".into(), if arm { "aarch64" } else { "x86_64" }.into(), "--cpu".into(), cpus.to_string(), "--memory".into(), mem,
              "--disk".into(), "100".into(), "--ssh-config=false".into()]);
    for m in mounts {
        a.extend(["--mount".into(), format!("{m}:w")]);
    }
    a
}

/// The helper PATH: the directories the tools were found in (in that order), then the usual ones.
pub fn helper_path(found: &[&Found]) -> String {
    let mut dirs: Vec<String> = vec![];
    for f in found {
        if let Some(d) = f.usable().and_then(Path::parent) {
            let d = d.display().to_string();
            if !dirs.contains(&d) {
                dirs.push(d);
            }
        }
    }
    for d in BASE_PATH.split(':') {
        if !dirs.iter().any(|x| x == d) {
            dirs.push(d.to_string());
        }
    }
    dirs.join(":")
}

/// What this Mac has, as the agent's account sees it.
#[cfg(target_os = "macos")]
pub fn detect(agent_home: &Path) -> Host {
    detect_with(dirs(agent_home, std::env::var_os("HOME").map(PathBuf::from).as_deref()))
}

/// The same, with Colima kept in `d`.
#[cfg(target_os = "macos")]
pub fn detect_with(d: Dirs) -> Host {
    let dirs_ = search_dirs(std::env::var_os("PATH").as_deref());
    let runnable = |p: &Path| executable(p);
    Host {
        arm: cfg!(target_arch = "aarch64"),
        colima: find("colima", &dirs_, &runnable),
        docker: find("docker", &dirs_, &runnable),
        limactl: find("limactl", &dirs_, &runnable),
        krunkit: find("krunkit", &dirs_, &runnable),
        rosetta: Path::new(ROSETTA_RUNTIME).exists(),
        config_writable: creatable(&d.config),
        owner: d.config.parent().and_then(owner_name),
        dirs: d,
        account: user_name(unsafe { libc::geteuid() }),
    }
}

#[cfg(unix)]
pub fn executable(p: &Path) -> bool {
    p.is_file() && std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0)
}

/// `p` is a directory this account may write, or the nearest existing ancestor is (it can be created).
#[cfg(unix)]
pub fn creatable(p: &Path) -> bool {
    let w = |q: &Path| std::ffi::CString::new(q.as_os_str().as_encoded_bytes()).is_ok_and(|c| unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) } == 0);
    match p.ancestors().find(|a| a.exists()) {
        Some(a) => a.is_dir() && w(a),
        None => false,
    }
}

#[cfg(target_os = "macos")]
fn owner_name(p: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| user_name(m.uid()))
}

#[cfg(target_os = "macos")]
fn user_name(uid: u32) -> String {
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return format!("uid {uid}");
    }
    unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        Host { arm: true, colima: Found::Usable("/opt/homebrew/bin/colima".into()), docker: Found::Usable("/opt/homebrew/bin/docker".into()),
               limactl: Found::Usable("/opt/homebrew/bin/limactl".into()), krunkit: Found::Absent, rosetta: true,
               dirs: dirs(Path::new("/Library/Application Support/Oarbank/agent"), Some(Path::new("/Library/Application Support/Oarbank"))),
               config_writable: true, account: "_oarbank".into(), owner: Some("_oarbank".into()) }
    }

    /// Homebrew's directories come first whatever PATH says (a launchd daemon's PATH has neither), then PATH's own
    /// absolute entries, once each.
    #[test]
    fn tools_are_looked_up_in_homebrew_whatever_the_path() {
        assert_eq!(search_dirs(None), [PathBuf::from("/opt/homebrew/bin"), PathBuf::from("/usr/local/bin")]);
        let p = std::env::join_paths(["/usr/bin", "/opt/homebrew/bin", "relative", "/Users/u/.local/bin"]).unwrap();
        assert_eq!(search_dirs(Some(&p)), ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/Users/u/.local/bin"].map(PathBuf::from));
    }

    #[test]
    #[cfg(unix)]
    fn a_tool_is_usable_only_where_this_account_may_run_it() {
        use std::os::unix::fs::PermissionsExt;
        let t = crate::scratch("colima-find");
        let (a, b) = (t.path().join("a"), t.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let dirs = [a.clone(), b.clone()];
        assert_eq!(find("colima", &dirs, &|p: &Path| executable(p)), Found::Absent);
        std::fs::write(a.join("colima"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(a.join("colima"), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(find("colima", &dirs, &|p: &Path| executable(p)), Found::NotRunnable(a.join("colima")), "present, not runnable");
        std::fs::write(b.join("colima"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(b.join("colima"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(find("colima", &dirs, &|p: &Path| executable(p)), Found::Usable(b.join("colima")), "a later runnable one wins");
        // a dangling Homebrew link (an uninstalled formula) is not usable either
        std::os::unix::fs::symlink(t.path().join("gone"), a.join("docker")).unwrap();
        assert_eq!(find("docker", &dirs, &|p: &Path| executable(p)), Found::NotRunnable(a.join("docker")));
        assert!(!executable(&b), "a directory is not a tool");
    }

    /// A system install keeps Colima in the agent's own home (its account's home belongs to root); a personal one in
    /// the person's ~/.colima, as Colima always does. Who runs the agent's CLI (root's HOME is /var/root) changes nothing.
    #[test]
    fn colima_lives_where_the_agent_may_write_and_its_sockets_fit() {
        let sys = Path::new("/Library/Application Support/Oarbank/agent");
        let d = dirs(sys, Some(Path::new("/Library/Application Support/Oarbank")));
        assert_eq!(d, Dirs { home: sys.join("colima"), config: sys.join("colima"), colima_home: Some(sys.join("colima")) });
        assert_eq!(dirs(sys, Some(Path::new("/var/root"))), d);
        assert_eq!(dirs(sys, None), d);
        assert_eq!(dirs(sys, Some(Path::new("/"))), d);
        let me = Path::new("/Users/u");
        let p = dirs(&me.join("Library/Application Support/Oarbank/agent"), Some(me));
        assert_eq!(p, Dirs { home: me.into(), config: me.join(".colima"), colima_home: None });
        // OARBANK_AGENT_HOME elsewhere (a test, a second agent) keeps its own
        assert_eq!(dirs(Path::new("/tmp/x"), Some(me)).config, PathBuf::from("/tmp/x/colima"));
        // the system home's longest socket fits (100 bytes); the agent's home itself as HOME (+/.colima) would also fit,
        // a personal home's Application Support path would not
        assert_eq!(longest_socket(&d.config, GPU_PROFILE).as_os_str().len(), 100);
        assert!(socket_fits(&d.config, CPU_PROFILE) && socket_fits(&d.config, GPU_PROFILE));
        assert!(!socket_fits(Path::new("/Users/someone/Library/Application Support/Oarbank/agent/colima"), GPU_PROFILE));
        assert!(socket_fits(&p.config, GPU_PROFILE));
    }

    #[test]
    fn each_missing_piece_names_its_fix() {
        assert!(missing(&host()).is_empty());
        let mut h = host();
        (h.colima, h.docker, h.rosetta, h.config_writable) = (Found::Absent, Found::NotRunnable("/Users/u/brew/bin/docker".into()), false, false);
        let m = missing(&h);
        let whats: Vec<&str> = m.iter().map(|m| m.what).collect();
        assert_eq!(whats, ["colima", "account_access", "rosetta", "colima_home"]);
        assert!(m[0].fix.contains("brew install colima"));
        assert!(m[1].detail.contains("/Users/u/brew/bin/docker") && m[1].detail.contains("_oarbank"));
        assert!(m[2].fix.contains("softwareupdate --install-rosetta"));
        assert!(m[3].detail.contains("/Library/Application Support/Oarbank/agent/colima") && m[3].fix.contains("chown -R _oarbank"));
        // run by another account (the owner at a terminal): that account's view says so instead of advising a chown
        let mut o = host();
        (o.account, o.config_writable) = ("tnt".into(), false);
        let m = missing(&o);
        assert_eq!(m.iter().map(|m| m.what).collect::<Vec<_>>(), ["account"]);
        assert!(m[0].fix.contains("sudo -u _oarbank") && !m[0].fix.contains("chown"));
        // lima comes with colima, but a broken install shows it
        let mut l = host();
        l.limactl = Found::Absent;
        assert_eq!(missing(&l)[0].what, "lima");
        // an Intel Mac needs no Rosetta (its VM is x86_64), and has no GPU profile
        let mut intel = host();
        (intel.arm, intel.rosetta) = (false, false);
        assert!(missing(&intel).is_empty());
        assert_eq!(gpu_missing(&intel)[0].what, "apple_silicon");
        // a home too long for Lima's sockets
        let mut long = host();
        long.dirs.config = PathBuf::from(format!("/{}/colima", "x".repeat(60)));
        assert_eq!(missing(&long).iter().map(|m| m.what).collect::<Vec<_>>(), ["socket_path"]);
        assert_eq!(gpu_missing(&host())[0].what, "krunkit");
        assert!(gpu_missing(&host())[0].fix.contains("brew install krunkit"));
        let mut k = host();
        k.krunkit = Found::Usable("/opt/homebrew/bin/krunkit".into());
        assert!(gpu_missing(&k).is_empty());
    }

    /// The report always names the runtime; the GPU is offered only from a ready runtime whose GPU profile can start
    /// (the Studio reported `virtio-gpu:venus` with no runtime at all).
    #[test]
    fn the_report_offers_the_gpu_only_from_a_ready_runtime() {
        let mut k = host();
        k.krunkit = Found::Usable("/opt/homebrew/bin/krunkit".into());
        let starting = Report::of(&k, State::Starting);
        let j = starting.json();
        assert_eq!((j["runtime"].as_str(), j["state"].as_str(), j["gpu"].as_str()), (Some("colima"), Some("starting"), Some("undetected")));
        assert_eq!(j["gpu_profile"]["state"], "on_demand");
        assert_eq!(j["platforms"], json!([]));
        assert_eq!(starting.container_apis().0, Vec::<String>::new());
        assert!(starting.container_apis().1.contains("is starting"));
        let ready = Report::of(&k, State::Ready);
        assert_eq!(ready.json()["gpu"], "virtio-gpu:venus");
        assert_eq!(ready.json()["platforms"], json!(["linux/arm64", "linux/amd64"]));
        assert_eq!(ready.container_apis().0, ["vulkan"]);
        let failed = Report { gpu_state: GpuState::Failed, gpu_detail: Some("no /dev/dri/renderD128".into()), ..ready.clone() };
        assert_eq!(failed.json()["gpu"], "undetected");
        assert!(failed.container_apis().1.contains("no /dev/dri/renderD128"));
        // no krunkit: a ready runtime without GPU
        let plain = Report::of(&host(), State::Ready);
        assert_eq!((plain.json()["gpu"].as_str(), plain.json()["gpu_profile"]["state"].as_str()), (Some("undetected"), Some("unavailable")));
        assert_eq!(plain.json()["gpu_profile"]["missing"][0]["what"], "krunkit");
        // a missing piece wins over the state asked for
        let mut none = host();
        none.colima = Found::Absent;
        let m = Report::of(&none, State::Ready);
        assert_eq!((m.json()["state"].as_str(), m.json()["missing"][0]["what"].as_str()), (Some("missing"), Some("colima")));
        assert!(m.json()["missing"][0]["fix"].as_str().unwrap().contains("brew install colima"));
        assert!(m.doctor_line().starts_with("colima: colima is not installed"));
        let f = Report { state: State::Failed, detail: Some("colima start oarbank failed (1)".into()), ..plain };
        assert_eq!(f.doctor_line(), "colima start oarbank failed (1)");
        assert_eq!(f.json()["detail"], "colima start oarbank failed (1)");
    }

    /// The facts read the runtime's last state; before any, what the agent finds now (absent, with what is missing).
    #[test]
    fn the_facts_read_the_last_state_or_what_is_there_now() {
        let t = crate::scratch("colima-state");
        let home = t.path();
        let mut none = host();
        none.docker = Found::Absent;
        let now = || Report::of(&none, State::Absent);
        let f = facts(home, now);
        assert_eq!((f["runtime"].as_str(), f["state"].as_str(), f["missing"][0]["what"].as_str()), (Some("colima"), Some("missing"), Some("docker")));
        assert_eq!(facts(home, || Report::of(&host(), State::Absent))["state"], "absent");
        let mut k = host();
        k.krunkit = Found::Usable("/opt/homebrew/bin/krunkit".into());
        let ready = Report::of(&k, State::Ready);
        crate::fsutil::write_private(&report_file(home), &serde_json::to_vec(&ready.state_json()).unwrap()).unwrap();
        assert_eq!(facts(home, now), ready.json());
        assert_eq!(container_apis(home, now), (vec!["vulkan".to_string()], ready.container_apis().1));
        // another runtime's file (a Windows report copied over) is not this one's
        std::fs::write(report_file(home), r#"{"containers": {"runtime": "wslc", "state": "ready"}}"#).unwrap();
        assert_eq!(facts(home, now)["runtime"], "colima");
    }

    #[test]
    fn start_arguments_follow_the_mac_and_the_profile() {
        let mounts = ["/a/work".to_string(), "/a/modules-data".to_string()];
        assert_eq!(start_args("colima", false, true, 6, 8.0, &mounts)[1..],
                   ["start", "oarbank", "--vm-type", "vz", "--vz-rosetta", "--arch", "aarch64", "--cpu", "6", "--memory", "8", "--disk", "100",
                    "--ssh-config=false", "--mount", "/a/work:w", "--mount", "/a/modules-data:w"]);
        assert_eq!(start_args("colima", false, false, 4, 2.5, &mounts)[1..9], ["start", "oarbank", "--vm-type", "vz", "--arch", "x86_64", "--cpu", "4"]);
        assert_eq!(start_args("colima", false, false, 4, 2.5, &mounts)[10], "2.5");
        assert_eq!(start_args("colima", true, true, 6, 8.0, &mounts)[1..7], ["start", "oarbank-gpu", "--vm-type", "krunkit", "--mount-type", "sshfs"]);
    }

    #[test]
    fn the_helper_path_starts_where_the_tools_are() {
        let c = Found::Usable("/opt/local/bin/colima".into());
        let d = Found::Usable("/opt/homebrew/bin/docker".into());
        assert_eq!(helper_path(&[&c, &d, &Found::Absent]), "/opt/local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
        assert_eq!(helper_path(&[]), BASE_PATH);
    }
}
