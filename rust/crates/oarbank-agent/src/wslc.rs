//! The Windows container runtime (docs/design/windows-containers.md, PLAN D39): a WSL containers (WSLc) session the
//! agent creates and owns. A session is a VM of its own, made by the WSL service for this account: its name is the
//! agent's (`oarbank-<hash of the home>`, session names are machine-wide), its storage lives under the agent's home and
//! its CPUs, memory and disk are the agent's budget. The session host (one thread) creates the session through the
//! WSLc SDK (`wslcsdk.dll`, loaded from the agent's own directory), holds it for the agent's life and recreates it when
//! its termination event fires; every container operation is `wslc.exe --session <name> ...` with a fixed shape (the
//! SDK has no per-container limits, labels or listing; the CLI reaches an SDK session of the same account by name).
//!
//! Everything above the WSL boundary (arguments, paths, the settings file, output parsing, the doctor report) is plain
//! code tested on every OS; the FFI and the process calls are Windows only.

use crate::container_runtime::{fmt_num, RunSpec, ATTEMPT_LABEL, MODULE_LABEL};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The SDK library, beside the agent's executable (the MSI installs it from Microsoft.WSL.Containers).
pub const SDK_DLL: &str = "wslcsdk.dll";
/// The CDI device kind the session's guest writes for GPU-PV (`/etc/cdi/microsoft.com-wslc.json`, device `gpu`).
pub const CDI_KIND: &str = "microsoft.com/wslc";
/// The session's disk: its VHD holds the images, containers and volumes (the Colima profile's `--disk` likewise).
pub const DISK_GB: u64 = 100;
/// The oldest WSL whose package carries WSLc.
pub const MIN_WSL: (u32, u32, u32) = (2, 9, 3);

/// The session's name: machine-wide, so one per agent home (a personal and a system agent on one machine differ).
pub fn session_name(home: &Path) -> String {
    use sha2::{Digest, Sha256};
    format!("oarbank-{}", &hex::encode(Sha256::digest(home.to_string_lossy().as_bytes()))[..12])
}

/// A host path as `wslc -v` takes it: the plain Windows spelling, without the `\\?\` (or `\\?\UNC\`) prefix that
/// canonical paths carry.
pub fn host_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    if let Some(unc) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
    }
}

/// The session VM's memory and CPUs: the budget the other runtimes get (`sizing`), within what the host has. A VM asked
/// for more processors than the host has does not start (`E_FAIL` on a 4-core runner asked for 6), and one taking more
/// than half the host's memory starves it.
pub fn session_size(ram_gb: f64, logical: u32) -> (f64, u32) {
    let (mem_gb, cpus, _) = crate::container_runtime::sizing(ram_gb, None, None);
    (mem_gb.min((ram_gb / 2.0).floor()).max(1.0), cpus.min(logical).max(1))
}

/// `wslc` memory: whole MiB (`2.5` GB is `2560m`).
pub fn mem_arg(gb: f64) -> String {
    format!("{}m", (gb * 1024.0).round().max(1.0) as u64)
}

/// Exactly: `--session S container run --rm --network none|bridge --cpus C --memory <MiB>m --label
/// oarbank.attempt_id=<id> --label oarbank.module=<name> [--gpus all] [-v host:dst[:ro]]... [--workdir W] [--entrypoint
/// E] [-e K=V]... image args...`. wslc has no `--platform` (a session runs its host's architecture; the broker already
/// checked the platform against the runtime's), and everything after the image goes to the container.
pub fn run_args(session: &str, spec: &RunSpec, image: &str) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "--session".into(), session.into(), "container".into(), "run".into(), "--rm".into(),
        "--network".into(), if spec.network { "bridge" } else { "none" }.into(),
        "--cpus".into(), fmt_num(spec.cpus), "--memory".into(), mem_arg(spec.mem_gb),
        "--label".into(), format!("{ATTEMPT_LABEL}={}", spec.attempt_id), "--label".into(), format!("{MODULE_LABEL}={}", spec.module),
    ];
    if spec.gpu_device.as_deref().is_some_and(|k| !k.is_empty()) {
        a.extend(["--gpus".into(), "all".into()]);
    }
    for m in &spec.mounts {
        a.push("-v".into());
        a.push(format!("{}:{}{}", host_path(&m.host), m.dst, if m.ro { ":ro" } else { "" }));
    }
    if let Some(w) = &spec.workdir {
        a.extend(["--workdir".into(), w.clone()]);
    }
    if let Some(e) = &spec.entrypoint {
        a.extend(["--entrypoint".into(), e.clone()]);
    }
    for (k, v) in &spec.env {
        a.extend(["-e".into(), format!("{k}={v}")]);
    }
    a.push(image.to_string());
    a.extend(spec.args.iter().cloned());
    a
}

/// wslc's text: UTF-8, or UTF-16LE where a console code page made it so.
pub fn decode(b: &[u8]) -> String {
    let utf16 = b.len() >= 2 && b.len().is_multiple_of(2) && b.iter().skip(1).step_by(2).filter(|c| **c == 0).count() * 2 >= b.len() / 2;
    if utf16 {
        let w: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&w).trim_start_matches('\u{feff}').to_string()
    } else {
        String::from_utf8_lossy(b).trim_start_matches('\u{feff}').to_string()
    }
}

/// The symbolic code wslc ends a failure with (`Error code: WSLC_E_SESSION_NOT_FOUND`).
pub fn error_code(stderr: &str) -> Option<String> {
    stderr.lines().find_map(|l| l.trim().strip_prefix("Error code:")).map(|c| c.trim().to_string()).filter(|c| !c.is_empty())
}

/// The first line of a failure, its message.
pub fn error_message(stderr: &str) -> String {
    stderr.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_string()
}

/// `image list --digests --format json` (one JSON object per line, Docker's fields): `repository@sha256:<digest>`.
pub fn parse_images(out: &str) -> Vec<String> {
    out.lines().filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .filter_map(|j| Some(format!("{}@{}", j["Repository"].as_str()?, j["Digest"].as_str()?)))
        .filter(|i| !i.contains("<none>")).collect()
}

/// `container list --quiet`: one container id per line.
pub fn parse_ids(out: &str) -> Vec<String> {
    out.lines().map(str::trim).filter(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_hexdigit())).map(str::to_string).collect()
}

/// Whether `system session list` (its table: ID, creator PID, display name) shows a session of this name.
pub fn session_listed(out: &str, name: &str) -> bool {
    out.lines().skip(1).any(|l| l.split_whitespace().nth(2) == Some(name))
}

/// What stops the runtime: a code from the design note, what was seen, and what to do about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Missing {
    pub what: &'static str,
    pub detail: String,
}

impl Missing {
    pub fn new(what: &'static str, detail: impl Into<String>) -> Missing {
        Missing { what, detail: detail.into() }
    }

    pub fn fix(&self) -> &'static str {
        match self.what {
            "virtual_machine_platform" => "enable the Virtual Machine Platform: run `oarbank-agent containers install` as an administrator \
                                           (or install the agent with `msiexec /i oarbank-agent.msi CONTAINERS=1`), then restart Windows",
            "wsl_package" => "install WSL 2.9.3 or later: run `oarbank-agent containers install` as an administrator (or `wsl --install \
                              --no-distribution`, then `wsl --update`)",
            "sdk_update" => "update the Oarbank agent: its WSL containers SDK is older than the WSL installed here",
            "sdk_library" => "reinstall the Oarbank agent: wslcsdk.dll belongs beside oarbank-agent.exe",
            "wslc_cli" => "install WSL 2.9.3 or later, which provides wslc.exe: `oarbank-agent containers install` as an administrator",
            "host_loopback" => "add `session:` with `  hostLoopback: none` to %LOCALAPPDATA%\\wslc\\settings.yaml of the agent's account \
                                (containers must not reach this machine's loopback services, as on Linux), then restart the agent",
            "virtualization" => "turn on hardware virtualization in the firmware (in a virtual machine: nested virtualization), then restart",
            "policy" => "an administrator's policy turns WSL containers off (HKLM\\Software\\Policies\\WSL, AllowWSLContainer)",
            "account" => "WSL containers refuse this account: run the agent's service as a local account (`oarbank-launcher service install \
                          --system --user ACCOUNT`)",
            _ => "see the detail",
        }
    }

    pub fn json(&self) -> Value {
        json!({"what": self.what, "detail": self.detail, "fix": self.fix()})
    }
}

/// The missing component an SDK flag names (`WslcGetMissingComponents`).
pub fn missing_components(flags: u32) -> Vec<Missing> {
    let mut m = vec![];
    if flags & 1 != 0 {
        m.push(Missing::new("virtual_machine_platform", "the Virtual Machine Platform feature is not installed"));
    }
    if flags & 2 != 0 {
        m.push(Missing::new("wsl_package", "WSL 2.9.3 or later is not installed"));
    }
    if flags & 4 != 0 {
        m.push(Missing::new("sdk_update", "the WSL installed needs a newer WSL containers SDK"));
    }
    m
}

/// What a wslc or SDK failure means for the node, by its symbolic code (recorded from WSL 3.0.1); None: not a missing
/// prerequisite (a failure to report as is).
pub fn classify(code: &str) -> Option<&'static str> {
    Some(match code {
        "HCS_E_SERVICE_NOT_AVAILABLE" => "virtual_machine_platform",
        "HCS_E_HYPERV_NOT_INSTALLED" | "WSL_E_VM_MODE_INVALID_STATE" | "HCS_E_INVALID_STATE" => "virtualization",
        "WSLC_E_CONTAINER_DISABLED" | "WSL_E_WSL_DISABLED_BY_POLICY" => "policy",
        "WSLC_E_SDK_UPDATE_NEEDED" => "sdk_update",
        "WSL_E_LOCAL_SYSTEM_NOT_SUPPORTED" | "E_ACCESSDENIED" => "account",
        _ => return None,
    })
}

/// Whether the account's WSLc settings (`settings.yaml`) turn the host loopback off: an uncommented `hostLoopback:
/// none` inside the top-level `session:` block.
pub fn host_loopback_off(settings: &str) -> bool {
    let mut in_session = false;
    for line in settings.lines() {
        let code = line.split('#').next().unwrap_or("");
        if code.trim().is_empty() {
            continue;
        }
        if !code.starts_with([' ', '\t']) {
            in_session = code.trim_end() == "session:";
            continue;
        }
        if let (true, Some(v)) = (in_session, code.trim().strip_prefix("hostLoopback:")) {
            return v.trim().trim_matches(|c| c == '"' || c == '\'') == "none";
        }
    }
    false
}

/// The settings file with `session.hostLoopback: none` (None: already so). Keeps everything else: a different value is
/// replaced in place, a missing key goes first in an existing `session:` block, else a block is appended.
pub fn with_host_loopback_off(settings: Option<&str>) -> Option<String> {
    let text = settings.unwrap_or("");
    if host_loopback_off(text) {
        return None;
    }
    let mut out: Vec<String> = vec![];
    let (mut in_session, mut done) = (false, false);
    for line in text.lines() {
        let code = line.split('#').next().unwrap_or("");
        if !code.trim().is_empty() && !code.starts_with([' ', '\t']) {
            in_session = code.trim_end() == "session:";
            out.push(line.to_string());
            if in_session && !done && !text.lines().any(|l| l.split('#').next().unwrap_or("").trim().starts_with("hostLoopback:")) {
                out.push("  hostLoopback: none".into());
                done = true;
            }
            continue;
        }
        if in_session && !done && code.trim().starts_with("hostLoopback:") {
            let indent: String = code.chars().take_while(|c| c.is_whitespace()).collect();
            out.push(format!("{indent}hostLoopback: none"));
            done = true;
            continue;
        }
        out.push(line.to_string());
    }
    if !done {
        if out.last().is_some_and(|l| !l.is_empty()) {
            out.push(String::new());
        }
        out.extend(["session:".to_string(), "  hostLoopback: none".to_string()]);
    }
    Some(out.join("\n") + "\n")
}

/// What the session VM itself shows (`system session run`): its architecture, the GPU-PV device, the WSL libraries
/// and the Linux user-mode drivers in the host's driver store, which the guest's CDI spec mounts into GPU containers.
pub const PROBE: &str = "echo \"arch:$(uname -m)\"; test -e /dev/dxg && echo dxg; \
    for f in /usr/lib/wsl/lib/*; do [ -e \"$f\" ] && echo \"lib:${f##*/}\"; done; \
    for f in /usr/lib/wsl/drivers/*/*.so*; do [ -e \"$f\" ] && echo \"drv:${f#/usr/lib/wsl/drivers/}\"; done; true";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Probe {
    pub arch: Option<String>,
    pub dxg: bool,
    pub libs: Vec<String>,
    /// `<driver store folder>/<library>`: the Linux user-mode drivers GPU drivers ship for WSL.
    pub drivers: Vec<String>,
}

pub fn parse_probe(out: &str) -> Probe {
    let mut p = Probe::default();
    for l in out.lines().map(str::trim) {
        if let Some(a) = l.strip_prefix("arch:") {
            p.arch = Some(a.to_string()).filter(|a| !a.is_empty());
        } else if l == "dxg" {
            p.dxg = true;
        } else if let Some(f) = l.strip_prefix("lib:") {
            p.libs.push(f.to_string());
        } else if let Some(f) = l.strip_prefix("drv:") {
            p.drivers.push(f.to_string());
        }
    }
    p
}

impl Probe {
    /// The OCI platform the session runs.
    pub fn platform(&self) -> Option<String> {
        match self.arch.as_deref()? {
            "x86_64" => Some("linux/amd64".into()),
            "aarch64" | "arm64" => Some("linux/arm64".into()),
            _ => None,
        }
    }

    /// GPU-PV with a host GPU behind it: the device, and a vendor driver that ships a Linux user-mode driver for WSL
    /// (`*.so` in its driver store folder). A VM's display adapter (Hyper-V Video) and the Basic Render Driver ship none.
    pub fn gpu(&self) -> bool {
        self.dxg && !self.drivers.is_empty()
    }

    /// The GPU APIs a `--gpus all` container gets from the host: D3D12 (DirectML) where WSL's D3D12 and DXCore are
    /// there, CUDA where the NVIDIA driver installed its WSL library. ROCm and Level Zero on WSL bring their runtimes in
    /// the image: not attested.
    pub fn gpu_apis(&self) -> Vec<String> {
        if !self.gpu() {
            return vec![];
        }
        let has = |n: &str| self.libs.iter().any(|l| l == n);
        let mut apis = vec![];
        if has("libcuda.so.1") || has("libcuda.so") {
            apis.push("cuda".to_string());
        }
        if has("libd3d12.so") && has("libdxcore.so") {
            apis.push("directml".to_string());
        }
        apis
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum State {
    /// No release wants containers yet: no session.
    #[default]
    Absent,
    Starting,
    Ready,
    Missing,
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

/// The runtime's report: facts `containers` on Windows (docs/design/windows-containers.md, "The node's report").
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub state: State,
    pub session: String,
    pub platforms: Vec<String>,
    pub probe: Probe,
    pub missing: Vec<Missing>,
    pub detail: Option<String>,
}

impl Report {
    pub fn ready(&self) -> bool {
        self.state == State::Ready
    }

    /// GPU passthrough: only from a ready session whose VM has a GPU.
    pub fn gpu(&self) -> bool {
        self.ready() && self.probe.gpu()
    }

    pub fn json(&self) -> Value {
        let mut j = json!({
            "runtime": "wslc", "state": self.state.as_str(), "session": self.session, "platforms": self.platforms,
            "gpu": if self.gpu() { format!("cdi:{CDI_KIND}") } else { "undetected".into() },
            "missing": self.missing.iter().map(Missing::json).collect::<Vec<_>>(),
        });
        if let Some(d) = &self.detail {
            j["detail"] = json!(d);
        }
        j
    }

    /// The GPU APIs a `gpus = "all"` container gets, and why (the doctor report's `gpu_apis.containers` and its evidence).
    pub fn container_apis(&self) -> (Vec<String>, String) {
        if self.gpu() {
            let libs: Vec<&str> = self.probe.libs.iter().map(String::as_str).filter(|l| l.contains(".so")).collect();
            return (self.probe.gpu_apis(), format!("cdi:{CDI_KIND} (WSL containers session {}: {})", self.session, libs.join(", ")));
        }
        let why = match self.state {
            State::Ready => "the WSL containers session's VM has no GPU".to_string(),
            _ => format!("the WSL containers session is {}", self.state.as_str()),
        };
        (vec![], format!("no GPU in containers: {why}"))
    }

    /// What the runtime writes for the facts and the GPU probe (which runs in a child process): the facts' `containers`
    /// and the GPU APIs in containers with their evidence.
    pub fn state_json(&self) -> Value {
        let (apis, evidence) = self.container_apis();
        json!({"containers": self.json(), "gpu_apis": apis, "evidence": evidence})
    }
}

/// The facts' `containers` before any session state was written (no release wants containers yet).
pub fn absent_report() -> Value {
    json!({"runtime": "wslc", "state": "absent", "platforms": [], "gpu": "undetected", "missing": []})
}

/// The runtime's last state as written (`state_json`), or the absent one.
fn last_state(home: &Path) -> Value {
    std::fs::read(report_file(home)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .filter(|v| v["containers"].is_object())
        .unwrap_or_else(|| json!({"containers": absent_report(), "gpu_apis": [], "evidence": "no GPU in containers: no WSL containers session yet"}))
}

/// The facts' `containers` on Windows.
pub fn facts(home: &Path) -> Value {
    last_state(home)["containers"].clone()
}

/// The GPU APIs in containers and their evidence, for gpuapi.rs.
pub fn container_apis(home: &Path) -> (Vec<String>, String) {
    let v = last_state(home);
    let apis = v["gpu_apis"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
    (apis, v["evidence"].as_str().unwrap_or("").to_string())
}

/// Where the runtime keeps its last report (facts read it; `oarbank-agent containers doctor` prints it).
pub fn report_file(home: &Path) -> PathBuf {
    home.join("state").join("containers.json")
}

/// The session's storage under the agent's home.
pub fn storage_dir(home: &Path) -> PathBuf {
    home.join("containers").join("wslc")
}

/// The system scope's home is under ProgramData (the service's virtual account owns its WSLc settings); the personal
/// scope's under the user's LocalAppData (the user's settings, never edited).
pub fn owns_account_settings(home: &Path, program_data: Option<&Path>) -> bool {
    program_data.is_some_and(|pd| home.starts_with(pd))
}

// MARK: Windows: the runtime

#[cfg(windows)]
pub use imp::*;

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::container_runtime::{exec, quick, qualified, tokens, ContainerRuntime, Exec, Out, RunResult, RuntimeStatus};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE};

    /// The SDK's entry points the agent uses (wslcsdk.h, Microsoft.WSL.Containers 3.0.1), resolved at run time.
    mod sdk {
        use std::ffi::c_void;
        pub type Hresult = i32;
        pub type Session = *mut c_void;

        #[repr(C, align(8))]
        pub struct SessionSettings(pub [u8; 72]);

        #[repr(C)]
        pub struct VhdRequirements {
            pub name: *const u8,
            pub size_bytes: u64,
            pub kind: u32,
            pub flags: u32,
            pub uid: u32,
            pub gid: u32,
        }

        pub const FEATURE_GPU: u32 = 0x4;
        pub const COMPONENT_VMP: u32 = 1;
        pub const COMPONENT_WSL: u32 = 2;
        pub const E_ALREADY_EXISTS: Hresult = 0x800700B7u32 as i32;

        pub struct Sdk {
            _lib: usize,
            pub version: unsafe extern "system" fn(*mut [u32; 3]) -> Hresult,
            pub missing: unsafe extern "system" fn(*mut u32) -> Hresult,
            pub install: unsafe extern "system" fn(u32, u32, Option<unsafe extern "system" fn(u32, u32, u32, *mut c_void)>, *mut c_void) -> Hresult,
            pub init: unsafe extern "system" fn(*const u16, *const u16, *mut SessionSettings) -> Hresult,
            pub cpus: unsafe extern "system" fn(*mut SessionSettings, u32) -> Hresult,
            pub memory: unsafe extern "system" fn(*mut SessionSettings, u32) -> Hresult,
            pub vhd: unsafe extern "system" fn(*mut SessionSettings, *const VhdRequirements) -> Hresult,
            pub features: unsafe extern "system" fn(*mut SessionSettings, u32) -> Hresult,
            pub create: unsafe extern "system" fn(*mut SessionSettings, *mut Session, *mut *mut u16) -> Hresult,
            pub termination: unsafe extern "system" fn(Session, *mut windows_sys::Win32::Foundation::HANDLE) -> Hresult,
            pub release: unsafe extern "system" fn(Session) -> Hresult,
        }

        // the function pointers are plain code addresses in a library that stays loaded
        unsafe impl Send for Sdk {}
        unsafe impl Sync for Sdk {}

        impl Sdk {
            /// Load the library from `path` only (never the DLL search path), and resolve every entry point.
            pub fn load(path: &std::path::Path) -> Result<Sdk, String> {
                use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
                                                                LOAD_LIBRARY_SEARCH_SYSTEM32};
                let w: Vec<u16> = path.as_os_str().to_string_lossy().encode_utf16().chain([0]).collect();
                let lib = unsafe { LoadLibraryExW(w.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32) };
                if lib.is_null() {
                    return Err(format!("{}: {}", path.display(), std::io::Error::last_os_error()));
                }
                let sym = |n: &str| -> Result<usize, String> {
                    let c = std::ffi::CString::new(n).expect("no NUL");
                    unsafe { GetProcAddress(lib, c.as_ptr() as *const u8) }.map(|f| f as usize)
                        .ok_or_else(|| format!("{}: no {n}", path.display()))
                };
                // an exported function's address as the entry point's type (both are one pointer wide)
                unsafe fn entry<T>(addr: usize) -> T {
                    unsafe { std::mem::transmute_copy(&addr) }
                }
                unsafe {
                    Ok(Sdk {
                        version: entry(sym("WslcGetVersion")?),
                        missing: entry(sym("WslcGetMissingComponents")?),
                        install: entry(sym("WslcInstallWithDependencies")?),
                        init: entry(sym("WslcInitSessionSettings")?),
                        cpus: entry(sym("WslcSetSessionSettingsCpuCount")?),
                        memory: entry(sym("WslcSetSessionSettingsMemory")?),
                        vhd: entry(sym("WslcSetSessionSettingsVhd")?),
                        features: entry(sym("WslcSetSessionSettingsFeatureFlags")?),
                        create: entry(sym("WslcCreateSession")?),
                        termination: entry(sym("WslcGetSessionTerminationEvent")?),
                        release: entry(sym("WslcReleaseSession")?),
                        _lib: lib as usize,
                    })
                }
            }
        }

        /// A wide string the SDK allocated (CoTaskMemAlloc), taken and freed.
        pub fn take_message(p: *mut u16) -> Option<String> {
            if p.is_null() {
                return None;
            }
            let n = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
            let s = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) });
            unsafe { windows_sys::Win32::System::Com::CoTaskMemFree(p as _) };
            Some(s)
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain([0]).collect()
    }

    /// The agent's own directory (the SDK library sits beside its executable).
    fn agent_dir() -> PathBuf {
        std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)).unwrap_or_default()
    }

    /// wslc.exe of the WSL package.
    fn find_wslc() -> PathBuf {
        let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
        pf.join("WSL").join("wslc.exe")
    }

    /// What every wslc call gets: the account's own environment entries a Windows program needs, nothing else.
    fn env() -> Vec<(String, String)> {
        ["SystemRoot", "SystemDrive", "windir", "ProgramFiles", "ProgramData", "LOCALAPPDATA", "APPDATA", "USERPROFILE",
         "TEMP", "TMP", "PATH", "COMPUTERNAME", "USERNAME", "USERDOMAIN"]
            .iter().filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v))).collect()
    }

    struct Shared {
        report: Mutex<Report>,
        changed: Condvar,
        /// Auto-reset: ask the host to (re)create the session (a release wants containers, a session vanished).
        kick: usize,
        stop: usize,
    }

    /// The agent's WSLc session and the CLI that drives it.
    pub struct WslcRuntime {
        pub home: PathBuf,
        pub session: String,
        pub wslc: PathBuf,
        pub sdk: PathBuf,
        pub mem_gb: f64,
        pub cpus: u32,
        shared: Arc<Shared>,
    }

    impl WslcRuntime {
        /// The runtime for this agent, sized by the host's RAM, with its session host started.
        pub fn start(layout: &crate::paths::Layout, ram_gb: f64) -> WslcRuntime {
            let logical = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
            let (mem_gb, cpus) = session_size(ram_gb, logical);
            WslcRuntime::start_at(&layout.home, agent_dir().join(SDK_DLL), mem_gb, cpus)
        }

        /// The same with an explicit SDK library and size (the live tests).
        pub fn start_at(home: &Path, sdk: PathBuf, mem_gb: f64, cpus: u32) -> WslcRuntime {
            let rt = WslcRuntime::new(home, sdk, find_wslc(), mem_gb, cpus);
            rt.spawn_host();
            rt
        }

        pub fn new(home: &Path, sdk: PathBuf, wslc: PathBuf, mem_gb: f64, cpus: u32) -> WslcRuntime {
            let event = |manual: i32| unsafe { CreateEventW(std::ptr::null(), manual, 0, std::ptr::null()) } as usize;
            let report = Report { state: State::Starting, session: session_name(home), ..Default::default() };
            WslcRuntime { home: home.to_path_buf(), session: session_name(home), wslc, sdk, mem_gb, cpus,
                          shared: Arc::new(Shared { report: Mutex::new(report), changed: Condvar::new(), kick: event(0), stop: event(1) }) }
        }

        fn spawn_host(&self) {
            let host = Host { home: self.home.clone(), session: self.session.clone(), wslc: self.wslc.clone(), sdk: self.sdk.clone(),
                              mem_gb: self.mem_gb, cpus: self.cpus, shared: self.shared.clone() };
            std::thread::Builder::new().name("wslc-session".into()).spawn(move || host.run()).expect("spawn the session host");
        }

        pub fn snapshot(&self) -> Report {
            self.shared.report.lock().unwrap().clone()
        }

        /// Ask the host to create the session again (it was missing, or a call found it gone).
        pub fn kick(&self) {
            unsafe { SetEvent(self.shared.kick as HANDLE) };
        }

        pub fn cli(&self, args: &[&str], timeout_s: u64) -> Result<Exec, String> {
            wslc_cli(&self.wslc, &self.session, args, timeout_s)
        }

        /// Remove every container the session lists for `filter` (a label filter); the ids removed.
        fn remove_labelled(&self, filter: &str) -> Vec<String> {
            let Ok(r) = self.cli(&["container", "list", "--all", "--quiet", "--no-trunc", "--filter", filter], 30) else { return vec![] };
            self.noticed(&r);
            let ids = parse_ids(&decode(&r.stdout));
            if !ids.is_empty() {
                let mut args = vec!["container", "rm", "--force"];
                args.extend(ids.iter().map(String::as_str));
                let _ = self.cli(&args, 120);
            }
            ids
        }

        /// A failed call that shows the session is gone: the host recreates it.
        fn noticed(&self, r: &Exec) {
            if !r.ok() && error_code(&decode(&r.stderr)).as_deref() == Some("WSLC_E_SESSION_NOT_FOUND") {
                self.kick();
            }
        }
    }

    impl Drop for WslcRuntime {
        fn drop(&mut self) {
            unsafe { SetEvent(self.shared.stop as HANDLE) };
        }
    }

    fn wslc_cli(wslc: &Path, session: &str, args: &[&str], timeout_s: u64) -> Result<Exec, String> {
        let mut argv = vec![wslc.display().to_string(), "--session".into(), session.into()];
        argv.extend(args.iter().map(|s| s.to_string()));
        quick(&argv, &env(), timeout_s)
    }

    impl ContainerRuntime for WslcRuntime {
        fn status(&self) -> Result<RuntimeStatus, String> {
            let r = self.snapshot();
            Ok(RuntimeStatus { running: r.ready(), mem_gb: Some(self.mem_gb), platforms: r.platforms.clone(),
                               detail: (!r.ready()).then(|| doctor_line(&r)) })
        }

        /// The session host starts the session; this waits for it to become ready (or to report why not).
        fn ensure_started(&self) -> Result<(), String> {
            self.kick();
            let deadline = std::time::Instant::now() + Duration::from_secs(180);
            let mut g = self.shared.report.lock().unwrap();
            loop {
                match g.state {
                    State::Ready => return Ok(()),
                    State::Missing | State::Failed => return Err(doctor_line(&g)),
                    _ => {}
                }
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    return Err("the agent's WSL containers session did not start within 180 s".into());
                }
                g = self.shared.changed.wait_timeout(g, left).unwrap().0;
            }
        }

        fn pull(&self, image: &str, _platform: &str) -> Result<(), String> {
            let r = self.cli(&["image", "pull", &qualified(image)], 1800)?;
            self.noticed(&r);
            if r.ok() { Ok(()) } else { Err(decode(&r.stderr).trim().to_string()) }
        }

        fn run(&self, spec: &RunSpec, cancel: &AtomicBool) -> Result<RunResult, String> {
            let mut argv = vec![self.wslc.display().to_string()];
            argv.extend(run_args(&self.session, spec, &qualified(&spec.image)));
            let file = |f: &Option<std::fs::File>| -> Result<Out, String> {
                Ok(match f {
                    Some(f) => Out::File(f.try_clone().map_err(|e| e.to_string())?),
                    None => Out::Null,
                })
            };
            // the wslc process is killed on timeout or cancel (its Job Object); the broker then removes the container
            let r = exec(&argv, &env(), Duration::from_secs_f64(spec.timeout_s.max(1.0)), file(&spec.stdout)?, file(&spec.stderr)?,
                         cancel, Duration::from_secs(10))?;
            Ok(RunResult { exit_code: r.code, timed_out: r.timed_out, cancelled: r.cancelled })
        }

        fn images(&self) -> Vec<String> {
            let Ok(r) = self.cli(&["image", "list", "--digests", "--no-trunc", "--format", "json"], 60) else { return vec![] };
            self.noticed(&r);
            parse_images(&decode(&r.stdout))
        }

        fn reap(&self) -> Vec<String> {
            if !self.snapshot().ready() {
                return vec![];
            }
            self.remove_labelled(&format!("label={ATTEMPT_LABEL}"))
        }

        fn remove_attempt(&self, attempt_id: i64) -> Vec<String> {
            self.remove_labelled(&format!("label={ATTEMPT_LABEL}={attempt_id}"))
        }

        fn pool_tokens(&self) -> u32 {
            if self.snapshot().ready() { tokens(self.mem_gb) } else { 0 }
        }

        fn gpu_device(&self) -> Option<String> {
            self.snapshot().gpu().then(|| format!("{CDI_KIND}=gpu"))
        }

        fn report(&self) -> Option<Value> {
            Some(self.snapshot().json())
        }

        fn recheck(&self) {
            if matches!(self.snapshot().state, State::Missing | State::Failed) {
                self.kick();
            }
        }
    }

    /// One line for a broker refusal or a log: the first missing prerequisite with its fix, or the failure.
    pub fn doctor_line(r: &Report) -> String {
        match (r.missing.first(), &r.detail) {
            (Some(m), _) => format!("{}: {} ({})", m.what, m.detail, m.fix()),
            (None, Some(d)) => d.clone(),
            (None, None) => format!("the WSL containers session is {}", r.state.as_str()),
        }
    }

    /// The session host's thread: create the session, prove it works, hold it until it ends or the agent stops.
    struct Host {
        home: PathBuf,
        session: String,
        wslc: PathBuf,
        sdk: PathBuf,
        mem_gb: f64,
        cpus: u32,
        shared: Arc<Shared>,
    }

    impl Host {
        fn set(&self, r: Report) {
            let _ = crate::fsutil::write_private(&report_file(&self.home), &serde_json::to_vec_pretty(&r.state_json()).unwrap_or_default());
            *self.shared.report.lock().unwrap() = r;
            self.shared.changed.notify_all();
        }

        fn report(&self, state: State) -> Report {
            Report { state, session: self.session.clone(), ..Default::default() }
        }

        /// Wait for a kick (or the agent's stop); true when stopping.
        fn wait_kick(&self) -> bool {
            let hs = [self.shared.stop as HANDLE, self.shared.kick as HANDLE];
            unsafe { WaitForMultipleObjects(2, hs.as_ptr(), 0, INFINITE) == WAIT_OBJECT_0 }
        }

        fn run(self) {
            use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
            unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
            let sdk = match sdk::Sdk::load(&self.sdk) {
                Ok(s) => s,
                Err(e) => {
                    // nothing can change that until the agent is reinstalled
                    self.set(Report { missing: vec![Missing::new("sdk_library", e)], ..self.report(State::Missing) });
                    return;
                }
            };
            loop {
                self.set(self.report(State::Starting));
                match self.create(&sdk) {
                    Ok(Some(session)) => {
                        let mut ev: HANDLE = std::ptr::null_mut();
                        let hr = unsafe { (sdk.termination)(session, &mut ev) };
                        let hs = [self.shared.stop as HANDLE, ev];
                        let n = if hr >= 0 && !ev.is_null() { 2 } else { 1 };
                        let which = unsafe { WaitForMultipleObjects(n, hs.as_ptr(), 0, INFINITE) };
                        unsafe { (sdk.release)(session) };
                        if which == WAIT_OBJECT_0 {
                            return;
                        }
                        tracing::warn!(session = %self.session, "the WSL containers session ended: creating it again");
                        // a moment for WSL to settle (an update restarts its service), then again
                        std::thread::sleep(Duration::from_secs(2));
                    }
                    // adopted, missing or failed: again when someone asks
                    Ok(None) | Err(()) => {
                        if self.wait_kick() {
                            return;
                        }
                    }
                }
            }
        }

        /// The session, created and proven ready (Some), adopted from an earlier agent process (None, ready), or the
        /// report says why not (Err).
        fn create(&self, sdk: &sdk::Sdk) -> Result<Option<sdk::Session>, ()> {
            let mut missing = self.prerequisites(sdk);
            // the account's settings shape a session when it is created: one that already runs (this agent's earlier
            // process; the service's, for an administrator's doctor) keeps its owner's
            let running = wslc_cli(&self.wslc, &self.session, &["system", "session", "list"], 60)
                .is_ok_and(|r| r.ok() && session_listed(&decode(&r.stdout), &self.session));
            if missing.is_empty() && !running {
                missing.extend(self.settings());
            }
            if !missing.is_empty() {
                self.set(Report { missing, ..self.report(State::Missing) });
                return Err(());
            }
            let (session, adopted) = match self.open(sdk) {
                Ok(s) => s,
                Err(detail) => {
                    self.set(Report { detail: Some(detail), ..self.report(State::Failed) });
                    return Err(());
                }
            };
            // the first VM-backed call starts the session's VM: it proves the host can run it
            match self.prove() {
                Ok(report) => {
                    self.set(report);
                    Ok((!adopted).then_some(session))
                }
                Err(report) => {
                    if !adopted {
                        unsafe { (sdk.release)(session) };
                    }
                    self.set(*report);
                    Err(())
                }
            }
        }

        /// What the SDK, the CLI and the account's settings lack.
        fn prerequisites(&self, sdk: &sdk::Sdk) -> Vec<Missing> {
            let mut v = [0u32; 3];
            let mut missing = vec![];
            if unsafe { (sdk.version)(&mut v) } < 0 || (v[0], v[1], v[2]) < MIN_WSL {
                missing.push(Missing::new("wsl_package", format!("WSL {}.{}.{} is installed; 2.9.3 or later is needed", v[0], v[1], v[2])));
            }
            let mut flags = 0u32;
            if unsafe { (sdk.missing)(&mut flags) } >= 0 {
                for m in missing_components(flags) {
                    if !missing.iter().any(|x: &Missing| x.what == m.what) {
                        missing.push(m);
                    }
                }
            }
            if !self.wslc.is_file() {
                missing.push(Missing::new("wslc_cli", format!("{} is missing", self.wslc.display())));
            }
            missing
        }

        /// Create the agent's session through the SDK: (handle, adopted). `adopted`: a session of this name already
        /// exists (this agent's previous process, until WSL releases it), and the CLI uses it by name.
        fn open(&self, sdk: &sdk::Sdk) -> Result<(sdk::Session, bool), String> {
            let storage = storage_dir(&self.home);
            std::fs::create_dir_all(&storage).map_err(|e| format!("{}: {e}", storage.display()))?;
            let mut s = sdk::SessionSettings([0; 72]);
            let (name, path) = (wide(&self.session), wide(&storage.display().to_string()));
            let vhd = sdk::VhdRequirements { name: c"oarbank".as_ptr() as *const u8, size_bytes: DISK_GB << 30, kind: 0, flags: 0, uid: 0, gid: 0 };
            let mut session: sdk::Session = std::ptr::null_mut();
            let mut msg: *mut u16 = std::ptr::null_mut();
            // GPU-PV is asked for always, as WSLc's own default session does: a host without a GPU shares none
            let hr = unsafe {
                let mut hr = (sdk.init)(name.as_ptr(), path.as_ptr(), &mut s);
                for step in [(sdk.cpus)(&mut s, self.cpus), (sdk.memory)(&mut s, (self.mem_gb * 1024.0) as u32), (sdk.vhd)(&mut s, &vhd),
                             (sdk.features)(&mut s, sdk::FEATURE_GPU)] {
                    if hr >= 0 {
                        hr = step;
                    }
                }
                if hr >= 0 { (sdk.create)(&mut s, &mut session, &mut msg) } else { hr }
            };
            let message = sdk::take_message(msg);
            match hr {
                sdk::E_ALREADY_EXISTS => Ok((std::ptr::null_mut(), true)),
                hr if hr < 0 => Err(format!("creating the session failed (0x{:08x}){}", hr as u32,
                                            message.map(|m| format!(": {m}")).unwrap_or_default())),
                _ => Ok((session, false)),
            }
        }

        /// `image list` answers, and the VM shows its architecture and GPU.
        fn prove(&self) -> Result<Report, Box<Report>> {
            let failed = |r: &Exec| -> Box<Report> {
                let err = decode(&r.stderr);
                Box::new(match error_code(&err).as_deref().and_then(classify) {
                    Some(what) => Report { missing: vec![Missing::new(what, error_message(&err))], ..self.report(State::Missing) },
                    None => Report { detail: Some(format!("wslc failed ({}): {}", r.code, err.trim())), ..self.report(State::Failed) },
                })
            };
            let call = |args: &[&str], t: u64| wslc_cli(&self.wslc, &self.session, args, t)
                .map_err(|e| Box::new(Report { detail: Some(e), ..self.report(State::Failed) }));
            let r = call(&["image", "list", "--format", "json"], 300)?;
            if !r.ok() {
                return Err(failed(&r));
            }
            let r = call(&["system", "session", "run", "/bin/sh", "-c", PROBE], 120)?;
            if !r.ok() {
                return Err(failed(&r));
            }
            let probe = parse_probe(&decode(&r.stdout));
            Ok(Report { platforms: probe.platform().into_iter().collect(), probe, ..self.report(State::Ready) })
        }

        /// The account's WSLc settings must keep containers off the host's loopback: the system scope's agent sets it
        /// in its own account's file; a personal one only reports it missing.
        fn settings(&self) -> Option<Missing> {
            let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
                .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local")))?;
            let file = local.join("wslc").join("settings.yaml");
            let text = std::fs::read_to_string(&file).ok();
            let updated = with_host_loopback_off(text.as_deref())?;
            let pd = std::env::var_os("ProgramData").map(PathBuf::from);
            if !owns_account_settings(&self.home, pd.as_deref()) {
                return Some(Missing::new("host_loopback", format!("{} does not set session.hostLoopback: none", file.display())));
            }
            let write = std::fs::create_dir_all(local.join("wslc")).and_then(|_| std::fs::write(&file, updated));
            write.err().map(|e| Missing::new("host_loopback", format!("{}: {e}", file.display())))
        }
    }

    impl Drop for Shared {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.kick as HANDLE);
                CloseHandle(self.stop as HANDLE);
            }
        }
    }

    /// `oarbank-agent containers install`: install the WSL components the SDK says are missing (administrator). Returns
    /// whether a restart is needed (the Virtual Machine Platform).
    pub fn install() -> Result<bool, String> {
        use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
        unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
        let sdk = sdk::Sdk::load(&agent_dir().join(SDK_DLL))?;
        let mut flags = 0u32;
        let hr = unsafe { (sdk.missing)(&mut flags) };
        if hr < 0 {
            return Err(format!("WslcGetMissingComponents failed (0x{:08x})", hr as u32));
        }
        let wanted = flags & (sdk::COMPONENT_VMP | sdk::COMPONENT_WSL);
        if wanted == 0 {
            return Ok(false);
        }
        // installing the Virtual Machine Platform "fails" with a restart request: done, once Windows restarts (recorded
        // from WSL 3.0.1 run by the MSI as LocalSystem)
        const REBOOT_REQUIRED: [u32; 2] = [0x8007_0BC2, 0x8007_0BC3];
        const NEEDS_ADMIN: [u32; 2] = [0x8007_0005, 0x8007_02E4];
        let hr = unsafe { (sdk.install)(wanted, 0, None, std::ptr::null_mut()) } as u32;
        if REBOOT_REQUIRED.contains(&hr) {
            return Ok(true);
        }
        if (hr as i32) < 0 {
            let admin = if NEEDS_ADMIN.contains(&hr) { ": run it as an administrator" } else { "" };
            return Err(format!("installing the WSL components failed (0x{hr:08x}){admin}"));
        }
        Ok(wanted & sdk::COMPONENT_VMP != 0)
    }

    /// The prerequisites as the SDK sees them now (doctor, without the agent's session).
    pub fn check() -> Vec<Missing> {
        use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
        unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
        let mut m = vec![];
        match sdk::Sdk::load(&agent_dir().join(SDK_DLL)) {
            Err(e) => m.push(Missing::new("sdk_library", e)),
            Ok(sdk) => {
                let mut v = [0u32; 3];
                if unsafe { (sdk.version)(&mut v) } < 0 || (v[0], v[1], v[2]) < MIN_WSL {
                    m.push(Missing::new("wsl_package", format!("WSL {}.{}.{} is installed; 2.9.3 or later is needed", v[0], v[1], v[2])));
                }
                let mut flags = 0u32;
                if unsafe { (sdk.missing)(&mut flags) } >= 0 {
                    for x in missing_components(flags) {
                        if !m.iter().any(|y: &Missing| y.what == x.what) {
                            m.push(x);
                        }
                    }
                }
            }
        }
        if !find_wslc().is_file() {
            m.push(Missing::new("wslc_cli", format!("{} is missing", find_wslc().display())));
        }
        m
    }

    /// `oarbank-agent containers remove`: end the agent's session (an administrator may end any session) and delete its
    /// storage. The WSL package stays.
    pub fn remove(home: &Path) -> Result<(), String> {
        let wslc = find_wslc();
        if wslc.is_file() {
            let _ = wslc_cli(&wslc, &session_name(home), &["system", "session", "terminate"], 60);
        }
        let dir = home.join("containers");
        let _ = std::fs::remove_file(report_file(home));
        // the session's VM lets go of its disk when it has shut down, which takes seconds after the session ends (WSL
        // gives a VM 30 s): until then the disk is in use (ERROR_SHARING_VIOLATION)
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) if e.raw_os_error() == Some(32) && std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_secs(1)),
                Err(e) => return Err(format!("{}: {e}", dir.display())),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The real SDK library and WSL on this machine (OARBANK_WSLC_SDK names the library): its version, the missing
        /// components it reports, and what the doctor makes of them. Any Windows host with WSL installed records it; a
        /// host without the Virtual Machine Platform must report it missing.
        #[test]
        #[ignore]
        fn live_sdk_reports_the_prerequisites() {
            let Some(path) = std::env::var_os("OARBANK_WSLC_SDK").map(PathBuf::from) else {
                eprintln!("set OARBANK_WSLC_SDK to wslcsdk.dll");
                return;
            };
            let sdk = sdk::Sdk::load(&path).unwrap();
            let mut v = [0u32; 3];
            let mut flags = 0u32;
            unsafe {
                windows_sys::Win32::System::Com::CoInitializeEx(std::ptr::null(), windows_sys::Win32::System::Com::COINIT_MULTITHREADED as u32);
                assert!((sdk.version)(&mut v) >= 0);
                assert!((sdk.missing)(&mut flags) >= 0);
            }
            eprintln!("WSL {}.{}.{}, missing components 0x{flags:x}: {:?}", v[0], v[1], v[2], missing_components(flags));
            assert!(v >= [2, 9, 3]);
        }

        /// The agent's own session through the real SDK, reached by name through the real CLI: created in a scratch
        /// home, then proven. On a host that can run WSL2 it is ready (with its platform); on one without the Virtual
        /// Machine Platform the CLI's error names it. Either way the CLI found the SDK's session (no
        /// WSLC_E_SESSION_NOT_FOUND) and the agent's FFI made the session.
        #[test]
        #[ignore]
        fn live_session_opens_through_the_sdk_and_the_cli_finds_it() {
            let Some(path) = std::env::var_os("OARBANK_WSLC_SDK").map(PathBuf::from) else {
                eprintln!("set OARBANK_WSLC_SDK to wslcsdk.dll");
                return;
            };
            let tmp = crate::scratch("wslc");
            let home = tmp.path().to_path_buf();
            std::fs::create_dir_all(home.join("state")).unwrap();
            let rt = WslcRuntime::new(&home, path.clone(), find_wslc(), 2.0, 2);
            let host = Host { home: home.clone(), session: rt.session.clone(), wslc: rt.wslc.clone(), sdk: path.clone(), mem_gb: 2.0, cpus: 2,
                              shared: rt.shared.clone() };
            unsafe { windows_sys::Win32::System::Com::CoInitializeEx(std::ptr::null(), windows_sys::Win32::System::Com::COINIT_MULTITHREADED as u32) };
            let sdk = sdk::Sdk::load(&path).unwrap();
            let (session, adopted) = host.open(&sdk).unwrap();
            assert!(!adopted && !session.is_null());
            let listed = rt.cli(&["system", "session", "list"], 60).unwrap();
            assert!(decode(&listed.stdout).contains(&rt.session), "{}", decode(&listed.stdout));
            let proven = host.prove();
            eprintln!("{:?}", proven.as_ref().map(|r| (r.json(), r.probe.clone())).unwrap_or_else(|r| (r.json(), r.probe.clone())));
            match proven {
                Ok(r) => assert!(r.ready() && !r.platforms.is_empty()),
                Err(r) => {
                    assert_eq!(r.state, State::Missing, "{:?}", r.detail);
                    assert_ne!(r.missing[0].detail, "", "{:?}", r.missing);
                }
            }
            unsafe { (sdk.release)(session) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container_runtime::Mount;

    fn spec() -> RunSpec {
        RunSpec {
            image: "x".into(), platform: "linux/amd64".into(), args: vec!["--privileged".into(), "-v".into(), "/:/host".into()],
            entrypoint: Some("/bin/tool".into()), workdir: Some("/in".into()),
            mounts: vec![Mount { host: PathBuf::from(r"\\?\C:\ProgramData\Oarbank\agent\work\7\inputs"), dst: "/in".into(), ro: true },
                         Mount { host: PathBuf::from(r"\\?\C:\ProgramData\Oarbank\agent\modules-data\toy\cache"), dst: "/cache".into(), ro: false }],
            env: vec![("A".into(), "1".into())], network: false, cpus: 2.5, mem_gb: 2.5, attempt_id: 7, module: "toy".into(),
            timeout_s: 10.0, stdout: None, stderr: None, gpu_device: None,
        }
    }

    /// The fixed shape: no `--platform`, memory in MiB, Windows paths without `\\?\`, the container's own arguments
    /// after the image (where wslc forwards everything to the container), `--gpus all` only for a GPU run.
    #[test]
    fn wslc_runs_have_a_fixed_shape() {
        let image = "docker.io/org/tool@sha256:00";
        assert_eq!(run_args("oarbank-0123456789ab", &spec(), image), [
            "--session", "oarbank-0123456789ab", "container", "run", "--rm", "--network", "none", "--cpus", "2.5", "--memory", "2560m",
            "--label", "oarbank.attempt_id=7", "--label", "oarbank.module=toy",
            "-v", r"C:\ProgramData\Oarbank\agent\work\7\inputs:/in:ro", "-v", r"C:\ProgramData\Oarbank\agent\modules-data\toy\cache:/cache",
            "--workdir", "/in", "--entrypoint", "/bin/tool", "-e", "A=1", image, "--privileged", "-v", "/:/host",
        ]);
        let gpu = RunSpec { gpu_device: Some(format!("{CDI_KIND}=gpu")), network: true, ..spec() };
        let a = run_args("s", &gpu, image);
        assert!(a.windows(2).any(|w| w == ["--gpus", "all"]) && a.windows(2).any(|w| w == ["--network", "bridge"]), "{a:?}");
        let image_at = a.iter().position(|x| x == image).unwrap();
        assert!(!a[..image_at].iter().any(|x| x.contains("platform") || x.contains("privileged") || x == "--device"));
        assert_eq!(mem_arg(0.25), "256m");
        assert_eq!(mem_arg(8.0), "8192m");
    }

    #[test]
    fn the_session_fits_the_host() {
        assert_eq!(session_size(16.0, 4), (8.0, 4), "a 4-core runner with 16 GB");
        assert_eq!(session_size(8.0, 8), (4.0, 6));
        assert_eq!(session_size(128.0, 32), (32.0, 8));
        assert_eq!(session_size(1.0, 1), (1.0, 1));
    }

    #[test]
    fn host_paths_lose_the_verbatim_prefix() {
        assert_eq!(host_path(Path::new(r"\\?\C:\a\b")), r"C:\a\b");
        assert_eq!(host_path(Path::new(r"\\?\UNC\server\share\x")), r"\\server\share\x");
        assert_eq!(host_path(Path::new(r"D:\plain")), r"D:\plain");
    }

    #[test]
    fn session_names_are_per_agent_home() {
        let a = session_name(Path::new(r"C:\ProgramData\Oarbank\agent"));
        let b = session_name(Path::new(r"C:\Users\u\AppData\Local\Oarbank\agent"));
        assert!(a.starts_with("oarbank-") && a.len() == 20 && a != b);
        assert_eq!(a, session_name(Path::new(r"C:\ProgramData\Oarbank\agent")));
        let pd = Path::new(r"C:\ProgramData");
        assert!(owns_account_settings(&pd.join("Oarbank").join("agent"), Some(pd)));
        assert!(!owns_account_settings(&Path::new(r"C:\Users\u\AppData\Local").join("Oarbank").join("agent"), Some(pd)));
        assert!(!owns_account_settings(&pd.join("Oarbank").join("agent"), None));
    }

    /// Output recorded from wslc 3.0.1 on Windows 11 arm64 without the Virtual Machine Platform.
    const NO_VMP: &str = "The operation could not be started because a required feature is not installed. \r\nError code: \
                          HCS_E_SERVICE_NOT_AVAILABLE\r\nIf this error was unexpected, please consider searching for existing issues \
                          or filing a new issue at https://github.com/microsoft/WSL/issues.\r\n";
    /// The same machine with the Virtual Machine Platform installed but no hardware virtualization (a VM without
    /// nesting).
    const NO_VIRTUALIZATION: &str = "WSL2 is unable to start since virtualization is not enabled on this machine.\r\nPlease ensure the \
        \"Virtual Machine Platform\" optional component is enabled and virtualization is turned on in your computer's firmware settings.\r\n\
        \r\nEnable \"Virtual Machine Platform\" by running: wsl.exe --install --no-distribution\r\n\r\nFor information please visit \
        https://aka.ms/enablevirtualization\r\nError code: HCS_E_HYPERV_NOT_INSTALLED\r\nIf this error was unexpected, please consider \
        searching for existing issues or filing a new issue at https://github.com/microsoft/WSL/issues.\r\n";
    const NO_SESSION: &str = "Session not found: 'oarbank-probe'\r\nError code: WSLC_E_SESSION_NOT_FOUND\r\nIf this error was unexpected, \
                              please consider searching for existing issues or filing a new issue at https://github.com/microsoft/WSL/issues.\r\n";

    #[test]
    fn recorded_wslc_failures_name_what_is_missing() {
        assert_eq!(error_code(NO_VMP).as_deref(), Some("HCS_E_SERVICE_NOT_AVAILABLE"));
        assert_eq!(classify("HCS_E_SERVICE_NOT_AVAILABLE"), Some("virtual_machine_platform"));
        assert_eq!(error_message(NO_VMP), "The operation could not be started because a required feature is not installed.");
        assert_eq!(error_code(NO_VIRTUALIZATION).as_deref().and_then(classify), Some("virtualization"));
        assert_eq!(error_message(NO_VIRTUALIZATION), "WSL2 is unable to start since virtualization is not enabled on this machine.");
        assert_eq!(error_code(NO_SESSION).as_deref(), Some("WSLC_E_SESSION_NOT_FOUND"));
        assert_eq!(classify("WSLC_E_SESSION_NOT_FOUND"), None, "a vanished session is recreated, not a missing prerequisite");
        assert_eq!(classify("WSLC_E_CONTAINER_DISABLED"), Some("policy"));
        assert_eq!(error_code("plain failure\n"), None);
        // the SDK's component flags
        let m: Vec<&str> = missing_components(1 | 2 | 4).iter().map(|m| m.what).collect();
        assert_eq!(m, ["virtual_machine_platform", "wsl_package", "sdk_update"]);
        assert!(missing_components(0).is_empty());
        assert!(Missing::new("virtual_machine_platform", "x").fix().contains("containers install"));
        // UTF-16 output (a console code page) decodes like UTF-8
        let w: Vec<u8> = "wslc 3.0.1.0\r\n".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(decode(&w), "wslc 3.0.1.0\r\n");
        assert_eq!(decode(b"wslc 3.0.1.0\r\n"), "wslc 3.0.1.0\r\n");
    }

    /// `wslc system session list`, recorded from wslc 3.0.1.
    #[test]
    fn session_lists_name_running_sessions() {
        let out = "ID   Creator PID   Display Name\r\n1    3520          wslc-cli-admin-oarbank\r\n2    4410          oarbank-15b482462755\r\n";
        assert!(session_listed(out, "oarbank-15b482462755"));
        assert!(!session_listed(out, "oarbank-000000000000"));
        assert!(!session_listed("ID   Creator PID   Display Name\r\n", "Display"));
    }

    #[test]
    fn container_lists_give_ids_only() {
        assert_eq!(parse_ids("0123abcd\r\n\nfedc9876\nError: something\n"), ["0123abcd", "fedc9876"]);
    }

    #[test]
    fn image_lists_give_digest_references() {
        let out = "{\"Containers\":\"N/A\",\"CreatedAt\":\"2026-09-01\",\"CreatedSince\":\"4 weeks ago\",\"Digest\":\"sha256:aa\",\"ID\":\"sha256:1\",\
                   \"Repository\":\"docker.io/library/alpine\",\"SharedSize\":\"N/A\",\"Size\":\"8MB\",\"Tag\":\"3.20\",\"UniqueSize\":\"N/A\"}\n\
                   {\"Digest\":\"<none>\",\"Repository\":\"localhost/built\",\"Tag\":\"x\"}\nnot json\n";
        assert_eq!(parse_images(out), ["docker.io/library/alpine@sha256:aa"]);
    }

    #[test]
    fn the_host_loopback_setting_is_merged_into_the_account_file() {
        assert_eq!(with_host_loopback_off(None).unwrap(), "session:\n  hostLoopback: none\n");
        // wslc's commented template: the commented key does not count, the rest stays
        let template = "# WSLc settings\nsession:\n  # cpuCount: default\n  # hostLoopback: default\n  idleTimeout: 60\ncredentialStore: wincred\n";
        let merged = with_host_loopback_off(Some(template)).unwrap();
        assert_eq!(merged, "# WSLc settings\nsession:\n  hostLoopback: none\n  # cpuCount: default\n  # hostLoopback: default\n  \
                            idleTimeout: 60\ncredentialStore: wincred\n");
        assert!(host_loopback_off(&merged));
        assert_eq!(with_host_loopback_off(Some(&merged)), None, "already off: left alone");
        let other = "session:\n  hostLoopback: host.wslc.internal\n  memorySize: 8GB\n";
        assert_eq!(with_host_loopback_off(Some(other)).unwrap(), "session:\n  hostLoopback: none\n  memorySize: 8GB\n");
        let no_session = "credentialStore: file";
        assert_eq!(with_host_loopback_off(Some(no_session)).unwrap(), "credentialStore: file\n\nsession:\n  hostLoopback: none\n");
        assert!(!host_loopback_off("other:\n  hostLoopback: none\n"), "only the session block counts");
        assert!(host_loopback_off("session:\n  hostLoopback: \"none\"  # off\n"));
    }

    #[test]
    fn the_vm_probe_names_platform_gpu_and_apis() {
        let nvidia = "arch:x86_64\ndxg\nlib:libcuda.so\nlib:libcuda.so.1\nlib:libcuda.so.1.1\nlib:libd3d12.so\nlib:libd3d12core.so\nlib:libdxcore.so\n\
                      lib:libnvidia-ml.so.1\nlib:nvidia-smi\ndrv:nv_dispi.inf_amd64_7ff3f9b2c2b3b0c1/libcuda.so.1.1\n\
                      drv:nv_dispi.inf_amd64_7ff3f9b2c2b3b0c1/libnvwgf2umx.so\n";
        let p = parse_probe(nvidia);
        assert_eq!((p.platform().as_deref(), p.gpu()), (Some("linux/amd64"), true));
        assert_eq!(p.gpu_apis(), ["cuda", "directml"]);
        let amd = parse_probe("arch:x86_64\ndxg\nlib:libd3d12.so\nlib:libd3d12core.so\nlib:libdxcore.so\ndrv:u0401234.inf_amd64_abc/libamdxc64.so\n");
        assert_eq!(amd.gpu_apis(), ["directml"], "ROCm on WSL brings its runtime in the image: not attested");
        // a VM without a host GPU (a cloud runner): the device may exist, but no driver is shared
        let none = parse_probe("arch:aarch64\ndxg\nlib:libd3d12.so\nlib:libdxcore.so\n");
        assert_eq!((none.platform().as_deref(), none.gpu(), none.gpu_apis().len()), (Some("linux/arm64"), false, 0));
        assert_eq!(parse_probe("").platform(), None);
    }

    #[test]
    fn the_report_offers_gpu_only_from_a_ready_session() {
        let probe = parse_probe("arch:x86_64\ndxg\nlib:libcuda.so.1\nlib:libd3d12.so\nlib:libdxcore.so\ndrv:nv/libcuda.so.1.1\n");
        let ready = Report { state: State::Ready, session: "oarbank-x".into(), platforms: vec!["linux/amd64".into()], probe: probe.clone(),
                             ..Default::default() };
        assert_eq!(ready.json(), json!({"runtime": "wslc", "state": "ready", "session": "oarbank-x", "platforms": ["linux/amd64"],
                                        "gpu": "cdi:microsoft.com/wslc", "missing": []}));
        let st = ready.state_json();
        assert_eq!((st["containers"].clone(), st["gpu_apis"].clone()), (ready.json(), json!(["cuda", "directml"])));
        assert_eq!(st["evidence"], "cdi:microsoft.com/wslc (WSL containers session oarbank-x: libcuda.so.1, libd3d12.so, libdxcore.so)");
        let missing = Report { state: State::Missing, probe, missing: vec![Missing::new("host_loopback", "not set")], ..Default::default() };
        let j = missing.json();
        assert_eq!((j["state"].as_str(), j["gpu"].as_str()), (Some("missing"), Some("undetected")));
        assert_eq!(missing.container_apis(), (vec![], "no GPU in containers: the WSL containers session is missing".to_string()));
        assert_eq!(j["missing"][0]["what"], "host_loopback");
        assert!(j["missing"][0]["fix"].as_str().unwrap().contains("hostLoopback: none"));
        assert_eq!(absent_report()["state"], "absent");
        // what the facts and the GPU probe read back
        let tmp = crate::scratch("wslc-state");
        let home = tmp.path().to_path_buf();
        assert_eq!(facts(&home), absent_report());
        assert_eq!(container_apis(&home).0, Vec::<String>::new());
        std::fs::create_dir_all(home.join("state")).unwrap();
        std::fs::write(report_file(&home), serde_json::to_vec(&st).unwrap()).unwrap();
        assert_eq!(facts(&home), ready.json());
        assert_eq!(container_apis(&home), (vec!["cuda".to_string(), "directml".to_string()], st["evidence"].as_str().unwrap().to_string()));
    }
}
