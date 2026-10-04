//! Facts (docs/protocol.md, "Enrollment": Facts): the node's platform, CPU, memory, GPUs and what its sandbox enforces.

use serde_json::{json, Value};

#[cfg(target_os = "macos")]
pub fn sysctl_string(name: &str) -> Option<String> {
    let c = std::ffi::CString::new(name).ok()?;
    let mut len: libc::size_t = 0;
    unsafe {
        if libc::sysctlbyname(c.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 || len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        if libc::sysctlbyname(c.as_ptr(), buf.as_mut_ptr() as *mut _, &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        buf.truncate(len);
        while buf.last() == Some(&0) {
            buf.pop();
        }
        String::from_utf8(buf).ok()
    }
}

#[cfg(target_os = "macos")]
pub fn sysctl_u64(name: &str) -> Option<u64> {
    let c = std::ffi::CString::new(name).ok()?;
    let mut v: u64 = 0;
    let mut len: libc::size_t = std::mem::size_of::<u64>();
    unsafe {
        if libc::sysctlbyname(c.as_ptr(), &mut v as *mut u64 as *mut _, &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
    }
    Some(match len { 4 => v & 0xffff_ffff, _ => v })
}

/// This node's platform token, `<os>-<arch>` (spec/platforms.md).
pub fn platform_token() -> String {
    let os = if cfg!(target_os = "macos") { "darwin" } else if cfg!(target_os = "windows") { "windows" } else { "linux" };
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else if cfg!(target_arch = "x86_64") { "amd64" } else { "unknown" };
    format!("{os}-{arch}")
}

/// The name this node reports: `OARBANK_NODE_NAME` when the owner set one, else the host name.
pub fn hostname() -> String {
    std::env::var("OARBANK_NODE_NAME").ok().map(|n| n.trim().to_string()).filter(|n| !n.is_empty() && n.len() <= 63)
        .unwrap_or_else(crate::sys::hostname)
}

pub fn disk_free_gb(path: &std::path::Path) -> Option<f64> {
    crate::sys::disk_free_gb(path)
}

/// What the macOS Seatbelt backend enforces (spec/sandbox/backends/macos.md, "Enforcement report").
pub fn sandbox_report() -> Value {
    crate::sandbox::report()
}

#[derive(Default)]
struct SysInfo {
    os_version: Option<String>,
    os_build: Option<String>,
    kernel: Option<String>,
    model: Option<String>,
    perf: Option<u64>,
    eff: Option<u64>,
    logical: Option<u64>,
    mem: Option<u64>,
    distro: Option<String>,
    libc: Option<String>,
    libc_version: Option<String>,
}

#[cfg(target_os = "macos")]
fn sysinfo() -> SysInfo {
    SysInfo { os_version: sysctl_string("kern.osproductversion"), os_build: sysctl_string("kern.osversion"),
              kernel: sysctl_string("kern.osrelease"), model: sysctl_string("machdep.cpu.brand_string"),
              perf: sysctl_u64("hw.perflevel0.logicalcpu"), eff: sysctl_u64("hw.perflevel1.logicalcpu"),
              logical: sysctl_u64("hw.logicalcpu"), mem: sysctl_u64("hw.memsize"), ..Default::default() }
}

/// /etc/os-release, /proc and uname; hybrid Intel parts expose their core types under /sys/devices/cpu_{core,atom}.
#[cfg(target_os = "linux")]
fn sysinfo() -> SysInfo {
    let rd = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let osr = rd("/etc/os-release");
    let field = |k: &str| osr.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).map(|v| v.trim_matches('"').to_string());
    let cpuinfo = rd("/proc/cpuinfo");
    let model = cpuinfo.lines().find(|l| l.starts_with("model name")).and_then(|l| l.split_once(':')).map(|(_, v)| v.trim().to_string());
    let mem = rd("/proc/meminfo").lines().find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok()).map(|kb| kb * 1024);
    let count = |p: &str| -> Option<u64> {
        // a cpulist such as "0-15" or "0-7,16-23"
        let s = std::fs::read_to_string(p).ok()?;
        Some(s.trim().split(',').filter(|r| !r.is_empty()).map(|r| match r.split_once('-') {
            Some((a, b)) => b.parse::<u64>().unwrap_or(0).saturating_sub(a.parse().unwrap_or(0)) + 1,
            None => 1,
        }).sum())
    };
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    let kernel = (unsafe { libc::uname(&mut u) } == 0)
        .then(|| unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy().to_string());
    #[cfg(target_env = "gnu")]
    let (libc_name, libc_version) = (Some("glibc".to_string()),
        Some(unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) }.to_string_lossy().to_string()));
    #[cfg(not(target_env = "gnu"))]
    let (libc_name, libc_version) = (Some("musl".to_string()), None);
    SysInfo { os_version: field("VERSION_ID"), os_build: None, kernel, model,
              perf: count("/sys/devices/cpu_core/cpus"), eff: count("/sys/devices/cpu_atom/cpus"),
              logical: std::thread::available_parallelism().ok().map(|n| n.get() as u64), mem, distro: field("ID"),
              libc: libc_name, libc_version }
}

/// RtlGetVersion (GetVersionEx lies to unmanifested programs), GlobalMemoryStatusEx, and the cores' efficiency
/// classes from GetLogicalProcessorInformationEx.
#[cfg(windows)]
fn sysinfo() -> SysInfo {
    use windows_sys::Win32::System::SystemInformation::{GetLogicalProcessorInformationEx, GlobalMemoryStatusEx, RelationProcessorCore,
                                                        MEMORYSTATUSEX, OSVERSIONINFOW, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX};
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlGetVersion(v: *mut OSVERSIONINFOW) -> i32;
    }
    let mut v: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    let ok = unsafe { RtlGetVersion(&mut v) } == 0;
    let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    let mem = (unsafe { GlobalMemoryStatusEx(&mut m) } != 0).then_some(m.ullTotalPhys);
    // cores by efficiency class: the highest class is the performance cores; logical processors per core by mask
    let (mut perf, mut eff) = (None, None);
    let mut len = 0u32;
    unsafe { GetLogicalProcessorInformationEx(RelationProcessorCore, std::ptr::null_mut(), &mut len) };
    if len > 0 {
        let mut buf = vec![0u8; len as usize];
        if unsafe { GetLogicalProcessorInformationEx(RelationProcessorCore, buf.as_mut_ptr() as *mut _, &mut len) } != 0 {
            let mut classes: Vec<(u8, u64)> = vec![];
            let mut off = 0usize;
            while off < len as usize {
                let e = unsafe { &*(buf.as_ptr().add(off) as *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX) };
                let core = unsafe { &e.Anonymous.Processor };
                let threads: u64 = (0..core.GroupCount as usize).map(|g| unsafe { *core.GroupMask.as_ptr().add(g) }.Mask.count_ones() as u64).sum();
                classes.push((core.EfficiencyClass, threads));
                off += e.Size as usize;
            }
            let top = classes.iter().map(|c| c.0).max().unwrap_or(0);
            if classes.iter().any(|c| c.0 != top) {
                perf = Some(classes.iter().filter(|c| c.0 == top).map(|c| c.1).sum());
                eff = Some(classes.iter().filter(|c| c.0 != top).map(|c| c.1).sum());
            }
        }
    }
    SysInfo { os_version: ok.then(|| format!("{}.{}", v.dwMajorVersion, v.dwMinorVersion)),
              os_build: ok.then(|| v.dwBuildNumber.to_string()), kernel: None, model: None, perf, eff,
              logical: std::thread::available_parallelism().ok().map(|n| n.get() as u64), mem, ..Default::default() }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn sysinfo() -> SysInfo {
    SysInfo { logical: std::thread::available_parallelism().ok().map(|n| n.get() as u64), ..Default::default() }
}

pub fn collect(home: &std::path::Path) -> Value {
    let plat = platform_token();
    let (os, arch) = plat.split_once('-').unwrap_or(("unknown", "unknown"));
    let SysInfo { os_version, os_build, kernel, model, perf, eff, logical, mem, distro, libc, libc_version } = sysinfo();
    let apple = cfg!(target_os = "macos") && arch == "arm64";
    let gpus = if apple {
        json!([{"vendor": "apple", "model": model.clone().unwrap_or_default(), "apis": ["metal"], "vram_gb": null, "unified": true}])
    } else {
        json!([])
    };
    json!({
        "facts": 2,
        "hostname": hostname(),
        "platform": {"os": os, "arch": arch, "os_version": os_version, "os_build": os_build, "kernel": kernel,
                     "distro": distro, "libc": libc, "libc_version": libc_version},
        "cpu": {"model": model, "perf_cores": perf, "eff_cores": eff, "logical": logical},
        "memory_gb": mem.map(|b| (b as f64 / 1073741824.0 * 10.0).round() / 10.0),
        "gpus": gpus,
        "sandbox": sandbox_report(),
        "containers": containers(home),
        "disk_free_gb": disk_free_gb(home),
    })
}

/// The node's container report (docs/design/windows-containers.md, "The node's report"): `gpu` is `cdi:<kind>` where
/// containers can get the node's GPUs, else `undetected`, and `gpu_apis` the GPU APIs such a container can use. Linux:
/// a container engine and a CDI spec with an `all` device; macOS: container runtimes have no Metal passthrough;
/// Windows: the agent's WSL containers session's last report (wslc.rs writes it on every change of state).
fn containers(home: &std::path::Path) -> Value {
    #[cfg(target_os = "linux")]
    {
        let _ = home;
        let engine = ["/usr/bin", "/usr/local/bin", "/bin"].iter()
            .any(|d| ["podman", "docker"].iter().any(|n| std::path::Path::new(d).join(n).is_file()));
        let dirs = crate::container_runtime::CDI_DIRS.map(std::path::Path::new);
        if let (true, Some(kind)) = (engine, crate::container_runtime::cdi_kind(&dirs)) {
            return json!({"gpu": format!("cdi:{kind}"), "gpu_apis": crate::container_runtime::cdi_apis(&kind)});
        }
    }
    #[cfg(windows)]
    {
        return std::fs::read(crate::wslc::report_file(home)).ok().and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_else(crate::wslc::absent_report);
    }
    #[allow(unreachable_code)]
    {
        let _ = home;
        json!({"gpu": "undetected", "gpu_apis": []})
    }
}
