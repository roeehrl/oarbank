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

// ---- physical cores by class, the same meaning on every OS: performance and efficiency cores, each core counted once
// however many hardware threads (SMT, Hyper-Threading) it runs; capacity counts perf + eff/2 (capacity.rs).

/// The cores capacity counts, from the facts' `cpu`: (perf, eff). Facts carry physical cores (perf = every core and
/// eff = 0 where the OS tells no classes apart); only facts without core counts fall back to logical processors.
pub fn capacity_cores(cpu: &Value) -> (i64, i64) {
    let perf = cpu["perf_cores"].as_i64().filter(|n| *n > 0);
    match perf {
        Some(p) => (p, cpu["eff_cores"].as_i64().unwrap_or(0).max(0)),
        None => (cpu["logical"].as_i64().unwrap_or(1).max(1), 0),
    }
}

/// macOS: `hw.perflevel0.physicalcpu` (performance) and `hw.perflevel1.physicalcpu` (efficiency) on Apple silicon;
/// an Intel Mac has no performance levels, so all of `hw.physicalcpu` (cores, not Hyper-Threading's threads).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))] // parsed on every OS in the tests
pub fn mac_cores(perflevel0: Option<u64>, perflevel1: Option<u64>, physical: Option<u64>) -> (Option<u64>, Option<u64>) {
    match perflevel0.filter(|n| *n > 0) {
        Some(p) => (Some(p), Some(perflevel1.unwrap_or(0))),
        None => (physical.filter(|n| *n > 0), physical.filter(|n| *n > 0).map(|_| 0)),
    }
}

/// A Linux cpulist such as "0-15" or "0-7,16-23" -> the CPU numbers.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // parsed on every OS in the tests
pub fn parse_cpulist(s: &str) -> Vec<u32> {
    let mut out = vec![];
    for r in s.trim().split(',').map(str::trim).filter(|r| !r.is_empty()) {
        match r.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                    out.extend(a..=b.min(a.saturating_add(65535)));
                }
            }
            None => out.extend(r.parse::<u32>().ok()),
        }
    }
    out
}

/// Linux, from sysfs (`devices` is /sys/devices): physical cores are the distinct sets of hardware threads that share
/// one (`topology/core_cpus_list`, `thread_siblings_list` before 5.7) among the online CPUs. Classes: Intel hybrid
/// parts list their performance and efficiency threads under `cpu_core/cpus` and `cpu_atom/cpus`; Arm big.LITTLE
/// gives each CPU a `cpu_capacity` (the efficiency cores are those under 60 % of the largest); AMD's compact cores
/// (Zen 4c/5c) run the same instructions at lower clocks and the kernel tells no class apart, so every core is a
/// performance core. None when the topology cannot be read.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // parsed on every OS in the tests
pub fn linux_cores(devices: &std::path::Path) -> (Option<u64>, Option<u64>) {
    use std::collections::BTreeSet;
    let rd = |p: std::path::PathBuf| std::fs::read_to_string(p).ok();
    let cpu = devices.join("system/cpu");
    let online = rd(cpu.join("online")).map(|s| parse_cpulist(&s)).unwrap_or_else(|| {
        std::fs::read_dir(&cpu).map(|d| d.filter_map(|e| e.ok()?.file_name().to_str()?.strip_prefix("cpu")?.parse().ok()).collect())
            .unwrap_or_default()
    });
    // one entry per physical core: its threads, keyed by the sorted list
    let mut cores: BTreeSet<Vec<u32>> = BTreeSet::new();
    for n in &online {
        let topo = cpu.join(format!("cpu{n}/topology"));
        let Some(list) = rd(topo.join("core_cpus_list")).or_else(|| rd(topo.join("thread_siblings_list"))) else {
            return (None, None);
        };
        let mut threads = parse_cpulist(&list);
        threads.sort_unstable();
        if threads.is_empty() {
            threads.push(*n);
        }
        cores.insert(threads);
    }
    if cores.is_empty() {
        return (None, None);
    }
    let set = |p: &str| rd(devices.join(p)).map(|s| parse_cpulist(&s).into_iter().collect::<BTreeSet<u32>>());
    if let (Some(p_threads), Some(e_threads)) = (set("cpu_core/cpus"), set("cpu_atom/cpus")) {
        let eff = cores.iter().filter(|t| t.iter().any(|c| e_threads.contains(c)) && !t.iter().any(|c| p_threads.contains(c))).count();
        return (Some((cores.len() - eff) as u64), Some(eff as u64));
    }
    let capacity = |t: &Vec<u32>| t.iter().filter_map(|c| rd(cpu.join(format!("cpu{c}/cpu_capacity")))?.trim().parse::<u64>().ok()).max();
    let caps: Vec<Option<u64>> = cores.iter().map(capacity).collect();
    if caps.iter().all(Option::is_some) {
        let top = caps.iter().flatten().copied().max().unwrap_or(0);
        let eff = caps.iter().flatten().filter(|c| (**c as f64) < top as f64 * 0.6).count();
        return (Some((cores.len() - eff) as u64), Some(eff as u64));
    }
    (Some(cores.len() as u64), Some(0))
}

/// Windows, from GetLogicalProcessorInformationEx(RelationProcessorCore)'s buffer: one record per physical core
/// (Relationship 0, Size, then PROCESSOR_RELATIONSHIP: Flags, EfficiencyClass, …). The highest efficiency class is
/// the performance cores (Intel hybrid: P-cores 1, E-cores 0); a part with one class has only performance cores.
/// Hyper-Threading shows as more bits in a core's group mask, never as more records. None for a malformed buffer.
#[cfg_attr(not(windows), allow(dead_code))] // parsed on every OS in the tests
pub fn windows_cores(buf: &[u8]) -> Option<(u64, u64)> {
    let mut classes = vec![];
    let mut off = 0usize;
    while off + 10 <= buf.len() {
        let rel = u32::from_le_bytes(buf[off..off + 4].try_into().ok()?);
        let size = u32::from_le_bytes(buf[off + 4..off + 8].try_into().ok()?) as usize;
        if size < 10 || off + size > buf.len() {
            return None;
        }
        if rel == 0 {
            classes.push(buf[off + 9]);
        }
        off += size;
    }
    if off != buf.len() {
        return None;
    }
    let top = *classes.iter().max()?;
    let perf = classes.iter().filter(|c| **c == top).count() as u64;
    Some((perf, classes.len() as u64 - perf))
}

#[cfg(target_os = "macos")]
fn sysinfo() -> SysInfo {
    let (perf, eff) = mac_cores(sysctl_u64("hw.perflevel0.physicalcpu"), sysctl_u64("hw.perflevel1.physicalcpu"),
                                sysctl_u64("hw.physicalcpu"));
    SysInfo { os_version: sysctl_string("kern.osproductversion"), os_build: sysctl_string("kern.osversion"),
              kernel: sysctl_string("kern.osrelease"), model: sysctl_string("machdep.cpu.brand_string"),
              perf, eff, logical: sysctl_u64("hw.logicalcpu"), mem: sysctl_u64("hw.memsize"), ..Default::default() }
}

/// /etc/os-release, /proc and uname; the cores from sysfs (`linux_cores`).
#[cfg(target_os = "linux")]
fn sysinfo() -> SysInfo {
    let rd = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    let osr = rd("/etc/os-release");
    let field = |k: &str| osr.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).map(|v| v.trim_matches('"').to_string());
    let cpuinfo = rd("/proc/cpuinfo");
    let model = cpuinfo.lines().find(|l| l.starts_with("model name")).and_then(|l| l.split_once(':')).map(|(_, v)| v.trim().to_string());
    let mem = rd("/proc/meminfo").lines().find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok()).map(|kb| kb * 1024);
    let (perf, eff) = linux_cores(std::path::Path::new("/sys/devices"));
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    let kernel = (unsafe { libc::uname(&mut u) } == 0)
        .then(|| unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy().to_string());
    #[cfg(target_env = "gnu")]
    let (libc_name, libc_version) = (Some("glibc".to_string()),
        Some(unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) }.to_string_lossy().to_string()));
    #[cfg(not(target_env = "gnu"))]
    let (libc_name, libc_version) = (Some("musl".to_string()), None);
    SysInfo { os_version: field("VERSION_ID"), os_build: None, kernel, model,
              perf, eff,
              logical: std::thread::available_parallelism().ok().map(|n| n.get() as u64), mem, distro: field("ID"),
              libc: libc_name, libc_version }
}

/// RtlGetVersion (GetVersionEx lies to unmanifested programs), GlobalMemoryStatusEx, and the physical cores and
/// their efficiency classes from GetLogicalProcessorInformationEx (`windows_cores`).
#[cfg(windows)]
fn sysinfo() -> SysInfo {
    use windows_sys::Win32::System::SystemInformation::{GetLogicalProcessorInformationEx, GlobalMemoryStatusEx, RelationProcessorCore,
                                                        MEMORYSTATUSEX, OSVERSIONINFOW};
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
    // one record per physical core, with its efficiency class
    let (mut perf, mut eff) = (None, None);
    let mut len = 0u32;
    unsafe { GetLogicalProcessorInformationEx(RelationProcessorCore, std::ptr::null_mut(), &mut len) };
    if len > 0 {
        let mut buf = vec![0u8; len as usize];
        if unsafe { GetLogicalProcessorInformationEx(RelationProcessorCore, buf.as_mut_ptr() as *mut _, &mut len) } != 0 {
            buf.truncate(len as usize);
            if let Some((p, e)) = windows_cores(&buf) {
                (perf, eff) = (Some(p), Some(e));
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
    // the GPU inventory; which APIs the node provides is the doctor's report (gpuapi.rs)
    let apple = cfg!(target_os = "macos") && arch == "arm64";
    let gpus = if apple {
        json!([{"vendor": "apple", "model": model.clone().unwrap_or_default(), "vram_gb": null, "unified": true}])
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

/// The node's container report: `gpu` is how containers get the node's GPUs (container_runtime::gpu_passthrough):
/// `cdi:<kind>` on Linux with a container engine and a CDI spec with an `all` device, `virtio-gpu:venus` on macOS with
/// krunkit, `cdi:microsoft.com/wslc` on Windows from a ready WSL containers session whose VM has a GPU, else
/// `undetected`. Windows adds its session's state (wslc.rs writes it on every change; docs/design/windows-containers.md,
/// "The node's report"). The APIs a GPU container gets are the doctor report's `gpu_apis.containers` (gpuapi.rs).
fn containers(home: &std::path::Path) -> Value {
    #[cfg(windows)]
    {
        crate::wslc::facts(home)
    }
    #[cfg(unix)]
    {
        let _ = home;
        json!({"gpu": crate::container_runtime::gpu_passthrough().map(|p| p.kind).unwrap_or_else(|| "undetected".into())})
    }
}

#[cfg(test)]
mod cores_tests {
    use super::*;
    use std::path::Path;

    /// A sysfs tree under a scratch directory: `cpus` is (cpu, its core's thread list, cpu_capacity).
    fn sysfs(online: &str, cpus: &[(u32, &str, Option<u32>)], extra: &[(&str, &str)]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let w = |p: &str, v: &str| {
            let f = d.path().join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, format!("{v}\n")).unwrap();
        };
        w("system/cpu/online", online);
        for (n, threads, cap) in cpus {
            w(&format!("system/cpu/cpu{n}/topology/core_cpus_list"), threads);
            w(&format!("system/cpu/cpu{n}/topology/thread_siblings_list"), threads);
            if let Some(c) = cap {
                w(&format!("system/cpu/cpu{n}/cpu_capacity"), &c.to_string());
            }
        }
        for (p, v) in extra {
            w(p, v);
        }
        d
    }

    #[test]
    fn cpulists() {
        assert_eq!(parse_cpulist("0-3,8,10-11\n"), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(parse_cpulist(""), Vec::<u32>::new());
        assert_eq!(parse_cpulist("7"), vec![7]);
    }

    /// Core i7-12700 (Alder Lake): 8 P-cores with Hyper-Threading (CPUs 0-15, siblings 0,1 … 14,15) and 4 E-cores
    /// (16-19), as Linux 6.x lays it out; cpu_core/cpus and cpu_atom/cpus are the hybrid PMUs' thread lists.
    #[test]
    fn linux_intel_hybrid_counts_cores_not_threads() {
        let mut cpus: Vec<(u32, String, Option<u32>)> = (0..16).map(|n| (n, format!("{}-{}", n & !1, (n & !1) + 1), None)).collect();
        cpus.extend((16..20).map(|n| (n, n.to_string(), None)));
        let cpus: Vec<(u32, &str, Option<u32>)> = cpus.iter().map(|(n, t, c)| (*n, t.as_str(), *c)).collect();
        let d = sysfs("0-19", &cpus, &[("cpu_core/cpus", "0-15"), ("cpu_atom/cpus", "16-19")]);
        assert_eq!(linux_cores(d.path()), (Some(8), Some(4)));
    }

    /// Ryzen 9 5950X: 16 cores with SMT, siblings n and n+16; no core classes.
    #[test]
    fn linux_amd_smt_threads_are_not_cores() {
        let lists: Vec<String> = (0..32).map(|n| format!("{},{}", n % 16, n % 16 + 16)).collect();
        let cpus: Vec<(u32, &str, Option<u32>)> = (0..32).map(|n| (n as u32, lists[n].as_str(), None)).collect();
        let d = sysfs("0-31", &cpus, &[]);
        assert_eq!(linux_cores(d.path()), (Some(16), Some(0)));
        // an offline half (SMT off at run time): the online CPUs' cores only
        let d = sysfs("0-15", &cpus[..16].iter().map(|(n, _, c)| (*n, "", *c)).collect::<Vec<_>>(), &[]);
        assert_eq!(linux_cores(d.path()), (Some(16), Some(0)));
    }

    /// RK3588: four Cortex-A55 (capacity 414) and four Cortex-A76 (1024), one thread each.
    #[test]
    fn linux_arm_big_little_by_capacity() {
        let names: Vec<String> = (0..8).map(|n: u32| n.to_string()).collect();
        let cpus: Vec<(u32, &str, Option<u32>)> =
            (0..8).map(|n| (n as u32, names[n].as_str(), Some(if n < 4 { 414 } else { 1024 }))).collect();
        let d = sysfs("0-7", &cpus, &[]);
        assert_eq!(linux_cores(d.path()), (Some(4), Some(4)));
        // a mid cluster (Cortex-A78 at 870) is a performance cluster
        let cpus: Vec<(u32, &str, Option<u32>)> =
            (0..8).map(|n| (n as u32, names[n].as_str(), Some([325, 325, 325, 325, 870, 870, 870, 1024][n]))).collect();
        let d = sysfs("0-7", &cpus, &[]);
        assert_eq!(linux_cores(d.path()), (Some(4), Some(4)));
    }

    #[test]
    fn linux_without_topology_is_unknown() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("system/cpu/cpu0")).unwrap();
        assert_eq!(linux_cores(d.path()), (None, None));
        assert_eq!(linux_cores(Path::new("/nonexistent-sysfs")), (None, None));
    }

    /// GetLogicalProcessorInformationEx(RelationProcessorCore) records on 64-bit Windows: Relationship, Size (48), Flags
    /// (LTP_PC_SMT 1 when the core runs two threads), EfficiencyClass, 20 reserved bytes, GroupCount, then one
    /// GROUP_AFFINITY (KAFFINITY mask, group) at offset 32.
    fn core_record(class: u8, mask: u64, group: u16) -> Vec<u8> {
        let mut r = vec![0u8; 48];
        r[4..8].copy_from_slice(&48u32.to_le_bytes());
        r[8] = u8::from(mask.count_ones() > 1);
        r[9] = class;
        r[30..32].copy_from_slice(&1u16.to_le_bytes());
        r[32..40].copy_from_slice(&mask.to_le_bytes());
        r[40..42].copy_from_slice(&group.to_le_bytes());
        r
    }

    #[test]
    fn windows_cores_from_processor_records() {
        // TNT-PC, recorded 2026-10-10: Core i7-9700, NumberOfCores 8, NumberOfLogicalProcessors 8 (no Hyper-Threading),
        // one efficiency class; its old facts said perf_cores null, eff_cores null, logical 8
        let pc: Vec<u8> = (0..8).flat_map(|n| core_record(0, 1 << n, 0)).collect();
        assert_eq!(windows_cores(&pc), Some((8, 0)));
        // a 4-core part with Hyper-Threading: 4 records with two bits each, 8 logical processors
        let ht: Vec<u8> = (0..4).flat_map(|n| core_record(0, 0b11 << (2 * n), 0)).collect();
        assert_eq!(windows_cores(&ht), Some((4, 0)));
        // Core i7-12700: 8 P-cores (class 1, two threads each) and 4 E-cores (class 0)
        let mut adl: Vec<u8> = (0..8).flat_map(|n| core_record(1, 0b11 << (2 * n), 0)).collect();
        adl.extend((0..4).flat_map(|n| core_record(0, 1 << (16 + n), 0)));
        assert_eq!(windows_cores(&adl), Some((8, 4)));
        // two processor groups of 64 cores (a 128-core server)
        let big: Vec<u8> = (0..128).flat_map(|n| core_record(0, 1 << (n % 64), n / 64)).collect();
        assert_eq!(windows_cores(&big), Some((128, 0)));
        // a record of another relationship is skipped; a truncated buffer is no answer
        let mut other = core_record(0, 1, 0);
        other[0] = 2;
        assert_eq!(windows_cores(&[other.clone(), core_record(0, 2, 0)].concat()), Some((1, 0)));
        assert_eq!(windows_cores(&pc[..100]), None);
        assert_eq!(windows_cores(&[]), None);
    }

    #[test]
    fn mac_cores_by_performance_level() {
        assert_eq!(mac_cores(Some(12), Some(4), Some(16)), (Some(12), Some(4)));      // M4 Max
        assert_eq!(mac_cores(Some(8), None, Some(8)), (Some(8), Some(0)));            // one level (a VM)
        assert_eq!(mac_cores(None, None, Some(6)), (Some(6), Some(0)));               // Intel Mac: 6 cores, 12 threads
        assert_eq!(mac_cores(None, None, None), (None, None));
    }

    #[test]
    fn capacity_counts_cores_and_falls_back_to_logical_only_without_them() {
        use serde_json::json;
        assert_eq!(capacity_cores(&json!({"perf_cores": 12, "eff_cores": 4, "logical": 16})), (12, 4));
        assert_eq!(capacity_cores(&json!({"perf_cores": 8, "eff_cores": 0, "logical": 8})), (8, 0));
        assert_eq!(capacity_cores(&json!({"perf_cores": 4, "eff_cores": null, "logical": 8})), (4, 0));
        assert_eq!(capacity_cores(&json!({"perf_cores": null, "eff_cores": null, "logical": 8})), (8, 0));
        assert_eq!(capacity_cores(&json!({})), (1, 0));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn this_mac_reports_physical_cores() {
        let SysInfo { perf, eff, logical, .. } = sysinfo();
        let (p, e) = (perf.unwrap(), eff.unwrap());
        assert!(p >= 1 && p + e <= logical.unwrap(), "{p}P {e}E {logical:?}");
    }
}
