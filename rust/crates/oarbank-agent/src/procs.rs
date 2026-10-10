//! Process containers and their usage (spec/platforms.md, "Process containers"): a job is a container the agent
//! created (a process group on Unix, a Job Object on Windows; see sys.rs), signalled and measured as a whole.

pub use crate::sys::{group_pids, Sig};

#[derive(Debug, Clone, Copy, Default)]
pub struct Usage {
    pub cpu_s: f64,
    pub footprint_gb: f64,
    pub procs: usize,
}

/// The members of a process group: macOS asks the kernel, Linux reads /proc.
#[cfg(target_os = "macos")]
pub fn unix_group_pids(pgid: i32) -> Vec<i32> {
    const PROC_PGRP_ONLY: u32 = 2;
    unsafe {
        let n = libc::proc_listpids(PROC_PGRP_ONLY, pgid as u32, std::ptr::null_mut(), 0);
        if n <= 0 {
            return vec![];
        }
        let mut buf = vec![0i32; (n as usize) / 4 + 16];
        let got = libc::proc_listpids(PROC_PGRP_ONLY, pgid as u32, buf.as_mut_ptr() as *mut _, (buf.len() * 4) as i32);
        buf.truncate(got.max(0) as usize / 4);
        buf.retain(|p| *p > 0);
        buf
    }
}

#[cfg(target_os = "linux")]
pub fn unix_group_pids(pgid: i32) -> Vec<i32> {
    let r = oarbank_protection::platform::linux::reader();
    r.pids().unwrap_or_default().into_iter().filter(|pid| r.stat(*pid).is_some_and(|s| s.pgrp == pgid)).collect()
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
pub fn unix_group_pids(_pgid: i32) -> Vec<i32> {
    vec![]
}

/// CPU seconds and physical footprint of every process in the container.
#[allow(deprecated)]                   // libc's mach_timebase_info: the only dependency-free way to read the timebase
pub fn group_usage(pgid: i32) -> Usage {
    let mut u = Usage::default();
    #[cfg(target_os = "macos")]
    for pid in group_pids(pgid) {
        unsafe {
            let mut ri: libc::rusage_info_v2 = std::mem::zeroed();
            if libc::proc_pid_rusage(pid, libc::RUSAGE_INFO_V2, &mut ri as *mut _ as *mut _) == 0 {
                // ri_user_time/ri_system_time are in mach absolute time units: nanoseconds on Apple silicon after
                // the timebase conversion below
                let mut tb = libc::mach_timebase_info { numer: 0, denom: 0 };
                libc::mach_timebase_info(&mut tb);
                let scale = if tb.denom > 0 { tb.numer as f64 / tb.denom as f64 } else { 1.0 };
                u.cpu_s += (ri.ri_user_time + ri.ri_system_time) as f64 * scale / 1e9;
                u.footprint_gb += ri.ri_phys_footprint as f64 / 1073741824.0;
                u.procs += 1;
            }
        }
    }
    #[cfg(target_os = "linux")]
    if let Some((cpu, mem)) = crate::cgroup::usage(pgid) {
        return Usage { cpu_s: cpu, footprint_gb: mem, procs: group_pids(pgid).len() };
    }
    #[cfg(target_os = "linux")]
    {
        let r = oarbank_protection::platform::linux::reader();
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as f64;
        for pid in group_pids(pgid) {
            let Some(s) = r.stat(pid) else { continue };
            u.cpu_s += (s.utime + s.stime) as f64 / r.clk_tck as f64;
            u.footprint_gb += s.rss_pages as f64 * page / 1073741824.0;
            u.procs += 1;
        }
    }
    #[cfg(windows)]
    for pid in group_pids(pgid) {
        use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
        use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX};
        use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
            if h.is_null() {
                continue;
            }
            let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
            let (mut c, mut e, mut k, mut us) = (z, z, z, z);
            let t = |f: FILETIME| ((f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64) as f64 / 1e7;
            if GetProcessTimes(h, &mut c, &mut e, &mut k, &mut us) != 0 {
                u.cpu_s += t(k) + t(us);
            }
            let mut m: PROCESS_MEMORY_COUNTERS_EX = std::mem::zeroed();
            m.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
            if GetProcessMemoryInfo(h, &mut m as *mut _ as *mut _, m.cb) != 0 {
                u.footprint_gb += m.PrivateUsage as f64 / 1073741824.0;
            }
            CloseHandle(h);
            u.procs += 1;
        }
    }
    let _ = pgid;
    u
}

pub fn signal_group(pgid: i32, sig: Sig) -> bool {
    crate::sys::signal_group(pgid, sig)
}

/// When a process started, in microseconds since the epoch (with its pid, its identity: a recycled pid has another
/// start time). Linux: the boot time plus its start in clock ticks (the protection crate's procfs reader).
#[cfg(target_os = "linux")]
pub use oarbank_protection::platform::linux::start_time_us;

/// macOS: the kernel's `pbi_start_tvsec`/`pbi_start_tvusec` (libproc).
#[cfg(target_os = "macos")]
pub use oarbank_protection::platform::macos::start_time_us;

/// Windows: the creation time GetProcessTimes reports (100 ns units since 1601).
#[cfg(windows)]
pub fn start_time_us(pid: i32) -> Option<u64> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    const EPOCH_1601_TO_1970_US: u64 = 11_644_473_600_000_000;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
        if h.is_null() {
            return None;
        }
        let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut c, mut e, mut k, mut u) = (z, z, z, z);
        let ok = GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) != 0;
        CloseHandle(h);
        let t = ((c.dwHighDateTime as u64) << 32 | c.dwLowDateTime as u64) / 10;
        (ok && t > EPOCH_1601_TO_1970_US).then(|| t - EPOCH_1601_TO_1970_US)
    }
}
