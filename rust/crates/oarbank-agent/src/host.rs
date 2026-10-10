//! Host signals for capacity and protection: memory, thermal state and power source (the Meter and Power interfaces,
//! docs/design/architecture.md, "Host interfaces"). macOS reads the kernel and IOKit; Linux reads /proc, PSI and /sys;
//! Windows asks Win32. User presence is the protection crate's (`oarbank_protection::platform::native_presence`).

#[derive(Debug, Clone, Copy, Default)]
pub struct Memory {
    pub ram_gb: f64,
    /// What cannot be handed to new work without paging, GB: on macOS app (internal minus purgeable) + wired +
    /// compressed; on Linux MemTotal − MemAvailable; on Windows physical minus ullAvailPhys (free + zeroed + standby).
    /// RAM minus this is the memory available to new work (capacity's in-use bound).
    pub used_gb: f64,
    /// The wire scale: 0 normal, 1 warning, 3 critical (from kern.memorystatus_vm_pressure_level's 1, 2, 4).
    pub pressure: i32,
    /// Data paged out to swap or the paging files, GB (None: unreadable).
    pub swap_used_gb: Option<f64>,
}

/// Windows' memory as GlobalMemoryStatusEx and the paging-file list report it, in bytes.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(not(windows), allow(dead_code))] // read on Windows, tested on every OS
pub struct WinMemory {
    pub total_phys: u64,
    pub avail_phys: u64,
    /// The commit charge and its limit (RAM plus the paging files): ullTotalPageFile − ullAvailPageFile, ullTotalPageFile.
    pub commit_total: u64,
    pub commit_limit: u64,
    /// dwMemoryLoad, percent of physical memory in use.
    pub load_pct: u32,
    /// Pages in use in every paging file, in bytes (None: the list could not be read).
    pub pagefile_in_use: Option<u64>,
}

/// The signals from Windows' figures. Swap is what the paging files actually hold: the commit charge beyond physical
/// use is not paging (programs commit memory long before they touch it; TNT-PC's guard read +282 MB/min of "swap"
/// from that with 54 % of its memory free and 39 MB in its paging file). Pressure is the worse of physical load
/// (85 % warning, 92 % critical) and the commit charge against its limit (90 %, 97 %): at the limit allocations fail
/// even with physical memory free.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_signals(w: &WinMemory) -> Memory {
    let gb = |b: u64| b as f64 / 1073741824.0;
    let phys = if w.load_pct >= 92 { 3 } else if w.load_pct >= 85 { 1 } else { 0 };
    let commit = if w.commit_limit == 0 {
        0
    } else {
        let r = w.commit_total as f64 / w.commit_limit as f64;
        if r >= 0.97 { 3 } else if r >= 0.90 { 1 } else { 0 }
    };
    Memory { ram_gb: gb(w.total_phys), used_gb: gb(w.total_phys.saturating_sub(w.avail_phys)), pressure: phys.max(commit),
             swap_used_gb: w.pagefile_in_use.map(gb) }
}

/// Pages in use summed over the SYSTEM_PAGEFILE_INFORMATION records NtQuerySystemInformation(SystemPageFileInformation)
/// fills: NextEntryOffset, TotalSize, TotalInUse, PeakUsage (pages, u32 each), then the file's name. An empty buffer is
/// a machine without a paging file (nothing paged out). None for a malformed buffer.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn pagefile_pages_in_use(buf: &[u8]) -> Option<u64> {
    let mut off = 0usize;
    let mut pages = 0u64;
    if buf.is_empty() {
        return Some(0);
    }
    loop {
        let rec = buf.get(off..off + 16)?;
        let u = |i: usize| u32::from_le_bytes([rec[i], rec[i + 1], rec[i + 2], rec[i + 3]]);
        pages += u64::from(u(8));
        match u(0) as usize {
            0 => return Some(pages),
            next => off = off.checked_add(next)?,
        }
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use std::ffi::{c_char, c_void};

    type CFTypeRef = *const c_void;
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOPSCopyPowerSourcesInfo() -> CFTypeRef;
        fn IOPSGetProvidingPowerSourceType(blob: CFTypeRef) -> CFTypeRef;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(cf: CFTypeRef);
        fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, size: isize, encoding: u32) -> bool;
    }
    const UTF8: u32 = 0x0800_0100;

    pub fn on_battery() -> bool {
        unsafe {
            let blob = IOPSCopyPowerSourcesInfo();
            if blob.is_null() {
                return false;
            }
            let t = IOPSGetProvidingPowerSourceType(blob);
            let mut buf = [0 as c_char; 64];
            let ok = !t.is_null() && CFStringGetCString(t, buf.as_mut_ptr(), 64, UTF8);
            CFRelease(blob);
            ok && std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy() == "Battery Power"
        }
    }

    /// Whether the Mac has an internal battery (a laptop): IOKit's AppleSmartBattery service exists only there. A UPS
    /// on a desktop is a power source but not this service.
    pub fn has_battery() -> bool {
        #[link(name = "IOKit", kind = "framework")]
        unsafe extern "C" {
            fn IOServiceMatching(name: *const c_char) -> *mut c_void;
            fn IOServiceGetMatchingService(main_port: u32, matching: *mut c_void) -> u32;
            fn IOObjectRelease(object: u32) -> i32;
        }
        unsafe {
            let matching = IOServiceMatching(c"AppleSmartBattery".as_ptr());
            if matching.is_null() {
                return false;
            }
            // consumes `matching`; 0 is kIOMainPortDefault
            let svc = IOServiceGetMatchingService(0, matching);
            if svc == 0 {
                return false;
            }
            IOObjectRelease(svc);
            true
        }
    }

    /// NSProcessInfo.thermalState through the Objective-C runtime: 0 nominal, 1 fair, 2 serious, 3 critical.
    pub fn thermal_state() -> i32 {
        #[link(name = "objc")]
        unsafe extern "C" {
            fn objc_getClass(name: *const c_char) -> *mut c_void;
            fn sel_registerName(name: *const c_char) -> *mut c_void;
            fn objc_msgSend();
        }
        #[link(name = "Foundation", kind = "framework")]
        unsafe extern "C" {}
        unsafe {
            let cls = objc_getClass(c"NSProcessInfo".as_ptr());
            if cls.is_null() {
                return 0;
            }
            let send0: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            let pi = send0(cls, sel_registerName(c"processInfo".as_ptr()));
            if pi.is_null() {
                return 0;
            }
            let send_i: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize = std::mem::transmute(objc_msgSend as unsafe extern "C" fn());
            send_i(pi, sel_registerName(c"thermalState".as_ptr())) as i32
        }
    }

    pub fn memory() -> super::Memory {
        use crate::facts::sysctl_u64;
        let ram = sysctl_u64("hw.memsize").unwrap_or(0) as f64 / 1073741824.0;
        let page = sysctl_u64("hw.pagesize").unwrap_or(16384) as f64;
        let mut vs: libc::vm_statistics64 = unsafe { std::mem::zeroed() };
        let mut count = (std::mem::size_of::<libc::vm_statistics64>() / std::mem::size_of::<libc::integer_t>()) as libc::mach_msg_type_number_t;
        #[allow(deprecated)]
        let kr = unsafe { libc::host_statistics64(libc::mach_host_self(), libc::HOST_VM_INFO64, &mut vs as *mut _ as *mut _, &mut count) };
        let used = if kr == 0 {
            let app = (vs.internal_page_count as f64 - vs.purgeable_count as f64).max(0.0);
            (app + vs.wire_count as f64 + vs.compressor_page_count as f64) * page / 1073741824.0
        } else {
            0.0
        };
        let pressure = match sysctl_u64("kern.memorystatus_vm_pressure_level") {
            Some(v) if v >= 4 => 3,
            Some(2) | Some(3) => 1,
            _ => 0,
        };
        let swap = unsafe {
            let mut x: libc::xsw_usage = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::xsw_usage>();
            let name = c"vm.swapusage";
            (libc::sysctlbyname(name.as_ptr(), &mut x as *mut _ as *mut _, &mut len, std::ptr::null_mut(), 0) == 0)
                .then_some(x.xsu_used as f64 / 1073741824.0)
        };
        super::Memory { ram_gb: ram, used_gb: used, pressure, swap_used_gb: swap }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    fn kb(meminfo: &str, key: &str) -> Option<f64> {
        meminfo.lines().find(|l| l.starts_with(key)).and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok())
    }

    /// avg10 of a PSI line ("some avg10=1.23 avg60=…").
    fn psi(text: &str, kind: &str) -> f64 {
        text.lines().find(|l| l.starts_with(kind)).and_then(|l| l.split_whitespace().find_map(|f| f.strip_prefix("avg10=")))
            .and_then(|v| v.parse().ok()).unwrap_or(0.0)
    }

    pub fn memory() -> super::Memory {
        let mi = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let gb = |k: &str| kb(&mi, k).map(|v| v / 1048576.0);
        let total = gb("MemTotal:").unwrap_or(0.0);
        let avail = gb("MemAvailable:").unwrap_or(total);
        let swap = match (gb("SwapTotal:"), gb("SwapFree:")) { (Some(t), Some(f)) => Some((t - f).max(0.0)), _ => None };
        // stall time under memory pressure: "full" (every task stalled) is critical, "some" a warning
        let p = std::fs::read_to_string("/proc/pressure/memory").unwrap_or_default();
        let pressure = if psi(&p, "full") > 5.0 { 3 } else if psi(&p, "some") > 10.0 { 1 } else { 0 };
        super::Memory { ram_gb: total, used_gb: (total - avail).max(0.0), pressure, swap_used_gb: swap }
    }

    /// The hottest thermal zone against its first trip point: 0 nominal, 1 within 10 °C, 2 within 3 °C, 3 at or over it.
    pub fn thermal_state() -> i32 {
        let Ok(rd) = std::fs::read_dir("/sys/class/thermal") else { return 0 };
        let mut worst = 0;
        for z in rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("thermal_zone"))) {
            let read = |f: &str| std::fs::read_to_string(z.join(f)).ok().and_then(|s| s.trim().parse::<f64>().ok());
            let (Some(t), Some(trip)) = (read("temp"), read("trip_point_0_temp")) else { continue };
            let margin = (trip - t) / 1000.0;
            worst = worst.max(if margin <= 0.0 { 3 } else if margin < 3.0 { 2 } else if margin < 10.0 { 1 } else { 0 });
        }
        worst
    }

    pub fn on_battery() -> bool {
        let Ok(rd) = std::fs::read_dir("/sys/class/power_supply") else { return false };
        let mut battery_discharging = false;
        let mut mains_online = false;
        for d in rd.filter_map(|e| e.ok()).map(|e| e.path()) {
            let read = |f: &str| std::fs::read_to_string(d.join(f)).unwrap_or_default().trim().to_string();
            match read("type").as_str() {
                "Battery" => battery_discharging |= read("status") == "Discharging",
                "Mains" | "USB" => mains_online |= read("online") == "1",
                _ => {}
            }
        }
        battery_discharging && !mains_online
    }

    /// A system battery (a laptop): a power supply of type Battery that powers the system, not a device's (a mouse's
    /// battery has scope Device).
    pub fn has_battery() -> bool {
        let Ok(rd) = std::fs::read_dir("/sys/class/power_supply") else { return false };
        rd.filter_map(|e| e.ok()).map(|e| e.path()).any(|d| {
            let read = |f: &str| std::fs::read_to_string(d.join(f)).unwrap_or_default().trim().to_string();
            read("type") == "Battery" && read("scope") != "Device"
        })
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO};

    const SYSTEM_PAGEFILE_INFORMATION: u32 = 18;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQuerySystemInformation(class: u32, info: *mut std::ffi::c_void, len: u32, ret: *mut u32) -> i32;
    }

    /// Bytes in use in the paging files (what Win32_PageFileUsage's CurrentUsage reports).
    fn pagefile_in_use() -> Option<u64> {
        let mut si: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetSystemInfo(&mut si) };
        let page = u64::from(si.dwPageSize.max(4096));
        let mut len = 4096u32;
        for _ in 0..6 {
            // u64 storage keeps the records aligned
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            let mut ret = 0u32;
            // SAFETY: the buffer holds `len` bytes.
            let st = unsafe { NtQuerySystemInformation(SYSTEM_PAGEFILE_INFORMATION, buf.as_mut_ptr().cast(), len, &mut ret) };
            if st == STATUS_INFO_LENGTH_MISMATCH {
                len = ret.max(len * 2);
                continue;
            }
            if st < 0 {
                return None;
            }
            let bytes = (ret as usize).min(buf.len() * 8);
            // SAFETY: the kernel wrote `ret` bytes at the start of `buf`.
            let b = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), bytes) };
            return super::pagefile_pages_in_use(b).map(|p| p * page);
        }
        None
    }

    pub fn memory() -> super::Memory {
        let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if unsafe { GlobalMemoryStatusEx(&mut m) } == 0 {
            return super::Memory::default();
        }
        super::windows_signals(&super::WinMemory { total_phys: m.ullTotalPhys, avail_phys: m.ullAvailPhys,
                                                   commit_total: m.ullTotalPageFile.saturating_sub(m.ullAvailPageFile),
                                                   commit_limit: m.ullTotalPageFile, load_pct: m.dwMemoryLoad,
                                                   pagefile_in_use: pagefile_in_use() })
    }

    pub fn on_battery() -> bool {
        use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
        let mut st: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
        // ACLineStatus 0 = offline; BatteryFlag 128 = no battery
        let ok = unsafe { GetSystemPowerStatus(&mut st) } != 0;
        ok && st.ACLineStatus == 0 && st.BatteryFlag != 128
    }

    /// A system battery (a laptop): BatteryFlag 128 is "no system battery", 255 "unknown status".
    pub fn has_battery() -> bool {
        use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
        let mut st: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
        let ok = unsafe { GetSystemPowerStatus(&mut st) } != 0;
        ok && st.BatteryFlag != 128 && st.BatteryFlag != 255
    }
}

pub fn memory() -> Memory {
    #[cfg(target_os = "macos")]
    return mac::memory();
    #[cfg(target_os = "linux")]
    return linux::memory();
    #[cfg(windows)]
    return win::memory();
    #[allow(unreachable_code)]
    Memory::default()
}

pub fn thermal() -> i32 {
    #[cfg(target_os = "macos")]
    return mac::thermal_state();
    #[cfg(target_os = "linux")]
    return linux::thermal_state();
    #[allow(unreachable_code)]
    0
}

pub fn on_battery() -> bool {
    #[cfg(target_os = "macos")]
    return mac::on_battery();
    #[cfg(target_os = "linux")]
    return linux::on_battery();
    #[cfg(windows)]
    return win::on_battery();
    #[allow(unreachable_code)]
    false
}

/// Whether this machine has a system battery (a laptop), for the facts' `power.battery`: groups select laptops on it
/// (docs/design/settings.md, "Groups and labels").
pub fn has_battery() -> bool {
    #[cfg(target_os = "macos")]
    return mac::has_battery();
    #[cfg(target_os = "linux")]
    return linux::has_battery();
    #[cfg(windows)]
    return win::has_battery();
    #[allow(unreachable_code)]
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TNT-PC (Core i7-9700, 15.8 GB, a 1 GB paging file), recorded read-only on 2026-10-10: Get-Counter's Available
    /// MBytes 8,810, Committed Bytes 8,230,338,560 of a Commit Limit of 18,016,935,936, Paging File % Usage 4,
    /// Win32_PageFileUsage CurrentUsage 39 MB. The old reading called commit − physical use "swap" (0.7 GB, and its
    /// growth +282 MB/min); the paging file holds 39 MB.
    #[test]
    fn windows_swap_is_the_paging_file_not_the_commit_charge() {
        let pc = WinMemory { total_phys: 16_546_088 * 1024, avail_phys: 8_810 * 1_048_576, commit_total: 8_230_338_560,
                             commit_limit: 18_016_935_936, load_pct: 46, pagefile_in_use: Some(39 * 1_048_576) };
        let m = windows_signals(&pc);
        assert!((m.ram_gb - 15.78).abs() < 0.01 && (m.used_gb - 7.18).abs() < 0.01, "{m:?}");
        assert_eq!(m.pressure, 0);
        assert!((m.swap_used_gb.unwrap() - 0.038).abs() < 0.001);
        // commit near its limit is pressure even with physical memory free: allocations would fail
        assert_eq!(windows_signals(&WinMemory { commit_total: 16_300_000_000, ..pc }).pressure, 1);
        assert_eq!(windows_signals(&WinMemory { commit_total: 17_600_000_000, ..pc }).pressure, 3);
        assert_eq!(windows_signals(&WinMemory { load_pct: 93, ..pc }).pressure, 3);
        // an unreadable paging-file list is no swap signal, never a made-up one
        assert_eq!(windows_signals(&WinMemory { pagefile_in_use: None, ..pc }).swap_used_gb, None);
    }

    /// SYSTEM_PAGEFILE_INFORMATION records: NextEntryOffset, TotalSize, TotalInUse, PeakUsage, then a UNICODE_STRING
    /// (16 bytes on 64-bit) whose characters follow.
    #[test]
    fn paging_file_records() {
        let rec = |next: u32, total: u32, in_use: u32| {
            let mut r = vec![0u8; 32];
            r[0..4].copy_from_slice(&next.to_le_bytes());
            r[4..8].copy_from_slice(&total.to_le_bytes());
            r[8..12].copy_from_slice(&in_use.to_le_bytes());
            r[12..16].copy_from_slice(&(in_use + 512).to_le_bytes());
            r
        };
        // TNT-PC: one 1 GB file (262,144 pages of 4 KiB), 9,984 pages (39 MB) in use
        assert_eq!(pagefile_pages_in_use(&rec(0, 262_144, 9_984)), Some(9_984));
        let mut two = rec(64, 262_144, 100);
        two.resize(64, 0);
        two.extend(rec(0, 524_288, 50));
        assert_eq!(pagefile_pages_in_use(&two), Some(150));
        assert_eq!(pagefile_pages_in_use(&[]), Some(0));          // no paging file
        assert_eq!(pagefile_pages_in_use(&two[..40]), None);      // the second record cut off
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn signals_are_sane_on_this_mac() {
        let m = super::memory();
        assert!(m.ram_gb > 1.0 && m.used_gb > 0.1 && m.used_gb < m.ram_gb, "{m:?}");
        assert!([0, 1, 3].contains(&m.pressure));
        assert!((0..=3).contains(&super::thermal()));
        let _ = super::on_battery();
        // a Mac without a battery never reports running on one
        if !super::has_battery() {
            assert!(!super::on_battery());
        }
    }
}

#[cfg(test)]
mod print {
    #[test]
    #[ignore]
    fn show() {
        println!("{:?}", super::memory());
    }
}
