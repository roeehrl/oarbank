//! Host signals for capacity and protection: memory, thermal state, power source and user presence (the Meter, Presence
//! and Power interfaces, docs/design/architecture.md, "Host interfaces"). macOS reads the kernel and IOKit; Linux reads
//! /proc, PSI and /sys; Windows asks Win32. User presence on Linux, and on Windows from the system service (session 0),
//! needs the per-session helper and is reported unknown.

#[derive(Debug, Clone, Copy, Default)]
pub struct Memory {
    pub ram_gb: f64,
    /// App + wired + compressed memory, GB (what cannot be dropped without paging).
    pub used_gb: f64,
    /// The wire scale: 0 normal, 1 warning, 3 critical (from kern.memorystatus_vm_pressure_level's 1, 2, 4).
    pub pressure: i32,
    pub swap_used_gb: Option<f64>,
}

#[cfg(target_os = "macos")]
mod mac {
    use std::ffi::{c_char, c_void, CString};

    type CFTypeRef = *const c_void;
    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IOPSCopyPowerSourcesInfo() -> CFTypeRef;
        fn IOPSGetProvidingPowerSourceType(blob: CFTypeRef) -> CFTypeRef;
        fn IOServiceMatching(name: *const c_char) -> *mut c_void;
        fn IOServiceGetMatchingService(main_port: u32, matching: *mut c_void) -> u32;
        fn IORegistryEntryCreateCFProperty(entry: u32, key: CFTypeRef, alloc: CFTypeRef, options: u32) -> CFTypeRef;
        fn IOObjectRelease(obj: u32) -> i32;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(cf: CFTypeRef);
        fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, size: isize, encoding: u32) -> bool;
        fn CFStringCreateWithCString(alloc: CFTypeRef, s: *const c_char, encoding: u32) -> CFTypeRef;
        fn CFNumberGetValue(n: CFTypeRef, kind: isize, out: *mut c_void) -> bool;
        fn CFGetTypeID(cf: CFTypeRef) -> usize;
        fn CFNumberGetTypeID() -> usize;
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

    /// Seconds since the last keyboard or mouse input (IOHIDSystem's HIDIdleTime).
    pub fn hid_idle_s() -> Option<f64> {
        unsafe {
            let name = CString::new("IOHIDSystem").ok()?;
            let svc = IOServiceGetMatchingService(0, IOServiceMatching(name.as_ptr()));
            if svc == 0 {
                return None;
            }
            let key_c = CString::new("HIDIdleTime").ok()?;
            let key = CFStringCreateWithCString(std::ptr::null(), key_c.as_ptr(), UTF8);
            let v = IORegistryEntryCreateCFProperty(svc, key, std::ptr::null(), 0);
            CFRelease(key);
            IOObjectRelease(svc);
            if v.is_null() {
                return None;
            }
            let mut ns: i64 = 0;
            let ok = CFGetTypeID(v) == CFNumberGetTypeID() && CFNumberGetValue(v, 4 /* kCFNumberSInt64Type */, &mut ns as *mut i64 as *mut c_void);
            CFRelease(v);
            ok.then_some(ns as f64 / 1e9)
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
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    pub fn memory() -> super::Memory {
        let mut m: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        if unsafe { GlobalMemoryStatusEx(&mut m) } == 0 {
            return super::Memory::default();
        }
        let gb = |b: u64| b as f64 / 1073741824.0;
        // dwMemoryLoad is the percentage of physical memory in use; the commit beyond physical memory is paging
        let pressure = if m.dwMemoryLoad >= 92 { 3 } else if m.dwMemoryLoad >= 85 { 1 } else { 0 };
        let committed = gb(m.ullTotalPageFile.saturating_sub(m.ullAvailPageFile));
        let used = gb(m.ullTotalPhys - m.ullAvailPhys);
        super::Memory { ram_gb: gb(m.ullTotalPhys), used_gb: used, pressure, swap_used_gb: Some((committed - used).max(0.0)) }
    }

    pub fn on_battery() -> bool {
        use windows_sys::Win32::System::Power::{GetSystemPowerStatus, SYSTEM_POWER_STATUS};
        let mut st: SYSTEM_POWER_STATUS = unsafe { std::mem::zeroed() };
        // ACLineStatus 0 = offline; BatteryFlag 128 = no battery
        let ok = unsafe { GetSystemPowerStatus(&mut st) } != 0;
        ok && st.ACLineStatus == 0 && st.BatteryFlag != 128
    }

    /// Seconds since the last input in this process's session; none in session 0 (the system service), where the
    /// per-session helper reports presence.
    pub fn idle_s() -> Option<f64> {
        use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        use windows_sys::Win32::System::SystemInformation::GetTickCount;
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
        let mut session = 0u32;
        if unsafe { ProcessIdToSessionId(std::process::id(), &mut session) } == 0 || session == 0 {
            return None;
        }
        let mut li = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
        (unsafe { GetLastInputInfo(&mut li) } != 0).then(|| unsafe { GetTickCount() }.wrapping_sub(li.dwTime) as f64 / 1000.0)
    }
}

/// A Screen Sharing session is in progress (someone is using the Mac remotely): `screensharingd` runs.
pub fn screen_sharing() -> bool {
    #[cfg(target_os = "macos")]
    unsafe {
        let n = libc::proc_listpids(1 /* PROC_ALL_PIDS */, 0, std::ptr::null_mut(), 0);
        if n <= 0 {
            return false;
        }
        let mut pids = vec![0i32; n as usize / 4 + 64];
        let got = libc::proc_listpids(1, 0, pids.as_mut_ptr() as *mut _, (pids.len() * 4) as i32);
        pids.truncate(got.max(0) as usize / 4);
        let mut buf = vec![0u8; 4096];
        return pids.iter().filter(|p| **p > 0).any(|&pid| {
            let k = libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut _, buf.len() as u32);
            k > 0 && buf[..k as usize].ends_with(b"/screensharingd")
        });
    }
    #[allow(unreachable_code)]
    false
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

pub fn hid_idle_s() -> Option<f64> {
    #[cfg(target_os = "macos")]
    return mac::hid_idle_s();
    #[cfg(windows)]
    return win::idle_s();
    #[allow(unreachable_code)]
    None
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "macos")]
    fn signals_are_sane_on_this_mac() {
        let m = super::memory();
        assert!(m.ram_gb > 1.0 && m.used_gb > 0.1 && m.used_gb < m.ram_gb, "{m:?}");
        assert!([0, 1, 3].contains(&m.pressure));
        assert!((0..=3).contains(&super::thermal()));
        let _ = super::on_battery();
        assert!(super::hid_idle_s().is_some_and(|s| s >= 0.0));
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
