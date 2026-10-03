//! The same-user process table without root: libproc for identity, parentage, CPU and footprint, sysctl
//! KERN_PROCARGS2 for argv, the app bundle's Info.plist for the bundle id.

use std::collections::HashSet;
use std::mem;
use std::sync::OnceLock;

use super::{cf, security};
use crate::signals::ProcCounters;
use crate::table::{ProcessSource, RawProcess, SigningIdentity, SourceError};

const PROC_PGRP_ONLY: u32 = 2;
const RUSAGE_INFO_V4: i32 = 4;
const RUSAGE_INFO_V6: i32 = 6;
const GB: f64 = 1_073_741_824.0;

#[repr(C)]
struct MachTimebase {
    numer: u32,
    denom: u32,
}

extern "C" {
    fn mach_timebase_info(info: *mut MachTimebase) -> i32;
}

/// Mach absolute-time units to nanoseconds.
fn timebase() -> f64 {
    static TB: OnceLock<f64> = OnceLock::new();
    *TB.get_or_init(|| {
        let mut tb = MachTimebase { numer: 0, denom: 0 };
        // SAFETY: tb is a valid out-pointer.
        unsafe { mach_timebase_info(&mut tb) };
        if tb.denom == 0 {
            1.0
        } else {
            f64::from(tb.numer) / f64::from(tb.denom)
        }
    })
}

pub fn all_pids() -> Vec<i32> {
    // SAFETY: a NULL buffer asks for the count; the second call fills a buffer we own.
    unsafe {
        let n = libc::proc_listallpids(std::ptr::null_mut(), 0);
        if n <= 0 {
            return vec![];
        }
        let mut buf = vec![0i32; n as usize + 64];
        let got = libc::proc_listallpids(
            buf.as_mut_ptr().cast(),
            (buf.len() * mem::size_of::<i32>()) as i32,
        );
        if got <= 0 {
            return vec![];
        }
        buf.truncate(got as usize);
        buf.retain(|&p| p > 0);
        buf
    }
}

/// Members of a process group.
pub fn pids_in_group(pgid: i32) -> Vec<i32> {
    // SAFETY: as in all_pids; proc_listpids returns bytes, not entries.
    unsafe {
        let n = libc::proc_listpids(PROC_PGRP_ONLY, pgid as u32, std::ptr::null_mut(), 0);
        if n <= 0 {
            return vec![];
        }
        let mut buf = vec![0i32; n as usize / mem::size_of::<i32>() + 16];
        let got = libc::proc_listpids(
            PROC_PGRP_ONLY,
            pgid as u32,
            buf.as_mut_ptr().cast(),
            (buf.len() * 4) as i32,
        );
        if got <= 0 {
            return vec![];
        }
        buf.truncate(got as usize / mem::size_of::<i32>());
        buf.retain(|&p| p > 0);
        buf
    }
}

pub(crate) fn bsd_info(pid: i32) -> Option<libc::proc_bsdinfo> {
    // SAFETY: proc_bsdinfo is plain data; the kernel fills it when the size matches.
    unsafe {
        let mut info: libc::proc_bsdinfo = mem::zeroed();
        let sz = mem::size_of::<libc::proc_bsdinfo>() as i32;
        let r = libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            sz,
        );
        (r == sz).then_some(info)
    }
}

fn start_of(b: &libc::proc_bsdinfo) -> u64 {
    b.pbi_start_tvsec * 1_000_000 + b.pbi_start_tvusec
}

/// Start time in microseconds since the epoch, or None if the process is gone or not visible.
pub fn start_time_us(pid: i32) -> Option<u64> {
    bsd_info(pid).map(|b| start_of(&b))
}

pub fn path(pid: i32) -> String {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is PROC_PIDPATHINFO_MAXSIZE bytes.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return String::new();
    }
    buf.truncate(n as usize);
    String::from_utf8_lossy(&buf).into_owned()
}

/// argv through KERN_PROCARGS2 (same-user processes only).
pub fn argv(pid: i32) -> Option<Vec<String>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    // SAFETY: a NULL buffer asks for the size; the second call fills a buffer we own of that size.
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
            || size <= 4
        {
            return None;
        }
        let mut buf = vec![0u8; size];
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
            || size <= 4
        {
            return None;
        }
        buf.truncate(size);
        let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]).max(0) as usize;
        let mut i = 4;
        while i < size && buf[i] != 0 {
            i += 1; // exec path
        }
        while i < size && buf[i] == 0 {
            i += 1; // padding
        }
        let mut out = vec![];
        while out.len() < argc && i < size {
            let mut j = i;
            while j < size && buf[j] != 0 {
                j += 1;
            }
            out.push(String::from_utf8_lossy(&buf[i..j]).into_owned());
            i = j + 1;
        }
        Some(out)
    }
}

/// A rusage_info buffer large enough for any kernel's version of the struct (read by offset).
fn rusage(pid: i32, flavor: i32) -> Option<[u64; 128]> {
    let mut buf = [0u64; 128];
    // SAFETY: the kernel writes at most its rusage_info size (well under 1 KiB) into our 1 KiB buffer.
    // (like the C API, the struct's own address is passed as the `rusage_info_t *`)
    let rc = unsafe {
        libc::proc_pid_rusage(pid, flavor, buf.as_mut_ptr().cast::<libc::rusage_info_t>())
    };
    (rc == 0).then_some(buf)
}

// rusage_info field indexes in u64 words: ri_uuid takes words 0-1.
const RI_USER_TIME: usize = 2;
const RI_SYSTEM_TIME: usize = 3;
const RI_PAGEINS: usize = 6;
const RI_PHYS_FOOTPRINT: usize = 9;
const RI_INSTRUCTIONS: usize = 31;
const RI_CYCLES: usize = 32;
const RI_RUNNABLE_TIME: usize = 36;

/// (cumulative CPU seconds, physical footprint GB) from rusage V4.
pub fn cpu_and_footprint(pid: i32) -> Option<(f64, f64)> {
    let r = rusage(pid, RUSAGE_INFO_V4)?;
    let cpu = r[RI_USER_TIME].wrapping_add(r[RI_SYSTEM_TIME]) as f64 * timebase() / 1e9;
    Some((cpu, r[RI_PHYS_FOOTPRINT] as f64 / GB))
}

/// rusage V6 counters for a same-user process (None: gone, or not permitted).
pub fn proc_counters(pid: i32) -> Option<ProcCounters> {
    let r = rusage(pid, RUSAGE_INFO_V6)?;
    let s = timebase() / 1e9;
    Some(ProcCounters {
        cpu_s: r[RI_USER_TIME].wrapping_add(r[RI_SYSTEM_TIME]) as f64 * s,
        runnable_s: r[RI_RUNNABLE_TIME] as f64 * s,
        instructions: r[RI_INSTRUCTIONS] as f64,
        cycles: r[RI_CYCLES] as f64,
        pageins: r[RI_PAGEINS] as f64,
    })
}

/// CFBundleIdentifier of the app bundle an executable sits in.
pub fn bundle_id_for_path(p: &str) -> Option<String> {
    let i = p.find(".app/Contents/")?;
    let plist = format!("{}.app/Contents/Info.plist", &p[..i]);
    let bytes = std::fs::read(plist).ok()?;
    let dict = cf::property_list(&bytes)?;
    cf::to_string(cf::dict_get_str(dict.get(), "CFBundleIdentifier"))
}

fn comm_of(b: &libc::proc_bsdinfo) -> String {
    let bytes: Vec<u8> = b
        .pbi_comm
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The macOS process table (same-user processes only; read-only).
#[derive(Debug, Default)]
pub struct NativeProcessSource;

impl NativeProcessSource {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessSource for NativeProcessSource {
    fn list(&mut self, excluding: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        let pids = all_pids();
        if pids.is_empty() {
            return Err(SourceError::Unreadable(
                "proc_listallpids returned nothing".into(),
            ));
        }
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let mut out = vec![];
        for pid in pids.into_iter().filter(|p| !excluding.contains(p)) {
            let Some(b) = bsd_info(pid) else { continue };
            if b.pbi_uid != uid {
                continue;
            }
            let (cpu_s, footprint_gb) = cpu_and_footprint(pid).unwrap_or((0.0, 0.0));
            out.push(RawProcess {
                pid,
                ppid: b.pbi_ppid as i32,
                start_us: start_of(&b),
                path: path(pid),
                comm: comm_of(&b),
                cpu_s,
                footprint_gb,
            });
        }
        Ok(out)
    }

    fn argv(&mut self, pid: i32) -> Option<Vec<String>> {
        argv(pid)
    }

    fn signing(&mut self, pid: i32) -> SigningIdentity {
        security::signing(pid)
    }

    fn satisfies(&mut self, pid: i32, requirement: &str) -> bool {
        security::satisfies(pid, requirement)
    }

    fn bundle_id(&mut self, path: &str) -> Option<String> {
        bundle_id_for_path(path)
    }
}
