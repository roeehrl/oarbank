//! The process table without root: `sysctl kern.proc` for identity, parentage and the short name (p_comm), libproc
//! for the path, CPU and footprint, sysctl KERN_PROCARGS2 for argv, the app bundle's Info.plist for the bundle id.
//! libproc's BSD info (macOS 27), rusage and argv answer only about the caller's own processes; `kern.proc` and the
//! executable's path answer about every account's, so the system service lists the people's processes from those
//! and takes the rest from their session helpers.

use std::collections::HashSet;
use std::mem;
use std::sync::{Arc, OnceLock};

use super::{cf, security};
use crate::session::{Principal, SessionHub};
use crate::signals::ProcCounters;
use crate::table::{ProcessSource, RawProcess, SigningIdentity, SourceError};

const PROC_PGRP_ONLY: u32 = 2;
/// `pbi_status` of a process that has exited and not been reaped (sys/proc.h).
const SZOMB: u32 = 5;
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

/// What `sysctl kern.proc` tells about a process of any account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KinfoProc {
    pub pid: i32,
    pub ppid: i32,
    /// The effective uid.
    pub uid: u32,
    pub start_us: u64,
    pub comm: String,
    pub zombie: bool,
}

/// `struct kinfo_proc` (sys/sysctl.h, 64-bit) and the offsets of the fields read: `kp_proc.p_starttime`,
/// `p_stat`, `p_pid`, `p_comm`, `kp_eproc.e_ucred.cr_uid` and `e_ppid`.
const KINFO_SIZE: usize = 648;
const KP_STARTTIME: usize = 0;
const KP_STAT: usize = 36;
const KP_PID: usize = 40;
const KP_COMM: usize = 243;
const KP_COMM_LEN: usize = 17;
const KP_UID: usize = 420;
const KP_PPID: usize = 560;

fn parse_kinfo(b: &[u8]) -> KinfoProc {
    let i32_at = |o: usize| i32::from_ne_bytes(b[o..o + 4].try_into().unwrap());
    let sec = i64::from_ne_bytes(b[KP_STARTTIME..KP_STARTTIME + 8].try_into().unwrap());
    let usec = i32_at(KP_STARTTIME + 8);
    let comm = &b[KP_COMM..KP_COMM + KP_COMM_LEN];
    let comm = &comm[..comm.iter().position(|&c| c == 0).unwrap_or(comm.len())];
    KinfoProc {
        pid: i32_at(KP_PID),
        ppid: i32_at(KP_PPID),
        uid: i32_at(KP_UID) as u32,
        start_us: (sec.max(0) as u64) * 1_000_000 + usec.max(0) as u64,
        comm: String::from_utf8_lossy(comm).into_owned(),
        zombie: u32::from(b[KP_STAT]) == SZOMB,
    }
}

/// `sysctl {CTL_KERN, KERN_PROC, what, arg}`: the matching processes.
fn kern_proc(what: i32, arg: i32) -> Vec<KinfoProc> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, what, arg];
    for _ in 0..3 {
        let mut size: libc::size_t = 0;
        // SAFETY: a NULL buffer asks for the size; the second call fills a buffer we own of the size given.
        unsafe {
            if libc::sysctl(
                mib.as_mut_ptr(),
                4,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                return vec![];
            }
            size += 16 * KINFO_SIZE; // processes started in between
            let mut buf = vec![0u8; size];
            if libc::sysctl(
                mib.as_mut_ptr(),
                4,
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            ) != 0
            {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOMEM) {
                    continue;
                }
                return vec![];
            }
            buf.truncate(size);
            return buf
                .as_chunks::<KINFO_SIZE>()
                .0
                .iter()
                .map(|b| parse_kinfo(b))
                .collect();
        }
    }
    vec![]
}

/// One process of any account (None: gone).
pub fn kinfo(pid: i32) -> Option<KinfoProc> {
    kern_proc(libc::KERN_PROC_PID, pid)
        .into_iter()
        .find(|k| k.pid == pid)
}

/// Every process whose effective uid is `uid`.
pub fn kinfo_of(uid: u32) -> Vec<KinfoProc> {
    kern_proc(libc::KERN_PROC_UID, uid as i32)
}

/// The executable's path (None: not readable).
pub fn path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer is PROC_PIDPATHINFO_MAXSIZE bytes.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(String::from_utf8_lossy(&buf).into_owned())
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

/// rusage V6 counters and the physical footprint (GB) of a same-user process (None: gone, or not permitted).
pub fn usage(pid: i32) -> Option<(ProcCounters, f64)> {
    let r = rusage(pid, RUSAGE_INFO_V6)?;
    let s = timebase() / 1e9;
    let counters = ProcCounters {
        cpu_s: r[RI_USER_TIME].wrapping_add(r[RI_SYSTEM_TIME]) as f64 * s,
        runnable_s: r[RI_RUNNABLE_TIME] as f64 * s,
        instructions: r[RI_INSTRUCTIONS] as f64,
        cycles: r[RI_CYCLES] as f64,
        pageins: r[RI_PAGEINS] as f64,
    };
    Some((counters, r[RI_PHYS_FOOTPRINT] as f64 / GB))
}

/// rusage V6 counters for a same-user process (None: gone, or not permitted).
pub fn proc_counters(pid: i32) -> Option<ProcCounters> {
    usage(pid).map(|(c, _)| c)
}

/// CFBundleIdentifier of the app bundle an executable sits in.
pub fn bundle_id_for_path(p: &str) -> Option<String> {
    let i = p.find(".app/Contents/")?;
    let plist = format!("{}.app/Contents/Info.plist", &p[..i]);
    let bytes = std::fs::read(plist).ok()?;
    let dict = cf::property_list(&bytes)?;
    cf::to_string(cf::dict_get_str(dict.get(), "CFBundleIdentifier"))
}

/// The macOS process table (read-only): the agent's own account's processes, and in the system service (`hub`) those
/// of every account a session helper reports for, with the arguments and resource use their helper read.
#[derive(Debug, Default)]
pub struct NativeProcessSource {
    hub: Option<Arc<SessionHub>>,
}

impl NativeProcessSource {
    pub fn new(hub: Option<Arc<SessionHub>>) -> Self {
        Self { hub }
    }
}

impl ProcessSource for NativeProcessSource {
    fn list(&mut self, excluding: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let mine = kinfo_of(uid);
        if mine.is_empty() {
            return Err(SourceError::Unreadable(
                "sysctl kern.proc lists none of this account's processes".into(),
            ));
        }
        let live = |k: &KinfoProc| !k.zombie && !excluding.contains(&k.pid);
        // a zombie has exited: it holds no memory or CPU and no longer has a path
        let mut out: Vec<RawProcess> = mine
            .into_iter()
            .filter(live)
            .map(|k| {
                let (cpu_s, footprint_gb) = cpu_and_footprint(k.pid).unwrap_or((0.0, 0.0));
                RawProcess {
                    pid: k.pid,
                    ppid: k.ppid,
                    start_us: k.start_us,
                    path: path(k.pid),
                    comm: k.comm,
                    cpu_s,
                    footprint_gb,
                }
            })
            .collect();
        let Some(hub) = self.hub.as_deref() else {
            return Ok(out);
        };
        for p in hub.principals() {
            let Principal::Uid(u) = p else { continue };
            if u == uid {
                continue;
            }
            for k in kinfo_of(u).into_iter().filter(live) {
                // listed once its helper has described it (at most one report after it started): until then its
                // arguments are unreadable, and it would match every rule they decide
                let Some(claim) = hub.identity(k.pid, k.start_us) else {
                    continue;
                };
                // a process its helper has not measured yet has used nothing so far
                let usage = hub.usage(k.pid).filter(|x| x.start_us == k.start_us);
                out.push(RawProcess {
                    pid: k.pid,
                    ppid: k.ppid,
                    start_us: k.start_us,
                    path: path(k.pid).or(claim.path),
                    comm: k.comm,
                    cpu_s: usage.map_or(0.0, |x| x.counters.cpu_s),
                    footprint_gb: usage.map_or(0.0, |x| x.footprint_gb),
                });
            }
        }
        Ok(out)
    }

    fn argv(&mut self, pid: i32, start_us: u64) -> Option<Vec<String>> {
        argv(pid).or_else(|| self.hub.as_ref()?.identity(pid, start_us)?.argv)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `sysctl kern.proc` read at the offsets above says what libproc says about this process; its short name keeps
    /// p_comm's 16 characters, where libproc's BSD info keeps 15.
    #[test]
    fn kinfo_proc_agrees_with_libproc() {
        let pid = std::process::id() as i32;
        let b = bsd_info(pid).unwrap();
        let k = kinfo(pid).unwrap();
        assert_eq!(
            (k.pid, k.ppid, k.uid, k.start_us, k.zombie),
            (pid, b.pbi_ppid as i32, b.pbi_uid, start_of(&b), false)
        );
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_str().unwrap();
        assert_eq!(k.comm, name.chars().take(16).collect::<String>());
        // SAFETY: getuid cannot fail.
        let mine = kinfo_of(unsafe { libc::getuid() });
        assert!(mine.contains(&k), "listed by uid too");
        assert!(
            kinfo_of(0).iter().any(|x| x.pid == 1),
            "and any account's: launchd is root's"
        );
        assert_eq!(kinfo(1).unwrap().uid, 0);
    }
}
