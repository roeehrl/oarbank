//! The Windows process table. One `NtQuerySystemInformation(SystemProcessInformation)` call lists every process
//! with its parent, session, times, private working set, hard faults and its threads' scheduling states, without
//! opening any process. The owner's processes are those in people's sessions (1 and up; session 0 holds the
//! services, the agent's system service and its jobs among them). An executable's path comes from
//! `SystemProcessIdInformation`, which needs no handle either; the command line needs a handle with
//! PROCESS_QUERY_LIMITED_INFORMATION, which another account's process denies the agent's service account, so
//! another account's arguments are unreadable to the system service (and count as matching).

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

use crate::procinfo::nt::{self, Process};
use crate::signals::ProcCounters;
use crate::table::{ProcessSource, RawProcess, SigningIdentity, SourceError};

const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const SYSTEM_PROCESS_ID_INFORMATION: u32 = 88;
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const GB: f64 = 1_073_741_824.0;

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    fn NtQueryInformationProcess(
        h: HANDLE,
        class: u32,
        info: *mut c_void,
        len: u32,
        ret: *mut u32,
    ) -> i32;
}

/// The process list now (None: the call failed).
pub fn processes() -> Option<Vec<Process>> {
    let mut len = 1u32 << 20;
    for _ in 0..8 {
        // u64 storage keeps the entries aligned
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let mut ret = 0u32;
        // SAFETY: the buffer holds `len` bytes.
        let st = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION,
                buf.as_mut_ptr().cast(),
                len,
                &mut ret,
            )
        };
        if st == STATUS_INFO_LENGTH_MISMATCH {
            // processes start between the calls: ask for more than the last answer
            len = ret.max(len) + (64 << 10);
            continue;
        }
        if st < 0 {
            return None;
        }
        let bytes = (ret as usize).min(buf.len() * 8);
        // SAFETY: the kernel wrote `ret` bytes at the start of `buf`.
        let b = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), bytes) };
        return Some(nt::parse_processes(b, buf.as_ptr() as usize));
    }
    None
}

/// The drives' devices (`("C:", "\Device\HarddiskVolume3")`).
fn drives() -> Vec<(String, String)> {
    let mut out = vec![];
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let name: Vec<u16> = drive.encode_utf16().chain([0]).collect();
        let mut buf = [0u16; 512];
        // SAFETY: a NUL-terminated name and a buffer of 512 units.
        let n = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n > 0 {
            let end = buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
            out.push((drive, String::from_utf16_lossy(&buf[..end])));
        }
    }
    out
}

/// An executable's kernel path (`\Device\HarddiskVolume3\...`), read without a handle to the process.
fn kernel_image_path(pid: u32) -> Option<String> {
    #[repr(C)]
    struct ProcessIdInformation {
        pid: usize,
        image: UNICODE_STRING,
    }
    let mut buf = vec![0u16; 4096];
    let mut info = ProcessIdInformation {
        pid: pid as usize,
        image: UNICODE_STRING {
            Length: 0,
            MaximumLength: (buf.len() * 2) as u16,
            Buffer: buf.as_mut_ptr(),
        },
    };
    // SAFETY: the structure names a buffer of MaximumLength bytes that outlives the call.
    let st = unsafe {
        NtQuerySystemInformation(
            SYSTEM_PROCESS_ID_INFORMATION,
            (&mut info as *mut ProcessIdInformation).cast(),
            std::mem::size_of::<ProcessIdInformation>() as u32,
            std::ptr::null_mut(),
        )
    };
    (st >= 0).then(|| String::from_utf16_lossy(&buf[..info.image.Length as usize / 2]))
}

/// A process's command line as arguments (None: the process may not be opened, or is gone).
pub fn command_line(pid: u32) -> Option<Vec<String>> {
    // SAFETY: plain call; the handle is closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut out = None;
    let mut len = 1024u32;
    for _ in 0..4 {
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let mut ret = 0u32;
        // SAFETY: a live handle and a buffer of `len` bytes; the result is a UNICODE_STRING pointing into it.
        let st = unsafe {
            NtQueryInformationProcess(
                h,
                PROCESS_COMMAND_LINE_INFORMATION,
                buf.as_mut_ptr().cast(),
                len,
                &mut ret,
            )
        };
        if st == STATUS_INFO_LENGTH_MISMATCH {
            len = ret.max(len * 2);
            continue;
        }
        if st >= 0 {
            // SAFETY: the kernel wrote a UNICODE_STRING whose buffer lies within `buf`.
            let s = unsafe { &*buf.as_ptr().cast::<UNICODE_STRING>() };
            let line = if s.Buffer.is_null() {
                String::new()
            } else {
                // SAFETY: Length bytes at Buffer, inside `buf`.
                String::from_utf16_lossy(unsafe {
                    std::slice::from_raw_parts(s.Buffer, s.Length as usize / 2)
                })
            };
            out = Some(nt::split_command_line(&line));
        }
        break;
    }
    // SAFETY: we own the handle.
    unsafe { CloseHandle(h) };
    out
}

/// The latest process list, shared by the table and the meter (one call a tick), and each process's
/// run-queue wait as estimated from its threads' states: a thread seen waiting for a core at a sample stands for
/// waiting since the previous one (the count at a random instant times the interval is an unbiased estimate of
/// the time spent waiting). Windows keeps no per-thread ready time outside ETW tracing.
#[derive(Default)]
pub struct Snapshots {
    at: Option<Instant>,
    procs: Vec<Process>,
    /// (pid, create time) -> (the sample it was last seen in, estimated seconds waiting so far)
    wait: HashMap<(u32, i64), (Instant, f64)>,
}

impl Snapshots {
    pub fn shared() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }

    /// The process list, taken again when the last one is over half a second old.
    fn fresh(&mut self) -> Option<&[Process]> {
        let now = Instant::now();
        if self
            .at
            .is_none_or(|t| now.duration_since(t).as_secs_f64() >= 0.5)
        {
            self.procs = processes()?;
            self.at = Some(now);
            let mut wait = HashMap::with_capacity(self.procs.len());
            for p in &self.procs {
                let key = (p.pid, p.create_time);
                let acc = match self.wait.get(&key) {
                    Some(&(t, acc)) => {
                        acc + f64::from(p.ready_threads) * now.duration_since(t).as_secs_f64()
                    }
                    None => 0.0,
                };
                wait.insert(key, (now, acc));
            }
            self.wait = wait;
        }
        Some(&self.procs)
    }

    fn counters(&mut self, pid: u32) -> Option<ProcCounters> {
        let p = self.fresh()?.iter().find(|p| p.pid == pid)?.clone();
        let waited = self.wait.get(&(p.pid, p.create_time)).map_or(0.0, |w| w.1);
        Some(ProcCounters {
            cpu_s: p.cpu_s(),
            runnable_s: p.cpu_s() + waited,
            instructions: 0.0,
            cycles: 0.0,
            pageins: f64::from(p.hard_faults),
        })
    }
}

/// Per-process counters from the shared process list: CPU time, the estimated run-queue wait (see
/// [`Snapshots`]) and hard faults as pageins. Windows has no per-process instruction counter, so IPC is unknown.
pub struct ProcessCounters(Arc<Mutex<Snapshots>>);

impl ProcessCounters {
    pub fn new(shared: Arc<Mutex<Snapshots>>) -> Self {
        Self(shared)
    }

    pub fn read(&mut self, pid: i32) -> Option<ProcCounters> {
        let pid = u32::try_from(pid).ok()?;
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .counters(pid)
    }
}

/// The owner's processes (read-only).
pub struct NativeProcessSource {
    shared: Arc<Mutex<Snapshots>>,
    drives: Vec<(String, String)>,
    /// Paths by (pid, create time): a process's executable never changes.
    paths: HashMap<(u32, i64), Option<String>>,
}

impl NativeProcessSource {
    pub fn new(shared: Arc<Mutex<Snapshots>>) -> Self {
        Self {
            shared,
            drives: drives(),
            paths: HashMap::new(),
        }
    }

    fn path(&mut self, pid: u32) -> Option<String> {
        let k = kernel_image_path(pid)?;
        if let Some(p) = nt::dos_path(&k, &self.drives) {
            return Some(p);
        }
        // a drive mapped since the agent started
        self.drives = drives();
        Some(nt::dos_path(&k, &self.drives).unwrap_or(k))
    }
}

impl ProcessSource for NativeProcessSource {
    fn list(&mut self, excluding: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        let procs: Vec<Process> = {
            let mut s = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            s.fresh()
                .ok_or_else(|| SourceError::Unreadable("NtQuerySystemInformation failed".into()))?
                .iter()
                .filter(|p| p.session != 0 && !excluding.contains(&(p.pid as i32)))
                .cloned()
                .collect()
        };
        let mut out = Vec::with_capacity(procs.len());
        let mut seen = HashSet::with_capacity(procs.len());
        for p in procs {
            let Some(start_us) = p.start_us() else {
                continue;
            };
            let key = (p.pid, p.create_time);
            seen.insert(key);
            let path = match self.paths.get(&key) {
                Some(path) => path.clone(),
                None => {
                    let path = self.path(p.pid);
                    self.paths.insert(key, path.clone());
                    path
                }
            };
            out.push(RawProcess {
                pid: p.pid as i32,
                ppid: p.ppid as i32,
                start_us,
                path,
                comm: p.image_name.clone(),
                cpu_s: p.cpu_s(),
                footprint_gb: p.private_ws_bytes as f64 / GB,
            });
        }
        self.paths.retain(|k, _| seen.contains(k));
        Ok(out)
    }

    fn argv(&mut self, pid: i32) -> Option<Vec<String>> {
        command_line(u32::try_from(pid).ok()?)
    }

    /// Authenticode is not a code-signing identity rules match on (they are refused here).
    fn signing(&mut self, _: i32) -> SigningIdentity {
        SigningIdentity::default()
    }

    fn satisfies(&mut self, _: i32, _: &str) -> bool {
        false
    }

    fn bundle_id(&mut self, _: &str) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::procinfo::nt::offsets;
    use std::mem::offset_of;
    use windows_sys::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION as Spi;

    /// The offsets the parser reads agree with the SDK's declaration where it names the field.
    #[test]
    fn the_parser_offsets_match_the_sdk() {
        assert_eq!(offset_of!(Spi, NextEntryOffset), offsets::NEXT_ENTRY);
        assert_eq!(offset_of!(Spi, NumberOfThreads), offsets::NUMBER_OF_THREADS);
        assert_eq!(offset_of!(Spi, ImageName), offsets::IMAGE_NAME);
        assert_eq!(offset_of!(Spi, UniqueProcessId), offsets::PROCESS_ID);
        assert_eq!(offset_of!(Spi, SessionId), offsets::SESSION_ID);
        assert_eq!(std::mem::size_of::<Spi>(), offsets::PROCESS_SIZE);
    }
}
