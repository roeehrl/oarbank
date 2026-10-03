//! The Linux process table from procfs. The owner's processes are those of the agent's own account and of every
//! person logged in (logind's user sessions). Any account may read another's `stat`, `status`, `cmdline` and
//! `schedstat`; the executable link (and the open files the GPU meter reads) need ptrace access to the process,
//! so another account's executable path is unreadable to the system service, and counts as matching.

use std::collections::HashSet;
use std::time::Instant;

use super::logind;
use crate::presence::logind::people;
use crate::procinfo::procfs::{self, Reader};
use crate::signals::ProcCounters;
use crate::table::{ProcessSource, RawProcess, SigningIdentity, SourceError};

/// procfs on this machine.
pub fn reader() -> Reader {
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    Reader::new("/proc", u64::try_from(hz).unwrap_or(100))
}

/// When a process started, in microseconds since the epoch (None: gone).
pub fn start_time_us(pid: i32) -> Option<u64> {
    reader().start_time_us(pid)
}

/// The accounts whose processes are the owner's: the agent's own and every logged-in person's.
pub fn owner_uids() -> HashSet<u32> {
    // SAFETY: getuid cannot fail.
    let mut uids = HashSet::from([unsafe { libc::getuid() }]);
    if let Some(s) = logind::sessions() {
        uids.extend(people(&s).map(|s| s.uid));
    }
    uids
}

/// The owner's processes (read-only).
#[derive(Debug)]
pub struct NativeProcessSource {
    reader: Reader,
}

impl NativeProcessSource {
    pub fn new() -> Self {
        Self { reader: reader() }
    }
}

impl Default for NativeProcessSource {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessSource for NativeProcessSource {
    fn list(&mut self, excluding: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        let owners = owner_uids();
        let entries = self
            .reader
            .list(|uid| owners.contains(&uid), excluding)
            .ok_or_else(|| SourceError::Unreadable("/proc cannot be listed".into()))?;
        Ok(entries
            .into_iter()
            .map(|e| RawProcess {
                pid: e.pid,
                ppid: e.ppid,
                start_us: e.start_us,
                path: e.path,
                comm: e.comm,
                cpu_s: e.cpu_s,
                footprint_gb: e.footprint_gb,
            })
            .collect())
    }

    fn argv(&mut self, pid: i32) -> Option<Vec<String>> {
        self.reader.cmdline(pid)
    }

    /// Linux executables carry no code-signing identity (rules that match on one are refused here).
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

/// Per-process scheduler counters (see [`procfs::Counters`]).
#[derive(Debug)]
pub struct ProcessCounters {
    reader: Reader,
    counters: procfs::Counters,
    t0: Instant,
}

impl ProcessCounters {
    pub fn new() -> Self {
        Self {
            reader: reader(),
            counters: procfs::Counters::new(),
            t0: Instant::now(),
        }
    }

    pub fn read(&mut self, pid: i32) -> Option<ProcCounters> {
        let stat = self.reader.stat(pid)?;
        let threads = self.reader.threads(pid)?;
        Some(self.counters.fold(
            pid,
            stat.starttime,
            threads,
            stat.majflt,
            self.t0.elapsed().as_secs_f64(),
        ))
    }
}

impl Default for ProcessCounters {
    fn default() -> Self {
        Self::new()
    }
}
