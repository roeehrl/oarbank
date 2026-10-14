//! The Linux process table from procfs. The owner's processes are those of the agent's own account and of every
//! person logged in (logind's user sessions) or reporting through a session helper. Any account may read
//! another's `stat`, `status`, `cmdline` and `schedstat`; the executable link (and the open files the GPU meter
//! reads) need ptrace access to the process, so the system service takes another account's executable paths from
//! that account's session helper, and without one they are unreadable (and count as matching). A person's account
//! stays the owner's when its session is not in front, when its helper has gone, and (logind unreadable) always.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use super::logind;
use crate::procinfo::procfs::{self, Owners, Reader};
use crate::session::{Principal, SessionHub};
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

/// The accounts whose processes are the owner's ([`Owners::new`]).
pub fn owners(hub: Option<&SessionHub>) -> Owners {
    let sessions = logind::sessions();
    let helpers = hub.map(SessionHub::known).unwrap_or_default().into_iter().filter_map(|p| match p {
        Principal::Uid(u) => Some(u),
        Principal::Session(_) => None,
    });
    // SAFETY: getuid cannot fail.
    Owners::new(unsafe { libc::getuid() }, sessions.as_deref().map(|s| s.as_slice()), helpers)
}

/// The owner's processes (read-only).
pub struct NativeProcessSource {
    reader: Reader,
    hub: Option<Arc<SessionHub>>,
}

impl NativeProcessSource {
    pub fn new(hub: Option<Arc<SessionHub>>) -> Self {
        Self {
            reader: reader(),
            hub,
        }
    }
}

impl ProcessSource for NativeProcessSource {
    fn list(&mut self, excluding: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        let owners = owners(self.hub.as_deref());
        let entries = self
            .reader
            .list(|uid| owners.contains(uid), excluding)
            .ok_or_else(|| SourceError::Unreadable("/proc cannot be listed".into()))?;
        let hub = self.hub.as_deref();
        let helped: HashSet<u32> = hub
            .map(SessionHub::principals)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|p| match p {
                Principal::Uid(u) => Some(u),
                Principal::Session(_) => None,
            })
            .collect();
        // SAFETY: getuid cannot fail.
        let own = unsafe { libc::getuid() };
        Ok(entries
            .into_iter()
            // a process whose path only its account's helper may read is listed once the helper has described it
            // (at most one report after it started): until then it would match every rule its path decides
            .filter(|e| {
                e.path.is_some()
                    || !helped.contains(&e.uid)
                    || hub.is_some_and(|h| h.identity(e.pid, e.start_us).is_some())
            })
            .map(|e| RawProcess {
                pid: e.pid,
                ppid: e.ppid,
                start_us: e.start_us,
                path: e.path.or_else(|| hub?.identity(e.pid, e.start_us)?.path),
                comm: e.comm,
                cpu_s: e.cpu_s,
                footprint_gb: e.footprint_gb,
                // another account's with no helper reporting: its path is unreadable (and matches); use is read here
                without_helper: e.uid != own && !helped.contains(&e.uid),
                usage_unread: false,
            })
            .collect())
    }

    fn argv(&mut self, pid: i32, start_us: u64) -> Option<Vec<String>> {
        self.reader
            .cmdline(pid)
            .or_else(|| self.hub.as_ref()?.identity(pid, start_us)?.argv)
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
