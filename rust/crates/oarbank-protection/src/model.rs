//! A process as protection sees it, and one sample of a rule's matched group.

use std::collections::BTreeSet;
use std::fmt;

/// A process. Identity is (pid, start time): PIDs are reused, so every cached fact and every actuation is
/// keyed by both.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessRecord {
    pub pid: i32,
    pub ppid: i32,
    /// Start time in microseconds since the epoch.
    pub start_us: u64,
    pub path: String,
    /// The kernel's short name (p_comm, 16 characters on macOS); empty means "the path's last component".
    pub comm: String,
    pub argv: Option<Vec<String>>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub bundle_id: Option<String>,
    /// Satisfied code-signing requirement strings (evaluated lazily by the live table).
    pub requirements_met: BTreeSet<String>,
    /// Cumulative CPU time (user + system), seconds.
    pub cpu_s: f64,
    /// Physical footprint (includes GPU allocations in unified memory), GB.
    pub footprint_gb: f64,
}

impl ProcessRecord {
    pub fn new(pid: i32, ppid: i32, start_us: u64, path: &str) -> Self {
        Self {
            pid,
            ppid,
            start_us,
            path: path.to_string(),
            ..Self::default()
        }
    }

    pub fn key(&self) -> ProcessKey {
        ProcessKey {
            pid: self.pid,
            start_us: self.start_us,
        }
    }

    /// The name a `name` matcher compares: p_comm, or the path's last component when there is none.
    pub fn effective_comm(&self) -> &str {
        if self.comm.is_empty() {
            self.path.rsplit('/').next().unwrap_or("")
        } else {
            &self.comm
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessKey {
    pub pid: i32,
    pub start_us: u64,
}

impl ProcessKey {
    pub fn new(pid: i32, start_us: u64) -> Self {
        Self { pid, start_us }
    }
}

impl fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.pid, self.start_us)
    }
}

/// One sample of a rule's matched group.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GroupSample {
    pub t: f64,
    pub cpu_cores: f64,
    pub footprint_gb: f64,
    pub count: usize,
}

impl GroupSample {
    pub fn new(t: f64, cpu_cores: f64, footprint_gb: f64, count: usize) -> Self {
        Self {
            t,
            cpu_cores,
            footprint_gb,
            count,
        }
    }
}
