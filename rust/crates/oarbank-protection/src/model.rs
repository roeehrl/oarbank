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
    /// The executable's path; None: not readable (another account's process the agent may not inspect).
    pub path: Option<String>,
    /// The kernel's short name (p_comm on macOS, 16 characters; comm on Linux, 15; the image file name on
    /// Windows); empty means "the path's last component".
    pub comm: String,
    /// The arguments; None: not resolved (no rule needs them) or not readable.
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
    /// A process whose path and arguments are readable, with no arguments (callers set the rest).
    pub fn new(pid: i32, ppid: i32, start_us: u64, path: &str) -> Self {
        Self {
            pid,
            ppid,
            start_us,
            path: Some(path.to_string()),
            argv: Some(vec![]),
            ..Self::default()
        }
    }

    pub fn key(&self) -> ProcessKey {
        ProcessKey {
            pid: self.pid,
            start_us: self.start_us,
        }
    }

    /// The name a `name` matcher compares: the kernel's short name, or the path's last component when there is
    /// none (None: neither is known).
    pub fn effective_comm(&self) -> Option<&str> {
        if self.comm.is_empty() {
            self.path.as_deref().and_then(|p| p.rsplit('/').next())
        } else {
            Some(&self.comm)
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
