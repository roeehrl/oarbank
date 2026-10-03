//! The Linux backend: the process table and per-process scheduler counters from procfs, GPU time from DRM
//! `fdinfo`, and presence from systemd-logind. The agent acts through its own process containers (cgroup leaves).

mod gpu;
mod logind;
mod procs;

use std::time::Instant;

pub use gpu::{gpu_times, process_gpu};
pub use logind::{sessions, NativePresence};
pub use procs::{owner_uids, reader, start_time_us, NativeProcessSource, ProcessCounters};

use crate::gpu::{drm, GpuTimes};
use crate::signals::{Front, Meter, ProcCounters};

/// Scheduler counters from procfs and GPU time from DRM `fdinfo`.
#[derive(Debug, Default)]
pub struct NativeMeter {
    counters: ProcessCounters,
    drm: drm::Usage,
    last: Option<Instant>,
}

impl NativeMeter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Meter for NativeMeter {
    fn proc_counters(&mut self, pid: i32) -> Option<ProcCounters> {
        self.counters.read(pid)
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        let now = Instant::now();
        let seconds = self.last.map(|t| now.duration_since(t).as_secs_f64());
        let t = gpu_times(&mut self.drm, seconds)?;
        self.last = Some(now);
        Some(t)
    }
    fn front(&mut self) -> Front {
        Front::Unknown
    }
}
