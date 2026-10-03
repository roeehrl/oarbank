//! The Linux backend. So far only the GPU meter: the process table is not written yet (rules match nothing
//! here), and the agent acts through its own process containers.

mod gpu;

use std::time::Instant;

pub use gpu::{gpu_times, process_gpu};

use crate::gpu::{drm, GpuTimes};
use crate::signals::{Meter, ProcCounters};

/// GPU time from DRM `fdinfo`; no per-process counters and no frontmost app yet (both unknown).
#[derive(Debug, Default)]
pub struct NativeMeter {
    drm: drm::Usage,
    last: Option<Instant>,
}

impl NativeMeter {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Meter for NativeMeter {
    fn proc_counters(&mut self, _: i32) -> Option<ProcCounters> {
        None
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        let now = Instant::now();
        let seconds = self.last.map(|t| now.duration_since(t).as_secs_f64());
        let t = gpu_times(&mut self.drm, seconds)?;
        self.last = Some(now);
        Some(t)
    }
    fn frontmost_pid(&mut self) -> Option<i32> {
        None
    }
}
