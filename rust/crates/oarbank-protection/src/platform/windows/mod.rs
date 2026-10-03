//! The Windows backend. So far only the GPU meter: the process table is not written yet (rules match nothing
//! here), and the agent acts through its own process containers.

mod pdh;
mod presence;

pub use pdh::{RawCounter, GPU_ENGINE_RUNNING_TIME};
pub use presence::{own_idle_s, own_session, sessions, NativePresence};

use crate::gpu::{self, GpuTimes};
use crate::signals::{Front, FrontReading, Meter, ProcCounters};

/// GPU time from the GPU Engine performance counters; no per-process counters and no frontmost app yet (both
/// unknown).
#[derive(Default)]
pub struct NativeMeter {
    gpu: Option<RawCounter>,
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
        if self.gpu.is_none() {
            self.gpu = RawCounter::open(GPU_ENGINE_RUNNING_TIME);
        }
        let items = self.gpu.as_mut()?.collect()?;
        Some(gpu::pdh::by_pid(
            items.iter().map(|(n, v)| (n.as_str(), *v)),
        ))
    }
    fn front(&mut self) -> FrontReading {
        FrontReading::new(Front::Unknown, "unknown: not read on Windows yet")
    }
}
