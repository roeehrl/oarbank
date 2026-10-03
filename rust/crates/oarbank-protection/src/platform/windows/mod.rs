//! The Windows backend: the process table and per-process counters from the native process list, GPU time from
//! the GPU Engine performance counters, presence and the session in front from the sessions WTS lists, and the
//! foreground window in the agent's own session. The agent acts through its own process containers (Job Objects).

mod front;
mod pdh;
mod presence;
mod procs;

use std::sync::{Arc, Mutex};

pub use front::{front, own_front};
pub use pdh::{RawCounter, GPU_ENGINE_RUNNING_TIME};
pub use presence::{own_idle_s, own_session, sessions, NativePresence};
pub use procs::{command_line, processes, NativeProcessSource, ProcessCounters, Snapshots};

use crate::gpu::{self, GpuTimes};
use crate::signals::{FrontReading, Meter, ProcCounters};

/// Counters from the native process list (shared with the table), GPU time from the GPU Engine performance
/// counters, and the front app.
pub struct NativeMeter {
    counters: ProcessCounters,
    gpu: Option<RawCounter>,
}

impl NativeMeter {
    pub fn new(shared: Arc<Mutex<Snapshots>>) -> Self {
        Self {
            counters: ProcessCounters::new(shared),
            gpu: None,
        }
    }
}

impl Meter for NativeMeter {
    fn proc_counters(&mut self, pid: i32) -> Option<ProcCounters> {
        self.counters.read(pid)
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
        front()
    }
}
