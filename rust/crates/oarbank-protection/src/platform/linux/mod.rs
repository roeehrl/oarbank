//! The Linux backend: the process table and per-process scheduler counters from procfs, GPU time from DRM
//! `fdinfo` and NVML, presence and the session in front from systemd-logind, and an X11 session's front window from its
//! X server. The agent acts through its own process containers (cgroup leaves).

mod front;
mod gpu;
mod logind;
mod procs;
mod session;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

pub use front::{x11_front, FrontReader};
pub use gpu::{gpu_times, nvml, process_gpu};
pub use logind::{sessions, NativePresence};
pub use procs::{owner_uids, reader, start_time_us, NativeProcessSource, ProcessCounters};
pub use session::{run_helper, serve, socket_path};

use crate::gpu::{GpuTimes, LinuxGpu};
use crate::session::SessionHub;
use crate::signals::{FrontReading, Meter, ProcCounters};

/// Scheduler counters from procfs, GPU time from DRM `fdinfo` and NVML (another account's from its session helper),
/// and the front app.
pub struct NativeMeter {
    counters: ProcessCounters,
    front: FrontReader,
    hub: Option<Arc<SessionHub>>,
    gpu: LinuxGpu,
    last: Option<Instant>,
    /// GPU time accumulated from session helpers' busy fractions, for the processes whose files only their own
    /// account may read.
    helped: HashMap<i32, f64>,
}

impl NativeMeter {
    pub fn new(hub: Option<Arc<SessionHub>>) -> Self {
        Self {
            counters: ProcessCounters::new(),
            front: FrontReader::new(hub.clone()),
            hub,
            gpu: gpu::reader(),
            last: None,
            helped: HashMap::new(),
        }
    }
}

impl Meter for NativeMeter {
    fn proc_counters(&mut self, pid: i32) -> Option<ProcCounters> {
        self.counters.read(pid)
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        let now = Instant::now();
        let seconds = self.last.map(|t| now.duration_since(t).as_secs_f64());
        let mut t = gpu_times(&mut self.gpu, seconds)?;
        self.last = Some(now);
        // a process whose files the agent may not read, whose helper reads them: its busy fraction, accumulated
        // over this reading's interval (the first reading has no interval, so it stays unknown)
        if let (Some(hub), Some(dt)) = (&self.hub, seconds) {
            let helped: Vec<(i32, f64)> = t
                .unknown
                .iter()
                .filter_map(|&pid| Some((pid, hub.gpu_busy(pid)??)))
                .collect();
            for (pid, busy) in helped {
                let ns = self.helped.entry(pid).or_insert(0.0);
                *ns += busy * dt * 1e9;
                t.ns.insert(pid, *ns);
                t.unknown.remove(&pid);
            }
            self.helped.retain(|pid, _| t.ns.contains_key(pid));
        }
        Some(t)
    }
    fn front(&mut self) -> FrontReading {
        self.front.read(sessions().as_deref().map(Vec::as_slice))
    }
}
