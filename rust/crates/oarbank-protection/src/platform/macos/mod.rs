//! The macOS backend.

mod cf;
mod gpu;
mod iokit;
mod presence;
mod procs;
mod security;

use std::process::{Command, Stdio};

pub use gpu::{creator_pid, gpu_time_by_pid};
pub use presence::{hid_idle_s, screen_sharing, NativePresence};
pub use procs::{
    all_pids, argv, bundle_id_for_path, cpu_and_footprint, path, pids_in_group, proc_counters,
    start_time_us, NativeProcessSource,
};
pub use security::{satisfies, signing};

use crate::gpu::GpuTimes;
use crate::signals::{frontmost, Front, FrontReading, Meter, ProcCounters};
use crate::spawn_registry::{Actuator, Signal};

/// rusage V6 counters, AGX GPU time and the frontmost app.
#[derive(Debug, Default)]
pub struct NativeMeter;

impl NativeMeter {
    pub fn new() -> Self {
        Self
    }
}

impl Meter for NativeMeter {
    fn proc_counters(&mut self, pid: i32) -> Option<ProcCounters> {
        proc_counters(pid)
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        gpu_time_by_pid().map(GpuTimes::known)
    }
    fn front(&mut self) -> FrontReading {
        match frontmost_pid() {
            Some(pid) => FrontReading::new(Front::App(pid), "lsappinfo"),
            None => FrontReading::new(Front::Unknown, "unknown: lsappinfo names no front app"),
        }
    }
}

/// Runs `/usr/bin/lsappinfo` (works from a LaunchAgent in the user's session and over ssh; no AppKit link).
pub fn lsappinfo(args: &[&str]) -> Option<String> {
    let out = Command::new("/usr/bin/lsappinfo")
        .args(args)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The frontmost application's pid (None: unknown).
pub fn frontmost_pid() -> Option<i32> {
    let asn = lsappinfo(&["front"]).and_then(|s| frontmost::serial_number(&s))?;
    frontmost::parse_pid(&lsappinfo(&["info", "-only", "pid", &asn])?)
}

/// Signals and Darwin-background scheduling. Crate-private: reachable only through the spawn registry.
pub(crate) struct NativeActuator;

impl Actuator for NativeActuator {
    fn start_time(&self, pid: i32) -> Option<u64> {
        start_time_us(pid)
    }

    fn signal_group(&self, pgid: i32, sig: Signal) -> i32 {
        // SAFETY: plain syscall; the registry verified (pid, start time) just before.
        unsafe { libc::killpg(pgid, sig.raw()) }
    }

    /// Darwin background QoS (low priority, efficiency cores) for the leader and every member of its group; a
    /// member that exited meanwhile is no failure.
    fn set_background(&self, pgid: i32, on: bool) -> i32 {
        let prio = if on { libc::PRIO_DARWIN_BG } else { 0 };
        let mut members = pids_in_group(pgid);
        if !members.contains(&pgid) {
            members.push(pgid);
        }
        let mut rc = 0;
        for pid in members {
            // SAFETY: plain syscall on a member of a group the registry verified.
            let r =
                unsafe { libc::setpriority(libc::PRIO_DARWIN_PROCESS, pid as libc::id_t, prio) };
            if r != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                rc = r;
            }
        }
        rc
    }
}
