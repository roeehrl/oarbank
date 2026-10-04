//! The macOS backend.

mod cf;
mod gpu;
mod iokit;
mod presence;
mod procs;
mod security;
mod session;

use std::process::{Command, Stdio};
use std::sync::Arc;

pub use gpu::{creator_pid, gpu_time_by_pid};
pub use presence::{hid_idle_s, screen_sharing, NativePresence};
pub use procs::{
    all_pids, argv, bundle_id_for_path, cpu_and_footprint, kinfo, kinfo_of, path, pids_in_group,
    proc_counters, start_time_us, usage, KinfoProc, NativeProcessSource,
};
pub use security::{satisfies, signing};
pub use session::{console_uid, run_helper, serve, socket_path};

use crate::gpu::GpuTimes;
use crate::session::{Principal, SessionHub};
use crate::signals::{frontmost, Front, FrontReading, Meter, ProcCounters};
use crate::spawn_registry::{Actuator, Signal};

/// rusage V6 counters, AGX GPU time and the frontmost app; in the system service (`hub`) another account's
/// counters and the console's front app come from that account's session helper.
#[derive(Debug, Default)]
pub struct NativeMeter {
    hub: Option<Arc<SessionHub>>,
}

impl NativeMeter {
    pub fn new(hub: Option<Arc<SessionHub>>) -> Self {
        Self { hub }
    }
}

impl Meter for NativeMeter {
    fn proc_counters(&mut self, pid: i32) -> Option<ProcCounters> {
        proc_counters(pid).or_else(|| {
            let u = self.hub.as_ref()?.usage(pid)?;
            (kinfo(pid)?.start_us == u.start_us).then_some(u.counters)
        })
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        gpu_time_by_pid().map(GpuTimes::known)
    }
    /// The personal scope asks `lsappinfo` in its own session. The system service runs in no one's: the console's
    /// account's helper tells it.
    fn front(&mut self) -> FrontReading {
        let Some(hub) = &self.hub else {
            return lsappinfo_front();
        };
        match console_uid() {
            None => FrontReading::new(Front::Nothing, "the login window is on the screen"),
            Some(uid) => hub.front(Principal::Uid(uid)).unwrap_or_else(|| {
                FrontReading::new(
                    Front::Unknown,
                    format!(
                        "unknown: no session helper reports for the console's account (uid {uid})"
                    ),
                )
            }),
        }
    }
}

/// What is in front of this account's GUI session, from `lsappinfo`.
pub fn lsappinfo_front() -> FrontReading {
    match frontmost_pid() {
        Some(pid) => FrontReading::new(Front::App(pid), "lsappinfo"),
        None => FrontReading::new(Front::Unknown, "unknown: lsappinfo names no front app"),
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
