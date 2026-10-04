//! The session helper on macOS. A LaunchAgent the system install puts in /Library/LaunchAgents runs it in every
//! GUI login (launchd starts it in each Aqua session); it reports to the system service over the Unix socket
//! `/Library/Application Support/Oarbank/run/session.sock` (a directory the install gives the service's account;
//! `OARBANK_SESSION_SOCKET` overrides it), whose peer credentials name the account. It tells what only the account
//! may read: its processes' arguments, CPU time, footprint and scheduler counters (rusage), and the app in front of
//! its GUI session. The service reads the rest itself: every account's processes and their paths, code-signing
//! identity, GPU time (the IORegistry) and the time since the last input (the HID system's, whoever gave it).

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;

use super::lsappinfo_front;
use super::procs::{argv, kinfo, kinfo_of, path, usage};
use crate::platform::unix_session;
use crate::session::{Described, FrontClaim, ProcClaim, Report, SessionHub, Usage, PROTOCOL};

/// Where the system service listens. The launcher's system install creates the directory for the service's
/// account (svc_launchd.rs).
pub fn socket_path() -> PathBuf {
    unix_session::socket_path("/Library/Application Support/Oarbank/run/session.sock")
}

/// Does the process belong to `uid` (and, unless `start_us` is 0, did it start then)?
fn owns(uid: u32, pid: i32, start_us: u64) -> bool {
    kinfo(pid)
        .is_some_and(|k| k.uid == uid && !k.zombie && (start_us == 0 || k.start_us == start_us))
}

/// Serve helpers (the system service).
pub fn serve(hub: Arc<SessionHub>) -> std::io::Result<()> {
    unix_session::serve(&socket_path(), hub, owns)
}

/// The account whose GUI session is on the screen (the owner of `/dev/console`); None at the login window.
pub fn console_uid() -> Option<u32> {
    std::fs::metadata("/dev/console")
        .ok()
        .map(|m| m.uid())
        .filter(|&u| u != 0)
}

/// What this account's helper reads each interval.
struct Collector {
    uid: u32,
    described: Described,
}

impl Collector {
    fn report(&mut self, first: bool) -> Report {
        if first {
            self.described = Described::default();
        }
        let mine: Vec<_> = kinfo_of(self.uid)
            .into_iter()
            .filter(|k| !k.zombie)
            .collect();
        let live: Vec<(i32, u64)> = mine.iter().map(|k| (k.pid, k.start_us)).collect();
        self.described.retain_live(&live);
        let procs = mine
            .iter()
            .filter(|k| self.described.is_new((k.pid, k.start_us)))
            .map(|k| ProcClaim {
                pid: k.pid,
                start_us: k.start_us,
                path: path(k.pid),
                argv: argv(k.pid),
            })
            .collect();
        let usage = mine
            .iter()
            .filter_map(|k| {
                let (counters, footprint_gb) = usage(k.pid)?;
                Some(Usage {
                    pid: k.pid,
                    start_us: k.start_us,
                    counters,
                    footprint_gb,
                })
            })
            .collect();
        Report {
            v: PROTOCOL,
            live,
            procs,
            front: Some(FrontClaim::of(&lsappinfo_front())),
            usage,
            ..Report::default()
        }
    }
}

/// The helper: report this account's processes and front app to the system service every interval. Never returns.
pub fn run_helper() -> ! {
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut c = Collector {
        uid,
        described: Described::default(),
    };
    unix_session::run_helper(&socket_path(), |first| c.report(first))
}
