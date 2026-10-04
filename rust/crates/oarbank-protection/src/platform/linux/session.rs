//! The session helper on Linux. Each person's systemd user manager runs it (a global user unit the system
//! install enables); it reports to the system service over the Unix socket `/run/oarbank/session.sock` (in the
//! service's runtime directory; `OARBANK_SESSION_SOCKET` overrides it), whose peer credentials name the account.
//! It tells what the system service may not read: its processes' executable paths (and arguments), their GPU
//! use, and the front window of the person's X11 display.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use super::front::FrontReader;
use super::gpu::process_gpu;
use super::{logind, reader};
use crate::gpu::{drm, GpuBusy};
use crate::platform::unix_session;
use crate::session::{Described, FrontClaim, ProcClaim, Report, SessionHub, PROTOCOL};

/// Where the system service listens.
pub fn socket_path() -> PathBuf {
    unix_session::socket_path("/run/oarbank/session.sock")
}

/// Does the process belong to `uid` (and, unless `start_us` is 0, did it start then)?
fn owns(uid: u32, pid: i32, start_us: u64) -> bool {
    let r = reader();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| crate::procinfo::procfs::parse_status(&s));
    status.is_some_and(|s| s.uid == uid)
        && (start_us == 0 || r.start_time_us(pid) == Some(start_us))
}

/// Serve helpers (the system service).
pub fn serve(hub: Arc<SessionHub>) -> std::io::Result<()> {
    unix_session::serve(&socket_path(), hub, owns)
}

/// What this account's helper reads each interval.
struct Collector {
    uid: u32,
    described: Described,
    front: FrontReader,
    drm: drm::Usage,
    gpu: Option<(Instant, crate::gpu::GpuTimes)>,
}

impl Collector {
    fn report(&mut self, first: bool) -> Report {
        if first {
            self.described = Described::default();
        }
        let r = reader();
        let mine = r
            .list(|u| u == self.uid, &Default::default())
            .unwrap_or_default();
        let live: Vec<(i32, u64)> = mine.iter().map(|e| (e.pid, e.start_us)).collect();
        self.described.retain_live(&live);
        let procs = mine
            .iter()
            .filter(|e| self.described.is_new((e.pid, e.start_us)))
            .map(|e| ProcClaim {
                pid: e.pid,
                start_us: e.start_us,
                path: e.path.clone(),
                argv: r.cmdline(e.pid),
            })
            .collect();
        // the front window, when the session in front is this account's
        let sessions = logind::sessions();
        let front = sessions
            .as_deref()
            .and_then(|s| {
                crate::presence::logind::front_session(s)
                    .filter(|f| f.uid == self.uid)
                    .map(|_| s)
            })
            .map(|s| FrontClaim::of(&self.front.read(Some(s))));
        // GPU use from the open files only this account may read
        let now = Instant::now();
        let held: Vec<(i32, drm::ProcessGpu)> = mine
            .iter()
            .filter_map(|e| Some((e.pid, process_gpu(e.pid)?)))
            .collect();
        let seconds = self
            .gpu
            .as_ref()
            .map(|(t, _)| now.duration_since(*t).as_secs_f64());
        let cur = self.drm.fold(held, seconds);
        let busy = self.gpu.as_ref().and_then(|(t, prev)| {
            GpuBusy::between(prev, &cur, now.duration_since(*t).as_secs_f64())
        });
        self.gpu = Some((now, cur));
        let (gpu_busy, gpu_unknown) = busy.map_or((HashMap::new(), vec![]), |b| {
            (b.by_pid, b.unknown.into_iter().collect())
        });
        Report {
            v: PROTOCOL,
            live,
            procs,
            idle_s: None,
            front,
            gpu_busy,
            gpu_unknown,
            usage: vec![],
        }
    }
}

/// The helper: report this account's processes and display to the system service every interval. Never returns.
pub fn run_helper() -> ! {
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    let mut c = Collector {
        uid,
        described: Described::default(),
        front: FrontReader::new(None),
        drm: drm::Usage::default(),
        gpu: None,
    };
    unix_session::run_helper(&socket_path(), |first| c.report(first))
}
