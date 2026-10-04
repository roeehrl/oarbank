//! The session helpers' transport on Linux and macOS: a Unix socket the system service binds, open to every local
//! account, whose peer credentials name the account that sent each report (`SO_PEERCRED` on Linux, `getpeereid`
//! on macOS). The platforms say what a helper reads and how the service checks that a process is the account's.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::session::{Principal, Report, SessionHub, INTERVAL, MAX_LINE};

/// Where the system service listens: `OARBANK_SESSION_SOCKET`, else the platform's place.
pub(super) fn socket_path(default: &str) -> PathBuf {
    std::env::var_os("OARBANK_SESSION_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

/// The connected peer's effective uid.
#[cfg(target_os = "linux")]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a connected socket and an out-buffer of the size given.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0).then_some(cred.uid)
}

/// The connected peer's effective uid.
#[cfg(target_os = "macos")]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: a connected socket and two out-pointers.
    let rc = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

/// Serve helpers (the system service): bind the socket at `path`, open to every local account (the peer's uid
/// says who it is), and take their reports on a thread each. `owns(uid, pid, start_us)`: does the process belong
/// to that account (and, unless `start_us` is 0, did it start then)?
pub(super) fn serve(
    path: &Path,
    hub: Arc<SessionHub>,
    owns: fn(u32, i32, u64) -> bool,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    std::thread::Builder::new()
        .name("session-hub".into())
        .spawn(move || {
            for s in l.incoming().flatten() {
                let hub = hub.clone();
                let _ = std::thread::Builder::new()
                    .name("session-helper".into())
                    .spawn(move || take_reports(&hub, s, owns));
            }
        })?;
    Ok(())
}

fn take_reports(hub: &SessionHub, s: UnixStream, owns: fn(u32, i32, u64) -> bool) {
    let Some(uid) = peer_uid(&s) else { return };
    let who = Principal::Uid(uid);
    let mut r = BufReader::new(s);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut r).take(MAX_LINE as u64).read_line(&mut line) {
            Ok(n) if n > 0 && line.ends_with('\n') => {}
            _ => break,
        }
        if let Ok(report) = serde_json::from_str::<Report>(&line) {
            hub.accept(who, report, |pid, start| owns(uid, pid, start));
        }
    }
    hub.gone(who);
}

/// The helper: send `report(first)` to the service at `path` every interval (`first`: the connection is new, so
/// the service knows none of the account's processes yet), connecting again every interval while it is not there.
pub(super) fn run_helper(path: &Path, mut report: impl FnMut(bool) -> Report) -> ! {
    loop {
        if let Ok(mut s) = UnixStream::connect(path) {
            let mut first = true;
            loop {
                let mut line = serde_json::to_string(&report(first)).unwrap_or_default();
                line.push('\n');
                if s.write_all(line.as_bytes()).is_err() {
                    break;
                }
                first = false;
                std::thread::sleep(INTERVAL);
            }
        }
        std::thread::sleep(INTERVAL);
    }
}
