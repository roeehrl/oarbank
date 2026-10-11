//! The session helpers' transport on Linux and macOS: a Unix socket the system service binds, open to every local
//! account, whose peer credentials name the account that sent each report (`SO_PEERCRED` on Linux, `getpeereid`
//! on macOS). The platforms say what a helper reads and how the service checks that a process is the account's.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::relay::Relay;
use crate::session::{Principal, Report, SessionHub, Watch, INTERVAL, MAX_LINE, PROTOCOL};

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

fn take_reports(hub: &Arc<SessionHub>, s: UnixStream, owns: fn(u32, i32, u64) -> bool) {
    let Some(uid) = peer_uid(&s) else { return };
    let who = Principal::Uid(uid);
    hub.set_account(who, crate::sources::account_of(uid));
    // one writer for what the service sends this person's helper: the owner sources to read (`Watch` lines) and
    // requests to act on a delegated process of this person (`act` lines)
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    if let Ok(w) = s.try_clone() {
        let w = Arc::new(std::sync::Mutex::new(w));
        let relay_w = w.clone();
        hub.register_relay(who, move |line: &str| {
            relay_w.lock().map(|mut w| w.write_all(line.as_bytes()).is_ok()).unwrap_or(false)
        });
        // the owner sources this person's helper should read: sent now and whenever the list changes
        let hub = hub.clone();
        let alive = alive.clone();
        let _ = std::thread::Builder::new().name("session-watch".into()).spawn(move || {
            let mut seen = u64::MAX;
            while alive.load(std::sync::atomic::Ordering::Relaxed) {
                let gen = hub.wanted_after(seen, INTERVAL * 5);
                if gen != seen {
                    seen = gen;
                    let mut line = serde_json::to_string(&Watch { v: PROTOCOL, watch: hub.asked(who) })
                        .unwrap_or_default();
                    line.push('\n');
                    if w.lock().map(|mut w| w.write_all(line.as_bytes()).is_err()).unwrap_or(true) {
                        return;
                    }
                }
            }
        });
    }
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
    alive.store(false, std::sync::atomic::Ordering::Relaxed);
    hub.gone(who);
}

/// The helper: send `report(first)` to the service at `path` every interval (`first`: the connection is new, so
/// the service knows none of the account's processes yet), connecting again every interval while it is not there.
/// It also reads the owner sources the service names (`Watch` lines on the same connection) and reports at once
/// when one of their phases changes.
pub(super) fn run_helper(path: &Path, mut report: impl FnMut(bool) -> Report) -> ! {
    let relay = Relay::own();
    loop {
        if let Ok(mut s) = UnixStream::connect(path) {
            // what the service sends on the same connection: the owner sources to read (`Watch`) and requests to
            // act on this person's delegated processes (`act`)
            if let Ok(r) = s.try_clone() {
                let relay = relay.clone();
                let _ = std::thread::Builder::new().name("session-watch".into()).spawn(move || {
                    let mut r = BufReader::new(r);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match (&mut r).take(MAX_LINE as u64).read_line(&mut line) {
                            Ok(n) if n > 0 && line.ends_with('\n') => {}
                            _ => return,
                        }
                        if let Some(a) = act_request(&line) {
                            let _ = act_on(&a);
                        } else if let Ok(w) = serde_json::from_str::<Watch>(&line) {
                            if w.v == PROTOCOL {
                                relay.set(w);
                            }
                        }
                    }
                });
            }
            let mut first = true;
            loop {
                let mut rep = report(first);
                rep.sources = relay.readings();
                let mut line = serde_json::to_string(&rep).unwrap_or_default();
                line.push('\n');
                if s.write_all(line.as_bytes()).is_err() {
                    break;
                }
                first = false;
                relay.wait(INTERVAL);
            }
        }
        std::thread::sleep(INTERVAL);
    }
}

/// The helper's side of `SessionHub::act`: a line `{"act": {pid, start_us, op}}` names one of this person's processes
/// (pid and start time) and a verb; the helper acts only if the process still has that start time, and only with the
/// four verbs (the kernel lets it act only on its own person's processes).
fn act_request(line: &str) -> Option<crate::session::Act> {
    let v = serde_json::from_str::<serde_json::Value>(line).ok()?;
    serde_json::from_value::<crate::session::Act>(v.get("act")?.clone()).ok()
}

/// Carry out one request on a process of this helper's own person.
pub(super) fn act_on(a: &crate::session::Act) -> bool {
    #[cfg(target_os = "macos")]
    let start = crate::platform::macos::start_time_us(a.pid);
    #[cfg(target_os = "linux")]
    let start = crate::platform::linux::start_time_us(a.pid);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let start: Option<u64> = None;
    if a.pid <= 1 || start != Some(a.start_us) {
        return false;
    }
    // SAFETY: plain system calls on a process whose identity was just checked.
    unsafe {
        match a.op.as_str() {
            "pause" => libc::kill(a.pid, libc::SIGSTOP) == 0,
            "resume" => libc::kill(a.pid, libc::SIGCONT) == 0,
            #[cfg(target_os = "macos")]
            "lower" => libc::setpriority(libc::PRIO_DARWIN_PROCESS, a.pid as libc::id_t, libc::PRIO_DARWIN_BG) == 0,
            #[cfg(target_os = "macos")]
            "restore" => libc::setpriority(libc::PRIO_DARWIN_PROCESS, a.pid as libc::id_t, 0) == 0,
            #[cfg(not(target_os = "macos"))]
            "lower" => libc::setpriority(libc::PRIO_PROCESS, a.pid as libc::id_t, 19) == 0,
            #[cfg(not(target_os = "macos"))]
            "restore" => libc::setpriority(libc::PRIO_PROCESS, a.pid as libc::id_t, 0) == 0,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A helper acts only on a process that still has the start time named, with the four verbs.
    #[test]
    fn a_helper_pauses_and_resumes_its_own_process_only_as_named() {
        let mut child = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        #[cfg(target_os = "macos")]
        let start = crate::platform::macos::start_time_us(pid).unwrap();
        #[cfg(target_os = "linux")]
        let start = crate::platform::linux::start_time_us(pid).unwrap();
        let act = |op: &str, start_us: u64| act_on(&crate::session::Act { pid, start_us, op: op.into() });
        let state = || String::from_utf8_lossy(&std::process::Command::new("/bin/ps").args(["-o", "stat=", "-p", &pid.to_string()])
            .output().unwrap().stdout).trim().to_string();
        assert!(!act("pause", start + 1), "another start time: another process");
        assert!(!act("stop", start), "no other verb");
        assert!(act("pause", start));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !state().starts_with('T') && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(state().starts_with('T'), "{}", state());
        assert!(act("resume", start) && act("lower", start));
        let _ = child.kill();
        let _ = child.wait();
    }
}
