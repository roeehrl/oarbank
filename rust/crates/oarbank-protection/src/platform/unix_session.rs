//! The session helpers' transport on Linux and macOS: a Unix socket the system service binds, open to every local
//! account, whose peer credentials name the account that sent each report (`SO_PEERCRED` on Linux, `getpeereid`
//! on macOS). The platforms say what a helper reads and how the service checks that a process is the account's.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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

/// The socket's directory, before binding in it: made when missing (this account's, 0755: everyone may reach the
/// socket, only the account creates in it), its mode put right when it is this account's. One another account owns
/// (root's, made by an install) is used as it is. `hint`: how the install makes it, for an error that says why not.
pub(super) fn socket_dir(dir: &Path, hint: &str) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let mode = || std::fs::Permissions::from_mode(0o755);
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(dir).map_err(|e| {
                std::io::Error::new(e.kind(), format!("cannot create {}: {e} ({hint})", dir.display()))
            })?;
            std::fs::set_permissions(dir, mode())
        }
        Err(e) => Err(e),
        Ok(m) if !m.is_dir() => Err(std::io::Error::other(format!(
            "{} is not a directory ({hint})",
            dir.display()
        ))),
        // SAFETY: geteuid cannot fail.
        Ok(m) if m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 != 0o755 => {
            std::fs::set_permissions(dir, mode())
        }
        Ok(_) => Ok(()),
    }
}

/// A bound socket, served on its own thread until this is dropped.
struct Listening {
    path: PathBuf,
    /// The socket's (device, inode): another file at the path is not this socket.
    id: (u64, u64),
    stop: Arc<AtomicBool>,
}

impl super::Served for Listening {
    fn alive(&self) -> bool {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        std::fs::symlink_metadata(&self.path)
            .is_ok_and(|m| m.file_type().is_socket() && (m.dev(), m.ino()) == self.id)
    }
}

impl Drop for Listening {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Serve helpers (the system service): bind the socket at `path` (its directory made first: `socket_dir`), open to
/// every local account (the peer's uid says who it is), and take their reports on a thread each. `owns(uid, pid,
/// start_us)`: does the process belong to that account (and, unless `start_us` is 0, did it start then)? Served until
/// what this returns is dropped.
pub(super) fn serve(
    path: &Path,
    hint: &str,
    hub: Arc<SessionHub>,
    owns: fn(u32, i32, u64) -> bool,
) -> std::io::Result<Box<dyn super::Served>> {
    use std::os::unix::fs::MetadataExt;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        socket_dir(dir, hint)?;
    }
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("cannot bind {}: {e} ({hint})", path.display()))
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let m = std::fs::symlink_metadata(path)?;
    // polled, so a dropped listener stops within a second instead of waiting for a connection that never comes
    l.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    std::thread::Builder::new()
        .name("session-hub".into())
        .spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let mut fd = libc::pollfd { fd: l.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                // SAFETY: one pollfd, for a listener this thread owns.
                if unsafe { libc::poll(&mut fd, 1, 1000) } <= 0 {
                    continue;
                }
                let Ok((s, _)) = l.accept() else { continue };
                // macOS hands the listener's O_NONBLOCK to the connection; its reader blocks
                if s.set_nonblocking(false).is_err() {
                    continue;
                }
                let hub = hub.clone();
                let _ = std::thread::Builder::new()
                    .name("session-helper".into())
                    .spawn(move || take_reports(&hub, s, owns));
            }
        })?;
    Ok(Box::new(Listening { path: path.to_path_buf(), id: (m.dev(), m.ino()), stop }))
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
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().mode() & 0o7777
    }

    fn any_owner(_uid: u32, _pid: i32, _start_us: u64) -> bool {
        false
    }

    fn until(what: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !what() {
            if Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    /// The socket's directory: made when missing (0755, this account's), put right when it is this account's, and
    /// an error that names the directory and how the install makes it when it cannot be.
    #[test]
    fn the_socket_directory_is_made_for_this_account_and_put_right() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("a/run");
        socket_dir(&dir, "the install makes it").unwrap();
        assert!(dir.is_dir() && mode(&dir) == 0o755);
        // SAFETY: geteuid cannot fail.
        assert_eq!(std::fs::metadata(&dir).unwrap().uid(), unsafe { libc::geteuid() });
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        socket_dir(&dir, "").unwrap();
        assert_eq!(mode(&dir), 0o755, "helpers of every account must reach the socket");
        socket_dir(&dir, "").unwrap(); // again: nothing to do
        let file = t.path().join("file");
        std::fs::write(&file, b"").unwrap();
        let e = socket_dir(&file, "the install makes it").unwrap_err().to_string();
        assert!(e.contains("is not a directory") && e.contains("the install makes it"), "{e}");
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            // a parent this account may not write in (root's, on an upgraded Mac)
            let locked = t.path().join("locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o555)).unwrap();
            let e = socket_dir(&locked.join("run"), "the install makes it").unwrap_err();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            let e = e.to_string();
            assert!(e.contains(&format!("cannot create {}", locked.join("run").display())) && e.contains("the install makes it"), "{e}");
        }
    }

    /// Serving makes the socket's missing directory, binds the socket open to every account, and knows when the
    /// socket is no longer where helpers look; a dropped listener lets the path be served again.
    #[test]
    fn serving_makes_the_missing_directory_and_sees_its_socket_go() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("run/s.sock");
        let served = serve(&path, "", SessionHub::new(), any_owner).unwrap();
        assert_eq!(mode(path.parent().unwrap()), 0o755);
        assert_eq!(mode(&path), 0o666);
        assert!(served.alive());
        UnixStream::connect(&path).expect("a helper connects");
        std::fs::remove_file(&path).unwrap();
        assert!(!served.alive(), "removed: no helper can reach it");
        drop(served);
        let again = serve(&path, "", SessionHub::new(), any_owner).unwrap();
        assert!(again.alive());
        UnixStream::connect(&path).expect("served again");
    }

    /// The system service keeps trying: a directory it cannot make at first (a file stands where it goes) fails with
    /// the reason, once that is gone the next try serves, and a socket removed under it is served again.
    #[test]
    fn the_service_serves_helpers_once_it_can_and_again_when_its_socket_goes() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("run");
        let path = dir.join("s.sock");
        std::fs::write(&dir, b"").unwrap();
        let hub = SessionHub::new();
        let (tx, rx) = std::sync::mpsc::channel();
        // the supervisor outlives the test: once it is over, it may not make the scratch directory again
        let over = Arc::new(AtomicBool::new(false));
        let (h, p, o) = (hub.clone(), path.clone(), over.clone());
        super::super::supervise(hub.clone(), path.display().to_string(), Duration::from_millis(20),
                                move || match o.load(Ordering::Relaxed) {
                                    false => serve(&p, "the install makes it", h.clone(), any_owner),
                                    true => Err(std::io::Error::other("the test is over")),
                                },
                                move |s: &crate::session::Serving| { let _ = tx.send(s.clone()); });
        let first = hub.serving().unwrap();
        assert!(!first.serving && first.at == path.display().to_string());
        assert!(first.error.as_deref().is_some_and(|e| e.contains("is not a directory")), "{first:?}");
        assert!(until(|| hub.serving().unwrap().failures >= 3), "it tries again");
        std::fs::remove_file(&dir).unwrap();
        assert!(until(|| hub.serving().unwrap().serving), "{:?}", hub.serving());
        assert!(hub.serving().unwrap().error.is_none() && hub.serving().unwrap().failures == 0);
        UnixStream::connect(&path).expect("helpers connect");
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(until(|| path.exists() && hub.serving().unwrap().serving), "served again");
        UnixStream::connect(&path).expect("helpers connect again");
        // each change heard once, however many tries failed the same way
        let heard: Vec<_> = rx.try_iter().map(|s| (s.serving, s.error.unwrap_or_default())).collect();
        assert_eq!(heard.iter().map(|x| x.0).collect::<Vec<_>>(), [false, true, false, true], "{heard:?}");
        assert!(heard[2].1.ends_with("was removed"), "{heard:?}");
        over.store(true, Ordering::Relaxed);
    }

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
