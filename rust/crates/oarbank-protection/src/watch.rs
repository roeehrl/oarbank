//! Event-driven owner sources (D51): a watcher thread that wakes the moment a source file changes, so a phase is
//! seen within milliseconds instead of at the next two-second tick.
//!
//! - **macOS:** kqueue `EVFILT_VNODE` on the newest matching file (`NOTE_WRITE`, `NOTE_EXTEND`, `NOTE_DELETE`,
//!   `NOTE_RENAME`) and on its directory (`NOTE_WRITE`: a file was created, renamed or removed), opened with
//!   `O_EVTONLY` so a watched volume can still be unmounted. FSEvents batches by a latency window and suits trees;
//!   kqueue reports one file at once.
//! - **Linux:** inotify on the directory (`IN_MODIFY`, `IN_CLOSE_WRITE`, `IN_CREATE`, `IN_MOVED_TO`, `IN_MOVED_FROM`,
//!   `IN_DELETE`, `IN_DELETE_SELF`, `IN_MOVE_SELF`), filtered by the file name pattern; `IN_Q_OVERFLOW` wakes every
//!   source.
//! - **Elsewhere (Windows):** a 250 ms poll of the newest matching file's size and modification time.
//!   `ReadDirectoryChangesW` reports appends late (the size and write time change when the cache flushes), so the
//!   poll is what bounds the reaction there either way.
//!
//! Every backend also re-resolves the newest file twice a second, and the controller's own two-second tick reads
//! every source regardless: a missed event costs at most that.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::time::Duration;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::Instant;

#[allow(unused_imports)]
use crate::sources::{name_matches, newest_path, wall_now};

/// Called on the watcher thread with the keys whose files changed and when the change was seen (wall clock).
pub type OnChange = Box<dyn FnMut(Vec<String>, f64) + Send>;

/// A watcher thread over a set of `(key, path or glob)` targets.
pub struct Watcher {
    tx: Sender<Vec<(String, PathBuf)>>,
}

/// How often the backends re-resolve the newest file of each target (and, on Windows, poll it).
pub const RESCAN: Duration = Duration::from_millis(250);

impl Watcher {
    /// Start the thread. `on_change` runs on it for every change.
    pub fn spawn(on_change: OnChange) -> std::io::Result<Watcher> {
        let (tx, rx) = channel();
        std::thread::Builder::new()
            .name("protection-sources".into())
            .spawn(move || run(rx, on_change))?;
        Ok(Watcher { tx })
    }

    /// Watch exactly these targets from now on.
    pub fn set(&self, targets: Vec<(String, PathBuf)>) {
        let _ = self.tx.send(targets);
    }
}

/// One target's directory and name pattern.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn split(p: &std::path::Path) -> (PathBuf, String) {
    let dir = p.parent().map(|d| if d.as_os_str().is_empty() { PathBuf::from(".") } else { d.to_path_buf() });
    (dir.unwrap_or_else(|| PathBuf::from(".")), p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
}

/// Each target's newest file, its size and modification time (the portable change signal).
fn stamp(p: &std::path::Path) -> Option<(PathBuf, u64, std::time::SystemTime)> {
    let f = newest_path(p)?;
    let m = std::fs::metadata(&f).ok()?;
    Some((f, m.len(), m.modified().ok()?))
}

#[cfg(target_os = "macos")]
fn run(rx: Receiver<Vec<(String, PathBuf)>>, mut on_change: OnChange) {
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: kqueue takes no arguments.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        return poll_loop(rx, on_change);
    }
    struct Open {
        fd: i32,
        keys: Vec<String>,
    }
    let mut targets: Vec<(String, PathBuf)> = vec![];
    // fd -> what it watches; path -> fd (directories and files)
    let mut open: HashMap<PathBuf, Open> = HashMap::new();
    let open_watch = |kq: i32, path: &std::path::Path, file: bool| -> Option<i32> {
        let c = CString::new(path.as_os_str().as_bytes()).ok()?;
        // SAFETY: a NUL-terminated path; O_EVTONLY opens for event notification only.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_EVTONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        let fflags = if file {
            libc::NOTE_WRITE | libc::NOTE_EXTEND | libc::NOTE_DELETE | libc::NOTE_RENAME | libc::NOTE_ATTRIB
        } else {
            libc::NOTE_WRITE | libc::NOTE_DELETE | libc::NOTE_RENAME
        };
        let ev = libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_VNODE,
            flags: libc::EV_ADD | libc::EV_CLEAR,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: one change record, no event buffer.
        let rc = unsafe { libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if rc < 0 {
            // SAFETY: our fd.
            unsafe { libc::close(fd) };
            return None;
        }
        Some(fd)
    };
    let mut last_scan = Instant::now() - RESCAN;
    loop {
        match rx.try_recv() {
            Ok(t) => {
                targets = t;
                last_scan = Instant::now() - RESCAN;
            }
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }
        if last_scan.elapsed() >= RESCAN {
            last_scan = Instant::now();
            // what should be open: each target's directory and its newest file
            let mut want: BTreeMap<PathBuf, (bool, Vec<String>)> = BTreeMap::new();
            for (k, p) in &targets {
                let (dir, _) = split(p);
                want.entry(dir).or_insert((false, vec![])).1.push(k.clone());
                if let Some(f) = newest_path(p) {
                    want.entry(f).or_insert((true, vec![])).1.push(k.clone());
                }
            }
            open.retain(|path, o| {
                if want.contains_key(path) {
                    return true;
                }
                // SAFETY: our fd (closing it removes its kevent).
                unsafe { libc::close(o.fd) };
                false
            });
            // a newly watched file may have changed before its watch existed: read its sources once now
            let mut fresh: Vec<String> = vec![];
            for (path, (file, keys)) in want {
                match open.get_mut(&path) {
                    Some(o) => o.keys = keys,
                    None => {
                        if let Some(fd) = open_watch(kq, &path, file) {
                            if file {
                                fresh.extend(keys.iter().cloned());
                            }
                            open.insert(path, Open { fd, keys });
                        }
                    }
                }
            }
            if !fresh.is_empty() {
                fresh.sort();
                fresh.dedup();
                on_change(fresh, wall_now());
            }
        }
        let mut evs: [libc::kevent; 32] = unsafe { std::mem::zeroed() };
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 100_000_000 };
        // SAFETY: an event buffer of 32 and a timeout.
        let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, evs.as_mut_ptr(), 32, &ts) };
        if n <= 0 {
            continue;
        }
        let t = wall_now();
        let mut keys: Vec<String> = vec![];
        let mut reopen = false;
        for ev in &evs[..n as usize] {
            let fd = ev.ident as i32;
            if let Some((_, o)) = open.iter().find(|(_, o)| o.fd == fd) {
                keys.extend(o.keys.iter().cloned());
            }
            if ev.fflags & (libc::NOTE_DELETE | libc::NOTE_RENAME) != 0 || ev.fflags & libc::NOTE_WRITE != 0 {
                reopen = true; // a directory changed, or the file moved: find the newest file again
            }
        }
        if reopen {
            last_scan = Instant::now() - RESCAN;
        }
        keys.sort();
        keys.dedup();
        if !keys.is_empty() {
            on_change(keys, t);
        }
    }
    for o in open.values() {
        // SAFETY: our fds.
        unsafe { libc::close(o.fd) };
    }
    // SAFETY: our kqueue.
    unsafe { libc::close(kq) };
}

#[cfg(target_os = "linux")]
fn run(rx: Receiver<Vec<(String, PathBuf)>>, mut on_change: OnChange) {
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: plain flags.
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd < 0 {
        return poll_loop(rx, on_change);
    }
    let mask = libc::IN_MODIFY
        | libc::IN_CLOSE_WRITE
        | libc::IN_CREATE
        | libc::IN_MOVED_TO
        | libc::IN_MOVED_FROM
        | libc::IN_DELETE
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF;
    let mut targets: Vec<(String, PathBuf)> = vec![];
    // watch descriptor -> (dir, [(key, name pattern)])
    let mut wds: HashMap<i32, (PathBuf, Vec<(String, String)>)> = HashMap::new();
    let mut last_scan = Instant::now() - RESCAN;
    let mut buf = vec![0u8; 64 << 10];
    loop {
        match rx.try_recv() {
            Ok(t) => {
                targets = t;
                last_scan = Instant::now() - RESCAN;
            }
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }
        if last_scan.elapsed() >= RESCAN {
            last_scan = Instant::now();
            let mut want: BTreeMap<PathBuf, Vec<(String, String)>> = BTreeMap::new();
            for (k, p) in &targets {
                let (dir, name) = split(p);
                want.entry(dir).or_default().push((k.clone(), name));
            }
            wds.retain(|wd, (dir, _)| {
                if want.contains_key(dir) {
                    return true;
                }
                // SAFETY: our descriptors.
                unsafe { libc::inotify_rm_watch(fd, *wd) };
                false
            });
            for (dir, pats) in want {
                if let Some((_, v)) = wds.values_mut().find(|(d, _)| *d == dir) {
                    *v = pats;
                    continue;
                }
                let Ok(c) = CString::new(dir.as_os_str().as_bytes()) else { continue };
                // SAFETY: a NUL-terminated path.
                let wd = unsafe { libc::inotify_add_watch(fd, c.as_ptr(), mask) };
                if wd >= 0 {
                    // a newly watched directory's files may have changed before the watch existed
                    on_change(pats.iter().map(|(k, _)| k.clone()).collect(), wall_now());
                    wds.insert(wd, (dir, pats));
                }
            }
        }
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one pollfd.
        let r = unsafe { libc::poll(&mut pfd, 1, 100) };
        if r <= 0 {
            continue;
        }
        // SAFETY: a buffer of its stated size.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            continue;
        }
        let t = wall_now();
        let mut keys: Vec<String> = vec![];
        let mut off = 0usize;
        let hdr = std::mem::size_of::<libc::inotify_event>();
        while off + hdr <= n as usize {
            // SAFETY: the kernel wrote whole records; read the header unaligned.
            let ev: libc::inotify_event = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr().cast()) };
            let name_bytes = &buf[off + hdr..off + hdr + ev.len as usize];
            let name = String::from_utf8_lossy(name_bytes.split(|b| *b == 0).next().unwrap_or_default()).into_owned();
            if ev.mask & libc::IN_Q_OVERFLOW != 0 {
                keys.extend(targets.iter().map(|(k, _)| k.clone())); // events were lost: read everything
            } else if let Some((_, pats)) = wds.get(&ev.wd) {
                for (k, pat) in pats {
                    if name.is_empty() || name_matches(pat, &name) {
                        keys.push(k.clone());
                    }
                }
            }
            if ev.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF | libc::IN_IGNORED) != 0 {
                wds.remove(&ev.wd);
                last_scan = Instant::now() - RESCAN;
            }
            off += hdr + ev.len as usize;
        }
        keys.sort();
        keys.dedup();
        if !keys.is_empty() {
            on_change(keys, t);
        }
    }
    // SAFETY: our descriptor.
    unsafe { libc::close(fd) };
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn run(rx: Receiver<Vec<(String, PathBuf)>>, on_change: OnChange) {
    poll_loop(rx, on_change)
}

/// The portable backend: poll each target's newest file every 250 ms.
#[allow(dead_code)]
fn poll_loop(rx: Receiver<Vec<(String, PathBuf)>>, mut on_change: OnChange) {
    type Stamp = Option<(PathBuf, u64, std::time::SystemTime)>;
    let mut targets: Vec<(String, PathBuf)> = vec![];
    let mut seen: BTreeMap<String, Stamp> = BTreeMap::new();
    loop {
        match rx.try_recv() {
            Ok(t) => {
                // no baseline: the list can arrive up to a scan after it was set, and a change in between would become
                // the baseline and never be reported; the first scan reports every target (the caller compares
                // readings, so a report without a change costs one read)
                targets = t;
                seen.clear();
            }
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }
        std::thread::sleep(RESCAN);
        let t = wall_now();
        let mut keys = vec![];
        for (k, p) in &targets {
            let now = stamp(p);
            if seen.get(k) != Some(&now) {
                seen.insert(k.clone(), now);
                keys.push(k.clone());
            }
        }
        if !keys.is_empty() {
            on_change(keys, t);
        }
    }
}

#[cfg(test)]
mod poll_tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    /// The portable backend (Windows) reports a change made right after its targets were set, before it took them up.
    #[test]
    fn a_change_between_set_and_the_first_scan_is_reported() {
        let dir = tempfile::Builder::new().prefix("oarbank-watch-poll-").tempdir().unwrap();
        let f = dir.path().join("events-1.jsonl");
        std::fs::write(&f, "{\"event\":\"a\"}\n").unwrap();
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let s2 = seen.clone();
        let (tx, rx) = channel();
        let t = std::thread::spawn(move || poll_loop(rx, Box::new(move |keys, _| s2.lock().unwrap().extend(keys))));
        tx.send(vec![("k".to_string(), dir.path().join("events-*.jsonl"))]).unwrap();
        std::fs::OpenOptions::new().append(true).open(&f).unwrap().write_all(b"{\"event\":\"b\"}\n").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while seen.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(seen.lock().unwrap().first().map(String::as_str), Some("k"));
        drop(tx);
        t.join().unwrap();
    }
}
