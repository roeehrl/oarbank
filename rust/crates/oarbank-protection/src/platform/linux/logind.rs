//! The login sessions systemd-logind tracks, read through `loginctl` (any account may read them, the system
//! service's included), cached for a second so the presence, the front app and the owner's accounts read one
//! listing per tick. Where logind has no input time for a person's text session (every ssh login: OpenSSH opens
//! the PAM session before it allocates the pty, so logind records no terminal), the controlling terminals of the
//! session's processes are read from its cgroup and procfs; any account may read those and the terminals' access
//! times.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::reader;
use crate::presence::logind::{self, Session, Terminal, Terminals};
use crate::procinfo::procfs::tty_device;
use crate::signals::{Presence, PresenceReading};

const PROPERTIES: [&str; 18] = [
    "Id",
    "User",
    "Name",
    "Service",
    "Class",
    "Type",
    "State",
    "Active",
    "Remote",
    "RemoteHost",
    "Seat",
    "TTY",
    "Display",
    "Leader",
    "Scope",
    "IdleHint",
    "IdleSinceHint",
    "LockedHint",
];

fn loginctl(args: &[&str]) -> Option<String> {
    let out = Command::new("loginctl")
        .args(args)
        .arg("--no-pager")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn read() -> Option<Vec<Session>> {
    let ids = logind::parse_list(&loginctl(&["list-sessions", "--no-legend"])?);
    if ids.is_empty() {
        return Some(vec![]);
    }
    let mut args = vec!["show-session"];
    args.extend(ids.iter().map(String::as_str));
    for p in PROPERTIES {
        args.extend(["-p", p]);
    }
    let mut sessions = logind::parse_show(&loginctl(&args)?);
    for s in sessions.iter_mut().filter(|s| s.needs_terminals()) {
        s.terminals = terminals(s);
    }
    Some(sessions)
}

/// The pids in a session's cgroup: its leader's, else the scope logind names under the user's slice (None: neither
/// can be read).
fn session_pids(s: &Session) -> Option<Vec<i32>> {
    let leader = (s.leader > 0)
        .then(|| fs::read_to_string(format!("/proc/{}/cgroup", s.leader)).ok())
        .flatten()
        .and_then(|c| logind::session_cgroup(&c));
    let scope =
        (!s.scope.is_empty()).then(|| format!("/user.slice/user-{}.slice/{}", s.uid, s.scope));
    leader.into_iter().chain(scope).find_map(|path| {
        [
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/unified",
            "/sys/fs/cgroup/systemd",
        ]
        .iter()
        .find_map(|root| fs::read_to_string(format!("{root}{path}/cgroup.procs")).ok())
        .map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect())
    })
}

/// The terminal device (major, minor) under /dev: by its usual name, else by looking through /dev and /dev/pts.
fn device_path(major: u32, minor: u32) -> Option<String> {
    let is = |path: &str| {
        fs::metadata(path).is_ok_and(|m| {
            m.file_type().is_char_device()
                && libc::major(m.rdev()) == major
                && libc::minor(m.rdev()) == minor
        })
    };
    let named = logind::tty_name(major, minor).map(|n| format!("/dev/{n}"));
    named.filter(|p| is(p)).or_else(|| {
        ["/dev", "/dev/pts"].iter().find_map(|dir| {
            fs::read_dir(dir)
                .ok()?
                .filter_map(|e| e.ok()?.path().to_str().map(str::to_string))
                .find(|p| is(p))
        })
    })
}

/// A controlling terminal and its last input (its access time).
fn terminal(tty_nr: u32) -> Option<Terminal> {
    let (major, minor) = tty_device(tty_nr);
    let path = device_path(major, minor)?;
    let m = fs::metadata(&path).ok()?;
    let input_us =
        u64::try_from(m.atime()).ok()? * 1_000_000 + u64::try_from(m.atime_nsec()).ok()? / 1000;
    Some(Terminal {
        name: path.strip_prefix("/dev/").unwrap_or(&path).to_string(),
        input_us,
    })
}

/// The most recently read controlling terminal of a session's processes. Not read when the processes cannot be
/// listed or their stat read (procfs mounted with hidepid), or a terminal they hold cannot be found.
fn terminals(s: &Session) -> Terminals {
    let Some(pids) = session_pids(s) else {
        return Terminals::NotRead;
    };
    let r = reader();
    let (mut read, mut lost) = (false, false);
    let mut seen = HashSet::new();
    let mut best: Option<Terminal> = None;
    for pid in pids {
        let Some(st) = r.stat(pid) else {
            continue; // exited since the cgroup was listed, or hidden
        };
        read = true;
        if st.tty_nr == 0 || !seen.insert(st.tty_nr) {
            continue;
        }
        match terminal(st.tty_nr) {
            Some(t) if best.as_ref().is_none_or(|b| t.input_us > b.input_us) => best = Some(t),
            Some(_) => {}
            None => lost = true,
        }
    }
    if !read || (best.is_none() && lost) {
        return Terminals::NotRead;
    }
    Terminals::Read(best)
}

/// The sessions now (None: logind is not running, or `loginctl` is missing).
pub fn sessions() -> Option<Arc<Vec<Session>>> {
    type Cache = Option<(Instant, Option<Arc<Vec<Session>>>)>;
    static CACHE: Mutex<Cache> = Mutex::new(None);
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    match &*c {
        Some((at, s)) if at.elapsed() < Duration::from_secs(1) => s.clone(),
        _ => {
            let s = read().map(Arc::new);
            *c = Some((Instant::now(), s.clone()));
            s
        }
    }
}

pub fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64)
}

/// Presence from logind.
#[derive(Debug, Default)]
pub struct NativePresence;

impl NativePresence {
    pub fn new() -> Self {
        Self
    }
}

impl Presence for NativePresence {
    fn read(&mut self) -> PresenceReading {
        match sessions() {
            Some(s) => logind::presence(&s, now_us()),
            None => PresenceReading::new(None, "unknown: systemd-logind is not running here"),
        }
    }
}
