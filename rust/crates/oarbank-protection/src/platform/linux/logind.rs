//! The login sessions systemd-logind tracks, read through `loginctl` (any account may read them, the system
//! service's included), cached for a second so the presence, the front app and the owner's accounts read one
//! listing per tick.

use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::presence::logind::{self, Session};
use crate::signals::{Presence, PresenceReading};

const PROPERTIES: [&str; 14] = [
    "Id", "User", "Name", "Service", "Class", "Type", "Active", "Remote", "Seat", "Display", "Leader", "IdleHint",
    "IdleSinceHint", "LockedHint",
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
    Some(logind::parse_show(&loginctl(&args)?))
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
