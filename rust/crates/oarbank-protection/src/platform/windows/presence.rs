//! User presence on Windows, from the sessions WTS lists. In the user's own session (the personal scope's
//! logon task) the last input comes from GetLastInputInfo; the system service runs in session 0, where WTS tells
//! who is logged on, connected and locked, but keeps no last-input time for the console. The system service's
//! virtual account may not ask WTS at all (the session manager refuses it), so the service asks the elevated helper,
//! which reads the same list as LocalSystem.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW,
    WTSSessionInfoEx, WTSINFOEXW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

use crate::presence::wts::{self, Session};
use crate::session::{Principal, SessionHub};
use crate::signals::{Presence, PresenceReading};

/// WTSINFOEX's SessionFlags.
const WTS_SESSIONSTATE_LOCK: i32 = 0;
const WTS_SESSIONSTATE_UNLOCK: i32 = 1;

/// This process's session (0: the services' session).
pub fn own_session() -> u32 {
    let mut s = 0u32;
    // SAFETY: a valid out-pointer.
    if unsafe { ProcessIdToSessionId(std::process::id(), &mut s) } == 0 {
        return 0;
    }
    s
}

/// Seconds since the last input in this process's own session (None in session 0, which has no input).
pub fn own_idle_s() -> Option<f64> {
    if own_session() == 0 {
        return None;
    }
    let mut li = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: li is initialized with its size.
    (unsafe { GetLastInputInfo(&mut li) } != 0)
        .then(|| unsafe { GetTickCount() }.wrapping_sub(li.dwTime) as f64 / 1000.0)
}

fn utf16(s: &[u16]) -> String {
    let n = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..n])
}

/// Every session with its user and lock state: from WTS, or where this process may not ask WTS (the system
/// service's virtual account), from the elevated helper. None: neither can tell.
pub fn sessions() -> Option<Vec<Session>> {
    wts_sessions().or_else(helper_sessions)
}

/// The elevated helper's pipe (`OARBANK_HELPER_PIPE` overrides it).
fn helper_pipe() -> String {
    std::env::var("OARBANK_HELPER_PIPE").unwrap_or_else(|_| r"\\.\pipe\oarbank-helper".into())
}

/// How long a helper reply stays good: presence and the front each read the list on every tick.
const HELPER_TTL: Duration = Duration::from_secs(1);
/// The longest the protection tick waits for the helper.
const HELPER_WAIT: Duration = Duration::from_secs(2);
const ERROR_PIPE_BUSY: i32 = 231;

/// The sessions as the elevated helper reads them (`{"op": "sessions"}`), kept for a second. A request is never
/// waited on longer than two seconds, and none is sent while an earlier one is still out (a helper that does not
/// answer costs one thread, not the tick).
pub fn helper_sessions() -> Option<Vec<Session>> {
    static LAST: Mutex<Option<(Instant, Option<Vec<Session>>)>> = Mutex::new(None);
    static OUT: AtomicBool = AtomicBool::new(false);
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, s)) = last.as_ref() {
        if at.elapsed() < HELPER_TTL {
            return s.clone();
        }
    }
    if OUT.swap(true, Ordering::SeqCst) {
        return None;
    }
    let (tx, rx) = mpsc::channel();
    let sent = std::thread::Builder::new()
        .name("helper-sessions".into())
        .spawn(move || {
            let _ = tx.send(ask_helper());
            OUT.store(false, Ordering::SeqCst);
        });
    if sent.is_err() {
        OUT.store(false, Ordering::SeqCst);
        return None;
    }
    let s = rx.recv_timeout(HELPER_WAIT).ok().flatten();
    *last = Some((Instant::now(), s.clone()));
    s
}

fn ask_helper() -> Option<Vec<Session>> {
    let name = helper_pipe();
    let mut pipe = None;
    for _ in 0..10 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
        {
            Ok(p) => {
                pipe = Some(p);
                break;
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(_) => return None, // no helper (the personal scope, where WTS answers anyway)
        }
    }
    let mut pipe = pipe?;
    pipe.write_all(b"{\"op\": \"sessions\"}\n").ok()?;
    let mut line = String::new();
    BufReader::new(&pipe)
        .take(1 << 20)
        .read_line(&mut line)
        .ok()?;
    wts::parse_helper_reply(&line)
}

/// Every session with its user and lock state, from WTS itself (None: WTS refuses this process).
pub fn wts_sessions() -> Option<Vec<Session>> {
    let mut list: *mut WTS_SESSION_INFOW = ptr::null_mut();
    let mut n = 0u32;
    // SAFETY: WTS allocates the list, freed below.
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut list, &mut n) } == 0 {
        return None;
    }
    // SAFETY: WTS wrote `n` entries.
    let ids: Vec<(u32, u32)> = unsafe { std::slice::from_raw_parts(list, n as usize) }
        .iter()
        .map(|s| (s.SessionId, s.State as u32))
        .collect();
    // SAFETY: allocated by WTSEnumerateSessionsW.
    unsafe { WTSFreeMemory(list.cast()) };
    let mut out = vec![];
    for (id, state) in ids {
        let mut s = Session {
            id,
            state,
            ..Session::default()
        };
        let mut buf: *mut u16 = ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: WTS allocates the buffer, freed below; for WTSSessionInfoEx it holds a WTSINFOEXW.
        if unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                id,
                WTSSessionInfoEx,
                &mut buf,
                &mut len,
            )
        } != 0
        {
            if len as usize >= std::mem::size_of::<WTSINFOEXW>() {
                // SAFETY: WTS wrote a WTSINFOEXW (level 1).
                let l = unsafe { &(*(buf as *const WTSINFOEXW)).Data.WTSInfoExLevel1 };
                s.user = utf16(&l.UserName);
                s.locked = match l.SessionFlags {
                    WTS_SESSIONSTATE_LOCK => Some(true),
                    WTS_SESSIONSTATE_UNLOCK => Some(false),
                    _ => None,
                };
            }
            // SAFETY: allocated by WTSQuerySessionInformationW.
            unsafe { WTSFreeMemory(buf.cast()) };
        }
        out.push(s);
    }
    Some(out)
}

/// Presence from the sessions, with the last input of this process's own session (or of any session, from its
/// helper) and the time each locked session was first seen locked.
pub struct NativePresence {
    hub: Option<Arc<SessionHub>>,
    locked_since: HashMap<u32, Instant>,
}

impl NativePresence {
    pub fn new(hub: Option<Arc<SessionHub>>) -> Self {
        Self {
            hub,
            locked_since: HashMap::new(),
        }
    }
}

impl Presence for NativePresence {
    fn read(&mut self) -> PresenceReading {
        let Some(sessions) = sessions() else {
            return PresenceReading::new(
                None,
                "unknown: the session list cannot be read (from WTS, or from the elevated helper)",
            );
        };
        let now = Instant::now();
        self.locked_since.retain(|id, _| {
            sessions
                .iter()
                .any(|s| s.id == *id && s.locked == Some(true))
        });
        for s in sessions.iter().filter(|s| s.locked == Some(true)) {
            self.locked_since.entry(s.id).or_insert(now);
        }
        let own = own_session();
        let own_idle = own_idle_s();
        let hub = self.hub.as_deref();
        wts::presence(
            &sessions,
            |id| {
                if id == own {
                    own_idle
                } else {
                    hub?.idle_s(Principal::Session(id))
                }
            },
            |id| {
                self.locked_since
                    .get(&id)
                    .map(|t| now.duration_since(*t).as_secs_f64())
            },
        )
    }
}
