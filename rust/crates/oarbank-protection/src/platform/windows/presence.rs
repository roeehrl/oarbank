//! User presence on Windows, from the sessions WTS lists. In the user's own session (the personal scope's
//! logon task) the last input comes from GetLastInputInfo; the system service runs in session 0, where WTS tells
//! who is logged on, connected and locked, but keeps no last-input time for the console.

use std::collections::HashMap;
use std::ptr;
use std::time::Instant;

use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW,
    WTSSessionInfoEx, WTSINFOEXW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

use crate::presence::wts::{self, Session};
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

/// Every session with its user and lock state (None: WTS is unavailable).
pub fn sessions() -> Option<Vec<Session>> {
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
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, WTSSessionInfoEx, &mut buf, &mut len)
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

/// Presence from the sessions, with the last input of this process's own session and the time each locked
/// session was first seen locked.
#[derive(Debug, Default)]
pub struct NativePresence {
    locked_since: HashMap<u32, Instant>,
}

impl NativePresence {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Presence for NativePresence {
    fn read(&mut self) -> PresenceReading {
        let Some(sessions) = sessions() else {
            return PresenceReading::new(None, "unknown: the session list (WTS) cannot be read");
        };
        let now = Instant::now();
        self.locked_since
            .retain(|id, _| sessions.iter().any(|s| s.id == *id && s.locked == Some(true)));
        for s in sessions.iter().filter(|s| s.locked == Some(true)) {
            self.locked_since.entry(s.id).or_insert(now);
        }
        let own = own_session();
        let own_idle = own_idle_s();
        wts::presence(
            &sessions,
            |id| if id == own { own_idle } else { None },
            |id| self.locked_since.get(&id).map(|t| now.duration_since(*t).as_secs_f64()),
        )
    }
}
