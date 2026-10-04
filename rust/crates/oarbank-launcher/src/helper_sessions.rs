//! The elevated helper's `{"op": "sessions"}`: the sessions WTS lists, read as LocalSystem for the agent's system
//! service, whose virtual account the session manager refuses (WTSEnumerateSessions fails there). Host protection
//! needs the list for presence and for the session in front (oarbank-protection, `platform/windows/presence.rs`,
//! which parses this reply; the format is shared through its `vectors/helper-sessions-reply.json`).

use serde_json::{json, Value};

/// One session as WTS lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WtsSession {
    pub id: u32,
    /// WTS_CONNECTSTATE_CLASS (0: active)
    pub state: u32,
    pub user: String,
    /// WTSINFOEX's SessionFlags: Some(true) locked, Some(false) unlocked, None unknown.
    pub locked: Option<bool>,
}

/// The reply: every session, or a refusal when WTS cannot be read.
pub fn reply(sessions: Option<&[WtsSession]>) -> Value {
    match sessions {
        Some(list) => json!({"ok": true, "sessions": list.iter().map(|s| json!({
            "id": s.id, "state": s.state, "user": s.user, "locked": s.locked})).collect::<Vec<_>>()}),
        None => json!({"ok": false, "error": "WTS cannot list the sessions"}),
    }
}

/// Every session with its user and lock state (None: WTS refuses this process).
#[cfg(windows)]
pub fn read() -> Option<Vec<WtsSession>> {
    use windows_sys::Win32::System::RemoteDesktop::{WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW, WTSSessionInfoEx,
                                                    WTSINFOEXW, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW};
    const WTS_SESSIONSTATE_LOCK: i32 = 0;
    const WTS_SESSIONSTATE_UNLOCK: i32 = 1;
    let mut list: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut n = 0u32;
    // SAFETY: WTS allocates the list, freed below.
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut list, &mut n) } == 0 {
        return None;
    }
    // SAFETY: WTS wrote `n` entries; allocated by WTSEnumerateSessionsW.
    let ids: Vec<(u32, u32)> = unsafe { std::slice::from_raw_parts(list, n as usize) }.iter().map(|s| (s.SessionId, s.State as u32)).collect();
    unsafe { WTSFreeMemory(list.cast()) };
    let mut out = vec![];
    for (id, state) in ids {
        let mut s = WtsSession { id, state, user: String::new(), locked: None };
        let (mut buf, mut len): (*mut u16, u32) = (std::ptr::null_mut(), 0);
        // SAFETY: WTS allocates the buffer, freed below; for WTSSessionInfoEx it holds a WTSINFOEXW.
        if unsafe { WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, WTSSessionInfoEx, &mut buf, &mut len) } != 0 {
            if len as usize >= std::mem::size_of::<WTSINFOEXW>() {
                // SAFETY: WTS wrote a WTSINFOEXW (level 1).
                let l = unsafe { &(*(buf as *const WTSINFOEXW)).Data.WTSInfoExLevel1 };
                let n = l.UserName.iter().position(|&c| c == 0).unwrap_or(l.UserName.len());
                s.user = String::from_utf16_lossy(&l.UserName[..n]);
                s.locked = match l.SessionFlags {
                    WTS_SESSIONSTATE_LOCK => Some(true),
                    WTS_SESSIONSTATE_UNLOCK => Some(false),
                    _ => None,
                };
            }
            unsafe { WTSFreeMemory(buf.cast()) };
        }
        out.push(s);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reply the protection crate parses: both sides are held to the same vector.
    #[test]
    fn the_reply_is_the_shared_vector() {
        let want: Value = serde_json::from_str(include_str!("../../oarbank-protection/vectors/helper-sessions-reply.json")).unwrap();
        let s = |id, state, user: &str, locked| WtsSession { id, state, user: user.into(), locked };
        let list = [s(0, 4, "", None), s(1, 0, "ada", Some(false)), s(2, 0, "bo", Some(true))];
        assert_eq!(reply(Some(&list)), want);
        assert_eq!(reply(None)["ok"], json!(false));
    }

    /// As the helper runs it (LocalSystem, or an administrator): WTS lists session 0 and the console session.
    #[cfg(windows)]
    #[test]
    #[ignore = "reads the live sessions"]
    fn reads_the_live_sessions() {
        let list = read().expect("WTS lists the sessions");
        assert!(list.iter().any(|s| s.id == 0), "{list:?}");
        let r = reply(Some(&list));
        assert_eq!(r["sessions"].as_array().map(Vec::len), Some(list.len()));
    }
}
