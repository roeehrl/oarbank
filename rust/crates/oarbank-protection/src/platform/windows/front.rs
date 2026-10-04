//! What is in front on Windows: the session whose desktop is on the screen (the console's, from WTS), and in
//! it the foreground window's process. Only a process in that session may ask for its foreground window
//! (GetForegroundWindow), so the personal scope's agent reads it itself; the system service, in session 0, does
//! not see it. A locked session shows the lock screen: no app is in front.

use windows_sys::Win32::Foundation::{CloseHandle, HWND, LPARAM};
use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumChildWindows, GetForegroundWindow, GetWindowThreadProcessId,
};

use super::presence::{own_session, sessions};
use crate::presence::wts::front_session;
use crate::session::{Principal, SessionHub};
use crate::signals::{Front, FrontReading};

fn window_pid(w: HWND) -> u32 {
    let mut pid = 0u32;
    // SAFETY: any window handle; pid is a valid out-pointer.
    unsafe { GetWindowThreadProcessId(w, &mut pid) };
    pid
}

fn image_name(pid: u32) -> Option<String> {
    // SAFETY: plain call; the handle is closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let mut n = buf.len() as u32;
    // SAFETY: a live handle and a buffer of `n` units.
    let ok =
        unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut n) } != 0;
    // SAFETY: we own the handle.
    unsafe { CloseHandle(h) };
    ok.then(|| String::from_utf16_lossy(&buf[..n as usize]))
}

/// A packaged (UWP) app's window is a frame owned by ApplicationFrameHost.exe; the app's own process owns the
/// child window inside it.
fn framed_app(frame: HWND, host: u32) -> Option<u32> {
    struct Search {
        host: u32,
        found: u32,
    }
    unsafe extern "system" fn visit(w: HWND, l: LPARAM) -> i32 {
        // SAFETY: l is the &mut Search passed below, alive for the enumeration.
        let s = unsafe { &mut *(l as *mut Search) };
        let pid = window_pid(w);
        if pid != 0 && pid != s.host {
            s.found = pid;
            return 0;
        }
        1
    }
    let mut s = Search { host, found: 0 };
    // SAFETY: the callback only reads window pids and writes `s`, which outlives the call.
    unsafe { EnumChildWindows(frame, Some(visit), &mut s as *mut Search as LPARAM) };
    (s.found != 0).then_some(s.found)
}

/// The foreground window's process in this process's own session.
pub fn own_front() -> FrontReading {
    // SAFETY: no preconditions.
    let w = unsafe { GetForegroundWindow() };
    if w.is_null() {
        // between windows, or the secure desktop (an elevation prompt) is in front
        return FrontReading::new(Front::Unknown, "unknown: no foreground window right now");
    }
    let mut pid = window_pid(w);
    let host = image_name(pid).is_some_and(|p| {
        p.to_ascii_lowercase()
            .ends_with("\\applicationframehost.exe")
    });
    if host {
        pid = framed_app(w, pid).unwrap_or(pid);
    }
    FrontReading::new(Front::App(pid as i32), "foreground window")
}

/// What is in front: nothing when nobody is logged on at the console or the session is locked; the foreground
/// window when this process runs in that session; from any other session, what that session's helper reports.
pub fn front(hub: Option<&SessionHub>) -> FrontReading {
    let Some(sessions) = sessions() else {
        return FrontReading::new(
            Front::Unknown,
            "unknown: the session list cannot be read (from WTS, or from the elevated helper)",
        );
    };
    // SAFETY: no preconditions.
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    let Some(s) = front_session(&sessions, console) else {
        return FrontReading::new(Front::Nothing, "no one logged on");
    };
    if s.locked == Some(true) {
        return FrontReading::new(Front::Nothing, format!("session {} is locked", s.id));
    }
    if s.id == own_session() {
        return own_front();
    }
    hub.and_then(|h| h.front(Principal::Session(s.id))).unwrap_or_else(|| {
        FrontReading::new(
            Front::Unknown,
            format!(
                "unknown: session {}'s foreground window is read only from inside it, and no session helper \
                 reports from there",
                s.id
            ),
        )
    })
}
