//! User presence on macOS: the HID system's idle time (keyboard, mouse, trackpad), and a Screen Sharing viewer
//! (someone watching the Mac remotely is present whatever the keyboard says, unless the node policy's
//! `screen_sharing_present` is off; `presence::hid`).

use std::process::{Command, Stdio};

use super::iokit::{matching_service, property};
use super::{all_pids, cf, path};
use crate::presence::hid::{established, ScreenSharing};
use crate::signals::{Presence, PresenceReading};

/// Seconds since the last HID input (IOHIDSystem's HIDIdleTime, nanoseconds).
pub fn hid_idle_s() -> Option<f64> {
    let svc = matching_service(c"IOHIDSystem")?;
    let ns = cf::to_f64(property(svc.0, "HIDIdleTime")?.get())?;
    Some(ns / 1e9)
}

/// Whether a Screen Sharing viewer is connected: an established TCP connection of `screensharingd`. The daemon
/// running is not enough: launchd starts it for a session and it
/// can stay running, listening on port 5900, after the viewer leaves.
/// Its sockets are read with `netstat` (the kernel's socket list, which the unprivileged system service may read;
/// the daemon's own file descriptors are root's). macOS hides other processes' internet sockets from a process
/// that Local Network privacy applies to and has not been allowed (the personal scope's LaunchAgent before its
/// owner allows it, a test binary run from a terminal; never a launchd daemon or root): netstat then lists no TCP
/// socket at all, and whether a viewer is connected is unknown.
pub fn screen_sharing() -> ScreenSharing {
    let pids: Vec<i32> = all_pids()
        .into_iter()
        .filter(|pid| path(*pid).is_some_and(|p| p.ends_with("/screensharingd")))
        .collect();
    if pids.is_empty() {
        return ScreenSharing::Off;
    }
    let out = Command::new("/usr/sbin/netstat")
        .args(["-anv", "-p", "tcp"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            match established(&String::from_utf8_lossy(&o.stdout), &pids) {
                Some(n) => ScreenSharing::Viewers(n),
                None => ScreenSharing::Unknown(
                    "netstat lists no TCP socket with its process: Local Network privacy hides them from this process"
                        .into(),
                ),
            }
        }
        Ok(o) => ScreenSharing::Unknown(format!("netstat failed: {}", o.status)),
        Err(e) => ScreenSharing::Unknown(format!("netstat: {e}")),
    }
}

#[derive(Debug)]
pub struct NativePresence {
    screen_sharing_present: bool,
}

impl Default for NativePresence {
    fn default() -> Self {
        Self::new()
    }
}

impl NativePresence {
    pub fn new() -> Self {
        Self {
            screen_sharing_present: true,
        }
    }
}

impl Presence for NativePresence {
    fn read(&mut self) -> PresenceReading {
        crate::presence::hid::presence(&screen_sharing(), hid_idle_s(), self.screen_sharing_present)
    }

    fn set_screen_sharing_present(&mut self, on: bool) {
        self.screen_sharing_present = on;
    }
}
