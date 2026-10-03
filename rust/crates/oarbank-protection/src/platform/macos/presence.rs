//! User presence on macOS: the HID system's idle time (keyboard, mouse, trackpad), and a Screen Sharing session
//! (someone using the Mac remotely is present whatever the local keyboard says).

use super::iokit::{matching_service, property};
use super::{all_pids, cf, path};
use crate::signals::{Presence, PresenceReading};

/// Seconds since the last HID input (IOHIDSystem's HIDIdleTime, nanoseconds).
pub fn hid_idle_s() -> Option<f64> {
    let svc = matching_service(c"IOHIDSystem")?;
    let ns = cf::to_f64(property(svc.0, "HIDIdleTime")?.get())?;
    Some(ns / 1e9)
}

/// A Screen Sharing session is in progress: `screensharingd` runs.
pub fn screen_sharing() -> bool {
    all_pids()
        .into_iter()
        .any(|pid| path(pid).is_some_and(|p| p.ends_with("/screensharingd")))
}

#[derive(Debug, Default)]
pub struct NativePresence;

impl NativePresence {
    pub fn new() -> Self {
        Self
    }
}

impl Presence for NativePresence {
    fn read(&mut self) -> PresenceReading {
        if screen_sharing() {
            return PresenceReading::new(Some(0.0), "screen sharing");
        }
        match hid_idle_s() {
            Some(s) => PresenceReading::new(Some(s), "hid"),
            None => PresenceReading::new(None, "unknown: IOHIDSystem has no HIDIdleTime"),
        }
    }
}
