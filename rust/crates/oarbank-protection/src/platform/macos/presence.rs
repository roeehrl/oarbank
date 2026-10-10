//! User presence on macOS: the HID system's idle time (keyboard, mouse, trackpad), and a Screen Sharing session
//! (someone using the Mac remotely is present whatever the local keyboard says, unless the node policy's
//! `screen_sharing_present` is off; `presence::hid`).

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
        crate::presence::hid::presence(screen_sharing(), hid_idle_s(), self.screen_sharing_present)
    }

    fn set_screen_sharing_present(&mut self, on: bool) {
        self.screen_sharing_present = on;
    }
}
