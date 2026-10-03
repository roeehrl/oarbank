//! Native backends. macOS reads the process table through libproc and sysctl, code-signing identity
//! through the Security framework, GPU time through IOKit, and acts through signals and `setpriority`.
//! Linux reads procfs, DRM `fdinfo` and systemd-logind; Windows the native process list, the GPU Engine
//! performance counters and the sessions WTS lists. On both, here is an actuator that never registers a
//! process: the agent builds its registry there with its own actuator over its process containers.

use crate::controller::Host;
use crate::signals::{Meter, Presence, PresenceReading};
use crate::table::ProcessSource;
use crate::sources::FileOwnerSources;
use crate::spawn_registry::Actuator;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

/// This platform's host interfaces.
pub fn native_host() -> Host {
    #[cfg(target_os = "macos")]
    let (processes, meter): (Box<dyn ProcessSource>, Box<dyn Meter>) =
        (Box::new(macos::NativeProcessSource::new()), Box::new(macos::NativeMeter::new()));
    #[cfg(target_os = "linux")]
    let (processes, meter): (Box<dyn ProcessSource>, Box<dyn Meter>) =
        (Box::new(linux::NativeProcessSource::new()), Box::new(linux::NativeMeter::new()));
    #[cfg(windows)]
    let (processes, meter): (Box<dyn ProcessSource>, Box<dyn Meter>) = {
        let shared = windows::Snapshots::shared();
        (
            Box::new(windows::NativeProcessSource::new(shared.clone())),
            Box::new(windows::NativeMeter::new(shared)),
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    let (processes, meter): (Box<dyn ProcessSource>, Box<dyn Meter>) = (
        Box::new(crate::table::UnsupportedProcessSource),
        Box::new(crate::signals::NullMeter),
    );
    Host {
        processes,
        meter,
        sources: Box::new(FileOwnerSources::new()),
    }
}

/// This platform's user-presence interface.
pub fn native_presence() -> Box<dyn Presence> {
    #[cfg(target_os = "macos")]
    return Box::new(macos::NativePresence::new());
    #[cfg(target_os = "linux")]
    return Box::new(linux::NativePresence::new());
    #[cfg(windows)]
    return Box::new(windows::NativePresence::new());
    #[allow(unreachable_code)]
    Box::new(UnknownPresence)
}

/// Presence on a platform without a backend: unknown, which counts as someone present.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnknownPresence;

impl Presence for UnknownPresence {
    fn read(&mut self) -> PresenceReading {
        PresenceReading::new(None, format!("unknown: no presence backend on {}", std::env::consts::OS))
    }
}

/// This platform's actuator. Crate-private on purpose: only [`crate::SpawnRegistry::native`] holds one, so
/// every native actuation passes the registry's (pid, start time) check.
pub(crate) fn native_actuator() -> Box<dyn Actuator> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::NativeActuator)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Box::new(crate::spawn_registry::UnsupportedActuator)
    }
}
