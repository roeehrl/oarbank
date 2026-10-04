//! Native backends. macOS reads the process table through libproc and sysctl, code-signing identity
//! through the Security framework, GPU time through IOKit, and acts through signals and `setpriority`.
//! Linux reads procfs, DRM `fdinfo` and systemd-logind; Windows the native process list, the GPU Engine
//! performance counters and the sessions WTS lists. On both, here is an actuator that never registers a
//! process: the agent builds its registry there with its own actuator over its process containers.

use std::sync::Arc;

use crate::controller::Host;
use crate::session::SessionHub;
use crate::signals::{Meter, Presence, PresenceReading};
use crate::sources::FileOwnerSources;
use crate::spawn_registry::Actuator;
use crate::support::Os;
use crate::table::ProcessSource;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

/// This platform's host interfaces; `hub` carries what the session helpers report (the system service's).
pub fn native_host(hub: Option<Arc<SessionHub>>) -> Host {
    #[cfg(target_os = "macos")]
    let (processes, meter): (Box<dyn ProcessSource>, Box<dyn Meter>) = {
        let _ = hub;
        (
            Box::new(macos::NativeProcessSource::new()),
            Box::new(macos::NativeMeter::new()),
        )
    };
    #[cfg(target_os = "linux")]
    let (processes, meter): (Box<dyn ProcessSource>, Box<dyn Meter>) = (
        Box::new(linux::NativeProcessSource::new(hub.clone())),
        Box::new(linux::NativeMeter::new(hub)),
    );
    #[cfg(windows)]
    let (processes, meter): (Box<dyn ProcessSource>, Box<dyn Meter>) = {
        let shared = windows::Snapshots::shared();
        (
            Box::new(windows::NativeProcessSource::new(
                shared.clone(),
                hub.clone(),
            )),
            Box::new(windows::NativeMeter::new(shared, hub)),
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    let (processes, meter): (Box<dyn ProcessSource>, Box<dyn Meter>) = {
        let _ = hub;
        (
            Box::new(crate::table::UnsupportedProcessSource),
            Box::new(crate::signals::NullMeter),
        )
    };
    Host {
        processes,
        meter,
        sources: Box::new(FileOwnerSources::new()),
        os: Os::current(),
    }
}

/// This platform's user-presence interface.
pub fn native_presence(hub: Option<Arc<SessionHub>>) -> Box<dyn Presence> {
    #[cfg(target_os = "macos")]
    return {
        let _ = hub;
        Box::new(macos::NativePresence::new())
    };
    #[cfg(target_os = "linux")]
    return {
        let _ = hub; // logind tells every session's idle time to any account
        Box::new(linux::NativePresence::new())
    };
    #[cfg(windows)]
    return Box::new(windows::NativePresence::new(hub));
    #[allow(unreachable_code)]
    {
        let _ = hub;
        Box::new(UnknownPresence)
    }
}

/// Serve session helpers (the system service on Linux and Windows): what they report goes into `hub`.
pub fn serve_sessions(hub: Arc<SessionHub>) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    return linux::serve(hub);
    #[cfg(windows)]
    return windows::serve(hub);
    #[allow(unreachable_code)]
    {
        let _ = hub;
        Err(std::io::Error::other(format!(
            "no session helpers on {}",
            std::env::consts::OS
        )))
    }
}

/// Run as a session helper (`oarbank-agent session-helper`): never returns on Linux and Windows.
pub fn run_session_helper() -> std::io::Error {
    #[cfg(target_os = "linux")]
    linux::run_helper();
    #[cfg(windows)]
    windows::run_helper();
    #[allow(unreachable_code)]
    std::io::Error::other(format!("no session helper on {}", std::env::consts::OS))
}

/// Presence on a platform without a backend: unknown, which counts as someone present.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnknownPresence;

impl Presence for UnknownPresence {
    fn read(&mut self) -> PresenceReading {
        PresenceReading::new(
            None,
            format!("unknown: no presence backend on {}", std::env::consts::OS),
        )
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
