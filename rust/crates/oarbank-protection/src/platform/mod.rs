//! Native backends. macOS reads the process table through libproc and sysctl, code-signing identity
//! through the Security framework, GPU time through IOKit, and acts through signals and `setpriority`.
//! Linux (DRM `fdinfo`) and Windows (the GPU Engine performance counters) so far only meter GPU time: they
//! report an unsupported process table, and here an actuator that never registers a process; the agent builds
//! its registry there with its own actuator over its process containers.

use crate::controller::Host;
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
    {
        Host {
            processes: Box::new(macos::NativeProcessSource::new()),
            meter: Box::new(macos::NativeMeter::new()),
            sources: Box::new(FileOwnerSources::new()),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(target_os = "linux")]
        let meter = Box::new(linux::NativeMeter::new());
        #[cfg(windows)]
        let meter = Box::new(windows::NativeMeter::new());
        #[cfg(not(any(target_os = "linux", windows)))]
        let meter = Box::new(crate::signals::NullMeter);
        Host {
            processes: Box::new(crate::table::UnsupportedProcessSource),
            meter,
            sources: Box::new(FileOwnerSources::new()),
        }
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
