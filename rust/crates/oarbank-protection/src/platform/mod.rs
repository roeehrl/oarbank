//! Native backends. macOS reads the process table through libproc and sysctl, code-signing identity
//! through the Security framework, GPU time through IOKit, and acts through signals and `setpriority`.
//! Linux reads procfs, DRM `fdinfo` and systemd-logind; Windows the native process list, the GPU Engine
//! performance counters and the sessions WTS lists. On both, here is an actuator that never registers a
//! process: the agent builds its registry there with its own actuator over its process containers. On every
//! OS a system install's agent learns what its account may not read from the people's session helpers.

use std::sync::Arc;

use crate::controller::Host;
use crate::session::SessionHub;
use crate::signals::{Meter, Presence, PresenceReading};
use crate::events::EventSources;
use crate::sources::FileOwnerSources;
use crate::spawn_registry::Actuator;
use crate::support::Os;
use crate::table::ProcessSource;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_session;
#[cfg(windows)]
pub mod windows;

/// This platform's host interfaces; `hub` carries what the session helpers report (the system service's).
pub fn native_host(hub: Option<Arc<SessionHub>>) -> Host {
    let hub_for_sources = hub.clone();
    #[cfg(target_os = "macos")]
    let (processes, meter): (Box<dyn ProcessSource>, Box<dyn Meter>) = (
        Box::new(macos::NativeProcessSource::new(hub.clone())),
        Box::new(macos::NativeMeter::new(hub)),
    );
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
    // owner sources, event-driven (D51): a system install's paths in a person's home are read by that person's
    // session helper; a second process source drives the fast listing of immediate exec triggers
    let hub = hub_for_sources;
    let files = match &hub {
        Some(h) => FileOwnerSources::system(Some(h.clone() as Arc<dyn crate::sources::PersonReader>)),
        None => FileOwnerSources::new(),
    };
    let sources = EventSources::new(files, None, exec_source(hub.clone()));
    if let Some(h) = &hub {
        h.set_source_hook(sources.helper_hook());
    }
    Host {
        processes,
        meter,
        sources: Box::new(sources),
        os: Os::current(),
    }
}

/// A process source of its own for the event path's exec listing.
fn exec_source(hub: Option<Arc<SessionHub>>) -> Option<Box<dyn ProcessSource>> {
    #[cfg(target_os = "macos")]
    return Some(Box::new(macos::NativeProcessSource::new(hub)));
    #[cfg(target_os = "linux")]
    return Some(Box::new(linux::NativeProcessSource::new(hub)));
    #[cfg(windows)]
    return Some(Box::new(windows::NativeProcessSource::new(windows::Snapshots::shared(), hub)));
    #[allow(unreachable_code)]
    {
        let _ = hub;
        None
    }
}

/// This platform's user-presence interface.
pub fn native_presence(hub: Option<Arc<SessionHub>>) -> Box<dyn Presence> {
    #[cfg(target_os = "macos")]
    return {
        let _ = hub; // the HID system's idle time is anyone's to read
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

/// A transport serving session helpers. Dropping a Unix socket's stops taking connections (those taken go on); a
/// Windows pipe, whose name stays ours, is served for the rest of the process.
pub trait Served: Send {
    /// Can helpers still reach it? A Unix socket whose path was removed (or replaced) cannot be reached any more.
    fn alive(&self) -> bool {
        true
    }
}

/// How long the system service waits to try serving helpers again, and between its checks that they still can reach it.
pub const SERVE_RETRY: std::time::Duration = std::time::Duration::from_secs(15);

/// Where helpers connect: the socket's path, or the pipe's name.
pub fn sessions_at() -> String {
    #[cfg(target_os = "linux")]
    return linux::socket_path().display().to_string();
    #[cfg(target_os = "macos")]
    return macos::socket_path().display().to_string();
    #[cfg(windows)]
    return windows::pipe_name();
    #[allow(unreachable_code)]
    {
        String::new()
    }
}

fn serve_once(hub: Arc<SessionHub>) -> std::io::Result<Box<dyn Served>> {
    #[cfg(target_os = "linux")]
    return linux::serve(hub);
    #[cfg(target_os = "macos")]
    return macos::serve(hub);
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

/// Serve session helpers (the system service) once, for the rest of the process: what they report goes into `hub`.
pub fn serve_sessions(hub: Arc<SessionHub>) -> std::io::Result<()> {
    serve_once(hub).map(std::mem::forget)
}

/// Serve session helpers (the system service) for the rest of the process, whatever stands in the way at first: try
/// now and, while that fails (the socket's directory missing and not ours to make, the pipe's name taken), again every
/// `every`; once serving, check every `every` that helpers can still reach it, and serve again when they cannot. The
/// hub keeps whether it serves and why not (`SessionHub::serving`); `changed` hears each change of that (the first
/// attempt's outcome included, before this returns).
pub fn supervise_sessions(
    hub: Arc<SessionHub>,
    every: std::time::Duration,
    changed: impl Fn(&crate::session::Serving) + Send + 'static,
) {
    let h = hub.clone();
    supervise(hub, sessions_at(), every, move || serve_once(h.clone()), changed);
}

/// `supervise_sessions` over any way to serve (`attempt`), at `at`.
pub(crate) fn supervise<A, C>(hub: Arc<SessionHub>, at: String, every: std::time::Duration, attempt: A, changed: C)
where
    A: FnMut() -> std::io::Result<Box<dyn Served>> + Send + 'static,
    C: Fn(&crate::session::Serving) + Send + 'static,
{
    let mut s = Supervisor { hub: hub.clone(), at: at.clone(), attempt, changed, failures: 0 };
    let mut current = s.serve();
    let spawned = std::thread::Builder::new().name("session-serve".into()).spawn(move || loop {
        std::thread::sleep(every);
        match current.as_ref().map(|x| x.alive()) {
            Some(true) => continue,
            Some(false) => {
                drop(current.take()); // stop the unreachable one before its path is taken again
                let gone = format!("{} was removed", s.at);
                s.record(false, Some(gone));
            }
            None => {}
        }
        current = s.serve();
    });
    if let Err(e) = spawned {
        // the transport went with the thread that would have kept it: nothing serves, and nothing will try again
        let error = Some(format!("cannot keep serving session helpers: {e}"));
        hub.set_serving(crate::session::Serving { at, serving: false, error, failures: 1 });
    }
}

struct Supervisor<A, C> {
    hub: Arc<SessionHub>,
    at: String,
    attempt: A,
    changed: C,
    failures: u64,
}

impl<A, C> Supervisor<A, C>
where
    A: FnMut() -> std::io::Result<Box<dyn Served>>,
    C: Fn(&crate::session::Serving),
{
    fn serve(&mut self) -> Option<Box<dyn Served>> {
        match (self.attempt)() {
            Ok(x) => {
                self.failures = 0;
                self.record(true, None);
                Some(x)
            }
            Err(e) => {
                self.failures += 1;
                self.record(false, Some(e.to_string()));
                None
            }
        }
    }

    fn record(&mut self, serving: bool, error: Option<String>) {
        let s = crate::session::Serving { at: self.at.clone(), serving, error, failures: self.failures };
        if self.hub.set_serving(s.clone()) {
            (self.changed)(&s);
        }
    }
}

/// Run as a session helper (`oarbank-agent session-helper`): never returns on macOS, Linux and Windows.
pub fn run_session_helper() -> std::io::Error {
    #[cfg(target_os = "linux")]
    linux::run_helper();
    #[cfg(target_os = "macos")]
    macos::run_helper();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    struct Fake(Arc<AtomicBool>);

    impl Served for Fake {
        fn alive(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }

    /// On every OS: a transport that cannot be served is tried again until it can (the hub says why not meanwhile,
    /// and how many tries failed), and one helpers can no longer reach is served anew.
    #[test]
    fn helpers_are_served_once_the_transport_allows_and_again_when_it_is_lost() {
        let hub = SessionHub::new();
        let (tries, works, alive) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(true)));
        let (t, w, a) = (tries.clone(), works.clone(), alive.clone());
        supervise(hub.clone(), "here".into(), Duration::from_millis(10), move || {
            t.fetch_add(1, Ordering::Relaxed);
            if w.load(Ordering::Relaxed) {
                a.store(true, Ordering::Relaxed);
                Ok(Box::new(Fake(a.clone())) as Box<dyn Served>)
            } else {
                Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "taken"))
            }
        }, |_| {});
        let until = |what: &dyn Fn() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !what() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            what()
        };
        let s = hub.serving().unwrap();
        assert_eq!((s.at.as_str(), s.serving, s.error.as_deref()), ("here", false, Some("taken")));
        assert!(until(&|| hub.serving().unwrap().failures >= 3));
        works.store(true, Ordering::Relaxed);
        assert!(until(&|| hub.serving().unwrap().serving));
        let n = tries.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(tries.load(Ordering::Relaxed), n, "served: no more tries");
        alive.store(false, Ordering::Relaxed);
        assert!(until(&|| tries.load(Ordering::Relaxed) > n && hub.serving().unwrap().serving));
    }
}
