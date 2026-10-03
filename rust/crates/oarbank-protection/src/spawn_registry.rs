//! The agent's spawned process groups, and the **only** path through which the agent may send a signal or
//! change scheduling policy (S16, generalized). Membership is (pid, start time): before every actuation the
//! target's current start time is read again, so a PID recycled into an owner process is never touched.
//! Every actuation, allowed or refused, is journaled; the S16 checker replays that journal.

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value};

use crate::journal::DecisionJournal;
use crate::json::{opt_int, opt_str};

/// The signals protection sends to fleet groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    Stop,
    Cont,
    Term,
    Kill,
}

impl Signal {
    /// The platform's signal number (journaled as `signal`).
    pub fn raw(self) -> i32 {
        #[cfg(unix)]
        {
            match self {
                Self::Stop => libc::SIGSTOP,
                Self::Cont => libc::SIGCONT,
                Self::Term => libc::SIGTERM,
                Self::Kill => libc::SIGKILL,
            }
        }
        #[cfg(not(unix))]
        {
            match self {
                Self::Stop => 19,
                Self::Cont => 18,
                Self::Term => 15,
                Self::Kill => 9,
            }
        }
    }
}

/// How the registry reads a process's start time and delivers actions. Only the registry holds one, so
/// every call passes the (pid, start time) check first.
pub trait Actuator: Send + Sync {
    /// Start time in microseconds since the epoch, or None if the process is gone or not visible.
    fn start_time(&self, pid: i32) -> Option<u64>;
    /// Signal a whole process group (the leader created it); 0 on success.
    fn signal_group(&self, pgid: i32, sig: Signal) -> i32;
    /// Move a whole group to background scheduling or back; 0 on success. What that is depends on the OS: macOS
    /// background QoS (low priority, efficiency cores), a CPU quota on Linux, the idle priority class and EcoQoS
    /// on Windows.
    fn set_background(&self, pgid: i32, on: bool) -> i32;
}

/// For platforms without a backend yet: no start time is ever readable, so nothing registers or actuates.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedActuator;

impl Actuator for UnsupportedActuator {
    fn start_time(&self, _: i32) -> Option<u64> {
        None
    }
    fn signal_group(&self, _: i32, _: Signal) -> i32 {
        -1
    }
    fn set_background(&self, _: i32, _: bool) -> i32 {
        -1
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub attempt_id: Option<i64>,
    pub service: Option<String>,
    /// Process-group leader.
    pub pid: i32,
    pub start_us: u64,
}

/// Persists the registry across agent restarts, so a new instance adopts (and may only signal) groups it
/// spawned.
pub trait RegistryStore: Send {
    fn load(&mut self) -> Vec<Member>;
    fn save(&mut self, members: &[Member]);
}

/// The registry as a JSON array: `[{"pid": 1, "start_us": "123", "attempt": 7, "service": null}]`.
pub struct FileRegistryStore {
    path: PathBuf,
}

impl FileRegistryStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl RegistryStore for FileRegistryStore {
    fn load(&mut self) -> Vec<Member> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return vec![];
        };
        let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&text) else {
            return vec![];
        };
        arr.iter()
            .filter_map(|e| {
                let pid = crate::json::int_of(e.get("pid"))?;
                let start = e.get("start_us")?.as_str()?.parse::<u64>().ok()?;
                Some(Member {
                    attempt_id: crate::json::int_of(e.get("attempt")),
                    service: e.get("service").and_then(Value::as_str).map(str::to_string),
                    pid: i32::try_from(pid).ok()?,
                    start_us: start,
                })
            })
            .collect()
    }

    fn save(&mut self, members: &[Member]) {
        let arr: Vec<Value> = members
            .iter()
            .map(|m| {
                serde_json::json!({"pid": m.pid, "start_us": m.start_us.to_string(), "attempt": opt_int(m.attempt_id),
                                   "service": opt_str(m.service.as_deref())})
            })
            .collect();
        let Ok(text) = serde_json::to_string(&arr) else {
            return;
        };
        // atomic replace: a crash mid-write never leaves a truncated registry
        let tmp = self.path.with_extension("tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotRegistered(i32),
    IdentityChanged(i32),
    Gone(i32),
    /// The group is the agent's, but the OS did not carry the action out.
    Failed(i32),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRegistered(p) => write!(f, "pid {p} is not in the spawn registry"),
            Self::IdentityChanged(p) => write!(f, "pid {p} was reused by another process"),
            Self::Gone(p) => write!(f, "pid {p} is gone"),
            Self::Failed(p) => write!(f, "the OS did not carry out the action on group {p}"),
        }
    }
}

impl std::error::Error for Refusal {}

struct Inner {
    members: HashMap<i32, Member>,
    store: Option<Box<dyn RegistryStore>>,
}

impl Inner {
    fn save(&mut self) {
        let mut ms: Vec<Member> = self.members.values().cloned().collect();
        ms.sort_by_key(|m| m.pid);
        if let Some(s) = self.store.as_mut() {
            s.save(&ms);
        }
    }
}

pub struct SpawnRegistry {
    inner: Mutex<Inner>,
    actuator: Box<dyn Actuator>,
    journal: Option<Arc<DecisionJournal>>,
}

fn detail<const N: usize>(pairs: [(&str, Value); N]) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

impl SpawnRegistry {
    pub fn new(
        actuator: Box<dyn Actuator>,
        journal: Option<Arc<DecisionJournal>>,
        store: Option<Box<dyn RegistryStore>>,
    ) -> Self {
        let mut store = store;
        let members = store
            .as_mut()
            .map(|s| s.load())
            .unwrap_or_default()
            .into_iter()
            .map(|m| (m.pid, m))
            .collect();
        Self {
            inner: Mutex::new(Inner { members, store }),
            actuator,
            journal,
        }
    }

    /// The registry with this platform's actuator (signals, background scheduling).
    pub fn native(
        journal: Option<Arc<DecisionJournal>>,
        store: Option<Box<dyn RegistryStore>>,
    ) -> Self {
        Self::new(crate::platform::native_actuator(), journal, store)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn journal(&self) -> Option<&Arc<DecisionJournal>> {
        self.journal.as_ref()
    }

    /// Adopt a group recorded by a previous instance: (pid, start time) must still match.
    pub fn adopt(&self, pid: i32, start_us: u64, attempt_id: Option<i64>) -> bool {
        if self.actuator.start_time(pid) != Some(start_us) {
            return false;
        }
        let mut g = self.lock();
        g.members.insert(
            pid,
            Member {
                attempt_id,
                service: None,
                pid,
                start_us,
            },
        );
        g.save();
        true
    }

    /// Forget members whose process is gone or whose PID now belongs to another process.
    pub fn prune(&self) {
        let mut g = self.lock();
        let before = g.members.len();
        let act = &self.actuator;
        g.members
            .retain(|pid, m| act.start_time(*pid) == Some(m.start_us));
        if g.members.len() != before {
            g.save();
        }
    }

    /// Record a freshly spawned group leader. Returns false if its start time cannot be read (it already
    /// exited): such a process is never actuated.
    pub fn register(&self, pid: i32, attempt_id: Option<i64>, service: Option<&str>) -> bool {
        let Some(start_us) = self.actuator.start_time(pid) else {
            return false;
        };
        let mut g = self.lock();
        g.members.insert(
            pid,
            Member {
                attempt_id,
                service: service.map(str::to_string),
                pid,
                start_us,
            },
        );
        g.save();
        true
    }

    pub fn unregister(&self, pid: i32) {
        let mut g = self.lock();
        g.members.remove(&pid);
        g.save();
    }

    pub fn member(&self, attempt_id: i64) -> Option<Member> {
        self.lock()
            .members
            .values()
            .find(|m| m.attempt_id == Some(attempt_id))
            .cloned()
    }

    pub fn all(&self) -> Vec<Member> {
        let mut v: Vec<Member> = self.lock().members.values().cloned().collect();
        v.sort_by_key(|m| m.pid);
        v
    }

    fn verify(&self, pid: i32) -> Result<Member, Refusal> {
        let m = self
            .lock()
            .members
            .get(&pid)
            .cloned()
            .ok_or(Refusal::NotRegistered(pid))?;
        let now = self.actuator.start_time(pid).ok_or(Refusal::Gone(pid))?;
        if now != m.start_us {
            return Err(Refusal::IdentityChanged(pid));
        }
        Ok(m)
    }

    fn journal_record(&self, kind: &str, reason: &str, d: Map<String, Value>) {
        if let Some(j) = &self.journal {
            j.record(kind, reason, None, d);
        }
    }

    /// Signal a registered group. Refuses anything else, and journals the attempt either way.
    pub fn signal(&self, pid: i32, sig: Signal, reason: &str) -> Result<(), Refusal> {
        match self.verify(pid) {
            Err(e) => {
                self.journal_record(
                    "actuation_refused",
                    "S16_GUARD",
                    detail([
                        ("pid", Value::from(pid)),
                        ("signal", Value::from(sig.raw())),
                        ("why", Value::from(e.to_string())),
                        ("for", Value::from(reason)),
                    ]),
                );
                Err(e)
            }
            Ok(m) => {
                let ok = self.actuator.signal_group(pid, sig) == 0;
                self.journal_record(
                    "actuation",
                    reason,
                    detail([
                        ("pid", Value::from(pid)),
                        ("start_us", Value::from(m.start_us.to_string())),
                        ("signal", Value::from(sig.raw())),
                        ("attempt", opt_int(m.attempt_id)),
                        ("service", opt_str(m.service.as_deref())),
                        ("ok", Value::from(ok)),
                    ]),
                );
                if ok {
                    Ok(())
                } else {
                    Err(Refusal::Failed(pid))
                }
            }
        }
    }

    /// Move a registered group to background scheduling or back (see [`Actuator::set_background`]).
    pub fn set_background(&self, pid: i32, on: bool, reason: &str) -> Result<(), Refusal> {
        let policy = if on { "background" } else { "default" };
        match self.verify(pid) {
            Err(e) => {
                self.journal_record(
                    "actuation_refused",
                    "S16_GUARD",
                    detail([
                        ("pid", Value::from(pid)),
                        ("policy", Value::from(policy)),
                        ("why", Value::from(e.to_string())),
                    ]),
                );
                Err(e)
            }
            Ok(m) => {
                let ok = self.actuator.set_background(pid, on) == 0;
                self.journal_record(
                    "actuation",
                    reason,
                    detail([
                        ("pid", Value::from(pid)),
                        ("start_us", Value::from(m.start_us.to_string())),
                        ("policy", Value::from(policy)),
                        ("attempt", opt_int(m.attempt_id)),
                        ("ok", Value::from(ok)),
                    ]),
                );
                if ok {
                    Ok(())
                } else {
                    Err(Refusal::Failed(pid))
                }
            }
        }
    }
}
