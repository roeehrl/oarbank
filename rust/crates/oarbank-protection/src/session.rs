//! The session helper: the agent's binary run as a person in their session (`oarbank-agent session-helper`),
//! telling the system service what only that person may read: their processes' paths and arguments (and, on
//! Linux, GPU use), what is in front on their display, and their last input. The system service checks every
//! claim against what it reads itself (the process belongs to the helper's account or session and started when
//! the claim says), forgets a helper ten seconds after its last report, and otherwise keeps to the fail-safe
//! defaults. A helper can only describe its own person's work, and that only ever restricts the fleet.
//!
//! The wire format is one JSON report per line, every two seconds. This module holds the format and the
//! service's view of the reports; the platforms carry them (a Unix socket on Linux, a named pipe on Windows) and
//! prove who sent them (the peer's uid, the client's session).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::signals::{Front, FrontReading};

pub const PROTOCOL: u32 = 1;
/// How often a helper reports.
pub const INTERVAL: Duration = Duration::from_secs(2);
/// A helper silent this long is gone.
pub const STALE: Duration = Duration::from_secs(10);
/// The longest report line a service reads.
pub const MAX_LINE: usize = 8 << 20;

/// One process a helper describes (the first time it reports it on a connection).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcClaim {
    pub pid: i32,
    pub start_us: u64,
    pub path: Option<String>,
    pub argv: Option<Vec<String>>,
}

/// What is in front on the helper's display.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrontClaim {
    /// "app", "nothing" or "unknown"
    pub kind: String,
    pub pid: Option<i32>,
    pub source: String,
}

impl FrontClaim {
    pub fn of(r: &FrontReading) -> Self {
        let (kind, pid) = match r.front {
            Front::App(p) => ("app", Some(p)),
            Front::Nothing => ("nothing", None),
            Front::Unknown => ("unknown", None),
        };
        Self {
            kind: kind.into(),
            pid,
            source: r.source.clone(),
        }
    }

    fn reading(&self) -> Option<FrontReading> {
        let front = match (self.kind.as_str(), self.pid) {
            ("app", Some(p)) if p > 0 => Front::App(p),
            ("nothing", _) => Front::Nothing,
            ("unknown", _) => Front::Unknown,
            _ => return None,
        };
        Some(FrontReading::new(
            front,
            format!("session helper: {}", self.source),
        ))
    }
}

/// One report.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub v: u32,
    /// Every process of the helper's person that is running, as (pid, start time).
    pub live: Vec<(i32, u64)>,
    /// The ones not described before on this connection.
    pub procs: Vec<ProcClaim>,
    /// Seconds since the person's last input, where the helper reads it (Windows).
    pub idle_s: Option<f64>,
    pub front: Option<FrontClaim>,
    /// GPU busy fractions of the person's processes over the helper's last interval, and those whose use it
    /// cannot read (Linux, where only the process's own account may read its open files).
    pub gpu_busy: HashMap<i32, f64>,
    pub gpu_unknown: Vec<i32>,
}

/// Who a helper speaks for, as the transport proved it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Principal {
    /// A Linux account (the Unix socket peer's uid).
    Uid(u32),
    /// A Windows session (the pipe client's session id).
    Session(u32),
}

#[derive(Debug)]
struct Entry {
    at: Instant,
    procs: HashMap<(i32, u64), ProcClaim>,
    idle_s: Option<f64>,
    front: Option<FrontReading>,
    gpu_busy: HashMap<i32, f64>,
    gpu_unknown: HashSet<i32>,
}

/// The system service's view of its helpers' reports.
#[derive(Debug, Default)]
pub struct SessionHub {
    entries: Mutex<HashMap<Principal, Entry>>,
}

impl SessionHub {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn fresh<T>(&self, f: impl FnOnce(&HashMap<Principal, Entry>) -> T) -> T {
        let mut e = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        e.retain(|_, x| x.at.elapsed() < STALE);
        f(&e)
    }

    /// Take a report from `who`. `owns(pid, start_us)` says whether that process belongs to `who` (the platform's
    /// own reading; a start time of 0 asks only about the pid); every claim about another process is dropped.
    pub fn accept(&self, who: Principal, r: Report, owns: impl Fn(i32, u64) -> bool) {
        if r.v != PROTOCOL {
            return;
        }
        let mut all = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let e = all.entry(who).or_insert_with(|| Entry {
            at: Instant::now(),
            procs: HashMap::new(),
            idle_s: None,
            front: None,
            gpu_busy: HashMap::new(),
            gpu_unknown: HashSet::new(),
        });
        e.at = Instant::now();
        let live: HashSet<(i32, u64)> = r.live.into_iter().collect();
        e.procs.retain(|k, _| live.contains(k));
        for p in r.procs {
            let key = (p.pid, p.start_us);
            if live.contains(&key) && owns(p.pid, p.start_us) {
                e.procs.insert(key, p);
            }
        }
        e.idle_s = r.idle_s.filter(|s| s.is_finite() && *s >= 0.0);
        e.front = r
            .front
            .and_then(|f| f.reading())
            .filter(|f| f.front.app().is_none_or(|p| owns(p, 0)));
        e.gpu_busy = r
            .gpu_busy
            .into_iter()
            .filter(|(p, b)| b.is_finite() && *b >= 0.0 && owns(*p, 0))
            .collect();
        e.gpu_unknown = r.gpu_unknown.into_iter().filter(|p| owns(*p, 0)).collect();
    }

    /// A helper's connection ended.
    pub fn gone(&self, who: Principal) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&who);
    }

    /// What a helper said about a process.
    pub fn identity(&self, pid: i32, start_us: u64) -> Option<ProcClaim> {
        self.fresh(|e| {
            e.values()
                .find_map(|x| x.procs.get(&(pid, start_us)))
                .cloned()
        })
    }

    pub fn front(&self, who: Principal) -> Option<FrontReading> {
        self.fresh(|e| e.get(&who).and_then(|x| x.front.clone()))
    }

    pub fn idle_s(&self, who: Principal) -> Option<f64> {
        self.fresh(|e| e.get(&who).and_then(|x| x.idle_s))
    }

    /// Everyone a helper speaks for now.
    pub fn principals(&self) -> Vec<Principal> {
        self.fresh(|e| e.keys().copied().collect())
    }

    /// A process's GPU busy fraction as its helper read it: Some(Some(b)) known, Some(None) unreadable there too,
    /// None when no helper speaks for it.
    pub fn gpu_busy(&self, pid: i32) -> Option<Option<f64>> {
        self.fresh(|e| {
            e.values().find_map(|x| {
                if x.gpu_unknown.contains(&pid) {
                    Some(None)
                } else {
                    x.gpu_busy.get(&pid).map(|b| Some(*b))
                }
            })
        })
    }
}

/// The helper's side: which processes it has described on the current connection.
#[derive(Debug, Default)]
pub struct Described(HashSet<(i32, u64)>);

impl Described {
    /// Keep only the processes still running, and say whether one is new.
    pub fn is_new(&mut self, key: (i32, u64)) -> bool {
        self.0.insert(key)
    }

    pub fn retain_live(&mut self, live: &[(i32, u64)]) {
        let live: HashSet<&(i32, u64)> = live.iter().collect();
        self.0.retain(|k| live.contains(k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(pid: i32, start_us: u64, path: &str) -> ProcClaim {
        ProcClaim {
            pid,
            start_us,
            path: Some(path.into()),
            argv: Some(vec![path.into(), "--x".into()]),
        }
    }

    #[test]
    fn the_wire_format_round_trips() {
        let r = Report {
            v: PROTOCOL,
            live: vec![(10, 1000)],
            procs: vec![claim(10, 1000, "/opt/a")],
            idle_s: Some(3.5),
            front: Some(FrontClaim::of(&FrontReading::new(Front::App(10), "x11 :0"))),
            gpu_busy: HashMap::from([(10, 0.25)]),
            gpu_unknown: vec![11],
        };
        let line = serde_json::to_string(&r).unwrap();
        assert!(!line.contains('\n'));
        assert_eq!(serde_json::from_str::<Report>(&line).unwrap(), r);
    }

    #[test]
    fn claims_about_other_people_s_processes_are_dropped() {
        let hub = SessionHub::new();
        let ada = Principal::Uid(1000);
        // ada's helper describes her process 10 and, falsely, process 20 (root's) and 30 (started at another time)
        let owns = |pid: i32, start: u64| {
            pid == 10 && (start == 0 || start == 1000) || pid == 30 && start == 0
        };
        hub.accept(
            ada,
            Report {
                v: PROTOCOL,
                live: vec![(10, 1000), (20, 5), (30, 7)],
                procs: vec![
                    claim(10, 1000, "/opt/a"),
                    claim(20, 5, "/sbin/x"),
                    claim(30, 7, "/y"),
                ],
                idle_s: Some(-1.0),
                front: Some(FrontClaim {
                    kind: "app".into(),
                    pid: Some(20),
                    source: "x11 :0".into(),
                }),
                gpu_busy: HashMap::from([(10, 0.5), (20, 0.9)]),
                gpu_unknown: vec![20],
            },
            owns,
        );
        assert_eq!(
            hub.identity(10, 1000).unwrap().path.as_deref(),
            Some("/opt/a")
        );
        assert_eq!(hub.identity(20, 5), None);
        assert_eq!(hub.identity(30, 7), None);
        assert_eq!(hub.front(ada), None, "the front pid is not hers");
        assert_eq!(hub.idle_s(ada), None, "a negative idle time is no reading");
        assert_eq!(
            (hub.gpu_busy(10), hub.gpu_busy(20)),
            (Some(Some(0.5)), None)
        );
        assert_eq!(hub.principals(), [ada]);
        // the next report: process 10 ended, 12 is new; its front is her own app
        hub.accept(
            ada,
            Report {
                v: PROTOCOL,
                live: vec![(12, 2000)],
                procs: vec![claim(12, 2000, "/opt/b")],
                front: Some(FrontClaim {
                    kind: "app".into(),
                    pid: Some(12),
                    source: "x11 :0".into(),
                }),
                ..Report::default()
            },
            |pid, _| pid == 12,
        );
        assert_eq!(hub.identity(10, 1000), None);
        assert!(hub.identity(12, 2000).is_some());
        assert_eq!(hub.front(ada).unwrap().front, Front::App(12));
        assert!(hub
            .front(ada)
            .unwrap()
            .source
            .starts_with("session helper: "));
        // another protocol version is ignored; a closed connection forgets everything
        hub.accept(
            ada,
            Report {
                v: 99,
                ..Report::default()
            },
            |_, _| true,
        );
        assert!(hub.identity(12, 2000).is_some());
        hub.gone(ada);
        assert_eq!(hub.identity(12, 2000), None);
        assert!(hub.principals().is_empty());
    }

    #[test]
    fn the_helper_describes_each_process_once_a_connection() {
        let mut d = Described::default();
        assert!(d.is_new((1, 10)));
        assert!(!d.is_new((1, 10)));
        d.retain_live(&[(2, 20)]);
        assert!(
            d.is_new((1, 10)),
            "a process seen again after it was dropped is described again"
        );
    }
}
