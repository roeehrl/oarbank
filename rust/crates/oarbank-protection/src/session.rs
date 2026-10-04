//! The session helper: the agent's binary run as a person in their session (`oarbank-agent session-helper`),
//! telling the system service what only that person may read: their processes' paths and arguments (on Linux
//! their GPU use, on macOS their CPU, memory and scheduler counters), what is in front on their display, and their
//! last input. The system service checks every claim against what it reads itself (the process belongs to the
//! helper's account or session and started when the claim says), forgets a helper ten seconds after its last
//! report, and otherwise keeps to the fail-safe defaults. A helper can only describe its own person's work.
//!
//! The wire format is one JSON report per line, every two seconds. This module holds the format and the
//! service's view of the reports; the platforms carry them (a Unix socket on Linux and macOS, a named pipe on
//! Windows) and prove who sent them (the peer's uid, the client's session).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::signals::{Front, FrontReading, ProcCounters};

pub const PROTOCOL: u32 = 2;
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

/// One process's resource use as its helper read it (macOS, where only the process's own account may read it):
/// cumulative counters and the footprint now.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Usage {
    pub pid: i32,
    pub start_us: u64,
    pub counters: ProcCounters,
    pub footprint_gb: f64,
}

impl Usage {
    /// The reading a fraction `f` of the way from `self` to `b`.
    fn lerp(&self, b: &Usage, f: f64) -> Usage {
        let (x, y) = (self.counters, b.counters);
        let at = |a: f64, b: f64| a + (b - a) * f;
        Usage {
            counters: ProcCounters {
                cpu_s: at(x.cpu_s, y.cpu_s),
                runnable_s: at(x.runnable_s, y.runnable_s),
                instructions: at(x.instructions, y.instructions),
                cycles: at(x.cycles, y.cycles),
                pageins: at(x.pageins, y.pageins),
            },
            footprint_gb: at(self.footprint_gb, b.footprint_gb),
            ..*b
        }
    }

    fn is_valid(&self) -> bool {
        let c = self.counters;
        [
            c.cpu_s,
            c.runnable_s,
            c.instructions,
            c.cycles,
            c.pageins,
            self.footprint_gb,
        ]
        .iter()
        .all(|x| x.is_finite() && *x >= 0.0)
    }
}

/// A process's last few usage readings, by when they arrived, read back as of one report interval ago: between two
/// readings the values are interpolated, so the rates the controller takes from them (over its own ticks) never
/// jump with the timing of the reports, and they are never extrapolated.
#[derive(Debug, Default)]
struct Track(VecDeque<(Instant, Usage)>);

impl Track {
    const KEEP: usize = 3;

    fn push(&mut self, at: Instant, u: Usage) {
        if self
            .0
            .back()
            .is_some_and(|(_, last)| last.start_us != u.start_us)
        {
            self.0.clear(); // the pid was reused
        }
        if self.0.len() == Self::KEEP {
            self.0.pop_front();
        }
        self.0.push_back((at, u));
    }

    fn at(&self, t: Instant) -> Option<Usage> {
        let (first, last) = (self.0.front()?, self.0.back()?);
        if t <= first.0 {
            return Some(first.1);
        }
        if t >= last.0 {
            return Some(last.1);
        }
        let (a, b) = self
            .0
            .iter()
            .zip(self.0.iter().skip(1))
            .find(|(_, b)| t < b.0)?;
        let f = (t - a.0).as_secs_f64() / (b.0 - a.0).as_secs_f64();
        Some(a.1.lerp(&b.1, f))
    }
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
    /// Every live process's resource use (macOS, where only the process's own account may read it).
    pub usage: Vec<Usage>,
}

/// Who a helper speaks for, as the transport proved it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Principal {
    /// A Linux or macOS account (the Unix socket peer's uid).
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
    usage: HashMap<i32, Track>,
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
        self.accept_at(Instant::now(), who, r, owns);
    }

    fn accept_at(&self, now: Instant, who: Principal, r: Report, owns: impl Fn(i32, u64) -> bool) {
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
            usage: HashMap::new(),
        });
        e.at = now;
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
        // usage of the processes described (and so checked) on this connection, still running
        e.usage.retain(|pid, t| {
            t.0.back()
                .is_some_and(|(_, u)| live.contains(&(*pid, u.start_us)))
        });
        for u in r.usage {
            if u.is_valid() && e.procs.contains_key(&(u.pid, u.start_us)) {
                e.usage.entry(u.pid).or_default().push(now, u);
            }
        }
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

    /// A process's resource use as its helper read it, as of one report interval ago (see [`Track`]).
    pub fn usage(&self, pid: i32) -> Option<Usage> {
        let now = Instant::now();
        self.usage_at(pid, now.checked_sub(INTERVAL).unwrap_or(now))
    }

    fn usage_at(&self, pid: i32, t: Instant) -> Option<Usage> {
        self.fresh(|e| e.values().find_map(|x| x.usage.get(&pid)?.at(t)))
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
            usage: vec![usage(10, 1000, 1.5, 0.25)],
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
                usage: vec![usage(10, 1000, 2.0, 0.5), usage(20, 5, 9.0, 9.0)],
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
        assert_eq!(hub.usage(10).unwrap().counters.cpu_s, 2.0);
        assert_eq!(hub.usage(20), None, "usage of a process not hers");
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
        assert_eq!(hub.usage(10), None, "an ended process's usage goes with it");
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

    fn usage(pid: i32, start_us: u64, cpu_s: f64, footprint_gb: f64) -> Usage {
        Usage {
            pid,
            start_us,
            counters: ProcCounters {
                cpu_s,
                runnable_s: cpu_s * 2.0,
                instructions: cpu_s * 1e9,
                cycles: cpu_s * 2e9,
                pageins: 0.0,
            },
            footprint_gb,
        }
    }

    /// Usage is read as of one interval ago, interpolated between reports, so a rate over the service's own ticks
    /// is the helper's whatever the reports' timing; it is never extrapolated past the last report.
    #[test]
    fn usage_is_interpolated_between_reports_and_never_extrapolated() {
        let hub = SessionHub::new();
        let ada = Principal::Uid(1000);
        let t0 = Instant::now();
        let at = |s: f64| t0 + Duration::from_secs_f64(s);
        let report = |cpu_s: f64, footprint_gb: f64| Report {
            v: PROTOCOL,
            live: vec![(10, 1000)],
            procs: vec![claim(10, 1000, "/opt/a")],
            usage: vec![usage(10, 1000, cpu_s, footprint_gb)],
            ..Report::default()
        };
        // a process busy on one core, reported at uneven times
        for (t, cpu) in [(0.0, 100.0), (1.5, 101.5), (4.0, 104.0)] {
            hub.accept_at(at(t), ada, report(cpu, 1.0 + t), |_, _| true);
        }
        let cpu = |t: f64| hub.usage_at(10, at(t)).unwrap().counters.cpu_s;
        assert!((cpu(0.75) - 100.75).abs() < 1e-9);
        assert!((cpu(3.0) - 103.0).abs() < 1e-9);
        assert!(
            (cpu(3.0) - cpu(1.0) - 2.0).abs() < 1e-9,
            "one core over two seconds"
        );
        let u = hub.usage_at(10, at(2.75)).unwrap();
        assert!((u.footprint_gb - 3.75).abs() < 1e-9 && u.start_us == 1000);
        assert_eq!(cpu(9.0), 104.0, "after the last report: the last report");
        // the oldest of more than three readings is forgotten: before the oldest kept, the oldest kept
        hub.accept_at(at(6.0), ada, report(106.0, 1.0), |_, _| true);
        assert_eq!(cpu(0.5), 101.5);
        // a reused pid starts a new track; readings that are no numbers are dropped
        let mut r = report(5.0, 1.0);
        r.live = vec![(10, 7000)];
        r.procs = vec![claim(10, 7000, "/opt/b")];
        r.usage = vec![usage(10, 7000, 5.0, 1.0)];
        hub.accept_at(at(7.0), ada, r.clone(), |_, _| true);
        assert_eq!(hub.usage_at(10, at(6.5)).unwrap().start_us, 7000);
        r.usage = vec![usage(10, 7000, f64::NAN, 1.0), usage(10, 7000, 6.0, -1.0)];
        hub.accept_at(at(8.0), ada, r, |_, _| true);
        assert_eq!(cpu(9.0), 5.0);
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
