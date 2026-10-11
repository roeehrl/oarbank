//! The event path (D51): owner sources watched instead of polled, and an out-of-band reaction for rules marked
//! `immediate = true`. A source change wakes the watcher thread; it re-reads only the phases the change can touch
//! and, when an immediate rule's phase turns on, asks the agent's [`FastPath`] to pause the fleet work the phase
//! covers at once, without waiting for the next two-second tick. The tick still does everything else (caps,
//! lowering, releases, the dynamic layer) and reads every source itself, so a missed event costs at most a tick.
//!
//! The event path only ever adds a pause (the fail-safe direction); the phase's exit is applied by the next tick.
//! Every phase change is journaled (`phase_change`), with the time the change was seen, so the coordinator can
//! check S25 (an immediate rule's pause request follows its source event within 100 ms).
//!
//! Process triggers (`on_exec`) are evaluated on the tick from the process table and, for immediate rules, by a
//! 250 ms process listing on the same thread: kqueue's `EVFILT_PROC` watches only known pids, the Linux proc
//! connector needs `CAP_NET_ADMIN`, and Windows' process events arrive on a one-second ETW flush, so a fast listing
//! is the quickest portable signal.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::config::{ProtectionConfig, ProtectionRule, ProtectionScope};
use crate::journal::DecisionJournal;
use crate::json::{obj, rounded};
use crate::matcher;
use crate::sources::{wall_now, FileOwnerSources, OwnerSources, PhaseReport, Progress};
use crate::table::{ProcessSource, ProcessTable};
use crate::watch::Watcher;

/// An immediate phase that just turned on, as the agent's fast path receives it.
#[derive(Debug, Clone, PartialEq)]
pub struct PhaseHit {
    /// `<rule id>#<n>`.
    pub key: String,
    pub rule: String,
    pub block: usize,
    /// The block's `pause_fleet` scope (None: it pauses nothing; its caps wait for the tick).
    pub pause: Option<ProtectionScope>,
    /// When the change was seen (wall clock): the watcher's wake, the helper's, or the process listing's.
    pub event_t: f64,
    /// `watch`, `helper` or `exec`.
    pub via: &'static str,
}

/// The agent's side of the event path: pause what an immediate phase covers, now.
pub trait FastPath: Send + Sync {
    /// Act on a phase that turned on; returns how many units of fleet work it asked to pause.
    fn phase_on(&self, hit: &PhaseHit) -> usize;
}

/// The latencies the event path measured (source event to pause request sent), last 1000.
#[derive(Debug, Default)]
pub struct Latency(VecDeque<f64>);

impl Latency {
    pub fn push(&mut self, ms: f64) {
        if self.0.len() == 1000 {
            self.0.pop_front();
        }
        self.0.push_back(ms.max(0.0));
    }

    pub fn to_json(&self) -> Value {
        let mut v: Vec<f64> = self.0.iter().copied().collect();
        if v.is_empty() {
            return json!({"n": 0});
        }
        v.sort_by(|a, b| a.total_cmp(b));
        let q = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
        let edges = [1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 250.0, 1000.0];
        let mut buckets = vec![0u64; edges.len() + 1];
        for x in &v {
            let i = edges.iter().position(|e| x <= e).unwrap_or(edges.len());
            buckets[i] += 1;
        }
        json!({"n": v.len(), "p50_ms": rounded(q(0.5), 2), "p99_ms": rounded(q(0.99), 2),
               "max_ms": rounded(*v.last().unwrap(), 2), "edges_ms": edges, "buckets": buckets})
    }
}

struct Shared {
    files: FileOwnerSources,
    /// Immediate blocks by key: their pause scope.
    immediate: HashMap<String, (String, usize, Option<ProtectionScope>)>,
    /// Immediate process triggers by key.
    exec: Vec<(String, ProtectionRule, usize)>,
    armed: BTreeSet<String>,
    fleet_pids: HashSet<i32>,
    fast: Option<Arc<dyn FastPath>>,
    journal: Option<Arc<DecisionJournal>>,
    latency: Latency,
    /// The exec triggers' last state (the fast listing's).
    exec_on: HashMap<String, bool>,
}

impl Shared {
    fn journal(&self, kind: &str, reason: &str, rule: &str, detail: serde_json::Map<String, Value>) {
        if let Some(j) = &self.journal {
            j.record(kind, reason, Some(rule), detail);
        }
    }

    /// A phase changed (seen by the tick or the event path): journal it, and act at once when it is immediate.
    fn changed(&mut self, key: &str, on: bool, event_t: f64, via: &'static str) {
        let Some(b) = self.files.blocks.get(key).cloned() else { return };
        let mut d = obj([
            ("block", Value::from(b.block)),
            ("on", Value::from(on)),
            ("event_t", rounded(event_t, 4)),
            ("via", Value::from(via)),
        ]);
        if !b.tags.is_empty() {
            d.insert("tags".into(), Value::from(b.tags.clone()));
        }
        self.journal("phase_change", if on { "PROTECTION_PHASE_ON" } else { "PROTECTION_PHASE_OFF" }, &b.rule, d);
        if !on || !self.armed.contains(&b.rule) {
            return;
        }
        let Some((rule, block, pause)) = self.immediate.get(key).cloned() else { return };
        let hit = PhaseHit { key: key.to_string(), rule, block, pause, event_t, via };
        if let Some(f) = self.fast.clone() {
            if pause.is_some() && f.phase_on(&hit) > 0 {
                self.latency.push((wall_now() - event_t) * 1000.0);
            }
        }
    }

    /// The watcher saw these keys' files change.
    fn on_files(&mut self, keys: Vec<String>, t: f64, via: &'static str) {
        for k in keys {
            if let Some((on, changed)) = self.files.repoll_phase(&k, t) {
                if changed {
                    self.changed(&k, on, t, via);
                }
            }
        }
    }
}

/// Owner sources with the event path: [`FileOwnerSources`] behind a lock shared with the watcher thread (and the
/// session hub's report threads, for sources a person's helper reads).
pub struct EventSources {
    shared: Arc<Mutex<Shared>>,
    watcher: Option<Watcher>,
}

fn lock(s: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

impl EventSources {
    /// `files`: the sources (a system install's relays person-read ones through its session hub). `processes`: a
    /// process source of its own for the fast exec listing (None: exec triggers only on the tick).
    pub fn new(
        files: FileOwnerSources,
        journal: Option<Arc<DecisionJournal>>,
        processes: Option<Box<dyn ProcessSource>>,
    ) -> Self {
        let shared = Arc::new(Mutex::new(Shared {
            files,
            immediate: HashMap::new(),
            exec: vec![],
            armed: BTreeSet::new(),
            fleet_pids: HashSet::new(),
            fast: None,
            journal,
            latency: Latency::default(),
            exec_on: HashMap::new(),
        }));
        let s2 = shared.clone();
        let watcher = Watcher::spawn(Box::new(move |keys, t| lock(&s2).on_files(keys, t, "watch"))).ok();
        if let Some(src) = processes {
            let s3 = Arc::downgrade(&shared);
            let _ = std::thread::Builder::new()
                .name("protection-exec".into())
                .spawn(move || exec_loop(s3, src));
        }
        Self { shared, watcher }
    }

    /// The agent's fast path (set once, after the agent built its actuation).
    pub fn set_fast_path(&self, f: Arc<dyn FastPath>) {
        lock(&self.shared).fast = Some(f);
    }

    /// A callback for the session hub: a helper reported that these keys' sources changed at `t`.
    pub fn helper_hook(&self) -> Box<dyn Fn(Vec<String>, f64) + Send + Sync> {
        let s = Arc::downgrade(&self.shared);
        Box::new(move |keys, t| {
            if let Some(s) = s.upgrade() {
                lock(&s).on_files(keys, t, "helper");
            }
        })
    }

    fn rewatch(&self, g: &mut Shared) {
        if let Some(w) = &self.watcher {
            w.set(g.files.agent_paths());
        }
    }
}

/// The 250 ms process listing for immediate exec triggers.
fn exec_loop(shared: std::sync::Weak<Mutex<Shared>>, src: Box<dyn ProcessSource>) {
    let mut table = ProcessTable::new(src);
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let Some(s) = shared.upgrade() else { return };
        let (rules, excluding) = {
            let g = lock(&s);
            let armed: Vec<(String, ProtectionRule, usize)> =
                g.exec.iter().filter(|(_, r, _)| g.armed.contains(&r.id)).cloned().collect();
            (armed, g.fleet_pids.clone())
        };
        if rules.is_empty() {
            continue;
        }
        // a config of just the triggers' matchers, so the table resolves only what they need
        let cfg = ProtectionConfig::new(
            Default::default(),
            rules
                .iter()
                .map(|(k, r, n)| {
                    let (m, tree) = r.during[*n].on_exec.clone().expect("an exec trigger");
                    let mut x = ProtectionRule::new(k, m);
                    x.tree = tree;
                    x
                })
                .collect(),
        );
        let t0 = Instant::now();
        let Ok(snap) = table.snapshot(&cfg, &excluding, wall_now()) else { continue };
        let t = wall_now() - t0.elapsed().as_secs_f64() / 2.0;
        let mut g = lock(&s);
        for x in &cfg.rules {
            let on = !matcher::group(&snap.procs, &x.match_, x.tree).is_empty();
            let was = g.exec_on.insert(x.id.clone(), on).unwrap_or(false);
            if on != was {
                g.files.set_exec_phase(&x.id, on);
                g.changed(&x.id, on, t, "exec");
            }
        }
    }
}

impl OwnerSources for EventSources {
    fn progress(&mut self, key: &str, spec: &Value, now: f64) -> Option<Progress> {
        let mut g = lock(&self.shared);
        let fresh = !g.files.has_progress(key);
        let r = g.files.progress(key, spec, now);
        if fresh {
            self.rewatch(&mut g);
        }
        r
    }

    fn phase_on(&mut self, key: &str, spec: &Value) -> bool {
        let mut g = lock(&self.shared);
        let before = g.files.phase_state(key).map(|p| p.0);
        let on = g.files.phase_on(key, spec);
        let after = g.files.phase_state(key).map(|p| p.0);
        if let Some(a) = after {
            if before.is_some_and(|b| b != a) || (before.is_none() && a) {
                g.changed(key, a, wall_now(), "poll");
            }
        }
        on
    }

    fn configure(&mut self, cfg: &ProtectionConfig) {
        let mut g = lock(&self.shared);
        g.files.configure(cfg);
        g.immediate.clear();
        g.exec.clear();
        g.exec_on.clear();
        for r in cfg.rules.iter().filter(|r| r.immediate) {
            for (n, d) in r.during.iter().enumerate() {
                let key = format!("{}#{n}", r.id);
                g.immediate.insert(key.clone(), (r.id.clone(), n, d.pause_fleet));
                if d.on_exec.is_some() {
                    g.exec.push((key, r.clone(), n));
                }
            }
        }
        self.rewatch(&mut g);
    }

    fn set_exec_phase(&mut self, key: &str, on: bool) {
        let mut g = lock(&self.shared);
        let was = g.files.phase_state(key).map(|p| p.0);
        // an immediate trigger's fast listing may have seen it first: it stays on until that listing sees it end
        let on = on || g.exec_on.get(key).copied().unwrap_or(false);
        g.files.set_exec_phase(key, on);
        if was != Some(on) && (was.is_some() || on) {
            g.changed(key, on, wall_now(), "exec");
        }
    }

    fn arm(&mut self, armed: &BTreeSet<String>, fleet_pids: &HashSet<i32>) {
        let mut g = lock(&self.shared);
        g.armed = armed.clone();
        g.fleet_pids = fleet_pids.clone();
        let rules: HashMap<String, String> = g.exec.iter().map(|(k, r, _)| (k.clone(), r.id.clone())).collect();
        g.exec_on.retain(|k, _| rules.get(k).is_some_and(|r| armed.contains(r)));
    }

    fn phases(&self) -> Vec<PhaseReport> {
        lock(&self.shared).files.phases()
    }

    fn progress_status(&self, key: &str) -> Option<(bool, String)> {
        lock(&self.shared).files.progress_status(key)
    }

    fn attach(&mut self, journal: Option<Arc<DecisionJournal>>) {
        lock(&self.shared).journal = journal;
    }

    fn set_fast_path(&mut self, f: Arc<dyn FastPath>) {
        lock(&self.shared).fast = Some(f);
    }

    fn latency(&self) -> Option<Value> {
        Some(lock(&self.shared).latency.to_json())
    }

    fn reset(&mut self) {
        lock(&self.shared).files.reset();
    }
}
