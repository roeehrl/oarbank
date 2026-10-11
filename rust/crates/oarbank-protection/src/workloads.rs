//! Workloads and owner-delegated processes in host protection (docs/design/workloads.md, "Protection on workloads"
//! and "Delegated external processes").
//!
//! A workload is fleet work with its own ladder: it is not started while the node admits no work of its kind, it is
//! throttled while the CPU budget binds, lowered as jobs are, paused only up to its declared tolerance, and stopped and
//! held for as long as a cause lasts (the memory guard's victim, a rule's evict, a pause beyond the tolerance, GPU work
//! that may not run). The dynamic controller decides the pause and lowering rungs for workloads as it does for jobs (a
//! workload enters it as a `DynJob` with a stable negative id and is never probed); this module turns its decisions into
//! one plan per workload and keeps the holds and pause clocks.
//!
//! A delegated tree is the owner's own processes that an owner rule lets protection pause or lower as fleet work. It
//! is never stopped: one paused for the pause ceiling is resumed and lowered instead until the pause would end.
//!
//! Pure: the agent applies the plans through the spawn registry.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::Value;

/// The id a workload or a delegated tree has in the dynamic controller's per-job state: stable for its key, and
/// negative and far below the small negative ids the memory guard gives services, so it never meets an attempt id.
pub fn fleet_id(key: &str) -> i64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    -(1i64 << 40) - (h & ((1u64 << 40) - 1)) as i64
}

/// Whether an id in a controller output is a workload's or a delegated tree's, not an attempt's or a service's.
pub fn is_fleet_id(id: i64) -> bool {
    id <= -(1i64 << 40)
}

/// One workload as protection sees it: running, or held down by protection (still evaluated, so the hold can end).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FleetWorkloadView {
    /// `module/workload`.
    pub key: String,
    pub running: bool,
    pub footprint_gb: f64,
    pub started_at: f64,
    /// Its declared `resources.cpu_cores` (the budget's share for it never exceeds this).
    pub cpu_cores: f64,
    /// The longest pause its peers survive (0: never paused).
    pub pause_tolerance_s: f64,
    /// `freeze_ok` or `cooperative_pause`.
    pub pausable: bool,
    /// `cooperative_throttle`: it honours the control document's `threads`.
    pub cooperative_throttle: bool,
    /// The OS can cap its container's CPU (Linux `cpu.max`, Windows job CPU rate).
    pub hard_cap: bool,
    /// `gpu.use` is not none.
    pub gpu: bool,
}

impl FleetWorkloadView {
    pub fn new(key: &str) -> Self {
        Self {
            key: key.into(),
            running: true,
            ..Self::default()
        }
    }

    pub fn id(&self) -> i64 {
        fleet_id(&format!("workload:{}", self.key))
    }

    /// It may be paused at all: it declared how, and a tolerance above zero.
    pub fn can_pause(&self) -> bool {
        self.pausable && self.pause_tolerance_s > 0.0
    }
}

/// Why protection holds a workload down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HoldCause {
    /// The memory guard chose it as its victim: held until the guard is clear.
    Memory,
    /// A rule's `evict` (or a phase's `evict_fleet`): held while it lasts.
    Evict,
    /// Paused for its tolerance (or the pause ceiling): held while it would still be paused.
    PauseTolerance,
    /// GPU work may not run and it cannot be paused: held until GPU work may run.
    Gpu,
}

impl HoldCause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Evict => "evict",
            Self::PauseTolerance => "pause_tolerance",
            Self::Gpu => "gpu",
        }
    }
}

/// A hold: the workload is stopped now and not started while the cause lasts.
#[derive(Debug, Clone, PartialEq)]
pub struct Hold {
    pub cause: HoldCause,
    /// The release reason it is stopped with (`preempt_memory`, `preempt_protection`).
    pub reason: String,
    /// The journal code (`WORKLOAD_HOLD`, `WORKLOAD_PAUSE_TOLERANCE`).
    pub code: &'static str,
    pub since: f64,
}

/// This tick's plan for one workload.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WorkloadAction {
    /// May start (when it is not running): no hold, and the node admits work of its kind.
    pub admit: bool,
    pub lowered: bool,
    pub paused: bool,
    /// The `threads` hint (cooperative throttle) while the CPU budget or a rule's thread cap binds.
    pub threads: Option<i64>,
    /// A hard CPU cap for its container (cores), where the OS has one.
    pub cpu_cap: Option<f64>,
    /// The GPU duty it should hold (`gpu_duty` in its control document; only for a workload with GPU use that
    /// declares `cooperative_throttle`): the share of a co-tenancy certificate's duty under `gpu_jobs = certified`
    /// (D50). None: no duty asked.
    pub gpu_duty: Option<f64>,
    /// Stop it, and keep it stopped.
    pub hold: Option<Hold>,
}

/// What the ladder reads this tick, from the rules, the memory guard and the dynamic controller.
#[derive(Debug, Clone)]
pub struct LadderInputs<'a> {
    pub now: f64,
    pub workloads: &'a [FleetWorkloadView],
    /// The dynamic controller's decisions, by id.
    pub paused_ids: &'a BTreeSet<i64>,
    pub lowered_ids: &'a BTreeSet<i64>,
    /// The dynamic controller would release these after the pause ceiling.
    pub ceiling_ids: &'a BTreeSet<i64>,
    /// Workloads the memory guard chose as its victim this tick.
    pub memory_victims: &'a BTreeSet<String>,
    /// A rule's evict is in force.
    pub evict_active: bool,
    /// The memory guard is clear.
    pub guard_clear: bool,
    /// The combined constraint admits no work at all.
    pub no_admit: bool,
    /// GPU work may run.
    pub gpu_allowed: bool,
    /// The last step's pause scopes cover CPU (non-GPU) work, GPU work.
    pub would_pause_cpu: bool,
    pub would_pause_gpu: bool,
    /// The threads each piece of fleet work gets while the budget (or a rule's thread cap) binds.
    pub threads: Option<i64>,
    /// The cores each piece of fleet work gets while the budget (or a rule's core cap) binds.
    pub cpu_share: Option<f64>,
}

/// A change the ladder journals.
#[derive(Debug, Clone, PartialEq)]
pub struct LadderEvent {
    pub kind: &'static str,
    pub reason: &'static str,
    pub detail: Vec<(&'static str, Value)>,
}

/// The ladder's state across ticks: each workload's pause clock, its hold, and the last plan (journaled on change).
#[derive(Debug, Default)]
pub struct WorkloadLadder {
    paused_since: HashMap<String, f64>,
    holds: HashMap<String, Hold>,
    last: BTreeMap<String, WorkloadAction>,
}

impl WorkloadLadder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The hold on a workload now, if any.
    pub fn hold(&self, key: &str) -> Option<&Hold> {
        self.holds.get(key)
    }

    pub fn step(&mut self, i: &LadderInputs) -> (BTreeMap<String, WorkloadAction>, Vec<LadderEvent>) {
        let mut out = BTreeMap::new();
        let mut events = vec![];
        for w in i.workloads {
            let id = w.id();
            let would_pause = if w.gpu { i.would_pause_gpu } else { i.would_pause_cpu };
            // a hold whose cause has cleared ends
            if let Some(h) = self.holds.get(&w.key) {
                let clear = match h.cause {
                    HoldCause::Memory => i.guard_clear,
                    HoldCause::Evict => !i.evict_active,
                    HoldCause::PauseTolerance => !would_pause,
                    HoldCause::Gpu => i.gpu_allowed,
                };
                if clear {
                    let h = self.holds.remove(&w.key).expect("present");
                    events.push(LadderEvent {
                        kind: "workload_released",
                        reason: "WORKLOAD_RELEASE",
                        detail: vec![("workload", Value::from(w.key.as_str())), ("cause", Value::from(h.cause.as_str())),
                                     ("held_s", Value::from(((i.now - h.since) * 10.0).round() / 10.0))],
                    });
                }
            }
            let dyn_paused = w.running && w.can_pause() && i.paused_ids.contains(&id);
            if dyn_paused {
                self.paused_since.entry(w.key.clone()).or_insert(i.now);
            } else {
                self.paused_since.remove(&w.key);
            }
            // a new hold: only a running workload is stopped
            if w.running && !self.holds.contains_key(&w.key) {
                let over = self.paused_since.get(&w.key).is_some_and(|s| i.now - s >= w.pause_tolerance_s.max(0.0));
                let cause = if i.memory_victims.contains(&w.key) {
                    Some((HoldCause::Memory, "preempt_memory", "WORKLOAD_HOLD"))
                } else if i.evict_active {
                    Some((HoldCause::Evict, "preempt_protection", "WORKLOAD_HOLD"))
                } else if w.gpu && !i.gpu_allowed && !w.can_pause() {
                    Some((HoldCause::Gpu, "preempt_protection", "WORKLOAD_HOLD"))
                } else if (dyn_paused && over) || (w.can_pause() && i.ceiling_ids.contains(&id)) {
                    Some((HoldCause::PauseTolerance, "preempt_protection", "WORKLOAD_PAUSE_TOLERANCE"))
                } else {
                    None
                };
                if let Some((cause, reason, code)) = cause {
                    let paused_s = self.paused_since.get(&w.key).map(|s| ((i.now - s) * 10.0).round() / 10.0);
                    self.holds.insert(w.key.clone(), Hold { cause, reason: reason.into(), code, since: i.now });
                    self.paused_since.remove(&w.key);
                    let mut d = vec![("workload", Value::from(w.key.as_str())), ("cause", Value::from(cause.as_str())),
                                     ("release", Value::from(reason))];
                    if let Some(p) = paused_s {
                        d.push(("paused_s", Value::from(p)));
                        d.push(("tolerance_s", Value::from(w.pause_tolerance_s)));
                    }
                    events.push(LadderEvent { kind: "workload_held", reason: code, detail: d });
                }
            }
            let hold = self.holds.get(&w.key).cloned();
            let paused = hold.is_none() && dyn_paused;
            let lowered = hold.is_none() && w.running && !paused && i.lowered_ids.contains(&id);
            let throttled = hold.is_none() && w.running;
            let cap = |x: f64| if w.cpu_cores > 0.0 { x.min(w.cpu_cores) } else { x };
            let a = WorkloadAction {
                admit: hold.is_none() && !i.no_admit && !would_pause && !i.evict_active && i.guard_clear
                    && (!w.gpu || i.gpu_allowed),
                lowered,
                paused,
                threads: i.threads.filter(|_| throttled && w.cooperative_throttle).map(|t| t.max(1)),
                cpu_cap: i.cpu_share.filter(|_| throttled && w.hard_cap).map(|c| cap(c).max(0.1)),
                gpu_duty: None,             // the controller fills it from the dynamic inputs (the certified share)
                hold,
            };
            let last = self.last.get(&w.key).cloned().unwrap_or_else(|| WorkloadAction { admit: true, ..Default::default() });
            let key = Value::from(w.key.as_str());
            if a.paused != last.paused {
                events.push(if a.paused {
                    LadderEvent { kind: "workload_paused", reason: "WORKLOAD_PAUSE",
                                  detail: vec![("workload", key.clone()), ("tolerance_s", Value::from(w.pause_tolerance_s))] }
                } else {
                    LadderEvent { kind: "workload_resumed", reason: "WORKLOAD_RESUME", detail: vec![("workload", key.clone())] }
                });
            }
            if a.lowered != last.lowered {
                events.push(LadderEvent {
                    kind: if a.lowered { "workload_lowered" } else { "workload_restored" },
                    reason: if a.lowered { "WORKLOAD_LOWER" } else { "WORKLOAD_RESTORE" },
                    detail: vec![("workload", key.clone())],
                });
            }
            if (a.threads, a.cpu_cap) != (last.threads, last.cpu_cap) && w.running {
                events.push(LadderEvent {
                    kind: "workload_throttled",
                    reason: "WORKLOAD_THROTTLE",
                    detail: vec![("workload", key.clone()), ("threads", a.threads.map_or(Value::Null, Value::from)),
                                 ("cpu_cap", a.cpu_cap.map_or(Value::Null, |c| Value::from((c * 100.0).round() / 100.0)))],
                });
            }
            self.last.insert(w.key.clone(), a.clone());
            out.insert(w.key.clone(), a);
        }
        let present: BTreeSet<&str> = i.workloads.iter().map(|w| w.key.as_str()).collect();
        self.paused_since.retain(|k, _| present.contains(k.as_str()));
        self.holds.retain(|k, _| present.contains(k.as_str()));
        self.last.retain(|k, _| present.contains(k.as_str()));
        (out, events)
    }
}

/// One owner rule's delegated processes this tick.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DelegatedGroup {
    /// The rule's id.
    pub rule: String,
    /// Each process's pid and start time.
    pub procs: Vec<(i32, u64)>,
    pub footprint_gb: f64,
    pub started_at: f64,
    pub pause: bool,
    pub lower: bool,
}

impl DelegatedGroup {
    pub fn id(&self) -> i64 {
        fleet_id(&format!("delegate:{}", self.rule))
    }
}

/// What to do with one rule's delegated processes this tick.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DelegatedAction {
    pub rule: String,
    pub procs: Vec<(i32, u64)>,
    pub paused: bool,
    pub lowered: bool,
}

/// The delegation ladder: pause and lower only; a tree paused for the pause ceiling is resumed and lowered until the
/// pause would end (it may not be stopped).
#[derive(Debug, Default)]
pub struct DelegationLadder {
    paused_since: HashMap<String, f64>,
    limited: BTreeSet<String>,
    last: BTreeMap<String, (bool, bool)>,
}

impl DelegationLadder {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn step(&mut self, now: f64, groups: &[DelegatedGroup], paused_ids: &BTreeSet<i64>, lowered_ids: &BTreeSet<i64>,
                ceiling_ids: &BTreeSet<i64>, would_pause_cpu: bool, max_pause_s: f64)
                -> (Vec<DelegatedAction>, Vec<LadderEvent>) {
        let mut out = vec![];
        let mut events = vec![];
        for g in groups {
            let id = g.id();
            if self.limited.contains(&g.rule) && !would_pause_cpu {
                self.limited.remove(&g.rule);
            }
            let want_pause = g.pause && paused_ids.contains(&id) && !self.limited.contains(&g.rule);
            if want_pause {
                let since = *self.paused_since.entry(g.rule.clone()).or_insert(now);
                if now - since >= max_pause_s || ceiling_ids.contains(&id) {
                    self.limited.insert(g.rule.clone());
                    self.paused_since.remove(&g.rule);
                    events.push(LadderEvent {
                        kind: "delegate_pause_limit",
                        reason: "DELEGATE_PAUSE_LIMIT",
                        detail: vec![("rule", Value::from(g.rule.as_str())), ("paused_s", Value::from((now - since).round()))],
                    });
                }
            } else {
                self.paused_since.remove(&g.rule);
            }
            let paused = want_pause && !self.limited.contains(&g.rule);
            let lowered = g.lower && !paused
                && (lowered_ids.contains(&id) || self.limited.contains(&g.rule) || (paused_ids.contains(&id) && !g.pause));
            let last = self.last.get(&g.rule).copied().unwrap_or((false, false));
            let rule = Value::from(g.rule.as_str());
            let n = Value::from(g.procs.len());
            if paused != last.0 {
                events.push(LadderEvent {
                    kind: if paused { "delegate_paused" } else { "delegate_resumed" },
                    reason: if paused { "DELEGATE_PAUSE" } else { "DELEGATE_RESUME" },
                    detail: vec![("rule", rule.clone()), ("processes", n.clone())],
                });
            }
            if lowered != last.1 {
                events.push(LadderEvent {
                    kind: if lowered { "delegate_lowered" } else { "delegate_restored" },
                    reason: if lowered { "DELEGATE_LOWER" } else { "DELEGATE_RESTORE" },
                    detail: vec![("rule", rule), ("processes", n)],
                });
            }
            self.last.insert(g.rule.clone(), (paused, lowered));
            out.push(DelegatedAction { rule: g.rule.clone(), procs: g.procs.clone(), paused, lowered });
        }
        let present: BTreeSet<&str> = groups.iter().map(|g| g.rule.as_str()).collect();
        self.paused_since.retain(|k, _| present.contains(k.as_str()));
        self.limited.retain(|k| present.contains(k.as_str()));
        self.last.retain(|k, _| present.contains(k.as_str()));
        (out, events)
    }
}

/// Whether an executable's exact path is one only an administrator can replace, so a delegation by path cannot be
/// claimed by a module's copy: on Linux (and other Unix) the file and every directory above it are owned by root and
/// writable by no one else; on Windows it lies under the system's Program Files or Windows folder, which only
/// administrators may write by default. (macOS delegations name a code-signing identity instead.)
pub fn path_trusted(path: &str) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let p = std::path::Path::new(path);
        if !p.is_absolute() || path.contains("/../") || path.contains("/./") {
            return false;
        }
        let mut cur = Some(p);
        while let Some(c) = cur {
            let Ok(m) = std::fs::metadata(c) else { return false };
            if m.uid() != 0 || m.mode() & 0o022 != 0 {
                return false;
            }
            cur = c.parent();
        }
        true
    }
    #[cfg(windows)]
    {
        let lower = path.to_ascii_lowercase();
        if lower.contains("..") {
            return false;
        }
        ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SystemRoot"].iter()
            .filter_map(|k| std::env::var(k).ok())
            .any(|root| lower.starts_with(&format!("{}\\", root.to_ascii_lowercase().trim_end_matches('\\'))))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs<'a>(now: f64, w: &'a [FleetWorkloadView], paused: &'a BTreeSet<i64>, empty: &'a BTreeSet<i64>,
                  victims: &'a BTreeSet<String>) -> LadderInputs<'a> {
        LadderInputs { now, workloads: w, paused_ids: paused, lowered_ids: empty, ceiling_ids: empty, memory_victims: victims,
                       evict_active: false, guard_clear: true, no_admit: false, gpu_allowed: true, would_pause_cpu: false,
                       would_pause_gpu: false, threads: None, cpu_share: None }
    }

    fn pausable(key: &str, tol: f64) -> FleetWorkloadView {
        FleetWorkloadView { pausable: true, pause_tolerance_s: tol, ..FleetWorkloadView::new(key) }
    }

    #[cfg(unix)]
    #[test]
    fn only_root_owned_paths_writable_by_no_one_else_are_trusted() {
        assert!(path_trusted("/bin/sh"), "a system binary");
        let tmp = std::env::temp_dir().join(format!("oarbank-trust-{}", std::process::id()));
        std::fs::write(&tmp, "x").unwrap();
        assert!(!path_trusted(tmp.to_str().unwrap()), "a file this account owns");
        let _ = std::fs::remove_file(&tmp);
        assert!(!path_trusted("bin/sh") && !path_trusted("/bin/../bin/sh") && !path_trusted("/no/such/file"));
    }

    #[test]
    fn ids_are_stable_negative_and_apart_from_attempts_and_services() {
        let a = fleet_id("workload:m/w");
        assert_eq!(a, fleet_id("workload:m/w"));
        assert!(is_fleet_id(a) && !is_fleet_id(-1) && !is_fleet_id(-1000) && !is_fleet_id(7));
        assert_ne!(a, fleet_id("workload:m/x"));
    }

    #[test]
    fn a_pause_beyond_the_tolerance_becomes_a_hold_that_lasts_while_the_pause_would() {
        let mut l = WorkloadLadder::new();
        let w = vec![pausable("m/w", 20.0)];
        let id = w[0].id();
        let paused: BTreeSet<i64> = [id].into();
        let (e, v) = (BTreeSet::new(), BTreeSet::new());
        let mut i = inputs(100.0, &w, &paused, &e, &v);
        i.would_pause_cpu = true;
        let (a, ev) = l.step(&i);
        assert!(a["m/w"].paused && a["m/w"].hold.is_none());
        assert_eq!(ev[0].reason, "WORKLOAD_PAUSE");
        i.now = 119.0;
        assert!(l.step(&i).0["m/w"].paused);
        i.now = 120.0;
        let (a, ev) = l.step(&i);
        let h = a["m/w"].hold.clone().unwrap();
        assert_eq!((h.cause, h.code, h.reason.as_str(), a["m/w"].paused), (HoldCause::PauseTolerance, "WORKLOAD_PAUSE_TOLERANCE",
                                                                          "preempt_protection", false));
        assert!(ev.iter().any(|e| e.reason == "WORKLOAD_PAUSE_TOLERANCE") && ev.iter().any(|e| e.reason == "WORKLOAD_RESUME"));
        // stopped now: still held, and not admitted, while the pause scope lasts
        let stopped = vec![FleetWorkloadView { running: false, ..w[0].clone() }];
        let none = BTreeSet::new();
        let mut i2 = inputs(200.0, &stopped, &none, &e, &v);
        i2.would_pause_cpu = true;
        let a = l.step(&i2).0;
        assert!(a["m/w"].hold.is_some() && !a["m/w"].admit);
        i2.would_pause_cpu = false;
        let (a, ev) = l.step(&i2);
        assert!(a["m/w"].hold.is_none() && a["m/w"].admit, "{a:?}");
        assert_eq!(ev[0].reason, "WORKLOAD_RELEASE");
    }

    #[test]
    fn a_workload_that_cannot_pause_is_never_paused_and_a_gpu_one_is_held_while_gpu_work_may_not_run() {
        let mut l = WorkloadLadder::new();
        let mut w = FleetWorkloadView::new("m/g");
        w.gpu = true;
        let ws = vec![w];
        let paused: BTreeSet<i64> = [ws[0].id()].into();
        let (e, v) = (BTreeSet::new(), BTreeSet::new());
        let mut i = inputs(1.0, &ws, &paused, &e, &v);
        i.gpu_allowed = false;
        i.would_pause_gpu = true;
        let a = l.step(&i).0;
        assert!(!a["m/g"].paused);
        assert_eq!(a["m/g"].hold.as_ref().map(|h| h.cause), Some(HoldCause::Gpu));
        let stopped = vec![FleetWorkloadView { running: false, ..ws[0].clone() }];
        let mut i = inputs(5.0, &stopped, &e, &e, &v);
        i.gpu_allowed = true;
        let a = l.step(&i).0;
        assert!(a["m/g"].hold.is_none() && a["m/g"].admit);
    }

    #[test]
    fn memory_and_evict_holds_last_as_long_as_their_cause() {
        let mut l = WorkloadLadder::new();
        let w = vec![FleetWorkloadView::new("m/a"), FleetWorkloadView::new("m/b")];
        let e = BTreeSet::new();
        let victims: BTreeSet<String> = ["m/a".to_string()].into();
        let mut i = inputs(1.0, &w, &e, &e, &victims);
        i.guard_clear = false;
        let a = l.step(&i).0;
        assert_eq!(a["m/a"].hold.as_ref().map(|h| (h.cause, h.reason.as_str())), Some((HoldCause::Memory, "preempt_memory")));
        assert!(a["m/b"].hold.is_none() && !a["m/b"].admit, "a node under memory pressure starts nothing");
        let none = BTreeSet::new();
        // the agent stopped m/a; m/b still runs when a rule's evict comes
        let w = vec![FleetWorkloadView { running: false, ..w[0].clone() }, w[1].clone()];
        let mut i = inputs(2.0, &w, &e, &e, &none);
        i.guard_clear = false;
        i.evict_active = true;
        let a = l.step(&i).0;
        assert_eq!(a["m/a"].hold.as_ref().map(|h| h.cause), Some(HoldCause::Memory));
        assert_eq!(a["m/b"].hold.as_ref().map(|h| h.cause), Some(HoldCause::Evict));
        let w = vec![w[0].clone(), FleetWorkloadView { running: false, ..w[1].clone() }];
        let mut i = inputs(3.0, &w, &e, &e, &none);
        i.evict_active = true;
        let a = l.step(&i).0;
        assert!(a["m/a"].hold.is_none() && !a["m/a"].admit, "released from the memory hold, but the evict still keeps it from starting");
        assert!(a["m/b"].hold.is_some());
        i.evict_active = false;
        let a = l.step(&i).0;
        assert!(a.values().all(|x| x.hold.is_none() && x.admit));
    }

    #[test]
    fn throttle_reaches_cooperative_workloads_as_threads_and_capped_ones_as_cores() {
        let mut l = WorkloadLadder::new();
        let w = vec![FleetWorkloadView { cooperative_throttle: true, cpu_cores: 2.0, ..FleetWorkloadView::new("m/t") },
                     FleetWorkloadView { hard_cap: true, cpu_cores: 1.5, ..FleetWorkloadView::new("m/c") }];
        let e = BTreeSet::new();
        let v = BTreeSet::new();
        let mut i = inputs(1.0, &w, &e, &e, &v);
        let a = l.step(&i).0;
        assert!(a.values().all(|x| x.threads.is_none() && x.cpu_cap.is_none()));
        i = inputs(2.0, &w, &e, &e, &v);
        i.threads = Some(3);
        i.cpu_share = Some(3.0);
        let (a, ev) = l.step(&i);
        assert_eq!((a["m/t"].threads, a["m/t"].cpu_cap), (Some(3), None));
        assert_eq!((a["m/c"].threads, a["m/c"].cpu_cap), (None, Some(1.5)), "never more than it declared");
        assert_eq!(ev.iter().filter(|e| e.reason == "WORKLOAD_THROTTLE").count(), 2);
    }

    #[test]
    fn a_delegated_tree_is_paused_then_lowered_at_the_ceiling_and_never_stopped() {
        let mut l = DelegationLadder::new();
        let g = vec![DelegatedGroup { rule: "app".into(), procs: vec![(10, 1)], pause: true, lower: true, ..Default::default() }];
        let id = g[0].id();
        let paused: BTreeSet<i64> = [id].into();
        let e = BTreeSet::new();
        let (a, ev) = l.step(0.0, &g, &paused, &e, &e, true, 600.0);
        assert!(a[0].paused && !a[0].lowered && ev[0].reason == "DELEGATE_PAUSE");
        let (a, ev) = l.step(600.0, &g, &paused, &e, &e, true, 600.0);
        assert!(!a[0].paused && a[0].lowered);
        assert!(ev.iter().any(|e| e.reason == "DELEGATE_PAUSE_LIMIT") && ev.iter().any(|e| e.reason == "DELEGATE_RESUME"));
        // stays lowered while the pause would last; then the tree is restored and may be paused again later
        assert!(l.step(700.0, &g, &paused, &e, &e, true, 600.0).0[0].lowered);
        let a = l.step(710.0, &g, &e, &e, &e, false, 600.0).0;
        assert!(!a[0].paused && !a[0].lowered);
        // a tree delegated for lowering only is lowered where it would be paused
        let low = vec![DelegatedGroup { rule: "lo".into(), procs: vec![(11, 1)], pause: false, lower: true, ..Default::default() }];
        let p2: BTreeSet<i64> = [low[0].id()].into();
        let a = l.step(800.0, &low, &p2, &e, &e, true, 600.0).0;
        assert!(!a[0].paused && a[0].lowered);
    }
}
