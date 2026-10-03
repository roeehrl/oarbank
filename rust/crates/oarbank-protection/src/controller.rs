//! Protection for one agent tick: rules (static actions), the L0 memory guard, the thermal and battery
//! gates, and (moderate, strict_yield) the dynamic controller over measured metrics, combined into one
//! constraint plus the per-attempt actuation plan (lower, pause, evict, throttle). The plan names only fleet
//! attempts; the spawn registry applies it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::config::{ProtectionConfig, ProtectionMode, ProtectionScope};
use crate::dynamic::{DynInputs, DynJob, DynamicController, ProtectedSignal, ThrottleDoc};
use crate::evaluator::{
    CombinedConstraint, ConstraintVector, ProtectionEvent, RuleEvaluator, RuleReport,
};
use crate::gpu::{GpuBusy, GpuTimes};
use crate::journal::DecisionJournal;
use crate::json::{obj, opt_num, opt_str, rounded, strings};
use crate::matcher;
use crate::memory_guard::{GuardLevel, MemoryGuard, MemorySignals, SystemGates, VictimCandidate};
use crate::model::{ProcessKey, ProcessRecord};
use crate::signals::{GroupMetrics, Meter, NullMeter, ProcCounters};
use crate::sources::{NoOwnerSources, OwnerSources};
use crate::table::{ProcessSource, ProcessSummaryRow, ProcessTable, UnsupportedProcessSource};
use crate::telemetry::ProtectionTelemetry;

/// One fleet job (a live attempt with a process group) as protection sees it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FleetJobView {
    pub attempt_id: i64,
    pub pgid: Option<i32>,
    pub footprint_gb: f64,
    pub started_at: f64,
    pub declared_mem_gb: f64,
    pub pausable: bool,
    pub cooperative: bool,
    pub gpu: bool,
    pub bandwidth: Option<String>,
}

impl FleetJobView {
    pub fn new(
        attempt_id: i64,
        pgid: Option<i32>,
        footprint_gb: f64,
        started_at: f64,
        declared_mem_gb: f64,
    ) -> Self {
        Self {
            attempt_id,
            pgid,
            footprint_gb,
            started_at,
            declared_mem_gb,
            ..Self::default()
        }
    }
}

/// An attempt to release now, with the release reason (`preempt_memory`, `limit_mem`, `preempt_protection`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eviction {
    pub attempt_id: i64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtectionTickResult {
    pub constraint: CombinedConstraint,
    pub reports: Vec<RuleReport>,
    pub guard_level: GuardLevel,
    pub guard_reason: String,
    pub evictions: Vec<Eviction>,
    /// Attempts to run on the E-cores (background) and attempts to pause (SIGSTOP).
    pub lowered: BTreeSet<i64>,
    pub paused: BTreeSet<i64>,
    /// Cooperative-throttle documents to write (only on change), by attempt.
    pub throttle: BTreeMap<i64, ThrottleDoc>,
    pub probing: bool,
    pub rung: i32,
    pub dynamic_reason: String,
    pub budget_cores: Option<f64>,
}

impl ProtectionTickResult {
    fn evicts(&self, attempt_id: i64) -> bool {
        self.evictions.iter().any(|e| e.attempt_id == attempt_id)
    }
}

/// What the agent's supervisor loop knows this tick.
#[derive(Debug, Clone)]
pub struct TickInputs {
    pub now: f64,
    /// Every pid in the agent's own groups (excluded from matching: fleet work is never protected).
    pub fleet_pids: HashSet<i32>,
    pub memory: MemorySignals,
    pub thermal: i32,
    pub on_battery: bool,
    pub run_on_battery: bool,
    pub jobs: Vec<FleetJobView>,
    /// Seconds since the last user input (0 while someone is present).
    pub user_idle_s: f64,
    /// perf + eff/2 cores; the dynamic budget's ceiling before reservations.
    pub allocatable_cores: f64,
}

impl TickInputs {
    pub fn new(now: f64, memory: MemorySignals) -> Self {
        Self {
            now,
            fleet_pids: HashSet::new(),
            memory,
            thermal: 0,
            on_battery: false,
            run_on_battery: false,
            jobs: vec![],
            user_idle_s: 1e9,
            allocatable_cores: 0.0,
        }
    }
}

/// The host interfaces the controller reads (never writes): the process table, the meters and the owner's
/// sources.
pub struct Host {
    pub processes: Box<dyn ProcessSource>,
    pub meter: Box<dyn Meter>,
    pub sources: Box<dyn OwnerSources>,
}

impl Host {
    /// Nothing measurable: an empty table, unknown metrics, no owner sources (tests and pure replays).
    pub fn unavailable() -> Self {
        Self {
            processes: Box::new(UnsupportedProcessSource),
            meter: Box::new(NullMeter),
            sources: Box::new(NoOwnerSources),
        }
    }

    /// This platform's process table and meters, and file-based owner sources.
    pub fn native() -> Self {
        crate::platform::native_host()
    }
}

/// The owner's local protection file, as read from disk.
#[derive(Debug, Clone, PartialEq)]
pub enum LocalProtection {
    Absent,
    /// The file exists but is not JSON (its path, for the error).
    Invalid(String),
    Json(Value),
}

impl LocalProtection {
    /// Read `protection.json` (absent when the path is None or the file does not exist).
    pub fn read(path: Option<&Path>) -> Self {
        let Some(p) = path else { return Self::Absent };
        if !p.exists() {
            return Self::Absent;
        }
        match std::fs::read_to_string(p)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        {
            Some(v) => Self::Json(v),
            None => Self::Invalid(p.display().to_string()),
        }
    }
}

#[derive(Debug, Clone)]
struct CachedInputs {
    vectors: Vec<ConstraintVector>,
    guard_vectors: Vec<ConstraintVector>,
    guard_level: GuardLevel,
}

pub struct ProtectionController {
    config: ProtectionConfig,
    pub evaluator: RuleEvaluator,
    pub memory_guard: MemoryGuard,
    pub dynamic: DynamicController,
    table: ProcessTable,
    meter: Box<dyn Meter>,
    sources: Box<dyn OwnerSources>,
    journal: Option<Arc<DecisionJournal>>,
    last_constraint: CombinedConstraint,
    last_guard: GuardLevel,
    last_rung: i32,
    /// The attempts paused and lowered on the last tick, and the rules behind them (journaled on change).
    last_paused: (BTreeSet<i64>, Vec<String>),
    last_lowered: (BTreeSet<i64>, Vec<String>),
    /// Per measured group: when it was last sampled and each process's counters then.
    last_counters: HashMap<String, (f64, HashMap<ProcessKey, ProcCounters>)>,
    /// The last GPU reading and when it was taken (the busy fractions are the change since).
    last_gpu: Option<(f64, GpuTimes)>,
    /// The coordinator asked for a pause probe (`run_probe`); consumed by the next tick.
    pub probe_requested: bool,
    /// The coordinator asked for a process summary (the rule editor is open), or the periodic one is due.
    pub processes_requested: bool,
    last_processes_at: f64,
    last_reports: Vec<RuleReport>,
    last_dynamic: String,
    config_error: Option<String>,
    source_error: Option<String>,
    last_inputs: Option<CachedInputs>,
}

fn signals_json(signals: &BTreeMap<String, f64>) -> Map<String, Value> {
    let o: Map<String, Value> = signals
        .iter()
        .map(|(k, v)| (k.clone(), rounded(*v, 3)))
        .collect();
    obj([("signals", Value::Object(o))])
}

impl ProtectionController {
    pub fn new(journal: Option<Arc<DecisionJournal>>, host: Host) -> Self {
        Self {
            config: ProtectionConfig::default(),
            evaluator: RuleEvaluator::new(),
            memory_guard: MemoryGuard::new(),
            dynamic: DynamicController::new(),
            table: ProcessTable::new(host.processes),
            meter: host.meter,
            sources: host.sources,
            journal,
            last_constraint: CombinedConstraint::default(),
            last_guard: GuardLevel::Clear,
            last_rung: 0,
            last_paused: Default::default(),
            last_lowered: Default::default(),
            last_counters: HashMap::new(),
            last_gpu: None,
            probe_requested: false,
            processes_requested: false,
            last_processes_at: 0.0,
            last_reports: vec![],
            last_dynamic: String::new(),
            config_error: None,
            source_error: None,
            last_inputs: None,
        }
    }

    pub fn config(&self) -> &ProtectionConfig {
        &self.config
    }

    /// Why the last config could not be applied in full (shown as PROTECTION_CONFIG_ERROR).
    pub fn config_error(&self) -> Option<&str> {
        self.config_error.as_deref()
    }

    /// Why the process table could not be read on the last tick (unsupported platform, permissions).
    pub fn source_error(&self) -> Option<&str> {
        self.source_error.as_deref()
    }

    pub fn last_reports(&self) -> &[RuleReport] {
        &self.last_reports
    }

    fn journal(&self, kind: &str, reason: &str, rule: Option<&str>, detail: Map<String, Value>) {
        if let Some(j) = &self.journal {
            j.record(kind, reason, rule, detail);
        }
    }

    /// Central section (from the node policy) unioned with the local file; a broken part is reported and
    /// ignored, never loosening: a broken local file keeps the central config, a broken central one keeps
    /// the last good config.
    pub fn apply(&mut self, central: Option<&Value>, local: &LocalProtection) {
        let mut c: Option<ProtectionConfig> = None;
        let mut errors: Vec<String> = vec![];
        match central {
            Some(j) => match ProtectionConfig::from_json(j, "central") {
                Ok(cfg) => c = Some(cfg),
                Err(e) => errors.push(format!("central: {e}")),
            },
            None => c = Some(ProtectionConfig::default()),
        }
        match local {
            LocalProtection::Absent => {}
            LocalProtection::Invalid(path) => errors.push(format!("local: {path} is not JSON")),
            LocalProtection::Json(j) => match ProtectionConfig::from_json(j, "local") {
                Ok(l) => c = Some(c.as_ref().unwrap_or(&self.config).union(&l)),
                Err(e) => errors.push(format!("local: {e}")),
            },
        }
        let new = c.unwrap_or_else(|| self.config.clone());
        self.config_error = (!errors.is_empty()).then(|| errors.join("; "));
        if new != self.config {
            let kind = if new.mode != self.config.mode {
                "mode_change"
            } else {
                "config_applied"
            };
            let ids: Vec<String> = new.rules.iter().map(|r| r.id.clone()).collect();
            self.journal(
                kind,
                "PROTECTION_CONFIG",
                None,
                obj([
                    ("mode", Value::from(new.mode.as_str())),
                    ("rules", strings(&ids)),
                    ("sources", strings(&new.sources)),
                    ("error", opt_str(self.config_error.as_deref())),
                ]),
            );
            self.config = new;
            self.sources.reset();
        }
    }

    /// A process summary when one is requested or every 5 minutes (None otherwise).
    pub fn process_summary(
        &mut self,
        now: f64,
        fleet_pids: &HashSet<i32>,
    ) -> Option<Vec<ProcessSummaryRow>> {
        if !self.processes_requested && now - self.last_processes_at < 300.0 {
            return None;
        }
        self.processes_requested = false;
        self.last_processes_at = now;
        self.table.summary(80, fleet_pids, now).ok()
    }

    /// One tick against the live host: snapshot the table, evaluate, measure the active groups, then run the
    /// dynamic layer on the measurements.
    pub fn tick(&mut self, i: &TickInputs) -> ProtectionTickResult {
        let need_table =
            !self.config.rules.is_empty() || self.config.mode != ProtectionMode::FleetFirst;
        let snap = if need_table {
            match self.table.snapshot(&self.config, &i.fleet_pids, i.now) {
                Ok(s) => {
                    self.source_error = None;
                    s
                }
                Err(e) => {
                    self.source_error = Some(e.to_string());
                    Default::default()
                }
            }
        } else {
            Default::default()
        };
        // the frontmost app: for rules active while an app is in front, and the implicit protection of the
        // app the user is working in
        let implicit_front = self.config.mode != ProtectionMode::FleetFirst
            && self.config.implicit_frontmost
            && i.user_idle_s < 300.0;
        let rules_front = self
            .config
            .rules
            .iter()
            .any(|r| r.active_when.frontmost.is_some());
        let front = if implicit_front || rules_front {
            self.meter.frontmost_pid()
        } else {
            None
        };
        let gpu = self.read_gpu(i.now);
        // evaluate first (it decides which rules are active), then measure the active groups
        let r =
            self.evaluate_with_metrics(i, &snap.procs, &snap.cpu_cores, front, gpu.as_ref(), None);
        let front = front.filter(|_| implicit_front);
        let metrics = self.live_metrics(i.now, &snap.procs, &i.fleet_pids, front, gpu.as_ref());
        self.redo_dynamic(r, i, &metrics, front.is_some())
    }

    /// Each process's GPU busy fraction since the last reading, when anything reads it: a `gpu_active` trigger,
    /// a `protect` rule (whether its group is GPU-bound decides which proxies may grow) or `gpu_jobs =
    /// when_no_gpu_protected`. None: unknown (the source is unavailable, or this is the first reading).
    fn read_gpu(&mut self, now: f64) -> Option<GpuBusy> {
        let need = self.config.gpu_jobs == "when_no_gpu_protected"
            || self
                .config
                .rules
                .iter()
                .any(|r| r.protect.is_some() || r.active_when.gpu_min_busy.is_some());
        let cur = if need { self.meter.gpu_times() } else { None };
        let Some(cur) = cur else {
            self.last_gpu = None;
            return None;
        };
        let busy = self
            .last_gpu
            .as_ref()
            .and_then(|(t, prev)| GpuBusy::between(prev, &cur, now - t));
        self.last_gpu = Some((now, cur));
        busy
    }

    /// The pure part of a tick with no measured metrics yet and the frontmost app and GPU use unknown (tests
    /// and the differential replay drive this).
    pub fn evaluate(
        &mut self,
        i: &TickInputs,
        procs: &[ProcessRecord],
        cpu_cores: &HashMap<ProcessKey, f64>,
    ) -> ProtectionTickResult {
        self.evaluate_with_metrics(i, procs, cpu_cores, None, None, Some(&HashMap::new()))
    }

    /// The pure part of a tick. `frontmost` is the frontmost app's pid and `gpu` each process's GPU busy
    /// fraction (None: unknown); `metrics` supplies measured protected metrics by source ("rule:<id>",
    /// "implicit:*"); None skips the dynamic layer (the caller runs it after measuring).
    pub fn evaluate_with_metrics(
        &mut self,
        i: &TickInputs,
        procs: &[ProcessRecord],
        cpu_cores: &HashMap<ProcessKey, f64>,
        frontmost: Option<i32>,
        gpu: Option<&GpuBusy>,
        metrics: Option<&HashMap<String, GroupMetrics>>,
    ) -> ProtectionTickResult {
        let now = i.now;
        let ev = self
            .evaluator
            .evaluate(&self.config, procs, cpu_cores, frontmost, gpu, now);
        for e in &ev.events {
            self.journal(&e.kind, &e.reason, Some(&e.rule), signals_json(&e.signals));
        }
        let mut guard_vectors = vec![];
        let (lvl, evict_now) = self
            .memory_guard
            .update(&i.memory, &self.config.memory, now);
        if lvl >= GuardLevel::Soft {
            guard_vectors.push(ConstraintVector::no_admit("guard:memory"));
        }
        if self.config.pause {
            guard_vectors.push(ConstraintVector::no_admit("local:pause"));
        }
        guard_vectors.extend(SystemGates::vectors(
            i.thermal,
            i.on_battery,
            i.run_on_battery,
        ));
        let mut evictions: Vec<Eviction> = vec![];
        let candidates: Vec<VictimCandidate> = i
            .jobs
            .iter()
            .map(|j| VictimCandidate {
                attempt_id: j.attempt_id,
                footprint_gb: j.footprint_gb,
                started_at: j.started_at,
            })
            .collect();
        if evict_now {
            if let Some(victim) = MemoryGuard::victim(&candidates) {
                evictions.push(Eviction {
                    attempt_id: victim,
                    reason: "preempt_memory".into(),
                });
                self.journal(
                    "guard_fired",
                    "MEMORY_HARD_FLOOR",
                    None,
                    obj([
                        ("attempt", Value::from(victim)),
                        ("why", Value::from(self.memory_guard.reason.as_str())),
                        ("free_pct", rounded(i.memory.free_pct(), 1)),
                    ]),
                );
            }
        }
        // Borg's overage rule: a job over 1.25x its declared memory is evicted first under a floor
        if lvl >= GuardLevel::Soft {
            for j in &i.jobs {
                if j.declared_mem_gb > 0.0
                    && j.footprint_gb > 1.25 * j.declared_mem_gb
                    && !evictions.iter().any(|e| e.attempt_id == j.attempt_id)
                {
                    evictions.push(Eviction {
                        attempt_id: j.attempt_id,
                        reason: "limit_mem".into(),
                    });
                }
            }
        }
        let all: Vec<ConstraintVector> = ev.vectors.iter().chain(&guard_vectors).cloned().collect();
        let static_combined = CombinedConstraint::combine(&all);
        if !static_combined.evict.is_empty() {
            let src = ev
                .vectors
                .iter()
                .find(|v| !v.evict.is_empty())
                .map_or("rule", |v| v.source.as_str());
            for j in &i.jobs {
                if !evictions.iter().any(|e| e.attempt_id == j.attempt_id) {
                    evictions.push(Eviction {
                        attempt_id: j.attempt_id,
                        reason: "preempt_protection".into(),
                    });
                }
            }
            if !i.jobs.is_empty() {
                let ids: Vec<Value> = i.jobs.iter().map(|j| Value::from(j.attempt_id)).collect();
                self.journal(
                    "attempt_evicted",
                    "PROTECTION_EVICT",
                    Some(src),
                    obj([("attempts", Value::Array(ids))]),
                );
            }
        }
        if lvl != self.last_guard {
            let kind = if lvl == GuardLevel::Clear {
                "guard_cleared"
            } else {
                "guard_fired"
            };
            self.journal(
                kind,
                &format!("MEMORY_{}", lvl.as_str().to_uppercase()),
                None,
                obj([
                    ("why", Value::from(self.memory_guard.reason.as_str())),
                    ("free_pct", rounded(i.memory.free_pct(), 1)),
                ]),
            );
            self.last_guard = lvl;
        }
        self.last_reports = ev.reports.clone();
        self.last_inputs = Some(CachedInputs {
            vectors: ev.vectors,
            guard_vectors,
            guard_level: lvl,
        });
        let base = ProtectionTickResult {
            constraint: static_combined,
            reports: ev.reports,
            guard_level: lvl,
            guard_reason: self.memory_guard.reason.clone(),
            evictions,
            lowered: BTreeSet::new(),
            paused: BTreeSet::new(),
            throttle: BTreeMap::new(),
            probing: false,
            rung: 0,
            dynamic_reason: String::new(),
            budget_cores: None,
        };
        match metrics {
            Some(m) => {
                let front = m.contains_key("implicit:frontmost");
                self.redo_dynamic(base, i, m, front)
            }
            None => base,
        }
    }

    fn measure(
        &mut self,
        key: &str,
        group: &[ProcessRecord],
        now: f64,
        gpu: Option<&GpuBusy>,
    ) -> Option<GroupMetrics> {
        let mut counters = HashMap::new();
        for p in group {
            if let Some(c) = self.meter.proc_counters(p.pid) {
                counters.insert(p.key(), c);
            }
        }
        let prev = self.last_counters.get(key).filter(|(t, _)| now > *t);
        // per process, over the processes sampled both times: one that started or exited in between would add
        // or take away its whole lifetime (stall spikes while processes come and go, as on a booting machine)
        let delta = prev.map(|(pt, pc)| {
            let d = counters
                .iter()
                .filter_map(|(k, c)| pc.get(k).map(|b| *c - *b))
                .fold(ProcCounters::default(), |a, d| a + d);
            (now - pt, d)
        });
        self.last_counters.insert(key.to_string(), (now, counters));
        let (seconds, d) = delta?;
        let mut m = GroupMetrics::from_delta(d, seconds);
        // the group's share of all GPU time (unknown when any of its processes' usage is)
        m.gpu_share = gpu.and_then(|g| {
            let mine = g.group(group.iter().map(|p| p.pid))?;
            let tot = g.total();
            Some(if tot > 0.0 { mine / tot } else { 0.0 })
        });
        Some(m)
    }

    /// Live metrics for the active protect rules (and the implicit protections): counter deltas, the owner's
    /// progress sources and (feature-detected) GPU time.
    fn live_metrics(
        &mut self,
        now: f64,
        procs: &[ProcessRecord],
        fleet_pids: &HashSet<i32>,
        frontmost: Option<i32>,
        gpu: Option<&GpuBusy>,
    ) -> HashMap<String, GroupMetrics> {
        let mut out = HashMap::new();
        let protect_rules: Vec<(String, Option<Value>)> = self
            .evaluator
            .active_rules
            .iter()
            .filter_map(|r| {
                r.protect
                    .as_ref()
                    .map(|p| (r.id.clone(), p.source_json.clone()))
            })
            .collect();
        for (id, source) in protect_rules {
            let group = self.evaluator.groups.get(&id).cloned().unwrap_or_default();
            let key = format!("rule:{id}");
            let mut m = self.measure(&key, &group, now, gpu).unwrap_or_default();
            if let Some(src) = source {
                m.progress_rate = self.sources.progress_rate(&id, &src, now);
            }
            out.insert(key, m);
        }
        if self.config.mode != ProtectionMode::FleetFirst {
            if let Some(fp) =
                frontmost.filter(|fp| self.config.implicit_frontmost && !fleet_pids.contains(fp))
            {
                let grp: Vec<ProcessRecord> = procs
                    .iter()
                    .filter(|p| p.pid == fp || p.ppid == fp)
                    .cloned()
                    .collect();
                if let Some(m) = self.measure("implicit:frontmost", &grp, now, gpu) {
                    out.insert("implicit:frontmost".into(), m);
                }
            }
            if self.config.owner_stall_max.is_some() {
                let ignored: HashSet<ProcessKey> = self
                    .config
                    .rules
                    .iter()
                    .filter(|r| r.ignore)
                    .flat_map(|r| matcher::group(procs, &r.match_, r.tree))
                    .map(|p| p.key())
                    .collect();
                let owner: Vec<ProcessRecord> = procs
                    .iter()
                    .filter(|p| !fleet_pids.contains(&p.pid) && !ignored.contains(&p.key()))
                    .cloned()
                    .collect();
                if let Some(m) = self.measure("implicit:owner_stall", &owner, now, gpu) {
                    out.insert("implicit:owner_stall".into(), m);
                }
            }
        }
        out
    }

    /// Apply the dynamic controller (and the rules' dynamic actions) on top of the static result.
    fn redo_dynamic(
        &mut self,
        r0: ProtectionTickResult,
        i: &TickInputs,
        metrics: &HashMap<String, GroupMetrics>,
        user_present_front: bool,
    ) -> ProtectionTickResult {
        let Some(cache) = self.last_inputs.clone() else {
            return r0;
        };
        let now = i.now;
        let cfg = &self.config;
        let mut r = r0;
        let mut di = DynInputs::new(
            now,
            cfg.mode,
            (i.allocatable_cores - r.constraint.reserved_cpu).max(0.0),
        );
        di.guard_level = cache.guard_level;
        di.user_idle_s = i.user_idle_s;
        di.any_protected_active = !self.evaluator.active_rules.is_empty();
        di.protection_started = !self.evaluator.started.is_empty();
        di.probe_requested = self.probe_requested;
        self.probe_requested = false;
        di.jobs = i
            .jobs
            .iter()
            .map(|j| DynJob {
                attempt_id: j.attempt_id,
                pausable: j.pausable,
                cooperative: j.cooperative,
                gpu: j.gpu,
                footprint_gb: j.footprint_gb,
                started_at: j.started_at,
                bandwidth: j.bandwidth.clone(),
            })
            .collect();
        let mut extra: Vec<ConstraintVector> = vec![];
        for rule in &self.evaluator.active_rules {
            if rule.lower_fleet {
                di.lower_rules.push(rule.id.clone());
            }
            if let Some(sc) = rule.pause_fleet {
                di.pause_rules.push((rule.id.clone(), sc));
            }
            if let Some(p) = &rule.protect {
                let m = metrics.get(&format!("rule:{}", rule.id));
                // GPU-bound when the group's GPU share is above 5 %, or unknown (fail-safe: CPU proxies then
                // cannot grow)
                let gpu_bound = m.and_then(|m| m.gpu_share).is_none_or(|g| g > 0.05);
                di.signals.push(ProtectedSignal {
                    source: format!("rule:{}", rule.id),
                    metric: p.metric.clone(),
                    value: m.and_then(|m| m.value(&p.metric)),
                    age_s: 0.0,
                    max: p.max,
                    max_slowdown: p.max_slowdown,
                    gpu_bound,
                });
                if p.metric == "gpu_share" && m.and_then(|m| m.gpu_share).is_some_and(|g| g > 0.05)
                {
                    di.gpu_protected_active = true;
                }
            }
            if matches!(
                rule.pause_fleet,
                Some(ProtectionScope::Gpu | ProtectionScope::All)
            ) {
                di.gpu_protected_active = di.gpu_protected_active || cfg.gpu_jobs != "always";
            }
            // phase-aware extras while the owner's source says the phase is on
            for (k, d) in rule.during.iter().enumerate() {
                let key = format!("{}#{k}", rule.id);
                if !self.sources.phase_on(&key, &d.source_json) {
                    continue;
                }
                let mut v = ConstraintVector::new(&format!("rule:{}/during", rule.id));
                if let Some(cf) = &d.cap_fleet {
                    v.cpu_cores = cf.cpu_cores;
                    v.slots = cf.slots;
                    v.staging_mbps = cf.staging_mbps;
                    v.gpu_jobs = cf.gpu_jobs;
                    v.threads = cf.threads;
                }
                extra.push(v);
                if d.lower_fleet {
                    di.lower_rules.push(key.clone());
                }
                if let Some(sc) = d.pause_fleet {
                    di.pause_rules.push((key, sc));
                }
            }
        }
        if cfg.mode != ProtectionMode::FleetFirst {
            if let Some(m) = metrics
                .get("implicit:frontmost")
                .filter(|_| user_present_front)
            {
                di.signals.push(ProtectedSignal::with_max(
                    "implicit:frontmost",
                    "cpu_stall",
                    m.cpu_stall,
                    cfg.owner_stall_max.unwrap_or(0.15),
                ));
            }
            if let (Some(mx), Some(m)) = (cfg.owner_stall_max, metrics.get("implicit:owner_stall"))
            {
                di.signals.push(ProtectedSignal::with_max(
                    "implicit:owner_stall",
                    "cpu_stall",
                    m.cpu_stall,
                    mx,
                ));
            }
        }
        if cfg.gpu_jobs == "never" {
            extra.push(ConstraintVector {
                gpu_jobs: Some(0),
                ..ConstraintVector::new("node:gpu_jobs")
            });
        }
        let pause_rules: Vec<String> = di.pause_rules.iter().map(|r| r.0.clone()).collect();
        let lower_rules = di.lower_rules.clone();
        let out = self.dynamic.step(&di);
        let mode = self.config.mode;
        let gpu_always = self.config.gpu_jobs == "always";
        for e in &out.events {
            self.journal_event(e);
        }
        if let Some(b) = out.budget_cores {
            let src = if mode == ProtectionMode::StrictYield {
                "mode:strict_yield"
            } else {
                "l1:budget"
            };
            extra.push(ConstraintVector {
                cpu_cores: Some(b),
                ..ConstraintVector::new(src)
            });
        }
        if out.no_admit {
            extra.push(ConstraintVector::no_admit(
                out.no_admit_reason.as_deref().unwrap_or("protection"),
            ));
        }
        if out.gpu_jobs_allowed == Some(0) && !gpu_always {
            extra.push(ConstraintVector {
                gpu_jobs: Some(0),
                ..ConstraintVector::new("protection:gpu")
            });
        }
        let all: Vec<ConstraintVector> = cache
            .vectors
            .iter()
            .chain(&cache.guard_vectors)
            .chain(&extra)
            .cloned()
            .collect();
        let combined = CombinedConstraint::combine(&all);
        r.constraint = combined.clone();
        r.lowered = out.lowered;
        r.paused = out.paused;
        r.throttle = out.throttle;
        r.probing = out.probing;
        r.rung = out.rung;
        r.dynamic_reason = out.reason.clone();
        r.budget_cores = out.budget_cores;
        for (id, reason) in out.evict {
            if !r.evicts(id) {
                r.evictions.push(Eviction {
                    attempt_id: id,
                    reason,
                });
            }
        }
        self.journal_fleet_action(true, &r.paused, pause_rules, &out.reason);
        self.journal_fleet_action(false, &r.lowered, lower_rules, &out.reason);
        if out.rung != self.last_rung {
            self.journal(
                "rung_change",
                &format!("RUNG_{}", out.rung),
                None,
                obj([
                    ("from", Value::from(self.last_rung)),
                    ("to", Value::from(out.rung)),
                    ("why", Value::from(out.reason.as_str())),
                ]),
            );
            self.last_rung = out.rung;
        }
        if combined != self.last_constraint {
            self.journal(
                "constraint",
                "CONSTRAINT_CHANGED",
                None,
                obj([("constraint", combined.to_json())]),
            );
            self.last_constraint = combined;
        }
        self.last_dynamic = out.reason;
        r
    }

    /// A pause or a lowering of fleet attempts, journaled when the attempts it covers or the rules behind it change
    /// (S18 checks that an active pause_fleet or lower_fleet rule reached the fleet). `rule` is the first rule's
    /// source, or `dynamic` when only the dynamic layer acts.
    fn journal_fleet_action(&mut self, paused: bool, attempts: &BTreeSet<i64>, rules: Vec<String>, why: &str) {
        let now = (attempts.clone(), rules);
        let last = if paused { &mut self.last_paused } else { &mut self.last_lowered };
        if *last == now {
            return;
        }
        *last = now.clone();
        let (attempts, rules) = now;
        if attempts.is_empty() {
            return;
        }
        let rule = rules.first().map_or_else(|| "dynamic".to_string(), |r| format!("rule:{r}"));
        let d = obj([
            ("attempts", Value::Array(attempts.iter().map(|a| Value::from(*a)).collect())),
            ("rules", Value::Array(rules.iter().map(|r| Value::from(r.as_str())).collect())),
            ("why", Value::from(why)),
        ]);
        if paused {
            self.journal("attempt_paused", "PROTECTION_PAUSE", Some(&rule), d);
        } else {
            self.journal("attempt_lowered", "PROTECTION_LOWER", Some(&rule), d);
        }
    }

    fn journal_event(&self, e: &ProtectionEvent) {
        self.journal(&e.kind, &e.reason, Some(&e.rule), signals_json(&e.signals));
    }

    /// The agent's local status page section.
    pub fn status_json(&self) -> Value {
        let rules: Vec<Value> = self.last_reports.iter().map(RuleReport::to_json).collect();
        Value::Object(obj([
            ("config", self.config.summary()),
            ("error", opt_str(self.config_error.as_deref())),
            ("rules", Value::Array(rules)),
            (
                "guard",
                Value::Object(obj([
                    ("level", Value::from(self.memory_guard.level.as_str())),
                    ("reason", Value::from(self.memory_guard.reason.as_str())),
                ])),
            ),
            ("constraint", self.last_constraint.to_json()),
            ("rung", Value::from(self.last_rung)),
            ("dynamic", Value::from(self.last_dynamic.as_str())),
            ("budget_cores", opt_num(self.dynamic.budget())),
        ]))
    }

    /// The heartbeat's `telemetry.protection` for this tick's result.
    pub fn telemetry(&self, r: &ProtectionTickResult) -> ProtectionTelemetry {
        ProtectionTelemetry::new(&self.config, r, self.config_error.as_deref())
    }
}
