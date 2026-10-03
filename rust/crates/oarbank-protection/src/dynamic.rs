//! The dynamic controller: L2 (fast, every tick) and L1 (AIMD, every 60 s) over the fleet CPU budget, the
//! escalation ladder, the pause probe with natural baselines, bandwidth classes, and the mode profiles. A
//! pure function of its inputs and its own state; the spawn registry applies the outputs, so the controller
//! cannot name a protected process.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::config::{ProtectionMode, ProtectionScope};
use crate::evaluator::ProtectionEvent;
use crate::memory_guard::GuardLevel;

/// One fleet job as the dynamic controller sees it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DynJob {
    pub attempt_id: i64,
    pub pausable: bool,
    pub cooperative: bool,
    pub gpu: bool,
    pub footprint_gb: f64,
    pub started_at: f64,
    /// The module's measured bandwidth class ("low" | "medium" | "high"); None = undeclared (medium).
    pub bandwidth: Option<String>,
}

impl DynJob {
    pub fn new(attempt_id: i64) -> Self {
        Self {
            attempt_id,
            ..Self::default()
        }
    }
}

/// A protected metric this tick, for one source (a `protect` rule or an implicit protection).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProtectedSignal {
    /// rule:<id> | implicit:frontmost | implicit:owner_stall
    pub source: String,
    pub metric: String,
    /// None: unknown (feature missing).
    pub value: Option<f64>,
    /// Older than three samples counts as a violation (fail-safe).
    pub age_s: f64,
    pub max: Option<f64>,
    pub max_slowdown: Option<f64>,
    /// The protected group is GPU-bound (its GPU share is above 5 %, or unknown). Decides which proxies may
    /// grow the budget, and that its harm is memory-bandwidth harm.
    pub gpu_bound: bool,
}

impl ProtectedSignal {
    /// A signal against an absolute ceiling.
    pub fn with_max(source: &str, metric: &str, value: Option<f64>, max: f64) -> Self {
        Self {
            source: source.into(),
            metric: metric.into(),
            value,
            max: Some(max),
            ..Self::default()
        }
    }

    /// A signal against a relative slowdown.
    pub fn with_slowdown(
        source: &str,
        metric: &str,
        value: Option<f64>,
        max_slowdown: f64,
    ) -> Self {
        Self {
            source: source.into(),
            metric: metric.into(),
            value,
            max_slowdown: Some(max_slowdown),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct DynInputs {
    pub now: f64,
    pub mode: ProtectionMode,
    pub signals: Vec<ProtectedSignal>,
    /// Static actions of active rules.
    pub lower_rules: Vec<String>,
    pub pause_rules: Vec<(String, ProtectionScope)>,
    pub guard_level: GuardLevel,
    pub user_idle_s: f64,
    pub any_protected_active: bool,
    pub gpu_protected_active: bool,
    /// Cores the fleet could use after reservations (the L1 budget's ceiling).
    pub allocatable_cores: f64,
    pub jobs: Vec<DynJob>,
    /// A protect rule became active this tick (feed-forward: reset the budget to the reservation-based value).
    pub protection_started: bool,
    pub probe_requested: bool,
    /// The OS can lower fleet jobs (false on Linux without a delegated cgroup): when it cannot, a job that would
    /// be lowered is paused if it can be (never a larger allowance, S19).
    pub lowering: bool,
}

impl DynInputs {
    pub fn new(now: f64, mode: ProtectionMode, allocatable_cores: f64) -> Self {
        Self {
            now,
            mode,
            signals: vec![],
            lower_rules: vec![],
            pause_rules: vec![],
            guard_level: GuardLevel::Clear,
            user_idle_s: 1e9,
            any_protected_active: false,
            gpu_protected_active: false,
            allocatable_cores,
            jobs: vec![],
            protection_started: false,
            probe_requested: false,
            lowering: true,
        }
    }
}

/// The cooperative-throttle document written to a job's workspace (`control.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottleDoc {
    pub threads: Option<i64>,
    pub pause: bool,
    pub seq: i64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DynOutputs {
    /// Ceiling on fleet CPU cores (None: none), from the L1 budget or the strict_yield ramp.
    pub budget_cores: Option<f64>,
    pub no_admit: bool,
    pub no_admit_reason: Option<String>,
    /// Attempts that should run on the E-cores now (background), and those that should be paused.
    pub lowered: BTreeSet<i64>,
    pub paused: BTreeSet<i64>,
    pub evict: Vec<(i64, String)>,
    pub throttle: BTreeMap<i64, ThrottleDoc>,
    pub gpu_jobs_allowed: Option<i64>,
    pub probing: bool,
    pub events: Vec<ProtectionEvent>,
    pub rung: i32,
    pub reason: String,
}

/// Which protected metrics may let the L1 budget grow back. Any metric may shrink the budget.
/// On the M5 Pro no CPU-side proxy (cpu_stall, gpu_share, ipc_ratio, system bandwidth) tracked the slowdown
/// of a GPU trainer, so a GPU-bound group grows only on its own progress rate; for CPU work ipc_ratio passed
/// (r = 0.97, 100 % sign agreement) and cpu_stall did not.
pub struct ProxyValidation;

impl ProxyValidation {
    pub fn growth_eligible(metric: &str, gpu_bound: bool) -> bool {
        match metric {
            "progress_rate" => true,
            "ipc_ratio" => !gpu_bound,
            _ => false,
        }
    }
}

/// Per-sample weight of a new implicit-signal value (a time constant of about 20 s at the 2 s sample period).
const IMPLICIT_SMOOTHING: f64 = 0.1;

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

#[derive(Debug, Clone)]
pub struct DynamicController {
    // tunables (docs/design/protection.md, "Defaults")
    pub l1_interval_s: f64,
    pub lockout_s: f64,
    pub revert_lockout_s: f64,
    pub restore_clean_s: f64,
    pub max_pause_s: f64,
    pub probe_every_s: f64,
    pub probe_length_s: f64,
    pub strict_idle_s: f64,
    pub strict_ramp_s: f64,
    pub sample_s: f64,

    budget: Option<f64>,
    last_l1: f64,
    lockout_until: f64,
    interval_clean: bool,
    interval_violated: bool,
    emergency_streak: u32,
    clean_since: Option<f64>,
    lowered: bool,
    paused_since: HashMap<i64, f64>,
    probe_start: Option<f64>,
    next_probe: f64,
    probe_running: BTreeMap<String, Vec<f64>>,
    probe_paused: BTreeMap<String, Vec<f64>>,
    /// Smoothed harm per source from probes (1 − running ÷ paused), last five.
    harm: HashMap<String, Vec<f64>>,
    baseline: HashMap<String, f64>,
    strict_admit_since: Option<f64>,
    throttle_seq: i64,
    last_throttle: HashMap<i64, ThrottleDoc>,
    hold_unvalidated: bool,
    /// The current harm is only to GPU-bound groups (memory-bandwidth harm), kept through the L2 restore window.
    harm_gpu_only: bool,
    last_pressure: HashMap<String, f64>,
    /// Implicit signals, smoothed per source.
    smoothed: HashMap<String, f64>,
}

impl Default for DynamicController {
    fn default() -> Self {
        Self {
            l1_interval_s: 60.0,
            lockout_s: 300.0,
            revert_lockout_s: 30.0,
            restore_clean_s: 30.0,
            max_pause_s: 600.0,
            probe_every_s: 600.0,
            probe_length_s: 6.0,
            strict_idle_s: 900.0,
            strict_ramp_s: 60.0,
            sample_s: 2.0,
            budget: None,
            last_l1: -1e18,
            lockout_until: -1e18,
            interval_clean: true,
            interval_violated: false,
            emergency_streak: 0,
            clean_since: None,
            lowered: false,
            paused_since: HashMap::new(),
            probe_start: None,
            next_probe: -1e18,
            probe_running: BTreeMap::new(),
            probe_paused: BTreeMap::new(),
            harm: HashMap::new(),
            baseline: HashMap::new(),
            strict_admit_since: None,
            throttle_seq: 0,
            last_throttle: HashMap::new(),
            hold_unvalidated: false,
            harm_gpu_only: false,
            last_pressure: HashMap::new(),
            smoothed: HashMap::new(),
        }
    }
}

impl DynamicController {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current L1 budget (None: no budget in force).
    pub fn budget(&self) -> Option<f64> {
        self.budget
    }

    /// Probe-measured harm per source, newest last.
    pub fn harm(&self) -> &HashMap<String, Vec<f64>> {
        &self.harm
    }

    /// Normalized pressure of one signal: 1.0 = at target; None = unknown (blocks growth only).
    fn raw_pressure(&self, s: &ProtectedSignal) -> Option<f64> {
        let v = s.value?;
        if let Some(m) = s.max {
            return Some(if m > 0.0 {
                v / m
            } else if v > 0.0 {
                10.0
            } else {
                0.0
            });
        }
        if let Some(ms) = s.max_slowdown.filter(|ms| *ms > 0.0) {
            // instantaneous harm against the paused-fleet baseline (refreshed by each probe and by natural
            // baselines); before the first baseline, the probes' own estimate
            if let Some(&b) = self.baseline.get(&s.source).filter(|b| **b > 0.0) {
                return Some((1.0 - v / b).max(0.0) / ms);
            }
            if let Some(h) = self.harm.get(&s.source).filter(|h| !h.is_empty()) {
                return Some(mean(h) / ms);
            }
            return None; // no baseline yet: no growth, no shrink
        }
        None
    }

    /// Pressure of an implicit signal (the frontmost app, owner stall). These watch whole groups of owner
    /// processes through `cpu_stall`, which no measurement validated as harm, and the owner's own work stalls
    /// too (a busy VM, a machine still booting). So they count only the stall the fleet adds: the smoothed
    /// value over the owner's own level, learned while no fleet job runs. With no fleet job running there is
    /// nothing to add.
    fn implicit_pressure(&mut self, s: &ProtectedSignal, fleet_running: bool) -> Option<f64> {
        let (v, max) = (s.value?, s.max?);
        let sm = self
            .smoothed
            .get(&s.source)
            .map_or(v, |x| x + IMPLICIT_SMOOTHING * (v - x));
        self.smoothed.insert(s.source.clone(), sm);
        if !fleet_running {
            let b = self
                .baseline
                .get(&s.source)
                .map_or(v, |b| 0.8 * b + 0.2 * v);
            self.baseline.insert(s.source.clone(), b);
            return Some(0.0);
        }
        // while fleet work runs the owner's level only falls, to at most half the target over the smoothed
        // value (a level learned in a busy spell must not hide harm that starts later); with no level learned
        // yet (fleet work ran from the start) all of it counts
        let b = match self.baseline.get_mut(&s.source) {
            Some(b) => {
                *b = b.min(sm + 0.5 * max);
                *b
            }
            None => 0.0,
        };
        let excess = (sm - b).max(0.0);
        Some(if max > 0.0 {
            excess / max
        } else if excess > 0.0 {
            10.0
        } else {
            0.0
        })
    }

    /// Stale signals are a violation, and never less severe than the last value seen (fail-safe, S19).
    fn pressure(&mut self, s: &ProtectedSignal, fleet_running: bool) -> Option<f64> {
        if s.age_s > 3.0 * self.sample_s {
            let last = self.last_pressure.get(&s.source).copied().unwrap_or(0.0);
            return Some(1.5f64.max(last).max(self.raw_pressure(s).unwrap_or(0.0)));
        }
        let p = if s.source.starts_with("implicit:") {
            self.implicit_pressure(s, fleet_running)
        } else {
            self.raw_pressure(s)
        };
        if let Some(p) = p {
            self.last_pressure.insert(s.source.clone(), p);
        }
        p
    }

    pub fn step(&mut self, i: &DynInputs) -> DynOutputs {
        let mut o = DynOutputs::default();
        let now = i.now;
        let jobs = &i.jobs;
        let pressures: Vec<(&ProtectedSignal, Option<f64>)> = i
            .signals
            .iter()
            .map(|s| (s, self.pressure(s, !jobs.is_empty())))
            .collect();
        let worst = pressures
            .iter()
            .filter_map(|p| p.1)
            .fold(None, |a: Option<f64>, x| Some(a.map_or(x, |a| a.max(x))));
        let worst = worst.unwrap_or(0.0);
        let unknown = pressures.iter().any(|p| p.1.is_none());
        let violating: Vec<_> = pressures
            .iter()
            .filter(|p| p.1.unwrap_or(0.0) >= 1.0)
            .collect();
        if !violating.is_empty() {
            self.harm_gpu_only = violating.iter().all(|p| p.0.gpu_bound);
        }
        // growth needs, for every active protect rule, a validated signal with a value (implicit sources only veto)
        let rule_sources: BTreeSet<&str> = i
            .signals
            .iter()
            .filter(|s| s.source.starts_with("rule:"))
            .map(|s| s.source.as_str())
            .collect();
        let unvalidated: Vec<&str> = rule_sources
            .into_iter()
            .filter(|src| {
                !i.signals.iter().any(|s| {
                    s.source == *src
                        && s.value.is_some()
                        && ProxyValidation::growth_eligible(&s.metric, s.gpu_bound)
                })
            })
            .collect();

        // natural baselines: the protected groups ran while no fleet job did
        if jobs.is_empty() {
            for s in i.signals.iter().filter(|s| s.max_slowdown.is_some()) {
                if let Some(v) = s.value {
                    let b = self
                        .baseline
                        .get(&s.source)
                        .map_or(v, |b| 0.8 * b + 0.2 * v);
                    self.baseline.insert(s.source.clone(), b);
                }
            }
        }

        // rule static actions (every mode): lower_fleet, pause_fleet scopes; they apply to every job
        let mut lower_all = !i.lower_rules.is_empty();
        let mut pause_scopes: BTreeSet<ProtectionScope> =
            i.pause_rules.iter().map(|r| r.1).collect();
        // the dynamic layer's own rungs, which bandwidth classes may refine
        let mut dyn_lower = false;
        let mut dyn_pause_cpu = false;

        match i.mode {
            ProtectionMode::FleetFirst => self.budget = None,
            ProtectionMode::StrictYield => {
                // any trigger pauses all fleet CPU and GPU work within one tick; admission waits for 15 idle
                // minutes with nothing protected active, then ramps one slot per minute
                let triggered =
                    i.any_protected_active || i.user_idle_s < self.strict_idle_s || worst > 1.0;
                if triggered {
                    pause_scopes.insert(ProtectionScope::All);
                    lower_all = true;
                    self.strict_admit_since = None;
                    self.budget = Some(0.0);
                    o.no_admit = true;
                    o.no_admit_reason = Some("mode:strict_yield".into());
                } else {
                    let since = *self.strict_admit_since.get_or_insert(now);
                    let slots = ((now - since) / self.strict_ramp_s).floor() + 1.0;
                    self.budget = Some(i.allocatable_cores.min(slots));
                }
            }
            ProtectionMode::Moderate => {
                self.moderate(
                    i,
                    &mut o,
                    worst,
                    unknown,
                    &pressures,
                    &unvalidated,
                    &mut dyn_pause_cpu,
                );
                dyn_lower = self.lowered;
                self.probe(i, &mut o);
            }
        }

        // GPU admission gating
        if i.gpu_protected_active {
            pause_scopes.insert(ProtectionScope::Gpu);
        }

        // bandwidth classes (moderate only, when the harm is only to GPU-bound groups): a "low" job
        // costs a GPU trainer nothing, so no dynamic rung touches it; a "high" job gains nothing from a thread
        // cap, so it is lowered as soon as the budget has shrunk. Undeclared jobs keep the default ladder.
        let bw_mode =
            i.mode == ProtectionMode::Moderate && self.harm_gpu_only && !i.signals.is_empty();
        let budget_shrunk =
            self.budget.unwrap_or(i.allocatable_cores) < i.allocatable_cores || worst > 1.0;
        let exempt = |j: &DynJob| bw_mode && j.bandwidth.as_deref() == Some("low");

        // map scopes onto jobs: pause what is pausable, lower (E-cores) what is not
        for j in jobs {
            let mut scopes = pause_scopes.clone();
            if dyn_pause_cpu && !exempt(j) {
                scopes.insert(ProtectionScope::Cpu);
            }
            let has = |s| scopes.contains(&s);
            let in_scope = has(ProtectionScope::All)
                || has(ProtectionScope::Io)
                || (has(ProtectionScope::Cpu) && !j.gpu)
                || (has(ProtectionScope::Gpu) && j.gpu)
                || (o.probing && !j.gpu);
            let lower_j = lower_all
                || (dyn_lower && !exempt(j))
                || (bw_mode && budget_shrunk && j.bandwidth.as_deref() == Some("high"));
            if (in_scope || (lower_j && !i.lowering)) && j.pausable {
                o.paused.insert(j.attempt_id);
            } else if in_scope || lower_j {
                o.lowered.insert(j.attempt_id);
            }
        }
        // max pause: a job paused for 10 minutes is evicted, so paused jobs stop holding unified memory (the
        // probe never counts)
        for j in jobs {
            let id = j.attempt_id;
            if o.paused.contains(&id) && !o.probing {
                let since = *self.paused_since.entry(id).or_insert(now);
                if now - since >= self.max_pause_s {
                    o.evict.push((id, "preempt_protection".into()));
                    o.paused.remove(&id);
                }
            } else if !o.paused.contains(&id) {
                self.paused_since.remove(&id);
            }
        }
        self.paused_since
            .retain(|k, _| jobs.iter().any(|j| j.attempt_id == *k));

        // cooperative throttle: the budget as a thread hint, the pause flag, sent only on change
        let per_job = self.budget.map(|b| {
            if jobs.is_empty() {
                b as i64
            } else {
                ((b as i64) / (jobs.len() as i64).max(1)).max(1)
            }
        });
        for j in jobs.iter().filter(|j| j.cooperative) {
            let threads = if exempt(j) { None } else { per_job };
            let pause = o.paused.contains(&j.attempt_id);
            // a job starts unthrottled: nothing is written or signalled until there is something to change
            let last = self
                .last_throttle
                .get(&j.attempt_id)
                .copied()
                .unwrap_or(ThrottleDoc {
                    threads: None,
                    pause: false,
                    seq: 0,
                });
            if last.threads == threads && last.pause == pause {
                continue;
            }
            self.throttle_seq += 1;
            let d = ThrottleDoc {
                threads,
                pause,
                seq: self.throttle_seq,
            };
            self.last_throttle.insert(j.attempt_id, d);
            o.throttle.insert(j.attempt_id, d);
        }
        self.last_throttle
            .retain(|k, _| jobs.iter().any(|j| j.attempt_id == *k));

        o.budget_cores = self.budget;
        if i.gpu_protected_active {
            o.gpu_jobs_allowed = Some(0);
        }
        if self.budget == Some(0.0) && !o.no_admit && !i.signals.is_empty() {
            o.no_admit = true;
            o.no_admit_reason = Some("l1:budget".into());
        }
        o.rung = if !o.evict.is_empty() {
            6
        } else if !o.paused.is_empty() {
            5
        } else if !o.lowered.is_empty() {
            3
        } else if self.budget.unwrap_or(i.allocatable_cores) < i.allocatable_cores {
            2
        } else if o.no_admit {
            1
        } else {
            0
        };
        o.reason = if o.probing {
            "probe".into()
        } else if self.lowered {
            format!("l2 lowered (pressure {worst:.2})")
        } else {
            self.budget
                .map(|b| format!("budget {} cores", b as i64))
                .unwrap_or_default()
        };
        o
    }

    /// L2 (emergency lowering) and L1 (AIMD) in moderate mode.
    #[allow(clippy::too_many_arguments)]
    fn moderate(
        &mut self,
        i: &DynInputs,
        o: &mut DynOutputs,
        worst: f64,
        unknown: bool,
        pressures: &[(&ProtectedSignal, Option<f64>)],
        unvalidated: &[&str],
        dyn_pause_cpu: &mut bool,
    ) {
        let now = i.now;
        // L2: an emergency (> 2x target for two samples) lowers the fleet at once; restore after 30 s clean
        self.emergency_streak = if worst > 2.0 {
            self.emergency_streak + 1
        } else {
            0
        };
        if self.emergency_streak >= 2 && !self.lowered {
            self.lowered = true;
            o.events.push(ProtectionEvent::new(
                "rung_change",
                "l2",
                "L2_EMERGENCY_LOWER",
                &[("pressure", worst)],
            ));
        }
        if worst < 1.0 && !pressures.iter().any(|p| p.1.unwrap_or(0.0) >= 1.0) {
            let since = *self.clean_since.get_or_insert(now);
            if self.lowered && now - since >= self.restore_clean_s {
                self.lowered = false;
                o.events.push(ProtectionEvent::new(
                    "rung_change",
                    "l2",
                    "L2_RESTORED",
                    &[("pressure", worst)],
                ));
            }
        } else {
            self.clean_since = None;
        }
        // L1: AIMD on the fleet CPU budget, only while something is protected
        if i.signals.is_empty() {
            self.budget = None;
            return;
        }
        if self.budget.is_none() || i.protection_started {
            self.budget = Some(i.allocatable_cores); // feed-forward reset (no windup)
        }
        self.interval_violated = self.interval_violated || worst > 1.0;
        self.interval_clean =
            self.interval_clean && worst < 0.5 && !unknown && i.guard_level == GuardLevel::Clear;
        if now - self.last_l1 >= self.l1_interval_s {
            let b = self.budget.unwrap_or(i.allocatable_cores);
            if i.guard_level != GuardLevel::Clear || worst > 2.0 {
                self.budget = Some(0.0);
                self.lockout_until = now + self.lockout_s;
                o.events.push(ProtectionEvent::new(
                    "budget_step",
                    "l1",
                    "L1_TAKE_BACK",
                    &[("budget", 0.0), ("pressure", worst)],
                ));
            } else if self.interval_violated {
                self.budget = Some((b / 2.0).floor());
                self.lockout_until = self.lockout_until.max(now + self.revert_lockout_s);
                o.events.push(ProtectionEvent::new(
                    "budget_step",
                    "l1",
                    "L1_HALVE",
                    &[("budget", (b / 2.0).floor()), ("pressure", worst)],
                ));
            } else if self.interval_clean && now >= self.lockout_until && b < i.allocatable_cores {
                if unvalidated.is_empty() {
                    self.budget = Some(i.allocatable_cores.min(b + 1.0));
                    self.hold_unvalidated = false;
                    o.events.push(ProtectionEvent::new(
                        "budget_step",
                        "l1",
                        "L1_GROW",
                        &[("budget", b + 1.0)],
                    ));
                } else if !self.hold_unvalidated {
                    self.hold_unvalidated = true;
                    o.events.push(ProtectionEvent::new(
                        "budget_step",
                        &unvalidated.join(","),
                        "L1_HOLD_UNVALIDATED",
                        &[("budget", b)],
                    ));
                }
            }
            self.last_l1 = now;
            self.interval_clean = true;
            self.interval_violated = false;
        }
        let budget = self.budget.unwrap_or(0.0).max(0.0).min(i.allocatable_cores);
        self.budget = Some(budget);
        // escalation: E-cores and caps failed and the violation persists, or an emergency: pause (cpu scope)
        if self.lowered && worst > 1.0 && budget <= 1.0 {
            *dyn_pause_cpu = true;
        }
    }

    /// The pause probe: 6 s every 10 min while a relative target is active (never under a guard).
    fn probe(&mut self, i: &DynInputs, o: &mut DynOutputs) {
        let now = i.now;
        let wants_probe = i.signals.iter().any(|s| s.max_slowdown.is_some())
            && i.guard_level == GuardLevel::Clear;
        let relative = || {
            i.signals
                .iter()
                .filter(|s| s.max_slowdown.is_some())
                .filter_map(|s| Some((s, s.value?)))
        };
        if let Some(ps) = self.probe_start {
            if now - ps < self.probe_length_s {
                o.probing = true;
                for (s, v) in relative() {
                    self.probe_paused
                        .entry(s.source.clone())
                        .or_default()
                        .push(v);
                }
            } else {
                for (src, paused) in &self.probe_paused {
                    if paused.is_empty() {
                        continue;
                    }
                    let Some(run) = self.probe_running.get(src).filter(|r| !r.is_empty()) else {
                        continue;
                    };
                    let (p, r) = (mean(paused), mean(run));
                    if p <= 0.0 {
                        continue;
                    }
                    let h = (1.0 - r / p).max(0.0);
                    let hs = self.harm.entry(src.clone()).or_default();
                    hs.push(h);
                    if hs.len() > 5 {
                        hs.drain(..hs.len() - 5);
                    }
                    self.baseline.insert(src.clone(), p);
                    o.events.push(ProtectionEvent::new(
                        "probe_result",
                        src,
                        "PROBE_HARM",
                        &[("harm", h)],
                    ));
                }
                self.probe_start = None;
                self.probe_paused.clear();
                self.probe_running.clear();
                self.next_probe = now + self.probe_every_s;
            }
        } else if wants_probe && !i.jobs.is_empty() && (now >= self.next_probe || i.probe_requested)
        {
            self.probe_start = Some(now);
            o.probing = true;
        } else if wants_probe {
            for (s, v) in relative() {
                let run = self.probe_running.entry(s.source.clone()).or_default();
                run.push(v);
                if run.len() > 30 {
                    run.drain(..run.len() - 30);
                }
            }
        }
    }
}
