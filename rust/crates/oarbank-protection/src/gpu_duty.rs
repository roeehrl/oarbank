//! The GPU duty governor (PLAN D50, docs/design/gpu-cotenancy.md, "The duty governor"): under `gpu_jobs =
//! "certified"`, how much of the GPU cooperative fleet work may keep busy beside a protected GPU group, and whether each
//! cooperative process actually holds what it is asked.
//!
//! - **The budget** `D` (a duty fraction, 0 to the certified ceiling) is an AIMD loop on the gating rules' own progress
//!   rate, the only signal validated for GPU-bound groups: every 60 s it grows by 0.05 when the last interval was clean
//!   (harm under half the target, every signal known, the memory guard clear) and is halved when the interval's harm
//!   reached the target. Harm over twice the target, a collapse (the progress rate under half its baseline over 30 s)
//!   or the memory guard takes it to 0 at once with a 5-minute lockout; an unreadable progress source takes it to 0 at
//!   once (fail-safe). It never exceeds the smallest valid certificate among the gating rules (the ceiling), and a
//!   missing, stale or worse signal never raises it (S19).
//! - **The baseline** each rule's harm is measured against is its progress rate while no fleet GPU work ran: natural
//!   windows (the budget at 0, the gate holding) and, when none is fresh, a baseline window in which the governor holds
//!   GPU work for 60 s (the first 20 s discarded as washout): before the first duty, and every 30 minutes after.
//! - **Each unit** (a job, or a workload) that declares `cooperative_throttle` gets `gpu_duty = D / n`.
//! - **Compliance:** each unit's GPU busy fraction is measured every sample from the per-process GPU time the meter
//!   reads. A unit over its duty plus 0.1 for three consecutive samples is held for 60 s (`GPU_DUTY_EXCEEDED`); the
//!   third such hold of the same module unit within an hour stops it, and that unit is not trusted with a duty for an
//!   hour (it waits beside the protected group like work that cannot throttle). A unit whose GPU time cannot be read for
//!   three samples is held the same way (`GPU_DUTY_UNVERIFIED`): a duty nobody can check is not granted.
//!
//! A pure function of its inputs and its own state, like the dynamic controller: the controller builds the inputs, the
//! spawn registry applies the outputs, and the governor never names a process.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use serde_json::{json, Value};

use crate::sources::Progress;

/// One unit of fleet GPU work as the governor sees it this tick.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DutyUnit {
    /// The attempt id (or a workload's fleet id): what the duty and the actions name.
    pub id: i64,
    /// `module/name` (the stage or workload): what loses the governor's trust after repeated excess.
    pub key: String,
    /// It declares `cooperative_throttle`: it honours `gpu_duty`.
    pub cooperative: bool,
    /// It can be paused (`cooperative_pause` or `freeze_ok`); a unit that cannot is stopped instead of held.
    pub pausable: bool,
    /// Its processes' GPU busy fraction over the last sample (None: unknown).
    pub busy: Option<f64>,
}

/// One gating rule's signal this tick.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DutySignal {
    pub rule: String,
    /// The rule protects `progress_rate` from an owner source: its harm drives the budget.
    pub has_source: bool,
    /// This tick's reading (None: nothing read this tick).
    pub progress: Option<Progress>,
    /// The source could be read on its last attempt (false: fail-safe, the budget falls to 0).
    pub readable: bool,
    /// The rule's target (`protect.max_slowdown`; 0.05 when the rule sets none).
    pub max_slowdown: f64,
}

#[derive(Debug, Clone, Default)]
pub struct DutyInputs {
    pub now: f64,
    /// `gpu_jobs = certified` and a gating group is active (the GPU gate would hold GPU work back).
    pub gating: bool,
    /// The smallest certified duty among the gating rules (None: some gating rule has no valid certificate).
    pub ceiling: Option<f64>,
    pub signals: Vec<DutySignal>,
    pub guard_clear: bool,
    pub units: Vec<DutyUnit>,
}

/// What the controller journals for the governor.
#[derive(Debug, Clone, PartialEq)]
pub struct DutyEvent {
    pub kind: &'static str,
    pub reason: &'static str,
    pub rule: Option<String>,
    pub detail: Value,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DutyOutputs {
    /// The budget in force (None: none, the gate decides alone).
    pub budget: Option<f64>,
    /// Per unit, the `gpu_duty` it holds beside the gated groups (only units that may run there).
    pub duty: BTreeMap<i64, f64>,
    /// Cooperative units held back this tick by compliance or distrust (they wait like work that cannot throttle).
    pub withheld: BTreeSet<i64>,
    /// Units to stop (the third excess within an hour).
    pub evict: Vec<i64>,
    pub events: Vec<DutyEvent>,
}

#[derive(Debug, Clone, Default)]
struct RuleTrack {
    /// The interval's progress while fleet GPU work ran.
    iv_events: f64,
    iv_seconds: f64,
    /// The last few readings while fleet GPU work ran (the collapse check).
    recent: VecDeque<(f64, f64, f64)>,
    /// Progress while no fleet GPU work ran, after the washout (the next baseline).
    base_events: f64,
    base_seconds: f64,
    baseline: Option<f64>,
    baseline_at: f64,
    last_pressure: Option<f64>,
}

#[derive(Debug, Clone, Default)]
struct UnitTrack {
    /// The duty asked of it on the last tick and the one before (None: none).
    duty_prev: Option<f64>,
    duty_prev2: Option<f64>,
    /// It ran (was not paused) through the last sample with a duty.
    ran: bool,
    over: u32,
    unverified: u32,
    held_until: f64,
    last_busy: Option<f64>,
    state: &'static str,
}

/// The governor's tunables and state (docs/design/gpu-cotenancy.md, "Defaults").
#[derive(Debug, Clone)]
pub struct DutyGovernor {
    pub interval_s: f64,
    pub step: f64,
    pub min_duty: f64,
    pub lockout_s: f64,
    pub revert_lockout_s: f64,
    pub collapse_window_s: f64,
    pub collapse_ratio: f64,
    pub baseline_window_s: f64,
    pub washout_s: f64,
    pub baseline_every_s: f64,
    pub resume_memory_s: f64,
    pub slack: f64,
    pub samples: u32,
    pub hold_s: f64,
    pub strikes: usize,
    pub strike_window_s: f64,
    pub distrust_s: f64,

    d: Option<f64>,
    /// The budget when the gate last went away, and when (a gate that comes back soon resumes from it, no windup).
    last_d: Option<(f64, f64)>,
    last_step: f64,
    lockout_until: f64,
    interval_violated: bool,
    interval_clean: bool,
    /// A baseline window: until when GPU work is held, and the budget to resume at.
    baseline_until: Option<(f64, f64)>,
    /// Fleet GPU work ran through the last sample, and since when none has (the washout).
    gpu_ran: bool,
    off_since: Option<f64>,
    rules: BTreeMap<String, RuleTrack>,
    units: HashMap<i64, UnitTrack>,
    strike_log: HashMap<String, Vec<f64>>,
    distrusted: BTreeMap<String, f64>,
    state: &'static str,
    ceiling: Option<f64>,
}

impl Default for DutyGovernor {
    fn default() -> Self {
        Self {
            interval_s: 60.0,
            step: 0.05,
            min_duty: 0.02,
            lockout_s: 300.0,
            revert_lockout_s: 30.0,
            collapse_window_s: 30.0,
            collapse_ratio: 0.5,
            baseline_window_s: 60.0,
            washout_s: 20.0,
            baseline_every_s: 1800.0,
            resume_memory_s: 600.0,
            slack: 0.1,
            samples: 3,
            hold_s: 60.0,
            strikes: 3,
            strike_window_s: 3600.0,
            distrust_s: 3600.0,
            d: None,
            last_d: None,
            last_step: -1e18,
            lockout_until: -1e18,
            interval_violated: false,
            interval_clean: true,
            baseline_until: None,
            gpu_ran: false,
            off_since: None,
            rules: BTreeMap::new(),
            units: HashMap::new(),
            strike_log: HashMap::new(),
            distrusted: BTreeMap::new(),
            state: "idle",
            ceiling: None,
        }
    }
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

/// A duty to 1/1000, never above `x` (a duty must never exceed the ceiling it was cut from).
fn floor3(x: f64) -> f64 {
    ((x * 1000.0) + 1e-9).floor() / 1000.0
}

impl DutyGovernor {
    pub fn new() -> Self {
        Self::default()
    }

    /// The budget in force (None: none).
    pub fn budget(&self) -> Option<f64> {
        self.d
    }

    /// `idle` (no gate), `not_certified`, `measuring` (a baseline window), `running`, `locked` (after a take-back),
    /// `held` (the budget is 0).
    pub fn state(&self) -> &'static str {
        self.state
    }

    /// Module units the governor does not trust with a duty now, and until when.
    pub fn distrusted(&self, now: f64) -> Vec<(String, f64)> {
        self.distrusted.iter().filter(|(_, u)| **u > now).map(|(k, u)| (k.clone(), *u)).collect()
    }

    fn event(&self, out: &mut DutyOutputs, reason: &'static str, why: &str, extra: Value) {
        let mut d = json!({"duty": self.d.map(round3), "ceiling": self.ceiling.map(round3), "why": why});
        if let (Some(o), Value::Object(e)) = (d.as_object_mut(), extra) {
            o.extend(e);
        }
        out.events.push(DutyEvent { kind: "gpu_duty", reason, rule: None, detail: d });
    }

    fn set_d(&mut self, out: &mut DutyOutputs, d: f64, reason: &'static str, why: &str, extra: Value) {
        let d = if d < self.min_duty { 0.0 } else { floor3(d) };
        let changed = self.d != Some(d);
        self.d = Some(d);
        if changed || reason != "GPU_DUTY_HOLD" {
            self.event(out, reason, why, extra);
        }
    }

    /// The gate went away or lost its certificate: no budget (remembered for a quick return).
    fn stand_down(&mut self, now: f64, state: &'static str) {
        if let Some(d) = self.d.take() {
            let resume = self.baseline_until.map_or(d, |(_, r)| r);
            self.last_d = Some((resume, now));
        }
        self.baseline_until = None;
        self.interval_violated = false;
        self.interval_clean = true;
        for r in self.rules.values_mut() {
            r.iv_events = 0.0;
            r.iv_seconds = 0.0;
            r.recent.clear();
        }
        self.state = state;
    }

    /// The level to start (or resume) at: the ceiling, or the budget the gate had when it went away moments ago.
    fn start_level(&self, now: f64, ceiling: f64) -> f64 {
        match self.last_d {
            Some((d, at)) if now - at < self.resume_memory_s => d.min(ceiling),
            _ => ceiling,
        }
    }

    pub fn step(&mut self, i: &DutyInputs) -> DutyOutputs {
        let mut out = DutyOutputs::default();
        let now = i.now;
        self.strike_log.values_mut().for_each(|v| v.retain(|t| now - t < self.strike_window_s));
        self.strike_log.retain(|_, v| !v.is_empty());
        self.distrusted.retain(|_, until| *until > now);
        self.ceiling = i.ceiling;

        // 1. progress readings: while fleet GPU work ran they measure its harm; while none ran (after the washout) they
        // are the baseline
        let washed = self.off_since.is_some_and(|t| now - t >= self.washout_s);
        for s in i.signals.iter().filter(|s| s.has_source) {
            let r = self.rules.entry(s.rule.clone()).or_default();
            let Some(p) = s.progress.filter(|p| p.seconds > 0.0) else { continue };
            if self.gpu_ran {
                r.iv_events += p.events;
                r.iv_seconds += p.seconds;
                r.recent.push_back((now, p.events, p.seconds));
                while r.recent.front().is_some_and(|x| now - x.0 > self.collapse_window_s) {
                    r.recent.pop_front();
                }
            } else if washed {
                r.base_events += p.events;
                r.base_seconds += p.seconds;
                let need = (self.baseline_window_s - self.washout_s).max(1.0);
                if r.base_seconds >= need {
                    let rate = r.base_events / r.base_seconds;
                    r.baseline = Some(match r.baseline {
                        Some(b) if now - r.baseline_at < self.baseline_every_s * 2.0 => 0.5 * b + 0.5 * rate,
                        _ => rate,
                    });
                    r.baseline_at = now;
                    r.base_events = 0.0;
                    r.base_seconds = 0.0;
                }
            }
        }
        self.rules.retain(|k, _| i.signals.iter().any(|s| s.has_source && &s.rule == k));

        // 2. the gate and the ceiling
        let ceiling = match (i.gating, i.ceiling) {
            (false, _) => {
                self.stand_down(now, "idle");
                return self.units_out(i, out);
            }
            (true, None) => {
                self.stand_down(now, "not_certified");
                return self.units_out(i, out);
            }
            (true, Some(c)) => c.clamp(0.0, 1.0),
        };
        let sources: Vec<&DutySignal> = i.signals.iter().filter(|s| s.has_source).collect();
        let fresh = |r: Option<&RuleTrack>| r.is_some_and(|r| r.baseline.is_some() && now - r.baseline_at < self.baseline_every_s);
        let all_fresh = sources.iter().all(|s| fresh(self.rules.get(&s.rule)));

        // 3. start: measure a baseline first when a rule has none fresh
        if self.d.is_none() {
            let start = self.start_level(now, ceiling);
            self.last_step = now;
            self.interval_violated = false;
            self.interval_clean = true;
            if all_fresh {
                self.set_d(&mut out, start, "GPU_DUTY_START", "a certified gate began", json!({}));
            } else {
                self.baseline_until = Some((now + self.baseline_window_s, start));
                self.set_d(&mut out, 0.0, "GPU_DUTY_BASELINE", "measuring the protected program without fleet GPU work",
                           json!({"until": round3(now + self.baseline_window_s)}));
            }
        }
        // a baseline window ends once every rule has a fresh baseline (and at least its length has passed)
        if let Some((until, resume)) = self.baseline_until {
            let unreadable = sources.iter().any(|s| !s.readable);
            if now >= until && (all_fresh || unreadable) {
                self.baseline_until = None;
                self.last_step = now;
                self.interval_violated = false;
                self.interval_clean = true;
                self.set_d(&mut out, resume.min(ceiling), "GPU_DUTY_START", "baseline measured", json!({}));
            } else if now >= until + 4.0 * self.baseline_window_s {
                // nothing to measure (the program makes no progress at all): stay at 0 rather than guess
                self.baseline_until = None;
                self.last_step = now;
                self.set_d(&mut out, 0.0, "GPU_DUTY_TAKE_BACK", "no baseline could be measured", json!({}));
            }
        }
        let measuring = self.baseline_until.is_some();
        let mut d = self.d.unwrap_or(0.0);

        // 4. at once, every tick: an unreadable source, the memory guard, a collapse
        if !measuring {
            if let Some(s) = sources.iter().find(|s| !s.readable) {
                self.interval_violated = true;
                if d > 0.0 {
                    self.set_d(&mut out, 0.0, "GPU_DUTY_TAKE_BACK", "a progress source cannot be read",
                               json!({"rule": s.rule}));
                    d = 0.0;
                }
            } else if !i.guard_clear {
                self.interval_violated = true;
                self.lockout_until = now + self.lockout_s;
                if d > 0.0 {
                    self.set_d(&mut out, 0.0, "GPU_DUTY_TAKE_BACK", "the memory guard acted", json!({}));
                    d = 0.0;
                }
            } else if d > 0.0 && self.gpu_ran {
                for s in &sources {
                    let r = &self.rules[&s.rule];
                    let (ev, secs) = r.recent.iter().fold((0.0, 0.0), |a, x| (a.0 + x.1, a.1 + x.2));
                    let Some(b) = r.baseline.filter(|b| *b > 0.0) else { continue };
                    if secs >= self.collapse_window_s - 1e-9 && ev / secs < self.collapse_ratio * b {
                        self.interval_violated = true;
                        self.lockout_until = now + self.lockout_s;
                        self.set_d(&mut out, 0.0, "GPU_DUTY_TAKE_BACK", "the protected program's progress collapsed",
                                   json!({"rule": s.rule, "rate": round3(ev / secs), "baseline": round3(b)}));
                        d = 0.0;
                        break;
                    }
                }
            }
        }

        // 5. the AIMD step every interval (not in a baseline window)
        if !measuring && now - self.last_step >= self.interval_s {
            let mut worst: Option<f64> = Some(0.0);
            let mut pressures = serde_json::Map::new();
            for s in &sources {
                let r = self.rules.get_mut(&s.rule).expect("tracked");
                let p = if d <= 0.0 || r.iv_seconds <= 0.0 {
                    // no fleet GPU work ran: nothing to harm, nothing measured
                    (d <= 0.0).then_some(0.0)
                } else if r.iv_seconds < 0.5 * self.interval_s {
                    None
                } else {
                    r.baseline.filter(|b| *b > 0.0).map(|b| {
                        let harm = (1.0 - (r.iv_events / r.iv_seconds) / b).max(0.0);
                        harm / s.max_slowdown.max(1e-6)
                    })
                };
                r.last_pressure = p;
                if let Some(p) = p {
                    pressures.insert(s.rule.clone(), json!(round3(p)));
                }
                worst = match (worst, p) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    _ => None,
                };
                r.iv_events = 0.0;
                r.iv_seconds = 0.0;
            }
            let extra = json!({"pressure": Value::Object(pressures)});
            let w = worst.unwrap_or(0.0);
            if w > 2.0 {
                self.lockout_until = now + self.lockout_s;
                self.set_d(&mut out, 0.0, "GPU_DUTY_TAKE_BACK", "harm over twice the target", extra);
            } else if w >= 1.0 || (self.interval_violated && d > 0.0) {
                self.lockout_until = self.lockout_until.max(now + self.revert_lockout_s);
                self.set_d(&mut out, d / 2.0, "GPU_DUTY_HALVE", "harm at the target", extra);
            } else if worst.is_some() && w < 0.5 && self.interval_clean && !self.interval_violated
                && now >= self.lockout_until && d < ceiling && !sources.is_empty()
            {
                self.set_d(&mut out, (d + self.step).min(ceiling), "GPU_DUTY_GROW", "a clean interval", extra);
            }
            self.last_step = now;
            self.interval_violated = false;
            self.interval_clean = true;
        } else if !measuring {
            self.interval_clean = self.interval_clean && i.guard_clear && sources.iter().all(|s| s.readable);
        }

        // 6. the ceiling binds at once
        if self.d.is_some_and(|d| d > ceiling + 1e-12) {
            self.set_d(&mut out, ceiling, "GPU_DUTY_CLAMP", "the certified ceiling fell", json!({}));
        }
        // 7. a periodic baseline window while work runs on a baseline that grew old
        if !measuring && self.d.is_some_and(|d| d > 0.0) && !all_fresh && self.gpu_ran {
            let resume = self.d.unwrap_or(0.0);
            self.baseline_until = Some((now + self.baseline_window_s, resume));
            self.d = Some(0.0);
            self.event(&mut out, "GPU_DUTY_BASELINE", "refreshing the protected program's baseline",
                       json!({"until": round3(now + self.baseline_window_s), "resume": round3(resume)}));
        }
        self.state = if self.baseline_until.is_some() {
            "measuring"
        } else if self.d.unwrap_or(0.0) <= 0.0 {
            if now < self.lockout_until { "locked" } else { "held" }
        } else {
            "running"
        };
        self.units_out(i, out)
    }

    /// Compliance, then each unit's duty under the budget.
    fn units_out(&mut self, i: &DutyInputs, mut out: DutyOutputs) -> DutyOutputs {
        let now = i.now;
        out.budget = self.d;
        // compliance: judge each unit on the sample that just ended
        for u in &i.units {
            let t = self.units.entry(u.id).or_default();
            t.last_busy = u.busy;
            let judged = t.ran && t.duty_prev.is_some() && t.duty_prev2.is_some();
            if !judged {
                t.over = 0;
                t.unverified = 0;
                continue;
            }
            let allowed = t.duty_prev.unwrap_or(1.0).max(t.duty_prev2.unwrap_or(1.0)) + self.slack;
            match u.busy {
                Some(b) => {
                    t.unverified = 0;
                    t.over = if b > allowed { t.over + 1 } else { 0 };
                }
                None => t.unverified += 1,
            }
            let detail = |action: &str, t: &UnitTrack| json!({"attempt": u.id, "unit": u.key, "measured": u.busy.map(round3),
                                                              "duty": t.duty_prev.map(round3), "action": action});
            if t.over >= self.samples {
                t.over = 0;
                t.held_until = now + self.hold_s;
                let log = self.strike_log.entry(u.key.clone()).or_default();
                log.push(now);
                if log.len() >= self.strikes || !u.pausable {
                    log.clear();
                    self.distrusted.insert(u.key.clone(), now + self.distrust_s);
                    out.evict.push(u.id);
                    out.events.push(DutyEvent { kind: "gpu_compliance", reason: "GPU_DUTY_EXCEEDED", rule: None,
                                                detail: detail("evicted", t) });
                } else {
                    out.events.push(DutyEvent { kind: "gpu_compliance", reason: "GPU_DUTY_EXCEEDED", rule: None,
                                                detail: detail("paused", t) });
                }
            } else if t.unverified >= self.samples {
                t.unverified = 0;
                t.held_until = now + self.hold_s;
                let action = if u.pausable { "paused" } else { "evicted" };
                if !u.pausable {
                    out.evict.push(u.id);
                }
                out.events.push(DutyEvent { kind: "gpu_compliance", reason: "GPU_DUTY_UNVERIFIED", rule: None,
                                            detail: detail(action, t) });
            }
        }
        self.units.retain(|id, _| i.units.iter().any(|u| u.id == *id));
        // who may run beside the gated groups, and at what duty
        let d = self.d.unwrap_or(0.0);
        let mut eligible = vec![];
        for u in i.units.iter().filter(|u| u.cooperative) {
            let t = self.units.get_mut(&u.id).expect("tracked");
            let distrusted = self.distrusted.contains_key(&u.key);
            if out.evict.contains(&u.id) {
                t.state = "evicted";
            } else if distrusted {
                t.state = "distrusted";
                out.withheld.insert(u.id);
            } else if now < t.held_until {
                t.state = "held";
                out.withheld.insert(u.id);
            } else {
                eligible.push(u.id);
            }
        }
        if self.d.is_some() && d >= self.min_duty && !eligible.is_empty() {
            let per = floor3(d / eligible.len() as f64).max(0.001);
            for id in eligible {
                out.duty.insert(id, per);
            }
        }
        for u in &i.units {
            let t = self.units.get_mut(&u.id).expect("tracked");
            if !out.withheld.contains(&u.id) && !out.evict.contains(&u.id) {
                t.state = if out.duty.contains_key(&u.id) {
                    "ok"
                } else if u.cooperative {
                    "waiting"
                } else {
                    "cannot_throttle"
                };
            }
        }
        out
    }

    /// After the tick's plan is final: which units actually ran with their duty (not paused by anything else), for
    /// the next sample's compliance and baseline.
    pub fn observe(&mut self, duty: &BTreeMap<i64, f64>, paused: &BTreeSet<i64>, now: f64) {
        let mut ran_any = false;
        for (id, t) in self.units.iter_mut() {
            let d = duty.get(id).copied();
            t.duty_prev2 = t.duty_prev;
            t.duty_prev = d;
            t.ran = d.is_some() && !paused.contains(id);
            ran_any |= t.ran;
        }
        if ran_any {
            self.off_since = None;
        } else if self.gpu_ran || self.off_since.is_none() {
            self.off_since = Some(now);
        }
        if ran_any != self.gpu_ran {
            for r in self.rules.values_mut() {
                r.base_events = 0.0;
                r.base_seconds = 0.0;
            }
        }
        self.gpu_ran = ran_any;
    }

    /// The heartbeat's `gpu_budget` beyond what the controller adds (rules, not_certified).
    pub fn telemetry(&self, now: f64) -> Value {
        let mut units: Vec<Value> = self.units.iter().map(|(id, t)| json!({
            "id": id, "duty": t.duty_prev.map(round3), "measured": t.last_busy.map(round3), "state": t.state,
        })).collect();
        units.sort_by_key(|u| u["id"].as_i64());
        let baseline: serde_json::Map<String, Value> = self.rules.iter()
            .map(|(k, r)| (k.clone(), json!({"rate": r.baseline.map(round3), "age_s": r.baseline.map(|_| round3(now - r.baseline_at)),
                                             "pressure": r.last_pressure.map(round3)})))
            .collect();
        json!({
            "state": self.state,
            "ceiling": self.ceiling.map(round3),
            "lockout_s": if self.lockout_until > now { json!(round3(self.lockout_until - now)) } else { Value::Null },
            "baseline": Value::Object(baseline),
            "units": units,
            "distrusted": self.distrusted(now).into_iter().map(|(k, u)| json!({"unit": k, "for_s": round3(u - now)})).collect::<Vec<_>>(),
        })
    }
}
