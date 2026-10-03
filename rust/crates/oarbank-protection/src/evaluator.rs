//! Owner rules per tick: matching, HTCondor-style activity timing with the doubling resume cooldown, and
//! the constraint vectors of the active rules, combined most-restrictive-wins.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use crate::config::{ProtectionConfig, ProtectionRule, ProtectionScope};
use crate::gpu::GpuBusy;
use crate::json::{opt_int, opt_num, rounded};
use crate::matcher;
use crate::model::{GroupSample, ProcessKey, ProcessRecord};

/// What one source (a rule or a guard) demands this tick. There is no PID field: the evaluator cannot
/// express an action against a protected process (S16 made structural). Reservations are keyed by the
/// protected process identity so that a process matched by several rules is reserved once.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConstraintVector {
    pub source: String,
    pub cpu_cores: Option<f64>,
    pub slots: Option<i64>,
    pub threads: Option<i64>,
    pub staging_mbps: Option<f64>,
    pub gpu_jobs: Option<i64>,
    pub pool_jobs_only: Option<BTreeMap<String, i64>>,
    pub evict: BTreeSet<ProtectionScope>,
    pub no_admit: bool,
    pub reserve_cpu: BTreeMap<String, f64>,
    pub reserve_mem_gb: BTreeMap<String, f64>,
}

impl ConstraintVector {
    pub fn new(source: &str) -> Self {
        Self {
            source: source.to_string(),
            ..Self::default()
        }
    }

    /// A vector that only stops admission.
    pub fn no_admit(source: &str) -> Self {
        Self {
            no_admit: true,
            ..Self::new(source)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CombinedConstraint {
    pub cpu_cores: Option<f64>,
    pub slots: Option<i64>,
    pub threads: Option<i64>,
    pub staging_mbps: Option<f64>,
    pub gpu_jobs: Option<i64>,
    pub pool_jobs_only: Option<BTreeMap<String, i64>>,
    pub evict: BTreeSet<ProtectionScope>,
    pub no_admit: bool,
    pub reserved_cpu: f64,
    pub reserved_mem_gb: f64,
    /// Dimension -> the source that binds it (shown on the node page).
    pub binding: BTreeMap<String, String>,
}

/// The first largest reservation and its source.
fn top<'a>(m: &BTreeMap<&str, (f64, &'a str)>) -> Option<(f64, &'a str)> {
    m.values().fold(None, |best, &(x, s)| match best {
        Some((b, _)) if x <= b => best,
        _ => Some((x, s)),
    })
}

/// The first strictly smallest value and its source.
fn min_dim<T: PartialOrd + Copy>(
    vs: &[ConstraintVector],
    binding: &mut BTreeMap<String, String>,
    name: &str,
    get: impl Fn(&ConstraintVector) -> Option<T>,
) -> Option<T> {
    let mut best: Option<(T, &str)> = None;
    for v in vs {
        if let Some(x) = get(v) {
            if best.is_none_or(|(b, _)| x < b) {
                best = Some((x, &v.source));
            }
        }
    }
    let (x, src) = best?;
    binding.insert(name.to_string(), src.to_string());
    Some(x)
}

impl CombinedConstraint {
    /// Most restrictive wins per dimension: min of ceilings, OR of evict scopes and the admission brake, and
    /// reservations summed over distinct processes at the largest reservation each.
    pub fn combine(vs: &[ConstraintVector]) -> CombinedConstraint {
        let mut c = CombinedConstraint::default();
        let b = &mut c.binding;
        c.cpu_cores = min_dim(vs, b, "cpu_cores", |v| v.cpu_cores);
        c.slots = min_dim(vs, b, "slots", |v| v.slots);
        c.threads = min_dim(vs, b, "threads", |v| v.threads);
        c.staging_mbps = min_dim(vs, b, "staging_mbps", |v| v.staging_mbps);
        c.gpu_jobs = min_dim(vs, b, "gpu_jobs", |v| v.gpu_jobs);
        for v in vs {
            c.evict.extend(v.evict.iter().copied());
            if v.no_admit {
                if !c.no_admit {
                    c.binding.insert("admit".into(), v.source.clone());
                }
                c.no_admit = true;
            }
            if let Some(p) = &v.pool_jobs_only {
                let mut merged = c.pool_jobs_only.clone().unwrap_or_else(|| p.clone());
                for (k, &n) in p {
                    let cur = merged.get(k).copied().unwrap_or(n);
                    merged.insert(k.clone(), cur.min(n));
                }
                c.pool_jobs_only = Some(merged);
                c.binding
                    .entry("pool_jobs_only".into())
                    .or_insert_with(|| v.source.clone());
            }
        }
        let mut rc: BTreeMap<&str, (f64, &str)> = BTreeMap::new();
        let mut rm: BTreeMap<&str, (f64, &str)> = BTreeMap::new();
        for v in vs {
            for (k, &x) in &v.reserve_cpu {
                if x > rc.get(k.as_str()).map_or(-1.0, |e| e.0) {
                    rc.insert(k, (x, &v.source));
                }
            }
            for (k, &x) in &v.reserve_mem_gb {
                if x > rm.get(k.as_str()).map_or(-1.0, |e| e.0) {
                    rm.insert(k, (x, &v.source));
                }
            }
        }
        c.reserved_cpu = rc.values().map(|e| e.0).sum();
        c.reserved_mem_gb = rm.values().map(|e| e.0).sum();
        if let Some((x, s)) = top(&rc) {
            if x > 0.0 {
                c.binding.insert("reserve_cpu".into(), s.to_string());
            }
        }
        if let Some((x, s)) = top(&rm) {
            if x > 0.0 {
                c.binding.insert("reserve_mem".into(), s.to_string());
            }
        }
        c
    }

    /// The wire form (heartbeat `telemetry.protection.constraint`, journal `constraint` records).
    pub fn to_json(&self) -> Value {
        let mut o = Map::new();
        o.insert("reserved_cpu".into(), rounded(self.reserved_cpu, 2));
        o.insert("reserved_mem_gb".into(), rounded(self.reserved_mem_gb, 2));
        o.insert("no_admit".into(), Value::from(self.no_admit));
        o.insert(
            "evict".into(),
            Value::Array(self.evict.iter().map(|s| Value::from(s.as_str())).collect()),
        );
        o.insert(
            "binding".into(),
            Value::Object(
                self.binding
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
                    .collect(),
            ),
        );
        o.insert("cpu_cores".into(), opt_num(self.cpu_cores));
        o.insert("slots".into(), opt_int(self.slots));
        o.insert("threads".into(), opt_int(self.threads));
        o.insert("staging_mbps".into(), opt_num(self.staging_mbps));
        o.insert("gpu_jobs".into(), opt_int(self.gpu_jobs));
        if let Some(p) = &self.pool_jobs_only {
            o.insert(
                "pool_jobs_only".into(),
                Value::Object(
                    p.iter()
                        .map(|(k, &n)| (k.clone(), Value::from(n)))
                        .collect(),
                ),
            );
        }
        Value::Object(o)
    }
}

impl Serialize for CombinedConstraint {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

/// Per-rule activity with HTCondor-style asymmetric timing: a rule becomes active after its condition held
/// for `enter_for_s` and inactive after it has been false for `exit_after_s`. A reserve-only rule enters at
/// once (reserving is the least intrusive action and must not lag the protected process).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleState {
    pub active: bool,
    pub condition_since: Option<f64>,
    pub clear_since: Option<f64>,
    pub history: Vec<GroupSample>,
    pub last_group_count: usize,
    /// Start times of recent activations (for the doubling resume cooldown) and the hold chosen at entry.
    pub activations: Vec<f64>,
    pub hold: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuleReport {
    pub id: String,
    pub active: bool,
    pub processes: usize,
    pub cpu_cores: f64,
    pub footprint_gb: f64,
    pub reason: String,
}

impl RuleReport {
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": self.id, "active": self.active, "processes": self.processes,
            "cpu_cores": rounded(self.cpu_cores, 2), "footprint_gb": rounded(self.footprint_gb, 2), "reason": self.reason,
        })
    }
}

impl Serialize for RuleReport {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

/// A transition worth journaling.
#[derive(Debug, Clone, PartialEq)]
pub struct ProtectionEvent {
    /// rule_active | rule_inactive | rung_change | budget_step | probe_result
    pub kind: String,
    pub rule: String,
    pub reason: String,
    pub signals: BTreeMap<String, f64>,
}

impl ProtectionEvent {
    pub fn new(kind: &str, rule: &str, reason: &str, signals: &[(&str, f64)]) -> Self {
        Self {
            kind: kind.into(),
            rule: rule.into(),
            reason: reason.into(),
            signals: signals.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }
}

/// One evaluation: the constraint vectors of the active rules, the per-rule report and the transitions.
#[derive(Debug, Clone, Default)]
pub struct Evaluation {
    pub vectors: Vec<ConstraintVector>,
    pub reports: Vec<RuleReport>,
    pub events: Vec<ProtectionEvent>,
}

#[derive(Debug, Clone, Default)]
pub struct RuleEvaluator {
    pub states: HashMap<String, RuleState>,
    /// The active rules of the last evaluation and the processes each protects (for metrics and dynamic actions).
    pub active_rules: Vec<ProtectionRule>,
    pub groups: HashMap<String, Vec<ProcessRecord>>,
    /// Rules that became active in the last evaluation.
    pub started: Vec<String>,
}

impl RuleEvaluator {
    pub fn new() -> Self {
        Self::default()
    }

    /// One tick: match every rule against the process table, update activity and history, and return the
    /// constraint vectors of the active rules, the per-rule report and the transitions. `frontmost` is the
    /// frontmost application's pid and `gpu` each process's GPU busy fraction since the last tick (None:
    /// unknown).
    pub fn evaluate(
        &mut self,
        config: &ProtectionConfig,
        procs: &[ProcessRecord],
        cpu_cores: &HashMap<ProcessKey, f64>,
        frontmost: Option<i32>,
        gpu: Option<&GpuBusy>,
        now: f64,
    ) -> Evaluation {
        self.active_rules.clear();
        self.groups.clear();
        self.started.clear();
        let mut out = Evaluation::default();
        let live: HashSet<&str> = config.rules.iter().map(|r| r.id.as_str()).collect();
        self.states.retain(|k, _| live.contains(k.as_str()));
        for rule in &config.rules {
            let group = matcher::group(procs, &rule.match_, rule.tree);
            let cpu: f64 = group
                .iter()
                .map(|p| cpu_cores.get(&p.key()).copied().unwrap_or(0.0))
                .sum();
            let mem: f64 = group.iter().map(|p| p.footprint_gb).sum();
            let mut st = self.states.remove(&rule.id).unwrap_or_default();
            st.history
                .push(GroupSample::new(now, cpu, mem, group.len()));
            let window = rule
                .reserve_cpu
                .as_ref()
                .map_or(0.0, |e| e.window_s)
                .max(rule.reserve_mem_gb.as_ref().map_or(0.0, |e| e.window_s))
                .max(60.0);
            st.history.retain(|s| now - s.t <= window + 1e-9);
            st.last_group_count = group.len();
            let aw = &rule.active_when;
            // the group's GPU busy fraction (None: unknown), read only for rules that trigger on it
            let gpu_busy = aw
                .gpu_min_busy
                .and_then(|_| gpu?.group(group.iter().map(|p| p.pid)));
            let mut cond = !group.is_empty();
            if cond && !aw.present {
                cond = false;
                if aw.cpu_cores_gt.is_some_and(|x| cpu > x) {
                    cond = true;
                }
                if aw.footprint_gb_gt.is_some_and(|x| mem > x) {
                    cond = true;
                }
                // the app in front is (or is not) one of the group's processes; an unknown front app satisfies
                // either (never looser)
                if aw.frontmost.is_some_and(|want| {
                    frontmost.is_none_or(|fp| group.iter().any(|p| p.pid == fp) == want)
                }) {
                    cond = true;
                }
                // GPU usage that cannot be read counts as busy (never looser)
                if aw
                    .gpu_min_busy
                    .is_some_and(|min| gpu_busy.is_none_or(|b| b >= min))
                {
                    cond = true;
                }
            }
            let reserve_only = rule.cap_fleet.is_none()
                && rule.evict.is_none()
                && !rule.lower_fleet
                && rule.pause_fleet.is_none();
            // rules that stop admission (rung 1 and up) resume only after the doubling cooldown; caps reverse
            // after exit_after (the dynamic layer grows them back through AIMD)
            let stops_admission = rule.cap_fleet.as_ref().is_some_and(|c| c.slots == Some(0))
                || rule.evict.is_some()
                || rule.pause_fleet.is_some();
            let enter = if reserve_only && aw.for_s.is_none() {
                0.0
            } else {
                aw.for_s.or(rule.enter_for_s).unwrap_or(config.enter_for_s)
            };
            let exit = rule.exit_after_s.unwrap_or(config.exit_after_s);
            let cooldown = |n: usize| {
                exit.max(
                    config
                        .cooldown_max_s
                        .min(config.cooldown_base_s * config.cooldown_backoff.powf(n as f64)),
                )
            };
            st.activations
                .retain(|a| now - a < config.cooldown_window_s);
            if cond {
                if st.active && st.clear_since.is_some() && stops_admission {
                    // re-triggered during the resume cooldown: a new activation, with a doubled cooldown
                    st.hold = cooldown(st.activations.len());
                    st.activations.push(now);
                }
                st.clear_since = None;
                let since = *st.condition_since.get_or_insert(now);
                if !st.active && now - since >= enter - 1e-9 {
                    st.active = true;
                    st.hold = if stops_admission {
                        cooldown(st.activations.len())
                    } else {
                        exit
                    };
                    st.activations.push(now);
                    self.started.push(rule.id.clone());
                    let mut e = ProtectionEvent::new(
                        "rule_active",
                        &rule.id,
                        "PROTECTION_ACTIVE",
                        &[
                            ("cpu_cores", cpu),
                            ("footprint_gb", mem),
                            ("processes", group.len() as f64),
                        ],
                    );
                    if let Some(b) = gpu_busy {
                        e.signals.insert("gpu_busy".into(), b);
                    }
                    out.events.push(e);
                }
            } else {
                st.condition_since = None;
                if st.active {
                    let since = *st.clear_since.get_or_insert(now);
                    // a group that vanished entirely releases at once for reserve-only rules (nothing to protect)
                    if (group.is_empty() && reserve_only) || now - since >= st.hold - 1e-9 {
                        st.active = false;
                        st.clear_since = None;
                        out.events.push(ProtectionEvent::new(
                            "rule_inactive",
                            &rule.id,
                            "PROTECTION_CLEARED",
                            &[("cpu_cores", cpu), ("footprint_gb", mem)],
                        ));
                    }
                }
            }
            let active = st.active;
            let reason = if rule.ignore {
                "ignore rule"
            } else if active {
                "active"
            } else if group.is_empty() {
                "no matching process"
            } else {
                "condition not met"
            };
            out.reports.push(RuleReport {
                id: rule.id.clone(),
                active: active && !rule.ignore,
                processes: group.len(),
                cpu_cores: cpu,
                footprint_gb: mem,
                reason: reason.into(),
            });
            if active && !rule.ignore {
                self.active_rules.push(rule.clone());
                let mut v = ConstraintVector::new(&format!("rule:{}", rule.id));
                // reservations are attributed to the group's oldest process (one key per protected group)
                let owner = group
                    .iter()
                    .min_by_key(|p| (p.start_us, p.pid))
                    .map_or_else(|| rule.id.clone(), |p| p.key().to_string());
                if let Some(e) = &rule.reserve_cpu {
                    v.reserve_cpu
                        .insert(owner.clone(), e.evaluate(&st.history, now));
                }
                if let Some(e) = &rule.reserve_mem_gb {
                    v.reserve_mem_gb.insert(owner, e.evaluate(&st.history, now));
                }
                if let Some(cf) = &rule.cap_fleet {
                    v.cpu_cores = cf.cpu_cores;
                    v.threads = cf.threads;
                    v.staging_mbps = cf.staging_mbps;
                    v.gpu_jobs = cf.gpu_jobs;
                    if cf.slots == Some(0) && !cf.pools.is_empty() {
                        v.pool_jobs_only = Some(cf.pools.clone());
                    } else {
                        v.slots = cf.slots;
                    }
                }
                if let Some(e) = rule.evict {
                    v.evict.insert(e);
                }
                out.vectors.push(v);
            }
            self.states.insert(rule.id.clone(), st);
            self.groups.insert(rule.id.clone(), group);
        }
        out
    }
}
