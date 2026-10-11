//! Protection for one agent tick: rules (static actions), the L0 memory guard, the thermal and battery
//! gates, and (moderate, strict_yield) the dynamic controller over measured metrics, combined into one
//! constraint plus the per-attempt actuation plan (lower, pause, evict, throttle). The plan names only fleet
//! attempts; the spawn registry applies it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::certificates::{self, CertContext, Certificate};
use crate::config::{ProtectionConfig, ProtectionMode, ProtectionRule, ProtectionScope};
use crate::harness::{AbSpec, Arm, Harness, HarnessTick, OffMode};
use crate::dynamic::{DynInputs, DynJob, DynamicController, ProtectedSignal, ThrottleDoc};
use crate::evaluator::{
    CombinedConstraint, ConstraintVector, ProtectionEvent, RuleEvaluator, RuleReport,
};
use crate::gpu::{GpuBusy, GpuTimes};
use crate::gpu_duty::{DutyGovernor, DutyInputs, DutySignal, DutyUnit};
use crate::journal::DecisionJournal;
use crate::json::{obj, opt_num, opt_str, rounded, strings};
use crate::matcher;
use crate::memory_guard::{GuardLevel, MemoryGuard, MemorySignals, SystemGates, VictimCandidate};
use crate::model::{ProcessKey, ProcessRecord};
use crate::signals::{Front, FrontReading, GroupMetrics, Meter, NullMeter, ProcCounters};
use crate::sources::{NoOwnerSources, OwnerSources, Progress};
use crate::support::{self, Os};
use crate::table::{ProcessSource, ProcessSummaryRow, ProcessTable, UnsupportedProcessSource};
use crate::telemetry::{ProgressReport, ProtectionTelemetry};
use crate::workloads::{
    DelegatedAction, DelegatedGroup, DelegationLadder, FleetWorkloadView, LadderInputs, WorkloadAction, WorkloadLadder,
};

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
    /// The module and the stage (the harness's work selector matches them).
    pub module: String,
    pub name: String,
    /// The runner declares `cooperative_throttle`: it honours `threads` and `gpu_duty` in its control document.
    pub duty: bool,
    /// Every process of the job (its group's members): whose GPU time the duty governor checks against `gpu_duty`.
    /// Empty: the group leader (`pgid`) alone.
    pub pids: Vec<i32>,
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

/// A running module service as protection sees it: fleet work like a job, which protection may stop (only when
/// `yieldable`), releasing the attempts that use it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FleetServiceView {
    /// `module/service`.
    pub key: String,
    pub footprint_gb: f64,
    pub started_at: f64,
    /// `gpu.use` is not none: GPU-resident.
    pub gpu: bool,
    pub yieldable: bool,
    /// The attempts that use it (released with it).
    pub users: Vec<i64>,
}

/// A service to stop now and keep down while this holds, with the release reason for its users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStop {
    pub key: String,
    pub reason: String,
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
    /// Services to stop and hold down (yieldable ones only): the memory guard's victim, a rule's evict, GPU work
    /// that may not run.
    pub service_stops: Vec<ServiceStop>,
    /// The plan for each workload (docs/design/workloads.md, "Protection on workloads"), by `module/workload`.
    pub workloads: BTreeMap<String, WorkloadAction>,
    /// What to do with each delegated tree of the owner's (only with `delegated_processes` on).
    pub delegated: Vec<DelegatedAction>,
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
    /// Running module services (their processes are in `fleet_pids` too).
    pub services: Vec<FleetServiceView>,
    /// Workloads that run or that protection holds down (a running one's processes are in `fleet_pids` too).
    pub workloads: Vec<FleetWorkloadView>,
    /// Seconds since the last user input (0 while someone is present).
    pub user_idle_s: f64,
    /// perf + eff/2 cores; the dynamic budget's ceiling before reservations.
    pub allocatable_cores: f64,
    /// The agent can lower its jobs here (see [`DynInputs::lowering`]).
    pub lowering: bool,
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
            services: vec![],
            workloads: vec![],
            user_idle_s: 1e9,
            allocatable_cores: 0.0,
            lowering: true,
        }
    }
}

/// The host interfaces the controller reads (never writes): the process table, the meters and the owner's
/// sources, and the OS whose limits a config must respect (None: no OS, nothing refused).
pub struct Host {
    pub processes: Box<dyn ProcessSource>,
    pub meter: Box<dyn Meter>,
    pub sources: Box<dyn OwnerSources>,
    pub os: Option<Os>,
}

impl Host {
    /// Nothing measurable: an empty table, unknown metrics, no owner sources, no OS (tests and pure replays).
    pub fn unavailable() -> Self {
        Self {
            processes: Box::new(UnsupportedProcessSource),
            meter: Box::new(NullMeter),
            sources: Box::new(NoOwnerSources),
            os: None,
        }
    }

    /// This platform's process table and meters, and file-based owner sources (no session helpers).
    pub fn native() -> Self {
        crate::platform::native_host(None)
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
    os: Option<Os>,
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
    /// What was in front on the last tick, when something needed it.
    last_front: Option<FrontReading>,
    /// Whether the agent could lower its jobs on the last tick.
    lowering: bool,
    /// Per `protect.metric = ipc_ratio` rule, whether its processes' instruction and cycle counters count, as last
    /// told by a sample with enough CPU time.
    instruction_counters: BTreeMap<String, bool>,
    last_inputs: Option<CachedInputs>,
    /// Services stopped on the last tick (journaled when that changes).
    last_service_stops: BTreeSet<String>,
    workload_ladder: WorkloadLadder,
    /// Workloads the memory guard chose as its victim this tick (from the evaluation to the dynamic layer).
    workload_victims: BTreeSet<String>,
    delegation_ladder: DelegationLadder,
    /// The node's `delegated_processes` setting: delegations count only while it is on.
    delegation_allowed: bool,
    /// The owner's delegated trees as of this tick's process table.
    delegated_groups: Vec<DelegatedGroup>,
    /// Whether a delegation by path may name this executable (`workloads::path_trusted`; tests replace it).
    pub path_trusted: fn(&str) -> bool,
    /// The paired on/off harness run (D52): the one running, or the last one until the coordinator has its result.
    harness: Option<Harness>,
    /// The arm the harness put the work under test in on the last tick (journaled when it changes).
    last_arm: Option<(String, Option<Arm>)>,
    /// Co-tenancy certificates the coordinator sent for this node, and what this node is (hardware, OS, agent).
    certificates: Vec<Certificate>,
    cert_context: CertContext,
    /// Per rule with a matched group: the protected program's identity this tick.
    identities: BTreeMap<String, String>,
    /// Per rule: its group's fingerprint (pids and start times) this tick.
    groups_fp: BTreeMap<String, u64>,
    /// Per protect rule: the last progress reading.
    progress: HashMap<String, Option<Progress>>,
    /// The GPU budget under `gpu_jobs = certified` on the last tick (telemetry), and why certified work was held
    /// back (journaled when it changes).
    gpu_budget: Option<Value>,
    last_not_certified: Option<String>,
    /// The last tick's battery state (the harness excludes a block when it changes).
    on_battery: bool,
    /// The GPU duty governor (D50): the AIMD budget under the certified ceiling and the compliance check.
    pub duty: DutyGovernor,
    /// Each process's GPU busy fraction over the last sample (the compliance check reads it; None: unknown).
    last_busy: Option<GpuBusy>,
}

/// Stop `svc` (once) and release every attempt using it with the same reason.
fn stop_service(svc: &FleetServiceView, reason: &str, stops: &mut Vec<ServiceStop>, evictions: &mut Vec<Eviction>) {
    if stops.iter().any(|s| s.key == svc.key) {
        return;
    }
    stops.push(ServiceStop {
        key: svc.key.clone(),
        reason: reason.into(),
    });
    for &a in &svc.users {
        if !evictions.iter().any(|e| e.attempt_id == a) {
            evictions.push(Eviction {
                attempt_id: a,
                reason: reason.into(),
            });
        }
    }
}

/// Parse one part of the config and refuse what cannot work on the host's OS (support.rs).
fn for_os(j: &Value, source: &str, os: Option<Os>) -> Result<ProtectionConfig, String> {
    let cfg = ProtectionConfig::from_json(j, source).map_err(|e| e.to_string())?;
    match os.map(|os| support::refusals(&cfg, os)) {
        Some(r) if !r.is_empty() => Err(r.join("; ")),
        _ => Ok(cfg),
    }
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
        let mut host = host;
        host.sources.attach(journal.clone());
        Self {
            config: ProtectionConfig::default(),
            os: host.os,
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
            last_front: None,
            lowering: true,
            instruction_counters: BTreeMap::new(),
            last_inputs: None,
            last_service_stops: BTreeSet::new(),
            workload_ladder: WorkloadLadder::new(),
            workload_victims: BTreeSet::new(),
            delegation_ladder: DelegationLadder::new(),
            delegation_allowed: false,
            delegated_groups: vec![],
            path_trusted: crate::workloads::path_trusted,
            harness: None,
            last_arm: None,
            certificates: vec![],
            cert_context: CertContext::default(),
            identities: BTreeMap::new(),
            groups_fp: BTreeMap::new(),
            progress: HashMap::new(),
            gpu_budget: None,
            last_not_certified: None,
            on_battery: false,
            duty: DutyGovernor::new(),
            last_busy: None,
        }
    }

    /// The node's `delegated_processes` setting (off by default; a machine's managed policy can force it off).
    pub fn set_delegation_allowed(&mut self, on: bool) {
        if on != self.delegation_allowed {
            self.journal("config_applied", "PROTECTION_CONFIG", None,
                         obj([("delegated_processes", Value::from(on))]));
        }
        self.delegation_allowed = on;
    }

    /// The owner's delegated trees in this process table (none while the setting is off).
    fn delegated_in(&self, procs: &[ProcessRecord]) -> Vec<DelegatedGroup> {
        if !self.delegation_allowed {
            return vec![];
        }
        let trusted = self.path_trusted;
        self.config.delegations.iter().filter_map(|d| {
            let exact = d.match_.path_prefix.clone().filter(|_| d.match_.requirement.is_none() && d.match_.identifier.is_none());
            let g = matcher::strict_group(procs, &d.match_, d.tree, |p| match &exact {
                Some(path) => p.path.as_deref() == Some(path.as_str()) && trusted(path),
                None => true,
            });
            (!g.is_empty()).then(|| DelegatedGroup {
                rule: d.id.clone(),
                procs: g.iter().map(|p| (p.pid, p.start_us)).collect(),
                footprint_gb: g.iter().map(|p| p.footprint_gb).sum(),
                started_at: g.iter().map(|p| p.start_us as f64 / 1e6).fold(f64::INFINITY, f64::min),
                pause: d.pause,
                lower: d.lower,
            })
        }).collect()
    }

    // ------------------------------------------------------------------ the harness and certificates (D52, D50)

    /// Start a paired on/off run. Refused while another runs, for a rule without a `progress_rate` source, or for GPU
    /// work on a node whose owner said `gpu_jobs = never`.
    pub fn start_ab(&mut self, spec: AbSpec, now: f64) -> Result<(), String> {
        if self.harness.as_ref().is_some_and(|h| !h.finished()) {
            return Err("another harness run is in progress on this node".into());
        }
        let rule = self.config.rules.iter().find(|r| r.id == spec.rule)
            .ok_or_else(|| format!("no rule {} on this node", spec.rule))?;
        let ok = rule.protect.as_ref().is_some_and(|p| p.metric == "progress_rate" && p.source_json.is_some());
        if !ok {
            return Err(format!("rule {} has no protect.metric = progress_rate source to measure", spec.rule));
        }
        let h = Harness::new(spec, now)?;
        if h.work.includes_gpu() && self.config.gpu_jobs == "never" && !matches!(h.work, crate::harness::WorkSelector::All) {
            return Err("this node's owner set gpu_jobs = never: no GPU work runs here to measure".into());
        }
        self.journal("ab_started", "AB_STARTED", Some(&h.spec.rule),
                     obj([("run_id", Value::from(h.spec.run_id.as_str())), ("work", Value::from(h.spec.work.as_str())),
                          ("duty", opt_num(h.spec.duty))]));
        self.harness = Some(h);
        Ok(())
    }

    /// Abort a run (the coordinator's `ab_abort`).
    pub fn abort_ab(&mut self, run_id: &str, now: f64, reason: &str) {
        if let Some(h) = self.harness.as_mut().filter(|h| h.spec.run_id == run_id) {
            h.abort(now, reason);
        }
    }

    /// The current or last run, for the heartbeat (`ab_runs`).
    pub fn ab_report(&self, now: f64) -> Option<Value> {
        self.harness.as_ref().map(|h| h.report(now))
    }

    /// The coordinator stored the finished run: forget it.
    pub fn ab_ack(&mut self, run_id: &str) {
        if self.harness.as_ref().is_some_and(|h| h.finished() && h.spec.run_id == run_id) {
            self.harness = None;
        }
    }

    /// The running harness (tests and the agent's status page).
    pub fn harness(&self) -> Option<&Harness> {
        self.harness.as_ref()
    }

    /// The certificates the coordinator sent, and this node's hardware, OS and agent (what they must match).
    pub fn set_certificates(&mut self, certs: Vec<Certificate>, context: CertContext) {
        self.certificates = certs;
        self.cert_context = context;
    }

    /// The protected program's identity under a rule now (None: its group is empty).
    pub fn identity(&self, rule: &str) -> Option<&str> {
        self.identities.get(rule).map(String::as_str)
    }

    /// The GPU duty a valid certificate allows beside a rule's protected group now (the step-4 duty controller's
    /// ceiling; None: no valid certificate covers GPU work for that rule).
    pub fn certified_duty(&self, rule: &str, now: f64) -> Option<f64> {
        let identity = self.identities.get(rule).map(String::as_str);
        self.certificates
            .iter()
            .filter(|c| c.rule == rule && c.invalid(now, identity, &self.cert_context).is_none())
            .filter_map(Certificate::gpu_duty)
            .fold(None, |a: Option<f64>, d| Some(a.map_or(d, |a| a.max(d))))
    }

    pub fn config(&self) -> &ProtectionConfig {
        &self.config
    }

    /// The agent's fast path for immediate phases (D51): what pauses fleet work between ticks.
    pub fn set_fast_path(&mut self, f: Arc<dyn crate::events::FastPath>) {
        self.sources.set_fast_path(f);
    }

    /// Why the last config could not be applied in full (shown as PROTECTION_CONFIG_ERROR).
    pub fn config_error(&self) -> Option<&str> {
        self.config_error.as_deref()
    }

    /// Why the process table could not be read on the last tick (unsupported platform, permissions).
    pub fn source_error(&self) -> Option<&str> {
        self.source_error.as_deref()
    }

    /// What was in front on the last tick (None: nothing needed it).
    pub fn last_front(&self) -> Option<&FrontReading> {
        self.last_front.as_ref()
    }

    pub fn last_reports(&self) -> &[RuleReport] {
        &self.last_reports
    }

    fn journal(&self, kind: &str, reason: &str, rule: Option<&str>, detail: Map<String, Value>) {
        if let Some(j) = &self.journal {
            j.record(kind, reason, rule, detail);
        }
    }

    /// Central section (from the node policy) unioned with the local file; a broken part (or one asking what
    /// this OS cannot do, support.rs) is reported and ignored, never loosening: a broken local file keeps the
    /// central config, a broken central one keeps the last good config.
    pub fn apply(&mut self, central: Option<&Value>, local: &LocalProtection) {
        let mut c: Option<ProtectionConfig> = None;
        let mut errors: Vec<String> = vec![];
        match central {
            Some(j) => match for_os(j, "central", self.os) {
                Ok(cfg) => c = Some(cfg),
                Err(e) => errors.push(format!("central: {e}")),
            },
            None => c = Some(ProtectionConfig::default()),
        }
        match local {
            LocalProtection::Absent => {}
            LocalProtection::Invalid(path) => errors.push(format!("local: {path} is not JSON")),
            LocalProtection::Json(j) => match for_os(j, "local", self.os) {
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
            self.dynamic.max_pause_s = new.max_pause_s;
            self.config = new;
            self.sources.reset();
            self.sources.configure(&self.config);
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
        let read_front = implicit_front || rules_front;
        let reading = read_front.then(|| self.meter.front());
        let front = reading.as_ref().map_or(Front::Unknown, |r| r.front);
        self.last_front = reading;
        let gpu = self.read_gpu(i.now);
        self.last_busy = gpu.clone();
        // evaluate first (it decides which rules are active), then measure the active groups
        let r =
            self.evaluate_with_metrics(i, &snap.procs, &snap.cpu_cores, front, gpu.as_ref(), None);
        let front = front.app().filter(|_| implicit_front);
        // the owner's delegated trees (found by the evaluation) are fleet work: no owner load
        let delegated: HashSet<i32> = self.delegated_groups.iter().flat_map(|g| g.procs.iter().map(|p| p.0)).collect();
        let procs: Vec<ProcessRecord> = snap.procs.iter().filter(|p| !delegated.contains(&p.pid)).cloned().collect();
        let fleet: HashSet<i32> = i.fleet_pids.union(&delegated).copied().collect();
        let metrics = self.live_metrics(i.now, &procs, &fleet, front, gpu.as_ref());
        self.redo_dynamic(r, i, &metrics, front.is_some())
    }

    /// Each process's GPU busy fraction since the last reading, when anything reads it: a `gpu_active` trigger,
    /// a `protect` rule (whether its group is GPU-bound decides which proxies may grow) or `gpu_jobs =
    /// when_no_gpu_protected`. None: unknown (the source is unavailable, or this is the first reading).
    fn read_gpu(&mut self, now: f64) -> Option<GpuBusy> {
        let need = matches!(self.config.gpu_jobs.as_str(), "when_no_gpu_protected" | "certified")
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

    /// The pure part of a tick with no measured metrics yet and the front app and GPU use unknown (tests and
    /// the differential replay drive this).
    pub fn evaluate(
        &mut self,
        i: &TickInputs,
        procs: &[ProcessRecord],
        cpu_cores: &HashMap<ProcessKey, f64>,
    ) -> ProtectionTickResult {
        self.evaluate_with_metrics(i, procs, cpu_cores, Front::Unknown, None, Some(&HashMap::new()))
    }

    /// The pure part of a tick. `front` is what is in front and `gpu` each process's GPU busy fraction
    /// (None: unknown); `metrics` supplies measured protected metrics by source ("rule:<id>", "implicit:*");
    /// None skips the dynamic layer (the caller runs it after measuring).
    pub fn evaluate_with_metrics(
        &mut self,
        i: &TickInputs,
        procs: &[ProcessRecord],
        cpu_cores: &HashMap<ProcessKey, f64>,
        front: Front,
        gpu: Option<&GpuBusy>,
        metrics: Option<&HashMap<String, GroupMetrics>>,
    ) -> ProtectionTickResult {
        let now = i.now;
        // the owner's delegated trees are fleet work: no rule protects them
        self.delegated_groups = self.delegated_in(procs);
        let delegated: HashSet<i32> = self.delegated_groups.iter().flat_map(|g| g.procs.iter().map(|p| p.0)).collect();
        let kept: Vec<ProcessRecord>;
        let procs = if delegated.is_empty() {
            procs
        } else {
            kept = procs.iter().filter(|p| !delegated.contains(&p.pid)).cloned().collect();
            &kept[..]
        };
        let ev = self
            .evaluator
            .evaluate(&self.config, procs, cpu_cores, front, gpu, now);
        for e in &ev.events {
            self.journal(&e.kind, &e.reason, Some(&e.rule), signals_json(&e.signals));
        }
        // the protected programs' identities (certificates), their groups' fingerprints (the harness), process
        // triggers, and the rules whose immediate phases may act between ticks
        self.identities.clear();
        self.groups_fp.clear();
        let mut armed: BTreeSet<String> = self.evaluator.active_rules.iter().map(|r| r.id.clone()).collect();
        for rule in &self.config.rules {
            let group = self.evaluator.groups.get(&rule.id).cloned().unwrap_or_default();
            let direct: Vec<ProcessRecord> =
                group.iter().filter(|p| matcher::matches(p, &rule.match_)).cloned().collect();
            if let Some(id) = certificates::identity(&direct) {
                self.identities.insert(rule.id.clone(), id);
            }
            self.groups_fp.insert(rule.id.clone(), certificates::group_fingerprint(&group));
            if rule.immediate && !group.is_empty() {
                armed.insert(rule.id.clone());
            }
            for (n, d) in rule.during.iter().enumerate() {
                if let Some((m, tree)) = &d.on_exec {
                    let on = !matcher::group(procs, m, *tree).is_empty();
                    self.sources.set_exec_phase(&format!("{}#{n}", rule.id), on);
                }
            }
        }
        self.sources.arm(&armed, &i.fleet_pids);
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
        let mut service_stops: Vec<ServiceStop> = vec![];
        // jobs and yieldable services compete as the memory guard's victim; a service stands as -(its index + 1)
        let yieldable: Vec<&FleetServiceView> = i.services.iter().filter(|s| s.yieldable).collect();
        let running_workloads: Vec<&FleetWorkloadView> = i.workloads.iter().filter(|w| w.running).collect();
        self.workload_victims.clear();
        let candidates: Vec<VictimCandidate> = i
            .jobs
            .iter()
            .map(|j| VictimCandidate {
                attempt_id: j.attempt_id,
                footprint_gb: j.footprint_gb,
                started_at: j.started_at,
            })
            .chain(yieldable.iter().enumerate().map(|(n, s)| VictimCandidate {
                attempt_id: -(n as i64) - 1,
                footprint_gb: s.footprint_gb,
                started_at: s.started_at,
            }))
            .chain(running_workloads.iter().map(|w| VictimCandidate {
                attempt_id: w.id(),
                footprint_gb: w.footprint_gb,
                started_at: w.started_at,
            }))
            .collect();
        if evict_now {
            if let Some(victim) = MemoryGuard::victim(&candidates) {
                let mut detail = vec![
                    ("why", Value::from(self.memory_guard.reason.as_str())),
                    ("free_pct", rounded(i.memory.free_pct(), 1)),
                ];
                let code = if crate::workloads::is_fleet_id(victim) {
                    let w = running_workloads.iter().find(|w| w.id() == victim).expect("a candidate");
                    self.workload_victims.insert(w.key.clone());
                    detail.push(("workload", Value::from(w.key.as_str())));
                    "MEMORY_HARD_FLOOR_WORKLOAD"
                } else if victim < 0 {
                    let svc = yieldable[(-victim - 1) as usize];
                    stop_service(svc, "preempt_memory", &mut service_stops, &mut evictions);
                    detail.push(("service", Value::from(svc.key.as_str())));
                    "MEMORY_HARD_FLOOR_SERVICE"
                } else {
                    evictions.push(Eviction {
                        attempt_id: victim,
                        reason: "preempt_memory".into(),
                    });
                    detail.push(("attempt", Value::from(victim)));
                    "MEMORY_HARD_FLOOR"
                };
                self.journal("guard_fired", code, None, obj(detail));
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
            for svc in &yieldable {
                stop_service(svc, "preempt_protection", &mut service_stops, &mut evictions);
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
            service_stops,
            workloads: BTreeMap::new(),
            delegated: vec![],
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
        self.progress.clear();
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
                let p = self.sources.progress(&id, &src, now);
                m.progress_rate = p.and_then(|p| p.rate());
                self.progress.insert(id.clone(), p);
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
        di.lowering = i.lowering;
        self.lowering = i.lowering;
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
                probe_exempt: false,
                gpu_duty: None,
            })
            .collect();
        // workloads and delegated trees: fleet work for the rungs, never probed (their own ladders decide the rest)
        di.jobs.extend(i.workloads.iter().filter(|w| w.running).map(|w| DynJob {
            attempt_id: w.id(),
            pausable: w.can_pause(),
            cooperative: false,
            gpu: w.gpu,
            footprint_gb: w.footprint_gb,
            started_at: w.started_at,
            bandwidth: None,
            probe_exempt: true,
            gpu_duty: None,
        }));
        di.jobs.extend(self.delegated_groups.iter().map(|g| DynJob {
            attempt_id: g.id(),
            pausable: g.pause,
            cooperative: false,
            gpu: false,
            footprint_gb: g.footprint_gb,
            started_at: g.started_at,
            bandwidth: None,
            probe_exempt: true,
            gpu_duty: None,
        }));
        let mut extra: Vec<ConstraintVector> = vec![];
        // rules whose GPU gate applies (gpu_jobs = certified asks each for a certificate)
        let mut gate_rules: Vec<String> = vec![];
        // the rules whose during blocks apply: the active ones, and immediate ones whose group is present
        let mut during_rules: Vec<(ProtectionRule, bool)> =
            self.evaluator.active_rules.iter().map(|r| (r.clone(), true)).collect();
        for r in self.config.rules.iter().filter(|r| r.immediate && !r.ignore) {
            let present = self.evaluator.groups.get(&r.id).is_some_and(|g| !g.is_empty());
            if present && !during_rules.iter().any(|(x, _)| x.id == r.id) {
                during_rules.push((r.clone(), false));
            }
        }
        let mut phase_rules: BTreeSet<String> = BTreeSet::new();
        for rule in &self.evaluator.active_rules {
            if rule.lower_fleet {
                di.lower_rules.push(rule.id.clone());
            }
            if let Some(sc) = rule.pause_fleet {
                di.pause_rules.push((rule.id.clone(), sc));
            }
            if let Some(p) = &rule.protect {
                let m = metrics.get(&format!("rule:{}", rule.id));
                if let Some(c) = m.and_then(|m| m.instruction_counters) {
                    if p.metric == "ipc_ratio" {
                        self.instruction_counters.insert(rule.id.clone(), c);
                    }
                }
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
                // a group using the GPU gates GPU work when its rule protects its GPU share, or its progress (the GPU
                // trainer a certificate is earned against, D50) unless the owner said gpu_jobs = always
                let gates = p.metric == "gpu_share" || (p.metric == "progress_rate" && cfg.gpu_jobs != "always");
                if gates && m.and_then(|m| m.gpu_share).is_some_and(|g| g > 0.05) {
                    di.gpu_protected_active = true;
                    gate_rules.push(rule.id.clone());
                }
            }
            if matches!(
                rule.pause_fleet,
                Some(ProtectionScope::Gpu | ProtectionScope::All)
            ) && cfg.gpu_jobs != "always"
            {
                di.gpu_protected_active = true;
                gate_rules.push(rule.id.clone());
            }
        }
        for (rule, _active) in &during_rules {
            // phase-aware extras while the owner's source says the phase is on
            for (k, d) in rule.during.iter().enumerate() {
                let key = format!("{}#{k}", rule.id);
                if !self.sources.phase_on(&key, &d.source_json) {
                    continue;
                }
                phase_rules.insert(rule.id.clone());
                let mut v = ConstraintVector::new(&format!("rule:{}/during", rule.id));
                if let Some(cf) = &d.cap_fleet {
                    v.cpu_cores = cf.cpu_cores;
                    v.slots = cf.slots;
                    v.staging_mbps = cf.staging_mbps;
                    v.gpu_jobs = cf.gpu_jobs;
                    v.threads = cf.threads;
                }
                if let Some(sc) = d.pause_fleet {
                    crate::evaluator::pause_vector(&mut v, sc);
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
        // gpu_jobs = certified (D50): GPU work that honours gpu_duty may run beside the gated groups at the duty
        // governor's budget, an AIMD loop on their progress under the smallest certified duty among them, while it holds
        // the duty it is asked; without a valid certificate for every one, the gate holds as in when_no_gpu_protected.
        // While a harness run measures GPU work, the governor stands down and the run alone decides what runs.
        self.gpu_budget = None;
        let mut duty_of: BTreeMap<i64, f64> = BTreeMap::new();
        let certified = cfg.gpu_jobs == "certified" && di.gpu_protected_active;
        let harness_gpu = self.harness.as_ref().is_some_and(|h| !h.finished() && h.work.includes_gpu());
        gate_rules.sort();
        gate_rules.dedup();
        let duties: Vec<(String, Option<f64>)> = if certified {
            gate_rules.iter().map(|r| (r.clone(), self.certified_duty(r, now))).collect()
        } else {
            vec![]
        };
        let missing: Vec<String> = duties.iter().filter(|d| d.1.is_none()).map(|d| d.0.clone()).collect();
        let ceiling = (certified && missing.is_empty()).then(|| duties.iter().filter_map(|d| d.1).fold(1.0f64, f64::min));
        let signals: Vec<DutySignal> = if certified {
            gate_rules
                .iter()
                .filter_map(|id| self.config.rules.iter().find(|r| &r.id == id))
                .map(|r| {
                    let p = r.protect.as_ref();
                    let has_source = p.is_some_and(|p| p.metric == "progress_rate" && p.source_json.is_some());
                    let progress = self.progress.get(&r.id).copied().flatten();
                    let readable = self.sources.progress_status(&r.id).map_or(progress.is_some(), |st| st.0);
                    DutySignal {
                        rule: r.id.clone(),
                        has_source,
                        progress,
                        readable: !has_source || readable,
                        max_slowdown: p.and_then(|p| p.max_slowdown).unwrap_or(0.05),
                    }
                })
                .collect()
        } else {
            vec![]
        };
        let units: Vec<DutyUnit> = i
            .jobs
            .iter()
            .filter(|j| j.gpu)
            .map(|j| {
                let pids: Vec<i32> = if j.pids.is_empty() { j.pgid.into_iter().collect() } else { j.pids.clone() };
                DutyUnit {
                    id: j.attempt_id,
                    key: if j.name.is_empty() { j.module.clone() } else { format!("{}/{}", j.module, j.name) },
                    cooperative: j.duty,
                    pausable: j.pausable,
                    busy: self.last_busy.as_ref().filter(|_| !pids.is_empty()).and_then(|g| g.group(pids.iter().copied())),
                }
            })
            // running workloads that use the GPU are units too: their key is `module/workload`, their processes the
            // workload's container; a stop goes through the workload ladder
            .chain(i.workloads.iter().filter(|w| w.running && w.gpu).map(|w| DutyUnit {
                id: w.id(),
                key: w.key.clone(),
                cooperative: w.cooperative_throttle,
                pausable: w.can_pause(),
                busy: self.last_busy.as_ref().filter(|_| !w.pids.is_empty()).and_then(|g| g.group(w.pids.iter().copied())),
            }))
            .collect();
        let dout = self.duty.step(&DutyInputs {
            now,
            gating: certified && !harness_gpu,
            ceiling,
            signals,
            guard_clear: cache.guard_level == GuardLevel::Clear,
            units,
        });
        for e in &dout.events {
            let d = match &e.detail {
                Value::Object(m) => m.clone(),
                _ => Map::new(),
            };
            self.journal(e.kind, e.reason, e.rule.as_deref(), d);
        }
        for (id, d) in &dout.duty {
            di.gpu_gate_exempt.insert(*id);
            duty_of.insert(*id, *d);
        }
        if certified {
            if missing.is_empty() {
                let n = dout.duty.len();
                let d = dout.budget.unwrap_or(0.0);
                let mut b = serde_json::json!({"duty": d, "rules": gate_rules, "jobs": n,
                                               "per_job": if n == 0 { d } else { d / n as f64 }});
                if harness_gpu {
                    b["state"] = Value::from("harness");
                }
                if let (Some(o), Value::Object(g)) = (b.as_object_mut(), self.duty.telemetry(now)) {
                    for (k, v) in g {
                        o.entry(k).or_insert(v);
                    }
                }
                self.gpu_budget = Some(b);
                self.last_not_certified = None;
            } else {
                let why = missing.join(",");
                self.gpu_budget = Some(serde_json::json!({"duty": 0.0, "rules": gate_rules, "not_certified": missing,
                                                          "state": "not_certified"}));
                if self.last_not_certified.as_deref() != Some(&why) {
                    self.journal("gpu_gate", "GPU_NOT_CERTIFIED", missing.first().map(String::as_str),
                                 obj([("rules", Value::from(missing.clone()))]));
                    self.last_not_certified = Some(why);
                }
            }
        }
        let governed = dout.duty.clone();
        let duty_evict = dout.evict;
        // the harness (D52): which arm the work under test is in, on top of everything above
        let mut harness_off: BTreeSet<i64> = BTreeSet::new();
        let mut harness_evict: Vec<i64> = vec![];
        let mut arm_now: Option<(String, Option<Arm>)> = None;
        if let Some(h) = self.harness.as_mut().filter(|h| !h.finished()) {
            let rule_id = h.spec.rule.clone();
            let target = self.config.rules.iter().find(|r| r.id == rule_id)
                .and_then(|r| r.protect.as_ref()).and_then(|p| p.max_slowdown);
            let t = HarnessTick {
                now,
                progress: self.progress.get(&rule_id).copied().flatten(),
                rule_active: self.evaluator.active_rules.iter().any(|r| r.id == rule_id),
                group: self.groups_fp.get(&rule_id).copied().unwrap_or(0),
                phase_on: phase_rules.contains(&rule_id),
                guard_clear: cache.guard_level == GuardLevel::Clear,
                on_battery: i.on_battery,
                target,
            };
            let arm = h.tick(&t);
            let under: Vec<&FleetJobView> = i.jobs.iter().filter(|j| h.work.matches(&j.module, &j.name, j.gpu)).collect();
            di.probe_suppressed = true;
            di.gpu_admit_open = h.work.includes_gpu();
            match arm {
                Some(Arm::On) => {
                    for j in &under {
                        if j.gpu {
                            di.gpu_gate_exempt.insert(j.attempt_id);
                            if j.duty {
                                if let Some(d) = h.spec.duty {
                                    duty_of.insert(j.attempt_id, d);
                                }
                            }
                        }
                    }
                }
                Some(Arm::Off) => {
                    for j in &under {
                        if j.pausable && h.spec.off == OffMode::Paused {
                            harness_off.insert(j.attempt_id);
                        } else {
                            harness_evict.push(j.attempt_id);
                        }
                    }
                }
                None => {}
            }
            arm_now = Some((h.spec.run_id.clone(), arm));
            if let Some(o) = h.outcome.as_ref().filter(|_| h.finished()) {
                let d = obj([("run_id", Value::from(h.spec.run_id.as_str())), ("decision", Value::from(o.decision.as_str())),
                             ("why", Value::from(o.reason.as_str()))]);
                if let Some(j) = &self.journal {
                    j.record("ab_finished", "AB_FINISHED", Some(&rule_id), d);
                }
            }
        }
        for dj in di.jobs.iter_mut() {
            dj.gpu_duty = duty_of.get(&dj.attempt_id).copied();
        }
        di.harness_off = harness_off;
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
        if let Some(n) = out.gpu_jobs_allowed.filter(|_| !gpu_always) {
            extra.push(ConstraintVector {
                gpu_jobs: Some(n),
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
        let fleet = crate::workloads::is_fleet_id;
        let (w_paused, a_paused): (BTreeSet<i64>, BTreeSet<i64>) = out.paused.iter().partition(|id| fleet(**id));
        let (w_lowered, a_lowered): (BTreeSet<i64>, BTreeSet<i64>) = out.lowered.iter().partition(|id| fleet(**id));
        // a workload's pause ceiling, or the duty governor's stop of one (the ladder stops and holds it)
        let ceiling: BTreeSet<i64> =
            out.evict.iter().map(|e| e.0).chain(duty_evict.iter().copied()).filter(|id| fleet(*id)).collect();
        let paused_all: BTreeSet<i64> = out.paused.clone();
        let n_jobs = di.jobs.len().max(1) as f64;
        let budget_binds = out.budget_cores.is_some_and(|b| b < di.allocatable_cores);
        let share = out.budget_cores.filter(|_| budget_binds).map(|b| (b / n_jobs).floor().max(1.0));
        let threads = match (share.map(|s| s as i64), combined.threads) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let cpu_share = match (share, combined.cpu_cores.map(|c| (c / n_jobs).max(0.1))) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let (plans, wev) = self.workload_ladder.step(&LadderInputs {
            now,
            workloads: &i.workloads,
            paused_ids: &w_paused,
            lowered_ids: &w_lowered,
            ceiling_ids: &ceiling,
            memory_victims: &self.workload_victims,
            evict_active: !combined.evict.is_empty(),
            guard_clear: cache.guard_level == GuardLevel::Clear,
            no_admit: combined.no_admit,
            gpu_allowed: combined.gpu_jobs != Some(0),
            would_pause_cpu: self.dynamic.would_pause(false),
            would_pause_gpu: self.dynamic.would_pause(true),
            threads,
            cpu_share,
        });
        let (dacts, dev) = self.delegation_ladder.step(now, &self.delegated_groups, &w_paused, &w_lowered, &ceiling,
                                                       self.dynamic.would_pause(false), self.config.max_pause_s);
        for e in wev.iter().chain(dev.iter()) {
            let d: Map<String, Value> = e.detail.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            self.journal(e.kind, e.reason, None, d);
        }
        // each workload's GPU duty, as the dynamic inputs carried it (the certified share above)
        let duty: BTreeMap<i64, f64> = di.jobs.iter().filter_map(|j| j.gpu_duty.map(|d| (j.attempt_id, d))).collect();
        let mut plans = plans;
        for w in &i.workloads {
            if let Some(p) = plans.get_mut(&w.key) {
                p.gpu_duty = duty.get(&w.id()).copied().filter(|_| w.cooperative_throttle && w.gpu);
            }
        }
        r.workloads = plans;
        r.delegated = dacts;
        r.lowered = a_lowered;
        r.paused = a_paused;
        r.throttle = out.throttle;
        r.probing = out.probing;
        r.rung = out.rung;
        r.dynamic_reason = out.reason.clone();
        r.budget_cores = out.budget_cores;
        for (id, reason) in out.evict.into_iter().filter(|e| !fleet(e.0)) {
            if !r.evicts(id) {
                r.evictions.push(Eviction {
                    attempt_id: id,
                    reason,
                });
            }
        }
        for id in harness_evict.into_iter().chain(duty_evict.into_iter().filter(|id| !fleet(*id))) {
            if !r.evicts(id) {
                r.evictions.push(Eviction { attempt_id: id, reason: "preempt_protection".into() });
            }
        }
        self.duty.observe(&governed, &paused_all, now);
        if arm_now != self.last_arm {
            if let Some((run, arm)) = &arm_now {
                let reason = match arm {
                    Some(Arm::On) => "AB_ON",
                    Some(Arm::Off) => "AB_OFF",
                    None => "AB_IDLE",
                };
                let d = obj([("run_id", Value::from(run.as_str())),
                             ("attempts", Value::Array(i.jobs.iter().map(|j| Value::from(j.attempt_id)).collect()))]);
                self.journal("ab_window", reason, None, d);
            }
            self.last_arm = arm_now;
        }
        self.on_battery = i.on_battery;
        self.journal_fleet_action(true, &r.paused, pause_rules, &out.reason);
        self.journal_fleet_action(false, &r.lowered, lower_rules, &out.reason);
        // GPU work may not run: GPU-resident services go too (yieldable ones; the others hold their GPU)
        if r.constraint.gpu_jobs == Some(0) {
            for svc in i.services.iter().filter(|s| s.gpu && s.yieldable) {
                stop_service(svc, "preempt_protection", &mut r.service_stops, &mut r.evictions);
            }
        }
        let stopped: BTreeSet<String> = r.service_stops.iter().map(|s| s.key.clone()).collect();
        for st in r.service_stops.iter().filter(|s| !self.last_service_stops.contains(&s.key)) {
            self.journal("service_stopped", "PROTECTION_SERVICE_STOP", None,
                         obj([("service", Value::from(st.key.as_str())), ("reason", Value::from(st.reason.as_str()))]));
        }
        self.last_service_stops = stopped;
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
            // owner phases and who reads them: an unreadable one (a person's home with nobody logged in) holds the fleet
            ("phases", serde_json::to_value(self.sources.phases()).unwrap_or(Value::Null)),
            ("harness", self.harness.as_ref().map(|h| h.report(crate::sources::wall_now())).unwrap_or(Value::Null)),
        ]))
    }

    /// The heartbeat's `telemetry.protection` for this tick's result.
    pub fn telemetry(&self, r: &ProtectionTickResult) -> ProtectionTelemetry {
        ProtectionTelemetry {
            mode: self.config.mode.as_str().to_string(),
            active: r
                .reports
                .iter()
                .filter(|x| x.active)
                .map(|x| x.id.clone())
                .collect(),
            rules: r.reports.clone(),
            constraint: r.constraint.clone(),
            guard_reason: r.guard_reason.clone(),
            config_error: self.config_error.clone(),
            rung: r.rung,
            budget_cores: r.budget_cores,
            dynamic: r.dynamic_reason.clone(),
            front: self.last_front.as_ref().map(FrontReading::describe),
            source_error: self.source_error.clone(),
            lowering: self.lowering,
            phases: self.sources.phases(),
            progress: self
                .config
                .rules
                .iter()
                .filter(|r| r.protect.as_ref().is_some_and(|p| p.source_json.is_some()))
                .filter_map(|r| {
                    let (readable, reader) = self.sources.progress_status(&r.id)?;
                    Some(ProgressReport {
                        rule: r.id.clone(),
                        readable,
                        reader,
                        rate: self.progress.get(&r.id).copied().flatten().and_then(|p| p.rate()),
                    })
                })
                .collect(),
            event_latency: self.sources.latency(),
            gpu_budget: self.gpu_budget.clone(),
            identities: self.identities.clone(),
            no_instruction_counters: self
                .instruction_counters
                .iter()
                .filter(|(id, counts)| {
                    !**counts
                        && self.config.rules.iter().any(|r| {
                            r.id == **id
                                && r.protect.as_ref().is_some_and(|p| p.metric == "ipc_ratio")
                        })
                })
                .map(|(id, _)| id.clone())
                .collect(),
        }
    }
}
