//! The heartbeat's `telemetry.protection` object (docs/protocol.md "Session"). The coordinator stores it as
//! is; the console reads `mode`, `active`, `rules`, `constraint`, `guard_reason`, `config_error`, `rung`,
//! `budget_cores`, `dynamic`, `front`, `source_error`, `lowering` and `no_instruction_counters` (and explain the last
//! four, with the rules' unreadable counts, as node conditions).

use serde::Serialize;
use serde_json::Value;

use crate::evaluator::{CombinedConstraint, RuleReport};
use crate::sources::PhaseReport;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProtectionTelemetry {
    pub mode: String,
    pub active: Vec<String>,
    pub rules: Vec<RuleReport>,
    pub constraint: CombinedConstraint,
    pub guard_reason: String,
    pub config_error: Option<String>,
    pub rung: i32,
    pub budget_cores: Option<f64>,
    pub dynamic: String,
    /// What was in front and where it was read ("app 812 (lsappinfo)", "nothing (…)", or why it is unknown),
    /// when a rule or the implicit protection read it.
    pub front: Option<String>,
    /// Why the process table could not be read on the last tick.
    pub source_error: Option<String>,
    /// Whether the agent can lower its jobs here (false: Linux without a delegated cgroup).
    pub lowering: bool,
    /// The `protect.metric = ipc_ratio` rules whose processes' instruction and cycle counters do not count here (no
    /// performance counters exposed, as in a virtual machine): their metric is unknown, which holds the budget.
    pub no_instruction_counters: Vec<String>,
    /// Every `during` block's phase (on, since, readable, who reads it, its tags): the console's conditions and the
    /// coordinator's per-site aggregation read it.
    pub phases: Vec<PhaseReport>,
    /// Each `progress_rate` rule's source: whether it reads, who reads it, and its last rate (events per second).
    pub progress: Vec<ProgressReport>,
    /// The event path's latency, source event to pause request (count, p50, p99, max, buckets).
    pub event_latency: Option<Value>,
    /// The GPU budget under `gpu_jobs = certified`: the duty fleet GPU work may hold beside protected GPU work now,
    /// with the rules and certificates behind it (None: the gate is not in force).
    pub gpu_budget: Option<Value>,
    /// Per active rule, the protected program's identity (what certificates are bound to).
    pub identities: std::collections::BTreeMap<String, String>,
}

/// One progress source as the agent last read it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProgressReport {
    pub rule: String,
    pub readable: bool,
    /// `agent` or `helper`.
    pub reader: String,
    pub rate: Option<f64>,
}
