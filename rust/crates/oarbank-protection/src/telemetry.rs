//! The heartbeat's `telemetry.protection` object (docs/protocol.md "Session"). The coordinator stores it as
//! is; the console reads `mode`, `active`, `rules`, `constraint`, `guard_reason`, `config_error`, `rung`,
//! `budget_cores`, `dynamic`, `front`, `source_error`, `lowering` and `no_instruction_counters` (and explain the last
//! four, with the rules' unreadable counts, as node conditions).

use serde::Serialize;

use crate::evaluator::{CombinedConstraint, RuleReport};

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
}
