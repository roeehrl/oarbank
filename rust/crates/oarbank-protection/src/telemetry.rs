//! The heartbeat's `telemetry.protection` object (docs/protocol.md "Session"). The coordinator stores it as
//! is; the console reads `mode`, `active`, `rules`, `constraint`, `guard_reason`, `config_error`, `rung`,
//! `budget_cores`, `dynamic` and `front`.

use serde::Serialize;

use crate::config::ProtectionConfig;
use crate::controller::ProtectionTickResult;
use crate::evaluator::{CombinedConstraint, RuleReport};
use crate::signals::Front;

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
    /// What was in front ("app", "nothing", "unknown"), when a rule or the implicit protection read it.
    pub front: Option<&'static str>,
}

impl ProtectionTelemetry {
    pub fn new(
        config: &ProtectionConfig,
        r: &ProtectionTickResult,
        config_error: Option<&str>,
        front: Option<Front>,
    ) -> Self {
        Self {
            mode: config.mode.as_str().to_string(),
            active: r
                .reports
                .iter()
                .filter(|x| x.active)
                .map(|x| x.id.clone())
                .collect(),
            rules: r.reports.clone(),
            constraint: r.constraint.clone(),
            guard_reason: r.guard_reason.clone(),
            config_error: config_error.map(str::to_string),
            rung: r.rung,
            budget_cores: r.budget_cores,
            dynamic: r.dynamic_reason.clone(),
            front: front.map(Front::as_str),
        }
    }
}
