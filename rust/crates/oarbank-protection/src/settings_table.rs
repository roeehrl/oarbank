//! The agent's settings table: every key of the policy and caps the coordinator sends, its type, bounds and
//! default. GENERATED from the settings registry (src/oarbank/coordinator/settings/registry.py) by
//! `uv run python -m oarbank.coordinator.settings.rustgen`; do not edit (tests/test_settings.py checks it).

use crate::settings::{Def, Kind, Section};

/// Every key, in the registry's order (the policy's extra keys last).
pub const DEFS: &[Def] = &[
    Def { key: "os_reserve_gb", section: Section::Policy, kind: Kind::Number, nullable: false, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "4" },
    Def { key: "user_reserve_gb", section: Section::Policy, kind: Kind::Number, nullable: false, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "8" },
    Def { key: "job_mem_gb", section: Section::Policy, kind: Kind::Number, nullable: false, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "1.5" },
    Def { key: "mem_in_use_bound", section: Section::Policy, kind: Kind::Bool, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "true" },
    Def { key: "user_present_slots", section: Section::Policy, kind: Kind::Integer, nullable: false, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "2" },
    Def { key: "user_idle_s", section: Section::Policy, kind: Kind::Number, nullable: false, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "300" },
    Def { key: "screen_sharing_present", section: Section::Policy, kind: Kind::Bool, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "true" },
    Def { key: "run_on_battery", section: Section::Policy, kind: Kind::Bool, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "false" },
    Def { key: "threads_per_job", section: Section::Policy, kind: Kind::Integer, nullable: false, min: Some(1.0), exclusive_min: false, max: None, choices: &[], default: "1" },
    Def { key: "max_slots", section: Section::Policy, kind: Kind::Integer, nullable: true, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "null" },
    Def { key: "nice", section: Section::Policy, kind: Kind::Integer, nullable: false, min: Some(0.0), exclusive_min: false, max: Some(20.0), choices: &[], default: "10" },
    Def { key: "hard_limits", section: Section::Policy, kind: Kind::Bool, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "false" },
    Def { key: "cpu_cores", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null" },
    Def { key: "mem_gb", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null" },
    Def { key: "jobs", section: Section::Limits, kind: Kind::Integer, nullable: true, min: Some(1.0), exclusive_min: false, max: None, choices: &[], default: "null" },
    Def { key: "schedule", section: Section::Limits, kind: Kind::Schedule, nullable: true, min: None, exclusive_min: false, max: None, choices: &[], default: "null" },
    Def { key: "enforce", section: Section::Limits, kind: Kind::Choice, nullable: false, min: None, exclusive_min: false, max: None, choices: &["soft", "hard"], default: "\"soft\"" },
    Def { key: "vm_mem_gb", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null" },
    Def { key: "vm_cpus", section: Section::Limits, kind: Kind::Integer, nullable: true, min: Some(1.0), exclusive_min: false, max: None, choices: &[], default: "null" },
    Def { key: "disk_gb", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null" },
    Def { key: "staging_mbps", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null" },
    Def { key: "disabled_services", section: Section::Policy, kind: Kind::Strings, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "[]" },
    Def { key: "module_settings", section: Section::Policy, kind: Kind::Object, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "{}" },
    Def { key: "protection", section: Section::Policy, kind: Kind::Object, nullable: true, min: None, exclusive_min: false, max: None, choices: &[], default: "null" },
];

// The defaults the capacity engine's Policy starts from (pre-first-heartbeat only).
pub const OS_RESERVE_GB: f64 = 4.0;
pub const USER_RESERVE_GB: f64 = 8.0;
pub const JOB_MEM_GB: f64 = 1.5;
pub const MEM_IN_USE_BOUND: bool = true;
pub const USER_PRESENT_SLOTS: i64 = 2;
pub const USER_IDLE_S: f64 = 300.0;
pub const SCREEN_SHARING_PRESENT: bool = true;
pub const RUN_ON_BATTERY: bool = false;
pub const THREADS_PER_JOB: i64 = 1;
pub const MAX_SLOTS: Option<i64> = None;
pub const NICE: i64 = 10;
pub const HARD_LIMITS: bool = false;
