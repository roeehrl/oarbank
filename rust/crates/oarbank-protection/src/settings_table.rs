//! The agent's settings table: every key of the policy and caps the coordinator sends, its type, bounds and
//! default. GENERATED from the settings registry (src/oarbank/coordinator/settings/registry.py) by
//! `uv run python -m oarbank.coordinator.settings.rustgen`; do not edit (tests/test_settings.py checks it).

use crate::settings::{Def, Kind, Section, Tighten};

/// Every key, in the registry's order (the policy's extra keys last).
pub const DEFS: &[Def] = &[
    Def { key: "os_reserve_gb", section: Section::Policy, kind: Kind::Number, nullable: false, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "4", tighten: Tighten::Higher, managed: true },
    Def { key: "user_reserve_gb", section: Section::Policy, kind: Kind::Number, nullable: false, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "8", tighten: Tighten::Higher, managed: true },
    Def { key: "job_mem_gb", section: Section::Policy, kind: Kind::Number, nullable: false, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "1.5", tighten: Tighten::None, managed: false },
    Def { key: "mem_in_use_bound", section: Section::Policy, kind: Kind::Bool, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "true", tighten: Tighten::Higher, managed: true },
    Def { key: "user_present_slots", section: Section::Policy, kind: Kind::Integer, nullable: false, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "2", tighten: Tighten::Lower, managed: true },
    Def { key: "user_idle_s", section: Section::Policy, kind: Kind::Number, nullable: false, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "300", tighten: Tighten::Higher, managed: true },
    Def { key: "screen_sharing_present", section: Section::Policy, kind: Kind::Bool, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "true", tighten: Tighten::Higher, managed: true },
    Def { key: "run_on_battery", section: Section::Policy, kind: Kind::Bool, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "false", tighten: Tighten::Lower, managed: true },
    Def { key: "threads_per_job", section: Section::Policy, kind: Kind::Integer, nullable: false, min: Some(1.0), exclusive_min: false, max: None, choices: &[], default: "1", tighten: Tighten::None, managed: false },
    Def { key: "max_slots", section: Section::Policy, kind: Kind::Integer, nullable: true, min: Some(0.0), exclusive_min: false, max: None, choices: &[], default: "null", tighten: Tighten::Lower, managed: true },
    Def { key: "nice", section: Section::Policy, kind: Kind::Integer, nullable: false, min: Some(0.0), exclusive_min: false, max: Some(20.0), choices: &[], default: "10", tighten: Tighten::None, managed: false },
    Def { key: "hard_limits", section: Section::Policy, kind: Kind::Bool, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "false", tighten: Tighten::Higher, managed: true },
    Def { key: "cpu_cores", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null", tighten: Tighten::Lower, managed: true },
    Def { key: "mem_gb", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null", tighten: Tighten::Lower, managed: true },
    Def { key: "jobs", section: Section::Limits, kind: Kind::Integer, nullable: true, min: Some(1.0), exclusive_min: false, max: None, choices: &[], default: "null", tighten: Tighten::Lower, managed: true },
    Def { key: "schedule", section: Section::Limits, kind: Kind::Schedule, nullable: true, min: None, exclusive_min: false, max: None, choices: &[], default: "null", tighten: Tighten::None, managed: false },
    Def { key: "enforce", section: Section::Limits, kind: Kind::Choice, nullable: false, min: None, exclusive_min: false, max: None, choices: &["soft", "hard"], default: "\"soft\"", tighten: Tighten::Higher, managed: true },
    Def { key: "vm_mem_gb", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null", tighten: Tighten::Lower, managed: true },
    Def { key: "vm_cpus", section: Section::Limits, kind: Kind::Integer, nullable: true, min: Some(1.0), exclusive_min: false, max: None, choices: &[], default: "null", tighten: Tighten::Lower, managed: true },
    Def { key: "disk_gb", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null", tighten: Tighten::Lower, managed: true },
    Def { key: "staging_mbps", section: Section::Limits, kind: Kind::Number, nullable: true, min: Some(0.0), exclusive_min: true, max: None, choices: &[], default: "null", tighten: Tighten::Lower, managed: true },
    Def { key: "inbound_listeners", section: Section::Policy, kind: Kind::Bool, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "true", tighten: Tighten::Lower, managed: true },
    Def { key: "listener_port_range", section: Section::Policy, kind: Kind::Text, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "\"41000-41999\"", tighten: Tighten::None, managed: false },
    Def { key: "listener_probe_endpoint", section: Section::Policy, kind: Kind::Text, nullable: true, min: None, exclusive_min: false, max: None, choices: &[], default: "null", tighten: Tighten::None, managed: false },
    Def { key: "listener_stun_server", section: Section::Policy, kind: Kind::Text, nullable: true, min: None, exclusive_min: false, max: None, choices: &[], default: "null", tighten: Tighten::None, managed: false },
    Def { key: "disabled_services", section: Section::Policy, kind: Kind::Strings, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "[]", tighten: Tighten::None, managed: false },
    Def { key: "module_settings", section: Section::Policy, kind: Kind::Object, nullable: false, min: None, exclusive_min: false, max: None, choices: &[], default: "{}", tighten: Tighten::None, managed: false },
    Def { key: "protection", section: Section::Policy, kind: Kind::Object, nullable: true, min: None, exclusive_min: false, max: None, choices: &[], default: "null", tighten: Tighten::None, managed: false },
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
pub const INBOUND_LISTENERS: bool = true;
