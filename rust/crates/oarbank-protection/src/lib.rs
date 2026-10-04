//! Host protection for the Oarbank node agent (docs/design/protection.md; the Python contract is
//! `oarbank.contracts.protection`).
//!
//! Every tick the agent decides how much fleet work the machine may run without harming the owner's own
//! processes: owner rules (reserve, cap, lower, pause, evict) matched against the process table, the L0
//! memory guard, the thermal and battery gates and, in `moderate` and `strict_yield`, the dynamic controller
//! (AIMD on measured harm, rungs, bandwidth classes, pause probes). The result is one combined constraint for
//! the capacity engine plus a per-attempt actuation plan, which only the [`SpawnRegistry`] may apply: it
//! signals nothing but the agent's own process groups (S16).
//!
//! The decision logic never touches the OS. Its inputs come through [`ProcessSource`], [`Meter`],
//! [`OwnerSources`], [`Clock`] and [`Actuator`]; [`platform`] holds the native implementations (macOS; on Linux
//! and Windows so far only the GPU meter).

mod json;

pub mod capacity;
pub mod config;
pub mod controller;
pub mod dynamic;
pub mod evaluator;
pub mod gpu;
pub mod journal;
pub mod matcher;
pub mod memory_guard;
pub mod model;
pub mod platform;
pub mod presence;
pub mod procinfo;
pub mod session;
pub mod signals;
pub mod sources;
pub mod spawn_registry;
pub mod support;
pub mod table;
pub mod telemetry;
pub mod x11;

pub use capacity::{
    CapacityInputs, CapacityModel, CapacityResult, Enforce, Enforcement, EnforcementAttempt,
    Limits, Policy, ReleaseDecision, Schedule,
};
pub use config::{
    ActiveWhen, CapFleet, ConfigError, DuringSpec, MemoryFloors, ProcessMatch, ProtectSpec,
    ProtectionConfig, ProtectionMode, ProtectionRule, ProtectionScope, ReserveExpr, ReserveMetric,
    TreeScope, DEFAULT_GPU_MIN_BUSY,
};
pub use controller::{
    Eviction, FleetJobView, FleetServiceView, Host, LocalProtection, ProtectionController,
    ProtectionTickResult, ServiceStop, TickInputs,
};
pub use dynamic::{
    DynInputs, DynJob, DynOutputs, DynamicController, ProtectedSignal, ProxyValidation, ThrottleDoc,
};
pub use evaluator::{
    CombinedConstraint, ConstraintVector, ProtectionEvent, RuleEvaluator, RuleReport, RuleState,
};
pub use gpu::{GpuBusy, GpuTimes};
pub use journal::{
    Clock, DecisionJournal, FileJournalSink, JournalRecord, JournalSink, SystemClock,
};
pub use memory_guard::{GuardLevel, MemPressure, MemoryGuard, MemorySignals, SystemGates, Thermal};
pub use model::{GroupSample, ProcessKey, ProcessRecord};
pub use signals::{
    Front, FrontReading, GroupMetrics, Meter, NullMeter, Presence, PresenceReading, ProcCounters,
};
pub use sources::{FileOwnerSources, NoOwnerSources, OwnerSources};
pub use spawn_registry::{
    Actuator, FileRegistryStore, Member, Refusal, RegistryStore, Signal, SpawnRegistry,
    UnsupportedActuator,
};
pub use table::{
    ProcessSource, ProcessSummaryRow, ProcessTable, RawProcess, SigningIdentity, Snapshot,
    SourceError, UnsupportedProcessSource,
};
pub use telemetry::ProtectionTelemetry;
