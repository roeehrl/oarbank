//! Shared test helpers: process records, a deterministic RNG for soaks, and a fake actuator.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oarbank_protection::*;
use serde_json::Value;

pub fn proc_(pid: i32, ppid: i32, start: u64, path: &str) -> ProcessRecord {
    ProcessRecord::new(pid, ppid, start, path)
}

/// A process with a footprint (the common case in rule tests).
pub fn proc_fp(pid: i32, path: &str, footprint: f64) -> ProcessRecord {
    ProcessRecord {
        footprint_gb: footprint,
        ..ProcessRecord::new(pid, 1, 1000, path)
    }
}

pub fn rule(j: Value) -> ProtectionRule {
    ProtectionRule::from_json(&j).expect("rule parses")
}

/// A GPU app's rule: its whole tree reserves its recent peak footprint plus 2 GB.
pub fn gpu_app_rule() -> ProtectionRule {
    rule(serde_json::json!({
        "id": "gpu-app", "match": {"path_contains": "Engine/bin"}, "tree": "descendants",
        "active_when": "present", "reserve": {"mem_gb": "peak(300s).footprint + 2"},
    }))
}

pub fn controller(central: Value) -> ProtectionController {
    let mut c = ProtectionController::new(None, Host::unavailable());
    c.apply(Some(&central), &LocalProtection::Absent);
    c
}

pub fn tick(now: f64, memory: MemorySignals, jobs: Vec<FleetJobView>) -> TickInputs {
    TickInputs {
        jobs,
        ..TickInputs::new(now, memory)
    }
}

pub fn no_cpu() -> HashMap<ProcessKey, f64> {
    HashMap::new()
}

/// Deterministic RNG for soaks (SplitMix64).
pub struct SeededRandom(u64);

impl SeededRandom {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    pub fn uniform(&mut self, a: f64, b: f64) -> f64 {
        a + (b - a) * self.unit()
    }

    /// Uniform integer in [a, b].
    pub fn int(&mut self, a: i64, b: i64) -> i64 {
        a + (self.next_u64() % (b - a + 1) as u64) as i64
    }

    pub fn boolean(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

#[derive(Default)]
pub struct FakeState {
    pub starts: HashMap<i32, u64>,
    pub delivered: Vec<(i32, Signal)>,
    pub background: Vec<(i32, bool)>,
    /// The OS refuses background scheduling (Linux without a delegated cgroup).
    pub no_background: bool,
}

/// A fake OS for the spawn registry: start times per pid, and a log of what would have been delivered.
#[derive(Clone, Default)]
pub struct FakeActuator(pub Arc<Mutex<FakeState>>);

impl FakeActuator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_start(&self, pid: i32, start: Option<u64>) {
        let mut s = self.0.lock().unwrap();
        match start {
            Some(v) => s.starts.insert(pid, v),
            None => s.starts.remove(&pid),
        };
    }

    pub fn start(&self, pid: i32) -> Option<u64> {
        self.0.lock().unwrap().starts.get(&pid).copied()
    }

    pub fn delivered(&self) -> Vec<(i32, Signal)> {
        self.0.lock().unwrap().delivered.clone()
    }

    pub fn registry(&self, journal: Option<Arc<DecisionJournal>>) -> SpawnRegistry {
        SpawnRegistry::new(Box::new(self.clone()), journal, None)
    }
}

impl Actuator for FakeActuator {
    fn start_time(&self, pid: i32) -> Option<u64> {
        self.start(pid)
    }
    fn signal_group(&self, pgid: i32, sig: Signal) -> i32 {
        self.0.lock().unwrap().delivered.push((pgid, sig));
        0
    }
    fn set_background(&self, pgid: i32, on: bool) -> i32 {
        let mut s = self.0.lock().unwrap();
        if s.no_background {
            return -1;
        }
        s.background.push((pgid, on));
        0
    }
}

/// A unique scratch directory under the system temp dir, removed on drop.
pub fn scratch(tag: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("oarbank-prot-{tag}-"))
        .tempdir()
        .unwrap()
}
