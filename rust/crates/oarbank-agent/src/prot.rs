//! Host protection and capacity in the agent (oarbank-protection; docs/protocol.md, "Capacity and host protection").
//! Every tick: sample the host, let the controller decide, act only through the spawn registry (S16), and compute
//! what the node may still take. The heartbeat carries the telemetry, the journal and the process summary.

use crate::jobs::Table;
use crate::paths::Layout;
use crate::{host, procs};
use oarbank_protection as P;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

pub struct Protection {
    pub ctrl: P::ProtectionController,
    presence: Box<dyn P::Presence>,
    pub registry: Arc<P::SpawnRegistry>,
    pub journal: Arc<P::DecisionJournal>,
    local: std::path::PathBuf,
    policy_seen: Value,
    lowered: BTreeSet<i64>,
    frozen: BTreeSet<i64>,
    pub last: Option<P::ProtectionTickResult>,
    pub capacity: Option<P::CapacityResult>,
    pub telemetry: Value,
    /// Service pools this node offers (`containers` tokens and the like), set by the agent before each tick.
    pub service_pools: std::collections::BTreeMap<String, i64>,
    /// Host memory running services reserve (`reserves_host_memory`), GB.
    pub service_reserved_mem_gb: f64,
}

impl Protection {
    pub fn new(l: &Layout) -> Self {
        let journal = Arc::new(P::DecisionJournal::new(Box::new(P::SystemClock),
                                                       Some(Box::new(P::FileJournalSink::new(l.state().join("journal"))))));
        let store = Some(Box::new(P::FileRegistryStore::new(l.state().join("spawn-registry.json"))) as Box<dyn P::RegistryStore>);
        #[cfg(target_os = "macos")]
        let registry = Arc::new(P::SpawnRegistry::native(Some(journal.clone()), store));
        #[cfg(not(target_os = "macos"))]
        let registry = Arc::new(P::SpawnRegistry::new(Box::new(ContainerActuator), Some(journal.clone()), store));
        let ctrl = P::ProtectionController::new(Some(journal.clone()), P::Host::native());
        // the owner's local protection file sits beside the agent's home (docs/protocol.md, "Agent config")
        let local = l.home.parent().unwrap_or(&l.home).join("protection.json");
        Protection { ctrl, presence: P::platform::native_presence(), registry, journal, local, policy_seen: Value::Null, lowered: BTreeSet::new(), frozen: BTreeSet::new(),
                     last: None, capacity: None, telemetry: json!({}),
                     service_pools: Default::default(), service_reserved_mem_gb: 0.0 }
    }

    pub fn tick(&mut self, d: &Value, table: &Table, facts: &Value) {
        let now = crate::doctor::now();
        let policy = &d["policy"];
        if *policy != self.policy_seen {
            self.ctrl.apply(policy.get("protection"), &P::LocalProtection::read(Some(&self.local)));
            self.policy_seen = policy.clone();
        }
        if d["run_probe"].as_bool() == Some(true) {
            self.ctrl.probe_requested = true;
        }
        if d["send_processes"].as_bool() == Some(true) {
            self.ctrl.processes_requested = true;
        }
        let m = host::memory();
        let mut mem = P::MemorySignals::new(m.ram_gb, m.used_gb, m.pressure);
        mem.swap_used_gb = m.swap_used_gb;
        let mut inputs = P::TickInputs::new(now, mem);
        let (jobs, fleet_pids, fleet_rss, used_cpu, used_mem, live) = {
            let t = table.lock().unwrap();
            let mut pids = HashSet::new();
            let mut views = vec![];
            for j in t.values() {
                if let Some(pg) = j.pgid {
                    pids.extend(procs::group_pids(pg));
                    pids.insert(pg);
                }
                let mut v = P::FleetJobView::new(j.attempt_id, j.pgid, j.usage.footprint_gb, j.started_at, j.mem_gb);
                // paused by a freeze, or at its safe points through control.json
                v.pausable = j.caps.iter().any(|c| c == "freeze_ok" || c == "cooperative_pause");
                v.cooperative = j.caps.iter().any(|c| c == "cooperative_pause" || c == "cooperative_throttle");
                v.gpu = j.gpu;
                v.bandwidth = j.bandwidth.clone();
                views.push(v);
            }
            let rss: f64 = t.values().map(|j| j.usage.footprint_gb).sum();
            (views, pids, rss, t.values().map(|j| j.cpu).sum::<f64>(), t.values().map(|j| j.mem_gb).sum::<f64>(), t.len() as i64)
        };
        let perf = facts["cpu"]["perf_cores"].as_i64().unwrap_or_else(|| facts["cpu"]["logical"].as_i64().unwrap_or(1));
        let eff = facts["cpu"]["eff_cores"].as_i64().unwrap_or(0);
        let thermal = host::thermal();
        let on_battery = host::on_battery();
        // unknown presence counts as someone present (S19); nobody logged in is idle for ever
        let presence = self.presence.read();
        let idle = presence.effective_idle_s();
        inputs.fleet_pids = fleet_pids.clone();
        inputs.thermal = thermal;
        inputs.on_battery = on_battery;
        inputs.run_on_battery = policy["run_on_battery"].as_bool().unwrap_or(false);
        inputs.jobs = jobs;
        inputs.user_idle_s = idle;
        inputs.allocatable_cores = perf as f64 + eff as f64 / 2.0;
        let r = self.ctrl.tick(&inputs);
        self.actuate(&r, table);
        let limits = P::Limits::from_json(d.get("limits"));
        let at = now as i64;
        let in_schedule = limits.schedule.as_ref().is_none_or(|s| s.contains_unix(at, crate::sys::utc_offset_s(at)));
        enforce_caps(&limits, table, self.service_reserved_mem_gb, in_schedule);
        let base = P::Policy::default();
        let mut ci = P::CapacityInputs::new(m.ram_gb, perf, eff, P::Policy::from_json(Some(policy), &base), limits);
        ci.in_schedule = in_schedule;
        ci.constraint = r.constraint.clone();
        ci.user_present = idle < policy["user_idle_s"].as_f64().unwrap_or(300.0);
        ci.thermal = thermal;
        ci.desired_state = d["desired_state"].as_str().unwrap_or("active").into();
        ci.fleet_rss_gb = fleet_rss;
        ci.live_attempts = live;
        ci.used_cpu = used_cpu;
        ci.used_mem_gb = used_mem;
        ci.service_pools = self.service_pools.clone();
        ci.service_reserved_mem_gb = self.service_reserved_mem_gb;
        let cap = P::CapacityModel::compute(&ci);
        self.telemetry = json!({
            "mem_used_gb": round1(m.used_gb), "mem_free_pct": if m.ram_gb > 0.0 { round1(100.0 * (1.0 - m.used_gb / m.ram_gb)) } else { 0.0 },
            "mem_pressure": m.pressure, "swap_used_gb": m.swap_used_gb.map(round1), "thermal": thermal, "on_battery": on_battery,
            "user_idle_s": if idle.is_finite() { json!(round1(idle)) } else { Value::Null }, "presence": presence.source,
            "fleet_rss_gb": round1(fleet_rss), "disk_free_gb": facts["disk_free_gb"].clone(), "guard": r.guard_level.as_str(),
            "protection": serde_json::to_value(self.ctrl.telemetry(&r)).unwrap_or(Value::Null),
        });
        self.capacity = Some(cap);
        self.last = Some(r);
        let _ = fleet_pids;
    }

    /// Apply this tick's plan to the agent's own process groups, only through the registry.
    fn actuate(&mut self, r: &P::ProtectionTickResult, table: &Table) {
        let mut t = table.lock().unwrap();
        for (aid, j) in t.iter_mut() {
            let Some(pg) = j.pgid else { continue };
            let lower = r.lowered.contains(aid);
            if lower != self.lowered.contains(aid) {
                let _ = self.registry.set_background(pg, lower, if lower { "PROTECTION_LOWER" } else { "PROTECTION_RESTORE" });
                if lower { self.lowered.insert(*aid); } else { self.lowered.remove(aid); }
            }
            let pause = r.paused.contains(aid);
            let freeze = j.caps.iter().any(|c| c == "freeze_ok");
            if pause != (self.frozen.contains(aid) || j.pause) {
                if freeze {
                    let sig = if pause { P::Signal::Stop } else { P::Signal::Cont };
                    let _ = self.registry.signal(pg, sig, if pause { "PROTECTION_PAUSE" } else { "PROTECTION_RESUME" });
                    if pause { self.frozen.insert(*aid); } else { self.frozen.remove(aid); }
                } else {
                    j.pause = pause;                        // cooperative: the job monitor writes control.json
                    j.wake.notify_one();
                }
            }
            if let Some(doc) = r.throttle.get(aid).filter(|d| d.threads != j.threads) {
                j.threads = doc.threads;
                j.wake.notify_one();
            }
            if let Some(e) = r.evictions.iter().find(|e| e.attempt_id == *aid) {
                if j.stop.is_none() {
                    j.stop = Some(crate::jobs::Stop::Release(e.reason.clone()));
                    j.wake.notify_one();
                }
            }
        }
        self.lowered.retain(|a| t.contains_key(a));
        self.frozen.retain(|a| t.contains_key(a));
    }

    pub fn journal_out(&self) -> Value {
        serde_json::to_value(self.journal.pending(200)).unwrap_or(json!([]))
    }

    pub fn ack(&self, d: &Value) {
        if let Some(a) = d["journal_ack"].as_i64() {
            self.journal.acknowledge(a);
        }
    }

    pub fn processes(&mut self, table: &Table) -> Option<Value> {
        let pids: HashSet<i32> = table.lock().unwrap().values().filter_map(|j| j.pgid)
            .flat_map(|pg| procs::group_pids(pg).into_iter().chain([pg])).collect();
        self.ctrl.process_summary(crate::doctor::now(), &pids).map(|rows| serde_json::to_value(rows).unwrap_or(json!([])))
    }
}

/// Linux and Windows: protection acts on the agent's process containers (sys.rs), so a freeze is the leaf's
/// `cgroup.freeze` (Linux, delegated; else SIGSTOP to the group) or NtSuspendProcess on every member of the Job Object
/// (Windows). macOS keeps the protection crate's own actuator (signals and darwin background scheduling).
#[cfg(not(target_os = "macos"))]
struct ContainerActuator;

#[cfg(not(target_os = "macos"))]
impl P::Actuator for ContainerActuator {
    fn start_time(&self, pid: i32) -> Option<u64> {
        procs::start_time_us(pid)
    }

    fn signal_group(&self, pgid: i32, sig: P::Signal) -> i32 {
        let s = match sig {
            P::Signal::Stop => procs::Sig::Stop,
            P::Signal::Cont => procs::Sig::Cont,
            P::Signal::Term => procs::Sig::Term,
            P::Signal::Kill => procs::Sig::Kill,
        };
        if procs::signal_group(pgid, s) { 0 } else { -1 }
    }

    /// No background scheduling class to move a process into here (lowering is a macOS action).
    fn set_background(&self, _pid: i32, _on: bool) -> i32 {
        -1
    }

    fn group_members(&self, pgid: i32) -> Vec<i32> {
        procs::group_pids(pgid)
    }
}

/// The owner's caps in `enforce: "hard"` (docs/protocol.md, "Limits and node policy"): release the youngest attempts
/// (`limit_*`) until the node is within them. Attempts already stopping are on their way out and do not count.
fn enforce_caps(limits: &P::Limits, table: &Table, service_reserved_mem_gb: f64, in_schedule: bool) {
    let mut t = table.lock().unwrap();
    let attempts: Vec<P::EnforcementAttempt> = t.values().filter(|j| j.stop.is_none()).map(|j| P::EnforcementAttempt {
        attempt_id: j.attempt_id, started_at: j.started_at, rss_gb: j.usage.footprint_gb, cpu: j.cpu }).collect();
    let fleet_rss_gb = attempts.iter().map(|a| a.rss_gb).sum();
    for d in P::Enforcement::hard_releases(limits, &attempts, fleet_rss_gb, service_reserved_mem_gb, in_schedule) {
        if let Some(j) = t.get_mut(&d.attempt_id) {
            j.stop = Some(crate::jobs::Stop::Release(d.reason));
            j.wake.notify_one();
        }
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

#[cfg(test)]
mod caps_tests {
    use super::*;
    use crate::jobs::{JobState, Stop};

    fn table(jobs: &[(i64, f64)]) -> Table {
        let t = Table::default();
        for &(aid, started_at) in jobs {
            t.lock().unwrap().insert(aid, JobState { attempt_id: aid, phase: "running".into(), cpu: 1.0, mem_gb: 1.0, gpu: false,
                pgid: None, stop: None, pause: false, usage: Default::default(), log_bytes: 0, started_at, caps: vec![],
                bandwidth: None, threads: None, needs: vec![], wake: Default::default() });
        }
        t
    }

    fn stops(t: &Table) -> Vec<(i64, Option<Stop>)> {
        let mut v: Vec<_> = t.lock().unwrap().values().map(|j| (j.attempt_id, j.stop.clone())).collect();
        v.sort_by_key(|x| x.0);
        v
    }

    #[test]
    fn hard_caps_release_the_youngest_and_wake_their_monitors() {
        let t = table(&[(1, 100.0), (2, 200.0), (3, 300.0)]);
        let woken = t.lock().unwrap()[&3].wake.clone();
        enforce_caps(&P::Limits::from_json(Some(&json!({"jobs": 2, "enforce": "hard"}))), &t, 0.0, true);
        assert_eq!(stops(&t), vec![(1, None), (2, None), (3, Some(Stop::Release("limit_cpu".into())))]);
        assert!(futures_util::FutureExt::now_or_never(woken.notified()).is_some(), "the job's monitor is woken");
        // the stopping attempt no longer counts: nothing more goes
        enforce_caps(&P::Limits::from_json(Some(&json!({"jobs": 2, "enforce": "hard"}))), &t, 0.0, true);
        assert_eq!(stops(&t)[1], (2, None));
    }

    #[test]
    fn soft_caps_release_nothing_and_hard_ones_empty_the_node_outside_the_schedule() {
        let t = table(&[(1, 100.0), (2, 200.0)]);
        enforce_caps(&P::Limits::from_json(Some(&json!({"jobs": 0}))), &t, 0.0, false);
        assert!(stops(&t).iter().all(|(_, s)| s.is_none()));
        enforce_caps(&P::Limits::from_json(Some(&json!({"enforce": "hard"}))), &t, 0.0, false);
        assert!(stops(&t).iter().all(|(_, s)| *s == Some(Stop::Release("limit_schedule".into()))));
    }

    #[test]
    fn the_local_offset_is_a_whole_quarter_hour_within_a_day() {
        let now = crate::doctor::now() as i64;
        for t in [0, now, now + 182 * 86_400] {
            let o = crate::sys::utc_offset_s(t);
            assert!(o.abs() <= 14 * 3600 && o % 900 == 0, "offset {o} at {t}");
        }
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    /// The registry admits the agent's own containers here, and protection's pause freezes them (Linux: the cgroup
    /// leaf when delegated, else SIGSTOP to the group).
    #[test]
    fn protection_pauses_and_resumes_a_registered_container() {
        let mut cmd = std::process::Command::new(if cfg!(windows) { "ping" } else { "sleep" });
        cmd.args(if cfg!(windows) { &["-n", "30", "127.0.0.1"][..] } else { &["30"][..] }).stdout(std::process::Stdio::null());
        crate::sys::new_group_std(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id() as i32;
        crate::sys::adopt(pid as u32).unwrap();
        let reg = P::SpawnRegistry::new(Box::new(ContainerActuator), None, None);
        let start = procs::start_time_us(pid).unwrap();
        assert_eq!(procs::start_time_us(pid), Some(start), "a process's start time is stable");
        assert!(reg.register(pid, Some(1), None));
        assert!(reg.signal(pid, P::Signal::Stop, "pause").is_ok());
        #[cfg(target_os = "linux")]
        assert!(paused(pid));
        assert!(reg.signal(pid, P::Signal::Cont, "resume").is_ok());
        #[cfg(target_os = "linux")]
        assert!(!paused(pid));
        assert!(reg.signal(pid, P::Signal::Kill, "evict").is_ok());
        let _ = child.wait();
        drop(child);
        crate::sys::release(pid);
        // Windows frees an exited process object a moment after its last handle closes
        for _ in 0..50 {
            if procs::start_time_us(pid).is_none() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(reg.signal(pid, P::Signal::Kill, "gone").is_err(), "a reaped container is never signalled again");
    }

    /// Frozen in its cgroup leaf, or stopped by SIGSTOP when there is none.
    #[cfg(target_os = "linux")]
    fn paused(pid: i32) -> bool {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Some(leaf) = crate::cgroup::leaf(pid) {
            return std::fs::read_to_string(leaf.join("cgroup.events")).unwrap().lines().any(|l| l == "frozen 1");
        }
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        s[s.rfind(')').unwrap() + 2..].starts_with('T')
    }
}
