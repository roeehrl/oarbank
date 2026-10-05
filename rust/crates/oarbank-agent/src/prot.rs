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
    /// Running module services, set by the agent before each tick: fleet work, which protection may stop.
    pub services: Vec<crate::services::ServiceView>,
}

impl Protection {
    /// `session_hub`: serve session helpers (a system install's service), whose reports tell what the
    /// service's own account may not read.
    pub fn new(l: &Layout, session_hub: bool) -> Self {
        let journal = Arc::new(P::DecisionJournal::new(Box::new(P::SystemClock),
                                                       Some(Box::new(P::FileJournalSink::new(l.state().join("journal"))))));
        let store = Some(Box::new(P::FileRegistryStore::new(l.state().join("spawn-registry.json"))) as Box<dyn P::RegistryStore>);
        #[cfg(target_os = "macos")]
        let registry = Arc::new(P::SpawnRegistry::native(Some(journal.clone()), store));
        #[cfg(not(target_os = "macos"))]
        let registry = Arc::new(P::SpawnRegistry::new(Box::new(ContainerActuator), Some(journal.clone()), store));
        let hub = session_hub.then(P::session::SessionHub::new);
        if let Some(h) = &hub {
            if let Err(e) = P::platform::serve_sessions(h.clone()) {
                tracing::warn!(error = %e, "cannot serve session helpers: other accounts' paths, arguments, display and input stay unreadable");
            }
        }
        let ctrl = P::ProtectionController::new(Some(journal.clone()), P::platform::native_host(hub.clone()));
        // the owner's local protection file sits beside the agent's home (docs/protocol.md, "Agent config")
        let local = l.home.parent().unwrap_or(&l.home).join("protection.json");
        Protection { ctrl, presence: P::platform::native_presence(hub), registry, journal, local, policy_seen: Value::Null, lowered: BTreeSet::new(), frozen: BTreeSet::new(),
                     last: None, capacity: None, telemetry: json!({}),
                     service_pools: Default::default(), service_reserved_mem_gb: 0.0, services: vec![] }
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
        let mut inputs_services = vec![];
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
            // services are fleet work too: never the owner's, and stoppable when yieldable (their users go with them)
            let svc_views: Vec<P::FleetServiceView> = self.services.iter().map(|s| {
                let usage = s.pgid.map(procs::group_usage).unwrap_or_default();
                if let Some(pg) = s.pgid {
                    pids.extend(procs::group_pids(pg));
                    pids.insert(pg);
                }
                let users = t.values().filter(|j| j.module == s.module && j.needs.iter().any(|n| s.pools.contains(n)))
                    .map(|j| j.attempt_id).collect();
                P::FleetServiceView { key: s.key.clone(), footprint_gb: usage.footprint_gb, started_at: s.started_at, gpu: s.gpu,
                                      yieldable: s.yieldable, users }
            }).collect();
            inputs_services = svc_views;
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
        inputs.services = inputs_services;
        inputs.user_idle_s = idle;
        inputs.allocatable_cores = perf as f64 + eff as f64 / 2.0;
        inputs.lowering = can_lower();
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

/// Linux and Windows: protection acts on the agent's process containers (sys.rs), so a freeze is the container's
/// `cgroup.freeze` (Linux, delegated; else SIGSTOP to the group) or NtSuspendProcess on every member of the Job Object
/// (Windows), and lowering is the container's background CPU quota (Linux, delegated) or the Job Object's idle priority
/// class with EcoQoS (Windows). macOS keeps the protection crate's own actuator (signals and darwin background
/// scheduling).
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

    /// The container's background CPU quota (Linux) or idle priority class and EcoQoS (Windows), sys.rs.
    fn set_background(&self, pgid: i32, on: bool) -> i32 {
        if crate::sys::set_background(pgid, on) { 0 } else { -1 }
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

/// Whether this node can lower its jobs (Linux needs a delegated cgroup; macOS and Windows always can).
fn can_lower() -> bool {
    #[cfg(not(target_os = "macos"))]
    return crate::sys::can_lower();
    #[allow(unreachable_code)]
    true
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
            t.lock().unwrap().insert(aid, JobState { attempt_id: aid, module: "m".into(), phase: "running".into(), cpu: 1.0, mem_gb: 1.0, gpu: false,
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

    /// The registry admits the agent's own containers here, protection's pause freezes them (Linux: the cgroup
    /// container when delegated, else SIGSTOP to the group), and lowering takes effect (Linux: the background CPU
    /// quota, which needs a delegated cgroup; Windows: the idle priority class).
    #[test]
    fn protection_pauses_and_resumes_a_registered_container() {
        // cgroups first, while this process has no children (as the agent's main does)
        #[cfg(target_os = "linux")]
        let _ = crate::cgroup::root();
        let mut cmd = std::process::Command::new(if cfg!(windows) { "ping" } else { "sleep" });
        cmd.args(if cfg!(windows) { &["-n", "30", "127.0.0.1"][..] } else { &["30"][..] }).stdout(std::process::Stdio::null());
        let mut child = crate::sys::spawn_contained(&mut cmd, false).unwrap();
        let pid = child.id() as i32;
        let reg = P::SpawnRegistry::new(Box::new(ContainerActuator), None, None);
        let start = procs::start_time_us(pid).unwrap();
        assert_eq!(procs::start_time_us(pid), Some(start), "a process's start time is stable");
        assert!(reg.register(pid, Some(1), None));
        assert!(reg.signal(pid, P::Signal::Stop, "pause").is_ok());
        #[cfg(target_os = "linux")]
        assert!(becomes_paused(pid, true), "never paused");
        assert!(reg.signal(pid, P::Signal::Cont, "resume").is_ok());
        #[cfg(target_os = "linux")]
        assert!(becomes_paused(pid, false), "never resumed");
        let lowered = reg.set_background(pid, true, "lower_fleet");
        eprintln!("lowering available here: {}; lowered: {lowered:?}", can_lower());
        #[cfg(target_os = "linux")]
        assert!(can_lower() || !crate::cgroup::required_in_tests(), "no cpu controller, and OARBANK_TEST_CGROUPS=required");
        assert_eq!(lowered.is_ok(), can_lower(), "{lowered:?}");
        assert_eq!(background(pid), lowered.is_ok());
        assert_eq!(reg.set_background(pid, false, "restore").is_ok(), can_lower());
        assert!(!background(pid));
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

    /// Whether it comes to be paused (`want`) or running: frozen in its cgroup container, or stopped by SIGSTOP when
    /// there is none. Both take effect after the call returns, so look until they do (a loaded host: up to 30 s).
    #[cfg(target_os = "linux")]
    fn becomes_paused(pid: i32, want: bool) -> bool {
        let paused = || match crate::cgroup::container(pid) {
            Some(c) => std::fs::read_to_string(c.join("cgroup.events")).unwrap().lines().any(|l| l == "frozen 1"),
            None => {
                let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
                s[s.rfind(')').unwrap() + 2..].starts_with('T')
            }
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while paused() != want {
            if std::time::Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        true
    }

    /// Lowered: its leaf's background quota (Linux), the idle priority class (Windows).
    fn background(pid: i32) -> bool {
        #[cfg(target_os = "linux")]
        return crate::cgroup::container(pid)
            .and_then(|c| std::fs::read_to_string(c.join("run/cpu.max")).ok())
            .is_some_and(|q| q.trim() != "max 100000");
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{GetPriorityClass, OpenProcess, IDLE_PRIORITY_CLASS,
                                                        PROCESS_QUERY_LIMITED_INFORMATION};
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32);
            let class = GetPriorityClass(h);
            CloseHandle(h);
            class == IDLE_PRIORITY_CLASS
        }
    }
}

/// Host protection end to end on this machine, through the agent's own code: a rule naming a running process of the
/// owner pauses one fleet job (frozen through its container) and lowers another, and both come back once that
/// process ends. Windows: run it in a person's session (session 0 holds no owner's processes).
#[cfg(test)]
mod e2e {
    use super::*;
    use crate::jobs::JobState;
    #[cfg(target_os = "macos")]
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// A busy fleet job in a container of its own, as jobs.rs starts runners; killed with its container on drop.
    struct Job(Child);

    impl Drop for Job {
        fn drop(&mut self) {
            let pg = self.0.id() as i32;
            crate::sys::signal_group(pg, crate::sys::Sig::Kill);
            let _ = self.0.wait();
            crate::sys::release(pg);
        }
    }

    /// A process of the owner's, killed on drop.
    struct Owner(Child);

    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn job() -> Job {
        let mut cmd = if cfg!(windows) {
            let mut c = Command::new("cmd");
            c.args(["/c", "for /l %i in (0,0,1) do @rem"]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", "while :; do :; done"]);
            c
        };
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        Job(crate::sys::spawn_contained(&mut cmd, false).unwrap())
    }

    fn state(aid: i64, pgid: i32, caps: &[&str]) -> JobState {
        JobState { attempt_id: aid, module: "m".into(), phase: "running".into(), cpu: 1.0, mem_gb: 0.1, gpu: false, pgid: Some(pgid), stop: None,
                   pause: false, usage: Default::default(), log_bytes: 0, started_at: crate::doctor::now(),
                   caps: caps.iter().map(|c| c.to_string()).collect(), bandwidth: None, threads: None, needs: vec![],
                   wake: Default::default() }
    }

    /// CPU seconds the container uses over `secs`.
    fn cpu_over(pgid: i32, secs: f64) -> f64 {
        let a = procs::group_usage(pgid).cpu_s;
        std::thread::sleep(Duration::from_secs_f64(secs));
        procs::group_usage(pgid).cpu_s - a
    }

    /// Lowered as this OS lowers: the container's background quota (Linux), background QoS (macOS), the idle priority
    /// class (Windows).
    fn lowered(pgid: i32) -> bool {
        #[cfg(target_os = "linux")]
        return crate::cgroup::container(pgid)
            .and_then(|c| std::fs::read_to_string(c.join("run/cpu.max")).ok())
            .is_some_and(|q| q.trim() != "max 100000");
        // getpriority(PRIO_DARWIN_PROCESS) answers only for the caller; background QoS runs at priority 4
        #[cfg(target_os = "macos")]
        return Command::new("/bin/ps").args(["-o", "pri=", "-p", &pgid.to_string()]).output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "4");
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::{GetPriorityClass, OpenProcess, IDLE_PRIORITY_CLASS,
                                                        PROCESS_QUERY_LIMITED_INFORMATION};
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pgid as u32);
            let class = GetPriorityClass(h);
            CloseHandle(h);
            class == IDLE_PRIORITY_CLASS
        }
    }

    #[test]
    #[ignore = "starts busy processes and runs protection for several seconds"]
    fn a_rule_naming_a_running_process_pauses_and_lowers_fleet_jobs() {
        #[cfg(target_os = "linux")]
        let _ = crate::cgroup::root(); // cgroups first, as the agent's main does
        let tmp = crate::scratch("prot-e2e");
        let home = tmp.path().to_path_buf();
        let l = Layout::new(home.clone());
        l.ensure().unwrap();
        let mut p = Protection::new(&l, false);
        let (a, b) = (job(), job());
        let (pa, pb) = (a.0.id() as i32, b.0.id() as i32);
        assert!(p.registry.register(pa, Some(1), None) && p.registry.register(pb, Some(2), None));
        let table = Table::default();
        table.lock().unwrap().insert(1, state(1, pa, &["freeze_ok"]));
        table.lock().unwrap().insert(2, state(2, pb, &[]));
        // the owner's process the rule names by its arguments
        let marker = if cfg!(windows) { "127.0.0.42" } else { "4242.5" };
        let owner = Owner(if cfg!(windows) {
            Command::new("ping").args(["-n", "600", marker]).stdout(Stdio::null()).spawn().unwrap()
        } else {
            Command::new("sleep").arg(marker).spawn().unwrap()
        });
        let rule = json!({"id": "owner", "match": {"argv_regex": marker.replace('.', "\\.")}, "active_when": {"for_s": 0},
                          "pause_fleet": {}, "lower_fleet": {}, "exit_after_s": 0});
        let d = json!({"desired_state": "active", "limits": {}, "policy": {"protection": {
            "node": {"mode": "fleet_first", "defaults": {"cooldown": {"base_s": 1, "max_s": 1}}}, "rule": [rule]}}});
        let facts = json!({"cpu": {"logical": 4}});
        p.tick(&d, &table, &facts);
        let r = p.last.clone().unwrap();
        assert!(r.reports[0].active, "{:?}", r.reports);
        assert_eq!((r.paused.iter().copied().collect::<Vec<_>>(), r.lowered.contains(&2)), (vec![1], true));
        // the pausable job is frozen; the other is lowered where this node can lower
        let frozen = cpu_over(pa, 1.0);
        assert!(frozen < 0.05, "a frozen job used {frozen} s of CPU");
        assert_eq!(lowered(pb), can_lower());
        // the owner's process ends: both come back
        drop(owner);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            std::thread::sleep(Duration::from_millis(500));
            p.tick(&d, &table, &facts);
            let r = p.last.as_ref().unwrap();
            if r.paused.is_empty() && r.lowered.is_empty() || Instant::now() > deadline {
                break;
            }
        }
        let r = p.last.clone().unwrap();
        assert!(!r.reports[0].active && r.paused.is_empty() && r.lowered.is_empty(), "{:?}", r.reports);
        let running = cpu_over(pa, 1.0);
        assert!(running > 0.3, "a resumed job used only {running} s of CPU");
        assert!(!lowered(pb));
        drop((a, b));
    }

    /// macOS, a system install's view of a person's work: the agent's protection serving session helpers runs as
    /// another account (`nobody`, through passwordless sudo), with its home and the helpers' socket in a throwaway
    /// directory, and this account's session helper reports to it. What only this account may read (arguments, CPU
    /// time) arrives through the helper and decides the rules, and the console's front app is the helper's.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "needs passwordless sudo: runs the service side as nobody"]
    fn a_system_agent_sees_a_person_s_work_through_their_session_helper() {
        const NAME: &str = "prot::e2e::a_system_agent_sees_a_person_s_work_through_their_session_helper";
        let role = std::env::var("OARBANK_E2E_ROLE").unwrap_or_default();
        if role == "helper" {
            panic!("{}", P::platform::run_session_helper());
        }
        if role == "service" {
            return session_service_side();
        }
        // short (the socket's path) and reachable by the service's account
        let tmp = tempfile::Builder::new().prefix("oarbank-session-e2e-").tempdir_in("/private/tmp").unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir = tmp.path().to_path_buf();
        let svc = dir.join("svc");
        std::fs::create_dir_all(&svc).unwrap();
        // the service's account makes its home and socket here; it runs a copy of this test (homes are private)
        std::fs::set_permissions(&svc, std::fs::Permissions::from_mode(0o777)).unwrap();
        let exe = dir.join("tests");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let socket = svc.join("session.sock");
        let marker = format!("oarbank-owner-{}", std::process::id());
        let _busy = Owner(Command::new("/bin/sh").args(["-c", "while :; do :; done", &format!("{marker}-busy")]).spawn().unwrap());
        // two commands, so the shell stays (it would exec a lone one) and keeps its marker
        let _idle = Owner(Command::new("/bin/sh").args(["-c", "sleep 600; :", &format!("{marker}-idle")]).spawn().unwrap());
        let _helper = Owner(Command::new(&exe).args(["--exact", NAME, "--ignored", "--nocapture"]).env("OARBANK_E2E_ROLE", "helper")
            .env("OARBANK_SESSION_SOCKET", &socket).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
        let out = Command::new("/usr/bin/sudo").args(["-n", "-u", "nobody", "/usr/bin/env", "OARBANK_E2E_ROLE=service"])
            .arg(format!("OARBANK_SESSION_SOCKET={}", socket.display())).arg(format!("OARBANK_E2E_DIR={}", svc.display()))
            .arg(format!("OARBANK_E2E_MARKER={marker}")).arg(&exe).args(["--exact", NAME, "--ignored", "--nocapture"])
            .output().unwrap();
        let _ = Command::new("/usr/bin/sudo").args(["-n", "-u", "nobody", "/bin/rm", "-rf"]).arg(svc.join("agent")).status();
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "the service side failed:\n{text}");
        eprintln!("{text}");
    }

    /// The service side, as `nobody`: wait until the helper's reports decide the rules.
    #[cfg(target_os = "macos")]
    fn session_service_side() {
        let dir = PathBuf::from(std::env::var("OARBANK_E2E_DIR").unwrap());
        let marker = std::env::var("OARBANK_E2E_MARKER").unwrap();
        let l = Layout::new(dir.join("agent"));
        l.ensure().unwrap();
        let mut p = Protection::new(&l, true);
        let rule = |id: &str, args: &str, when: Value| json!({"id": id, "match": {"argv_regex": args}, "active_when": when,
                                                             "pause_fleet": {}, "exit_after_s": 0});
        let d = json!({"desired_state": "active", "limits": {}, "policy": {"protection": {"node": {"mode": "fleet_first"}, "rule": [
            rule("busy", &format!("{marker}-busy"), json!({"for_s": 0, "cpu_cores_gt": 0.5})),
            rule("idle", &format!("{marker}-idle"), json!({"for_s": 0, "cpu_cores_gt": 0.5})),
            rule("present", &format!("{marker}-idle"), json!({"for_s": 0})),
            rule("absent", "no-such-arguments-anywhere", json!({"for_s": 0})),
            rule("front", "no-such-arguments-anywhere", json!({"for_s": 0, "frontmost": false}))]}}});
        let (table, facts) = (Table::default(), json!({"cpu": {"logical": 4}}));
        let want = [("busy", true), ("idle", false), ("present", true), ("absent", false)];
        let deadline = Instant::now() + Duration::from_secs(40);
        let r = loop {
            p.tick(&d, &table, &facts);
            let r = p.last.clone().unwrap();
            let active = |id: &str| r.reports.iter().any(|x| x.id == id && x.active);
            if want.iter().all(|(id, a)| active(id) == *a) || Instant::now() > deadline {
                break r;
            }
            std::thread::sleep(Duration::from_secs(1));
        };
        let report = |id: &str| r.reports.iter().find(|x| x.id == id).unwrap().clone();
        eprintln!("{:#?}", r.reports);
        for (id, a) in want {
            assert_eq!(report(id).active, a, "{id}: {:?}", report(id));
        }
        // the arguments came from the helper: this account cannot read them, and nothing matched for want of them
        let busy = report("busy");
        assert!(busy.processes == 1 && busy.unreadable == 0 && busy.cpu_cores > 0.5, "{busy:?}");
        let theirs = P::platform::macos::kinfo_of(P::platform::macos::console_uid().unwrap());
        assert!(theirs.iter().all(|k| P::platform::macos::argv(k.pid).is_none()), "the service reads no argv of theirs itself");
        // the front app: the console's account's helper read it
        let front = p.ctrl.telemetry(&r).front.unwrap();
        eprintln!("front: {front}; presence: {}", p.telemetry["presence"]);
        assert!(front.contains("session helper: lsappinfo"), "{front}");
        assert!(P::platform::macos::hid_idle_s().is_some(), "the HID idle time is anyone's to read");
        // code-signing identity is read by the service itself
        let sleep = theirs.iter().find(|k| P::platform::macos::path(k.pid).as_deref() == Some("/bin/sleep")).unwrap();
        assert_eq!(P::platform::macos::signing(sleep.pid).signing_id.as_deref(), Some("com.apple.sleep"));
    }
}
