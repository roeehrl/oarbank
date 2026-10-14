//! A co-tenancy soak in virtual time: the real controller against a scripted host for 12 hours of 2 s ticks, with a
//! protected GPU program that restarts, an immediate phase and a process trigger that come and go, GPU and CPU fleet
//! jobs arriving and leaving, certificates appearing, expiring and going stale, and harness runs started one after
//! another. Checked every tick:
//!
//! - a phase on (or a trigger's process running) while its rule is armed pauses every pausable job in its scope;
//! - under `gpu_jobs = certified`, a GPU job runs beside the protected GPU program only with a valid certificate for
//!   every gating rule and only if it honours `gpu_duty`, at no more than the certified duty (the duty governor's
//!   budget stays under the ceiling), and no GPU work is admitted beyond what runs;
//! - in a harness run's OFF window every pausable job under test is paused, and every run ends with a decision within
//!   its cap.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use common::SeededRandom;
use oarbank_protection::harness::RunState;
use oarbank_protection::sources::{PhaseReport, Progress};
use oarbank_protection::*;
use serde_json::{json, Value};

#[derive(Default)]
struct World {
    procs: Vec<RawProcess>,
    gpu_ns: f64,
    phase: bool,
    rate: f64,
    exec: HashMap<String, bool>,
}

#[derive(Clone, Default)]
struct Host(Arc<Mutex<World>>);

impl ProcessSource for Host {
    fn list(&mut self, ex: &std::collections::HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        Ok(self.0.lock().unwrap().procs.iter().filter(|p| !ex.contains(&p.pid)).cloned().collect())
    }
    fn argv(&mut self, pid: i32, _: u64) -> Option<Vec<String>> {
        Some(vec![format!("p{pid}")])
    }
    fn signing(&mut self, _: i32) -> SigningIdentity {
        SigningIdentity::default()
    }
    fn satisfies(&mut self, _: i32, _: &str) -> bool {
        false
    }
    fn bundle_id(&mut self, _: &str) -> Option<String> {
        None
    }
}

impl Meter for Host {
    fn proc_counters(&mut self, _: i32) -> Option<ProcCounters> {
        Some(ProcCounters::default())
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        let w = self.0.lock().unwrap();
        let pid = w.procs.iter().find(|p| p.path.as_deref().is_some_and(|x| x.starts_with("/opt/trainer/")))?.pid;
        Some(GpuTimes::known(HashMap::from([(pid, w.gpu_ns)])))
    }
    fn front(&mut self) -> FrontReading {
        FrontReading::new(Front::Nothing, "soak")
    }
}

impl OwnerSources for Host {
    fn progress(&mut self, _: &str, _: &Value, _: f64) -> Option<Progress> {
        Some(Progress { events: self.0.lock().unwrap().rate * 2.0, seconds: 2.0 })
    }
    fn phase_on(&mut self, key: &str, _: &Value) -> bool {
        let w = self.0.lock().unwrap();
        (key == "trainer#0" && w.phase) || w.exec.get(key).copied().unwrap_or(false)
    }
    fn set_exec_phase(&mut self, key: &str, on: bool) {
        self.0.lock().unwrap().exec.insert(key.to_string(), on);
    }
    fn phases(&self) -> Vec<PhaseReport> {
        vec![]
    }
    fn reset(&mut self) {}
}

fn raw(pid: i32, start: u64, path: &str) -> RawProcess {
    RawProcess { pid, ppid: 1, start_us: start, path: Some(path.into()), comm: String::new(), cpu_s: 0.0, footprint_gb: 1.0, ..Default::default() }
}

#[test]
fn twelve_hours_of_co_tenancy() {
    let host = Host::default();
    let mut rng = SeededRandom::new(1210);
    let mut ctl = ProtectionController::new(
        Some(Arc::new(DecisionJournal::in_memory())),
        oarbank_protection::Host { processes: Box::new(host.clone()), meter: Box::new(host.clone()),
                                   sources: Box::new(host.clone()), os: None },
    );
    ctl.apply(Some(&json!({"schema": 1, "node": {"mode": "moderate", "gpu_jobs": "certified",
                                                  "implicit": {"frontmost_app": false, "owner_stall": null}},
        "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"}, "active_when": "present", "enter_for_s": 0,
                  "immediate": true,
                  "protect": {"metric": "progress_rate", "max_slowdown": 0.05, "source": {"jsonl": "/x", "event": "s"}},
                  "during": [{"source": {"jsonl": "/x", "enter": "a", "exit": "b"}, "pause_fleet": {"scope": "gpu"}},
                             {"source": {"on_exec": {"match": {"path_prefix": "/opt/uploader/"}}},
                              "pause_fleet": {"scope": "all"}}]},
                 {"id": "gate", "match": {"path_prefix": "/opt/trainer/"}, "active_when": "present", "enter_for_s": 0,
                  "protect": {"metric": "gpu_share", "max": 0.99}}]})), &LocalProtection::Absent);
    let ctx = CertContext { hardware: "h".into(), os_major: "o".into(), agent_version: "a".into() };
    let mut jobs: Vec<FleetJobView> = vec![];
    let (mut next_job, mut next_pid, mut trainer_start) = (1i64, 50_000i32, 1000u64);
    let mut uploader = false;
    let mut certs: Vec<Certificate> = vec![];
    let (mut runs, mut runs_done, mut checked_off, mut certified_ran) = (0, 0, 0, 0);
    let mut run_started = 0.0f64;
    let mut t = 0.0;
    while t < 12.0 * 3600.0 {
        // the world changes
        {
            let mut w = host.0.lock().unwrap();
            if rng.chance(0.0005) {
                trainer_start += 1; // the protected program restarts
            }
            if rng.chance(0.004) {
                w.phase = !w.phase;
            }
            if rng.chance(0.003) {
                uploader = !uploader;
            }
            w.gpu_ns += 1.8e9;
            w.rate = 10.0 * if jobs.iter().any(|j| j.gpu) { rng.uniform(0.985, 1.005) } else { rng.uniform(0.99, 1.01) };
            w.procs = vec![raw(7, trainer_start, "/opt/trainer/train")];
            if uploader {
                w.procs.push(raw(9, 2000, "/opt/uploader/up"));
            }
        }
        if rng.chance(0.02) && jobs.len() < 6 {
            let mut j = FleetJobView::new(next_job, Some(next_pid), 1.0, t, 1.0);
            j.gpu = rng.chance(0.5);
            j.pausable = rng.chance(0.8);
            j.cooperative = j.pausable;
            j.duty = j.gpu && rng.chance(0.6);
            j.module = "m".into();
            j.name = "s".into();
            jobs.push(j);
            next_job += 1;
            next_pid += 1;
        }
        if rng.chance(0.01) && !jobs.is_empty() {
            let k = rng.int(0, jobs.len() as i64 - 1) as usize;
            jobs.remove(k);
        }
        // certificates: issued for the current program, expiring, or for an old build
        if rng.chance(0.001) {
            // both rules gate GPU work (a GPU-bound progress_rate group gates, D50), so each needs its own
            if let Some(id) = ctl.identity("gate") {
                let stale = rng.chance(0.3);
                certs = ["gate", "trainer"].iter().map(|rule| Certificate {
                    id: format!("c-{rule}"), rule: rule.to_string(), work: "gpu".into(), duty: Some(rng.uniform(0.1, 0.6)),
                    r: 1.0, r_lo: 0.99, r_hi: 1.01, margin: 0.02, run_id: "r".into(), issued_at: t,
                    valid_until: t + rng.uniform(600.0, 7200.0) + 1.79e9,
                    identity: if stale { "0000000000000000".into() } else { id.to_string() }, context: ctx.clone() }).collect();
                ctl.set_certificates(certs.clone(), ctx.clone());
            }
        }
        // harness runs, one after another
        if ctl.harness().is_none_or(|h| h.finished()) && rng.chance(0.002) {
            if let Some(h) = ctl.harness() {
                assert!(h.outcome.is_some(), "a finished run has a decision");
                let id = h.spec.run_id.clone();
                ctl.ab_ack(&id);
                runs_done += 1;
            }
            let spec: AbSpec = serde_json::from_value(json!({"run_id": format!("ab_{runs}"), "rule": "trainer",
                "work": if rng.chance(0.5) { "gpu" } else { "cpu" }, "duty": 0.3, "blocks": 4, "window_s": 60,
                "washout_s": 10, "margin": 0.05, "max_hours": 1.0, "seed": runs})).unwrap();
            ctl.start_ab(spec, t + 1.79e9).unwrap();
            runs += 1;
            run_started = t;
        }
        if let Some(h) = ctl.harness().filter(|h| !h.finished()) {
            assert!(t - run_started <= 3600.0 + 4.0, "a run outlived its cap");
            let _ = h;
        }
        let mut i = TickInputs::new(t + 1.79e9, MemorySignals::new(64.0, 20.0, 0));
        i.jobs = jobs.clone();
        i.allocatable_cores = 8.0;
        let measuring_before = ctl.harness().is_some_and(|h| !h.finished());
        let r = ctl.tick(&i);
        // a run that ended on this tick still held its arm during it
        let ended_now = measuring_before && ctl.harness().is_some_and(|h| h.finished());
        let now = t + 1.79e9;
        // phases: an armed rule's phase (or trigger) pauses every pausable job in its scope
        let phase = host.0.lock().unwrap().phase;
        for j in jobs.iter().filter(|j| j.pausable) {
            if (phase && j.gpu) || uploader {
                let evicted = r.evictions.iter().any(|e| e.attempt_id == j.attempt_id);
                assert!(r.paused.contains(&j.attempt_id) || evicted, "t {t}: phase on, job {} not paused", j.attempt_id);
            }
        }
        // released attempts leave (a pause past the limit, the harness's evicted OFF)
        let gone: Vec<i64> = r.evictions.iter().map(|e| e.attempt_id).collect();
        // certified GPU co-tenancy (the gate holds once GPU time has been read twice)
        if t > 2.0 {
            let duty = match (ctl.certified_duty("gate", now), ctl.certified_duty("trainer", now)) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None,
            };
            // (a GPU job that can be neither paused nor frozen is lowered, as under when_no_gpu_protected)
            for j in jobs.iter().filter(|j| j.gpu && !j.pausable && duty.is_none() && ctl.harness().is_none_or(|h| h.finished())) {
                assert!(r.lowered.contains(&j.attempt_id) || gone.contains(&j.attempt_id), "t {t}: unpausable GPU job not lowered");
            }
            for j in jobs.iter().filter(|j| j.gpu && j.pausable && !r.paused.contains(&j.attempt_id) && !gone.contains(&j.attempt_id)) {
                let under_test = ctl.harness().is_some_and(|h| !h.finished() && h.arm() == Some(Arm::On)
                                                            && h.work.matches(&j.module, &j.name, true));
                if under_test || (ended_now && ctl.harness().is_some_and(|h| h.work.matches(&j.module, &j.name, true))) {
                    continue; // the harness's ON window exempts the work it measures
                }
                assert!(j.duty, "t {t}: a GPU job that cannot honour gpu_duty ran beside the protected GPU program");
                let d = duty.unwrap_or_else(|| panic!("t {t}: GPU work ran with no valid certificate: job {:?} tel {:?} rules {:?} harness {:?}",
                    j, ctl.telemetry(&r).gpu_budget, r.reports.iter().map(|x| (x.id.clone(), x.active)).collect::<Vec<_>>(),
                    ctl.harness().map(|h| (h.state, h.arm(), h.spec.work.clone()))));
                certified_ran += 1;
                if let Some(doc) = r.throttle.get(&j.attempt_id) {
                    assert!(doc.gpu_duty.unwrap_or(1.0) <= d + 1e-9, "t {t}: duty above the certificate: {doc:?} (ceiling {d})");
                }
            }
            if ctl.harness().is_none_or(|h| h.finished()) && !ended_now {
                let running = jobs.iter().filter(|j| j.gpu && j.duty && duty.is_some()).count() as i64;
                assert!(r.constraint.gpu_jobs.is_some_and(|n| n <= running), "t {t}: GPU admission past what runs");
            }
        }
        // the harness's OFF windows hold the work under test
        if let Some(h) = ctl.harness().filter(|h| !h.finished() && h.arm() == Some(Arm::Off)) {
            for j in jobs.iter().filter(|j| j.pausable && h.work.matches(&j.module, &j.name, j.gpu)) {
                assert!(r.paused.contains(&j.attempt_id) || gone.contains(&j.attempt_id),
                        "t {t}: OFF window, job {} runs", j.attempt_id);
                checked_off += 1;
            }
        }
        jobs.retain(|j| !gone.contains(&j.attempt_id));
        t += 2.0;
    }
    eprintln!("{runs} runs started, {runs_done} finished and acknowledged; {checked_off} OFF checks; \
               {certified_ran} certified GPU job-ticks");
    assert!(runs >= 5 && runs_done >= 4 && checked_off > 0 && certified_ran > 0);
    if let Some(h) = ctl.harness() {
        assert!(matches!(h.state, RunState::Pilot | RunState::Running | RunState::Done | RunState::Aborted));
    }
}
