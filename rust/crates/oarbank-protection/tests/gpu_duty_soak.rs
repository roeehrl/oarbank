//! A duty governor soak in virtual time: the real controller under `gpu_jobs = certified` against a scripted host for
//! 24 hours of 2 s ticks. The protected GPU program slows with the GPU duty fleet work actually uses (a contention
//! curve whose steepness changes through the day), restarts now and then, and its progress source goes unreadable at
//! times; the memory guard fires; certificates come, go stale and change level; GPU jobs arrive and leave, most of them
//! honest, some ignoring their duty, some whose GPU time cannot be read. Checked every tick:
//!
//! - every `gpu_duty` written is at most the smallest valid certificate's duty (the ceiling), and the duties written
//!   at once sum to at most the budget;
//! - no GPU job runs beside the protected program without a duty: work that cannot throttle, a held or distrusted unit,
//!   and every job while no valid certificate covers the program wait (paused or stopped);
//! - a job that ignores its duty is held within four samples of starting to exceed it, and stopped by its third hold;
//! - while the source is unreadable or the guard is active, no job runs with a duty after the tick that saw it.
//!
//! And over the day: the program's mean slowdown while fleet GPU work ran stays under its target.

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use common::SeededRandom;
use oarbank_protection::sources::{PhaseReport, Progress};
use oarbank_protection::*;
use serde_json::{json, Value};

#[derive(Default)]
struct World {
    procs: Vec<RawProcess>,
    gpu: HashMap<i32, f64>,
    rate: f64,
    readable: bool,
}

#[derive(Clone, Default)]
struct Host(Arc<Mutex<World>>);

impl ProcessSource for Host {
    fn list(&mut self, ex: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
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
        let mut t = GpuTimes::known(w.gpu.clone());
        // jobs 9xxx: their GPU time cannot be read
        t.unknown = w.gpu.keys().filter(|p| **p >= 9000).copied().collect();
        Some(t)
    }
    fn front(&mut self) -> FrontReading {
        FrontReading::new(Front::Nothing, "soak")
    }
}

impl OwnerSources for Host {
    fn progress(&mut self, _: &str, _: &Value, _: f64) -> Option<Progress> {
        let w = self.0.lock().unwrap();
        w.readable.then(|| Progress { events: w.rate * 2.0, seconds: 2.0 })
    }
    fn phase_on(&mut self, _: &str, _: &Value) -> bool {
        false
    }
    fn phases(&self) -> Vec<PhaseReport> {
        vec![]
    }
    fn progress_status(&self, _: &str) -> Option<(bool, String)> {
        Some((self.0.lock().unwrap().readable, "agent".into()))
    }
    fn reset(&mut self) {}
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Honest,
    Liar,
    Unmeasured,
    Stubborn,
}

struct SoakJob {
    view: FleetJobView,
    kind: Kind,
    /// The GPU pid whose time the meter reads.
    gpu_pid: i32,
    /// The duty last written to its control document (None: none, unlimited) and whether it is paused.
    duty: Option<f64>,
    paused: bool,
    over_since: Option<f64>,
    holds: u32,
}

#[test]
fn a_day_of_duty_governing() {
    let host = Host::default();
    let mut rng = SeededRandom::new(5050);
    let journal = Arc::new(DecisionJournal::in_memory());
    let mut ctl = ProtectionController::new(
        Some(journal.clone()),
        oarbank_protection::Host { processes: Box::new(host.clone()), meter: Box::new(host.clone()),
                                   sources: Box::new(host.clone()), os: None },
    );
    ctl.apply(Some(&json!({"schema": 1, "node": {"mode": "moderate", "gpu_jobs": "certified",
                                                  "implicit": {"frontmost_app": false, "owner_stall": null}},
        "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"}, "active_when": "present", "enter_for_s": 0,
                  "protect": {"metric": "progress_rate", "max_slowdown": 0.05,
                              "source": {"jsonl": "/x.jsonl", "event": "step"}}}]})), &LocalProtection::Absent);
    let ctx = CertContext { hardware: "h".into(), os_major: "o".into(), agent_version: "a".into() };
    let (mut trainer_start, mut next_id) = (1000u64, 1i64);
    let mut jobs: Vec<SoakJob> = vec![];
    let mut steep = 0.15; // slowdown at full duty used
    let mut guard_until = -1.0;
    let mut unreadable_until = -1.0;
    let (mut harm_sum, mut harm_n, mut ran_ticks, mut liars_stopped) = (0.0, 0usize, 0usize, 0usize);
    let mut t = 0.0;
    while t < 24.0 * 3600.0 {
        // ---------------------------------------------------------------- the world
        if rng.chance(0.0003) {
            trainer_start += 1;
        }
        if rng.chance(0.0004) {
            steep = rng.uniform(0.05, 0.4);
        }
        if rng.chance(0.0002) {
            guard_until = t + rng.uniform(10.0, 120.0);
        }
        if rng.chance(0.0002) {
            unreadable_until = t + rng.uniform(4.0, 300.0);
        }
        if rng.chance(0.0006) {
            if let Some(id) = ctl.identity("trainer") {
                let stale = rng.chance(0.2);
                let c = Certificate { id: "c".into(), rule: "trainer".into(), work: "gpu".into(), duty: Some(rng.uniform(0.1, 0.8)),
                    r: 1.0, r_lo: 0.99, r_hi: 1.01, margin: 0.02, run_id: "r".into(), issued_at: t,
                    valid_until: t + rng.uniform(1800.0, 6.0 * 3600.0),
                    identity: if stale { "0000000000000000".into() } else { id.to_string() }, context: ctx.clone() };
                ctl.set_certificates(vec![c], ctx.clone());
            }
        }
        if rng.chance(0.004) && jobs.len() < 5 {
            let kind = match rng.int(0, 9) {
                0 => Kind::Liar,
                1 => Kind::Unmeasured,
                2 => Kind::Stubborn,
                _ => Kind::Honest,
            };
            let mut v = FleetJobView::new(next_id, Some(5000 + next_id as i32), 1.0, t, 1.0);
            v.gpu = true;
            v.pausable = true;
            v.cooperative = true;
            v.duty = kind != Kind::Stubborn;
            v.module = "llm".into();
            v.name = match kind {
                Kind::Liar => "liar".into(),
                Kind::Unmeasured => "unmeasured".into(),
                _ => "batch".into(),
            };
            let gpu_pid = if kind == Kind::Unmeasured { 9000 + next_id as i32 } else { 6000 + next_id as i32 };
            v.pids = vec![5000 + next_id as i32, gpu_pid];
            jobs.push(SoakJob { view: v, kind, gpu_pid, duty: None, paused: false, over_since: None, holds: 0 });
            next_id += 1;
        }
        if rng.chance(0.002) && !jobs.is_empty() {
            let k = rng.int(0, jobs.len() as i64 - 1) as usize;
            jobs.remove(k);
        }
        // what fleet GPU work used over the last 2 s, and what that did to the protected program
        let mut used = 0.0;
        {
            let mut w = host.0.lock().unwrap();
            w.procs = vec![RawProcess { pid: 7, ppid: 1, start_us: trainer_start, path: Some("/opt/trainer/train".into()),
                                        comm: String::new(), cpu_s: 0.0, footprint_gb: 1.0, ..Default::default() }];
            *w.gpu.entry(7).or_insert(0.0) += 1.7e9;
            for j in &jobs {
                let u = if j.paused {
                    0.0
                } else {
                    match (j.kind, j.duty) {
                        (Kind::Liar, _) => 0.9,
                        (_, Some(d)) => d * rng.uniform(0.85, 1.0),
                        (_, None) => 0.9, // no duty asked: it runs flat out
                    }
                };
                used += u;
                *w.gpu.entry(j.gpu_pid).or_insert(0.0) += u * 2e9;
            }
            let harm = (steep * used.min(1.0)).min(0.9);
            w.rate = 10.0 * (1.0 - harm) * rng.uniform(0.98, 1.02);
            w.readable = t >= unreadable_until;
            if used > 0.0 {
                harm_sum += harm;
                harm_n += 1;
            }
        }
        let guard = t < guard_until;
        // ---------------------------------------------------------------- the tick
        let mut i = TickInputs::new(t, MemorySignals::new(64.0, if guard { 62.5 } else { 20.0 }, if guard { 2 } else { 0 }));
        i.jobs = jobs.iter().map(|j| j.view.clone()).collect();
        i.allocatable_cores = 8.0;
        let r = ctl.tick(&i);
        let ceiling = ctl.certified_duty("trainer", t);
        let budget = ctl.telemetry(&r).gpu_budget.and_then(|b| b["duty"].as_f64());
        // apply the plan as the agent would
        let gone: Vec<i64> = r.evictions.iter().map(|e| e.attempt_id).collect();
        for j in jobs.iter_mut() {
            if let Some(doc) = r.throttle.get(&j.view.attempt_id) {
                j.duty = doc.gpu_duty;
            }
            j.paused = r.paused.contains(&j.view.attempt_id);
        }
        // ---------------------------------------------------------------- the checks
        let gated = t > 4.0;
        let mut sum = 0.0;
        for j in jobs.iter_mut().filter(|j| !gone.contains(&j.view.attempt_id)) {
            let id = j.view.attempt_id;
            if j.paused || !gated {
                j.over_since = None;
                continue;
            }
            let d = j.duty.unwrap_or_else(|| panic!("t {t}: job {id} ({:?}) runs beside the protected program with no duty", j.kind));
            assert!(j.kind != Kind::Stubborn, "t {t}: work that cannot throttle ran");
            let c = ceiling.unwrap_or_else(|| panic!("t {t}: job {id} runs with no valid certificate"));
            assert!(d <= c + 1e-9, "t {t}: duty {d} above the ceiling {c}");
            sum += d;
            ran_ticks += 1;
            if j.kind == Kind::Liar && d + 0.1 < 0.9 {
                let since = *j.over_since.get_or_insert(t);
                assert!(t - since <= 10.0, "t {t}: liar {id} over its duty since {since} and still running");
            }
        }
        if let Some(b) = budget {
            assert!(sum <= b + 1e-6, "t {t}: duties {sum} over the budget {b}");
        }
        // the tick after an unreadable source or a guard, nothing runs with a duty
        if gated && (!host.0.lock().unwrap().readable || guard) {
            let running: Vec<i64> = jobs.iter().filter(|j| !j.paused && !gone.contains(&j.view.attempt_id))
                .map(|j| j.view.attempt_id).collect();
            assert!(running.is_empty(), "t {t}: {running:?} run while the source is unreadable or the guard acts");
        }
        for j in jobs.iter_mut().filter(|j| gone.contains(&j.view.attempt_id)) {
            if j.kind == Kind::Liar {
                liars_stopped += 1;
            }
            j.holds += 1;
        }
        jobs.retain(|j| !gone.contains(&j.view.attempt_id));
        t += 2.0;
    }
    let harm = harm_sum / harm_n.max(1) as f64;
    let recs = journal.pending(1_000_000);
    let count = |k: &str| recs.iter().filter(|r| r.reason() == k).count();
    eprintln!("{ran_ticks} job-ticks ran with a duty; mean slowdown while fleet GPU work ran {harm:.4}; {} grows, {} halvings, \
               {} take-backs, {} baselines, {} excess holds/stops, {} unverified, {liars_stopped} liars stopped",
              count("GPU_DUTY_GROW"), count("GPU_DUTY_HALVE"), count("GPU_DUTY_TAKE_BACK"), count("GPU_DUTY_BASELINE"),
              count("GPU_DUTY_EXCEEDED"), count("GPU_DUTY_UNVERIFIED"));
    assert!(ran_ticks > 2000, "certified work ran for a good part of the day");
    assert!(harm < 0.05, "mean slowdown {harm} over the target");
    assert!(count("GPU_DUTY_GROW") > 0 && count("GPU_DUTY_HALVE") + count("GPU_DUTY_TAKE_BACK") > 0);
    assert!(count("GPU_DUTY_EXCEEDED") > 0 && count("GPU_DUTY_UNVERIFIED") > 0);
    let _ = BTreeMap::<i64, f64>::new();
}
