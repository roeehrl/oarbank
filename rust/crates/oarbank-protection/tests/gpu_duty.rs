//! The GPU duty governor (D50): the AIMD budget under the certified ceiling, its baselines, S19 for the budget (a
//! missing, stale or worse signal never raises it), and the compliance check against measured GPU time. Pure tests on
//! the governor, then the controller with a scripted host. Synthetic processes and plants only.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use common::SeededRandom;
use oarbank_protection::sources::{PhaseReport, Progress};
use oarbank_protection::*;
use serde_json::{json, Value};

fn sig(rate: Option<f64>) -> DutySignal {
    DutySignal {
        rule: "trainer".into(),
        has_source: true,
        progress: rate.map(|r| Progress { events: r * 2.0, seconds: 2.0 }),
        readable: rate.is_some(),
        max_slowdown: 0.05,
    }
}

fn unit(id: i64, busy: Option<f64>) -> DutyUnit {
    DutyUnit { id, key: "llm/batch".into(), cooperative: true, pausable: true, busy }
}

/// One governor tick at `now` with the gate active and `ceiling`; the plan is applied as given (nothing else pauses).
fn tick(g: &mut DutyGovernor, now: f64, ceiling: Option<f64>, rate: Option<f64>, units: Vec<DutyUnit>) -> DutyOutputs {
    let o = g.step(&DutyInputs { now, gating: true, ceiling, signals: vec![sig(rate)], guard_clear: true, units });
    g.observe(&o.duty, &BTreeSet::new(), now);
    o
}

fn reasons(o: &DutyOutputs) -> Vec<&'static str> {
    o.events.iter().map(|e| e.reason).collect()
}

/// Run the governor from `t0` for `secs` with a plant: the protected program's rate is `base * (1 - harm(duty used))`.
fn run(g: &mut DutyGovernor, t0: f64, secs: f64, ceiling: f64, base: f64, harm: impl Fn(f64) -> f64) -> (f64, Vec<DutyOutputs>) {
    let mut t = t0;
    let mut used = 0.0;
    let mut outs = vec![];
    while t < t0 + secs {
        let rate = base * (1.0 - harm(used));
        let o = tick(g, t, Some(ceiling), Some(rate), vec![unit(1, Some(used))]);
        used = o.duty.get(&1).copied().unwrap_or(0.0);
        outs.push(o);
        t += 2.0;
    }
    (t, outs)
}

#[test]
fn a_rule_without_a_baseline_is_measured_first_then_the_budget_starts_at_the_ceiling() {
    let mut g = DutyGovernor::new();
    let o = tick(&mut g, 0.0, Some(0.4), Some(10.0), vec![unit(1, Some(0.0))]);
    assert_eq!(reasons(&o), vec!["GPU_DUTY_BASELINE"]);
    assert_eq!(o.budget, Some(0.0));
    assert!(o.duty.is_empty(), "no GPU work while the baseline is measured");
    assert_eq!(g.state(), "measuring");
    let (_, outs) = run(&mut g, 2.0, 70.0, 0.4, 10.0, |_| 0.0);
    let started = outs.iter().position(|o| reasons(o).contains(&"GPU_DUTY_START")).expect("the budget starts");
    // washout 20 s, then 40 s of readings: the window ends about a minute in
    assert!((25..=32).contains(&started), "started at tick {started}");
    assert_eq!(outs[started].budget, Some(0.4));
    assert_eq!(outs[started].duty.get(&1), Some(&0.4));
    assert_eq!(g.state(), "running");
}

#[test]
fn a_gate_without_progress_sources_starts_at_the_ceiling_and_holds() {
    let mut g = DutyGovernor::new();
    let i = DutyInputs { now: 0.0, gating: true, ceiling: Some(0.35), guard_clear: true, units: vec![unit(1, Some(0.0))],
                         signals: vec![DutySignal { rule: "gate".into(), has_source: false, readable: true, max_slowdown: 0.05,
                                                    progress: None }] };
    let o = g.step(&i);
    assert_eq!((o.budget, o.duty.get(&1).copied()), (Some(0.35), Some(0.35)));
    // nothing validates growth or harm: it holds
    for k in 1..200 {
        let o = g.step(&DutyInputs { now: k as f64 * 2.0, ..i.clone() });
        g.observe(&o.duty, &BTreeSet::new(), k as f64 * 2.0);
        assert_eq!(o.budget, Some(0.35));
    }
}

#[test]
fn harm_at_the_target_halves_harm_over_twice_takes_back_and_clean_intervals_grow_to_the_ceiling_only() {
    let mut g = DutyGovernor::new();
    // baseline first, harmless
    let (t, _) = run(&mut g, 0.0, 70.0, 0.6, 10.0, |_| 0.0);
    assert_eq!(g.budget(), Some(0.6));
    // harm of 6 % at any duty: halved at the next interval
    let (t, outs) = run(&mut g, t, 62.0, 0.6, 10.0, |u| if u > 0.0 { 0.06 } else { 0.0 });
    assert!(outs.iter().any(|o| reasons(o).contains(&"GPU_DUTY_HALVE")));
    assert_eq!(g.budget(), Some(0.3));
    // harm of 12 % (over twice the target): back to 0 with a lockout
    let t0 = t;
    let (t, outs) = run(&mut g, t, 62.0, 0.6, 10.0, |u| if u > 0.0 { 0.12 } else { 0.0 });
    let k = outs.iter().position(|o| reasons(o).contains(&"GPU_DUTY_TAKE_BACK")).expect("taken back");
    let taken_at = t0 + 2.0 * k as f64;
    assert_eq!(g.budget(), Some(0.0));
    assert_eq!(g.state(), "locked");
    // harmless again: nothing for the 5-minute lockout, then +0.05 a minute, never past the ceiling
    let t1 = t;
    let (t, outs) = run(&mut g, t, taken_at + 300.0 - t, 0.6, 10.0, |_| 0.0);
    assert!(outs.iter().all(|o| !reasons(o).contains(&"GPU_DUTY_GROW")), "no growth in the lockout");
    let _ = t1;
    let (_, outs) = run(&mut g, t, 3600.0, 0.6, 10.0, |_| 0.0);
    let grows: Vec<f64> = outs.iter().filter(|o| reasons(o).contains(&"GPU_DUTY_GROW")).filter_map(|o| o.budget).collect();
    assert!(grows.windows(2).all(|w| (w[1] - w[0] - 0.05).abs() < 1e-9 || w[1] == 0.6), "{grows:?}");
    assert_eq!(g.budget(), Some(0.6));
    assert!(outs.iter().all(|o| o.budget.unwrap_or(0.0) <= 0.6));
}

#[test]
fn the_budget_settles_where_the_plant_harms_less_than_the_target() {
    // harm grows with the duty used: 20 % harm at full duty, so 0.25 is the level at the 5 % target
    let mut g = DutyGovernor::new();
    let (_, outs) = run(&mut g, 0.0, 6.0 * 3600.0, 0.8, 10.0, |u| 0.2 * u);
    let late: Vec<f64> = outs[outs.len() / 2..].iter().filter_map(|o| o.budget).collect();
    let mean = late.iter().sum::<f64>() / late.len() as f64;
    assert!(late.iter().all(|d| *d <= 0.8));
    assert!(mean < 0.25 && mean > 0.05, "settles under the safe level, not at the ceiling or at 0: {mean}");
    let harm: f64 = late.iter().map(|d| 0.2 * d).sum::<f64>() / late.len() as f64;
    assert!(harm < 0.05, "mean harm {harm} under the target");
}

#[test]
fn an_unreadable_source_takes_the_budget_to_zero_at_once_and_a_collapse_too() {
    let mut g = DutyGovernor::new();
    let (t, _) = run(&mut g, 0.0, 70.0, 0.5, 10.0, |_| 0.0);
    assert_eq!(g.budget(), Some(0.5));
    let o = tick(&mut g, t, Some(0.5), None, vec![unit(1, Some(0.5))]);
    assert_eq!(o.budget, Some(0.0));
    assert!(o.duty.is_empty());
    assert!(reasons(&o).contains(&"GPU_DUTY_TAKE_BACK"));
    // readable again: it grows back from 0 (no lockout for an unreadable source), after a fresh baseline
    let (t, _) = run(&mut g, t + 2.0, 400.0, 0.5, 10.0, |_| 0.0);
    assert!(g.budget().unwrap() > 0.0);
    // a collapse (under half the baseline over 30 s) takes it back between intervals
    g.interval_s = 1e9;
    let mut seen = false;
    let mut now = t;
    for _ in 0..30 {
        let o = tick(&mut g, now, Some(0.5), Some(3.0), vec![unit(1, Some(0.1))]);
        if reasons(&o).contains(&"GPU_DUTY_TAKE_BACK") {
            seen = true;
            assert_eq!(o.events[0].detail["why"], "the protected program's progress collapsed");
            break;
        }
        now += 2.0;
    }
    assert!(seen && now - t <= 34.0, "taken back within the 30 s window");
}

#[test]
fn a_falling_ceiling_binds_at_once_and_a_lost_certificate_ends_the_budget() {
    let mut g = DutyGovernor::new();
    let (t, _) = run(&mut g, 0.0, 70.0, 0.6, 10.0, |_| 0.0);
    let o = tick(&mut g, t, Some(0.2), Some(10.0), vec![unit(1, Some(0.6))]);
    assert_eq!(o.budget, Some(0.2));
    assert!(reasons(&o).contains(&"GPU_DUTY_CLAMP"));
    let o = tick(&mut g, t + 2.0, None, Some(10.0), vec![unit(1, Some(0.2))]);
    assert_eq!((o.budget, o.duty.len(), g.state()), (None, 0, "not_certified"));
    // the certificate comes back within 10 minutes: resume where it was, not at the ceiling (no windup)
    let o = tick(&mut g, t + 30.0, Some(0.6), Some(10.0), vec![unit(1, Some(0.0))]);
    assert_eq!(o.budget, Some(0.2));
}

#[test]
fn the_budget_is_split_among_the_cooperative_units_and_others_get_none() {
    let mut g = DutyGovernor::new();
    run(&mut g, 0.0, 70.0, 0.6, 10.0, |_| 0.0);
    let mut stubborn = unit(3, Some(0.0));
    stubborn.cooperative = false;
    let o = tick(&mut g, 72.0, Some(0.6), Some(10.0), vec![unit(1, Some(0.0)), unit(2, Some(0.0)), stubborn]);
    assert_eq!(o.duty.get(&1), Some(&0.3));
    assert_eq!(o.duty.get(&2), Some(&0.3));
    assert!(!o.duty.contains_key(&3), "work that cannot throttle gets no duty (the gate holds it)");
}

/// S19 for the budget, over random signal sequences: the budget never exceeds the ceiling, it rises only by a start or
/// a growth step, and it grows only at the end of an interval (60 s) whose every sample was readable with the memory
/// guard clear and whose harm stayed under half the target.
#[test]
fn property_the_budget_never_grows_on_a_missing_stale_or_worse_signal() {
    for seed in 0..40u64 {
        let mut rng = SeededRandom::new(seed);
        let mut g = DutyGovernor::new();
        let mut ceiling = rng.uniform(0.1, 1.0);
        let mut t = 0.0;
        let mut used = 0.0;
        let mut log: Vec<(f64, bool)> = vec![]; // (time, the sample was readable with the guard clear)
        let mut last_budget = None;
        let mut grows = 0;
        for _ in 0..3000 {
            if rng.chance(0.003) {
                ceiling = rng.uniform(0.05, 1.0);
            }
            let readable = !rng.chance(0.02);
            let guard = !rng.chance(0.01);
            let harm = if used > 0.0 && rng.chance(0.1) { rng.uniform(0.0, 0.3) } else { 0.0 };
            let rate = readable.then_some(10.0 * (1.0 - harm));
            let o = g.step(&DutyInputs { now: t, gating: true, ceiling: Some(ceiling), signals: vec![sig(rate)],
                                         guard_clear: guard, units: vec![unit(1, Some(used))] });
            g.observe(&o.duty, &BTreeSet::new(), t);
            log.push((t, readable && guard));
            used = o.duty.get(&1).copied().unwrap_or(0.0);
            let b = o.budget.unwrap_or(0.0);
            assert!(b <= ceiling + 1e-9, "seed {seed} t {t}: budget {b} above the ceiling {ceiling}");
            for e in o.events.iter().filter(|e| e.reason == "GPU_DUTY_GROW") {
                grows += 1;
                let unclean: Vec<f64> = log.iter().filter(|(at, ok)| *at > t - 60.0 && !ok).map(|x| x.0).collect();
                assert!(unclean.is_empty(), "seed {seed} t {t}: grew after unclean samples at {unclean:?}: {:?}", e.detail);
                assert!(e.detail["pressure"]["trainer"].as_f64().unwrap_or(0.0) < 0.5);
            }
            if let (Some(a), Some(b)) = (last_budget, o.budget) {
                if b > a + 1e-9 {
                    let why = reasons(&o);
                    assert!(why.iter().any(|r| ["GPU_DUTY_GROW", "GPU_DUTY_START"].contains(r)), "seed {seed}: rose by {why:?}");
                }
            }
            last_budget = o.budget;
            t += 2.0;
        }
        assert!(grows > 0, "seed {seed}: the property was exercised");
    }
}

#[test]
fn a_unit_over_its_duty_for_three_samples_is_held_and_the_third_hold_in_an_hour_stops_it() {
    let mut g = DutyGovernor::new();
    run(&mut g, 0.0, 70.0, 0.4, 10.0, |_| 0.0);
    let mut t = 72.0;
    let mut holds = 0;
    let mut evicted_at = None;
    for _ in 0..2000 {
        // a liar: it keeps the GPU 90 % busy whatever it is asked
        let o = tick(&mut g, t, Some(0.4), Some(10.0), vec![unit(1, Some(0.9))]);
        for e in o.events.iter().filter(|e| e.reason == "GPU_DUTY_EXCEEDED") {
            holds += 1;
            assert_eq!(e.detail["attempt"], 1);
            if e.detail["action"] == "evicted" {
                evicted_at = Some(t);
            } else {
                assert_eq!(e.detail["action"], "paused");
                assert!(o.withheld.contains(&1) && !o.duty.contains_key(&1), "held: no duty, the gate pauses it");
            }
        }
        if !o.evict.is_empty() {
            assert_eq!(o.evict, vec![1]);
            break;
        }
        t += 2.0;
    }
    assert_eq!(holds, 3, "two holds, then the stop");
    assert!(evicted_at.unwrap() < 72.0 + 3600.0);
    // the same module unit is not trusted with a duty for an hour: a new attempt of it waits
    let o = tick(&mut g, t + 2.0, Some(0.4), Some(10.0), vec![DutyUnit { id: 9, ..unit(9, Some(0.0)) }]);
    assert!(o.withheld.contains(&9) && o.duty.is_empty());
    assert_eq!(g.distrusted(t + 2.0).len(), 1);
    let o = tick(&mut g, t + 3700.0, Some(0.4), Some(10.0), vec![unit(9, Some(0.0))]);
    assert!(o.duty.contains_key(&9), "trusted again after an hour");
}

#[test]
fn compliance_judges_only_whole_samples_at_a_settled_duty_and_allows_the_slack() {
    let mut g = DutyGovernor::new();
    run(&mut g, 0.0, 70.0, 0.4, 10.0, |_| 0.0);
    let mut t = 72.0;
    // within duty + 0.1: never held
    for _ in 0..100 {
        let o = tick(&mut g, t, Some(0.4), Some(10.0), vec![unit(1, Some(0.49))]);
        assert!(o.events.iter().all(|e| e.kind != "gpu_compliance"));
        t += 2.0;
    }
    // a unit just given a duty (it ran unthrottled before) is not judged on its first samples
    let o = tick(&mut g, t, Some(0.4), Some(10.0), vec![unit(1, Some(0.4)), unit(2, Some(1.0))]);
    assert!(o.events.iter().all(|e| e.kind != "gpu_compliance"));
    let o = tick(&mut g, t + 2.0, Some(0.4), Some(10.0), vec![unit(1, Some(0.2)), unit(2, Some(1.0))]);
    assert!(o.events.iter().all(|e| e.kind != "gpu_compliance"));
    // a unit paused by something else is not judged either
    let mut paused = BTreeSet::new();
    paused.insert(2);
    for k in 0..5 {
        let now = t + 4.0 + 2.0 * k as f64;
        let o = g.step(&DutyInputs { now, gating: true, ceiling: Some(0.4), signals: vec![sig(Some(10.0))], guard_clear: true,
                                     units: vec![unit(1, Some(0.2)), unit(2, Some(1.0))] });
        g.observe(&o.duty, &paused, now);
        assert!(o.events.iter().all(|e| e.kind != "gpu_compliance"), "{:?}", o.events);
    }
}

#[test]
fn a_unit_whose_gpu_time_cannot_be_read_is_held_and_one_that_cannot_pause_is_stopped() {
    let mut g = DutyGovernor::new();
    run(&mut g, 0.0, 70.0, 0.4, 10.0, |_| 0.0);
    let mut t = 72.0;
    let mut got = None;
    for _ in 0..10 {
        let o = tick(&mut g, t, Some(0.4), Some(10.0), vec![unit(1, None)]);
        if let Some(e) = o.events.iter().find(|e| e.reason == "GPU_DUTY_UNVERIFIED") {
            got = Some((e.detail["action"].clone(), o.withheld.contains(&1)));
            break;
        }
        t += 2.0;
    }
    assert_eq!(got, Some((json!("paused"), true)));
    // a cooperative unit that cannot be paused and exceeds its duty is stopped at once
    let mut g = DutyGovernor::new();
    run(&mut g, 0.0, 70.0, 0.4, 10.0, |_| 0.0);
    let mut t = 72.0;
    let mut u = unit(4, Some(0.95));
    u.pausable = false;
    for _ in 0..10 {
        let o = tick(&mut g, t, Some(0.4), Some(10.0), vec![u.clone()]);
        if !o.evict.is_empty() {
            assert_eq!(o.evict, vec![4]);
            return;
        }
        t += 2.0;
    }
    panic!("never stopped");
}

#[test]
fn the_memory_guard_takes_the_budget_back_with_a_lockout() {
    let mut g = DutyGovernor::new();
    run(&mut g, 0.0, 70.0, 0.5, 10.0, |_| 0.0);
    let o = g.step(&DutyInputs { now: 72.0, gating: true, ceiling: Some(0.5), signals: vec![sig(Some(10.0))],
                                 guard_clear: false, units: vec![unit(1, Some(0.5))] });
    assert_eq!(o.budget, Some(0.0));
    assert_eq!(g.state(), "locked");
}

#[test]
fn an_old_baseline_is_refreshed_with_a_baseline_window() {
    let mut g = DutyGovernor::new();
    let (_, outs) = run(&mut g, 0.0, 2.0 * 3600.0, 0.5, 10.0, |_| 0.0);
    let windows = outs.iter().filter(|o| reasons(o).contains(&"GPU_DUTY_BASELINE")).count();
    assert!((4..=6).contains(&windows), "the first, then about every 30 minutes: {windows}");
    // GPU work was held about 60 s of every 30 minutes
    let held = outs.iter().filter(|o| o.duty.is_empty()).count() as f64 / outs.len() as f64;
    assert!(held < 0.06, "held {held}");
}

// ------------------------------------------------------------------ the controller

#[derive(Clone, Default)]
struct World {
    procs: Vec<RawProcess>,
    gpu: HashMap<i32, f64>,
    rate: f64,
    readable: bool,
}

#[derive(Clone, Default)]
struct Scripted(Arc<Mutex<World>>);

impl ProcessSource for Scripted {
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

impl Meter for Scripted {
    fn proc_counters(&mut self, _: i32) -> Option<ProcCounters> {
        Some(ProcCounters::default())
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        Some(GpuTimes::known(self.0.lock().unwrap().gpu.clone()))
    }
    fn front(&mut self) -> FrontReading {
        FrontReading::new(Front::Nothing, "test")
    }
}

impl OwnerSources for Scripted {
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

fn trainer(gpu_jobs: &str) -> (ProtectionController, Scripted, Arc<DecisionJournal>) {
    let host = Scripted::default();
    {
        let mut w = host.0.lock().unwrap();
        w.procs = vec![RawProcess { pid: 7, ppid: 1, start_us: 1007, path: Some("/opt/trainer/train".into()),
                                    comm: String::new(), cpu_s: 0.0, footprint_gb: 1.0 }];
        w.rate = 10.0;
        w.readable = true;
    }
    let journal = Arc::new(DecisionJournal::in_memory());
    let mut ctl = ProtectionController::new(
        Some(journal.clone()),
        Host { processes: Box::new(host.clone()), meter: Box::new(host.clone()), sources: Box::new(host.clone()), os: None },
    );
    ctl.apply(Some(&json!({"schema": 1, "node": {"mode": "moderate", "gpu_jobs": gpu_jobs,
                                                  "implicit": {"frontmost_app": false, "owner_stall": null}},
        "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"}, "active_when": "present", "enter_for_s": 0,
                  "protect": {"metric": "progress_rate", "max_slowdown": 0.05,
                              "source": {"jsonl": "/x.jsonl", "event": "step"}}}]})), &LocalProtection::Absent);
    (ctl, host, journal)
}

fn job(id: i64, duty: bool) -> FleetJobView {
    let mut j = FleetJobView::new(id, Some(600 + id as i32), 1.0, 0.0, 1.0);
    j.gpu = true;
    j.pausable = true;
    j.cooperative = true;
    j.duty = duty;
    j.module = "llm".into();
    j.name = "batch".into();
    j.pids = vec![600 + id as i32, 700 + id as i32];
    j
}

/// Advance the scripted world 2 s: the trainer keeps the GPU 90 % busy, each job uses `use_of(id, duty asked)` of it.
fn advance(ctl: &mut ProtectionController, host: &Scripted, now: f64, jobs: &[FleetJobView], duty: &BTreeMap<i64, f64>,
           use_of: &dyn Fn(i64, f64) -> f64) -> ProtectionTickResult {
    {
        let mut w = host.0.lock().unwrap();
        *w.gpu.entry(7).or_insert(0.0) += 1.8e9;
        for j in jobs {
            let d = duty.get(&j.attempt_id).copied().unwrap_or(0.0);
            // the child process does the GPU work
            *w.gpu.entry(700 + j.attempt_id as i32).or_insert(0.0) += use_of(j.attempt_id, d) * 2e9;
        }
    }
    let mut i = TickInputs::new(now, MemorySignals::new(64.0, 20.0, 0));
    i.jobs = jobs.to_vec();
    i.allocatable_cores = 8.0;
    ctl.tick(&i)
}

fn cert(ctl: &ProtectionController, duty: f64) -> Certificate {
    Certificate {
        id: "c1".into(), rule: "trainer".into(), work: "gpu".into(), duty: Some(duty), r: 0.995, r_lo: 0.985, r_hi: 1.004,
        margin: 0.02, run_id: "ab_1".into(), issued_at: 0.0, valid_until: 1e12,
        identity: ctl.identity("trainer").expect("identity").to_string(),
        context: CertContext { hardware: "h".into(), os_major: "o".into(), agent_version: "a".into() },
    }
}

/// A protected progress_rate group that uses the GPU gates GPU work like a gpu_share group does (D3d, D50), under
/// when_no_gpu_protected as under certified.
#[test]
fn a_gpu_bound_progress_rate_group_gates_gpu_work() {
    let (mut ctl, host, _) = trainer("when_no_gpu_protected");
    let jobs = vec![job(1, true)];
    let mut duty = BTreeMap::new();
    advance(&mut ctl, &host, 0.0, &jobs, &duty, &|_, _| 0.0);
    let r = advance(&mut ctl, &host, 2.0, &jobs, &duty, &|_, _| 0.0);
    assert!(r.paused.contains(&1), "the trainer uses the GPU: GPU work waits");
    // a group that does not use the GPU does not gate
    host.0.lock().unwrap().gpu.insert(7, 0.0);
    let (mut ctl, host, _) = trainer("when_no_gpu_protected");
    for k in 0..3 {
        let r = ctl.tick(&{
            let mut i = TickInputs::new(k as f64 * 2.0, MemorySignals::new(64.0, 20.0, 0));
            i.jobs = jobs.clone();
            i
        });
        assert!(!r.paused.contains(&1));
    }
    duty.clear();
    let _ = host;
    // gpu_jobs = always: a progress_rate group never holds GPU work back
    let (mut ctl, host, _) = trainer("always");
    advance(&mut ctl, &host, 0.0, &jobs, &duty, &|_, _| 0.0);
    let r = advance(&mut ctl, &host, 2.0, &jobs, &duty, &|_, _| 0.0);
    assert!(!r.paused.contains(&1), "gpu_jobs = always runs GPU work beside it");
}

#[test]
fn certified_work_runs_at_the_governors_budget_after_a_baseline_and_a_liar_is_held_then_stopped() {
    let (mut ctl, host, journal) = trainer("certified");
    let jobs = vec![job(1, true), job(2, true)];
    let mut duty: BTreeMap<i64, f64> = BTreeMap::new();
    advance(&mut ctl, &host, 0.0, &jobs, &duty, &|_, _| 0.0);
    let r = advance(&mut ctl, &host, 2.0, &jobs, &duty, &|_, _| 0.0);
    assert!(r.paused.contains(&1), "no certificate yet: the gate holds");
    let c = cert(&ctl, 0.5);
    ctl.set_certificates(vec![c], CertContext { hardware: "h".into(), os_major: "o".into(), agent_version: "a".into() });
    let mut t = 4.0;
    let mut first_duty = None;
    let honest = |_: i64, d: f64| d;
    while t < 200.0 {
        let r = advance(&mut ctl, &host, t, &jobs, &duty, &honest);
        for (id, d) in r.throttle.iter() {
            if let Some(g) = d.gpu_duty {
                duty.insert(*id, g);
            } else {
                duty.remove(id);
            }
        }
        for id in &r.paused {
            duty.remove(id);
        }
        if first_duty.is_none() && !duty.is_empty() {
            first_duty = Some(t);
        }
        t += 2.0;
    }
    let started = first_duty.expect("certified work ran");
    assert!(started >= 60.0, "a baseline window came first ({started})");
    assert_eq!(duty.get(&1), Some(&0.25), "the budget split between the two cooperative jobs");
    let last = advance(&mut ctl, &host, t, &jobs, &duty, &honest);
    let tel = ctl.telemetry(&last);
    let b = tel.gpu_budget.unwrap();
    assert_eq!((b["duty"].as_f64(), b["state"].as_str(), b["jobs"].as_i64()), (Some(0.5), Some("running"), Some(2)));
    assert!(b["units"].as_array().unwrap().iter().all(|u| u["state"] == "ok"), "{b}");
    // job 2 starts ignoring its duty: held (paused, journaled), then stopped on the third hold within the hour
    let liar = |id: i64, d: f64| if id == 2 { 0.95 } else { d };
    let mut stopped = None;
    let mut paused_seen = false;
    t += 2.0;
    while t < 4000.0 {
        let r = advance(&mut ctl, &host, t, &jobs, &duty, &liar);
        for (id, d) in r.throttle.iter() {
            match d.gpu_duty {
                Some(g) => duty.insert(*id, g),
                None => duty.remove(id),
            };
        }
        if r.paused.contains(&2) {
            paused_seen = true;
            duty.remove(&2);
        }
        if r.evictions.iter().any(|e| e.attempt_id == 2) {
            stopped = Some(t);
            break;
        }
        t += 2.0;
    }
    assert!(paused_seen && stopped.is_some(), "held, then stopped");
    let recs = journal.pending(100_000);
    let exceeded: Vec<&JournalRecord> = recs.iter().filter(|r| r.reason() == "GPU_DUTY_EXCEEDED").collect();
    assert_eq!(exceeded.len(), 3, "two holds and the stop are journaled");
    let reasons: Vec<&str> = recs.iter().map(|r| r.reason()).collect();
    for k in ["GPU_DUTY_BASELINE", "GPU_DUTY_START"] {
        assert!(reasons.contains(&k), "{k} journaled");
    }
}

/// While a harness run measures GPU work, the governor stands down: the run alone decides what runs.
#[test]
fn the_governor_stands_down_while_a_harness_run_measures_gpu_work() {
    let (mut ctl, host, _) = trainer("certified");
    let jobs = vec![job(1, true)];
    let duty = BTreeMap::new();
    advance(&mut ctl, &host, 0.0, &jobs, &duty, &|_, _| 0.0);
    advance(&mut ctl, &host, 2.0, &jobs, &duty, &|_, _| 0.0);
    let c = cert(&ctl, 0.5);
    ctl.set_certificates(vec![c], CertContext { hardware: "h".into(), os_major: "o".into(), agent_version: "a".into() });
    let spec: AbSpec = serde_json::from_value(json!({"run_id": "ab_9", "rule": "trainer", "work": "gpu", "duty": 0.3,
                                                     "blocks": 4, "window_s": 30, "washout_s": 4, "margin": 0.05})).unwrap();
    ctl.start_ab(spec, 4.0).unwrap();
    let r = advance(&mut ctl, &host, 4.0, &jobs, &duty, &|_, _| 0.0);
    let tel = ctl.telemetry(&r);
    assert_eq!(tel.gpu_budget.unwrap()["state"], "harness");
    assert_eq!(ctl.duty.state(), "idle");
}
