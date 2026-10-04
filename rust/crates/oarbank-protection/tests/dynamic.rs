//! The dynamic controller (its measured defaults and the cooperative throttle), and the signal formulas.

mod common;

use std::collections::BTreeSet;

use common::SeededRandom;
use oarbank_protection::signals::frontmost;
use oarbank_protection::*;

/// A protected reporter that slows down as fleet work shares its machine: harmless up to `free` cores, then
/// `per_core` per extra P-core-equivalent. E-core (lowered) fleet work costs a third of a P-core; paused work
/// costs nothing. A crude stand-in for measured bandwidth/cache interference.
struct ReporterPlant {
    free: f64,
    per_core: f64,
    base_rate: f64,
}

impl Default for ReporterPlant {
    fn default() -> Self {
        Self {
            free: 6.0,
            per_core: 0.01,
            base_rate: 100.0,
        }
    }
}

impl ReporterPlant {
    fn slowdown(&self, p: f64, e: f64) -> f64 {
        ((p + e / 3.0) - self.free).max(0.0) * self.per_core
    }
    fn rate(&self, p: f64, e: f64) -> f64 {
        self.base_rate * (1.0 - self.slowdown(p, e))
    }
}

fn job(i: i64, pausable: bool, gpu: bool) -> DynJob {
    DynJob {
        attempt_id: i,
        pausable,
        gpu,
        ..DynJob::new(i)
    }
}

fn jobs(n: i64) -> Vec<DynJob> {
    (1..=n).map(|i| job(i, true, false)).collect()
}

fn set(ids: &[i64]) -> BTreeSet<i64> {
    ids.iter().copied().collect()
}

/// moderate, protect progress_rate max_slowdown 0.05: the reporter stays within 5 % once converged while the
/// fleet keeps at least half of its fleet_first throughput.
#[test]
fn moderate_holds_the_slowdown_and_keeps_throughput() {
    let plant = ReporterPlant::default();
    let mut c = DynamicController::new();
    let allocatable = 14.0;
    let (mut slowdowns, mut cores) = (vec![], vec![]);
    let mut last: Option<DynOutputs> = None;
    let (mut probe_ticks, mut ticks) = (0, 0);
    let mut t = 0.0;
    while t < 6.0 * 3600.0 {
        // the fleet fills its budget; lowered jobs run on the E-cores, paused ones not at all
        let budget = last
            .as_ref()
            .and_then(|o| o.budget_cores)
            .unwrap_or(allocatable);
        let paused = last.as_ref().is_some_and(|o| !o.paused.is_empty());
        let lowered = last.as_ref().is_some_and(|o| !o.lowered.is_empty());
        let p = if paused || lowered { 0.0 } else { budget };
        let e = if paused {
            0.0
        } else if lowered {
            budget
        } else {
            0.0
        };
        let rate = plant.rate(p, e);
        let mut i = DynInputs::new(t, ProtectionMode::Moderate, allocatable);
        i.signals = vec![ProtectedSignal::with_slowdown(
            "rule:mlx",
            "progress_rate",
            Some(rate),
            0.05,
        )];
        i.any_protected_active = true;
        i.protection_started = t == 0.0;
        i.jobs = jobs(allocatable as i64);
        let o = c.step(&i);
        if o.probing {
            probe_ticks += 1;
        }
        ticks += 1;
        if t > 3600.0 && !o.probing {
            slowdowns.push(plant.slowdown(p, e));
            cores.push(p + e / 3.0);
        }
        last = Some(o);
        t += 2.0;
    }
    let avg_slow = slowdowns.iter().sum::<f64>() / slowdowns.len() as f64;
    let avg_cores = cores.iter().sum::<f64>() / cores.len() as f64;
    let probe = probe_ticks as f64 / ticks as f64;
    println!("moderate: avg slowdown {avg_slow:.4}, fleet {avg_cores:.2} of {allocatable} cores, probe {probe:.4}");
    assert!(avg_slow <= 0.05);
    assert!(avg_cores >= 0.5 * allocatable);
    assert!(probe <= 0.015); // probe cost
}

/// S19: a worse (or stale, or guarded) signal never yields a larger allowance than a better one from the same
/// controller state.
#[test]
fn s19_monotone_and_fail_safe() {
    let mut rng = SeededRandom::new(19);
    for _ in 0..400 {
        let mut c = DynamicController::new();
        let mut t = 0.0;
        for _ in 0..rng.int(1, 200) {
            let mut i = DynInputs::new(t, ProtectionMode::Moderate, 12.0);
            i.signals = vec![ProtectedSignal::with_max(
                "rule:a",
                "cpu_stall",
                Some(rng.uniform(0.0, 0.3)),
                0.1,
            )];
            i.jobs = jobs(4);
            c.step(&i);
            t += 2.0;
        }
        let v = rng.uniform(0.0, 0.3);
        let worse = v + rng.uniform(0.0, 0.3);
        let run = |s: ProtectedSignal, guard: GuardLevel| {
            let mut copy = c.clone();
            let mut i = DynInputs::new(t + 60.0, ProtectionMode::Moderate, 12.0);
            i.signals = vec![s];
            i.guard_level = guard;
            i.jobs = jobs(4);
            copy.step(&i)
        };
        let sig = |val: f64| ProtectedSignal::with_max("rule:a", "cpu_stall", Some(val), 0.1);
        let good = run(sig(v), GuardLevel::Clear);
        let bad = run(sig(worse), GuardLevel::Clear);
        let stale = run(
            ProtectedSignal {
                age_s: 30.0,
                ..sig(v)
            },
            GuardLevel::Clear,
        );
        let guarded = run(sig(v), GuardLevel::Soft);
        for o in [bad, stale, guarded] {
            assert!(o.budget_cores.unwrap_or(12.0) <= good.budget_cores.unwrap_or(12.0) + 1e-9);
            assert!(
                o.paused.len() + o.lowered.len() >= good.paused.len() + good.lowered.len()
                    || o.paused.len() >= good.paused.len()
            );
            assert!(!good.no_admit || o.no_admit);
        }
    }
}

#[test]
fn strict_yield_pauses_at_once_and_ramps_after_fifteen_idle_minutes() {
    let mut c = DynamicController::new();
    let mut i = DynInputs::new(0.0, ProtectionMode::StrictYield, 8.0);
    i.jobs = vec![job(1, true, false), job(2, false, false)];
    i.user_idle_s = 5.0; // someone is at the keyboard
    let o = c.step(&i);
    assert_eq!(
        (o.paused.clone(), o.lowered.clone(), o.no_admit),
        (set(&[1]), set(&[2]), true)
    );
    assert_eq!(o.no_admit_reason.as_deref(), Some("mode:strict_yield"));
    i.user_idle_s = 600.0;
    i.now = 2.0;
    assert!(c.step(&i).no_admit); // idle 10 min < 15
    i.user_idle_s = 901.0;
    i.now = 4.0;
    let o = c.step(&i);
    assert!(!o.no_admit && o.budget_cores == Some(1.0) && o.paused.is_empty());
    i.now = 4.0 + 120.0;
    assert_eq!(c.step(&i).budget_cores, Some(3.0)); // one slot per minute
}

#[test]
fn paused_jobs_are_evicted_after_ten_minutes() {
    let mut c = DynamicController::new();
    let mut i = DynInputs::new(0.0, ProtectionMode::FleetFirst, 8.0);
    i.jobs = vec![job(1, true, false)];
    i.pause_rules = vec![("calls".into(), ProtectionScope::All)];
    assert_eq!(c.step(&i).paused, set(&[1]));
    i.now = 599.0;
    assert!(c.step(&i).evict.is_empty());
    i.now = 601.0;
    let o = c.step(&i);
    assert_eq!(o.evict, [(1, "preempt_protection".to_string())]);
    assert!(o.paused.is_empty());
    assert_eq!(o.rung, 6);
}

#[test]
fn gpu_protection_holds_gpu_jobs_at_zero() {
    let mut c = DynamicController::new();
    let mut i = DynInputs::new(0.0, ProtectionMode::Moderate, 8.0);
    i.jobs = vec![job(1, true, true), job(2, true, false)];
    i.gpu_protected_active = true;
    let o = c.step(&i);
    assert_eq!(o.gpu_jobs_allowed, Some(0));
    assert!(o.paused.contains(&1) && !o.paused.contains(&2));
}

#[test]
fn unknown_signals_never_grow_but_guards_stay_intact() {
    let mut c = DynamicController::new();
    let mut t = 0.0;
    let mut max_budget: f64 = 0.0;
    while t < 3600.0 {
        let mut i = DynInputs::new(t, ProtectionMode::Moderate, 10.0);
        // the private source is gone
        i.signals = vec![ProtectedSignal::with_max(
            "rule:gpu",
            "gpu_share",
            None,
            0.2,
        )];
        i.jobs = vec![job(1, true, false)];
        i.protection_started = t == 0.0;
        i.guard_level = if t > 1800.0 {
            GuardLevel::Soft
        } else {
            GuardLevel::Clear
        };
        let o = c.step(&i);
        if t > 60.0 {
            max_budget = max_budget.max(o.budget_cores.unwrap_or(0.0));
        }
        if t > 1900.0 {
            assert!(o.budget_cores == Some(0.0) && o.no_admit); // the guard still takes everything back
        }
        t += 2.0;
    }
    assert!(max_budget <= 10.0);
}

/// Anti-flapping: a co-tenant oscillating around the target produces at most 12 lower/pause transitions per
/// hour (deadband, lockouts, one change per interval, 30 s clean before restoring).
#[test]
fn anti_flapping() {
    let mut c = DynamicController::new();
    let (mut transitions, mut last) = (0, false);
    let mut t: f64 = 0.0;
    while t < 4.0 * 3600.0 {
        let mut i = DynInputs::new(t, ProtectionMode::Moderate, 12.0);
        let v = 0.1 * (1.0 + 2.2 * (t / 7.0).sin()); // swings between -1.2x and 3.2x target
        i.signals = vec![ProtectedSignal::with_max(
            "rule:x",
            "cpu_stall",
            Some(v.max(0.0)),
            0.1,
        )];
        i.jobs = jobs(4);
        let o = c.step(&i);
        let now = !o.lowered.is_empty() || !o.paused.is_empty();
        if now != last {
            transitions += 1;
            last = now;
        }
        t += 2.0;
    }
    assert!(transitions as f64 / 4.0 <= 12.0);
}

#[test]
fn probes_measure_harm_and_set_the_baseline() {
    let mut c = DynamicController::new();
    let mut t = 0.0;
    let mut results = vec![];
    let mut probing_seen = false;
    while t < 1300.0 {
        let mut i = DynInputs::new(t, ProtectionMode::Moderate, 8.0);
        // running at 80, paused at 100: harm 0.2
        let probing = probing_seen;
        i.signals = vec![ProtectedSignal::with_slowdown(
            "rule:r",
            "progress_rate",
            Some(if probing { 100.0 } else { 80.0 }),
            0.5,
        )];
        i.jobs = jobs(2);
        i.probe_requested = t == 10.0;
        let o = c.step(&i);
        probing_seen = o.probing;
        results.extend(o.events.into_iter().filter(|e| e.kind == "probe_result"));
        t += 2.0;
    }
    assert!(!results.is_empty());
    assert!((results[0].signals["harm"] - 0.2).abs() < 1e-9);
    assert_eq!(results[0].rule, "rule:r");
    assert_eq!(c.harm()["rule:r"].len(), results.len().min(5));
}

// ---- which proxies may grow the budget, and the bandwidth-class rungs

/// Drive one source through a violation (the budget halves) and then a long clean stretch; return the final
/// budget and the events seen.
fn halve_then_clean(metric: &str, gpu_bound: bool, source: &str) -> (Option<f64>, Vec<String>) {
    let mut c = DynamicController::new();
    let mut reasons = vec![];
    let mut t = 0.0;
    while t < 1800.0 {
        let mut i = DynInputs::new(t, ProtectionMode::Moderate, 10.0);
        let value = if t < 120.0 { 0.3 } else { 0.01 };
        i.signals = vec![ProtectedSignal {
            gpu_bound,
            ..ProtectedSignal::with_max(source, metric, Some(value), 0.1)
        }];
        i.any_protected_active = true;
        i.protection_started = t == 0.0;
        i.jobs = jobs(2); // implicit sources count only the stall added while fleet work runs
        reasons.extend(c.step(&i).events.into_iter().map(|e| e.reason));
        t += 2.0;
    }
    (c.budget(), reasons)
}

#[test]
fn unvalidated_proxies_shrink_but_never_grow() {
    for (metric, gpu) in [
        ("cpu_stall", false),
        ("gpu_share", true),
        ("ipc_ratio", true),
        ("pageins_rate", false),
    ] {
        let (b, ev) = halve_then_clean(metric, gpu, "rule:a");
        assert!(b.unwrap_or(10.0) < 10.0, "{metric} shrank");
        assert!(!ev.iter().any(|e| e == "L1_GROW"), "{metric} must not grow");
        assert_eq!(
            ev.iter().filter(|e| *e == "L1_HOLD_UNVALIDATED").count(),
            1,
            "one hold event, not one per interval"
        );
    }
}

/// ipc_ratio may grow the budget, but not while it is unknown (a VM's guest has no instruction or cycle counters):
/// after a violation halves the budget, a stretch with no value never grows it back.
#[test]
fn an_unknown_ipc_ratio_never_grows_the_budget() {
    let mut c = DynamicController::new();
    let mut t = 0.0;
    while t < 1800.0 {
        let mut i = DynInputs::new(t, ProtectionMode::Moderate, 10.0);
        let value = (t < 120.0).then_some(0.3);
        i.signals = vec![ProtectedSignal::with_max("rule:a", "ipc_ratio", value, 0.1)];
        i.any_protected_active = true;
        i.protection_started = t == 0.0;
        i.jobs = jobs(2);
        let o = c.step(&i);
        assert!(
            !o.events.iter().any(|e| e.reason == "L1_GROW"),
            "grew at {t}"
        );
        t += 2.0;
    }
    assert!(c.budget().unwrap_or(10.0) < 10.0);
}

#[test]
fn validated_proxies_grow_back() {
    for (metric, gpu) in [
        ("progress_rate", true),
        ("progress_rate", false),
        ("ipc_ratio", false),
    ] {
        let (b, ev) = halve_then_clean(metric, gpu, "rule:a");
        assert!(
            ev.iter().any(|e| e == "L1_GROW") && b == Some(10.0),
            "{metric} gpu_bound={gpu} grows back to the ceiling"
        );
    }
}

#[test]
fn implicit_protections_only_veto_and_do_not_block_growth() {
    let (b, ev) = halve_then_clean("cpu_stall", false, "implicit:owner_stall");
    assert!(ev.iter().any(|e| e == "L1_GROW") && b == Some(10.0));
}

/// A fresh `moderate` agent on a busy VM: from boot the owner's own processes stall at about twice the 0.15
/// target (0.3 ± `noise`), whatever the fleet does, and each running one-core fleet job adds `harm`. The fleet
/// runs as many jobs as the last budget allows. Returns the mean number of jobs running over two hours and
/// the L1 events seen.
fn busy_vm(noise: f64, harm: f64) -> (f64, Vec<String>) {
    let mut rng = SeededRandom::new(9);
    let mut c = DynamicController::new();
    let (mut running, mut sum, mut ticks, mut reasons) = (0i64, 0.0, 0.0, vec![]);
    let mut t = 0.0;
    while t < 7200.0 {
        let mut i = DynInputs::new(t, ProtectionMode::Moderate, 8.0);
        let stall = 0.3 + rng.uniform(-noise, noise) + harm * running as f64;
        i.signals = vec![ProtectedSignal::with_max(
            "implicit:owner_stall",
            "cpu_stall",
            Some(stall.max(0.0)),
            0.15,
        )];
        i.jobs = jobs(running);
        let o = c.step(&i);
        reasons.extend(o.events.into_iter().map(|e| e.reason));
        running = o.budget_cores.unwrap_or(8.0) as i64;
        sum += running as f64;
        ticks += 1.0;
        t += 2.0;
    }
    (sum / ticks, reasons)
}

/// The demo node's case: the owner's own stall read twice the target from boot. It is not fleet harm (no fleet
/// job ran), so a fresh agent keeps its budget and takes work, however noisy the signal.
#[test]
fn owner_stall_without_fleet_work_never_pins_the_budget() {
    for noise in [0.0, 0.1, 0.25] {
        let (mean, reasons) = busy_vm(noise, 0.0);
        assert!(mean >= 7.5, "noise {noise}: {mean} of 8 jobs ran");
        assert!(
            !reasons.iter().any(|r| r == "L1_TAKE_BACK"),
            "noise {noise}: {reasons:?}"
        );
    }
}

/// Stall the fleet adds on top of the owner's own level is harm: the budget comes down to what keeps the added
/// stall under the target (0.03 a job: about 4 jobs) and further when each job harms more.
#[test]
fn sustained_owner_stall_from_fleet_work_still_lowers_the_budget() {
    let (mean, reasons) = busy_vm(0.1, 0.03);
    assert!((3.0..=5.0).contains(&mean), "{mean}");
    assert!(reasons.iter().any(|r| r == "L1_HALVE"));
    let (mean, _) = busy_vm(0.1, 0.1);
    assert!(mean <= 2.0, "{mean}");
}

#[test]
fn proxy_validation_table() {
    assert!(ProxyValidation::growth_eligible("progress_rate", true));
    assert!(ProxyValidation::growth_eligible("ipc_ratio", false));
    assert!(!ProxyValidation::growth_eligible("ipc_ratio", true));
    assert!(!ProxyValidation::growth_eligible("cpu_stall", false));
}

fn lowered(
    gpu_bound: bool,
    pressure: f64,
) -> (BTreeSet<i64>, std::collections::BTreeMap<i64, ThrottleDoc>) {
    let mut c = DynamicController::new();
    let mut o = DynOutputs::default();
    let mut docs = std::collections::BTreeMap::new(); // throttle documents are sent on change: keep the latest
    let js = vec![
        DynJob {
            cooperative: true,
            bandwidth: Some("low".into()),
            ..DynJob::new(1)
        },
        DynJob {
            cooperative: true,
            bandwidth: Some("medium".into()),
            ..DynJob::new(2)
        },
        DynJob {
            cooperative: true,
            bandwidth: Some("high".into()),
            ..DynJob::new(3)
        },
        DynJob {
            cooperative: true,
            ..DynJob::new(4)
        },
    ];
    for k in 0..4 {
        let mut i = DynInputs::new(f64::from(k) * 2.0, ProtectionMode::Moderate, 10.0);
        i.signals = vec![ProtectedSignal {
            gpu_bound,
            ..ProtectedSignal::with_max("rule:a", "progress_rate", Some(pressure * 0.1), 0.1)
        }];
        i.any_protected_active = true;
        i.protection_started = k == 0;
        i.jobs = js.clone();
        o = c.step(&i);
        docs.extend(o.throttle.clone());
    }
    (o.lowered, docs)
}

#[test]
fn gpu_bandwidth_harm_spares_low_jobs_and_lowers_high_jobs_first() {
    // an emergency (pressure 3 for two samples) lowers the fleet, except a low job
    assert_eq!(lowered(true, 3.0).0, set(&[2, 3, 4]));
    // a plain violation: only the high job is lowered (a thread cap does not help it), low gets no cap
    let (mild, docs) = lowered(true, 1.2);
    assert_eq!(mild, set(&[3]));
    assert_eq!(docs.get(&1).and_then(|d| d.threads), None);
    assert!(docs.get(&2).and_then(|d| d.threads).is_some());
}

#[test]
fn cpu_contention_harm_keeps_the_default_ladder_for_every_class() {
    // a CPU-bound protected group is hurt by cores, which low jobs use too
    assert_eq!(lowered(false, 3.0).0, set(&[1, 2, 3, 4]));
    assert!(lowered(false, 1.2).0.is_empty());
}

/// A job that nothing throttles is never nudged (no document, no SIGUSR1).
#[test]
fn a_job_nothing_throttles_is_never_nudged() {
    let mut c = DynamicController::new();
    for mode in [ProtectionMode::FleetFirst, ProtectionMode::Moderate] {
        for k in 0..30 {
            let mut i = DynInputs::new(f64::from(k) * 2.0, mode, 8.0);
            i.jobs = vec![
                DynJob {
                    cooperative: true,
                    ..DynJob::new(1)
                },
                DynJob {
                    pausable: true,
                    cooperative: true,
                    ..DynJob::new(2)
                },
            ];
            assert!(
                c.step(&i).throttle.is_empty(),
                "mode {mode}: no document or nudge without something to change"
            );
        }
    }
}

#[test]
fn throttle_documents_carry_a_sequence_and_the_pause_flag() {
    let mut c = DynamicController::new();
    let mut i = DynInputs::new(0.0, ProtectionMode::StrictYield, 8.0);
    i.user_idle_s = 1.0;
    i.jobs = vec![
        DynJob {
            pausable: true,
            cooperative: true,
            ..DynJob::new(1)
        },
        DynJob {
            cooperative: true,
            ..DynJob::new(2)
        },
    ];
    let o = c.step(&i);
    assert_eq!(
        o.throttle[&1],
        ThrottleDoc {
            threads: Some(1),
            pause: true,
            seq: 1
        }
    );
    assert_eq!(
        o.throttle[&2],
        ThrottleDoc {
            threads: Some(1),
            pause: false,
            seq: 2
        }
    );
    i.now = 2.0;
    assert!(c.step(&i).throttle.is_empty()); // unchanged: nothing sent
    i.now = 4.0;
    i.user_idle_s = 1e9;
    let o = c.step(&i);
    assert_eq!(
        o.throttle[&1],
        ThrottleDoc {
            threads: Some(1),
            pause: false,
            seq: 3
        }
    );
}

#[test]
fn rungs_and_reasons() {
    let mut c = DynamicController::new();
    let mut i = DynInputs::new(0.0, ProtectionMode::FleetFirst, 8.0);
    assert_eq!(c.step(&i).rung, 0);
    i.lower_rules = vec!["xcode".into()];
    i.jobs = vec![job(1, false, false)];
    assert_eq!(c.step(&i).rung, 3);
    let mut m = DynamicController::new();
    let mut i = DynInputs::new(0.0, ProtectionMode::Moderate, 8.0);
    i.signals = vec![ProtectedSignal::with_max(
        "rule:a",
        "cpu_stall",
        Some(0.01),
        0.1,
    )];
    let o = m.step(&i);
    assert_eq!(o.reason, "budget 8 cores");
    assert_eq!(o.rung, 0);
}

/// Where the OS cannot lower fleet jobs (Linux without a delegated cgroup), a job that would be lowered is paused
/// when it can be; one that cannot be paused stays in the lowered set, which the agent reports undelivered.
#[test]
fn without_lowering_a_pausable_job_is_paused_instead() {
    let mut c = DynamicController::new();
    let mut i = DynInputs::new(0.0, ProtectionMode::FleetFirst, 8.0);
    i.lower_rules = vec!["writing".into()];
    i.jobs = vec![job(1, true, false), job(2, false, false)];
    let o = c.step(&i);
    assert_eq!((o.paused.len(), o.lowered.len()), (0, 2));
    i.lowering = false;
    let o = c.step(&i);
    assert_eq!(o.paused.iter().copied().collect::<Vec<_>>(), [1]);
    assert_eq!(o.lowered.iter().copied().collect::<Vec<_>>(), [2]);
    assert_eq!(o.rung, 5);
}

// ---- signal formulas (SignalSourceTests)

#[test]
fn cpu_stall_is_the_waiting_share_of_runnable_time() {
    // runnable time includes time on a core: a thread that never waits has runnable == cpu
    let d = |cpu_s, runnable_s| ProcCounters {
        cpu_s,
        runnable_s,
        ..ProcCounters::default()
    };
    assert_eq!(
        GroupMetrics::from_delta(d(2.0, 2.0), 2.0).cpu_stall,
        Some(0.0)
    );
    assert_eq!(
        GroupMetrics::from_delta(d(1.0, 4.0), 2.0).cpu_stall,
        Some(0.75)
    );
    assert_eq!(
        GroupMetrics::from_delta(d(0.0, 0.0), 2.0).cpu_stall,
        Some(0.0)
    );
    let ipc = GroupMetrics::from_delta(
        ProcCounters {
            cpu_s: 1.0,
            instructions: 300.0,
            cycles: 100.0,
            pageins: 10.0,
            ..d(1.0, 1.0)
        },
        2.0,
    );
    assert_eq!(
        (ipc.ipc, ipc.pageins_rate, ipc.cpu_cores),
        (Some(3.0), Some(5.0), 0.5)
    );
    assert_eq!(
        GroupMetrics::from_delta(
            ProcCounters {
                cycles: 100.0,
                ..d(0.1, 0.1)
            },
            2.0
        )
        .ipc,
        None
    ); // below 0.25 cores
    assert_eq!(
        GroupMetrics::from_delta(d(1.0, 1.0), 0.0),
        GroupMetrics::default()
    );
    assert_eq!(
        GroupMetrics {
            gpu_share: Some(0.3),
            ..Default::default()
        }
        .value("gpu_share"),
        Some(0.3)
    );
    assert_eq!(GroupMetrics::default().value("nonsense"), None);
    // a VM exposes no performance counters: rusage's instructions and cycles stay 0 while the group runs, which is
    // no IPC of zero but none at all; a group that barely ran tells nothing either way
    let no_pmu = GroupMetrics::from_delta(d(1.0, 1.2), 2.0);
    assert_eq!(
        (no_pmu.ipc, no_pmu.instruction_counters),
        (None, Some(false))
    );
    assert_eq!(no_pmu.value("ipc_ratio"), None);
    assert!(
        no_pmu
            .cpu_stall
            .is_some_and(|x| (x - 0.2 / 1.2).abs() < 1e-12),
        "the stall needs no PMU"
    );
    assert_eq!(ipc.instruction_counters, Some(true));
    assert_eq!(
        GroupMetrics::from_delta(d(0.01, 0.01), 2.0).instruction_counters,
        None
    );
    // a delta never goes negative
    assert_eq!((d(1.0, 1.0) - d(2.0, 2.0)).cpu_s, 0.0);
}

#[test]
fn frontmost_lookup_parses_both_lsappinfo_formats() {
    assert_eq!(
        frontmost::serial_number("ASN:0x0-0x13e0bdf8:\n").as_deref(),
        Some("ASN:0x0-0x13e0bdf8:")
    );
    assert_eq!(frontmost::serial_number("[ NULL ]  [ NULL ]"), None);
    assert_eq!(frontmost::parse_pid("\"pid\"=86096\n"), Some(86096)); // macOS 26.5: -only pid
                                                                      // macOS 27 ignores -only and prints the full record (captured from an M5 Max on 27.0)
    let record = "\"GPU App\" ASN:0x0-0x8b08b: (in front)\n    bundleID=[ NULL ]\n    pid = 36536 !cgsConnection \
                  !signalled type=[ NULL ]  flavor=[ NULL ]  Version=[ NULL ]  Arch=!!none\n";
    assert_eq!(frontmost::parse_pid(record), Some(36536));
    // macOS 27.0.1 honours -only again but pads it with the record's empty fields
    let only = "[ NULL ]  [ NULL ]  \n    bundleID=[ NULL ] \n    bundle path=[ NULL ] \n    executable path=[ NULL ] \n    \
                pid = 2639 !cgsConnection !signalled type=[ NULL ]  flavor=[ NULL ]  Version=[ NULL ]  Arch=!!none \n\n";
    assert_eq!(frontmost::parse_pid(only), Some(2639));
    assert_eq!(frontmost::parse_pid(""), None);
    assert_eq!(frontmost::parse_pid("pid = 0"), None);
}
