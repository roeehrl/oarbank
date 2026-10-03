//! Soaks in virtual time, with a nemesis and with the dynamic controller: the real
//! controller, spawn registry and capacity engine against a fake OS. Checked every tick: S16 (every delivered
//! signal targets a registered (pid, start)), S17 (no admission under a memory floor; admitted memory plus
//! reservations within the host), S19 (never a budget above allocatable) and the anti-flapping bound.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use common::{no_cpu, FakeActuator, SeededRandom};
use oarbank_protection::*;
use serde_json::json;

struct Job {
    pid: i32,
    start: u64,
    mem: f64,
    fp: f64,
    t0: f64,
}

fn pick<V>(rng: &mut SeededRandom, m: &BTreeMap<i64, V>) -> Option<i64> {
    if m.is_empty() {
        return None;
    }
    m.keys()
        .nth(rng.int(0, m.len() as i64 - 1) as usize)
        .copied()
}

/// 24 hours (2 s ticks): a co-tenant that balloons memory, a protected process that comes and goes and flaps
/// around its threshold, PID recycling between decisions and actuations, stale memory signals and pressure
/// spikes.
#[test]
fn twenty_four_hours_of_faults() {
    let f = FakeActuator::new();
    let journal = Arc::new(DecisionJournal::in_memory());
    let reg = f.registry(Some(journal.clone()));
    let mut ctl = ProtectionController::new(Some(journal.clone()), Host::unavailable());
    ctl.apply(
        Some(&json!({"schema": 1, "node": {"mode": "fleet_first"},
            "rule": [{"id": "gpu-app", "match": {"path_contains": "Engine/bin"}, "tree": "descendants",
                      "active_when": "present", "reserve": {"mem_gb": "peak(300s).footprint + 2"}},
                     {"id": "calls", "match": {"bundle_id": ["us.zoom.xos"]}, "active_when": "present",
                      "cap_fleet": {"slots": 0}, "exit_after_s": 120}]})),
        &LocalProtection::Absent,
    );
    let mut rng = SeededRandom::new(20261001);
    let ram = 64.0;
    let mut jobs: BTreeMap<i64, Job> = BTreeMap::new();
    let (mut next_attempt, mut next_pid) = (1i64, 20000i32);
    let (mut app_on, mut app_fp, mut zoom, mut hog) = (true, 3.5, false, 0.0);
    let mut registered: HashSet<String> = HashSet::new();
    let (mut s17, mut evictions, mut last_call_active, mut call_flips) = (0, 0, false, 0);
    let policy = Policy::from_json(Some(&json!({"os_reserve_gb": 6})), &Policy::default());
    let mut t = 0.0;
    while t < 86400.0 {
        // nemesis
        if rng.chance(0.002) {
            app_on = !app_on;
        }
        app_fp = (app_fp + rng.uniform(-0.2, 0.2)).clamp(0.5, 9.0);
        if rng.chance(0.0005) {
            zoom = !zoom;
        }
        if rng.chance(0.001) {
            hog = rng.uniform(10.0, 40.0); // a co-tenant balloons
        }
        hog = (hog - rng.uniform(0.0, 0.5)).max(0.0);
        let stale = if rng.chance(0.01) {
            rng.uniform(7.0, 30.0)
        } else {
            0.0
        };
        let pressure = if rng.chance(0.005) {
            if rng.boolean() {
                1
            } else {
                3
            }
        } else {
            0
        };
        // PID recycling: a job's leader exits and its PID is reused by an owner process before we act
        if let Some(aid) = pick(&mut rng, &jobs) {
            if rng.chance(0.01) {
                let j = jobs.remove(&aid).unwrap();
                f.set_start(j.pid, Some(j.start + 7));
            }
        }
        // the node
        let mut procs = vec![];
        if app_on {
            procs.push(ProcessRecord {
                footprint_gb: app_fp,
                ..ProcessRecord::new(900, 1, 1, "/A/Engine/bin/w")
            });
        }
        if zoom {
            procs.push(ProcessRecord {
                bundle_id: Some("us.zoom.xos".into()),
                footprint_gb: 1.0,
                ..ProcessRecord::new(
                    901,
                    1,
                    2,
                    "/Applications/zoom.us.app/Contents/MacOS/zoom.us",
                )
            });
        }
        if hog > 0.0 {
            procs.push(ProcessRecord {
                footprint_gb: hog,
                ..ProcessRecord::new(902, 1, 3, "/Users/o/hog")
            });
        }
        let fleet_mem: f64 = jobs.values().map(|j| j.fp).sum();
        let used = 12.0 + if app_on { app_fp } else { 0.0 } + hog + fleet_mem;
        let views: Vec<FleetJobView> = jobs
            .iter()
            .map(|(id, j)| FleetJobView::new(*id, Some(j.pid), j.fp, j.t0, j.mem))
            .collect();
        let mut inputs = TickInputs::new(
            t,
            MemorySignals::new(ram, used.min(ram), pressure).with_age(stale),
        );
        inputs.jobs = views;
        let r = ctl.evaluate(&inputs, &procs, &no_cpu());
        for e in &r.evictions {
            let Some(j) = jobs.remove(&e.attempt_id) else {
                continue;
            };
            let before = f.delivered().len();
            let _ = reg.signal(j.pid, Signal::Kill, &e.reason);
            if f.delivered().len() > before {
                evictions += 1;
            }
            reg.unregister(j.pid);
        }
        let call_active = r
            .reports
            .iter()
            .find(|x| x.id == "calls")
            .is_some_and(|x| x.active);
        if call_active != last_call_active {
            call_flips += 1;
            last_call_active = call_active;
        }
        // capacity and admission
        let mut ci = CapacityInputs::new(ram, 12, 4, policy.clone(), Limits::uncapped());
        ci.constraint = r.constraint.clone();
        ci.live_attempts = jobs.len() as i64;
        ci.used_cpu = jobs.len() as f64;
        ci.used_mem_gb = jobs.values().map(|j| j.mem).sum();
        let cap = CapacityModel::compute(&ci);
        if r.guard_level != GuardLevel::Clear && cap.admit {
            s17 += 1;
        }
        if cap.admit && cap.mem_gb_free >= 1.5 && cap.free_cpu >= 1.0 && rng.chance(0.2) {
            let pid = next_pid;
            next_pid += 1;
            let start = (t * 1e6) as u64 + 11;
            f.set_start(pid, Some(start));
            reg.register(pid, Some(next_attempt), None);
            registered.insert(format!("{pid}@{start}"));
            jobs.insert(
                next_attempt,
                Job {
                    pid,
                    start,
                    mem: 1.5,
                    fp: rng.uniform(0.5, 2.2),
                    t0: t,
                },
            );
            next_attempt += 1;
            // S17 at admission: declared memory plus reservations stays within the host budget
            if ci.used_mem_gb + 1.5 + r.constraint.reserved_mem_gb + 6.0 > ram + 1e-9 {
                s17 += 1;
            }
        }
        if let Some(aid) = pick(&mut rng, &jobs) {
            if rng.chance(0.02) {
                // jobs finish
                let j = jobs.remove(&aid).unwrap();
                reg.unregister(j.pid);
            }
        }
        t += 2.0;
    }
    // S16: every delivered signal went to a registered (pid, start) of that moment
    let mut s16 = f
        .delivered()
        .iter()
        .filter(|d| {
            !registered
                .iter()
                .any(|k| k.starts_with(&format!("{}@", d.0)))
        })
        .count();
    s16 += DecisionJournal::s16_violations(&journal.recent_records(), &registered).len();
    assert_eq!(s16, 0);
    assert_eq!(s17, 0);
    assert!(evictions > 0, "the hog did force evictions");
    assert!(
        call_flips as f64 / 24.0 <= 12.0,
        "anti-flapping bound: <= 12 transitions per hour"
    );
}

/// 72 h: moderate mode, a protected reporter, co-tenant storms and flapping, the memory guard, PID recycling.
#[test]
fn seventy_two_hours_of_dynamic_protection() {
    let f = FakeActuator::new();
    let journal = Arc::new(DecisionJournal::in_memory());
    let reg = f.registry(Some(journal));
    let mut c = DynamicController::new();
    let mut g = MemoryGuard::new();
    let mut rng = SeededRandom::new(72);
    let (free, per_core) = (6.0, 0.01);
    let rate = |p: f64, e: f64| 100.0 * (1.0 - ((p + e / 3.0) - free).max(0.0) * per_core);
    let mut jobs: BTreeMap<i64, (i32, u64)> = BTreeMap::new();
    let mut paused: BTreeSet<i64> = BTreeSet::new();
    let (mut next_id, mut next_pid) = (1i64, 30000i32);
    let (mut s17, mut s19, mut transitions, mut last_low) = (0, 0, 0, false);
    let mut storm: f64 = 0.0;
    let mut last: Option<DynOutputs> = None;
    let mut t = 0.0;
    while t < 72.0 * 3600.0 {
        if rng.chance(0.001) {
            storm = rng.uniform(5.0, 30.0);
        }
        storm = (storm - 0.05).max(0.0);
        let budget = last.as_ref().and_then(|o| o.budget_cores).unwrap_or(12.0);
        let low = last.as_ref().is_some_and(|o| !o.lowered.is_empty());
        let r = if low {
            rate(0.0, budget)
        } else {
            rate(budget, 0.0)
        };
        let mem = MemorySignals::new(
            64.0,
            (30.0 + storm + jobs.len() as f64).min(64.0),
            if storm > 28.0 { 3 } else { 0 },
        );
        let gl = g.update(&mem, &MemoryFloors::default(), t).0;
        let mut i = DynInputs::new(t, ProtectionMode::Moderate, 12.0);
        i.signals = vec![
            ProtectedSignal::with_slowdown(
                "rule:r",
                "progress_rate",
                Some(r * rng.uniform(0.97, 1.03)),
                0.05,
            ),
            ProtectedSignal::with_max(
                "implicit:owner_stall",
                "cpu_stall",
                Some(if storm > 20.0 { 0.3 } else { 0.05 }),
                0.15,
            ),
        ];
        i.guard_level = gl;
        i.jobs = jobs
            .keys()
            .map(|id| DynJob {
                pausable: true,
                ..DynJob::new(*id)
            })
            .collect();
        i.protection_started = t == 0.0;
        let o = c.step(&i);
        if o.budget_cores.unwrap_or(0.0) > 12.0 + 1e-9 {
            s19 += 1;
        }
        // actuation through the registry only
        for id in o.paused.difference(&paused) {
            if let Some(j) = jobs.get(id) {
                let _ = reg.signal(j.0, Signal::Stop, "pause");
            }
        }
        for id in paused.difference(&o.paused) {
            if let Some(j) = jobs.get(id) {
                let _ = reg.signal(j.0, Signal::Cont, "resume");
            }
        }
        paused = o
            .paused
            .iter()
            .filter(|id| jobs.contains_key(id))
            .copied()
            .collect();
        for (id, reason) in &o.evict {
            if let Some(j) = jobs.remove(id) {
                let _ = reg.signal(j.0, Signal::Kill, reason);
                reg.unregister(j.0);
            }
        }
        let low_now = !o.lowered.is_empty() || !o.paused.is_empty();
        if low_now != last_low {
            transitions += 1;
            last_low = low_now;
        }
        // admission (the guard vector blocks it independently of the controller)
        let admit = gl == GuardLevel::Clear && !o.no_admit;
        if gl != GuardLevel::Clear && admit {
            s17 += 1;
        }
        if admit && (jobs.len() as f64) < o.budget_cores.unwrap_or(12.0) && rng.chance(0.3) {
            let pid = next_pid;
            next_pid += 1;
            let start = (t * 1e6) as u64 + 3;
            f.set_start(pid, Some(start));
            reg.register(pid, Some(next_id), None);
            jobs.insert(next_id, (pid, start));
            next_id += 1;
        }
        if let Some(id) = pick(&mut rng, &jobs) {
            if rng.chance(0.01) {
                let j = jobs.remove(&id).unwrap();
                if rng.chance(0.3) {
                    f.set_start(j.0, Some(j.1 + 9)); // exited; PID recycled into an owner process
                }
                reg.unregister(j.0);
                paused.remove(&id);
            }
        }
        last = Some(o);
        t += 2.0;
    }
    let s16 = f.delivered().iter().filter(|d| d.0 < 30000).count();
    assert_eq!((s16, s17, s19), (0, 0, 0));
    assert!(
        transitions as f64 / 72.0 <= 12.0,
        "{transitions} transitions in 72 h"
    );
}
