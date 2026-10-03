//! The capacity engine with host protection: the formula, reservations from protection rules, hard-cap
//! enforcement and the schedule window.

mod common;

use std::collections::BTreeMap;

use common::SeededRandom;
use oarbank_protection::*;
use serde_json::json;

fn pools(p: &[(&str, i64)]) -> BTreeMap<String, i64> {
    p.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

/// A 64 GB host, 12 P + 4 E, os_reserve 6 GB.
fn host_64gb(f: impl FnOnce(&mut CapacityInputs)) -> CapacityResult {
    let policy = Policy::from_json(Some(&json!({"os_reserve_gb": 6})), &Policy::default());
    let mut i = CapacityInputs::new(64.0, 12, 4, policy, Limits::uncapped());
    f(&mut i);
    CapacityModel::compute(&i)
}

/// A 24 GB host, 5 P + 10 E, with a VM service holding 8 GB and offering two pool tokens.
fn host_24gb(limits: Limits, f: impl FnOnce(&mut CapacityInputs)) -> CapacityResult {
    let mut i = CapacityInputs::new(24.0, 5, 10, Policy::default(), limits);
    i.service_reserved_mem_gb = 8.0;
    i.service_pools = pools(&[("docker_amd64", 2)]);
    f(&mut i);
    CapacityModel::compute(&i)
}

fn constraint(vs: &[ConstraintVector]) -> CombinedConstraint {
    CombinedConstraint::combine(vs)
}

#[test]
fn formula_and_reservations() {
    let c = host_64gb(|_| {});
    assert_eq!((c.cpu_slots, c.host_budget_gb, c.admit), (14, 58.0, true));
    assert_eq!(c.binding_limit, "auto");
    let mut cons = CombinedConstraint {
        reserved_mem_gb: 10.0,
        ..Default::default()
    };
    cons.binding
        .insert("reserve_mem".into(), "rule:gpu-app".into());
    let r = host_64gb(|i| {
        i.constraint = cons;
        i.service_reserved_mem_gb = 12.0;
        i.service_pools = pools(&[("vm", 4)]);
    });
    assert_eq!(r.host_budget_gb, 36.0);
    assert_eq!(r.pools, pools(&[("vm", 4)]));
    assert_eq!(r.reserved_mem_gb, 10.0);
}

#[test]
fn protection_brakes_and_pool_jobs_only() {
    let mut no_admit = CombinedConstraint {
        no_admit: true,
        ..Default::default()
    };
    no_admit
        .binding
        .insert("admit".into(), "guard:memory".into());
    let a = host_64gb(|i| i.constraint = no_admit);
    assert!(!a.admit);
    assert_eq!(a.not_admitting_because.as_deref(), Some("guard:memory"));
    let mut pj = CombinedConstraint {
        pool_jobs_only: Some(pools(&[("vm", 1)])),
        ..Default::default()
    };
    pj.binding
        .insert("pool_jobs_only".into(), "rule:app".into());
    let p = host_64gb(|i| {
        i.constraint = pj;
        i.service_pools = pools(&[("vm", 4), ("gpu", 1)]);
    });
    assert!(!p.admit && p.pool_jobs_only);
    assert_eq!(p.pools, pools(&[("vm", 1), ("gpu", 0)]));
    let mut cap = CombinedConstraint {
        cpu_cores: Some(4.0),
        ..Default::default()
    };
    cap.binding.insert("cpu_cores".into(), "rule:xcode".into());
    let c = host_64gb(|i| i.constraint = cap);
    assert_eq!(c.cpu_slots, 4);
    assert_eq!(c.binding_limit, "rule:xcode");
}

/// S17 and S19 as properties of the pure engine over random inputs: memory accounting never exceeds the
/// host, no admission under a brake, and a worse signal never yields a larger allowance.
#[test]
fn s17_and_s19_properties() {
    let mut rng = SeededRandom::new(1719);
    for _ in 0..2000 {
        let ram = rng.int(16, 128) as f64;
        let policy = Policy::from_json(
            Some(&json!({"os_reserve_gb": rng.uniform(2.0, 8.0)})),
            &Policy::default(),
        );
        let mut i = CapacityInputs::new(
            ram,
            rng.int(4, 16),
            rng.int(0, 12),
            policy,
            Limits::uncapped(),
        );
        i.constraint.reserved_mem_gb = rng.uniform(0.0, 20.0);
        i.constraint.reserved_cpu = rng.uniform(0.0, 4.0);
        i.service_reserved_mem_gb = [0.0, 8.0, 12.0][rng.int(0, 2) as usize];
        i.used_mem_gb = rng.uniform(0.0, 20.0);
        i.user_present = rng.boolean();
        i.thermal = rng.int(0, 3) as i32;
        let c = CapacityModel::compute(&i);
        // S17: what is admitted plus what is reserved never exceeds the host
        assert!(c.mem_gb_free + i.used_mem_gb <= c.host_budget_gb.max(i.used_mem_gb) + 1e-9);
        assert!(
            c.host_budget_gb.max(0.0)
                + i.policy.os_reserve_gb
                + i.service_reserved_mem_gb
                + i.constraint.reserved_mem_gb
                <= ram + 1e-9
                || c.host_budget_gb < 0.0
        );
        // no admission under a brake
        let mut braked = i.clone();
        braked.constraint.no_admit = true;
        assert!(!CapacityModel::compute(&braked).admit);
        // S19: more reserved memory or CPU, or a hotter machine, never enlarges the allowance
        let mut worse = i.clone();
        worse.constraint.reserved_mem_gb += rng.uniform(0.0, 8.0);
        worse.constraint.reserved_cpu += rng.uniform(0.0, 4.0);
        worse.thermal = (i.thermal + rng.int(0, 1) as i32).min(3);
        let w = CapacityModel::compute(&worse);
        assert!(
            w.cpu_slots <= c.cpu_slots
                && w.mem_gb_free <= c.mem_gb_free + 1e-9
                && w.slots <= c.slots
        );
        assert!(!w.admit || c.admit);
    }
}

// ---- the formula on the 24 GB host

#[test]
fn uncapped_24gb_host() {
    // host_budget = 24 − 4 (os) − 8 (VM service) = 12 → floor(12 / 1.5) = 8; cpu = 5 + 10/2 = 10
    let c = host_24gb(Limits::uncapped(), |_| {});
    assert_eq!(c.host_budget_gb, 12.0);
    assert_eq!((c.mem_slots, c.auto_slots, c.slots), (8, 8, 8));
    assert_eq!((c.cpu_slots, c.auto_cpu_slots), (10, 10));
    assert_eq!(c.mem_gb_free, 12.0);
    assert_eq!(c.pools["docker_amd64"], 2);
    assert_eq!(c.binding_limit, "auto");
    assert!(c.admit);
    assert_eq!(c.free_cpu, 10.0);
}

#[test]
fn null_limits_mean_uncapped() {
    let j = json!({"cpu_cores": null, "mem_gb": null, "jobs": null, "vm_mem_gb": null, "vm_cpus": null, "disk_gb": null,
                   "staging_mbps": null, "schedule": null, "enforce": "soft"});
    let l = Limits::from_json(Some(&j));
    assert_eq!(l, Limits::uncapped());
    assert_eq!(host_24gb(l, |_| {}), host_24gb(Limits::uncapped(), |_| {}));
    assert_eq!(Limits::from_json(Some(&json!({}))), Limits::uncapped());
    assert_eq!(Limits::from_json(None), Limits::uncapped());
}

#[test]
fn limits_parse_and_round_trip() {
    let j = json!({"cpu_cores": 4.5, "mem_gb": 12, "jobs": 3.7, "vm_cpus": 4.2, "enforce": "hard",
                   "schedule": {"days": [4, 9], "start": "22:00", "end": "07:30"}});
    let l = Limits::from_json(Some(&j));
    assert_eq!(
        (l.cpu_cores, l.mem_gb, l.jobs, l.vm_cpus),
        (Some(4.5), Some(12.0), Some(3), Some(4))
    );
    assert_eq!(l.enforce, Enforce::Hard);
    assert_eq!(
        l.schedule,
        Some(Schedule::new(Some(&[4]), 22 * 60, 7 * 60 + 30))
    );
    let back = l.to_json();
    assert_eq!(
        back["schedule"],
        json!({"days": [4], "start": "22:00", "end": "07:30"})
    );
    assert_eq!(back["enforce"], json!("hard"));
    assert_eq!(back["vm_mem_gb"], json!(null));
    // an invalid schedule inside limits is ignored (uncapped), not fatal
    assert_eq!(
        Limits::from_json(Some(&json!({"schedule": {"start": "bad"}}))).schedule,
        None
    );
}

#[test]
fn policy_parses_capacity_keys() {
    let p = Policy::from_json(
        Some(
            &json!({"os_reserve_gb": 6, "max_slots": 3.9, "threads_per_job": 0, "job_mem_gb": -1, "user_present_slots": -2,
                     "nice": 40, "run_on_battery": true, "protection": {"schema": 1}}),
        ),
        &Policy::default(),
    );
    assert_eq!(p.os_reserve_gb, 6.0);
    assert_eq!(p.max_slots, Some(3));
    assert_eq!(p.threads_per_job, 1);
    assert_eq!(p.job_mem_gb, 1.5);
    assert_eq!(p.user_present_slots, 0);
    assert_eq!(p.nice, 20);
    assert!(p.run_on_battery);
    assert_eq!(p.protection, Some(json!({"schema": 1})));
    let q = Policy::from_json(Some(&json!({"max_slots": null})), &p);
    assert_eq!(q.max_slots, None);
}

#[test]
fn cap_is_min_of_auto_and_cap() {
    // a cap above the automatic value changes nothing
    let loose = host_24gb(
        Limits {
            cpu_cores: Some(64.0),
            mem_gb: Some(200.0),
            jobs: Some(100),
            ..Limits::default()
        },
        |_| {},
    );
    assert_eq!((loose.slots, loose.cpu_slots), (8, 10));
    assert_eq!(loose.binding_limit, "auto");
    // cap.jobs below auto binds the slots
    let jobs = host_24gb(
        Limits {
            jobs: Some(3),
            ..Limits::default()
        },
        |_| {},
    );
    assert_eq!((jobs.auto_slots, jobs.slots), (8, 3));
    assert_eq!(jobs.binding_limit, "cap.jobs");
}

#[test]
fn cpu_cores_cap() {
    // cpu_slots = min(auto_cpu_slots, floor(cap.cpu_cores)); job slots divide by threads_per_job
    let c = host_24gb(
        Limits {
            cpu_cores: Some(4.5),
            ..Limits::default()
        },
        |_| {},
    );
    assert_eq!((c.auto_cpu_slots, c.cpu_slots, c.slots), (10, 4, 4));
    assert_eq!(c.binding_limit, "cap.cpu_cores");
    let t = host_24gb(
        Limits {
            cpu_cores: Some(4.5),
            ..Limits::default()
        },
        |i| i.policy.threads_per_job = 2,
    );
    assert_eq!((t.slots, t.cpu_slots), (2, 4));
}

#[test]
fn mem_cap() {
    // host_budget = min(12, 12 − 8) = 4 → floor(4 / 1.5) = 2
    let c = host_24gb(
        Limits {
            mem_gb: Some(12.0),
            ..Limits::default()
        },
        |_| {},
    );
    assert_eq!(c.host_budget_gb, 4.0);
    assert_eq!((c.slots, c.mem_gb_free), (2, 4.0));
    assert_eq!(c.binding_limit, "cap.mem_gb");
    assert_eq!(c.cpu_slots, 10); // memory does not reduce CPUs
                                 // without the VM service its share is not subtracted from the cap
    let no_vm = host_24gb(
        Limits {
            mem_gb: Some(12.0),
            ..Limits::default()
        },
        |i| {
            i.service_reserved_mem_gb = 0.0;
            i.service_pools = BTreeMap::new();
        },
    );
    assert_eq!(no_vm.host_budget_gb, 12.0); // min(24 − 4 = 20, 12)
    assert!(no_vm.pools.is_empty());
}

#[test]
fn mem_gb_free_subtracts_running_job_resources() {
    let used = |i: &mut CapacityInputs, live, cpu, mem| {
        i.live_attempts = live;
        i.used_cpu = cpu;
        i.used_mem_gb = mem;
    };
    let c = host_24gb(Limits::uncapped(), |i| used(i, 2, 2.0, 3.0));
    assert_eq!((c.mem_gb_free, c.free_cpu, c.free_slots), (9.0, 8.0, 6));
    // with a mem cap the free memory comes off the capped budget; never negative
    let capped = host_24gb(
        Limits {
            mem_gb: Some(12.0),
            ..Limits::default()
        },
        |i| used(i, 2, 2.0, 3.0),
    );
    assert_eq!(capped.mem_gb_free, 1.0);
    let over = host_24gb(
        Limits {
            mem_gb: Some(12.0),
            ..Limits::default()
        },
        |i| used(i, 4, 4.0, 6.0),
    );
    assert_eq!(over.mem_gb_free, 0.0);
}

#[test]
fn jobs_cap_zeroes_free_cpu_when_reached() {
    let set = |i: &mut CapacityInputs| {
        i.live_attempts = 2;
        i.used_cpu = 2.0;
        i.used_mem_gb = 3.0;
    };
    assert_eq!(
        host_24gb(
            Limits {
                jobs: Some(2),
                ..Limits::default()
            },
            set
        )
        .free_cpu,
        0.0
    );
    assert_eq!(
        host_24gb(
            Limits {
                jobs: Some(3),
                ..Limits::default()
            },
            set
        )
        .free_cpu,
        8.0
    );
}

#[test]
fn thermal() {
    // a big box so CPU binds, not memory: 128 GB, 12 P + 4 E → 14 cpu slots
    let big = |thermal: i32| {
        let mut i = CapacityInputs::new(128.0, 12, 4, Policy::default(), Limits::uncapped());
        i.thermal = thermal;
        // the thermal gate's vector reaches capacity through the combined constraint
        i.constraint = constraint(&SystemGates::vectors(thermal, false, false));
        CapacityModel::compute(&i)
    };
    assert_eq!(big(Thermal::NOMINAL).auto_cpu_slots, 14);
    let fair = big(Thermal::FAIR);
    assert_eq!((fair.auto_cpu_slots, fair.cpu_slots), (10, 10)); // floor(14 × 0.75)
    assert_eq!(fair.binding_limit, "thermal");
    assert!(fair.admit);
    let serious = big(Thermal::SERIOUS);
    assert_eq!((serious.cpu_slots, serious.slots), (0, 0));
    assert!(!serious.admit);
    assert_eq!(serious.binding_limit, "guard:thermal");
}

#[test]
fn user_presence() {
    // user_present_slots (2) and the user reserve (8 GB) apply: budget 24 − 4 − 8 − 8 = 4
    let c = host_24gb(Limits::uncapped(), |i| i.user_present = true);
    assert_eq!(c.cpu_slots, 2);
    assert_eq!(c.host_budget_gb, 4.0);
    assert_eq!(c.slots, 2);
}

#[test]
fn reserved_memory_of_a_protected_process() {
    // a protected process's peak footprint plus headroom, 1.7 + 2: budget 24 − 4 − 8 − 3.7 = 8.3
    let c = host_24gb(Limits::uncapped(), |i| {
        i.constraint.reserved_mem_gb = 3.7;
        i.constraint
            .binding
            .insert("reserve_mem".into(), "rule:gpu-app".into());
    });
    assert!((c.host_budget_gb - 8.3).abs() < 1e-9);
    assert_eq!(c.slots, 5);
    assert_eq!(c.binding_limit, "rule:gpu-app");
}

#[test]
fn negative_budget_gives_zero() {
    let c = host_24gb(Limits::uncapped(), |i| i.constraint.reserved_mem_gb = 22.0);
    assert_eq!((c.slots, c.mem_gb_free), (0, 0.0));
}

#[test]
fn max_slots() {
    let c = host_24gb(Limits::uncapped(), |i| i.policy.max_slots = Some(3));
    assert_eq!((c.auto_slots, c.auto_cpu_slots), (3, 3));
}

#[test]
fn a_hold_rule_zeroes_cpu_and_blocks_admission() {
    // a hold is a rule with cap_fleet.slots = 0
    let mut v = ConstraintVector::new("rule:app");
    v.slots = Some(0);
    let c = host_24gb(Limits::uncapped(), |i| i.constraint = constraint(&[v]));
    assert_eq!((c.cpu_slots, c.auto_cpu_slots), (0, 10));
    assert!(!c.admit);
    assert_eq!(c.binding_limit, "rule:app");
}

#[test]
fn admission_rules() {
    let desired = |s: &str| host_24gb(Limits::uncapped(), |i| i.desired_state = s.into());
    assert!(!desired("paused").admit);
    assert_eq!(desired("paused").binding_limit, "user");
    assert_eq!(
        desired("paused").not_admitting_because.as_deref(),
        Some("desired_state=paused")
    );
    assert!(!desired("draining").admit);
    let mut g = MemoryGuard::new();
    for (pressure, used) in [(MemPressure::WARNING, 10.0), (MemPressure::CRITICAL, 10.0)] {
        let (lvl, _) = g.update(
            &MemorySignals::new(24.0, used, pressure),
            &MemoryFloors::default(),
            0.0,
        );
        assert!(lvl >= GuardLevel::Soft);
        let c = host_24gb(Limits::uncapped(), |i| {
            i.constraint = constraint(&[ConstraintVector::no_admit("guard:memory")])
        });
        assert!(!c.admit);
        assert_eq!(c.binding_limit, "guard:memory");
    }
    let battery = host_24gb(Limits::uncapped(), |i| {
        i.constraint = constraint(&SystemGates::vectors(0, true, false))
    });
    assert!(!battery.admit);
    assert_eq!(battery.binding_limit, "guard:battery");
    assert!(
        host_24gb(Limits::uncapped(), |i| i.constraint =
            constraint(&SystemGates::vectors(0, true, true)))
        .admit
    );
    let out = host_24gb(Limits::uncapped(), |i| i.in_schedule = false);
    assert!(!out.admit);
    assert_eq!(out.binding_limit, "user");
    let paused = host_24gb(Limits::uncapped(), |i| i.local_pause = true);
    assert_eq!(
        (paused.admit, paused.not_admitting_because.as_deref()),
        (false, Some("local_pause"))
    );
}

#[test]
fn soft_mem_cap_stops_admitting_when_exceeded() {
    // fleet RSS 5 + VM 8 > cap 12
    let c = host_24gb(
        Limits {
            mem_gb: Some(12.0),
            ..Limits::default()
        },
        |i| i.fleet_rss_gb = 5.0,
    );
    assert!(!c.admit);
    assert_eq!(c.binding_limit, "cap.mem_gb");
    assert!(
        host_24gb(
            Limits {
                mem_gb: Some(12.0),
                ..Limits::default()
            },
            |i| i.fleet_rss_gb = 3.5
        )
        .admit
    );
}

#[test]
fn wire_json_carries_the_capacity_fields() {
    let j = host_24gb(Limits::uncapped(), |_| {}).to_json();
    for k in [
        "cpu_slots",
        "mem_gb_free",
        "pools",
        "auto_cpu_slots",
        "binding_limit",
        "admit",
        "auto_slots",
        "slots",
        "pool_jobs_only",
        "reserved_cpu",
        "reserved_mem_gb",
        "why",
        "gpu_jobs",
    ] {
        assert!(j.get(k).is_some(), "missing {k}");
    }
    assert_eq!(j["pools"]["docker_amd64"], json!(2));
    assert_eq!(j["why"], json!(null));
    assert_eq!(
        serde_json::to_value(host_24gb(Limits::uncapped(), |_| {})).unwrap(),
        j
    );
}

// ---- protection rules as reservations and holds

#[test]
fn reserved_cpu_shrinks_slots_instead_of_stopping() {
    assert_eq!(host_64gb(|_| {}).cpu_slots, 14); // 12 P + 4 E / 2
    // a protected process measured at 0.5 cores peak: 0.5 × 1.5 + 1 headroom = 1.75 reserved → 12, still admitting
    let c = host_64gb(|i| i.constraint.reserved_cpu = 0.5 * 1.5 + 1.0);
    assert_eq!(c.cpu_slots, 12);
    assert!(c.admit);
    // its memory peak (10 + 2) is reserved from the host budget beside a 12 GB VM: 64 − 4 − 12 − 12
    let mut i = CapacityInputs::new(64.0, 12, 4, Policy::default(), Limits::uncapped());
    i.service_reserved_mem_gb = 12.0;
    i.constraint.reserved_mem_gb = 12.0;
    assert_eq!(CapacityModel::compute(&i).host_budget_gb, 36.0);
}

#[test]
fn pool_jobs_only_while_yielding_when_the_rule_allows() {
    let hold = |pools_allowed: Option<i64>, service_pools: &[(&str, i64)]| {
        let mut v = ConstraintVector::new("rule:app");
        match pools_allowed {
            Some(n) => v.pool_jobs_only = Some(pools(&[("docker_amd64", n)])),
            None => v.slots = Some(0),
        }
        host_64gb(|i| {
            i.constraint = constraint(&[v]);
            i.service_pools = pools(service_pools);
        })
    };
    assert!(!hold(None, &[("docker_amd64", 2)]).pool_jobs_only); // default: fully yielded
    let c = hold(Some(1), &[("docker_amd64", 2)]);
    assert!(!c.admit && c.pool_jobs_only);
    assert_eq!(c.pools["docker_amd64"], 1);
    // no VM service, nothing to score with
    assert!(hold(Some(1), &[]).pools.is_empty());
}

// ---- hard-cap enforcement

fn attempts() -> Vec<EnforcementAttempt> {
    (1..=4)
        .map(|i| EnforcementAttempt::new(i, i as f64 * 100.0, 1.0))
        .collect()
}

#[test]
fn soft_never_releases() {
    let l = Limits {
        cpu_cores: Some(1.0),
        mem_gb: Some(1.0),
        jobs: Some(1),
        ..Limits::default()
    };
    assert!(Enforcement::hard_releases(&l, &attempts(), 4.0, 8.0, false).is_empty());
}

#[test]
fn hard_jobs_cap_releases_youngest() {
    let l = Limits {
        jobs: Some(2),
        enforce: Enforce::Hard,
        ..Limits::default()
    };
    assert_eq!(
        Enforcement::hard_releases(&l, &attempts(), 4.0, 0.0, true),
        [
            ReleaseDecision::new(4, "limit_cpu"),
            ReleaseDecision::new(3, "limit_cpu")
        ]
    );
}

#[test]
fn hard_cpu_cap_uses_resources_cpu() {
    let two: Vec<EnforcementAttempt> = attempts()
        .into_iter()
        .map(|a| EnforcementAttempt { cpu: 2.0, ..a })
        .collect();
    let l = Limits {
        cpu_cores: Some(5.0),
        enforce: Enforce::Hard,
        ..Limits::default()
    };
    let d = Enforcement::hard_releases(&l, &two, 4.0, 0.0, true);
    // 8 CPUs used, cap 5 → drop the two youngest (4 CPUs left)
    assert_eq!(d.iter().map(|x| x.attempt_id).collect::<Vec<_>>(), [4, 3]);
    assert!(d.iter().all(|x| x.reason == "limit_cpu"));
}

#[test]
fn hard_mem_cap_releases_until_it_fits() {
    // 4 GB of jobs + 8 GB VM = 12 > 10 → release the two youngest
    let l = Limits {
        mem_gb: Some(10.0),
        enforce: Enforce::Hard,
        ..Limits::default()
    };
    assert_eq!(
        Enforcement::hard_releases(&l, &attempts(), 4.0, 8.0, true),
        [
            ReleaseDecision::new(4, "limit_mem"),
            ReleaseDecision::new(3, "limit_mem")
        ]
    );
}

#[test]
fn hard_outside_schedule_releases_all() {
    let l = Limits {
        enforce: Enforce::Hard,
        ..Limits::default()
    };
    let d = Enforcement::hard_releases(&l, &attempts(), 4.0, 8.0, false);
    assert_eq!(d.len(), 4);
    assert!(d.iter().all(|x| x.reason == "limit_schedule"));
    assert_eq!(d[0].attempt_id, 4);
}

#[test]
fn within_caps_nothing() {
    let l = Limits {
        cpu_cores: Some(8.0),
        mem_gb: Some(32.0),
        jobs: Some(8),
        enforce: Enforce::Hard,
        ..Limits::default()
    };
    assert!(Enforcement::hard_releases(&l, &attempts(), 4.0, 8.0, true).is_empty());
}

// ---- the schedule window; 2026-09-28 is a Monday

/// Unix seconds for a UTC date and time.
fn at(month: u32, day: u32, h: i64, m: i64) -> i64 {
    // days since 1970-01-01 for 2026-09-01 and 2026-10-01
    let base = if month == 9 { 20_697 } else { 20_727 };
    (base + i64::from(day) - 1) * 86400 + h * 3600 + m * 60
}

#[test]
fn weekday_numbering_is_monday_zero() {
    assert_eq!(Schedule::monday_zero_weekday(at(9, 28, 12, 0)), 0);
    assert_eq!(Schedule::monday_zero_weekday(at(10, 2, 12, 0)), 4);
    assert_eq!(Schedule::monday_zero_weekday(at(10, 4, 12, 0)), 6);
}

#[test]
fn schedule_parse() {
    let s = Schedule::from_json(&json!({"days": [4], "start": "22:00", "end": "07:30"})).unwrap();
    assert_eq!(s.days, Some([4].into()));
    assert_eq!((s.start_minute, s.end_minute), (22 * 60, 7 * 60 + 30));
    assert!(Schedule::from_json(&json!({"start": "25:00", "end": "07:30"})).is_none());
    assert!(Schedule::from_json(&json!({"days": [1]})).is_none());
    assert_eq!(Schedule::parse_hhmm("7:05"), Some(425));
    assert_eq!(Schedule::parse_hhmm("24:00"), Some(1440));
    assert_eq!(Schedule::parse_hhmm("24:01"), None);
    assert_eq!(Schedule::parse_hhmm("x"), None);
    assert_eq!(
        Schedule::from_json(&json!({"days": [], "start": "1:00", "end": "2:00"}))
            .unwrap()
            .days,
        None
    );
}

#[test]
fn overnight_window_belongs_to_its_start_day() {
    // Friday 22:00 → Saturday 07:30
    let s = Schedule::new(Some(&[4]), 22 * 60, 7 * 60 + 30);
    let c = |d, h, m| s.contains_unix(at(10, d, h, m), 0);
    assert!(!c(2, 21, 59));
    assert!(c(2, 22, 0));
    assert!(c(2, 23, 59));
    assert!(c(3, 3, 0)); // Saturday 03:00 (the window started Friday)
    assert!(c(3, 7, 29));
    assert!(!c(3, 7, 30)); // the end is exclusive
    assert!(!c(3, 22, 30)); // Saturday night: not a listed day
    assert!(!c(2, 3, 0)); // Friday 03:00 belongs to Thursday's window
}

#[test]
fn same_day_window() {
    let s = Schedule::new(Some(&[0, 1, 2, 3, 4]), 9 * 60, 17 * 60);
    let c = |d, h, m| s.contains_unix(at(10, d, h, m), 0);
    assert!(c(2, 9, 0));
    assert!(c(2, 16, 59));
    assert!(!c(2, 17, 0));
    assert!(!c(2, 8, 59));
    assert!(!c(3, 12, 0)); // Saturday
}

#[test]
fn all_days_and_full_day() {
    let every = Schedule::new(None, 22 * 60, 6 * 60);
    assert!(every.contains_unix(at(10, 3, 23, 0), 0));
    assert!(every.contains_unix(at(10, 4, 1, 0), 0));
    assert!(!every.contains_unix(at(10, 4, 12, 0), 0));
    let full = Schedule::new(Some(&[5, 6]), 0, 0);
    assert!(full.contains_unix(at(10, 3, 12, 0), 0));
    assert!(!full.contains_unix(at(10, 2, 12, 0), 0));
    let midnight = Schedule::new(Some(&[5]), 0, 1440);
    assert!(midnight.contains_unix(at(10, 3, 23, 59), 0));
    // a UTC offset moves the local day: 23:30 UTC Friday is 01:30 Saturday at +2 h
    assert!(Schedule::new(Some(&[5]), 60, 120).contains_unix(at(10, 2, 23, 30), 7200));
}
