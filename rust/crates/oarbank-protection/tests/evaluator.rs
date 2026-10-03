//! Rule activity, timing and the doubling resume cooldown of a hold rule.

mod common;

use std::collections::HashMap;

use common::{gpu_app_rule, no_cpu, proc_fp, rule};
use oarbank_protection::signals::frontmost;
use oarbank_protection::*;
use serde_json::json;

#[test]
fn reserve_only_rule_enters_at_once_and_leaves_when_the_group_is_gone() {
    let mut ev = RuleEvaluator::new();
    let cfg = ProtectionConfig::new(ProtectionMode::FleetFirst, vec![gpu_app_rule()]);
    let r = ev.evaluate(
        &cfg,
        &[proc_fp(10, "/X/Engine/bin/w", 3.5)],
        &no_cpu(),
        None,
        None,
        0.0,
    );
    assert_eq!(r.vectors.len(), 1);
    assert_eq!(r.vectors[0].reserve_mem_gb.values().next(), Some(&5.5));
    assert_eq!(
        r.events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
        ["rule_active"]
    );
    let r = ev.evaluate(
        &cfg,
        &[proc_fp(10, "/X/Engine/bin/w", 1.0)],
        &no_cpu(),
        None,
        None,
        100.0,
    );
    assert_eq!(r.vectors[0].reserve_mem_gb.values().next(), Some(&5.5)); // peak over 300 s, not the current value
    let r = ev.evaluate(&cfg, &[], &no_cpu(), None, None, 110.0);
    assert!(r.vectors.is_empty());
    assert_eq!(
        r.events.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
        ["rule_inactive"]
    );
}

#[test]
fn reservations_key_on_the_groups_oldest_process() {
    let mut ev = RuleEvaluator::new();
    let cfg = ProtectionConfig::new(ProtectionMode::FleetFirst, vec![gpu_app_rule()]);
    let procs = [
        ProcessRecord {
            footprint_gb: 1.0,
            ..ProcessRecord::new(10, 1, 900, "/X/Engine/bin/w")
        },
        ProcessRecord {
            footprint_gb: 1.0,
            ..ProcessRecord::new(11, 10, 1000, "/bin/sh")
        },
    ];
    let r = ev.evaluate(&cfg, &procs, &no_cpu(), None, None, 0.0);
    assert_eq!(
        r.vectors[0].reserve_mem_gb.keys().collect::<Vec<_>>(),
        ["10@900"]
    );
    assert_eq!(r.reports[0].processes, 2);
    assert_eq!(r.reports[0].reason, "active");
}

#[test]
fn cap_rules_use_enter_and_exit_timing() {
    let mut ev = RuleEvaluator::new();
    let r = rule(
        json!({"id": "xcode", "match": {"name": "xcodebuild"}, "active_when": {"cpu_cores_gt": 1.0},
                        "cap_fleet": {"cpu_cores": 2}}),
    );
    let cfg = ProtectionConfig::new(ProtectionMode::Moderate, vec![r]);
    let p = ProcessRecord::new(7, 1, 1000, "/usr/bin/xcodebuild");
    let busy = HashMap::from([(p.key(), 4.0)]);
    let idle = HashMap::from([(p.key(), 0.1)]);
    let procs = [p];
    let mut v =
        |c: &HashMap<ProcessKey, f64>, t: f64| ev.evaluate(&cfg, &procs, c, None, None, t).vectors;
    assert!(v(&busy, 0.0).is_empty()); // enter_for 4 s
    assert!(v(&busy, 2.0).is_empty());
    assert_eq!(v(&busy, 4.0).first().and_then(|x| x.cpu_cores), Some(2.0));
    assert_eq!(v(&idle, 30.0).len(), 1); // exit_after 60 s
    assert_eq!(v(&idle, 89.0).len(), 1);
    assert!(v(&idle, 91.0).is_empty());
}

#[test]
fn reports_explain_inactive_rules() {
    let mut ev = RuleEvaluator::new();
    let cfg = ProtectionConfig::new(
        ProtectionMode::Moderate,
        vec![
            rule(
                json!({"id": "big", "match": {"name": "w"}, "active_when": {"footprint_gb_gt": 10}, "evict": {}}),
            ),
            rule(json!({"id": "gone", "match": {"name": "nobody"}, "evict": {}})),
            rule(json!({"id": "ign", "match": {"name": "w"}, "ignore": true})),
        ],
    );
    let r = ev.evaluate(&cfg, &[proc_fp(1, "/x/w", 1.0)], &no_cpu(), None, None, 0.0);
    let reasons: Vec<(&str, bool, &str)> = r
        .reports
        .iter()
        .map(|x| (x.id.as_str(), x.active, x.reason.as_str()))
        .collect();
    assert_eq!(
        reasons,
        [
            ("big", false, "condition not met"),
            ("gone", false, "no matching process"),
            ("ign", false, "ignore rule")
        ]
    );
    assert!(r.vectors.is_empty());
}

/// The previous agent's soft yield: enter at once, resume after 120 s, doubled for each earlier activation
/// within the hour, and a re-trigger during the cooldown restarts it doubled.
#[test]
fn hold_rules_resume_after_the_doubling_cooldown() {
    let mut ev = RuleEvaluator::new();
    let r = rule(json!({"id": "y", "match": {"name": "w"}, "exit_after_s": 0,
                        "active_when": {"footprint_gb_gt": 3.0, "for_s": 0}, "cap_fleet": {"slots": 0}}));
    let cfg = ProtectionConfig::new(ProtectionMode::FleetFirst, vec![r]);
    let hi = [proc_fp(1, "/x/w", 4.0)];
    let lo = [proc_fp(1, "/x/w", 1.0)];
    let mut active =
        |p: &[ProcessRecord], t: f64| !ev.evaluate(&cfg, p, &no_cpu(), None, None, t).vectors.is_empty();
    assert!(active(&hi, 0.0)); // enters at once
    assert!(active(&lo, 10.0)); // cooling down (120 s from t=10)
    assert!(active(&lo, 129.0));
    assert!(!active(&lo, 131.0));
    assert!(active(&hi, 200.0)); // second activation within the hour: 240 s
    assert!(active(&lo, 210.0) && active(&lo, 449.0));
    assert!(!active(&lo, 451.0));
    assert!(active(&hi, 500.0)); // third: 480 s ...
    assert!(active(&lo, 510.0));
    assert!(active(&hi, 600.0)); // ... re-triggered while cooling down: the fourth, 960 s
    assert!(active(&lo, 610.0) && active(&lo, 1569.0));
    assert!(!active(&lo, 1571.0));
}

/// A hold rule (`cap_fleet.slots = 0`) driven tick by tick: the caller says whether the protected process is
/// active at each time.
struct Yield {
    ev: RuleEvaluator,
    cfg: ProtectionConfig,
}

impl Yield {
    fn new(base: f64, max: f64, window: f64) -> Self {
        let r = rule(
            json!({"id": "app", "match": {"name": "w"}, "exit_after_s": 0,
                            "active_when": {"footprint_gb_gt": 3.0, "for_s": 0}, "cap_fleet": {"slots": 0}}),
        );
        let mut cfg = ProtectionConfig::new(ProtectionMode::FleetFirst, vec![r]);
        cfg.cooldown_base_s = base;
        cfg.cooldown_max_s = max;
        cfg.cooldown_window_s = window;
        Self {
            ev: RuleEvaluator::new(),
            cfg,
        }
    }

    /// Returns whether admission is held back after this tick.
    fn update(&mut self, app_active: bool, now: f64) -> bool {
        let p = [proc_fp(1, "/x/w", if app_active { 4.0 } else { 1.0 })];
        !self
            .ev
            .evaluate(&self.cfg, &p, &no_cpu(), None, None, now)
            .vectors
            .is_empty()
    }

    fn hold(&self) -> f64 {
        self.ev.states["app"].hold
    }
}

#[test]
fn yield_basic_cooldown_and_clear() {
    let mut y = Yield::new(120.0, 3840.0, 3600.0);
    assert!(!y.update(false, 0.0));
    assert!(y.update(true, 10.0));
    assert_eq!(y.hold(), 120.0);
    assert!(y.update(true, 20.0));
    assert!(y.update(false, 100.0)); // cooldown until 220
    assert!(y.update(false, 219.0));
    assert!(!y.update(false, 220.0));
}

#[test]
fn yield_cooldown_doubles_on_repeat_within_an_hour() {
    let mut y = Yield::new(120.0, 3840.0, 3600.0);
    y.update(true, 0.0);
    assert!(y.update(false, 10.0) && y.update(false, 129.0)); // cooldown until 130
    assert!(!y.update(false, 130.0));
    assert!(y.update(true, 600.0));
    assert_eq!(y.hold(), 240.0);
    assert!(y.update(false, 700.0) && y.update(false, 939.0)); // until 940
    assert!(!y.update(false, 940.0));
    assert!(y.update(true, 1200.0));
    assert_eq!(y.hold(), 480.0);
    y.update(false, 1300.0);
    assert!(!y.update(false, 1780.0));
    // more than an hour after the last yield: back to 120 s
    assert!(y.update(true, 1200.0 + 3601.0));
    assert_eq!(y.hold(), 120.0);
}

#[test]
fn yield_counts_only_activations_within_the_window() {
    let mut y = Yield::new(120.0, 3840.0, 3600.0);
    y.update(true, 0.0);
    y.update(false, 1.0);
    assert!(!y.update(false, 200.0));
    y.update(true, 3000.0); // one earlier yield in the hour: 240
    assert_eq!(y.hold(), 240.0);
    y.update(false, 3001.0);
    assert!(!y.update(false, 3300.0));
    // at 3700 the yield at 0 has aged out; the one at 3000 remains: 240
    y.update(true, 3700.0);
    assert_eq!(y.hold(), 240.0);
}

#[test]
fn yield_activity_during_cooldown_restarts_it_doubled() {
    let mut y = Yield::new(120.0, 3840.0, 3600.0);
    y.update(true, 0.0);
    y.update(false, 50.0); // cooldown until 170
    assert!(y.update(true, 100.0));
    assert_eq!(y.hold(), 240.0);
    assert!(y.update(false, 150.0) && y.update(false, 389.0)); // until 390
    assert!(!y.update(false, 390.0));
}

#[test]
fn yield_cooldown_is_capped() {
    let mut y = Yield::new(120.0, 600.0, 3600.0);
    let mut t = 0.0;
    for _ in 0..8 {
        y.update(true, t);
        y.update(false, t + 1.0);
        t += 5.0;
    }
    assert_eq!(y.hold(), 600.0);
    assert!(y.update(false, 36.0 + 599.0));
    assert!(!y.update(false, 36.0 + 600.0));
}

#[test]
fn combine_takes_minima_and_reserves_each_process_once() {
    let mut a = ConstraintVector::new("rule:a");
    a.cpu_cores = Some(6.0);
    a.reserve_mem_gb.insert("10@1".into(), 4.0);
    a.reserve_cpu.insert("10@1".into(), 1.0);
    let mut b = ConstraintVector::new("rule:b");
    b.cpu_cores = Some(2.0);
    b.slots = Some(3);
    b.reserve_mem_gb.insert("10@1".into(), 5.0);
    b.reserve_mem_gb.insert("20@2".into(), 1.0);
    let g = ConstraintVector::no_admit("guard:memory");
    let c = CombinedConstraint::combine(&[a, b, g]);
    assert_eq!((c.cpu_cores, c.slots), (Some(2.0), Some(3)));
    assert_eq!(c.binding["cpu_cores"], "rule:b");
    assert_eq!((c.reserved_mem_gb, c.reserved_cpu), (6.0, 1.0)); // 10@1 once at its largest (5), plus 20@2
    assert!(c.no_admit);
    assert_eq!(c.binding["admit"], "guard:memory");
    assert_eq!(c.binding["reserve_mem"], "rule:b");
    assert_eq!(c.binding["reserve_cpu"], "rule:a");
}

#[test]
fn combine_pools_evict_and_ties() {
    let mut a = ConstraintVector::new("rule:a");
    a.pool_jobs_only = Some([("vm".to_string(), 2), ("gpu".to_string(), 1)].into());
    a.slots = Some(1);
    a.evict.insert(ProtectionScope::Gpu);
    let mut b = ConstraintVector::new("rule:b");
    b.pool_jobs_only = Some([("vm".to_string(), 1)].into());
    b.slots = Some(1);
    b.evict.insert(ProtectionScope::Cpu);
    let c = CombinedConstraint::combine(&[a, b]);
    assert_eq!(
        c.pool_jobs_only,
        Some([("vm".to_string(), 1), ("gpu".to_string(), 1)].into())
    );
    assert_eq!(c.binding["pool_jobs_only"], "rule:a");
    assert_eq!(c.binding["slots"], "rule:a"); // a tie binds the first source
    assert_eq!(
        c.evict.iter().copied().collect::<Vec<_>>(),
        [ProtectionScope::Cpu, ProtectionScope::Gpu]
    );
    let j = c.to_json();
    assert_eq!(j["evict"], json!(["cpu", "gpu"]));
    assert_eq!(j["pool_jobs_only"], json!({"vm": 1, "gpu": 1}));
    assert_eq!(j["cpu_cores"], json!(null));
    assert_eq!(j["slots"], json!(1));
    assert!(CombinedConstraint::combine(&[])
        .to_json()
        .get("pool_jobs_only")
        .is_none());
}

#[test]
fn rule_vectors_carry_caps_pools_and_evict() {
    let mut ev = RuleEvaluator::new();
    let cfg = ProtectionConfig::new(
        ProtectionMode::FleetFirst,
        vec![
            rule(
                json!({"id": "pools", "match": {"name": "w"}, "cap_fleet": {"slots": 0, "pools": {"vm": 1}, "threads": 2},
                        "active_when": {"for_s": 0}}),
            ),
            rule(
                json!({"id": "ev", "match": {"name": "w"}, "evict": {"scope": "gpu"}, "active_when": {"for_s": 0}}),
            ),
        ],
    );
    let r = ev.evaluate(&cfg, &[proc_fp(1, "/x/w", 1.0)], &no_cpu(), None, None, 0.0);
    assert_eq!(r.vectors.len(), 2);
    assert_eq!(
        r.vectors[0].pool_jobs_only,
        Some([("vm".to_string(), 1)].into())
    );
    assert_eq!(r.vectors[0].slots, None);
    assert_eq!(r.vectors[0].threads, Some(2));
    assert_eq!(
        r.vectors[1].evict.iter().copied().collect::<Vec<_>>(),
        [ProtectionScope::Gpu]
    );
    assert_eq!(ev.started, ["pools", "ev"]);
    assert_eq!(ev.active_rules.len(), 2);
    // a removed rule's state is dropped
    let cfg2 = ProtectionConfig::new(ProtectionMode::FleetFirst, vec![]);
    ev.evaluate(&cfg2, &[], &no_cpu(), None, None, 2.0);
    assert!(ev.states.is_empty());
}

fn app(pid: i32, bundle_id: &str, path: &str) -> ProcessRecord {
    ProcessRecord {
        bundle_id: Some(bundle_id.into()),
        ..ProcessRecord::new(pid, 1, 1000, path)
    }
}

/// The demo node's "writing" rule (TextEdit in front pauses fleet work), fed the front app's pid the way the
/// macOS backend reads it: `lsappinfo info -only pid <ASN>` as macOS 27.0.1 prints it.
#[test]
fn frontmost_rules_follow_the_app_in_front() {
    let procs = [
        app(812, "com.apple.TextEdit", "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit"),
        app(640, "com.apple.Terminal", "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"),
    ];
    let lsappinfo = |pid: i32| {
        format!(
            "[ NULL ]  [ NULL ]  \n    bundleID=[ NULL ] \n    bundle path=[ NULL ] \n    executable path=[ NULL ] \n    \
             pid = {pid} !cgsConnection !signalled type=[ NULL ]  flavor=[ NULL ]  Version=[ NULL ]  Arch=!!none \n\n"
        )
    };
    let (textedit, terminal) = (frontmost::parse_pid(&lsappinfo(812)), frontmost::parse_pid(&lsappinfo(640)));
    assert_eq!((textedit, terminal), (Some(812), Some(640)));
    let writing = rule(json!({"id": "writing", "match": {"bundle_id": "com.apple.TextEdit"},
                              "active_when": {"frontmost": true}, "pause_fleet": {"scope": "all"}, "exit_after_s": 20}));
    let cfg = ProtectionConfig::new(ProtectionMode::FleetFirst, vec![writing]);
    let mut ev = RuleEvaluator::new();
    let mut active = |front: Option<i32>, t: f64| {
        let r = ev.evaluate(&cfg, &procs, &no_cpu(), front, None, t);
        (r.reports[0].active, r.reports[0].reason.clone())
    };
    assert_eq!(active(terminal, 0.0), (false, "condition not met".into()));
    assert!(!active(textedit, 2.0).0); // enter_for 4 s
    assert!(active(textedit, 6.0).0);
    // another app in front: released after the resume cooldown (a pause holds admission back)
    assert!(active(terminal, 8.0).0);
    assert!(active(terminal, 126.0).0);
    assert!(!active(terminal, 128.0).0);
    // an unknown front app counts as in front (never looser)
    assert!(!active(None, 130.0).0);
    assert!(active(None, 134.0).0);

    // frontmost = false: the group runs but is not in front
    let background = rule(json!({"id": "bg", "match": {"bundle_id": "com.apple.TextEdit"},
                                 "active_when": {"frontmost": false, "for_s": 0}, "cap_fleet": {"cpu_cores": 2}}));
    let cfg = ProtectionConfig::new(ProtectionMode::FleetFirst, vec![background]);
    let mut ev = RuleEvaluator::new();
    assert!(ev.evaluate(&cfg, &procs, &no_cpu(), terminal, None, 0.0).reports[0].active);
    let mut ev = RuleEvaluator::new();
    assert!(!ev.evaluate(&cfg, &procs, &no_cpu(), textedit, None, 0.0).reports[0].active);
    // not running at all: nothing to protect, whatever is in front
    let mut ev = RuleEvaluator::new();
    assert!(!ev.evaluate(&cfg, &procs[1..], &no_cpu(), terminal, None, 0.0).reports[0].active);
}

fn busy(by_pid: &[(i32, f64)], unknown: &[i32]) -> GpuBusy {
    GpuBusy {
        by_pid: by_pid.iter().copied().collect(),
        unknown: unknown.iter().copied().collect(),
    }
}

/// A game and its helper keep the GPU busy: fleet GPU jobs stop while the group's busy share is at least
/// `min_busy`, and usage that cannot be read counts as busy.
#[test]
fn gpu_active_rules_follow_the_groups_gpu_use() {
    let procs = [
        ProcessRecord::new(500, 1, 1000, "/opt/game/bin/game"),
        ProcessRecord::new(501, 500, 1001, "/opt/game/bin/helper"),
        ProcessRecord::new(600, 1, 1002, "/usr/bin/other"),
    ];
    let game = rule(json!({"id": "game", "match": {"path_prefix": "/opt/game/"}, "tree": "descendants",
                           "active_when": {"gpu_active": {"min_busy": 0.1}, "for_s": 0},
                           "cap_fleet": {"gpu_jobs": 0}, "exit_after_s": 0}));
    let cfg = ProtectionConfig::new(ProtectionMode::FleetFirst, vec![game]);
    let mut ev = RuleEvaluator::new();
    let mut eval = |gpu: Option<&GpuBusy>, procs: &[ProcessRecord], t: f64| ev.evaluate(&cfg, procs, &no_cpu(), None, gpu, t);
    // another process's GPU use does not count; the group's 0.02 + 0.05 is under 0.1
    let r = eval(Some(&busy(&[(500, 0.02), (501, 0.05), (600, 0.9)], &[])), &procs, 0.0);
    assert_eq!((r.reports[0].active, r.reports[0].reason.as_str()), (false, "condition not met"));
    // summed over the group: 0.06 + 0.05
    let r = eval(Some(&busy(&[(500, 0.06), (501, 0.05)], &[])), &procs, 2.0);
    assert!(r.reports[0].active);
    assert_eq!(r.vectors[0].gpu_jobs, Some(0));
    let e = r.events.iter().find(|e| e.kind == "rule_active").unwrap();
    assert!((e.signals["gpu_busy"] - 0.11).abs() < 1e-9);
    assert!(!eval(Some(&busy(&[], &[])), &procs, 4.0).reports[0].active);
    // fail-safe: a group process whose usage cannot be read, or no reading at all, counts as busy
    let r = eval(Some(&busy(&[(500, 0.0)], &[501])), &procs, 6.0);
    assert!(r.reports[0].active);
    assert!(!r.events[0].signals.contains_key("gpu_busy"));
    assert!(!eval(Some(&busy(&[], &[600])), &procs, 8.0).reports[0].active); // not one of the group
    assert!(eval(None, &procs, 10.0).reports[0].active);
    // not running at all: nothing to protect, whatever the GPU reads
    assert!(!eval(None, &procs[2..], 12.0).reports[0].active);
    // gpu_active = {} holds at 5 % busy
    let dflt = rule(json!({"id": "d", "match": {"path_prefix": "/opt/game/"}, "active_when": {"gpu_active": {}, "for_s": 0},
                           "cap_fleet": {"gpu_jobs": 0}}));
    let cfg = ProtectionConfig::new(ProtectionMode::FleetFirst, vec![dflt]);
    let mut ev = RuleEvaluator::new();
    assert!(!ev.evaluate(&cfg, &procs, &no_cpu(), None, Some(&busy(&[(500, 0.049)], &[])), 0.0).reports[0].active);
    assert!(ev.evaluate(&cfg, &procs, &no_cpu(), None, Some(&busy(&[(500, 0.05)], &[])), 2.0).reports[0].active);
}

#[test]
fn report_json_shape() {
    let r = RuleReport {
        id: "a".into(),
        active: true,
        processes: 3,
        cpu_cores: 0.456,
        footprint_gb: 4.111,
        reason: "active".into(),
    };
    assert_eq!(
        serde_json::to_value(&r).unwrap(),
        json!({"id": "a", "active": true, "processes": 3, "cpu_cores": 0.46, "footprint_gb": 4.11, "reason": "active"})
    );
}
