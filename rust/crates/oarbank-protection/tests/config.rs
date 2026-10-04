//! Protection config schema 1: parsing, validation, the strictest-wins union and reservation expressions.

mod common;

use oarbank_protection::*;
use serde_json::json;

#[test]
fn parses_schema_one_and_rejects_bad_rules() {
    let c = ProtectionConfig::from_json(
        &json!({
            "schema": 1, "node": {"mode": "fleet_first", "memory": {"soft_free_pct": 15}},
            "rule": [{"id": "chrome", "match": {"team_id": "EQHXZ8M8AV"}, "tree": "same_team",
                      "active_when": {"frontmost": true}, "cap_fleet": {"cpu_cores": 6}},
                     {"id": "idx", "match": {"bundle_id": ["com.getdropbox.dropbox"]}, "ignore": true}],
        }),
        "central",
    )
    .unwrap();
    assert_eq!(c.mode, ProtectionMode::FleetFirst);
    assert_eq!(c.memory.soft_free_pct, 15.0);
    assert_eq!(c.memory.hard_free_pct, 8.0);
    assert_eq!(
        c.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["chrome", "idx"]
    );
    assert_eq!(c.rules[0].cap_fleet.as_ref().unwrap().cpu_cores, Some(6.0));
    assert_eq!(c.sources, ["central"]);
    let bad = |j: serde_json::Value| ProtectionConfig::from_json(&j, "c").is_err();
    assert!(bad(
        json!({"rule": [{"id": "x", "match": {}, "ignore": true}]})
    ));
    // ignore cannot carry actions
    assert!(bad(
        json!({"rule": [{"id": "x", "match": {"name": "a"}, "ignore": true, "evict": {}}]})
    ));
    // same_team needs a team matcher
    assert!(bad(
        json!({"rule": [{"id": "x", "match": {"name": "a"}, "tree": "same_team", "evict": {}}]})
    ));
    assert!(bad(json!({"schema": 2})));
}

#[test]
fn rejection_messages_name_the_rule() {
    let e = |j: serde_json::Value| {
        ProtectionConfig::from_json(&j, "c")
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        e(json!({"rule": [{"match": {"name": "a"}, "evict": {}}]})),
        "rule without an id"
    );
    assert_eq!(e(json!({"rule": [{"id": "x"}]})), "rule x: no match");
    assert_eq!(
        e(json!({"rule": [{"id": "x", "match": {"name": "a"}}]})),
        "rule x: needs an action or ignore"
    );
    assert_eq!(
        e(json!({"rule": [{"id": "x", "match": {"name": "a"}, "tree": "kids", "evict": {}}]})),
        "rule x: unknown tree kids"
    );
    assert_eq!(
        e(json!({"node": {"mode": "yolo"}})),
        "unknown protection mode yolo"
    );
    assert_eq!(
        e(json!({"schema": 2})),
        "protection schema 2 is not supported (1)"
    );
    assert_eq!(
        e(
            json!({"rule": [{"id": "a", "match": {"name": "x"}, "evict": {}}, {"id": "a", "match": {"name": "y"}, "evict": {}}]})
        ),
        "duplicate rule id a"
    );
    assert_eq!(
        e(
            json!({"rule": [{"id": "x", "match": {"name": "a"}, "protect": {"metric": "cpu_stall"}}]})
        ),
        "rule x: protect needs exactly one of max / max_slowdown"
    );
    assert_eq!(
        e(
            json!({"rule": [{"id": "x", "match": {"name": "a"}, "during": [{"cap_fleet": {"slots": 0}}]}]})
        ),
        "rule x: during needs a source"
    );
    assert!(
        e(json!({"rule": [{"id": "x", "match": {"argv_regex": "("}, "evict": {}}]}))
            .starts_with("match.argv_regex does not compile")
    );
    assert_eq!(
        e(json!({"rule": [{"id": "x", "match": {"name": "a"}, "reserve": {"cpu": true}}]})),
        "reservation must be a number or an expression"
    );
    // an empty key is no key (the coordinator's schema and the preview matcher agree)
    assert_eq!(
        e(json!({"rule": [{"id": "x", "match": {"name": ""}, "evict": {}}]})),
        "match needs at least one key"
    );
}

#[test]
fn rule_fields_parse() {
    let r = common::rule(json!({
        "id": "r", "match": {"bundle_id": "us.zoom.xos"}, "active_when": {"for_s": 3},
        "cap_fleet": {"slots": 0, "pools": {"vm": 2, "neg": -1, "bad": "x"}}, "lower_fleet": {"to": "e_cores"},
        "pause_fleet": {"scope": "gpu"}, "evict": {"scope": "nonsense"}, "enter_for_s": 1, "exit_after_s": 9,
        "protect": {"metric": "progress_rate", "max_slowdown": 0.1, "source": {"jsonl": "/x"}},
        "during": [{"source": {"jsonl": "/p", "enter": "a", "exit": "b"}, "cap_fleet": {"staging_mbps": 0}, "pause_fleet": {}}],
    }));
    assert_eq!(r.match_.bundle_ids, ["us.zoom.xos"]);
    // an active_when object with only for_s is still "present"
    assert!(r.active_when.present);
    assert_eq!(r.active_when.for_s, Some(3.0));
    let cf = r.cap_fleet.as_ref().unwrap();
    assert_eq!(cf.slots, Some(0));
    assert_eq!(cf.pools.get("vm"), Some(&2));
    assert_eq!(cf.pools.get("neg"), Some(&0));
    assert!(!cf.pools.contains_key("bad"));
    assert!(r.lower_fleet);
    assert_eq!(r.pause_fleet, Some(ProtectionScope::Gpu));
    assert_eq!(r.evict, Some(ProtectionScope::All)); // an object with an unknown scope means all
    assert_eq!(r.protect_metric(), Some("progress_rate"));
    assert_eq!(r.protect.as_ref().unwrap().window_s, 20.0);
    assert_eq!(r.during.len(), 1);
    assert_eq!(r.during[0].pause_fleet, Some(ProtectionScope::All));
    assert_eq!(
        r.during[0].cap_fleet.as_ref().unwrap().staging_mbps,
        Some(0.0)
    );
    // lower_fleet: null is absent; a during block alone is an action
    let r2 = common::rule(
        json!({"id": "d", "match": {"name": "a"}, "lower_fleet": null,
                                 "during": [{"source": {"jsonl": "/p"}}]}),
    );
    assert!(!r2.lower_fleet && r2.during.len() == 1);
}

#[test]
fn node_section_defaults_and_overrides() {
    let d = ProtectionConfig::from_json(&json!({}), "local").unwrap();
    assert_eq!(d.mode, ProtectionMode::Moderate);
    assert_eq!((d.enter_for_s, d.exit_after_s), (4.0, 60.0));
    assert_eq!(
        (
            d.cooldown_base_s,
            d.cooldown_backoff,
            d.cooldown_max_s,
            d.cooldown_window_s
        ),
        (120.0, 2.0, 3840.0, 3600.0)
    );
    assert_eq!(d.owner_stall_max, Some(0.15));
    let c = ProtectionConfig::from_json(
        &json!({"node": {"gpu_jobs": "never", "pause": true,
                         "implicit": {"frontmost_app": false, "owner_stall": null},
                         "defaults": {"enter_for_s": 2, "exit_after_s": 30, "cooldown": {"backoff": 0.5, "base_s": 60}}},
                "rules": [{"id": "a", "match": {"name": "x"}, "evict": {}}]}),
        "local",
    )
    .unwrap();
    assert_eq!(c.gpu_jobs, "never");
    assert!(c.pause && !c.implicit_frontmost);
    assert_eq!(c.owner_stall_max, None);
    assert_eq!(
        (c.enter_for_s, c.exit_after_s, c.cooldown_base_s),
        (2.0, 30.0, 60.0)
    );
    assert_eq!(c.cooldown_backoff, 1.0); // never below 1
    assert_eq!(c.rules.len(), 1); // "rules" is read when "rule" is absent
    let im = ProtectionConfig::from_json(&json!({"node": {"implicit": {"owner_stall": {}}}}), "c")
        .unwrap();
    assert_eq!(im.owner_stall_max, Some(0.15));
}

#[test]
fn union_is_strictest_on_every_dimension() {
    let central = ProtectionConfig::from_json(
        &json!({"node": {"mode": "fleet_first", "memory": {"soft_free_pct": 12, "swap_growth_hard_mb_min": 1024}},
                "rule": [{"id": "a", "match": {"name": "x"}, "evict": {}}]}),
        "central",
    )
    .unwrap();
    let local = ProtectionConfig::from_json(
        &json!({"node": {"mode": "strict_yield", "pause": true, "memory": {"soft_free_pct": 10, "swap_growth_hard_mb_min": 500}},
                "rule": [{"id": "a", "match": {"name": "y"}, "evict": {}}]}),
        "local",
    )
    .unwrap();
    let u = central.union(&local);
    assert_eq!(u.mode, ProtectionMode::StrictYield);
    assert!(u.pause);
    assert_eq!(u.memory.soft_free_pct, 12.0);
    assert_eq!(u.memory.swap_growth_hard_mb_min, 500.0);
    assert_eq!(
        u.rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        ["a", "a@local"]
    );
    assert_eq!(u.sources, ["central", "local"]);
    assert_eq!(local.union(&central).mode, ProtectionMode::StrictYield); // order never loosens
}

#[test]
fn union_timing_gpu_and_implicit() {
    let a = ProtectionConfig::from_json(
        &json!({"node": {"gpu_jobs": "always", "defaults": {"enter_for_s": 8, "exit_after_s": 10},
                         "implicit": {"owner_stall": {"max": 0.3}}}}),
        "central",
    )
    .unwrap();
    let b = ProtectionConfig::from_json(
        &json!({"node": {"gpu_jobs": "never", "defaults": {"enter_for_s": 2, "exit_after_s": 90},
                         "implicit": {"owner_stall": {"max": 0.1}}}}),
        "local",
    )
    .unwrap();
    let u = a.union(&b);
    assert_eq!(u.gpu_jobs, "never");
    assert_eq!((u.enter_for_s, u.exit_after_s), (2.0, 90.0));
    assert_eq!(u.owner_stall_max, Some(0.1));
}

#[test]
fn reservation_expressions() {
    let e = ReserveExpr::parse("peak(300s).footprint * 1.5 + 2").unwrap();
    let h = [
        GroupSample::new(0.0, 1.0, 4.0, 1),
        GroupSample::new(200.0, 3.0, 6.0, 1),
        GroupSample::new(400.0, 1.0, 3.0, 1),
    ];
    assert_eq!(e.evaluate(&h, 400.0), 6.0 * 1.5 + 2.0); // t=0 is outside the window
    assert_eq!(
        ReserveExpr::parse("peak(60s).cpu")
            .unwrap()
            .evaluate(&h, 400.0),
        1.0
    );
    assert_eq!(ReserveExpr::parse("3").unwrap().evaluate(&[], 0.0), 3.0);
    assert!(ReserveExpr::parse("max(footprint)").is_err());
    assert_eq!(ReserveExpr::parse("-2").unwrap().evaluate(&[], 0.0), 0.0); // never negative
    assert_eq!(
        ReserveExpr::parse("peak(10s).cpu")
            .unwrap()
            .evaluate(&[], 0.0),
        0.0
    ); // no samples
}

#[test]
fn summary_shape() {
    let c = ProtectionConfig::from_json(
        &json!({"rule": [{"id": "a", "match": {"name": "x"}, "evict": {}}]}),
        "central",
    )
    .unwrap();
    assert_eq!(
        c.summary(),
        json!({"mode": "moderate", "pause": false, "rules": ["a"], "sources": ["central"],
               "memory": {"soft_free_pct": 12.0, "hard_free_pct": 8.0, "swap_growth_soft_mb_min": 256.0,
                          "swap_growth_hard_mb_min": 1024.0, "min_reclaim_gb": 2.0}})
    );
}

#[test]
fn gpu_active_parses_with_a_default_threshold_and_rejects_bad_ones() {
    let aw = |a: serde_json::Value| {
        ProtectionRule::from_json(&json!({"id": "g", "match": {"name": "game"}, "active_when": a,
                                          "pause_fleet": {"scope": "gpu"}}))
    };
    let r = aw(json!({"gpu_active": {"min_busy": 0.2}, "for_s": 5})).unwrap();
    assert_eq!(r.active_when.gpu_min_busy, Some(0.2));
    assert_eq!(r.active_when.for_s, Some(5.0));
    assert!(!r.active_when.present); // a threshold, not mere presence
    assert_eq!(aw(json!({"gpu_active": {}})).unwrap().active_when.gpu_min_busy, Some(DEFAULT_GPU_MIN_BUSY));
    assert_eq!(aw(json!({"gpu_active": {"min_busy": 1}})).unwrap().active_when.gpu_min_busy, Some(1.0));
    // null is absent: the rule is active while the group runs
    let r = aw(json!({"gpu_active": null})).unwrap();
    assert_eq!(r.active_when.gpu_min_busy, None);
    assert!(r.active_when.present);
    for bad in [json!({"gpu_active": true}), json!({"gpu_active": 0.1}), json!({"gpu_active": {"min_busy": 0}}),
                json!({"gpu_active": {"min_busy": 1.5}}), json!({"gpu_active": {"min_busy": null}}),
                json!({"gpu_active": {"min_busy": "high"}})] {
        let e = aw(bad.clone()).unwrap_err().0;
        assert!(e.starts_with("rule g: active_when.gpu_active"), "{bad}: {e}");
    }
}

/// What each OS can be asked: the shared vectors the coordinator's own tests use
/// (src/oarbank/contracts/fixtures/protection-support-vectors.json).
#[test]
fn support_vectors_agree_with_python() {
    let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src/oarbank/contracts/fixtures/protection-support-vectors.json");
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    for c in cases {
        let cfg = ProtectionConfig::from_json(&json!({"rule": [c["rule"]]}), "central").unwrap();
        let os = support::Os::parse(c["os"].as_str().unwrap()).unwrap();
        let got = support::refusals(&cfg, os);
        let want: Vec<&str> = c["refused"].as_array().unwrap().iter().map(|w| w.as_str().unwrap()).collect();
        assert_eq!(got.len(), want.len(), "{}: {got:?}", c["name"]);
        for (g, w) in got.iter().zip(&want) {
            assert!(g.contains(w), "{}: {g:?} lacks {w:?}", c["name"]);
        }
    }
}

/// The agent refuses a part that asks what its OS cannot do, as it refuses a broken one: the last good config
/// stays, and the error names the rule.
#[test]
fn the_agent_refuses_what_its_os_cannot_do() {
    let mut c = ProtectionController::new(None, Host::native());
    let os = support::Os::current().unwrap();
    let rule = if os == support::Os::Darwin {
        json!({"id": "n", "match": {"name": "Google Chrome Hel"}, "evict": {}})
    } else {
        json!({"id": "t", "match": {"team_id": "EQHXZ8M8AV"}, "evict": {}})
    };
    c.apply(Some(&json!({"node": {"mode": "strict_yield"}, "rule": [rule]})), &LocalProtection::Absent);
    let e = c.config_error().unwrap();
    assert!(e.starts_with("central: rule "), "{e}");
    assert_eq!(c.config().mode, ProtectionMode::Moderate, "the last good config (the default) stays");
    assert!(c.config().rules.is_empty());
}

/// `[node] max_pause_s`: an owner may shorten the longest pause (never past 10 minutes); the union keeps the shorter.
#[test]
fn max_pause_is_bounded_and_the_union_keeps_the_shorter() {
    use oarbank_protection::config::{ProtectionConfig, MAX_PAUSE_S};
    let c = |v: serde_json::Value| ProtectionConfig::from_json(&serde_json::json!({"schema": 1, "node": v}), "central");
    assert_eq!(c(serde_json::json!({})).unwrap().max_pause_s, MAX_PAUSE_S);
    let short = c(serde_json::json!({"max_pause_s": 30})).unwrap();
    assert_eq!(short.max_pause_s, 30.0);
    assert!(c(serde_json::json!({"max_pause_s": 601})).is_err() && c(serde_json::json!({"max_pause_s": 5})).is_err());
    assert_eq!(ProtectionConfig::default().union(&short).max_pause_s, 30.0);
}
