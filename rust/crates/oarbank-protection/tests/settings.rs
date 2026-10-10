//! The agent's settings check (settings.rs over the generated settings_table.rs): what it applies, what it refuses and
//! reports, and that nothing falls back silently.

use oarbank_protection::settings::{defaults, validate, Section};
use oarbank_protection::Policy;
use serde_json::json;

#[test]
fn the_defaults_are_the_generated_table_and_the_capacity_engine_starts_from_them() {
    let p = defaults(Section::Policy);
    assert_eq!(p["os_reserve_gb"], json!(4));
    assert_eq!(p["job_mem_gb"], json!(1.5));
    assert_eq!(p["max_slots"], json!(null));
    assert_eq!(p["disabled_services"], json!([]));
    assert_eq!(p["module_settings"], json!({}));
    let l = defaults(Section::Limits);
    assert_eq!(l["enforce"], json!("soft"));
    assert_eq!(l["jobs"], json!(null));
    let from_table = Policy::from_json(Some(&p), &Policy::default());
    assert_eq!(from_table, Policy::default());
}

#[test]
fn a_well_typed_section_is_applied_whole() {
    let mut want = defaults(Section::Policy);
    want["job_mem_gb"] = json!(2.5);
    want["user_present_slots"] = json!(3.0); // an integral double of an integer key reads as the integer
    let (applied, rejected) = validate(Section::Policy, &want, &defaults(Section::Policy));
    assert!(rejected.is_empty(), "{rejected:?}");
    assert_eq!(applied["job_mem_gb"], json!(2.5));
    assert_eq!(applied["user_present_slots"], json!(3));
}

#[test]
fn a_mistyped_or_out_of_range_key_is_refused_reported_and_keeps_its_previous_value() {
    let mut prev = defaults(Section::Policy);
    prev["job_mem_gb"] = json!(3.0);
    let mut sent = defaults(Section::Policy);
    sent["job_mem_gb"] = json!("abc");
    sent["nice"] = json!(40);
    sent["threads_per_job"] = json!(1.5);
    let (applied, rejected) = validate(Section::Policy, &sent, &prev);
    let keys: Vec<&str> = rejected.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(keys, vec!["job_mem_gb", "threads_per_job", "nice"]);
    assert_eq!(applied["job_mem_gb"], json!(3.0)); // the last applied value, not a silent default
    assert_eq!(applied["nice"], json!(10));
    assert!(rejected[0].reason.contains("expected a number"));
    assert!(rejected[2].reason.contains("out of range"));
}

#[test]
fn a_missing_or_unknown_key_is_reported() {
    let mut sent = defaults(Section::Limits);
    sent.as_object_mut().unwrap().remove("mem_gb");
    sent["warp_factor"] = json!(9);
    sent["schedule"] = json!({"start": "22:00", "end": "07:30", "days": [0, 1]});
    let (applied, rejected) = validate(Section::Limits, &sent, &defaults(Section::Limits));
    assert_eq!(applied["mem_gb"], json!(null));
    assert_eq!(applied["schedule"]["start"], json!("22:00"));
    assert!(applied.get("warp_factor").is_none());
    let keys: Vec<&str> = rejected.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(keys, vec!["mem_gb", "warp_factor"]);
    let (_, bad) = validate(Section::Limits, &json!({"schedule": {"start": "late"}}), &defaults(Section::Limits));
    assert!(bad.iter().any(|r| r.key == "schedule"));
}

#[test]
fn a_cap_section_with_a_cap_set_reads_as_the_capacity_engines_limits() {
    let mut sent = defaults(Section::Limits);
    sent["jobs"] = json!(2);
    sent["enforce"] = json!("hard");
    let (applied, rejected) = validate(Section::Limits, &sent, &defaults(Section::Limits));
    assert!(rejected.is_empty());
    let l = oarbank_protection::Limits::from_json(Some(&applied));
    assert_eq!(l.jobs, Some(2));
    assert_eq!(l.enforce, oarbank_protection::Enforce::Hard);
    assert_eq!(l.mem_gb, None);
}
