//! Rule matching and the D20 vectors shared with the console's preview matcher.

mod common;

use std::path::PathBuf;

use common::{gpu_app_rule, proc_, rule};
use oarbank_protection::matcher::{group, matches};
use oarbank_protection::*;
use serde_json::{json, Value};

fn pids(g: &[ProcessRecord]) -> Vec<i32> {
    g.iter().map(|p| p.pid).collect()
}

#[test]
fn descendants_follow_ppid_but_not_recycled_parents() {
    let procs = [
        proc_(
            10,
            1,
            1000,
            "/Applications/X.app/Contents/Engine/bin/1/w",
        ),
        proc_(11, 10, 1100, "/usr/bin/python3"),
        proc_(12, 11, 1200, "/bin/sh"),
        proc_(13, 10, 500, "/bin/zsh"), // older than pid 10: a reused ppid
        proc_(20, 1, 1000, "/usr/bin/other"),
    ];
    let r = gpu_app_rule();
    assert_eq!(pids(&group(&procs, &r.match_, r.tree)), [10, 11, 12]);
}

#[test]
fn path_contains_sees_arguments() {
    let r = gpu_app_rule();
    let p = ProcessRecord {
        argv: Some(vec!["python3".into(), "/x/Engine/bin/run.py".into()]),
        ..proc_(5, 1, 1000, "/usr/bin/python3")
    };
    assert!(matches(&p, &r.match_));
    let q = ProcessRecord {
        argv: Some(vec!["python3".into(), "other.py".into()]),
        ..proc_(6, 1, 1000, "/usr/bin/python3")
    };
    assert!(!matches(&q, &r.match_));
}

#[test]
fn same_team_pulls_in_helpers() {
    let r = rule(
        json!({"id": "c", "match": {"team_id": "EQHXZ8M8AV", "bundle_id": ["com.google.Chrome"]},
                        "tree": "same_team", "cap_fleet": {"cpu_cores": 6}}),
    );
    let team = |pid, path: &str, team: &str, bundle: Option<&str>| ProcessRecord {
        team_id: Some(team.into()),
        bundle_id: bundle.map(Into::into),
        ..proc_(pid, 1, 1000, path)
    };
    let procs = [
        team(
            1,
            "/Applications/Chrome.app/Contents/MacOS/Chrome",
            "EQHXZ8M8AV",
            Some("com.google.Chrome"),
        ),
        team(
            2,
            "/.../Helper",
            "EQHXZ8M8AV",
            Some("com.google.Chrome.helper"),
        ),
        team(3, "/other", "OTHERTEAM1", None),
    ];
    assert_eq!(pids(&group(&procs, &r.match_, r.tree)), [1, 2]);
}

#[test]
fn requirement_and_argv_regex() {
    let mut p = ProcessRecord {
        argv: Some(
            ["python", "train.py", "--lr", "1e-4"]
                .map(String::from)
                .to_vec(),
        ),
        ..proc_(1, 1, 1000, "/Users/o/venv/bin/python")
    };
    let m = ProcessMatch::from_json(
        &json!({"path_prefix": "/Users/o/venv/bin/python", "argv_regex": r"train\.py"}),
    )
    .unwrap();
    assert!(matches(&p, &m));
    let req_s = r#"anchor apple and identifier "com.apple.dt.Xcode""#;
    let req = ProcessMatch::from_json(&json!({ "requirement": req_s })).unwrap();
    assert!(!matches(&p, &req));
    p.requirements_met.insert(req_s.into());
    assert!(matches(&p, &req));
}

#[test]
fn name_prefers_p_comm() {
    let m = ProcessMatch::from_json(&json!({"name": "Google Chrome H"})).unwrap();
    let p = ProcessRecord {
        comm: "Google Chrome H".into(),
        ..proc_(1, 1, 1, "/x/Google Chrome Helper")
    };
    assert!(matches(&p, &m));
    let by_path = ProcessMatch::from_json(&json!({"name": "Google Chrome Helper"})).unwrap();
    assert!(!matches(&p, &by_path));
    assert!(matches(
        &proc_(2, 1, 1, "/x/Google Chrome Helper"),
        &by_path
    ));
}

#[test]
fn regex_needs_argv() {
    let m = ProcessMatch::from_json(&json!({"argv_regex": ".*"})).unwrap();
    assert!(!matches(&proc_(1, 1, 1, "/bin/x"), &m)); // argv unknown: never matches
    assert!(matches(
        &ProcessRecord {
            argv: Some(vec![]),
            ..proc_(1, 1, 1, "/bin/x")
        },
        &m
    ));
}

/// One vector file: build the processes, run every case through the matcher.
fn check_vectors(path: PathBuf, min_cases: usize) {
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text).unwrap();
    let strs = |v: &Value| {
        v.as_array().map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
    };
    let s = |p: &Value, k: &str| p.get(k).and_then(Value::as_str).map(String::from);
    let procs: Vec<ProcessRecord> = doc["processes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| ProcessRecord {
            pid: p["pid"].as_i64().unwrap() as i32,
            ppid: p["ppid"].as_i64().unwrap() as i32,
            start_us: p["start_us"].as_u64().unwrap(),
            path: s(p, "path").unwrap_or_default(),
            comm: s(p, "comm").unwrap_or_default(),
            argv: p.get("argv").and_then(strs),
            team_id: s(p, "team_id"),
            signing_id: s(p, "signing_id"),
            bundle_id: s(p, "bundle_id"),
            requirements_met: p
                .get("requirements_met")
                .and_then(strs)
                .unwrap_or_default()
                .into_iter()
                .collect(),
            ..ProcessRecord::default()
        })
        .collect();
    let cases = doc["cases"].as_array().unwrap();
    assert!(
        cases.len() >= min_cases,
        "{}: {} cases",
        path.display(),
        cases.len()
    );
    let mut failures = vec![];
    for c in cases {
        let m = ProcessMatch::from_json_unchecked(&c["match"]);
        let tree = TreeScope::parse(c["tree"].as_str().unwrap()).unwrap();
        let got: Vec<i64> = group(&procs, &m, tree)
            .iter()
            .map(|p| i64::from(p.pid))
            .collect();
        let want: Vec<i64> = c["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_i64().unwrap())
            .collect();
        if got != want {
            failures.push(format!("{}: got {got:?}, want {want:?}", c["name"]));
        }
        // the same answer through a parsed rule, when the coordinator's schema would accept the match
        if let Ok(r) = ProtectionRule::from_json(
            &json!({"id": "v", "match": c["match"], "tree": c["tree"], "cap_fleet": {"slots": 0}}),
        ) {
            let via_rule: Vec<i64> = group(&procs, &r.match_, r.tree)
                .iter()
                .map(|p| i64::from(p.pid))
                .collect();
            assert_eq!(via_rule, want, "{} (parsed rule)", c["name"]);
        }
    }
    assert!(
        failures.is_empty(),
        "{}:\n{}",
        path.display(),
        failures.join("\n")
    );
}

/// The vectors the coordinator's own tests use (src/oarbank/contracts/fixtures).
#[test]
fn shared_vectors_agree_with_python() {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src/oarbank/contracts/fixtures/protection-match-vectors.json");
    check_vectors(p, 10);
}

/// Every match key, tree scope and edge case, generated from the Python matcher by vectors/gen.py.
#[test]
fn generated_vectors_agree_with_python() {
    check_vectors(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors/match-vectors.json"),
        40,
    );
}
