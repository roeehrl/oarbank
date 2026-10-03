//! The spawn registry, the only path to a signal.

mod common;

use std::collections::HashSet;
use std::sync::Arc;

use common::{FakeActuator, SeededRandom, TempDir};
use oarbank_protection::*;
use serde_json::json;

#[test]
fn signals_only_registered_groups_with_the_same_start_time() {
    let f = FakeActuator::new();
    f.set_start(100, Some(1));
    f.set_start(200, Some(2));
    let j = Arc::new(DecisionJournal::in_memory());
    let reg = f.registry(Some(j.clone()));
    assert!(reg.register(100, Some(7), None));
    assert!(reg.signal(100, Signal::Term, "test").is_ok());
    assert_eq!(
        reg.signal(200, Signal::Term, "test"),
        Err(Refusal::NotRegistered(200))
    ); // an owner process
    f.set_start(100, Some(99)); // pid recycled
    assert_eq!(
        reg.signal(100, Signal::Kill, "test"),
        Err(Refusal::IdentityChanged(100))
    );
    f.set_start(100, None);
    assert_eq!(
        reg.signal(100, Signal::Kill, "test"),
        Err(Refusal::Gone(100))
    );
    assert_eq!(f.delivered().iter().map(|d| d.0).collect::<Vec<_>>(), [100]);
    let recs = j.recent_records();
    let kinds: Vec<&str> = recs.iter().map(|r| r.kind()).collect();
    assert_eq!(
        kinds,
        [
            "actuation",
            "actuation_refused",
            "actuation_refused",
            "actuation_refused"
        ]
    );
    assert_eq!(recs[0].get("start_us"), Some(&json!("1")));
    assert_eq!(recs[0].get("attempt"), Some(&json!(7)));
    assert_eq!(recs[0].get("signal"), Some(&json!(Signal::Term.raw())));
    assert_eq!(recs[1].reason(), "S16_GUARD");
    assert_eq!(
        recs[1].get("why"),
        Some(&json!("pid 200 is not in the spawn registry"))
    );
    assert_eq!(recs[1].get("for"), Some(&json!("test")));
    assert!(
        DecisionJournal::s16_violations(&recs, &HashSet::from(["100@1".to_string()])).is_empty()
    );
    assert!(!DecisionJournal::s16_violations(&recs, &HashSet::new()).is_empty());
}

#[test]
fn background_goes_through_the_same_check() {
    let f = FakeActuator::new();
    f.set_start(300, Some(5));
    let j = Arc::new(DecisionJournal::in_memory());
    let reg = f.registry(Some(j.clone()));
    assert!(reg.register(300, Some(1), Some("svc")));
    assert!(reg.set_background(300, true, "lower_fleet").is_ok());
    assert_eq!(
        reg.set_background(301, true, "lower_fleet"),
        Err(Refusal::NotRegistered(301))
    );
    assert_eq!(f.0.lock().unwrap().background, [(300, true)]);
    let recs = j.recent_records();
    assert_eq!(recs[0].get("policy"), Some(&json!("background")));
    assert_eq!(recs[0].get("ok"), Some(&json!(true)));
    assert_eq!(recs[0].get("attempt"), Some(&json!(1)));
    assert_eq!(recs[1].kind(), "actuation_refused");
    assert_eq!(reg.member(1).unwrap().service.as_deref(), Some("svc"));
    reg.unregister(300);
    assert!(reg.all().is_empty());
    // a process whose start time cannot be read is never registered
    assert!(!reg.register(999, None, None));
}

/// The OS may decline an action on one of the agent's own groups: the caller learns it, and the journal says so.
#[test]
fn a_declined_actuation_is_reported_not_hidden() {
    let f = FakeActuator::new();
    f.set_start(300, Some(5));
    f.0.lock().unwrap().no_background = true;
    let j = Arc::new(DecisionJournal::in_memory());
    let reg = f.registry(Some(j.clone()));
    assert!(reg.register(300, Some(1), None));
    assert_eq!(reg.set_background(300, true, "lower_fleet"), Err(Refusal::Failed(300)));
    let recs = j.recent_records();
    assert_eq!((recs[0].kind(), recs[0].get("ok")), ("actuation", Some(&json!(false))));
    assert_eq!(
        Refusal::Failed(300).to_string(),
        "the OS did not carry out the action on group 300"
    );
}

/// PID-reuse fuzz: between a decision and its actuation the PID is recycled into an owner process at random;
/// no signal may ever land on it.
#[test]
fn pid_reuse_fuzz() {
    let f = FakeActuator::new();
    let reg = f.registry(None);
    let mut rng = SeededRandom::new(5000);
    let mut owner = HashSet::new();
    for round in 0..5000u64 {
        let pid = rng.int(1000, 1050) as i32;
        f.set_start(pid, Some(round * 10 + 1));
        if rng.boolean() {
            reg.register(pid, Some(round as i64), None);
            owner.remove(&pid);
        }
        if rng.int(0, 2) == 0 {
            // recycled into an owner process
            f.set_start(pid, Some(round * 10 + 5));
            owner.insert(pid);
        }
        let before = f.delivered().len();
        let _ = reg.signal(pid, Signal::Term, "fuzz");
        if owner.contains(&pid) {
            assert_eq!(f.delivered().len(), before);
        }
    }
}

#[test]
fn persists_and_adopts_across_restarts() {
    let f = FakeActuator::new();
    f.set_start(300, Some(42));
    let dir = TempDir::new("reg");
    let path = dir.path().join("spawn-registry.json");
    let store = || Some(Box::new(FileRegistryStore::new(&path)) as Box<dyn RegistryStore>);
    SpawnRegistry::new(Box::new(f.clone()), None, store()).register(300, Some(9), None);
    let on_disk: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        on_disk,
        json!([{"pid": 300, "start_us": "42", "attempt": 9, "service": null}])
    );
    let again = SpawnRegistry::new(Box::new(f.clone()), None, store());
    assert_eq!(again.member(9).map(|m| m.start_us), Some(42));
    f.set_start(300, Some(43));
    again.prune();
    assert!(again.member(9).is_none());
    assert!(!again.adopt(300, 42, Some(9)));
    assert!(again.adopt(300, 43, Some(9)));
    assert_eq!(
        SpawnRegistry::new(Box::new(f.clone()), None, store())
            .member(9)
            .map(|m| m.start_us),
        Some(43)
    );
}

#[test]
fn unsupported_platforms_never_actuate() {
    let reg = SpawnRegistry::new(Box::new(UnsupportedActuator), None, None);
    assert!(!reg.register(1, Some(1), None));
    assert_eq!(
        reg.signal(1, Signal::Kill, "x"),
        Err(Refusal::NotRegistered(1))
    );
}
