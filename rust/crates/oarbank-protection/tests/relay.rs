//! The owner-source relay (D51): a session helper reads sources under its person's home and reports counts and
//! phases, never contents; the service's hub keeps them, checks who may report what, and wakes the event path.
//! Synthetic files in a scratch home only.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::scratch;
use oarbank_protection::relay::Relay;
use oarbank_protection::session::{Principal, Report, SessionHub, SourceReport, Watch, PROTOCOL};
use oarbank_protection::sources::{PersonReader, PersonReading, RelayedSource};
use serde_json::json;

fn append(path: &std::path::Path, text: &str) {
    use std::io::Write;
    std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap().write_all(text.as_bytes()).unwrap();
}

fn watch(account: Option<&str>) -> Watch {
    Watch {
        v: PROTOCOL,
        watch: vec![
            RelayedSource { key: "t".into(), kind: "progress".into(), account: account.map(str::to_string),
                            rel: "app/events-*.jsonl".into(), spec: json!({"event": "backward_complete"}) },
            RelayedSource { key: "t#0".into(), kind: "phase".into(), account: None, rel: "app/events-*.jsonl".into(),
                            spec: json!({"event": "heartbeat_response", "field": "response.phase", "on": ["uploading"]}) },
            RelayedSource { key: "esc".into(), kind: "phase".into(), account: None, rel: "../../etc/x".into(),
                            spec: json!({"enter": "a", "exit": "b"}) },
        ],
    }
}

#[test]
fn a_helper_reads_its_own_home_and_reports_counts_and_phases_only() {
    let home = scratch("relay-home");
    std::fs::create_dir_all(home.path().join("app")).unwrap();
    let f = home.path().join("app/events-1.jsonl");
    append(&f, "{\"event\":\"heartbeat_response\",\"response\":{\"phase\":\"training\"}}\n");
    let r = Relay::new(home.path().to_path_buf(), Some("ada".into()));
    r.set(watch(Some("ada")));
    let get = |r: &Relay, k: &str| r.readings().into_iter().find(|s| s.key == k).map(|s| s.reading);
    assert_eq!(get(&r, "t").unwrap().events, 0);
    assert!(!get(&r, "t#0").unwrap().on && get(&r, "t#0").unwrap().readable);
    assert!(!get(&r, "esc").unwrap().readable, "a path that leaves the home is never read");
    append(&f, "{\"event\":\"backward_complete\"}\n{\"event\":\"backward_complete\"}\n");
    append(&f, "{\"event\":\"heartbeat_response\",\"response\":{\"phase\":\"uploading\"}}\n");
    assert!(r.wait(Duration::from_secs(5)), "the watcher reports the phase change at once");
    let rs = r.readings();
    let line = serde_json::to_string(&rs).unwrap();
    assert!(!line.contains("backward_complete") && !line.contains("uploading"), "no content leaves: {line}");
    assert_eq!(get(&r, "t").unwrap().events, 2);
    assert!(get(&r, "t#0").unwrap().on);
    // a source for another person is left out
    let other = Relay::new(home.path().to_path_buf(), Some("bob".into()));
    other.set(watch(Some("ada")));
    assert!(other.readings().iter().all(|s| s.key != "t"));
}

#[test]
fn the_hub_keeps_asked_sources_only_and_wakes_the_event_path_on_a_phase_change() {
    let hub = SessionHub::new();
    let ada = Principal::Uid(501);
    hub.set_account(ada, Some("ada".into()));
    hub.want(watch(Some("ada")).watch);
    assert_eq!(hub.asked(ada).len(), 3);
    let bob = Principal::Uid(502);
    hub.set_account(bob, Some("bob".into()));
    assert_eq!(hub.asked(bob).iter().map(|s| s.key.as_str()).collect::<Vec<_>>(), ["t#0", "esc"]);
    let woken: Arc<Mutex<Vec<(Vec<String>, f64)>>> = Arc::default();
    let w = woken.clone();
    hub.set_source_hook(Box::new(move |k, t| w.lock().unwrap().push((k, t))));
    let rd = |on: bool, events: u64| PersonReading { events, epoch: 1, on, readable: true, event_t: 100.0 };
    let report = |srcs: Vec<SourceReport>| Report { v: PROTOCOL, sources: srcs, ..Report::default() };
    // bob may not report ada's progress source
    hub.accept(bob, report(vec![SourceReport { key: "t".into(), reading: rd(false, 99) }]), |_, _| true);
    assert_eq!(hub.reading("t"), None);
    hub.accept(ada, report(vec![SourceReport { key: "t".into(), reading: rd(false, 5) },
                                SourceReport { key: "t#0".into(), reading: rd(false, 0) }]), |_, _| true);
    assert_eq!(hub.reading("t").unwrap().events, 5);
    let n = woken.lock().unwrap().len();
    hub.accept(ada, report(vec![SourceReport { key: "t".into(), reading: rd(false, 7) },
                                SourceReport { key: "t#0".into(), reading: rd(true, 0) }]), |_, _| true);
    let w = woken.lock().unwrap().clone();
    assert_eq!(w.len(), n + 1, "a phase change wakes the event path");
    assert_eq!(w.last().unwrap(), &(vec!["t#0".to_string()], 100.0));
    assert!(hub.reading("t#0").unwrap().on);
    // a phase on at any person's helper wins (never looser)
    hub.accept(bob, report(vec![SourceReport { key: "t#0".into(), reading: rd(false, 0) }]), |_, _| true);
    assert!(hub.reading("t#0").unwrap().on);
    // the helper leaves: its sources are gone, and the event path hears of it
    hub.gone(ada);
    hub.gone(bob);
    assert_eq!(hub.reading("t#0"), None);
    assert!(woken.lock().unwrap().len() > n + 1);
}

#[test]
fn the_wire_format_round_trips() {
    let w = watch(None);
    let line = serde_json::to_string(&w).unwrap();
    assert_eq!(serde_json::from_str::<Watch>(&line).unwrap(), w);
    let r = Report { v: PROTOCOL, sources: vec![SourceReport { key: "k".into(),
        reading: PersonReading { events: 3, epoch: 2, on: true, readable: true, event_t: 1.5 } }], ..Report::default() };
    let line = serde_json::to_string(&r).unwrap();
    assert!(line.contains("\"events\":3"), "{line}");
    assert_eq!(serde_json::from_str::<Report>(&line).unwrap(), r);
    // an older helper's report without sources still reads
    let old = serde_json::to_string(&Report { v: PROTOCOL, ..Report::default() }).unwrap().replace(",\"sources\":[]", "");
    assert!(serde_json::from_str::<Report>(&old).unwrap().sources.is_empty());
}
