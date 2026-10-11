//! Owner sources: progress rates and phases (driven by the controller for `protect.source` and `during`), the
//! rotation- and truncation-safe tail, where a path is read (the agent or a person's session helper), the watcher
//! and the event path. Synthetic files in scratch directories only.

mod common;

use std::collections::{BTreeSet, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::scratch;
use oarbank_protection::events::{EventSources, FastPath, PhaseHit, PhaseListener};
use oarbank_protection::sources::{
    name_matches, newest, Location, PersonReader, PersonReading, PhaseRule, RelayedSource, Start, Tail,
};
use oarbank_protection::*;
use serde_json::json;

fn append(path: &std::path::Path, text: &str) {
    OpenOptions::new().create(true).append(true).open(path).unwrap().write_all(text.as_bytes()).unwrap();
}

#[test]
fn jsonl_progress_counts_one_event_type_per_second_after_the_first_read() {
    let dir = scratch("progress");
    let f = dir.path().join("events-1.jsonl");
    append(&f, "{\"event\": \"step\"}\n");
    let mut s = FileOwnerSources::new();
    let spec = json!({"jsonl": format!("{}/events-*.jsonl", dir.path().display()), "event": "step"});
    assert_eq!(s.progress_rate("r", &spec, 0.0), None); // the first read only sets the offset
    append(&f, "{\"event\": \"step\"}\n{\"event\": \"other\"}\n{\"event\": \"step\", \"note\": \"\\\"step\\\"\"}\n");
    assert_eq!(s.progress_rate("r", &spec, 2.0), Some(1.0)); // 2 events in 2 s
    assert_eq!(s.progress("r", &spec, 4.0).unwrap().events, 0.0);
    // a quoted mention of the event name elsewhere in a line never counts: the type field decides
    append(&f, "{\"event\": \"other\", \"msg\": \"step\"}\n");
    assert_eq!(s.progress_rate("r", &spec, 6.0), Some(0.0));
    s.reset();
    assert_eq!(s.progress_rate("r", &spec, 8.0), None);
}

#[test]
fn an_event_key_can_be_nested_and_a_missing_file_reads_as_unreadable() {
    let dir = scratch("eventkey");
    let f = dir.path().join("e.jsonl");
    append(&f, "");
    let mut s = FileOwnerSources::new();
    let spec = json!({"jsonl": f.display().to_string(), "event_key": "meta.kind", "event": "backward_complete"});
    assert_eq!(s.progress("r", &spec, 0.0), None);
    append(&f, "{\"meta\": {\"kind\": \"backward_complete\"}}\n{\"meta\": {\"kind\": \"forward\"}}\nnot json\n");
    assert_eq!(s.progress_rate("r", &spec, 1.0), Some(1.0));
    assert_eq!(s.progress_status("r"), Some((true, "agent".to_string())));
    let gone = json!({"jsonl": dir.path().join("none-*.jsonl").display().to_string(), "event": "x"});
    assert_eq!(s.progress("g", &gone, 0.0), None);
    assert_eq!(s.progress_status("g"), Some((false, "agent".to_string())));
}

#[test]
fn log_regex_and_exec_progress() {
    let dir = scratch("logrx");
    let f = dir.path().join("train.log");
    append(&f, "start\n");
    let mut s = FileOwnerSources::new();
    let spec = json!({"log_regex": r"it=\d+", "path": f.display().to_string()});
    assert_eq!(s.progress_rate("r", &spec, 0.0), None);
    append(&f, "it=1 it=2\nnoise\nit=3\n");
    assert_eq!(s.progress_rate("r", &spec, 3.0), Some(1.0));
    let probe = if cfg!(windows) {
        let cmd = std::path::Path::new(&std::env::var("SystemRoot").unwrap()).join(r"System32\cmd.exe");
        json!({"exec": [cmd, "/c", "echo 4.5"]})
    } else {
        json!({"exec": ["/bin/echo", "4.5"]})
    };
    assert_eq!(s.progress_rate("p", &probe, 0.0), Some(4.5));
    assert_eq!(s.progress_rate("bad", &json!({"exec": []}), 0.0), None);
    assert_eq!(s.progress_rate("bad", &json!("x"), 0.0), None);
}

#[test]
fn phase_follows_the_newest_enter_or_exit_event_and_enter_soon_counts_as_on() {
    let dir = scratch("phase");
    let f = dir.path().join("phase.jsonl");
    append(&f, "{\"event\": \"upload_start\"}\n");
    let spec = json!({"jsonl": f.display().to_string(), "enter": "upload_start", "exit": "upload_end",
                      "enter_soon": "upload_soon"});
    let mut s = FileOwnerSources::new();
    assert!(s.phase_on("r#0", &spec), "the newest state already written is read at start");
    assert!(s.phase_on("r#0", &spec)); // nothing new: stays on
    append(&f, "{\"event\": \"upload_end\"}\n");
    assert!(!s.phase_on("r#0", &spec));
    append(&f, "{\"event\": \"upload_soon\"}\n");
    assert!(s.phase_on("r#0", &spec), "announced: on before it starts");
}

/// The shape an owner program with per-session event files writes: a new `events-<session>.jsonl` on every restart,
/// and the phase in a nested field of one event type.
#[test]
fn a_field_phase_follows_the_newest_session_file() {
    let dir = scratch("session-files");
    let pat = dir.path().join("events-*.jsonl").display().to_string();
    let hb = |phase: &str| {
        format!("{{\"event\":\"heartbeat_response\",\"response\":{{\"phase\":\"{phase}\"}},\"wall_time\":1}}\n")
    };
    let a = dir.path().join("events-aaa.jsonl");
    append(&a, &hb("training"));
    let spec = json!({"jsonl": pat, "event": "heartbeat_response", "field": "response.phase",
                      "on": ["weights_uploading", "merging_partitions"]});
    let mut s = FileOwnerSources::new();
    assert!(!s.phase_on("r#0", &spec));
    append(&a, "{\"event\":\"backward_complete\"}\n");
    append(&a, &hb("weights_uploading"));
    assert!(s.phase_on("r#0", &spec));
    // the program restarts: a new session file appears; the old file's rest is read first, then the new one
    std::thread::sleep(Duration::from_millis(30));
    append(&a, &hb("training"));
    let b = dir.path().join("events-bbb.jsonl");
    append(&b, &hb("merging_partitions"));
    assert!(s.phase_on("r#0", &spec), "the new file's state wins");
    append(&b, &hb("training"));
    assert!(!s.phase_on("r#0", &spec));
}

#[test]
fn the_tail_survives_rotation_truncation_and_partial_lines() {
    let dir = scratch("tail");
    let f = dir.path().join("log.jsonl");
    append(&f, "old\n");
    let mut t = Tail::new(&f);
    assert!(t.read(Start::End).unwrap().is_empty());
    // a partial line waits for its newline
    append(&f, "one\ntw");
    assert_eq!(t.read(Start::End).unwrap(), ["one"]);
    append(&f, "o\n");
    assert_eq!(t.read(Start::End).unwrap(), ["two"]);
    // truncated in place: read from the start again
    std::fs::write(&f, "three\n").unwrap();
    assert_eq!(t.read(Start::End).unwrap(), ["three"]);
    // rotated: the old file's last lines first, then the new file from its start
    append(&f, "four\nfive");
    std::fs::rename(&f, dir.path().join("log.jsonl.1")).unwrap();
    append(&f, "six\n");
    assert_eq!(t.read(Start::End).unwrap(), ["four", "five", "six"]);
    // the file disappears: unreadable, and it reads again when it comes back
    std::fs::remove_file(&f).unwrap();
    assert!(t.read(Start::End).is_err());
    append(&f, "seven\n");
    assert_eq!(t.read(Start::End).unwrap(), ["seven"]);
}

#[test]
fn a_phase_reader_starting_mid_file_skips_the_fragment() {
    let dir = scratch("lookback");
    let f = dir.path().join("p.jsonl");
    let line = "{\"event\": \"noise\", \"pad\": \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}\n";
    let mut text = String::from("{\"event\": \"enter\"}\n");
    while text.len() < (oarbank_protection::sources::PHASE_LOOKBACK as usize) + 4096 {
        text.push_str(line);
    }
    std::fs::write(&f, &text).unwrap();
    let mut t = Tail::new(&f);
    let lines = t.read(Start::Last(oarbank_protection::sources::PHASE_LOOKBACK)).unwrap();
    assert!(!lines.is_empty());
    assert!(lines.iter().all(|l| l.starts_with("{\"event\": \"noise\"")), "no fragment, no line older than the window");
    let r = PhaseRule::from_json(&json!({"enter": "enter", "exit": "exit"})).unwrap();
    assert_eq!(r.apply("{\"event\": \"enter\"}"), Some(true));
    assert_eq!(r.apply("{\"event\": \"exit\", \"x\": 1}"), Some(false));
    assert_eq!(r.apply("{\"event\": \"other\"}"), None);
    assert_eq!(r.apply("enter"), None);
}

#[test]
fn newest_matches_a_glob_in_the_last_component() {
    let dir = scratch("glob");
    append(&dir.path().join("a-1.log"), "x");
    std::thread::sleep(Duration::from_millis(20));
    append(&dir.path().join("a-2.log"), "x");
    append(&dir.path().join("b-3.txt"), "x");
    let pat = format!("{}/a-*.log", dir.path().display());
    assert!(newest(&pat).unwrap().ends_with("a-2.log"));
    assert!(newest(&format!("{}/none-*.log", dir.path().display())).is_none());
    assert!(newest(&format!("{}/b-3.txt", dir.path().display())).is_some());
    assert!(name_matches("events-*.jsonl", "events-abc.jsonl"));
    assert!(name_matches("a*b*c", "a-x-b-y-c"));
    assert!(!name_matches("a*b*c", "a-x-c"));
    assert!(!name_matches("events-*.jsonl", "events-.json"));
}

/// `~` is the person's home: the agent's own when it runs as the person, the session helper's in a system install
/// (the service account's own home was the bug: a source there was unreadable for good).
#[test]
fn where_a_path_is_read() {
    let home = std::env::var("HOME").unwrap_or_default();
    if !home.is_empty() {
        assert_eq!(Location::of("~/a/b.jsonl", false),
                   Location::Agent(std::path::PathBuf::from(&home).join("a/b.jsonl")));
    }
    assert_eq!(Location::of("~/a/b.jsonl", true), Location::Person { account: None, rel: "a/b.jsonl".into() });
    assert_eq!(Location::of("~ada/x.log", true), Location::Person { account: Some("ada".into()), rel: "x.log".into() });
    assert_eq!(Location::of("/Users/ada/Library/x.log", true),
               Location::Person { account: Some("ada".into()), rel: "Library/x.log".into() });
    assert_eq!(Location::of("/home/ada/x.log", true),
               Location::Person { account: Some("ada".into()), rel: "x.log".into() });
    assert_eq!(Location::of("C:\\Users\\ada\\AppData\\x.log", true),
               Location::Person { account: Some("ada".into()), rel: "AppData/x.log".into() });
    assert_eq!(Location::of("/Users/Shared/x.log", true), Location::Agent("/Users/Shared/x.log".into()));
    assert_eq!(Location::of("/var/log/x.log", true), Location::Agent("/var/log/x.log".into()));
    assert_eq!(Location::of("/Users/ada/x.log", false), Location::Agent("/Users/ada/x.log".into()));
}

/// A fake session hub: what helpers report, keyed by source.
#[derive(Default)]
struct FakeHub {
    wanted: Mutex<Vec<RelayedSource>>,
    readings: Mutex<std::collections::HashMap<String, PersonReading>>,
}

impl PersonReader for FakeHub {
    fn want(&self, s: Vec<RelayedSource>) {
        *self.wanted.lock().unwrap() = s;
    }
    fn reading(&self, key: &str) -> Option<PersonReading> {
        self.readings.lock().unwrap().get(key).copied()
    }
}

#[test]
fn a_system_install_relays_person_paths_and_holds_while_nobody_reads_them() {
    let hub = Arc::new(FakeHub::default());
    let mut s = FileOwnerSources::system(Some(hub.clone()));
    let cfg = ProtectionConfig::from_json(&json!({"rule": [{
        "id": "t", "match": {"name": "trainer"},
        "protect": {"metric": "progress_rate", "max_slowdown": 0.05,
                    "source": {"jsonl": "~/Library/App/events-*.jsonl", "event": "backward_complete"}},
        "during": [{"source": {"jsonl": "~/Library/App/events-*.jsonl", "event": "heartbeat_response",
                               "field": "response.phase", "on": ["uploading"]}, "pause_fleet": {"scope": "gpu"}}]}]}), "x").unwrap();
    s.configure(&cfg);
    let wanted = hub.wanted.lock().unwrap().clone();
    assert_eq!(wanted.len(), 2);
    assert!(wanted.iter().all(|w| w.account.is_none() && w.rel == "Library/App/events-*.jsonl"));
    assert!(wanted.iter().all(|w| w.spec.get("jsonl").is_none()), "the helper gets the rule, never the agent's path");
    let pspec = cfg.rules[0].protect.as_ref().unwrap().source_json.clone().unwrap();
    let dspec = cfg.rules[0].during[0].source_json.clone();
    // nobody logged in (no helper reports): progress unknown, and the phase counts as on (never looser)
    assert_eq!(s.progress("t", &pspec, 0.0), None);
    assert_eq!(s.progress_status("t"), Some((false, "helper".to_string())));
    assert!(s.phase_on("t#0", &dspec), "an unreadable phase holds the fleet back");
    let ph = s.phases();
    assert_eq!((ph[0].reader.as_str(), ph[0].readable), ("helper", false));
    // a helper reports: counts arrive as deltas, a new epoch is a new baseline
    let put = |events: u64, epoch: u64, on: bool| {
        let mut r = hub.readings.lock().unwrap();
        r.insert("t".into(), PersonReading { events, epoch, on: false, readable: true, event_t: 1.0 });
        r.insert("t#0".into(), PersonReading { events: 0, epoch, on, readable: true, event_t: 1.0 });
    };
    put(10, 1, false);
    assert_eq!(s.progress("t", &pspec, 1.0), None);
    put(16, 1, false);
    assert_eq!(s.progress_rate("t", &pspec, 4.0), Some(2.0));
    assert!(!s.phase_on("t#0", &dspec));
    put(3, 2, true);
    assert_eq!(s.progress("t", &pspec, 6.0), None, "the helper reconnected: a new baseline");
    assert!(s.phase_on("t#0", &dspec));
}

struct RecordingFastPath(Mutex<Vec<(PhaseHit, Instant)>>);

impl FastPath for RecordingFastPath {
    fn phase_on(&self, hit: &PhaseHit) -> usize {
        self.0.lock().unwrap().push((hit.clone(), Instant::now()));
        1
    }
}

/// An immediate rule's phase turns on between ticks: the watcher wakes, the phase is re-read and the fast path is
/// asked to pause within milliseconds; each phase change is journaled with the time it was seen (S25's evidence).
#[test]
fn the_event_path_pauses_an_immediate_phase_between_ticks() {
    let dir = scratch("events");
    let f = dir.path().join("events-1.jsonl");
    append(&f, "{\"event\": \"phase\", \"value\": \"idle\"}\n");
    let journal = Arc::new(DecisionJournal::in_memory());
    let mut s = EventSources::new(FileOwnerSources::new(), None, None);
    s.attach(Some(journal.clone()));
    let fast = Arc::new(RecordingFastPath(Mutex::new(vec![])));
    s.set_fast_path(fast.clone());
    let cfg = ProtectionConfig::from_json(&json!({"rule": [{
        "id": "t", "match": {"name": "trainer"}, "immediate": true,
        "during": [{"source": {"jsonl": format!("{}/events-*.jsonl", dir.path().display()), "event": "phase",
                               "field": "value", "on": ["upload"]},
                    "pause_fleet": {"scope": "gpu"}, "tags": ["uplink"]}]}]}), "x").unwrap();
    s.configure(&cfg);
    s.arm(&BTreeSet::from(["t".to_string()]), &HashSet::new());
    let spec = cfg.rules[0].during[0].source_json.clone();
    assert!(!s.phase_on("t#0", &spec));
    std::thread::sleep(Duration::from_millis(600)); // the watcher has the file
    let mut worst = 0.0f64;
    for round in 0..5 {
        let t0 = Instant::now();
        append(&f, "{\"event\": \"phase\", \"value\": \"upload\"}\n");
        let deadline = Instant::now() + Duration::from_secs(5);
        while fast.0.lock().unwrap().len() <= round && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let hits = fast.0.lock().unwrap();
        assert_eq!(hits.len(), round + 1, "no fast pause for round {round}");
        let (hit, at) = hits.last().unwrap().clone();
        drop(hits);
        assert_eq!((hit.rule.as_str(), hit.block, hit.pause, hit.via), ("t", 0, Some(ProtectionScope::Gpu), "watch"));
        worst = worst.max(at.duration_since(t0).as_secs_f64() * 1000.0);
        append(&f, "{\"event\": \"phase\", \"value\": \"idle\"}\n");
        std::thread::sleep(Duration::from_millis(400));
        assert!(!s.phase_on("t#0", &spec));
    }
    eprintln!("source write to fast pause request: worst of 5 = {worst:.1} ms");
    // a loaded shared machine: reported, gated loosely (the 50 ms p99 target is measured on real nodes)
    assert!(worst < 2000.0, "{worst} ms");
    let lat = s.latency().unwrap();
    assert_eq!(lat["n"], 5);
    let rec = journal.recent_records();
    let on: Vec<_> = rec.iter().filter(|r| r.kind() == "phase_change" && r.reason() == "PROTECTION_PHASE_ON").collect();
    assert_eq!(on.len(), 5);
    assert!(on.iter().all(|r| r.get("event_t").is_some() && r.get("tags").is_some()));
    let ph = s.phases();
    assert_eq!((ph[0].immediate, ph[0].tags.clone()), (true, vec!["uplink".to_string()]));
}

struct RecordingListener(Mutex<Vec<(String, bool, Vec<String>)>>);

impl PhaseListener for RecordingListener {
    fn phase_changed(&self, key: &str, on: bool, tags: &[String], _event_t: f64) {
        self.0.lock().unwrap().push((key.to_string(), on, tags.to_vec()));
    }
}

/// The phase listener (docs/design/sites.md) hears every phase change with its tags, on and off, immediate or not and
/// armed or not: the agent reports an `uplink` phase to its site at once instead of at the next heartbeat.
#[test]
fn the_phase_listener_hears_every_change_with_its_tags() {
    let dir = scratch("listener");
    let f = dir.path().join("events-1.jsonl");
    append(&f, "{\"event\": \"phase\", \"value\": \"idle\"}\n");
    let mut s = EventSources::new(FileOwnerSources::new(), None, None);
    let heard = Arc::new(RecordingListener(Mutex::new(vec![])));
    s.set_phase_listener(heard.clone());
    let cfg = ProtectionConfig::from_json(&json!({"rule": [{
        "id": "t", "match": {"name": "trainer"},
        "during": [{"source": {"jsonl": format!("{}/events-*.jsonl", dir.path().display()), "event": "phase",
                               "field": "value", "on": ["upload"]},
                    "cap_fleet": {"staging_mbps": 0}, "tags": ["uplink"]}]}]}), "x").unwrap();
    s.configure(&cfg);
    let spec = cfg.rules[0].during[0].source_json.clone();
    assert!(!s.phase_on("t#0", &spec));
    std::thread::sleep(Duration::from_millis(600));
    append(&f, "{\"event\": \"phase\", \"value\": \"upload\"}\n");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !heard.0.lock().unwrap().iter().any(|x| x.1) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(s.phase_on("t#0", &spec));
    append(&f, "{\"event\": \"phase\", \"value\": \"idle\"}\n");
    std::thread::sleep(Duration::from_millis(400));
    assert!(!s.phase_on("t#0", &spec));
    let h = heard.0.lock().unwrap().clone();
    let uplink = vec!["uplink".to_string()];
    assert!(h.contains(&("t#0".to_string(), true, uplink.clone())), "{h:?}");
    assert_eq!(h.last(), Some(&("t#0".to_string(), false, uplink)), "{h:?}");
}

/// A rule not armed (inactive, and its group absent) is never paused by the event path; nor is a rule that is not
/// immediate (the tick applies its phase).
#[test]
fn the_event_path_acts_only_for_armed_immediate_rules() {
    let dir = scratch("unarmed");
    let f = dir.path().join("p.jsonl");
    append(&f, "{\"event\": \"exit\"}\n");
    let mut s = EventSources::new(FileOwnerSources::new(), None, None);
    let fast = Arc::new(RecordingFastPath(Mutex::new(vec![])));
    s.set_fast_path(fast.clone());
    let cfg = ProtectionConfig::from_json(&json!({"rule": [
        {"id": "a", "match": {"name": "x"}, "immediate": true,
         "during": [{"source": {"jsonl": f.display().to_string(), "enter": "enter", "exit": "exit"}, "pause_fleet": {}}]},
        {"id": "b", "match": {"name": "y"},
         "during": [{"source": {"jsonl": f.display().to_string(), "enter": "enter", "exit": "exit"}, "pause_fleet": {}}]}]}),
        "x").unwrap();
    s.configure(&cfg);
    s.arm(&BTreeSet::from(["b".to_string()]), &HashSet::new());
    std::thread::sleep(Duration::from_millis(600));
    append(&f, "{\"event\": \"enter\"}\n");
    std::thread::sleep(Duration::from_millis(800));
    assert!(fast.0.lock().unwrap().is_empty(), "a is not armed and b is not immediate");
}
