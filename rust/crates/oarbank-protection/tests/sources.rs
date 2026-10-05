//! Owner sources: progress rates and phase files (driven by the controller for `protect.source` and
//! `during`).

mod common;

use std::fs::OpenOptions;
use std::io::Write;

use common::scratch;
use oarbank_protection::sources::newest;
use oarbank_protection::*;
use serde_json::json;

fn append(path: &std::path::Path, text: &str) {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}

#[test]
fn jsonl_progress_counts_events_per_second_after_the_first_read() {
    let dir = scratch("progress");
    let f = dir.path().join("events-1.jsonl");
    append(&f, "{\"event\": \"step\"}\n");
    let mut s = FileOwnerSources::new();
    let spec =
        json!({"jsonl": format!("{}/events-*.jsonl", dir.path().display()), "event": "step"});
    assert_eq!(s.progress_rate("r", &spec, 0.0), None); // the first read only sets the offset
    append(
        &f,
        "{\"event\": \"step\"}\n{\"event\": \"other\"}\n{\"event\": \"step\"}\n",
    );
    assert_eq!(s.progress_rate("r", &spec, 2.0), Some(1.0)); // 2 events in 2 s
    assert_eq!(s.progress_rate("r", &spec, 4.0), Some(0.0));
    s.reset();
    assert_eq!(s.progress_rate("r", &spec, 6.0), None);
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
fn phase_follows_the_newest_enter_or_exit_event() {
    let dir = scratch("phase");
    let f = dir.path().join("phase.jsonl");
    append(&f, "{\"e\": \"upload_start\"}\n");
    let spec =
        json!({"jsonl": f.display().to_string(), "enter": "upload_start", "exit": "upload_end"});
    let mut s = FileOwnerSources::new();
    assert!(s.phase_on("r#0", &spec));
    assert!(s.phase_on("r#0", &spec)); // nothing new: stays on
    append(&f, "{\"e\": \"upload_end\"}\n");
    assert!(!s.phase_on("r#0", &spec));
    assert!(!s.phase_on("r#1", &json!({"jsonl": "/nonexistent"}))); // incomplete spec
}

#[test]
fn newest_matches_a_glob_in_the_last_component() {
    let dir = scratch("glob");
    append(&dir.path().join("a-1.log"), "x");
    std::thread::sleep(std::time::Duration::from_millis(20));
    append(&dir.path().join("a-2.log"), "x");
    append(&dir.path().join("b-3.txt"), "x");
    let pat = format!("{}/a-*.log", dir.path().display());
    let got = newest(&pat).unwrap();
    assert!(got.ends_with("a-2.log") || got.ends_with("a-1.log"));
    assert!(newest(&format!("{}/none-*.log", dir.path().display())).is_none());
    assert!(newest(&format!("{}/b-3.txt", dir.path().display())).is_some());
}
