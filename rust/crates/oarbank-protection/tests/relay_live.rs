//! The relay end to end over the real session transport, in one account: the service side serves a socket in a
//! scratch directory, a session helper (this process's own, with HOME pointed at a scratch home) connects, reads
//! the source the service names under that home, and its phase reaches the service's event path through the hub.
//! Its own test binary: it sets HOME and OARBANK_SESSION_SOCKET for the whole process.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::time::{Duration, Instant};

use oarbank_protection::session::SessionHub;
use oarbank_protection::sources::{PersonReader, RelayedSource};
use oarbank_protection::*;
use serde_json::json;

#[test]
fn a_session_helper_relays_a_source_in_its_home() {
    let dir = tempfile::Builder::new().prefix("oarbank-relay-").tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join("Library/App")).unwrap();
    let f = home.join("Library/App/events-1.jsonl");
    std::fs::write(&f, "{\"event\":\"phase\",\"v\":\"idle\"}\n").unwrap();
    std::env::set_var("OARBANK_SESSION_SOCKET", dir.path().join("s.sock"));
    std::env::set_var("HOME", &home);
    let hub = SessionHub::new();
    platform::serve_sessions(hub.clone()).expect("serving");
    hub.want(vec![RelayedSource { key: "r#0".into(), kind: "phase".into(), account: None,
                                  rel: "Library/App/events-*.jsonl".into(),
                                  spec: json!({"event": "phase", "field": "v", "on": ["up"]}) }]);
    let (tx, rx) = std::sync::mpsc::channel();
    hub.set_source_hook(Box::new(move |k, t| {
        let _ = tx.send((k, t));
    }));
    std::thread::spawn(|| platform::run_session_helper());
    let deadline = Instant::now() + Duration::from_secs(30);
    while hub.reading("r#0").is_none_or(|r| !r.readable) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let r = hub.reading("r#0").expect("the helper reported the source");
    assert!(r.readable && !r.on);
    while rx.try_recv().is_ok() {}
    let t0 = Instant::now();
    use std::io::Write;
    std::fs::OpenOptions::new().append(true).open(&f).unwrap().write_all(b"{\"event\":\"phase\",\"v\":\"up\"}\n").unwrap();
    let (keys, _) = rx.recv_timeout(Duration::from_secs(10)).expect("the phase change reached the hub");
    eprintln!("helper-relayed phase change: {:.1} ms", t0.elapsed().as_secs_f64() * 1000.0);
    assert_eq!(keys, ["r#0"]);
    assert!(hub.reading("r#0").unwrap().on);
}
