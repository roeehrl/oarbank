//! The Windows GPU meter against the live GPU Engine performance counters.

#![cfg(windows)]

use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::Duration;

use oarbank_protection::platform::windows::{self, RawCounter, GPU_ENGINE_RUNNING_TIME};
use oarbank_protection::*;

#[test]
#[ignore = "reads the live performance counters"]
fn gpu_time_comes_from_the_gpu_engine_counters() {
    let mut c =
        RawCounter::open(GPU_ENGINE_RUNNING_TIME).expect("a WDDM 2 driver exposes GPU Engine");
    let items = c.collect().unwrap();
    assert!(
        items.iter().all(|(n, v)| n.starts_with("pid_") && *v >= 0),
        "{items:?}"
    );
    let mut meter = windows::NativeMeter::new();
    let a = meter.gpu_times().unwrap();
    sleep(Duration::from_secs(1));
    let b = meter.gpu_times().unwrap();
    let busy = GpuBusy::between(&a, &b, 1.0).unwrap();
    assert!(b.unknown.is_empty());
    // this test holds no GPU: zero
    assert_eq!(busy.group([std::process::id() as i32]), Some(0.0));
    eprintln!(
        "{} engine instances; GPU time by pid: {:?}",
        items.len(),
        b.ns
    );
}

/// A wildcard counter lists the instances that exist at each collection: a process started after the query
/// was opened appears in the next one.
#[test]
#[ignore = "reads the live performance counters"]
fn wildcard_counters_pick_up_new_instances() {
    let mut c = RawCounter::open(r"\Process(*)\ID Process").unwrap();
    let before = c.collect().unwrap();
    let mut child = Command::new("ping")
        .args(["-n", "30", "127.0.0.1"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let pid = i64::from(child.id());
    assert!(!before.iter().any(|(_, v)| *v == pid));
    sleep(Duration::from_millis(500));
    let after = c.collect().unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        after.iter().any(|(_, v)| *v == pid),
        "pid {pid} not among {} instances",
        after.len()
    );
}
