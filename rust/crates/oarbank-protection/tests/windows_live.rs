//! The Windows backend against the live system: the process table and counters from the native process list,
//! the GPU meter (the GPU Engine performance counters) and presence from the sessions WTS lists.

#![cfg(windows)]

use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

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
    let mut meter = windows::NativeMeter::new(windows::Snapshots::shared());
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

#[test]
#[ignore = "reads the live sessions"]
fn presence_comes_from_the_session_list() {
    let sessions = windows::sessions().expect("WTS lists sessions");
    assert!(sessions.iter().any(|s| s.id == 0), "session 0 (services) always exists: {sessions:?}");
    let r = platform::native_presence().read();
    eprintln!("own session {}; sessions {sessions:?}; presence {r:?}", windows::own_session());
    if windows::own_session() != 0 {
        assert!(windows::own_idle_s().is_some());
    }
    assert!(r.source.starts_with("wts") || r.source.starts_with("unknown: no idle time"), "{r:?}");
}

/// The table lists the processes in people's sessions (1 and up) with their paths; session 0 (services, and the
/// ssh session this test runs in) is not the owner's.
#[test]
#[ignore = "reads the live process table"]
fn the_process_table_lists_the_people_s_sessions() {
    let me = std::process::id();
    let all = windows::processes().expect("the process list");
    let mine = all.iter().find(|p| p.pid == me).expect("this test is listed");
    assert!(mine.threads >= 1 && mine.start_us().is_some() && mine.cpu_s() >= 0.0);
    let mut t = ProcessTable::new(Box::new(windows::NativeProcessSource::new(windows::Snapshots::shared())));
    let rows = t.summary(100_000, &HashSet::new(), SystemClock.now()).unwrap();
    eprintln!("this test in session {}; {} processes in people's sessions", mine.session, rows.len());
    for r in rows.iter().take(6) {
        eprintln!("  {} {} {:?} {:?}", r.pid, r.comm, r.path, r.argv);
    }
    if mine.session == 0 {
        assert!(!rows.iter().any(|r| r.pid == me as i32), "session 0 is not a person's");
    }
    if let Some(explorer) = rows.iter().find(|r| r.comm.eq_ignore_ascii_case("explorer.exe")) {
        let path = explorer.path.as_deref().expect("a path needs no handle");
        assert!(path.to_ascii_lowercase().ends_with(r"\windows\explorer.exe"), "{path}");
        assert!(explorer.footprint_gb > 0.0);
    }
    // this test's own command line
    let argv = windows::command_line(me).expect("our own process opens");
    assert!(argv[0].to_ascii_lowercase().contains("windows_live"), "{argv:?}");
}

/// CPU time from the process list; the run-queue wait estimated from threads seen waiting for a core: a lone
/// busy thread waits little, twice as many busy threads as cores about as long as they run.
#[test]
#[ignore = "loads every core for a few seconds"]
fn counters_estimate_run_queue_wait_from_thread_states() {
    let me = std::process::id() as i32;
    let mut c = windows::ProcessCounters::new(windows::Snapshots::shared());
    let spin = |ms: u64| {
        let end = Instant::now() + Duration::from_millis(ms);
        let mut x = 0.0f64;
        while Instant::now() < end {
            x += 1e-9;
            std::hint::black_box(x);
        }
    };
    let sample = |c: &mut windows::ProcessCounters, secs: f64| {
        let a = c.read(me).unwrap();
        let t0 = Instant::now();
        // several samples through the interval, as the agent's ticks give
        while t0.elapsed().as_secs_f64() < secs {
            sleep(Duration::from_millis(550));
            c.read(me);
        }
        GroupMetrics::from_delta(c.read(me).unwrap() - a, t0.elapsed().as_secs_f64())
    };
    let busy = std::thread::spawn(move || spin(3000));
    sleep(Duration::from_millis(200));
    let m = sample(&mut c, 2.5);
    busy.join().unwrap();
    assert!(m.cpu_cores > 0.5 && m.cpu_stall.unwrap() < 0.3, "{m:?}");
    assert_eq!(m.ipc, None, "no instruction counters on Windows");
    let cores = std::thread::available_parallelism().unwrap().get();
    let threads: Vec<_> = (0..cores * 2).map(|_| std::thread::spawn(move || spin(6000))).collect();
    sleep(Duration::from_millis(300));
    let m = sample(&mut c, 5.0);
    threads.into_iter().for_each(|t| t.join().unwrap());
    eprintln!("{} busy threads on {cores} cores: {m:?}", cores * 2);
    assert!(m.cpu_stall.unwrap() > 0.25, "{m:?}");
}
