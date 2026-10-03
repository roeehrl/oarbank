//! The Linux backend against the live system: the process table and scheduler counters from procfs, the GPU
//! meter (DRM clients from fdinfo, unknown where the files cannot be read) and presence from logind.

#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::thread::sleep;
use std::time::{Duration, Instant};

use oarbank_protection::platform::linux;
use oarbank_protection::*;

#[test]
#[ignore = "reads every process's open files"]
fn gpu_time_comes_from_drm_fdinfo() {
    let mut meter = linux::NativeMeter::new();
    let a = meter.gpu_times().expect("/proc lists");
    sleep(Duration::from_secs(1));
    let b = meter.gpu_times().unwrap();
    let busy = GpuBusy::between(&a, &b, 1.0).unwrap();
    // this test holds no GPU: known, and zero
    let me = std::process::id() as i32;
    assert_eq!(linux::process_gpu(me), Some(Default::default()));
    assert_eq!(busy.group([me]), Some(0.0));
    // another user's open files cannot be read (without root): unknown, never zero
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        assert!(b.unknown.contains(&1), "pid 1 belongs to root");
        assert_eq!(busy.group([1]), None);
    }
    let gpus = std::fs::read_dir("/dev/dri")
        .map(|d| d.count())
        .unwrap_or(0);
    eprintln!(
        "/dev/dri entries: {gpus}; GPU clients: {:?}; unknown: {}",
        b.ns,
        b.unknown.len()
    );
}

#[test]
#[ignore = "reads the live logind sessions"]
fn presence_comes_from_logind() {
    let sessions = linux::sessions().expect("systemd-logind runs");
    let r = platform::native_presence().read();
    eprintln!("{} sessions; presence {r:?}", sessions.len());
    // whoever runs this test is logged in (ssh, a terminal or a desktop)
    assert!(sessions.iter().any(|s| s.is_person()), "{sessions:?}");
    assert!(r.source.starts_with("logind") || r.source.starts_with("unknown: logind has no idle time"), "{r:?}");
    assert!(r.idle_s.is_none_or(|s| s.is_finite() && s >= 0.0));
}

/// The table lists the owner's processes with the identity rules match on; another account's executable link
/// cannot be read without ptrace rights, and its path is unreadable (None), not empty.
#[test]
#[ignore = "reads the live process table"]
fn the_process_table_reads_procfs() {
    let me = std::process::id() as i32;
    let mut t = ProcessTable::new(Box::new(linux::NativeProcessSource::new()));
    let rows = t.summary(100_000, &HashSet::new(), SystemClock.now()).unwrap();
    let mine = rows.iter().find(|r| r.pid == me).expect("own process listed");
    let exe = std::env::current_exe().unwrap();
    assert_eq!(mine.path.as_deref(), exe.to_str());
    assert!(mine.argv.as_ref().is_some_and(|a| !a.is_empty()));
    assert!(!mine.comm.is_empty() && mine.comm.len() <= 15);
    assert_eq!(mine.start_us, linux::start_time_us(me).unwrap());
    assert!(mine.footprint_gb > 0.0);
    assert!(!rows.iter().any(|r| r.pid == 1), "pid 1 is root's, not a person's");
    // SAFETY: geteuid cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        let all = linux::reader().list(|_| true, &HashSet::new()).unwrap();
        let init = all.iter().find(|e| e.pid == 1).expect("pid 1");
        assert_eq!(init.path, None, "root's executable link is unreadable");
        assert!(linux::reader().cmdline(1).is_some(), "but its arguments are world-readable");
    }
    // excluded pids (the agent's own groups) never appear
    let rows = t.summary(100_000, &HashSet::from([me]), SystemClock.now()).unwrap();
    assert!(!rows.iter().any(|r| r.pid == me));
}

/// schedstat's run-queue wait is the stall macOS reads as runnable minus CPU time: a lone busy thread waits
/// little, more busy threads than cores wait about as long as they run.
#[test]
#[ignore = "loads every core for two seconds"]
fn scheduler_counters_measure_cpu_and_run_queue_wait() {
    let me = std::process::id() as i32;
    let mut c = linux::ProcessCounters::new();
    let spin = |ms: u64| {
        let end = Instant::now() + Duration::from_millis(ms);
        let mut x = 0.0f64;
        while Instant::now() < end {
            x += 1e-9;
            std::hint::black_box(x);
        }
    };
    let a = c.read(me).unwrap();
    spin(400);
    let b = c.read(me).unwrap();
    let m = GroupMetrics::from_delta(b - a, 0.4);
    assert!(m.cpu_cores > 0.5 && m.cpu_stall.unwrap() < 0.3, "{m:?}");
    assert_eq!(m.ipc, None, "no instruction counters on Linux");
    let cores = std::thread::available_parallelism().unwrap().get();
    let threads: Vec<_> = (0..cores * 2).map(|_| std::thread::spawn(move || spin(1500))).collect();
    sleep(Duration::from_millis(300));
    let a = c.read(me).unwrap();
    sleep(Duration::from_millis(1000));
    let b = c.read(me).unwrap();
    threads.into_iter().for_each(|t| t.join().unwrap());
    let m = GroupMetrics::from_delta(b - a, 1.0);
    eprintln!("{} busy threads on {cores} cores: {m:?}", cores * 2);
    assert!(m.cpu_stall.unwrap() > 0.3, "{m:?}");
}

#[test]
#[ignore = "reads the live process table"]
fn the_native_host_ticks() {
    let mut ctl = ProtectionController::new(None, Host::native());
    ctl.apply(
        Some(&serde_json::json!({"node": {"mode": "moderate"},
                                 "rule": [{"id": "me", "match": {"path_contains": "linux_live"}, "reserve": {"cpu": 1}}]})),
        &LocalProtection::Absent,
    );
    let mut i = TickInputs::new(SystemClock.now(), MemorySignals::new(8.0, 2.0, 0));
    i.allocatable_cores = 4.0;
    let r = ctl.tick(&i);
    assert_eq!(ctl.source_error(), None);
    assert_eq!(r.reports[0].reason, "active"); // this test binary matches its own rule
    assert_eq!(r.constraint.reserved_cpu, 1.0);
}
