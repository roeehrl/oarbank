//! The macOS backend against the live kernel: real processes and real signals (a job is killed and the
//! co-tenant never signalled, a real pause and resume), the signal sources, the process summary and the
//! footprint probe.

#![cfg(target_os = "macos")]

mod common;

use std::collections::HashSet;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use common::TempDir;
use oarbank_protection::platform::macos;
use oarbank_protection::*;

/// A child in its own process group (the way the agent spawns jobs), killed on drop.
struct Spawned(Child);

impl Spawned {
    fn new(argv: &[&str]) -> Self {
        let c = Command::new(argv[0])
            .args(&argv[1..])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        Self(c)
    }

    fn pid(&self) -> i32 {
        self.0.id() as i32
    }
}

impl Drop for Spawned {
    fn drop(&mut self) {
        // SAFETY: plain syscalls on our own child's group.
        unsafe { libc::killpg(self.pid(), libc::SIGKILL) };
        let _ = self.0.wait();
    }
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks existence.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn state(pid: i32) -> String {
    let out = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A fleet job (own process group, registered) and a co-tenant (not registered): the registry kills the job
/// and refuses the co-tenant, which keeps running.
#[test]
fn real_job_is_killed_and_the_co_tenant_is_never_signalled() {
    let dir = TempDir::new("s16");
    let mut job = Spawned::new(&["/bin/sleep", "30"]);
    let cotenant = Spawned::new(&["/bin/sleep", "30"]);
    let j = Arc::new(DecisionJournal::new(
        Box::new(SystemClock),
        Some(Box::new(FileJournalSink::new(dir.path().join("journal")))),
    ));
    let reg = SpawnRegistry::native(Some(j), None);
    assert!(reg.register(job.pid(), Some(1), None));
    assert_eq!(
        reg.signal(cotenant.pid(), Signal::Kill, "must refuse"),
        Err(Refusal::NotRegistered(cotenant.pid()))
    );
    assert!(reg.signal(job.pid(), Signal::Kill, "evict").is_ok());
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut reaped = false;
    while !reaped && Instant::now() < deadline {
        reaped = job.0.try_wait().unwrap().is_some();
        sleep(Duration::from_millis(50));
    }
    assert!(reaped);
    assert!(alive(cotenant.pid())); // still alive, never touched
    let files: Vec<String> = std::fs::read_dir(dir.path().join("journal"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(files.iter().any(|f| f.starts_with("journal-")));
}

/// strict_yield on real processes: a registered fleet job is stopped within one tick (2 s) of a trigger and
/// continued afterwards.
#[test]
fn strict_yield_stops_a_real_job_within_two_seconds() {
    let job = Spawned::new(&["/bin/sleep", "30"]);
    let reg = SpawnRegistry::native(None, None);
    assert!(reg.register(job.pid(), Some(1), None));
    let mut c = DynamicController::new();
    let mut i = DynInputs::new(0.0, ProtectionMode::StrictYield, 8.0);
    i.jobs = vec![DynJob {
        pausable: true,
        ..DynJob::new(1)
    }];
    i.user_idle_s = 1.0;
    let t0 = Instant::now();
    let o = c.step(&i);
    assert_eq!(o.paused.iter().copied().collect::<Vec<_>>(), [1]);
    assert!(reg
        .signal(job.pid(), Signal::Stop, "pause_fleet")
        .is_ok());
    let mut stopped = false;
    while t0.elapsed() < Duration::from_secs(2) && !stopped {
        stopped = state(job.pid()).contains('T');
        if !stopped {
            sleep(Duration::from_millis(50));
        }
    }
    assert!(stopped);
    assert!(reg.signal(job.pid(), Signal::Cont, "resume").is_ok());
    assert!(reg.set_background(job.pid(), true, "lower_fleet").is_ok());
    assert!(reg.set_background(job.pid(), false, "restore").is_ok());
}

/// A lone busy process is runnable the whole time, on a core or waiting for one, so its stall is the share of the
/// time it waited: zero on a quiet machine, and whatever the neighbours take on a loaded one (a CI runner's VM, a
/// machine with a build running). Measured on a child process, which nothing else in this test binary shares.
#[test]
fn a_lone_busy_process_stalls_only_for_the_time_it_waits() {
    let job = Spawned::new(&["/bin/sh", "-c", "while :; do :; done"]);
    sleep(Duration::from_millis(100));
    let t0 = Instant::now();
    let a = macos::proc_counters(job.pid()).unwrap();
    sleep(Duration::from_secs(1));
    let b = macos::proc_counters(job.pid()).unwrap();
    let wall = t0.elapsed().as_secs_f64();
    let m = GroupMetrics::from_delta(b - a, wall);
    let runnable = (b.runnable_s - a.runnable_s) / wall;
    assert!(
        (0.8..1.2).contains(&runnable),
        "runnable {runnable:.2} of the time"
    );
    // runnable time includes the time on a core: the old formula, which counted it as waiting, read 0.5 or more
    // on a quiet machine, where the time on a core is nearly all of it
    let stall = m.cpu_stall.unwrap();
    assert!(
        (stall - (1.0 - m.cpu_cores)).abs() < 0.2,
        "stall {stall:.2} with {:.2} cores",
        m.cpu_cores
    );
    // the instruction and cycle counters count on a Mac, and are absent in a virtual machine's guest (no PMU
    // exposed: rusage reports 0), where ipc_ratio is unknown (tests/dynamic.rs and tests/controller.rs hold that
    // path with fixtures)
    if virtual_machine() {
        eprintln!("a virtual machine: instruction counters {:?}", m.instruction_counters);
    } else {
        assert_eq!(m.instruction_counters, Some(true), "{a:?} -> {b:?}");
        assert!(m.ipc.is_some_and(|x| x > 0.0));
    }
}

/// Whether this Mac is a virtual machine's guest (the hypervisor framework says so).
fn virtual_machine() -> bool {
    Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.hv_vmm_present"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "1")
}

#[test]
fn frontmost_is_found_when_there_is_a_front_app() {
    let front = macos::lsappinfo(&["front"]).and_then(|s| signals::frontmost::serial_number(&s));
    if front.is_none() {
        return; // headless
    }
    assert!(macos::frontmost_pid().is_some());
}

/// The front app as a personal-scope agent sees it from the user's session: its pid resolves to the bundle id
/// lsappinfo reports for it, and a rule on that bundle id active while it is in front is active. Run in a
/// logged-in GUI session with `cargo test -p oarbank-protection --test macos_live -- --ignored frontmost`.
#[test]
#[ignore = "needs a logged-in GUI session with an app in front"]
fn frontmost_detection_returns_the_front_apps_bundle_id() {
    let asn = macos::lsappinfo(&["front"])
        .and_then(|s| signals::frontmost::serial_number(&s))
        .expect("an app in front");
    let info = macos::lsappinfo(&["info", &asn]).expect("lsappinfo describes it");
    let bundle = info
        .split("bundleID=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("the front app has a bundle id")
        .to_string();
    let pid = macos::frontmost_pid().expect("the front app's pid");
    let path = macos::path(pid).expect("the front app's path");
    assert_eq!(macos::bundle_id_for_path(&path), Some(bundle.clone()));
    let mut ctl = ProtectionController::new(None, Host::native());
    ctl.apply(
        Some(&serde_json::json!({"node": {"mode": "fleet_first"},
                                 "rule": [{"id": "front", "match": {"bundle_id": bundle},
                                           "active_when": {"frontmost": true, "for_s": 0}, "cap_fleet": {"cpu_cores": 1}}]})),
        &LocalProtection::Absent,
    );
    let r = ctl.tick(&TickInputs::new(SystemClock.now(), MemorySignals::new(64.0, 20.0, 0)));
    assert_eq!(ctl.source_error(), None);
    assert_eq!(r.reports[0].reason, "active", "{bundle} in front");
    assert_eq!(r.constraint.cpu_cores, Some(1.0));
}

#[test]
fn presence_reads_the_hid_idle_time() {
    let r = platform::native_presence(None).read();
    assert!(r.idle_s.is_some_and(|s| s >= 0.0), "{r:?}");
    assert!(r.source == "hid" || r.source == "screen sharing", "{r:?}");
    assert!(macos::hid_idle_s().is_some());
}

/// Whether this Mac has an Apple GPU (the AGX driver's accelerator): a virtual machine's paravirtualized GPU does
/// not, and has no AGX user clients to read.
fn apple_gpu() -> bool {
    Command::new("/usr/sbin/ioreg")
        .args(["-r", "-d", "1", "-c", "AGXAccelerator"])
        .output()
        .is_ok_and(|o| !o.stdout.is_empty())
}

/// The AGX user clients are not matchable services; the registry walk must find them where an Apple GPU and a
/// window server (which holds one) run. Without an Apple GPU the source is unavailable, never an empty reading,
/// so GPU use counts as unknown there.
#[test]
fn gpu_time_is_read_from_the_agx_user_clients() {
    assert_eq!(macos::creator_pid("pid 1234, WindowServer"), Some(1234));
    assert_eq!(macos::creator_pid("WindowServer"), None);
    if !apple_gpu() {
        assert_eq!(macos::gpu_time_by_pid(), None);
        eprintln!("skipped: no Apple GPU here (a virtual machine's GPU has no AGX user clients)");
        return;
    }
    let ws = Command::new("/usr/bin/pgrep")
        .args(["-x", "WindowServer"])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    if !ws.success() {
        eprintln!("skipped: no window server, so possibly no AGX user client");
        return;
    }
    let by_pid = macos::gpu_time_by_pid().expect("AGX user clients found");
    assert!(!by_pid.is_empty());
}

/// The process picker's summary: same-user processes with the identity rules match on, excluding the agent's
/// own groups.
#[test]
fn summary_lists_own_processes_with_identity_and_honours_exclusions() {
    let mut t = ProcessTable::new(Box::new(macos::NativeProcessSource::new(None)));
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
    let now = SystemClock.now();
    let all = t.summary(5000, &HashSet::new(), now).unwrap();
    assert!(all.len() > 3);
    let mine = all
        .iter()
        .find(|r| r.pid == me)
        .expect("own process listed");
    assert!(mine.path.as_ref().is_some_and(|p| !p.is_empty()));
    assert!(mine.start_us > 0);
    assert!(mine.argv.as_ref().is_some_and(|a| !a.is_empty()));
    let without = t.summary(5000, &HashSet::from([me]), now).unwrap();
    assert!(!without.iter().any(|r| r.pid == me));
    assert_eq!(t.summary(2, &HashSet::new(), now).unwrap().len(), 2);
}

#[test]
fn snapshot_resolves_signing_argv_and_requirements_of_a_live_process() {
    // a distinct argv: other tests in this binary run `sleep 30` in parallel
    let job = Spawned::new(&["/bin/sleep", "29"]);
    sleep(Duration::from_millis(100));
    let cfg = ProtectionConfig::from_json(
        &serde_json::json!({"rule": [{"id": "s", "match": {"identifier": "com.apple.sleep", "requirement": "anchor apple",
                                                           "argv_regex": "^/bin/sleep 29$"}, "evict": {}}]}),
        "central",
    )
    .unwrap();
    let mut t = ProcessTable::new(Box::new(macos::NativeProcessSource::new(None)));
    let snap = t
        .snapshot(&cfg, &HashSet::new(), SystemClock.now())
        .unwrap();
    let p = snap
        .procs
        .iter()
        .find(|p| p.pid == job.pid())
        .expect("the child is listed");
    assert_eq!(p.comm, "sleep");
    assert_eq!(
        p.argv.as_deref(),
        Some(&["/bin/sleep".to_string(), "29".to_string()][..])
    );
    assert_eq!(p.signing_id.as_deref(), Some("com.apple.sleep"));
    assert_eq!(p.team_id, None); // platform binaries carry no Team ID
    assert!(p.requirements_met.contains("anchor apple"));
    assert_eq!(macos::start_time_us(job.pid()), Some(p.start_us));
    let g = matcher::group(&snap.procs, &cfg.rules[0].match_, cfg.rules[0].tree);
    assert_eq!(g.iter().map(|p| p.pid).collect::<Vec<_>>(), [job.pid()]);
    // excluded pids (the agent's own groups) never appear
    let snap = t
        .snapshot(&cfg, &HashSet::from([job.pid()]), SystemClock.now())
        .unwrap();
    assert!(!snap.procs.iter().any(|p| p.pid == job.pid()));
}

#[test]
fn bundle_ids_come_from_the_app_bundle() {
    let calc = "/System/Applications/Calculator.app/Contents/MacOS/Calculator";
    if std::path::Path::new(calc).exists() {
        assert_eq!(
            macos::bundle_id_for_path(calc).as_deref(),
            Some("com.apple.calculator")
        );
    }
    assert_eq!(macos::bundle_id_for_path("/bin/sleep"), None);
}

#[test]
fn footprint_probe_reads_real_processes() {
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
    let (cpu, fp) = macos::cpu_and_footprint(me).unwrap();
    assert!(fp > 0.0 && cpu > 0.0);
    assert!(macos::cpu_and_footprint(-1).is_none());
}

#[test]
fn the_native_host_ticks() {
    let mut ctl = ProtectionController::new(None, Host::native());
    ctl.apply(
        Some(&serde_json::json!({"node": {"mode": "moderate"},
                                 "rule": [{"id": "me", "match": {"path_contains": "macos_live"}, "reserve": {"cpu": 1}}]})),
        &LocalProtection::Absent,
    );
    let mut i = TickInputs::new(SystemClock.now(), MemorySignals::new(64.0, 20.0, 0));
    i.allocatable_cores = 8.0;
    let r = ctl.tick(&i);
    assert_eq!(ctl.source_error(), None);
    assert_eq!(r.reports[0].reason, "active"); // this test binary matches its own rule
    assert_eq!(r.constraint.reserved_cpu, 1.0);
    i.now += 2.0;
    let r = ctl.tick(&i);
    assert!(r.constraint.reserved_cpu == 1.0 && r.guard_level == GuardLevel::Clear);
}

/// `gpu_active` against the live AGX clients, read only: the controller runs with no fleet jobs, so it acts on
/// nothing. This test binary never touches the GPU, so its own rule is idle once two readings exist; a
/// same-user process that kept the GPU busy between two readings (when there is one) keeps its rule active.
#[test]
#[ignore = "reads the live GPU for a few seconds"]
fn gpu_active_rules_read_live_gpu_use() {
    let mut meter = macos::NativeMeter::new(None);
    let a = meter.gpu_times().expect("AGX user clients found");
    let t0 = SystemClock.now();
    sleep(Duration::from_secs(2));
    let b = meter.gpu_times().unwrap();
    let busy = GpuBusy::between(&a, &b, SystemClock.now() - t0).unwrap();
    // the IORegistry walk knows every client
    assert!(busy.unknown.is_empty());
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
    assert_eq!(busy.group([me]), Some(0.0));
    // the busiest same-user GPU process right now, if any
    let mut t = ProcessTable::new(Box::new(macos::NativeProcessSource::new(None)));
    let own = t.summary(5000, &HashSet::new(), SystemClock.now()).unwrap();
    let busiest = own
        .iter()
        .filter(|r| r.pid != me && busy.by_pid.get(&r.pid).copied().unwrap_or(0.0) >= 0.05)
        .max_by(|x, y| busy.by_pid[&x.pid].total_cmp(&busy.by_pid[&y.pid]));
    let exe = std::env::current_exe().unwrap();
    let mut rules = vec![serde_json::json!({"id": "me", "match": {"path_prefix": exe.to_str().unwrap()},
                                            "active_when": {"gpu_active": {"min_busy": 0.05}, "for_s": 0},
                                            "cap_fleet": {"gpu_jobs": 0}, "exit_after_s": 0})];
    if let Some(p) = busiest {
        // well under its measured share, which varies between intervals
        rules.push(serde_json::json!({"id": "busy", "match": {"path_prefix": p.path},
                                      "active_when": {"gpu_active": {"min_busy": 0.01}, "for_s": 0},
                                      "cap_fleet": {"gpu_jobs": 0}, "exit_after_s": 0}));
    }
    let mut ctl = ProtectionController::new(None, Host::native());
    ctl.apply(
        Some(&serde_json::json!({"node": {"mode": "fleet_first"}, "rule": rules})),
        &LocalProtection::Absent,
    );
    let mut i = TickInputs::new(SystemClock.now(), MemorySignals::new(64.0, 20.0, 0));
    let r = ctl.tick(&i);
    assert!(r.reports[0].active, "the first reading has no baseline: unknown counts as busy");
    sleep(Duration::from_secs(2));
    i.now = SystemClock.now();
    let r = ctl.tick(&i);
    assert_eq!((r.reports[0].active, r.reports[0].reason.as_str()), (false, "condition not met"));
    if let Some(p) = busiest {
        assert!(r.reports[1].active, "{:?} at {:.2} GPU busy", p.path, busy.by_pid[&p.pid]);
        assert_eq!(r.constraint.gpu_jobs, Some(0));
    }
    let mut top: Vec<(i32, f64)> = busy.by_pid.iter().map(|(&p, &b)| (p, b)).collect();
    top.sort_by(|x, y| y.1.total_cmp(&x.1));
    top.truncate(3);
    eprintln!("GPU busy, top pids: {top:?}; busiest same-user: {:?}", busiest.map(|p| &p.path));
}
