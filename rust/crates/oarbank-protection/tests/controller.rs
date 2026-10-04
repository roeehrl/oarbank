//! The per-tick controller (with S18), its journal records, and the wire shapes the coordinator reads (telemetry.protection, journal, processes).

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use common::{controller, no_cpu, proc_fp, tick, TempDir};
use oarbank_protection::*;
use serde_json::{json, Value};

fn gpu_app_central() -> Value {
    json!({"schema": 1, "node": {"mode": "fleet_first"},
           "rule": [{"id": "gpu-app", "match": {"path_contains": "Engine/bin"}, "tree": "descendants",
                     "active_when": "present", "reserve": {"mem_gb": "peak(300s).footprint + 2"}}]})
}

#[test]
fn a_reserving_rule_holds_memory_and_a_memory_hog_co_tenant_evicts_only_fleet_work() {
    let mut ctl = controller(gpu_app_central());
    let app = vec![
        proc_fp(10, "/A/Engine/bin/w", 4.0),
        ProcessRecord {
            footprint_gb: 1.0,
            ..ProcessRecord::new(11, 10, 1100, "/usr/bin/python3")
        },
    ];
    let jobs = vec![
        FleetJobView::new(1, Some(500), 2.0, 10.0, 1.5),
        FleetJobView::new(2, Some(501), 3.0, 20.0, 4.0),
    ];
    let r = ctl.evaluate(
        &tick(0.0, MemorySignals::new(64.0, 30.0, 0), jobs.clone()),
        &app,
        &no_cpu(),
    );
    assert_eq!(r.constraint.reserved_mem_gb, 7.0);
    assert!(r.evictions.is_empty());
    assert_eq!(r.guard_level, GuardLevel::Clear);
    // a co-tenant balloons: the guard hits the hard floor and evicts the largest fleet job within the tick
    let mut with_hog = app.clone();
    with_hog.push(proc_fp(99, "/Users/o/hog", 30.0));
    let r = ctl.evaluate(
        &tick(2.0, MemorySignals::new(64.0, 61.0, 3), jobs),
        &with_hog,
        &no_cpu(),
    );
    assert_eq!(r.guard_level, GuardLevel::Hard);
    assert!(r.constraint.no_admit);
    let ids: Vec<i64> = r.evictions.iter().map(|e| e.attempt_id).collect();
    assert!(ids.contains(&2)); // the largest footprint first
    assert!(ids.contains(&1)); // 2.0 > 1.25 × 1.5 declared: the overage rule
    assert!(ids.iter().all(|i| [1, 2].contains(i))); // only fleet attempts can be named
    assert_eq!(
        r.evictions[0],
        Eviction {
            attempt_id: 2,
            reason: "preempt_memory".into()
        }
    );
    assert_eq!(
        r.evictions[1],
        Eviction {
            attempt_id: 1,
            reason: "limit_mem".into()
        }
    );
}

#[test]
fn broken_local_file_never_loosens_the_central_config() {
    let dir = TempDir::new("local");
    let local = dir.path().join("protection.json");
    std::fs::write(&local, "{not json").unwrap();
    let mut ctl = ProtectionController::new(None, Host::unavailable());
    let central = json!({"schema": 1, "node": {"mode": "moderate"}, "rule": [{"id": "a", "match": {"name": "x"}, "evict": {}}]});
    ctl.apply(Some(&central), &LocalProtection::read(Some(&local)));
    assert_eq!(
        ctl.config()
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ["a"]
    );
    assert!(ctl.config_error().unwrap().starts_with("local: "));
    std::fs::write(&local, r#"{"schema": 1, "node": {"mode": "strict_yield"}}"#).unwrap();
    ctl.apply(
        Some(&json!({"schema": 1, "node": {"mode": "moderate"}})),
        &LocalProtection::read(Some(&local)),
    );
    assert_eq!(ctl.config().mode, ProtectionMode::StrictYield);
    assert_eq!(ctl.config_error(), None);
    assert_eq!(
        LocalProtection::read(Some(&dir.path().join("missing.json"))),
        LocalProtection::Absent
    );
    assert_eq!(LocalProtection::read(None), LocalProtection::Absent);
}

#[test]
fn a_broken_central_config_keeps_the_last_good_one() {
    let j = Arc::new(DecisionJournal::in_memory());
    let mut ctl = ProtectionController::new(Some(j.clone()), Host::unavailable());
    ctl.apply(
        Some(&json!({"node": {"mode": "fleet_first"}})),
        &LocalProtection::Absent,
    );
    ctl.apply(
        Some(&json!({"node": {"mode": "yolo"}})),
        &LocalProtection::Absent,
    );
    assert_eq!(ctl.config().mode, ProtectionMode::FleetFirst);
    assert_eq!(
        ctl.config_error(),
        Some("central: unknown protection mode yolo")
    );
    // a broken central part plus a good local file: the local file unions onto the last good config
    ctl.apply(
        Some(&json!({"node": {"mode": "yolo"}})),
        &LocalProtection::Json(json!({"node": {"pause": true}})),
    );
    assert!(ctl.config().pause);
    assert_eq!(ctl.config().mode, ProtectionMode::Moderate); // fleet_first ∪ the local default (moderate)
    let kinds: Vec<String> = j
        .recent_records()
        .iter()
        .map(|r| r.kind().to_string())
        .collect();
    assert_eq!(kinds, ["mode_change", "mode_change"]);
    let first = &j.recent_records()[0];
    assert_eq!(first.reason(), "PROTECTION_CONFIG");
    assert_eq!(first.get("mode"), Some(&json!("fleet_first")));
    assert_eq!(first.get("error"), Some(&json!(null)));
}

/// S18: a rule's pause/lower is in effect within enter_for_s + 2 samples of the rule becoming active.
#[test]
fn s18_static_actions_apply_within_two_samples() {
    let mut ctl = controller(json!({"schema": 1, "node": {"mode": "fleet_first"},
        "rule": [{"id": "calls", "match": {"bundle_id": ["us.zoom.xos"]}, "active_when": "present", "pause_fleet": {"scope": "all"}},
                 {"id": "xcode", "match": {"name": "xcodebuild"}, "active_when": "present", "lower_fleet": {"to": "e_cores"}}]}));
    let jobs = vec![
        FleetJobView {
            pausable: true,
            ..FleetJobView::new(1, Some(10), 1.0, 0.0, 1.0)
        },
        FleetJobView::new(2, Some(11), 1.0, 0.0, 1.0),
    ];
    let zoom = ProcessRecord {
        bundle_id: Some("us.zoom.xos".into()),
        ..ProcessRecord::new(50, 1, 1, "/Applications/zoom.us.app/Contents/MacOS/zoom.us")
    };
    let mem = MemorySignals::new(64.0, 20.0, 0);
    let mut first_applied = None;
    for k in 0..=10 {
        let t = f64::from(k) * 2.0;
        let procs = if k >= 1 { vec![zoom.clone()] } else { vec![] };
        let r = ctl.evaluate(&tick(t, mem, jobs.clone()), &procs, &no_cpu());
        if r.paused.contains(&1) && r.lowered.contains(&2) && first_applied.is_none() {
            first_applied = Some(t);
        }
    }
    // the condition appears at t=2; enter_for_s 4 + 2 samples of 2 s -> by t=2+4+4
    assert!(first_applied.is_some_and(|t| t <= 2.0 + 4.0 + 4.0));
}

#[test]
fn rule_evict_releases_every_fleet_job_and_journals_it() {
    let j = Arc::new(DecisionJournal::in_memory());
    let mut ctl = ProtectionController::new(Some(j.clone()), Host::unavailable());
    ctl.apply(
        Some(&json!({"node": {"mode": "fleet_first"},
                     "rule": [{"id": "game", "match": {"name": "game"}, "active_when": {"for_s": 0}, "evict": {}}]})),
        &LocalProtection::Absent,
    );
    let jobs = vec![
        FleetJobView::new(1, Some(10), 1.0, 0.0, 1.0),
        FleetJobView::new(2, Some(11), 1.0, 0.0, 1.0),
    ];
    let r = ctl.evaluate(
        &tick(0.0, MemorySignals::new(64.0, 20.0, 0), jobs),
        &[proc_fp(5, "/x/game", 1.0)],
        &no_cpu(),
    );
    assert_eq!(
        r.evictions
            .iter()
            .map(|e| (e.attempt_id, e.reason.as_str()))
            .collect::<Vec<_>>(),
        [(1, "preempt_protection"), (2, "preempt_protection")]
    );
    let ev = j
        .recent_records()
        .into_iter()
        .find(|r| r.kind() == "attempt_evicted")
        .unwrap();
    assert_eq!(ev.get("rule"), Some(&json!("rule:game")));
    assert_eq!(ev.get("attempts"), Some(&json!([1, 2])));
}

#[test]
fn guards_brakes_and_gpu_policy_reach_the_constraint() {
    let mut ctl =
        controller(json!({"node": {"mode": "fleet_first", "pause": true, "gpu_jobs": "never"}}));
    let mut i = tick(0.0, MemorySignals::new(64.0, 20.0, 0), vec![]);
    i.thermal = Thermal::SERIOUS;
    i.on_battery = true;
    let r = ctl.evaluate(&i, &[], &no_cpu());
    assert!(r.constraint.no_admit);
    assert_eq!(r.constraint.binding["admit"], "local:pause");
    assert_eq!(r.constraint.cpu_cores, Some(0.0));
    assert_eq!(r.constraint.gpu_jobs, Some(0));
    assert_eq!(r.constraint.binding["gpu_jobs"], "node:gpu_jobs");
}

#[test]
fn journal_records_transitions_rungs_and_constraints() {
    let j = Arc::new(DecisionJournal::in_memory());
    let mut ctl = ProtectionController::new(Some(j.clone()), Host::unavailable());
    ctl.apply(
        Some(&json!({"node": {"mode": "fleet_first"},
                     "rule": [{"id": "calls", "match": {"name": "zoom"}, "pause_fleet": {}, "active_when": {"for_s": 0}}]})),
        &LocalProtection::Absent,
    );
    let jobs = vec![FleetJobView {
        pausable: true,
        ..FleetJobView::new(1, Some(10), 1.0, 0.0, 1.0)
    }];
    let mem = MemorySignals::new(64.0, 20.0, 0);
    ctl.evaluate(
        &tick(0.0, mem, jobs.clone()),
        &[proc_fp(5, "/x/zoom", 0.5)],
        &no_cpu(),
    );
    ctl.evaluate(
        &tick(2.0, MemorySignals::new(64.0, 58.0, 0), jobs),
        &[proc_fp(5, "/x/zoom", 0.5)],
        &no_cpu(),
    );
    let recs = j.recent_records();
    let kinds: Vec<&str> = recs.iter().map(|r| r.kind()).collect();
    assert_eq!(
        kinds,
        [
            "mode_change",
            "rule_active",
            "attempt_paused",
            "rung_change",
            "constraint",
            "guard_fired",
            "constraint"
        ]
    );
    let active = &recs[1];
    assert_eq!(active.get("rule"), Some(&json!("calls")));
    assert_eq!(
        active.get("signals"),
        Some(&json!({"cpu_cores": 0.0, "footprint_gb": 0.5, "processes": 1.0}))
    );
    assert_eq!((recs[2].reason(), recs[2].get("attempts")), ("PROTECTION_PAUSE", Some(&json!([1]))));
    let rung = &recs[3];
    assert_eq!(rung.reason(), "RUNG_5");
    assert_eq!(
        (rung.get("from"), rung.get("to")),
        (Some(&json!(0)), Some(&json!(5)))
    );
    // a whole-fleet pause holds GPU jobs at zero too (gpu_jobs = when_no_gpu_protected)
    assert_eq!(
        recs[4].get("constraint").unwrap()["binding"],
        json!({"gpu_jobs": "protection:gpu"})
    );
    assert_eq!(recs[5].reason(), "MEMORY_SOFT");
    assert_eq!(recs[5].get("free_pct"), Some(&json!(9.4)));
    assert_eq!(
        recs[6].get("constraint").unwrap()["binding"],
        json!({"admit": "guard:memory", "gpu_jobs": "protection:gpu"})
    );
    // seq is per node and monotonic; the coordinator's _ingest_journal needs seq, t, kind, reason
    let seqs: Vec<i64> = recs.iter().map(JournalRecord::seq).collect();
    assert_eq!(seqs, (1..=7).collect::<Vec<_>>());
    for r in &recs {
        assert!(r.get("t").and_then(Value::as_f64).is_some());
    }
}

#[test]
fn telemetry_and_status_shapes() {
    let mut ctl = controller(gpu_app_central());
    let r = ctl.evaluate(
        &tick(0.0, MemorySignals::new(64.0, 30.0, 0), vec![]),
        &[proc_fp(10, "/A/Engine/bin/w", 4.0)],
        &no_cpu(),
    );
    let t = serde_json::to_value(ctl.telemetry(&r)).unwrap();
    assert_eq!(t["mode"], json!("fleet_first"));
    assert_eq!(t["active"], json!(["gpu-app"]));
    assert_eq!(
        t["rules"],
        json!([{"id": "gpu-app", "active": true, "processes": 1, "unreadable": 0, "cpu_cores": 0.0,
                                    "footprint_gb": 4.0, "reason": "active"}])
    );
    assert_eq!(t["constraint"]["reserved_mem_gb"], json!(6.0));
    assert_eq!(
        t["constraint"]["binding"],
        json!({"reserve_mem": "rule:gpu-app"})
    );
    assert_eq!(t["guard_reason"], json!(""));
    assert_eq!(t["config_error"], json!(null));
    assert_eq!(t["rung"], json!(0));
    assert_eq!(t["budget_cores"], json!(null));
    assert_eq!(t["dynamic"], json!(""));
    let s = ctl.status_json();
    for k in [
        "config",
        "error",
        "rules",
        "guard",
        "constraint",
        "rung",
        "dynamic",
        "budget_cores",
    ] {
        assert!(s.get(k).is_some(), "status missing {k}");
    }
    assert_eq!(s["guard"], json!({"level": "clear", "reason": ""}));
}

#[test]
fn journal_pending_acknowledge_and_bounds() {
    let j = DecisionJournal::in_memory();
    for k in 0..2100 {
        j.record(
            "rule_active",
            "PROTECTION_ACTIVE",
            Some("r"),
            serde_json::Map::from_iter([("n".to_string(), json!(k))]),
        );
    }
    assert_eq!(j.recent_records().len(), 500);
    let p = j.pending(200);
    assert_eq!(p.len(), 200);
    assert_eq!(p[0].seq(), 101); // the oldest 100 fell out of the 2000-record backlog
    j.acknowledge(1000);
    assert_eq!(j.pending(5000).len(), 1100);
    assert_eq!(j.pending(1)[0].seq(), 1001);
    let wire = serde_json::to_value(&p[0]).unwrap();
    assert_eq!(wire["kind"], json!("rule_active"));
    assert_eq!(wire["rule"], json!("r"));
    assert_eq!(wire["n"], json!(100));
}

#[test]
fn journal_file_sink_writes_daily_jsonl() {
    let dir = TempDir::new("journal");
    let j = DecisionJournal::new(
        Box::new(SystemClock),
        Some(Box::new(FileJournalSink::new(dir.path().join("journal")))),
    );
    j.record("actuation", "test", None, serde_json::Map::new());
    j.record("actuation", "test", None, serde_json::Map::new());
    let files: Vec<_> = std::fs::read_dir(dir.path().join("journal"))
        .unwrap()
        .flatten()
        .collect();
    assert_eq!(files.len(), 1);
    let name = files[0].file_name().to_string_lossy().into_owned();
    assert!(name.starts_with("journal-") && name.ends_with(".jsonl"));
    let text = std::fs::read_to_string(files[0].path()).unwrap();
    assert_eq!(text.lines().count(), 2);
    let first: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(first["seq"], json!(1));
    j.prune(7); // fresh files survive
    assert_eq!(
        std::fs::read_dir(dir.path().join("journal"))
            .unwrap()
            .count(),
        1
    );
}

// ---- a full tick against a scripted host

#[derive(Clone, Default)]
struct Script {
    procs: Vec<RawProcess>,
    counters: HashMap<i32, ProcCounters>,
    gpu: Option<GpuTimes>,
    front: Option<i32>,
    calls: Vec<String>,
}

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Script>>);

impl ProcessSource for Shared {
    fn list(&mut self, excluding: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        let s = self.0.lock().unwrap();
        Ok(s.procs
            .iter()
            .filter(|p| !excluding.contains(&p.pid))
            .cloned()
            .collect())
    }
    fn argv(&mut self, pid: i32, _: u64) -> Option<Vec<String>> {
        self.0.lock().unwrap().calls.push(format!("argv {pid}"));
        Some(vec![format!("p{pid}"), "--flag".into()])
    }
    fn signing(&mut self, pid: i32) -> SigningIdentity {
        self.0.lock().unwrap().calls.push(format!("signing {pid}"));
        SigningIdentity {
            team_id: (pid == 7).then(|| "ABCDE12345".into()),
            signing_id: Some(format!("id.{pid}")),
        }
    }
    fn satisfies(&mut self, pid: i32, _: &str) -> bool {
        self.0.lock().unwrap().calls.push(format!("req {pid}"));
        pid == 7
    }
    fn bundle_id(&mut self, path: &str) -> Option<String> {
        path.contains(".app/").then(|| "com.example.app".into())
    }
}

impl Meter for Shared {
    fn proc_counters(&mut self, pid: i32) -> Option<ProcCounters> {
        self.0.lock().unwrap().counters.get(&pid).copied()
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        self.0.lock().unwrap().gpu.clone()
    }
    fn front(&mut self) -> FrontReading {
        let front = self.0.lock().unwrap().front.map_or(Front::Unknown, Front::App);
        FrontReading::new(front, "test")
    }
}

fn raw(pid: i32, ppid: i32, path: &str, cpu_s: f64) -> RawProcess {
    RawProcess {
        pid,
        ppid,
        start_us: 1000 + pid as u64,
        path: Some(path.into()),
        comm: String::new(),
        cpu_s,
        footprint_gb: 1.0,
    }
}

#[test]
fn tick_measures_protected_groups_and_feeds_the_dynamic_layer() {
    let host = Shared::default();
    {
        let mut s = host.0.lock().unwrap();
        s.procs = vec![
            raw(7, 1, "/Applications/Render.app/Contents/MacOS/t", 0.0),
            raw(8, 7, "/bin/helper", 0.0),
            raw(900, 1, "/fleet/job", 0.0),
        ];
        s.gpu = Some(GpuTimes::known(HashMap::from([(7, 0.0), (900, 0.0)])));
        s.counters = HashMap::from([(7, ProcCounters::default()), (8, ProcCounters::default())]);
        s.front = Some(7);
    }
    let mut ctl = ProtectionController::new(
        None,
        Host {
            processes: Box::new(host.clone()),
            meter: Box::new(host.clone()),
            sources: Box::new(NoOwnerSources),
            os: None,
        },
    );
    ctl.apply(
        Some(&json!({"node": {"mode": "moderate"},
                     "rule": [{"id": "app", "match": {"team_id": "ABCDE12345"}, "tree": "descendants",
                               "active_when": {"for_s": 0}, "protect": {"metric": "cpu_stall", "max": 0.1}}]})),
        &LocalProtection::Absent,
    );
    let mut i = TickInputs::new(0.0, MemorySignals::new(64.0, 20.0, 0));
    i.fleet_pids = HashSet::from([900]);
    i.allocatable_cores = 10.0;
    i.user_idle_s = 0.0;
    i.jobs = vec![FleetJobView::new(1, Some(900), 1.0, 0.0, 1.0)];
    let r0 = ctl.tick(&i);
    assert_eq!(r0.reports[0].processes, 2); // the team match plus its descendant; the fleet job is excluded
    assert!(ctl.evaluator.groups["app"].iter().all(|p| p.pid != 900));
    // identity resolved once per process: signing (a rule needs it) and requirements none, argv not needed
    {
        let s = host.0.lock().unwrap();
        assert_eq!(
            s.calls.iter().filter(|c| c.starts_with("signing")).count(),
            2
        );
        assert!(!s.calls.iter().any(|c| c.starts_with("argv")));
    }
    // second tick: the protected group stalls (runnable 4 s for 1 s of CPU over 2 s) and uses the GPU
    {
        let mut s = host.0.lock().unwrap();
        s.procs[0].cpu_s = 1.0;
        s.counters = HashMap::from([
            (
                7,
                ProcCounters {
                    cpu_s: 1.0,
                    runnable_s: 4.0,
                    ..Default::default()
                },
            ),
            (8, ProcCounters::default()),
        ]);
        s.gpu = Some(GpuTimes::known(HashMap::from([(7, 3e9), (900, 1e9)])));
    }
    i.now = 2.0;
    let r = ctl.tick(&i);
    assert_eq!(
        host.0
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.starts_with("signing"))
            .count(),
        2
    ); // cached
    assert_eq!(r.reports[0].cpu_cores, 0.5); // 1 s of CPU over 2 s
                                             // pressure 0.75 / 0.1 = 7.5, but L1 steps once a minute: the budget is still the allocatable 10
    assert_eq!(r.budget_cores, Some(10.0));
    // a minute later, still stalled: the L1 step takes the budget back, L2 has lowered the fleet job
    {
        let mut s = host.0.lock().unwrap();
        s.counters.insert(
            7,
            ProcCounters {
                cpu_s: 2.0,
                runnable_s: 8.0,
                ..Default::default()
            },
        );
    }
    i.now = 62.0;
    let r = ctl.tick(&i);
    assert_eq!(r.budget_cores, Some(0.0));
    assert!(r.constraint.no_admit);
    assert_eq!(r.constraint.binding["admit"], "l1:budget");
    assert_eq!(r.constraint.cpu_cores, Some(0.0));
    assert!(r.lowered.contains(&1));
    assert_eq!(r.rung, 3);
    // the process picker: rows by resource use, identity resolved, the fleet job excluded
    ctl.processes_requested = true;
    let rows = ctl.process_summary(62.0, &HashSet::from([900])).unwrap();
    assert_eq!(rows.iter().map(|r| r.pid).collect::<Vec<_>>(), [7, 8]);
    let row = serde_json::to_value(&rows[0]).unwrap();
    assert_eq!(
        row,
        json!({"pid": 7, "ppid": 1, "start_us": 1007, "path": "/Applications/Render.app/Contents/MacOS/t",
                           "comm": "", "argv": ["p7", "--flag"], "team_id": "ABCDE12345", "signing_id": "id.7",
                           "bundle_id": "com.example.app", "cpu_cores": 0.0, "footprint_gb": 1.0})
    );
    assert!(ctl.process_summary(63.0, &HashSet::new()).is_none()); // not again until requested or 5 minutes pass
    assert!(ctl.process_summary(400.0, &HashSet::new()).is_some());
}

/// Without instruction and cycle counters (a VM's guest: rusage reports 0 for both while the process runs), an
/// `ipc_ratio` rule's metric is unknown, not a ratio of zeros (dynamic.rs: an unknown ipc_ratio never grows the
/// budget), and the node reports the rule; once the counters count, it is measured and the report goes.
#[test]
fn an_ipc_rule_without_instruction_counters_is_unknown_and_holds_the_budget() {
    let host = Shared::default();
    {
        let mut s = host.0.lock().unwrap();
        s.procs = vec![raw(7, 1, "/opt/build/cc", 0.0)];
        s.counters = HashMap::from([(7, ProcCounters::default())]);
    }
    let mut ctl = scripted(
        &host,
        json!({"node": {"mode": "moderate"},
               "rule": [{"id": "build", "match": {"path_prefix": "/opt/build/"}, "active_when": {"for_s": 0},
                         "protect": {"metric": "ipc_ratio", "max_slowdown": 0.1}}]}),
    );
    let mut i = TickInputs::new(0.0, MemorySignals::new(64.0, 20.0, 0));
    i.allocatable_cores = 8.0;
    let counters = |cpu_s: f64, instructions: f64, cycles: f64| ProcCounters {
        cpu_s,
        runnable_s: cpu_s,
        instructions,
        cycles,
        pageins: 0.0,
    };
    let mut r = ctl.tick(&i);
    for t in 1..=3 {
        host.0
            .lock()
            .unwrap()
            .counters
            .insert(7, counters(t as f64, 0.0, 0.0));
        i.now = 2.0 * t as f64;
        r = ctl.tick(&i);
    }
    assert!(r.reports[0].active);
    assert_eq!(ctl.telemetry(&r).no_instruction_counters, ["build"]);
    // the counters count: measured, no longer reported
    for t in 4..=5 {
        let c = t as f64;
        host.0
            .lock()
            .unwrap()
            .counters
            .insert(7, counters(c, 3e9 * c, 1e9 * c));
        i.now = 2.0 * c;
        r = ctl.tick(&i);
    }
    assert!(ctl.telemetry(&r).no_instruction_counters.is_empty());
}

fn scripted(host: &Shared, central: Value) -> ProtectionController {
    let mut ctl = ProtectionController::new(
        None,
        Host {
            processes: Box::new(host.clone()),
            meter: Box::new(host.clone()),
            sources: Box::new(NoOwnerSources),
            os: None,
        },
    );
    ctl.apply(Some(&central), &LocalProtection::Absent);
    ctl
}

/// fleet_first has no implicit protections, yet a rule active while its app is in front still needs the front
/// app: the tick reads it for the rule (the demo node never matched its "writing" rule).
#[test]
fn a_frontmost_rule_reads_the_front_app_in_every_mode() {
    let host = Shared::default();
    {
        let mut s = host.0.lock().unwrap();
        s.procs = vec![
            raw(40, 1, "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit", 0.0),
            raw(41, 1, "/bin/zsh", 0.0),
        ];
        s.front = Some(40);
    }
    let mut ctl = scripted(
        &host,
        json!({"node": {"mode": "fleet_first"},
               "rule": [{"id": "writing", "match": {"bundle_id": "com.example.app"},
                         "active_when": {"frontmost": true, "for_s": 0}, "pause_fleet": {"scope": "all"}}]}),
    );
    let mut i = TickInputs::new(0.0, MemorySignals::new(64.0, 20.0, 0));
    i.jobs = vec![FleetJobView {
        pausable: true,
        ..FleetJobView::new(1, Some(900), 1.0, 0.0, 1.0)
    }];
    let r = ctl.tick(&i);
    assert!(r.reports[0].active && r.paused.contains(&1), "{:?}", r.reports);
    // the shell in front instead: the rule's condition no longer holds
    host.0.lock().unwrap().front = Some(41);
    i.now = 2.0;
    ctl.tick(&i);
    assert!(ctl.evaluator.states["writing"].clear_since.is_some());
}

/// A `gpu_active` rule over ticks: the controller reads GPU time once a tick and the busy fraction is the
/// change since the last reading. The first reading has no baseline and a missing source is unknown: both count
/// as busy (never looser).
#[test]
fn a_gpu_active_rule_reads_gpu_time_between_ticks() {
    let host = Shared::default();
    let gpu = |s: &Shared, game: f64, other: f64| {
        s.0.lock().unwrap().gpu = Some(GpuTimes::known(HashMap::from([(50, game), (60, other)])));
    };
    {
        let mut s = host.0.lock().unwrap();
        s.procs = vec![raw(50, 1, "/opt/game/bin/game", 0.0), raw(60, 1, "/usr/bin/other", 0.0)];
    }
    gpu(&host, 0.0, 0.0);
    let mut ctl = scripted(
        &host,
        json!({"node": {"mode": "fleet_first", "gpu_jobs": "always", "defaults": {"enter_for_s": 4, "exit_after_s": 0}},
               "rule": [{"id": "game", "match": {"path_prefix": "/opt/game/"},
                         "active_when": {"gpu_active": {"min_busy": 0.2}}, "cap_fleet": {"gpu_jobs": 0}}]}),
    );
    let mut i = TickInputs::new(0.0, MemorySignals::new(64.0, 20.0, 0));
    let mut at = |ctl: &mut ProtectionController, t: f64| {
        i.now = t;
        let r = ctl.tick(&i);
        (r.reports[0].active, r.constraint.gpu_jobs)
    };
    // first reading: unknown, so the condition starts to hold
    assert_eq!(at(&mut ctl, 0.0), (false, None));
    assert_eq!(ctl.evaluator.states["game"].condition_since, Some(0.0));
    // 0.2 s of GPU over 2 s is 10 %: under the threshold (the other process's 4 s does not count)
    gpu(&host, 0.2e9, 4e9);
    assert_eq!(at(&mut ctl, 2.0), (false, None));
    assert_eq!(ctl.evaluator.states["game"].condition_since, None);
    // 1 s over 2 s: busy for enter_for_s, then active
    gpu(&host, 1.2e9, 4e9);
    assert_eq!(at(&mut ctl, 4.0), (false, None));
    gpu(&host, 2.2e9, 4e9);
    assert_eq!(at(&mut ctl, 6.0), (false, None));
    gpu(&host, 3.2e9, 4e9);
    assert_eq!(at(&mut ctl, 8.0), (true, Some(0)));
    // idle again: released (exit_after 0)
    gpu(&host, 3.2e9, 4e9);
    assert_eq!(at(&mut ctl, 10.0), (false, None));
    // the source disappears: unknown counts as busy, and the rule enters again
    host.0.lock().unwrap().gpu = None;
    at(&mut ctl, 12.0);
    assert_eq!(at(&mut ctl, 16.0), (true, Some(0)));
}

/// Owner stall is measured per process: a process that appears with a long stalled history adds nothing (a
/// summed delta read every arrival as a stall spike, as while a machine boots).
#[test]
fn owner_stall_ignores_processes_that_appear_with_a_history() {
    let host = Shared::default();
    let mut ctl = scripted(&host, json!({"node": {"mode": "moderate"}}));
    let mut i = TickInputs::new(0.0, MemorySignals::new(64.0, 20.0, 0));
    i.fleet_pids = HashSet::from([900]);
    i.allocatable_cores = 8.0;
    i.jobs = vec![FleetJobView::new(1, Some(900), 1.0, 0.0, 1.0)];
    for k in 0..90 {
        // pid 10 runs without waiting; every tick another process appears with 300 s of runnable time for
        // 100 s of CPU behind it
        {
            let mut s = host.0.lock().unwrap();
            let busy = 100.0 + 2.0 * f64::from(k);
            s.procs.push(raw(1000 + k, 1, "/bin/newcomer", 0.0));
            s.procs.retain(|p| p.pid != 10);
            s.procs.push(raw(10, 1, "/bin/owner", 0.0));
            s.counters.insert(10, ProcCounters { cpu_s: busy, runnable_s: busy, ..Default::default() });
            s.counters.insert(1000 + k, ProcCounters { cpu_s: 100.0, runnable_s: 300.0, ..Default::default() });
        }
        i.now = 2.0 * f64::from(k);
        let r = ctl.tick(&i);
        assert_eq!(r.budget_cores.unwrap_or(8.0), 8.0, "t={}", i.now);
        assert!(r.lowered.is_empty());
    }
}

#[test]
fn an_unsupported_table_leaves_only_the_guards() {
    let mut ctl = ProtectionController::new(None, Host::unavailable());
    ctl.apply(
        Some(&json!({"rule": [{"id": "a", "match": {"name": "x"}, "evict": {}}]})),
        &LocalProtection::Absent,
    );
    let r = ctl.tick(&TickInputs::new(0.0, MemorySignals::new(64.0, 60.0, 0)));
    assert_eq!(r.guard_level, GuardLevel::Hard);
    assert!(r.constraint.no_admit);
    assert!(ctl.source_error().unwrap().contains("unsupported"));
}

/// S18 reads per-attempt records: a pause or lowering is journaled when it starts or changes, not every tick.
#[test]
fn pausing_and_lowering_fleet_attempts_is_journaled_on_change() {
    let j = Arc::new(DecisionJournal::in_memory());
    let mut ctl = ProtectionController::new(Some(j.clone()), Host::unavailable());
    ctl.apply(
        Some(&json!({"node": {"mode": "fleet_first"},
                     "rule": [{"id": "calls", "match": {"name": "zoom"}, "pause_fleet": {}, "active_when": {"for_s": 0}},
                              {"id": "build", "match": {"name": "xcodebuild"}, "lower_fleet": {}, "active_when": {"for_s": 0}}]})),
        &LocalProtection::Absent,
    );
    let jobs = vec![
        FleetJobView {
            pausable: true,
            ..FleetJobView::new(1, Some(10), 1.0, 0.0, 1.0)
        },
        FleetJobView::new(2, Some(11), 1.0, 0.0, 1.0),
    ];
    let mem = MemorySignals::new(64.0, 20.0, 0);
    let both = [proc_fp(5, "/x/zoom", 0.5), proc_fp(6, "/x/xcodebuild", 0.5)];
    let records = |kind: &str| j.recent_records().into_iter().filter(|r| r.kind() == kind).collect::<Vec<_>>();
    for k in 0..3 {
        ctl.evaluate(&tick(f64::from(k) * 2.0, mem, jobs.clone()), &both, &no_cpu());
    }
    let (paused, lowered) = (records("attempt_paused"), records("attempt_lowered"));
    assert_eq!(paused.len(), 1, "once, not every tick");
    assert_eq!((paused[0].reason(), paused[0].get("rule"), paused[0].get("attempts")),
               ("PROTECTION_PAUSE", Some(&json!("rule:calls")), Some(&json!([1]))));
    assert_eq!(lowered.len(), 1);
    assert_eq!((lowered[0].reason(), lowered[0].get("attempts")), ("PROTECTION_LOWER", Some(&json!([2]))));
    // the rules clear, then the pause comes back: journaled again
    for t in [10.0, 300.0, 600.0] {
        ctl.evaluate(&tick(t, mem, jobs.clone()), &[], &no_cpu());
    }
    assert_eq!(ctl.evaluate(&tick(602.0, mem, jobs.clone()), &[], &no_cpu()).paused.len(), 0, "the rules cleared");
    ctl.evaluate(&tick(604.0, mem, jobs), &both[..1], &no_cpu());
    assert_eq!(records("attempt_paused").len(), 2);
}
