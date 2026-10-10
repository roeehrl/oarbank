//! Co-tenancy (D50 certificates, D52 harness): the harness state machine on a simulated protected process, and the
//! controller applying its arms, `gpu_duty`, and `gpu_jobs = certified` against certificates. Synthetic processes
//! and plants only.

mod common;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use common::scratch;
use oarbank_protection::abstats::SplitMix;
use oarbank_protection::harness::{HarnessTick, RunState};
use oarbank_protection::sources::{Progress, PhaseReport};
use oarbank_protection::*;
use serde_json::{json, Value};

fn spec(window: f64, blocks: u32) -> AbSpec {
    serde_json::from_value(json!({"run_id": "ab_1", "rule": "trainer", "work": "gpu", "blocks": blocks,
                                  "window_s": window, "washout_s": 10.0, "margin": 0.02, "seed": 5}))
        .unwrap()
}

/// A protected process making `base` events per second, `effect` slower while the fleet is ON, with noise per
/// tick; drives a harness to its end.
fn drive(h: &mut Harness, base: f64, effect: f64, noise: f64, seed: u64, mut tweak: impl FnMut(f64, &mut HarnessTick)) {
    let mut rng = SplitMix(seed);
    let mut now = 0.0;
    let mut arm = h.tick(&HarnessTick { now, rule_active: true, guard_clear: true, group: 1, ..HarnessTick::default() });
    while let Some(a) = arm {
        now += 2.0;
        let u = (rng.next() as f64 / u64::MAX as f64 - 0.5) * 2.0;
        let rate = base * (1.0 + noise * u) * if a == Arm::On { 1.0 - effect } else { 1.0 };
        let mut t = HarnessTick {
            now,
            progress: Some(Progress { events: rate * 2.0, seconds: 2.0 }),
            rule_active: true,
            group: 1,
            guard_clear: true,
            target: Some(0.05),
            ..HarnessTick::default()
        };
        tweak(now, &mut t);
        arm = h.tick(&t);
        assert!(now < 1e6, "the run never ends");
    }
}

#[test]
fn a_harmless_co_tenant_earns_no_slowdown_shown() {
    let mut h = Harness::new(spec(60.0, 6), 0.0).unwrap();
    drive(&mut h, 10.0, 0.0, 0.02, 1, |_, _| {});
    let o = h.outcome.clone().unwrap();
    assert_eq!(o.decision, "no_slowdown", "{o:?}");
    let a = o.analysis.unwrap();
    assert!(a.r_lo > 0.98 && a.n >= 3);
    assert!(o.min_detectable.is_some(), "the pilot reports the detectable effect");
    // ON and OFF came first in both orders (a coin per block)
    assert!(h.blocks.iter().any(|b| b.on_first) && h.blocks.iter().any(|b| !b.on_first));
}

#[test]
fn a_harmful_co_tenant_is_a_slowdown() {
    let mut h = Harness::new(spec(60.0, 6), 0.0).unwrap();
    drive(&mut h, 10.0, 0.06, 0.01, 2, |_, _| {});
    let o = h.outcome.clone().unwrap();
    assert_eq!(o.decision, "slowdown", "{o:?}");
}

#[test]
fn a_collapse_in_an_on_window_aborts_the_run_at_once() {
    let mut h = Harness::new(spec(120.0, 6), 0.0).unwrap();
    drive(&mut h, 10.0, 0.5, 0.0, 3, |_, _| {});
    let o = h.outcome.clone().unwrap();
    assert_eq!(o.decision, "slowdown");
    assert!(o.reason.starts_with("guard:"), "{}", o.reason);
    assert!(h.blocks.len() <= 1, "it stopped within the first blocks");
}

#[test]
fn outside_causes_exclude_a_block_symmetrically_and_it_is_repeated() {
    let mut h = Harness::new(spec(60.0, 4), 0.0).unwrap();
    drive(&mut h, 10.0, 0.0, 0.01, 4, |now, t| {
        if (130.0..140.0).contains(&now) {
            t.phase_on = true; // a during phase of the rule
        }
        if now >= 300.0 {
            t.group = 2; // the protected process restarted (and keeps running)
        }
        if (500.0..502.0).contains(&now) {
            t.guard_clear = false;
        }
        if (650.0..750.0).contains(&now) {
            t.on_battery = true; // the power source changed
        }
    });
    let reasons: Vec<&str> = h.excluded.iter().map(|e| e.reason.as_str()).collect();
    assert!(reasons.contains(&"a during phase of the rule was on"), "{reasons:?}");
    assert!(reasons.contains(&"the protected process restarted"), "{reasons:?}");
    assert!(reasons.contains(&"the memory guard acted"), "{reasons:?}");
    assert!(reasons.contains(&"the power source changed"), "{reasons:?}");
    assert_eq!(h.outcome.as_ref().unwrap().decision, "no_slowdown");
    assert!(h.blocks.len() >= 3, "excluded blocks were repeated");
}

#[test]
fn a_gap_in_the_ticks_is_a_sleep_and_excludes_the_block() {
    let mut h = Harness::new(spec(60.0, 3), 0.0).unwrap();
    let base = HarnessTick { rule_active: true, guard_clear: true, group: 1, ..HarnessTick::default() };
    h.tick(&HarnessTick { now: 0.0, ..base.clone() });
    h.tick(&HarnessTick { now: 2.0, progress: Some(Progress { events: 20.0, seconds: 2.0 }), ..base.clone() });
    h.tick(&HarnessTick { now: 60.0, progress: Some(Progress { events: 580.0, seconds: 58.0 }), ..base.clone() });
    for k in 0..40 {
        let now = 62.0 + 2.0 * k as f64;
        h.tick(&HarnessTick { now, progress: Some(Progress { events: 20.0, seconds: 2.0 }), ..base.clone() });
    }
    assert_eq!(h.excluded.first().map(|e| e.reason.as_str()), Some("the node slept (a gap in the agent's ticks)"));
}

#[test]
fn a_run_that_cannot_reach_the_margin_within_its_cap_is_refused_after_the_pilot() {
    let mut s = spec(60.0, 6);
    s.max_hours = 0.2; // six blocks of two minutes
    let mut h = Harness::new(s, 0.0).unwrap();
    drive(&mut h, 10.0, 0.0, 0.4, 5, |_, _| {});
    let o = h.outcome.clone().unwrap();
    assert_eq!(o.decision, "refused", "{o:?}");
    assert!(o.reason.contains("blocks"));
    assert_eq!(h.blocks.len(), 3);
}

#[test]
fn specs_are_checked_and_a_run_can_be_aborted() {
    let mut bad = spec(60.0, 6);
    bad.work = "a/".into();
    assert!(Harness::new(bad, 0.0).is_err());
    let mut bad = spec(10.0, 6);
    bad.washout_s = 20.0;
    assert!(Harness::new(bad, 0.0).is_err());
    let mut bad = spec(60.0, 6);
    bad.duty = Some(1.5);
    assert!(Harness::new(bad, 0.0).is_err());
    let mut h = Harness::new(spec(60.0, 6), 0.0).unwrap();
    h.tick(&HarnessTick { now: 0.0, rule_active: true, guard_clear: true, ..HarnessTick::default() });
    h.abort(5.0, "owner");
    assert_eq!(h.state, RunState::Aborted);
    assert_eq!(h.outcome.as_ref().unwrap().decision, "aborted");
    assert_eq!(h.tick(&HarnessTick { now: 7.0, ..HarnessTick::default() }), None);
    assert_eq!(WorkSelector::parse("mod/miner"), Some(WorkSelector::Unit("mod".into(), "miner".into())));
    assert!(WorkSelector::parse("mod").unwrap().matches("mod", "x", true));
    assert!(!WorkSelector::Cpu.matches("m", "x", true));
}

// ------------------------------------------------------------------ the controller

#[derive(Clone, Default)]
struct Script {
    procs: Vec<RawProcess>,
    gpu: Option<GpuTimes>,
}

#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Script>>);

impl ProcessSource for Shared {
    fn list(&mut self, excluding: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        Ok(self.0.lock().unwrap().procs.iter().filter(|p| !excluding.contains(&p.pid)).cloned().collect())
    }
    fn argv(&mut self, pid: i32, _: u64) -> Option<Vec<String>> {
        Some(vec![format!("p{pid}")])
    }
    fn signing(&mut self, _: i32) -> SigningIdentity {
        SigningIdentity::default()
    }
    fn satisfies(&mut self, _: i32, _: &str) -> bool {
        false
    }
    fn bundle_id(&mut self, _: &str) -> Option<String> {
        None
    }
}

impl Meter for Shared {
    fn proc_counters(&mut self, _: i32) -> Option<ProcCounters> {
        Some(ProcCounters::default())
    }
    fn gpu_times(&mut self) -> Option<GpuTimes> {
        self.0.lock().unwrap().gpu.clone()
    }
    fn front(&mut self) -> FrontReading {
        FrontReading::new(Front::Nothing, "test")
    }
}

/// Owner sources a test scripts: a progress rate and phase states by key.
#[derive(Clone, Default)]
struct Sources(Arc<Mutex<(f64, HashMap<String, bool>)>>);

impl OwnerSources for Sources {
    fn progress(&mut self, _: &str, _: &Value, _: f64) -> Option<Progress> {
        Some(Progress { events: self.0.lock().unwrap().0 * 2.0, seconds: 2.0 })
    }
    fn phase_on(&mut self, key: &str, _: &Value) -> bool {
        self.0.lock().unwrap().1.get(key).copied().unwrap_or(false)
    }
    fn phases(&self) -> Vec<PhaseReport> {
        vec![]
    }
    fn reset(&mut self) {}
}

fn raw(pid: i32, path: &str) -> RawProcess {
    RawProcess { pid, ppid: 1, start_us: 1000 + pid as u64, path: Some(path.into()), comm: String::new(), cpu_s: 0.0,
                 footprint_gb: 1.0 }
}

/// A GPU trainer protected by a gpu_share target (so the GPU gate holds), with a progress source.
fn trainer_controller(gpu_jobs: &str) -> (ProtectionController, Shared, Sources, Arc<DecisionJournal>) {
    let host = Shared::default();
    host.0.lock().unwrap().procs = vec![raw(7, "/opt/trainer/bin/train")];
    let src = Sources::default();
    src.0.lock().unwrap().0 = 10.0;
    let journal = Arc::new(DecisionJournal::in_memory());
    let mut ctl = ProtectionController::new(
        Some(journal.clone()),
        Host { processes: Box::new(host.clone()), meter: Box::new(host.clone()), sources: Box::new(src.clone()), os: None },
    );
    let central = json!({"schema": 1, "node": {"mode": "moderate", "gpu_jobs": gpu_jobs,
                                                "implicit": {"frontmost_app": false, "owner_stall": null}},
        "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"}, "active_when": "present",
                  "enter_for_s": 0, "pause_fleet": {"scope": "gpu"},
                  "protect": {"metric": "progress_rate", "max_slowdown": 0.05,
                              "source": {"jsonl": "/tmp/x.jsonl", "event": "step"}}}]});
    ctl.apply(Some(&central), &LocalProtection::Absent);
    (ctl, host, src, journal)
}

fn gpu_job(id: i64, duty: bool) -> FleetJobView {
    let mut j = FleetJobView::new(id, Some(500 + id as i32), 1.0, 0.0, 1.0);
    j.gpu = true;
    j.pausable = true;
    j.cooperative = true;
    j.duty = duty;
    j.module = "llm".into();
    j.name = "batch".into();
    j
}

fn inputs(now: f64, jobs: Vec<FleetJobView>) -> TickInputs {
    let mut i = TickInputs::new(now, MemorySignals::new(64.0, 20.0, 0));
    i.jobs = jobs;
    i.allocatable_cores = 8.0;
    i
}

/// The pause_fleet = gpu rule's own pause still applies to every GPU job (an owner action, not the gate); the
/// harness never lifts it, so here the work under test is CPU work and the rule pauses GPU work only.
#[test]
fn the_harness_pauses_the_work_under_test_in_off_windows_and_writes_gpu_duty_in_on_windows() {
    let (mut ctl, _host, _src, journal) = trainer_controller("when_no_gpu_protected");
    // a rule without its own pause: the gate (gpu_share) is what would hold GPU work
    let central = json!({"schema": 1, "node": {"mode": "moderate", "implicit": {"frontmost_app": false, "owner_stall": null}},
        "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"}, "active_when": "present", "enter_for_s": 0,
                  "protect": {"metric": "progress_rate", "max_slowdown": 0.05,
                              "source": {"jsonl": "/tmp/x.jsonl", "event": "step"}}}]});
    ctl.apply(Some(&central), &LocalProtection::Absent);
    let mut s = spec(30.0, 4);
    s.duty = Some(0.3);
    s.washout_s = 4.0;
    ctl.start_ab(s, 0.0).unwrap();
    assert!(ctl.start_ab(spec(30.0, 4), 0.0).is_err(), "one run at a time");
    let jobs = vec![gpu_job(1, true), gpu_job(2, false)];
    let mut seen_on = false;
    let mut seen_off = false;
    let mut now = 0.0;
    while ctl.harness().is_some_and(|h| !h.finished()) && now < 4000.0 {
        let r = ctl.tick(&inputs(now, jobs.clone()));
        match ctl.harness().and_then(|h| h.arm()) {
            Some(Arm::On) => {
                seen_on = true;
                assert!(!r.paused.contains(&1) && !r.paused.contains(&2));
                if let Some(d) = r.throttle.get(&1) {
                    assert_eq!(d.gpu_duty, Some(0.3), "the duty-capable job gets the level under test");
                }
                assert!(r.throttle.get(&2).is_none_or(|d| d.gpu_duty.is_none()), "a job that cannot throttle gets none");
            }
            Some(Arm::Off) => {
                seen_off = true;
                assert!(r.paused.contains(&1) && r.paused.contains(&2), "OFF pauses the work under test");
            }
            None => {}
        }
        now += 2.0;
    }
    assert!(seen_on && seen_off);
    let rep = ctl.ab_report(now).unwrap();
    assert_eq!(rep["outcome"]["decision"], "no_slowdown", "{rep}");
    let kinds: Vec<String> = journal.pending(100_000).iter().map(|r| r.reason().to_string()).collect();
    for k in ["AB_STARTED", "AB_ON", "AB_OFF", "AB_FINISHED"] {
        assert!(kinds.iter().any(|x| x == k), "{k} not journaled: {:?}", &kinds[kinds.len().saturating_sub(8)..]);
    }
    ctl.ab_ack("ab_1");
    assert!(ctl.ab_report(now).is_none());
}

#[test]
fn a_run_is_refused_without_a_progress_source() {
    let (mut ctl, ..) = trainer_controller("when_no_gpu_protected");
    let mut s = spec(30.0, 4);
    s.rule = "nope".into();
    assert!(ctl.start_ab(s, 0.0).unwrap_err().contains("no rule"));
}

fn cert(identity: &str, duty: f64, valid_until: f64) -> Certificate {
    Certificate {
        id: "c1".into(),
        rule: "trainer".into(),
        work: "gpu".into(),
        duty: Some(duty),
        r: 0.995,
        r_lo: 0.985,
        r_hi: 1.004,
        margin: 0.02,
        run_id: "ab_1".into(),
        issued_at: 0.0,
        valid_until,
        identity: identity.into(),
        context: CertContext { hardware: "Mac16,9".into(), os_major: "26".into(), agent_version: "2.10.0".into() },
    }
}

/// gpu_jobs = certified: without a valid certificate the gate holds (GPU work paused, GPU_NOT_CERTIFIED journaled);
/// with one, cooperative GPU work runs at the certified duty, and a job that cannot throttle stays paused.
#[test]
fn certified_gpu_work_runs_only_up_to_a_valid_certificate() {
    let (mut ctl, _host, _src, journal) = trainer_controller("certified");
    let central = json!({"schema": 1, "node": {"mode": "moderate", "gpu_jobs": "certified",
                                                "implicit": {"frontmost_app": false, "owner_stall": null}},
        "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"}, "active_when": "present", "enter_for_s": 0,
                  "protect": {"metric": "gpu_share", "max": 0.99}}]});
    ctl.apply(Some(&central), &LocalProtection::Absent);
    _host.0.lock().unwrap().gpu = Some(GpuTimes::known(HashMap::from([(7, 0.0)])));
    let jobs = vec![gpu_job(1, true), gpu_job(2, false)];
    ctl.tick(&inputs(0.0, jobs.clone()));
    _host.0.lock().unwrap().gpu = Some(GpuTimes::known(HashMap::from([(7, 1.8e9)])));
    let r = ctl.tick(&inputs(2.0, jobs.clone()));
    assert!(r.paused.contains(&1) && r.paused.contains(&2), "no certificate: the gate holds");
    assert!(journal.recent_records().iter().any(|x| x.reason() == "GPU_NOT_CERTIFIED"));
    let id = ctl.identity("trainer").expect("the trainer's identity").to_string();
    let ctx = CertContext { hardware: "Mac16,9".into(), os_major: "26".into(), agent_version: "2.10.0".into() };
    // a certificate for another build of the program, or an expired one, or another agent: none counts
    let mut now = 2.0;
    let mut busy = 1.8e9;
    let mut step = |ctl: &mut ProtectionController| {
        now += 2.0;
        busy += 1.8e9;
        _host.0.lock().unwrap().gpu = Some(GpuTimes::known(HashMap::from([(7, busy)])));
        (now, ctl.tick(&inputs(now, jobs.clone())))
    };
    for (c, cx) in [(cert("0000000000000000", 0.35, 1e12), ctx.clone()), (cert(&id, 0.35, 3.0), ctx.clone()),
                    (cert(&id, 0.35, 1e12), CertContext { agent_version: "2.11.0".into(), ..ctx.clone() })] {
        ctl.set_certificates(vec![c], cx);
        let (t, r) = step(&mut ctl);
        assert!(r.paused.contains(&1), "an invalid certificate never loosens");
        assert_eq!(ctl.certified_duty("trainer", t), None);
    }
    ctl.set_certificates(vec![cert(&id, 0.35, 1e12)], ctx);
    let (t, r) = step(&mut ctl);
    assert_eq!(ctl.certified_duty("trainer", t), Some(0.35));
    assert!(!r.paused.contains(&1), "the certified cooperative job runs");
    assert!(r.paused.contains(&2), "a job that cannot honour gpu_duty stays paused");
    assert_eq!(r.throttle.get(&1).and_then(|d| d.gpu_duty), Some(0.35));
    let tel = ctl.telemetry(&r);
    assert_eq!(tel.gpu_budget.as_ref().unwrap()["duty"], 0.35);
    assert_eq!(r.constraint.gpu_jobs, Some(1), "no new GPU work beyond what the certificate covers");
}

/// An immediate rule's during block applies on the tick as soon as its group is present, before the rule's own
/// enter_for_s has passed; a process trigger (on_exec) is evaluated from the process table.
#[test]
fn immediate_phases_and_process_triggers_apply_on_the_tick() {
    let host = Shared::default();
    host.0.lock().unwrap().procs = vec![raw(7, "/opt/trainer/bin/train")];
    let src = Sources::default();
    let journal = Arc::new(DecisionJournal::in_memory());
    let files = FileOwnerSources::new();
    let _ = files;
    let mut ctl = ProtectionController::new(
        Some(journal.clone()),
        Host { processes: Box::new(host.clone()), meter: Box::new(host.clone()), sources: Box::new(src.clone()), os: None },
    );
    let central = json!({"schema": 1, "node": {"mode": "fleet_first"},
        "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"}, "active_when": "present",
                  "enter_for_s": 30, "immediate": true,
                  "during": [{"source": {"jsonl": "/x", "enter": "a", "exit": "b"}, "pause_fleet": {"scope": "gpu"}}]}]});
    ctl.apply(Some(&central), &LocalProtection::Absent);
    src.0.lock().unwrap().1.insert("trainer#0".into(), true);
    let r = ctl.tick(&inputs(0.0, vec![gpu_job(1, true)]));
    assert!(r.paused.contains(&1), "an immediate phase applies while the group is present, before enter_for_s");
    // process triggers: on while a matching process runs
    let dir = scratch("exec");
    let _ = dir;
    let mut ctl2 = ProtectionController::new(
        None,
        Host { processes: Box::new(host.clone()), meter: Box::new(host.clone()),
               sources: Box::new(FileOwnerSources::new()), os: None },
    );
    let central = json!({"schema": 1, "node": {"mode": "fleet_first"},
        "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"}, "active_when": "present", "enter_for_s": 0,
                  "during": [{"source": {"on_exec": {"match": {"path_prefix": "/opt/uploader/"}}},
                              "pause_fleet": {"scope": "all"}, "tags": ["uplink"]}]}]});
    ctl2.apply(Some(&central), &LocalProtection::Absent);
    let r = ctl2.tick(&inputs(0.0, vec![gpu_job(1, true)]));
    assert!(!r.paused.contains(&1));
    host.0.lock().unwrap().procs.push(raw(9, "/opt/uploader/up"));
    let r = ctl2.tick(&inputs(2.0, vec![gpu_job(1, true)]));
    assert!(r.paused.contains(&1), "the uploader runs: the phase is on");
    let ph = ctl2.telemetry(&r).phases;
    assert_eq!((ph[0].on, ph[0].reader.as_str(), ph[0].tags.clone()), (true, "exec", vec!["uplink".to_string()]));
    let _ = BTreeSet::<i64>::new();
}
