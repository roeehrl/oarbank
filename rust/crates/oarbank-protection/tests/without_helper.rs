//! Another account's processes without their session helper (docs/design/protection.md, "Without a session helper"):
//! listed from what the service reads itself and evaluated fail-safe. Facts it cannot read (arguments, code-signing
//! identity, bundle id) count as holding from a process's second sighting, use it cannot read counts as over any
//! threshold, and reservations take the last reading or bounded stand-ins.

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use common::{no_cpu, rule};
use oarbank_protection::*;
use serde_json::json;

/// An injected process table: the processes, and which facts are unreadable.
#[derive(Default)]
struct World {
    procs: Vec<RawProcess>,
    /// Pids whose arguments can be read (the rest: unreadable).
    argv: HashMap<i32, Vec<String>>,
    /// Team IDs by pid; a pid in `signing_unread` has an identity that cannot be read.
    team: HashMap<i32, String>,
    signing_unread: HashSet<i32>,
    /// Paths of app bundles whose Info.plist cannot be read.
    bundle_unread: HashSet<String>,
}

struct Fake(Arc<Mutex<World>>);

impl ProcessSource for Fake {
    fn list(&mut self, excluding: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        let w = self.0.lock().unwrap();
        Ok(w.procs.iter().filter(|p| !excluding.contains(&p.pid)).cloned().collect())
    }
    fn argv(&mut self, pid: i32, _: u64) -> Option<Vec<String>> {
        self.0.lock().unwrap().argv.get(&pid).cloned()
    }
    fn signing(&mut self, pid: i32) -> SigningIdentity {
        let w = self.0.lock().unwrap();
        SigningIdentity {
            team_id: w.team.get(&pid).cloned(),
            signing_id: None,
            unreadable: w.signing_unread.contains(&pid),
        }
    }
    fn satisfies(&mut self, _: i32, _: &str) -> bool {
        false
    }
    fn bundle_id(&mut self, _: &str) -> Option<String> {
        None
    }
    fn bundle_unreadable(&mut self, path: &str) -> bool {
        self.0.lock().unwrap().bundle_unread.iter().any(|b| path.starts_with(b.as_str()))
    }
}

fn own(pid: i32, ppid: i32, path: &str) -> RawProcess {
    RawProcess { pid, ppid, start_us: 1000 + pid as u64, path: Some(path.into()), comm: String::new(), ..Default::default() }
}

/// A person's process listed without their helper: path readable (macOS reads every account's), use unknown.
fn helperless(pid: i32, ppid: i32, path: &str) -> RawProcess {
    RawProcess { without_helper: true, usage_unread: true, ..own(pid, ppid, path) }
}

fn table(w: &Arc<Mutex<World>>) -> ProcessTable {
    ProcessTable::new(Box::new(Fake(w.clone())))
}

fn config(rules: Vec<ProtectionRule>) -> ProtectionConfig {
    ProtectionConfig::new(ProtectionMode::FleetFirst, rules)
}

fn matched(cfg: &ProtectionConfig, snap: &Snapshot, id: &str) -> Vec<i32> {
    let r = cfg.rules.iter().find(|r| r.id == id).unwrap();
    matcher::group(&snap.procs, &r.match_, r.tree).iter().map(|p| p.pid).collect()
}

/// A trainer started by a person whose helper is not connected: the program's marker sits in its arguments, which only
/// the helper may read. It is protected from its second sighting on (the fail-safe match), with its whole tree; with the
/// helper reporting, the arguments decide, and processes without the marker no longer match.
#[test]
fn an_argument_rule_protects_a_helperless_tree_from_its_second_sighting() {
    let w = Arc::new(Mutex::new(World::default()));
    {
        let mut g = w.lock().unwrap();
        g.procs = vec![
            own(5, 1, "/bin/zsh"),
            helperless(100, 1, "/usr/bin/python3"),
            helperless(101, 100, "/bin/sh"),
            helperless(102, 101, "/usr/bin/python3"),
            helperless(200, 1, "/usr/bin/top"),
        ];
        g.argv.insert(5, vec!["zsh".into()]);
    }
    let cfg = config(vec![rule(json!({"id": "trainer", "match": {"path_contains": "Trainer/releases"},
                                      "tree": "descendants", "active_when": "present", "reserve": {"mem_gb": "peak(60s).footprint + 1"}}))]);
    let mut t = table(&w);
    let first = t.snapshot(&cfg, &HashSet::new(), 0.0).unwrap();
    assert_eq!(first.procs.iter().map(|p| p.pid).collect::<Vec<_>>(), [5], "an unreadable process waits one sighting");
    let second = t.snapshot(&cfg, &HashSet::new(), 2.0).unwrap();
    assert_eq!(matched(&cfg, &second, "trainer"), [100, 101, 102, 200], "every unread process counts (fail-safe)");
    assert!(second.procs.iter().filter(|p| p.pid >= 100).all(|p| p.without_helper && p.argv.is_none()));
    let mut ev = RuleEvaluator::new();
    let r = ev.evaluate(&cfg, &second.procs, &second.cpu_cores, Front::Unknown, None, 2.0);
    let rep = &r.reports[0];
    assert!(rep.active && rep.processes == 4 && rep.unreadable == 4 && rep.without_helper == 4, "{rep:?}");
    // the helper connects: its report replaces the fallback, and the arguments decide
    {
        let mut g = w.lock().unwrap();
        for p in g.procs.iter_mut().filter(|p| p.pid >= 100) {
            p.without_helper = false;
            p.usage_unread = false;
        }
        g.argv.insert(100, vec!["python3".into(), "/Users/p/Trainer/releases/7/train.py".into()]);
        g.argv.insert(101, vec!["sh".into(), "-c".into(), "x".into()]);
        g.argv.insert(102, vec!["python3".into(), "worker.py".into()]);
        g.argv.insert(200, vec!["top".into()]);
    }
    let helped = t.snapshot(&cfg, &HashSet::new(), 4.0).unwrap();
    assert_eq!(matched(&cfg, &helped, "trainer"), [100, 101, 102], "the marker's process and its descendants");
    let r = ev.evaluate(&cfg, &helped.procs, &helped.cpu_cores, Front::Unknown, None, 4.0);
    assert_eq!((r.reports[0].unreadable, r.reports[0].without_helper), (0, 0));
}

/// A code-signing or bundle-id key on a process whose identity the service cannot read (an app in a person's home)
/// counts as holding; an identity it read decides as before, and an unsigned process of its own never matches.
#[test]
fn unreadable_signing_and_bundle_ids_count_as_matches() {
    let app = "/Users/p/Applications/Trainer.app";
    let w = Arc::new(Mutex::new(World::default()));
    {
        let mut g = w.lock().unwrap();
        g.procs = vec![
            own(5, 1, "/Applications/Other.app/Contents/MacOS/Other"),
            helperless(100, 1, &format!("{app}/Contents/MacOS/Trainer")),
            helperless(101, 1, "/Applications/Editor.app/Contents/MacOS/Editor"),
        ];
        g.signing_unread.insert(100);
        g.team.insert(101, "OTHERTEAM1".into());
        g.bundle_unread.insert(app.into());
    }
    let cfg = config(vec![
        rule(json!({"id": "team", "match": {"team_id": "TEAM123456"}, "active_when": "present", "reserve": {"mem_gb": "peak(60s).footprint + 1"}})),
        rule(json!({"id": "bundle", "match": {"bundle_id": ["com.example.trainer"]}, "active_when": "present", "reserve": {"mem_gb": "peak(60s).footprint + 1"}})),
    ]);
    let mut t = table(&w);
    let first = t.snapshot(&cfg, &HashSet::new(), 0.0).unwrap();
    assert_eq!(matched(&cfg, &first, "team"), Vec::<i32>::new(), "held back on its first sighting");
    let snap = t.snapshot(&cfg, &HashSet::new(), 2.0).unwrap();
    assert_eq!(matched(&cfg, &snap, "team"), [100]);
    assert_eq!(matched(&cfg, &snap, "bundle"), [100]);
    let p = snap.procs.iter().find(|p| p.pid == 100).unwrap();
    assert!(p.signing_unread && p.bundle_unread);
    let q = snap.procs.iter().find(|p| p.pid == 101).unwrap();
    assert!(!q.signing_unread && !q.bundle_unread, "read: another team, outside any unreadable bundle");
}

/// Use that cannot be read counts as over any threshold, and the rule reserves from its expression with the last
/// reading where there is one and bounded stand-ins where there is none, never an unbounded amount.
#[test]
fn unknown_use_activates_thresholds_and_reserves_a_bounded_estimate() {
    let cfg = config(vec![rule(json!({"id": "trainer", "match": {"path_prefix": "/Users/p/Trainer/"},
                                      "tree": "descendants", "active_when": {"cpu_cores_gt": 50, "for_s": 0},
                                      "reserve": {"mem_gb": "peak(300s).footprint + 2", "cpu": "peak(60s).cpu + 1"},
                                      "cap_fleet": {"slots": 1}}))]);
    let rec = |pid: i32, ppid: i32, path: &str| ProcessRecord {
        without_helper: true,
        usage_unread: true,
        ..ProcessRecord::new(pid, ppid, 1000 + pid as u64, path)
    };
    // helper connected and measuring: below the threshold, not active
    let measured = ProcessRecord { footprint_gb: 0.5, ..ProcessRecord::new(100, 1, 1100, "/Users/p/Trainer/bin/t") };
    let mut ev = RuleEvaluator::new();
    let cpu = HashMap::from([(measured.key(), 0.2)]);
    let r = ev.evaluate(&cfg, std::slice::from_ref(&measured), &cpu, Front::Unknown, None, 0.0);
    assert!(!r.reports[0].active && r.vectors.is_empty());
    // without the helper: unknown use is over the threshold; one unmeasured process reserves 1 GB + 2 and 1 core + 1
    let mut ev = RuleEvaluator::new();
    let one = vec![rec(100, 1, "/Users/p/Trainer/bin/t")];
    let r = ev.evaluate(&cfg, &one, &no_cpu(), Front::Unknown, None, 0.0);
    assert!(r.reports[0].active, "{:?}", r.reports[0]);
    assert_eq!(r.vectors[0].reserve_mem_gb.values().copied().collect::<Vec<_>>(), [UNMEASURED_FOOTPRINT_GB + 2.0]);
    assert_eq!(r.vectors[0].reserve_cpu.values().copied().collect::<Vec<_>>(), [UNMEASURED_CPU_CORES + 1.0]);
    assert_eq!(r.vectors[0].slots, Some(1), "a cap applies too");
    // a large unmeasured tree is capped per group; a process its helper measured before counts at its last reading
    let mut ev = RuleEvaluator::new();
    let mut tree: Vec<ProcessRecord> = (0..40).map(|i| rec(200 + i, 100, "/bin/sh")).collect();
    tree.push(ProcessRecord { footprint_gb: 12.0, ..rec(100, 1, "/Users/p/Trainer/bin/t") });
    let last_rate = HashMap::from([(tree[40].key(), 3.0)]);
    let r = ev.evaluate(&cfg, &tree, &last_rate, Front::Unknown, None, 0.0);
    let rep = &r.reports[0];
    assert_eq!((rep.processes, rep.without_helper), (41, 41));
    assert_eq!(rep.footprint_gb, 12.0 + UNMEASURED_GROUP_FOOTPRINT_GB);
    assert_eq!(rep.cpu_cores, 3.0 + UNMEASURED_GROUP_CPU_CORES);
    assert_eq!(r.vectors[0].reserve_mem_gb.values().copied().collect::<Vec<_>>(), [12.0 + UNMEASURED_GROUP_FOOTPRINT_GB + 2.0]);
    // a footprint threshold the same way
    let fp = config(vec![rule(json!({"id": "fp", "match": {"path_prefix": "/Users/p/Trainer/"},
                                     "active_when": {"footprint_gb_gt": 100, "for_s": 0}, "cap_fleet": {"slots": 0}}))]);
    let mut ev = RuleEvaluator::new();
    assert!(ev.evaluate(&fp, &one, &no_cpu(), Front::Unknown, None, 0.0).reports[0].active);
}

/// The table keeps a process's last measured CPU rate for the ticks its use cannot be read, so reservations and
/// reports carry it instead of a stand-in.
#[test]
fn the_table_carries_the_last_measured_rate_while_use_is_unread() {
    let w = Arc::new(Mutex::new(World::default()));
    w.lock().unwrap().procs = vec![RawProcess { cpu_s: 10.0, ..own(100, 1, "/Users/p/Trainer/bin/t") }];
    let cfg = config(vec![rule(json!({"id": "t", "match": {"path_prefix": "/Users/p/Trainer/"}, "active_when": "present", "reserve": {"mem_gb": "peak(60s).footprint + 1"}}))]);
    let mut t = table(&w);
    t.snapshot(&cfg, &HashSet::new(), 0.0).unwrap();
    w.lock().unwrap().procs[0].cpu_s = 14.0;
    let s = t.snapshot(&cfg, &HashSet::new(), 2.0).unwrap();
    let key = ProcessKey::new(100, 1100);
    assert_eq!(s.cpu_cores.get(&key), Some(&2.0));
    // the helper goes away: no reading, the last rate stands
    {
        let mut g = w.lock().unwrap();
        g.procs[0].cpu_s = 0.0;
        g.procs[0].usage_unread = true;
        g.procs[0].without_helper = true;
    }
    let s = t.snapshot(&cfg, &HashSet::new(), 4.0).unwrap();
    assert_eq!(s.cpu_cores.get(&key), Some(&2.0));
    // a process never measured has no rate (the evaluator's stand-in applies)
    w.lock().unwrap().procs.push(helperless(101, 1, "/Users/p/Trainer/bin/u"));
    let s = t.snapshot(&cfg, &HashSet::new(), 6.0).unwrap();
    assert_eq!(s.cpu_cores.get(&ProcessKey::new(101, 1101)), None);
}
