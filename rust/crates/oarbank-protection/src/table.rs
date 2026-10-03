//! The process table: a platform [`ProcessSource`] for the raw facts, and the caching layer that resolves the
//! expensive identity (code signing, argv, bundle id) lazily and once per (pid, start time). Read-only:
//! nothing here can signal or reprioritize a process.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::config::{ProtectionConfig, TreeScope};
use crate::model::{ProcessKey, ProcessRecord};

/// One of the owner's processes as the platform reports it, before identity is resolved.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RawProcess {
    pub pid: i32,
    pub ppid: i32,
    /// Microseconds since the epoch.
    pub start_us: u64,
    /// None: not readable (another account's process the agent may not inspect).
    pub path: Option<String>,
    pub comm: String,
    /// Cumulative CPU time (user + system), seconds.
    pub cpu_s: f64,
    /// Physical footprint, GB.
    pub footprint_gb: f64,
}

/// The code-signing identity of a running process (None: unsigned, ad hoc, or not readable).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SigningIdentity {
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    #[error("process table unsupported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("process table unreadable: {0}")]
    Unreadable(String),
}

/// The platform's view of the owner's processes (macOS: the agent's own account's; Linux and Windows: the
/// processes of the people using the machine, see each backend). Implementations only read, never act.
pub trait ProcessSource: Send {
    /// The owner's processes, without the ones in `excluding` (the agent's own groups).
    fn list(&mut self, excluding: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError>;
    /// argv; None when unreadable.
    fn argv(&mut self, pid: i32) -> Option<Vec<String>>;
    fn signing(&mut self, pid: i32) -> SigningIdentity;
    /// Does the live process satisfy a code-signing requirement string?
    fn satisfies(&mut self, pid: i32, requirement: &str) -> bool;
    /// The bundle identifier of the app bundle an executable path sits in.
    fn bundle_id(&mut self, path: &str) -> Option<String>;
}

/// A source for platforms whose backend has not been written yet: an empty table and an error, so only the
/// memory, thermal and battery guards apply.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedProcessSource;

impl ProcessSource for UnsupportedProcessSource {
    fn list(&mut self, _: &HashSet<i32>) -> Result<Vec<RawProcess>, SourceError> {
        Err(SourceError::Unsupported(std::env::consts::OS))
    }
    fn argv(&mut self, _: i32) -> Option<Vec<String>> {
        None
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

/// Per-process identity cache: `Some("")` is "resolved, nothing there", None is "not resolved yet". Unreadable
/// arguments are not cached: they may become readable (a session helper reports them).
#[derive(Debug, Clone, Default)]
struct Identity {
    team_id: Option<String>,
    signing_id: Option<String>,
    bundle_id: Option<String>,
    argv: Option<Vec<String>>,
    requirements: HashMap<String, bool>,
}

fn non_empty(s: &Option<String>) -> Option<String> {
    s.clone().filter(|s| !s.is_empty())
}

/// One tick's table: the processes, and each one's CPU use since the previous snapshot (cores).
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub procs: Vec<ProcessRecord>,
    pub cpu_cores: HashMap<ProcessKey, f64>,
}

/// A row of the console's process picker (heartbeat `processes`). A null path or argv is unreadable.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProcessSummaryRow {
    pub pid: i32,
    pub ppid: i32,
    pub start_us: u64,
    pub path: Option<String>,
    pub comm: String,
    pub argv: Option<Vec<String>>,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub bundle_id: Option<String>,
    pub cpu_cores: f64,
    pub footprint_gb: f64,
}

fn prefix(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

pub struct ProcessTable {
    source: Box<dyn ProcessSource>,
    identities: HashMap<ProcessKey, Identity>,
    last_cpu: HashMap<ProcessKey, (f64, f64)>,
}

impl ProcessTable {
    pub fn new(source: Box<dyn ProcessSource>) -> Self {
        Self {
            source,
            identities: HashMap::new(),
            last_cpu: HashMap::new(),
        }
    }

    fn identity(&mut self, key: ProcessKey, path: Option<&str>) -> Identity {
        match self.identities.get(&key) {
            Some(id) => id.clone(),
            None => Identity {
                bundle_id: path.and_then(|p| self.source.bundle_id(p)),
                ..Identity::default()
            },
        }
    }

    /// Snapshot the table. Signing identity and argv are resolved only when some rule needs them (and then
    /// once per process); `excluding` drops the agent's own groups (they are fleet, never protected).
    pub fn snapshot(
        &mut self,
        config: &ProtectionConfig,
        excluding: &HashSet<i32>,
        now: f64,
    ) -> Result<Snapshot, SourceError> {
        let raw = self.source.list(excluding)?;
        let need_signing = config
            .rules
            .iter()
            .any(|r| r.match_.needs_signing() || r.tree == TreeScope::SameTeam);
        let need_argv = config
            .rules
            .iter()
            .any(|r| r.match_.needs_argv() || r.match_.path_contains.is_some());
        let requirements: Vec<String> = {
            let mut v: Vec<String> = config
                .rules
                .iter()
                .filter_map(|r| r.match_.requirement.clone())
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let mut snap = Snapshot::default();
        let mut seen = HashSet::new();
        for rp in raw.into_iter().filter(|p| !excluding.contains(&p.pid)) {
            let key = ProcessKey::new(rp.pid, rp.start_us);
            seen.insert(key);
            let mut id = self.identity(key, rp.path.as_deref());
            if need_argv && id.argv.is_none() {
                id.argv = self.source.argv(rp.pid);
            }
            if need_signing && id.team_id.is_none() && id.signing_id.is_none() {
                let s = self.source.signing(rp.pid);
                id.team_id = Some(s.team_id.unwrap_or_default());
                id.signing_id = Some(s.signing_id.unwrap_or_default());
            }
            for r in &requirements {
                if !id.requirements.contains_key(r) {
                    let ok = self.source.satisfies(rp.pid, r);
                    id.requirements.insert(r.clone(), ok);
                }
            }
            let rec = ProcessRecord {
                pid: rp.pid,
                ppid: rp.ppid,
                start_us: rp.start_us,
                path: rp.path,
                comm: rp.comm,
                argv: id.argv.clone(),
                team_id: non_empty(&id.team_id),
                signing_id: non_empty(&id.signing_id),
                bundle_id: id.bundle_id.clone(),
                requirements_met: id
                    .requirements
                    .iter()
                    .filter(|(_, ok)| **ok)
                    .map(|(k, _)| k.clone())
                    .collect(),
                cpu_s: rp.cpu_s,
                footprint_gb: rp.footprint_gb,
            };
            self.identities.insert(key, id);
            if let Some(&(t, cpu)) = self.last_cpu.get(&key) {
                if now > t {
                    snap.cpu_cores
                        .insert(key, ((rec.cpu_s - cpu) / (now - t)).max(0.0));
                }
            }
            self.last_cpu.insert(key, (now, rec.cpu_s));
            snap.procs.push(rec);
        }
        self.identities.retain(|k, _| seen.contains(k));
        self.last_cpu.retain(|k, _| seen.contains(k));
        Ok(snap)
    }

    /// The process picker's view (heartbeat `processes`): the owner's processes by resource use, with the
    /// identity a rule can match on (signing resolved for these only, once per process). The agent's own groups
    /// are excluded. Paths and argv are truncated; argv is limited to 12 entries.
    pub fn summary(
        &mut self,
        limit: usize,
        excluding: &HashSet<i32>,
        now: f64,
    ) -> Result<Vec<ProcessSummaryRow>, SourceError> {
        let raw = self.source.list(excluding)?;
        let mut rows: Vec<(RawProcess, f64)> = raw
            .into_iter()
            .filter(|p| !excluding.contains(&p.pid))
            .map(|p| {
                let key = ProcessKey::new(p.pid, p.start_us);
                let cores = match self.last_cpu.get(&key) {
                    Some(&(t, cpu)) if now > t => ((p.cpu_s - cpu) / (now - t)).max(0.0),
                    _ => 0.0,
                };
                (p, cores)
            })
            .collect();
        let score = |r: &(RawProcess, f64)| r.1 * 4.0 + r.0.footprint_gb;
        rows.sort_by(|a, b| score(b).total_cmp(&score(a)));
        rows.truncate(limit);
        let mut out = Vec::with_capacity(rows.len());
        for (p, cores) in rows {
            let key = ProcessKey::new(p.pid, p.start_us);
            let mut id = self.identity(key, p.path.as_deref());
            if id.team_id.is_none() && id.signing_id.is_none() {
                let s = self.source.signing(p.pid);
                id.team_id = Some(s.team_id.unwrap_or_default());
                id.signing_id = Some(s.signing_id.unwrap_or_default());
            }
            if id.argv.is_none() {
                id.argv = self.source.argv(p.pid);
            }
            out.push(ProcessSummaryRow {
                pid: p.pid,
                ppid: p.ppid,
                start_us: p.start_us,
                path: p.path.as_deref().map(|s| prefix(s, 400)),
                comm: p.comm.clone(),
                argv: id
                    .argv
                    .as_ref()
                    .map(|a| a.iter().take(12).map(|a| prefix(a, 200)).collect()),
                team_id: non_empty(&id.team_id),
                signing_id: non_empty(&id.signing_id),
                bundle_id: id.bundle_id.clone(),
                cpu_cores: round2(cores),
                footprint_gb: round2(p.footprint_gb),
            });
            self.identities.insert(key, id);
        }
        Ok(out)
    }
}
