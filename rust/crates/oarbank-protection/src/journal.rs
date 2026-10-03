//! The decision journal: an append-only record of protection decisions and actuations. The heartbeat ships
//! unacknowledged records to oarbankd (`journal`, answered by `journal_ack`) for the node's decision
//! timeline; a [`JournalSink`] keeps them on disk (JSONL, rotated daily, 7 days kept).

use std::collections::{HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Map, Value};

use crate::json::rounded;

/// Wall-clock time, seconds since the epoch.
pub trait Clock: Send + Sync {
    fn now(&self) -> f64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64())
    }
}

/// Where journal lines are persisted.
pub trait JournalSink: Send {
    fn append(&mut self, t: f64, line: &str);
    /// Drop persisted records older than `keep_days`.
    fn prune(&mut self, keep_days: u32, now: f64);
}

/// One record: `t`, `seq`, `kind`, `reason`, optional `rule`, and the detail fields at the top level.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct JournalRecord(pub Map<String, Value>);

impl JournalRecord {
    pub fn get(&self, k: &str) -> Option<&Value> {
        self.0.get(k)
    }

    pub fn seq(&self) -> i64 {
        self.get("seq").and_then(Value::as_i64).unwrap_or(0)
    }

    pub fn kind(&self) -> &str {
        self.get("kind").and_then(Value::as_str).unwrap_or("")
    }

    pub fn reason(&self) -> &str {
        self.get("reason").and_then(Value::as_str).unwrap_or("")
    }
}

struct Inner {
    seq: i64,
    recent: VecDeque<JournalRecord>,
    unsent: VecDeque<JournalRecord>,
    sink: Option<Box<dyn JournalSink>>,
}

/// Shared by the controller, the spawn registry and the agent (wrap it in an `Arc`).
pub struct DecisionJournal {
    inner: Mutex<Inner>,
    clock: Box<dyn Clock>,
}

const RECENT_MAX: usize = 500;
const UNSENT_MAX: usize = 2000;

impl DecisionJournal {
    /// An in-memory journal on the system clock.
    pub fn in_memory() -> Self {
        Self::new(Box::new(SystemClock), None)
    }

    pub fn new(clock: Box<dyn Clock>, sink: Option<Box<dyn JournalSink>>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                seq: 0,
                recent: VecDeque::new(),
                unsent: VecDeque::new(),
                sink,
            }),
            clock,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Append a record; detail fields sit beside the base fields (and override them on a name clash).
    pub fn record(&self, kind: &str, reason: &str, rule: Option<&str>, detail: Map<String, Value>) {
        let t = self.clock.now();
        let mut g = self.lock();
        g.seq += 1;
        let mut o = Map::new();
        o.insert("t".into(), rounded(t, 3));
        o.insert("seq".into(), Value::from(g.seq));
        o.insert("kind".into(), Value::from(kind));
        o.insert("reason".into(), Value::from(reason));
        if let Some(rule) = rule {
            o.insert("rule".into(), Value::from(rule));
        }
        o.extend(detail);
        let rec = JournalRecord(o);
        g.recent.push_back(rec.clone());
        while g.recent.len() > RECENT_MAX {
            g.recent.pop_front();
        }
        g.unsent.push_back(rec.clone());
        while g.unsent.len() > UNSENT_MAX {
            g.unsent.pop_front();
        }
        if let Some(sink) = g.sink.as_mut() {
            if let Ok(line) = serde_json::to_string(&rec) {
                sink.append(t, &line);
            }
        }
    }

    /// Records not yet acknowledged by the coordinator (the heartbeat sends at most `max`).
    pub fn pending(&self, max: usize) -> Vec<JournalRecord> {
        self.lock().unsent.iter().take(max).cloned().collect()
    }

    pub fn acknowledge(&self, up_to: i64) {
        self.lock().unsent.retain(|r| r.seq() > up_to);
    }

    pub fn recent_records(&self) -> Vec<JournalRecord> {
        self.lock().recent.iter().cloned().collect()
    }

    pub fn prune(&self, keep_days: u32) {
        let now = self.clock.now();
        if let Some(sink) = self.lock().sink.as_mut() {
            sink.prune(keep_days, now);
        }
    }

    /// S16 checker: every actuation in the journal targets a (pid, start) that was a registry member.
    pub fn s16_violations(records: &[JournalRecord], registered: &HashSet<String>) -> Vec<String> {
        records
            .iter()
            .filter(|r| r.kind() == "actuation")
            .filter_map(|r| {
                let pid = r.get("pid").and_then(Value::as_i64).unwrap_or(-1);
                let start = r.get("start_us").and_then(Value::as_str).unwrap_or("?");
                let key = format!("{pid}@{start}");
                (!registered.contains(&key))
                    .then(|| format!("actuation on {key} outside the spawn registry"))
            })
            .collect()
    }
}

/// `journal-<local date>.jsonl` files in one directory.
pub struct FileJournalSink {
    dir: PathBuf,
}

impl FileJournalSink {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        let _ = fs::create_dir_all(&dir);
        Self { dir }
    }
}

impl JournalSink for FileJournalSink {
    fn append(&mut self, t: f64, line: &str) {
        let path = self.dir.join(format!("journal-{}.jsonl", local_date(t)));
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(format!("{line}\n").as_bytes());
        }
    }

    fn prune(&mut self, keep_days: u32, now: f64) {
        let cutoff =
            UNIX_EPOCH + Duration::from_secs_f64((now - f64::from(keep_days) * 86400.0).max(0.0));
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        for e in entries.flatten() {
            if !e.file_name().to_string_lossy().starts_with("journal-") {
                continue;
            }
            if e.metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|m| m < cutoff)
            {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

/// YYYY-MM-DD in the local time zone (UTC where the zone cannot be read).
fn local_date(t: f64) -> String {
    let secs = t.floor() as i64;
    #[cfg(unix)]
    {
        // SAFETY: localtime_r writes only into the tm we own.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let tt = secs as libc::time_t;
        if !unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
            return format!(
                "{:04}-{:02}-{:02}",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday
            );
        }
    }
    let (y, m, d) = civil_from_days(secs.div_euclid(86400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}
