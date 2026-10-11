//! Owner-supplied sources (never from a module): progress rates for `protect.metric = progress_rate`, and
//! phases for `during` rules. Owner configuration may exec a probe because the owner wrote it.
//!
//! A file source names a path or a glob (`*` in the last component). The reader follows the newest matching file:
//! a program that starts a new file on every restart (`events-<session>.jsonl`) is picked up as soon as the new file
//! appears, and the rest of the old one is read first. The tail is rotation- and truncation-safe: it keeps the file's
//! identity (device and inode where the OS has them) and its offset, finishes the old file on rotation, starts again
//! on truncation, and parses complete lines only (a partial last line waits for its newline).
//!
//! JSONL lines are matched by event type: the value of `event_key` (default `event`, a dotted path) equals `event`.
//! A phase is either a pair of event types (`enter`, `exit`, optionally `enter_soon`) or a field of one event type
//! (`field`, a dotted path, whose value is one of `on` or `soon` while the phase is on). `enter_soon` and `soon`
//! announce a phase about to start; protection treats the phase as on from that moment, so fleet work is clear
//! before it begins.
//!
//! Where a path lives decides who reads it ([`Location`]): the agent reads what its own account can read; in a
//! system install, paths in a person's home (`~`, `~name`, or an absolute path under a home directory) are read by
//! that person's session helper and relayed as counts and phase states ([`PersonReader`]), never as file contents.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::SystemTime;

use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::ProtectionConfig;
use crate::json::{get, str_of};

/// Wall-clock seconds since the epoch.
pub fn wall_now() -> f64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

/// Events counted over an interval (a progress source's reading).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Progress {
    pub events: f64,
    pub seconds: f64,
}

impl Progress {
    pub fn rate(&self) -> Option<f64> {
        (self.seconds > 0.0).then(|| self.events / self.seconds)
    }
}

/// One `during` block's phase as the agent last read it (the heartbeat's `protection.phases`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhaseReport {
    /// `<rule id>#<n>`.
    pub key: String,
    pub rule: String,
    pub block: usize,
    pub on: bool,
    /// Wall-clock time of the last change (None: not seen to change yet).
    pub since: Option<f64>,
    /// Whether the source could be read on the last attempt.
    pub readable: bool,
    /// `agent` (read by the agent), `helper` (relayed by a session helper), `exec` (a process trigger).
    pub reader: String,
    /// The block's owner-set tags (`uplink`, ...), for coordinator-side aggregation.
    pub tags: Vec<String>,
    /// The rule's phases act at once (`immediate = true`).
    pub immediate: bool,
}

/// How the controller reads owner sources. Keys are stable per rule (`<rule id>` for progress,
/// `<rule id>#<n>` for a rule's n-th `during` block); `reset` drops all state when the config changes.
pub trait OwnerSources: Send {
    /// Events since the last read and the seconds they cover (None on the first read, or when unreadable).
    fn progress(&mut self, key: &str, spec: &Value, now: f64) -> Option<Progress>;
    /// Events per second since the last read.
    fn progress_rate(&mut self, key: &str, spec: &Value, now: f64) -> Option<f64> {
        self.progress(key, spec, now).and_then(|p| p.rate())
    }
    /// Whether the phase is on (the newest phase event decides).
    fn phase_on(&mut self, key: &str, spec: &Value) -> bool;
    /// The config whose sources these are (called after `reset`): event-driven sources watch them from here on.
    fn configure(&mut self, _cfg: &ProtectionConfig) {}
    /// A process trigger's state this tick (`on_exec` sources are evaluated against the process table).
    fn set_exec_phase(&mut self, _key: &str, _on: bool) {}
    /// The rules whose immediate phases may act between ticks (active, or their group is present), and the fleet's
    /// pids (never an exec trigger's match).
    fn arm(&mut self, _armed: &BTreeSet<String>, _fleet_pids: &HashSet<i32>) {}
    /// Every configured phase as last read.
    fn phases(&self) -> Vec<PhaseReport> {
        vec![]
    }
    /// A progress source's last read: whether it could be read, and who reads it (`agent`, `helper`).
    fn progress_status(&self, _key: &str) -> Option<(bool, String)> {
        None
    }
    /// The journal phase changes go to (the controller attaches its own).
    fn attach(&mut self, _journal: Option<Arc<crate::journal::DecisionJournal>>) {}
    /// The agent's fast path for immediate phases (the event path, `events.rs`).
    fn set_fast_path(&mut self, _f: Arc<dyn crate::events::FastPath>) {}
    /// The event path's measured latencies (source event to pause request), for telemetry.
    fn latency(&self) -> Option<Value> {
        None
    }
    fn reset(&mut self);
}

/// No owner sources: progress unknown, phases off.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOwnerSources;

impl OwnerSources for NoOwnerSources {
    fn progress(&mut self, _: &str, _: &Value, _: f64) -> Option<Progress> {
        None
    }
    fn phase_on(&mut self, _: &str, _: &Value) -> bool {
        false
    }
    fn reset(&mut self) {}
}

// ------------------------------------------------------------------ where a source lives

/// Who reads a source path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Location {
    /// The agent reads it itself (a path, or a glob in the last component).
    Agent(PathBuf),
    /// A person's session helper reads it: `rel` under that person's home (`account` None: the person at the
    /// console, or any person whose helper finds it).
    Person { account: Option<String>, rel: String },
}

impl Location {
    /// Resolve a source path. `system`: the agent runs as a service account (a system install), so paths in a
    /// person's home go to that person's helper; otherwise `~` is the agent's own home (it runs as the person).
    /// Before this, `~` always meant the agent process's own `HOME`, which for a system install is the service
    /// account's home: a source in the person's home was unreadable and held fleet work back for good.
    pub fn of(path: &str, system: bool) -> Location {
        let norm = path.replace('\\', "/");
        if let Some(rest) = norm.strip_prefix('~') {
            let (name, rel) = rest.split_once('/').unwrap_or((rest, ""));
            let rel = rel.trim_start_matches('/').to_string();
            if system {
                return Location::Person { account: (!name.is_empty()).then(|| name.to_string()), rel };
            }
            let home = if name.is_empty() { own_home() } else { home_of(name) };
            return match home {
                Some(h) => Location::Agent(if rel.is_empty() { h } else { h.join(rel) }),
                None => Location::Agent(PathBuf::from(path)),
            };
        }
        if system {
            if let Some((account, rel)) = under_home_dir(&norm) {
                return Location::Person { account: Some(account), rel };
            }
        }
        Location::Agent(PathBuf::from(path))
    }
}

fn own_home() -> Option<PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from)
}

/// A named account's home directory.
#[cfg(unix)]
pub fn home_of(name: &str) -> Option<PathBuf> {
    use std::ffi::{CStr, CString};
    let c = CString::new(name).ok()?;
    // SAFETY: a zeroed passwd is a valid out-parameter.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 << 10];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: valid buffers of the stated sizes; the result points into `pw` and `buf`, read before they drop.
    let rc = unsafe { libc::getpwnam_r(c.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: getpwnam_r succeeded, pw_dir is a NUL-terminated string in `buf`.
    let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
    Some(PathBuf::from(dir.to_string_lossy().into_owned()))
}

/// A named account's home directory (the profile directory beside the others).
#[cfg(not(unix))]
pub fn home_of(name: &str) -> Option<PathBuf> {
    let drive = std::env::var_os("SystemDrive")?;
    Some(PathBuf::from(format!("{}\\Users", drive.to_string_lossy())).join(name))
}

/// The account name of a uid (None: unknown).
#[cfg(unix)]
pub fn account_of(uid: u32) -> Option<String> {
    use std::ffi::CStr;
    // SAFETY: a zeroed passwd is a valid out-parameter.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 << 10];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: as in home_of.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 || out.is_null() || pw.pw_name.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated name in `buf`.
    Some(unsafe { CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned())
}

/// `/Users/<name>/...` (macOS), `/home/<name>/...` (Linux), `<drive>:/Users/<name>/...` (Windows): the account and
/// the rest of the path.
fn under_home_dir(norm: &str) -> Option<(String, String)> {
    let lower = norm.to_ascii_lowercase();
    let rest = ["/users/", "/home/"]
        .iter()
        .find_map(|p| lower.starts_with(p).then(|| &norm[p.len()..]))
        .or_else(|| {
            let b = lower.as_bytes();
            (b.len() > 9 && b[1] == b':' && lower[2..].starts_with("/users/")).then(|| &norm[9..])
        })?;
    let (name, rel) = rest.split_once('/')?;
    if name.is_empty() || name.eq_ignore_ascii_case("shared") || name.eq_ignore_ascii_case("public") {
        return None;
    }
    Some((name.to_string(), rel.to_string()))
}

/// What a person's session helper last said about a source (the service's view; see `session.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct PersonReading {
    /// Events counted since the helper started watching this source on its connection.
    pub events: u64,
    /// Changes when the helper's count restarts (a new connection): the next read sets a new baseline.
    pub epoch: u64,
    pub on: bool,
    pub readable: bool,
    /// Wall-clock time the helper saw the newest change.
    pub event_t: f64,
}

/// The session helpers' readings, as the system service keeps them (implemented by the session hub).
pub trait PersonReader: Send + Sync {
    /// The sources the helpers should read.
    fn want(&self, sources: Vec<RelayedSource>);
    /// The newest reading of a source (None: no helper reports it).
    fn reading(&self, key: &str) -> Option<PersonReading>;
}

/// A source a session helper reads for the service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayedSource {
    pub key: String,
    /// `progress` or `phase`.
    pub kind: String,
    /// None: any person (the console's first).
    pub account: Option<String>,
    /// The path under the person's home (may hold a `*` in its last component).
    pub rel: String,
    /// The source spec (event filter, phase rule), with its path left out.
    pub spec: Value,
}

// ------------------------------------------------------------------ line matching

/// A dotted path into a JSON object (`response.phase`).
pub fn field<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').filter(|p| !p.is_empty()).try_fold(v, |v, k| v.as_object()?.get(k))
}

fn text_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn strings_of(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(text_of).collect(),
        _ => vec![],
    }
}

/// Which lines count (progress) or carry the phase (a field phase): those whose `event_key` is `event`. No event
/// counts every complete line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventFilter {
    pub event_key: String,
    pub event: Option<String>,
}

impl EventFilter {
    fn from_json(j: Option<&Value>) -> Self {
        Self {
            event_key: str_of(get(j, "event_key")).filter(|s| !s.is_empty()).unwrap_or("event").to_string(),
            event: str_of(get(j, "event")).filter(|s| !s.is_empty()).map(str::to_string),
        }
    }

    /// The event type of a line (None: not a JSON object, or no such field).
    fn kind(&self, line: &Value) -> Option<String> {
        text_of(field(line, &self.event_key)?)
    }

    pub fn counts(&self, line: &str) -> bool {
        match &self.event {
            None => !line.trim().is_empty(),
            Some(e) => serde_json::from_str::<Value>(line).ok().is_some_and(|v| self.kind(&v).as_deref() == Some(e)),
        }
    }
}

/// How a phase follows its source's lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhaseRule {
    /// Event types that turn it on (`enter`, `enter_soon`) and off (`exit`).
    Events { key: String, enter: Vec<String>, exit: Vec<String> },
    /// A field of one event type: on while its value is one of `on` or `soon`.
    Field { filter: EventFilter, field: String, on: Vec<String>, soon: Vec<String> },
}

impl PhaseRule {
    pub fn from_json(j: &Value) -> Option<Self> {
        let j = Some(j);
        if let Some(f) = str_of(get(j, "field")).filter(|s| !s.is_empty()) {
            let (on, soon) = (strings_of(get(j, "on")), strings_of(get(j, "soon")));
            if on.is_empty() && soon.is_empty() {
                return None;
            }
            return Some(PhaseRule::Field { filter: EventFilter::from_json(j), field: f.to_string(), on, soon });
        }
        let mut enter = strings_of(get(j, "enter"));
        enter.extend(strings_of(get(j, "enter_soon")));
        let exit = strings_of(get(j, "exit"));
        if enter.is_empty() || exit.is_empty() {
            return None;
        }
        let key = str_of(get(j, "event_key")).filter(|s| !s.is_empty()).unwrap_or("event").to_string();
        Some(PhaseRule::Events { key, enter, exit })
    }

    /// The phase after this line (None: the line says nothing about it).
    pub fn apply(&self, line: &str) -> Option<bool> {
        let v: Value = serde_json::from_str(line).ok()?;
        match self {
            PhaseRule::Events { key, enter, exit } => {
                let k = text_of(field(&v, key)?)?;
                if exit.contains(&k) {
                    Some(false)
                } else if enter.contains(&k) {
                    Some(true)
                } else {
                    None
                }
            }
            PhaseRule::Field { filter, field: f, on, soon } => {
                if let Some(e) = &filter.event {
                    if filter.kind(&v).as_deref() != Some(e) {
                        return None;
                    }
                }
                let val = text_of(field(&v, f)?)?;
                Some(on.contains(&val) || soon.contains(&val))
            }
        }
    }
}

// ------------------------------------------------------------------ the tail

/// A file's identity: device and inode where the OS has them (a rename keeps it, a new file changes it); on
/// Windows its creation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId(u64, u64);

fn file_id(m: &std::fs::Metadata) -> FileId {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FileId(m.dev(), m.ino())
    }
    #[cfg(not(unix))]
    {
        let created = m
            .created()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos() as u64);
        FileId(created, 0)
    }
}

/// The longest partial line kept while waiting for its newline, and the most read at once.
const MAX_PARTIAL: usize = 1 << 20;
const MAX_READ: u64 = 8 << 20;

/// Where a new tail starts reading the first file it finds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// At its end: only lines written from now on (progress counts).
    End,
    /// Its last bytes (at most this many): the newest state already written (phases).
    Last(u64),
}

/// A rotation- and truncation-safe reader of complete lines from the newest file matching a pattern.
#[derive(Debug)]
pub struct Tail {
    pattern: PathBuf,
    current: Option<(FileId, File)>,
    offset: u64,
    partial: Vec<u8>,
    /// The first line read is a fragment (reading started in the middle of a file).
    skip_fragment: bool,
}

impl Tail {
    pub fn new(pattern: impl Into<PathBuf>) -> Self {
        Self { pattern: pattern.into(), current: None, offset: 0, partial: vec![], skip_fragment: false }
    }

    /// The path or glob this tail follows.
    pub fn pattern(&self) -> &Path {
        &self.pattern
    }

    /// The complete lines written since the last read (Err: no matching file, or it cannot be read). The first
    /// read starts where `start` says; a file that appears later (a restart's new file) is read from its start.
    pub fn read(&mut self, start: Start) -> Result<Vec<String>, String> {
        let path = newest_path(&self.pattern).ok_or_else(|| format!("{}: no such file", self.pattern.display()))?;
        let meta = std::fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let id = file_id(&meta);
        let mut lines = vec![];
        let first = self.current.is_none();
        if self.current.as_ref().is_none_or(|(cid, _)| *cid != id) {
            // finish the old file through the handle we hold (renamed or deleted, it still reads), then the new one
            if let Some((_, mut old)) = self.current.take() {
                self.drain(&mut old, &mut lines);
                let rest = std::mem::take(&mut self.partial);
                if !rest.is_empty() && !self.skip_fragment {
                    lines.push(String::from_utf8_lossy(&rest).into_owned()); // no newline is coming to it
                }
            }
            let f = File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let len = meta.len();
            self.offset = match (first, start) {
                (true, Start::End) => len,
                (true, Start::Last(n)) => len.saturating_sub(n),
                (false, _) => 0,
            };
            self.partial.clear();
            self.skip_fragment = first && self.offset > 0 && matches!(start, Start::Last(_));
            self.current = Some((id, f));
        }
        let (cid, mut f) = self.current.take().expect("set above");
        self.drain(&mut f, &mut lines);
        self.current = Some((cid, f));
        Ok(lines)
    }

    /// Read from the offset to the end of `f` (from 0 again after a truncation), keeping a partial last line.
    fn drain(&mut self, f: &mut File, out: &mut Vec<String>) {
        let Ok(end) = f.seek(SeekFrom::End(0)) else { return };
        if end < self.offset {
            self.offset = 0; // truncated: start again
            self.partial.clear();
            self.skip_fragment = false;
        }
        if end == self.offset || f.seek(SeekFrom::Start(self.offset)).is_err() {
            return;
        }
        let mut data = vec![];
        let n = f.take(MAX_READ).read_to_end(&mut data).unwrap_or(0);
        self.offset += n as u64;
        let mut buf = std::mem::take(&mut self.partial);
        buf.extend_from_slice(&data[..n]);
        let mut parts: Vec<&[u8]> = buf.split(|b| *b == b'\n').collect();
        let last = parts.pop().unwrap_or_default();
        for p in parts {
            if std::mem::take(&mut self.skip_fragment) {
                continue;
            }
            let s = String::from_utf8_lossy(p);
            let s = s.trim_end_matches('\r');
            if !s.is_empty() {
                out.push(s.to_string());
            }
        }
        if last.len() <= MAX_PARTIAL {
            self.partial = last.to_vec();
        } else {
            self.skip_fragment = true; // an overlong line: drop it whole
        }
    }
}

// ------------------------------------------------------------------ progress and phase sources

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressKind {
    Jsonl { path: String, filter: EventFilter },
    LogRegex { path: String, regex: String },
    Exec(Vec<String>),
}

impl ProgressKind {
    pub fn from_json(j: &Value) -> Option<Self> {
        if !j.is_object() {
            return None;
        }
        let o = Some(j);
        if let Some(p) = str_of(get(o, "jsonl")) {
            return Some(ProgressKind::Jsonl { path: p.to_string(), filter: EventFilter::from_json(o) });
        }
        if let (Some(rx), Some(file)) = (str_of(get(o, "log_regex")), str_of(get(o, "path"))) {
            return Some(ProgressKind::LogRegex { path: file.to_string(), regex: rx.to_string() });
        }
        let argv: Vec<String> =
            get(o, "exec")?.as_array()?.iter().filter_map(|x| x.as_str().map(str::to_string)).collect();
        (!argv.is_empty()).then_some(ProgressKind::Exec(argv))
    }

    /// The source path (none for a probe).
    pub fn path(&self) -> Option<&str> {
        match self {
            ProgressKind::Jsonl { path, .. } | ProgressKind::LogRegex { path, .. } => Some(path),
            ProgressKind::Exec(_) => None,
        }
    }
}

/// Counts matching lines (or regex matches) of a tail.
#[derive(Debug)]
pub struct LineCounter {
    tail: Tail,
    filter: Option<EventFilter>,
    regex: Option<Regex>,
}

impl LineCounter {
    pub fn new(path: impl Into<PathBuf>, kind: &ProgressKind) -> Option<Self> {
        let (filter, regex) = match kind {
            ProgressKind::Jsonl { filter, .. } => (Some(filter.clone()), None),
            ProgressKind::LogRegex { regex, .. } => (None, Some(Regex::new(regex).ok()?)),
            ProgressKind::Exec(_) => return None,
        };
        Some(Self { tail: Tail::new(path), filter, regex })
    }

    pub fn tail(&self) -> &Tail {
        &self.tail
    }

    /// Matching events since the last read (Err: unreadable). The first read only finds the end.
    pub fn count(&mut self) -> Result<u64, String> {
        let lines = self.tail.read(Start::End)?;
        Ok(match (&self.regex, &self.filter) {
            (Some(re), _) => lines.iter().map(|l| re.find_iter(l).filter(|m| m.is_ok()).count() as u64).sum(),
            (None, Some(f)) => lines.iter().filter(|l| f.counts(l)).count() as u64,
            _ => 0,
        })
    }
}

/// Follows a phase from a tail.
#[derive(Debug)]
pub struct PhaseTail {
    tail: Tail,
    rule: PhaseRule,
    pub on: bool,
}

/// How far back a phase reader looks when it starts (the newest state already written).
pub const PHASE_LOOKBACK: u64 = 4 << 20;

impl PhaseTail {
    pub fn new(path: impl Into<PathBuf>, rule: PhaseRule) -> Self {
        Self { tail: Tail::new(path), rule, on: false }
    }

    pub fn tail(&self) -> &Tail {
        &self.tail
    }

    /// Read what is new; Ok(true) when the phase changed. Err: unreadable (the phase keeps its last state).
    pub fn poll(&mut self) -> Result<bool, String> {
        let lines = self.tail.read(Start::Last(PHASE_LOOKBACK))?;
        let before = self.on;
        for l in &lines {
            if let Some(on) = self.rule.apply(l) {
                self.on = on;
            }
        }
        Ok(self.on != before)
    }
}

/// Run an owner-written probe and parse the number it prints (the owner's path as written, never a PATH lookup).
pub fn run_probe(argv: &[String]) -> Option<f64> {
    let p = Path::new(argv.first()?);
    let exe = if p.is_absolute() || p.parent().is_some_and(|d| !d.as_os_str().is_empty()) {
        p.to_path_buf()
    } else {
        Path::new(".").join(p)
    };
    let out = Command::new(exe).args(&argv[1..]).stdout(Stdio::piped()).output().ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

enum Prog {
    Lines(LineCounter),
    Exec(Vec<String>),
    Person { key: String, last: Option<(u64, u64)> },
}

struct ProgressState {
    reader: Prog,
    last_at: Option<f64>,
    readable: bool,
}

enum PhaseReader {
    Tail(PhaseTail),
    Person(String),
    Exec,
}

struct PhaseState {
    reader: PhaseReader,
    on: bool,
    since: Option<f64>,
    readable: bool,
}

/// A phase spec that is a process trigger (`on_exec`) rather than a file.
pub fn is_exec_phase(spec: &Value) -> bool {
    spec.get("on_exec").is_some_and(|v| v.is_object())
}

/// What a configured `during` block is, for telemetry and the event path.
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub rule: String,
    pub block: usize,
    pub tags: Vec<String>,
    pub immediate: bool,
    pub spec: Value,
}

/// Owner sources read from files and owner-written probes (portable: std only), and, in a system install, from
/// the people's session helpers.
#[derive(Default)]
pub struct FileOwnerSources {
    system: bool,
    person: Option<Arc<dyn PersonReader>>,
    progress: HashMap<String, ProgressState>,
    phases: HashMap<String, PhaseState>,
    /// Every `during` block of the config, by key.
    pub blocks: HashMap<String, BlockInfo>,
}

impl FileOwnerSources {
    pub fn new() -> Self {
        Self::default()
    }

    /// A system install's sources: paths in a person's home are read by their session helper through `person`
    /// (None: nobody relays them, and they read as unreadable).
    pub fn system(person: Option<Arc<dyn PersonReader>>) -> Self {
        Self { system: true, person, ..Self::default() }
    }

    fn location(&self, path: &str) -> Location {
        Location::of(path, self.system)
    }

    fn new_progress(&self, key: &str, spec: &Value) -> Option<ProgressState> {
        let kind = ProgressKind::from_json(spec)?;
        let reader = match &kind {
            ProgressKind::Exec(argv) => Prog::Exec(argv.clone()),
            k => match self.location(k.path()?) {
                Location::Agent(p) => Prog::Lines(LineCounter::new(p, k)?),
                Location::Person { .. } => Prog::Person { key: key.to_string(), last: None },
            },
        };
        Some(ProgressState { reader, last_at: None, readable: true })
    }

    fn new_phase(&self, key: &str, spec: &Value) -> Option<PhaseState> {
        let reader = if is_exec_phase(spec) {
            PhaseReader::Exec
        } else {
            let rule = PhaseRule::from_json(spec)?;
            match self.location(str_of(spec.get("jsonl"))?) {
                Location::Agent(p) => PhaseReader::Tail(PhaseTail::new(p, rule)),
                Location::Person { .. } => PhaseReader::Person(key.to_string()),
            }
        };
        Some(PhaseState { reader, on: false, since: None, readable: true })
    }

    /// Whether a progress source has its reader yet.
    pub fn has_progress(&self, key: &str) -> bool {
        self.progress.contains_key(key)
    }

    /// A phase's last read state (on, readable).
    pub fn phase_state(&self, key: &str) -> Option<(bool, bool)> {
        self.phases.get(key).map(|p| (p.on, p.readable))
    }

    /// The paths (or globs) the agent reads itself, by key: what a watcher watches.
    pub fn agent_paths(&mut self) -> Vec<(String, PathBuf)> {
        // every configured source gets its reader now, so a watcher knows its path before the first tick reads it
        let blocks: Vec<(String, Value)> = self.blocks.iter().map(|(k, b)| (k.clone(), b.spec.clone())).collect();
        for (k, spec) in blocks {
            if !self.phases.contains_key(&k) {
                if let Some(p) = self.new_phase(&k, &spec) {
                    self.phases.insert(k, p);
                }
            }
        }
        let mut out = vec![];
        for (k, p) in &self.progress {
            if let Prog::Lines(c) = &p.reader {
                out.push((k.clone(), c.tail().pattern().to_path_buf()));
            }
        }
        for (k, p) in &self.phases {
            if let PhaseReader::Tail(t) = &p.reader {
                out.push((k.clone(), t.tail().pattern().to_path_buf()));
            }
        }
        out.sort();
        out
    }

    /// Re-read one configured phase now (the event path): its state, and whether it changed.
    pub fn repoll_phase(&mut self, key: &str, now: f64) -> Option<(bool, bool)> {
        let spec = self.blocks.get(key)?.spec.clone();
        if is_exec_phase(&spec) {
            return None;
        }
        let before = self.phases.get(key).map(|p| p.on);
        let on = self.read_phase(key, &spec, now);
        Some((on, before != Some(on) && (before.is_some() || on)))
    }

    fn read_phase(&mut self, key: &str, spec: &Value, now: f64) -> bool {
        if !self.phases.contains_key(key) {
            match self.new_phase(key, spec) {
                Some(p) => {
                    self.phases.insert(key.to_string(), p);
                }
                None => return false,
            }
        }
        let person = self.person.clone();
        let st = self.phases.get_mut(key).expect("inserted");
        let (on, readable) = match &mut st.reader {
            PhaseReader::Tail(t) => match t.poll() {
                Ok(_) => (t.on, true),
                Err(_) => (st.on, false),
            },
            PhaseReader::Person(k) => match person.as_ref().and_then(|p| p.reading(k)) {
                Some(r) => (r.on, r.readable),
                None => (st.on, false),
            },
            PhaseReader::Exec => (st.on, true),
        };
        if on != st.on {
            st.since = Some(now);
        }
        st.on = on;
        st.readable = readable;
        on
    }

    /// The person-read sources of the config, for the session helpers.
    pub fn relayed(&self, cfg: &ProtectionConfig) -> Vec<RelayedSource> {
        let mut out = vec![];
        let mut push = |key: String, kind: &str, spec: &Value, path: Option<&str>| {
            if let Some(Location::Person { account, rel }) = path.map(|p| self.location(p)) {
                let mut s = spec.clone();
                if let Some(o) = s.as_object_mut() {
                    o.remove("jsonl");
                    o.remove("path");
                    o.remove("exec");
                }
                out.push(RelayedSource { key, kind: kind.into(), account, rel, spec: s });
            }
        };
        for r in &cfg.rules {
            if let Some(src) = r.protect.as_ref().and_then(|p| p.source_json.as_ref()) {
                let path = ProgressKind::from_json(src).and_then(|k| k.path().map(str::to_string));
                push(r.id.clone(), "progress", src, path.as_deref());
            }
            for (n, d) in r.during.iter().enumerate() {
                if !is_exec_phase(&d.source_json) {
                    push(format!("{}#{n}", r.id), "phase", &d.source_json, str_of(d.source_json.get("jsonl")));
                }
            }
        }
        out
    }
}

impl OwnerSources for FileOwnerSources {
    fn progress(&mut self, key: &str, spec: &Value, now: f64) -> Option<Progress> {
        if !self.progress.contains_key(key) {
            let p = self.new_progress(key, spec)?;
            self.progress.insert(key.to_string(), p);
        }
        let person = self.person.clone();
        let st = self.progress.get_mut(key)?;
        let events = match &mut st.reader {
            // the probe prints a rate itself
            Prog::Exec(argv) => return run_probe(argv).map(|r| Progress { events: r, seconds: 1.0 }),
            Prog::Lines(c) => match c.count() {
                Ok(n) => {
                    st.readable = true;
                    n as f64
                }
                Err(_) => {
                    st.readable = false;
                    st.last_at = None;
                    return None;
                }
            },
            Prog::Person { key, last } => {
                let Some(r) = person.as_ref().and_then(|p| p.reading(key)).filter(|r| r.readable) else {
                    st.readable = false;
                    st.last_at = None;
                    *last = None;
                    return None;
                };
                st.readable = true;
                match last.replace((r.epoch, r.events)) {
                    Some((e, n)) if e == r.epoch && r.events >= n => (r.events - n) as f64,
                    _ => {
                        st.last_at = Some(now); // a new baseline
                        return None;
                    }
                }
            }
        };
        // the first read only sets the baseline
        let last = st.last_at.replace(now)?;
        let seconds = now - last;
        (seconds > 0.0).then_some(Progress { events, seconds })
    }

    /// On when the source says so, and also while it cannot be read (never looser: a phase source in a person's
    /// home with no helper to read it, a glob that matches nothing). The condition is reported
    /// (`PROTECTION_SOURCE_UNREADABLE`, `PROTECTION_SOURCE_NEEDS_HELPER`).
    fn progress_status(&self, key: &str) -> Option<(bool, String)> {
        let p = self.progress.get(key)?;
        let reader = match p.reader {
            Prog::Person { .. } => "helper",
            Prog::Exec(_) => "exec",
            Prog::Lines(_) => "agent",
        };
        Some((p.readable, reader.into()))
    }

    fn phase_on(&mut self, key: &str, spec: &Value) -> bool {
        let on = self.read_phase(key, spec, wall_now());
        on || self.phases.get(key).is_some_and(|p| !p.readable)
    }

    fn configure(&mut self, cfg: &ProtectionConfig) {
        self.blocks.clear();
        for r in &cfg.rules {
            for (n, d) in r.during.iter().enumerate() {
                self.blocks.insert(
                    format!("{}#{n}", r.id),
                    BlockInfo {
                        rule: r.id.clone(),
                        block: n,
                        tags: d.tags.clone(),
                        immediate: r.immediate,
                        spec: d.source_json.clone(),
                    },
                );
            }
        }
        if let Some(p) = &self.person {
            p.want(self.relayed(cfg));
        }
    }

    fn set_exec_phase(&mut self, key: &str, on: bool) {
        let now = wall_now();
        let st = self
            .phases
            .entry(key.to_string())
            .or_insert(PhaseState { reader: PhaseReader::Exec, on: false, since: None, readable: true });
        if st.on != on {
            st.since = Some(now);
        }
        st.on = on;
    }

    fn phases(&self) -> Vec<PhaseReport> {
        let mut out: Vec<PhaseReport> = self
            .blocks
            .iter()
            .map(|(k, b)| {
                let st = self.phases.get(k);
                let reader = match st.map(|s| &s.reader) {
                    Some(PhaseReader::Person(_)) => "helper",
                    Some(PhaseReader::Exec) => "exec",
                    _ if is_exec_phase(&b.spec) => "exec",
                    _ => "agent",
                };
                PhaseReport {
                    key: k.clone(),
                    rule: b.rule.clone(),
                    block: b.block,
                    on: st.is_some_and(|s| s.on),
                    since: st.and_then(|s| s.since),
                    readable: st.is_none_or(|s| s.readable),
                    reader: reader.into(),
                    tags: b.tags.clone(),
                    immediate: b.immediate,
                }
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    }

    fn reset(&mut self) {
        self.progress.clear();
        self.phases.clear();
    }
}

/// The newest file matching a simple `*` glob in the last path component (`~` is the agent's own home).
pub fn newest(pattern: &str) -> Option<PathBuf> {
    match Location::of(pattern, false) {
        Location::Agent(p) => newest_path(&p),
        Location::Person { .. } => None,
    }
}

/// The newest file matching a path whose last component may hold `*` (by modification time, then name).
pub fn newest_path(full: &Path) -> Option<PathBuf> {
    let pat = full.file_name()?.to_string_lossy().into_owned();
    if !pat.contains('*') {
        return full.is_file().then(|| full.to_path_buf());
    }
    let dir = full.parent().map(Path::to_path_buf).unwrap_or_default();
    let mtime = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
    std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| name_matches(&pat, &e.file_name().to_string_lossy()) && e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.path())
        .max_by_key(|p| (mtime(p), p.clone()))
}

/// Whether a file name matches a last-component glob (`*` matches any run of characters).
pub fn name_matches(pat: &str, name: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return pat == name;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if name.len() < first.len() + last.len() || !name.starts_with(first) || !name.ends_with(last) {
        return false;
    }
    // the middle pieces in order, between the prefix and the suffix
    let mut rest = &name[first.len()..name.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}
