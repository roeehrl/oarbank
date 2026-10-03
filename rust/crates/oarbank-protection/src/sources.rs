//! Owner-supplied sources (never from a module): progress rates for `protect.metric = progress_rate`, and
//! phase files for `during` rules. Owner configuration may exec a probe because the owner wrote it.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use fancy_regex::Regex;
use serde_json::Value;

use crate::json::{get, str_of};

/// How the controller reads owner sources. Keys are stable per rule (`<rule id>` for progress,
/// `<rule id>#<n>` for a rule's n-th `during` block); `reset` drops all state when the config changes.
pub trait OwnerSources: Send {
    /// Events per second since the last read (None on the first read, or when unreadable).
    fn progress_rate(&mut self, key: &str, spec: &Value, now: f64) -> Option<f64>;
    /// Whether the phase is on (the newest enter/exit event decides).
    fn phase_on(&mut self, key: &str, spec: &Value) -> bool;
    fn reset(&mut self);
}

/// No owner sources: progress unknown, phases off.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOwnerSources;

impl OwnerSources for NoOwnerSources {
    fn progress_rate(&mut self, _: &str, _: &Value, _: f64) -> Option<f64> {
        None
    }
    fn phase_on(&mut self, _: &str, _: &Value) -> bool {
        false
    }
    fn reset(&mut self) {}
}

/// Owner sources read from files and owner-written probes (portable: std only).
#[derive(Default)]
pub struct FileOwnerSources {
    progress: HashMap<String, ProgressSource>,
    phases: HashMap<String, PhaseSource>,
}

impl FileOwnerSources {
    pub fn new() -> Self {
        Self::default()
    }
}

impl OwnerSources for FileOwnerSources {
    fn progress_rate(&mut self, key: &str, spec: &Value, now: f64) -> Option<f64> {
        if !self.progress.contains_key(key) {
            self.progress
                .insert(key.to_string(), ProgressSource::from_json(spec)?);
        }
        self.progress.get_mut(key)?.rate(now)
    }

    fn phase_on(&mut self, key: &str, spec: &Value) -> bool {
        if !self.phases.contains_key(key) {
            match PhaseSource::from_json(spec) {
                Some(p) => self.phases.insert(key.to_string(), p),
                None => return false,
            };
        }
        self.phases.get_mut(key).is_some_and(|p| p.poll())
    }

    fn reset(&mut self) {
        self.progress.clear();
        self.phases.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressKind {
    Jsonl { path: String, event: String },
    LogRegex { path: String, regex: String },
    Exec(Vec<String>),
}

/// Counts matching events per window from a JSONL file, a log regex, or an exec probe printing a number.
#[derive(Debug, Clone)]
pub struct ProgressSource {
    pub kind: ProgressKind,
    offset: u64,
    file: Option<PathBuf>,
    last_at: Option<f64>,
}

impl ProgressSource {
    pub fn new(kind: ProgressKind) -> Self {
        Self {
            kind,
            offset: 0,
            file: None,
            last_at: None,
        }
    }

    pub fn from_json(j: &Value) -> Option<Self> {
        if !j.is_object() {
            return None;
        }
        let j = Some(j);
        if let Some(p) = str_of(get(j, "jsonl")) {
            let event = str_of(get(j, "event")).unwrap_or("").to_string();
            return Some(Self::new(ProgressKind::Jsonl {
                path: p.to_string(),
                event,
            }));
        }
        if let (Some(rx), Some(file)) = (str_of(get(j, "log_regex")), str_of(get(j, "path"))) {
            return Some(Self::new(ProgressKind::LogRegex {
                path: file.to_string(),
                regex: rx.to_string(),
            }));
        }
        let argv: Vec<String> = get(j, "exec")?
            .as_array()?
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect();
        (!argv.is_empty()).then(|| Self::new(ProgressKind::Exec(argv)))
    }

    /// Events per second since the last read (None on the first read or when the source is unreadable).
    pub fn rate(&mut self, now: f64) -> Option<f64> {
        let (pattern, event) = match &self.kind {
            ProgressKind::Exec(argv) => {
                // the owner's path as written, never a PATH lookup (a bare name is relative to the cwd)
                let p = Path::new(&argv[0]);
                let exe = if p.is_absolute() || p.parent().is_some_and(|d| !d.as_os_str().is_empty()) {
                    p.to_path_buf()
                } else {
                    Path::new(".").join(p)
                };
                let out = Command::new(exe)
                    .args(&argv[1..])
                    .stdout(Stdio::piped())
                    .output()
                    .ok()?;
                return String::from_utf8_lossy(&out.stdout).trim().parse().ok();
            }
            ProgressKind::Jsonl { path, event } | ProgressKind::LogRegex { path, regex: event } => {
                (path.clone(), event.clone())
            }
        };
        let path = newest(&pattern)?;
        let mut f = File::open(&path).ok()?;
        if self.file.as_ref() != Some(&path) {
            self.file = Some(path);
            self.offset = 0;
            self.last_at = None;
        }
        let end = f.seek(SeekFrom::End(0)).ok()?;
        if end < self.offset {
            self.offset = 0;
        }
        let Some(last) = self.last_at else {
            self.offset = end;
            self.last_at = Some(now);
            return None;
        };
        f.seek(SeekFrom::Start(self.offset)).ok()?;
        let mut data = vec![];
        f.read_to_end(&mut data).ok()?;
        self.offset = end;
        let text = String::from_utf8_lossy(&data);
        let regex = match self.kind {
            ProgressKind::LogRegex { .. } => Regex::new(&event).ok(),
            _ => None,
        };
        let n = match regex {
            Some(re) => re.find_iter(&*text).filter(|m| m.is_ok()).count(),
            None => count_lines(&text, &event),
        };
        let dt = now - last;
        self.last_at = Some(now);
        (dt > 0.0).then(|| n as f64 / dt)
    }
}

/// Non-empty lines carrying `"<event>"` (every line when the event is empty).
fn count_lines(text: &str, event: &str) -> usize {
    let quoted = format!("\"{event}\"");
    text.split('\n')
        .filter(|l| !l.is_empty() && (event.is_empty() || l.contains(&quoted)))
        .count()
}

/// A phase source for `during` rules: a JSONL file whose newest enter/exit event decides.
#[derive(Debug, Clone)]
pub struct PhaseSource {
    pattern: String,
    enter: String,
    exit: String,
    on: bool,
    offset: u64,
    file: Option<PathBuf>,
}

impl PhaseSource {
    pub fn from_json(j: &Value) -> Option<Self> {
        let j = Some(j);
        Some(Self {
            pattern: str_of(get(j, "jsonl"))?.to_string(),
            enter: str_of(get(j, "enter"))?.to_string(),
            exit: str_of(get(j, "exit"))?.to_string(),
            on: false,
            offset: 0,
            file: None,
        })
    }

    pub fn poll(&mut self) -> bool {
        let Some(path) = newest(&self.pattern) else {
            return self.on;
        };
        let Ok(mut f) = File::open(&path) else {
            return self.on;
        };
        if self.file.as_ref() != Some(&path) {
            self.file = Some(path);
            self.offset = 0;
        }
        let Ok(end) = f.seek(SeekFrom::End(0)) else {
            return self.on;
        };
        if end < self.offset {
            self.offset = 0;
        }
        let mut data = vec![];
        if f.seek(SeekFrom::Start(self.offset)).is_ok() {
            let _ = f.read_to_end(&mut data);
        }
        self.offset = end;
        let (enter, exit) = (format!("\"{}\"", self.enter), format!("\"{}\"", self.exit));
        for line in String::from_utf8_lossy(&data)
            .split('\n')
            .filter(|l| !l.is_empty())
        {
            if line.contains(&enter) {
                self.on = true;
            }
            if line.contains(&exit) {
                self.on = false;
            }
        }
        self.on
    }
}

fn expand_tilde(p: &str) -> PathBuf {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    match (p.strip_prefix('~'), home) {
        (Some(rest), Some(h)) if rest.is_empty() || rest.starts_with('/') => {
            PathBuf::from(format!("{}{}", h.to_string_lossy(), rest))
        }
        _ => PathBuf::from(p),
    }
}

/// The newest file matching a simple `*` glob in the last path component.
pub fn newest(pattern: &str) -> Option<PathBuf> {
    let full = expand_tilde(pattern);
    let pat = full.file_name()?.to_string_lossy().into_owned();
    if !pat.contains('*') {
        return full.exists().then_some(full);
    }
    let dir = full.parent().map(Path::to_path_buf).unwrap_or_default();
    let parts: Vec<&str> = pat.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    let mtime = |p: &Path| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    };
    std::fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(first) && n.ends_with(last)
        })
        .map(|e| e.path())
        .max_by_key(|p| mtime(p))
}
