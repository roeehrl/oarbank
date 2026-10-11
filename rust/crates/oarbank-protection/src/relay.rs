//! The session helper's side of the owner-source relay (D51). A system install's agent runs as a service account
//! that may not read a person's home, where owner programs usually keep their logs and event files. The service
//! tells each helper which sources under its person's home to read (`Watch`, from the owner's protection config);
//! the helper reads them as the person, with the same rotation-safe tail and the same event-driven watcher as the
//! agent, and reports per source only what protection needs: a count of matching events, the phase, and whether the
//! source could be read. No file content leaves the helper, and the helper gains no privilege: it reads only what
//! its person can read, only paths under that person's home, and never runs a probe (`exec` sources stay the
//! agent's).
//!
//! A phase change is reported at once (the report loop is woken), so a relayed phase reaches the service's event
//! path within milliseconds, like one the agent watches itself.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::session::{SourceReport, Watch};
use crate::sources::{
    wall_now, LineCounter, PersonReading, PhaseRule, PhaseTail, ProgressKind, RelayedSource,
};
use crate::watch::Watcher;

enum Reader {
    Count(LineCounter),
    Phase(PhaseTail),
}

struct Source {
    reader: Option<Reader>,
    reading: PersonReading,
}

#[derive(Default)]
struct Inner {
    want: Vec<RelayedSource>,
    sources: HashMap<String, Source>,
    epoch: u64,
    /// A phase changed since the last report: report now.
    urgent: bool,
}

/// What a helper reads for the service.
pub struct Relay {
    home: PathBuf,
    account: Option<String>,
    inner: Arc<Mutex<Inner>>,
    wake: Arc<Condvar>,
    watcher: Option<Watcher>,
}

/// A relative path that stays under the home (no `..`, not absolute).
fn under(home: &Path, rel: &str) -> Option<PathBuf> {
    let p = Path::new(rel);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return None;
    }
    Some(home.join(p))
}

impl Relay {
    /// A relay reading under `home`, for the person `account` (None: unknown).
    pub fn new(home: PathBuf, account: Option<String>) -> Arc<Relay> {
        let inner = Arc::new(Mutex::new(Inner {
            epoch: (wall_now() * 1000.0) as u64,
            ..Inner::default()
        }));
        let wake = Arc::new(Condvar::new());
        let (i2, w2) = (Arc::downgrade(&inner), wake.clone());
        let watcher = Watcher::spawn(Box::new(move |keys, t| {
            if let Some(i) = i2.upgrade() {
                let mut g = i.lock().unwrap_or_else(|e| e.into_inner());
                if poll(&mut g, &keys, t) {
                    g.urgent = true;
                    w2.notify_all();
                }
            }
        }))
        .ok();
        Arc::new(Relay { home, account, inner, wake, watcher })
    }

    /// This process's own relay (its HOME and account).
    pub fn own() -> Arc<Relay> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let account = std::env::var("USER").ok().or_else(|| std::env::var("USERNAME").ok());
        Relay::new(home, account)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The service's list (a `Watch` line). Sources for another account are left out (the service sends only
    /// ours where it knows who we are; on Windows, where the pipe proves the session but not the account, this
    /// filter is the helper's own).
    pub fn set(&self, w: Watch) {
        let want: Vec<RelayedSource> = w
            .watch
            .into_iter()
            .filter(|s| s.account.is_none() || s.account == self.account)
            .collect();
        let mut g = self.lock();
        if g.want == want {
            return;
        }
        g.sources.clear();
        for s in &want {
            let reader = under(&self.home, &s.rel).and_then(|path| match s.kind.as_str() {
                "progress" => {
                    let mut spec = s.spec.clone();
                    let field = if spec.get("log_regex").is_some() { "path" } else { "jsonl" };
                    if let Some(o) = spec.as_object_mut() {
                        o.insert(field.into(), path.to_string_lossy().into_owned().into());
                    }
                    LineCounter::new(path, &ProgressKind::from_json(&spec)?).map(Reader::Count)
                }
                "phase" => PhaseRule::from_json(&s.spec).map(|r| Reader::Phase(PhaseTail::new(path, r))),
                _ => None,
            });
            let epoch = g.epoch;
            g.sources.insert(s.key.clone(), Source { reader, reading: PersonReading { epoch, ..PersonReading::default() } });
        }
        g.epoch += 1;
        g.want = want;
        let keys: Vec<String> = g.sources.keys().cloned().collect();
        poll(&mut g, &keys, wall_now());
        let targets: Vec<(String, PathBuf)> = g
            .want
            .iter()
            .filter_map(|s| Some((s.key.clone(), under(&self.home, &s.rel)?)))
            .collect();
        drop(g);
        if let Some(w) = &self.watcher {
            w.set(targets);
        }
    }

    /// Every source as read now (the periodic read: the safety net under the watcher).
    pub fn readings(&self) -> Vec<SourceReport> {
        let mut g = self.lock();
        let keys: Vec<String> = g.sources.keys().cloned().collect();
        poll(&mut g, &keys, wall_now());
        g.urgent = false;
        let mut out: Vec<SourceReport> =
            g.sources.iter().map(|(k, s)| SourceReport { key: k.clone(), reading: s.reading }).collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    }

    /// Wait up to `timeout` for a phase change (true: one happened, report now).
    pub fn wait(&self, timeout: Duration) -> bool {
        let g = self.lock();
        if g.urgent {
            return true;
        }
        let (g, _) = self.wake.wait_timeout(g, timeout).unwrap_or_else(|e| e.into_inner());
        g.urgent
    }
}

/// Read the given sources; true when a phase changed (or became readable or unreadable).
fn poll(g: &mut Inner, keys: &[String], t: f64) -> bool {
    let mut urgent = false;
    for k in keys {
        let Some(s) = g.sources.get_mut(k) else { continue };
        let before = s.reading;
        match &mut s.reader {
            None => s.reading.readable = false,
            Some(Reader::Count(c)) => match c.count() {
                Ok(n) => {
                    s.reading.events += n;
                    s.reading.readable = true;
                    if n > 0 {
                        s.reading.event_t = t;
                    }
                }
                Err(_) => s.reading.readable = false,
            },
            Some(Reader::Phase(p)) => match p.poll() {
                Ok(_) => {
                    s.reading.on = p.on;
                    s.reading.readable = true;
                }
                Err(_) => s.reading.readable = false,
            },
        }
        if s.reading.on != before.on || s.reading.readable != before.readable {
            s.reading.event_t = t;
            urgent = true;
        }
    }
    urgent
}
