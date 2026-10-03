//! Rule matching. Gives the same answers as the console's preview matcher
//! (`oarbank.contracts.protection_match`), checked by shared test vectors (D20).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use fancy_regex::Regex;

use crate::config::{ProcessMatch, TreeScope};
use crate::model::{ProcessKey, ProcessRecord};

/// Compiled argv regexes, by pattern (owner configs hold a handful; a broken pattern caches as None).
fn compiled(pattern: &str) -> Option<Arc<Regex>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Arc<Regex>>>>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(r) = cache.get(pattern) {
        return r.clone();
    }
    if cache.len() >= 256 {
        cache.clear();
    }
    let r = Regex::new(pattern).ok().map(Arc::new);
    cache.insert(pattern.to_string(), r.clone());
    r
}

fn key_set(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|s| !s.is_empty())
}

/// How one process stands against a rule's match keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// A key does not hold.
    No,
    /// Every key holds.
    Yes,
    /// No key fails, but one needs a fact the agent could not read (another account's path or arguments).
    /// It counts as a match: a failed identity lookup never leaves a process unprotected.
    Unreadable,
}

/// Check one process against the match keys: all given keys must hold; an empty key is no key.
pub fn check(p: &ProcessRecord, m: &ProcessMatch) -> Match {
    let mut unreadable = false;
    if let Some(r) = key_set(&m.requirement) {
        if !p.requirements_met.contains(r) {
            return Match::No;
        }
    }
    if let Some(t) = key_set(&m.team_id) {
        if p.team_id.as_deref() != Some(t) {
            return Match::No;
        }
    }
    if let Some(i) = key_set(&m.identifier) {
        if p.signing_id.as_deref() != Some(i) {
            return Match::No;
        }
    }
    if !m.bundle_ids.is_empty()
        && !p
            .bundle_id
            .as_ref()
            .is_some_and(|b| m.bundle_ids.contains(b))
    {
        return Match::No;
    }
    if let Some(pre) = key_set(&m.path_prefix) {
        match &p.path {
            Some(path) if !path.starts_with(pre) => return Match::No,
            Some(_) => {}
            None => unreadable = true,
        }
    }
    if let Some(c) = key_set(&m.path_contains) {
        // the command line as `ps` shows it: the path plus arguments (a marker may sit in an argument); what
        // is known may already hold it, else an unreadable part might
        let mut line = p.path.clone().unwrap_or_default();
        for a in p.argv.iter().flatten().skip(1) {
            line.push(' ');
            line.push_str(a);
        }
        if !line.contains(c) {
            if p.path.is_some() && p.argv.is_some() {
                return Match::No;
            }
            unreadable = true;
        }
    }
    if let Some(n) = key_set(&m.name) {
        match p.effective_comm() {
            Some(comm) if comm != n => return Match::No,
            Some(_) => {}
            None => unreadable = true,
        }
    }
    if let Some(rx) = key_set(&m.argv_regex) {
        match &p.argv {
            Some(argv) => {
                let joined = argv.join(" ");
                if !compiled(rx).is_some_and(|re| re.is_match(&joined).unwrap_or(false)) {
                    return Match::No;
                }
            }
            None => unreadable = true,
        }
    }
    if unreadable {
        Match::Unreadable
    } else {
        Match::Yes
    }
}

/// Does one process satisfy the match keys (an unreadable fact counts as satisfying its key)?
pub fn matches(p: &ProcessRecord, m: &ProcessMatch) -> bool {
    check(p, m) != Match::No
}

/// The processes a rule protects, sorted by pid: the direct matches plus their tree (descendants through
/// ppid, or every process sharing a matched Team ID).
pub fn group(procs: &[ProcessRecord], m: &ProcessMatch, tree: TreeScope) -> Vec<ProcessRecord> {
    let direct: Vec<&ProcessRecord> = procs.iter().filter(|p| matches(p, m)).collect();
    if direct.is_empty() {
        return vec![];
    }
    let mut out: Vec<&ProcessRecord> = match tree {
        TreeScope::SelfOnly => direct,
        TreeScope::SameTeam => {
            let teams: HashSet<&str> = direct
                .iter()
                .filter_map(|p| p.team_id.as_deref())
                .filter(|t| !t.is_empty())
                .collect();
            let keys: HashSet<ProcessKey> = direct.iter().map(|p| p.key()).collect();
            procs
                .iter()
                .filter(|p| {
                    keys.contains(&p.key())
                        || p.team_id.as_deref().is_some_and(|t| teams.contains(t))
                })
                .collect()
        }
        TreeScope::Descendants => {
            let mut children: HashMap<i32, Vec<&ProcessRecord>> = HashMap::new();
            for p in procs {
                children.entry(p.ppid).or_default().push(p);
            }
            let mut seen = HashSet::new();
            let mut out = vec![];
            let mut stack = direct;
            while let Some(p) = stack.pop() {
                if !seen.insert(p.key()) {
                    continue;
                }
                out.push(p);
                // a child started before its parent is a reused ppid, not a descendant
                if let Some(cs) = children.get(&p.pid) {
                    stack.extend(
                        cs.iter()
                            .filter(|c| c.start_us >= p.start_us && c.pid != p.pid),
                    );
                }
            }
            out
        }
    };
    out.sort_by_key(|p| p.pid);
    out.into_iter().cloned().collect()
}
