//! The dataset cache's index (docs/protocol.md, "Module cleanup"): which modules on this node use each cached dataset
//! and each loose blob (a checkpoint's files), and when each was last used. The blobs stay content-addressed in
//! `cache/blobs` (staging.rs) and a dataset's files are listed by its manifest under `state/datasets/`; the index is
//! `state/cache-index.json`.
//!
//! What goes, and when (`collect`):
//! - a dataset no module left on the node uses: at once once its last module was deleted (cleanup.rs), or, if it never
//!   had one (a prefetch, a cache from before the index), once it was not used for the idle period;
//! - a loose blob once it was not used for the idle period, or at once once its module was deleted;
//! - above the `disk_gb` cap, the least recently used datasets and loose blobs, until the cache fits;
//! - a blob nothing above names, an hour after it was written.
//!
//! A dataset or blob a running job or a staging holds (`hold`), or that pending work wants (the directive's prefetch
//! list), is never deleted.

use crate::paths::Layout;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// A blob nothing names is deleted only this long after it was written (a staging or an upload between writing it and
/// recording it).
const STRAY_AGE_S: f64 = 3600.0;

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Use {
    /// The modules whose jobs used it on this node.
    #[serde(default)]
    pub modules: BTreeSet<String>,
    /// When it was last staged or used (Unix seconds).
    #[serde(default)]
    pub used: f64,
    /// When its last module was deleted from the node: it goes at the next collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orphaned: Option<f64>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct Index {
    #[serde(default)]
    datasets: BTreeMap<String, Use>,
    /// Loose blobs by digest: a checkpoint's files, which no dataset lists.
    #[serde(default)]
    blobs: BTreeMap<String, Use>,
}

fn index_path(l: &Layout) -> PathBuf {
    l.state().join("cache-index.json")
}

/// One writer of the index at a time; a collection holds it while it decides and deletes, so a hold taken meanwhile
/// waits and then finds the blobs either kept or gone.
fn lock() -> MutexGuard<'static, ()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

fn holds() -> MutexGuard<'static, BTreeMap<String, usize>> {
    static H: OnceLock<Mutex<BTreeMap<String, usize>>> = OnceLock::new();
    H.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner())
}

fn load(l: &Layout) -> Index {
    std::fs::read(index_path(l)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(l: &Layout, ix: &Index) {
    if let Err(e) = serde_json::to_vec(ix).map_err(std::io::Error::other).and_then(|b| crate::fsutil::write_private(&index_path(l), &b)) {
        tracing::warn!(error = %e, "cannot keep the dataset cache's index");
    }
}

fn now() -> f64 {
    crate::doctor::now()
}

/// Datasets and blobs in use: never collected while a hold names them.
pub struct Hold(Vec<String>);

impl Drop for Hold {
    fn drop(&mut self) {
        let mut h = holds();
        for k in &self.0 {
            if let Some(n) = h.get_mut(k) {
                *n -= 1;
                if *n == 0 {
                    h.remove(k);
                }
            }
        }
    }
}

/// Hold datasets (by id) and blobs (by digest) until the returned value is dropped.
pub fn hold(datasets: &[String], blobs: &[String]) -> Hold {
    let _one = lock();
    let keys: Vec<String> = datasets.iter().map(|d| format!("d:{d}")).chain(blobs.iter().map(|b| format!("b:{b}"))).collect();
    let mut h = holds();
    for k in &keys {
        *h.entry(k.clone()).or_default() += 1;
    }
    Hold(keys)
}

fn held(h: &BTreeMap<String, usize>, kind: char, key: &str) -> bool {
    h.contains_key(&format!("{kind}:{key}"))
}

/// Datasets and blobs were staged or used now, by a job of `module` (None: a prefetch, an upload).
pub fn used(l: &Layout, datasets: &[String], blobs: &[String], module: Option<&str>) {
    let _one = lock();
    let mut ix = load(l);
    let t = now();
    for (map, keys) in [(&mut ix.datasets, datasets), (&mut ix.blobs, blobs)] {
        for k in keys {
            let u = map.entry(k.clone()).or_default();
            u.used = t;
            if let Some(m) = module {
                u.modules.insert(m.to_string());
                u.orphaned = None;
            }
        }
    }
    save(l, &ix);
}

/// A module was deleted from the node: it no longer uses anything, and what it was the last user of goes at the next
/// collection.
pub fn drop_module(l: &Layout, module: &str) {
    let _one = lock();
    let mut ix = load(l);
    let t = now();
    for u in ix.datasets.values_mut().chain(ix.blobs.values_mut()) {
        if u.modules.remove(module) && u.modules.is_empty() {
            u.orphaned = Some(t);
        }
    }
    save(l, &ix);
}

/// Every module the index names (what a module may have left in the cache).
pub fn modules(l: &Layout) -> BTreeSet<String> {
    let ix = load(l);
    ix.datasets.values().chain(ix.blobs.values()).flat_map(|u| u.modules.iter().cloned()).collect()
}

/// A cached dataset manifest: where it is, its id, its files' digests and sizes, and when it was written.
struct Manifest {
    path: PathBuf,
    id: String,
    files: Vec<(String, u64)>,
    written: f64,
}

fn manifests(l: &Layout) -> Vec<Manifest> {
    let mut out = vec![];
    for e in std::fs::read_dir(l.state().join("datasets")).into_iter().flatten().flatten() {
        let Ok(v) = std::fs::read(e.path()).map_err(|_| ()).and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|_| ())) else { continue };
        let Some(id) = v["dataset_id"].as_str() else { continue };
        let files = v["files"].as_array().into_iter().flatten()
            .filter_map(|f| Some((f["digest"].as_str()?.to_string(), f["size"].as_u64().unwrap_or(0)))).collect();
        let written = e.metadata().ok().and_then(|m| m.modified().ok()).map(secs).unwrap_or(0.0);
        out.push(Manifest { path: e.path(), id: id.to_string(), files, written });
    }
    out
}

fn secs(t: std::time::SystemTime) -> f64 {
    t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Delete a cached blob (read-only, which Windows refuses to delete as it is).
fn remove_blob(p: &Path) -> bool {
    if let Ok(m) = std::fs::metadata(p) {
        let mut perm = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        let _ = std::fs::set_permissions(p, perm);
    }
    std::fs::remove_file(p).is_ok()
}

/// What a collection keeps from, and to.
pub struct Keep<'a> {
    /// The modules still on the node: in its release, or waiting for their deletion.
    pub alive: &'a BTreeSet<String>,
    /// Datasets pending work wants here (the directive's prefetch list).
    pub wanted: &'a BTreeSet<String>,
    /// How long an unused dataset no module on the node uses (or an unused loose blob) stays.
    pub idle_s: f64,
    /// The `disk_gb` cap, in bytes.
    pub cap: Option<u64>,
}

/// What a collection did and left.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Collected {
    pub freed: u64,
    pub evicted: usize,
    /// What the cache holds now.
    pub bytes: u64,
    pub datasets: usize,
    pub cap: Option<u64>,
    /// Still above the cap: what is left is held or wanted.
    pub over_cap: bool,
    /// Per module: the bytes and datasets of what it uses (a dataset two modules use counts for each).
    pub by_module: BTreeMap<String, (u64, usize)>,
}

/// Collect the cache (the module comment says what goes).
pub fn collect(l: &Layout, k: &Keep, now: f64) -> Collected {
    let _one = lock();
    let mut ix = load(l);
    let h = holds().clone();
    let mut out = Collected { cap: k.cap, ..Default::default() };
    let mut kept: Vec<Manifest> = vec![];
    let mut gone: Vec<Manifest> = vec![];
    for m in manifests(l) {
        let u = ix.datasets.get(&m.id).cloned().unwrap_or(Use { used: m.written, ..Default::default() });
        let busy = held(&h, 'd', &m.id) || k.wanted.contains(&m.id);
        let users = u.modules.iter().any(|x| k.alive.contains(x));
        let stale = u.orphaned.is_some() || now - u.used >= k.idle_s;
        if busy || users || !stale {
            kept.push(m);
        } else {
            gone.push(m);
        }
    }
    let ids: BTreeSet<&str> = kept.iter().map(|m| m.id.as_str()).collect();
    ix.datasets.retain(|id, _| ids.contains(id.as_str()));
    let mut loose: BTreeMap<String, Use> = BTreeMap::new();
    for (d, u) in std::mem::take(&mut ix.blobs) {
        if held(&h, 'b', &d) || (u.orphaned.is_none() && now - u.used < k.idle_s) {
            loose.insert(d, u);
        }
    }
    for m in &gone {
        let _ = std::fs::remove_file(&m.path);
    }
    // every blob in the cache, with its size and when it was written
    let mut blobs: BTreeMap<String, (PathBuf, u64, f64)> = BTreeMap::new();
    for sub in std::fs::read_dir(l.cache_blobs()).into_iter().flatten().flatten() {
        for e in std::fs::read_dir(sub.path()).into_iter().flatten().flatten() {
            let Ok(meta) = e.metadata() else { continue };
            let written = meta.modified().ok().map(secs).unwrap_or(0.0);
            blobs.insert(e.file_name().to_string_lossy().to_string(), (e.path(), meta.len(), written));
        }
    }
    let named = |kept: &[Manifest], loose: &BTreeMap<String, Use>| -> BTreeSet<String> {
        kept.iter().flat_map(|m| m.files.iter().map(|f| f.0.clone())).chain(loose.keys().cloned()).collect()
    };
    let mut refs = named(&kept, &loose);
    for (d, (p, size, written)) in blobs.clone() {
        if !refs.contains(&d) && !held(&h, 'b', &d) && now - written >= STRAY_AGE_S && remove_blob(&p) {
            out.freed += size;
            blobs.remove(&d);
        }
    }
    let mut bytes: u64 = blobs.values().map(|b| b.1).sum();
    // above the cap: the least recently used dataset or loose blob that nothing holds or wants goes first
    if let Some(cap) = k.cap {
        let mut order: Vec<(f64, bool, String)> = kept.iter().filter(|m| !held(&h, 'd', &m.id) && !k.wanted.contains(&m.id))
            .map(|m| (ix.datasets.get(&m.id).map(|u| u.used).unwrap_or(m.written), true, m.id.clone()))
            .chain(loose.iter().filter(|(d, _)| !held(&h, 'b', d)).map(|(d, u)| (u.used, false, d.clone()))).collect();
        order.sort_by(|a, b| a.0.total_cmp(&b.0));
        for (_, dataset, key) in order {
            if bytes <= cap {
                break;
            }
            let digests: Vec<String> = if dataset {
                let Some(i) = kept.iter().position(|m| m.id == key) else { continue };
                let m = kept.remove(i);
                let _ = std::fs::remove_file(&m.path);
                ix.datasets.remove(&key);
                m.files.into_iter().map(|f| f.0).collect()
            } else {
                loose.remove(&key);
                vec![key]
            };
            out.evicted += 1;
            refs = named(&kept, &loose);
            for d in digests {
                let Some((p, size, _)) = blobs.get(&d).cloned() else { continue };
                if !refs.contains(&d) && !held(&h, 'b', &d) && remove_blob(&p) {
                    out.freed += size;
                    bytes -= size;
                    blobs.remove(&d);
                }
            }
        }
        out.over_cap = bytes > cap;
    }
    out.bytes = bytes;
    out.datasets = kept.len();
    for m in &kept {
        let size: u64 = m.files.iter().map(|f| f.1).sum();
        for x in ix.datasets.get(&m.id).map(|u| u.modules.clone()).unwrap_or_default() {
            let e = out.by_module.entry(x).or_default();
            e.0 += size;
            e.1 += 1;
        }
    }
    for (d, u) in &loose {
        let size = blobs.get(d).map(|b| b.1).unwrap_or(0);
        for x in &u.modules {
            out.by_module.entry(x.clone()).or_default().0 += size;
        }
    }
    ix.blobs = loose;
    save(l, &ix);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: f64 = 86400.0;

    /// A cache with datasets of blobs (each blob `size` bytes, written `age` seconds ago).
    struct Fx {
        _dir: tempfile::TempDir,
        l: Layout,
    }

    impl Fx {
        fn new(tag: &str) -> Fx {
            let d = crate::scratch(&format!("cache-{tag}"));
            let l = Layout::new(d.path().join("home"));
            l.ensure().unwrap();
            Fx { _dir: d, l }
        }

        fn blob(&self, digest: &str, size: usize, age: f64) {
            let p = crate::staging::blob_path(&self.l, digest);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, vec![b'x'; size]).unwrap();
            let t = std::time::SystemTime::now() - std::time::Duration::from_secs_f64(age);
            std::fs::File::options().write(true).open(&p).unwrap().set_modified(t).unwrap();
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_readonly(true);
            std::fs::set_permissions(&p, perm).unwrap();
        }

        fn dataset(&self, id: &str, digests: &[(&str, usize)], age: f64) {
            for (d, size) in digests {
                self.blob(d, *size, age);
            }
            let files: Vec<Value> = digests.iter().map(|(d, s)| serde_json::json!({"path": d, "digest": d, "size": s})).collect();
            let p = self.l.state().join("datasets").join(format!("{}.json", id.replace(['/', ':'], "_")));
            crate::fsutil::write_private(&p, &serde_json::to_vec(&serde_json::json!({"dataset_id": id, "files": files})).unwrap()).unwrap();
            let t = std::time::SystemTime::now() - std::time::Duration::from_secs_f64(age);
            std::fs::File::options().write(true).open(&p).unwrap().set_modified(t).unwrap();
        }

        fn has(&self, digest: &str) -> bool {
            crate::staging::blob_path(&self.l, digest).exists()
        }

        fn collect(&self, alive: &[&str], wanted: &[&str], cap: Option<u64>) -> Collected {
            let alive = alive.iter().map(|s| s.to_string()).collect();
            let wanted = wanted.iter().map(|s| s.to_string()).collect();
            collect(&self.l, &Keep { alive: &alive, wanted: &wanted, idle_s: DAY, cap }, now())
        }
    }

    fn d(c: char) -> String {
        std::iter::repeat_n(c, 64).collect()
    }

    /// A dataset goes with the last module that used it, or after a day unused when no module ever did; one a live module
    /// uses, a job holds or pending work wants stays.
    #[test]
    fn datasets_go_with_their_last_module_or_when_nobody_used_them_for_a_while() {
        let fx = Fx::new("users");
        let (a, b, c, e) = (d('a'), d('b'), d('c'), d('e'));
        fx.dataset("ds:shared", &[(&a, 10)], 2.0 * DAY);
        fx.dataset("ds:mine", &[(&b, 20)], 2.0 * DAY);
        fx.dataset("ds:old", &[(&c, 30)], 2.0 * DAY);         // from before the index: no module recorded
        fx.dataset("ds:fresh", &[(&e, 40)], 60.0);
        used(&fx.l, &["ds:shared".into()], &[], Some("render"));
        used(&fx.l, &["ds:shared".into(), "ds:mine".into()], &[], Some("bench"));
        assert_eq!(modules(&fx.l), ["bench", "render"].iter().map(|s| s.to_string()).collect());
        let r = fx.collect(&["render", "bench"], &[], None);
        assert!(!fx.has(&c) && fx.has(&a) && fx.has(&b) && fx.has(&e), "only the unused dataset nobody uses goes");
        assert_eq!((r.freed, r.bytes, r.datasets), (30, 70, 3));
        assert_eq!(r.by_module["bench"], (30, 2));
        drop_module(&fx.l, "bench");
        let r = fx.collect(&["render"], &[], None);
        assert!(fx.has(&a) && !fx.has(&b), "the shared dataset stays with render; bench's own goes at once");
        assert_eq!((r.by_module.get("bench"), r.by_module["render"]), (None, (10, 1)));
        drop_module(&fx.l, "render");
        let held = hold(&["ds:shared".into()], &[]);
        fx.collect(&[], &[], None);
        assert!(fx.has(&a), "a running job holds it");
        drop(held);
        fx.collect(&[], &["ds:shared"], None);
        assert!(fx.has(&a), "pending work wants it");
        fx.collect(&[], &[], None);
        assert!(!fx.has(&a));
    }

    /// Above the cap the least recently used datasets and loose blobs go first, never what is held or wanted; a blob
    /// nothing names goes an hour after it was written.
    #[test]
    fn the_cap_evicts_the_least_recently_used_and_stray_blobs_go() {
        let fx = Fx::new("cap");
        let (a, b, c, s, t, k) = (d('a'), d('b'), d('c'), d('1'), d('2'), d('3'));
        fx.dataset("ds:a", &[(&a, 100)], 60.0);
        fx.dataset("ds:b", &[(&b, 100)], 60.0);
        fx.dataset("ds:c", &[(&c, 100)], 60.0);
        for (id, m) in [("ds:b", "x"), ("ds:a", "x"), ("ds:c", "x")] {
            used(&fx.l, &[id.into()], &[], Some(m));
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        fx.blob(&k, 50, 60.0);
        used(&fx.l, &[], &[k.clone()], Some("x"));            // a checkpoint's file, used now
        fx.blob(&s, 7, 2.0 * 3600.0);                         // a stray: named by nothing, two hours old
        fx.blob(&t, 9, 60.0);                                 // a stray written a minute ago (a staging under way)
        let r = fx.collect(&["x"], &["ds:b"], Some(100));
        assert!(!fx.has(&s) && fx.has(&t), "the old stray goes, the fresh one stays");
        assert!(fx.has(&b) && !fx.has(&a) && !fx.has(&c) && !fx.has(&k), "b is wanted; a, c, then the loose blob were older");
        assert!(r.over_cap && r.evicted == 3 && r.bytes == 109 && r.freed == 257, "{r:?}");
        let r = fx.collect(&["x"], &[], Some(100));
        assert!(!fx.has(&b) && fx.has(&t) && !r.over_cap && r.bytes == 9 && r.evicted == 1, "{r:?}");
    }
}
