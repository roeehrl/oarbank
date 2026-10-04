//! Folder grants on the node (spec/sandbox.md, "Folders"; docs/design/datasets-media-checkpoints.md).
//!
//! A module version asks for folders by id (`[sandbox].folders`, carried in the signed release's module entry as
//! `sandbox.folders: [{id, access}]`); the operator maps each id to a path on this node, and the coordinator sends the
//! mapping as this node's **folder statement**: `{"type": "oarbank.folders/v1", "fleet_id", "node_id", "seq", "folders":
//! {id: {access, path}}, "signed_at"}`. With a release key pinned (signing mode) a statement applies only with a valid
//! signature and a seq above the last one applied, as releases do; until then the last applied one stays.
//!
//! Every folder of an applied statement is checked here: the path must exist and be a directory; it is granted by its
//! canonical path; it may not be a filesystem root, a home directory itself, inside or around the Oarbank data root, a
//! system directory, or overlap another folder of the statement. Each folder is reported (`ok` or why not) with its
//! access in every heartbeat, which is what the coordinator places jobs by.

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

pub const STATEMENT_TYPE: &str = "oarbank.folders/v1";

/// The statement this node applies, and what it found for each folder.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Folders {
    pub seq: i64,
    /// id -> {access, path (as mapped), canonical (granted), status ("ok" or why not)}
    pub folders: Map<String, Value>,
}

/// Directories no folder may be, contain or lie in (besides roots, homes and the Oarbank data root): what the sandbox
/// grants every module process already, and where the OS keeps itself.
#[cfg(target_os = "macos")]
const SYSTEM: &[&str] = &["/System", "/usr", "/bin", "/sbin", "/etc", "/private/etc", "/private/var/db", "/Library", "/opt",
                          "/Applications", "/dev", "/cores"];
#[cfg(target_os = "linux")]
const SYSTEM: &[&str] = &["/usr", "/lib", "/lib32", "/lib64", "/bin", "/sbin", "/etc", "/opt", "/proc", "/sys", "/dev", "/boot",
                          "/run", "/var/lib", "/snap"];
#[cfg(windows)]
const SYSTEM: &[&str] = &[];

impl Folders {
    pub fn load(p: &Path) -> Folders {
        std::fs::read(p).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .map(|v| Folders { seq: v["seq"].as_i64().unwrap_or(0), folders: v["folders"].as_object().cloned().unwrap_or_default() })
            .unwrap_or_default()
    }

    pub fn save(&self, p: &Path) -> std::io::Result<()> {
        crate::fsutil::write_private(p, &serde_json::to_vec(&json!({"seq": self.seq, "folders": self.folders}))?)
    }

    /// The heartbeat's `folders`: {id: {access, status}}.
    pub fn report(&self) -> Value {
        Value::Object(self.folders.iter().map(|(id, f)| (id.clone(), json!({"access": f["access"], "status": f["status"]}))).collect())
    }

    /// What a runner of a module whose release entry asks for `wanted` folders gets: {id: {path (canonical), access}}
    /// for each one this node provides with that access.
    pub fn granted(&self, wanted: &Value) -> Map<String, Value> {
        let mut out = Map::new();
        for w in wanted.as_array().cloned().unwrap_or_default() {
            let (Some(id), Some(access)) = (w["id"].as_str(), w["access"].as_str()) else { continue };
            if let Some(f) = self.folders.get(id).filter(|f| f["status"] == "ok" && f["access"] == access) {
                out.insert(id.to_string(), json!({"path": f["canonical"], "access": access}));
            }
        }
        out
    }
}

/// Apply a `folders` directive: verify it (signature with `pinned_key`, this node, a seq above the applied one), then
/// check every folder. Returns the new state, or None when the directive changes nothing or is refused (why in Err).
pub fn apply(cur: &Folders, d: &Value, node_id: &str, fleet_id: Option<&str>, pinned_key: Option<&str>, data_root: &Path)
             -> Result<Option<Folders>> {
    let Some(stmt) = d["statement"].as_str() else { return Ok(None) };
    let s: Value = serde_json::from_str(stmt).context("a folder statement that is not JSON")?;
    if s["type"].as_str() != Some(STATEMENT_TYPE) || s["node_id"].as_str() != Some(node_id) {
        bail!("a folder statement for another node or of another type");
    }
    if let (Some(f), Some(have)) = (s["fleet_id"].as_str(), fleet_id) {
        if f != have {
            bail!("a folder statement of another fleet");
        }
    }
    let seq = s["seq"].as_i64().unwrap_or(0);
    if seq <= cur.seq {
        return Ok(None);
    }
    if let Some(key) = pinned_key {
        let sig = d["signature"].as_str().context("the folder statement is not signed yet: a release key is pinned (oarbank folders sign)")?;
        crate::identity::verify_ed25519(key, stmt.as_bytes(), sig).context("bad folder statement signature")?;
    }
    let mut out = Folders { seq, folders: Map::new() };
    let wanted = s["folders"].as_object().cloned().unwrap_or_default();
    let mut canon: Vec<(String, Option<PathBuf>)> = vec![];
    for (id, f) in &wanted {
        let path = f["path"].as_str().unwrap_or("");
        let c = check_path(Path::new(path), data_root);
        canon.push((id.clone(), c.as_ref().ok().cloned()));
        out.folders.insert(id.clone(), json!({"access": f["access"], "path": path,
            "canonical": c.as_ref().map(|p| display(p)).unwrap_or_default(),
            "status": match &c { Ok(_) => "ok".to_string(), Err(e) => e.to_string() }}));
    }
    for (i, (a, pa)) in canon.iter().enumerate() {
        for (b, pb) in canon.iter().skip(i + 1) {
            if let (Some(pa), Some(pb)) = (pa, pb) {
                if overlaps(pa, pb) {
                    for (id, other) in [(a, b), (b, a)] {
                        out.folders[id]["status"] = json!(format!("overlaps folder {other}"));
                    }
                }
            }
        }
        if let Some(f) = out.folders.get(a) {
            if !matches!(f["access"].as_str(), Some("read" | "write")) {
                out.folders[a]["status"] = json!("access is neither read nor write");
            }
        }
    }
    Ok(Some(out))
}

/// A path as it is granted and reported (without Windows' `\\?\` prefix).
pub fn display(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

/// Whether one path is the other or lies inside it.
pub fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

/// The canonical directory a mapped path grants, or why it may not be granted.
pub fn check_path(p: &Path, data_root: &Path) -> Result<PathBuf> {
    if !p.is_absolute() {
        bail!("not an absolute path");
    }
    let c = std::fs::canonicalize(p).with_context(|| format!("{} does not exist here", p.display()))?;
    if !c.is_dir() {
        bail!("not a directory");
    }
    if c.parent().is_none() {
        bail!("a filesystem root");
    }
    for home in homes() {
        if c == home {
            bail!("a home directory itself (map a directory inside it)");
        }
    }
    if let Some(parent) = c.parent() {
        let users = [Path::new("/Users"), Path::new("/home"), Path::new(r"C:\Users")];
        if users.iter().any(|u| std::fs::canonicalize(u).is_ok_and(|u| u == parent)) {
            bail!("a home directory itself (map a directory inside it)");
        }
    }
    if let Ok(root) = std::fs::canonicalize(data_root) {
        if overlaps(&c, &root) {
            bail!("overlaps the Oarbank data directory");
        }
    }
    for sys in system_dirs() {
        if overlaps(&c, &sys) {
            bail!("overlaps the system directory {}", display(&sys));
        }
    }
    Ok(c)
}

fn homes() -> Vec<PathBuf> {
    ["HOME", "USERPROFILE"].iter().filter_map(std::env::var_os).filter_map(|h| std::fs::canonicalize(h).ok()).collect()
}

fn system_dirs() -> Vec<PathBuf> {
    let listed = SYSTEM.iter().filter_map(|p| std::fs::canonicalize(p).ok());
    #[cfg(windows)]
    let listed = listed.chain(["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "ProgramW6432"].iter()
        .filter_map(|k| std::env::var_os(k).and_then(|v| std::fs::canonicalize(v).ok())));
    listed.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oarbank-folders-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(d).unwrap()
    }

    fn stmt(seq: i64, folders: Value) -> Value {
        json!({"statement": json!({"type": STATEMENT_TYPE, "fleet_id": "f1", "node_id": "n1", "seq": seq, "folders": folders,
                                   "signed_at": 1}).to_string(), "signature": null})
    }

    #[test]
    fn a_statement_applies_once_for_this_node_with_a_rising_seq() {
        let t = scratch("seq");
        std::fs::create_dir_all(t.join("in")).unwrap();
        let d = stmt(2, json!({"inputs": {"access": "read", "path": t.join("in").display().to_string()}}));
        let f = apply(&Folders::default(), &d, "n1", Some("f1"), None, &t.join("data")).unwrap().unwrap();
        assert_eq!(f.report(), json!({"inputs": {"access": "read", "status": "ok"}}));
        assert!(apply(&f, &d, "n1", Some("f1"), None, &t.join("data")).unwrap().is_none());      // not newer
        assert!(apply(&Folders::default(), &d, "n2", Some("f1"), None, &t).is_err());              // another node
        assert!(apply(&Folders::default(), &d, "n1", Some("f2"), None, &t).is_err());              // another fleet
        let _ = std::fs::remove_dir_all(t);
    }

    #[test]
    fn with_a_pinned_key_only_a_signed_statement_applies() {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let b64 = base64::engine::general_purpose::STANDARD;
        let t = scratch("sig");
        let owner = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let key = b64.encode(owner.verifying_key().to_bytes());
        let mut d = stmt(1, json!({}));
        assert!(apply(&Folders::default(), &d, "n1", None, Some(&key), &t).unwrap_err().to_string().contains("not signed"));
        d["signature"] = json!(b64.encode(ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]).sign(d["statement"].as_str().unwrap().as_bytes()).to_bytes()));
        assert!(apply(&Folders::default(), &d, "n1", None, Some(&key), &t).is_err());              // another key signed it
        d["signature"] = json!(b64.encode(owner.sign(d["statement"].as_str().unwrap().as_bytes()).to_bytes()));
        assert_eq!(apply(&Folders::default(), &d, "n1", None, Some(&key), &t).unwrap().unwrap().seq, 1);
        let _ = std::fs::remove_dir_all(t);
    }

    #[test]
    fn roots_homes_data_roots_system_directories_and_overlaps_are_refused() {
        let t = scratch("paths");
        let data = t.join("oarbank");
        for d in ["in", "in/sub", "out", "oarbank/agent"] {
            std::fs::create_dir_all(t.join(d)).unwrap();
        }
        let p = |s: &str| t.join(s).display().to_string();
        let f = apply(&Folders::default(), &stmt(1, json!({
            "inputs": {"access": "read", "path": p("in")}, "nested": {"access": "write", "path": p("in/sub")},
            "outbox": {"access": "write", "path": p("out")}, "missing": {"access": "read", "path": p("nope")},
            "data": {"access": "read", "path": p("oarbank/agent")}, "relative": {"access": "read", "path": "in"}})),
            "n1", None, None, &data).unwrap().unwrap();
        let st = |id: &str| f.folders[id]["status"].as_str().unwrap().to_string();
        assert_eq!(st("outbox"), "ok");
        assert!(st("inputs").contains("overlaps folder nested") && st("nested").contains("overlaps folder inputs"));
        assert!(st("missing").contains("does not exist") && st("data").contains("data directory") && st("relative").contains("absolute"));
        #[cfg(unix)]
        {
            assert!(check_path(Path::new("/"), &data).unwrap_err().to_string().contains("root"));
            assert!(check_path(Path::new("/usr/share"), &data).unwrap_err().to_string().contains("system directory"));
            if let Some(h) = homes().first() {
                assert!(check_path(h, &data).unwrap_err().to_string().contains("home directory"));
            }
            std::os::unix::fs::symlink(t.join("out"), t.join("link")).unwrap();
            assert_eq!(check_path(&t.join("link"), &data).unwrap(), t.join("out"));        // granted by its target
        }
        let granted = f.granted(&json!([{"id": "outbox", "access": "write"}, {"id": "outbox", "access": "read"},
                                        {"id": "inputs", "access": "read"}]));
        assert_eq!(granted.keys().collect::<Vec<_>>(), ["outbox"]);
        let _ = std::fs::remove_dir_all(t);
    }
}
