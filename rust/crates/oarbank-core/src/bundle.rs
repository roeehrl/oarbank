//! Module bundles (spec/bundles.md) and release manifests: the checks a node runs on what it unpacked.
//!
//! A bundle's identity is its h2 `content_digest`: sha256 over sorted `<sha256> <mode> <path>\n` lines (mode 644 or
//! 755), not over the archive, so the same identity verifies a tarball, a mirror or an unpacked directory. This is
//! the SDK's `bundle.py` (`content_digest`, `_mode`, `check_paths`, `verify_dir`).
//!
//! A release tarball carries `MANIFEST.json` (`{"files": [{"path", "sha256", "mode"}]}`, written by the
//! coordinator's `releases.build` with modes as `oct()` strings such as `"0o644"`); `verify_release_dir` checks an
//! unpacked release against it.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{portable, py};

pub const BUNDLE_FORMAT: u64 = 2;
pub const BUNDLE_FILE: &str = "bundle.json";
pub const MANIFEST_FILE: &str = "oarbank-module.toml";
pub const RELEASE_MANIFEST: &str = "MANIFEST.json";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct BundleError(pub String);

fn fail<T>(msg: impl Into<String>) -> Result<T, BundleError> {
    Err(BundleError(msg.into()))
}

/// One file of a bundle as `bundle.json` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    pub path: String,
    pub sha256: String,
    /// As written in `bundle.json`; `mode` normalises it to `644` or `755`.
    pub mode: String,
}

/// What `verify_dir` vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundle {
    pub module_id: String,
    pub name: String,
    pub version: String,
    pub compat: String,
    pub content_digest: String,
    pub files: Vec<BundleFile>,
}

impl VerifiedBundle {
    /// The first 12 hex digits of the digest.
    pub fn short_digest(&self) -> &str {
        let hex = self.content_digest.split_once(':').map_or("", |(_, h)| h);
        &hex[..hex.len().min(12)]
    }
}

/// `_mode`: a bundle file mode as `"644"` or `"755"`. An octal string as Python's `int(m, 8)` reads it, or an integer;
/// then only 0o644 and 0o755.
pub fn mode(m: &Value) -> Result<&'static str, BundleError> {
    let v: i128 = match m {
        Value::String(s) => match py::int(s, 8) {
            Some(v) => v,
            None => return fail(format!("file mode {}: not an octal number", py::repr(s))),
        },
        Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => i as i128,
            (_, Some(u)) => u as i128,
            _ => return fail(format!("file mode {n}: an octal string or an integer")),
        },
        other => return fail(format!("file mode {other}: an octal string or an integer")),
    };
    match v {
        0o644 => Ok("644"),
        0o755 => Ok("755"),
        _ => fail(format!("file mode {}: only 644 and 755", py::oct(v))),
    }
}

/// `mode` for a string as written in `bundle.json`.
pub fn mode_str(m: &str) -> Result<&'static str, BundleError> {
    mode(&Value::String(m.to_string()))
}

/// The h2 content digest of a file list (any order).
pub fn content_digest(files: &[BundleFile]) -> Result<String, BundleError> {
    let mut lines: Vec<(&str, String)> = Vec::with_capacity(files.len());
    for f in files {
        lines.push((f.path.as_str(), format!("{} {} {}\n", f.sha256, mode_str(&f.mode)?, f.path)));
    }
    Ok(digest_lines(lines))
}

/// `content_digest` over the `files` array of a `bundle.json` (modes may be strings or numbers, as in Python).
pub fn content_digest_value(files: &Value) -> Result<String, BundleError> {
    let Value::Array(items) = files else { return fail("files: not a list") };
    let mut lines: Vec<(&str, String)> = Vec::with_capacity(items.len());
    for f in items {
        let (Some(path), Some(sha)) = (f.get("path").and_then(Value::as_str), f.get("sha256").and_then(Value::as_str)) else {
            return fail(format!("file entry {f}: needs string path and sha256"));
        };
        let m = mode(f.get("mode").unwrap_or(&Value::Null))?;
        lines.push((path, format!("{sha} {m} {path}\n")));
    }
    Ok(digest_lines(lines))
}

fn digest_lines(mut lines: Vec<(&str, String)>) -> String {
    lines.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes())); // stable, like Python's sorted
    let mut h = Sha256::new();
    for (_, l) in &lines {
        h.update(l.as_bytes());
    }
    format!("h2:{}", hex::encode(h.finalize()))
}

/// Every path is a PortablePath (dotfiles allowed) and the set is case-fold unique.
pub fn check_paths<S: AsRef<str>>(paths: &[S]) -> Result<(), BundleError> {
    for p in paths {
        if let Err(e) = portable::check_portable_path(p.as_ref(), true) {
            return fail(format!("not a portable path: {e}"));
        }
    }
    let clash = portable::casefold_collisions(paths);
    if !clash.is_empty() {
        let shown: Vec<String> = clash.iter().take(3).map(|(a, b)| format!("({}, {})", py::repr(a), py::repr(b))).collect();
        return fail(format!("paths collide on case-insensitive filesystems: [{}]", shown.join(", ")));
    }
    Ok(())
}

/// A bundle member name, which must be a PortablePath exactly as written.
pub fn safe_member(name: &str) -> Result<&str, BundleError> {
    portable::check_portable_path(name, true).map_err(|e| BundleError(format!("unsafe path in bundle: {e}")))
}

/// sha256 of a file's contents, in hex.
pub fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// `root` joined with a checked relative path, refusing a symlink at any component (a release or bundle never holds
/// one, and following one could leave `root`). Ok(None) when something on the way is missing.
fn regular_file_under(root: &Path, rel: &str) -> Result<Option<PathBuf>, String> {
    let mut p = root.to_path_buf();
    let segs: Vec<&str> = rel.split('/').collect();
    for (i, seg) in segs.iter().enumerate() {
        p.push(seg);
        let md = match fs::symlink_metadata(&p) {
            Ok(md) => md,
            Err(_) => return Ok(None),
        };
        if md.file_type().is_symlink() {
            return Err(format!("{rel}: {} is a symlink", segs[..=i].join("/")));
        }
        let last = i + 1 == segs.len();
        if last && !md.is_file() {
            return Err(format!("{rel}: not a regular file"));
        }
        if !last && !md.is_dir() {
            return Ok(None);
        }
    }
    Ok(Some(p))
}

#[cfg(unix)]
fn perm_bits(p: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::metadata(p)?.permissions().mode() & 0o7777)
}

fn str_field(meta: &Value, k: &str) -> Result<String, BundleError> {
    match meta.get(k) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => fail(format!("{BUNDLE_FILE}: {k} missing or not a string")),
    }
}

/// Re-verify an unpacked bundle directory against its `bundle.json` (the tamper check at load time): every listed
/// file is a regular file with its sha256 and, on POSIX, its exec-ness (any x bit = 755); the paths are portable and
/// case-fold unique; the content digest matches; the module manifest is among the verified files.
///
/// Like the SDK it does not refuse files that are not listed; `verify_dir_exact` does.
/// Stricter than the SDK: a symlink in place of a listed file (or a parent) is refused where Python follows it, and
/// the case-fold check runs here as it does in `verify` for tarballs. Validating the TOML manifest is the caller's.
pub fn verify_dir(root: &Path) -> Result<VerifiedBundle, BundleError> {
    let raw = fs::read_to_string(root.join(BUNDLE_FILE)).map_err(|e| BundleError(format!("{BUNDLE_FILE}: {e}")))?;
    let meta: Value = serde_json::from_str(&raw).map_err(|e| BundleError(format!("{BUNDLE_FILE}: {e}")))?;
    let Some(Value::Array(items)) = meta.get("files") else { return fail(format!("{BUNDLE_FILE}: files missing")) };
    let mut files = Vec::with_capacity(items.len());
    for f in items {
        let Some(path) = f.get("path").and_then(Value::as_str) else { return fail(format!("file entry {f}: no path")) };
        let sha = f.get("sha256").and_then(Value::as_str).unwrap_or("");
        safe_member(path)?;
        let p = match regular_file_under(root, path) {
            Ok(Some(p)) => p,
            Ok(None) => return fail(format!("{path}: missing or modified")),
            Err(e) => return fail(e),
        };
        if sha256_file(&p).ok().as_deref() != Some(sha) {
            return fail(format!("{path}: missing or modified"));
        }
        let want = mode(f.get("mode").unwrap_or(&Value::Null))?;
        #[cfg(unix)]
        {
            let bits = perm_bits(&p).map_err(|e| BundleError(format!("{path}: {e}")))?;
            if (if bits & 0o111 != 0 { "755" } else { "644" }) != want {
                return fail(format!("{path}: mode changed"));
            }
        }
        files.push(BundleFile { path: path.to_string(), sha256: sha.to_string(), mode: want.to_string() });
    }
    let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
    check_paths(&paths)?;
    let digest = content_digest_value(&Value::Array(items.clone()))?;
    if meta.get("content_digest").and_then(Value::as_str) != Some(digest.as_str()) {
        return fail("content digest mismatch");
    }
    if !paths.contains(&MANIFEST_FILE) {
        return fail(format!("no {MANIFEST_FILE}"));
    }
    Ok(VerifiedBundle {
        module_id: str_field(&meta, "module_id")?,
        name: str_field(&meta, "name")?,
        version: str_field(&meta, "version")?,
        compat: str_field(&meta, "compat")?,
        content_digest: digest,
        files,
    })
}

/// `verify_dir`, and nothing but the listed files and `bundle.json` in the directory (directories aside).
pub fn verify_dir_exact(root: &Path) -> Result<VerifiedBundle, BundleError> {
    let info = verify_dir(root)?;
    let mut listed: HashSet<String> = info.files.iter().map(|f| f.path.clone()).collect();
    listed.insert(BUNDLE_FILE.to_string());
    let extra = unlisted(root, &listed)?;
    if !extra.is_empty() {
        return fail(format!("files not in {BUNDLE_FILE}: {}", extra.iter().take(5).cloned().collect::<Vec<_>>().join(", ")));
    }
    Ok(info)
}

/// Every non-directory entry under `root` (symlinks included, not followed) whose relative path is not in `listed`.
pub fn unlisted(root: &Path, listed: &HashSet<String>) -> Result<Vec<String>, BundleError> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let rd = fs::read_dir(&dir).map_err(|e| BundleError(format!("{}: {e}", dir.display())))?;
        for entry in rd {
            let entry = entry.map_err(|e| BundleError(format!("{}: {e}", dir.display())))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let r = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            let ft = entry.file_type().map_err(|e| BundleError(format!("{r}: {e}")))?;
            if ft.is_dir() {
                stack.push((entry.path(), r));
            } else if !listed.contains(&r) {
                out.push(r);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// One `MANIFEST.json` entry of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseEntry {
    pub path: String,
    /// Lowercase hex.
    pub sha256: String,
    /// Permission bits (`& 0o7777`).
    pub mode: u32,
}

/// A mode as the coordinator writes it: Python's `oct()` of the permission bits (`"0o755"`).
fn release_mode(m: &Value) -> Option<u32> {
    let v = u32::from_str_radix(m.as_str()?.strip_prefix("0o")?, 8).ok()?;
    (v <= 0o7777).then_some(v)
}

fn release_sha(s: &str) -> Option<String> {
    (s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))).then(|| s.to_string())
}

/// Parse a release `MANIFEST.json`: `{"files": [{path, sha256, mode}]}` with lowercase hex digests and `oct()` modes,
/// as the coordinator writes it. Paths are PortablePaths (dotfiles allowed), unique and case-fold unique.
pub fn parse_release_manifest(v: &Value) -> Result<Vec<ReleaseEntry>, BundleError> {
    let Some(Value::Array(items)) = v.get("files") else {
        return fail(format!("{RELEASE_MANIFEST} is not {{\"files\": [{{path, sha256, mode}}]}}"));
    };
    let mut out = Vec::with_capacity(items.len());
    let mut seen = HashSet::new();
    for e in items {
        let Some(path) = e.get("path").and_then(Value::as_str) else {
            return fail(format!("manifest entry with no path: {e}"));
        };
        if let Err(err) = portable::check_portable_path(path, true) {
            return fail(format!("manifest entry with bad path: {err}"));
        }
        if !seen.insert(path) {
            return fail(format!("{path}: listed twice"));
        }
        let Some(sha256) = e.get("sha256").and_then(Value::as_str).and_then(release_sha) else {
            return fail(format!("manifest entry {path} has bad sha256"));
        };
        let Some(mode) = e.get("mode").and_then(release_mode) else {
            return fail(format!("manifest entry {path} has bad mode"));
        };
        out.push(ReleaseEntry { path: path.to_string(), sha256, mode });
    }
    if out.is_empty() {
        return fail(format!("{RELEASE_MANIFEST} lists no files"));
    }
    let paths: Vec<&str> = out.iter().map(|e| e.path.as_str()).collect();
    let clash = portable::casefold_collisions(&paths);
    if let Some((a, b)) = clash.first() {
        return fail(format!("paths collide on case-insensitive filesystems: {a} and {b}"));
    }
    Ok(out)
}

/// Verify every entry of `root/MANIFEST.json`: a regular file reached without symlinks, its sha256 and, on POSIX, its
/// exact permission bits. Reports up to ten problems at once. Returns the entries.
pub fn verify_release_dir(root: &Path) -> Result<Vec<ReleaseEntry>, BundleError> {
    let raw = fs::read_to_string(root.join(RELEASE_MANIFEST))
        .map_err(|e| BundleError(format!("{RELEASE_MANIFEST} missing or unreadable: {e}")))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| BundleError(format!("{RELEASE_MANIFEST} is not JSON: {e}")))?;
    let entries = parse_release_manifest(&v)?;
    let mut problems = Vec::new();
    for e in &entries {
        if problems.len() >= 10 {
            break;
        }
        let p = match regular_file_under(root, &e.path) {
            Ok(Some(p)) => p,
            Ok(None) => {
                problems.push(format!("{}: missing", e.path));
                continue;
            }
            Err(m) => {
                problems.push(m);
                continue;
            }
        };
        #[cfg(unix)]
        match perm_bits(&p) {
            Ok(bits) if bits != e.mode => problems.push(format!("{}: mode {:o} != {:o}", e.path, bits, e.mode)),
            Ok(_) => {}
            Err(err) => problems.push(format!("{}: {err}", e.path)),
        }
        match sha256_file(&p) {
            Ok(h) if h == e.sha256 => {}
            Ok(_) => problems.push(format!("{}: sha256 mismatch", e.path)),
            Err(err) => problems.push(format!("{}: {err}", e.path)),
        }
    }
    if !problems.is_empty() {
        return fail(format!("manifest verification failed: {}", problems.join("; ")));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn modes_follow_python_int() {
        for ok in [json!("644"), json!("0o644"), json!(" 6_44 "), json!("0644"), json!(420)] {
            assert_eq!(mode(&ok).unwrap(), "644", "{ok}");
        }
        assert_eq!(mode(&json!("755")).unwrap(), "755");
        assert_eq!(mode(&json!(493)).unwrap(), "755");
        assert_eq!(mode(&json!("600")).unwrap_err().0, "file mode 0o600: only 644 and 755");
        assert_eq!(mode(&json!(644)).unwrap_err().0, "file mode 0o1204: only 644 and 755");
        for bad in [json!("rw-"), json!(true), json!(null), json!("100644"), json!([]), json!(420.9), json!(420.0)] {
            assert!(mode(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn digest_is_order_free_and_covers_modes() {
        let f = |p: &str, m: &str| BundleFile { path: p.into(), sha256: "ab".repeat(32), mode: m.into() };
        let a = content_digest(&[f("b", "644"), f("a", "644")]).unwrap();
        assert_eq!(a, content_digest(&[f("a", "644"), f("b", "644")]).unwrap());
        assert_ne!(a, content_digest(&[f("a", "755"), f("b", "644")]).unwrap());
        assert!(a.starts_with("h2:") && a.len() == 67);
        let lines = format!("{0} 644 a\n{0} 644 b\n", "ab".repeat(32));
        assert_eq!(a, format!("h2:{}", hex::encode(Sha256::digest(lines.as_bytes()))));
        let v = json!([{"path": "b", "sha256": "ab".repeat(32), "mode": "644"}, {"path": "a", "sha256": "ab".repeat(32), "mode": 420}]);
        assert_eq!(content_digest_value(&v).unwrap(), a);
        // bytewise path order: "B" < "a" < "é"
        let order = json!([{"path": "é", "sha256": "x", "mode": "644"}, {"path": "a", "sha256": "x", "mode": "644"}, {"path": "B", "sha256": "x", "mode": "644"}]);
        let want = format!("h2:{}", hex::encode(Sha256::digest("x 644 B\nx 644 a\nx 644 é\n".as_bytes())));
        assert_eq!(content_digest_value(&order).unwrap(), want);
    }

    #[test]
    fn paths_are_checked() {
        assert!(check_paths(&["a", ".env", "cfg/.x"]).is_ok());
        for evil in ["..\\..\\evil.txt", "C:/Windows/x", "CON", "a/nul.txt", "dir./f", "../../etc/evil"] {
            assert!(check_paths(&["README.md", evil]).is_err(), "{evil}");
        }
        let e = check_paths(&["README.md", "Readme.md"]).unwrap_err();
        assert_eq!(e.0, "paths collide on case-insensitive filesystems: [('README.md', 'Readme.md')]");
    }

    #[test]
    fn release_manifest_parsing() {
        let h = "ab".repeat(32);
        let v = json!({"files": [{"path": "modules.json", "sha256": h, "mode": "0o644"},
                                 {"path": "modules/x/run", "sha256": h, "mode": "0o755"}]});
        let e = parse_release_manifest(&v).unwrap();
        assert_eq!(e[0].mode, 0o644);
        assert_eq!(e[1].mode, 0o755);
        assert_eq!(e[1].sha256, h);
        for bad in [
            json!([{"path": "a", "sha256": h, "mode": "0o644"}]),
            json!({"files": [{"path": "a", "sha256": h, "mode": "644"}]}),
            json!({"files": [{"path": "a", "sha256": h, "mode": 420}]}),
            json!({"files": [{"path": "a", "sha256": h, "mode": "0o100644"}]}),
            json!({"files": [{"path": "a", "sha256": format!("sha256:{h}"), "mode": "0o644"}]}),
            json!({"files": [{"path": "a", "sha256": h.to_uppercase(), "mode": "0o644"}]}),
            json!({"files": []}),
            json!({"files": [{"path": "../x", "sha256": h, "mode": "0o644"}]}),
            json!({"files": [{"path": "a", "sha256": "zz", "mode": "0o644"}]}),
            json!({"files": [{"path": "a", "sha256": h, "mode": "rw"}]}),
            json!({"files": [{"path": "a", "sha256": h, "mode": "0o644"}, {"path": "a", "sha256": h, "mode": "0o644"}]}),
            json!({"files": [{"path": "A", "sha256": h, "mode": "0o644"}, {"path": "a", "sha256": h, "mode": "0o644"}]}),
            json!({"nope": 1}),
        ] {
            assert!(parse_release_manifest(&bad).is_err(), "{bad}");
        }
    }
}
