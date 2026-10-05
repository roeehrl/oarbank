//! Unpacked bundles against their bundle.json, and unpacked releases against their MANIFEST.json.

use std::fs;
use std::path::{Path, PathBuf};

use oarbank_core::bundle::{self, BundleFile};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// A fresh directory under the system temp dir, resolved: (what removes it when dropped, its path).
fn scratch(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let base = std::env::temp_dir().canonicalize().unwrap();
    let d = tempfile::Builder::new().prefix(&format!("oarbank-core-{tag}-")).tempdir_in(base).unwrap();
    let p = d.path().to_path_buf();
    (d, p)
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

#[cfg(unix)]
fn chmod(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}
#[cfg(not(unix))]
fn chmod(_: &Path, _: u32) {}

const FILES: [(&str, &[u8], &str); 4] = [
    ("oarbank-module.toml", b"manifest = 1\n", "644"),
    ("toy_module.py", b"print('hi')\n", "644"),
    ("bin/run.sh", b"#!/bin/sh\necho hi\n", "755"),
    (".gitattributes", b"* text\n", "644"),
];

/// An unpacked bundle as `bundle.verify(dest=...)` leaves it: (what removes it when dropped, its path).
fn unpacked(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let (d, root) = scratch(tag);
    let mut files = Vec::new();
    for (path, data, mode) in FILES {
        let p = root.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
        chmod(&p, if mode == "755" { 0o755 } else { 0o644 });
        files.push(json!({"path": path, "sha256": sha(data), "mode": mode}));
    }
    let digest = bundle::content_digest_value(&Value::Array(files.clone())).unwrap();
    let meta = json!({"bundle": 2, "module_id": "dev.codonic.oarbank.toy", "name": "toy", "version": "1.0.0",
                      "compat": "toy1", "files": files, "content_digest": digest, "sdk_version": "1.0.0rc2"});
    fs::write(root.join("bundle.json"), serde_json::to_string_pretty(&meta).unwrap()).unwrap();
    (d, root)
}

fn edit_meta(root: &Path, f: impl FnOnce(&mut Value)) {
    let p = root.join("bundle.json");
    let mut meta: Value = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
    f(&mut meta);
    fs::write(&p, serde_json::to_string(&meta).unwrap()).unwrap();
}

#[test]
fn an_intact_directory_verifies() {
    let (_root, root) = unpacked("intact");
    let info = bundle::verify_dir(&root).unwrap();
    assert_eq!(info.module_id, "dev.codonic.oarbank.toy");
    assert_eq!((info.name.as_str(), info.version.as_str(), info.compat.as_str()), ("toy", "1.0.0", "toy1"));
    assert!(info.content_digest.starts_with("h2:") && info.short_digest().len() == 12);
    assert_eq!(info.files.len(), 4);
    let files: Vec<BundleFile> = FILES
        .iter()
        .rev()
        .map(|(p, d, m)| BundleFile { path: p.to_string(), sha256: sha(d), mode: m.to_string() })
        .collect();
    assert_eq!(bundle::content_digest(&files).unwrap(), info.content_digest, "the digest is over contents, any order");
    assert!(bundle::verify_dir_exact(&root).is_ok());
    fs::create_dir_all(root.join("emptydir")).unwrap();
    assert!(bundle::verify_dir_exact(&root).is_ok(), "directories are not files");
}

#[test]
fn tampering_is_refused() {
    let err = |root: &Path| bundle::verify_dir(root).unwrap_err().0;

    let (_root, root) = unpacked("t-content");
    fs::write(root.join("toy_module.py"), b"print('evil')\n").unwrap();
    assert_eq!(err(&root), "toy_module.py: missing or modified");

    let (_root, root) = unpacked("t-missing");
    fs::remove_file(root.join("bin/run.sh")).unwrap();
    assert_eq!(err(&root), "bin/run.sh: missing or modified");

    let (_root, root) = unpacked("t-digest");
    edit_meta(&root, |m| m["content_digest"] = json!(format!("h2:{}", "0".repeat(64))));
    assert_eq!(err(&root), "content digest mismatch");

    let (_root, root) = unpacked("t-listmode");
    edit_meta(&root, |m| m["files"][1]["mode"] = json!("755")); // the listing changes, the digest no longer matches
    #[cfg(unix)]
    assert_eq!(err(&root), "toy_module.py: mode changed");
    #[cfg(not(unix))]
    assert_eq!(err(&root), "content digest mismatch");

    let (_root, root) = unpacked("t-unsafe");
    edit_meta(&root, |m| m["files"].as_array_mut().unwrap().push(json!({"path": "../../etc/evil", "sha256": "x", "mode": "644"})));
    assert!(err(&root).starts_with("unsafe path in bundle:"));

    let (_root, root) = unpacked("t-collide");
    fs::write(root.join("Toy_module.py"), b"print('hi')\n").ok();
    edit_meta(&root, |m| {
        let f = m["files"].as_array_mut().unwrap();
        f.push(json!({"path": "Toy_Module.py", "sha256": sha(b"print('hi')\n"), "mode": "644"}));
    });
    if root.join("Toy_Module.py").exists() {
        // case-insensitive filesystem: the file "exists", the listing collides
        assert!(err(&root).starts_with("paths collide on case-insensitive filesystems"), "{}", err(&root));
    }

    let (_root, root) = unpacked("t-nomanifest");
    edit_meta(&root, |m| {
        let f = m["files"].as_array_mut().unwrap();
        f.remove(0);
        let d = bundle::content_digest_value(&Value::Array(f.clone())).unwrap();
        m["content_digest"] = json!(d);
    });
    assert_eq!(err(&root), "no oarbank-module.toml");

    let (_root, root) = unpacked("t-extra");
    fs::write(root.join("extra.py"), b"x=1").unwrap();
    assert!(bundle::verify_dir(&root).is_ok(), "like the SDK, verify_dir ignores unlisted files");
    assert_eq!(bundle::verify_dir_exact(&root).unwrap_err().0, "files not in bundle.json: extra.py");
}

#[cfg(unix)]
#[test]
fn modes_and_symlinks_on_posix() {
    let (_root, root) = unpacked("p-mode");
    chmod(&root.join("toy_module.py"), 0o744); // any x bit means 755
    assert_eq!(bundle::verify_dir(&root).unwrap_err().0, "toy_module.py: mode changed");
    chmod(&root.join("toy_module.py"), 0o600); // no x bit: still "644", as the SDK compares
    assert!(bundle::verify_dir(&root).is_ok());
    chmod(&root.join("bin/run.sh"), 0o644);
    assert_eq!(bundle::verify_dir(&root).unwrap_err().0, "bin/run.sh: mode changed");

    let (_root, root) = unpacked("p-link");
    let (_elsewhere, elsewhere) = scratch("p-link-target");
    fs::write(elsewhere.join("toy_module.py"), b"print('hi')\n").unwrap();
    fs::remove_file(root.join("toy_module.py")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("toy_module.py"), root.join("toy_module.py")).unwrap();
    assert_eq!(bundle::verify_dir(&root).unwrap_err().0, "toy_module.py: toy_module.py is a symlink");
}

/// An unpacked release as the coordinator's `releases.build` lays it out: (what removes it when dropped, its path).
fn release(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let (d, root) = scratch(tag);
    let files: [(&str, &[u8], u32); 3] = [
        ("modules.json", b"{\"format\": 2}", 0o644),
        ("modules/toy/oarbank-module.toml", b"manifest = 1\n", 0o644),
        ("modules/toy/node/run", b"#!/bin/sh\n", 0o755),
    ];
    let mut entries = Vec::new();
    for (path, data, mode) in files {
        let p = root.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
        chmod(&p, mode);
        entries.push(json!({"path": path, "sha256": sha(data), "mode": format!("0o{mode:o}")}));
    }
    fs::write(root.join("MANIFEST.json"), serde_json::to_string_pretty(&json!({"files": entries})).unwrap()).unwrap();
    (d, root)
}

#[test]
fn release_manifest_entries_verify() {
    let (_root, root) = release("r-ok");
    let entries = bundle::verify_release_dir(&root).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[2].mode, 0o755);

    fs::write(root.join("modules/toy/node/run"), b"#!/bin/sh\nevil\n").unwrap();
    fs::remove_file(root.join("modules.json")).unwrap();
    let e = bundle::verify_release_dir(&root).unwrap_err().0;
    assert!(e.starts_with("manifest verification failed: "), "{e}");
    assert!(e.contains("modules.json: missing") && e.contains("modules/toy/node/run: sha256 mismatch"), "{e}");

    let (_root, root) = release("r-nomanifest");
    fs::remove_file(root.join("MANIFEST.json")).unwrap();
    assert!(bundle::verify_release_dir(&root).unwrap_err().0.starts_with("MANIFEST.json missing"));

    let (_root, root) = release("r-escape");
    fs::write(root.join("MANIFEST.json"), json!({"files": [{"path": "../x", "sha256": "0".repeat(64), "mode": "0o644"}]}).to_string()).unwrap();
    assert!(bundle::verify_release_dir(&root).unwrap_err().0.starts_with("manifest entry with bad path"));
}

#[cfg(unix)]
#[test]
fn release_modes_are_exact_and_symlinks_refused() {
    let (_root, root) = release("r-mode");
    chmod(&root.join("modules/toy/node/run"), 0o775);
    assert_eq!(bundle::verify_release_dir(&root).unwrap_err().0, "manifest verification failed: modules/toy/node/run: mode 775 != 755");

    let (_root, root) = release("r-link");
    let real = root.join("elsewhere");
    fs::rename(root.join("modules/toy"), &real).unwrap();
    std::os::unix::fs::symlink(&real, root.join("modules/toy")).unwrap();
    let e = bundle::verify_release_dir(&root).unwrap_err().0;
    assert!(e.contains("modules/toy is a symlink"), "{e}");
}
