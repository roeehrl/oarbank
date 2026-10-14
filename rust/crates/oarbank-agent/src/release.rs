//! Releases (docs/protocol.md, "Releases"): download, check the sha256 (and the signature in signing mode), unpack
//! with every member checked, verify MANIFEST.json, build module environments, switch `current` atomically.
//!
//! **Empty releases.** With a release key pinned, an unsigned release is installed only if it is empty: no module, no
//! tool definition, and no file but modules.json (`check_empty`), checked on the unpacked files before `current`
//! moves, whether it was just downloaded or is already on disk. It carries no code, so it needs no owner signature; the
//! node runs no module and is ready (docs/release-signing.md, "Empty releases"). Anything else unsigned is refused.

use crate::api::Api;
use crate::paths::Layout;
use crate::runtime::Runtime;
use crate::signing::ReleaseTrust;
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone)]
pub struct Release {
    pub id: String,
    pub dir: PathBuf,
    pub modules: Vec<Value>,
    /// The fleet's host tool definitions for this platform (docs/design/host-tools.md): what tools.rs detects besides
    /// its built-in kinds. Never a path to grant.
    pub tools: Value,
}

impl Release {
    pub fn module(&self, name: &str) -> Option<&Value> {
        self.modules.iter().find(|m| m["name"].as_str() == Some(name))
    }
    pub fn bundle(&self, entry: &Value) -> PathBuf {
        let name = entry["name"].as_str().unwrap_or("");
        self.dir.join(entry["bundle"].as_str().map(str::to_string).unwrap_or_else(|| format!("modules/{name}")))
    }
}

fn load(dir: &Path) -> Result<Release> {
    let doc: Value = serde_json::from_slice(&std::fs::read(dir.join("modules.json"))?)?;
    if doc["format"].as_i64() != Some(2) {
        bail!("modules.json format {} is not 2", doc["format"]);
    }
    let id = dir.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
    Ok(Release { id, dir: dir.to_path_buf(), modules: doc["modules"].as_array().cloned().unwrap_or_default(),
                 tools: doc["tools"].clone() })
}

/// An empty release's tarball is a few hundred bytes; an unsigned download stops well before anything bigger.
const MAX_UNSIGNED_BYTES: u64 = 64 * 1024;

/// The check an unsigned release must pass while a release key is pinned: modules.json lists no module and no tool
/// definition, and MANIFEST.json vouches for modules.json alone, with nothing else in the directory. So nothing in it
/// can make the agent run anything.
pub fn check_empty(dir: &Path) -> Result<()> {
    let refuse = |why: String| anyhow::anyhow!("unsigned release refused: a release key is pinned and {why}");
    let rel = load(dir).map_err(|e| refuse(format!("its modules.json is unreadable ({e:#})")))?;
    if !rel.modules.is_empty() {
        return Err(refuse(format!("it holds {} module(s); only an empty release needs no signature", rel.modules.len())));
    }
    if !(rel.tools.is_null() || rel.tools.as_object().is_some_and(|m| m.is_empty())) {
        return Err(refuse("it carries tool definitions".into()));
    }
    let entries = oarbank_core::bundle::verify_release_dir(dir).map_err(|e| refuse(e.0))?;
    if entries.iter().any(|e| e.path != "modules.json") {
        return Err(refuse("its manifest lists files besides modules.json".into()));
    }
    let listed: std::collections::HashSet<String> = ["modules.json".to_string(), "MANIFEST.json".to_string()].into();
    let extra = oarbank_core::bundle::unlisted(dir, &listed).map_err(|e| refuse(e.0))?;
    if !extra.is_empty() {
        return Err(refuse(format!("it holds other files: {:?}", &extra[..extra.len().min(5)])));
    }
    Ok(())
}

pub fn current(l: &Layout) -> Option<Release> {
    let target = crate::fsutil::pointed(&l.releases().join("current"))?;
    load(&l.releases().join(target)).ok()
}

/// An installed release by id.
pub fn by_id(l: &Layout, id: &str) -> Option<Release> {
    (id.starts_with("r_") && !id.contains(['/', '\\', '.'])).then(|| load(&l.releases().join(id)).ok()).flatten()
}

/// The newest installed release that holds `module` (a module no longer in the current one: its cleanup stage runs from
/// there).
pub fn holding(l: &Layout, module: &str) -> Option<Release> {
    let mut rels: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(l.releases()).ok()?.filter_map(|e| e.ok()).map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("r_")))
        .filter_map(|p| Some((p.metadata().ok()?.modified().ok()?, p))).collect();
    rels.sort();
    rels.into_iter().rev().filter_map(|(_, p)| load(&p).ok()).find(|r| r.module(module).is_some())
}

/// Unpack a release tarball: only regular files and directories whose names are PortablePaths, never links or
/// devices, never outside `dest`; then MANIFEST.json must vouch for every byte and mode.
pub fn unpack(tarball: &Path, dest: &Path) -> Result<()> {
    let f = std::fs::File::open(tarball)?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f));
    std::fs::create_dir_all(dest)?;
    for e in ar.entries()? {
        let mut e = e?;
        let raw = e.path()?.to_string_lossy().to_string();
        let name = raw.trim_start_matches("./").trim_end_matches('/');
        if name.is_empty() {
            continue;
        }
        oarbank_core::portable::check_portable_path(name, true).map_err(|err| anyhow::anyhow!("unsafe member {raw:?}: {}", err.0))?;
        let out = dest.join(name);
        match e.header().entry_type() {
            tar::EntryType::Directory => std::fs::create_dir_all(&out)?,
            tar::EntryType::Regular => {
                if let Some(p) = out.parent() {
                    std::fs::create_dir_all(p)?;
                }
                let mut w = std::fs::File::create(&out)?;
                std::io::copy(&mut e, &mut w)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    // exactly the archived bits (never setuid/setgid/sticky); MANIFEST.json then checks them
                    let mode = e.header().mode().unwrap_or(0o644) & 0o777;
                    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode))?;
                }
            }
            other => bail!("member {raw:?} is a {other:?}; a release holds only files and directories"),
        }
    }
    let entries = oarbank_core::bundle::verify_release_dir(dest).map_err(|e| anyhow::anyhow!("{}", e.0))?;
    let listed: std::collections::HashSet<String> = entries.iter().map(|e| e.path.clone())
        .chain(["MANIFEST.json".to_string()]).collect();
    let extra = oarbank_core::bundle::unlisted(dest, &listed).map_err(|e| anyhow::anyhow!("{}", e.0))?;
    if !extra.is_empty() {
        bail!("files the manifest does not list: {:?}", &extra[..extra.len().min(5)]);
    }
    Ok(())
}

async fn download(api: &Api, url: &str, to: &Path, sha256: &str, max: Option<u64>) -> Result<()> {
    let r = api.download(url, 0).await?;
    let mut f = tokio::fs::File::create(to).await?;
    let mut h = Sha256::new();
    let mut s = r.bytes_stream();
    let mut n = 0u64;
    while let Some(chunk) = s.next().await {
        let chunk = chunk?;
        n += chunk.len() as u64;
        if let Some(max) = max.filter(|m| n > *m) {
            bail!("unsigned release refused: a release key is pinned and it is over {max} bytes, too big to be empty");
        }
        h.update(&chunk);
        f.write_all(&chunk).await?;
    }
    f.sync_all().await?;
    let got = hex::encode(h.finalize());
    if got != sha256 {
        bail!("release sha256 {} does not match the directive's {}", &got[..12], &sha256[..12.min(sha256.len())]);
    }
    Ok(())
}

/// Install the release a directive names; returns it. A failure leaves `current` untouched.
pub async fn install(api: &Api, l: &Layout, rt: &Runtime, d: &Value, signing: &crate::signing::Signing) -> Result<Release> {
    let id = d["release_id"].as_str().context("release directive without an id")?;
    if !id.starts_with("r_") || id.len() > 64 || !id[2..].chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("bad release id {id:?}");
    }
    let sha = d["sha256"].as_str().context("release directive without a sha256")?;
    let trust = signing.check_release(d)?;
    let empty_only = trust == ReleaseTrust::EmptyOnly;
    let final_dir = l.releases().join(id);
    if final_dir.exists() && empty_only {
        check_empty(&final_dir)?;            // the id is the coordinator's word: what is on disk under it must be empty
    }
    if !final_dir.exists() {
        let incoming = l.releases().join(".incoming");
        crate::fsutil::private_dir(&incoming)?;
        let tarball = incoming.join(format!("{id}.tar.gz"));
        download(api, d["url"].as_str().context("release without a url")?, &tarball, sha,
                 empty_only.then_some(MAX_UNSIGNED_BYTES)).await?;
        let partial = l.releases().join(format!(".{id}.partial"));
        let _ = std::fs::remove_dir_all(&partial);
        let (tb, pd) = (tarball.clone(), partial.clone());
        tokio::task::spawn_blocking(move || unpack(&tb, &pd)).await??;
        if empty_only {
            if let Err(e) = check_empty(&partial) {
                let _ = std::fs::remove_dir_all(&partial);
                let _ = std::fs::remove_file(&tarball);
                return Err(e);
            }
        }
        let rel = load(&partial)?;
        let scratch = l.run().join(format!("install-{id}"));
        for m in &rel.modules {
            let (rt, p, m, s) = (rt.clone(), partial.clone(), m.clone(), scratch.clone());
            tokio::task::spawn_blocking(move || rt.build_env(&p, &m, &s)).await??;
        }
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::rename(&partial, &final_dir)?;
        let _ = std::fs::remove_file(&tarball);
    }
    switch(l, id)?;
    prune(l, id);
    load(&final_dir)
}

/// Point `current` at a release atomically.
pub fn switch(l: &Layout, id: &str) -> Result<()> {
    crate::fsutil::point(&l.releases().join("current"), id)?;
    Ok(())
}

/// Keep the current release and the one before it, and those holding the bundle of a module whose deletion is still
/// pending (its cleanup stage runs from there: cleanup.rs).
fn prune(l: &Layout, keep: &str) {
    let Ok(rd) = std::fs::read_dir(l.releases()) else { return };
    let pending = crate::cleanup::kept_releases(l);
    let mut old: Vec<(std::time::SystemTime, PathBuf)> = rd.filter_map(|e| e.ok()).map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("r_") && n != keep))
        .filter_map(|p| Some((p.metadata().ok()?.modified().ok()?, p))).collect();
    old.sort();
    for (_, p) in old.iter().rev().skip(1) {
        if p.file_name().and_then(|n| n.to_str()).is_some_and(|n| pending.contains(n)) {
            continue;
        }
        let _ = std::fs::remove_dir_all(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A release directory as the coordinator builds one: `files` (path, bytes) plus MANIFEST.json vouching for them.
    fn release(dir: &Path, modules: Value, extra: &[(&str, &[u8])]) {
        let doc = serde_json::to_vec(&json!({"format": 2, "platform": "darwin-arm64", "modules": modules.get("modules"),
                                             "tools": modules.get("tools")})).unwrap();
        let mut files: Vec<(String, Vec<u8>)> = vec![("modules.json".into(), doc)];
        files.extend(extra.iter().map(|(p, b)| (p.to_string(), b.to_vec())));
        let mut entries = vec![];
        for (p, b) in &files {
            let out = dir.join(p);
            std::fs::create_dir_all(out.parent().unwrap()).unwrap();
            std::fs::write(&out, b).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            entries.push(json!({"path": p, "sha256": hex::encode(Sha256::digest(b)), "mode": "0o644"}));
        }
        std::fs::write(dir.join("MANIFEST.json"), serde_json::to_vec(&json!({"files": entries})).unwrap()).unwrap();
    }

    fn check(modules: Value, extra: &[(&str, &[u8])]) -> Result<()> {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("r_test");
        std::fs::create_dir_all(&dir).unwrap();
        release(&dir, modules, extra);
        check_empty(&dir)
    }

    #[test]
    fn an_empty_release_passes_the_unsigned_check() {
        check(json!({"modules": [], "tools": {}}), &[]).unwrap();
        check(json!({"modules": []}), &[]).unwrap();                 // no tools key at all
    }

    #[test]
    fn an_unsigned_release_with_anything_that_runs_is_refused() {
        let module = json!({"name": "toy", "bundle": "modules/toy", "runner": {"exec": ["python", "{bundle}/run.py"]}});
        let e = check(json!({"modules": [module], "tools": {}}), &[("modules/toy/run.py", b"print(1)")]).unwrap_err();
        assert!(format!("{e:#}").contains("holds 1 module"), "{e:#}");
        let tools = json!({"samtools": {"kind": "executable", "search": ["/opt/*/bin/samtools"],
                                        "version": {"args": ["--version"], "regex": "(\\S+)"}}});
        let e = check(json!({"modules": [], "tools": tools}), &[]).unwrap_err();
        assert!(format!("{e:#}").contains("tool definitions"), "{e:#}");
        // no module listed, but a file beside modules.json (code the agent never meant to run is still code)
        let e = check(json!({"modules": [], "tools": {}}), &[("modules/toy/run.py", b"print(1)")]).unwrap_err();
        assert!(format!("{e:#}").contains("besides modules.json"), "{e:#}");
        // a file the manifest does not list
        let t = tempfile::tempdir().unwrap();
        release(t.path(), json!({"modules": []}), &[]);
        std::fs::write(t.path().join("stray.sh"), b"#!/bin/sh\n").unwrap();
        let e = check_empty(t.path()).unwrap_err();
        assert!(format!("{e:#}").contains("other files"), "{e:#}");
        // a tampered modules.json no longer matches its manifest entry
        let t = tempfile::tempdir().unwrap();
        release(t.path(), json!({"modules": []}), &[]);
        std::fs::write(t.path().join("modules.json"), br#"{"format": 2, "modules": []}"#).unwrap();
        assert!(check_empty(t.path()).is_err());
    }
}
