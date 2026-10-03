//! Releases (docs/protocol.md, "Releases"): download, check the sha256 (and the signature in signing mode), unpack
//! with every member checked, verify MANIFEST.json, build module environments, switch `current` atomically.

use crate::api::Api;
use crate::paths::Layout;
use crate::runtime::Runtime;
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
    Ok(Release { id, dir: dir.to_path_buf(), modules: doc["modules"].as_array().cloned().unwrap_or_default() })
}

pub fn current(l: &Layout) -> Option<Release> {
    let target = crate::fsutil::pointed(&l.releases().join("current"))?;
    load(&l.releases().join(target)).ok()
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

async fn download(api: &Api, url: &str, to: &Path, sha256: &str) -> Result<()> {
    let r = api.download(url, 0).await?;
    let mut f = tokio::fs::File::create(to).await?;
    let mut h = Sha256::new();
    let mut s = r.bytes_stream();
    while let Some(chunk) = s.next().await {
        let chunk = chunk?;
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
    signing.check_release(d)?;
    let final_dir = l.releases().join(id);
    if !final_dir.exists() {
        let incoming = l.releases().join(".incoming");
        crate::fsutil::private_dir(&incoming)?;
        let tarball = incoming.join(format!("{id}.tar.gz"));
        download(api, d["url"].as_str().context("release without a url")?, &tarball, sha).await?;
        let partial = l.releases().join(format!(".{id}.partial"));
        let _ = std::fs::remove_dir_all(&partial);
        let (tb, pd) = (tarball.clone(), partial.clone());
        tokio::task::spawn_blocking(move || unpack(&tb, &pd)).await??;
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

/// Keep the current release and the one before it.
fn prune(l: &Layout, keep: &str) {
    let Ok(rd) = std::fs::read_dir(l.releases()) else { return };
    let mut old: Vec<(std::time::SystemTime, PathBuf)> = rd.filter_map(|e| e.ok()).map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("r_") && n != keep))
        .filter_map(|p| Some((p.metadata().ok()?.modified().ok()?, p))).collect();
    old.sort();
    for (_, p) in old.iter().rev().skip(1) {
        let _ = std::fs::remove_dir_all(p);
    }
}
