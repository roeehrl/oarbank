//! Agent self-update (docs/protocol.md, "Agent self-update"; the launcher owns the version pointer).
//!
//! On an `agent_update` directive the agent downloads the build, checks its size, sha256, signature (signing mode),
//! that it is an executable for this platform and that its embedded version marker is the directive's version. It
//! installs it beside the running version, drains (no new claims; running attempts finish), records
//! `state/upgrade.json {state: staged, target}` and exits 75. The launcher flips to it on trial; the new agent confirms
//! after its first hello and heartbeat. A build that failed is not retried (a missed confirmation: not for 6 hours).

use crate::api::Api;
use crate::paths::Layout;
use crate::signing::Signing;
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

pub const SWAP_EXIT: i32 = 75;
const CONFIRM_WITHIN_S: f64 = 600.0;
const RETRY_AFTER_MISSED_S: f64 = 6.0 * 3600.0;

pub struct SelfUpdate {
    pub build_sha: String,
    pub launcher: bool,
    pub state: Value,
    refused: HashMap<String, f64>,
    started: f64,
    confirming: bool,
    /// A staged build waiting for the node to drain.
    pub staged: Option<Value>,
}

fn now() -> f64 {
    crate::doctor::now()
}

fn upgrade_path(l: &Layout) -> PathBuf {
    l.state().join("upgrade.json")
}

fn refused_path(l: &Layout) -> PathBuf {
    l.state().join("agent-update-refused.json")
}

/// The platform a binary is built for, from its header (64-bit Mach-O and ELF, PE).
pub fn binary_platform(data: &[u8]) -> Option<String> {
    let u32le = |o: usize| data.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let u16le = |o: usize| data.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    if data.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return match u32le(4)? { 0x0100_000C => Some("darwin-arm64".into()), 0x0100_0007 => Some("darwin-amd64".into()), _ => None };
    }
    if data.starts_with(b"\x7fELF") && data.get(4) == Some(&2) {
        return match u16le(18)? { 0xB7 => Some("linux-arm64".into()), 0x3E => Some("linux-amd64".into()), _ => None };
    }
    if data.starts_with(b"MZ") {
        let off = u32le(0x3C)? as usize;
        if data.get(off..off + 4) == Some(b"PE\0\0") {
            return match u16le(off + 4)? { 0xAA64 => Some("windows-arm64".into()), 0x8664 => Some("windows-amd64".into()), _ => None };
        }
    }
    None
}

pub fn version_marker(data: &[u8]) -> Option<String> {
    let p = b"oarbank-agent-version:";
    // the prefix also appears as a plain literal (the code that looks for it): take the occurrence a version follows
    let mut from = 0;
    while let Some(i) = data[from..].windows(p.len()).position(|w| w == p) {
        let rest = &data[from + i + p.len()..];
        if let Some(end) = rest.iter().take(64).position(|&b| b == 0) {
            let v = &rest[..end];
            if !v.is_empty() && v[0].is_ascii_digit() && v.iter().all(|c| c.is_ascii_alphanumeric() || b".+-".contains(c)) {
                return String::from_utf8(v.to_vec()).ok();
            }
        }
        from += i + 1;
    }
    None
}

impl SelfUpdate {
    pub fn open(l: &Layout) -> Self {
        let exe = std::env::current_exe().ok();
        let build_sha = exe.as_ref().and_then(|p| crate::fsutil::sha256_file(p).ok()).unwrap_or_default();
        let launcher = std::env::var_os("OARBANK_LAUNCHER").is_some();
        let refused: HashMap<String, f64> = std::fs::read(refused_path(l)).ok().and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mut s = SelfUpdate { build_sha, launcher, state: json!({"state": if launcher { "idle" } else { "blocked" }}),
                                 refused, started: now(), confirming: false, staged: None };
        if let Some(up) = std::fs::read(upgrade_path(l)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
            let target_sha = up["sha256"].as_str().unwrap_or("").to_string();
            match up["state"].as_str() {
                Some("trial") if target_sha == s.build_sha => {
                    s.confirming = true;
                    s.state = json!({"state": "confirming", "target": target_sha, "version": up["version"], "at": now()});
                }
                Some("rolled_back") | Some("failed") => {
                    let missed = up["error"].as_str().is_some_and(|e| e.contains("confirm"));
                    s.refused.insert(target_sha.clone(), if missed { now() + RETRY_AFTER_MISSED_S } else { f64::MAX });
                    s.save_refused(l);
                    s.state = json!({"state": up["state"], "target": target_sha, "version": up["version"],
                                     "error": up["error"], "at": now()});
                    let _ = std::fs::remove_file(upgrade_path(l));
                }
                _ => {}
            }
        }
        s
    }

    fn save_refused(&self, l: &Layout) {
        let _ = crate::fsutil::write_private(&refused_path(l), &serde_json::to_vec(&self.refused).unwrap_or_default());
    }

    pub fn report(&self) -> Value {
        json!({"agent_build": self.build_sha, "agent_update": self.state})
    }

    /// After the first successful hello and heartbeat: this build stays.
    pub fn confirm(&mut self, l: &Layout) {
        if self.confirming {
            self.confirming = false;
            let _ = std::fs::remove_file(upgrade_path(l));
            self.state = json!({"state": "confirmed", "target": self.build_sha, "at": now()});
        }
    }

    /// An unconfirmed new version gives up after 600 s; the launcher then rolls back on its next start.
    pub fn should_give_up(&self) -> bool {
        self.confirming && now() - self.started > CONFIRM_WITHIN_S
    }

    /// Act on the directive; returns true when the node should drain for a staged update.
    pub async fn handle(&mut self, api: &Api, l: &Layout, d: &Value, signing: &Signing) -> bool {
        if d.is_null() || self.staged.is_some() {
            return self.staged.is_some();
        }
        if !self.launcher {
            self.state = json!({"state": "blocked", "error": "not started by oarbank-launcher", "at": now()});
            return false;
        }
        let sha = d["sha256"].as_str().unwrap_or("").to_string();
        if sha.is_empty() || sha == self.build_sha {
            return false;
        }
        if self.refused.get(&sha).is_some_and(|until| now() < *until) {
            return false;
        }
        self.state = json!({"state": "staging", "target": sha, "version": d["version"], "at": now()});
        match self.stage(api, l, d, signing).await {
            Ok(rel) => {
                self.staged = Some(json!({"state": "staged", "target": rel, "sha256": sha, "version": d["version"], "at": now()}));
                self.state = json!({"state": "draining", "target": sha, "version": d["version"], "at": now()});
                true
            }
            Err(e) => {
                self.refused.insert(sha.clone(), f64::MAX);
                self.save_refused(l);
                self.state = json!({"state": "failed", "target": sha, "version": d["version"], "error": format!("{e:#}"), "at": now()});
                false
            }
        }
    }

    async fn stage(&self, api: &Api, l: &Layout, d: &Value, signing: &Signing) -> Result<String> {
        let sha = d["sha256"].as_str().context("no sha256")?;
        let version = d["version"].as_str().context("no version")?;
        if sha.len() != 64 || !sha.bytes().all(|c| c.is_ascii_hexdigit()) {
            bail!("bad sha256");
        }
        if version.is_empty() || version.len() > 64 || !version.chars().all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c)) {
            bail!("bad version {version:?}");
        }
        let platform = crate::facts::platform_token();
        signing.check_agent_build(d, &platform)?;
        let incoming = l.home.join("versions").join(".incoming");
        crate::fsutil::private_dir(&incoming)?;
        let tmp = incoming.join(sha);
        let r = api.download(d["url"].as_str().context("agent update without a url")?, 0).await?;
        let mut f = tokio::fs::File::create(&tmp).await?;
        let mut h = Sha256::new();
        let mut n = 0u64;
        let mut s = r.bytes_stream();
        while let Some(c) = s.next().await {
            let c = c?;
            h.update(&c);
            n += c.len() as u64;
            f.write_all(&c).await?;
        }
        f.sync_all().await?;
        if hex::encode(h.finalize()) != sha {
            bail!("the downloaded build does not match its sha256");
        }
        if d["size"].as_u64().is_some_and(|sz| sz != n) {
            bail!("the downloaded build has the wrong size");
        }
        let data = std::fs::read(&tmp)?;
        if binary_platform(&data).as_deref() != Some(platform.as_str()) {
            bail!("the build is not an executable for {platform}");
        }
        if version_marker(&data).as_deref() != Some(version) {
            bail!("the build's embedded version is not {version}");
        }
        // the vendor's TUF metadata must list exactly this build (when this agent trusts a vendor root)
        crate::tuf::check_agent_build(api, l, &crate::tuf::agent_target(version, &platform), sha, n).await?;
        let rel = format!("versions/{version}-{}/oarbank-agent{}", &sha[..12], std::env::consts::EXE_SUFFIX);
        let dst = l.home.join(&rel);
        std::fs::create_dir_all(dst.parent().unwrap())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::rename(&tmp, &dst)?;
        Ok(rel)
    }

    /// Drained: hand the staged build to the launcher.
    pub fn hand_over(&mut self, l: &Layout) -> Result<()> {
        let up = self.staged.take().context("nothing staged")?;
        crate::fsutil::write_private(&upgrade_path(l), &serde_json::to_vec_pretty(&up)?)?;
        self.state = json!({"state": "restarting", "target": up["sha256"], "version": up["version"], "at": now()});
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_platform_and_version_from_the_binary_itself() {
        let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(binary_platform(&me).as_deref(), Some(crate::facts::platform_token().as_str()));
        assert!(binary_platform(b"#!/bin/sh\n").is_none());
        let fake = [&b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01"[..], b"oarbank-agent-version:upgrade.json", b"....oarbank-agent-version:9.1.2\0"].concat();
        assert_eq!((binary_platform(&fake).as_deref(), version_marker(&fake).as_deref()), (Some("darwin-arm64"), Some("9.1.2")));
    }
}
