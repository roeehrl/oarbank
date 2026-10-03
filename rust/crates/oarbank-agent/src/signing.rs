//! Release and agent-build signatures (D31: on by default). The coordinator advertises the owner's release key; the
//! agent pins it on first sight and then refuses unsigned or rolled-back statements (a seq at or below the highest
//! it accepted).

use anyhow::{bail, Context, Result};
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct Signing {
    pub pinned_key: Option<String>,
    pub release_seq: i64,
    pub agent_seq: i64,
}

impl Signing {
    /// Pin the advertised key on first sight; a different key later is refused (rotation goes through the owner key set).
    pub fn observe_key(&mut self, advertised: Option<&str>) -> Result<()> {
        match (&self.pinned_key, advertised) {
            (None, Some(k)) => {
                self.pinned_key = Some(k.to_string());
                Ok(())
            }
            (Some(p), Some(k)) if p != k => bail!("the coordinator advertises another release key than the pinned one"),
            _ => Ok(()),
        }
    }

    pub fn check_release(&self, d: &Value) -> Result<()> {
        let Some(key) = &self.pinned_key else { return Ok(()) };
        let stmt = d["statement"].as_str().context("unsigned release refused: a release key is pinned")?;
        let sig = d["signature"].as_str().context("unsigned release refused: no signature")?;
        crate::identity::verify_ed25519(key, stmt.as_bytes(), sig).context("bad release signature")?;
        let s: Value = serde_json::from_str(stmt)?;
        if s["release_id"] != d["release_id"] || s["sha256"] != d["sha256"] {
            bail!("the release statement names another release");
        }
        if s["seq"].as_i64().unwrap_or(0) < self.release_seq {
            bail!("release statement seq {} is below the accepted {}", s["seq"], self.release_seq);
        }
        Ok(())
    }

    pub fn accept_release(&mut self, d: &Value) {
        if let Some(seq) = d["statement"].as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()).and_then(|s| s["seq"].as_i64()) {
            self.release_seq = self.release_seq.max(seq);
        }
    }

    pub fn check_agent_build(&self, d: &Value, platform: &str) -> Result<()> {
        let Some(key) = &self.pinned_key else { return Ok(()) };
        let stmt = d["statement"].as_str().context("unsigned agent build refused")?;
        let sig = d["signature"].as_str().context("unsigned agent build refused")?;
        crate::identity::verify_ed25519(key, stmt.as_bytes(), sig).context("bad agent build signature")?;
        let s: Value = serde_json::from_str(stmt)?;
        if s["agent_sha256"] != d["sha256"] || s["version"] != d["version"] {
            bail!("the agent build statement names another build");
        }
        if !s["platforms"].as_array().is_some_and(|p| p.iter().any(|x| x.as_str() == Some(platform))) {
            bail!("the agent build statement is not for {platform}");
        }
        if s["seq"].as_i64().unwrap_or(0) <= self.agent_seq {
            bail!("agent build seq {} is not above the installed {}", s["seq"], self.agent_seq);
        }
        Ok(())
    }
}
