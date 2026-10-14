//! Release and agent-build signatures (D31: on by default). The coordinator advertises the owner's release key; the
//! agent pins it on first sight and then refuses unsigned or rolled-back statements (a seq at or below the highest
//! it accepted).

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// What `check_release` allows (see there).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseTrust {
    /// No release key is pinned (developer mode, or before the first hello that advertises one).
    Open,
    /// Signed by the pinned key, for this release id and sha256, at an accepted seq.
    Signed,
    /// Unsigned while a key is pinned: installed only if it holds no module, no tool definition and no other file.
    EmptyOnly,
}

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

    /// How a release directive may be installed: anything (no key pinned), as the owner signed it, or, unsigned, only
    /// once the release proves empty (release::check_empty). An empty release carries no code, so it needs no signature
    /// (docs/release-signing.md, "Empty releases"); a directive with a statement or a signature must carry both, valid.
    pub fn check_release(&self, d: &Value) -> Result<ReleaseTrust> {
        let Some(key) = &self.pinned_key else { return Ok(ReleaseTrust::Open) };
        if d["statement"].is_null() && d["signature"].is_null() {
            return Ok(ReleaseTrust::EmptyOnly);
        }
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
        Ok(ReleaseTrust::Signed)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn keypair() -> (ed25519_dalek::SigningKey, String) {
        use base64::Engine;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        (sk, pk)
    }

    fn signed(sk: &ed25519_dalek::SigningKey, rid: &str, sha: &str, seq: i64) -> Value {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let stmt = json!({"release_id": rid, "sha256": sha, "seq": seq}).to_string();
        let sig = base64::engine::general_purpose::STANDARD.encode(sk.sign(stmt.as_bytes()).to_bytes());
        json!({"release_id": rid, "sha256": sha, "statement": stmt, "signature": sig})
    }

    #[test]
    fn a_pinned_key_lets_an_unsigned_release_through_only_as_empty() {
        let (sk, pk) = keypair();
        let open = Signing::default();
        assert_eq!(open.check_release(&json!({"release_id": "r_a", "sha256": "ab"})).unwrap(), ReleaseTrust::Open);
        let s = Signing { pinned_key: Some(pk), release_seq: 3, agent_seq: 0 };
        // no statement and no signature: only an empty release may be installed (release::check_empty decides)
        let bare = json!({"release_id": "r_a", "sha256": "ab", "statement": null, "signature": null});
        assert_eq!(s.check_release(&bare).unwrap(), ReleaseTrust::EmptyOnly);
        assert_eq!(s.check_release(&json!({"release_id": "r_a", "sha256": "ab"})).unwrap(), ReleaseTrust::EmptyOnly);
        assert_eq!(s.check_release(&signed(&sk, "r_a", "ab", 4)).unwrap(), ReleaseTrust::Signed);
        // half a signature, a forged one, another release's, a rolled-back seq: refused outright
        let mut half = signed(&sk, "r_a", "ab", 4);
        half["signature"] = Value::Null;
        assert!(s.check_release(&half).is_err());
        let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        assert!(s.check_release(&signed(&other, "r_a", "ab", 4)).is_err());
        let mut moved = signed(&sk, "r_a", "ab", 4);
        moved["release_id"] = json!("r_b");
        assert!(s.check_release(&moved).is_err());
        assert!(s.check_release(&signed(&sk, "r_a", "ab", 2)).is_err());
    }
}
