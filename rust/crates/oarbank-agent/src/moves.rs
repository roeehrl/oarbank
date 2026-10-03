//! Coordinator moves, agent side (docs/protocol.md, "Coordinator identity and moves"; docs/design/coordinator-move.md).
//!
//! A move statement names the next coordinator's URL and key at exactly the next epoch. The agent records it only when
//! the coordinator it trusts (`from`) and the target (`to`) both signed it (and the owner, once owner keys are pinned;
//! an owner-signed rescue move, read from the owner's rescue locations by rescue.rs, needs no `from` signature),
//! and follows it after the time lock: the target's tailnet identity (when named), its identity proof with the named
//! key, active at that epoch, then a successful hello. Only then does it commit; the old key is retired for good.

use crate::config::Trust;
use crate::identity::verify_ed25519;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct Statement {
    pub raw: String,
    pub signatures: serde_json::Map<String, Value>,
    pub move_id: String,
    pub fleet_id: String,
    pub epoch: i64,
    pub from_cik: String,
    pub to_url: String,
    pub to_cik: String,
    pub to_stable_id: Option<String>,
    pub not_before: f64,
    pub expires: f64,
    pub rescue: bool,
}

impl Statement {
    pub fn parse(j: &Value) -> Result<Statement> {
        let raw = j["statement"].as_str().context("move: no statement")?.to_string();
        let s: Value = serde_json::from_str(&raw).context("move: statement is not JSON")?;
        if s["type"].as_str() != Some("oarbank.coordinator-move/v1") {
            bail!("move: not a move statement");
        }
        let get = |p: &[&str]| -> Option<String> {
            let mut v = &s;
            for k in p {
                v = &v[*k];
            }
            v.as_str().map(str::to_string)
        };
        Ok(Statement {
            signatures: j["signatures"].as_object().cloned().unwrap_or_default(),
            move_id: get(&["move_id"]).context("move: no id")?,
            fleet_id: get(&["fleet_id"]).context("move: no fleet")?,
            epoch: s["epoch"].as_i64().context("move: no epoch")?,
            from_cik: get(&["from", "cik"]).context("move: no from key")?,
            to_url: get(&["to", "url"]).context("move: no target URL")?,
            to_cik: get(&["to", "cik"]).context("move: no target key")?,
            to_stable_id: get(&["to", "ts_stable_node_id"]),
            not_before: s["not_before"].as_f64().context("move: no time lock")?,
            expires: s["expires"].as_f64().context("move: no expiry")?,
            rescue: s["rescue"].as_bool().unwrap_or(false),
            raw,
        })
    }

    fn sig(&self, who: &str) -> Option<&str> {
        self.signatures.get(who).and_then(Value::as_str)
    }

    /// Before recording: this fleet, the next epoch, from the trusted key (or an owner-signed rescue), signed by the
    /// target, by the owner when owner keys are pinned, never to a retired key, not expired.
    pub fn verify(&self, trust: &Trust, now: f64, check_expiry: bool) -> Result<()> {
        if Some(&self.fleet_id) != trust.fleet_id.as_ref() {
            bail!("move: statement for another fleet");
        }
        if self.epoch != trust.max_epoch + 1 {
            bail!("move: statement epoch {} is not {}", self.epoch, trust.max_epoch + 1);
        }
        if Some(&self.from_cik) != trust.cik.as_ref() {
            bail!("move: not from the coordinator key this agent trusts");
        }
        if trust.retired.contains(&self.to_cik) || self.to_cik == self.from_cik {
            bail!("move: names a retired coordinator key");
        }
        if check_expiry && now > self.expires {
            bail!("move: statement expired");
        }
        let data = self.raw.as_bytes();
        if self.rescue {
            if trust.owner_keys.is_empty() {
                bail!("move: a rescue needs the owner keys, which this agent has not pinned");
            }
        } else {
            let s = self.sig("from").context("move: not signed by the current coordinator")?;
            verify_ed25519(&self.from_cik, data, s).context("move: bad signature from the current coordinator")?;
        }
        let s = self.sig("to").context("move: not signed by the target")?;
        verify_ed25519(&self.to_cik, data, s).context("move: bad signature from the target")?;
        if !trust.owner_keys.is_empty() {
            let s = self.sig("owner").context("move: lacks the owner's signature")?;
            if !trust.owner_keys.iter().any(|k| verify_ed25519(k, data, s).is_ok()) {
                bail!("move: the owner signature verifies with no pinned owner key");
            }
        }
        Ok(())
    }

    pub fn json(&self) -> Value {
        json!({"statement": self.raw, "signatures": self.signatures})
    }
}

/// A cancellation `{payload, sig}` signed by the coordinator the agent trusts, naming the pending move.
pub fn check_cancel(j: &Value, trust: &Trust, pending: &Statement) -> Result<()> {
    let payload = j["payload"].as_str().context("cancel: no payload")?;
    let sig = j["sig"].as_str().context("cancel: no signature")?;
    verify_ed25519(trust.cik.as_deref().context("no trusted key")?, payload.as_bytes(), sig)?;
    let doc: Value = serde_json::from_str(payload)?;
    if doc["move_id"].as_str() != Some(pending.move_id.as_str()) {
        bail!("cancel: names another move");
    }
    Ok(())
}

/// A verified owner key set.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnerSet {
    pub version: i64,
    pub keys: Vec<String>,
    /// Rescue locations: http(s) URLs where the owner publishes a rescue move.
    pub rescue: Vec<String>,
}

/// The owner key set (TUF-style root rotation): version + 1, every new key signs it, and a key of the pinned set too.
pub fn check_owner_anchors(j: &Value, trust: &Trust) -> Result<OwnerSet> {
    let stmt = j["statement"].as_str().context("owner keys: no statement")?;
    let doc: Value = serde_json::from_str(stmt)?;
    if doc["type"].as_str() != Some("oarbank.owner-anchors/v1") || doc["threshold"].as_i64() != Some(1) {
        bail!("owner keys: malformed set");
    }
    if trust.fleet_id.as_deref().is_some_and(|f| doc["fleet_id"].as_str() != Some(f)) {
        bail!("owner keys: another fleet");
    }
    let version = doc["version"].as_i64().context("owner keys: no version")?;
    if version != trust.owner_version + 1 {
        bail!("owner keys: version {version} is not {}", trust.owner_version + 1);
    }
    let keys: Vec<String> = doc["keys"].as_array().cloned().unwrap_or_default().iter().filter_map(|k| k.as_str().map(str::to_string)).collect();
    if keys.is_empty() {
        bail!("owner keys: empty set");
    }
    let mut rescue = vec![];
    for u in doc["rescue"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        match u.as_str().filter(|s| s.starts_with("https://") || s.starts_with("http://")) {
            Some(s) => rescue.push(s.to_string()),
            None => bail!("owner keys: rescue location {u} is not a URL"),
        }
    }
    let sigs: std::collections::HashMap<String, String> = j["signatures"].as_array().cloned().unwrap_or_default().iter()
        .filter_map(|s| Some((s["key"].as_str()?.to_string(), s["sig"].as_str()?.to_string()))).collect();
    for k in &keys {
        verify_ed25519(k, stmt.as_bytes(), sigs.get(k).map(String::as_str).unwrap_or("")).context("owner keys: every key must sign")?;
    }
    if !trust.owner_keys.is_empty()
        && !trust.owner_keys.iter().any(|k| sigs.get(k).is_some_and(|s| verify_ed25519(k, stmt.as_bytes(), s).is_ok())) {
        bail!("owner keys: a key of the current set must sign the new set");
    }
    Ok(OwnerSet { version, keys, rescue })
}

/// Whether the target address is a Tailscale address (100.64.0.0/10 or fd7a:115c:a1e0::/48).
pub fn tailnet_address(host: &str) -> bool {
    let h = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if h.starts_with("fd7a:115c:a1e0:") {
        return true;
    }
    let p: Vec<u8> = h.split('.').filter_map(|x| x.parse().ok()).collect();
    p.len() == 4 && p[0] == 100 && (64..=127).contains(&p[1])
}

/// `tailscale whois --json <ip>`'s StableID, when Tailscale is available.
pub fn tailnet_stable_id(ip: &str) -> Option<String> {
    let cli = std::env::var("OARBANK_TAILSCALE").ok().or_else(|| {
        ["/opt/homebrew/bin/tailscale", "/usr/local/bin/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"]
            .iter().find(|p| std::path::Path::new(p).is_file()).map(|p| p.to_string())
    })?;
    let out = std::process::Command::new(cli).args(["whois", "--json", ip]).output().ok()?;
    let v: Value = serde_json::from_slice(&out.stdout).ok()?;
    v["Node"]["StableID"].as_str().map(str::to_string)
}

/// Commit a followed move: the new URL and key, the epoch raised, the old key retired and its URL kept as a fallback.
pub fn commit(trust: &mut Trust, coordinator: &mut String, s: &Statement) {
    trust.retired.push(s.from_cik.clone());
    trust.fallback = Some(coordinator.clone());
    trust.cik = Some(s.to_cik.clone());
    trust.max_epoch = s.epoch;
    trust.pending_move = None;
    *coordinator = s.to_url.trim_end_matches('/').to_string();
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    fn k(n: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[n; 32]);
        let p = B64.encode(sk.verifying_key().to_bytes());
        (sk, p)
    }

    fn statement(from: &(SigningKey, String), to: &(SigningKey, String), epoch: i64, owner: Option<&SigningKey>, rescue: bool) -> Value {
        let raw = serde_json::to_string(&json!({"type": "oarbank.coordinator-move/v1", "fleet_id": "fleet_a", "move_id": "mv_1",
            "epoch": epoch, "from": {"url": "https://a:7443", "cik": from.1}, "to": {"url": "https://b:7443", "cik": to.1},
            "not_before": 0, "expires": 4e9, "rescue": rescue})).unwrap();
        let mut sigs = json!({"to": B64.encode(to.0.sign(raw.as_bytes()).to_bytes())});
        if !rescue {
            sigs["from"] = json!(B64.encode(from.0.sign(raw.as_bytes()).to_bytes()));
        }
        if let Some(o) = owner {
            sigs["owner"] = json!(B64.encode(o.sign(raw.as_bytes()).to_bytes()));
        }
        json!({"statement": raw, "signatures": sigs})
    }

    #[test]
    fn a_move_needs_both_coordinators_the_next_epoch_and_the_owner_once_pinned() {
        let (a, b, owner) = (k(1), k(2), k(3));
        let mut t = Trust { cik: Some(a.1.clone()), fleet_id: Some("fleet_a".into()), max_epoch: 1, ..Default::default() };
        let s = Statement::parse(&statement(&a, &b, 2, None, false)).unwrap();
        s.verify(&t, 1.0, true).unwrap();
        assert!(Statement::parse(&statement(&a, &b, 3, None, false)).unwrap().verify(&t, 1.0, true).is_err());     // skips an epoch
        let rogue = k(9);
        assert!(Statement::parse(&statement(&rogue, &b, 2, None, false)).unwrap().verify(&t, 1.0, true).is_err()); // not from A
        let mut unsigned = statement(&a, &b, 2, None, false);
        unsigned["signatures"].as_object_mut().unwrap().remove("to");
        assert!(Statement::parse(&unsigned).unwrap().verify(&t, 1.0, true).is_err());                              // B never signed
        t.owner_keys = vec![owner.1.clone()];
        assert!(s.verify(&t, 1.0, true).is_err());                                                                 // owner now required
        Statement::parse(&statement(&a, &b, 2, Some(&owner.0), false)).unwrap().verify(&t, 1.0, true).unwrap();
        Statement::parse(&statement(&a, &b, 2, Some(&owner.0), true)).unwrap().verify(&t, 1.0, true).unwrap();     // owner rescue
        let mut coord = "https://a:7443".to_string();
        commit(&mut t, &mut coord, &s);
        assert_eq!((coord.as_str(), t.max_epoch, t.cik.as_deref()), ("https://b:7443", 2, Some(b.1.as_str())));
        assert!(t.retired.contains(&a.1));
        assert!(Statement::parse(&statement(&b, &a, 3, Some(&owner.0), false)).unwrap().verify(&t, 1.0, true).is_err()); // back to a retired key
    }

    #[test]
    fn owner_key_sets_rotate_only_with_the_old_set_signing() {
        let (o1, o2, o3) = (k(4), k(5), k(6));
        let sign_set = |version: i64, keys: &[&(SigningKey, String)], signers: &[&(SigningKey, String)], rescue: Value| {
            let raw = serde_json::to_string(&json!({"type": "oarbank.owner-anchors/v1", "fleet_id": "fleet_a", "version": version,
                "threshold": 1, "keys": keys.iter().map(|k| k.1.clone()).collect::<Vec<_>>(), "rescue": rescue})).unwrap();
            json!({"statement": raw, "signatures": signers.iter().map(|s| json!({"key": s.1, "sig": B64.encode(s.0.sign(raw.as_bytes()).to_bytes())})).collect::<Vec<_>>()})
        };
        let mut t = Trust { fleet_id: Some("fleet_a".into()), ..Default::default() };
        let set = check_owner_anchors(&sign_set(1, &[&o1], &[&o1], json!(["https://rescue.example.org/fleet_a.json"])), &t).unwrap();
        assert_eq!((set.version, set.rescue.as_slice()), (1, &["https://rescue.example.org/fleet_a.json".to_string()][..]));
        t.owner_version = set.version;
        t.owner_keys = set.keys;
        assert!(check_owner_anchors(&sign_set(2, &[&o2], &[&o2], json!([])), &t).is_err());        // the old set did not sign
        assert!(check_owner_anchors(&sign_set(3, &[&o2], &[&o1, &o2], json!([])), &t).is_err());   // skips a version
        assert!(check_owner_anchors(&sign_set(2, &[&o2, &o3], &[&o1, &o2], json!([])), &t).is_err()); // o3 did not sign
        assert!(check_owner_anchors(&sign_set(2, &[&o2], &[&o1, &o2], json!(["ftp://x/y"])), &t).is_err()); // not a URL
        assert!(check_owner_anchors(&sign_set(2, &[&o2], &[&o1, &o2], json!([])), &t).unwrap().rescue.is_empty());
    }

    #[test]
    fn tailnet_addresses() {
        assert!(tailnet_address("100.64.0.10") && tailnet_address("[fd7a:115c:a1e0::1]"));
        assert!(!tailnet_address("100.12.0.1") && !tailnet_address("192.168.1.2"));
    }
}
