//! The coordinator's identity (docs/protocol.md, "Coordinator identity and moves"): agents trust a key, not a URL.
//!
//! `GET /v1/identity?nonce=<n>` answers `{payload, sig}`: canonical JSON naming the fleet, epoch, role, CIK, the nonce
//! and the TLS CA pin, signed with the CIK. The agent verifies the signature over the exact payload bytes, pins the
//! key and fleet on first use, refuses a lower epoch, and learns the CA pin only through this signature.

use crate::config::Trust;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

pub const IDENTITY_TYPE: &str = "oarbank.coordinator-identity/v1";

#[derive(Debug, Clone)]
pub struct Proof {
    pub fleet_id: String,
    pub epoch: i64,
    pub role: String,
    pub cik: String,
    pub ca_spki_sha256: Option<String>,
    pub ca_next_spki_sha256: Option<String>,
}

pub fn verify_ed25519(pub_b64: &str, msg: &[u8], sig_b64: &str) -> Result<()> {
    let pk: [u8; 32] = B64.decode(pub_b64)?.try_into().map_err(|_| anyhow::anyhow!("an Ed25519 key is 32 bytes"))?;
    let sig: [u8; 64] = B64.decode(sig_b64)?.try_into().map_err(|_| anyhow::anyhow!("an Ed25519 signature is 64 bytes"))?;
    VerifyingKey::from_bytes(&pk)?.verify_strict(msg, &Signature::from_bytes(&sig))?;
    Ok(())
}

pub fn new_nonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// Check an identity answer against the nonce and what the agent already trusts (nothing yet: first use).
pub fn check(answer: &Value, nonce: &str, trust: &Trust) -> Result<Proof> {
    let payload = answer["payload"].as_str().context("identity: no payload")?;
    let sig = answer["sig"].as_str().context("identity: no signature")?;
    let doc: Value = serde_json::from_str(payload).context("identity: payload is not JSON")?;
    let cik = doc["cik"].as_str().context("identity: no key")?.to_string();
    if let Some(pinned) = &trust.cik {
        if pinned != &cik {
            bail!("identity: the coordinator presents another key than the one this agent trusts");
        }
    }
    if trust.retired.contains(&cik) {
        bail!("identity: that key was retired by a coordinator move");
    }
    verify_ed25519(&cik, payload.as_bytes(), sig).context("identity: bad signature")?;
    if doc["type"].as_str() != Some(IDENTITY_TYPE) {
        bail!("identity: unexpected payload type");
    }
    if doc["nonce"].as_str() != Some(nonce) {
        bail!("identity: the proof answers another challenge");
    }
    let fleet_id = doc["fleet_id"].as_str().context("identity: no fleet")?.to_string();
    if let Some(f) = &trust.fleet_id {
        if f != &fleet_id {
            bail!("identity: the coordinator belongs to another fleet");
        }
    }
    let epoch = doc["epoch"].as_i64().context("identity: no epoch")?;
    if epoch < trust.max_epoch {
        bail!("stale_coordinator: epoch {epoch} is below {} that this agent has seen", trust.max_epoch);
    }
    let tls = &doc["tls"];
    Ok(Proof { fleet_id, epoch, role: doc["role"].as_str().unwrap_or("").to_string(), cik,
               ca_spki_sha256: tls["ca_spki_sha256"].as_str().map(str::to_string),
               ca_next_spki_sha256: tls["ca_next_spki_sha256"].as_str().map(str::to_string) })
}

/// Record what a checked proof establishes (first use pins the key and fleet; the epoch only rises).
pub fn apply(trust: &mut Trust, p: &Proof) {
    trust.cik.get_or_insert_with(|| p.cik.clone());
    trust.fleet_id.get_or_insert_with(|| p.fleet_id.clone());
    trust.max_epoch = trust.max_epoch.max(p.epoch);
    if p.ca_spki_sha256.is_some() {
        trust.ca_spki_sha256 = p.ca_spki_sha256.clone();
        trust.ca_next_spki_sha256 = p.ca_next_spki_sha256.clone();
    }
}

pub fn pins(trust: &Trust) -> Vec<String> {
    trust.ca_spki_sha256.iter().chain(trust.ca_next_spki_sha256.iter()).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn answer(sk: &SigningKey, doc: Value) -> Value {
        let payload = serde_json::to_string(&doc).unwrap();
        serde_json::json!({"payload": payload, "sig": B64.encode(sk.sign(payload.as_bytes()).to_bytes())})
    }

    #[test]
    fn first_use_pins_then_refuses_another_key_a_lower_epoch_or_a_replay() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let cik = B64.encode(sk.verifying_key().to_bytes());
        let doc = |nonce: &str, epoch: i64| serde_json::json!({"type": IDENTITY_TYPE, "fleet_id": "fleet_a",
            "epoch": epoch, "role": "active", "cik": cik, "nonce": nonce, "tls": {"ca_spki_sha256": "ab"}});
        let mut t = Trust::default();
        let p = check(&answer(&sk, doc("n1", 2)), "n1", &t).unwrap();
        apply(&mut t, &p);
        assert_eq!((t.cik.as_deref(), t.max_epoch, t.ca_spki_sha256.as_deref()), (Some(cik.as_str()), 2, Some("ab")));
        assert!(check(&answer(&sk, doc("n1", 2)), "n2", &t).is_err());                  // answers another challenge
        assert!(check(&answer(&sk, doc("n3", 1)), "n3", &t).unwrap_err().to_string().contains("stale_coordinator"));
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let mut d = doc("n4", 2);
        d["cik"] = Value::from(B64.encode(other.verifying_key().to_bytes()));
        assert!(check(&answer(&other, d), "n4", &t).is_err());                            // another key
        let mut forged = answer(&sk, doc("n5", 2));
        forged["payload"] = Value::from(forged["payload"].as_str().unwrap().replace("fleet_a", "fleet_b"));
        assert!(check(&forged, "n5", &t).is_err());                                       // tampered payload
    }
}
