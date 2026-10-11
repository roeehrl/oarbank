//! Owner statements (`signing.py` is the reference): Ed25519 over the UTF-8 bytes of the statement text, base64, and the
//! owner key set's rotation rule. Shared by the agent (moves.rs, nodeupdate.rs) and the node update runner (fleet.rs).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct OwnerError(pub String);

fn err<T>(s: impl Into<String>) -> Result<T, OwnerError> {
    Err(OwnerError(s.into()))
}

/// Verify a base64 Ed25519 signature over `msg` with a base64 raw public key (strict: no malleable signatures).
pub fn verify_ed25519(pub_b64: &str, msg: &[u8], sig_b64: &str) -> Result<(), OwnerError> {
    let pk: [u8; 32] = B64.decode(pub_b64).map_err(|e| OwnerError(e.to_string()))?.try_into()
        .map_err(|_| OwnerError("an Ed25519 key is 32 bytes".into()))?;
    let sig: [u8; 64] = B64.decode(sig_b64).map_err(|e| OwnerError(e.to_string()))?.try_into()
        .map_err(|_| OwnerError("an Ed25519 signature is 64 bytes".into()))?;
    VerifyingKey::from_bytes(&pk).map_err(|e| OwnerError(e.to_string()))?
        .verify_strict(msg, &Signature::from_bytes(&sig)).map_err(|e| OwnerError(e.to_string()))
}

/// Whether any of `keys` verifies `sig` over `msg`.
pub fn any_key_verifies(keys: &[String], msg: &[u8], sig: &str) -> bool {
    keys.iter().any(|k| verify_ed25519(k, msg, sig).is_ok())
}

/// A verified owner key set.
#[derive(Debug, Clone, PartialEq)]
pub struct OwnerSet {
    pub version: i64,
    pub keys: Vec<String>,
    /// Rescue locations: http(s) URLs where the owner publishes a rescue move.
    pub rescue: Vec<String>,
}

/// The owner key set (TUF-style root rotation) against the pinned one (`fleet_id`, `version`, `keys`; none pinned:
/// version 0, no keys): version + 1, every new key signs it, and a key of the pinned set too.
pub fn check_owner_anchors(j: &Value, fleet_id: Option<&str>, version: i64, pinned: &[String]) -> Result<OwnerSet, OwnerError> {
    let Some(stmt) = j["statement"].as_str() else { return err("owner keys: no statement") };
    let doc: Value = serde_json::from_str(stmt).map_err(|e| OwnerError(format!("owner keys: {e}")))?;
    if doc["type"].as_str() != Some("oarbank.owner-anchors/v1") || doc["threshold"].as_i64() != Some(1) {
        return err("owner keys: malformed set");
    }
    if fleet_id.is_some_and(|f| doc["fleet_id"].as_str() != Some(f)) {
        return err("owner keys: another fleet");
    }
    let Some(v) = doc["version"].as_i64() else { return err("owner keys: no version") };
    if v != version + 1 {
        return err(format!("owner keys: version {v} is not {}", version + 1));
    }
    let keys: Vec<String> = doc["keys"].as_array().into_iter().flatten().filter_map(|k| k.as_str().map(str::to_string)).collect();
    if keys.is_empty() {
        return err("owner keys: empty set");
    }
    let mut rescue = vec![];
    for u in doc["rescue"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        match u.as_str().filter(|s| s.starts_with("https://") || s.starts_with("http://")) {
            Some(s) => rescue.push(s.to_string()),
            None => return err(format!("owner keys: rescue location {u} is not a URL")),
        }
    }
    let sigs: std::collections::HashMap<String, String> = j["signatures"].as_array().into_iter().flatten()
        .filter_map(|s| Some((s["key"].as_str()?.to_string(), s["sig"].as_str()?.to_string()))).collect();
    for k in &keys {
        verify_ed25519(k, stmt.as_bytes(), sigs.get(k).map(String::as_str).unwrap_or(""))
            .map_err(|e| OwnerError(format!("owner keys: every key must sign: {e}")))?;
    }
    if !pinned.is_empty() && !pinned.iter().any(|k| sigs.get(k).is_some_and(|s| verify_ed25519(k, stmt.as_bytes(), s).is_ok())) {
        return err("owner keys: a key of the current set must sign the new set");
    }
    Ok(OwnerSet { version: v, keys, rescue })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    pub fn key(n: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[n; 32]);
        let p = B64.encode(sk.verifying_key().to_bytes());
        (sk, p)
    }

    pub fn sign(k: &SigningKey, msg: &str) -> String {
        B64.encode(k.sign(msg.as_bytes()).to_bytes())
    }

    pub fn owner_set(version: i64, keys: &[&(SigningKey, String)], signers: &[&(SigningKey, String)]) -> Value {
        let raw = serde_json::to_string(&json!({"type": "oarbank.owner-anchors/v1", "fleet_id": "fleet_a", "version": version,
            "threshold": 1, "keys": keys.iter().map(|k| k.1.clone()).collect::<Vec<_>>(), "rescue": []})).unwrap();
        json!({"statement": raw, "signatures": signers.iter().map(|s| json!({"key": s.1, "sig": sign(&s.0, &raw)})).collect::<Vec<_>>()})
    }

    #[test]
    fn signatures_verify_strictly() {
        let (k, p) = key(1);
        let s = sign(&k, "hello");
        verify_ed25519(&p, b"hello", &s).unwrap();
        assert!(verify_ed25519(&p, b"hellO", &s).is_err());
        assert!(verify_ed25519(&key(2).1, b"hello", &s).is_err());
        assert!(verify_ed25519("AAAA", b"hello", &s).is_err());
        assert!(verify_ed25519(&p, b"hello", "not base64!").is_err());
        assert!(any_key_verifies(&[key(2).1, p], b"hello", &s));
    }

    #[test]
    fn owner_sets_rotate_only_with_the_pinned_set_signing() {
        let (o1, o2, o3) = (key(4), key(5), key(6));
        let set = check_owner_anchors(&owner_set(1, &[&o1], &[&o1]), Some("fleet_a"), 0, &[]).unwrap();
        assert_eq!((set.version, set.keys.clone()), (1, vec![o1.1.clone()]));
        assert!(check_owner_anchors(&owner_set(1, &[&o1], &[&o1]), Some("fleet_b"), 0, &[]).is_err());       // another fleet
        let pinned = set.keys;
        assert!(check_owner_anchors(&owner_set(2, &[&o2], &[&o2]), None, 1, &pinned).is_err());              // old set did not sign
        assert!(check_owner_anchors(&owner_set(3, &[&o2], &[&o1, &o2]), None, 1, &pinned).is_err());         // skips a version
        assert!(check_owner_anchors(&owner_set(2, &[&o2, &o3], &[&o1, &o2]), None, 1, &pinned).is_err());    // o3 did not sign
        assert_eq!(check_owner_anchors(&owner_set(2, &[&o2], &[&o1, &o2]), None, 1, &pinned).unwrap().keys, vec![o2.1]);
    }
}
