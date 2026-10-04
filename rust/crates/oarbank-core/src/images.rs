//! Container image sets approved by signature (the SDK's spec/sandbox.md, "Image sets"; reference: `oarbank_sdk.images`).
//!
//! A set names a registry and repository prefix, a platform and a pinned cosign public key (ECDSA P-256). This module
//! holds the pure decisions both sides must make identically, replayed from `spec/vectors/image-signatures.json`:
//! reference normalization, prefix membership, the two cosign signature formats (a Sigstore bundle's DSSE envelope over
//! an in-toto statement, and a simple-signing payload with its signature) and the signed image index document. Fetching
//! the artifacts from a registry is the agent's (`registry.rs`). Verification needs only the key: no transparency log,
//! no network.

use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const SIG_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
pub const SIMPLE_SIGNING: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
pub const SIMPLE_TYPE: &str = "cosign container image signature";
pub const BUNDLE_TYPES: [&str; 1] = ["application/vnd.dev.sigstore.bundle.v0.3+json"];
pub const INTOTO_PAYLOAD: &str = "application/vnd.in-toto+json";
pub const INTOTO_STATEMENT: &str = "https://in-toto.io/Statement/v1";
pub const COSIGN_PREDICATE: &str = "https://sigstore.dev/cosign/sign/v1";
pub const INDEX_TYPE: &str = "application/vnd.oarbank.image-set.v1+json";
pub const INDEX_DOC_TYPE: &str = "oarbank.image-set/v1";
/// Manifests, signature payloads, bundles and index documents are at most this large.
pub const MAX_DOC: usize = 4 << 20;
const SPKI_P256: [u8; 26] = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
                             0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct ImageError(pub String);

fn err<T>(s: impl Into<String>) -> Result<T, ImageError> {
    Err(ImageError(s.into()))
}

/// `sha256:<64 lowercase hex>`.
pub fn is_digest(s: &str) -> bool {
    s.len() == 71 && s.starts_with("sha256:") && s[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn name_char(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'/' | b':' | b'-')
}

fn tag_ok(t: &str) -> bool {
    let b = t.as_bytes();
    !b.is_empty() && b.len() <= 128 && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

/// A normalized reference: the repository with its registry, and the tag and digest when given.
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

/// As Docker resolves a reference: `org/tool` is `docker.io/org/tool`, `tool` is `docker.io/library/tool`,
/// `index.docker.io` is `docker.io`.
pub fn normalize(reference: &str) -> Result<Reference, ImageError> {
    let bad = || ImageError(format!("{reference:?} is not an image reference"));
    let (rest, digest) = match reference.split_once('@') {
        Some((r, d)) if is_digest(d) => (r, Some(d.to_string())),
        Some(_) => return Err(bad()),
        None => (reference, None),
    };
    // a tag is after the last ':' that follows the last '/' (a ':' before it is a registry port)
    let slash = rest.rfind('/').map(|i| i + 1).unwrap_or(0);
    let (name, tag) = match rest[slash..].rfind(':') {
        Some(i) => (&rest[..slash + i], Some(rest[slash + i + 1..].to_string())),
        None => (rest, None),
    };
    if name.is_empty() || !name.as_bytes()[0].is_ascii_alphanumeric() || !name.bytes().all(name_char)
        || name.as_bytes()[0].is_ascii_uppercase() || tag.as_deref().is_some_and(|t| !tag_ok(t)) {
        return Err(bad());
    }
    let first = name.split('/').next().unwrap_or("");
    let mut repo = if name.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost") {
        name.to_string()
    } else if name.contains('/') {
        format!("docker.io/{name}")
    } else {
        format!("docker.io/library/{name}")
    };
    if let Some(r) = repo.strip_prefix("index.docker.io/") {
        repo = format!("docker.io/{r}");
    }
    Ok(Reference { repository: repo, tag, digest })
}

/// The simple-signing tag of a digest: `sha256-<hex>.sig`.
pub fn signature_tag(digest: &str) -> String {
    format!("{}.sig", digest.replace(':', "-"))
}

/// A container set as the release carries it (the key as PEM).
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerSet {
    pub name: String,
    pub registry: String,
    pub repository: String,
    pub platform: String,
    pub key_pem: String,
    pub index: Option<String>,
}

impl ContainerSet {
    pub fn from_json(v: &Value) -> Result<ContainerSet, ImageError> {
        let s = |k: &str| v[k].as_str().map(str::to_string).ok_or_else(|| ImageError(format!("container set without {k}")));
        Ok(ContainerSet { name: s("name")?, registry: s("registry")?, repository: s("repository")?, platform: s("platform")?,
                          key_pem: s("key")?, index: v["index"].as_str().map(str::to_string) })
    }

    /// Whether a normalized repository (`<registry>/<path>`) lies in this set.
    pub fn covers(&self, repository: &str) -> bool {
        let (reg, path) = repository.split_once('/').unwrap_or((repository, ""));
        reg == self.registry
            && if self.repository.ends_with('/') { path.starts_with(&self.repository) } else { path == self.repository }
    }
}

/// The DER (SPKI) of a PEM `PUBLIC KEY`.
pub fn spki_der(pem: &str) -> Result<Vec<u8>, ImageError> {
    let start = "-----BEGIN PUBLIC KEY-----";
    let end = "-----END PUBLIC KEY-----";
    let (Some(a), Some(b)) = (pem.find(start), pem.find(end)) else { return err("the key is not a PEM PUBLIC KEY") };
    if b < a {
        return err("the key is not a PEM PUBLIC KEY");
    }
    let body: String = pem[a + start.len()..b].chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(body).map_err(|e| ImageError(format!("the key's PEM body is not base64: {e}")))
}

/// The uncompressed point (65 bytes) of an ECDSA P-256 public key in PEM SPKI form, as cosign writes cosign.pub.
pub fn public_key(pem: &str) -> Result<Vec<u8>, ImageError> {
    let der = spki_der(pem)?;
    if der.len() != 91 || der[..26] != SPKI_P256 || der[26] != 4 {
        return err("the key is not an uncompressed ECDSA P-256 public key (cosign.pub)");
    }
    // the point's place on the curve is checked by the install (oarbank_sdk.images.public_key) and by ring at every
    // verification, which fails for a point off the curve
    Ok(der[26..].to_vec())
}

/// The key's fingerprint as approval shows it: SHA-256 of its DER (SPKI), lowercase hex.
pub fn key_sha256(pem: &str) -> Result<String, ImageError> {
    public_key(pem)?;
    Ok(hex::encode(Sha256::digest(spki_der(pem)?)))
}

/// ECDSA P-256 with SHA-256 over `message`, the signature in ASN.1 DER (cosign's encoding).
pub fn verify_ecdsa(point: &[u8], message: &[u8], sig_der: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, point).verify(message, sig_der).is_ok()
}

fn b64(s: Option<&str>, what: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD.decode(s.unwrap_or("")).map_err(|_| format!("{what} is not base64"))
}

/// Why a simple-signing payload and its signature do not approve `digest` (None: they do). `covers` says whether the
/// payload's docker-reference lies in the set.
pub fn check_simple_signing(point: &[u8], payload: &[u8], signature_b64: &str, digest: &str,
                            covers: impl Fn(&str) -> bool) -> Option<String> {
    let sig = match b64(Some(signature_b64), "the signature") {
        Ok(s) => s,
        Err(e) => return Some(e),
    };
    if !verify_ecdsa(point, payload, &sig) {
        return Some("the signature does not verify with the set's key".into());
    }
    let Ok(doc) = serde_json::from_slice::<Value>(payload) else {
        return Some("the signed payload is not a cosign simple-signing document".into());
    };
    let c = &doc["critical"];
    let (Some(got), Some(kind), Some(r)) = (c["image"]["docker-manifest-digest"].as_str(), c["type"].as_str(),
                                            c["identity"]["docker-reference"].as_str()) else {
        return Some("the signed payload is not a cosign simple-signing document".into());
    };
    if kind != SIMPLE_TYPE {
        return Some(format!("the signed payload's type is {kind:?}, not {SIMPLE_TYPE:?}"));
    }
    if got != digest {
        return Some(format!("the signature is for {got}, not {digest}"));
    }
    match normalize(r) {
        Ok(n) if covers(&n.repository) => None,
        Ok(_) => Some(format!("the signed docker-reference {r:?} is outside the set")),
        Err(_) => Some(format!("the signed docker-reference {r:?} is not a reference")),
    }
}

/// DSSE's pre-authentication encoding: what a DSSE signature covers.
pub fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, body.len()).into_bytes();
    out.extend_from_slice(body);
    out
}

/// Why a Sigstore bundle does not approve `digest` (None: it does): a DSSE envelope signed by the key over an in-toto
/// statement whose predicate is cosign's signature predicate and whose subject names the digest.
pub fn check_bundle(point: &[u8], bundle: &[u8], digest: &str) -> Option<String> {
    let Ok(doc) = serde_json::from_slice::<Value>(bundle) else { return Some("the bundle has no DSSE envelope".into()) };
    let env = &doc["dsseEnvelope"];
    let (Some(ptype), Some(sigs)) = (env["payloadType"].as_str(), env["signatures"].as_array()) else {
        return Some("the bundle has no DSSE envelope".into());
    };
    let body = match b64(env["payload"].as_str(), "the DSSE payload") {
        Ok(b) if env["payload"].is_string() => b,
        Ok(_) => return Some("the bundle has no DSSE envelope".into()),
        Err(e) => return Some(e),
    };
    if ptype != INTOTO_PAYLOAD {
        return Some(format!("the DSSE payload type is {ptype:?}, not {INTOTO_PAYLOAD:?}"));
    }
    let msg = pae(ptype, &body);
    if !sigs.iter().any(|s| b64(s["sig"].as_str(), "a DSSE signature").is_ok_and(|sig| verify_ecdsa(point, &msg, &sig))) {
        return Some("no DSSE signature verifies with the set's key".into());
    }
    let Ok(st) = serde_json::from_slice::<Value>(&body) else {
        return Some("the DSSE payload is not an in-toto statement".into());
    };
    let (Some(stype), Some(pred), Some(subjects)) = (st["_type"].as_str(), st["predicateType"].as_str(), st["subject"].as_array())
    else {
        return Some("the DSSE payload is not an in-toto statement".into());
    };
    if stype != INTOTO_STATEMENT || pred != COSIGN_PREDICATE {
        return Some(format!("the statement is {stype} {pred}, not a cosign signature ({COSIGN_PREDICATE})"));
    }
    let hexd = digest.split_once(':').map(|x| x.1).unwrap_or("");
    if !subjects.iter().any(|s| s["digest"]["sha256"].as_str() == Some(hexd)) {
        return Some(format!("the statement's subject is not {digest}"));
    }
    None
}

/// (seq, digests) of an image index document for this set.
pub fn parse_index(doc: &[u8], registry: &str, repository: &str) -> Result<(u64, Vec<String>), ImageError> {
    let d: Value = serde_json::from_slice(doc).map_err(|_| ImageError("the index is not an oarbank image-set document".into()))?;
    let (Some(kind), Some(reg), Some(repo), Some(imgs)) = (d["type"].as_str(), d["registry"].as_str(), d["repository"].as_str(),
                                                           d["images"].as_array()) else {
        return err("the index is not an oarbank image-set document");
    };
    if kind != INDEX_DOC_TYPE {
        return err(format!("the index type is {kind:?}, not {INDEX_DOC_TYPE:?}"));
    }
    if (reg, repo) != (registry, repository) {
        return err(format!("the index is for {reg}/{repo}, not this set ({registry}/{repository})"));
    }
    let Some(seq) = d["seq"].as_u64() else { return err("the index seq is not a non-negative integer") };
    let mut out = Vec::with_capacity(imgs.len());
    for i in imgs {
        match i.as_str() {
            Some(s) if is_digest(s) => out.push(s.to_string()),
            _ => return err("the index images are not sha256 digests"),
        }
    }
    Ok((seq, out))
}

/// `sha256:<hex>` of bytes.
pub fn digest_of(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}
