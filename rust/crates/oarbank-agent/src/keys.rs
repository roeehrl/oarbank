//! The node's P-256 key (generated here, never sent anywhere), its certificate request, and the certificates the
//! coordinator issued (D29).

use crate::paths::Layout;
use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};

pub fn ensure_key(l: &Layout) -> Result<KeyPair> {
    if let Ok(pem) = std::fs::read_to_string(l.node_key()) {
        return KeyPair::from_pem(&pem).context("node.key is not a PEM private key");
    }
    let k = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    crate::fsutil::write_private(&l.node_key(), k.serialize_pem().as_bytes())?;
    Ok(k)
}

/// A fresh key and its CSR for a renewal (the old key stays until the new certificate arrives).
pub fn new_key() -> Result<KeyPair> {
    Ok(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?)
}

pub fn csr_pem(key: &KeyPair, hostname: &str) -> Result<String> {
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    p.distinguished_name = dn;
    Ok(p.serialize_request(key)?.pem()?)
}

/// `sha256:` and the first 16 hex digits of the SHA-256 of the node's public key: what the join window and the console
/// show for a machine waiting for approval.
pub fn fingerprint(key: &KeyPair) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", &hex::encode(Sha256::digest(rcgen::PublicKeyData::subject_public_key_info(key)))[..16])
}

pub fn have_cert(l: &Layout) -> bool {
    l.node_cert().exists() && l.ca_cert().exists() && l.node_key().exists()
}

pub fn store_cert(l: &Layout, cert_pem: &str, ca_pem: &str, key: Option<&KeyPair>) -> Result<()> {
    if let Some(k) = key {
        crate::fsutil::write_private(&l.node_key(), k.serialize_pem().as_bytes())?;
    }
    crate::fsutil::write_private(&l.node_cert(), cert_pem.as_bytes())?;
    crate::fsutil::write_private(&l.ca_cert(), ca_pem.as_bytes())?;
    Ok(())
}
