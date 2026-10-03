//! TLS to the coordinator (D29; docs/design/architecture.md, "Network and access").
//!
//! The trust anchor is the coordinator's own CA, whose SPKI hash the agent learned from the CIK-signed identity
//! payload. The server certificate must chain to exactly that CA (pinned by SPKI, current or next); host names are
//! not checked, because the private CA is the authentication and agents reach the coordinator by addresses that
//! change (tailnet IPs, LAN names, a move). The agent's client certificate is its identity.
//!
//! The only unverified connection is the bootstrap that fetches the identity proof itself; nothing is sent over it but
//! a nonce, and its answer is checked against the pinned CIK.

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// SHA-256 of a certificate's SubjectPublicKeyInfo (what the identity payload pins).
pub fn spki_sha256(der: &[u8]) -> Result<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).context("not an X.509 certificate")?;
    Ok(hex::encode(Sha256::digest(cert.tbs_certificate.subject_pki.raw)))
}

pub fn certs_from_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        bail!("no certificate in PEM");
    }
    Ok(certs)
}

pub fn key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut rd)?.context("no private key in PEM")
}

#[derive(Debug)]
struct PinnedCa {
    roots: RootCertStore,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCa {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>],
                          _name: &ServerName<'_>, _ocsp: &[u8], now: UnixTime) -> Result<ServerCertVerified, TlsError> {
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert, &self.roots, intermediates, now, self.provider.signature_verification_algorithms.all).map_err(clock_skew)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct)
                              -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct)
                              -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A certificate outside its validity at this node's clock: say that the clock may be the cause.
fn clock_skew(e: TlsError) -> TlsError {
    use rustls::CertificateError as E;
    match e {
        TlsError::InvalidCertificate(E::Expired | E::NotValidYet | E::ExpiredContext { .. } | E::NotValidYetContext { .. }) =>
            TlsError::General(format!("the coordinator's certificate is not valid now ({e}); {}",
                                      crate::clock::skew_hint(crate::doctor::now()))),
        e => e,
    }
}

#[derive(Debug)]
struct Unverified(Arc<CryptoProvider>);

impl ServerCertVerifier for Unverified {
    fn verify_server_cert(&self, _e: &CertificateDer<'_>, _i: &[CertificateDer<'_>], _n: &ServerName<'_>, _o: &[u8],
                          _now: UnixTime) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct)
                              -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct)
                              -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn http(cfg: rustls::ClientConfig) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(cfg)
        .redirect(reqwest::redirect::Policy::none())          // an agent never follows a redirect
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(120))
        .build()?)
}

/// The bootstrap client: TLS without verification, for `GET /v1/identity` only.
pub fn bootstrap_client() -> Result<reqwest::Client> {
    let p = provider();
    let cfg = rustls::ClientConfig::builder_with_provider(p.clone()).with_safe_default_protocol_versions()?
        .dangerous().with_custom_certificate_verifier(Arc::new(Unverified(p))).with_no_client_auth();
    http(cfg)
}

/// A client that trusts only the coordinator CA in `ca_pem`, after checking it is the one the identity pinned
/// (`pins`: the current and next SPKI hashes), and presents the node's certificate when given.
pub fn pinned_client(ca_pem: &str, pins: &[String], identity: Option<(&str, &str)>) -> Result<reqwest::Client> {
    let p = provider();
    let mut roots = RootCertStore::empty();
    for c in certs_from_pem(ca_pem)? {
        let spki = spki_sha256(&c)?;
        if !pins.iter().any(|x| x.eq_ignore_ascii_case(&spki)) {
            bail!("the coordinator CA {} is not the one its identity pins", &spki[..16]);
        }
        roots.add(c)?;
    }
    let builder = rustls::ClientConfig::builder_with_provider(p.clone()).with_safe_default_protocol_versions()?
        .dangerous().with_custom_certificate_verifier(Arc::new(PinnedCa { roots, provider: p }));
    let cfg = match identity {
        Some((cert_pem, key_pem)) => builder.with_client_auth_cert(certs_from_pem(cert_pem)?, key_from_pem(key_pem)?)?,
        None => builder.with_no_client_auth(),
    };
    http(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_outside_its_validity_names_the_clock() {
        for e in [rustls::CertificateError::Expired, rustls::CertificateError::NotValidYet] {
            let TlsError::General(msg) = clock_skew(TlsError::InvalidCertificate(e)) else { panic!("not mapped") };
            assert!(msg.contains("clock is skewed"), "{msg}");
        }
        assert!(matches!(clock_skew(TlsError::InvalidCertificate(rustls::CertificateError::BadSignature)),
                         TlsError::InvalidCertificate(rustls::CertificateError::BadSignature)));
    }
}
