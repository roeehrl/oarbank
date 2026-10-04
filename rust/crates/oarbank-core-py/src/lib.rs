//! Python bindings for oarbank-core (module `oarbank_core`), so the SDK's own tests can check the Rust rules against
//! the Python reference. Every refusal raises ValueError.

use std::collections::BTreeSet;

use ::oarbank_core::{bundle, canonical, deps, egress, images, portable, sandbox};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn value_error(e: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// RFC 8785 canonical JSON of a JSON document.
#[pyfunction]
fn canonical_json(json_text: &str) -> PyResult<String> {
    canonical::canonical_json_str(json_text).map_err(value_error)
}

/// `sha256(canonical {"module", "compat", "inputs"})`, with `:<stage>` for a non-empty stage.
#[pyfunction]
#[pyo3(signature = (module_id, compat, key_inputs_json, stage=None))]
fn job_key(module_id: &str, compat: &str, key_inputs_json: &str, stage: Option<&str>) -> PyResult<String> {
    let inputs = canonical::parse_json(key_inputs_json).map_err(value_error)?;
    canonical::job_key(module_id, compat, &inputs, stage).map_err(value_error)
}

/// The path itself if it is a PortablePath.
#[pyfunction]
#[pyo3(signature = (path, allow_dotfiles=false))]
fn check_portable_path(path: &str, allow_dotfiles: bool) -> PyResult<String> {
    portable::check_portable_path(path, allow_dotfiles).map(str::to_string).map_err(value_error)
}

/// Pairs of paths that collide on a case-insensitive filesystem.
#[pyfunction]
fn casefold_collisions(paths: Vec<String>) -> Vec<(String, String)> {
    portable::casefold_collisions(&paths)
}

#[pyfunction]
fn is_platform_token(s: &str) -> bool {
    portable::is_platform_token(s)
}

/// The h2 content digest of a JSON list of `{path, sha256, mode}`.
#[pyfunction]
fn content_digest(files_json: &str) -> PyResult<String> {
    let v: serde_json::Value = serde_json::from_str(files_json).map_err(value_error)?;
    bundle::content_digest_value(&v).map_err(value_error)
}

/// The Seatbelt profile text for a policy shape.
#[pyfunction]
#[pyo3(signature = (kind, n_ro, n_rw, n_links, net, broker, gpu, proxy_port=None, exec_rw=false, n_rd=0, n_wo=0))]
#[allow(clippy::too_many_arguments)]
fn render_sandbox_text(
    kind: &str,
    n_ro: usize,
    n_rw: usize,
    n_links: usize,
    net: &str,
    broker: bool,
    gpu: bool,
    proxy_port: Option<i64>,
    exec_rw: bool,
    n_rd: usize,
    n_wo: usize,
) -> PyResult<String> {
    let port = match proxy_port {
        None => None,
        Some(p) => Some(u16::try_from(p).map_err(|_| value_error(format!("proxy port {p} is not a TCP port")))?),
    };
    sandbox::render_text(kind, n_ro, n_rw, n_links, net, broker, gpu, port, exec_rw, n_rd, n_wo).map_err(value_error)
}

/// Whether the allow list lets `host:port` through (a malformed entry raises, as in the SDK).
#[pyfunction]
fn egress_allowed(allow: Vec<String>, host: &str, port: i64) -> PyResult<bool> {
    let Ok(port) = u16::try_from(port) else { return Ok(false) };
    egress::allowed_checked(&allow, host, port).map_err(value_error)
}

/// `ipaddress.ip_address(s).is_global`; ValueError if `s` is not an address.
#[pyfunction]
fn ip_is_global(s: &str) -> PyResult<bool> {
    egress::parse_ip(s).map(egress::is_global).ok_or_else(|| value_error(format!("{s:?} does not appear to be an IPv4 or IPv6 address")))
}

#[pyfunction]
fn wheel_fits(filename: &str, platform: &str) -> bool {
    deps::wheel_fits(filename, platform)
}

/// `[(name, version, sorted hashes)]` of a hash-pinned requirements file; `host_provided` as the SDK's
/// `deps.host_provided()`.
#[pyfunction]
fn parse_requirements(text: &str, host_provided: BTreeSet<String>) -> PyResult<Vec<(String, String, Vec<String>)>> {
    let reqs = deps::parse_requirements(text, &host_provided).map_err(value_error)?;
    Ok(reqs.into_iter().map(|r| (r.name, r.version, r.hashes.into_iter().collect())).collect())
}

/// (repository, tag, digest) of an image reference, normalized as Docker resolves it.
#[pyfunction]
fn image_normalize(reference: &str) -> PyResult<(String, Option<String>, Option<String>)> {
    images::normalize(reference).map(|r| (r.repository, r.tag, r.digest)).map_err(value_error)
}

/// The SHA-256 (hex) of an ECDSA P-256 public key's DER, as approval shows it.
#[pyfunction]
fn image_key_sha256(pem: &str) -> PyResult<String> {
    images::key_sha256(pem).map_err(value_error)
}

/// Why a cosign simple-signing payload and signature do not approve `digest` (None: they do); `prefix` is the set's
/// `<registry>/<repository>` the docker-reference must lie in.
#[pyfunction]
fn image_check_simple(pem: &str, payload: &[u8], signature_b64: &str, digest: &str, registry: &str, repository: &str)
                      -> PyResult<Option<String>> {
    let point = images::public_key(pem).map_err(value_error)?;
    let set = images::ContainerSet { name: "s".into(), registry: registry.into(), repository: repository.into(),
                                     platform: String::new(), key_pem: pem.into(), index: None };
    Ok(images::check_simple_signing(&point, payload, signature_b64, digest, |r| set.covers(r)))
}

/// Why a Sigstore bundle does not approve `digest` (None: it does).
#[pyfunction]
fn image_check_bundle(pem: &str, bundle: &[u8], digest: &str) -> PyResult<Option<String>> {
    let point = images::public_key(pem).map_err(value_error)?;
    Ok(images::check_bundle(&point, bundle, digest))
}

/// (seq, digests) of an image index document for the set `<registry>/<repository>`.
#[pyfunction]
fn image_parse_index(doc: &[u8], registry: &str, repository: &str) -> PyResult<(u64, Vec<String>)> {
    images::parse_index(doc, registry, repository).map_err(value_error)
}

#[pyfunction]
fn version() -> &'static str {
    ::oarbank_core::version()
}

#[pymodule]
#[pyo3(name = "oarbank_core")]
fn oarbank_core_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(canonical_json, m)?)?;
    m.add_function(wrap_pyfunction!(job_key, m)?)?;
    m.add_function(wrap_pyfunction!(check_portable_path, m)?)?;
    m.add_function(wrap_pyfunction!(casefold_collisions, m)?)?;
    m.add_function(wrap_pyfunction!(is_platform_token, m)?)?;
    m.add_function(wrap_pyfunction!(content_digest, m)?)?;
    m.add_function(wrap_pyfunction!(render_sandbox_text, m)?)?;
    m.add_function(wrap_pyfunction!(egress_allowed, m)?)?;
    m.add_function(wrap_pyfunction!(ip_is_global, m)?)?;
    m.add_function(wrap_pyfunction!(wheel_fits, m)?)?;
    m.add_function(wrap_pyfunction!(parse_requirements, m)?)?;
    m.add_function(wrap_pyfunction!(image_normalize, m)?)?;
    m.add_function(wrap_pyfunction!(image_key_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(image_check_simple, m)?)?;
    m.add_function(wrap_pyfunction!(image_check_bundle, m)?)?;
    m.add_function(wrap_pyfunction!(image_parse_index, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}
