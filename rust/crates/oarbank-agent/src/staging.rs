//! Datasets and staging (docs/protocol.md, "Datasets and staging").
//!
//! Blobs are content-addressed in `cache/blobs/<d[0:2]>/<d>`. A download tries the dataset's origins first, then the
//! coordinator, resuming partials and hashing while streaming; the final SHA-256 guards every blob. Origins are
//! fetched outside any module's sandbox, so they are held to a strict rule: `https` only, to names that resolve to
//! public addresses only, and a redirect only to a URL under the same rule, at most five (a dataset manifest cannot
//! point the agent at the LAN or loopback; the public places models live answer with a redirect to their CDN).
//! Workspaces get read-only regular files (a clone or hardlink where possible, else a copy), never symlinks.

use crate::api::Api;
use crate::paths::Layout;
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A partial download untouched this long is abandoned (its dataset is gone or its origin dead).
const PARTIAL_MAX_AGE_S: u64 = 7 * 86400;

pub fn blob_path(l: &Layout, digest: &str) -> PathBuf {
    l.cache_blobs().join(&digest[..2]).join(digest)
}

fn valid_digest(d: &str) -> bool {
    d.len() == 64 && d.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// How many redirects an origin download follows, each checked like the origin itself.
const MAX_REDIRECTS: usize = 5;

fn origin_client_builder() -> Result<reqwest::ClientBuilder> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    #[cfg(debug_assertions)]
    if let Ok(pem) = std::env::var("OARBANK_TEST_ORIGIN_CA") {
        // test builds only: the end-to-end suite serves origins from a local https server with its own CA
        for c in rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(pem)?)) {
            roots.add(c?)?;
        }
    }
    let cfg = rustls::ClientConfig::builder_with_provider(crate::tls::provider()).with_safe_default_protocol_versions()?
        .with_root_certificates(roots).with_no_client_auth();
    Ok(reqwest::Client::builder().use_preconfigured_tls(cfg).redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(15)))
}

/// A client with public CA roots and no redirects (rescue locations answer themselves or not at all).
pub fn origin_client() -> Result<reqwest::Client> {
    Ok(origin_client_builder()?.build()?)
}

/// The addresses an origin URL may be fetched from: https, a host name (never an IP literal) resolving only to public
/// addresses. The fetch connects to exactly these, so a name cannot resolve to a public address for the check and to
/// the LAN for the connection.
async fn origin_addrs(u: &reqwest::Url) -> Result<(String, Vec<std::net::SocketAddr>)> {
    if u.scheme() != "https" {
        bail!("origin {u}: only https");
    }
    let host = u.host_str().context("origin without a host")?.to_string();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        bail!("origin {u}: an IP address");
    }
    let port = u.port_or_known_default().unwrap_or(443);
    #[cfg(debug_assertions)]
    if test_origin_host(&host) {
        return Ok((host, vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))]));
    }
    let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), port)).await?.collect();
    if addrs.is_empty() {
        bail!("origin {host}: no address");
    }
    for a in &addrs {
        let ip = a.ip();
        if !oarbank_core::egress::is_global(ip) || ip.is_multicast() {
            bail!("origin {host} resolves to {ip}, which is not a public address");
        }
    }
    Ok((host, addrs))
}

/// Test builds only: the end-to-end suite serves origins from a local https server under public-looking names
/// (OARBANK_TEST_ORIGIN_HOSTS, comma-separated), which then resolve to loopback.
#[cfg(debug_assertions)]
fn test_origin_host(host: &str) -> bool {
    std::env::var("OARBANK_TEST_ORIGIN_HOSTS").is_ok_and(|v| v.split(',').any(|h| h.trim() == host))
}

/// GET an origin from byte `have`: every URL on the way (redirects included) is held to `origin_addrs`.
async fn origin_get(url: &str, have: u64) -> Result<reqwest::Response> {
    let mut u = reqwest::Url::parse(url).context("origin is not a URL")?;
    for _ in 0..=MAX_REDIRECTS {
        let (host, addrs) = origin_addrs(&u).await?;
        let mut req = origin_client_builder()?.resolve_to_addrs(&host, &addrs).build()?.get(u.clone());
        if have > 0 {
            req = req.header("range", format!("bytes={have}-"));
        }
        let r = req.send().await?;
        if r.status().is_redirection() {
            let loc = r.headers().get("location").and_then(|v| v.to_str().ok()).context("a redirect without a location")?;
            u = u.join(loc)?;
            continue;
        }
        return Ok(r);
    }
    bail!("origin {url}: more than {MAX_REDIRECTS} redirects")
}

async fn prehash(path: &Path) -> Result<(Sha256, u64)> {
    let mut h = Sha256::new();
    let mut n = 0u64;
    if let Ok(mut f) = tokio::fs::File::open(path).await {
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let k = f.read(&mut buf).await?;
            if k == 0 {
                break;
            }
            h.update(&buf[..k]);
            n += k as u64;
        }
    }
    Ok((h, n))
}

/// Stream `resp` onto the partial, hashing; true when the digest matches.
async fn stream_into(resp: reqwest::Response, partial: &Path, mut h: Sha256, append: bool, digest: &str) -> Result<bool> {
    let mut f = tokio::fs::OpenOptions::new().create(true).append(append).write(true).truncate(!append).open(partial).await?;
    let mut s = resp.bytes_stream();
    while let Some(c) = s.next().await {
        let c = c?;
        h.update(&c);
        f.write_all(&c).await?;
    }
    f.sync_all().await?;
    Ok(hex::encode(h.finalize()) == digest)
}

/// Fetch one blob into the cache (no-op when present). Origin first, then the coordinator; resumable.
pub async fn fetch_blob(api: &Api, l: &Layout, file: &Value) -> Result<PathBuf> {
    let digest = file["digest"].as_str().context("file without a digest")?;
    if !valid_digest(digest) {
        bail!("bad digest {digest:?}");
    }
    let dst = blob_path(l, digest);
    if dst.exists() {
        return Ok(dst);
    }
    crate::fsutil::private_dir(dst.parent().unwrap())?;
    let partial = l.cache_tmp().join(format!("{digest}.partial"));
    let origins: Vec<String> = file["origins"].as_array().cloned().unwrap_or_default().iter()
        .filter_map(|o| o.as_str().map(str::to_string)).collect();
    let mut last_err = None;
    if !origins.is_empty() {
        for o in &origins {
            match async {
                let (h, have) = prehash(&partial).await?;
                let r = origin_get(o, have).await?;
                let ok = match r.status().as_u16() {
                    206 => stream_into(r, &partial, h, true, digest).await?,
                    200 => stream_into(r, &partial, Sha256::new(), false, digest).await?,
                    416 => {
                        let _ = tokio::fs::remove_file(&partial).await;
                        false
                    }
                    s => bail!("origin answered {s}"),
                };
                Ok::<bool, anyhow::Error>(ok)
            }.await {
                Ok(true) => {
                    std::fs::rename(&partial, &dst)?;
                    readonly(&dst)?;
                    return Ok(dst);
                }
                Ok(false) => {
                    let _ = tokio::fs::remove_file(&partial).await;
                    last_err = Some(anyhow::anyhow!("origin {o}: digest mismatch"));
                }
                Err(e) => last_err = Some(e),
            }
        }
    }
    let (h, have) = prehash(&partial).await?;
    let r = api.download(&format!("/v1/blobs/{digest}"), have).await
        .map_err(|e| anyhow::anyhow!("coordinator blob {}: {e}{}", &digest[..12],
                                     last_err.map(|x| format!(" (origins: {x})")).unwrap_or_default()))?;
    let ok = if r.status().as_u16() == 206 { stream_into(r, &partial, h, true, digest).await? }
             else { stream_into(r, &partial, Sha256::new(), false, digest).await? };
    if !ok {
        let _ = tokio::fs::remove_file(&partial).await;
        bail!("blob {} failed its digest check", &digest[..12]);
    }
    std::fs::rename(&partial, &dst)?;
    readonly(&dst)?;
    Ok(dst)
}

/// A dataset's manifest, cached under state/datasets/.
pub async fn manifest(api: &Api, l: &Layout, id: &str) -> Result<Value> {
    let safe = id.replace(['/', ':'], "_");
    let p = l.state().join("datasets").join(format!("{safe}.json"));
    if let Ok(b) = std::fs::read(&p) {
        if let Ok(v) = serde_json::from_slice::<Value>(&b) {
            return Ok(v);
        }
    }
    let v = api.get(&format!("/v1/datasets/{id}")).await?;
    crate::fsutil::write_private(&p, &serde_json::to_vec(&v)?)?;
    Ok(v)
}

/// Stage every file of a dataset; true when it is ready.
pub async fn stage(api: &Api, l: &Layout, id: &str) -> Result<()> {
    let m = manifest(api, l, id).await?;
    for f in m["files"].as_array().cloned().unwrap_or_default() {
        fetch_blob(api, l, &f).await?;
    }
    Ok(())
}

/// Datasets whose every blob is cached.
pub fn ready(l: &Layout) -> Vec<String> {
    let dir = l.state().join("datasets");
    let Ok(rd) = std::fs::read_dir(&dir) else { return vec![] };
    rd.filter_map(|e| e.ok()).filter_map(|e| {
        let v: Value = serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok()?;
        let files = v["files"].as_array()?;
        files.iter().all(|f| f["digest"].as_str().is_some_and(|d| valid_digest(d) && blob_path(l, d).exists()))
            .then(|| v["dataset_id"].as_str().map(str::to_string)).flatten()
    }).collect()
}

/// Place a cached blob at `dst` as a read-only regular file: an APFS clone, else a hardlink, else a copy.
pub fn place(blob: &Path, dst: &Path) -> Result<()> {
    if let Some(p) = dst.parent() {
        std::fs::create_dir_all(p)?;
    }
    let _ = std::fs::remove_file(dst);
    #[cfg(target_os = "macos")]
    {
        let (s, d) = (std::ffi::CString::new(blob.as_os_str().as_encoded_bytes())?, std::ffi::CString::new(dst.as_os_str().as_encoded_bytes())?);
        if unsafe { libc::clonefile(s.as_ptr(), d.as_ptr(), 0) } == 0 {
            return readonly(dst);
        }
    }
    if std::fs::hard_link(blob, dst).is_ok() {
        return Ok(());                    // the cache copy is already read-only
    }
    std::fs::copy(blob, dst)?;
    readonly(dst)
}

fn readonly(p: &Path) -> Result<()> {
    let mut perm = std::fs::metadata(p)?.permissions();
    perm.set_readonly(true);
    std::fs::set_permissions(p, perm)?;
    Ok(())
}

/// Drop partials older than a week (at agent start: a younger one is resumed by the next fetch of its blob).
pub fn sweep_partials(l: &Layout) {
    let Ok(rd) = std::fs::read_dir(l.cache_tmp()) else { return };
    for e in rd.filter_map(|e| e.ok()) {
        let old = e.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age.as_secs() > PARTIAL_MAX_AGE_S);
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_partials_older_than_a_week_are_swept() {
        let home = std::env::temp_dir().join(format!("oarbank-staging-{}", std::process::id()));
        let l = Layout::new(home.clone());
        std::fs::create_dir_all(l.cache_tmp()).unwrap();
        let (old, young) = (l.cache_tmp().join("a.partial"), l.cache_tmp().join("b.partial"));
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&young, b"y").unwrap();
        let week_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(PARTIAL_MAX_AGE_S + 60);
        std::fs::File::options().write(true).open(&old).unwrap().set_modified(week_ago).unwrap();
        sweep_partials(&l);
        assert!(!old.exists() && young.exists());
        let _ = std::fs::remove_dir_all(home);
    }

    #[tokio::test]
    async fn origins_are_https_names_resolving_only_to_public_addresses() {
        for (url, why) in [("http://example.org/m.bin", "only https"), ("https://93.184.216.34/m.bin", "an IP address"),
                           ("https://[::1]/m.bin", "an IP address"), ("https://localhost/m.bin", "not a public address")] {
            let e = origin_addrs(&reqwest::Url::parse(url).unwrap()).await.unwrap_err().to_string();
            assert!(e.contains(why), "{url}: {e}");
        }
    }
}
