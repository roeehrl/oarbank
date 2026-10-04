//! Container image sets approved by signature (the SDK's spec/sandbox.md, "Image sets"): the agent verifies that a set
//! image's digest carries a cosign signature by the set's pinned key (or that the set's signed index lists it) before
//! the broker lets the runtime pull it. The decisions are `oarbank_core::images` (held to the SDK's reference by the
//! shared vectors); this module fetches what they judge, through a small OCI distribution client: anonymous bearer
//! tokens, `https` except for registries on localhost or a loopback address, redirects only to `https` or the same host,
//! and every manifest and blob size-capped and checked against its digest before it is parsed.

use oarbank_core::images::{self as I, ContainerSet};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

const ACCEPT_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json";
const ACCEPT_INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// Why a set image is not run: `image_not_approved` (verification failed) or `registry_unavailable` (could not tell).
#[derive(Debug, Clone, PartialEq)]
pub struct Refused {
    pub code: &'static str,
    pub detail: String,
}

fn not_approved(d: impl Into<String>) -> Refused {
    Refused { code: "image_not_approved", detail: d.into() }
}

fn unavailable(d: impl Into<String>) -> Refused {
    Refused { code: "registry_unavailable", detail: d.into() }
}

/// The OCI distribution API's reads.
pub struct Registry {
    client: reqwest::Client,
    tokens: Mutex<HashMap<String, String>>,
}

fn base(registry: &str) -> String {
    let host = match registry.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => registry,
    };
    let scheme = if matches!(host, "localhost" | "127.0.0.1" | "[::1]") { "http" } else { "https" };
    let reg = if registry == "docker.io" { "registry-1.docker.io" } else { registry };
    format!("{scheme}://{reg}")
}

fn split(repository: &str) -> (&str, &str) {
    repository.split_once('/').unwrap_or((repository, ""))
}

impl Registry {
    pub fn new() -> anyhow::Result<Registry> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder_with_provider(crate::tls::provider()).with_safe_default_protocol_versions()?
            .with_root_certificates(roots).with_no_client_auth();
        // blob downloads redirect to object storage: follow only to https, or within the registry's own host
        let policy = reqwest::redirect::Policy::custom(|a| {
            let same = a.previous().first().and_then(|u| u.host_str()) == a.url().host_str();
            if a.previous().len() > 5 {
                a.error("too many redirects")
            } else if a.url().scheme() == "https" || same {
                a.follow()
            } else {
                a.stop()
            }
        });
        let client = reqwest::Client::builder().use_preconfigured_tls(cfg).redirect(policy)
            .connect_timeout(Duration::from_secs(15)).timeout(Duration::from_secs(120)).build()?;
        Ok(Registry { client, tokens: Mutex::new(HashMap::new()) })
    }

    /// GET with the registry's bearer token, fetching one anonymously on a 401. (status, body) with the body capped.
    async fn get(&self, registry: &str, path: &str, accept: Option<&str>) -> Result<(u16, Vec<u8>), String> {
        for attempt in 0..2 {
            let mut req = self.client.get(format!("{}{path}", base(registry)));
            if let Some(a) = accept {
                req = req.header("Accept", a);
            }
            if let Some(t) = self.tokens.lock().unwrap().get(registry) {
                req = req.bearer_auth(t);
            }
            let mut resp = req.send().await.map_err(|e| format!("{registry}: {e}"))?;
            let status = resp.status().as_u16();
            if status == 401 && attempt == 0 {
                let challenge = resp.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                if self.login(registry, &challenge).await {
                    continue;
                }
            }
            if resp.content_length().is_some_and(|n| n as usize > I::MAX_DOC) {
                return Err(format!("{registry}{path}: larger than {} bytes", I::MAX_DOC));
            }
            let mut body = Vec::new();
            while let Some(chunk) = resp.chunk().await.map_err(|e| format!("{registry}: {e}"))? {
                body.extend_from_slice(&chunk);
                if body.len() > I::MAX_DOC {
                    return Err(format!("{registry}{path}: larger than {} bytes", I::MAX_DOC));
                }
            }
            return Ok((status, body));
        }
        Err(format!("{registry}: authentication failed"))
    }

    async fn login(&self, registry: &str, challenge: &str) -> bool {
        let Some(rest) = challenge.strip_prefix("Bearer ").or_else(|| challenge.strip_prefix("bearer ")) else { return false };
        let mut params: Vec<(String, String)> = Vec::new();
        let mut realm = None;
        for part in rest.split(',') {
            let Some((k, v)) = part.trim().split_once('=') else { continue };
            let v = v.trim_matches('"').to_string();
            if k == "realm" { realm = Some(v) } else { params.push((k.to_string(), v)) }
        }
        let Some(realm) = realm.filter(|r| r.starts_with("https://") || r.starts_with(&base(registry))) else { return false };
        let Ok(mut url) = reqwest::Url::parse(&realm) else { return false };
        url.query_pairs_mut().extend_pairs(params.iter());
        let Ok(resp) = self.client.get(url).send().await else { return false };
        let Ok(doc) = resp.json::<Value>().await else { return false };
        match doc["token"].as_str().or(doc["access_token"].as_str()) {
            Some(t) => {
                self.tokens.lock().unwrap().insert(registry.to_string(), t.to_string());
                true
            }
            None => false,
        }
    }

    /// A manifest by tag or digest: (bytes, digest), None when absent.
    pub async fn manifest(&self, repository: &str, reference: &str) -> Result<Option<(Vec<u8>, String)>, String> {
        let (reg, path) = split(repository);
        let (status, body) = self.get(reg, &format!("/v2/{path}/manifests/{reference}"), Some(ACCEPT_MANIFEST)).await?;
        match status {
            404 => Ok(None),
            200 => {
                let d = I::digest_of(&body);
                if I::is_digest(reference) && d != reference {
                    return Err(format!("{repository}@{reference}: the registry served other content"));
                }
                Ok(Some((body, d)))
            }
            s => Err(format!("{repository}:{reference}: the registry answered {s}")),
        }
    }

    pub async fn blob(&self, repository: &str, digest: &str) -> Result<Vec<u8>, String> {
        let (reg, path) = split(repository);
        let (status, body) = self.get(reg, &format!("/v2/{path}/blobs/{digest}"), None).await?;
        if status != 200 {
            return Err(format!("blob {repository}@{digest}: the registry answered {status}"));
        }
        if I::digest_of(&body) != digest {
            return Err(format!("blob {repository}@{digest} does not match its digest"));
        }
        Ok(body)
    }

    /// The descriptors of manifests whose subject is `digest`; None when the registry has no referrers API.
    pub async fn referrers(&self, repository: &str, digest: &str) -> Result<Option<Vec<Value>>, String> {
        let (reg, path) = split(repository);
        let (status, body) = self.get(reg, &format!("/v2/{path}/referrers/{digest}"), Some(ACCEPT_INDEX)).await?;
        if status != 200 {
            return Ok(None);
        }
        Ok(serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["manifests"].as_array().cloned()))
    }
}

/// A set's index as last verified: its manifest digest, its seq and its members.
type VerifiedIndex = (String, u64, HashSet<String>);

/// Verifies set images for every attempt of this agent: verified `(set, digest)` pairs are remembered for the agent's
/// lifetime (a signature cannot be withdrawn; a new key is a new module version), an index is fetched again for each
/// image not yet verified (cheap when its digest is the one already verified), and the highest index `seq` accepted per
/// set is kept in the agent's home so an older signed index is never accepted again.
pub struct Verifier {
    registry: Registry,
    verified: Mutex<HashSet<(String, String)>>,
    indexes: Mutex<HashMap<String, VerifiedIndex>>,
    seq_file: PathBuf,
}

/// The identity of a set's trust: its prefix, platform, key and index.
fn set_id(s: &ContainerSet) -> String {
    let key = I::key_sha256(&s.key_pem).unwrap_or_default();
    format!("{}|{}/{}|{}|{}|{}", s.name, s.registry, s.repository, s.platform, key, s.index.as_deref().unwrap_or(""))
}

impl Verifier {
    pub fn new(seq_file: PathBuf) -> anyhow::Result<Verifier> {
        Ok(Verifier { registry: Registry::new()?, verified: Mutex::new(HashSet::new()), indexes: Mutex::new(HashMap::new()),
                      seq_file })
    }

    fn highest_seq(&self, id: &str) -> Option<u64> {
        let doc: Value = std::fs::read(&self.seq_file).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!({}));
        doc[id].as_u64()
    }

    fn keep_seq(&self, id: &str, seq: u64) {
        let mut doc: Value = std::fs::read(&self.seq_file).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!({}));
        if doc[id].as_u64().is_some_and(|s| s >= seq) {
            return;
        }
        doc[id] = json!(seq);
        let _ = crate::fsutil::write_private(&self.seq_file, &serde_json::to_vec(&doc).unwrap_or_default());
    }

    /// Why `digest` in `repository` carries no signature by the key (Ok(None): it does).
    async fn unsigned(&self, point: &[u8], set: &ContainerSet, repository: &str, digest: &str) -> Result<Option<String>, Refused> {
        let reg = &self.registry;
        let mut why: Vec<String> = Vec::new();
        let refs = match reg.referrers(repository, digest).await.map_err(unavailable)? {
            Some(r) => r,
            None => match reg.manifest(repository, &digest.replace(':', "-")).await.map_err(unavailable)? {
                Some((b, _)) => serde_json::from_slice::<Value>(&b).ok().and_then(|v| v["manifests"].as_array().cloned()).unwrap_or_default(),
                None => vec![],
            },
        };
        for d in refs.iter().filter(|d| d["artifactType"].as_str().is_some_and(|t| I::BUNDLE_TYPES.contains(&t))) {
            let Some(md) = d["digest"].as_str().filter(|x| I::is_digest(x)) else { continue };
            let Some((body, _)) = reg.manifest(repository, md).await.map_err(unavailable)? else { continue };
            let m: Value = serde_json::from_slice(&body).unwrap_or_default();
            for layer in m["layers"].as_array().cloned().unwrap_or_default() {
                if layer["mediaType"].as_str().is_some_and(|t| I::BUNDLE_TYPES.contains(&t)) {
                    let Some(ld) = layer["digest"].as_str() else { continue };
                    let b = reg.blob(repository, ld).await.map_err(unavailable)?;
                    match I::check_bundle(point, &b, digest) {
                        None => return Ok(None),
                        Some(r) => why.push(r),
                    }
                }
            }
        }
        if let Some((body, _)) = reg.manifest(repository, &I::signature_tag(digest)).await.map_err(unavailable)? {
            let m: Value = serde_json::from_slice(&body).unwrap_or_default();
            for layer in m["layers"].as_array().cloned().unwrap_or_default() {
                let (Some(t), Some(sig), Some(ld)) = (layer["mediaType"].as_str(), layer["annotations"][I::SIG_ANNOTATION].as_str(),
                                                      layer["digest"].as_str()) else { continue };
                if t != I::SIMPLE_SIGNING {
                    continue;
                }
                let payload = reg.blob(repository, ld).await.map_err(unavailable)?;
                match I::check_simple_signing(point, &payload, sig, digest, |r| set.covers(r)) {
                    None => return Ok(None),
                    Some(r) => why.push(r),
                }
            }
        }
        Ok(Some(why.into_iter().next().unwrap_or_else(|| format!("{repository}@{digest} has no cosign signature"))))
    }

    /// Whether `reference` (`platform`) is a member of `set`.
    pub async fn verify(&self, set: &ContainerSet, reference: &str, platform: &str) -> Result<(), Refused> {
        let r = I::normalize(reference).map_err(|e| not_approved(e.0))?;
        let digest = r.digest.clone().ok_or_else(|| not_approved(format!("{reference} is not pinned by digest")))?;
        if platform != set.platform || !set.covers(&r.repository) {
            return Err(not_approved(format!("{reference} ({platform}) is outside set {}", set.name)));
        }
        let id = set_id(set);
        if self.verified.lock().unwrap().contains(&(id.clone(), digest.clone())) {
            return Ok(());
        }
        let point = I::public_key(&set.key_pem).map_err(|e| not_approved(format!("set {}: {}", set.name, e.0)))?;
        let Some(index) = &set.index else {
            if let Some(why) = self.unsigned(&point, set, &r.repository, &digest).await? {
                return Err(not_approved(why));
            }
            self.verified.lock().unwrap().insert((id, digest));
            return Ok(());
        };
        let ir = I::normalize(index).map_err(|e| not_approved(e.0))?;
        let tag = ir.tag.clone().unwrap_or_else(|| "latest".into());
        let (body, idigest) = self.registry.manifest(&ir.repository, &tag).await.map_err(unavailable)?
            .ok_or_else(|| not_approved(format!("the set's index {index} is not in the registry")))?;
        let cached = self.indexes.lock().unwrap().get(&id).filter(|(d, _, _)| *d == idigest).cloned();
        let (seq, members) = match cached {
            Some((_, seq, members)) => (seq, members),
            None => {
                if let Some(why) = self.unsigned(&point, set, &ir.repository, &idigest).await? {
                    return Err(not_approved(format!("the set's index: {why}")));
                }
                let m: Value = serde_json::from_slice(&body).unwrap_or_default();
                let layers: Vec<Value> = m["layers"].as_array().cloned().unwrap_or_default().into_iter()
                    .filter(|l| l["mediaType"].as_str() == Some(I::INDEX_TYPE)).collect();
                let [layer] = layers.as_slice() else { return Err(not_approved("the set's index has no image-set layer")) };
                let doc = self.registry.blob(&ir.repository, layer["digest"].as_str().unwrap_or("")).await.map_err(unavailable)?;
                let (seq, imgs) = I::parse_index(&doc, &set.registry, &set.repository).map_err(|e| not_approved(e.0))?;
                (seq, imgs.into_iter().collect::<HashSet<_>>())
            }
        };
        if let Some(h) = self.highest_seq(&id).filter(|h| seq < *h) {
            return Err(not_approved(format!("the set's index is seq {seq}, older than seq {h} already accepted")));
        }
        self.keep_seq(&id, seq);
        self.indexes.lock().unwrap().insert(id, (idigest, seq, members.clone()));
        if !members.contains(&digest) {
            return Err(not_approved(format!("{digest} is not in the set's index (seq {seq})")));
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    //! A local registry serving an OCI layout from memory, and cosign-format signatures made with ring: the same shapes
    //! the SDK's `imagetest` writes.
    use super::*;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub struct Key(EcdsaKeyPair);

    impl Key {
        pub fn new() -> Key {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            Key(EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap())
        }

        pub fn pem(&self) -> String {
            let mut der = vec![0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
                               0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];
            der.extend_from_slice(self.0.public_key().as_ref());
            format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", base64::engine::general_purpose::STANDARD.encode(der))
        }

        pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
            self.0.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec()
        }
    }

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    /// Repositories' manifests (by tag and digest), blobs and referrers, all in memory.
    #[derive(Default)]
    pub struct Store {
        pub manifests: HashMap<(String, String), Vec<u8>>,
        pub blobs: HashMap<String, Vec<u8>>,
        pub referrers: HashMap<String, Vec<Value>>,
        pub referrers_api: bool,
        pub hits: u64,
    }

    impl Store {
        fn put(&mut self, data: &[u8]) -> Value {
            let d = I::digest_of(data);
            self.blobs.insert(d.clone(), data.to_vec());
            json!({"digest": d, "size": data.len()})
        }

        fn manifest(&mut self, path: &str, doc: Value, tag: Option<&str>) -> String {
            let b = serde_json::to_vec(&doc).unwrap();
            let d = I::digest_of(&b);
            self.manifests.insert((path.into(), d.clone()), b.clone());
            if let Some(t) = tag {
                self.manifests.insert((path.into(), t.into()), b);
            }
            d
        }

        /// A one-layer image; its manifest digest.
        pub fn image(&mut self, path: &str, content: &[u8]) -> String {
            let cfg = self.put(br#"{"architecture":"amd64","os":"linux"}"#);
            let layer = self.put(content);
            self.manifest(path, json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg["digest"], "size": cfg["size"]},
                "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer["digest"], "size": layer["size"]}]}),
                Some("latest"))
        }

        /// A cosign signature of `digest` in `path`: a Sigstore bundle referrer, or the simple-signing .sig manifest.
        pub fn sign(&mut self, key: &Key, registry: &str, path: &str, digest: &str, simple: bool) {
            let reference = format!("{registry}/{path}@{digest}");
            if simple {
                let payload = serde_json::to_vec(&json!({"critical": {"identity": {"docker-reference": reference},
                    "image": {"docker-manifest-digest": digest}, "type": I::SIMPLE_TYPE}, "optional": null})).unwrap();
                let sig = b64(&key.sign(&payload));
                let p = self.put(&payload);
                let cfg = self.put(b"{}");
                self.manifest(path, json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg["digest"], "size": 2},
                    "layers": [{"mediaType": I::SIMPLE_SIGNING, "digest": p["digest"], "size": p["size"],
                                "annotations": {I::SIG_ANNOTATION: sig}}]}), Some(&I::signature_tag(digest)));
                return;
            }
            let st = serde_json::to_vec(&json!({"_type": I::INTOTO_STATEMENT, "predicateType": I::COSIGN_PREDICATE, "predicate": {},
                "subject": [{"name": reference, "digest": {"sha256": &digest[7..]}}]})).unwrap();
            let sig = key.sign(&I::pae(I::INTOTO_PAYLOAD, &st));
            let bundle = serde_json::to_vec(&json!({"mediaType": I::BUNDLE_TYPES[0], "dsseEnvelope": {"payload": b64(&st),
                "payloadType": I::INTOTO_PAYLOAD, "signatures": [{"sig": b64(&sig), "keyid": ""}]}})).unwrap();
            let b = self.put(&bundle);
            let empty = self.put(b"{}");
            let md = self.manifest(path, json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": I::BUNDLE_TYPES[0], "config": {"mediaType": "application/vnd.oci.empty.v1+json",
                "digest": empty["digest"], "size": 2}, "layers": [{"mediaType": I::BUNDLE_TYPES[0], "digest": b["digest"],
                "size": b["size"]}], "subject": {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest}}), None);
            self.referrers.entry(digest.into()).or_default().push(json!({"mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": md, "artifactType": I::BUNDLE_TYPES[0]}));
        }

        /// A signed image index at `path:tag` listing `digests`, for the set `org/tasks/`.
        pub fn index(&mut self, key: &Key, registry: &str, path: &str, tag: &str, seq: u64, digests: &[String]) {
            let mut ds = digests.to_vec();
            ds.sort();
            let doc = serde_json::to_vec(&json!({"images": ds, "registry": registry, "repository": "org/tasks/", "seq": seq,
                                                 "type": I::INDEX_DOC_TYPE})).unwrap();
            let l = self.put(&doc);
            let empty = self.put(b"{}");
            let d = self.manifest(path, json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "artifactType": I::INDEX_TYPE, "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": empty["digest"],
                "size": 2}, "layers": [{"mediaType": I::INDEX_TYPE, "digest": l["digest"], "size": l["size"]}]}), Some(tag));
            self.sign(key, registry, path, &d, false);
        }
    }

    /// Serve `store` on 127.0.0.1 (HTTP/1.1, one request per connection); the registry name `127.0.0.1:<port>`.
    pub async fn serve(store: Arc<Mutex<Store>>) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = l.accept().await else { return };
                let store = store.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = c.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (status, body) = answer(&store, &path);
                    let head = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    let _ = c.write_all(head.as_bytes()).await;
                    let _ = c.write_all(&body).await;
                });
            }
        });
        format!("127.0.0.1:{}", addr.port())
    }

    fn answer(store: &Arc<Mutex<Store>>, path: &str) -> (u16, Vec<u8>) {
        let mut s = store.lock().unwrap();
        s.hits += 1;
        let Some(rest) = path.strip_prefix("/v2/") else { return (404, vec![]) };
        for (kind, sep) in [("manifests", "/manifests/"), ("blobs", "/blobs/"), ("referrers", "/referrers/")] {
            if let Some((repo, r)) = rest.split_once(sep) {
                return match kind {
                    "manifests" => s.manifests.get(&(repo.to_string(), r.to_string())).map(|b| (200, b.clone())).unwrap_or((404, vec![])),
                    "blobs" => s.blobs.get(r).map(|b| (200, b.clone())).unwrap_or((404, vec![])),
                    _ if s.referrers_api => (200, serde_json::to_vec(&json!({"schemaVersion": 2, "manifests":
                        s.referrers.get(r).cloned().unwrap_or_default()})).unwrap()),
                    _ => (404, vec![]),
                };
            }
        }
        (404, vec![])
    }

    pub fn set(registry: &str, key: &Key, index: Option<String>) -> ContainerSet {
        ContainerSet { name: "tasks".into(), registry: registry.into(), repository: "org/tasks/".into(),
                       platform: "linux/amd64".into(), key_pem: key.pem(), index }
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oarbank-imageset-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("image-sets.json")
    }

    #[tokio::test]
    async fn signed_images_verify_in_either_cosign_format_and_others_are_refused() {
        let key = Key::new();
        let store = Arc::new(Mutex::new(Store { referrers_api: true, ..Default::default() }));
        let reg = serve(store.clone()).await;
        let (a, b, c, o) = {
            let mut s = store.lock().unwrap();
            let a = s.image("org/tasks/a", b"a");
            s.sign(&key, &reg, "org/tasks/a", &a, false);
            let b = s.image("org/tasks/b", b"b");
            s.sign(&key, &reg, "org/tasks/b", &b, true);
            let c = s.image("org/tasks/c", b"c");
            s.sign(&Key::new(), &reg, "org/tasks/c", &c, false);
            let o = s.image("org/other", b"o");
            s.sign(&key, &reg, "org/other", &o, false);
            (a, b, c, o)
        };
        let v = Verifier::new(scratch("formats")).unwrap();
        let s = set(&reg, &key, None);
        v.verify(&s, &format!("{reg}/org/tasks/a@{a}"), "linux/amd64").await.unwrap();
        v.verify(&s, &format!("{reg}/org/tasks/b@{b}"), "linux/amd64").await.unwrap();
        let e = v.verify(&s, &format!("{reg}/org/tasks/c@{c}"), "linux/amd64").await.unwrap_err();
        assert_eq!(e.code, "image_not_approved");
        assert!(e.detail.contains("verifies with the set's key"), "{e:?}");
        let e = v.verify(&s, &format!("{reg}/org/other@{o}"), "linux/amd64").await.unwrap_err();
        assert!(e.detail.contains("outside set"), "{e:?}");
        assert!(v.verify(&s, &format!("{reg}/org/tasks/a@{a}"), "linux/arm64").await.is_err());
        let unsigned = format!("sha256:{}", "1".repeat(64));
        let e = v.verify(&s, &format!("{reg}/org/tasks/x@{unsigned}"), "linux/amd64").await.unwrap_err();
        assert!(e.detail.contains("no cosign signature"), "{e:?}");
        // a verified digest is remembered: no registry traffic the second time
        let before = store.lock().unwrap().hits;
        v.verify(&s, &format!("{reg}/org/tasks/a@{a}"), "linux/amd64").await.unwrap();
        assert_eq!(store.lock().unwrap().hits, before);
        // without the referrers API the bundle is found under the referrers tag scheme (an index at sha256-<hex>)
        {
            let mut st = store.lock().unwrap();
            st.referrers_api = false;
            let refs = st.referrers.get(&a).cloned().unwrap();
            let idx = serde_json::to_vec(&json!({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
                                                 "manifests": refs})).unwrap();
            st.manifests.insert(("org/tasks/a".into(), a.replace(':', "-")), idx);
        }
        Verifier::new(scratch("fallback")).unwrap().verify(&s, &format!("{reg}/org/tasks/a@{a}"), "linux/amd64").await.unwrap();
    }

    #[tokio::test]
    async fn an_index_lists_members_and_its_seq_never_goes_back() {
        let key = Key::new();
        let store = Arc::new(Mutex::new(Store { referrers_api: true, ..Default::default() }));
        let reg = serve(store.clone()).await;
        let (a, b) = {
            let mut s = store.lock().unwrap();
            let a = s.image("org/tasks/a", b"a");
            let b = s.image("org/tasks/b", b"b");
            s.index(&key, &reg, "org/tasks-index", "current", 5, std::slice::from_ref(&a));
            (a, b)
        };
        let seqs = scratch("index");
        let v = Verifier::new(seqs.clone()).unwrap();
        let s = set(&reg, &key, Some(format!("{reg}/org/tasks-index:current")));
        v.verify(&s, &format!("{reg}/org/tasks/a@{a}"), "linux/amd64").await.unwrap();
        let e = v.verify(&s, &format!("{reg}/org/tasks/b@{b}"), "linux/amd64").await.unwrap_err();
        assert!(e.detail.contains("not in the set's index (seq 5)"), "{e:?}");
        store.lock().unwrap().index(&key, &reg, "org/tasks-index", "current", 6, &[a.clone(), b.clone()]);
        v.verify(&s, &format!("{reg}/org/tasks/b@{b}"), "linux/amd64").await.unwrap();
        // an older signed index served again is refused, by this agent and by the next one (the seq is in its home)
        store.lock().unwrap().index(&key, &reg, "org/tasks-index", "current", 4, &[a.clone(), b.clone()]);
        let e = Verifier::new(seqs).unwrap().verify(&s, &format!("{reg}/org/tasks/a@{a}"), "linux/amd64").await.unwrap_err();
        assert!(e.detail.contains("older than seq 6"), "{e:?}");
        // an index signed by another key is refused
        store.lock().unwrap().index(&Key::new(), &reg, "org/tasks-index", "current", 9, std::slice::from_ref(&a));
        let e = Verifier::new(scratch("index-forged")).unwrap().verify(&s, &format!("{reg}/org/tasks/a@{a}"), "linux/amd64")
            .await.unwrap_err();
        assert!(e.detail.starts_with("the set's index"), "{e:?}");
    }

    #[tokio::test]
    async fn an_unreachable_registry_is_unavailable_not_a_refusal() {
        let key = Key::new();
        let s = set("127.0.0.1:9", &key, None);
        let e = Verifier::new(scratch("down")).unwrap()
            .verify(&s, &format!("127.0.0.1:9/org/tasks/a@sha256:{}", "2".repeat(64)), "linux/amd64").await.unwrap_err();
        assert_eq!(e.code, "registry_unavailable");
    }

    #[test]
    fn registries_on_loopback_are_plain_http_and_others_https() {
        assert_eq!(base("127.0.0.1:5000"), "http://127.0.0.1:5000");
        assert_eq!(base("localhost:5000"), "http://localhost:5000");
        assert_eq!(base("ghcr.io"), "https://ghcr.io");
        assert_eq!(base("docker.io"), "https://registry-1.docker.io");
        assert_eq!(base("registry.example.org:8443"), "https://registry.example.org:8443");
    }
}
