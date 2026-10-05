//! Vendor update trust (PLAN D31; docs/design/architecture.md, "Updates and trust"). An agent build carries the Oarbank
//! vendor's root metadata (compiled in from `OARBANK_TUF_ROOT` by build.rs; builds without it skip this check). Before
//! installing an agent build the agent fetches the vendor's TUF metadata through its coordinator, which only mirrors it
//! (`GET /v1/tuf/<file>`), and checks the client workflow of the TUF specification 1.0 (§5) for the subset the vendor
//! uses (ed25519 keys, no delegations, no consistent snapshots):
//!
//! 1. root: each next version `N+1.root.json` must be signed by a threshold of keys of both the trusted and the new
//!    root, with exactly the next version; the final root must not be expired;
//! 2. timestamp: signed by the root's timestamp keys, not older than the cached one, not expired;
//! 3. snapshot: the version (and hashes, if listed) the timestamp names, signed by the snapshot keys, not expired;
//! 4. targets: the version the snapshot names, signed by the targets keys, not expired;
//! 5. the build must be a target with exactly its length and sha256.
//!
//! The trusted root and the last versions seen are cached in `<home>/tuf/` (anti-rollback across restarts).

use crate::api::Api;
use crate::paths::Layout;
use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The vendor root this build trusts, when it was built with one.
pub fn embedded_root() -> Option<&'static [u8]> {
    const ROOT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tuf-root.json"));
    (!ROOT.is_empty()).then_some(ROOT)
}

/// OLPC canonical JSON, as securesystemslib signs TUF metadata: sorted keys, no whitespace, strings escaping only
/// `\` and `"`. Floats never appear in TUF metadata and are refused.
pub fn canonical(v: &Value) -> Result<String> {
    Ok(match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
        Value::Number(_) => bail!("a float in TUF metadata"),
        Value::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Value::Array(a) => format!("[{}]", a.iter().map(canonical).collect::<Result<Vec<_>>>()?.join(",")),
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            let parts = keys.iter().map(|k| Ok(format!("{}:{}", canonical(&Value::String((*k).clone()))?, canonical(&o[*k])?)))
                .collect::<Result<Vec<_>>>()?;
            format!("{{{}}}", parts.join(","))
        }
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ` as Unix seconds.
pub fn parse_time(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    // days from civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60 + ss)
}

fn now() -> i64 {
    crate::doctor::now() as i64
}

/// Whether `role` in `root` is satisfied by `doc`'s signatures: at least `threshold` distinct keys of the role.
fn verify_role(root: &Value, role: &str, doc: &Value) -> Result<()> {
    let r = &root["signed"]["roles"][role];
    let threshold = r["threshold"].as_u64().filter(|t| *t >= 1).context("role without a threshold")?;
    let keyids: Vec<&str> = r["keyids"].as_array().context("role without keys")?.iter().filter_map(Value::as_str).collect();
    let msg = canonical(&doc["signed"])?;
    let mut good: Vec<&str> = vec![];
    for sig in doc["signatures"].as_array().context("no signatures")? {
        let (Some(kid), Some(hexsig)) = (sig["keyid"].as_str(), sig["sig"].as_str()) else { continue };
        if !keyids.contains(&kid) || good.contains(&kid) {
            continue;
        }
        let key = &root["signed"]["keys"][kid];
        if key["keytype"] != "ed25519" || key["scheme"] != "ed25519" {
            continue;
        }
        let (Some(pubhex), Ok(sigb)) = (key["keyval"]["public"].as_str(), hex::decode(hexsig)) else { continue };
        let Ok(pk) = hex::decode(pubhex) else { continue };
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        if crate::identity::verify_ed25519(&b64.encode(&pk), msg.as_bytes(), &b64.encode(&sigb)).is_ok() {
            good.push(kid);
        }
    }
    if (good.len() as u64) < threshold {
        bail!("{role}: {} valid signature(s), {threshold} needed", good.len());
    }
    Ok(())
}

fn check_type(doc: &Value, ty: &str) -> Result<()> {
    if doc["signed"]["_type"].as_str() != Some(ty) {
        bail!("not {ty} metadata");
    }
    Ok(())
}

fn not_expired(doc: &Value, what: &str) -> Result<()> {
    let exp = doc["signed"]["expires"].as_str().and_then(parse_time).context("metadata without an expiry")?;
    if exp <= now() {
        bail!("{what} metadata expired at {exp} (Unix time); {}", crate::clock::skew_hint(now() as f64));
    }
    Ok(())
}

fn version(doc: &Value) -> i64 {
    doc["signed"]["version"].as_i64().unwrap_or(0)
}

/// The trusted state, cached between runs.
struct Store {
    dir: std::path::PathBuf,
}

impl Store {
    fn read(&self, name: &str) -> Option<Value> {
        std::fs::read(self.dir.join(name)).ok().and_then(|b| serde_json::from_slice(&b).ok())
    }

    fn write(&self, name: &str, v: &Value) -> Result<()> {
        crate::fsutil::private_dir(&self.dir)?;
        crate::fsutil::write_private(&self.dir.join(name), &serde_json::to_vec(v)?)?;
        Ok(())
    }
}

/// Where the metadata comes from (the coordinator's mirror; a map in tests).
#[allow(async_fn_in_trait)]
pub trait Fetch {
    /// The file's bytes, or None when the mirror does not have it.
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>>;
}

pub struct Mirror<'a>(pub &'a Api);

impl Fetch for Mirror<'_> {
    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        match self.0.download(&format!("/v1/tuf/{name}"), 0).await {
            Ok(r) => Ok(Some(r.bytes().await?.to_vec())),
            Err(crate::api::ApiError::Http { status: 404, .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

fn parse(b: &[u8], what: &str) -> Result<Value> {
    serde_json::from_slice(b).with_context(|| format!("{what} is not JSON"))
}

/// Refresh the vendor metadata and return the verified targets (TUF §5.3–5.6).
pub async fn refresh(fetch: &impl Fetch, root_bytes: &[u8], dir: &std::path::Path) -> Result<Map<String, Value>> {
    let store = Store { dir: dir.to_path_buf() };
    // 1. the root chain, from the newest trusted root (the cached one when it is newer than the embedded)
    let embedded = parse(root_bytes, "the embedded root")?;
    let mut root = match store.read("root.json") {
        Some(c) if version(&c) > version(&embedded) => c,
        _ => embedded,
    };
    check_type(&root, "root")?;
    for _ in 0..1024 {
        let next = version(&root) + 1;
        let Some(b) = fetch.get(&format!("{next}.root.json")).await? else { break };
        let new = parse(&b, "a root")?;
        check_type(&new, "root")?;
        verify_role(&root, "root", &new).context("the next root is not signed by the trusted root")?;
        verify_role(&new, "root", &new).context("the next root is not signed by its own keys")?;
        if version(&new) != next {
            bail!("root version {} is not {next}", version(&new));
        }
        root = new;
        store.write("root.json", &root)?;
    }
    not_expired(&root, "root")?;
    // 2. timestamp
    let ts = parse(&fetch.get("timestamp.json").await?.context("the mirror has no timestamp.json")?, "timestamp.json")?;
    check_type(&ts, "timestamp")?;
    verify_role(&root, "timestamp", &ts)?;
    if let Some(old) = store.read("timestamp.json") {
        if version(&ts) < version(&old) {
            bail!("timestamp rolled back from version {} to {}", version(&old), version(&ts));
        }
    }
    not_expired(&ts, "timestamp")?;
    // 3. snapshot, as the timestamp names it
    let snap_meta = &ts["signed"]["meta"]["snapshot.json"];
    let snap_bytes = fetch.get("snapshot.json").await?.context("the mirror has no snapshot.json")?;
    if let Some(len) = snap_meta["length"].as_u64() {
        if len != snap_bytes.len() as u64 {
            bail!("snapshot.json has the wrong length");
        }
    }
    if let Some(h) = snap_meta["hashes"]["sha256"].as_str() {
        if hex::encode(Sha256::digest(&snap_bytes)) != h {
            bail!("snapshot.json does not match the timestamp's hash");
        }
    }
    let snap = parse(&snap_bytes, "snapshot.json")?;
    check_type(&snap, "snapshot")?;
    verify_role(&root, "snapshot", &snap)?;
    if Some(version(&snap)) != snap_meta["version"].as_i64() {
        bail!("snapshot version {} is not the timestamp's {}", version(&snap), snap_meta["version"]);
    }
    if let Some(old) = store.read("snapshot.json") {
        if version(&snap) < version(&old) {
            bail!("snapshot rolled back");
        }
    }
    not_expired(&snap, "snapshot")?;
    // 4. targets, as the snapshot names it
    let tmeta = &snap["signed"]["meta"]["targets.json"];
    let tb = fetch.get("targets.json").await?.context("the mirror has no targets.json")?;
    if let Some(h) = tmeta["hashes"]["sha256"].as_str() {
        if hex::encode(Sha256::digest(&tb)) != h {
            bail!("targets.json does not match the snapshot's hash");
        }
    }
    let targets = parse(&tb, "targets.json")?;
    check_type(&targets, "targets")?;
    verify_role(&root, "targets", &targets)?;
    if Some(version(&targets)) != tmeta["version"].as_i64() {
        bail!("targets version {} is not the snapshot's {}", version(&targets), tmeta["version"]);
    }
    if let Some(old) = store.read("targets.json") {
        if version(&targets) < version(&old) {
            bail!("targets rolled back");
        }
    }
    not_expired(&targets, "targets")?;
    store.write("timestamp.json", &ts)?;
    store.write("snapshot.json", &snap)?;
    store.write("targets.json", &targets)?;
    Ok(targets["signed"]["targets"].as_object().cloned().unwrap_or_default())
}

/// The vendor's target name for an agent build: `oarbank-agent-<version>-<platform>`.
pub fn agent_target(version: &str, platform: &str) -> String {
    format!("oarbank-agent-{version}-{platform}")
}

/// When this build trusts a vendor root: the build must be the vendor's target `name`, with this length and sha256.
pub async fn check_agent_build(api: &Api, layout: &Layout, name: &str, sha256: &str, length: u64) -> Result<()> {
    let Some(root) = embedded_root() else { return Ok(()) };
    let targets = refresh(&Mirror(api), root, &layout.home.join("tuf")).await.context("vendor metadata")?;
    let t = targets.get(name).with_context(|| format!("the vendor does not list {name}"))?;
    if t["length"].as_u64() != Some(length) || t["hashes"]["sha256"].as_str() != Some(sha256) {
        bail!("the build is not the vendor's {name}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn expired_metadata_names_this_nodes_clock() {
        let e = not_expired(&json!({"signed": {"expires": "2000-01-01T00:00:00Z"}}), "timestamp").unwrap_err();
        assert!(format!("{e}").contains("timestamp metadata expired") && format!("{e}").contains("clock is skewed"), "{e}");
    }

    struct Files(HashMap<String, Vec<u8>>);
    impl Fetch for Files {
        async fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.0.get(name).cloned())
        }
    }

    fn key(seed: u8) -> (SigningKey, String, Value) {
        let k = SigningKey::from_bytes(&[seed; 32]);
        let public = hex::encode(k.verifying_key().as_bytes());
        let kid = hex::encode(Sha256::digest(public.as_bytes()));
        (k, kid, json!({"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": public}}))
    }

    fn sign(signed: Value, keys: &[&(SigningKey, String, Value)]) -> Value {
        let msg = canonical(&signed).unwrap();
        let sigs: Vec<Value> = keys.iter().map(|(k, kid, _)| json!({"keyid": kid, "sig": hex::encode(k.sign(msg.as_bytes()).to_bytes())})).collect();
        json!({"signed": signed, "signatures": sigs})
    }

    fn root(v: i64, keys: &[&(SigningKey, String, Value)]) -> Value {
        let mut ks = Map::new();
        for (_, kid, k) in keys {
            ks.insert(kid.clone(), k.clone());
        }
        let ids = |i: usize| json!([keys[i].1]);
        json!({"_type": "root", "spec_version": "1.0.31", "version": v, "expires": "2099-01-01T00:00:00Z", "consistent_snapshot": false,
               "keys": ks, "roles": {"root": {"keyids": ids(0), "threshold": 1}, "targets": {"keyids": ids(1), "threshold": 1},
                                     "snapshot": {"keyids": ids(2), "threshold": 1}, "timestamp": {"keyids": ids(3), "threshold": 1}}})
    }

    fn repo(target_sha: &str, root_keys: [&(SigningKey, String, Value); 4]) -> HashMap<String, Vec<u8>> {
        let [_, t, s, ts] = root_keys;
        let targets = sign(json!({"_type": "targets", "spec_version": "1.0.31", "version": 1, "expires": "2099-01-01T00:00:00Z",
                                  "targets": {"oarbank-agent-1.0.0-darwin-arm64": {"length": 10, "hashes": {"sha256": target_sha}}}}), &[t]);
        let tb = serde_json::to_vec(&targets).unwrap();
        let snap = sign(json!({"_type": "snapshot", "spec_version": "1.0.31", "version": 1, "expires": "2099-01-01T00:00:00Z",
                               "meta": {"targets.json": {"version": 1, "hashes": {"sha256": hex::encode(Sha256::digest(&tb))}}}}), &[s]);
        let sb = serde_json::to_vec(&snap).unwrap();
        let ts = sign(json!({"_type": "timestamp", "spec_version": "1.0.31", "version": 1, "expires": "2099-01-01T00:00:00Z",
                             "meta": {"snapshot.json": {"version": 1, "length": sb.len(), "hashes": {"sha256": hex::encode(Sha256::digest(&sb))}}}}), &[ts]);
        HashMap::from([("targets.json".into(), tb), ("snapshot.json".into(), sb), ("timestamp.json".into(), serde_json::to_vec(&ts).unwrap())])
    }

    fn tmp() -> tempfile::TempDir {
        crate::scratch("tuf")
    }

    #[test]
    fn times_and_canonical_json() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("2026-10-03T12:00:00Z"), Some(1791028800));
        assert_eq!(parse_time("2026-10-03 12:00:00"), None);
        assert_eq!(canonical(&json!({"b": 1, "a": ["x\"y", true, null]})).unwrap(), r#"{"a":["x\"y",true,null],"b":1}"#);
        assert!(canonical(&json!({"a": 1.5})).is_err());
    }

    #[tokio::test]
    async fn verifies_the_chain_and_refuses_tampering() {
        let (r, t, s, ts) = (key(1), key(2), key(3), key(4));
        let sha = "ab".repeat(32);
        let root1 = sign(root(1, &[&r, &t, &s, &ts]), &[&r]);
        let files = Files(repo(&sha, [&r, &t, &s, &ts]));
        let dir = tmp();
        let targets = refresh(&files, &serde_json::to_vec(&root1).unwrap(), dir.path()).await.unwrap();
        assert_eq!(targets["oarbank-agent-1.0.0-darwin-arm64"]["hashes"]["sha256"], sha.as_str());

        // a root rotation signed by the old and the new root keys is followed; one signed by the new keys alone is not
        let r2 = key(5);
        let mut f2 = repo(&sha, [&r2, &t, &s, &ts]);
        f2.insert("2.root.json".into(), serde_json::to_vec(&sign(root(2, &[&r2, &t, &s, &ts]), &[&r, &r2])).unwrap());
        refresh(&Files(f2), &serde_json::to_vec(&root1).unwrap(), dir.path()).await.unwrap();
        let mut f3 = repo(&sha, [&r2, &t, &s, &ts]);
        f3.insert("2.root.json".into(), serde_json::to_vec(&sign(root(2, &[&r2, &t, &s, &ts]), &[&r2])).unwrap());
        assert!(refresh(&Files(f3), &serde_json::to_vec(&root1).unwrap(), tmp().path()).await.is_err());

        // targets signed by the wrong key, or changed after the snapshot hashed them, are refused
        let mut bad = repo(&sha, [&r, &s, &s, &ts]);
        bad.insert("targets.json".into(), files.0["targets.json"].clone());
        assert!(refresh(&Files(bad), &serde_json::to_vec(&root1).unwrap(), tmp().path()).await.is_err());
        let mut forged = repo(&sha, [&r, &t, &s, &ts]);
        let mut tj: Value = serde_json::from_slice(&forged["targets.json"]).unwrap();
        tj["signed"]["targets"]["oarbank-agent-1.0.0-darwin-arm64"]["hashes"]["sha256"] = json!("cd".repeat(32));
        forged.insert("targets.json".into(), serde_json::to_vec(&tj).unwrap());
        assert!(refresh(&Files(forged), &serde_json::to_vec(&root1).unwrap(), tmp().path()).await.is_err());
    }
}
