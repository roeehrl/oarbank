//! Fleet releases and the node update runner (docs/design/fleet-updates.md, D56 and D57; its "Interfaces" section is the
//! contract).
//!
//! - The fleet release manifest (`oarbank-fleet-<v>.json`): parsed from its exact text, which is what `manifest_sha256`
//!   and the owner's statement (`oarbank.fleet-release/v1`) cover; no party ever re-serializes it.
//! - The runner's root-owned files: `trust.json` (the owner keys an administrator pinned, or `unsigned`) and
//!   `journal.json` (its state machine, fsynced before every step).
//! - The runner itself ([`Runner`]), over an [`Installer`] (the OS's package tool, or a fake), a [`Clock`] and a
//!   [`Spool`] (the agent's spool and the runner's state directory). Every step is journaled before it acts, so a runner
//!   that dies anywhere resumes where it stopped. A request is untrusted data: the runner copies the package into its
//!   own directory and verifies the copy, and no path ever comes from the request.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MANIFEST_TYPE: &str = "oarbank-fleet-release";
pub const STATEMENT_TYPE: &str = "oarbank.fleet-release/v1";
/// The node package formats a runner installs.
pub const FORMATS: [&str; 5] = ["pkg", "msi", "deb", "rpm", "tar"];
/// A manifest (and so a request, which carries one) is at most this large.
pub const MAX_MANIFEST: usize = 4 << 20;
const MAX_REQUEST: u64 = 2 * MAX_MANIFEST as u64;
/// How long a new agent has to confirm itself (D57).
pub const PROBATION_S: f64 = 600.0;
/// An install the OS reports busy (MSI 1618, a held dpkg or rpm lock) is tried again after these waits, then failed.
pub const BUSY_RETRY_S: [f64; 3] = [300.0, 900.0, 3600.0];
/// Finished request ids the journal remembers (a request with one of them is ignored).
const FINISHED_KEPT: usize = 32;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct FleetError(pub String);

fn err<T>(s: impl Into<String>) -> Result<T, FleetError> {
    Err(FleetError(s.into()))
}

/// This build's platform token, `<os>-<arch>` (spec/platforms.md; the agent's facts.rs `platform_token`).
pub fn platform() -> String {
    let os = if cfg!(target_os = "macos") { "darwin" } else if cfg!(target_os = "windows") { "windows" } else { "linux" };
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else if cfg!(target_arch = "x86_64") { "amd64" } else { "unknown" };
    format!("{os}-{arch}")
}

/// A version as releases spell it: digits first, then letters, digits, `.`, `+` and `-` (at most 64).
pub fn valid_version(v: &str) -> bool {
    !v.is_empty() && v.len() <= 64 && v.as_bytes()[0].is_ascii_digit() && v.chars().all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c))
}

/// 64 lowercase hex digits.
pub fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_token(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The manifest's hash: over its exact text.
pub fn manifest_sha256(text: &str) -> String {
    sha256_hex(text.as_bytes())
}

/// Seconds since the epoch from a number or an RFC 3339 time (`2026-10-20T00:00:00Z`, or with an offset).
pub fn parse_time(v: &Value) -> Result<Option<f64>, FleetError> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => Ok(n.as_f64()),
        Value::String(s) => rfc3339(s).map(Some).ok_or_else(|| FleetError(format!("not a time: {s:?}"))),
        _ => err("not a time"),
    }
}

fn rfc3339(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
    let (y, mo, d, h, mi, se) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = &s[19..];
    let mut frac = 0.0;
    if let Some(r) = rest.strip_prefix('.') {
        let n = r.bytes().take_while(u8::is_ascii_digit).count();
        frac = format!("0.{}", &r[..n]).parse().ok()?;
        rest = &r[n..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        o if o.len() == 6 && (o.starts_with('+') || o.starts_with('-')) && &o[3..4] == ":" => {
            let m = o[1..3].parse::<i64>().ok()? * 3600 + o[4..6].parse::<i64>().ok()? * 60;
            if o.starts_with('-') { -m } else { m }
        }
        _ => return None,
    };
    // days from the civil date (Howard Hinnant's algorithm)
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + h * 3600 + mi * 60 + se - offset) as f64 + frac)
}

/// One artifact of a fleet release.
#[derive(Debug, Clone, PartialEq)]
pub struct Artifact {
    pub name: String,
    pub role: String,
    pub platform: String,
    pub format: String,
    pub sha256: String,
    pub size: u64,
    pub agent_version: Option<String>,
}

/// A fleet release manifest, as parsed from its text.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub version: String,
    pub seq: i64,
    pub agent_min: Option<String>,
    pub stops: Vec<String>,
    pub expires: Option<f64>,
    pub artifacts: Vec<Artifact>,
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Manifest, FleetError> {
        if text.len() > MAX_MANIFEST {
            return err("the manifest is too large");
        }
        let v: Value = serde_json::from_str(text).map_err(|e| FleetError(format!("the manifest is not JSON: {e}")))?;
        if v["type"].as_str() != Some(MANIFEST_TYPE) {
            return err("not a fleet release manifest");
        }
        if v["format"].as_i64() != Some(1) {
            return err(format!("fleet release manifest format {} is not 1", v["format"]));
        }
        let version = v["version"].as_str().filter(|s| valid_version(s)).ok_or_else(|| FleetError("the manifest's version is malformed".into()))?;
        let seq = v["seq"].as_i64().filter(|s| *s >= 0).ok_or_else(|| FleetError("the manifest has no seq".into()))?;
        let agent_min = match &v["agent_min"] {
            Value::Null => None,
            Value::String(s) if valid_version(s) => Some(s.clone()),
            _ => return err("the manifest's agent_min is malformed"),
        };
        let mut stops = vec![];
        for s in v["stops"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            match s.as_str().filter(|s| valid_version(s)) {
                Some(s) => stops.push(s.to_string()),
                None => return err("the manifest's stops are malformed"),
            }
        }
        let expires = parse_time(&v["expires"]).map_err(|e| FleetError(format!("the manifest's expiry: {e}")))?;
        let mut artifacts = vec![];
        for a in v["artifacts"].as_array().ok_or_else(|| FleetError("the manifest lists no artifacts".into()))? {
            let s = |k: &str| a[k].as_str().map(str::to_string).ok_or_else(|| FleetError(format!("an artifact has no {k}")));
            let art = Artifact { name: s("name")?, role: s("role")?, platform: s("platform")?, format: s("format")?, sha256: s("sha256")?,
                                 size: a["size"].as_u64().ok_or_else(|| FleetError("an artifact has no size".into()))?,
                                 agent_version: a["agent_version"].as_str().map(str::to_string) };
            if art.name.len() > 200 || art.name.is_empty() || art.name.contains(['/', '\\']) || art.name.starts_with('.') {
                return err(format!("artifact name {:?} is not a file name", art.name));
            }
            if !valid_sha256(&art.sha256) {
                return err(format!("artifact {} has a malformed sha256", art.name));
            }
            if art.agent_version.as_deref().is_some_and(|v| !valid_version(v)) {
                return err(format!("artifact {} has a malformed agent_version", art.name));
            }
            artifacts.push(art);
        }
        Ok(Manifest { version: version.to_string(), seq, agent_min, stops, expires, artifacts })
    }

    /// The node package this release has for a platform and an install format.
    pub fn node_artifact(&self, platform: &str, format: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.role == "node" && a.platform == platform && a.format == format)
    }
}

/// The owner's statement over a manifest, checked: its signature by a key of `owner_keys`, and that it names exactly
/// this manifest (version, seq, the hash of its text).
pub fn verify_release(signature: &Value, manifest_text: &str, m: &Manifest, owner_keys: &[String]) -> Result<(), FleetError> {
    if owner_keys.is_empty() {
        return err("no owner keys are pinned");
    }
    let (Some(stmt), Some(sig)) = (signature["statement"].as_str(), signature["signature"].as_str()) else {
        return err("the release is not signed by the owner");
    };
    if !crate::owner::any_key_verifies(owner_keys, stmt.as_bytes(), sig) {
        return err("the owner signature verifies with no pinned owner key");
    }
    let s: Value = serde_json::from_str(stmt).map_err(|_| FleetError("the owner's statement is not JSON".into()))?;
    if s["type"].as_str() != Some(STATEMENT_TYPE) {
        return err("the owner's statement is not a fleet release statement");
    }
    if s["version"].as_str() != Some(m.version.as_str()) || s["seq"].as_i64() != Some(m.seq)
        || s["manifest_sha256"].as_str() != Some(manifest_sha256(manifest_text).as_str()) {
        return err("the owner's statement names another manifest");
    }
    Ok(())
}

// ---- the runner's files ----

/// The command that pins the update trust by hand on this OS, exactly as a person types it: the launcher's own path on
/// macOS (the pkg links only `oarbank-node` onto PATH, which runs the same launcher), `oarbank-launcher` on a Linux
/// package's PATH, `oarbank-node` on Windows' (the launcher under its second name). `--from-agent` copies the owner keys
/// the agent pinned when it joined; a bare `update-trust` only prints its usage. The coordinator shows the same per
/// package format (fleetupdates.py, TRUST_REMEDY).
pub const TRUST_REMEDY: &str = if cfg!(target_os = "macos") {
    "sudo /Library/Oarbank/bin/oarbank-launcher update-trust --from-agent"
} else if cfg!(windows) {
    "oarbank-node update-trust --from-agent (in an elevated prompt)"
} else {
    "sudo oarbank-launcher update-trust --from-agent"
};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Signed,
    Unsigned,
}

/// `trust.json`: written only by `oarbank-launcher update-trust` (and a verified owner key rotation), as root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trust {
    pub format: i64,
    pub mode: Mode,
    pub fleet_id: Option<String>,
    pub owner_version: i64,
    pub owner_keys: Vec<String>,
    pub pinned_at: f64,
    pub pinned_by: String,
}

impl Trust {
    pub fn signed(fleet_id: Option<String>, owner_version: i64, owner_keys: Vec<String>, at: f64, by: &str) -> Trust {
        Trust { format: 1, mode: Mode::Signed, fleet_id, owner_version, owner_keys, pinned_at: at, pinned_by: by.into() }
    }

    pub fn unsigned(at: f64, by: &str) -> Trust {
        Trust { format: 1, mode: Mode::Unsigned, fleet_id: None, owner_version: 0, owner_keys: vec![], pinned_at: at, pinned_by: by.into() }
    }

    /// Whether this trust can verify anything: unsigned, or owner keys pinned.
    pub fn usable(&self) -> bool {
        self.mode == Mode::Unsigned || !self.owner_keys.is_empty()
    }
}

/// A package the runner keeps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pkg {
    pub sha256: String,
    pub release: String,
    pub format: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Verified,
    Installing,
    Installed,
    Probation,
    Committing,
    RollingBack,
}

/// The update in progress (`journal.active`). Besides the contract's fields: the package's size, the error and the
/// outcome a rollback ends in (`rolled_back` after a failed probation, `failed` after a failed install), whether the
/// failed install left the old product in place (MSI's transaction), the busy retries, and reboot_pending.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Active {
    pub id: String,
    pub release: String,
    pub seq: i64,
    pub sha256: String,
    pub format: String,
    pub rollback: bool,
    pub step: Step,
    pub deadline: Option<f64>,
    pub previous_agent: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub restored: bool,
    #[serde(default)]
    pub busy: u32,
    #[serde(default)]
    pub retry_at: Option<f64>,
    #[serde(default)]
    pub reboot_pending: bool,
}

/// `journal.json`. `finished`: the ids of the latest requests the runner finished (refused ones included).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Journal {
    pub format: i64,
    pub committed_seq: i64,
    pub committed_release: Option<String>,
    pub current: Option<Pkg>,
    pub previous: Option<Pkg>,
    pub active: Option<Active>,
    #[serde(default)]
    pub finished: Vec<String>,
}

impl Default for Journal {
    fn default() -> Self {
        Journal { format: 1, committed_seq: 0, committed_release: None, current: None, previous: None, active: None, finished: vec![] }
    }
}

impl Journal {
    fn finish(&mut self, id: &str) {
        self.finished.retain(|x| x != id);
        self.finished.push(id.to_string());
        let n = self.finished.len();
        if n > FINISHED_KEPT {
            self.finished.drain(..n - FINISHED_KEPT);
        }
    }
}

/// `request.json` from the agent's spool: untrusted data, every field checked for shape.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub id: String,
    pub release: String,
    pub seq: i64,
    pub format: String,
    pub sha256: String,
    pub size: u64,
    pub manifest: String,
    pub signature: Value,
    pub owner_anchors: Value,
    pub rollback: bool,
}

impl Request {
    /// The id alone, when the rest does not parse (the refusal still names it).
    pub fn id_of(bytes: &[u8]) -> Option<String> {
        let v: Value = serde_json::from_slice(bytes).ok()?;
        v["id"].as_str().filter(|s| valid_token(s, 64)).map(str::to_string)
    }

    pub fn parse(bytes: &[u8]) -> Result<Request, FleetError> {
        let v: Value = serde_json::from_slice(bytes).map_err(|_| FleetError("the request is not JSON".into()))?;
        let s = |k: &str| v[k].as_str().map(str::to_string).ok_or_else(|| FleetError(format!("the request has no {k}")));
        let r = Request { id: s("id")?, release: s("release")?, seq: v["seq"].as_i64().ok_or_else(|| FleetError("the request has no seq".into()))?,
                          format: s("format")?, sha256: s("sha256")?,
                          size: v["size"].as_u64().ok_or_else(|| FleetError("the request has no size".into()))?,
                          manifest: s("manifest")?, signature: v["signature"].clone(), owner_anchors: v["owner_anchors"].clone(),
                          rollback: v["rollback"].as_bool().unwrap_or(false) };
        if !valid_token(&r.id, 64) {
            return err("the request id is malformed");
        }
        if !valid_version(&r.release) {
            return err("the request's release is malformed");
        }
        if !FORMATS.contains(&r.format.as_str()) {
            return err(format!("{:?} is not a package format", r.format));
        }
        if !valid_sha256(&r.sha256) {
            return err("the request's sha256 is malformed");
        }
        if !r.signature.is_null() && !r.signature.is_object() {
            return err("the request's signature is malformed");
        }
        Ok(r)
    }
}

// ---- what the runner acts through ----

/// How an install ended.
#[derive(Debug, Clone, PartialEq)]
pub enum InstallOutcome {
    Installed { reboot_pending: bool },
    /// Another install holds the OS's installer (MSI 1618, the dpkg or rpm lock): nothing changed, try later.
    Busy(String),
    /// `restored`: the OS put the old product back itself (an MSI transaction), so the runner reinstalls nothing.
    Failed { error: String, restored: bool },
}

/// msiexec's exit code (the MSI's log names the detail).
pub fn msi_outcome(code: i32) -> InstallOutcome {
    match code {
        0 => InstallOutcome::Installed { reboot_pending: false },
        3010 | 1641 => InstallOutcome::Installed { reboot_pending: true },
        1618 => InstallOutcome::Busy("another installation is in progress (1618)".into()),
        1603 => InstallOutcome::Failed { error: "the installation failed (1603); Windows restored the previous version".into(), restored: true },
        c => InstallOutcome::Failed { error: format!("msiexec exited {c}"), restored: true },
    }
}

/// The OS's package tool, and the agent's `current` pointer (oarbank-launcher's `install`).
pub trait Installer {
    /// How this machine's node package was installed (one of [`FORMATS`]).
    fn format(&self) -> String;
    /// The native signature, where the build pins one (Developer ID Installer team, Authenticode subject).
    fn check_native(&mut self, _format: &str, _package: &Path) -> Result<(), String> {
        Ok(())
    }
    /// Install `package` (the runner's own verified copy). Idempotent: a resumed runner installs again.
    fn install(&mut self, format: &str, package: &Path, release: &str, rollback: bool) -> InstallOutcome;
    /// Make the installed package's agent `current`.
    fn point_agent(&mut self, format: &str, release: &str) -> Result<(), String>;
    /// What `current` points at now (a path relative to the agent home).
    fn current_agent(&self) -> Option<String>;
    /// Point `current` at what [`Installer::current_agent`] said before.
    fn point_back(&mut self, previous: &str) -> Result<(), String>;
}

/// The runner stopped mid-update (an I/O error, or a test's crash): the next start resumes from the journal.
#[derive(Debug, Clone, PartialEq)]
pub struct Halt(pub String);

impl std::fmt::Display for Halt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn io(e: std::io::Error) -> Halt {
    Halt(e.to_string())
}

/// Time, for the runner. `checkpoint` is called after every journal write and around every install; a test's clock
/// ends the run there to play a crash.
pub trait Clock {
    fn now(&mut self) -> f64;
    fn sleep(&mut self, secs: f64);
    fn checkpoint(&mut self, _at: &str) -> Result<(), Halt> {
        Ok(())
    }
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&mut self) -> f64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
    }
    fn sleep(&mut self, secs: f64) {
        std::thread::sleep(std::time::Duration::from_secs_f64(secs.clamp(0.0, 3600.0)));
    }
}

/// Write `data` to `p` durably: a temporary file, fsynced, renamed over it, and the directory fsynced.
pub fn write_durable(p: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = p.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.tmp", p.file_name().and_then(|n| n.to_str()).unwrap_or("file")));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, p)?;
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The agent's spool (`<agent home>/updates/`, the agent account's) and the runner's state directory (root's).
pub struct Spool {
    pub agent: PathBuf,
    pub state: PathBuf,
}

impl Spool {
    pub fn new(agent_home: &Path, state: &Path) -> Spool {
        Spool { agent: agent_home.join("updates"), state: state.to_path_buf() }
    }
    pub fn request(&self) -> PathBuf { self.agent.join("request.json") }
    pub fn package(&self) -> PathBuf { self.agent.join("package") }
    pub fn result(&self) -> PathBuf { self.agent.join("result.json") }
    pub fn confirmed(&self) -> PathBuf { self.agent.join("confirmed") }
    pub fn trust(&self) -> PathBuf { self.state.join("trust.json") }
    pub fn journal(&self) -> PathBuf { self.state.join("journal.json") }
    pub fn packages(&self) -> PathBuf { self.state.join("packages") }
    pub fn kept(&self, sha: &str) -> PathBuf { self.packages().join(sha) }
    pub fn incoming(&self) -> PathBuf { self.packages().join(".incoming") }

    pub fn read_journal(&self) -> Result<Journal, Halt> {
        match std::fs::read(self.journal()) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| Halt(format!("{} is unreadable: {e}", self.journal().display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Journal::default()),
            Err(e) => Err(io(e)),
        }
    }

    pub fn write_journal(&self, j: &Journal) -> Result<(), Halt> {
        write_durable(&self.journal(), &serde_json::to_vec_pretty(j).expect("serializes")).map_err(io)
    }

    pub fn read_trust(&self) -> Option<Trust> {
        serde_json::from_slice(&std::fs::read(self.trust()).ok()?).ok()
    }

    pub fn write_trust(&self, t: &Trust) -> std::io::Result<()> {
        write_durable(&self.trust(), &serde_json::to_vec_pretty(t).expect("serializes"))
    }

    /// Read a file of the agent's spool: a regular file (never through a link), at most `max` bytes.
    fn read_spool(&self, p: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
        match std::fs::symlink_metadata(p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
            Ok(m) if !m.is_file() => return Err(std::io::Error::other(format!("{} is not a regular file", p.display()))),
            Ok(_) => {}
        }
        let mut out = vec![];
        std::fs::File::open(p)?.take(max + 1).read_to_end(&mut out)?;
        if out.len() as u64 > max {
            return Err(std::io::Error::other(format!("{} is too large", p.display())));
        }
        Ok(Some(out))
    }

    /// The request is taken (the agent may have withdrawn it meanwhile).
    /// Never left in place: a request that stays would start the runner again and again (a systemd path unit stops
    /// at its start limit). What cannot be removed (not a file) is moved aside to `request.rejected-<ts>.json`.
    fn remove_request(&self) -> Result<(), Halt> {
        match std::fs::remove_file(self.request()) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
                std::fs::rename(self.request(), self.agent.join(format!("request.rejected-{ts}.json"))).map_err(|_| io(e))
            }
            _ => Ok(()),
        }
    }

    /// The agent's result document, as the runner last wrote it.
    pub fn read_result(&self) -> Option<Value> {
        serde_json::from_slice(&std::fs::read(self.result()).ok()?).ok()
    }

    /// `result.json`, the agent account's (it owns the spool).
    pub fn write_result(&self, doc: &Value) -> Result<(), Halt> {
        let p = self.result();
        write_durable(&p, &serde_json::to_vec_pretty(doc).expect("serializes")).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let (Ok(d), Ok(f)) = (std::fs::metadata(&self.agent), std::fs::metadata(&p)) {
                if (d.uid(), d.gid()) != (f.uid(), f.gid()) {
                    let _ = std::os::unix::fs::chown(&p, Some(d.uid()), Some(d.gid()));
                }
            }
        }
        Ok(())
    }

    /// Copy the agent's package into `packages/.incoming` (at most `max` bytes): the copy's (sha256, size).
    fn copy_package(&self, max: u64) -> Result<(String, u64), String> {
        let src = self.package();
        match std::fs::symlink_metadata(&src) {
            Ok(m) if m.is_file() => {}
            Ok(_) => return Err("the spool's package is not a regular file".into()),
            Err(e) => return Err(format!("no package in the spool: {e}")),
        }
        let dir = self.packages();
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        private(&dir);
        let dst = self.incoming();
        let _ = std::fs::remove_file(&dst);
        let copy = || -> std::io::Result<(String, u64)> {
            let mut from = std::fs::File::open(&src)?.take(max + 1);
            let mut to = std::fs::File::create(&dst)?;
            let (mut h, mut n, mut buf) = (Sha256::new(), 0u64, vec![0u8; 1 << 20]);
            loop {
                let k = from.read(&mut buf)?;
                if k == 0 {
                    break;
                }
                h.update(&buf[..k]);
                to.write_all(&buf[..k])?;
                n += k as u64;
            }
            to.sync_all()?;
            Ok((hex::encode(h.finalize()), n))
        };
        copy().map_err(|e| format!("copying the package: {e}"))
    }

    /// The agent's confirmation names this update, written by an agent of its release.
    fn confirmed_for(&self, a: &Active) -> bool {
        let Ok(Some(b)) = self.read_spool(&self.confirmed(), 64 << 10) else { return false };
        let Ok(c) = serde_json::from_slice::<Value>(&b) else { return false };
        c["id"].as_str() == Some(a.id.as_str()) && c["release"].as_str() == Some(a.release.as_str())
            && c["agent_version"].as_str() == Some(a.release.as_str())
    }

    /// Keep only these packages.
    fn prune(&self, keep: &[&str]) {
        for e in std::fs::read_dir(self.packages()).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !keep.contains(&name.as_str()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Owner-only, on Unix (the runner's directories; Windows: %ProgramData%'s ACLs).
pub fn private(_p: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(_p, std::fs::Permissions::from_mode(0o700));
    }
}

/// What one round of the runner did.
#[derive(Debug, Clone, PartialEq)]
pub enum Ran {
    /// No request, nothing in progress.
    Idle,
    /// A request whose id the runner already finished: removed, not run again.
    Ignored(String),
    /// A request ran to its end: `refused`, `done`, `rolled_back` or `failed`.
    Finished { id: String, state: String },
}

/// The node update runner (D57): takes one request at a time, or resumes the one its journal holds, to its end.
pub struct Runner<I: Installer, C: Clock> {
    pub spool: Spool,
    pub installer: I,
    pub clock: C,
    pub platform: String,
    pub probation_s: f64,
    /// How often probation looks for the agent's confirmation.
    pub poll_s: f64,
}

/// A verified request, its copy in `packages/.incoming`.
struct Verified {
    req: Request,
}

impl<I: Installer, C: Clock> Runner<I, C> {
    pub fn new(spool: Spool, installer: I, clock: C) -> Self {
        Runner { spool, installer, clock, platform: platform(), probation_s: PROBATION_S, poll_s: 2.0 }
    }

    fn result(&mut self, a_id: Option<&str>, release: Option<&str>, state: &str, error: Option<&str>, partial: bool, reboot: bool) -> Result<(), Halt> {
        let at = self.clock.now();
        self.spool.write_result(&json!({"id": a_id, "release": release, "state": state, "error": error, "partial": partial,
                                        "reboot_pending": reboot, "at": at}))
    }

    fn save(&mut self, j: &Journal, at: &str) -> Result<(), Halt> {
        self.spool.write_journal(j)?;
        self.clock.checkpoint(at)
    }

    /// Resume the update the journal holds, else take the spool's request; return once the runner is idle again.
    pub fn run_once(&mut self) -> Result<Ran, Halt> {
        let mut j = self.spool.read_journal()?;
        if let Some(a) = &j.active {
            // taken and journaled, but the runner stopped before it removed the request
            if std::fs::read(self.spool.request()).ok().and_then(|b| Request::id_of(&b)).as_deref() == Some(a.id.as_str()) {
                self.spool.remove_request()?;
            }
            return self.drive(&mut j);
        }
        let raw = match self.spool.read_spool(&self.spool.request(), MAX_REQUEST) {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(Ran::Idle),
            Err(e) => {
                let wrote = self.result(None, None, "refused", Some(&format!("the request is unreadable: {e}")), false, false);
                self.spool.remove_request()?;
                wrote?;
                return Ok(Ran::Finished { id: String::new(), state: "refused".into() });
            }
        };
        let id = Request::id_of(&raw);
        if let Some(id) = id.as_ref().filter(|id| j.finished.contains(id)) {
            self.spool.remove_request()?;
            return Ok(Ran::Ignored(id.clone()));
        }
        match self.verify(&raw, &j) {
            Err(e) => {
                let _ = std::fs::remove_file(self.spool.incoming());
                let release = Request::parse(&raw).ok().map(|r| r.release);
                // the refusal is written and journaled first, and the request consumed whatever happens to those
                let wrote = self.result(id.as_deref(), release.as_deref(), "refused", Some(&e), false, false).and_then(|_| match &id {
                    Some(id) => {
                        j.finish(id);
                        self.spool.write_journal(&j)
                    }
                    None => Ok(()),
                });
                self.spool.remove_request()?;
                wrote?;
                Ok(Ran::Finished { id: id.unwrap_or_default(), state: "refused".into() })
            }
            Ok(v) => {
                let r = v.req;
                let kept = self.spool.kept(&r.sha256);
                std::fs::rename(self.spool.incoming(), &kept).map_err(io)?;
                self.clock.checkpoint("kept")?;
                j.active = Some(Active { id: r.id.clone(), release: r.release.clone(), seq: r.seq, sha256: r.sha256.clone(),
                                         format: r.format.clone(), rollback: r.rollback, step: Step::Verified, deadline: None,
                                         previous_agent: self.installer.current_agent(), error: None, outcome: None,
                                         restored: false, busy: 0, retry_at: None, reboot_pending: false });
                self.save(&j, "verified")?;
                self.spool.remove_request()?;
                self.drive(&mut j)
            }
        }
    }

    /// Step 1: every check, on the runner's own copy. The error is the refusal's reason.
    fn verify(&mut self, raw: &[u8], j: &Journal) -> Result<Verified, String> {
        let r = Request::parse(raw).map_err(|e| e.0)?;
        let installed = self.installer.format();
        if r.format != installed {
            return Err(format!("this node's package is {installed}, not {}", r.format));
        }
        let m = Manifest::parse(&r.manifest).map_err(|e| e.0)?;
        if m.version != r.release || m.seq != r.seq {
            return Err("the request names another release than its manifest".into());
        }
        let art = m.node_artifact(&self.platform, &r.format)
            .ok_or_else(|| format!("the manifest names no {} package for {}", r.format, self.platform))?.clone();
        if art.sha256 != r.sha256 || art.size != r.size {
            return Err("the request's package is not the one the manifest names".into());
        }
        if m.expires.is_some_and(|e| self.clock.now() > e) {
            return Err(format!("release {} expired", m.version));
        }
        let mut trust = self.spool.read_trust().ok_or_else(|| format!("no update trust is pinned ({TRUST_REMEDY})"))?;
        if trust.mode == Mode::Signed {
            // a newer owner key set the agent relays: rotated here only by the pinned set's own rule
            if r.owner_anchors.is_object() {
                if let Ok(set) = crate::owner::check_owner_anchors(&r.owner_anchors, trust.fleet_id.as_deref(), trust.owner_version, &trust.owner_keys) {
                    trust.owner_version = set.version;
                    trust.owner_keys = set.keys;
                    self.spool.write_trust(&trust).map_err(|e| format!("cannot keep the rotated owner keys: {e}"))?;
                }
            }
            verify_release(&r.signature, &r.manifest, &m, &trust.owner_keys).map_err(|e| e.0)?;
        }
        if r.seq < j.committed_seq && !(r.rollback && j.previous.as_ref().is_some_and(|p| p.sha256 == r.sha256)) {
            return Err(format!("release seq {} is below the committed {}", r.seq, j.committed_seq));
        }
        let (sha, size) = self.spool.copy_package(art.size)?;
        if sha != art.sha256 || size != art.size {
            return Err("the package does not match the manifest's sha256 and size".into());
        }
        self.installer.check_native(&r.format, &self.spool.incoming())?;
        Ok(Verified { req: r })
    }

    /// Steps 2 to 5, from wherever the journal stands.
    fn drive(&mut self, j: &mut Journal) -> Result<Ran, Halt> {
        loop {
            let mut a = j.active.clone().expect("an update in progress");
            match a.step {
                Step::Verified => {
                    a.step = Step::Installing;
                    j.active = Some(a.clone());
                    self.save(j, "installing")?;
                    self.result(Some(&a.id), Some(&a.release), "installing", None, false, false)?;
                }
                Step::Installing => {
                    if let Some(t) = a.retry_at {
                        let now = self.clock.now();
                        if now < t {
                            self.clock.sleep(t - now);
                            continue;
                        }
                    }
                    self.clock.checkpoint("install")?;
                    let out = self.installer.install(&a.format, &self.spool.kept(&a.sha256), &a.release, false);
                    self.clock.checkpoint("installed")?;
                    match out {
                        InstallOutcome::Installed { reboot_pending } => {
                            a.step = Step::Installed;
                            a.reboot_pending = reboot_pending;
                            a.retry_at = None;
                        }
                        InstallOutcome::Busy(e) if (a.busy as usize) < BUSY_RETRY_S.len() => {
                            a.retry_at = Some(self.clock.now() + BUSY_RETRY_S[a.busy as usize]);
                            a.busy += 1;
                            a.error = Some(e);
                        }
                        InstallOutcome::Busy(e) => {
                            (a.error, a.outcome, a.restored, a.step) = (Some(format!("busy: {e}")), Some("failed".into()), true, Step::RollingBack);
                        }
                        InstallOutcome::Failed { error, restored } => {
                            (a.error, a.outcome, a.restored, a.step) = (Some(error), Some("failed".into()), restored, Step::RollingBack);
                        }
                    }
                    j.active = Some(a);
                    self.save(j, "install outcome")?;
                }
                Step::Installed => {
                    if let Err(e) = self.installer.point_agent(&a.format, &a.release) {
                        (a.error, a.outcome, a.step) = (Some(format!("the package's agent could not be made current: {e}")), Some("failed".into()), Step::RollingBack);
                        j.active = Some(a);
                        self.save(j, "point failed")?;
                        continue;
                    }
                    self.clock.checkpoint("pointed")?;
                    let _ = std::fs::remove_file(self.spool.confirmed());
                    self.result(Some(&a.id), Some(&a.release), "installed", None, false, a.reboot_pending)?;
                    a.step = Step::Probation;
                    a.deadline = Some(self.clock.now() + self.probation_s);
                    a.error = None;
                    j.active = Some(a);
                    self.save(j, "probation")?;
                }
                Step::Probation => {
                    if self.spool.confirmed_for(&a) {
                        a.step = Step::Committing;
                        j.active = Some(a);
                        self.save(j, "committing")?;
                        continue;
                    }
                    let (now, deadline) = (self.clock.now(), a.deadline.unwrap_or(0.0));
                    if now >= deadline {
                        a.error = Some(format!("release {}'s agent did not confirm within {} s", a.release, self.probation_s.round()));
                        (a.outcome, a.step) = (Some("rolled_back".into()), Step::RollingBack);
                        j.active = Some(a);
                        self.save(j, "rolling back")?;
                        continue;
                    }
                    self.clock.sleep(self.poll_s.min(deadline - now));
                }
                Step::Committing => {
                    let new = Pkg { sha256: a.sha256.clone(), release: a.release.clone(), format: a.format.clone() };
                    let previous = match &j.current {
                        Some(c) if c.sha256 != new.sha256 => Some(c.clone()),
                        _ => j.previous.clone(),
                    };
                    let keep: Vec<&str> = [Some(new.sha256.as_str()), previous.as_ref().map(|p| p.sha256.as_str())].into_iter().flatten().collect();
                    self.spool.prune(&keep);
                    self.result(Some(&a.id), Some(&a.release), "done", None, false, a.reboot_pending)?;
                    self.clock.checkpoint("done written")?;
                    j.committed_seq = if a.rollback { a.seq } else { j.committed_seq.max(a.seq) };
                    j.committed_release = Some(a.release.clone());
                    (j.previous, j.current) = (previous, Some(new));
                    j.active = None;
                    j.finish(&a.id);
                    self.spool.write_journal(j)?;
                    let _ = std::fs::remove_file(self.spool.confirmed());
                    return Ok(Ran::Finished { id: a.id, state: "done".into() });
                }
                Step::RollingBack => return self.roll_back(j, a),
            }
        }
    }

    /// Put back what ran before: the kept package (unless the OS already restored it), then the previous agent.
    /// Without a kept package (the node's first fleet update after an install by hand) only the agent goes back:
    /// `partial`.
    fn roll_back(&mut self, j: &mut Journal, a: Active) -> Result<Ran, Halt> {
        let mut partial = false;
        let mut error = a.error.clone().unwrap_or_else(|| "rolled back".into());
        if !a.restored {
            match j.current.clone() {
                Some(cur) if cur.sha256 != a.sha256 && self.spool.kept(&cur.sha256).is_file() => {
                    self.clock.checkpoint("reinstall")?;
                    match self.installer.install(&cur.format, &self.spool.kept(&cur.sha256), &cur.release, true) {
                        InstallOutcome::Installed { .. } => {}
                        InstallOutcome::Busy(e) | InstallOutcome::Failed { error: e, .. } => {
                            partial = true;
                            error = format!("{error}; reinstalling {} failed: {e}", cur.release);
                        }
                    }
                    self.clock.checkpoint("reinstalled")?;
                }
                Some(cur) if cur.sha256 == a.sha256 => {}       // the same package again: nothing else to put back
                _ => partial = true,
            }
        }
        let pointed = match (&a.previous_agent, &j.current) {
            (Some(p), _) => self.installer.point_back(p),
            (None, Some(cur)) => self.installer.point_agent(&cur.format, &cur.release),
            (None, None) => Err("no previous agent is known".into()),
        };
        if let Err(e) = pointed {
            partial = true;
            error = format!("{error}; the previous agent could not be made current: {e}");
        }
        self.clock.checkpoint("pointed back")?;
        let state = a.outcome.clone().unwrap_or_else(|| "rolled_back".into());
        self.result(Some(&a.id), Some(&a.release), &state, Some(&error), partial, false)?;
        let keep: Vec<&str> = [j.current.as_ref(), j.previous.as_ref()].into_iter().flatten().map(|p| p.sha256.as_str()).collect();
        self.spool.prune(&keep);
        j.active = None;
        j.finish(&a.id);
        self.spool.write_journal(j)?;
        Ok(Ran::Finished { id: a.id, state })
    }
}

#[cfg(test)]
mod tests;
