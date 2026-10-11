//! The write-ahead journal of every mapping the agent requests (`<home>/state/portmaps.json`): an entry is written
//! **before** its request goes out (`intended`), updated when the router answers (`held`, with what it granted), marked
//! `releasing` before a delete and removed after it. A crash at any point leaves the journal knowing every mapping the
//! router might hold for this node, so the next start can delete those it no longer wants; nothing outside the journal
//! (and the router's own listing of this node's description and address) is ever deleted.

use crate::types::{Family, Proto};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Intended,
    Held,
    Releasing,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub key: String,
    pub family: Family,
    pub protocol: Proto,
    pub state: State,
    pub gateway: IpAddr,
    pub internal: SocketAddr,
    pub external_port: u16,
    #[serde(default)]
    pub external_ip: Option<IpAddr>,
    pub lifetime: u32,
    #[serde(default)]
    pub permanent: bool,
    /// Wall-clock expiry of a held lease (None: permanent, or not answered yet).
    #[serde(default)]
    pub expires_at: Option<f64>,
    /// The PCP nonce (hex), reused for renewals and the delete.
    pub nonce: String,
    pub description: String,
    #[serde(default)]
    pub pinhole: Option<u16>,
    pub written_at: f64,
}

impl Entry {
    pub fn nonce_bytes(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        if let Ok(v) = hex::decode(&self.nonce) {
            if v.len() == 12 {
                n.copy_from_slice(&v);
            }
        }
        n
    }

    /// When the router has certainly forgotten it on its own (None: possibly never: a permanent mapping, or a UPnP
    /// request whose answer never came, which a permanent-only router may have made permanent).
    pub fn gone_by(&self) -> Option<f64> {
        if self.permanent {
            return None;
        }
        match self.expires_at {
            Some(t) => Some(t),
            // a NAT-PMP or PCP request whose answer never came: those protocols make no permanent mappings
            None if self.protocol != Proto::Upnp => Some(self.written_at + self.lifetime as f64 + 60.0),
            None => None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct File {
    version: u32,
    entries: Vec<Entry>,
}

/// The journal; `path` None keeps it in memory (tests).
#[derive(Debug, Clone, Default)]
pub struct Journal {
    path: Option<PathBuf>,
    entries: Vec<Entry>,
    /// Writes that failed (the disk is full, the directory gone): the agent reports it, and requests stop until a
    /// write succeeds again (a request is never sent unjournaled).
    pub write_error: Option<String>,
}

impl Journal {
    pub fn memory() -> Journal {
        Journal::default()
    }

    /// Load from `path` (a missing or unreadable file is an empty journal; an unreadable one is kept aside).
    pub fn load(path: &Path) -> Journal {
        let entries = match std::fs::read(path) {
            Ok(b) => match serde_json::from_slice::<File>(&b) {
                Ok(f) => f.entries,
                Err(_) => {
                    let _ = std::fs::rename(path, path.with_extension("json.unreadable"));
                    vec![]
                }
            },
            Err(_) => vec![],
        };
        Journal { path: Some(path.to_path_buf()), entries, write_error: None }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Insert or replace by id, durably. Err: the write failed and nothing changed on disk (the caller must not send
    /// the request).
    pub fn put(&mut self, e: Entry) -> Result<(), String> {
        let mut next = self.entries.clone();
        match next.iter_mut().find(|x| x.id == e.id) {
            Some(x) => *x = e,
            None => next.push(e),
        }
        self.commit(next)
    }

    pub fn remove(&mut self, id: &str) -> Result<(), String> {
        if !self.entries.iter().any(|e| e.id == id) {
            return Ok(());
        }
        let next = self.entries.iter().filter(|e| e.id != id).cloned().collect();
        self.commit(next)
    }

    fn commit(&mut self, next: Vec<Entry>) -> Result<(), String> {
        if let Some(p) = &self.path {
            let f = File { version: 1, entries: next.clone() };
            let bytes = serde_json::to_vec_pretty(&f).map_err(|e| e.to_string())?;
            if let Err(e) = write_atomic(p, &bytes) {
                let msg = format!("cannot write {}: {e}", p.display());
                self.write_error = Some(msg.clone());
                return Err(msg);
            }
        }
        self.write_error = None;
        self.entries = next;
        Ok(())
    }
}

/// Write through a temporary file, flushed to disk, then renamed over the target: a crash leaves the old or the new
/// journal, never half of one. Owner-only on POSIX.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(d) = path.parent() {
        if let Ok(dir) = std::fs::File::open(d) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

pub fn new_id() -> String {
    hex::encode(rand::random::<[u8; 8]>())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> Entry {
        Entry { id: id.into(), key: "m/l".into(), family: Family::Ipv4, protocol: Proto::Upnp, state: State::Intended,
                gateway: "192.168.1.1".parse().unwrap(), internal: "192.168.1.20:41000".parse().unwrap(), external_port: 9000,
                external_ip: None, lifetime: 3600, permanent: false, expires_at: None, nonce: hex::encode([3u8; 12]),
                description: "oarbank:n:m/l".into(), pinhole: None, written_at: 100.0 }
    }

    #[test]
    fn entries_survive_a_reload_and_removal_is_durable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("state/portmaps.json");
        let mut j = Journal::load(&p);
        j.put(entry("a")).unwrap();
        j.put(Entry { state: State::Held, expires_at: Some(3700.0), ..entry("a") }).unwrap();
        j.put(entry("b")).unwrap();
        let k = Journal::load(&p);
        assert_eq!(k.entries().len(), 2);
        assert_eq!(k.get("a").unwrap().state, State::Held);
        assert_eq!(k.get("a").unwrap().nonce_bytes(), [3u8; 12]);
        let mut k = k;
        k.remove("a").unwrap();
        assert_eq!(Journal::load(&p).entries().len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn a_corrupt_journal_is_kept_aside_not_trusted() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("portmaps.json");
        std::fs::write(&p, b"{not json").unwrap();
        assert!(Journal::load(&p).entries().is_empty());
        assert!(p.with_extension("json.unreadable").exists());
    }

    #[test]
    fn when_the_router_has_forgotten_an_entry() {
        let e = entry("a");
        assert_eq!(e.gone_by(), None, "a UPnP request without its answer may be permanent");
        assert_eq!(Entry { protocol: Proto::Natpmp, ..entry("a") }.gone_by(), Some(100.0 + 3600.0 + 60.0));
        assert_eq!(Entry { state: State::Held, expires_at: Some(5.0), ..entry("a") }.gone_by(), Some(5.0));
        assert_eq!(Entry { permanent: true, expires_at: Some(5.0), ..entry("a") }.gone_by(), None);
    }
}
