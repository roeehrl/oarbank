//! Where the agent keeps its state, per OS (docs/design/architecture.md, "Data roots"). `OARBANK_AGENT_HOME` overrides
//! it (tests, a second agent on one machine).

use std::path::PathBuf;

pub fn agent_home() -> PathBuf {
    if let Some(h) = std::env::var_os("OARBANK_AGENT_HOME") {
        return PathBuf::from(h);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Oarbank/agent")
    } else if cfg!(target_os = "windows") {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or(home).join("Oarbank").join("agent")
    } else {
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".local/share"))
            .join("oarbank").join("agent")
    }
}

pub struct Layout {
    pub home: PathBuf,
}

impl Layout {
    pub fn new(home: PathBuf) -> Self {
        Layout { home }
    }
    pub fn config(&self) -> PathBuf { self.home.join("agent.json") }
    pub fn keys(&self) -> PathBuf { self.home.join("keys") }
    pub fn node_key(&self) -> PathBuf { self.keys().join("node.key") }
    pub fn node_cert(&self) -> PathBuf { self.keys().join("node.pem") }
    pub fn ca_cert(&self) -> PathBuf { self.keys().join("ca.pem") }
    pub fn releases(&self) -> PathBuf { self.home.join("releases") }
    pub fn work(&self) -> PathBuf { self.home.join("work") }
    pub fn module_data(&self) -> PathBuf { self.home.join("modules-data") }
    pub fn cache_blobs(&self) -> PathBuf { self.home.join("cache/blobs") }
    pub fn cache_tmp(&self) -> PathBuf { self.home.join("cache/tmp") }
    pub fn state(&self) -> PathBuf { self.home.join("state") }
    pub fn outbox(&self) -> PathBuf { self.home.join("outbox") }
    pub fn logs(&self) -> PathBuf { self.home.join("logs") }
    pub fn run(&self) -> PathBuf { self.home.join("run") }

    /// Create the tree, every directory owner-only.
    pub fn ensure(&self) -> std::io::Result<()> {
        for d in [self.home.clone(), self.keys(), self.releases(), self.work(), self.module_data(), self.cache_blobs(),
                  self.cache_tmp(), self.state(), self.outbox(), self.logs(), self.run()] {
            crate::fsutil::private_dir(&d)?;
        }
        Ok(())
    }
}

/// A Unix socket path for this agent: under `run/`, unless that exceeds the 104-byte limit, then a short owner-only
/// directory under /tmp named after the home (refused when another account owns it).
#[cfg(unix)]
pub fn socket_path(home: &std::path::Path, name: &str) -> std::io::Result<PathBuf> {
    let p = home.join("run").join(name);
    if p.as_os_str().len() <= 100 {
        return Ok(p);
    }
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt;
    let uid = crate::sys::uid();
    let base = PathBuf::from("/tmp").join(format!("oarbank-agent-{uid}"));
    let dir = base.join(&hex::encode(Sha256::digest(home.to_string_lossy().as_bytes()))[..12]);
    for d in [&base, &dir] {
        crate::fsutil::private_dir(d)?;
        let m = std::fs::metadata(d)?;
        if m.uid() != uid || m.mode() & 0o077 != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("{} is not private", d.display())));
        }
    }
    Ok(dir.join(name))
}
