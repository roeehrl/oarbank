//! agent.json: where the coordinator is and what the agent trusts about it (docs/protocol.md, "Agent config").

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Trust {
    /// The coordinator identity key (base64 Ed25519), pinned on first use.
    pub cik: Option<String>,
    pub fleet_id: Option<String>,
    /// The highest epoch seen; a coordinator answering below it is refused.
    pub max_epoch: i64,
    /// The CA's SPKI SHA-256 from the CIK-signed identity, and a successor during a CA rotation.
    pub ca_spki_sha256: Option<String>,
    pub ca_next_spki_sha256: Option<String>,
    pub retired: Vec<String>,
    pub fallback: Option<String>,
    pub pending_move: Option<serde_json::Value>,
    /// Owner key set (signing mode): base64 Ed25519 keys, their version, and the rescue locations it names (URLs where
    /// the owner publishes a rescue move; rescue.rs).
    pub owner_keys: Vec<String>,
    pub owner_version: i64,
    pub owner_rescue: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub coordinator: String,
    pub enrollment_id: Option<String>,
    pub node_id: Option<String>,
    pub heartbeat_s: f64,
    pub manage_services: bool,
    pub coordinator_trust: Trust,
    /// Highest signed seq per statement kind (anti-rollback for releases and agent builds).
    pub release_seq: i64,
    /// A join code's one-time secret, sent with the enrollment (then dropped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_secret: Option<String>,
    /// The owner's release key, pinned on first sight (signing mode).
    pub release_pubkey: Option<String>,
    pub agent_seq: i64,
}

impl Config {
    pub fn new(coordinator: &str) -> Self {
        Config { coordinator: coordinator.trim_end_matches('/').to_string(), enrollment_id: None, node_id: None,
                 heartbeat_s: 10.0, manage_services: true, coordinator_trust: Trust::default(), release_seq: 0, join_secret: None, release_pubkey: None, agent_seq: 0 }
    }

    pub fn load(p: &Path) -> anyhow::Result<Option<Config>> {
        match std::fs::read(p) {
            Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, p: &Path) -> anyhow::Result<()> {
        crate::fsutil::write_private(p, &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}
