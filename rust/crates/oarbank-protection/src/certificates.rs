//! Co-tenancy certificates (D52): a harness run that showed "no slowdown" for one rule, one fleet configuration and
//! one node, kept by the coordinator and sent back to the node. `gpu_jobs = "certified"` (D50) lets cooperative fleet
//! GPU work run beside a protected GPU group only up to a valid certificate's duty level.
//!
//! The agent checks validity itself, never looser: the certificate must not have expired, and the node's hardware,
//! OS major version, agent version and the protected program's identity must be the ones it was earned under. A
//! certificate the agent cannot validate counts as none, and `certified` then behaves as `when_no_gpu_protected`.

use serde::{Deserialize, Serialize};

use crate::harness::WorkSelector;
use crate::model::ProcessRecord;

/// What a certificate was earned under, beside the protected program (the agent fills in its own at run time).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertContext {
    pub hardware: String,
    pub os_major: String,
    pub agent_version: String,
}

/// One certificate, as the coordinator sends it (`certificates` directive).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Certificate {
    pub id: String,
    pub rule: String,
    /// The fleet configuration: which work (`gpu`, `cpu`, `all`, `<module>`, `<module>/<workload>`) at which GPU duty.
    pub work: String,
    #[serde(default)]
    pub duty: Option<f64>,
    pub r: f64,
    pub r_lo: f64,
    pub r_hi: f64,
    pub margin: f64,
    pub run_id: String,
    pub issued_at: f64,
    pub valid_until: f64,
    /// The protected program's identity when the run passed ([`identity`]).
    pub identity: String,
    pub context: CertContext,
}

impl Certificate {
    /// Why this certificate does not hold now (None: it holds).
    pub fn invalid(&self, now: f64, identity: Option<&str>, context: &CertContext) -> Option<String> {
        if now >= self.valid_until {
            return Some("expired".into());
        }
        if self.context != *context {
            return Some("the node's hardware, OS or agent changed".into());
        }
        match identity {
            Some(i) if i == self.identity => None,
            Some(_) => Some("the protected program changed".into()),
            None => Some("the protected program is not running".into()),
        }
    }

    /// The GPU duty this certificate allows for fleet GPU work (None: it covers no GPU work at a duty level).
    pub fn gpu_duty(&self) -> Option<f64> {
        let w = WorkSelector::parse(&self.work)?;
        if !w.includes_gpu() {
            return None;
        }
        self.duty.filter(|d| *d > 0.0 && *d <= 1.0)
    }
}

/// The identity of a protected program: a short hash over the distinct (path, Team ID, signing identifier) of its
/// group's processes. A new build of the program at another path, or signed differently, is another program; a
/// restart is the same one.
pub fn identity(group: &[ProcessRecord]) -> Option<String> {
    if group.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = group
        .iter()
        .map(|p| {
            format!(
                "{}|{}|{}",
                p.path.as_deref().unwrap_or("?"),
                p.team_id.as_deref().unwrap_or(""),
                p.signing_id.as_deref().unwrap_or("")
            )
        })
        .collect();
    parts.sort();
    parts.dedup();
    // FNV-1a, 64 bits: stable across builds and platforms (this is a fingerprint, not a security boundary)
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in parts.join("\n").bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    Some(format!("{h:016x}"))
}

/// A fingerprint of a group's processes (pids and start times): changes when the protected process restarts.
pub fn group_fingerprint(group: &[ProcessRecord]) -> u64 {
    let mut keys: Vec<(i32, u64)> = group.iter().map(|p| (p.pid, p.start_us)).collect();
    keys.sort();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (pid, s) in keys {
        for b in pid.to_le_bytes().into_iter().chain(s.to_le_bytes()) {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
    h
}
