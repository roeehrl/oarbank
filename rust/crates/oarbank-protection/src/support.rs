//! What a protection config can ask of each OS. A field that cannot work on an OS is refused there with the
//! reason, by the agent for its own OS and by the coordinator for the node's (`oarbank.contracts.protection`,
//! held equal by shared vectors), so that no field is silently inert. What depends on the moment rather than the
//! OS (whether the front app or the owner's presence can be read now, a Wayland session, the system service's
//! view of another account's process) is reported by the agent instead, and the fail-safe defaults apply.

use std::fmt;

use crate::config::ProtectionConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Darwin,
    Linux,
    Windows,
}

impl Os {
    /// The OS this agent runs on (None: one without a backend, where nothing is refused).
    pub fn current() -> Option<Self> {
        match std::env::consts::OS {
            "macos" => Some(Self::Darwin),
            "linux" => Some(Self::Linux),
            "windows" => Some(Self::Windows),
            _ => None,
        }
    }

    /// A platform token's OS (`darwin`, `linux`, `windows`).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "darwin" => Some(Self::Darwin),
            "linux" => Some(Self::Linux),
            "windows" => Some(Self::Windows),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Darwin => "darwin",
            Self::Linux => "linux",
            Self::Windows => "windows",
        }
    }

    /// The longest `match.name` that can match: the kernel's short name keeps 16 characters on macOS (p_comm)
    /// and 15 on Linux (comm); a Windows image name is the whole file name.
    pub fn name_limit(self) -> usize {
        match self {
            Self::Darwin => 16,
            Self::Linux => 15,
            Self::Windows => 255,
        }
    }

    /// Why this OS has no code-signing identity to match (None on macOS).
    fn no_signing(self) -> Option<&'static str> {
        match self {
            Self::Darwin => None,
            Self::Linux => Some("Linux executables carry no code-signing identity"),
            Self::Windows => {
                Some("Windows signatures (Authenticode) carry no Team ID or signing identifier")
            }
        }
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every reason `config` cannot run as written on `os` (empty: it can).
pub fn refusals(config: &ProtectionConfig, os: Os) -> Vec<String> {
    let mut out = vec![];
    for r in &config.rules {
        let id = &r.id;
        let m = &r.match_;
        if let Some(why) = os.no_signing() {
            for (key, set) in [
                ("requirement", m.requirement.is_some()),
                ("team_id", m.team_id.is_some()),
                ("identifier", m.identifier.is_some()),
            ] {
                if set {
                    out.push(format!(
                        "rule {id}: match.{key} is a macOS code-signing identity, and {why} \
                         (match on path_prefix, path_contains, name or argv_regex)"
                    ));
                }
            }
            if !m.bundle_ids.is_empty() {
                out.push(format!(
                    "rule {id}: match.bundle_id names a macOS app bundle, and {os} has none \
                     (match on path_prefix, path_contains, name or argv_regex)"
                ));
            }
        }
        if let Some(n) = &m.name {
            let limit = os.name_limit();
            if n.chars().count() > limit {
                out.push(format!(
                    "rule {id}: match.name {n:?} is longer than the {limit} characters {os} keeps of a process's \
                     name, so it would never match"
                ));
            }
        }
        if r.protect_metric() == Some("ipc_ratio") && os != Os::Darwin {
            out.push(format!(
                "rule {id}: protect.metric = ipc_ratio needs per-process instruction and cycle counters, which \
                 only macOS gives an unprivileged agent (use progress_rate, cpu_stall or gpu_share)"
            ));
        }
    }
    out
}
