//! The vocabulary of the mapping lifecycle: what a listener wants, what a router granted, and how a request can fail.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Pcp,
    Natpmp,
    Upnp,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Pcp => "pcp",
            Proto::Natpmp => "natpmp",
            Proto::Upnp => "upnp",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Proto::Pcp => "PCP",
            Proto::Natpmp => "NAT-PMP",
            Proto::Upnp => "UPnP",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn name(self) -> &'static str {
        match self {
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
        }
    }
}

/// What happens when the router says the wanted external port is taken (docs/design/inbound-listeners.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    Refuse,
    NextFree { lo: u16, hi: u16 },
    RouterChoice,
}

impl Fallback {
    pub fn parse(s: &str) -> Option<Fallback> {
        match s {
            "refuse" => Some(Fallback::Refuse),
            "router_choice" => Some(Fallback::RouterChoice),
            _ => {
                let r = s.strip_prefix("next_free:")?;
                let (a, b) = r.split_once('-')?;
                let (lo, hi) = (a.trim().parse::<u16>().ok()?, b.trim().parse::<u16>().ok()?);
                (lo >= 1024 && lo <= hi).then_some(Fallback::NextFree { lo, hi })
            }
        }
    }

    /// The ports to try, in order, starting with the wanted one: deterministic, so the same inputs give the same port.
    /// `router_choice` walks up from the wanted port too: the agent never lets a UPnP router pick the port
    /// (AddAnyPortMapping), because a request whose answer is lost would leave a mapping on a port the journal could not
    /// know; NAT-PMP and PCP substitute a port themselves, but their mappings are keyed by the internal port, which the
    /// journal always knows.
    pub fn ports(&self, wanted: u16) -> Vec<u16> {
        match *self {
            Fallback::NextFree { lo, hi } => {
                let mut v = vec![wanted];
                v.extend((lo..=hi).filter(|p| *p != wanted).take(256));
                v
            }
            Fallback::RouterChoice => (wanted..=u16::MAX).take(64).collect(),
            Fallback::Refuse => vec![wanted],
        }
    }

    /// Whether a port the router assigned instead is acceptable.
    pub fn accepts(&self, wanted: u16, got: u16) -> bool {
        match *self {
            Fallback::Refuse => got == wanted,
            Fallback::NextFree { lo, hi } => got == wanted || (lo..=hi).contains(&got),
            Fallback::RouterChoice => got != 0,
        }
    }
}

impl std::fmt::Display for Fallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fallback::Refuse => write!(f, "refuse"),
            Fallback::RouterChoice => write!(f, "router_choice"),
            Fallback::NextFree { lo, hi } => write!(f, "next_free:{lo}-{hi}"),
        }
    }
}

/// How a listener reaches the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// PCP, else NAT-PMP, else UPnP.
    Auto,
    Only(Proto),
    /// The owner forwarded the port by hand: nothing is mapped, reachability is only verified.
    Manual,
    /// The machine has a public address: nothing to map.
    None,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        Some(match s {
            "auto" => Mode::Auto,
            "pcp" => Mode::Only(Proto::Pcp),
            "natpmp" => Mode::Only(Proto::Natpmp),
            "upnp" => Mode::Only(Proto::Upnp),
            "manual" => Mode::Manual,
            "none" => Mode::None,
            _ => return None,
        })
    }
}

/// One mapping a listener wants on the router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Want {
    /// `<module>/<listener>`.
    pub key: String,
    pub family: Family,
    /// The address and port the listener is bound to (IPv4: the node's address on the default route; IPv6: its global
    /// address).
    pub internal: SocketAddr,
    pub external_port: u16,
    pub fallback: Fallback,
    pub mode: Mode,
    /// The UPnP description that marks the mapping as this node's (`oarbank:<node prefix>:<key>`).
    pub description: String,
}

/// A request to the router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapReq {
    pub family: Family,
    pub internal: SocketAddr,
    pub external_port: u16,
    /// Let the router choose (UPnP AddAnyPortMapping; NAT-PMP and PCP take the suggestion as a hint anyway).
    pub any: bool,
    /// PCP `PREFER_FAILURE`: never substitute another port.
    pub prefer_failure: bool,
    pub lifetime: u32,
    pub nonce: [u8; 12],
    pub description: String,
    /// A pinhole being renewed (IPv6 over UPnP).
    pub pinhole: Option<u16>,
}

/// What the router granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    pub gateway: IpAddr,
    pub external_port: u16,
    pub external_ip: Option<IpAddr>,
    /// Seconds; 0 with `permanent`.
    pub lifetime: u32,
    pub permanent: bool,
    /// The router's epoch (NAT-PMP, PCP).
    pub epoch: Option<u32>,
    pub pinhole: Option<u16>,
    /// IPv6 through a router whose firewall is off: nothing to open.
    pub not_needed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MapErr {
    /// The external port is held by someone else (UPnP 718, PCP CANNOT_PROVIDE_EXTERNAL under PREFER_FAILURE).
    #[error("the port is taken{}", .holder.as_ref().map(|h| format!(" by {h}")).unwrap_or_default())]
    Conflict { holder: Option<String> },
    /// The router answers but will not do it (not authorized, unsupported): try the next protocol.
    #[error("refused: {0}")]
    Refused(String),
    /// Nothing answered: the request may or may not have been applied.
    #[error("no answer: {0}")]
    NoAnswer(String),
    /// Any other failure: retried with a backoff.
    #[error("{0}")]
    Failed(String),
}

/// A verification's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The router still holds the mapping, as ours.
    pub present: bool,
    pub external_ip: Option<IpAddr>,
    pub epoch: Option<u32>,
}

/// A release's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    Deleted,
    /// The router holds no such mapping.
    Absent,
    /// The router holds that port for someone else: left alone.
    NotOurs,
    /// The router could not be asked (gone, or this node's address changed so NAT-PMP and PCP cannot delete): retried
    /// until the lease runs out.
    Unreachable,
}

/// Which mapping protocols answer on the network now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovery {
    pub gateway: Option<IpAddr>,
    pub pcp: bool,
    pub natpmp: bool,
    /// "IGD:1" or "IGD:2".
    pub upnp: Option<String>,
    pub external_ip: Option<IpAddr>,
    /// (NAT-PMP or PCP, epoch) from the probe.
    pub epoch: Option<(Proto, u32)>,
    /// IPv6: the router's firewall (enabled, inbound pinholes allowed), when it has the UPnP firewall service.
    pub firewall: Option<(bool, bool)>,
}

impl Discovery {
    pub fn any(&self) -> bool {
        self.pcp || self.natpmp || self.upnp.is_some()
    }

    pub fn has(&self, p: Proto) -> bool {
        match p {
            Proto::Pcp => self.pcp,
            Proto::Natpmp => self.natpmp,
            Proto::Upnp => self.upnp.is_some(),
        }
    }
}

/// The lifecycle's constants (the design's defaults; tests compress them).
#[derive(Debug, Clone, PartialEq)]
pub struct Timing {
    pub lease_pcp: u32,
    pub lease_natpmp: u32,
    pub lease_upnp: u32,
    pub lease_pinhole: u32,
    /// UPnP read-back and NAT-PMP/PCP epoch check.
    pub verify_s: f64,
    /// How long a discovery that found a protocol is trusted.
    pub discovery_ttl_s: f64,
    pub retry_min_s: f64,
    pub retry_max_s: f64,
    /// A refused port is asked for again after this long (the holder may have gone).
    pub port_taken_retry_s: f64,
    /// Orphaned mappings (no longer wanted) are released at least this often until they are gone or expired.
    pub release_retry_s: f64,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing { lease_pcp: 7200, lease_natpmp: 7200, lease_upnp: 3600, lease_pinhole: 3600, verify_s: 300.0,
                 discovery_ttl_s: 600.0, retry_min_s: 5.0, retry_max_s: 600.0, port_taken_retry_s: 600.0, release_retry_s: 30.0 }
    }
}

impl Timing {
    pub fn lease(&self, p: Proto, family: Family) -> u32 {
        match (p, family) {
            (Proto::Upnp, Family::Ipv6) => self.lease_pinhole,
            (Proto::Upnp, _) => self.lease_upnp,
            (Proto::Natpmp, _) => self.lease_natpmp,
            (Proto::Pcp, _) => self.lease_pcp,
        }
    }

    /// Exponential backoff from `retry_min_s`, capped.
    pub fn backoff(&self, attempts: u32) -> f64 {
        (self.retry_min_s * 2f64.powi(attempts.min(16) as i32)).min(self.retry_max_s)
    }
}

/// The UPnP description that marks a mapping as this node's: `oarbank:<node prefix>:<key>`, shortened to a digest of
/// the key when it would be long (some routers cut descriptions).
pub fn description(node_prefix: &str, key: &str) -> String {
    let d = format!("oarbank:{node_prefix}:{key}");
    if d.len() <= 48 {
        return d;
    }
    use sha2::Digest;
    let h = hex::encode(&sha2::Sha256::digest(key.as_bytes())[..6]);
    format!("oarbank:{node_prefix}:{h}")
}

/// A node id's prefix for descriptions: its first 10 letters and digits.
pub fn node_prefix(node_id: &str) -> String {
    let p: String = node_id.chars().filter(|c| c.is_ascii_alphanumeric()).take(10).collect();
    if p.is_empty() { "node".into() } else { p }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallbacks_parse_and_walk_deterministically() {
        assert_eq!(Fallback::parse("refuse"), Some(Fallback::Refuse));
        assert_eq!(Fallback::parse("next_free:9000-9003"), Some(Fallback::NextFree { lo: 9000, hi: 9003 }));
        assert_eq!(Fallback::parse("next_free:9003-9000"), None);
        assert_eq!(Fallback::parse("next_free:80-90"), None, "never below 1024");
        let f = Fallback::NextFree { lo: 9000, hi: 9003 };
        assert_eq!(f.ports(9001), vec![9001, 9000, 9002, 9003]);
        assert_eq!(f.ports(9001), f.ports(9001));
        assert!(f.accepts(9001, 9003) && !f.accepts(9001, 9100));
        assert!(!Fallback::Refuse.accepts(9000, 9001) && Fallback::RouterChoice.accepts(9000, 31000));
        assert_eq!(f.to_string(), "next_free:9000-9003");
    }

    #[test]
    fn descriptions_carry_the_node_prefix_and_stay_short() {
        assert_eq!(description("n1abc", "mod/peer"), "oarbank:n1abc:mod/peer");
        let long = description("n1abc", &format!("{}/{}", "m".repeat(40), "l".repeat(20)));
        assert!(long.starts_with("oarbank:n1abc:") && long.len() <= 48, "{long}");
        assert_eq!(node_prefix("n_0123456789abcdef"), "n012345678");
    }
}
