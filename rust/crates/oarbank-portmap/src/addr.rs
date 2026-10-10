//! What kind of address an address is: the facts NAT classification rests on (RFC 1918 private space, RFC 6598 shared
//! space 100.64.0.0/10 that carrier-grade NATs use, loopback, link-local, unique local IPv6).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Unspecified,
    Loopback,
    LinkLocal,
    /// RFC 1918 (IPv4) or unique local fc00::/7 (IPv6): behind a NAT or a firewall of the owner's network.
    Private,
    /// RFC 6598 100.64.0.0/10: the provider's carrier-grade NAT (also Tailscale's range, never a router's WAN side).
    Shared,
    Multicast,
    /// Anything else: an address the internet can reach (documentation ranges count as global, so tests read the same).
    Global,
}

pub fn scope(ip: IpAddr) -> Scope {
    match ip {
        IpAddr::V4(v4) => scope_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => scope_v4(v4),
            None => scope_v6(v6),
        },
    }
}

fn scope_v4(ip: Ipv4Addr) -> Scope {
    let o = ip.octets();
    if ip.is_unspecified() {
        Scope::Unspecified
    } else if ip.is_loopback() {
        Scope::Loopback
    } else if ip.is_link_local() {
        Scope::LinkLocal
    } else if ip.is_private() {
        Scope::Private
    } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
        Scope::Shared
    } else if ip.is_multicast() || ip.is_broadcast() {
        Scope::Multicast
    } else {
        Scope::Global
    }
}

fn scope_v6(ip: Ipv6Addr) -> Scope {
    let s = ip.segments();
    if ip.is_unspecified() {
        Scope::Unspecified
    } else if ip.is_loopback() {
        Scope::Loopback
    } else if (s[0] & 0xffc0) == 0xfe80 {
        Scope::LinkLocal
    } else if (s[0] & 0xfe00) == 0xfc00 {
        Scope::Private
    } else if ip.is_multicast() {
        Scope::Multicast
    } else {
        Scope::Global
    }
}

/// An address the internet can reach.
pub fn is_global(ip: IpAddr) -> bool {
    scope(ip) == Scope::Global
}

/// An address only the node's own network can come from: a probe from one proves nothing about reachability.
pub fn is_local_network(ip: IpAddr) -> bool {
    matches!(scope(ip), Scope::Loopback | Scope::LinkLocal | Scope::Private | Scope::Unspecified)
}

/// The key a per-address limit counts by: the address itself for IPv4, its /64 for IPv6 (one host usually holds a
/// whole /64, so per-address limits on IPv6 count the prefix).
pub fn limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// A CIDR block (`198.51.100.0/24`, `2001:db8::/32`, or a bare address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    pub net: IpAddr,
    pub len: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (a, l) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let ip: IpAddr = a.trim().parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let len = match l {
            Some(l) => l.trim().parse::<u8>().ok().filter(|n| *n <= max)?,
            None => max,
        };
        Some(Cidr { net: mask(ip, len), len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        ip.is_ipv4() == self.net.is_ipv4() && mask(ip, self.len) == self.net
    }

    /// The intersection of two blocks: the narrower one when one contains the other, else nothing.
    pub fn intersect(&self, other: &Cidr) -> Option<Cidr> {
        if self.net.is_ipv4() != other.net.is_ipv4() {
            return None;
        }
        if self.len >= other.len && other.contains(self.net) {
            Some(*self)
        } else if other.len >= self.len && self.contains(other.net) {
            Some(*other)
        } else {
            None
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.len)
    }
}

fn mask(ip: IpAddr, len: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if len == 0 { 0 } else { u32::MAX << (32 - len as u32) };
            IpAddr::V4(Ipv4Addr::from(bits & m))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if len == 0 { 0 } else { u128::MAX << (128 - len as u32) };
            IpAddr::V6(Ipv6Addr::from(bits & m))
        }
    }
}

/// Who may connect: the owner's blocks (none: everyone) intersected with the module's (None: no narrowing).
pub fn allowed(ip: IpAddr, owner: &[Cidr], module: Option<&[Cidr]>) -> bool {
    let owner_ok = owner.is_empty() || owner.iter().any(|c| c.contains(ip));
    let module_ok = module.is_none_or(|m| m.iter().any(|c| c.contains(ip)));
    owner_ok && module_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn scopes() {
        assert_eq!(scope(ip("192.168.1.20")), Scope::Private);
        assert_eq!(scope(ip("10.0.0.1")), Scope::Private);
        assert_eq!(scope(ip("172.16.5.4")), Scope::Private);
        assert_eq!(scope(ip("100.64.0.1")), Scope::Shared);
        assert_eq!(scope(ip("100.127.255.254")), Scope::Shared);
        assert_eq!(scope(ip("100.128.0.1")), Scope::Global);
        assert_eq!(scope(ip("198.51.100.7")), Scope::Global);
        assert_eq!(scope(ip("127.0.0.1")), Scope::Loopback);
        assert_eq!(scope(ip("169.254.1.1")), Scope::LinkLocal);
        assert_eq!(scope(ip("0.0.0.0")), Scope::Unspecified);
        assert_eq!(scope(ip("fe80::1")), Scope::LinkLocal);
        assert_eq!(scope(ip("fd00::1")), Scope::Private);
        assert_eq!(scope(ip("2001:db8::7")), Scope::Global);
        assert_eq!(scope(ip("::ffff:192.168.1.1")), Scope::Private);
        assert!(is_local_network(ip("::1")) && !is_local_network(ip("100.64.0.1")));
    }

    #[test]
    fn cidrs() {
        let c = Cidr::parse("198.51.100.0/24").unwrap();
        assert!(c.contains(ip("198.51.100.200")) && !c.contains(ip("198.51.101.1")));
        assert!(c.contains(ip("::ffff:198.51.100.9")));
        assert_eq!(Cidr::parse("198.51.100.77/24").unwrap().to_string(), "198.51.100.0/24");
        assert_eq!(Cidr::parse("2001:db8::/32").unwrap().len, 32);
        assert!(Cidr::parse("2001:db8::/129").is_none() && Cidr::parse("nonsense").is_none());
        let wide = Cidr::parse("198.51.0.0/16").unwrap();
        assert_eq!(wide.intersect(&c), Some(c));
        assert_eq!(c.intersect(&wide), Some(c));
        assert_eq!(c.intersect(&Cidr::parse("203.0.113.0/24").unwrap()), None);
    }

    #[test]
    fn owner_and_module_narrow_together() {
        let owner = vec![Cidr::parse("198.51.0.0/16").unwrap()];
        let module = vec![Cidr::parse("198.51.100.0/24").unwrap(), Cidr::parse("203.0.113.0/24").unwrap()];
        assert!(allowed(ip("198.51.100.1"), &owner, Some(&module)));
        assert!(!allowed(ip("203.0.113.1"), &owner, Some(&module)), "the module cannot widen the owner's list");
        assert!(!allowed(ip("198.51.7.1"), &owner, Some(&module)));
        assert!(allowed(ip("198.51.7.1"), &owner, None));
        assert!(allowed(ip("192.0.2.1"), &[], None));
        assert!(!allowed(ip("192.0.2.1"), &[], Some(&[])), "an empty module list admits nobody");
    }

    #[test]
    fn per_address_limits_count_an_ipv6_slash_64() {
        assert_eq!(limit_key(ip("2001:db8:1:2:aaaa::1")), ip("2001:db8:1:2::"));
        assert_eq!(limit_key(ip("198.51.100.7")), ip("198.51.100.7"));
    }
}
