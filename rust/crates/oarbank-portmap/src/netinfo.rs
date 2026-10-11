//! The node's view of its network: the default gateway, its own address on the default route and its global IPv6
//! address. Read in process (netdev: the routing table and the interface list on macOS, Linux and Windows), cheaply
//! enough to compare every few seconds; a change is a network change (the lifecycle re-maps).
//!
//! Tests never read the real network: `Target::Fixed` names a fake gateway on loopback, and the local address is then
//! whatever address the OS uses to reach it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetSnapshot {
    /// The default IPv4 gateway (the router NAT-PMP, PCP and UPnP talk to).
    pub gateway_v4: Option<Ipv4Addr>,
    /// This node's address on the default route.
    pub local_v4: Option<Ipv4Addr>,
    /// The default IPv6 router, when the default interface has one.
    pub gateway_v6: Option<Ipv6Addr>,
    /// A stable (not temporary, not deprecated) global IPv6 address on the default interface.
    pub global_v6: Option<Ipv6Addr>,
    /// The default interface's name.
    pub iface: Option<String>,
}

impl NetSnapshot {
    /// Read it from the OS.
    pub fn system() -> NetSnapshot {
        let mut out = NetSnapshot::default();
        let Ok(i) = netdev::get_default_interface() else {
            out.local_v4 = route_local(SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9))).and_then(as_v4);
            return out;
        };
        out.iface = Some(i.name.clone());
        if let Some(g) = &i.gateway {
            out.gateway_v4 = g.ipv4.first().copied();
            out.gateway_v6 = g.ipv6.iter().find(|a| !a.is_unspecified()).copied();
        }
        // the address the OS picks to reach the gateway (a UDP connect sends nothing), else the interface's first
        out.local_v4 = out.gateway_v4.and_then(|g| route_local(SocketAddr::from((g, 9)))).and_then(as_v4)
            .or_else(|| i.ipv4.first().map(|n| n.addr()));
        let flags = &i.ipv6_addr_flags;
        out.global_v6 = i.ipv6.iter().enumerate()
            .filter(|(_, n)| crate::addr::is_global(IpAddr::V6(n.addr())))
            .filter(|(k, _)| flags.get(*k).is_none_or(|f| !f.temporary && !f.deprecated))
            .map(|(_, n)| n.addr()).next();
        out
    }

    /// A fixed gateway (tests, and an owner who names the router): the local address is the one the OS uses to reach it.
    pub fn fixed(gateway: SocketAddr) -> NetSnapshot {
        let local = route_local(gateway);
        NetSnapshot { gateway_v4: as_v4(gateway.ip()), local_v4: local.and_then(as_v4), gateway_v6: None, global_v6: None,
                      iface: None }
    }
}

fn as_v4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v) => Some(v),
        IpAddr::V6(v) => v.to_ipv4_mapped(),
    }
}

/// The local address the OS routes `to` from. A UDP connect only picks the route; no packet is sent.
pub fn route_local(to: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if to.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let s = UdpSocket::bind(bind).ok()?;
    s.connect(to).ok()?;
    s.local_addr().ok().map(|a| a.ip()).filter(|ip| !ip.is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_loopback_gateway_is_reached_from_loopback() {
        let s = NetSnapshot::fixed("127.0.0.1:5351".parse().unwrap());
        assert_eq!(s.gateway_v4, Some(Ipv4Addr::LOCALHOST));
        assert_eq!(s.local_v4, Some(Ipv4Addr::LOCALHOST));
    }
}
