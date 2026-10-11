//! The real router: the PCP and NAT-PMP clients and UPnP through igd-next, behind the lifecycle's `Router` trait.
//!
//! `Target::System` talks to the node's default gateway (the agent in production). `Target::Fixed` talks to named
//! addresses, which is how every test reaches the fake gateways on loopback: no test ever sends a packet to a real
//! router (a test build refuses `Target::System`).

use crate::journal::Entry;
use crate::manager::{Lease, RouterMapping, Router};
use crate::netinfo::NetSnapshot;
use crate::types::*;
use crate::{natpmp, pcp, upnp};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The default gateway (NAT-PMP and PCP on UDP 5351) and SSDP multicast.
    System,
    /// Fixed addresses: `pmp` answers NAT-PMP and PCP, `ssdp` answers M-SEARCH, `pcp_v6` answers PCP for IPv6.
    Fixed { pmp: Option<SocketAddr>, ssdp: Option<SocketAddr>, pcp_v6: Option<SocketAddr> },
}

pub struct NetRouter {
    pub target: Target,
    pub net: NetSnapshot,
    pub upnp_timeout: Duration,
    pub udp_timeouts: Vec<Duration>,
    device: Option<upnp::Upnp>,
}

impl NetRouter {
    pub fn new(target: Target) -> NetRouter {
        #[cfg(test)]
        assert!(target != Target::System, "tests talk to fake gateways only");
        let net = match &target {
            Target::System => NetSnapshot::system(),
            Target::Fixed { pmp, ssdp, .. } => pmp.or(*ssdp).map(NetSnapshot::fixed).unwrap_or_default(),
        };
        NetRouter { target, net, upnp_timeout: Duration::from_secs(2), udp_timeouts: vec![Duration::from_millis(250), Duration::from_millis(500)],
                    device: None }
    }

    /// Read the network again (the agent's network watch); the UPnP device is searched for again.
    pub fn refresh(&mut self) -> &NetSnapshot {
        self.net = match &self.target {
            Target::System => NetSnapshot::system(),
            Target::Fixed { pmp, ssdp, .. } => pmp.or(*ssdp).map(NetSnapshot::fixed).unwrap_or_default(),
        };
        &self.net
    }

    fn pmp_server(&self, family: Family) -> Option<SocketAddr> {
        match (&self.target, family) {
            (Target::Fixed { pmp, .. }, Family::Ipv4) => *pmp,
            (Target::Fixed { pcp_v6, .. }, Family::Ipv6) => *pcp_v6,
            (Target::System, Family::Ipv4) => self.net.gateway_v4.map(|g| SocketAddr::from((g, natpmp::PORT))),
            (Target::System, Family::Ipv6) => self.net.gateway_v6.filter(|g| crate::addr::is_global(IpAddr::V6(*g)))
                .map(|g| SocketAddr::from((g, pcp::PORT))),
        }
    }

    fn ssdp(&self) -> Option<SocketAddr> {
        match &self.target {
            Target::Fixed { ssdp, .. } => *ssdp,
            Target::System => Some(upnp::ssdp_target(None)),
        }
    }

    fn local_v4(&self) -> IpAddr {
        self.net.local_v4.map(IpAddr::V4).unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
    }

    fn natpmp(&self) -> Option<natpmp::Client> {
        self.pmp_server(Family::Ipv4).map(|s| natpmp::Client { gateway: s, timeouts: self.udp_timeouts.clone() })
    }

    fn pcp(&self, family: Family) -> Option<pcp::Client> {
        self.pmp_server(family).map(|s| pcp::Client { server: s, timeouts: self.udp_timeouts.clone() })
    }

    async fn device(&mut self) -> Result<&upnp::Upnp, MapErr> {
        if self.device.is_none() {
            let Some(t) = self.ssdp() else { return Err(MapErr::NoAnswer("no SSDP target".into())) };
            let bind = match self.target {
                Target::Fixed { .. } => t.ip().is_loopback().then_some(IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap_or(self.local_v4()),
                Target::System => self.local_v4(),
            };
            match upnp::discover(t, bind, self.upnp_timeout).await {
                Ok(d) => self.device = Some(d),
                Err(e) => return Err(MapErr::NoAnswer(e.to_string())),
            }
        }
        Ok(self.device.as_ref().expect("set above"))
    }
}

fn pcp_err(e: pcp::Error) -> MapErr {
    use pcp::ResultCode as R;
    match e {
        pcp::Error::NoAnswer(s) => MapErr::NoAnswer(format!("PCP at {s}")),
        pcp::Error::NotPcp => MapErr::Refused("the gateway does not speak PCP".into()),
        pcp::Error::Refused(R::CannotProvideExternal) => MapErr::Conflict { holder: None },
        pcp::Error::Refused(c @ (R::NotAuthorized | R::UnsuppOpcode | R::UnsuppProtocol | R::UnsuppOption | R::UnsuppVersion
                                 | R::MalformedOption | R::MalformedRequest)) => MapErr::Refused(format!("{c:?}")),
        pcp::Error::Refused(R::AddressMismatch) =>
            MapErr::Refused("address mismatch: the PCP server sees another address than this node's (another NAT on the way)".into()),
        pcp::Error::Refused(c) => MapErr::Failed(format!("PCP {c:?}")),
        pcp::Error::Io(e) => MapErr::Failed(e.to_string()),
    }
}

fn natpmp_err(e: natpmp::Error) -> MapErr {
    match e {
        natpmp::Error::NoAnswer(s) => MapErr::NoAnswer(format!("NAT-PMP at {s}")),
        natpmp::Error::Refused(c @ (natpmp::ResultCode::NotAuthorized | natpmp::ResultCode::UnsupportedOpcode
                                   | natpmp::ResultCode::UnsupportedVersion)) => MapErr::Refused(format!("NAT-PMP {c:?}")),
        natpmp::Error::Refused(c) => MapErr::Failed(format!("NAT-PMP {c:?}")),
        natpmp::Error::Io(e) => MapErr::Failed(e.to_string()),
    }
}

fn upnp_err(e: upnp::Error) -> MapErr {
    match e {
        upnp::Error::Code(718, _) => MapErr::Conflict { holder: None },
        upnp::Error::Code(724, _) => MapErr::Refused("the router requires the same external and internal port (UPnP 724)".into()),
        upnp::Error::Code(c @ (606 | 605 | 401 | 402 | 501 | 703 | 702 | 729), d) => MapErr::Refused(format!("UPnP {c} {d}")),
        upnp::Error::Unsupported(a) => MapErr::Refused(format!("UPnP has no {a}")),
        upnp::Error::NotFound => MapErr::NoAnswer("no UPnP gateway".into()),
        upnp::Error::Transport(t) => MapErr::NoAnswer(t),
        e => MapErr::Failed(e.to_string()),
    }
}

impl Router for NetRouter {
    async fn discover(&mut self, family: Family) -> Discovery {
        self.device = None;
        let mut d = Discovery { gateway: self.pmp_server(family).map(|s| s.ip()), ..Default::default() };
        let pcp = self.pcp(family);
        let nat = if family == Family::Ipv4 { self.natpmp() } else { None };
        let pcp_f = async move { match pcp { Some(c) => c.announce().await.ok(), None => None } };
        let nat_f = async move { match nat { Some(c) => c.external().await.ok(), None => None } };
        let (p, n) = tokio::join!(pcp_f, nat_f);
        if let Some(r) = p {
            d.pcp = true;
            d.epoch = Some((Proto::Pcp, r.epoch));
        }
        if let Some((a, _)) = n {
            d.natpmp = true;
            d.external_ip = Some(IpAddr::V4(a.external));
            if d.epoch.is_none() {
                d.epoch = Some((Proto::Natpmp, a.epoch));
            }
        }
        if let Ok(dev) = self.device().await {
            let (ver, addr, fw) = (dev.version().to_string(), dev.addr(), dev.has_firewall());
            d.upnp = Some(ver);
            if d.gateway.is_none() {
                d.gateway = Some(addr.ip());
            }
            let dev = self.device.as_ref().expect("found");
            if family == Family::Ipv4 && d.external_ip.is_none() {
                d.external_ip = dev.external_ip().await.ok();
            }
            if family == Family::Ipv6 {
                d.firewall = if fw { dev.firewall_status().await.ok().flatten() } else { None };
                if !fw {
                    d.upnp = None;               // no pinhole service: UPnP cannot help IPv6
                }
            }
        }
        d
    }

    async fn map(&mut self, proto: Proto, req: &MapReq) -> Result<Granted, MapErr> {
        match (proto, req.family) {
            (Proto::Pcp, fam) => {
                let c = self.pcp(fam).ok_or_else(|| MapErr::NoAnswer("no PCP server".into()))?;
                let r = c.map(&pcp::MapRequest { lifetime: req.lifetime, client: req.internal.ip(), nonce: req.nonce,
                                                 internal_port: req.internal.port(), suggested_port: req.external_port,
                                                 suggested_ip: None, prefer_failure: req.prefer_failure }).await.map_err(pcp_err)?;
                let m = r.map.ok_or_else(|| MapErr::Failed("PCP answer without its mapping".into()))?;
                Ok(Granted { gateway: c.server.ip(), external_port: m.external_port, external_ip: Some(m.external_ip),
                             lifetime: r.lifetime, permanent: false, epoch: Some(r.epoch), pinhole: None, not_needed: false })
            }
            (Proto::Natpmp, Family::Ipv4) => {
                let c = self.natpmp().ok_or_else(|| MapErr::NoAnswer("no NAT-PMP gateway".into()))?;
                let a = c.map(req.internal.port(), req.external_port, req.lifetime).await.map_err(natpmp_err)?;
                let ext = c.external().await.ok().map(|(e, _)| IpAddr::V4(e.external));
                Ok(Granted { gateway: c.gateway.ip(), external_port: a.external_port, external_ip: ext, lifetime: a.lifetime,
                             permanent: false, epoch: Some(a.epoch), pinhole: None, not_needed: false })
            }
            (Proto::Natpmp, Family::Ipv6) => Err(MapErr::Refused("NAT-PMP is IPv4 only".into())),
            (Proto::Upnp, Family::Ipv4) => {
                let dev = self.device().await?;
                let gw = dev.addr().ip();
                let (port, permanent) = if req.any {
                    dev.add_any(req.internal, req.lifetime, &req.description).await.map_err(upnp_err)?
                } else {
                    match dev.add(req.external_port, req.internal, req.lifetime, &req.description).await {
                        Ok(p) => (req.external_port, p),
                        Err(upnp::Error::Code(718, _)) => {
                            let holder = dev.get_specific(req.external_port).await.ok().flatten().map(|e| e.internal_client);
                            return Err(MapErr::Conflict { holder });
                        }
                        Err(e) => return Err(upnp_err(e)),
                    }
                };
                let ext = dev.external_ip().await.ok();
                Ok(Granted { gateway: gw, external_port: port, external_ip: ext, lifetime: if permanent { 0 } else { req.lifetime },
                             permanent, epoch: None, pinhole: None, not_needed: false })
            }
            (Proto::Upnp, Family::Ipv6) => {
                let dev = self.device().await?;
                let gw = dev.addr().ip();
                let IpAddr::V6(v6) = req.internal.ip() else { return Err(MapErr::Refused("an IPv6 pinhole needs an IPv6 address".into())) };
                if let Some(id) = req.pinhole {
                    dev.update_pinhole(id, req.lifetime).await.map_err(upnp_err)?;
                    return Ok(Granted { gateway: gw, external_port: req.internal.port(), external_ip: Some(req.internal.ip()),
                                        lifetime: req.lifetime, permanent: false, epoch: None, pinhole: Some(id), not_needed: false });
                }
                match dev.firewall_status().await.map_err(upnp_err)? {
                    Some((false, _)) => return Ok(Granted { gateway: gw, external_port: req.internal.port(), external_ip: Some(req.internal.ip()),
                                                            lifetime: 0, permanent: false, epoch: None, pinhole: None, not_needed: true }),
                    Some((true, false)) => return Err(MapErr::Refused("the router's IPv6 firewall allows no inbound pinholes".into())),
                    _ => {}
                }
                let id = dev.add_pinhole(SocketAddrV6::new(v6, req.internal.port(), 0, 0), req.lifetime).await.map_err(upnp_err)?;
                Ok(Granted { gateway: gw, external_port: req.internal.port(), external_ip: Some(req.internal.ip()), lifetime: req.lifetime,
                             permanent: false, epoch: None, pinhole: Some(id), not_needed: false })
            }
        }
    }

    async fn verify(&mut self, l: &Lease) -> Result<Verified, MapErr> {
        match (l.proto, l.family) {
            (Proto::Upnp, Family::Ipv4) => {
                let dev = self.device().await?;
                let e = dev.get_specific(l.external_port).await.map_err(upnp_err)?;
                let present = e.as_ref().is_some_and(|e| upnp::is_ours(e, l.internal.ip(), &l.description));
                let ext = dev.external_ip().await.ok();
                Ok(Verified { present, external_ip: ext, epoch: None })
            }
            (Proto::Upnp, Family::Ipv6) => {
                let dev = self.device().await?;
                let present = match l.pinhole {
                    Some(id) => dev.check_pinhole(id).await.map_err(upnp_err)?.unwrap_or(true),
                    None => true,
                };
                Ok(Verified { present, external_ip: None, epoch: None })
            }
            (Proto::Natpmp, _) => {
                let c = self.natpmp().ok_or_else(|| MapErr::NoAnswer("no NAT-PMP gateway".into()))?;
                let (a, _) = c.external().await.map_err(natpmp_err)?;
                Ok(Verified { present: true, external_ip: Some(IpAddr::V4(a.external)), epoch: Some(a.epoch) })
            }
            (Proto::Pcp, fam) => {
                let c = self.pcp(fam).ok_or_else(|| MapErr::NoAnswer("no PCP server".into()))?;
                let r = c.announce().await.map_err(pcp_err)?;
                Ok(Verified { present: true, external_ip: None, epoch: Some(r.epoch) })
            }
        }
    }

    async fn release(&mut self, e: &Entry, own: Option<IpAddr>) -> Released {
        match (e.protocol, e.family) {
            (Proto::Upnp, Family::Ipv4) => {
                let Ok(dev) = self.device().await else { return Released::Unreachable };
                if dev.addr().ip() != e.gateway {
                    return Released::Unreachable;          // another router now: the old one's lease runs out
                }
                match dev.get_specific(e.external_port).await {
                    Err(_) => Released::Unreachable,
                    Ok(None) => Released::Absent,
                    Ok(Some(m)) if !upnp::is_ours(&m, e.internal.ip(), &e.description) => Released::NotOurs,
                    Ok(Some(_)) => match dev.delete_own(e.external_port, e.internal.ip(), &e.description).await {
                        Ok(true) => Released::Deleted,
                        Ok(false) => Released::Absent,
                        Err(_) => Released::Unreachable,
                    },
                }
            }
            (Proto::Upnp, Family::Ipv6) => {
                let Some(id) = e.pinhole else { return Released::Absent };
                let Ok(dev) = self.device().await else { return Released::Unreachable };
                if dev.addr().ip() != e.gateway {
                    return Released::Unreachable;
                }
                match dev.delete_pinhole(id).await {
                    Ok(()) => Released::Deleted,
                    Err(_) => Released::Unreachable,
                }
            }
            (Proto::Natpmp, _) => {
                // only the address that made it can delete it: this node's current one, or the old one while an
                // interface still holds it (Ethernet plugged in, Wi-Fi still up)
                if own != Some(e.internal.ip()) && !pcp::local_has(e.internal.ip()) {
                    return Released::Unreachable;
                }
                let Some(c) = self.natpmp().filter(|c| c.gateway.ip() == e.gateway) else { return Released::Unreachable };
                match c.map_from(Some(e.internal.ip()), e.internal.port(), 0, 0).await {
                    Ok(_) => Released::Deleted,
                    Err(natpmp::Error::NoAnswer(_)) => Released::Unreachable,
                    Err(_) => Released::Absent,
                }
            }
            (Proto::Pcp, fam) => {
                if own != Some(e.internal.ip()) && !pcp::local_has(e.internal.ip()) {
                    return Released::Unreachable;
                }
                let Some(c) = self.pcp(fam).filter(|c| c.server.ip() == e.gateway) else { return Released::Unreachable };
                let r = c.map(&pcp::MapRequest { lifetime: 0, client: e.internal.ip(), nonce: e.nonce_bytes(), internal_port: e.internal.port(),
                                                 suggested_port: e.external_port, suggested_ip: None, prefer_failure: false }).await;
                match r {
                    Ok(_) => Released::Deleted,
                    Err(pcp::Error::NoAnswer(_)) | Err(pcp::Error::Io(_)) => Released::Unreachable,
                    Err(pcp::Error::Refused(pcp::ResultCode::NotAuthorized)) => Released::NotOurs,
                    Err(_) => Released::Absent,
                }
            }
        }
    }

    async fn list(&mut self, internal: IpAddr) -> Vec<RouterMapping> {
        let Ok(dev) = self.device().await else { return vec![] };
        let Ok(all) = dev.list(128).await else { return vec![] };
        all.into_iter().filter(|m| m.protocol == "TCP" && m.internal_client.trim().parse::<IpAddr>().ok() == Some(internal))
            .map(|m| RouterMapping { external_port: m.external_port, internal: format!("{}:{}", m.internal_client, m.internal_port),
                                     ours: m.description.starts_with("oarbank:"), description: m.description })
            .collect()
    }
}
