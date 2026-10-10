//! NAT-PMP (RFC 6886): the client the agent maps with on routers that speak it. The wire format is small and fixed:
//! a 2-byte request for the external address, a 12-byte mapping request, and answers that carry the router's
//! seconds since its start of epoch (a value lower than expected means the router rebooted and lost its mappings).
//! Mappings are keyed by the requesting host's own address and internal port, so a delete (lifetime 0) can only ever
//! remove this host's own mapping.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

pub const PORT: u16 = 5351;
/// Routers send address-change announcements here (multicast to 224.0.0.1).
pub const ANNOUNCE_PORT: u16 = 5350;
const OP_EXTERNAL: u8 = 0;
const OP_MAP_TCP: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    Success,
    UnsupportedVersion,
    NotAuthorized,
    NetworkFailure,
    OutOfResources,
    UnsupportedOpcode,
    Other(u16),
}

impl ResultCode {
    pub fn from_u16(v: u16) -> ResultCode {
        match v {
            0 => ResultCode::Success,
            1 => ResultCode::UnsupportedVersion,
            2 => ResultCode::NotAuthorized,
            3 => ResultCode::NetworkFailure,
            4 => ResultCode::OutOfResources,
            5 => ResultCode::UnsupportedOpcode,
            n => ResultCode::Other(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            ResultCode::Success => 0,
            ResultCode::UnsupportedVersion => 1,
            ResultCode::NotAuthorized => 2,
            ResultCode::NetworkFailure => 3,
            ResultCode::OutOfResources => 4,
            ResultCode::UnsupportedOpcode => 5,
            ResultCode::Other(n) => n,
        }
    }
}

/// The answer to an external-address request (also the shape of an announcement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAnswer {
    pub result: ResultCode,
    pub epoch: u32,
    pub external: Ipv4Addr,
}

/// The answer to a mapping request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapAnswer {
    pub result: ResultCode,
    pub epoch: u32,
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime: u32,
}

pub fn external_request() -> [u8; 2] {
    [0, OP_EXTERNAL]
}

pub fn map_request(internal_port: u16, suggested_external: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[1] = OP_MAP_TCP;
    b[4..6].copy_from_slice(&internal_port.to_be_bytes());
    b[6..8].copy_from_slice(&suggested_external.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

pub fn parse_external(b: &[u8]) -> Option<ExternalAnswer> {
    if b.len() < 12 || b[0] != 0 || b[1] != 128 + OP_EXTERNAL {
        return None;
    }
    Some(ExternalAnswer { result: ResultCode::from_u16(u16::from_be_bytes([b[2], b[3]])),
                          epoch: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
                          external: Ipv4Addr::new(b[8], b[9], b[10], b[11]) })
}

pub fn parse_map(b: &[u8]) -> Option<MapAnswer> {
    if b.len() < 16 || b[0] != 0 || b[1] != 128 + OP_MAP_TCP {
        return None;
    }
    Some(MapAnswer { result: ResultCode::from_u16(u16::from_be_bytes([b[2], b[3]])),
                     epoch: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
                     internal_port: u16::from_be_bytes([b[8], b[9]]),
                     external_port: u16::from_be_bytes([b[10], b[11]]),
                     lifetime: u32::from_be_bytes([b[12], b[13], b[14], b[15]]) })
}

/// Serialise answers (the fake gateway's side).
pub fn external_answer(a: &ExternalAnswer) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[1] = 128 + OP_EXTERNAL;
    b[2..4].copy_from_slice(&a.result.to_u16().to_be_bytes());
    b[4..8].copy_from_slice(&a.epoch.to_be_bytes());
    b[8..12].copy_from_slice(&a.external.octets());
    b
}

pub fn map_answer(a: &MapAnswer) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[1] = 128 + OP_MAP_TCP;
    b[2..4].copy_from_slice(&a.result.to_u16().to_be_bytes());
    b[4..8].copy_from_slice(&a.epoch.to_be_bytes());
    b[8..10].copy_from_slice(&a.internal_port.to_be_bytes());
    b[10..12].copy_from_slice(&a.external_port.to_be_bytes());
    b[12..16].copy_from_slice(&a.lifetime.to_be_bytes());
    b
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no NAT-PMP answer from {0}")]
    NoAnswer(SocketAddr),
    #[error("NAT-PMP: {0:?}")]
    Refused(ResultCode),
    #[error("NAT-PMP: {0}")]
    Io(#[from] std::io::Error),
}

/// One request with retransmissions: `timeouts` are the waits for an answer after each send (RFC 6886 starts at 250 ms
/// and doubles; the agent stops after two, as iroh's portmapper does, because a router that answers does so at once).
/// Only answers from `to` that `parse` accepts count.
pub async fn exchange<T>(to: SocketAddr, local: Option<SocketAddr>, req: &[u8], timeouts: &[Duration],
                         parse: impl Fn(&[u8]) -> Option<T>) -> Result<(T, SocketAddr), std::io::Error> {
    let bind = local.unwrap_or_else(|| if to.is_ipv4() { SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)) }
                                        else { SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)) });
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(to).await?;
    let me = sock.local_addr()?;
    let mut buf = [0u8; 1100];
    for wait in timeouts {
        sock.send(req).await?;
        let deadline = tokio::time::Instant::now() + *wait;
        loop {
            match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                Err(_) => break,
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => break,   // ICMP port unreachable
                Ok(Err(e)) => return Err(e),
                Ok(Ok(n)) => {
                    if let Some(v) = parse(&buf[..n]) {
                        return Ok((v, me));
                    }
                }
            }
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no answer"))
}

/// A NAT-PMP client for one gateway.
#[derive(Debug, Clone)]
pub struct Client {
    pub gateway: SocketAddr,
    pub timeouts: Vec<Duration>,
}

impl Client {
    pub fn new(gateway: SocketAddr) -> Client {
        Client { gateway, timeouts: vec![Duration::from_millis(250), Duration::from_millis(500)] }
    }

    fn timed_out(&self, e: std::io::Error) -> Error {
        if e.kind() == std::io::ErrorKind::TimedOut { Error::NoAnswer(self.gateway) } else { Error::Io(e) }
    }

    /// The gateway's external address and epoch; also the local address the request left from (this host's address as
    /// the router sees it, which keys its mappings).
    pub async fn external(&self) -> Result<(ExternalAnswer, SocketAddr), Error> {
        let (a, me) = exchange(self.gateway, None, &external_request(), &self.timeouts, parse_external).await
            .map_err(|e| self.timed_out(e))?;
        if a.result != ResultCode::Success {
            return Err(Error::Refused(a.result));
        }
        Ok((a, me))
    }

    /// Map (or renew, or with lifetime 0 delete) TCP `internal_port`, suggesting `external`.
    pub async fn map(&self, internal_port: u16, external: u16, lifetime: u32) -> Result<MapAnswer, Error> {
        self.map_from(None, internal_port, external, lifetime).await
    }

    /// `map`, sent from `from` (a delete must come from the address that made the mapping).
    pub async fn map_from(&self, from: Option<std::net::IpAddr>, internal_port: u16, external: u16, lifetime: u32) -> Result<MapAnswer, Error> {
        let (a, _) = exchange(self.gateway, from.map(|ip| SocketAddr::new(ip, 0)), &map_request(internal_port, external, lifetime), &self.timeouts,
                              |b| parse_map(b).filter(|m| m.internal_port == internal_port)).await
            .map_err(|e| self.timed_out(e))?;
        if a.result != ResultCode::Success {
            return Err(Error::Refused(a.result));
        }
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_round_trips() {
        let m = MapAnswer { result: ResultCode::Success, epoch: 77, internal_port: 41000, external_port: 9000, lifetime: 7200 };
        assert_eq!(parse_map(&map_answer(&m)), Some(m));
        let e = ExternalAnswer { result: ResultCode::NotAuthorized, epoch: 5, external: Ipv4Addr::new(198, 51, 100, 7) };
        assert_eq!(parse_external(&external_answer(&e)), Some(e));
        let r = map_request(41000, 9000, 7200);
        assert_eq!(r, [0, 2, 0, 0, 0xa0, 0x28, 0x23, 0x28, 0, 0, 0x1c, 0x20]);
        assert_eq!(parse_map(&r), None, "a request is not an answer");
        assert_eq!(parse_external(&[0, 128, 0]), None, "short");
    }
}
