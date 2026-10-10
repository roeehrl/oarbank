//! PCP (RFC 6887): the preferred mapping protocol. A MAP request carries a 96-bit nonce that the client reuses for
//! renewals and the delete (a server refuses a MAP for an existing mapping with another nonce), the client's own address
//! (the server checks it against the packet's source), and options such as `PREFER_FAILURE` (do not substitute another
//! port). Answers carry the server's epoch time, as NAT-PMP's do. A MAP for an IPv6 internal address opens an IPv6
//! firewall pinhole on servers that run one. `ANNOUNCE` (opcode 0) is the cheap probe and epoch check.
//!
//! A server that only speaks NAT-PMP answers a version-2 request with a NAT-PMP packet (version 0, result 1): that is
//! "no PCP here".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

pub const PORT: u16 = 5351;
pub const VERSION: u8 = 2;
pub const OP_ANNOUNCE: u8 = 0;
pub const OP_MAP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const OPT_PREFER_FAILURE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    Success,
    UnsuppVersion,
    NotAuthorized,
    MalformedRequest,
    UnsuppOpcode,
    UnsuppOption,
    MalformedOption,
    NetworkFailure,
    NoResources,
    UnsuppProtocol,
    UserExQuota,
    CannotProvideExternal,
    AddressMismatch,
    ExcessiveRemotePeers,
    Other(u8),
}

impl ResultCode {
    pub fn from_u8(v: u8) -> ResultCode {
        use ResultCode::*;
        match v {
            0 => Success, 1 => UnsuppVersion, 2 => NotAuthorized, 3 => MalformedRequest, 4 => UnsuppOpcode,
            5 => UnsuppOption, 6 => MalformedOption, 7 => NetworkFailure, 8 => NoResources, 9 => UnsuppProtocol,
            10 => UserExQuota, 11 => CannotProvideExternal, 12 => AddressMismatch, 13 => ExcessiveRemotePeers,
            n => Other(n),
        }
    }

    pub fn to_u8(self) -> u8 {
        use ResultCode::*;
        match self {
            Success => 0, UnsuppVersion => 1, NotAuthorized => 2, MalformedRequest => 3, UnsuppOpcode => 4,
            UnsuppOption => 5, MalformedOption => 6, NetworkFailure => 7, NoResources => 8, UnsuppProtocol => 9,
            UserExQuota => 10, CannotProvideExternal => 11, AddressMismatch => 12, ExcessiveRemotePeers => 13,
            Other(n) => n,
        }
    }
}

/// An address in PCP's 128-bit form (IPv4 as `::ffff:a.b.c.d`).
pub fn to_wire(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

pub fn from_wire(b: &[u8]) -> IpAddr {
    let mut a = [0u8; 16];
    a.copy_from_slice(&b[..16]);
    let v6 = Ipv6Addr::from(a);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// A MAP request (or, with lifetime 0, its delete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapRequest {
    pub lifetime: u32,
    pub client: IpAddr,
    pub nonce: [u8; 12],
    pub internal_port: u16,
    pub suggested_port: u16,
    pub suggested_ip: Option<IpAddr>,
    pub prefer_failure: bool,
}

impl MapRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; 24 + 36];
        b[0] = VERSION;
        b[1] = OP_MAP;
        b[4..8].copy_from_slice(&self.lifetime.to_be_bytes());
        b[8..24].copy_from_slice(&to_wire(self.client));
        b[24..36].copy_from_slice(&self.nonce);
        b[36] = PROTO_TCP;
        b[40..42].copy_from_slice(&self.internal_port.to_be_bytes());
        b[42..44].copy_from_slice(&self.suggested_port.to_be_bytes());
        let any = if self.client.is_ipv4() { IpAddr::V4(Ipv4Addr::UNSPECIFIED) } else { IpAddr::V6(Ipv6Addr::UNSPECIFIED) };
        b[44..60].copy_from_slice(&to_wire(self.suggested_ip.unwrap_or(any)));
        if self.prefer_failure {
            b.extend_from_slice(&[OPT_PREFER_FAILURE, 0, 0, 0]);
        }
        b
    }

    /// The fake server's side: a request it can read, with the options it saw.
    pub fn decode(b: &[u8]) -> Option<MapRequest> {
        if b.len() < 60 || b[0] != VERSION || b[1] != OP_MAP || b[36] != PROTO_TCP {
            return None;
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&b[24..36]);
        let mut prefer_failure = false;
        let mut i = 60;
        while i + 4 <= b.len() {
            let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
            if b[i] == OPT_PREFER_FAILURE {
                prefer_failure = true;
            }
            i += 4 + len;
        }
        let sip = from_wire(&b[44..60]);
        Some(MapRequest { lifetime: u32::from_be_bytes([b[4], b[5], b[6], b[7]]), client: from_wire(&b[8..24]), nonce,
                          internal_port: u16::from_be_bytes([b[40], b[41]]), suggested_port: u16::from_be_bytes([b[42], b[43]]),
                          suggested_ip: (!sip.is_unspecified()).then_some(sip), prefer_failure })
    }
}

pub fn announce_request(client: IpAddr) -> Vec<u8> {
    let mut b = vec![0u8; 24];
    b[0] = VERSION;
    b[1] = OP_ANNOUNCE;
    b[8..24].copy_from_slice(&to_wire(client));
    b
}

/// A response header (both opcodes) and, for MAP, its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub opcode: u8,
    pub result: ResultCode,
    pub lifetime: u32,
    pub epoch: u32,
    pub map: Option<MapBody>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapBody {
    pub nonce: [u8; 12],
    pub internal_port: u16,
    pub external_port: u16,
    pub external_ip: IpAddr,
}

/// What came back: a PCP response, or a NAT-PMP packet (the server does not speak PCP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Pcp(Response),
    NatPmpOnly,
}

pub fn parse(b: &[u8]) -> Option<Answer> {
    if b.len() >= 2 && b[0] == 0 && b[1] >= 128 {
        return Some(Answer::NatPmpOnly);
    }
    if b.len() < 24 || b[0] != VERSION || b[1] & 0x80 == 0 {
        return None;
    }
    let opcode = b[1] & 0x7f;
    let map = if opcode == OP_MAP && b.len() >= 60 {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&b[24..36]);
        Some(MapBody { nonce, internal_port: u16::from_be_bytes([b[40], b[41]]), external_port: u16::from_be_bytes([b[42], b[43]]),
                       external_ip: from_wire(&b[44..60]) })
    } else {
        None
    };
    Some(Answer::Pcp(Response { opcode, result: ResultCode::from_u8(b[3]), lifetime: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
                                epoch: u32::from_be_bytes([b[8], b[9], b[10], b[11]]), map }))
}

/// Serialise a response (the fake server's side).
pub fn encode_response(r: &Response) -> Vec<u8> {
    let mut b = vec![0u8; if r.map.is_some() { 60 } else { 24 }];
    b[0] = VERSION;
    b[1] = 0x80 | r.opcode;
    b[3] = r.result.to_u8();
    b[4..8].copy_from_slice(&r.lifetime.to_be_bytes());
    b[8..12].copy_from_slice(&r.epoch.to_be_bytes());
    if let Some(m) = &r.map {
        b[24..36].copy_from_slice(&m.nonce);
        b[36] = PROTO_TCP;
        b[40..42].copy_from_slice(&m.internal_port.to_be_bytes());
        b[42..44].copy_from_slice(&m.external_port.to_be_bytes());
        b[44..60].copy_from_slice(&to_wire(m.external_ip));
    }
    b
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no PCP answer from {0}")]
    NoAnswer(SocketAddr),
    #[error("the gateway speaks NAT-PMP, not PCP")]
    NotPcp,
    #[error("PCP: {0:?}")]
    Refused(ResultCode),
    #[error("PCP: {0}")]
    Io(#[from] std::io::Error),
}

/// Whether this host holds `ip` (a bind to it succeeds).
pub fn local_has(ip: IpAddr) -> bool {
    std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// A PCP client for one server.
#[derive(Debug, Clone)]
pub struct Client {
    pub server: SocketAddr,
    pub timeouts: Vec<Duration>,
}

impl Client {
    pub fn new(server: SocketAddr) -> Client {
        Client { server, timeouts: vec![Duration::from_millis(250), Duration::from_millis(500)] }
    }

    fn timed_out(&self, e: std::io::Error) -> Error {
        if e.kind() == std::io::ErrorKind::TimedOut { Error::NoAnswer(self.server) } else { Error::Io(e) }
    }

    /// The address this host sends from to the server: PCP's client address field must equal it.
    pub fn client_address(&self) -> Option<IpAddr> {
        crate::netinfo::route_local(self.server)
    }

    /// ANNOUNCE: is there a PCP server, and its epoch.
    pub async fn announce(&self) -> Result<Response, Error> {
        let client = self.client_address().ok_or(Error::NoAnswer(self.server))?;
        let (a, _) = crate::natpmp::exchange(self.server, None, &announce_request(client), &self.timeouts, parse).await
            .map_err(|e| self.timed_out(e))?;
        match a {
            Answer::NatPmpOnly => Err(Error::NotPcp),
            Answer::Pcp(r) if r.result == ResultCode::Success => Ok(r),
            Answer::Pcp(r) if r.result == ResultCode::UnsuppVersion => Err(Error::NotPcp),
            Answer::Pcp(r) => Err(Error::Refused(r.result)),
        }
    }

    /// MAP (create, renew with the same nonce, or delete with lifetime 0), sent from the request's client address when
    /// this host has it (PCP checks the source against it), else from the routed address.
    pub async fn map(&self, req: &MapRequest) -> Result<Response, Error> {
        let nonce = req.nonce;
        let from = (crate::netinfo::route_local(self.server) != Some(req.client) && local_has(req.client))
            .then(|| SocketAddr::new(req.client, 0));
        let (a, _) = crate::natpmp::exchange(self.server, from, &req.encode(), &self.timeouts, |b| match parse(b) {
            Some(Answer::Pcp(r)) if r.opcode == OP_MAP && r.map.as_ref().is_some_and(|m| m.nonce == nonce) => Some(Answer::Pcp(r)),
            Some(Answer::NatPmpOnly) => Some(Answer::NatPmpOnly),
            _ => None,
        }).await.map_err(|e| self.timed_out(e))?;
        match a {
            Answer::NatPmpOnly => Err(Error::NotPcp),
            Answer::Pcp(r) if r.result == ResultCode::Success => Ok(r),
            Answer::Pcp(r) => Err(Error::Refused(r.result)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_request_round_trips_with_prefer_failure() {
        let r = MapRequest { lifetime: 7200, client: "192.168.1.20".parse().unwrap(), nonce: [7; 12], internal_port: 41000,
                             suggested_port: 9000, suggested_ip: None, prefer_failure: true };
        let b = r.encode();
        assert_eq!(b.len(), 64);
        assert_eq!(&b[8..24], &Ipv4Addr::new(192, 168, 1, 20).to_ipv6_mapped().octets());
        assert_eq!(MapRequest::decode(&b), Some(r));
    }

    #[test]
    fn responses_round_trip_and_natpmp_is_recognised() {
        let r = Response { opcode: OP_MAP, result: ResultCode::CannotProvideExternal, lifetime: 0, epoch: 99,
                           map: Some(MapBody { nonce: [1; 12], internal_port: 41000, external_port: 9000,
                                               external_ip: "198.51.100.7".parse().unwrap() }) };
        assert_eq!(parse(&encode_response(&r)), Some(Answer::Pcp(r)));
        assert_eq!(parse(&[0, 129, 0, 1, 0, 0, 0, 0]), Some(Answer::NatPmpOnly));
        let v6 = Response { opcode: OP_MAP, result: ResultCode::Success, lifetime: 3600, epoch: 1,
                            map: Some(MapBody { nonce: [2; 12], internal_port: 9000, external_port: 9000,
                                                external_ip: "2001:db8::7".parse().unwrap() }) };
        assert_eq!(parse(&encode_response(&v6)), Some(Answer::Pcp(v6)));
    }
}
