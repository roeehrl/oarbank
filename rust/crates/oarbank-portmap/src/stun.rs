//! One STUN binding request (RFC 8489) to learn the address the internet sees: used only when the owner names a STUN
//! server (`listener_stun_server`); by default no third party is ever contacted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAPPED_ADDRESS: u16 = 0x0001;

pub fn request(txid: &[u8; 12]) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    b[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    b[8..20].copy_from_slice(txid);
    b
}

/// The mapped address of a binding success for `txid`.
pub fn parse(b: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if b.len() < 20 || u16::from_be_bytes([b[0], b[1]]) != BINDING_SUCCESS || b[4..8] != MAGIC_COOKIE.to_be_bytes() || &b[8..20] != txid {
        return None;
    }
    let len = u16::from_be_bytes([b[2], b[3]]) as usize;
    let body = b.get(20..20 + len)?;
    let mut i = 0;
    let mut plain = None;
    while i + 4 <= body.len() {
        let t = u16::from_be_bytes([body[i], body[i + 1]]);
        let l = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let v = body.get(i + 4..i + 4 + l)?;
        if (t == XOR_MAPPED_ADDRESS || t == MAPPED_ADDRESS) && v.len() >= 8 {
            let xor = t == XOR_MAPPED_ADDRESS;
            let mut port = u16::from_be_bytes([v[2], v[3]]);
            if xor {
                port ^= (MAGIC_COOKIE >> 16) as u16;
            }
            let ip = match v[1] {
                1 => {
                    let mut a = [v[4], v[5], v[6], v[7]];
                    if xor {
                        for (k, x) in a.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                            *k ^= x;
                        }
                    }
                    IpAddr::V4(Ipv4Addr::from(a))
                }
                2 if v.len() >= 20 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&v[4..20]);
                    if xor {
                        let mut key = [0u8; 16];
                        key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                        key[4..].copy_from_slice(txid);
                        for (k, x) in a.iter_mut().zip(key) {
                            *k ^= x;
                        }
                    }
                    IpAddr::V6(Ipv6Addr::from(a))
                }
                _ => return None,
            };
            let sa = SocketAddr::new(ip, port);
            if xor {
                return Some(sa);
            }
            plain = Some(sa);
        }
        i += 4 + l.div_ceil(4) * 4;
    }
    plain
}

/// Ask `server` (`host:port`) for this node's public address, from `local` when given.
pub async fn binding(server: &str, local: Option<IpAddr>, timeout: Duration) -> Result<SocketAddr, String> {
    let to = tokio::net::lookup_host(server).await.map_err(|e| format!("{server}: {e}"))?.find(|a| a.is_ipv4())
        .ok_or_else(|| format!("{server}: no IPv4 address"))?;
    let sock = tokio::net::UdpSocket::bind(SocketAddr::new(local.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), 0)).await
        .map_err(|e| e.to_string())?;
    sock.connect(to).await.map_err(|e| e.to_string())?;
    let txid: [u8; 12] = rand::random();
    let mut buf = [0u8; 576];
    for wait in [timeout / 2, timeout] {
        sock.send(&request(&txid)).await.map_err(|e| e.to_string())?;
        if let Ok(Ok(n)) = tokio::time::timeout(wait, sock.recv(&mut buf)).await {
            if let Some(a) = parse(&buf[..n], &txid) {
                return Ok(a);
            }
        }
    }
    Err(format!("no STUN answer from {server}"))
}

/// A binding success (the fake server's side, and the tests').
pub fn success(txid: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let mut attr = vec![0u8, if mapped.is_ipv4() { 1 } else { 2 }];
    attr.extend_from_slice(&(mapped.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    match mapped.ip() {
        IpAddr::V4(v4) => attr.extend(v4.octets().iter().zip(MAGIC_COOKIE.to_be_bytes()).map(|(a, b)| a ^ b)),
        IpAddr::V6(v6) => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(txid);
            attr.extend(v6.octets().iter().zip(key).map(|(a, b)| a ^ b));
        }
    }
    let mut b = vec![];
    b.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    b.extend_from_slice(&((attr.len() + 4) as u16).to_be_bytes());
    b.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    b.extend_from_slice(txid);
    b.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    b.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    b.extend_from_slice(&attr);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_mapped_addresses_decode() {
        let t = [9u8; 12];
        for a in ["198.51.100.7:41000", "[2001:db8::7]:9000"] {
            let sa: SocketAddr = a.parse().unwrap();
            assert_eq!(parse(&success(&t, sa), &t), Some(sa));
        }
        assert_eq!(parse(&success(&t, "198.51.100.7:1".parse().unwrap()), &[8u8; 12]), None, "another transaction");
    }

    #[tokio::test]
    async fn a_binding_round_trip_on_loopback() {
        let srv = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let at = srv.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 100];
            let (n, from) = srv.recv_from(&mut b).await.unwrap();
            let mut t = [0u8; 12];
            t.copy_from_slice(&b[8..20]);
            assert_eq!(n, 20);
            srv.send_to(&success(&t, "198.51.100.7:5000".parse().unwrap()), from).await.unwrap();
        });
        let got = binding(&at.to_string(), Some("127.0.0.1".parse().unwrap()), Duration::from_secs(2)).await.unwrap();
        assert_eq!(got, "198.51.100.7:5000".parse().unwrap());
    }
}
