//! The egress allow list for `net.mode = "egress-allowlist"` (spec/sandbox.md, "Network"), as the SDK's
//! `egress_proxy.py`: which `host:port` a module may reach through the agent's proxy, and which resolved addresses
//! count as public.
//!
//! - an `allow` entry is `host[:port]` (port 443 by default) or `*.domain[:port]` (subdomains only);
//! - IP literals are never allowed; a name must also resolve only to global addresses (`is_global`), so a DNS answer
//!   cannot turn an allowed name into a local service.
//!
//! `parse_ip` and `is_global` follow Python 3.12's `ipaddress` (`ip_address(s)`, `.is_global`) exactly, including
//! IPv4-mapped IPv6 addresses taking their IPv4 answer and IPv6 scope ids (`fe80::1%en0`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::py;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct EgressError(pub String);

/// Whether the allow list lets `host:port` through. A malformed entry (an unparseable port) refuses: the SDK raises
/// ValueError there, which its proxy turns into a closed connection.
pub fn allowed<S: AsRef<str>>(allow: &[S], host: &str, port: u16) -> bool {
    allowed_checked(allow, host, port).unwrap_or(false)
}

/// `allowed`, with Python's ValueError for a malformed entry surfaced as Err (entries after a match are not read).
pub fn allowed_checked<S: AsRef<str>>(allow: &[S], host: &str, port: u16) -> Result<bool, EgressError> {
    let host = host.to_lowercase();
    let host = host.trim_end_matches('.');
    if parse_ip(host.trim_matches(['[', ']'])).is_some() {
        return Ok(false); // never an IP literal
    }
    for e in allow {
        let (h, p) = split_entry(e.as_ref())?;
        if p != port as i128 {
            continue;
        }
        if h.starts_with("*.") && host.ends_with(&h[1..]) && host != &h[2..] {
            return Ok(true);
        }
        if h == host {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `host[:port]` -> (lowercase host, port); the port is read like Python's `int()`.
fn split_entry(entry: &str) -> Result<(String, i128), EgressError> {
    let e = py::strip(entry).to_lowercase();
    if !entry.contains(':') {
        return Ok((e, 443));
    }
    let (h, p) = e.rsplit_once(':').unwrap_or(("", e.as_str()));
    match py::int(p, 10) {
        Some(port) => Ok((h.to_string(), port)),
        None => Err(EgressError(format!("invalid literal for int() with base 10: {}", py::repr(p)))),
    }
}

/// `ipaddress.ip_address(s)`: strict dotted-quad IPv4 (no leading zeros) or IPv6 (with an optional `%scope`).
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    if let Some(v4) = parse_v4(s) {
        return Some(IpAddr::V4(v4));
    }
    parse_v6(s).map(IpAddr::V6)
}

fn parse_v4(s: &str) -> Option<Ipv4Addr> {
    if s.is_empty() || s.contains('/') {
        return None;
    }
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut b = [0u8; 4];
    for (i, o) in octets.iter().enumerate() {
        if o.is_empty() || !o.bytes().all(|c| c.is_ascii_digit()) || o.len() > 3 || (*o != "0" && o.starts_with('0')) {
            return None;
        }
        b[i] = o.parse::<u16>().ok().filter(|v| *v <= 255)? as u8;
    }
    Some(Ipv4Addr::from(b))
}

fn parse_v6(s: &str) -> Option<Ipv6Addr> {
    if s.contains('/') {
        return None;
    }
    let addr = match s.split_once('%') {
        None => s,
        Some((a, scope)) if !scope.is_empty() && !scope.contains('%') => a,
        Some(_) => return None,
    };
    if addr.is_empty() || addr.chars().count() > 45 {
        return None;
    }
    let mut parts: Vec<String> = addr.split(':').map(str::to_string).collect();
    if parts.len() < 3 {
        return None;
    }
    if parts.last().is_some_and(|p| p.contains('.')) {
        let v4 = u32::from(parse_v4(&parts.pop()?)?);
        parts.push(format!("{:x}", (v4 >> 16) & 0xffff));
        parts.push(format!("{:x}", v4 & 0xffff));
    }
    if parts.len() > 9 {
        return None;
    }
    let mut skip = None;
    for (i, p) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if p.is_empty() {
            if skip.is_some() {
                return None; // at most one '::'
            }
            skip = Some(i);
        }
    }
    let n = parts.len();
    let (hi, lo, skipped) = match skip {
        Some(i) => {
            let (mut hi, mut lo) = (i, n - i - 1);
            if parts[0].is_empty() {
                hi -= 1;
                if hi > 0 {
                    return None;
                }
            }
            if parts[n - 1].is_empty() {
                lo -= 1;
                if lo > 0 {
                    return None;
                }
            }
            if hi + lo >= 8 {
                return None;
            }
            (hi, lo, 8 - hi - lo)
        }
        None => {
            if n != 8 || parts[0].is_empty() || parts[n - 1].is_empty() {
                return None;
            }
            (n, 0, 0)
        }
    };
    let hextet = |h: &str| -> Option<u16> {
        if h.is_empty() || h.len() > 4 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(h, 16).ok()
    };
    let mut v: u128 = 0;
    for p in &parts[..hi] {
        v = (v << 16) | hextet(p)? as u128;
    }
    v = v.checked_shl(16 * skipped as u32).unwrap_or(0);
    for p in &parts[n - lo..] {
        v = (v << 16) | hextet(p)? as u128;
    }
    Some(Ipv6Addr::from(v))
}

const fn net4(a: [u8; 4], len: u32) -> (u32, u32) {
    (u32::from_be_bytes(a), len)
}

fn in4(ip: u32, (net, len): (u32, u32)) -> bool {
    len == 0 || (ip ^ net) >> (32 - len) == 0
}

fn in6(ip: u128, (net, len): (u128, u32)) -> bool {
    len == 0 || (ip ^ net) >> (128 - len) == 0
}

/// Not globally reachable (IANA IPv4 special registry, as Python 3.12.14 lists it).
const V4_PRIVATE: [(u32, u32); 14] = [
    net4([0, 0, 0, 0], 8),
    net4([10, 0, 0, 0], 8),
    net4([127, 0, 0, 0], 8),
    net4([169, 254, 0, 0], 16),
    net4([172, 16, 0, 0], 12),
    net4([192, 0, 0, 0], 24),
    net4([192, 0, 0, 170], 31),
    net4([192, 0, 2, 0], 24),
    net4([192, 168, 0, 0], 16),
    net4([198, 18, 0, 0], 15),
    net4([198, 51, 100, 0], 24),
    net4([203, 0, 113, 0], 24),
    net4([240, 0, 0, 0], 4),
    net4([255, 255, 255, 255], 32),
];
const V4_PRIVATE_EXCEPTIONS: [(u32, u32); 2] = [net4([192, 0, 0, 9], 32), net4([192, 0, 0, 10], 32)];
/// Shared address space (RFC 6598): neither private nor global.
const V4_SHARED: (u32, u32) = net4([100, 64, 0, 0], 10);

const fn net6(a: [u16; 8], len: u32) -> (u128, u32) {
    let mut v: u128 = 0;
    let mut i = 0;
    while i < 8 {
        v = (v << 16) | a[i] as u128;
        i += 1;
    }
    (v, len)
}

/// Not globally reachable (IANA IPv6 special registry, as Python 3.12.14 lists it).
const V6_PRIVATE: [(u128, u32); 11] = [
    net6([0, 0, 0, 0, 0, 0, 0, 1], 128),
    net6([0, 0, 0, 0, 0, 0, 0, 0], 128),
    net6([0, 0, 0, 0, 0, 0xffff, 0, 0], 96),
    net6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
    net6([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
    net6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    net6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
    net6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
    net6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
    net6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    net6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
];
const V6_PRIVATE_EXCEPTIONS: [(u128, u32); 6] = [
    net6([0x2001, 1, 0, 0, 0, 0, 0, 1], 128),
    net6([0x2001, 1, 0, 0, 0, 0, 0, 2], 128),
    net6([0x2001, 3, 0, 0, 0, 0, 0, 0], 32),
    net6([0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48),
    net6([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
    net6([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28),
];

fn v4_is_private(ip: Ipv4Addr) -> bool {
    let x = u32::from(ip);
    V4_PRIVATE.iter().any(|n| in4(x, *n)) && !V4_PRIVATE_EXCEPTIONS.iter().any(|n| in4(x, *n))
}

/// `ipaddress.ip_address(ip).is_global` (Python 3.12.14).
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !in4(u32::from(v4), V4_SHARED) && !v4_is_private(v4),
        IpAddr::V6(v6) => {
            let x = u128::from(v6);
            if x >> 32 == 0xffff {
                return is_global(IpAddr::V4(Ipv4Addr::from(x as u32))); // IPv4-mapped: the IPv4 answer
            }
            !(V6_PRIVATE.iter().any(|n| in6(x, *n)) && !V6_PRIVATE_EXCEPTIONS.iter().any(|n| in6(x, *n)))
        }
    }
}

/// `is_global` of a textual address as `resolve_public` checks it (`sa[0].split("%")[0]`); None if not an address.
pub fn is_global_str(s: &str) -> Option<bool> {
    parse_ip(s.split('%').next().unwrap_or(s)).map(is_global)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_matching() {
        let allow = ["api.example.org", "*.files.example.org:8443"];
        for (host, port, ok) in [
            ("api.example.org", 443, true),
            ("api.example.org", 80, false),
            ("x.files.example.org", 8443, true),
            ("files.example.org", 8443, false),
            ("evil.example.org", 443, false),
            ("127.0.0.1", 443, false),
            ("[::1]", 443, false),
            ("API.Example.org.", 443, true),
            ("a.b.files.example.org", 8443, true),
            ("xfiles.example.org", 8443, false),
        ] {
            assert_eq!(allowed(&allow, host, port), ok, "{host}:{port}");
        }
        assert!(allowed(&[" API.example.org:8080 "], "api.example.org", 8080));
        assert!(allowed(&["h: 4_43 "], "h", 443));
        assert!(allowed(&["localhost:5000"], "localhost", 5000)); // by name; resolve-time checks refuse it
        assert!(!allowed(&["1.2.3.4:443"], "1.2.3.4", 443));
        assert!(!allowed(&["[::1]:443"], "[::1]", 443));
        assert_eq!(allowed_checked(&["h:abc"], "h", 1).unwrap_err().0, "invalid literal for int() with base 10: 'abc'");
        assert!(!allowed(&["h:abc", "h"], "h", 443));
        assert!(allowed(&["h", "h:abc"], "h", 443));
        assert!(!allowed(&["h:"], "h", 443));
        let none: [&str; 0] = [];
        assert!(!allowed(&none, "h", 443));
    }

    #[test]
    fn ip_parsing_matches_python() {
        for ok in ["0.0.0.0", "1.2.3.4", "255.255.255.255", "::", "::1", "1::", "1:2:3:4:5:6:7:8", "::ffff:1.2.3.4",
                   "fe80::1%en0", "1:2:3:4:5:6:1.2.3.4", "1::8", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "ABCD::ef"] {
            assert!(parse_ip(ok).is_some(), "{ok}");
        }
        for bad in ["", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.256", "1.2.3.4/32", "1.2.3.-4", " 1.2.3.4", "1.2.3.4%x",
                    ":", "::1%", "::1%a%b", "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "1::2::3", ":1::", "1:::2",
                    "12345::", "g::", "1:2:3:4:5:6:7:8::", "::1.2.3", "::1/128", "localhost",
                    "0000:0000:0000:0000:0000:0000:0000:00000001"] {
            assert!(parse_ip(bad).is_none(), "{bad}");
        }
        assert_eq!(parse_ip("::ffff:1.2.3.4"), Some("::ffff:1.2.3.4".parse().unwrap()));
        assert_eq!(parse_ip("1:2:3:4:5:6:7::"), Some("1:2:3:4:5:6:7:0".parse().unwrap()));
    }

    #[test]
    fn global_addresses() {
        let g = |s: &str| is_global_str(s).unwrap();
        for public in ["1.1.1.1", "8.8.8.8", "192.0.0.9", "2606:4700::1111", "::ffff:8.8.8.8", "2001:4:112::1", "2001:20::1"] {
            assert!(g(public), "{public}");
        }
        for local in ["127.0.0.1", "10.1.2.3", "100.64.0.1", "100.127.255.255", "169.254.1.1", "172.31.0.1", "192.168.1.1",
                      "0.1.2.3", "240.0.0.1", "255.255.255.255", "192.0.2.1",
                      "::1", "::", "fe80::1%en0", "fc00::1", "fd12::1", "2001:db8::1", "2002::1", "::ffff:127.0.0.1",
                      "64:ff9b:1::1", "3fff::1", "100::1"] {
            assert!(!g(local), "{local}");
        }
        // Python 3.12: multicast is not in the private list, so it counts as global
        assert!(g("224.0.0.1") && g("ff02::1"));
        assert_eq!(is_global_str("nope"), None);
    }
}
