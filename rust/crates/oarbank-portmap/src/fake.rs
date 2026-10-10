//! Fake gateways for tests (feature `fake`, and every unit test): one in-process router with one mapping table,
//! answering NAT-PMP and PCP on a UDP port, SSDP M-SEARCH on another, and UPnP IGD v1 or v2 (device description, SCPD,
//! SOAP control, the IPv6 firewall service) over HTTP, all on loopback. Behaviours a real router shows are switches:
//! conflicts (718), only permanent leases (725, or 402), not authorized (606), the same port required (724),
//! AddAnyPortMapping substitution, listing, lifetime clamping, PCP nonces and `PREFER_FAILURE`, IPv6 pinholes, a
//! reboot that drops every mapping and resets the epoch, address-change announcements, and silence (a router that is
//! down). The router also records every delete, so a test can check that nobody else's mapping was ever deleted.

use crate::{natpmp, pcp};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FakeMapping {
    /// natpmp, pcp, upnp, or "foreign" (another device's, made through UPnP).
    pub proto: String,
    pub external_port: u16,
    pub client: IpAddr,
    pub internal_port: u16,
    pub description: String,
    /// Seconds left; None: permanent.
    pub ttl: Option<u64>,
    #[serde(skip)]
    pub expires: Option<Instant>,
    #[serde(skip)]
    pub nonce: Option<[u8; 12]>,
    /// Made by another device than the one under test.
    pub foreign: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FakePinhole {
    pub id: u16,
    pub client: Ipv6Addr,
    pub port: u16,
    #[serde(skip)]
    pub expires: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Delete {
    pub proto: String,
    pub external_port: u16,
    pub foreign: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(default)]
pub struct FakeConfig {
    pub natpmp: bool,
    pub pcp: bool,
    pub upnp: bool,
    pub igd_v2: bool,
    pub permanent_only: bool,
    /// The error a permanent-only router answers a lease with: 725, or 402 on some devices.
    pub permanent_only_code: u16,
    pub not_authorized: bool,
    pub same_port_required: bool,
    /// Lifetimes are clamped to this.
    pub max_lifetime: u32,
    /// The IPv6 firewall: (enabled, inbound pinholes allowed); None: no firewall service.
    pub firewall: Option<(bool, bool)>,
    /// Answer nothing at all (a router that is down or rebooting).
    pub silent: bool,
    /// UPnP: refuse a mapping for another internal client than the requester (miniupnpd's secure mode).
    pub secure: bool,
}

impl Default for FakeConfig {
    fn default() -> FakeConfig {
        FakeConfig { natpmp: true, pcp: true, upnp: true, igd_v2: true, permanent_only: false, permanent_only_code: 725,
                     not_authorized: false, same_port_required: false, max_lifetime: 86400, firewall: Some((true, true)),
                     silent: false, secure: true }
    }
}

#[derive(Debug)]
pub struct RouterState {
    pub cfg: FakeConfig,
    pub mappings: Vec<FakeMapping>,
    pub pinholes: Vec<FakePinhole>,
    next_pinhole: u16,
    pub external: Ipv4Addr,
    pub epoch_start: Instant,
    /// Shift the epoch's clock (tests that compress time).
    pub epoch_scale: f64,
    pub deletes: Vec<Delete>,
    pub requests: u64,
}

impl RouterState {
    fn new(cfg: FakeConfig) -> RouterState {
        RouterState { cfg, mappings: vec![], pinholes: vec![], next_pinhole: 1, external: Ipv4Addr::new(198, 51, 100, 7),
                      epoch_start: Instant::now(), epoch_scale: 1.0, deletes: vec![], requests: 0 }
    }

    pub fn epoch(&self) -> u32 {
        (self.epoch_start.elapsed().as_secs_f64() * self.epoch_scale) as u32 + 1000
    }

    fn expire(&mut self) {
        let now = Instant::now();
        self.mappings.retain(|m| m.expires.is_none_or(|e| e > now));
        self.pinholes.retain(|p| p.expires > now);
        for m in self.mappings.iter_mut() {
            m.ttl = m.expires.map(|e| e.saturating_duration_since(now).as_secs());
        }
    }

    fn taken_by_other(&self, port: u16, me: &dyn Fn(&FakeMapping) -> bool) -> bool {
        self.mappings.iter().any(|m| m.external_port == port && !me(m))
    }

    fn free_from(&self, start: u16, me: &dyn Fn(&FakeMapping) -> bool) -> u16 {
        let mut p = start.max(1024);
        for _ in 0..60000 {
            if !self.taken_by_other(p, me) {
                return p;
            }
            p = if p == u16::MAX { 1024 } else { p + 1 };
        }
        0
    }

    fn life(&self, l: u32) -> u32 {
        l.min(self.cfg.max_lifetime)
    }

    fn delete_where(&mut self, f: impl Fn(&FakeMapping) -> bool) {
        let (gone, keep): (Vec<FakeMapping>, Vec<FakeMapping>) = self.mappings.drain(..).partition(|m| f(m));
        for m in gone {
            self.deletes.push(Delete { proto: m.proto.clone(), external_port: m.external_port, foreign: m.foreign });
        }
        self.mappings = keep;
    }

    /// The router restarts: every mapping and pinhole is gone and the epoch starts over.
    pub fn reboot(&mut self) {
        self.mappings.clear();
        self.pinholes.clear();
        self.epoch_start = Instant::now();
    }

    /// Another device maps `port` to itself.
    pub fn add_foreign(&mut self, port: u16, client: IpAddr, internal_port: u16, description: &str, ttl: Option<Duration>) {
        self.mappings.retain(|m| m.external_port != port);
        self.mappings.push(FakeMapping { proto: "foreign".into(), external_port: port, client, internal_port,
                                         description: description.into(), ttl: ttl.map(|t| t.as_secs()),
                                         expires: ttl.map(|t| Instant::now() + t), nonce: None, foreign: true });
    }

    pub fn ours(&self) -> Vec<FakeMapping> {
        self.mappings.iter().filter(|m| !m.foreign).cloned().collect()
    }

    fn natpmp(&mut self, b: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        let epoch = self.epoch();
        match b.get(1)? {
            0 => Some(natpmp::external_answer(&natpmp::ExternalAnswer {
                result: if self.cfg.not_authorized { natpmp::ResultCode::NotAuthorized } else { natpmp::ResultCode::Success },
                epoch, external: self.external }).to_vec()),
            2 if b.len() >= 12 => {
                let ip = from.ip();
                let internal = u16::from_be_bytes([b[4], b[5]]);
                let suggested = u16::from_be_bytes([b[6], b[7]]);
                let lifetime = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
                let mut ans = natpmp::MapAnswer { result: natpmp::ResultCode::Success, epoch, internal_port: internal, external_port: 0, lifetime: 0 };
                if self.cfg.not_authorized {
                    ans.result = natpmp::ResultCode::NotAuthorized;
                } else if lifetime == 0 {
                    self.delete_where(|m| m.proto == "natpmp" && m.client == ip && m.internal_port == internal);
                } else {
                    let life = self.life(lifetime);
                    let me = |m: &FakeMapping| m.proto == "natpmp" && m.client == ip && m.internal_port == internal;
                    if let Some(m) = self.mappings.iter_mut().find(|m| me(m)) {
                        m.expires = Some(Instant::now() + Duration::from_secs(life as u64));
                        ans.external_port = m.external_port;
                    } else {
                        let port = self.free_from(if suggested == 0 { internal } else { suggested }, &me);
                        self.mappings.push(FakeMapping { proto: "natpmp".into(), external_port: port, client: ip, internal_port: internal,
                                                         description: String::new(), ttl: Some(life as u64),
                                                         expires: Some(Instant::now() + Duration::from_secs(life as u64)), nonce: None,
                                                         foreign: false });
                        ans.external_port = port;
                    }
                    ans.lifetime = life;
                }
                Some(natpmp::map_answer(&ans).to_vec())
            }
            op => Some(vec![0, 128 + op, 0, 5, 0, 0, 0, 0]),
        }
    }

    fn pcp(&mut self, b: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
        let epoch = self.epoch();
        let err = |opcode: u8, rc: pcp::ResultCode, map: Option<pcp::MapBody>| {
            Some(pcp::encode_response(&pcp::Response { opcode, result: rc, lifetime: 0, epoch, map }))
        };
        if b.len() < 24 {
            return None;
        }
        let op = b[1] & 0x7f;
        if op == pcp::OP_ANNOUNCE {
            return err(op, if self.cfg.not_authorized { pcp::ResultCode::NotAuthorized } else { pcp::ResultCode::Success }, None);
        }
        let Some(r) = pcp::MapRequest::decode(b) else { return err(op, pcp::ResultCode::MalformedRequest, None) };
        let body = |port: u16, ext: IpAddr| Some(pcp::MapBody { nonce: r.nonce, internal_port: r.internal_port, external_port: port, external_ip: ext });
        let src = match from.ip() {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),
            v4 => v4,
        };
        if r.client != src {
            return err(op, pcp::ResultCode::AddressMismatch, body(0, IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        }
        if self.cfg.not_authorized {
            return err(op, pcp::ResultCode::NotAuthorized, body(0, IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        }
        let v6 = r.client.is_ipv6();
        let ext_ip = if v6 { r.client } else { IpAddr::V4(self.external) };
        let me = |m: &FakeMapping| m.proto == "pcp" && m.client == r.client && m.internal_port == r.internal_port;
        let existing = self.mappings.iter().position(|m| me(m));
        if let Some(i) = existing {
            if self.mappings[i].nonce != Some(r.nonce) {
                return err(op, pcp::ResultCode::NotAuthorized, body(0, ext_ip));
            }
        }
        if r.lifetime == 0 {
            if existing.is_some() {
                let (c, p) = (r.client, r.internal_port);
                self.delete_where(|m| m.proto == "pcp" && m.client == c && m.internal_port == p);
            }
            return Some(pcp::encode_response(&pcp::Response { opcode: op, result: pcp::ResultCode::Success, lifetime: 0, epoch,
                                                              map: body(r.suggested_port, ext_ip) }));
        }
        let life = self.life(r.lifetime);
        let port = if let Some(i) = existing {
            self.mappings[i].expires = Some(Instant::now() + Duration::from_secs(life as u64));
            self.mappings[i].external_port
        } else {
            let want = if v6 { r.internal_port } else if r.suggested_port == 0 { r.internal_port } else { r.suggested_port };
            let port = if !v6 && self.taken_by_other(want, &me) {
                if r.prefer_failure {
                    return err(op, pcp::ResultCode::CannotProvideExternal, body(0, ext_ip));
                }
                self.free_from(want, &me)
            } else {
                want
            };
            self.mappings.push(FakeMapping { proto: "pcp".into(), external_port: port, client: r.client, internal_port: r.internal_port,
                                             description: String::new(), ttl: Some(life as u64),
                                             expires: Some(Instant::now() + Duration::from_secs(life as u64)), nonce: Some(r.nonce),
                                             foreign: false });
            port
        };
        Some(pcp::encode_response(&pcp::Response { opcode: op, result: pcp::ResultCode::Success, lifetime: life, epoch, map: body(port, ext_ip) }))
    }

    fn soap(&mut self, action: &str, body: &str, peer: IpAddr) -> Result<String, (u16, &'static str)> {
        use crate::upnp::tag;
        let arg = |n: &str| tag(body, n).unwrap_or_default();
        let num = |n: &str| arg(n).trim().parse::<u32>().unwrap_or(0);
        let auth = |s: &RouterState| if s.cfg.not_authorized { Err((606, "Action not authorized")) } else { Ok(()) };
        match action {
            "GetExternalIPAddress" => Ok(format!("<NewExternalIPAddress>{}</NewExternalIPAddress>", self.external)),
            "AddPortMapping" | "AddAnyPortMapping" => {
                auth(self)?;
                if action == "AddAnyPortMapping" && !self.cfg.igd_v2 {
                    return Err((401, "Invalid Action"));
                }
                let ext = num("NewExternalPort") as u16;
                let internal = num("NewInternalPort") as u16;
                let client: IpAddr = arg("NewInternalClient").trim().parse().map_err(|_| (402, "Invalid Args"))?;
                let lease = num("NewLeaseDuration");
                if self.cfg.secure && client != peer {
                    return Err((606, "Action not authorized"));
                }
                if internal < 1 || (action == "AddPortMapping" && ext < 1) {
                    return Err((716, "WildCardNotPermittedInExtPort"));
                }
                if self.cfg.same_port_required && ext != internal {
                    return Err((724, "SamePortValuesRequired"));
                }
                if self.cfg.permanent_only && lease != 0 {
                    return Err(if self.cfg.permanent_only_code == 402 { (402, "Invalid Args") } else { (725, "OnlyPermanentLeasesSupported") });
                }
                if self.cfg.igd_v2 && lease > 604800 {
                    return Err((402, "Invalid Args"));
                }
                let desc = arg("NewPortMappingDescription");
                let me = |m: &FakeMapping| m.proto == "upnp" && m.client == client;
                let port = if self.taken_by_other(ext, &me) {
                    if action == "AddPortMapping" {
                        return Err((718, "ConflictInMappingEntry"));
                    }
                    self.free_from(ext.max(1024), &me)
                } else {
                    ext
                };
                self.mappings.retain(|m| !(m.external_port == port && m.proto == "upnp" && m.client == client));
                let life = if lease == 0 { None } else { Some(Duration::from_secs(lease as u64)) };
                self.mappings.push(FakeMapping { proto: "upnp".into(), external_port: port, client, internal_port: internal, description: desc,
                                                 ttl: life.map(|l| l.as_secs()), expires: life.map(|l| Instant::now() + l), nonce: None,
                                                 foreign: false });
                Ok(if action == "AddAnyPortMapping" { format!("<NewReservedPort>{port}</NewReservedPort>") } else { String::new() })
            }
            "DeletePortMapping" => {
                auth(self)?;
                let ext = num("NewExternalPort") as u16;
                if !self.mappings.iter().any(|m| m.external_port == ext) {
                    return Err((714, "NoSuchEntryInArray"));
                }
                self.delete_where(|m| m.external_port == ext);
                Ok(String::new())
            }
            "GetSpecificPortMappingEntry" => {
                let ext = num("NewExternalPort") as u16;
                let m = self.mappings.iter().find(|m| m.external_port == ext).ok_or((714, "NoSuchEntryInArray"))?;
                Ok(entry_xml(m, false))
            }
            "GetGenericPortMappingEntry" => {
                let i = num("NewPortMappingIndex") as usize;
                let m = self.mappings.get(i).ok_or((713, "SpecifiedArrayIndexInvalid"))?;
                Ok(entry_xml(m, true))
            }
            "GetFirewallStatus" => {
                let (on, inbound) = self.cfg.firewall.ok_or((401, "Invalid Action"))?;
                Ok(format!("<FirewallEnabled>{}</FirewallEnabled><InboundPinholeAllowed>{}</InboundPinholeAllowed>", on as u8, inbound as u8))
            }
            "AddPinhole" => {
                auth(self)?;
                let (_, inbound) = self.cfg.firewall.ok_or((401, "Invalid Action"))?;
                if !inbound {
                    return Err((703, "InboundPinholeNotAllowed"));
                }
                let client: Ipv6Addr = arg("InternalClient").trim().parse().map_err(|_| (402, "Invalid Args"))?;
                let port = num("InternalPort") as u16;
                let lease = num("LeaseTime").clamp(1, 86400);
                let id = self.next_pinhole;
                self.next_pinhole = self.next_pinhole.wrapping_add(1).max(1);
                self.pinholes.push(FakePinhole { id, client, port, expires: Instant::now() + Duration::from_secs(lease as u64) });
                Ok(format!("<UniqueID>{id}</UniqueID>"))
            }
            "UpdatePinhole" => {
                let id = num("UniqueID") as u16;
                let lease = num("NewLeaseTime").clamp(1, 86400);
                let p = self.pinholes.iter_mut().find(|p| p.id == id).ok_or((704, "NoSuchEntry"))?;
                p.expires = Instant::now() + Duration::from_secs(lease as u64);
                Ok(String::new())
            }
            "DeletePinhole" => {
                let id = num("UniqueID") as u16;
                if !self.pinholes.iter().any(|p| p.id == id) {
                    return Err((704, "NoSuchEntry"));
                }
                self.pinholes.retain(|p| p.id != id);
                self.deletes.push(Delete { proto: "pinhole".into(), external_port: id, foreign: false });
                Ok(String::new())
            }
            "CheckPinholeWorking" => {
                let id = num("UniqueID") as u16;
                self.pinholes.iter().find(|p| p.id == id).ok_or((704, "NoSuchEntry"))?;
                Ok("<IsWorking>1</IsWorking>".into())
            }
            _ => Err((401, "Invalid Action")),
        }
    }
}

fn entry_xml(m: &FakeMapping, with_port: bool) -> String {
    let ext = if with_port { format!("<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>TCP</NewProtocol>", m.external_port) }
              else { String::new() };
    format!("{ext}<NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>{}</NewPortMappingDescription><NewLeaseDuration>{}</NewLeaseDuration>",
            m.internal_port, m.client, xml_escape(&m.description), m.ttl.unwrap_or(0))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// A running fake gateway.
pub struct FakeGateway {
    pub state: Arc<Mutex<RouterState>>,
    /// NAT-PMP and PCP (UDP).
    pub pmp: SocketAddr,
    /// PCP over IPv6 on [::1] (when the host has IPv6 loopback).
    pub pcp_v6: Option<SocketAddr>,
    /// SSDP (UDP).
    pub ssdp: SocketAddr,
    /// The device's HTTP server.
    pub http: SocketAddr,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for FakeGateway {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

fn lock(s: &Arc<Mutex<RouterState>>) -> std::sync::MutexGuard<'_, RouterState> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

impl FakeGateway {
    pub async fn start(cfg: FakeConfig) -> std::io::Result<FakeGateway> {
        let state = Arc::new(Mutex::new(RouterState::new(cfg)));
        let pmp_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
        let pmp = pmp_sock.local_addr()?;
        let v6_sock = tokio::net::UdpSocket::bind("[::1]:0").await.ok().map(Arc::new);
        let pcp_v6 = v6_sock.as_ref().and_then(|s| s.local_addr().ok());
        let ssdp_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
        let ssdp = ssdp_sock.local_addr()?;
        let http_l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let http = http_l.local_addr()?;
        let mut tasks = vec![];
        for sock in std::iter::once(pmp_sock).chain(v6_sock) {
            let st = state.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = [0u8; 1100];
                while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                    let reply = {
                        let mut s = lock(&st);
                        s.expire();
                        s.requests += 1;
                        if s.cfg.silent {
                            None
                        } else {
                            match buf[0] {
                                0 if s.cfg.natpmp => s.natpmp(&buf[..n], from),
                                2 if s.cfg.pcp => s.pcp(&buf[..n], from),
                                2 if s.cfg.natpmp => Some(vec![0, 128 + (buf[1] & 0x7f), 0, 1, 0, 0, 0, 0]),
                                _ => None,
                            }
                        }
                    };
                    if let Some(r) = reply {
                        let _ = sock.send_to(&r, from).await;
                    }
                }
            }));
        }
        {
            let st = state.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                while let Ok((n, from)) = ssdp_sock.recv_from(&mut buf).await {
                    let (silent, upnp, v2) = { let s = lock(&st); (s.cfg.silent, s.cfg.upnp, s.cfg.igd_v2) };
                    if silent || !upnp || !String::from_utf8_lossy(&buf[..n]).contains("M-SEARCH") {
                        continue;
                    }
                    let msg = format!("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:{}\r\n\
                                       USN: uuid:00000000-0000-0000-0000-00000000fake::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                                       EXT:\r\nSERVER: fake/1.0 UPnP/1.1\r\nLOCATION: http://{http}/rootDesc.xml\r\n\r\n", if v2 { 2 } else { 1 });
                    let _ = ssdp_sock.send_to(msg.as_bytes(), from).await;
                }
            }));
        }
        {
            let st = state.clone();
            tasks.push(tokio::spawn(async move {
                while let Ok((s, peer)) = http_l.accept().await {
                    let st = st.clone();
                    tokio::spawn(async move {
                        let _ = serve_http(s, peer, st).await;
                    });
                }
            }));
        }
        Ok(FakeGateway { state, pmp, pcp_v6, ssdp, http, tasks })
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut RouterState) -> T) -> T {
        let mut s = lock(&self.state);
        s.expire();
        f(&mut s)
    }

    pub fn reboot(&self) {
        self.with(|s| s.reboot());
    }

    /// Change the external address and send a NAT-PMP announcement to `to` (the agent's announcement socket).
    pub async fn set_external(&self, ip: Ipv4Addr, to: Option<SocketAddr>) {
        let (epoch, msg) = self.with(|s| {
            s.external = ip;
            let e = s.epoch();
            (e, natpmp::external_answer(&natpmp::ExternalAnswer { result: natpmp::ResultCode::Success, epoch: e, external: ip }))
        });
        let _ = epoch;
        if let Some(to) = to {
            if let Ok(sock) = tokio::net::UdpSocket::bind("127.0.0.1:0").await {
                let _ = sock.send_to(&msg, to).await;
            }
        }
    }

    pub fn target(&self) -> crate::router::Target {
        crate::router::Target::Fixed { pmp: Some(self.pmp), ssdp: Some(self.ssdp), pcp_v6: self.pcp_v6 }
    }

    /// Every delete of another device's mapping (must stay empty).
    pub fn foreign_deletes(&self) -> Vec<Delete> {
        self.with(|s| s.deletes.iter().filter(|d| d.foreign).cloned().collect())
    }
}

async fn serve_http(mut s: tokio::net::TcpStream, peer: SocketAddr, st: Arc<Mutex<RouterState>>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 65536 {
            return Ok(());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let len = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..]).to_string();
    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
    let (silent, v2, fw) = { let g = lock(&st); (g.cfg.silent, g.cfg.igd_v2, g.cfg.firewall.is_some()) };
    if silent {
        return Ok(());
    }
    let v = if v2 { 2 } else { 1 };
    let (status, text) = match path.as_str() {
        "/rootDesc.xml" => (200, root_desc(v, fw)),
        "/WANIPCn.xml" => (200, scpd(v2)),
        "/WANIP6FC.xml" => (200, scpd_fw()),
        p if p.starts_with("/ctl/") => {
            let action = head.lines().find_map(|l| {
                let low = l.to_ascii_lowercase();
                low.starts_with("soapaction:").then(|| l.split('#').nth(1).unwrap_or("").trim_matches(|c| c == '"' || c == ' ').to_string())
            }).unwrap_or_default();
            let service = if p == "/ctl/IP6FCtl" { "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1".to_string() }
                          else { format!("urn:schemas-upnp-org:service:WANIPConnection:{v}") };
            let r = { let mut g = lock(&st); g.expire(); g.requests += 1; g.soap(&action, &body, peer.ip()) };
            match r {
                Ok(inner) => (200, format!("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
                    s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action}Response xmlns:u=\"{service}\">{inner}\
                    </u:{action}Response></s:Body></s:Envelope>")),
                Err((code, d)) => (500, format!("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
                    s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><s:Fault><faultcode>s:Client</faultcode>\
                    <faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode>\
                    <errorDescription>{d}</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>")),
            }
        }
        _ => (404, String::new()),
    };
    let reason = match status { 200 => "OK", 500 => "Internal Server Error", _ => "Not Found" };
    let resp = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                       text.len());
    s.write_all(resp.as_bytes()).await?;
    s.shutdown().await
}

fn root_desc(v: u8, fw: bool) -> String {
    let fw_service = if fw {
        "<service><serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPv6Firewall1</serviceId>\
         <controlURL>/ctl/IP6FCtl</controlURL><eventSubURL>/evt/IP6FCtl</eventSubURL><SCPDURL>/WANIP6FC.xml</SCPDURL></service>"
    } else { "" };
    format!("<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\"><specVersion><major>1</major><minor>1</minor></specVersion>\
        <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:{v}</deviceType><friendlyName>Fake gateway</friendlyName>\
        <UDN>uuid:00000000-0000-0000-0000-00000000fake</UDN><serviceList></serviceList><deviceList>\
        <device><deviceType>urn:schemas-upnp-org:device:WANDevice:{v}</deviceType><UDN>uuid:fake-wan</UDN><serviceList></serviceList><deviceList>\
        <device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:{v}</deviceType><UDN>uuid:fake-wanconn</UDN><serviceList>\
        <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:{v}</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>\
        <controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL><SCPDURL>/WANIPCn.xml</SCPDURL></service>{fw_service}\
        </serviceList></device></deviceList></device></deviceList></device></root>")
}

fn action(name: &str, ins: &[&str]) -> String {
    let args: String = ins.iter().map(|a| format!("<argument><name>{a}</name><direction>in</direction><relatedStateVariable>X</relatedStateVariable></argument>")).collect();
    format!("<action><name>{name}</name><argumentList>{args}</argumentList></action>")
}

fn scpd(v2: bool) -> String {
    let add = ["NewRemoteHost", "NewExternalPort", "NewProtocol", "NewInternalPort", "NewInternalClient", "NewEnabled",
               "NewPortMappingDescription", "NewLeaseDuration"];
    let mut actions = vec![
        action("AddPortMapping", &add),
        action("DeletePortMapping", &["NewRemoteHost", "NewExternalPort", "NewProtocol"]),
        action("GetExternalIPAddress", &[]),
        action("GetGenericPortMappingEntry", &["NewPortMappingIndex"]),
        action("GetSpecificPortMappingEntry", &["NewRemoteHost", "NewExternalPort", "NewProtocol"]),
    ];
    if v2 {
        actions.push(action("AddAnyPortMapping", &add));
    }
    format!("<?xml version=\"1.0\"?><scpd xmlns=\"urn:schemas-upnp-org:service-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion>\
             <actionList>{}</actionList><serviceStateTable></serviceStateTable></scpd>", actions.join(""))
}

fn scpd_fw() -> String {
    format!("<?xml version=\"1.0\"?><scpd xmlns=\"urn:schemas-upnp-org:service-1-0\"><actionList>{}{}{}{}{}</actionList></scpd>",
            action("GetFirewallStatus", &[]), action("AddPinhole", &["RemoteHost", "RemotePort", "InternalClient", "InternalPort", "Protocol", "LeaseTime"]),
            action("UpdatePinhole", &["UniqueID", "NewLeaseTime"]), action("DeletePinhole", &["UniqueID"]), action("CheckPinholeWorking", &["UniqueID"]))
}
