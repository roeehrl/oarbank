//! UPnP IGD v1 and v2 through igd-next (discovery by SSDP, the device description, SOAP control), plus the actions it
//! lacks, sent on its own request path: `GetSpecificPortMappingEntry` (the read-back every verify and every delete
//! rests on: the agent deletes only an entry whose internal client and description are its own) and
//! `CheckPinholeWorking`.
//!
//! The agent is a control point only: it sends one M-SEARCH from an ephemeral port, never answers SSDP and never
//! subscribes to events (CallStranger was the event callbacks).

use igd_next::aio::tokio::Tokio;
use igd_next::aio::{Gateway, Provider};
use igd_next::{PortMappingProtocol, RequestError, SearchOptions};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

/// The standard SSDP target.
pub const SSDP: &str = "239.255.255.250:1900";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A UPnP error code from the device (718 conflict, 725 only permanent leases, 606 not authorized, …).
    #[error("UPnP error {0}: {1}")]
    Code(u16, String),
    #[error("the gateway does not offer {0}")]
    Unsupported(String),
    #[error("no UPnP gateway answered")]
    NotFound,
    #[error("UPnP: {0}")]
    Transport(String),
}

impl Error {
    pub fn code(&self) -> Option<u16> {
        match self {
            Error::Code(c, _) => Some(*c),
            _ => None,
        }
    }
}

fn from_request(e: RequestError) -> Error {
    match e {
        RequestError::ErrorCode(c, d) => Error::Code(c, d),
        RequestError::UnsupportedAction(a) => Error::Unsupported(a),
        e => Error::Transport(e.to_string()),
    }
}

/// One port mapping entry as the device reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub external_port: u16,
    pub protocol: String,
    pub internal_client: String,
    pub internal_port: u16,
    pub description: String,
    pub enabled: bool,
    pub lease: u32,
}

/// A discovered Internet Gateway Device.
#[derive(Debug, Clone)]
pub struct Upnp {
    pub gw: Gateway<Tokio>,
}

/// Search for a gateway: one M-SEARCH to `target` (the standard multicast address, or a fake gateway's address in
/// tests) from `bind`, answers trusted only from the responder's own address.
pub async fn discover(target: SocketAddr, bind: IpAddr, timeout: Duration) -> Result<Upnp, Error> {
    let mut o = SearchOptions::default();
    o.bind_addr = SocketAddr::new(bind, 0);
    o.broadcast_address = target;
    o.timeout = Some(timeout);
    o.single_search_timeout = Some(timeout);
    if target.ip().is_loopback() {
        // a fake gateway on loopback (tests): igd-next trusts a loopback device only when named
        o.allowed_gateway_ips = vec![target.ip()];
    }
    match igd_next::aio::tokio::search_gateway(o).await {
        Ok(gw) => Ok(Upnp { gw }),
        Err(igd_next::SearchError::NoResponseWithinTimeout) => Err(Error::NotFound),
        Err(e) => Err(Error::Transport(e.to_string())),
    }
}

pub(crate) fn tag(xml: &str, name: &str) -> Option<String> {
    // a SOAP element may carry a namespace prefix (`<u:NewInternalClient>`): match on the local name
    let mut from = 0;
    while let Some(i) = xml[from..].find('<') {
        let start = from + i + 1;
        let end = start + xml[start..].find('>')?;
        let head = &xml[start..end];
        let local = head.split_whitespace().next().unwrap_or("").rsplit(':').next().unwrap_or("");
        if local == name && !head.starts_with('/') {
            if head.ends_with('/') {
                return Some(String::new());
            }
            let rest = &xml[end + 1..];
            let close = rest.find("</")?;
            return Some(unescape(&rest[..close]));
        }
        from = end;
    }
    None
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// A SOAP fault's UPnP error code and description, if the answer is one.
fn fault(xml: &str) -> Option<Error> {
    let code = tag(xml, "errorCode")?.trim().parse::<u16>().ok()?;
    Some(Error::Code(code, tag(xml, "errorDescription").unwrap_or_default()))
}

const HEAD: &str = r#"<?xml version="1.0"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>"#;
const TAIL: &str = "</s:Body>\n</s:Envelope>";
const FIREWALL: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";

fn control_url(addr: SocketAddr, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("http://{addr}{}{path}", if path.starts_with('/') { "" } else { "/" })
    }
}

impl Upnp {
    /// "IGD:2" when the WAN connection service is version 2 (AddAnyPortMapping, lease limits), else "IGD:1".
    pub fn version(&self) -> &'static str {
        if self.gw.service_type.ends_with(":2") || self.gw.control_schema.contains_key("AddAnyPortMapping") {
            "IGD:2"
        } else {
            "IGD:1"
        }
    }

    pub fn has_firewall(&self) -> bool {
        self.gw.ipv6_firewall_control_url.is_some()
    }

    /// The device's HTTP address (where its control URLs live).
    pub fn addr(&self) -> SocketAddr {
        self.gw.addr
    }

    async fn call(&self, service: &str, url: &str, action: &str, args: &str) -> Result<String, Error> {
        let body = format!("{HEAD}<u:{action} xmlns:u=\"{service}\">{args}</u:{action}>{TAIL}");
        let header = format!("\"{service}#{action}\"");
        let text = Tokio::send_async(url, &header, &body).await.map_err(from_request)?;
        if let Some(f) = fault(&text) {
            return Err(f);
        }
        if !text.contains(&format!("{action}Response")) {
            return Err(Error::Transport(format!("{action}: an answer that is not its response")));
        }
        Ok(text)
    }

    pub async fn external_ip(&self) -> Result<IpAddr, Error> {
        self.gw.get_external_ip().await.map_err(|e| match e {
            igd_next::GetExternalIpError::ActionNotAuthorized => Error::Code(606, "Action not authorized".into()),
            igd_next::GetExternalIpError::RequestError(r) => from_request(r),
        })
    }

    /// AddPortMapping. A device that takes only permanent mappings (725, or 402 for a lease it will not take) gets lease
    /// 0; the answer says so (`permanent`).
    pub async fn add(&self, external: u16, internal: SocketAddr, lease: u32, description: &str) -> Result<bool, Error> {
        match self.add_once(external, internal, lease, description).await {
            Err(Error::Code(725 | 402, _)) if lease != 0 => self.add_once(external, internal, 0, description).await.map(|_| true),
            r => r.map(|_| lease == 0),
        }
    }

    async fn add_once(&self, external: u16, internal: SocketAddr, lease: u32, description: &str) -> Result<(), Error> {
        use igd_next::AddPortError as E;
        self.gw.add_port(PortMappingProtocol::TCP, external, internal, lease, description).await.map_err(|e| match e {
            E::ActionNotAuthorized => Error::Code(606, "Action not authorized".into()),
            E::PortInUse => Error::Code(718, "ConflictInMappingEntry".into()),
            E::SamePortValuesRequired => Error::Code(724, "SamePortValuesRequired".into()),
            E::OnlyPermanentLeasesSupported => Error::Code(725, "OnlyPermanentLeasesSupported".into()),
            E::DescriptionTooLong => Error::Code(605, "String argument too long".into()),
            E::ExternalPortZeroInvalid | E::InternalPortZeroInvalid => Error::Code(716, "port zero".into()),
            E::RequestError(r) => from_request(r),
        })
    }

    /// AddAnyPortMapping (IGDv2; igd-next falls back to AddPortMapping with random ports on IGDv1): the port the
    /// device chose, and whether the mapping is permanent.
    pub async fn add_any(&self, internal: SocketAddr, lease: u32, description: &str) -> Result<(u16, bool), Error> {
        use igd_next::AddAnyPortError as E;
        let once = |lease: u32| async move {
            self.gw.add_any_port(PortMappingProtocol::TCP, internal, lease, description).await.map_err(|e| match e {
                E::ActionNotAuthorized => Error::Code(606, "Action not authorized".into()),
                E::NoPortsAvailable | E::ExternalPortInUse => Error::Code(728, "NoPortMapsAvailable".into()),
                E::OnlyPermanentLeasesSupported => Error::Code(725, "OnlyPermanentLeasesSupported".into()),
                E::DescriptionTooLong => Error::Code(605, "String argument too long".into()),
                E::InternalPortZeroInvalid => Error::Code(716, "port zero".into()),
                E::RequestError(r) => from_request(r),
            })
        };
        match once(lease).await {
            Err(Error::Code(725 | 402, _)) if lease != 0 => once(0).await.map(|p| (p, true)),
            r => r.map(|p| (p, lease == 0)),
        }
    }

    /// GetSpecificPortMappingEntry for TCP `external` (None: no such entry, 714).
    pub async fn get_specific(&self, external: u16) -> Result<Option<Entry>, Error> {
        let url = control_url(self.gw.addr, &self.gw.control_url);
        let args = format!("<NewRemoteHost></NewRemoteHost><NewExternalPort>{external}</NewExternalPort><NewProtocol>TCP</NewProtocol>");
        match self.call(&self.gw.service_type, &url, "GetSpecificPortMappingEntry", &args).await {
            Err(Error::Code(714, _)) => Ok(None),
            Err(e) => Err(e),
            Ok(t) => Ok(Some(Entry {
                external_port: external,
                protocol: "TCP".into(),
                internal_client: tag(&t, "NewInternalClient").unwrap_or_default(),
                internal_port: tag(&t, "NewInternalPort").and_then(|p| p.trim().parse().ok()).unwrap_or(0),
                description: tag(&t, "NewPortMappingDescription").unwrap_or_default(),
                enabled: tag(&t, "NewEnabled").is_none_or(|e| e.trim() == "1" || e.trim().eq_ignore_ascii_case("true")),
                lease: tag(&t, "NewLeaseDuration").and_then(|p| p.trim().parse().ok()).unwrap_or(0),
            })),
        }
    }

    /// DeletePortMapping for TCP `external` (an entry already gone, 714, is not an error). Callers read the entry back
    /// first and delete only their own (see `delete_own`).
    async fn delete(&self, external: u16) -> Result<(), Error> {
        use igd_next::RemovePortError as E;
        match self.gw.remove_port(PortMappingProtocol::TCP, external).await {
            Ok(()) | Err(E::NoSuchPortMapping) => Ok(()),
            Err(E::ActionNotAuthorized) => Err(Error::Code(606, "Action not authorized".into())),
            Err(E::RequestError(r)) => Err(from_request(r)),
        }
    }

    /// Delete TCP `external` only if the device says it is ours: our internal client and our description. Returns
    /// whether something was deleted (false: absent, or someone else's, which is left alone).
    pub async fn delete_own(&self, external: u16, internal_client: IpAddr, description: &str) -> Result<bool, Error> {
        match self.get_specific(external).await? {
            Some(e) if is_ours(&e, internal_client, description) => self.delete(external).await.map(|_| true),
            _ => Ok(false),
        }
    }

    /// Every TCP entry the device lists (GetGenericPortMappingEntry by index), at most `max`.
    pub async fn list(&self, max: u32) -> Result<Vec<Entry>, Error> {
        use igd_next::GetGenericPortMappingEntryError as E;
        let mut out = vec![];
        for i in 0..max {
            match self.gw.get_generic_port_mapping_entry(i).await {
                Ok(e) => out.push(Entry { external_port: e.external_port, protocol: e.protocol.to_string(),
                                          internal_client: e.internal_client, internal_port: e.internal_port,
                                          description: e.port_mapping_description, enabled: e.enabled, lease: e.lease_duration }),
                Err(E::SpecifiedArrayIndexInvalid) => break,
                Err(E::RequestError(RequestError::ErrorCode(713, _))) => break,
                Err(E::ActionNotAuthorized) => return Err(Error::Code(606, "Action not authorized".into())),
                Err(E::RequestError(r)) => {
                    if out.is_empty() {
                        return Err(from_request(r));
                    }
                    break;
                }
            }
        }
        Ok(out)
    }

    /// The IPv6 firewall's state: (enabled, inbound pinholes allowed); None without the service.
    pub async fn firewall_status(&self) -> Result<Option<(bool, bool)>, Error> {
        if !self.has_firewall() {
            return Ok(None);
        }
        match self.gw.get_firewall_status().await {
            Ok(s) => Ok(Some((s.firewall_enabled, s.inbound_pinhole_allowed))),
            Err(e) => Err(pinhole_err(e)),
        }
    }

    pub async fn add_pinhole(&self, internal: SocketAddrV6, lease: u32) -> Result<u16, Error> {
        self.gw.add_pinhole(PortMappingProtocol::TCP, internal, lease.clamp(1, 86400)).await.map_err(pinhole_err)
    }

    pub async fn update_pinhole(&self, id: u16, lease: u32) -> Result<(), Error> {
        self.gw.update_pinhole(id, lease.clamp(1, 86400)).await.map_err(pinhole_err)
    }

    pub async fn delete_pinhole(&self, id: u16) -> Result<(), Error> {
        match self.gw.remove_pinhole(id).await {
            Err(igd_next::PinholeError::NoSuchEntry) => Ok(()),
            r => r.map_err(pinhole_err),
        }
    }

    /// CheckPinholeWorking: is the pinhole still there (None: the device cannot tell).
    pub async fn check_pinhole(&self, id: u16) -> Result<Option<bool>, Error> {
        let Some(path) = self.gw.ipv6_firewall_control_url.clone() else { return Ok(None) };
        let url = control_url(self.gw.addr, &path);
        match self.call(FIREWALL, &url, "CheckPinholeWorking", &format!("<UniqueID>{id}</UniqueID>")).await {
            Ok(t) => Ok(tag(&t, "IsWorking").map(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))),
            Err(Error::Code(704, _)) => Ok(Some(false)),              // NoSuchEntry
            Err(Error::Code(401 | 602, _)) | Err(Error::Unsupported(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn pinhole_err(e: igd_next::PinholeError) -> Error {
    use igd_next::PinholeError as P;
    match e {
        P::FirewallControlUnavailable => Error::Unsupported("WANIPv6FirewallControl".into()),
        P::InvalidLeaseDuration => Error::Code(402, "Invalid lease".into()),
        P::ActionNotAuthorized => Error::Code(606, "Action not authorized".into()),
        P::PinholeSpaceExhausted => Error::Code(701, "PinholeSpaceExhausted".into()),
        P::FirewallDisabled => Error::Code(702, "FirewallDisabled".into()),
        P::InboundPinholeNotAllowed => Error::Code(703, "InboundPinholeNotAllowed".into()),
        P::NoSuchEntry => Error::Code(704, "NoSuchEntry".into()),
        P::RequestError(r) => from_request(r),
    }
}

/// An entry is ours when its internal client is our address and its description is ours.
pub fn is_ours(e: &Entry, internal_client: IpAddr, description: &str) -> bool {
    e.description == description && e.internal_client.trim().parse::<IpAddr>().ok() == Some(internal_client)
}

/// The SSDP target as a socket address (the standard one unless overridden).
pub fn ssdp_target(over: Option<SocketAddr>) -> SocketAddr {
    over.unwrap_or_else(|| SSDP.parse().unwrap_or(SocketAddr::from((Ipv4Addr::new(239, 255, 255, 250), 1900))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn soap_answers_are_read_by_local_name() {
        let t = r#"<s:Envelope><s:Body><u:GetSpecificPortMappingEntryResponse xmlns:u="x"><NewInternalPort>41000</NewInternalPort>
            <NewInternalClient>192.168.1.20</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>oarbank:ab:m/l &amp; x</NewPortMappingDescription>
            <NewLeaseDuration>3500</NewLeaseDuration></u:GetSpecificPortMappingEntryResponse></s:Body></s:Envelope>"#;
        assert_eq!(tag(t, "NewInternalClient").as_deref(), Some("192.168.1.20"));
        assert_eq!(tag(t, "NewPortMappingDescription").as_deref(), Some("oarbank:ab:m/l & x"));
        assert_eq!(tag(t, "Missing"), None);
        let f = r#"<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode><errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"#;
        assert_eq!(fault(f), Some(Error::Code(718, "ConflictInMappingEntry".into())));
        assert_eq!(fault(t), None);
    }

    #[test]
    fn ours_means_our_client_and_our_description() {
        let e = Entry { external_port: 9000, protocol: "TCP".into(), internal_client: "192.168.1.20".into(), internal_port: 41000,
                        description: "oarbank:ab:m/l".into(), enabled: true, lease: 3600 };
        let me: IpAddr = "192.168.1.20".parse().unwrap();
        assert!(is_ours(&e, me, "oarbank:ab:m/l"));
        assert!(!is_ours(&e, "192.168.1.21".parse().unwrap(), "oarbank:ab:m/l"));
        assert!(!is_ours(&e, me, "oarbank:ab:m/other"));
    }
}
