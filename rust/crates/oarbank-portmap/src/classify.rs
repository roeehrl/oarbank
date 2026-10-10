//! Reachability as the owner reads it (docs/design/inbound-listeners.md, "Reachability and the doctor"): one result,
//! some flags, the sentence that says what is going on and the concrete fix. The console, the CLI and the heartbeat all
//! show these words, so they live in one place.

use crate::addr::{is_global, scope, Scope};
use crate::manager::Unmappable;
use crate::types::{Mode, Proto};
use std::net::{IpAddr, SocketAddr};

/// The latest dial-back.
#[derive(Debug, Clone, PartialEq)]
pub enum Dialback {
    Reachable { via: String, at: f64 },
    Unreachable { via: String, at: f64, detail: Option<String> },
    /// No node on another network and no probe endpoint.
    NoProber,
}

/// Everything the classification looks at.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub mode: Option<Mode>,
    /// The external port asked for (or got).
    pub port: u16,
    /// This node's address and the listener's internal port.
    pub internal: Option<SocketAddr>,
    /// The address on the default route is a public one (no NAT on this host).
    pub interface_public: bool,
    /// The mapping's state (`manager::Status::state`).
    pub map_state: String,
    pub protocol: Option<Proto>,
    pub unmappable: Option<Unmappable>,
    /// Who holds the port, as the router says.
    pub holder: Option<String>,
    pub gateway_external: Option<IpAddr>,
    pub observed: Option<IpAddr>,
    pub external: Option<SocketAddr>,
    pub dialback: Option<Dialback>,
    /// The local firewall does not let the agent accept connections (None: unknown).
    pub firewall_blocks: Option<bool>,
    /// Seconds since the external address last changed, when it changed in the last 30 days.
    pub address_changed_ago_s: Option<f64>,
    pub permanent_only_router: bool,
    pub renewed_ago_s: Option<f64>,
    /// IPv6: the listener's global address (with port), whether it is reachable or the router would need a pinhole.
    pub v6: Option<V6>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct V6 {
    pub address: SocketAddr,
    /// mapped (a pinhole opened), not_needed (no firewall), unmappable (no way to open one), or another lifecycle state.
    pub state: String,
    pub reachable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub result: &'static str,
    pub flags: Vec<&'static str>,
    pub text: String,
    pub fix: Option<String>,
}

fn ago(s: f64) -> String {
    let s = s.max(0.0);
    if s < 90.0 {
        "just now".into()
    } else if s < 5400.0 {
        format!("{} minutes ago", (s / 60.0).round() as u64)
    } else if s < 129_600.0 {
        format!("{} hours ago", (s / 3600.0).round() as u64)
    } else {
        format!("{} days ago", (s / 86400.0).round() as u64)
    }
}

pub fn classify(i: &Inputs) -> Outcome {
    let port = i.port;
    let ext = i.external.map(|e| e.to_string()).unwrap_or_else(|| format!("port {port}"));
    let me = i.internal.map(|a| format!("{} (port {})", a.ip(), a.port())).unwrap_or_else(|| "this machine".into());
    let by = i.protocol.map(|p| format!("mapped by {}", p.label()));
    let mut flags = vec![];
    if let Some(a) = i.address_changed_ago_s {
        flags.push("DYNAMIC_ADDRESS");
        let _ = a;
    }
    if i.permanent_only_router {
        flags.push("PERMANENT_ONLY_ROUTER");
    }
    if let Some(v6) = &i.v6 {
        match (v6.reachable, v6.state.as_str()) {
            (Some(true), _) => flags.push("IPV6_REACHABLE"),
            (_, "unmappable") => flags.push("IPV6_PINHOLE_NEEDED"),
            _ => {}
        }
    }
    let out = |result: &'static str, text: String, fix: Option<String>| Outcome { result, flags: flags.clone(), text, fix };
    let unreachable = matches!(i.dialback, Some(Dialback::Unreachable { .. }));
    let manual = i.mode == Some(Mode::Manual);

    if let Some(Dialback::Reachable { .. }) = &i.dialback {
        let how = match (&by, i.renewed_ago_s) {
            (Some(b), Some(r)) => format!(" ({b}, lease renewed {})", ago(r)),
            (Some(b), None) => format!(" ({b})"),
            (None, _) if manual => " (forwarded by hand)".into(),
            (None, _) => String::new(),
        };
        return out("REACHABLE", format!("Reachable from the internet at {ext}{how}."), None);
    }
    if i.interface_public || i.mode == Some(Mode::None) {
        if unreachable && i.firewall_blocks == Some(true) {
            return firewall(&flags);
        }
        return out("PUBLIC_ADDRESS", format!("This machine has a public address; no router mapping is needed. Make sure no firewall blocks port {port}."),
                   unreachable.then(|| format!("Connections from outside do not arrive: check this machine's firewall and any firewall in front of it for TCP port {port}.")));
    }
    if i.map_state == "port_taken" {
        let who = i.holder.as_ref().map(|h| format!(" ({h})")).unwrap_or_default();
        return out("PORT_TAKEN", format!("Port {port} on your router is already forwarded to another device{who}."),
                   Some("Free it in the router's settings, choose another external port for this listener, or allow a fallback range.".into()));
    }
    let gx = i.gateway_external;
    let shared = |ip: IpAddr| scope(ip) == Scope::Shared;
    let cgnat = || out("CGNAT", "Your internet provider shares one public address among many customers (carrier-grade NAT). Port forwarding cannot work.".into(),
                       Some("Ask the provider for a public IPv4 address (often a paid option), use IPv6 if the workload accepts it, or run the workload elsewhere.".into()));
    let double = || out("DOUBLE_NAT", "This machine is behind two routers. The mapping on the inner router works, but the outer one (often the provider's modem) blocks it.".into(),
                        Some(format!("Put the provider's device in bridge mode, or forward port {port} on both devices, or run this workload on a machine that is reachable.")));
    if let Some(g) = gx {
        if shared(g) {
            return cgnat();
        }
        if !is_global(g) {
            return double();
        }
        if let Some(o) = i.observed {
            if o != g {
                return if shared(o) { cgnat() } else { double() };
            }
        }
    } else if i.observed.is_some_and(shared) {
        return cgnat();
    }
    if i.map_state == "unmappable" {
        let refused = i.unmappable == Some(Unmappable::Refused);
        let text = if refused { "Your router answers port-mapping requests but refuses them.".to_string() }
                   else { "Your router does not accept automatic port mapping.".to_string() };
        return out("NO_MAPPING_PROTOCOL", text,
                   Some(format!("Turn on UPnP or NAT-PMP in the router's settings, or forward TCP port {port} to {me} by hand and set the listener's mapping to manual.")));
    }
    if unreachable && (i.map_state == "mapped" || manual) {
        if i.firewall_blocks == Some(true) {
            return firewall(&flags);
        }
        return if manual {
            out("MAPPED_UNREACHABLE", format!("You forward port {port} by hand, but connections from outside do not arrive."),
                Some(format!("Check that the router forwards TCP port {port} to {me}, the router's own firewall, and whether your provider blocks inbound ports.")))
        } else {
            out("MAPPED_UNREACHABLE", "The router accepted the mapping but connections from outside do not arrive.".into(),
                Some("Check the router's own firewall, an upstream firewall, or whether your provider blocks inbound ports.".into()))
        };
    }
    if manual {
        return out("MANUAL_UNVERIFIED", format!("You forward port {port} by hand; not yet checked from outside."), no_prober(&i.dialback));
    }
    if i.map_state == "mapped" {
        let b = by.unwrap_or_else(|| "Mapped".into());
        let b = format!("{}{}", b[..1].to_uppercase(), &b[1..]);
        return out("MAPPED_UNVERIFIED", format!("{b} at {ext}; not yet checked from outside."), no_prober(&i.dialback));
    }
    out("MAPPING", "Asking the router for a port mapping.".into(), None)
}

fn no_prober(d: &Option<Dialback>) -> Option<String> {
    matches!(d, Some(Dialback::NoProber)).then(|| "Add a node on another network, or set a probe endpoint, to confirm it.".into())
}

fn firewall(flags: &[&'static str]) -> Outcome {
    Outcome { result: "FIREWALL_BLOCKED", flags: flags.to_vec(),
              text: "This machine's firewall blocks incoming connections for Oarbank.".into(),
              fix: Some("Allow oarbank-agent in the firewall settings (as an administrator: oarbank-agent firewall allow).".into()) }
}

/// The IPv6 sentence, for the owner's view beside the IPv4 result.
pub fn v6_text(v6: &V6, port: u16) -> Option<(String, Option<String>)> {
    match (v6.reachable, v6.state.as_str()) {
        (Some(true), _) => Some((format!("Reachable over IPv6 at {}.", v6.address), None)),
        (_, "unmappable") => Some(("Your router's IPv6 firewall blocks inbound connections and does not accept automatic pinholes.".into(),
                                   Some(format!("Allow TCP port {port} to this machine in the router's IPv6 firewall settings.")))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Inputs {
        Inputs { mode: Some(Mode::Auto), port: 9000, internal: Some("192.168.1.20:41000".parse().unwrap()), map_state: "mapped".into(),
                 protocol: Some(Proto::Upnp), gateway_external: Some("198.51.100.7".parse().unwrap()),
                 external: Some("198.51.100.7:9000".parse().unwrap()), ..Default::default() }
    }

    fn reach() -> Option<Dialback> {
        Some(Dialback::Reachable { via: "fleet:n2".into(), at: 0.0 })
    }

    fn nope() -> Option<Dialback> {
        Some(Dialback::Unreachable { via: "fleet:n2".into(), at: 0.0, detail: None })
    }

    #[test]
    fn every_row_of_the_table() {
        let r = classify(&Inputs { dialback: reach(), renewed_ago_s: Some(720.0), ..base() });
        assert_eq!(r.result, "REACHABLE");
        assert_eq!(r.text, "Reachable from the internet at 198.51.100.7:9000 (mapped by UPnP, lease renewed 12 minutes ago).");
        assert_eq!(classify(&Inputs { interface_public: true, map_state: "not_needed".into(), ..base() }).result, "PUBLIC_ADDRESS");
        let r = classify(&Inputs { map_state: "unmappable".into(), unmappable: Some(Unmappable::NoProtocol), protocol: None, external: None,
                                   gateway_external: None, ..base() });
        assert_eq!(r.result, "NO_MAPPING_PROTOCOL");
        assert!(r.fix.unwrap().contains("192.168.1.20 (port 41000)"));
        assert_eq!(classify(&Inputs { gateway_external: Some("192.168.0.1".parse().unwrap()), ..base() }).result, "DOUBLE_NAT");
        assert_eq!(classify(&Inputs { gateway_external: Some("100.70.1.2".parse().unwrap()), ..base() }).result, "CGNAT");
        assert_eq!(classify(&Inputs { observed: Some("100.70.1.2".parse().unwrap()), ..base() }).result, "CGNAT");
        assert_eq!(classify(&Inputs { observed: Some("203.0.113.9".parse().unwrap()), ..base() }).result, "DOUBLE_NAT");
        let r = classify(&Inputs { map_state: "port_taken".into(), holder: Some("192.168.1.31".into()), ..base() });
        assert_eq!((r.result, r.text.as_str()), ("PORT_TAKEN", "Port 9000 on your router is already forwarded to another device (192.168.1.31)."));
        assert_eq!(classify(&Inputs { dialback: nope(), ..base() }).result, "MAPPED_UNREACHABLE");
        assert_eq!(classify(&Inputs { dialback: nope(), firewall_blocks: Some(true), ..base() }).result, "FIREWALL_BLOCKED");
        let r = classify(&Inputs { dialback: Some(Dialback::NoProber), protocol: Some(Proto::Natpmp), ..base() });
        assert_eq!(r.result, "MAPPED_UNVERIFIED");
        assert_eq!(r.text, "Mapped by NAT-PMP at 198.51.100.7:9000; not yet checked from outside.");
        assert!(r.fix.is_some());
        assert_eq!(classify(&Inputs { mode: Some(Mode::Manual), map_state: "manual".into(), protocol: None, ..base() }).result, "MANUAL_UNVERIFIED");
        assert_eq!(classify(&Inputs { map_state: "requesting".into(), ..base() }).result, "MAPPING");
    }

    #[test]
    fn flags_ride_along() {
        let r = classify(&Inputs { dialback: reach(), address_changed_ago_s: Some(3.0 * 86400.0), permanent_only_router: true,
                                   v6: Some(V6 { address: "[2001:db8::7]:9000".parse().unwrap(), state: "mapped".into(), reachable: Some(true) }),
                                   ..base() });
        assert_eq!(r.flags, vec!["DYNAMIC_ADDRESS", "PERMANENT_ONLY_ROUTER", "IPV6_REACHABLE"]);
        let v6 = V6 { address: "[2001:db8::7]:9000".parse().unwrap(), state: "unmappable".into(), reachable: None };
        assert!(classify(&Inputs { v6: Some(v6.clone()), ..base() }).flags.contains(&"IPV6_PINHOLE_NEEDED"));
        assert!(v6_text(&v6, 9000).unwrap().1.is_some());
    }
}
