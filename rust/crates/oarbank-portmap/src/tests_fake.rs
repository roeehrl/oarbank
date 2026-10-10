//! The lifecycle with the real protocol clients against the fake gateways on loopback: every protocol, every router
//! behaviour the design names, crashes and restarts from the journal, and the rule that nobody else's mapping is ever
//! deleted.

use crate::fake::{FakeConfig, FakeGateway};
use crate::journal::Journal;
use crate::manager::{Manager, Phase, Unmappable};
use crate::router::NetRouter;
use crate::types::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

fn fast() -> Timing {
    Timing { lease_pcp: 6, lease_natpmp: 6, lease_upnp: 6, lease_pinhole: 6, verify_s: 1.0, discovery_ttl_s: 30.0, retry_min_s: 0.2,
             retry_max_s: 1.0, port_taken_retry_s: 2.0, release_retry_s: 0.5 }
}

fn router(gw: &FakeGateway) -> NetRouter {
    let mut r = NetRouter::new(gw.target());
    r.upnp_timeout = Duration::from_millis(400);
    r.udp_timeouts = vec![Duration::from_millis(150), Duration::from_millis(250)];
    r
}

fn manager(gw: &FakeGateway, j: Journal) -> Manager<NetRouter> {
    let mut m = Manager::new(router(gw), j, fast(), "n1test");
    m.set_network(Family::Ipv4, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), Some(gw.pmp.ip()), crate::now());
    m
}

const UPNP: Mode = Mode::Only(Proto::Upnp);
const NATPMP: Mode = Mode::Only(Proto::Natpmp);

fn want(key: &str, internal_port: u16, ext: u16, fallback: Fallback, mode: Mode) -> Want {
    Want { key: key.into(), family: Family::Ipv4, internal: SocketAddr::from((Ipv4Addr::LOCALHOST, internal_port)), external_port: ext,
           fallback, mode, description: description("n1test", key) }
}

fn cfg(natpmp: bool, pcp: bool, upnp: bool) -> FakeConfig {
    FakeConfig { natpmp, pcp, upnp, ..Default::default() }
}

/// Step until `done` holds (or fail after several seconds of real time).
async fn until(m: &mut Manager<NetRouter>, what: &str, done: impl Fn(&Manager<NetRouter>) -> bool) {
    for _ in 0..120 {
        m.step(crate::now()).await;
        if done(m) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{what}: {:?}", m.statuses(crate::now()));
}

fn st(m: &Manager<NetRouter>, key: &str) -> crate::Status {
    m.status(key, Family::Ipv4, crate::now()).expect("lifecycle")
}

fn s6(m: &Manager<NetRouter>) -> crate::Status {
    m.status("mod/peer", Family::Ipv6, crate::now()).expect("lifecycle")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_protocol_maps_verifies_renews_and_releases() {
    for (name, c, proto) in [("pcp", cfg(true, true, true), Proto::Pcp), ("natpmp", cfg(true, false, true), Proto::Natpmp),
                             ("upnp", cfg(false, false, true), Proto::Upnp)] {
        let gw = FakeGateway::start(c).await.unwrap();
        let mut m = manager(&gw, Journal::memory());
        m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
        until(&mut m, name, |m| st(m, "mod/peer").state == "mapped").await;
        let s = st(&m, "mod/peer");
        assert_eq!(s.protocol, Some(proto), "{name}: the preferred protocol that answers");
        assert_eq!(s.external, Some("198.51.100.7:9000".parse().unwrap()), "{name}");
        assert!(s.fresh);
        assert_eq!(gw.with(|g| g.ours().len()), 1, "{name}");
        // the lease renews at half life (3 s here) and the verifications keep it fresh
        let first_exp = s.expires_at.unwrap();
        until(&mut m, name, |m| st(m, "mod/peer").expires_at.unwrap() > first_exp + 1.0).await;
        assert_eq!(gw.with(|g| g.ours().len()), 1, "{name}: a renewal is not a second mapping");
        assert_eq!(m.journal.entries().len(), 1);
        m.set_wants(vec![], crate::now());
        until(&mut m, name, |m| m.journal.entries().is_empty()).await;
        assert!(gw.with(|g| g.ours().is_empty()), "{name}: released when the listener went");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_router_reboot_is_seen_and_the_mapping_comes_back() {
    for (name, c) in [("pcp", cfg(true, true, false)), ("natpmp", cfg(true, false, false)), ("upnp", cfg(false, false, true))] {
        let gw = FakeGateway::start(c).await.unwrap();
        let mut m = manager(&gw, Journal::memory());
        m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
        until(&mut m, name, |m| st(m, "mod/peer").state == "mapped").await;
        let changes = st(&m, "mod/peer").changes;
        tokio::time::sleep(Duration::from_millis(3200)).await;      // the epoch has advanced well past what a reboot resets
        gw.reboot();
        assert!(gw.with(|g| g.ours().is_empty()));
        // within a verify interval the loss is seen (NAT-PMP and PCP: the epoch went back; UPnP: the read-back, or the
        // next renewal, which adds the mapping again), and it is mapped again
        until(&mut m, name, |m| (name == "upnp" || st(m, "mod/peer").changes > changes) && st(m, "mod/peer").state == "mapped"
                                && gw.with(|g| g.ours().len()) == 1).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_taken_port_is_refused_or_walked_never_stolen() {
    for (name, c) in [("pcp", cfg(true, true, false)), ("upnp", cfg(false, false, true))] {
        let gw = FakeGateway::start(c).await.unwrap();
        gw.with(|g| g.add_foreign(9000, "192.168.1.31".parse().unwrap(), 9000, "another device", None));
        let mut m = manager(&gw, Journal::memory());
        m.set_wants(vec![want("mod/stable", 41000, 9000, Fallback::Refuse, Mode::Auto),
                         want("mod/flex", 41001, 9000, Fallback::NextFree { lo: 9000, hi: 9003 }, Mode::Auto)], crate::now());
        until(&mut m, name, |m| st(m, "mod/stable").state == "port_taken" && st(m, "mod/flex").state == "mapped").await;
        let flex = st(&m, "mod/flex").external.unwrap().port();
        assert_eq!(flex, 9001, "{name}: the first free port of the range, deterministically");
        if name == "upnp" {
            assert_eq!(st(&m, "mod/stable").holder.as_deref(), Some("192.168.1.31"), "the router says who holds it");
        }
        assert!(gw.with(|g| g.mappings.iter().any(|x| x.foreign && x.external_port == 9000)), "{name}: still the other device's");
        m.release_all(crate::now()).await;
        assert!(gw.foreign_deletes().is_empty(), "{name}: nobody else's mapping is ever deleted");
        assert!(gw.with(|g| g.ours().is_empty()));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upnp_router_behaviours() {
    // only permanent leases (725, and 402 on some devices): mapped with lease 0, flagged, deleted at the end
    for code in [725u16, 402] {
        let gw = FakeGateway::start(FakeConfig { permanent_only: true, permanent_only_code: code, ..cfg(false, false, true) }).await.unwrap();
        let mut m = manager(&gw, Journal::memory());
        m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, UPNP)], crate::now());
        until(&mut m, "permanent", |m| st(m, "mod/peer").state == "mapped").await;
        assert!(st(&m, "mod/peer").permanent && m.permanent_seen);
        assert_eq!(gw.with(|g| g.ours()[0].ttl), None);
        m.release_all(crate::now()).await;
        assert!(gw.with(|g| g.ours().is_empty()), "a permanent mapping is deleted when the agent stops");
    }
    // the router's choice: AddAnyPortMapping substitutes a free port (IGD:2)
    let gw = FakeGateway::start(cfg(false, false, true)).await.unwrap();
    gw.with(|g| g.add_foreign(9000, "192.168.1.31".parse().unwrap(), 9000, "another device", None));
    let mut m = manager(&gw, Journal::memory());
    m.set_wants(vec![want("mod/any", 41000, 9000, Fallback::RouterChoice, Mode::Auto)], crate::now());
    until(&mut m, "router choice", |m| st(m, "mod/any").state == "mapped").await;
    assert_ne!(st(&m, "mod/any").external.unwrap().port(), 9000);
    // the same port required (724): the listener is told to bind the external port itself
    let gw = FakeGateway::start(FakeConfig { same_port_required: true, ..cfg(false, false, true) }).await.unwrap();
    let mut m = manager(&gw, Journal::memory());
    m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
    until(&mut m, "724", |m| st(m, "mod/peer").state == "unmappable").await;
    assert!(m.lifecycles().next().unwrap().same_port_required);
    m.set_wants(vec![want("mod/peer", 9000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
    until(&mut m, "724 then same port", |m| st(m, "mod/peer").state == "mapped").await;
    // IGD:1: no AddAnyPortMapping, still mapped
    let gw = FakeGateway::start(FakeConfig { igd_v2: false, ..cfg(false, false, true) }).await.unwrap();
    let mut m = manager(&gw, Journal::memory());
    m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
    until(&mut m, "IGD:1", |m| st(m, "mod/peer").state == "mapped").await;
    assert_eq!(m.discovery(Family::Ipv4).unwrap().upnp.as_deref(), Some("IGD:1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusals_fall_through_and_silence_is_unmappable() {
    let gw = FakeGateway::start(FakeConfig { not_authorized: true, ..cfg(true, true, true) }).await.unwrap();
    let mut m = manager(&gw, Journal::memory());
    m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
    until(&mut m, "refused", |m| st(m, "mod/peer").state == "unmappable").await;
    let s = st(&m, "mod/peer");
    assert!(matches!(s.unmappable, Some(Unmappable::Refused) | Some(Unmappable::NoProtocol)), "{s:?}");
    assert!(m.journal.entries().is_empty(), "a refused request made nothing, so nothing stays journaled");
    let gw = FakeGateway::start(FakeConfig { silent: true, ..Default::default() }).await.unwrap();
    let mut m = manager(&gw, Journal::memory());
    m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
    until(&mut m, "silent", |m| st(m, "mod/peer").state == "unmappable").await;
    // the router comes back: mapped on the next retry
    gw.with(|g| g.cfg.silent = false);
    until(&mut m, "back", |m| st(m, "mod/peer").state == "mapped").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_leaves_a_journal_the_next_start_cleans_or_adopts() {
    for (name, c) in [("pcp", cfg(true, true, false)), ("natpmp", cfg(true, false, false)), ("upnp", cfg(false, false, true))] {
        let gw = FakeGateway::start(c).await.unwrap();
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("portmaps.json");
        {
            let mut m = manager(&gw, Journal::load(&path));
            m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
            until(&mut m, name, |m| st(m, "mod/peer").state == "mapped").await;
            // crash: the manager is dropped without releasing
        }
        assert_eq!(gw.with(|g| g.ours().len()), 1);
        // the listener is still wanted after the restart: the journaled lease is adopted (one mapping, the same port)
        {
            let mut m = manager(&gw, Journal::load(&path));
            m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
            until(&mut m, name, |m| st(m, "mod/peer").state == "mapped" && st(m, "mod/peer").fresh).await;
            assert_eq!(gw.with(|g| g.ours().len()), 1, "{name}: adopted, not mapped twice");
            assert_eq!(m.journal.entries().len(), 1);
        }
        // a restart that no longer wants it releases it
        let mut m = manager(&gw, Journal::load(&path));
        m.set_wants(vec![], crate::now());
        until(&mut m, name, |m| m.journal.entries().is_empty()).await;
        assert!(gw.with(|g| g.ours().is_empty()), "{name}: the stale mapping is gone");
        assert!(gw.foreign_deletes().is_empty());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_routers_listing_is_swept_for_this_nodes_own_stale_mappings_only() {
    let gw = FakeGateway::start(cfg(false, false, true)).await.unwrap();
    let me: IpAddr = Ipv4Addr::LOCALHOST.into();
    gw.with(|g| {
        // ours, not journaled (a journal lost with a disk): swept
        g.add_foreign(9100, me, 41100, "oarbank:n1test:mod/old", None);
        // another node's, on this address: kept; and a mapping by another program of this machine: kept
        g.add_foreign(9101, me, 41101, "oarbank:otherxnode:mod/x", None);
        g.add_foreign(9102, me, 22, "someone's game", None);
        // ours by description, but for another address: kept
        g.add_foreign(9103, "192.168.1.31".parse().unwrap(), 41103, "oarbank:n1test:mod/old", None);
        for m in g.mappings.iter_mut() {
            m.foreign = m.external_port != 9100;
        }
    });
    let mut m = manager(&gw, Journal::memory());
    m.set_wants(vec![want("mod/peer", 41000, 9000, Fallback::Refuse, Mode::Auto)], crate::now());
    until(&mut m, "sweep", |m| st(m, "mod/peer").state == "mapped" && m.journal.entries().len() == 1
                               && !gw.with(|g| g.mappings.iter().any(|x| x.external_port == 9100))).await;
    let ports: Vec<u16> = gw.with(|g| g.mappings.iter().map(|x| x.external_port).collect());
    assert!(ports.contains(&9101) && ports.contains(&9102) && ports.contains(&9103), "{ports:?}");
    assert!(gw.foreign_deletes().is_empty());
    assert!(m.others.iter().any(|o| o.external_port == 9102 && !o.ours), "the owner sees the router's other mappings");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_pinholes_by_upnp_and_pcp() {
    let v6 = |internal: &str| Want { key: "mod/peer".into(), family: Family::Ipv6, internal: internal.parse().unwrap(), external_port: 9000,
                                     fallback: Fallback::Refuse, mode: Mode::Auto, description: description("n1test", "mod/peer") };
    async fn settle(m: &mut Manager<NetRouter>, state: &str) {
        for _ in 0..40 {
            m.step(crate::now()).await;
            if s6(m).state == state {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{state}: {:?}", s6(m));
    }
    // UPnP IGDv2 WANIPv6FirewallControl
    let gw = FakeGateway::start(cfg(false, false, true)).await.unwrap();
    let mut m = Manager::new(router(&gw), Journal::memory(), fast(), "n1test");
    m.set_wants(vec![v6("[2001:db8::7]:9000")], crate::now());
    settle(&mut m, "mapped").await;
    assert_eq!(s6(&m).external, Some("[2001:db8::7]:9000".parse().unwrap()));
    assert_eq!(gw.with(|g| g.pinholes.len()), 1);
    m.release_all(crate::now()).await;
    assert!(gw.with(|g| g.pinholes.is_empty()));
    // a router whose IPv6 firewall is off: nothing to open
    let gw = FakeGateway::start(FakeConfig { firewall: Some((false, false)), ..cfg(false, false, true) }).await.unwrap();
    let mut m = Manager::new(router(&gw), Journal::memory(), fast(), "n1test");
    m.set_wants(vec![v6("[2001:db8::7]:9000")], crate::now());
    settle(&mut m, "not_needed").await;
    // a router that allows no inbound pinholes: unmappable (the owner is told to open the port)
    let gw = FakeGateway::start(FakeConfig { firewall: Some((true, false)), ..cfg(false, false, true) }).await.unwrap();
    let mut m = Manager::new(router(&gw), Journal::memory(), fast(), "n1test");
    m.set_wants(vec![v6("[2001:db8::7]:9000")], crate::now());
    settle(&mut m, "unmappable").await;
    // PCP over IPv6 (the fake answers on [::1] when the host has IPv6 loopback)
    let gw = FakeGateway::start(cfg(false, true, false)).await.unwrap();
    if gw.pcp_v6.is_some() {
        let mut m = Manager::new(router(&gw), Journal::memory(), fast(), "n1test");
        m.set_network(Family::Ipv6, Some("::1".parse().unwrap()), None, crate::now());
        m.set_wants(vec![v6("[::1]:9000")], crate::now());
        settle(&mut m, "mapped").await;
        assert_eq!(s6(&m).protocol, Some(Proto::Pcp));
        m.release_all(crate::now()).await;
        assert!(gw.with(|g| g.ours().is_empty()));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_and_none_touch_no_router() {
    let gw = FakeGateway::start(Default::default()).await.unwrap();
    let mut m = manager(&gw, Journal::memory());
    m.set_wants(vec![want("mod/a", 41000, 9000, Fallback::Refuse, Mode::Manual), want("mod/b", 41001, 9001, Fallback::Refuse, Mode::None)],
                crate::now());
    m.step(crate::now()).await;
    assert_eq!((st(&m, "mod/a").state, st(&m, "mod/b").state), ("manual", "not_needed"));
    assert_eq!(gw.with(|g| g.requests), 0);
    assert!(matches!(m.lifecycles().next().unwrap().phase, Phase::Manual));
}

/// A soak of renewals in real time with compressed leases: renewals, reboots, an external address change, a re-bind
/// of a listener, a conflict. At the end nothing stale is left and nobody else's mapping was touched. (The model tests
/// cover days of virtual time.) `OARBANK_PORTMAP_SOAK_S` makes it longer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn soak_with_renewals_reboots_and_changes() {
    let secs: u64 = std::env::var("OARBANK_PORTMAP_SOAK_S").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let gw = FakeGateway::start(cfg(true, true, true)).await.unwrap();
    gw.with(|g| g.add_foreign(9002, "192.168.1.31".parse().unwrap(), 9002, "another device", None));
    let d = tempfile::tempdir().unwrap();
    let mut m = manager(&gw, Journal::load(&d.path().join("portmaps.json")));
    let wants = || vec![want("mod/a", 41000, 9000, Fallback::Refuse, Mode::Auto), want("mod/b", 41001, 9001, Fallback::Refuse, NATPMP),
                        want("mod/c", 41002, 9002, Fallback::NextFree { lo: 9002, hi: 9010 }, UPNP)];
    m.set_wants(wants(), crate::now());
    let start = std::time::Instant::now();
    let mut stale_announced = 0u32;
    let mut i = 0u64;
    while start.elapsed() < Duration::from_secs(secs) {
        i += 1;
        m.step(crate::now()).await;
        match i % 40 {
            10 => gw.reboot(),
            20 => gw.set_external(Ipv4Addr::new(203, 0, 113, (i % 200) as u8 + 1), None).await,
            30 => {
                // the listener of mod/a moves to another internal port (a re-bind)
                let mut w = wants();
                w[0].internal.set_port(41000 + (i % 7) as u16);
                m.set_wants(w, crate::now());
            }
            _ => {}
        }
        // a lease the lifecycle calls fresh must exist on the router, or have been lost within the bound
        let now = crate::now();
        for s in m.statuses(now).into_iter().filter(|s| s.fresh) {
            let present = gw.with(|g| g.ours().iter().any(|x| Some(x.external_port) == s.external.map(|e| e.port())));
            if !present && s.verified_at.is_some_and(|v| now - v > 2.0 * fast().verify_s + 0.5) {
                stale_announced += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(stale_announced, 0, "announced a mapping the router lost for longer than the bound");
    m.set_wants(vec![], crate::now());
    until(&mut m, "clean", |m| m.journal.entries().is_empty()).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;   // a lease left to run out (released too close to its end) is gone
    assert!(gw.with(|g| g.ours().is_empty()), "{:?}", gw.with(|g| g.ours()));
    assert!(gw.foreign_deletes().is_empty());
}

