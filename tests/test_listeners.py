"""Inbound listeners on the coordinator (docs/design/inbound-listeners.md; PLAN D47-D49, invariant S24): the release
entry and the grant, the owner's entries in the node statement (defaults, approval gating, removal), the operations,
the settings keys, the heartbeat reports, the dial-back probes, the directives, the alerts, S24, the console and the
CLI. The agent side is tested in the Rust crates and tests/rust."""
import argparse
import base64
import json
import shutil
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oarbank.contracts import operations as registry
from oarbank.coordinator import (clock, core, explain, invariants, listeners, modcalls, modsandbox, modstore, ops,
                                 releases, statements)
from oarbank.coordinator.settings import registry as R

from helpers import FACTS, enrolled_node, fresh, install, make_db, run_op

ECHO_DIR = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "publicecho"
LFACTS = {**FACTS, "listeners": {"version": 1, "probe": True}}
WIN_FACTS = {**LFACTS, "platform": {"os": "windows", "arch": "amd64", "os_version": "10.0.26100", "os_build": "26100"}}
PEER = '''
[[sandbox.net.inbound]]
name = "peer"
port_hint = 9100
port_policy = "stable"
handover = "listen_fd"
max_conns = 64
'''


@pytest.fixture
def echo(tmp_path):
    """publicecho with a second, stable listener `peer` served on an inherited listening socket."""
    d = tmp_path / "publicecho"
    shutil.copytree(ECHO_DIR, d, ignore=shutil.ignore_patterns("__pycache__"))
    text = (d / "oarbank-module.toml").read_text(encoding="utf-8")
    text = text.replace('listeners = ["echo"]', 'listeners = ["echo", "peer"]').replace("[[services]]", PEER + "\n[[services]]", 1)
    (d / "oarbank-module.toml").write_text(text, encoding="utf-8")
    return d


@pytest.fixture
def db(tmp_path, echo, monkeypatch):
    monkeypatch.setattr(modstore, "CORE_VERSION", "2.10.0")       # the manifest needs core >= 2.10
    d = make_db(tmp_path / "oarbank.sqlite3")
    r = install(d, echo, enable=False)
    modsandbox.approve(d, "publicecho", r["version"], "test", None)
    modstore.enable(d, "publicecho", r["version"])
    modcalls.use(d)
    releases.sync(d)
    listeners._STATUS_CACHE.clear()
    return d


def node(db, name="a", facts=LFACTS):
    return enrolled_node(db, name, facts)[1]


def stmt(db, n) -> dict:
    cur = statements.statement(db, n["node_id"])
    return json.loads(cur["statement"]) if cur else None


def configure(db, n, key="publicecho/echo", actor="test", **fields):
    return run_op(db, "listeners.configure", n["node_id"], params={"key": key, **fields}, actor=actor)


def hb(db, n, peer_ip="", **body):
    return core.heartbeat(db, fresh(db, n), {"attempts": [], **body}, peer_ip)


def listening(key="publicecho/echo", external="198.51.100.7:9000", seq=1, **kw):
    return {"key": key, "service": "publicecho/echo", "state": "listening", "refused": None, "detail": None,
            "statement_seq": seq, "bind": "192.168.1.20:41000", "external": external, "announced": "mapped_unverified",
            "since": 1.0, "reachability": {"result": "MAPPED_UNVERIFIED", "flags": [], "text": "Mapped; not yet checked.",
                                           "fix": None, "via": None, "at": 1.0},
            "conns": {"open": 0, "accepted": 0, "bytes_in": 0, "bytes_out": 0,
                      "refused": {"rate": 0, "cap": 0, "per_ip": 0, "allow": 0, "held": 0, "disabled": 0}},
            "probe_wanted": False, **kw}


def network(external="198.51.100.7"):
    return {"gateway": "192.168.1.1", "local": "192.168.1.20", "local_v6": None, "gateway_external": external,
            "observed": None, "protocols": {"pcp": False, "natpmp": True, "upnp": "IGD:2"}, "checked_at": 1.0,
            "router_mappings": [{"protocol": "TCP", "external_port": 8080, "internal": "192.168.1.20:8080",
                                 "description": "a game console", "ours": False}],
            "firewall": {"kind": "macos-alf", "enabled": True, "agent_allowed": True}}


def portmap(key="publicecho/echo"):
    return {"key": key, "family": "ipv4", "protocol": "natpmp", "gateway": "192.168.1.1", "external": "198.51.100.7:9000",
            "internal": "192.168.1.20:41000", "lease_s": 7200, "expires_at": 9e9, "verified_at": 1.0, "permanent": False,
            "state": "mapped", "error": None}


# ------------------------------------------------------------------ release entry and grant

def test_the_release_entry_carries_the_listeners_and_the_services_that_serve_them(db):
    entry = releases.module_entry("publicecho", "0.1.0", "h2:x", modstore.record(db, "publicecho", "0.1.0")["path"])
    inbound = {x["name"]: x for x in entry["sandbox"]["net"]["inbound"]}
    assert inbound["echo"] == {"name": "echo", "protocol": "tcp", "port_hint": 9000, "port_policy": "flexible",
                               "tls": "passthrough", "handover": "connections", "proxy_protocol": False, "max_conns": 32,
                               "max_conns_per_ip": 4, "new_conns_per_ip_per_s": 2.0, "idle_timeout_s": 60.0,
                               "max_bytes_per_s": None}
    assert inbound["peer"]["handover"] == "listen_fd" and inbound["peer"]["proxy_protocol"] is True    # its default
    assert entry["services"][0]["listeners"] == ["echo", "peer"]
    # every other entry keeps its bytes: no inbound, no listeners
    toy = releases.module_entry("toy", modstore.channel(db, "toy")["current"], "h2:y",
                                modstore.record(db, "toy", modstore.channel(db, "toy")["current"])["path"])
    assert "inbound" not in toy["sandbox"]["net"] and all("listeners" not in s for s in toy["services"])


def test_the_grant_is_approved_by_digest_and_reads_as_the_design_says(db):
    st = modsandbox.status(db, "publicecho", "0.1.0")
    assert [x["name"] for x in st["requests"]["inbound"]] == ["echo", "peer"] and st["approved"]
    text = modsandbox.describe(st["requests"])
    assert ("accepts connections from the internet on nodes the owner assigns: listener echo (TCP, port 9000 wanted, "
            "flexible; at most 32 connections, 4 per address, 2 new a second per address, idle 60 s)") in text
    assert "listener peer (TCP, port 9100 wanted, stable, handed over as a listening socket; at most 64 connections" in text
    # the digest covers the listeners: another ceiling is another grant
    req = dict(st["requests"], inbound=[{**st["requests"]["inbound"][0], "max_conns": 33}, st["requests"]["inbound"][1]])
    assert modsandbox.digest(req) != st["digest"]


# ------------------------------------------------------------------ the node statement

def test_an_entry_resolves_every_default_into_the_statement(db):
    a = node(db)
    assert statements.statement(db, a["node_id"]) is None            # nothing assigned: no statement
    r = configure(db, a)
    assert r["result"]["statements"] == [a["node_id"]] and r["result"]["in_statement"]
    s = stmt(db, a)
    assert s["seq"] == 1 and s["folders"] == {} and s["tools"] == []
    assert s["listeners"] == {"publicecho/echo": {"external_port": 9000, "fallback": "next_free:9000-9015", "mapping": "auto",
                                                  "ipv6": "auto", "bind": "default_route", "internal_port": None,
                                                  "limits": {}, "allow": []}}
    configure(db, a, key="publicecho/peer", limits={"max_conns": 64, "max_conns_per_ip": 8}, allow=["198.51.100.0/24"])
    peer = stmt(db, a)["listeners"]["publicecho/peer"]
    assert peer["fallback"] == "refuse" and peer["external_port"] == 9100
    assert peer["limits"] == {"max_conns_per_ip": 8} and peer["allow"] == ["198.51.100.0/24"]   # only what is lowered
    # a flexible listener without a wanted port takes the router's choice; the owner's fields override defaults
    lst = listeners.declared(db, a["node_id"], "publicecho/echo")[3].model_copy(update={"port_hint": None})
    assert listeners.resolve({}, lst)["fallback"] == "router_choice" and listeners.resolve({}, lst)["external_port"] is None
    configure(db, a, external_port=9500, fallback="next_free:9500-9510", mapping="manual", ipv6="off", internal_port=41010)
    e = stmt(db, a)["listeners"]["publicecho/echo"]
    assert (e["external_port"], e["fallback"], e["mapping"], e["ipv6"], e["internal_port"]) == (9500, "next_free:9500-9510", "manual", "off", 41010)
    configure(db, a, external_port=None, fallback=None)               # back to the defaults; the rest stays
    e = stmt(db, a)["listeners"]["publicecho/echo"]
    assert (e["external_port"], e["fallback"], e["mapping"]) == (9000, "next_free:9000-9015", "manual")
    assert stmt(db, a)["seq"] == 4


def test_only_approved_grants_reach_the_statement_and_removal_leaves_an_empty_map(db):
    a, b = node(db, "a"), node(db, "b")
    configure(db, a)
    db.x("DELETE FROM module_grants WHERE name='publicecho'")         # the grants are no longer approved
    assert listeners.refresh_statements(db) == [a["node_id"]]
    assert stmt(db, a)["listeners"] == {} and stmt(db, a)["seq"] == 2
    modsandbox.approve(db, "publicecho", "0.1.0", "test", None)
    assert listeners.refresh_statements(db) == [a["node_id"]] and "publicecho/echo" in stmt(db, a)["listeners"]
    r = run_op(db, "listeners.remove", a["node_id"], params={"key": "publicecho/echo"})
    assert r["result"]["removed"] and stmt(db, a)["listeners"] == {} and stmt(db, a)["seq"] == 4
    assert run_op(db, "listeners.remove", a["node_id"], params={"key": "publicecho/echo"})["result"]["removed"] is False
    assert statements.statement(db, b["node_id"]) is None and listeners.refresh_statements(db) == []


def test_a_statement_from_before_listeners_gets_no_new_seq_and_stays_signable(db):
    a = node(db)
    owner = Ed25519PrivateKey.generate()
    db.set_state("release_pubkey", base64.b64encode(owner.public_key().public_bytes_raw()).decode())
    old = json.dumps({"type": statements.TYPE, "fleet_id": "f", "node_id": a["node_id"], "seq": 3,
                      "folders": {"x": {"access": "read", "path": "/data"}}, "tools": [], "signed_at": 1},
                     sort_keys=True, separators=(",", ":"))
    db.set_state(statements.KEY, {a["node_id"]: {"seq": 3, "statement": old, "signature": None}})
    from oarbank.coordinator import settings
    settings.write_fleet(db, "folder_registry", {"x": {"access": "read", "nodes": {a["node_id"]: "/data"}}}, "test")
    assert statements.refresh(db, [a["node_id"]]) == []
    statements.sign(db, a["node_id"], old, base64.b64encode(owner.sign(old.encode())).decode())
    configure(db, a)
    new = statements.statement(db, a["node_id"])["statement"]
    assert json.loads(new)["seq"] == 4
    with pytest.raises(statements.StatementError):                     # a new statement must carry listeners
        statements.sign(db, a["node_id"], new.replace(',"listeners":{', ',"x":{'),
                        base64.b64encode(owner.sign(new.encode())).decode())
    statements.sign(db, a["node_id"], new, base64.b64encode(owner.sign(new.encode())).decode())
    assert statements.directive(db, a["node_id"])["signature"]


# ------------------------------------------------------------------ operations

def test_the_operations_tiers_and_roles():
    o = registry.REGISTRY
    assert (o["listeners.configure"].tier, o["listeners.configure"].min_role, o["listeners.configure"].preview) == ("T2", "admin", True)
    assert (o["listeners.remove"].tier, o["listeners.remove"].min_role) == ("T1", "admin")
    assert (o["listeners.disable"].tier, o["listeners.disable"].min_role) == ("T0", "operator")
    assert (o["listeners.resume"].tier, o["listeners.probe"].tier, o["listeners.probe"].min_role) == ("T1", "T0", "operator")


@pytest.mark.parametrize("fields,match", [
    ({"key": "publicecho/nope"}, "does not request an inbound listener named 'nope'"),
    ({"key": "nomodule/echo"}, "not enabled"),
    ({"key": "bad key"}, "not <module>/<listener>"),
    ({"external_port": 80}, "from 1024 to 65535"),
    ({"internal_port": 70000}, "from 1024 to 65535"),
    ({"fallback": "next_free:9000-8000"}, "fallback"),
    ({"fallback": "always"}, "fallback"),
    ({"mapping": "igd"}, "mapping: one of"),
    ({"ipv6": "on"}, "ipv6: auto or off"),
    ({"bind": "0.0.0.0"}, "wildcard"),
    ({"bind": "here"}, "bind: default_route or an IP address"),
    ({"limits": {"max_conns": 300}}, "above the module's ceiling of 32"),
    ({"limits": {"max_conns": 1.5}}, "whole number"),
    ({"limits": {"burst": 3}}, "unknown key"),
    ({"allow": ["198.51.100.0/33"]}, "not a CIDR"),
    ({"colour": "red"}, "unknown fields"),
])
def test_configure_refuses_what_is_wrong_with_a_clear_message(db, fields, match):
    a = node(db)
    with pytest.raises(core.ApiError, match=match):
        configure(db, a, **{"key": "publicecho/echo", **fields} if "key" in fields else fields)
    assert statements.statement(db, a["node_id"]) is None


def test_configure_needs_an_agent_with_listeners_the_admin_role_and_no_listen_fd_on_windows(db):
    old = node(db, "old", FACTS)
    with pytest.raises(core.ApiError, match="does not support inbound listeners") as e:
        configure(db, old)
    assert e.value.status == 409
    win = node(db, "win", WIN_FACTS)
    configure(db, win)                                                 # connections hand-over: fine on Windows
    with pytest.raises(core.ApiError, match="Windows nodes do not support"):
        configure(db, win, key="publicecho/peer")
    a = node(db)
    with pytest.raises(ops.OpError, match="needs the admin role"):
        ops.execute(db, ops.OpRequest(op="listeners.configure", actor="op", role="operator", target=a["node_id"],
                                      params={"key": "publicecho/echo"}, dry_run=True))
    rows = db.q("SELECT outcome FROM audit WHERE operation='listeners.configure' ORDER BY event_id")
    assert {"ok", "conflict", "denied"} <= {r["outcome"] for r in rows}          # every request is audited


def test_the_preview_names_node_port_module_limits_and_the_signature(db, monkeypatch):
    a = node(db)
    monkeypatch.setattr(ops, "_signing", lambda: True)
    plan = ops.execute(db, ops.OpRequest(op="listeners.configure", actor="t", target=a["node_id"], dry_run=True,
                                         params={"key": "publicecho/echo", "external_port": 9001,
                                                 "limits": {"max_conns": 16}}))["plan"]
    imp = plan["impact"]
    assert imp["node"].startswith("a (") and imp["external_port"] == 9001 and imp["module"] == "publicecho 0.1.0"
    assert imp["limits"].startswith("at most 16 connections, 4 per address") and "max_conns 16 (module 32)" in imp["limits_lowered"]
    assert "sign the node statement (oarbank node sign a) before the node applies it" in imp["then"]


def test_the_kill_switch_for_a_node_and_the_fleet(db):
    a, b = node(db, "a"), node(db, "b")
    assert hb(db, a)["listeners_disabled"] is False
    run_op(db, "listeners.disable", a["node_id"])
    assert hb(db, a)["listeners_disabled"] is True and hb(db, b)["listeners_disabled"] is False
    run_op(db, "listeners.disable", "fleet")
    assert hb(db, b)["listeners_disabled"] is True
    run_op(db, "listeners.resume", "fleet")
    assert hb(db, b)["listeners_disabled"] is False and hb(db, a)["listeners_disabled"] is True
    run_op(db, "listeners.resume", a["node_id"])
    assert hb(db, a)["listeners_disabled"] is False
    kinds = [e["kind"] for e in db.q("SELECT kind FROM events WHERE kind LIKE 'listeners_%' ORDER BY event_id")]
    assert kinds == ["listeners_disabled", "listeners_disabled", "listeners_resumed", "listeners_resumed"]


def test_retiring_an_offline_node_with_router_mappings_warns(db, monkeypatch):
    a = node(db)
    hb(db, a, listeners=[listening()], portmaps=[portmap()], network=network())
    imp = lambda: ops.execute(db, ops.OpRequest(op="nodes.retire", actor="t", target=a["node_id"], dry_run=True))["plan"]["impact"]
    assert "warning" not in imp()                                       # online: it releases them when told
    db.x("UPDATE nodes SET last_heartbeat_at=1 WHERE node_id=?", (a["node_id"],))
    assert "router mappings may persist until their lease expires" in imp()["warning"]


# ------------------------------------------------------------------ settings

def test_the_network_settings():
    il, pr = R.REGISTRY["inbound_listeners"], R.REGISTRY["listener_port_range"]
    assert (il.default, il.wire, il.managed, il.tighten_dir, il.section) == (True, "policy", True, "lower", "network")
    assert R.tighter(il, True, False) is False and R.loosens(il, True, False)     # a managed policy may only turn it off
    assert (pr.default, pr.wire, "node" in pr.scopes) == ("41000-41999", "policy", True)
    for key in ("listener_probe_endpoint", "listener_stun_server"):
        d = R.REGISTRY[key]
        assert (d.default, d.scopes, d.wire, d.section) == (None, ("fleet",), "policy", "network")
    assert R.check("listener_port_range", "42000-42099") == "42000-42099"
    for key, bad in (("listener_port_range", "80-90"), ("listener_port_range", "5000-4000"),
                     ("listener_probe_endpoint", "http://probe.example.net"), ("listener_stun_server", "stun.example.net")):
        with pytest.raises(R.SettingError):
            R.check(key, bad)
    assert "network" in R.NODE_SECTIONS and R.SECTIONS["network"][0] == "Network"
    from oarbank.coordinator.settings import rustgen
    assert '"inbound_listeners"' in rustgen.render() and "pub const INBOUND_LISTENERS: bool = true;" in rustgen.render()


def test_the_policy_carries_the_network_keys(db):
    a = node(db)
    pol = hb(db, a)["policy"]
    assert pol["inbound_listeners"] is True and pol["listener_port_range"] == "41000-41999"
    assert pol["listener_probe_endpoint"] is None and pol["listener_stun_server"] is None


# ------------------------------------------------------------------ reports and directives

def test_the_heartbeat_keeps_the_reports_and_the_directives_carry_the_rest(db):
    a = node(db)
    configure(db, a)
    d = hb(db, a, peer_ip="203.0.113.9", listeners=[listening()], portmaps=[portmap()], network=network(),
           listener_talkers={"publicecho/echo": [{"addr": "203.0.113.5", "conns": 40, "refused": 2, "last": 1.0}] * 30})
    assert d["observed_addr"] == "203.0.113.9" and d["listener_probes"] == [] and d["dial_probes"] == []
    assert d["listener_reachability"] == {} and d["send_listener_talkers"] is False
    assert json.loads(d["statement"]["statement"])["listeners"]["publicecho/echo"]["mapping"] == "auto"
    n = fresh(db, a)
    rep = listeners.report(n)
    assert rep["listeners"][0]["external"] == "198.51.100.7:9000" and rep["portmaps"][0]["protocol"] == "natpmp"
    assert rep["network"]["router_mappings"][0]["ours"] is False and n["listeners_at"]
    assert len(json.loads(n["listener_talkers_json"])["publicecho/echo"]) == listeners.MAX_TALKERS
    for private in ("192.168.1.5", "100.101.102.103", "10.0.0.1", "127.0.0.1", "fd7a:115c:a1e0::1", "fe80::1"):
        assert "observed_addr" not in hb(db, a, peer_ip=private)
    assert hb(db, a, peer_ip="2001:db8::5")["observed_addr"] == "2001:db8::5"
    hb(db, a, listeners=[listening()] * 500)                            # bounded
    assert len(listeners.report(fresh(db, a))["listeners"]) == listeners.MAX_LISTENERS


def test_looking_at_a_listener_asks_for_the_top_talkers_once(db):
    from fastapi.testclient import TestClient
    from oarbank.coordinator import app as coord_app
    from helpers import admin_headers
    a = node(db)
    hb(db, a, listeners=[listening()], network=network())
    api = TestClient(coord_app.admin_app(db), base_url="http://127.0.0.1:7401")
    doc = api.get(f"/api/v1/nodes/{a['node_id']}/listeners/publicecho/echo", headers=admin_headers(db)).json()
    assert doc["listener"]["key"] == "publicecho/echo" and doc["listener"]["talkers"] is None
    assert api.get(f"/api/v1/nodes/{a['node_id']}/listeners/publicecho/nope", headers=admin_headers(db)).status_code == 404
    assert hb(db, a)["send_listener_talkers"] is True
    hb(db, a, listener_talkers={"publicecho/echo": [{"addr": "203.0.113.5", "conns": 40, "refused": 2, "last": 1.0}]})
    assert hb(db, a)["send_listener_talkers"] is False                  # sent once
    doc = api.get(f"/api/v1/nodes/{a['node_id']}/listeners/publicecho/echo", headers=admin_headers(db)).json()
    assert doc["listener"]["talkers"][0]["addr"] == "203.0.113.5"
    listeners.tick(db, clock.now() + listeners.TALKERS_TTL_S + 1)       # kept 10 minutes only
    assert fresh(db, a)["listener_talkers_json"] is None
    full = api.get("/api/v1/listeners", headers=admin_headers(db)).json()
    assert [x["hostname"] for x in full["nodes"]] == ["a"] and full["nodes"][0]["router_mappings"][0]["external_port"] == 8080
    assert api.get(f"/api/v1/nodes/{a['node_id']}", headers=admin_headers(db)).json()["listeners"]["listeners"][0]["key"] == "publicecho/echo"


# ------------------------------------------------------------------ probes (D49)

def probe_fleet(db):
    """a (the target, public 198.51.100.7), b (public 203.0.113.20), c (address unknown), d (cannot probe), e (shares a's
    address)."""
    a, b, c = node(db, "a"), node(db, "b"), node(db, "c")
    d = node(db, "d", {**FACTS, "listeners": {"version": 1}})
    e = node(db, "e")
    configure(db, a)
    hb(db, b, network=network("203.0.113.20"), listeners=[], portmaps=[])
    hb(db, c)
    hb(db, d, network=network("203.0.113.30"))
    hb(db, e, network=network("198.51.100.7"))
    return a, b, c, d, e


def test_a_probe_goes_to_a_node_on_another_network_with_a_nonce_only_the_two_know(db):
    a, b, c, d, e = probe_fleet(db)
    hb(db, a, listeners=[listening(probe_wanted=True)], network=network())
    p = db.one("SELECT * FROM listener_probes WHERE node_id=?", (a["node_id"],))
    assert p["prober"] == b["node_id"] and (p["host"], p["port"]) == ("198.51.100.7", 9000) and p["state"] == "pending"
    assert len(p["probe_id"]) == 32 and len(p["nonce"]) == 32 and p["via"] == f"fleet:{b['node_id']}"
    da, dbb, dc = hb(db, a), hb(db, b), hb(db, c)
    assert da["listener_probes"] == [{"probe_id": p["probe_id"], "key": "publicecho/echo", "nonce": p["nonce"],
                                      "expires_at": p["created_at"] + 60}]
    assert dbb["dial_probes"] == [{"probe_id": p["probe_id"], "host": "198.51.100.7", "port": 9000, "nonce": p["nonce"]}]
    assert dc["dial_probes"] == [] and da["dial_probes"] == []
    # at most one a minute per listener, whoever asks
    hb(db, a, listeners=[listening(probe_wanted=True)])
    with pytest.raises(core.ApiError, match="at most one probe a minute") as err:
        run_op(db, "listeners.probe", a["node_id"], params={"key": "publicecho/echo"})
    assert err.value.status == 429
    assert db.one("SELECT COUNT(*) n FROM listener_probes")["n"] == 1
    # only the prober may report success; a stranger is ignored
    hb(db, c, probe_results=[{"probe_id": p["probe_id"], "ok": True, "detail": None, "rtt_ms": 12.0}])
    assert db.one("SELECT state FROM listener_probes")["state"] == "pending"
    hb(db, b, probe_results=[{"probe_id": p["probe_id"], "ok": True, "detail": None, "rtt_ms": 41.0}])
    r = hb(db, a)["listener_reachability"]["publicecho/echo"]
    assert (r["state"], r["via"], r["detail"]) == ("reachable", f"fleet:{b['node_id']}", "rtt 41 ms") and r["at"]
    assert hb(db, a)["listener_probes"] == [] and hb(db, b)["dial_probes"] == []


def test_without_a_known_different_address_any_prober_is_tried_and_same_network_tries_another_once(db):
    a, b, c, d, e = probe_fleet(db)
    db.x("UPDATE nodes SET last_heartbeat_at=1 WHERE node_id=?", (b["node_id"],))          # b went away
    f = node(db, "f")
    hb(db, f)
    hb(db, a, listeners=[listening(probe_wanted=True)], network=network())
    p = db.one("SELECT * FROM listener_probes WHERE state='pending'")
    first, other = (c, f) if p["prober"] == c["node_id"] else (f, c)
    assert p["prober"] == first["node_id"]                               # e shares a's address: never chosen
    hb(db, a, probe_results=[{"probe_id": p["probe_id"], "ok": False, "detail": "same_network", "rtt_ms": None}])
    p2 = db.one("SELECT * FROM listener_probes WHERE state='pending'")
    assert p2["prober"] == other["node_id"] and json.loads(p2["tried_json"]) == [first["node_id"]] and p2["nonce"] != p["nonce"]
    hb(db, other, probe_results=[{"probe_id": p2["probe_id"], "ok": False, "detail": "same_network", "rtt_ms": None}])
    r = hb(db, a)["listener_reachability"]["publicecho/echo"]
    assert r["state"] == "no_prober" and r["via"] is None


def test_no_prober_and_expiry(db):
    a = node(db, "a")
    configure(db, a)
    hb(db, a, listeners=[listening(probe_wanted=True)], network=network())
    assert hb(db, a)["listener_reachability"]["publicecho/echo"]["state"] == "no_prober"
    hb(db, a, listeners=[listening(external=None)])
    with pytest.raises(listeners.ListenerError, match="no external address"):
        listeners.schedule(db, a["node_id"], "publicecho/echo", clock.now() + 120)
    hb(db, a, listeners=[listening()])
    b = node(db, "b")
    hb(db, b, network=network("203.0.113.20"))
    t = clock.now() + 120
    listeners.schedule(db, a["node_id"], "publicecho/echo", t)
    listeners.expire_probes(db, t + 61)
    db.x("UPDATE nodes SET last_heartbeat_at=? WHERE node_id=?", (t + 61, b["node_id"]))
    assert listeners.reachability(db, a["node_id"])["publicecho/echo"]["state"] in ("unreachable", "no_prober")
    # the prober online at expiry: unreachable; gone: no_prober
    t2 = t + 200
    db.x("UPDATE nodes SET last_heartbeat_at=? WHERE node_id=?", (t2 + 50, b["node_id"]))
    listeners.schedule(db, a["node_id"], "publicecho/echo", t2)
    listeners.expire_probes(db, t2 + 61)
    assert listeners.reachability(db, a["node_id"])["publicecho/echo"] == {**listeners.reachability(db, a["node_id"])["publicecho/echo"],
                                                                            "state": "unreachable", "detail": "expired"}
    t3 = t2 + 200
    listeners.schedule(db, a["node_id"], "publicecho/echo", t3)
    listeners.expire_probes(db, t3 + 61)                                # b's last heartbeat is long before: offline
    assert listeners.reachability(db, a["node_id"])["publicecho/echo"]["state"] == "no_prober"


def test_check_now_reaches_the_prober(db):
    a, b, *_ = probe_fleet(db)
    hb(db, a, listeners=[listening()], network=network())
    r = run_op(db, "listeners.probe", a["node_id"], params={"key": "publicecho/echo"})
    assert r["result"]["prober"] == b["node_id"] and hb(db, b)["dial_probes"][0]["port"] == 9000
    with pytest.raises(core.ApiError, match="reports no listener"):
        run_op(db, "listeners.probe", a["node_id"], params={"key": "publicecho/peer"})


# ------------------------------------------------------------------ alerts and explain

def test_unreachable_and_saturated_listeners_alert(db):
    a = node(db)
    configure(db, a)
    bad = listening(reachability={"result": "DOUBLE_NAT", "flags": [], "text": "This machine is behind two routers.",
                                  "fix": "Put the provider's device in bridge mode.", "via": None, "at": 1.0})
    hb(db, a, listeners=[bad])
    al = db.one("SELECT * FROM alerts WHERE rule='listener_unreachable:publicecho/echo'")
    assert al["state"] == "pending" and al["subject"] == a["node_id"] and "behind two routers" in al["detail"]
    hb(db, a, listeners=[listening(reachability={"result": "REACHABLE", "flags": [], "text": "Reachable.", "fix": None,
                                                 "via": "fleet:n_x", "at": 2.0})])
    assert db.one("SELECT state FROM alerts WHERE rule='listener_unreachable:publicecho/echo'")["state"] == "dismissed"
    sat = lambda cap: listening(conns={"open": 32, "accepted": 900, "bytes_in": 0, "bytes_out": 0,
                                       "refused": {"rate": 0, "cap": cap, "per_ip": 0, "allow": 0, "held": 0, "disabled": 0}})
    hb(db, a, listeners=[sat(5)])
    assert db.one("SELECT * FROM alerts WHERE rule='listener_saturated:publicecho/echo'")["state"] == "open"
    from oarbank.contracts import alert_rules
    assert alert_rules.policy("listener_unreachable:x")["severity"] == "P3" and alert_rules.policy("listener_saturated:x")["severity"] == "P4"
    doc = explain.explain(db, "node", a["node_id"])
    codes = [s.code for s in doc.summary]
    assert "LISTENER_UNAVAILABLE" not in codes
    hb(db, a, listeners=[listening(state="refused", refused="LISTENERS_FORBIDDEN", detail="the machine's managed policy",
                                   reachability={"result": "PORT_TAKEN", "flags": [], "text": "Port 9000 is forwarded "
                                                 "to another device (192.168.1.31).", "fix": "Free it.", "via": None, "at": 3})])
    doc = explain.explain(db, "node", a["node_id"])
    rows = {s.code: s for s in doc.summary}
    assert rows["LISTENER_UNAVAILABLE"].detail["why"] == "LISTENERS_FORBIDDEN" and "192.168.1.31" in rows["PORT_TAKEN"].detail["text"]
    assert "listeners.configure" in {r.op for r in doc.remedies}


# ------------------------------------------------------------------ S24

def test_s24_holds_for_assigned_listeners_and_catches_a_broken_database(db):
    a = node(db)
    assert invariants.s24_listeners_granted_and_assigned(db) == []
    configure(db, a)
    seq = stmt(db, a)["seq"]
    hb(db, a, listeners=[listening(seq=seq)], portmaps=[portmap()])
    assert invariants.s24_listeners_granted_and_assigned(db) == []
    # removed, but the node still runs the statement that listed it (signing mode lag): fine until it applies the new one
    run_op(db, "listeners.remove", a["node_id"], params={"key": "publicecho/echo"})
    assert invariants.s24_listeners_granted_and_assigned(db) == []
    hb(db, a, listeners=[listening(seq=seq + 1)], portmaps=[portmap()])          # applied the new one, still listening
    v = invariants.s24_listeners_granted_and_assigned(db)
    assert len(v) == 2 and all("neither its current statement" in x for x in v)
    # a listener the module does not request, and a statement the coordinator never issued
    hb(db, a, listeners=[listening(key="publicecho/rogue", seq=seq)], portmaps=[])
    assert "no approved grant" in invariants.s24_listeners_granted_and_assigned(db)[0]
    configure(db, a)
    hb(db, a, listeners=[listening(seq=99)], portmaps=[])
    assert "above the latest issued" in invariants.s24_listeners_granted_and_assigned(db)[0]
    # a closed or refused listener holds nothing open
    hb(db, a, listeners=[listening(key="publicecho/rogue", state="refused", seq=1)], portmaps=[])
    assert invariants.s24_listeners_granted_and_assigned(db) == []
    assert "s24_listeners_granted_and_assigned" in invariants.report(db)["checked"]


# ------------------------------------------------------------------ console and CLI

def test_the_console_renders_the_network_card_and_the_module_listeners(db, monkeypatch):
    from fastapi.testclient import TestClient
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from helpers import sign_in
    a = node(db)
    configure(db, a)
    hb(db, a, listeners=[listening(reachability={"result": "NO_MAPPING_PROTOCOL", "flags": ["DYNAMIC_ADDRESS"],
                                                 "text": "Your router does not accept automatic port mapping.",
                                                 "fix": "Turn on UPnP or NAT-PMP in its settings.", "via": None, "at": 1.0})],
       portmaps=[portmap()], network=network())
    from test_console import SECRET, Server
    from oarbank.coordinator import app as coord_app
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(db.path, f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        state.poll_fleetd(__import__("httpx").Client())
        with TestClient(console_app(state), client=("127.0.0.1", 50001)) as c:
            sign_in(c, db)
            html = c.get(f"/nodes/{a['node_id']}?listener=publicecho/echo").text
            page = c.get("/modules/publicecho/nodes").text
    assert fresh(db, a)["want_talkers_until"]                           # looking asked the node for its top talkers
    assert 'id="network"' in html and "198.51.100.7:9000" in html and "Your router does not accept automatic port mapping." in html
    assert "Turn on UPnP or NAT-PMP in its settings." in html and "a game console" in html and "NO_MAPPING_PROTOCOL" in html
    for op in ("listeners.probe", "listeners.remove", "listeners.disable", "listeners.configure"):
        assert f'action="/do/{op}"' in html, op
    assert "Top client addresses" in html and 'value="publicecho/echo"' in html            # the form offers the listener
    assert 'id="listeners"' in page and "publicecho/echo" in page and "198.51.100.7:9000" in page
    from oarbank.console import forms
    p = forms.params_for("listeners.configure", {"key": "publicecho/echo", "external_port": "9001", "fallback": "",
                                                 "mapping": "upnp", "limit.max_conns": "16", "allow": "198.51.100.0/24, 203.0.113.0/24"}, {})
    assert p == {"key": "publicecho/echo", "external_port": 9001, "internal_port": None, "fallback": None, "mapping": "upnp",
                 "ipv6": None, "bind": None, "limits": {"max_conns": 16}, "allow": ["198.51.100.0/24", "203.0.113.0/24"]}


def test_the_cli_prints_the_agents_words_and_runs_the_operations(db, monkeypatch, capsys):
    from fastapi.testclient import TestClient
    from oarbank.cli import main as cli
    from oarbank.coordinator import app as coord_app
    from helpers import admin_headers
    a = node(db)
    configure(db, a)
    hb(db, a, listeners=[listening(reachability={"result": "CGNAT", "flags": [], "text": "Your internet provider shares one "
                                                 "public address among many customers.", "fix": "Ask the provider for a public "
                                                 "IPv4 address.", "via": None, "at": 1.0})], portmaps=[portmap()], network=network())
    api = TestClient(coord_app.admin_app(db), base_url="http://127.0.0.1:7401")
    monkeypatch.setattr(cli, "api", lambda method, path, body=None, timeout=600:
                        api.request(method, path, headers=admin_headers(db), json=body).json())
    calls = []
    monkeypatch.setattr(cli, "run_op", lambda op, target=None, params=None, reason=None, yes=False, **k:
                        calls.append((op, target, params)) or {"result": {"ok": True}})
    ns = lambda **kw: argparse.Namespace(**{"action": "list", "target": None, "key": None, "node": None, "all": False,
                                            "external_port": None, "fallback": None, "mapping": None, "ipv6": None,
                                            "bind": None, "internal_port": None, "limit": None, "allow": None,
                                            "json": False, "reason": None, "yes": True, **kw})
    cli.cmd_listener(ns())
    out = capsys.readouterr().out
    assert "publicecho/echo" in out and "Your internet provider shares one public address among many customers." in out
    assert "fix: Ask the provider for a public IPv4 address." in out
    cli.cmd_listener(ns(action="mappings"))
    out = capsys.readouterr().out
    assert "natpmp" in out and "198.51.100.7:9000 -> 192.168.1.20:41000" in out and "a game console" in out
    cli.cmd_listener(ns(action="show", target="a", key="publicecho/echo"))
    assert "top client addresses: asked for" in capsys.readouterr().out and fresh(db, a)["want_talkers_until"]
    cli.cmd_listener(ns(action="set", target="a", key="publicecho/echo", external_port=9001, limit=["max_conns=16"],
                        allow=["198.51.100.0/24,203.0.113.0/24"]))
    cli.cmd_listener(ns(action="remove", target="a", key="publicecho/echo"))
    cli.cmd_listener(ns(action="probe", target="a", key="publicecho/echo"))
    cli.cmd_listener(ns(action="disable", all=True))
    cli.cmd_listener(ns(action="resume", node="a"))
    assert calls == [("listeners.configure", "a", {"key": "publicecho/echo", "external_port": 9001, "limits": {"max_conns": 16},
                                                   "allow": ["198.51.100.0/24", "203.0.113.0/24"]}),
                     ("listeners.remove", "a", {"key": "publicecho/echo"}), ("listeners.probe", "a", {"key": "publicecho/echo"}),
                     ("listeners.disable", "fleet", {}), ("listeners.resume", "a", {})]
    with pytest.raises(SystemExit):
        cli.cmd_listener(ns(action="disable"))
    args = cli.parser().parse_args(["listener", "set", "a", "publicecho/echo", "--external-port", "9001", "--limit",
                                    "max_conns=16", "--ipv6", "off"])
    assert (args.target, args.key, args.external_port, args.ipv6) == ("a", "publicecho/echo", 9001, "off")


def test_old_probes_go_but_each_listeners_latest_outcome_stays(db):
    a, b, *_ = probe_fleet(db)
    hb(db, a, listeners=[listening()], network=network())
    t = clock.now()
    for i in range(3):
        db.x("UPDATE nodes SET last_heartbeat_at=? WHERE node_id=?", (t + i * 100, b["node_id"]))
        listeners.schedule(db, a["node_id"], "publicecho/echo", t + i * 100)
        listeners.expire_probes(db, t + i * 100 + 61)
    assert db.one("SELECT COUNT(*) n FROM listener_probes")["n"] == 3
    listeners._LAST_TICK.clear()
    listeners.tick(db, t + 3 * 86400)
    assert db.one("SELECT COUNT(*) n FROM listener_probes")["n"] == 1
    assert listeners.reachability(db, a["node_id"])["publicecho/echo"]["at"] == t + 261
