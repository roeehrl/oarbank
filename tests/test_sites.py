"""Sites on the coordinator (PLAN D55; docs/design/sites.md): sites as owner operations (one site per node), the hold
from the members' `uplink`-tagged phases (on, unreadable, or a silent node), transfer leases under the budget and
their revocation, network-heavy jobs held and budgeted by claim and explained, suggestions from keyed network
fingerprints (never an address), the measured-capacity hint, S27, and a property test of the budget and the hold."""
import dataclasses
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from oarbank.coordinator import clock, core, explain, invariants, modcalls, ops, protection, sites
from oarbank_sdk import manifest as mf

from helpers import PARAMS, READY, SCENES, certify, create_study, enrolled_node, fresh, make_db, run_op

T0 = 1_900_000_000.0


@pytest.fixture
def db(tmp_path):
    clock.set_fake(T0)
    d = make_db(tmp_path / "oarbank.sqlite3")
    yield d
    clock.set_fake(None)
    d.conn.close()


def phase(on=False, readable=True, tags=("uplink",), key="trainer#0"):
    return {"key": key, "rule": key.split("#")[0], "block": 0, "on": on, "since": T0, "readable": readable,
            "reader": "agent", "tags": list(tags), "immediate": True}


def hb(db, node, phases=None, **body):
    tel = {"protection": {"phases": phases}} if phases is not None else {}
    return core.heartbeat(db, fresh(db, node), {"telemetry": tel, "capacity": {"pools": {"scorer": 4}}, **body})


def nodes(db, *names):
    out = []
    for n in names:
        node = enrolled_node(db, n)[1]
        db.x("UPDATE nodes SET lifecycle='ready' WHERE node_id=?", (node["node_id"],))
        out.append(fresh(db, node))
    return out


def make_site(db, name="home", members=(), **budget):
    return run_op(db, "sites.create", name, {"nodes": [m["node_id"] for m in members], **budget})["result"]


def test_a_node_is_at_one_site_and_operations_say_what_moves(db):
    a, b, c = nodes(db, "mini", "studio", "laptop")
    plan = ops.execute(db, ops.OpRequest(op="sites.create", actor="o", target="home", params={"nodes": ["mini", "studio"]},
                                         dry_run=True))["plan"]
    assert plan["impact"]["nodes"] == ["mini: joins", "studio: joins"] and "network-heavy" in plan["impact"]["summary"]
    home = make_site(db, "home", (a, b))
    assert (home["max_transfers"], home["max_heavy_jobs"], home["uplink_mbps"]) == (1, 1, None)
    with pytest.raises(core.ApiError) as e:
        make_site(db, "home", (c,))
    assert e.value.code == "exists"
    office = make_site(db, "office", (c,), uplink_mbps=200, max_transfers=2)
    # a node at another site moves (it shares one line)
    plan = ops.execute(db, ops.OpRequest(op="sites.assign", actor="o", target="office", params={"nodes": ["studio"]},
                                         dry_run=True))["plan"]
    assert plan["impact"]["nodes"] == ["studio: moves from home"]
    run_op(db, "sites.assign", "office", {"nodes": ["studio"]})
    assert sites.members(db, home["site_id"]) == [a["node_id"]]
    assert sorted(sites.members(db, office["site_id"])) == sorted([b["node_id"], c["node_id"]])
    run_op(db, "sites.unassign", None, {"nodes": ["laptop"]})
    assert sites.site_of(db, c["node_id"]) is None
    with pytest.raises(core.ApiError):
        run_op(db, "sites.update", "office", {"max_transfers": 0})
    run_op(db, "sites.update", "office", {"name": "lab", "uplink_mbps": 300})
    assert sites.get(db, "lab")["uplink_mbps"] == 300
    out = run_op(db, "sites.delete", "lab")
    assert out["result"]["released"] == [b["node_id"]] and sites.site_of(db, b["node_id"]) is None
    audit = [r["operation"] for r in db.q("SELECT operation FROM audit WHERE operation LIKE 'sites.%' AND dry_run=0 AND outcome='ok'")]
    assert audit.count("sites.create") == 2 and "sites.delete" in audit
    assert not invariants.check_all(db)


def test_the_hold_follows_tagged_phases_on_unreadable_or_silent(db):
    a, b = nodes(db, "mini", "studio")
    home = make_site(db, "home", (a, b))
    sid = home["site_id"]
    hb(db, a, [phase(), phase(True, tags=("other",), key="other#0")])
    hb(db, b, [])
    d = hb(db, b)
    assert d["uplink"]["site"]["hold"] is False and d["uplink"]["site"]["name"] == "home" and d["uplink"]["salt"]
    # mini's protected process begins an upload: every node of the site is told
    hb(db, a, [phase(True)])
    d = hb(db, b)
    s = d["uplink"]["site"]
    assert s["hold"] and s["code"] == "SITE_UPLINK_BUSY" and "mini's rule trainer is in an upload phase" in s["why"]
    assert sites.summary(db, sites.get(db, "home"))["state"].startswith("paused because mini's rule trainer")
    assert sites.state(db, sites.get(db, sid))["hold"] == protection.any_phase_on(db, [a["node_id"], b["node_id"]], "uplink")["on"]
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='site_uplink_hold'")["n"] == 1
    hb(db, a, [phase(False)])
    assert hb(db, b)["uplink"]["site"]["hold"] is False
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='site_uplink_free'")["n"] == 1
    # an unreadable phase counts as on
    hb(db, a, [phase(False, readable=False)])
    assert "cannot be read" in sites.state(db, sites.get(db, sid))["why"]
    hb(db, a, [phase(False)])
    # a node with an uplink phase that falls silent holds its site (the reaper sees it)
    clock.advance(protection.PHASES_FRESH_S + 5)
    hb(db, b, [])
    sites.tick(db)
    st = sites.state(db, sites.get(db, sid))
    assert st["hold"] and "has not reported" in st["why"]
    # a node without uplink phases holds nothing by being silent
    hb(db, a, [phase(False)])
    clock.advance(protection.PHASES_FRESH_S + 5)
    hb(db, a, [phase(False)])
    assert not sites.state(db, sites.get(db, sid))["hold"]


def test_leases_keep_to_the_budget_and_a_hold_revokes_them(db):
    a, b, c = nodes(db, "mini", "studio", "laptop")
    home = make_site(db, "home", (a, b), uplink_mbps=100, max_transfers=2)
    hb(db, a, [phase()])
    r1 = sites.lease(db, fresh(db, a), {"kind": "staging", "dir": "down", "bytes": 1 << 30})
    r2 = sites.lease(db, fresh(db, b), {"kind": "upload", "dir": "up", "bytes": 1 << 30})
    assert r1["granted"] and r2["granted"] and r1["mbps"] == r2["mbps"] == 50
    r3 = sites.lease(db, fresh(db, b), {"kind": "upload", "dir": "up"})
    assert not r3["granted"] and r3["code"] == "SITE_UPLINK_BUDGET" and r3["retry_s"] == sites.POLL_S
    # a node at no site needs no lease
    assert sites.lease(db, fresh(db, c), {"kind": "staging"}) == {"granted": True, "lease_id": None, "site": None}
    assert sites.renew(db, fresh(db, a), {"leases": [r1["lease_id"]]})["leases"] == {r1["lease_id"]: "ok"}
    # someone else's lease is never renewed for this node
    assert sites.renew(db, fresh(db, a), {"leases": [r2["lease_id"]]})["leases"][r2["lease_id"]] == "revoked"
    assert not invariants.s27_site_uplink_budget(db)
    # the phase begins: every lease is revoked and none is granted until it ends
    hb(db, a, [phase(True)])
    out = sites.renew(db, fresh(db, b), {"leases": [r2["lease_id"]]})
    assert out["leases"] == {r2["lease_id"]: "revoked"} and out["site"]["hold"]
    assert db.one("SELECT COUNT(*) n FROM uplink_leases")["n"] == 0
    refused = sites.lease(db, fresh(db, b), {"kind": "upload"})
    assert not refused["granted"] and refused["code"] == "SITE_UPLINK_BUSY" and "mini" in refused["why"]
    assert not invariants.s27_site_uplink_budget(db)
    hb(db, a, [phase(False)])
    r4 = sites.lease(db, fresh(db, b), {"kind": "upload", "dir": "up", "bytes": 64 << 20})
    assert r4["granted"]
    # a lease nobody renews is gone after its TTL
    clock.advance(sites.LEASE_TTL_S + 1)
    hb(db, a, [phase(False)])
    sites.tick(db)
    assert sites.renew(db, fresh(db, b), {"leases": [r4["lease_id"]]})["leases"][r4["lease_id"]] == "revoked"
    # a budget change renews every lease at the new terms
    r5 = sites.lease(db, fresh(db, a), {"kind": "staging"})
    run_op(db, "sites.update", "home", {"max_transfers": 1})
    assert sites.renew(db, fresh(db, a), {"leases": [r5["lease_id"]]})["leases"][r5["lease_id"]] == "revoked"
    assert sites.lease(db, fresh(db, a), {"kind": "staging"})["mbps"] == 100
    sites.release(db, fresh(db, a), {"lease_id": "nope"})
    assert home["site_id"]


def test_s27_names_a_lease_over_the_budget_or_during_a_hold(db):
    a, = nodes(db, "mini")
    home = make_site(db, "home", (a,), uplink_mbps=10, max_transfers=1)
    for i in range(2):
        db.x("INSERT INTO uplink_leases(lease_id,site_id,node_id,mbps,granted_at,expires_at) VALUES(?,?,?,?,?,?)",
             (f"x{i}", home["site_id"], a["node_id"], 10, T0, T0 + 60))
    db.x("UPDATE sites SET hold_on=1, hold_why='test'")
    v = invariants.s27_site_uplink_budget(db)
    assert any("2 live transfer leases, budget 1" in x for x in v) and any("20 Mbit/s" in x for x in v)
    assert any("while it holds" in x for x in v)


BODY = {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY}


def heavy_relay(monkeypatch):
    """The relay fixture with every stage declaring network-heavy use (stages[].requires.resources.network)."""
    info = modcalls.info("relay")
    man = info.manifest
    stages = [s.model_copy(update={"requires": s.requires.model_copy(update={
        "resources": s.requires.resources.model_copy(update={"network": "heavy"})})}) for s in man.stages]
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=man.model_copy(update={"stages": stages})))


def test_network_heavy_jobs_are_held_and_budgeted_and_explain_says_why(db, monkeypatch):
    heavy_relay(monkeypatch)
    mini = certify(db, enrolled_node(db, "mini")[1])
    studio = certify(db, enrolled_node(db, "studio")[1])
    make_site(db, "home", (mini, studio), max_heavy_jobs=1)
    sid = create_study(db, "p", [{"label": "c0", "params": {**PARAMS, "samples": 21}}], list(SCENES[:2]),
                       {"label": "base", "params": PARAMS})
    jobs = db.q("SELECT * FROM jobs WHERE campaign_id=? AND state='pending' ORDER BY job_id", (sid,))
    assert jobs and all(json.loads(j["resources_json"]).get("network") == "heavy" for j in jobs)
    # studio's protected process is uploading: nothing network-heavy is admitted anywhere at the site
    hb(db, studio, [phase(True)])
    assert not [g for g in core.claim(db, fresh(db, mini), BODY)["grants"] if g["module"] == "relay"]
    doc = explain.job_doc(db, jobs[0]["job_id"], bodies={mini["node_id"]: BODY}, now=clock.now())
    codes = {r.code for m in doc.matrix if m.node == "mini" for r in m.results if r.outcome != "pass"}
    assert "SITE_UPLINK_BUSY" in codes
    text = json.dumps(doc.model_dump(), default=str)
    assert "site home holds such work while studio's rule trainer is in an upload phase" in text
    # free again: the budget admits one network-heavy job at the site, then explains the rest
    hb(db, studio, [phase(False)])
    g = [g for g in core.claim(db, fresh(db, mini), BODY)["grants"] if g["module"] == "relay"]
    assert len(g) == 1 and g[0]["spec"]["resources"]["network"] == "heavy"
    assert not [g for g in core.claim(db, fresh(db, studio), BODY)["grants"] if g["module"] == "relay"]
    left = db.one("SELECT job_id FROM jobs WHERE campaign_id=? AND state='pending' ORDER BY job_id", (sid,))
    doc = explain.job_doc(db, left["job_id"], bodies={studio["node_id"]: BODY}, now=clock.now())
    codes = {r.code for m in doc.matrix if m.node == "studio" for r in m.results if r.outcome != "pass"}
    assert "SITE_UPLINK_BUDGET" in codes
    assert sites.usage(db, sites.get(db, "home"))["heavy_jobs"] == 1
    # a node at no site is not held to the site's budget
    run_op(db, "sites.unassign", None, {"nodes": ["studio"]})
    assert [g for g in core.claim(db, fresh(db, studio), BODY)["grants"] if g["module"] == "relay"]
    # a released network-heavy job (it could not pause) is no failure
    core.release(db, fresh(db, mini), g[0]["attempt_id"], "preempt_site")
    assert db.one("SELECT exec_failures FROM jobs WHERE job_id=?", (g[0]["job_id"],))["exec_failures"] == 0


def test_suggestions_rest_on_keyed_fingerprints_never_addresses(db):
    a, b, c = nodes(db, "mini", "studio", "laptop")
    salt = sites.agent_salt(db)
    assert salt == sites.agent_salt(db) and len(salt) == 64
    gw = "ab" * 16
    sites.observe_network(db, a, {"gateway_fp": gw}, "192.168.1.20")
    sites.observe_network(db, b, {"gateway_fp": gw}, "100.64.0.7")
    sites.observe_network(db, c, {"gateway_fp": "cd" * 16}, "203.0.113.9")       # documentation range: not global
    sites.observe_network(db, c, {"gateway_fp": "cd" * 16}, "8.8.8.8")
    rows = {r["node_id"]: r for r in db.q("SELECT * FROM node_net")}
    assert rows[a["node_id"]]["public_fp"] is None and rows[b["node_id"]]["public_fp"] is None
    assert rows[c["node_id"]]["public_fp"] and "8.8.8.8" not in json.dumps(rows)
    sug = sites.suggestions(db)
    assert len(sug) == 1 and sug[0]["evidence"] == "gateway" and [n["hostname"] for n in sug[0]["nodes"]] == ["mini", "studio"]
    assert gw not in json.dumps(sug)                                    # only a short label of the fingerprint
    make_site(db, "home", (a, b), suggestion=sug[0]["key"])
    assert sites.suggestions(db) == []
    # two nodes behind one public address at different sites are offered again, unless dismissed
    sites.observe_network(db, a, {"gateway_fp": gw}, "8.8.8.8")
    sug = sites.suggestions(db)
    assert len(sug) == 1 and sug[0]["evidence"] == "public" and sug[0]["sites"] == ["home"]
    run_op(db, "sites.dismiss", sug[0]["key"])
    assert sites.suggestions(db) == []
    assert sites.public_fp(db, "2001:4860:4860::8888") == sites.public_fp(db, "2001:4860:4860::1")   # one /64


def test_the_hint_is_the_rate_large_solo_unpaced_transfers_reached(db):
    a, b = nodes(db, "mini", "studio")
    make_site(db, "home", (a, b), max_transfers=2)
    for i, (size, secs, paced) in enumerate([(1 << 30, 40, False), (1 << 30, 35, False), (1 << 30, 80, True), (1 << 20, 1, False)]):
        lid = sites.lease(db, fresh(db, a), {"kind": "upload", "dir": "up"})["lease_id"]
        sites.release(db, fresh(db, a), {"lease_id": lid, "dir": "up", "bytes": size, "seconds": secs, "paced": paced})
    # two at once: neither counts
    l1 = sites.lease(db, fresh(db, a), {"dir": "up"})["lease_id"]
    l2 = sites.lease(db, fresh(db, b), {"dir": "up"})["lease_id"]
    for n, lid in ((a, l1), (b, l2)):
        sites.release(db, fresh(db, n), {"lease_id": lid, "dir": "up", "bytes": 1 << 30, "seconds": 150})
    h = sites.hint(db, sites.get(db, "home")["site_id"])
    assert h == {"up": {"mbps": round((1 << 30) * 8 / 35 / 1e6, 1), "n": 2}}


def test_a_node_detail_names_its_site_and_its_state(db):
    a, b = nodes(db, "mini", "studio")
    make_site(db, "home", (a, b))
    hb(db, a, [phase(True)])
    from oarbank.coordinator import detail
    d = detail.node(db, "studio", clock.now(), lambda m: None)
    assert d["site"]["name"] == "home" and d["site"]["hold"] and d["site"]["state"].startswith("paused because mini's")
    listing = sites.listing(db)
    assert listing["sites"][0]["members"] == ["mini", "studio"] and listing["unplaced"] == []


# ------------------------------------------------------------------ property: the budget and the hold

ACTIONS = st.lists(st.tuples(st.sampled_from(["lease", "renew", "release", "phase_on", "phase_off", "unreadable", "silent",
                                              "advance", "tick", "budget"]),
                             st.integers(0, 2), st.integers(1, 4)), min_size=1, max_size=40)


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(ACTIONS)
def test_property_the_budget_is_never_exceeded_and_a_hold_grants_nothing(tmp_path_factory, actions):
    clock.set_fake(T0)
    db = make_db(tmp_path_factory.mktemp("p") / "oarbank.sqlite3", modules=())
    try:
        ns = nodes(db, "a", "b", "c")
        site = make_site(db, "home", ns, uplink_mbps=90, max_transfers=2)
        held = {n["node_id"]: [phase()] for n in ns}
        mine = {n["node_id"]: [] for n in ns}
        for n in ns:
            hb(db, n, held[n["node_id"]])
        for act, i, k in actions:
            n = fresh(db, ns[i])
            nid = n["node_id"]
            if act == "lease":
                r = sites.lease(db, n, {"kind": "staging"})
                hold = protection.any_phase_on(db, [x["node_id"] for x in ns], "uplink", now=clock.now())["on"]
                if hold:
                    assert not r["granted"], "a lease granted while a tagged phase is on, unreadable or silent"
                if r.get("lease_id"):
                    mine[nid].append(r["lease_id"])
            elif act == "renew":
                out = sites.renew(db, n, {"leases": mine[nid]})
                if out["site"]["hold"]:
                    assert all(v == "revoked" for v in out["leases"].values())
                mine[nid] = [x for x, v in out["leases"].items() if v == "ok"]
            elif act == "release" and mine[nid]:
                sites.release(db, n, {"lease_id": mine[nid].pop(0), "bytes": k << 20, "seconds": k})
            elif act in ("phase_on", "phase_off", "unreadable"):
                held[nid] = [phase(act == "phase_on", readable=act != "unreadable")]
                hb(db, n, held[nid])
            elif act == "silent":
                clock.advance(protection.PHASES_FRESH_S + 1)
                for x in ns:
                    if x["node_id"] != nid:
                        hb(db, x, held[x["node_id"]])
            elif act == "advance":
                clock.advance(k * 3)
            elif act == "tick":
                sites.tick(db)
            elif act == "budget":
                run_op(db, "sites.update", site["site_id"], {"max_transfers": k, "uplink_mbps": 30 * k})
            assert not invariants.s27_site_uplink_budget(db), (act, invariants.s27_site_uplink_budget(db))
            s = sites.get(db, "home")
            live = db.q("SELECT mbps FROM uplink_leases WHERE expires_at>=?", (clock.now(),))
            assert len(live) <= s["max_transfers"] and sum(x["mbps"] or 0 for x in live) <= s["uplink_mbps"] + 1e-6
    finally:
        clock.set_fake(None)
        db.conn.close()
