"""Workloads (docs/design/workloads.md, PLAN D45, D46): the owner assigns a module's workload to nodes; a workload with a
per-node identity runs only under a seat lease whose fence rises with each new holder, named by the node's secrets, so
one identity never runs on two nodes; a seat moves on its holder's fenced release or after its lease and grace; a
workload's secrets reach only the seat's holder; its report events reach the module's workload.report verb."""
import shutil
from pathlib import Path

import pytest

from oarbank.coordinator import clock, core, invariants, modcalls, modstore, ops, releases, workloads as W

from helpers import FACTS, enrolled_node, fresh, install, make_db, run_op

EXAMPLE = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "workload"
KEY = "hotkey-value-0001"


def identity_module(tmp_path) -> Path:
    """The SDK's workload example with a per-node identity: one secret, the seat named by its value on each node."""
    src = tmp_path / "workload"
    shutil.copytree(EXAMPLE, src)
    m = (src / "oarbank-module.toml").read_text(encoding="utf-8")
    m = m.replace('identity = "none"', 'identity = "per_node"\nsecrets = ["signing_key"]')
    m = m.replace("[results]", '[[secrets]]\nname = "signing_key"\ndescription = "The key the worker signs with"\n\n[results]')
    (src / "oarbank-module.toml").write_text(m, encoding="utf-8")
    return src


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr(modstore, "CORE_VERSION", "2.10.0")       # the manifest needs core >= 2.10 (still numbered 2.8)
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    install(d, identity_module(tmp_path))
    modcalls.use(d)
    releases.sync(d)
    return d


def node(db, name):
    _, n = enrolled_node(db, name, FACTS)
    core.hello(db, n, {"release_id": releases.assigned(db, fresh(db, n)), "facts": FACTS, "live_attempts": [], "ready_datasets": []})
    return fresh(db, n)


def set_key(db, n, value=KEY):
    return run_op(db, "secrets.set", "workload", {"name": "signing_key", "node": n["node_id"]}, secret=value)["result"]


def assign(db, n):
    """Previewed, then applied: the plan's impact is what the owner reviewed."""
    req = dict(op="workloads.assign", actor="test", source="system", target="workload/worker", params={"node": n["node_id"]},
               reason="test")
    plan = ops.execute(db, ops.OpRequest(**req, dry_run=True))["plan"]
    ops.execute(db, ops.OpRequest(**req, plan_id=plan["plan_id"]))
    return plan


def beat(db, n, workloads=None, reports=None):
    body = {"attempts": [], "ready_datasets": []}
    if workloads is not None:
        body["workloads"] = workloads
    if reports is not None:
        body["workload_reports"] = reports
    return core.heartbeat(db, fresh(db, n), body)


def entry(d):
    return next(e for e in d["workloads"] if e["key"] == "workload/worker")


def test_the_release_carries_the_workload_and_the_preview_names_what_the_node_gets(db):
    entry_ = releases.module_entry("workload", "0.1.0", "d", Path(modcalls.info("workload").path), "darwin-arm64")
    w = entry_["workloads"][0]
    assert (w["name"], w["identity"], w["secrets"], w["pause_tolerance_s"], w["reports"]) == \
        ("worker", "per_node", ["signing_key"], 60, True)
    n = node(db, "mini")
    set_key(db, n)
    plan = assign(db, n)
    row = plan["impact"]["nodes"][0]
    assert (row["node_id"], row["identity"], row["blocked"]) == (n["node_id"], "per_node", None)
    assert row["seat_id"].startswith("s_") and [s["name"] for s in row["secrets"]] == ["signing_key"]
    assert KEY not in str(plan)
    assert db.one("SELECT * FROM workload_assignments")["assigned_by"] == "test"


def test_a_seat_is_leased_to_one_node_and_moves_only_on_its_fenced_release_or_after_its_lease(db, monkeypatch):
    a, b = node(db, "mini"), node(db, "desk")
    set_key(db, a)
    set_key(db, b)                                                  # the same key on both: one identity, one seat
    assign(db, a)
    assign(db, b)
    da = entry(beat(db, a))
    assert (da["desired"], da["fence"], da["reason"]) == ("running", 1, None) and 1700 < da["lease_s"] <= 1800
    db_ = entry(beat(db, b))
    assert (db_["desired"], db_["reason"], db_["seat_id"]) == ("stopped", "WORKLOAD_SEAT_ELSEWHERE", da["seat_id"])
    seat = da["seat_id"]
    running = [{"key": "workload/worker", "running": True, "seat_id": seat, "fence": 1}]
    beat(db, a, running)
    assert invariants.s26_single_seat(db) == []
    # a stop report without release keeps the seat; one with an older fence is ignored
    beat(db, a, [{"key": "workload/worker", "running": False, "seat_id": seat, "fence": 1}])
    assert entry(beat(db, b))["reason"] == "WORKLOAD_SEAT_ELSEWHERE"
    beat(db, a, [{"key": "workload/worker", "running": False, "release": True, "seat_id": seat, "fence": 0}])
    assert entry(beat(db, b))["reason"] == "WORKLOAD_SEAT_ELSEWHERE"
    # unassigned, a stops and gives the seat up with its fence: the seat moves at once, with a higher fence
    run_op(db, "workloads.unassign", "workload/worker", {"node": a["node_id"]}, reason="t")
    beat(db, a, [{"key": "workload/worker", "running": False, "release": True, "seat_id": seat, "fence": 1}])
    eb = entry(beat(db, b))
    assert (eb["desired"], eb["fence"]) == ("running", 2)
    # b's agent goes quiet: only after its lease and the grace may a (assigned again) take the seat
    assign(db, a)
    t0 = clock.now()
    monkeypatch.setattr(clock, "now", lambda: t0 + W.LEASE_S + 30)
    assert entry(beat(db, a))["reason"] == "WORKLOAD_SEAT_ELSEWHERE"
    monkeypatch.setattr(clock, "now", lambda: t0 + W.LEASE_S + W.GRACE_S + 5)
    ea = entry(beat(db, a))
    assert (ea["desired"], ea["fence"]) == ("running", 3), ea


def test_s26_sees_one_identity_running_on_two_nodes(db):
    a, b = node(db, "mini"), node(db, "desk")
    set_key(db, a)
    set_key(db, b)
    assign(db, a)
    seat = entry(beat(db, a))["seat_id"]
    beat(db, a, [{"key": "workload/worker", "running": True, "seat_id": seat, "fence": 1}])
    beat(db, b, [{"key": "workload/worker", "running": True, "seat_id": seat, "fence": 1}])
    v = invariants.s26_single_seat(db)
    assert any("runs on 2 nodes" in x for x in v), v


def test_secrets_reach_only_the_seats_holder_and_a_shared_value_is_refused(db):
    from helpers import agent_client, node_headers
    der_a, a = enrolled_node(db, "mini", FACTS)
    core.hello(db, a, {"release_id": releases.assigned(db, fresh(db, a)), "facts": FACTS, "live_attempts": [], "ready_datasets": []})
    set_key(db, a)
    assign(db, fresh(db, a))
    e = entry(beat(db, a))
    c = agent_client(db)
    body = {"key": "workload/worker", "seat_id": e["seat_id"], "fence": e["fence"]}
    r = c.post("/v1/agent/workloads/secrets", json=body, headers=node_headers(der_a))
    assert r.status_code == 200 and r.json() == {"secrets": {"signing_key": KEY}}
    r = c.post("/v1/agent/workloads/secrets", json={**body, "fence": e["fence"] + 1}, headers=node_headers(der_a))
    assert r.status_code == 409 and r.json()["error"] == "seat_not_held" and KEY not in r.text
    # a value set for the whole module is no per-node identity
    b = node(db, "desk")
    run_op(db, "secrets.set", "workload", {"name": "signing_key"}, secret="shared-for-all")
    with pytest.raises(ops.OpError, match="workload_identity_shared"):
        assign(db, b)


def test_unassign_and_restart(db):
    a = node(db, "mini")
    set_key(db, a)
    assign(db, a)
    run_op(db, "workloads.restart", "workload/worker", {"node": a["node_id"]}, reason="t")
    assert entry(beat(db, a))["restart_seq"] == 1
    run_op(db, "workloads.unassign", "workload/worker", {"node": a["node_id"]}, reason="t")
    assert [e for e in beat(db, a)["workloads"] if e["key"] == "workload/worker"] == []
    with pytest.raises(ops.OpError, match="not_assigned"):
        run_op(db, "workloads.unassign", "workload/worker", {"node": a["node_id"]}, reason="t")


def test_report_events_are_stored_once_acknowledged_and_delivered_to_the_module(db):
    a = node(db, "mini")
    set_key(db, a)
    assign(db, a)
    seat = entry(beat(db, a))["seat_id"]
    ev = [{"seq": 10, "t": 1.0, "data": {"unit": "u-1", "amount": 3}}, {"seq": 11, "t": 2.0, "data": {"unit": "u-2", "amount": 4}}]
    d = beat(db, a, reports=[{"key": "workload/worker", "seat_id": seat, "fence": 1, "events": ev}])
    assert d["workload_reports_ack"] == {"workload/worker": 11}
    beat(db, a, reports=[{"key": "workload/worker", "seat_id": seat, "fence": 1, "events": ev}])     # a retry
    assert db.one("SELECT COUNT(*) n FROM workload_reports")["n"] == 2
    assert W.process_reports(db) == 1
    assert {r["state"] for r in db.q("SELECT state FROM workload_reports")} == {"done"}
    docs = db.q("SELECT * FROM module_store WHERE module='workload'")
    assert len(docs) == 2, docs
    audit = db.one("SELECT * FROM audit WHERE operation='workload.report'")
    assert audit and audit["outcome"] == "ok"
