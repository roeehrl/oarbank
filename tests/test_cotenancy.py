"""Co-tenancy on the coordinator (D50, D52; docs/design/gpu-cotenancy.md): harness runs as owner operations, the
agent's reports, certificates and their validity, the duty sweep, the directives, the node conditions for owner
sources, invariant S25, and the statistics' Python twin."""
import json
import math
import time

import pytest

from oarbank.contracts import abstats
from oarbank.coordinator import core, cotenancy, invariants, ops

from helpers import enrolled_node, fresh, make_db, run_op, set_protection

TRAINER = {"schema": 1, "node": {"mode": "moderate", "gpu_jobs": "certified"},
           "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"}, "immediate": True,
                     "protect": {"metric": "progress_rate", "max_slowdown": 0.05,
                                 "source": {"jsonl": "~/Library/App/events-*.jsonl", "event": "backward_complete"}},
                     "during": [{"source": {"jsonl": "~/Library/App/events-*.jsonl", "event": "heartbeat_response",
                                            "field": "response.phase", "on": ["uploading"]},
                                 "pause_fleet": {"scope": "gpu"}, "tags": ["uplink"]}]},
                    {"id": "editor", "match": {"name": "editor"}, "cap_fleet": {"cpu_cores": 4}}]}
CTX = {"hardware": "Apple M4 Max 12p/4e", "os_major": "darwin 26", "agent_version": "2.10.0"}


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


@pytest.fixture
def node(db):
    n = enrolled_node(db)[1]
    db.x("UPDATE nodes SET lifecycle='ready' WHERE node_id=?", (n["node_id"],))
    set_protection(db, n, TRAINER)
    return fresh(db, n)


def report(run_id, state="running", decision=None, blocks=4, ratio=1.0, identity="abc123"):
    rep = {"run_id": run_id, "rule": "trainer", "work": "gpu", "state": state, "started_at": time.time(),
           "target_blocks": blocks, "blocks": [{"on_first": i % 2 == 0, "on_rate": 10 * ratio, "off_rate": 10.0,
                                                 "start": 0, "end": 1} for i in range(blocks)],
           "excluded": [], "identity": identity}
    if decision:
        a = abstats.analyse([math.log(ratio) + (0.001 if i % 2 else -0.001) for i in range(blocks)], 0.02, 1)
        rep["outcome"] = {"decision": decision, "reason": a["reason"], "analysis": a, "ended_at": time.time()}
    return rep


def hb(db, node, **body):
    return core.heartbeat(db, fresh(db, node), {"telemetry": {"cert_context": CTX}, **body})


def test_a_run_is_previewed_requested_reported_and_certified(db, node):
    plan = ops.execute(db, ops.OpRequest(op="protection.ab.start", actor="o", target=node["node_id"],
                                         params={"rule": "trainer", "work": "gpu", "duty": 0.3}, dry_run=True))["plan"]
    imp = plan["impact"]
    assert imp["rule"] == "trainer" and imp["duty"] == 0.3 and imp["planned_hours"] == pytest.approx(2.0)
    assert imp["source"]["event"] == "backward_complete"
    out = run_op(db, "protection.ab.start", node["node_id"], {"rule": "trainer", "work": "gpu", "duty": 0.3,
                                                              "blocks": 4, "window_s": 60, "washout_s": 10})
    rid = out["result"]["run_id"]
    # the next heartbeat reply asks the node for it, once a run at a time
    d = hb(db, node)
    assert d["ab_run"]["run_id"] == rid and d["ab_run"]["duty"] == 0.3 and d["ab_run"]["window_s"] == 60
    with pytest.raises(core.ApiError):
        run_op(db, "protection.ab.start", node["node_id"], {"rule": "trainer"})
    hb(db, node, ab_runs=[report(rid)])
    assert db.one("SELECT state FROM ab_runs WHERE run_id=?", (rid,))["state"] == "running"
    d = hb(db, node, ab_runs=[report(rid, state="done", decision="no_slowdown", blocks=6, ratio=1.0)])
    run = db.one("SELECT * FROM ab_runs WHERE run_id=?", (rid,))
    assert (run["state"], run["decision"]) == ("done", "no_slowdown") and run["cert_id"]
    certs = d["certificates"]
    assert len(certs) == 1
    c = certs[0]
    assert (c["rule"], c["work"], c["duty"], c["identity"], c["context"]) == ("trainer", "gpu", 0.3, "abc123", CTX)
    assert c["valid_until"] - c["issued_at"] == pytest.approx(cotenancy.CERT_VALID_S)
    assert d["ab_run"] is None and d["ab_ack"] == rid
    # the console's and CLI's views
    detail = cotenancy.run_detail(db, rid)
    assert detail["summary"].startswith("No slowdown shown") and detail["blocks_done"] == 6
    lst = cotenancy.list_certificates(db, node["node_id"])
    assert lst[0]["status"] == "valid"


def test_certificate_validity_follows_the_node_and_the_protected_program(db, node):
    rid = run_op(db, "protection.ab.start", node["node_id"], {"rule": "trainer", "duty": 0.2})["result"]["run_id"]
    hb(db, node, ab_runs=[report(rid, state="done", decision="no_slowdown", blocks=6)])
    st = lambda: cotenancy.list_certificates(db, node["node_id"])[0]
    assert st()["status"] == "valid"
    core.heartbeat(db, fresh(db, node), {"telemetry": {"cert_context": {**CTX, "agent_version": "2.10.1"}}})
    assert (st()["status"], st()["why"]) == ("stale", "the node's hardware, OS or agent changed")
    core.heartbeat(db, fresh(db, node), {"telemetry": {"cert_context": CTX, "protection": {"identities": {"trainer": "zzz"}}}})
    assert (st()["status"], st()["why"]) == ("stale", "the protected program changed")
    db.x("UPDATE certificates SET valid_until=?", (time.time() - 1,))
    assert st()["status"] == "expired"
    assert hb(db, node)["certificates"] == [], "an expired certificate is never sent"


def test_a_slowdown_earns_nothing_and_a_restart_aborts_the_run(db, node):
    rid = run_op(db, "protection.ab.start", node["node_id"], {"rule": "trainer"})["result"]["run_id"]
    hb(db, node, ab_runs=[report(rid, state="done", decision="slowdown", blocks=6, ratio=0.9)])
    assert db.one("SELECT cert_id, decision FROM ab_runs WHERE run_id=?", (rid,)) == {"cert_id": None, "decision": "slowdown"}
    rid2 = run_op(db, "protection.ab.start", node["node_id"], {"rule": "trainer"})["result"]["run_id"]
    hb(db, node, ab_runs=[report(rid2)])
    core.hello(db, fresh(db, node), {"boot_id": "another-process", "facts": {}})
    r = db.one("SELECT state, decision FROM ab_runs WHERE run_id=?", (rid2,))
    assert r == {"state": "aborted", "decision": "aborted"}


def test_abort_before_and_during_a_run(db, node):
    rid = run_op(db, "protection.ab.start", node["node_id"], {"rule": "trainer"})["result"]["run_id"]
    assert run_op(db, "protection.ab.abort", rid)["result"]["state"] == "aborted"
    rid = run_op(db, "protection.ab.start", node["node_id"], {"rule": "trainer"})["result"]["run_id"]
    hb(db, node, ab_runs=[report(rid)])
    assert run_op(db, "protection.ab.abort", rid)["result"]["state"] == "aborting"
    d = hb(db, node)
    assert d["ab_abort"] == [rid] and d["ab_run"] is None
    hb(db, node, ab_runs=[{**report(rid, state="aborted"), "outcome": {"decision": "aborted", "reason": "aborted by the owner"}}])
    assert db.one("SELECT state FROM ab_runs WHERE run_id=?", (rid,))["state"] == "aborted"


def test_runs_are_refused_without_a_progress_source_or_with_bad_specs(db, node):
    for params, why in [({"rule": "editor"}, "progress_rate"), ({"rule": "nope"}, "no protection rule"),
                        ({"rule": "trainer", "duty": 2}, "duty"), ({"rule": "trainer", "window_s": 10}, "window_s"),
                        ({"rule": "trainer", "margin": 0.7}, "margin"), ({"rule": "trainer", "off": "x"}, "off")]:
        with pytest.raises(core.ApiError) as e:
            run_op(db, "protection.ab.start", node["node_id"], params)
        assert why in str(e.value.detail), (params, e.value.detail)


def test_a_sweep_climbs_the_duty_levels_until_one_fails(db, node):
    out = run_op(db, "protection.ab.sweep", node["node_id"], {"rule": "trainer", "levels": "0.1,0.2,0.35"})["result"]
    sid = out["sweep_id"]
    for duty, decision in [(0.1, "no_slowdown"), (0.2, "no_slowdown"), (0.35, "inconclusive")]:
        run = db.one("SELECT * FROM ab_runs WHERE sweep_id=? AND state IN ('requested','running')", (sid,))
        assert run["duty"] == duty
        hb(db, node, ab_runs=[report(run["run_id"], state="done", decision=decision, blocks=6)])
    sw = db.one("SELECT * FROM ab_sweeps WHERE sweep_id=?", (sid,))
    assert (sw["state"], sw["certified_duty"]) == ("done", 0.2)
    assert sorted(c["duty"] for c in hb(db, node)["certificates"]) == [0.1, 0.2]


def test_owner_source_conditions_name_the_fix(db, node):
    from oarbank.coordinator import protection
    tel = {"protection": {"phases": [{"key": "trainer#0", "rule": "trainer", "readable": False, "reader": "helper"},
                                     {"key": "x#0", "rule": "x", "readable": False, "reader": "agent"}],
                          "progress": [{"rule": "trainer", "readable": True, "reader": "helper"}],
                          "gpu_budget": {"duty": 0.0, "rules": ["trainer"], "not_certified": ["trainer"]}}}
    codes = [c["code"] for c in protection.runtime_conditions(tel)]
    assert codes == ["PROTECTION_SOURCE_NEEDS_HELPER", "PROTECTION_SOURCE_UNREADABLE", "GPU_NOT_CERTIFIED"]
    msg = protection.runtime_conditions(tel)[0]["message"]
    assert "session helper" in msg and "holds fleet work back" in msg


def test_s25_judges_the_event_path_from_the_journal(db, node):
    nid = node["node_id"]
    t = time.time()
    phase = lambda seq, at, via="watch": {"t": at, "seq": seq, "kind": "phase_change", "reason": "PROTECTION_PHASE_ON",
                                          "rule": "trainer", "block": 0, "on": True, "event_t": at, "via": via}
    pause = lambda seq, at, ev=None: {"t": at, "seq": seq, "kind": "attempt_paused", "reason": "PROTECTION_PAUSE",
                                      "rule": "rule:trainer", "attempts": [1], "rules": ["trainer#0"],
                                      **({"event_t": ev} if ev is not None else {})}
    hb(db, node, journal=[phase(1, t), pause(2, t + 0.004, ev=t)])
    assert invariants.s25_immediate_phases_pause_at_once(db) == []
    hb(db, node, journal=[phase(3, t + 10), pause(4, t + 10.3, ev=t + 10)])        # 300 ms: too slow
    v = invariants.s25_immediate_phases_pause_at_once(db)
    assert len(v) == 1 and "300 ms" in v[0]
    db.x("DELETE FROM protection_decisions WHERE node_id=?", (nid,))
    hb(db, node, journal=[phase(5, t + 20), pause(6, t + 21.5)])                   # only a tick paused it
    assert "not the event path" in invariants.s25_immediate_phases_pause_at_once(db)[0]
    db.x("DELETE FROM protection_decisions WHERE node_id=?", (nid,))
    hb(db, node, journal=[phase(7, t + 30, via="poll"), pause(8, t + 31)])         # a tick saw it first: S18's
    assert invariants.s25_immediate_phases_pause_at_once(db) == []


def test_the_statistics_twin_matches_the_shared_vectors():
    from pathlib import Path
    v = json.loads((Path(abstats.__file__).parent / "vectors" / "abstats-vectors.json").read_text())
    for c in v["cases"]:
        a = abstats.analyse(c["log_ratios"], c["margin"], c["seed"])
        assert a["decision"] == c["analysis"]["decision"], c["name"]
    rng = abstats.SplitMix(42)
    assert [rng.next() for _ in range(5)] == v["splitmix_42"]
    assert abstats.describe({"n": 1}) == "Not enough blocks to decide."
