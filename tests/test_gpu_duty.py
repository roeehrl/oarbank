"""The GPU duty governor on the coordinator (D50; docs/design/gpu-cotenancy.md, "The duty governor"): the node's
reported budget with each unit's job, the conditions for units held or not trusted, invariant S28 from the decision
journal, the API and the `oarbank protection duty` command."""
import argparse
import time

import pytest

from oarbank.coordinator import core, cotenancy, invariants, protection

from helpers import enrolled_node, fresh, make_db, set_protection

TRAINER = {"schema": 1, "node": {"mode": "moderate", "gpu_jobs": "certified"},
           "rule": [{"id": "trainer", "match": {"path_prefix": "/opt/trainer/"},
                     "protect": {"metric": "progress_rate", "max_slowdown": 0.05,
                                 "source": {"jsonl": "/var/log/trainer/events-*.jsonl", "event": "step"}}}]}


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


@pytest.fixture
def node(db):
    n = enrolled_node(db)[1]
    db.x("UPDATE nodes SET lifecycle='ready' WHERE node_id=?", (n["node_id"],))
    set_protection(db, n, TRAINER)
    return fresh(db, n)


def attempt(db, node, module="dev.example.llm", stage="batch", state="live"):
    jid = db.x("INSERT INTO jobs (state, module, stage, created_at) VALUES ('leased', ?, ?, ?)", (module, stage, time.time()))
    return db.x("INSERT INTO attempts (job_id, node_id, generation, state, granted_at) VALUES (?, ?, 1, ?, ?)",
                (jid, node["node_id"], state, time.time()))


def budget(units, **kw):
    return {"duty": 0.4, "ceiling": 0.5, "rules": ["trainer"], "jobs": len(units), "per_job": 0.2, "state": "running",
            "lockout_s": None, "baseline": {"trainer": {"rate": 9.9, "age_s": 120.0, "pressure": 0.2}},
            "units": units, "distrusted": [], **kw}


def hb(db, node, **body):
    return core.heartbeat(db, fresh(db, node), body)


def test_the_node_card_and_the_duty_view_name_each_units_job(db, node):
    a1, a2 = attempt(db, node), attempt(db, node, stage="score")
    b = budget([{"id": a1, "duty": 0.2, "measured": 0.19, "state": "ok"},
                {"id": a2, "duty": None, "measured": 0.0, "state": "held", "why": "exceeded", "for_s": 42.0}])
    hb(db, node, telemetry={"protection": {"gpu_budget": b}})
    card = cotenancy.node_card(db, fresh(db, node))
    units = card["gpu_budget"]["units"]
    assert [(u["attempt_id"], u["module"], u["stage"], u["state"]) for u in units] == \
        [(a1, "dev.example.llm", "batch", "ok"), (a2, "dev.example.llm", "score", "held")]
    v = cotenancy.duty_view(db)
    assert len(v) == 1 and (v[0]["duty"], v[0]["ceiling"], v[0]["state"]) == (0.4, 0.5, "running")
    assert v[0]["baseline"]["trainer"]["rate"] == 9.9
    # a node without a budget is left out of the fleet view, but shown when named
    n2 = enrolled_node(db, "other")[1]
    assert all(x["node_id"] != n2["node_id"] for x in cotenancy.duty_view(db))
    assert cotenancy.duty_view(db, n2["node_id"])[0]["state"] is None
    assert cotenancy.duty_view(db, node["node_id"])[0]["units"][1]["why"] == "exceeded"


def test_conditions_name_units_not_trusted_and_unreadable_gpu_time(db, node):
    tel = {"protection": {"gpu_budget": budget([{"id": 7, "state": "held", "why": "unverified", "for_s": 30.0}],
                                               distrusted=[{"unit": "dev.example.llm/batch", "for_s": 1800.0}])}}
    conds = protection.runtime_conditions(tel)
    codes = [c["code"] for c in conds]
    assert codes == ["GPU_DUTY_EXCEEDED", "GPU_DUTY_UNVERIFIED"]
    assert "30 min" in conds[0]["message"] and "conform" in conds[0]["message"]
    assert "attempts 7" in conds[1]["message"]


def test_s28_the_budget_never_exceeds_its_ceiling_and_held_units_are_paused(db, node):
    a = attempt(db, node)
    t = time.time() - 100
    step = lambda seq, at, duty, ceiling: {"t": at, "seq": seq, "kind": "gpu_duty", "reason": "GPU_DUTY_GROW",
                                           "duty": duty, "ceiling": ceiling, "why": "a clean interval"}
    held = lambda seq, at, action="paused", reason="GPU_DUTY_EXCEEDED": {
        "t": at, "seq": seq, "kind": "gpu_compliance", "reason": reason, "attempt": a, "unit": "dev.example.llm/batch",
        "measured": 0.9, "duty": 0.2, "action": action}
    paused = lambda seq, at: {"t": at, "seq": seq, "kind": "attempt_paused", "reason": "PROTECTION_PAUSE",
                              "rule": "dynamic", "attempts": [a], "rules": [], "why": ""}
    hb(db, node, journal=[step(1, t, 0.35, 0.4), held(2, t + 1), paused(3, t + 3)])
    assert invariants.s28_gpu_duty_within_ceiling_and_enforced(db) == []
    hb(db, node, journal=[step(4, t + 5, 0.45, 0.4)])
    v = invariants.s28_gpu_duty_within_ceiling_and_enforced(db)
    assert len(v) == 1 and "above the certified ceiling" in v[0]
    db.x("DELETE FROM protection_decisions WHERE node_id=?", (node["node_id"],))
    hb(db, node, journal=[held(5, t + 10, reason="GPU_DUTY_UNVERIFIED")])            # held, never paused
    v = invariants.s28_gpu_duty_within_ceiling_and_enforced(db)
    assert len(v) == 1 and "no pause of it followed" in v[0]
    # ... unless the attempt ended in the window
    db.x("UPDATE attempts SET state='completed', ended_at=? WHERE attempt_id=?", (t + 12, a))
    assert invariants.s28_gpu_duty_within_ceiling_and_enforced(db) == []
    # a stopped unit must be gone a minute later
    db.x("UPDATE attempts SET state='live', ended_at=NULL WHERE attempt_id=?", (a,))
    db.x("DELETE FROM protection_decisions WHERE node_id=?", (node["node_id"],))
    hb(db, node, journal=[held(6, t + 20, action="evicted")])
    assert "still live" in invariants.s28_gpu_duty_within_ceiling_and_enforced(db)[0]
    assert invariants.s28_gpu_duty_within_ceiling_and_enforced in invariants.SAFETY


def test_the_api_and_the_cli_show_the_governor(db, node, monkeypatch, capsys):
    from fastapi.testclient import TestClient
    from oarbank.coordinator import access, app as coord_app
    from oarbank.cli import main as cli
    a1 = attempt(db, node)
    hb(db, node, telemetry={"protection": {"gpu_budget": budget(
        [{"id": a1, "duty": 0.2, "measured": 0.95, "state": "held", "why": "exceeded", "for_s": 40.0}],
        distrusted=[{"unit": "dev.example.other/batch", "for_s": 600.0}])}},
       journal=[{"t": time.time(), "seq": 1, "kind": "gpu_compliance", "reason": "GPU_DUTY_EXCEEDED", "attempt": a1,
                 "unit": "dev.example.llm/batch", "measured": 0.95, "duty": 0.2, "action": "paused"}])
    access.create_account(db, "owner", "admin", None, "test")
    tok = access.new_token(db, "owner", "laptop", "admin", 1)["token"]
    with TestClient(coord_app.admin_app(db)) as c:
        r = c.get("/api/v1/protection/duty", headers={"authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        d = r.json()
        assert d["nodes"][0]["units"][0]["stage"] == "batch" and d["nodes"][0]["events"][0]["reason"] == "GPU_DUTY_EXCEEDED"
        assert c.get("/api/v1/protection/duty?node=nope", headers={"authorization": f"Bearer {tok}"}).status_code == 404
    monkeypatch.setattr(cli, "api", lambda *a, **k: d)
    cli.cmd_protection(argparse.Namespace(action="duty", node=None, value=None, json=False, reason=None, yes=False))
    out = capsys.readouterr().out
    assert "gpu_duty budget 0.4 of ceiling 0.5 (running)" in out
    assert "dev.example.llm/batch attempt" in out and "held (exceeded, 40 s left)" in out
    assert "not trusted: dev.example.other/batch for 10 min more" in out and "GPU_DUTY_EXCEEDED" in out
    monkeypatch.setattr(cli, "api", lambda *a, **k: {"nodes": [{**d["nodes"][0], "not_certified": ["trainer"]}]})
    cli.cmd_protection(argparse.Namespace(action="duty", node=None, value=None, json=False, reason=None, yes=False))
    assert "not certified for trainer" in capsys.readouterr().out


from test_console import env  # noqa: E402,F401  (the console fixture: a signed-in console over a real oarbankd)


def test_the_protection_page_shows_the_gpu_duty_card(env):  # noqa: F811
    c, db, n = env["c"], env["db"], env["node"]
    set_protection(db, n, TRAINER)
    a1 = attempt(db, n)
    a2 = attempt(db, n, stage="score")
    core.heartbeat(db, fresh(db, n), {"telemetry": {"protection": {"gpu_budget": budget(
        [{"id": a1, "duty": 0.2, "measured": 0.18, "state": "ok"},
         {"id": a2, "duty": None, "measured": 0.0, "state": "held", "why": "unverified", "for_s": 50.0}],
        lockout_s=None, distrusted=[{"unit": "dev.example.other/batch", "for_s": 1200.0}])}}})
    r = c.get(f"/nodes/{n['node_id']}/protection")
    assert r.status_code == 200
    t = r.text
    assert "GPU duty" in t and "gpu_duty 0.4</b> of the certified 0.5" in t and ">running<" in t
    assert "dev.example.llm/batch" in t and "holds its duty" in t and "held: GPU time unreadable" in t
    assert "exceeded its gpu_duty three times within an hour: no duty for 20 min more" in t
    assert "GPU_DUTY_EXCEEDED" in t and "GPU_DUTY_UNVERIFIED" in t            # the node conditions
    core.heartbeat(db, fresh(db, n), {"telemetry": {"protection": {"gpu_budget": {
        "duty": 0.0, "rules": ["trainer"], "not_certified": ["trainer"], "state": "not_certified"}}}})
    assert "0: not certified for trainer" in c.get(f"/nodes/{n['node_id']}/protection").text


def test_the_prio_darwin_gpu_experiment_runs_only_by_hand_on_work_it_starts(monkeypatch, capsys):
    """bench/prio_darwin_gpu.py (owner-run, never shipped behaviour): without --i-understand and a command it does
    nothing; its reading of the driver's per-process GPU time matches the agent's."""
    import importlib.util
    import subprocess as sp
    from pathlib import Path
    path = Path(__file__).parents[1] / "bench" / "prio_darwin_gpu.py"
    spec = importlib.util.spec_from_file_location("prio_darwin_gpu", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    calls = []
    monkeypatch.setattr(mod, "set_gpu", lambda *a: calls.append(a) or {})
    monkeypatch.setattr(mod.subprocess, "Popen", lambda *a, **k: calls.append(("spawn", a)) or None)
    assert mod.main(["--seconds", "1", "--", "true"]) == 2
    assert mod.main(["--seconds", "1", "--i-understand"]) == 2
    assert calls == [], "it starts nothing and switches nothing without both"
    sample = ('+-o AGXDeviceUserClient  <class AGXDeviceUserClient>\n  "AppUsage" = ({"API"="Metal","accumulatedGPUTime"=1500},'
              '{"API"="Metal","accumulatedGPUTime"=500})\n  "IOUserClientCreator" = "pid 42, python3"\n'
              '+-o AGXDeviceUserClient  <class AGXDeviceUserClient>\n  "IOUserClientCreator" = "pid 7, other"\n'
              '  "AppUsage" = ({"API"="Metal","accumulatedGPUTime"=9})\n')
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: sp.CompletedProcess(a, 0, stdout=sample))
    assert mod.gpu_ns_by_pid() == {42: 2000.0, 7: 9.0}
    assert (mod.PRIO_DARWIN_GPU, mod.PRIO_DARWIN_GPU_ALLOW, mod.PRIO_DARWIN_GPU_DENY) == (5, 1, 2)
