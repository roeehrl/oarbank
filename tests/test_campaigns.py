"""Campaigns (PLAN D22): the core's only grouping of work, generic operations on them, and the gate that
keeps module concepts out of the core."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from oarbank.coordinator import app as coord_app
from oarbank.coordinator import core, modviews

from helpers import (admin_headers, sign_in, SCENES, PARAMS, READY, certify, create_study, enrolled_node, facts_for, fresh, make_db,
                     relay_result, run_op, tick)

SRC = Path(__file__).resolve().parents[1] / "src" / "oarbank"
# Words that name one module's concepts: the core must not use them. The simulator drives the relay fixture module,
# whose workload is a render-and-score parameter search, so it is exempt.
GATED = re.compile(r"image_sha256|tile_size|\bscenes?\b|sampler|denois|study|studies|trial|holdout", re.I)
EXEMPT_FILES = {"sim.py"}


def test_core_names_no_module_concepts():
    hits = []
    for p in sorted(SRC.rglob("*")):
        rel = p.relative_to(SRC).as_posix()
        if p.suffix not in (".py", ".html", ".js", ".css", ".json") or rel in EXEMPT_FILES or "__pycache__" in rel:
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if GATED.search(line):
                hits.append(f"{rel}:{i}: {line.strip()[:120]}")
    assert not hits, "module concepts in the core:\n" + "\n".join(hits)


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def test_pause_resume_cancel_gate_dispatch(db):
    node = certify(db, enrolled_node(db)[1])
    cid = create_study(db, "s", [], SCENES[:2], {"label": "base", "params": PARAMS})
    run_op(db, "campaigns.pause", cid)
    assert core.claim(db, fresh(db, node), {"free_slots": 4, "ready_datasets": READY})["grants"] == []
    from oarbank.coordinator import explain
    e = explain.job_doc(db, db.one("SELECT job_id FROM jobs WHERE campaign_id=? LIMIT 1", (cid,))["job_id"])
    assert "CAMPAIGN_PAUSED" in e.model_dump_json()
    run_op(db, "campaigns.resume", cid)
    g = core.claim(db, fresh(db, node), {"free_slots": 1, "ready_datasets": READY})["grants"]
    assert len(g) == 1
    run_op(db, "campaigns.cancel", cid, reason="test")
    assert {j["state"] for j in db.q("SELECT state FROM jobs WHERE campaign_id=?", (cid,))} == {"cancelled"}
    assert db.one("SELECT state FROM campaigns WHERE campaign_id=?", (cid,))["state"] == "cancelled"
    with pytest.raises(core.ApiError):
        run_op(db, "campaigns.resume", cid)                   # cancelled is final


def test_priority_moves_open_jobs_and_weight_shares_the_fleet(db):
    node = certify(db, enrolled_node(db)[1])
    a = create_study(db, "a", [], SCENES[:6], {"label": "base", "params": PARAMS})
    b = create_study(db, "b", [], SCENES[:6], {"label": "base", "params": {**PARAMS, "samples": 11}})
    run_op(db, "campaigns.set_priority", b, params={"priority": 5})
    assert {j["priority"] for j in db.q("SELECT priority FROM jobs WHERE campaign_id=?", (b,))} == {6}   # baseline +1 kept
    g = core.claim(db, fresh(db, node), {"free_slots": 4, "ready_datasets": READY})["grants"]
    assert {db.one("SELECT campaign_id FROM jobs WHERE job_id=?", (x["job_id"],))["campaign_id"] for x in g} == {b}
    run_op(db, "campaigns.set_priority", b, params={"priority": 0})
    run_op(db, "campaigns.set_weight", a, params={"weight": 3})
    for x in g:
        core.complete(db, fresh(db, node), x["attempt_id"], relay_result())
    g = core.claim(db, fresh(db, node), {"free_slots": 4, "ready_datasets": READY})["grants"]
    per = [db.one("SELECT campaign_id FROM jobs WHERE job_id=?", (x["job_id"],))["campaign_id"] for x in g]
    assert per.count(a) >= 3                                # weight 3 : 1


def test_retry_failed_reopens_a_done_campaign(db):
    node = certify(db, enrolled_node(db)[1])
    cid = create_study(db, "s", [], SCENES[:1], {"label": "base", "params": PARAMS})
    j = db.one("SELECT job_id FROM jobs WHERE campaign_id=?", (cid,))["job_id"]
    db.x("UPDATE jobs SET state='failed' WHERE job_id=?", (j,))
    tick(db)
    assert db.one("SELECT state FROM campaigns WHERE campaign_id=?", (cid,))["state"] == "done"
    assert run_op(db, "campaigns.retry_failed", cid)["result"]["retried"] == [j]
    assert db.one("SELECT state FROM campaigns WHERE campaign_id=?", (cid,))["state"] == "running"
    assert core.claim(db, fresh(db, node), {"free_slots": 1, "ready_datasets": READY})["grants"]


def test_campaign_page_shows_the_owning_modules_panel(db, tmp_path):
    from test_console import SECRET, Server
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    cid = create_study(db, "cmp", [{"label": "c1", "params": {**PARAMS, "samples": 25}}], SCENES[:1],
                       {"label": "base", "params": PARAMS})
    modviews.refresh(db, force=True)
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(str(db.path), f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        c = TestClient(console_app(state, tmp_path / "logs"))
        sign_in(c, db)
        html = c.get(f"/campaigns/{cid}").text
        assert "Trials" in html and "relay" in html and ">c1<" in html
        assert "Re-run the baseline" in html                           # the module's own operation, registry title
        assert c.get("/campaigns").status_code == 200 and cid in c.get("/campaigns").text
        from test_ops import LOCAL
        api = TestClient(coord_app.admin_app(db, coord_app.EventBus()), client=LOCAL, headers=admin_headers(db))
        assert api.get(f"/api/v1/campaigns/{cid}").json()["jobs"]["n"] == 2
        rows = api.get(f"/api/v1/modules/relay/views/trials?campaign={cid}").json()["rows"]
        assert [r["label"] for r in rows] == ["base", "c1"]


def test_effects_are_checked_for_declaration_and_ownership(db):
    from oarbank.coordinator import effects
    cid = create_study(db, "cmp", [], SCENES[:1], {"label": "base", "params": PARAMS})
    with pytest.raises(effects.EffectError) as e:
        with db.tx():
            effects.apply(db, "relay", {"store.write"}, [{"kind": "campaigns.cancel", "args": {"campaign_id": cid}}])
    assert e.value.code == "undeclared_effect"
    with pytest.raises(effects.EffectError) as e:
        with db.tx():
            effects.apply(db, "toy", {"campaigns.update"}, [{"kind": "campaigns.update", "args": {"campaign_id": cid, "state": "done"}}])
    assert e.value.code == "not_owner"
    with db.tx():                                 # a stale "done" while work is open is deferred, not applied
        rec = effects.apply(db, "relay", {"campaigns.update"}, [{"kind": "campaigns.update", "args": {"campaign_id": cid, "state": "done"}}])
    assert rec[0]["deferred"] and db.one("SELECT state FROM campaigns WHERE campaign_id=?", (cid,))["state"] == "running"


def test_host_callbacks_answer_only_the_modules_own_rows(db):
    from oarbank.coordinator import modcalls
    cid = create_study(db, "cmp", [], SCENES[:1], {"label": "base", "params": PARAMS})
    cb = modcalls.host_callbacks(db)
    assert cb["host.store.get"]("relay", {"collection": "trial", "key": f"{cid}:0"})["doc"]["label"] == "base"
    assert cb["host.store.get"]("toy", {"collection": "trial", "key": f"{cid}:0"})["doc"] is None
    assert [d["_key"] for d in cb["host.store.query"]("relay", {"collection": "trial", "where": {"campaign_id": cid}})["docs"]] \
        == [f"{cid}:0"]
    jobs = cb["host.jobs.query"]("relay", {"campaign_id": cid})["jobs"]
    assert len(jobs) == 1 and jobs[0]["labels"] == {"trial": 0} and jobs[0]["dataset_id"] == SCENES[0]
    assert cb["host.jobs.query"]("toy", {"campaign_id": cid})["jobs"] == []        # another module's campaign: nothing
    ds = cb["host.datasets.query"]("relay", {"ids": [SCENES[0], "nope"]})["datasets"]
    assert [d["id"] for d in ds] == [SCENES[0]] and ds[0]["attrs"]["scene"] == "atrium"


def test_modules_see_node_platforms_and_where_each_result_came_from(db):
    from oarbank.coordinator import campaigns, modcalls
    box = certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1])
    certify(db, enrolled_node(db, "mini")[1])
    cb = modcalls.host_callbacks(db)
    nodes = {n["hostname"]: n for n in cb["host.nodes.query"]("relay", {})["nodes"]}
    assert {k: nodes["box"][k] for k in ("platform", "os", "arch", "os_version")} == \
        {"platform": "linux-amd64", "os": "linux", "arch": "amd64", "os_version": "6.8"}
    assert nodes["mini"]["platform"] == "darwin-arm64"
    for want, names in ((["linux"], ["box"]), (["darwin-arm64"], ["mini"]), (["windows"], []), ([], ["box", "mini"])):
        assert sorted(n["hostname"] for n in cb["host.nodes.query"]("relay", {"platforms": want})["nodes"]) == names
    cid = create_study(db, "where", [], SCENES[:1], {"label": "base", "params": PARAMS})
    g = core.claim(db, fresh(db, box), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"][0]
    core.complete(db, fresh(db, box), g["attempt_id"], relay_result())
    assert [j["platform"] for j in cb["host.jobs.query"]("relay", {"campaign_id": cid})["jobs"]] == ["linux-amd64"]
    assert [j["platform"] for j in campaigns.campaign_jobs(db, cid)] == ["linux-amd64"]



def test_retiring_a_node_settles_the_work_pinned_to_it(db):
    # a run_all job pinned to a node that is then retired can never run: its campaign stayed "running" for ever
    from oarbank.coordinator import effects
    a, b = certify(db, enrolled_node(db, "a")[1]), certify(db, enrolled_node(db, "b")[1])
    run = run_op(db, "mod.toy.queue_sums", params={"ns": [7], "campaign_id": "c_toy_pinned"})
    cid = run["result"]["result"]["campaign_id"]
    effects.enqueue(db, "toy", db.one("SELECT * FROM campaigns WHERE campaign_id=?", (cid,)),
                    [{"job_key": f"k-{n['node_id']}", "spec": {"n": 3}, "labels": {"node": n["node_id"]}, "target_node": n["node_id"]}
                     for n in (a, b)])
    out = run_op(db, "nodes.retire", a["node_id"])
    assert out["result"]["pinned_jobs_cancelled"] == 1
    state = {r["target_node"]: r["state"] for r in db.q("SELECT target_node, state FROM jobs WHERE campaign_id=?", (cid,))}
    assert state[a["node_id"]] == "cancelled" and state[b["node_id"]] == "pending" and state[None] == "pending"
