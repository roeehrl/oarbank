"""max_slots is a node's CPU-slot budget, not a job count: every running job draws its stage's `resources.cpu` from it
(core.claim, predicates INSUFFICIENT_CPU), so a budget below a stage's cpu keeps that stage off the node for good.
`jobs` is what limits how many jobs run. The setting says so wherever it is shown, and readiness, Explain and the
`settings set` preview say when the budget is below the cpu of an enabled module's stage, with the fix."""
import json
import shutil

import pytest

from helpers import RELAY_DIR, READY, TOY_DIR, certify, enrolled_node, fresh, make_db, run_op, set_node
from oarbank.contracts import impact
from oarbank.coordinator import explain, nodepolicy, readiness
from oarbank.coordinator.settings import apply as A, registry as R

FIX = "max_slots 1 is below stage run's cpu 2: raise max_slots to 2 or more, or use jobs to limit how many jobs run"


def toy_cpu2(tmp_path):
    """The toy with its stage (and the jobs it queues) declaring cpu = 2."""
    d = tmp_path / "toy-cpu2"
    shutil.copytree(TOY_DIR, d, ignore=shutil.ignore_patterns("dist", "__pycache__"))
    m = d / "oarbank-module.toml"
    m.write_text(m.read_text(encoding="utf-8").replace("{ cpu = 1, mem_gb = 0.1 }", "{ cpu = 2, mem_gb = 0.1 }"),
                 encoding="utf-8")
    py = d / "toy_module.py"
    py.write_text(py.read_text(encoding="utf-8").replace('{"cpu": 1, "mem_gb": 0.1}', '{"cpu": 2, "mem_gb": 0.1}'),
                  encoding="utf-8")
    return d


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3", modules=(toy_cpu2(tmp_path), RELAY_DIR))


def test_max_slots_says_it_is_a_cpu_budget_and_points_to_jobs():
    d = R.REGISTRY["max_slots"]
    assert d.label == "CPU slots for jobs (cores)"
    assert "resources.cpu" in d.help and "not a job count" in d.help and "Concurrent jobs (jobs)" in d.help
    assert "one job at a time" in R.REGISTRY["jobs"].help
    # the why line names it a CPU budget, never "slots in settings" an owner reads as jobs
    cap = {"cpu_slots": 1, "idle_cpu_slots": 1, "slots": 1, "mem_gb_free": 8.0, "admit": True, "binding_limit": "auto"}
    w = nodepolicy.why(cap, {}, {}, {"max_slots": 1})
    assert w["slots"] == "1 CPU slot (max_slots caps the cores for jobs at 1)" and "in settings" not in w["line"]
    assert [c["key"] for c in w["cites"]] == ["max_slots"]


def test_slot_budget_short():
    assert nodepolicy.slot_budget_short(1, 2, "run") == FIX
    assert nodepolicy.slot_budget_short(1, 2.5).startswith("max_slots 1 is below this stage's cpu 2.5: raise max_slots to 3")
    assert nodepolicy.slot_budget_short(2, 2) is None and nodepolicy.slot_budget_short(None, 8) is None


def test_readiness_says_the_budget_is_below_the_stage_cpu(db):
    _, n = enrolled_node(db)
    assert FIX not in json.dumps(readiness.module(db, "toy"))
    set_node(db, n, "max_slots", 1)
    assert FIX in json.dumps(readiness.module(db, "toy"))
    assert "max_slots" not in json.dumps(readiness.module(db, "relay"))       # its stages take at most 1 cpu


def test_explain_says_the_budget_is_below_the_stage_cpu(db):
    n = certify(db, enrolled_node(db)[1])
    run_op(db, "mod.toy.queue_sums", params={"ns": [7]})
    job = db.one("SELECT job_id FROM jobs WHERE module='toy' AND state='pending' AND kind!='golden'")["job_id"]
    set_node(db, n, "max_slots", 1)
    n = fresh(db, n)
    body = {n["node_id"]: {"free_cpu": 1, "free_mem_gb": 32, "ready_datasets": READY}}   # as the agent reports it: 1 slot
    doc = explain.job_doc(db, job, bodies=body)
    assert doc.headline.code == "NO_ELIGIBLE_NODE"
    why = "max_slots 1 is below this stage's cpu 2: raise max_slots to 2 or more, or use jobs to limit how many jobs run"
    assert doc.headline.text == f"No node can run this job right now: Needs 2.0 cores, 1.0 allocatable (1 node: 1 darwin-arm64); on mini: {why}"
    assert any(why in s.detail["text"] for s in doc.summary if s.code == "INSUFFICIENT_CPU")
    nd = explain.node_doc(db, n["node_id"], body=body[n["node_id"]])
    assert f"toy stage run never runs here: {FIX}" in nd.system_actions
    # a budget that fits: no such line
    set_node(db, n, "max_slots", 2)
    assert not explain.node_doc(db, n["node_id"]).system_actions


def test_settings_set_previews_a_budget_below_an_enabled_stage(db):
    _, n = enrolled_node(db)
    p = A.plan(db, [{"scope": "node", "scope_id": n["node_id"], "key": "max_slots", "value": 1}])
    assert p["warnings"] == [f"mini: toy stage run would never run there: {FIX}"]
    # the CLI preview (oarbank settings set ... --dry-run) prints it with the plan
    assert f"  warnings: mini: toy stage run would never run there: {FIX}" in impact.lines(p)
    # 2 fits, and no bound is none
    assert A.plan(db, [{"scope": "node", "scope_id": n["node_id"], "key": "max_slots", "value": 2}])["warnings"] == []
    # only modules enabled there count
    set_node(db, n, "enabled", False, module="toy")
    assert A.plan(db, [{"scope": "fleet", "key": "max_slots", "value": 1}])["warnings"] == []
    # the jobs cap, which limits job count, never warns
    assert A.plan(db, [{"scope": "node", "scope_id": n["node_id"], "key": "jobs", "value": 1}])["warnings"] == []
