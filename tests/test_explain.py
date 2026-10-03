"""explain v1 (PLAN D16): the explanation comes from the claim path's own predicates, so it never lies.
Property: for random fleet states, explain's verdict for (job, node) equals claim()'s decision."""
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from helpers import create_study, PARAMS, READY, certify, enrolled_node, fresh, make_db
from oarbank.coordinator import core, explain


class Rollback(Exception):
    pass


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    db = make_db(tmp_path_factory.mktemp("explain") / "oarbank.sqlite3")
    node = certify(db, enrolled_node(db)[1])
    create_study(db, "s", [], ["scene:s1"], {"label": "base", "params": PARAMS})
    job = db.one("SELECT * FROM jobs WHERE state='pending' AND kind='eval'")
    assert db.one("SELECT COUNT(*) n FROM jobs WHERE state='pending'")["n"] == 1
    return db, node, job


GOOD = {"fleet_state": "active", "desired_state": "active", "lifecycle": "ready", "mod_state": "certified",
        "golden": False, "target": None, "cpu": 1, "mem": 2, "pools": "none", "pool_cap": None,
        "datasets_ready": True, "free_cpu": 8, "free_mem": 32, "jobs_cap": None, "dispute_party": False,
        "failed_here": False, "backoff": False, "campaign_paused": False, "disabled": False, "pool_jobs_only": False,
        "by_platform": None, "unit": None, "job_platforms": None, "dataset_platform": None, "compare": None, "failures": 0}
VARIANTS = {"fleet_state": ["paused"], "desired_state": ["paused", "draining"], "lifecycle": ["quarantined"],
            "mod_state": ["certifying", "doctor_failed"], "golden": [True], "target": ["self", "other"],
            "cpu": [0.5, 4, 16], "mem": [0.5, 64], "pools": ["reserve", "needs"], "pool_cap": [0, 1, 2],
            "datasets_ready": [False], "free_cpu": [0, 1], "free_mem": [1], "jobs_cap": [0, 5],
            "dispute_party": [True], "failed_here": [True], "backoff": [True], "campaign_paused": [True],
            "disabled": [True], "pool_jobs_only": [True],
            # per-platform stage resources (stages[].variants): the node's OS or token applies, another platform's never
            "by_platform": [{"darwin": {"mem_gb": 48}}, {"darwin-arm64": {"cpu": 12}}, {"linux": {"mem_gb": 48}},
                            {"darwin": {"mem_gb": 48}, "darwin-arm64": {"mem_gb": 2}}],
            # placement (D33): the job's unit bound here, elsewhere, waiting for a pin, or feasible only elsewhere; its own
            # platforms; its dataset's platform; a comparison class; its stage's retries spent (relay's eval allows 3)
            "unit": ["same", "other", "unbound", "unpinned", "infeasible"], "job_platforms": [["linux"], ["darwin"]],
            "dataset_platform": ["linux-amd64", "darwin-arm64"],
            "compare": [{"scope": "same-os", "class": "linux"}, {"scope": "same-arch", "class": "arm64"}], "failures": [2, 3]}
UNITS = {"same": ("same-platform", "darwin-arm64", "soft", "first-claim", ["darwin-arm64", "linux-amd64"]),
         "other": ("same-os", "linux", "hard", "first-claim", ["darwin", "linux"]),
         "unbound": ("same-os", None, "unbound", "first-claim", ["darwin", "linux"]),
         "unpinned": ("same-platform", None, "unbound", "explicit", ["darwin-arm64"]),
         "infeasible": ("same-platform", None, "unbound", "first-claim", ["linux-amd64"])}


@st.composite
def STATE(draw):
    """The passing state with 0-3 dimensions perturbed: eligible states are common, and each predicate
    (and pairs of them, e.g. pools x pool capacity) is exercised on its own."""
    keys = draw(st.lists(st.sampled_from(sorted(VARIANTS)), max_size=3, unique=True))
    return {**GOOD, **{k: draw(st.sampled_from(VARIANTS[k])) for k in keys}}


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(s=STATE())
def test_explain_verdict_equals_claim_decision(world, s):
    db, node, job = world
    nid, jid = node["node_id"], job["job_id"]
    try:
        with db.tx():
            db.set_setting("fleet_state", s["fleet_state"])
            db.set_setting("modules_disabled", ["relay"] if s["disabled"] else [])
            mods = json.loads(fresh(db, node)["modules_json"])
            mods["relay"]["state"] = s["mod_state"]
            caps = {} if s["pool_cap"] is None else {"pools": {"scorer": s["pool_cap"]}}
            db.x("UPDATE nodes SET desired_state=?, lifecycle=?, modules_json=?, limits_json=?, capacity_json=? WHERE node_id=?",
                 (s["desired_state"], s["lifecycle"], json.dumps(mods),
                  json.dumps({} if s["jobs_cap"] is None else {"jobs": s["jobs_cap"]}), json.dumps(caps), nid))
            res = {"cpu": s["cpu"], "mem_gb": s["mem"]}
            if s["pools"] == "reserve":
                res["pools"] = {"scorer": 1}
            elif s["pools"] == "needs":
                res["needs_pools"] = ["scorer"]
            if s["by_platform"]:
                res["by_platform"] = s["by_platform"]
            target = {None: None, "self": nid, "other": "n_other"}[s["target"]]
            dispute = {**({"nodes": [nid], "results": [1]} if s["dispute_party"] else {}), **(s["compare"] or {})}
            db.x("UPDATE jobs SET kind=?, target_node=?, resources_json=?, not_before=?, dispute_json=?, platforms_json=?, "
                 "exec_failures=?, placement_unit=? WHERE job_id=?",
                 ("golden" if s["golden"] else "eval", target, json.dumps(res), 9e12 if s["backoff"] else 0,
                  json.dumps(dispute) if dispute else None, json.dumps(s["job_platforms"]) if s["job_platforms"] else None,
                  s["failures"], "u:prop" if s["unit"] else None, jid))
            if s["unit"]:
                mix, cls, st_, bind, feas = UNITS[s["unit"]]
                db.x("INSERT INTO placement_bindings(unit,module,campaign_id,mix,class,state,bind,feasible_json) VALUES(?,?,?,?,?,?,?,?)",
                     ("u:prop", "relay", job["campaign_id"], mix, cls, st_, bind, json.dumps(feas)))
            db.x("UPDATE datasets SET platform=? WHERE dataset_id='scene:s1'", (s["dataset_platform"],))
            db.x("UPDATE campaigns SET state=? WHERE campaign_id=?", ("paused" if s["campaign_paused"] else "running", job["campaign_id"]))
            if s["failed_here"]:
                db.x("INSERT INTO attempts(job_id,node_id,generation,state,granted_at,ended_at,end_reason) "
                     "VALUES(?,?,1,'failed',0,0,'exit_nonzero')", (jid, nid))
            body = {"free_cpu": s["free_cpu"], "free_mem_gb": s["free_mem"], "pool_jobs_only": s["pool_jobs_only"],
                    "ready_datasets": READY if s["datasets_ready"] else ["tool:other"]}
            doc = explain.job_doc(db, jid, bodies={nid: body})
            row = next(r for r in doc.matrix if r.node == node["hostname"])
            explained = all(r.outcome == "pass" for r in row.results)
            granted = any(g["job_id"] == jid for g in core.claim(db, fresh(db, node), body)["grants"])
            assert granted == explained, (s, [r for r in row.results if r.outcome != "pass"])
            if granted and s["unit"] == "unbound":            # the first claim bound the unit to this node's class
                assert db.one("SELECT class, state FROM placement_bindings WHERE unit='u:prop'") == {"class": "darwin", "state": "soft"}
            if not explained:
                assert doc.headline.code == "NO_ELIGIBLE_NODE" and doc.summary      # the blocking reason is named
            raise Rollback
    except Rollback:
        pass


def test_the_all_passing_state_is_granted_and_explained_eligible(world):
    db, node, job = world
    body = {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY}
    try:
        with db.tx():
            doc = explain.job_doc(db, job["job_id"], bodies={node["node_id"]: body})
            assert doc.headline.code == "QUEUED_BEHIND" and doc.summary[0].nodes == [node["hostname"]]
            assert any(g["job_id"] == job["job_id"] for g in core.claim(db, fresh(db, node), body)["grants"])
            raise Rollback
    except Rollback:
        pass


def test_node_explain_names_the_admission_blocker(world):
    db, node, _ = world
    try:
        with db.tx():
            db.x("UPDATE nodes SET desired_state='paused' WHERE node_id=?", (node["node_id"],))
            d = explain.node_doc(db, node["node_id"], body={"free_cpu": 8, "ready_datasets": READY})
            assert d.verdict == "blocked" and d.headline.code == "NODE_PAUSED_BY_ADMIN"
            assert any(r.op == "nodes.resume" for r in d.remedies)
            raise Rollback
    except Rollback:
        pass
    d = explain.node_doc(db, node["node_id"], body={"free_cpu": 8, "ready_datasets": READY})
    assert d.verdict == "admitting" and any(s.code == "QUEUED_BEHIND" for s in d.summary)


def test_job_explain_names_a_platform_the_module_does_not_support(world):
    db, node, job = world
    import json as _j
    try:
        with db.tx():
            facts = _j.loads(fresh(db, node)["facts_json"])
            facts["platform"] = {"os": "linux", "arch": "riscv64", "os_version": "6.8"}
            from oarbank.coordinator import releases
            rid = releases.build(db, platform="linux-riscv64")["release_id"]       # its release: no module supports it
            assert releases.composition_of(db, rid) == {}
            db.x("UPDATE nodes SET facts_json=?, platform='linux-riscv64', release_id=? WHERE node_id=?",
                 (_j.dumps(facts), rid, node["node_id"]))
            doc = explain.job_doc(db, job["job_id"], bodies={node["node_id"]: {"free_cpu": 8, "free_mem_gb": 32,
                                                                               "ready_datasets": READY}})
            assert any(s.code == "PLATFORM_UNSUPPORTED" for s in doc.summary), doc.summary
            assert not core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]
            raise Rollback
    except Rollback:
        pass
