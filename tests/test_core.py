"""Coordinator logic: lifecycle, dispatch, fencing, acceptance, caps, caching, reaper."""
import base64
import time
import uuid

import pytest

from oarbank.coordinator import core

from helpers import (CAPACITY, DOCTOR_OK, FACTS, PARAMS, create_study, enrolled_node, fresh, golden_result, make_db,
                     node_key_and_csr, release_id, relay_result as result, tick)
from helpers import set_node

READY = ["demo:atrium", "scene:s1", "scene:s2"]


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def certify(db, node, doctor=DOCTOR_OK):
    core.hello(db, node, {"release_id": release_id(db), "facts": FACTS, "live_attempts": [], "ready_datasets": READY})
    node = fresh(db, node)
    assert node["lifecycle"] == "ready"
    core.heartbeat(db, node, {"capacity": CAPACITY, "doctor": doctor, "attempts": [], "ready_datasets": READY})
    node = fresh(db, node)
    g = core.claim(db, node, {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]
    assert g and all(x["kind"] == "golden" for x in g)
    for x in g:
        assert core.complete(db, node, x["attempt_id"], golden_result(x))["canonical"]
    node = fresh(db, node)
    assert set(core.certified_modules(node)) == set(doctor["modules"])
    return node


def test_enroll_certificate_issued_once(db):
    with pytest.raises(core.ApiError, match="csr_required"):
        core.enroll(db, "mini", FACTS, "127.0.0.1", "")
    e = core.enroll(db, "mini", FACTS, "127.0.0.1", node_key_and_csr()[1])
    assert core.enroll_status(db, e["enrollment_id"])["status"] == "pending"
    core.approve_enrollment(db, e["enrollment_id"], "test")
    first = core.enroll_status(db, e["enrollment_id"])
    assert first["status"] == "approved" and "BEGIN CERTIFICATE" in first["cert_pem"]
    assert core.enroll_status(db, e["enrollment_id"]) == {"status": "claimed"}
    with pytest.raises(core.ApiError):
        core.auth_cert(db, b"not a certificate", "127.0.0.1")


def test_lifecycle_doctor_golden_certify(db):
    _, node = enrolled_node(db)
    certify(db, node)


def test_failed_module_doctor_blocks_only_that_module(db):
    _, node = enrolled_node(db)
    doc = {"modules": {"relay": {"health": "unhealthy", "checks": [{"name": "docker_on_path", "ok": False}]},
                       "toy": {"health": "healthy", "checks": []}}}
    node = certify(db, node, {"modules": {"toy": doc["modules"]["toy"]}})
    core.heartbeat(db, node, {"capacity": CAPACITY, "doctor": doc})
    node = fresh(db, node)
    assert core.node_modules(node)["relay"]["state"] == "doctor_failed"
    assert db.one("SELECT * FROM alerts WHERE rule='doctor_failed:relay'")
    study_with_jobs(db, ("scene:s1",))                       # relay work pending
    assert core.claim(db, node, {"free_cpu": 4, "free_mem_gb": 16, "ready_datasets": READY})["grants"] == []


def test_an_undetected_module_is_not_offered_and_never_alerts(db):
    """A doctor that reports `undetected` means this node cannot run the module (runner protocol): no doctor_failed, no
    alert, no goldens; once it reports healthy the module certifies."""
    _, node = enrolled_node(db)
    toy_only = {"modules": {"toy": DOCTOR_OK["modules"]["toy"]}}
    node = certify(db, node, toy_only)
    core.heartbeat(db, node, {"capacity": CAPACITY, "doctor": {"modules": {**toy_only["modules"],
                                                                           "relay": {"health": "undetected", "checks": []}}}})
    node = fresh(db, node)
    assert core.node_modules(node)["relay"]["state"] == "undetected"
    assert not db.one("SELECT * FROM alerts WHERE rule='doctor_failed:relay'")
    assert not db.one("SELECT 1 FROM jobs WHERE kind='golden' AND module='relay' AND target_node=?", (node["node_id"],))
    node = certify(db, node)
    assert core.node_modules(node)["relay"]["state"] == "certified"


def test_golden_mismatch_revokes_that_module_only(db):
    _, node = enrolled_node(db)
    core.hello(db, node, {"release_id": release_id(db), "facts": FACTS, "live_attempts": []})
    core.heartbeat(db, fresh(db, node), {"capacity": CAPACITY, "doctor": DOCTOR_OK})
    node = fresh(db, node)
    g = core.claim(db, node, {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]
    for x in g:
        r = core.complete(db, node, x["attempt_id"], result(score="0.883600") if x["module"] == "relay" else golden_result(x))
        if x["module"] == "relay":
            assert r["reason"] == "golden_mismatch" and not r["accepted"]
    node = fresh(db, node)
    assert core.node_modules(node)["relay"]["state"] == "revoked"
    assert core.node_modules(node)["toy"]["state"] == "certified"
    assert node["lifecycle"] == "ready"


def study_with_jobs(db, datasets=("scene:s1", "scene:s2")):
    return create_study(db, "t", [{"label": "c1", "params": {**PARAMS, "samples": 25}}],
                                list(datasets), {"label": "base", "params": PARAMS})


def test_dispatch_ready_datasets_and_limits(db):
    _, node = enrolled_node(db)
    node = certify(db, node)
    study_with_jobs(db)
    # datasets not staged -> nothing granted
    assert core.claim(db, node, {"free_slots": 4, "ready_datasets": ["tool:other"]})["grants"] == []
    # resources: 1.5 GB per relay job -> only 2 fit in 3 GB
    assert len(core.claim(db, node, {"free_cpu": 8, "free_mem_gb": 3.0, "ready_datasets": READY})["grants"]) == 2
    db.x("UPDATE attempts SET state='released' WHERE node_id=?", (node["node_id"],))
    db.x("UPDATE jobs SET state='pending' WHERE state='leased'")
    set_node(db, node, "jobs", 1)
    node = db.one("SELECT * FROM nodes WHERE node_id=?", (node["node_id"],))
    g = core.claim(db, node, {"free_slots": 4, "ready_datasets": READY})["grants"]
    assert len(g) == 1, "user cap jobs=1 must bound grants"
    set_node(db, node, "jobs", reset=True)
    node = db.one("SELECT * FROM nodes WHERE node_id=?", (node["node_id"],))
    assert core.node_limits(node) == {"enforce": "soft"}
    g2 = core.claim(db, node, {"free_slots": 4, "ready_datasets": READY})["grants"]
    assert len(g2) == 3   # 4 jobs total (2 trials x 2 datasets), 1 already granted


def test_limits_validation(db):
    from oarbank.coordinator.settings.apply import ApplyError
    _, node = enrolled_node(db)
    for key, value, why in (("mem_gb", 64, "more than this node's 24 GB of RAM"), ("cpu_cores", 99, "more than this node's 15 cores"),
                            ("bogus", 1, "no setting 'bogus'"), ("jobs", 0, "below 1"), ("jobs", "two", "expected integer")):
        with pytest.raises(ApplyError) as e:
            set_node(db, node, key, value)
        assert why in e.value.detail, e.value.detail
    set_node(db, node, "mem_gb", 12)
    set_node(db, node, "enforce", "hard")
    assert core.node_limits(fresh(db, node)) == {"mem_gb": 12, "enforce": "hard"}
    set_node(db, node, "mem_gb", reset=True)
    assert core.node_limits(fresh(db, node)) == {"enforce": "hard"}


def test_fencing_stale_generation_and_late_replica(db):
    _, node = enrolled_node(db)
    node = certify(db, node)
    study_with_jobs(db, ("scene:s1",))
    g = core.claim(db, node, {"free_slots": 2, "ready_datasets": READY})["grants"]
    a1, a2 = g[0]["attempt_id"], g[1]["attempt_id"]
    # user retries job of a1 while it runs -> generation bump fences a1's result
    j1 = g[0]["job_id"]
    db.x("UPDATE jobs SET generation=generation+1 WHERE job_id=?", (j1,))
    r = core.complete(db, node, a1, result(score="0.8"))
    assert r["reason"] == "stale_generation" and not r["canonical"]
    # a2 completes canonically; a replayed completion is idempotent
    r2 = core.complete(db, node, a2, result(score="0.81"))
    assert r2["canonical"]
    assert core.complete(db, node, a2, result(score="0.81")) == r2


def test_mode_mismatch_rejected(db):
    _, node = enrolled_node(db)
    node = certify(db, node)
    study_with_jobs(db, ("scene:s1",))
    g = core.claim(db, node, {"free_slots": 1, "ready_datasets": READY})["grants"]
    r = core.complete(db, node, g[0]["attempt_id"], result(mode={"runtime": "native-arm64", "sampler": "random",
                                                                "filter": "box"}))
    assert r["reason"] == "mode_mismatch" and not r["accepted"]
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (g[0]["job_id"],))["state"] == "pending"


def _dispute_setup(db, first_wrong: bool):
    """n1 goes silent (lease expires); n2 finishes the job; n1 returns late with a different
    answer -> dispute; n3 breaks the tie. `first_wrong` decides which of n1/n2 was wrong."""
    nodes = [certify(db, enrolled_node(db, n)[1]) for n in ("n1", "n2", "n3")]
    study_with_jobs(db, ("scene:s1",))
    n1, n2, n3 = nodes
    g1 = core.claim(db, n1, {"free_slots": 1, "ready_datasets": READY})["grants"][0]
    db.x("UPDATE attempts SET expires_at=? WHERE attempt_id=?", (time.time() - 1, g1["attempt_id"]))
    core.reap(db)
    g2 = [g for g in core.claim(db, n2, {"free_slots": 4, "ready_datasets": READY})["grants"] if g["job_id"] == g1["job_id"]][0]
    right, wrong = result(score="0.850000", image="A"), result(score="0.860000", image="B")
    assert core.complete(db, n2, g2["attempt_id"], wrong if first_wrong else right)["canonical"]
    late = core.complete(db, n1, g1["attempt_id"], right if first_wrong else wrong)
    assert late["reason"] == "disputed"
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (g1["job_id"],))
    assert j["state"] == "pending" and j["dispute_json"]
    assert invariants_ok(db)
    # neither disputed node may take the tie-break
    assert not [g for g in core.claim(db, fresh(db, n1), {"free_slots": 4, "ready_datasets": READY})["grants"]
                if g["job_id"] == j["job_id"]]
    g3 = [g for g in core.claim(db, n3, {"free_slots": 4, "ready_datasets": READY})["grants"] if g["job_id"] == j["job_id"]][0]
    assert core.complete(db, n3, g3["attempt_id"], right)["canonical"]
    return n1, n2, n3


def invariants_ok(db):
    from oarbank.coordinator import invariants
    v = invariants.check_all(db)
    assert not v, v
    return True


def test_dispute_quorum_blames_late_wrong_node(db):
    n1, n2, n3 = _dispute_setup(db, first_wrong=False)
    life = {n["hostname"]: fresh(db, n)["lifecycle"] for n in (n1, n2, n3)}
    assert life == {"n1": "quarantined", "n2": "ready", "n3": "ready"}
    assert invariants_ok(db)


def test_dispute_quorum_blames_first_wrong_node_not_the_late_one(db):
    """The canonical result came from the WRONG node; the late node was right. The tie-break must
    vindicate the late node and quarantine the original canonical author."""
    n1, n2, n3 = _dispute_setup(db, first_wrong=True)
    life = {n["hostname"]: fresh(db, n)["lifecycle"] for n in (n1, n2, n3)}
    assert life == {"n1": "ready", "n2": "quarantined", "n3": "ready"}
    assert invariants_ok(db)


def test_late_identical_replica_is_evidence_not_quarantine(db):
    _, n1 = enrolled_node(db, "mini")
    n1 = certify(db, n1)
    _, n2 = enrolled_node(db, "desk")
    n2 = certify(db, n2)
    study_with_jobs(db, ("scene:s1",))
    g1 = core.claim(db, n1, {"free_slots": 1, "ready_datasets": READY})["grants"][0]
    db.x("UPDATE attempts SET expires_at=? WHERE attempt_id=?", (time.time() - 1, g1["attempt_id"]))
    core.reap(db)
    g2 = [g for g in core.claim(db, n2, {"free_slots": 4, "ready_datasets": READY})["grants"] if g["job_id"] == g1["job_id"]][0]
    core.complete(db, n2, g2["attempt_id"], result(score="0.850000", image="A"))
    core.complete(db, n1, g1["attempt_id"], result(score="0.850000", image="A"))
    assert db.one("SELECT lifecycle FROM nodes WHERE node_id=?", (n1["node_id"],))["lifecycle"] == "ready"
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='replica_match'")["n"] == 1


def test_completion_from_closed_attempt_rejected(db):
    _, node = enrolled_node(db)
    node = certify(db, node)
    study_with_jobs(db, ("scene:s1",))
    g = core.claim(db, node, {"free_slots": 1, "ready_datasets": READY})["grants"][0]
    core.fail(db, node, g["attempt_id"], {"reason": "exit_nonzero"})
    r = core.complete(db, node, g["attempt_id"], result())
    assert r["reason"] == "attempt_closed" and not r["canonical"]


def test_duplicate_completion_other_key_is_idempotent(db):
    _, node = enrolled_node(db)
    node = certify(db, node)
    study_with_jobs(db, ("scene:s1",))
    g = core.claim(db, node, {"free_slots": 1, "ready_datasets": READY})["grants"][0]
    r1 = core.complete(db, node, g["attempt_id"], result() | {"idempotency_key": "a"})
    r2 = core.complete(db, node, g["attempt_id"], result(score="0.1") | {"idempotency_key": "b"})
    assert r1["canonical"] and r2["canonical"] and r2.get("duplicate")


def test_toy_campaign_runs_caches_and_finishes(db):
    """The SDK's reference module end to end: its operation enqueues jobs, runners' envelopes are judged by
    its result.evaluate, a drained campaign of a module without campaign.tick is finished by the core, and
    the same inputs later are a result-cache hit."""
    from helpers import toy_result
    from oarbank.coordinator import ops
    n1 = certify(db, enrolled_node(db, "mini")[1])
    r = ops.execute(db, ops.OpRequest(op="mod.toy.queue_sums", actor="test", idempotency_key=uuid.uuid4().hex, params={"ns": [10, 20]}))
    cid = r["result"]["result"]["campaign_id"]
    g = core.claim(db, n1, {"free_cpu": 4, "free_mem_gb": 8, "ready_datasets": READY})["grants"]
    assert sorted(x["spec"]["payload"]["n"] for x in g) == [10, 20] and {x["module"] for x in g} == {"toy"}
    assert all(x["spec"]["envelope"] == 1 and x["spec"]["module_id"] == "dev.codonic.oarbank.toy" for x in g)
    for x in g:
        assert core.complete(db, n1, x["attempt_id"], toy_result(x["spec"]["payload"]["n"]))["canonical"]
    bad = core.claim(db, n1, {"free_cpu": 4, "free_mem_gb": 8, "ready_datasets": READY})["grants"]
    assert bad == []
    assert sorted(v["value"] for v in db.q("SELECT r.value FROM results r JOIN jobs j ON j.job_id=r.job_id "
                                           "WHERE j.campaign_id=? AND r.canonical=1", (cid,))) == [45.0, 190.0]
    tick(db)
    assert db.one("SELECT state FROM campaigns WHERE campaign_id=?", (cid,))["state"] == "done"
    r = ops.execute(db, ops.OpRequest(op="mod.toy.queue_sums", actor="test", idempotency_key=uuid.uuid4().hex, params={"ns": [20], "campaign_id": "c_again"}))
    assert db.one("SELECT state FROM jobs WHERE campaign_id='c_again'")["state"] == "done"      # cache hit


def test_expiry_is_not_a_failure_but_exec_failure_is(db):
    _, node = enrolled_node(db)
    node = certify(db, node)
    study_with_jobs(db, ("scene:s1",))
    g = core.claim(db, node, {"free_slots": 2, "ready_datasets": READY})["grants"]
    db.x("UPDATE attempts SET expires_at=? WHERE attempt_id=?", (time.time() - 1, g[0]["attempt_id"]))
    core.reap(db)
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (g[0]["job_id"],))
    assert j["state"] == "pending" and j["exec_failures"] == 0 and j["expirations"] == 1
    core.fail(db, node, g[1]["attempt_id"], {"reason": "exit_nonzero"})
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (g[1]["job_id"],))
    assert j["state"] == "pending" and j["exec_failures"] == 1 and j["not_before"] > time.time()


def test_protection_release_requeues_immediately(db):
    _, node = enrolled_node(db)
    node = certify(db, node)
    study_with_jobs(db, ("scene:s1",))
    g = core.claim(db, node, {"free_slots": 1, "ready_datasets": READY})["grants"][0]
    core.release(db, node, g["attempt_id"], "preempt_protection")
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (g["job_id"],))
    assert j["state"] == "pending" and j["exec_failures"] == 0


def test_result_cache_dedupes_across_studies(db):
    _, node = enrolled_node(db)
    node = certify(db, node)
    study_with_jobs(db, ("scene:s1",))
    for g in core.claim(db, node, {"free_slots": 4, "ready_datasets": READY})["grants"]:
        core.complete(db, node, g["attempt_id"], result(score="0.850000"))
    sid2 = study_with_jobs(db, ("scene:s1",))
    assert db.one("SELECT COUNT(*) n FROM jobs WHERE campaign_id=? AND state='pending'", (sid2,))["n"] == 0
    assert {j["state"] for j in db.q("SELECT state FROM jobs WHERE campaign_id=?", (sid2,))} == {"done"}
    assert invariants_ok(db)          # S2/S3 must accept a cache hit (found live on 09-29)


def test_conviction_recomputes_cache_hits_too(db):
    nodes = [certify(db, enrolled_node(db, n)[1]) for n in ("n1", "n2")]
    study_with_jobs(db, ("scene:s1",))
    for g in core.claim(db, nodes[0], {"free_slots": 4, "ready_datasets": READY})["grants"]:
        core.complete(db, nodes[0], g["attempt_id"], result(score="0.850000"))
    sid2 = study_with_jobs(db, ("scene:s1",))
    core.quarantine(db, nodes[0]["node_id"], "nondeterminism: test", "test")
    assert db.one("SELECT COUNT(*) n FROM jobs WHERE campaign_id=? AND state='pending'", (sid2,))["n"] == 2
    assert invariants_ok(db)


def test_hello_kills_unknown_attempts_and_releases_forgotten(db):
    _, node = enrolled_node(db)
    node = certify(db, node)
    study_with_jobs(db, ("scene:s1",))
    g = core.claim(db, node, {"free_slots": 1, "ready_datasets": READY})["grants"][0]
    out = core.hello(db, node, {"release_id": release_id(db), "facts": FACTS, "live_attempts": [999999]})
    assert out["kill"] == [999999]
    a = db.one("SELECT state, end_reason FROM attempts WHERE attempt_id=?", (g["attempt_id"],))
    assert a["state"] == "released" and a["end_reason"] == "agent_restart"




def test_a_join_codes_label_names_the_node_and_the_reported_hostname_does_not_rename_it(db):
    # the label went into the approval reason ("join:owner (mini-2)") and the node took the host name it reported
    from oarbank.coordinator import joincodes
    cik = base64.b64encode(bytes(32)).decode()

    def join(label, hostname):
        token = joincodes.decode(joincodes.create(db, urls=["https://127.0.0.1:7443"], pins=["ab" * 32], cik=cik,
                                                  actor="owner", label=label)["code"])["token"]
        e = core.enroll(db, hostname, {**FACTS, "hostname": hostname}, "127.0.0.1", node_key_and_csr()[1], join=token)
        assert e["status"] == "approved"
        row = db.one("SELECT node_id, decided_by FROM enrollments WHERE enrollment_id=?", (e["enrollment_id"],))
        assert row["decided_by"] == "join:owner"
        return db.one("SELECT * FROM nodes WHERE node_id=?", (row["node_id"],))

    labelled = join(" mini-2 ", "Office-Mac-mini.local")
    assert (labelled["hostname"], labelled["label"]) == ("mini-2", "mini-2")
    core.hello(db, labelled, {"facts": {**FACTS, "hostname": "renamed-mac"}, "boot_id": "b1"})
    assert fresh(db, labelled)["hostname"] == "mini-2"                         # the label wins over the reported name
    plain = join("", "studio")
    assert (plain["hostname"], plain["label"]) == ("studio", None)
    core.hello(db, plain, {"facts": {**FACTS, "hostname": "studio-2"}, "boot_id": "b2"})
    assert fresh(db, plain)["hostname"] == "studio-2"                          # no label: it follows the agent


@pytest.mark.parametrize("skew", [-7 * 3600, 7 * 3600])
def test_a_skewed_node_clock_is_flagged_and_grants_carry_the_coordinators_time(db, skew):
    """A node whose clock is hours off still gets work it can time correctly (grants carry issued_at, directives now:
    protocol.md, "Clocks"), and the owner sees the skew as a node condition in the console and in explain."""
    from oarbank.console import views
    from oarbank.coordinator import clock, explain
    _, node = enrolled_node(db)
    node = certify(db, node)
    d = core.heartbeat(db, node, {"capacity": CAPACITY, "attempts": [], "ready_datasets": READY, "clock": clock.now() + skew})
    assert abs(d["now"] - clock.now()) < 5
    node = fresh(db, node)
    assert abs(node["clock_offset_s"] - skew) < 5
    assert [s.detail for s in explain.node_doc(db, node["node_id"]).summary if s.code == "CLOCK_SKEW"]
    cond = [c for c in views.node_page(db, node["node_id"], time.time(), lambda m: None)["conditions"] if c["code"] == "CLOCK_SKEW"]
    assert cond and ("ahead of" if skew > 0 else "behind") in cond[0]["message"]
    create_study(db, "s", [], ["scene:s1"], {"label": "base", "params": PARAMS})
    g = core.claim(db, node, {"free_cpu": 4, "free_mem_gb": 8, "ready_datasets": READY})["grants"][0]
    assert abs(g["issued_at"] - clock.now()) < 5 and g["hard_deadline"] - g["issued_at"] == max(600, g["spec"]["timeout_s"])
    core.heartbeat(db, node, {"capacity": CAPACITY, "attempts": [], "ready_datasets": READY, "clock": clock.now() + 3})
    assert not [s for s in explain.node_doc(db, node["node_id"]).summary if s.code == "CLOCK_SKEW"]
    assert not [c for c in views.node_page(db, node["node_id"], time.time(), lambda m: None)["conditions"] if c["code"] == "CLOCK_SKEW"]
