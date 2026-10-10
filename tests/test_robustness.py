"""Regression tests for the result-integrity layer: adaptive replication, quorum disputes, conviction
and invalidation, soft anti-affinity and stranded disputes. Each test pins a bug or gap that the
seeded fault-injecting simulator (oarbank.sim) found; see docs/verification.md."""
import pytest

from oarbank.coordinator import clock, core, invariants

from helpers import CAPACITY, release_id, create_study, tick, SCENES, PARAMS, READY, certified_fleet, certify, enrolled_node, fresh, golden_result, make_db, relay_result
from helpers import set_fleet

RIGHT, WRONG = relay_result(score="0.850000", image="A"), relay_result(score="0.860000", image="B")


@pytest.fixture
def db(tmp_path):
    clock.set_fake(1_900_000_000.0)
    d = make_db(tmp_path / "oarbank.sqlite3")
    yield d
    clock.set_fake(None)
    d.conn.close()


def ok(db):
    v = invariants.check_all(db)
    assert not v, v
    return True


def study(db, datasets):
    return create_study(db, "t", [{"label": "c1", "params": {**PARAMS, "samples": 25}}],
                                list(datasets), {"label": "base", "params": PARAMS})


def claim(db, node, job_id=None, free=8):
    gs = core.claim(db, fresh(db, node), {"free_cpu": free, "free_mem_gb": 64, "ready_datasets": READY})["grants"]
    return [g for g in gs if job_id is None or g["job_id"] == job_id]


def run_one(db, node, res, job_id=None):
    g = claim(db, node, job_id, free=1)[0]
    return g, core.complete(db, fresh(db, node), g["attempt_id"], res)


def test_replication_catches_a_silently_wrong_node_and_invalidates_its_work(db):
    """A node that returns plausible but wrong results is never caught by fencing or validation.
    Replicas of a sample of its jobs run elsewhere; a mismatch opens a quorum dispute; the third node
    convicts it; every canonical result it produced is recomputed."""
    set_fleet(db, "replica_rate", 1.0)
    bad, good1, good2 = certified_fleet(db, ("bad", "good1", "good2"))
    study(db, SCENES[:2])
    g1, r1 = run_one(db, bad, WRONG)
    g2, r2 = run_one(db, bad, WRONG)
    assert r1["canonical"] and r2["canonical"]
    replicas = db.q("SELECT * FROM jobs WHERE kind='replica'")
    assert len(replicas) == 2 and ok(db)
    assert not [g for g in claim(db, bad) if g["kind"] == "replica"]      # never replicated on its author
    rep = [g for g in claim(db, good1, free=1) if g["kind"] == "replica"][0]
    core.complete(db, fresh(db, good1), rep["attempt_id"], RIGHT)
    orig = db.one("SELECT * FROM jobs WHERE job_id=(SELECT job_id FROM jobs WHERE job_key=?)",
                  (db.one("SELECT job_key FROM jobs WHERE job_id=?", (rep["job_id"],))["job_key"].split(":")[0],))
    assert orig["state"] == "pending" and orig["dispute_json"] and ok(db)
    tie = claim(db, good2, orig["job_id"])[0]
    assert core.complete(db, fresh(db, good2), tie["attempt_id"], RIGHT)["canonical"]
    assert fresh(db, bad)["lifecycle"] == "quarantined"
    assert fresh(db, good1)["lifecycle"] == fresh(db, good2)["lifecycle"] == "ready"
    # the bad node's other canonical result was invalidated and requeued
    other = g2["job_id"] if orig["job_id"] == g1["job_id"] else g1["job_id"]
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (other,))["state"] == "pending"
    assert ok(db)


def test_conviction_reopens_a_finished_study(db):
    """Invalidated jobs of a study that already finished must be claimable again."""
    n1, n2, n3 = certified_fleet(db, ("n1", "n2", "n3"))
    sid = study(db, SCENES[:1])
    for n in (n1, n1):
        run_one(db, n, RIGHT)
    tick(db)
    assert db.one("SELECT state FROM campaigns WHERE campaign_id=?", (sid,))["state"] == "done"
    core.quarantine(db, n1["node_id"], "nondeterminism: test", "test")
    assert db.one("SELECT state FROM campaigns WHERE campaign_id=?", (sid,))["state"] == "running"
    assert len(claim(db, n2)) == 2 and ok(db)


def test_late_result_from_convicted_node_is_rejected(db):
    """A node that slept through its conviction must not deliver a canonical result afterwards."""
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:1])
    g = claim(db, n1, free=1)[0]
    clock.advance(120)
    core.reap(db)                                     # lease expired while asleep
    core.quarantine(db, n1["node_id"], "nondeterminism: test", "test")
    r = core.complete(db, fresh(db, n1), g["attempt_id"], RIGHT)
    assert not r["canonical"] and r["reason"] == "node_quarantined"
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (g["job_id"],))["state"] == "pending" and ok(db)


def test_failure_anti_affinity_is_soft(db):
    """A transient failure must not strand a job: a node skips a job it failed only while another
    eligible node exists (the simulator found jobs stuck pending forever)."""
    (n1,) = certified_fleet(db, ("n1",))
    study(db, SCENES[:1])
    g = claim(db, n1, free=1)[0]
    core.fail(db, fresh(db, n1), g["attempt_id"], {"reason": "exit_nonzero"})
    clock.advance(3600)                               # past the retry backoff
    retry = claim(db, n1, g["job_id"])
    assert retry, "the only node must be allowed to retry"
    # with a second eligible node, the node that failed it steps aside
    core.fail(db, fresh(db, n1), retry[0]["attempt_id"], {"reason": "exit_nonzero"})
    clock.advance(3600)
    n2 = certify(db, enrolled_node(db, "n2")[1])
    assert not claim(db, n1, g["job_id"])
    assert claim(db, n2, g["job_id"])
    assert ok(db)


def test_three_way_disagreement_keeps_job_leased_while_another_attempt_runs(db):
    """S5 regression: a widening dispute used to set the job pending while another attempt was live."""
    nodes = certified_fleet(db, ("n1", "n2", "n3", "n4", "n5"))
    study(db, SCENES[:1])
    n1, n2, n3, n4, n5 = nodes
    g1 = claim(db, n1, free=1)[0]
    clock.advance(120)
    core.reap(db)
    g2 = claim(db, n2, g1["job_id"])[0]
    core.complete(db, fresh(db, n2), g2["attempt_id"], relay_result(score="0.810000", image="X"))
    core.complete(db, fresh(db, n1), g1["attempt_id"], relay_result(score="0.820000", image="Y"))   # dispute
    g3 = claim(db, n3, g1["job_id"])[0]
    clock.advance(120)
    core.reap(db)                                     # n3 goes silent; n4 picks the tie-break up
    g4 = claim(db, n4, g1["job_id"])[0]
    core.complete(db, fresh(db, n3), g3["attempt_id"], relay_result(score="0.830000", image="Z"))   # third answer
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (g1["job_id"],))
    assert j["state"] == "leased", "n4 is still running it"
    assert ok(db)
    assert core.complete(db, fresh(db, n4), g4["attempt_id"], relay_result(score="0.810000", image="X"))["canonical"]
    assert fresh(db, n2)["lifecycle"] == "ready" and fresh(db, n4)["lifecycle"] == "ready"
    assert fresh(db, n1)["lifecycle"] == fresh(db, n3)["lifecycle"] == "quarantined"
    assert ok(db)


def test_second_late_golden_result_is_not_canonical(db):
    """S1 regression: both golden attempts expired, both reported late -> two canonical results."""
    _, node = enrolled_node(db, "g")
    core.hello(db, node, {"release_id": release_id(db), "facts": {}, "live_attempts": [], "ready_datasets": READY})
    from helpers import DOCTOR_OK
    core.heartbeat(db, fresh(db, node), {"capacity": CAPACITY, "doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY})
    first = [g for g in claim(db, node) if g["module"] == "relay"][0]
    clock.advance(120)
    core.reap(db)
    second = [g for g in claim(db, node) if g["job_id"] == first["job_id"]][0]
    clock.advance(120)
    core.reap(db)
    assert core.complete(db, fresh(db, node), first["attempt_id"], golden_result(first))["canonical"]
    r = core.complete(db, fresh(db, node), second["attempt_id"], golden_result(second))
    assert not r["canonical"] and r["reason"] == "job_done"
    assert ok(db)


def test_dispute_without_a_possible_tie_breaker_is_quarantined_and_alerted(db):
    """Two nodes that disagree cannot be adjudicated; the job must settle (quarantined, alert) rather
    than wait forever (liveness L1)."""
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:1])
    g1 = claim(db, n1, free=1)[0]
    clock.advance(120)
    core.reap(db)
    g2 = claim(db, n2, g1["job_id"])[0]
    core.complete(db, fresh(db, n2), g2["attempt_id"], RIGHT)
    assert core.complete(db, fresh(db, n1), g1["attempt_id"], WRONG)["reason"] == "disputed"
    core.reap(db)
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (g1["job_id"],))["state"] == "quarantined"
    assert db.one("SELECT 1 FROM alerts WHERE rule=? AND state='open'", (f"dispute:{g1['job_id']}",))
    assert fresh(db, n1)["lifecycle"] == fresh(db, n2)["lifecycle"] == "ready"      # nobody convicted on a coin flip
    assert ok(db)


def test_replica_match_is_recorded_and_changes_nothing(db):
    set_fleet(db, "replica_rate", 1.0)
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:1])
    g, _ = run_one(db, n1, RIGHT)
    rep = [x for x in claim(db, n2) if x["kind"] == "replica"][0]
    core.complete(db, fresh(db, n2), rep["attempt_id"], RIGHT)
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (g["job_id"],))["state"] == "done"
    assert db.one("SELECT 1 FROM events WHERE kind='replica_match' AND job_id=?", (g["job_id"],))
    assert ok(db)


def test_platform_scoped_results_replicate_and_compare_only_within_a_platform(db, monkeypatch):
    """determinism_scope = "platform": a replica runs on the original's platform, and results from different platforms
    are never compared (so never disputed)."""
    import dataclasses
    from oarbank.coordinator import modcalls
    from helpers import facts_for
    info = modcalls.info("relay")
    man = info.manifest.model_copy(update={"results": info.manifest.results.model_copy(update={"determinism_scope": "platform"})})
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=man))
    set_fleet(db, "replica_rate", 1.0)
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    box = certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1])
    study(db, SCENES[:1])
    g, _ = run_one(db, n1, RIGHT)
    rj = db.one("SELECT * FROM jobs WHERE kind='replica'")
    assert '"scope": "same-platform", "class": "darwin-arm64"' in rj["dispute_json"]
    assert not [x for x in claim(db, box) if x["kind"] == "replica"]                 # the Linux node never takes it
    from oarbank.coordinator import explain
    doc = explain.job_doc(db, rj["job_id"], bodies={box["node_id"]: {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY}})
    assert any(s.code == "COMPARED_ON_PLATFORM" for s in doc.summary), doc.summary
    rep = [x for x in claim(db, n2) if x["kind"] == "replica"][0]
    core.complete(db, fresh(db, n2), rep["attempt_id"], WRONG)                       # same platform: a real dispute
    d = db.one("SELECT dispute_json FROM jobs WHERE job_id=?", (g["job_id"],))["dispute_json"]
    assert '"class": "darwin-arm64"' in d
    assert ok(db)


def _relay_with(monkeypatch, scope=None, stage_platforms=None, stage_variants=None):
    """relay with determinism_scope, its eval stage limited to some platforms and/or per-platform eval stage variants
    (patched in the catalog)."""
    import dataclasses
    from oarbank.coordinator import modcalls
    from oarbank_sdk import manifest as mf
    info = modcalls.info("relay")
    upd = {}
    if scope:
        upd["results"] = info.manifest.results.model_copy(update={"determinism_scope": scope})
    if stage_platforms is not None:
        upd["stages"] = [st.model_copy(update={"requires": st.requires.model_copy(update={"platforms": stage_platforms})})
                         if st.name == "eval" else st for st in info.manifest.stages]
    if stage_variants is not None:
        upd["stages"] = [st.model_copy(update={"variants": {k: mf.StageVariant.model_validate(v) for k, v in stage_variants.items()}})
                         if st.name == "eval" else st for st in upd.get("stages", info.manifest.stages)]
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=info.manifest.model_copy(update=upd)))


def test_a_stage_limited_to_a_platform_is_never_granted_elsewhere(db, monkeypatch):
    from helpers import facts_for
    from oarbank.coordinator import explain
    mini = certify(db, enrolled_node(db, "mini")[1])
    box = certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1])
    _relay_with(monkeypatch, stage_platforms=["darwin-arm64"])
    study(db, SCENES[:2])
    assert not [g for g in claim(db, box) if g["module"] == "relay"]
    j = db.one("SELECT * FROM jobs WHERE module='relay' AND kind!='golden' AND state='pending' ORDER BY job_id LIMIT 1")
    body = {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY}
    doc = explain.job_doc(db, j["job_id"], bodies={box["node_id"]: body, mini["node_id"]: body})
    assert {s.code: s.nodes for s in doc.summary}.get("STAGE_PLATFORM_UNSUPPORTED") == ["box"], doc.summary
    assert "jobs.cancel" in [r.op for r in doc.remedies]
    assert {g["module"] for g in claim(db, mini)} == {"relay"}
    assert ok(db)


def test_a_stages_windows_timeout_and_resources_reach_the_envelope_the_deadline_and_explain(db, monkeypatch):
    import json
    from helpers import facts_for
    from oarbank.coordinator import explain
    mini = certify(db, enrolled_node(db, "mini")[1])
    win = certify(db, enrolled_node(db, "win", facts=facts_for("windows-amd64", os_version="10.0.26100"))[1])
    _relay_with(monkeypatch, stage_variants={"windows": {"timeout_s": 5400, "requires": {"resources": {"mem_gb": 10}}},
                                             "windows-amd64": {"requires": {"resources": {"cpu": 2}}}})
    study(db, SCENES[:2])
    j = db.one("SELECT * FROM jobs WHERE module='relay' AND kind='eval' AND state='pending' ORDER BY job_id LIMIT 1")
    assert json.loads(j["resources_json"])["by_platform"] == {"windows": {"mem_gb": 10}, "windows-amd64": {"cpu": 2}}
    # explain resolves the job's resources for each node: 8 GB free is too little on Windows only
    body = {"free_cpu": 8, "free_mem_gb": 8, "ready_datasets": READY}
    doc = explain.job_doc(db, j["job_id"], bodies={win["node_id"]: body, mini["node_id"]: body})
    assert {s.code: s.nodes for s in doc.summary}.get("INSUFFICIENT_MEM") == ["win"], doc.summary
    assert not [g for g in core.claim(db, fresh(db, win), body)["grants"] if g["module"] == "relay"]
    g = [x for x in claim(db, mini, free=1) if x["module"] == "relay"][0]
    assert g["spec"]["timeout_s"] == 1800 and g["spec"]["resources"] == {"cpu": 1, "mem_gb": 1.5, "needs_pools": ["scorer"]}
    g = [x for x in claim(db, win, free=2) if x["module"] == "relay"][0]
    assert g["spec"]["timeout_s"] == 5400 and g["hard_deadline"] - clock.now() == 5400
    assert g["spec"]["resources"] == {"cpu": 2, "mem_gb": 10, "needs_pools": ["scorer"]}
    assert db.one("SELECT hard_deadline - granted_at d FROM attempts WHERE attempt_id=?", (g["attempt_id"],))["d"] == 5400
    assert ok(db)


def test_comparisons_use_the_platform_a_result_was_produced_on(db, monkeypatch):
    """A node that changes platform after producing the canonical result: a later result from its old platform is still
    compared with it (and disputed), because results.platform is a snapshot, not the node's current platform."""
    from helpers import facts_for
    _relay_with(monkeypatch, scope="platform")
    set_fleet(db, "replica_rate", 0.0)
    n1, n2, n3 = certified_fleet(db, ("n1", "n2", "n3"))
    study(db, SCENES[:1])
    g1 = claim(db, n1, free=1)[0]
    clock.advance(120)
    core.reap(db)
    g2 = claim(db, n2, g1["job_id"])[0]
    assert core.complete(db, fresh(db, n2), g2["attempt_id"], RIGHT)["canonical"]
    assert db.one("SELECT platform FROM results WHERE attempt_id=?", (g2["attempt_id"],))["platform"] == "darwin-arm64"
    core.hello(db, fresh(db, n2), {"release_id": release_id(db), "facts": facts_for("linux-amd64", os_version="6.8"),
                                   "live_attempts": [], "ready_datasets": READY})
    assert fresh(db, n2)["platform"] == "linux-amd64"
    assert core.complete(db, fresh(db, n1), g1["attempt_id"], WRONG)["reason"] == "disputed"
    assert '"class": "darwin-arm64"' in db.one("SELECT dispute_json FROM jobs WHERE job_id=?", (g1["job_id"],))["dispute_json"]
    assert ok(db)


def test_a_platform_scoped_dispute_counts_only_nodes_of_its_platform_as_takers(db):
    from helpers import facts_for
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1])
    study(db, SCENES[:1])
    j = db.one("SELECT * FROM jobs WHERE module='relay' AND kind!='golden' ORDER BY job_id LIMIT 1")
    j = {**j, "dispute_json": '{"nodes": ["%s"], "scope": "same-platform", "class": "darwin-arm64"}' % n2["node_id"]}
    assert not core._other_node_can_take(db, j, n1["node_id"])         # box is the only other non-party: wrong platform
    assert core._other_node_can_take(db, {**j, "dispute_json": '{"nodes": ["%s"]}' % n2["node_id"]}, n1["node_id"])


def test_a_grant_names_the_nodes_platform(db):
    from helpers import facts_for
    from oarbank_sdk.envelopes import SpecEnvelope
    box = certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1])
    study(db, SCENES[:1])
    g = [x for x in claim(db, box) if x["module"] == "relay"][0]
    assert g["spec"]["platform"] == "linux-amd64"
    assert SpecEnvelope.model_validate(g["spec"]).platform == "linux-amd64"


# ---------------------------------------------------------------- TLA+ findings (specs/README.md)
def test_F1_claim_rereads_the_node_inside_its_transaction(db):
    """A node row read by auth before a quarantine must not yield grants afterwards."""
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:2])
    stale = fresh(db, n1)                                    # auth_node's read
    core.quarantine(db, n1["node_id"], "operator", "test")   # commits in between
    assert core.claim(db, stale, {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY})["grants"] == []
    assert ok(db)


def test_F1_claim_after_revoke_uses_current_certification(db):
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:1])
    stale = fresh(db, n1)
    core.revoke_module(db, n1["node_id"], "relay", "test")
    gs = core.claim(db, stale, {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY})["grants"]
    assert all(g["kind"] == "golden" for g in gs) and ok(db)


def test_F2_a_dispute_party_cannot_break_its_own_tie(db):
    """The TLC counterexample: faulty n2 holds two expired attempts with the same wrong answer; its
    second one used to count as the tie-break vote and convict the correct n1."""
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:1])
    a1 = claim(db, n2, free=1)[0]
    jid = a1["job_id"]
    clock.advance(120); core.reap(db)
    a2 = claim(db, n1, jid)[0]
    clock.advance(120); core.reap(db)
    a3 = claim(db, n2, jid)[0]
    assert core.complete(db, fresh(db, n2), a3["attempt_id"], WRONG)["canonical"]
    assert core.complete(db, fresh(db, n1), a2["attempt_id"], RIGHT)["reason"] == "disputed"
    late = core.complete(db, fresh(db, n2), a1["attempt_id"], WRONG)
    assert not late["canonical"] and late["reason"] in ("stale_generation", "dispute_party")
    assert fresh(db, n1)["lifecycle"] == "ready", "the correct node must never be convicted"
    core.reap(db)                                            # two nodes: no tie-breaker -> quarantined
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (jid,))["state"] == "quarantined"
    assert ok(db)


def test_F2_late_vote_does_not_revive_a_quarantined_job(db):
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:1])
    g1 = claim(db, n1, free=1)[0]
    clock.advance(120); core.reap(db)
    g2 = claim(db, n2, g1["job_id"])[0]
    clock.advance(120); core.reap(db)
    g2b = claim(db, n2, g1["job_id"])[0]
    core.complete(db, fresh(db, n2), g2["attempt_id"], RIGHT)
    core.complete(db, fresh(db, n1), g1["attempt_id"], WRONG)
    core.reap(db)
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (g1["job_id"],))["state"] == "quarantined"
    r = core.complete(db, fresh(db, n2), g2b["attempt_id"], RIGHT)
    assert not r["canonical"]
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (g1["job_id"],))["state"] == "quarantined" and ok(db)


def test_node_giving_two_answers_for_one_job_convicts_itself(db):
    n1, n2, n3 = certified_fleet(db, ("n1", "n2", "n3"))
    study(db, SCENES[:1])
    a = claim(db, n1, free=1)[0]
    clock.advance(120); core.reap(db)
    b = claim(db, n1, a["job_id"])[0]
    assert core.complete(db, fresh(db, n1), b["attempt_id"], RIGHT)["canonical"]
    r = core.complete(db, fresh(db, n1), a["attempt_id"], WRONG)
    assert r["reason"] == "self_inconsistent"
    assert fresh(db, n1)["lifecycle"] == "quarantined"
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (a["job_id"],))["state"] == "pending"    # recomputed
    assert fresh(db, n2)["lifecycle"] == fresh(db, n3)["lifecycle"] == "ready" and ok(db)


def test_F3_no_replica_without_another_eligible_node(db):
    set_fleet(db, "replica_rate", 1.0)
    (n1,) = certified_fleet(db, ("n1",))
    study(db, SCENES[:1])
    run_one(db, n1, RIGHT)
    assert not db.q("SELECT 1 FROM jobs WHERE kind='replica'")


def test_F3_reaper_drops_a_replica_nobody_can_run(db):
    set_fleet(db, "replica_rate", 1.0)
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:1])
    run_one(db, n1, RIGHT)
    assert db.one("SELECT state FROM jobs WHERE kind='replica'")["state"] == "pending"
    core.quarantine(db, n2["node_id"], "operator", "test")
    core.reap(db)
    assert db.one("SELECT state FROM jobs WHERE kind='replica'")["state"] == "cancelled"
    assert ok(db)


def test_F4_failed_golden_job_stays_eligible_for_its_target(db):
    """A golden job that failed once used to be skipped by its (only possible) target forever."""
    from helpers import DOCTOR_OK
    n2 = certified_fleet(db, ("other",))[0]
    _, node = enrolled_node(db, "new")
    core.hello(db, node, {"release_id": release_id(db), "facts": {}, "live_attempts": [], "ready_datasets": READY})
    core.heartbeat(db, fresh(db, node), {"capacity": CAPACITY, "doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY})
    g = [x for x in claim(db, node) if x["module"] == "relay"][0]
    core.fail(db, fresh(db, node), g["attempt_id"], {"reason": "exit_nonzero"})
    clock.advance(3600)
    again = [x for x in claim(db, node) if x["job_id"] == g["job_id"]]
    assert again, "the target node must be able to retry its golden job"
    core.complete(db, fresh(db, node), again[0]["attempt_id"], golden_result(again[0]))
    assert "relay" in core.certified_modules(fresh(db, node)) and ok(db)


def test_F5_node_stuck_certifying_does_not_hold_a_replica_or_dispute_open(db):
    """A node whose goldens never finish (lease keeps expiring) is `certifying` forever. It must stop
    counting as an eligible replica runner / tie-breaker after the grace period."""
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    _, stuck = enrolled_node(db, "stuck")
    from helpers import DOCTOR_OK
    core.hello(db, stuck, {"release_id": release_id(db), "facts": {}, "live_attempts": [], "ready_datasets": READY})
    core.heartbeat(db, fresh(db, stuck), {"capacity": CAPACITY, "doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY})
    study(db, SCENES[:1])
    g1 = claim(db, n1, free=1)[0]
    clock.advance(120); core.reap(db)
    g2 = claim(db, n2, g1["job_id"])[0]
    core.complete(db, fresh(db, n2), g2["attempt_id"], RIGHT)
    core.complete(db, fresh(db, n1), g1["attempt_id"], WRONG)          # dispute {n1, n2}; only `stuck` could break it
    core.reap(db)
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (g1["job_id"],))["state"] == "pending"   # within grace
    clock.advance(core.CERTIFYING_GRACE_S + 60)
    core.reap(db)
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (g1["job_id"],))["state"] == "quarantined"
    assert ok(db)


def test_F5_replica_only_a_stuck_node_could_run_is_dropped(db):
    from helpers import DOCTOR_OK
    set_fleet(db, "replica_rate", 1.0)
    (n1,) = certified_fleet(db, ("n1",))
    _, stuck = enrolled_node(db, "stuck")
    core.hello(db, stuck, {"release_id": release_id(db), "facts": {}, "live_attempts": [], "ready_datasets": READY})
    core.heartbeat(db, fresh(db, stuck), {"capacity": CAPACITY, "doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY})
    study(db, SCENES[:1])
    run_one(db, n1, RIGHT)
    assert db.one("SELECT state FROM jobs WHERE kind='replica'")["state"] == "pending"      # stuck may still certify
    clock.advance(core.CERTIFYING_GRACE_S + 60)
    core.reap(db)
    assert db.one("SELECT state FROM jobs WHERE kind='replica'")["state"] == "cancelled"
    assert ok(db)


def test_F6_repeatedly_failing_goldens_stop_and_alert(db):
    """Every third failure used to trip the breaker, re-doctor queued a fresh golden set, old ones
    piled up and the module never settled. Now: bounded, one alert, no stale goldens."""
    from helpers import DOCTOR_OK
    _, node = enrolled_node(db, "flaky")
    core.hello(db, node, {"release_id": release_id(db), "facts": {}, "live_attempts": [], "ready_datasets": READY})
    hb = lambda: core.heartbeat(db, fresh(db, node), {"capacity": CAPACITY, "doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY})
    hb()
    for _ in range(30):
        clock.advance(700)
        hb()
        for g in [x for x in claim(db, node) if x["module"] == "relay"]:
            core.fail(db, fresh(db, node), g["attempt_id"], {"reason": "exit_nonzero"})
    st = core.node_modules(fresh(db, node))["relay"]
    assert st["state"] == "golden_failed"
    assert db.one("SELECT COUNT(*) n FROM jobs WHERE target_node=? AND kind='golden' AND module='relay' "
                  "AND state IN ('pending','leased')", (node["node_id"],))["n"] == 0
    assert db.one("SELECT 1 FROM alerts WHERE rule='golden_failed:relay' AND state='open'")
    assert db.one("SELECT COUNT(*) n FROM jobs WHERE kind='golden' AND module='relay' AND target_node=?",
                  (node["node_id"],))["n"] <= 3, "no pile-up of golden sets"
    assert ok(db)
    # automatic retry after RECERT_EVERY
    from oarbank.coordinator import config as C
    clock.advance(C.RECERT_EVERY + 60)
    hb()
    assert core.node_modules(fresh(db, node))["relay"]["state"] == "certifying"
    g = [x for x in claim(db, node) if x["module"] == "relay"][0]
    core.complete(db, fresh(db, node), g["attempt_id"], golden_result(g))
    assert "relay" in core.certified_modules(fresh(db, node)) and ok(db)
    assert not db.one("SELECT 1 FROM alerts WHERE rule='golden_failed:relay' AND state='open'"), "certifying resolves it"


def test_job_fault_does_not_trip_the_breaker_on_healthy_nodes(db):
    """A parameter combination that crashes the tool fails everywhere (seen live 09-29): after it has
    failed on one host, further failures on other hosts are the job's fault, not theirs."""
    nodes = certified_fleet(db, ("n1", "n2", "n3"))
    for i in range(4):
        study(db, [SCENES[i]])
    jobs = sorted({r["job_id"] for r in db.q("SELECT job_id FROM jobs WHERE kind='eval'")})
    for jid in jobs:
        g = claim(db, nodes[0], jid)
        if g:
            core.fail(db, fresh(db, nodes[0]), g[0]["attempt_id"], {"reason": "exit_nonzero"})
            clock.advance(3600)
    before = fresh(db, nodes[1])["breaker_failures"]
    for jid in jobs:
        g = claim(db, nodes[1], jid)
        if g:
            core.fail(db, fresh(db, nodes[1]), g[0]["attempt_id"], {"reason": "exit_nonzero"})
    assert fresh(db, nodes[1])["breaker_failures"] == before
    assert "relay" in core.certified_modules(fresh(db, nodes[1])), "healthy node must stay certified"
    assert ok(db)


def test_stuck_certifying_raises_an_alert_and_certify_resolves_it(db):
    from helpers import DOCTOR_OK
    _, node = enrolled_node(db, "sleepy")
    core.hello(db, node, {"release_id": release_id(db), "facts": {}, "live_attempts": [], "ready_datasets": READY})
    core.heartbeat(db, fresh(db, node), {"capacity": CAPACITY, "doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY})
    clock.advance(core.CERTIFYING_GRACE_S + 60)
    core.reap(db)
    assert db.one("SELECT 1 FROM alerts WHERE rule='certifying_stuck:relay' AND state='open'")
    for g in claim(db, node):
        core.complete(db, fresh(db, node), g["attempt_id"], golden_result(g))
    assert not db.one("SELECT 1 FROM alerts WHERE rule='certifying_stuck:relay' AND state='open'")
    assert ok(db)


def test_yielding_node_is_not_reported_stuck_and_verify_reports_health(db):
    from helpers import DOCTOR_OK
    _, node = enrolled_node(db, "busy")
    core.hello(db, node, {"release_id": release_id(db), "facts": {}, "live_attempts": [], "ready_datasets": READY})
    core.heartbeat(db, fresh(db, node), {"capacity": CAPACITY, "doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY,
                                         "capacity": {"admit": False, "binding_limit": "yield"}})
    db.x("UPDATE nodes SET capacity_json=? WHERE node_id=?", ('{"admit": false, "binding_limit": "yield"}', node["node_id"]))
    clock.advance(core.CERTIFYING_GRACE_S + 60)
    core.reap(db)
    assert not db.one("SELECT 1 FROM alerts WHERE rule LIKE 'certifying_stuck:%' AND state='open'")
    r = invariants.report(db, clock.now())
    assert r["ok"] and any(w.startswith("info: node busy not admitting") for w in r["warnings"])


def test_breaker_alert_resolves_when_the_node_recertifies(db):
    nodes = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:3])
    for _ in range(3):
        g = claim(db, nodes[0], free=1)
        if g:
            core.fail(db, fresh(db, nodes[0]), g[0]["attempt_id"], {"reason": "exit_nonzero"})
    assert db.one("SELECT 1 FROM alerts WHERE rule='breaker' AND state='pending'")      # a 15 min pending period
    from helpers import DOCTOR_OK
    core.heartbeat(db, fresh(db, nodes[0]), {"capacity": CAPACITY, "doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY})
    for g in [x for x in claim(db, nodes[0]) if x["kind"] == "golden"]:
        core.complete(db, fresh(db, nodes[0]), g["attempt_id"], golden_result(g, db))
    assert not db.one("SELECT 1 FROM alerts WHERE rule='breaker' AND state IN ('open','pending')") and ok(db)
    assert db.one("SELECT resolved_how FROM alerts WHERE rule='breaker'")["resolved_how"] == "cleared while pending"


# ---------------------------------------------------------------- stages[].retry (D33)
def _fail(db, node, job_id, **body):
    g = claim(db, node, job_id)[0]
    core.fail(db, fresh(db, node), g["attempt_id"], {"reason": "exit_nonzero", **body})
    clock.advance(700)                                       # past the backoff
    return db.one("SELECT * FROM jobs WHERE job_id=?", (job_id,))


def _retries_left(db, job_id, node):
    from oarbank.coordinator import explain
    doc = explain.job_doc(db, job_id, bodies={node["node_id"]: {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY}})
    row = next(r for r in doc.matrix if r.node == node["hostname"])
    return next(r.observed for r in row.results if r.predicate == "retries left (stage retry)")


def test_a_stages_retry_quarantines_a_job_once_every_platform_spent_it(db, monkeypatch):
    """stages[].retry.max_attempts (its per-platform variant for the node) is how often a job may fail: on darwin twice
    here, three times (the stage's own) on Linux. Explain shows the retries left per node."""
    from helpers import facts_for
    _relay_with(monkeypatch, stage_variants={"darwin": {"retry": {"max_attempts": 2}}})
    mini = certify(db, enrolled_node(db, "mini")[1])
    study(db, SCENES[:1])
    jid = db.one("SELECT job_id FROM jobs WHERE module='relay' AND kind='eval' ORDER BY job_id LIMIT 1")["job_id"]
    assert _retries_left(db, jid, mini) == 2
    j = _fail(db, mini, jid)
    assert (j["state"], j["exec_failures"]) == ("pending", 1) and _retries_left(db, jid, mini) == 1
    box = certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1])
    j = _fail(db, box, jid)                     # darwin's two attempts are spent; the Linux node still has one left
    assert (j["state"], j["exec_failures"]) == ("pending", 2) and _retries_left(db, jid, box) == 1
    assert not claim(db, mini, jid)
    from oarbank.coordinator import explain
    doc = explain.job_doc(db, jid, bodies={n["node_id"]: {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY} for n in (mini, box)},
                          now=clock.now())
    assert {s.code: s.nodes for s in doc.summary}.get("RETRIES_EXHAUSTED") == ["mini"], doc.summary
    j = _fail(db, box, jid)
    assert (j["state"], j["exec_failures"]) == ("quarantined", 3)
    assert ok(db)


def test_a_single_node_quarantines_after_the_stages_attempts(db, monkeypatch):
    _relay_with(monkeypatch, stage_variants={"darwin-arm64": {"retry": {"max_attempts": 1}}})
    mini = certify(db, enrolled_node(db, "mini")[1])
    study(db, SCENES[:1])
    jid = db.one("SELECT job_id FROM jobs WHERE module='relay' AND kind='eval' ORDER BY job_id LIMIT 1")["job_id"]
    assert _fail(db, mini, jid, fault="job")["state"] == "quarantined"
    assert ok(db)


def test_transient_and_host_faults_never_spend_a_jobs_retries(db, monkeypatch):
    """fault = transient is no failure at all; a host fault (a missing dependency) sends the node back to its doctor and
    the job elsewhere, without spending the job's retries; a job fault spends one."""
    _relay_with(monkeypatch, stage_variants={"darwin": {"retry": {"max_attempts": 1}}})
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db, SCENES[:1])
    jid = db.one("SELECT job_id FROM jobs WHERE module='relay' AND kind='eval' ORDER BY job_id LIMIT 1")["job_id"]
    j = _fail(db, n1, jid, fault="transient")
    assert (j["state"], j["exec_failures"]) == ("pending", 0)
    j = _fail(db, n1, jid, fault="host", reason="doctor")
    assert (j["state"], j["exec_failures"]) == ("pending", 0)
    assert db.one("SELECT want_doctor FROM nodes WHERE node_id=?", (n1["node_id"],))["want_doctor"] == 1
    assert _fail(db, n2, jid, fault="job")["state"] == "quarantined"
    assert ok(db)
