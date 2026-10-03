"""Staged pipelines (render -> score): workers run the render stage anywhere and upload artifacts; the
score stage runs only on nodes that advertise the scoring pool (the coordinator's VM by default). The head stage's job
has the core's job kind 'call'; the tail keeps kind 'eval'."""
import hashlib
import json

import pytest

from oarbank.coordinator import clock, core, invariants

from helpers import (release_id, create_study, SCENES, MODE, PARAMS, READY, agent_client, certified_fleet,
                     enrolled_node, fresh, make_db, node_headers)


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


def roles(db, worker, scorer, tokens=2):
    db.x("UPDATE nodes SET policy_json=?, capacity_json=? WHERE node_id=?",
         (json.dumps({"disabled_services": ["relay/scorer"]}), json.dumps({"pools": {"scorer": 0}}), worker["node_id"]))
    db.x("UPDATE nodes SET policy_json=?, capacity_json=? WHERE node_id=?",
         (json.dumps({"disabled_services": []}), json.dumps({"pools": {"scorer": tokens}}), scorer["node_id"]))


def split_study(db, datasets=SCENES[:1], bq=25):
    db.set_setting("pipeline:relay", "split")
    return create_study(db, "s", [{"label": "c1", "params": {**PARAMS, "samples": bq}}],
                                list(datasets), {"label": "base", "params": PARAMS})


def claim(db, node, free=8, mem=64):
    return core.claim(db, fresh(db, node), {"free_cpu": free, "free_mem_gb": mem, "ready_datasets": READY})["grants"]


def score_claims(db, scorer, n=2):
    """The scorer can render too. Offer memory for exactly n score jobs (1 GB each; a render needs 1.5 GB, and
    score jobs sort ahead of renders/replicas), so the scorer takes scores only."""
    return [g for g in claim(db, scorer, mem=1.0 * n + (0.2 if n == 1 else 0.1)) if g["kind"] == "eval"]


def artifact(db, image="A"):
    """Pretend the agent uploaded the frame + its metadata (PUT /v1/artifacts) and return the render result."""
    files = []
    for name, body in (("frame.exr", f"frame-{image}"), ("frame.json", f"meta-{image}")):
        d = hashlib.sha256(body.encode()).hexdigest()
        db.x("INSERT OR IGNORE INTO blobs(digest,path,size) VALUES(?,?,?)", (d, "/dev/null", len(body)))
        files.append({"path": name, "digest": d, "size": len(body)})
    return {"result": {"envelope": 1, "schema": "relay/result@1", "module_version": "1.0.0", "effective": {"mode": MODE},
                       "provenance": {"argv": {"renderer": ["renderer", "--scene", "x"]}},
                       "payload": {"tiles": 1536, "image_sha256": image, "render_s": 12.0},
                       "artifacts": [{"name": "frame", "files": files}]}}


def score(image="A", s="0.850000"):
    return {"result": {"envelope": 1, "schema": "relay/result@1", "module_version": "1.0.0",
                       "payload": {"score": s, "image_sha256": image, "score_s": 4.0, "psnr": "38.5", "worst_tile": "0.8",
                                   "metrics": {"tiles_over_threshold": 3, "tiles_ok": 40}}}}


def run_renders(db, node, image="A"):
    gs = [g for g in claim(db, node) if g["kind"] == "call"]
    for g in gs:
        assert core.complete(db, fresh(db, node), g["attempt_id"], artifact(db, image))["canonical"]
    return gs


def test_split_off_keeps_single_stage_jobs_and_keys(db):
    certified_fleet(db, ("n1",))
    sid = create_study(db, "s", [{"label": "c1", "params": {**PARAMS, "samples": 25}}],
                               SCENES[:1], {"label": "base", "params": PARAMS})
    single = {r["job_key"] for r in db.q("SELECT job_key FROM jobs WHERE campaign_id=?", (sid,))}
    assert not db.q("SELECT 1 FROM jobs WHERE kind='call'")
    db.set_setting("pipeline:relay", "split")
    sid2 = create_study(db, "s2", [{"label": "c9", "params": {**PARAMS, "samples": 26}}],
                                SCENES[:1], {"label": "base", "params": PARAMS})
    evals = db.q("SELECT * FROM jobs WHERE campaign_id=? AND kind='eval'", (sid2,))
    assert {e["job_key"] for e in evals} & single, "the same (config, dataset) keeps its job key when split"
    new = evals[0]
    head = db.one("SELECT * FROM jobs WHERE job_id=?", (new["depends_on"],))
    assert new["stage"] == "score" and head["kind"] == "call" and head["stage"] == "render"
    assert head["job_key"] == new["job_key"] + ":render"
    assert ok(db)


def test_a_campaigns_jobs_are_its_evaluations_whatever_the_head_stage_is_named(db):
    """Module views and campaign.tick see one row per evaluation: the tail job, never the head job, whose stage
    name is the module's own (here `render`)."""
    from oarbank.coordinator import campaigns
    sid = split_study(db)
    rows = campaigns.campaign_jobs(db, sid)
    assert len(rows) == 2 and {(r["kind"], r["stage"]) for r in rows} == {("eval", "score")}
    assert ok(db)


def test_workers_render_scorers_score_and_the_result_merges(db):
    worker, scorer = certified_fleet(db, ("worker", "scorer"))
    roles(db, worker, scorer)
    sid = split_study(db)
    assert not score_claims(db, scorer, n=1), "score must wait for its render"
    renders = run_renders(db, worker)
    assert len(renders) == 2 and not [g for g in claim(db, worker) if g["kind"] == "eval"], "worker has no VM"
    assert ok(db)
    evals = score_claims(db, scorer)
    assert len(evals) == 2
    g = evals[0]
    assert g["spec"]["stage"] == "score" and g["spec"]["inputs"]["frame"]["dataset"].startswith("art:")
    art = g["spec"]["inputs"]["frame"]["dataset"]
    assert art in g["spec"]["datasets"] and g["spec"]["mounts"][art] == "frame"
    assert core.complete(db, fresh(db, scorer), g["attempt_id"], score())["canonical"]
    r = db.one("SELECT r.* FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id WHERE j.job_id=?", (g["job_id"],))
    res = json.loads(r["result_json"])
    # the canonical result has the same shape as a single-stage evaluation (search reads these)
    for k in ("score", "tiles", "image_sha256", "metrics", "render_s", "score_s"):
        assert k in res["payload"], k
    assert res["effective"] == {"mode": MODE} and res["artifacts"][0]["name"] == "frame"
    assert r["value"] == 0.85 and r["node_id"] == scorer["node_id"]
    assert ok(db)


def test_score_of_a_different_input_is_rejected(db):
    worker, scorer = certified_fleet(db, ("worker", "scorer"))
    roles(db, worker, scorer)
    split_study(db)
    run_renders(db, worker, image="A")
    g = score_claims(db, scorer)[0]
    r = core.complete(db, fresh(db, scorer), g["attempt_id"], score(image="B"))
    assert not r["canonical"] and r["reason"] == "input_mismatch" and ok(db)


def test_pool_tokens_cap_concurrent_scores(db):
    worker, scorer = certified_fleet(db, ("worker", "scorer"))
    roles(db, worker, scorer, tokens=1)
    split_study(db, SCENES[:3])
    run_renders(db, worker)
    assert len(score_claims(db, scorer)) == 1      # one token -> one score at a time
    assert ok(db)


def test_render_dispute_requeues_its_scored_dependents(db):
    db.set_setting("replica_rate", 1.0)
    w1, w2, w3 = certified_fleet(db, ("w1", "w2", "w3"))
    scorer = certified_fleet(db, ("scorer",))[0]
    for w in (w1, w2, w3):
        roles(db, w, scorer)
    sid = split_study(db)
    run_renders(db, w1, image="BAD")                       # w1 is wrong but first
    for g in score_claims(db, scorer):
        core.complete(db, fresh(db, scorer), g["attempt_id"], score(image="BAD", s="0.990000"))
    done = db.q("SELECT * FROM jobs WHERE campaign_id=? AND kind='eval' AND state='done'", (sid,))
    assert len(done) == 2
    # replicas of the renders run on another worker and disagree -> dispute -> the scores are withdrawn
    reps = [g for g in claim(db, w2) if g["kind"] == "replica"]
    assert reps and all(g["spec"].get("stage") == "render" for g in reps)
    for g in reps:
        core.complete(db, fresh(db, w2), g["attempt_id"], artifact(db, image="GOOD"))
    evals = db.q("SELECT * FROM jobs WHERE campaign_id=? AND kind='eval'", (sid,))
    assert all(e["state"] == "pending" and e["canonical_result_id"] is None for e in evals), [e["state"] for e in evals]
    assert ok(db)
    # the tie-break on w3 convicts w1; re-scoring uses the corrected frame
    for g in [x for x in claim(db, w3) if x["kind"] == "call"]:
        core.complete(db, fresh(db, w3), g["attempt_id"], artifact(db, image="GOOD"))
    assert fresh(db, w1)["lifecycle"] == "quarantined"
    for g in score_claims(db, scorer):
        assert g["spec"]["inputs"]["frame"]["dataset"].startswith("art:")
        assert core.complete(db, fresh(db, scorer), g["attempt_id"], score(image="GOOD"))["canonical"]
    assert all(e["state"] == "done" for e in db.q("SELECT state FROM jobs WHERE campaign_id=? AND kind='eval'", (sid,)))
    assert ok(db)


def test_cancelled_or_quarantined_render_settles_its_score(db):
    worker, scorer = certified_fleet(db, ("worker", "scorer"))
    roles(db, worker, scorer)
    split_study(db, SCENES[:2])
    renders = db.q("SELECT * FROM jobs WHERE kind='call' ORDER BY job_id")
    core.cancel_job(db, renders[0]["job_id"], "test")
    db.x("UPDATE jobs SET state='quarantined' WHERE job_id=?", (renders[1]["job_id"],))
    core.reap(db)
    states = {r["depends_on"]: r["state"] for r in db.q("SELECT depends_on, state FROM jobs WHERE kind='eval' AND depends_on IS NOT NULL")}
    assert states[renders[0]["job_id"]] == "cancelled" and states[renders[1]["job_id"]] == "quarantined"
    assert ok(db)


def test_retrying_a_render_reruns_its_scores(db):
    worker, scorer = certified_fleet(db, ("worker", "scorer"))
    roles(db, worker, scorer)
    sid = split_study(db)
    renders = run_renders(db, worker)
    for g in score_claims(db, scorer):
        core.complete(db, fresh(db, scorer), g["attempt_id"], score())
    core.retry_job(db, renders[0]["job_id"], "test")
    dep = db.one("SELECT * FROM jobs WHERE depends_on=?", (renders[0]["job_id"],))
    assert dep["state"] == "pending" and not [g for g in score_claims(db, scorer) if g["job_id"] == dep["job_id"]]
    assert ok(db)


def test_render_only_node_certifies_on_a_byte_identical_frame(db):
    db.set_setting("pipeline:relay", "split")
    st = db.get_setting("module_settings:relay")
    st["goldens"][0]["expected"]["image_sha256"] = "GOLDFRAME"
    db.set_setting("module_settings:relay", st)
    _, node = enrolled_node(db, "worker")
    db.x("UPDATE nodes SET policy_json=? WHERE node_id=?", (json.dumps({"disabled_services": ["relay/scorer"]}), node["node_id"]))
    from helpers import DOCTOR_OK, FACTS
    core.hello(db, fresh(db, node), {"release_id": release_id(db), "facts": FACTS, "live_attempts": [], "ready_datasets": READY})
    core.heartbeat(db, fresh(db, node), {"doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY})
    gs = claim(db, node)
    gm = [g for g in gs if g["module"] == "relay"][0]
    exp = json.loads(db.one("SELECT spec_json FROM jobs WHERE job_id=?", (gm["job_id"],))["spec_json"])["expected"]
    assert gm["spec"]["stage"] == "render" and exp == {"tiles": 1536, "image_sha256": "GOLDFRAME"}
    assert "expected" not in gm["spec"]["payload"]                                  # host-side: never shown to the runner
    bad = artifact(db, image="OTHER")
    core.complete(db, fresh(db, node), gm["attempt_id"], bad)
    assert core.node_modules(fresh(db, node))["relay"]["state"] == "revoked", "a different frame must not certify"
    assert ok(db)


def test_artifact_upload_endpoint(db, tmp_path, monkeypatch):
    from oarbank.coordinator import config as C
    monkeypatch.setattr(C, "HOME", tmp_path)
    der, node = enrolled_node(db, "w")
    agent = agent_client(db)
    h = node_headers(der)
    body = b"P3 64 64 255\n" * 100
    d = hashlib.sha256(body).hexdigest()
    assert agent.head(f"/v1/artifacts/{d}", headers=h).status_code == 404
    assert agent.put(f"/v1/artifacts/{'0' * 64}", content=body, headers=h).status_code == 400      # digest mismatch
    assert agent.put(f"/v1/artifacts/{d}", content=body, headers=h).json()["size"] == len(body)
    assert agent.head(f"/v1/artifacts/{d}", headers=h).status_code == 200
    assert agent.get(f"/v1/blobs/{d}", headers=h).content == body
    assert agent.put(f"/v1/artifacts/{d}", content=body, headers=h).json()["existing"]


def test_changing_a_nodes_vm_role_recertifies_it(db):
    db.set_setting("default_worker_disabled_services", ["relay/scorer"])
    (n,) = certified_fleet(db, ("n1",))
    assert set(core.certified_modules(fresh(db, n))) == {"relay", "toy"}
    assert core.node_disabled_services(fresh(db, n)) == ["relay/scorer"]   # a worker: not the coordinator's Mac
    core.set_policy(db, n["node_id"], {"disabled_services": []}, "test")
    assert not core.certified_modules(fresh(db, n)) and fresh(db, n)["want_doctor"] == 1
    core.set_policy(db, n["node_id"], {"nice": 5}, "test")          # unrelated change: no re-certification
    assert ok(db)


def test_vm_service_defaults_to_the_coordinators_own_mac(monkeypatch):
    import socket
    from oarbank.coordinator import config as C
    monkeypatch.setattr(socket, "gethostname", lambda: "coord.local")
    workers_off = ["relay/scorer"]
    assert C.policy_for({"hostname": "coord", "ram_gb": 64}, workers_off)["disabled_services"] == []
    assert C.policy_for({"hostname": "mini-a", "ram_gb": 24}, workers_off)["disabled_services"] == workers_off
    assert C.policy_for({"hostname": "mini-a", "ram_gb": 24})["protection"]["node"]["mode"] == "moderate"


def test_score_failure_on_the_only_scorer_does_not_strand_it(db):
    """Simulator finding: failure anti-affinity counted render-only workers as able to take a score job,
    so after one failure on the sole scorer the job was never claimed again."""
    worker, scorer = certified_fleet(db, ("worker", "scorer"))
    roles(db, worker, scorer)
    split_study(db)
    run_renders(db, worker)
    g = score_claims(db, scorer, n=1)[0]
    core.fail(db, fresh(db, scorer), g["attempt_id"], {"reason": "exit_nonzero"})
    clock.advance(3600)
    assert [x for x in score_claims(db, scorer) if x["job_id"] == g["job_id"]], "the sole scorer must retry it"
    assert ok(db)


def test_set_pipeline_splits_queued_jobs_and_render_only_nodes_get_render_goldens(db):
    (n1,) = certified_fleet(db, ("n1",))
    create_study(db, "s", [{"label": "c1", "params": {**PARAMS, "samples": 25}}],
                 SCENES[:2], {"label": "base", "params": PARAMS})
    out = core.set_pipeline(db, "relay", "split", "test")
    assert out["expanded"] == 4 and db.get_setting("pipeline:relay") == "split"
    from oarbank.coordinator import modcalls
    db.x("UPDATE nodes SET policy_json=? WHERE node_id=?", (json.dumps({"disabled_services": ["relay/scorer"]}), n1["node_id"]))
    g = modcalls.goldens(db, "relay", fresh(db, n1))[0]
    assert g["stage"] == "render" and g["expected"] == {"tiles": 1536, "image_sha256": "v1"} and g["key"].endswith(":render")
    assert modcalls.goldens(db, "relay", None)[0]["stage"] is None                     # every service on: the whole job
    assert len(db.q("SELECT 1 FROM jobs WHERE kind='call'")) == 4
    assert core.set_pipeline(db, "relay", "split", "test")["expanded"] == 0          # idempotent
    with pytest.raises(core.ApiError):
        core.set_pipeline(db, "toy", "split", "test")                                    # toy has no stage chain
    assert ok(db)


def test_render_only_node_gets_no_vm_tokens_even_if_it_reports_them(db):
    """e2e finding: a worker on a Mac where another agent runs Colima saw it up and advertised tokens."""
    worker, scorer = certified_fleet(db, ("worker", "scorer"))
    roles(db, worker, scorer)
    db.x("UPDATE nodes SET capacity_json=? WHERE node_id=?", (json.dumps({"pools": {"scorer": 4}}), worker["node_id"]))
    split_study(db)
    run_renders(db, worker)
    assert not [g for g in claim(db, worker) if g["kind"] == "eval"]
    assert score_claims(db, scorer)
    assert ok(db)
