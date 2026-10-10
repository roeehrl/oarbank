"""Portable checkpoints on the coordinator (docs/design/datasets-media-checkpoints.md, #15): a live attempt records its
job's latest checkpoint (replacing and releasing the previous one); the job's next attempt, on any node, resumes from it
(the envelope's `resume`, the grant's files); a checkpoint lives for one generation of an open job; a result resumed
from another node's checkpoint is always replicated on a third node; a conviction reaches through checkpoints; S23."""
import hashlib
import json
import sys
from pathlib import Path

import pytest

from oarbank.coordinator import checkpoints, clock, core, explain, invariants, modcalls, releases
from oarbank.coordinator import config as C

from helpers import FACTS, agent_client, enrolled_node, fresh, install, make_db, node_headers, run_op

REEL_DIR = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "reel"
sys.path.insert(0, str(REEL_DIR))
import reel_frames as F  # noqa: E402
from helpers import set_fleet

DOCTOR = {"modules": {"reel": {"health": "healthy", "checks": []}}}


@pytest.fixture
def db(tmp_path):
    clock.set_fake(None)
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    install(d, REEL_DIR)
    modcalls.use(d)
    releases.sync(d)
    set_fleet(d, "replica_rate", 0.0)
    yield d
    d.conn.close()


def blob(db, body: bytes) -> dict:
    d = hashlib.sha256(body).hexdigest()
    db.x("INSERT OR IGNORE INTO blobs(digest,path,size) VALUES(?,?,?)", (d, "/dev/null", len(body)))
    return {"digest": d, "size": len(body)}


def reel_result(db, payload: dict, resumed_at: int = 0) -> dict:
    n, seed = payload["frames"], payload.get("seed", 0)
    frames = [{"path": F.frame_name(i), **blob(db, F.png(F.pixels(seed, i)))} for i in range(n)]
    return {"result": {"envelope": 1, "schema": "reel/result@1", "module_version": "0.1.0", "protocol": 1,
                       "effective": {"frames": n, "resumed_at": resumed_at},
                       "artifacts": [{"name": "frames", "files": frames}],
                       "payload": {"frames": n, "digest": F.expected(seed, n)}}}


def certified(db, name):
    return certify(db, enrolled_node(db, name)[1])


def certify(db, node):
    core.hello(db, node, {"release_id": releases.assigned(db, fresh(db, node)), "facts": FACTS, "live_attempts": [], "ready_datasets": []})
    core.heartbeat(db, fresh(db, node), {"doctor": DOCTOR, "attempts": [], "ready_datasets": [], "capacity": {}})
    for g in core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32})["grants"]:
        assert core.complete(db, fresh(db, node), g["attempt_id"], reel_result(db, g["spec"]["payload"]))["canonical"]
    assert core.node_modules(fresh(db, node))["reel"]["state"] == "certified"
    return fresh(db, node)


def queue(db, frames=40):
    r = run_op(db, "mod.reel.queue_render", params={"renders": [{"frames": frames, "seed": 3, "step_ms": 10}]})
    return db.one("SELECT * FROM jobs WHERE campaign_id=? ", (r["result"]["result"]["campaign_id"],))


def claim(db, node):
    (g,) = core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32})["grants"]
    return g


def ckpt(db, n=8):
    return [{"name": "state.json", **blob(db, json.dumps({"next": n}).encode())},
            {"name": f"frames/{F.frame_name(0)}", **blob(db, F.png(F.pixels(3, 0)))}]


def ok(db):
    v = invariants.check_all(db)
    assert not v, v
    return True


def test_a_released_job_resumes_on_another_node_from_its_checkpoint(db):
    a, b = certified(db, "a"), certified(db, "b")
    j = queue(db)
    g = claim(db, a)
    assert "resume" not in g["spec"] and "checkpoint" not in g
    r = checkpoints.record(db, a, g["attempt_id"], {"seq": 1, "files": ckpt(db, 8), "data": {"next": 8}})
    assert r["recorded"] and db.one("SELECT 1 FROM events WHERE kind='checkpoint_recorded'")
    core.release(db, fresh(db, a), g["attempt_id"], "preempt_protection")       # paused past its limit
    core.set_node_state(db, a["node_id"], "paused", "test")
    g2 = claim(db, b)
    want = sorted(ckpt(db, 8), key=lambda f: f["name"])
    assert g2["checkpoint"] == {"files": want}
    from oarbank_sdk.runner_protocol import checkpoint_digest
    assert g2["spec"]["resume"] == {"from_attempt": g["attempt_id"], "digest": checkpoint_digest(want), "data": {"next": 8}}
    att = db.one("SELECT resume_json FROM attempts WHERE attempt_id=?", (g2["attempt_id"],))
    assert json.loads(att["resume_json"]) == {"from_attempt": g["attempt_id"], "node_id": a["node_id"], "digest": checkpoint_digest(want)}
    assert ok(db)
    doc = explain.job_doc(db, j["job_id"])
    assert any("resumed from attempt" in s for s in doc.system_actions)
    # it finishes there with the uninterrupted result: done, its checkpoint dropped, and a replica on a third node
    c = certified(db, "c")
    res = core.complete(db, fresh(db, b), g2["attempt_id"], reel_result(db, g2["spec"]["payload"], resumed_at=8))
    assert res["canonical"]
    assert not db.one("SELECT 1 FROM checkpoints WHERE job_id=?", (j["job_id"],))
    rep = db.one("SELECT * FROM jobs WHERE kind='replica'")
    assert rep and set(json.loads(rep["dispute_json"])["nodes"]) == {a["node_id"], b["node_id"]}
    assert c and ok(db)


def test_a_newer_checkpoint_replaces_the_older_and_releases_its_blobs(db, tmp_path):
    a = certified(db, "a")
    queue(db)
    g = claim(db, a)
    old = tmp_path / "old.bin"
    old.write_bytes(b"old state")
    od = hashlib.sha256(b"old state").hexdigest()
    db.x("INSERT INTO blobs(digest,path,size) VALUES(?,?,?)", (od, str(old), 9))
    checkpoints.record(db, a, g["attempt_id"], {"seq": 1, "files": [{"name": "state.bin", "digest": od, "size": 9}]})
    assert not checkpoints.record(db, a, g["attempt_id"], {"seq": 1, "files": ckpt(db)})["recorded"]    # not newer
    checkpoints.record(db, a, g["attempt_id"], {"seq": 2, "files": ckpt(db)})
    assert not old.exists() and not db.one("SELECT 1 FROM blobs WHERE digest=?", (od,))
    assert db.one("SELECT seq FROM checkpoints")["seq"] == 2


def test_a_golden_keeps_no_checkpoint(db):
    _, node = enrolled_node(db, "g")
    core.hello(db, node, {"release_id": releases.assigned(db, fresh(db, node)), "facts": FACTS, "live_attempts": [], "ready_datasets": []})
    core.heartbeat(db, fresh(db, node), {"doctor": DOCTOR, "attempts": [], "ready_datasets": [], "capacity": {}})
    (g,) = core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32})["grants"]
    assert g["kind"] == "golden"
    with pytest.raises(checkpoints.CheckpointError) as e:
        checkpoints.record(db, node, g["attempt_id"], {"seq": 1, "files": ckpt(db)})
    assert e.value.code == "no_checkpoints" and "golden" in e.value.detail


def test_checkpoints_are_refused_for_closed_attempts_oversized_files_unheld_blobs_and_stages_that_keep_none(db):
    a = certified(db, "a")
    queue(db)
    g = claim(db, a)
    big = [{"name": "huge.bin", **blob(db, b"x")}]
    db.x("UPDATE blobs SET size=? WHERE digest=?", (65 * 1024 * 1024, big[0]["digest"]))
    big[0]["size"] = 65 * 1024 * 1024
    for body, code in [({"seq": 1, "files": big}, "checkpoint_too_large"),
                       ({"seq": 1, "files": [{"name": "s", "digest": "ab" * 32, "size": 1}]}, "artifact_missing"),
                       ({"seq": 1, "files": []}, "bad_checkpoint"),
                       ({"seq": 1, "files": [{"name": "../x", **blob(db, b"y")}]}, "bad_checkpoint"),
                       ({"seq": 1, "files": ckpt(db), "data": {"x": "y" * 5000}}, "bad_checkpoint")]:
        with pytest.raises(checkpoints.CheckpointError) as e:
            checkpoints.record(db, a, g["attempt_id"], body)
        assert e.value.code == code
    _, other = enrolled_node(db, "other")
    with pytest.raises(checkpoints.CheckpointError) as e:
        checkpoints.record(db, other, g["attempt_id"], {"seq": 1, "files": ckpt(db)})
    assert e.value.code == "lease_lost"
    core.release(db, fresh(db, a), g["attempt_id"], "user_cancel")
    with pytest.raises(checkpoints.CheckpointError) as e:
        checkpoints.record(db, a, g["attempt_id"], {"seq": 1, "files": ckpt(db)})
    assert e.value.code == "attempt_closed"


def test_a_checkpoint_lives_for_one_generation_of_an_open_job(db):
    a, b = certified(db, "a"), certified(db, "b")
    j = queue(db)
    g = claim(db, a)
    checkpoints.record(db, a, g["attempt_id"], {"seq": 1, "files": ckpt(db)})
    core.release(db, fresh(db, a), g["attempt_id"], "preempt_protection")
    db.x("UPDATE jobs SET generation=generation+1 WHERE job_id=?", (j["job_id"],))     # a dispute, a conviction
    assert checkpoints.for_job(db, db.one("SELECT * FROM jobs WHERE job_id=?", (j["job_id"],))) is None
    core.reap(db)
    assert not db.one("SELECT 1 FROM checkpoints") and db.one("SELECT 1 FROM events WHERE kind='checkpoint_dropped'")
    g2 = claim(db, b)
    assert "resume" not in g2["spec"]


def test_a_conviction_reaches_the_results_resumed_from_the_convicts_checkpoints(db):
    a, b = certified(db, "a"), certified(db, "b")
    j = queue(db)
    g = claim(db, a)
    checkpoints.record(db, a, g["attempt_id"], {"seq": 1, "files": ckpt(db)})
    core.release(db, fresh(db, a), g["attempt_id"], "preempt_protection")
    core.set_node_state(db, a["node_id"], "paused", "test")
    g2 = claim(db, b)
    core.complete(db, fresh(db, b), g2["attempt_id"], reel_result(db, g2["spec"]["payload"]))
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (j["job_id"],))["state"] == "done"
    core.invalidate_node_results(db, a["node_id"], "convicted")
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (j["job_id"],))["state"] == "pending"
    assert ok(db)


def test_s23_catches_an_attempt_resuming_from_another_jobs_checkpoint(db):
    a = certified(db, "a")
    j1, j2 = queue(db), queue(db, frames=41)
    g1, g2 = core.claim(db, fresh(db, a), {"free_cpu": 8, "free_mem_gb": 32})["grants"]
    db.x("UPDATE attempts SET resume_json=? WHERE attempt_id=?",
         (json.dumps({"from_attempt": g1["attempt_id"], "node_id": a["node_id"], "digest": "ab" * 32}), g2["attempt_id"]))
    v = invariants.s23_resume_from_own_checkpoint(db)
    assert v and "S23" in v[0] and j1 and j2


def test_the_lease_holds_while_the_agent_uploads_a_checkpoint(db):
    a = certified(db, "a")
    queue(db)
    g = claim(db, a)
    db.x("UPDATE attempts SET expires_at=?, cpu_s=10 WHERE attempt_id=?", (clock.now() + 5, g["attempt_id"]))
    core.heartbeat(db, fresh(db, a), {"attempts": [{"attempt_id": g["attempt_id"], "phase": "checkpointing", "cpu_s": 10}],
                                      "ready_datasets": []})
    assert db.one("SELECT expires_at FROM attempts WHERE attempt_id=?", (g["attempt_id"],))["expires_at"] > clock.now() + C.LEASE_TTL - 5


def test_the_agent_records_a_checkpoint_over_http(db):
    der, node = enrolled_node(db, "h")
    node = certify(db, node)
    other, _ = enrolled_node(db, "o")
    queue(db)
    g = claim(db, node)
    agent = agent_client(db)
    r = agent.post(f"/v1/attempts/{g['attempt_id']}/checkpoint", headers=node_headers(der),
                   json={"seq": 1, "files": ckpt(db), "data": {"next": 8}})
    assert r.status_code == 200 and r.json()["recorded"]
    r = agent.post(f"/v1/attempts/{g['attempt_id']}/checkpoint", headers=node_headers(other), json={"seq": 2, "files": ckpt(db)})
    assert r.status_code == 404 and r.json()["error"] == "lease_lost"
