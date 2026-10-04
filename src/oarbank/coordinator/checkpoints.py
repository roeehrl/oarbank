"""Portable checkpoints (oarbank-sdk spec/runner-protocol.md, "Checkpoints"; docs/design/datasets-media-checkpoints.md).

A runner that declares `checkpoint`, on a stage with `checkpoint = {max_mb, min_interval_s}`, announces checkpoints;
the agent uploads their files as blobs and records them here (`POST /v1/attempts/{id}/checkpoint`). One row per job
holds its latest checkpoint, valid for the job's current generation while it is open (pending or leased). Claim hands it
to the job's next attempt on any node (the envelope's `resume`, the grant's `checkpoint`). A replaced or dropped
checkpoint's blobs are released (deleted when nothing else names them).

A resumed result depends on the node that wrote the checkpoint as much as on the one that finished, so: a result that
resumed from another node's checkpoint is always replicated when its stage compares (core.complete), and a node convicted
of nondeterminism takes its checkpoints and the results resumed from them down with it (invalidate).
"""
import json

from oarbank_sdk.origins import DIGEST
from oarbank_sdk.portable import check_portable_path
from oarbank_sdk.runner_protocol import CHECKPOINT_DATA_MAX, checkpoint_digest

from . import blobstore, clock, modcalls
from .db import DB, jl

MiB = 1 << 20


class CheckpointError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail = status, code, detail


def limits(module: str, stage: str | None, version: str | None):
    """The stage's checkpoint limits in the module version (None: it keeps no portable checkpoints)."""
    try:
        mi = modcalls.info_for(module, version)
    except KeyError:
        mi = modcalls.info(module)
    return mi.manifest.checkpoint_of(stage)


def record(db: DB, node: dict, attempt_id: int, body: dict) -> dict:
    """Record a checkpoint a live attempt of the node uploaded: `{seq, files: [{name, digest, size}], data}`. It replaces
    the job's checkpoint when it is newer (a later attempt, or a higher seq of the same one)."""
    files, seq, data = body.get("files") or [], body.get("seq"), body.get("data") or {}
    if not isinstance(seq, int) or seq < 0 or not isinstance(files, list) or not files or not isinstance(data, dict):
        raise CheckpointError(400, "bad_checkpoint", "send {seq, files: [{name, digest, size}], data}")
    if len(json.dumps(data, separators=(",", ":")).encode()) > CHECKPOINT_DATA_MAX:
        raise CheckpointError(400, "bad_checkpoint", f"data is over {CHECKPOINT_DATA_MAX} bytes")
    names = set()
    for f in files:
        try:
            check_portable_path(f.get("name"))
        except (ValueError, TypeError) as e:
            raise CheckpointError(400, "bad_checkpoint", f"name {f.get('name')!r}: {e}") from None
        if f["name"] in names or not DIGEST.match(str(f.get("digest") or "")) or not isinstance(f.get("size"), int):
            raise CheckpointError(400, "bad_checkpoint", f"{f['name']}: unique names, a sha256 digest and a size")
        names.add(f["name"])
    with db.tx():
        a = db.one("SELECT * FROM attempts WHERE attempt_id=?", (attempt_id,))
        if not a or a["node_id"] != node["node_id"]:
            raise CheckpointError(404, "lease_lost", str(attempt_id))
        j = db.one("SELECT * FROM jobs WHERE job_id=?", (a["job_id"],))
        if a["state"] != "live" or a["generation"] != j["generation"] or j["state"] not in ("pending", "leased"):
            raise CheckpointError(409, "attempt_closed", f"attempt {attempt_id} is {a['state']} (job {j['state']})")
        lim = limits(j["module"], j["stage"], a["module_version"])
        if j["kind"] == "golden":
            raise CheckpointError(422, "no_checkpoints", "a golden runs whole: certification never resumes one")
        if lim is None:
            raise CheckpointError(422, "no_checkpoints", f"stage {j['stage'] or 'default'} of {j['module']} keeps no checkpoints")
        total = 0
        for f in files:
            b = db.one("SELECT size FROM blobs WHERE digest=?", (f["digest"],))
            if not b or b["size"] != f["size"]:
                raise CheckpointError(422, "artifact_missing", f"{f['name']}: the coordinator holds no {f['digest'][:12]} of "
                                      f"{f['size']} bytes")
            total += f["size"]
        if total > lim.max_mb * MiB:
            raise CheckpointError(413, "checkpoint_too_large", f"{total} bytes > the stage's max_mb ({lim.max_mb})")
        cur = db.one("SELECT * FROM checkpoints WHERE job_id=?", (j["job_id"],))
        if cur and (cur["attempt_id"], cur["seq"]) >= (attempt_id, seq) and cur["generation"] == j["generation"]:
            return {"recorded": False, "digest": cur["digest"], "reason": "not newer than the job's checkpoint"}
        entries = sorted(({"name": f["name"], "digest": f["digest"], "size": f["size"]} for f in files), key=lambda f: f["name"])
        digest = checkpoint_digest(entries)
        db.x("INSERT INTO checkpoints(job_id,generation,attempt_id,node_id,seq,digest,files_json,data_json,size,at) "
             "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET generation=excluded.generation, "
             "attempt_id=excluded.attempt_id, node_id=excluded.node_id, seq=excluded.seq, digest=excluded.digest, "
             "files_json=excluded.files_json, data_json=excluded.data_json, size=excluded.size, at=excluded.at",
             (j["job_id"], j["generation"], attempt_id, node["node_id"], seq, digest, json.dumps(entries), json.dumps(data),
              total, clock.now()))
        if cur:
            blobstore.release(db, {f["digest"] for f in jl(cur["files_json"], [])} - {f["digest"] for f in entries})
    db.event("checkpoint_recorded", node_id=node["node_id"], attempt_id=attempt_id, job_id=j["job_id"],
             reason=f"{len(entries)} files, {total} bytes", digest=digest)
    return {"recorded": True, "digest": digest}


def for_job(db: DB, j: dict) -> dict | None:
    """The job's checkpoint a new attempt resumes from: one recorded under its current generation."""
    c = db.one("SELECT * FROM checkpoints WHERE job_id=?", (j["job_id"],))
    return c if c and c["generation"] == j["generation"] else None


def resume_of(c: dict) -> dict:
    """The spec envelope's `resume`."""
    return {"from_attempt": c["attempt_id"], "digest": c["digest"], "data": jl(c["data_json"], {}) or {}}


def drop(db: DB, job_ids, why: str) -> int:
    """Drop the checkpoints of these jobs and release their blobs."""
    n = 0
    for jid in sorted(set(job_ids)):
        c = db.one("SELECT * FROM checkpoints WHERE job_id=?", (jid,))
        if not c:
            continue
        db.x("DELETE FROM checkpoints WHERE job_id=?", (jid,))
        blobstore.release(db, {f["digest"] for f in jl(c["files_json"], [])})
        db.event("checkpoint_dropped", job_id=jid, attempt_id=c["attempt_id"], reason=why)
        n += 1
    return n


def reap(db: DB) -> int:
    """Checkpoints of jobs that are no longer open, or of an older generation (a dispute, a conviction, a demoted head),
    are of no use to any attempt: drop them."""
    stale = db.q("SELECT c.job_id FROM checkpoints c LEFT JOIN jobs j ON j.job_id=c.job_id "
                 "WHERE j.job_id IS NULL OR j.state NOT IN ('pending','leased') OR j.generation != c.generation")
    return drop(db, [r["job_id"] for r in stale], "the job settled or its generation moved on")


def invalidate(db: DB, node_id: str) -> list[int]:
    """A node convicted of nondeterminism: drop the checkpoints it wrote, and return the done jobs whose canonical result
    resumed from one of its checkpoints (the caller recomputes them)."""
    drop(db, [r["job_id"] for r in db.q("SELECT job_id FROM checkpoints WHERE node_id=?", (node_id,))],
         f"node {node_id} was convicted of nondeterminism")
    rows = db.q("SELECT j.job_id FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id "
                "JOIN attempts a ON a.attempt_id=r.attempt_id WHERE j.state='done' AND a.resume_json IS NOT NULL "
                "AND json_extract(a.resume_json, '$.node_id')=?", (node_id,))
    return [r["job_id"] for r in rows]


def resumed_from_another_node(attempt: dict) -> str | None:
    """The node whose checkpoint the attempt resumed from, when that is another node."""
    r = jl(attempt.get("resume_json"))
    return r["node_id"] if r and r.get("node_id") != attempt["node_id"] else None
