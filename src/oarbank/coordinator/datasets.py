"""Dataset registry (generic): a dataset is a list of content-addressed files {path, digest, size, origins}.

Agents download origin-first and fall back to oarbankd's blob server, which serves the coordinator's copy by digest,
or fetches it from the origins once when it has none (blobstore.origin_stream). What a dataset contains and where it
comes from is its module's business: `oarbank dataset upload` (and the console) upload a folder's files and call the
`datasets.register` operation, and a module's importer operation derives its own datasets from them.
"""
import json
import re
from pathlib import Path

from . import clock
from .db import DB, jl

DATASET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")


def register_blob(db: DB, digest: str, path: str, size: int):
    path = db.rel(path) if path and path != "/dev/null" else path
    db.x("INSERT OR IGNORE INTO blobs(digest,path,size) VALUES(?,?,?)", (digest, path, size))
    db.x("UPDATE blobs SET path=?, size=? WHERE digest=?", (path, size, digest))


def register(db: DB, p: dict) -> dict:
    """Upsert a dataset. Every file names its digest and size; files that carry `local_path` (a file on the coordinator)
    register their blob (the file must exist with the stated size; agents verify digests on download); files with
    `origins` may name a blob the coordinator does not hold (the URL rule and the operator's origin host policy apply);
    every other file's blob must be held at that size. With `module`, the dataset is that module's (its kind one of the
    module's `[datasets].kinds`); without, the operator's, which every module sees. Raises ValueError for bad input."""
    from oarbank_sdk.origins import file_problem
    from . import blobstore, modcalls
    did, kind, module = p.get("dataset_id") or "", p.get("kind") or "", p.get("module") or None
    if not DATASET_ID.match(did):
        raise ValueError(f"bad dataset id {did!r}")
    if not kind or not re.match(r"^[a-z][a-z0-9_-]{0,40}$", kind):
        raise ValueError(f"bad kind {kind!r}")
    if module:
        try:
            kinds = modcalls.info(module).manifest.datasets.kinds
        except KeyError:
            raise ValueError(f"module {module!r} is not installed") from None
        if kind not in kinds:
            raise ValueError(f"kind {kind!r} is not one of {module}'s [datasets].kinds {kinds}")
    files, blobs = [], []
    for i, f in enumerate(p.get("files") or []):
        f = {k: v for k, v in f.items() if k != "local_path" or v} if isinstance(f, dict) else f
        why = file_problem({k: v for k, v in f.items() if k != "local_path"}) if isinstance(f, dict) else "not an object"
        if why:
            raise ValueError(f"files[{i}]: {why}")
        dig, size = f["digest"], int(f["size"])
        if f.get("local_path"):
            lp = Path(f["local_path"])
            if not lp.is_file() or lp.stat().st_size != size:
                raise ValueError(f"files[{i}]: {lp} missing or not {size} bytes")
            blobs.append((dig, str(lp), size))
        else:
            h = db.one("SELECT size FROM blobs WHERE digest=?", (dig,))
            if h and h["size"] is not None and h["size"] != size:
                raise ValueError(f"files[{i}]: the coordinator holds {dig[:12]} at {h['size']} bytes, not {size}")
            if not h and not f.get("origins"):
                raise ValueError(f"files[{i}]: unknown blob {dig} (upload it, send local_path, or name origins)")
        files.append({"path": f["path"], "digest": dig, "size": size, "origins": list(f.get("origins") or [])})
    why = blobstore.check_origins(db, files)
    if why:
        raise ValueError(f"origin refused: {why}")
    with db.tx():
        for b in blobs:
            register_blob(db, *b)
        db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?) "
             "ON CONFLICT(dataset_id) DO UPDATE SET kind=excluded.kind, module=excluded.module, "
             "meta_json=excluded.meta_json, files_json=excluded.files_json",
             (did, kind, module, json.dumps(p.get("meta") or {}), json.dumps(files), clock.now()))
        db.event("dataset_imported", reason=did, n_files=len(files))
    return {"dataset_id": did, "files": len(files), "blobs": len(blobs), "module": module}


def manifest(db: DB, dataset_id: str) -> dict | None:
    """What an agent stages: the files with the origins the URL rule and the operator's current policy admit."""
    from . import blobstore
    d = db.one("SELECT * FROM datasets WHERE dataset_id=?", (dataset_id,))
    if not d:
        return None
    return {"dataset_id": dataset_id, "kind": d["kind"], "files": blobstore.served_files(db, jl(d["files_json"], []))}


def detail(db: DB, dataset_id: str) -> dict | None:
    """A dataset for people (the admin API, `oarbank dataset download`): its kind, owner, meta, platform and files,
    each with whether the coordinator holds its blob."""
    from . import blobstore
    d = db.one("SELECT * FROM datasets WHERE dataset_id=?", (dataset_id,))
    if not d:
        return None
    files = [{**f, "held": blobstore.path(db, f.get("digest") or "") is not None} for f in jl(d["files_json"], [])]
    return {"dataset_id": dataset_id, "kind": d["kind"], "module": d["module"], "meta": jl(d["meta_json"], {}),
            "platform": d["platform"], "created_at": d["created_at"], "files": files,
            "size": sum(int(f.get("size") or 0) for f in files)}


def list_by(db: DB, kind: str | None = None) -> list[dict]:
    rows = db.q("SELECT dataset_id, kind, module, meta_json FROM datasets" + (" WHERE kind=?" if kind else "")
                + " ORDER BY dataset_id", (kind,) if kind else ())
    return [{**r, "meta": jl(r.pop("meta_json"), {})} for r in rows]
