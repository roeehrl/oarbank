"""Dataset registry (generic): a dataset is a list of content-addressed files {path, digest, size, origins}.

Agents download origin-first and fall back to oarbankd's blob server, which serves the coordinator's local
copy by digest. What a dataset contains and where it comes from is its module's business: module importers
(module CLIs, run on the coordinator) hash their files and call the `datasets.register` operation.
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
    """Upsert a dataset. Files that carry `local_path` (a file on the coordinator) register their blob; the
    file must exist with the stated size (digests are the importer's, and agents verify them on download).
    Every other file's blob must already be known. Raises ValueError for bad input."""
    did, kind = p.get("dataset_id") or "", p.get("kind") or ""
    if not DATASET_ID.match(did):
        raise ValueError(f"bad dataset id {did!r}")
    if not kind or not re.match(r"^[a-z][a-z0-9_-]{0,40}$", kind):
        raise ValueError(f"bad kind {kind!r}")
    files, blobs = [], []
    for i, f in enumerate(p.get("files") or []):
        dig, size, path = f.get("digest") or "", f.get("size"), f.get("path") or ""
        if not DIGEST.match(dig) or not path or ".." in Path(path).parts or path.startswith("/"):
            raise ValueError(f"files[{i}]: needs a relative path and a sha256 digest")
        if f.get("local_path"):
            lp = Path(f["local_path"])
            if not lp.is_file() or (size is not None and lp.stat().st_size != int(size)):
                raise ValueError(f"files[{i}]: {lp} missing or not {size} bytes")
            blobs.append((dig, str(lp), lp.stat().st_size))
        elif not db.one("SELECT 1 FROM blobs WHERE digest=?", (dig,)):
            raise ValueError(f"files[{i}]: unknown blob {dig} (send local_path)")
        files.append({"path": path, "digest": dig, "size": size, "origins": list(f.get("origins") or [])})
    with db.tx():
        for b in blobs:
            register_blob(db, *b)
        db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?) "
             "ON CONFLICT(dataset_id) DO UPDATE SET kind=excluded.kind, module=excluded.module, "
             "meta_json=excluded.meta_json, files_json=excluded.files_json",
             (did, kind, p.get("module"), json.dumps(p.get("meta") or {}), json.dumps(files), clock.now()))
        db.event("dataset_imported", reason=did, n_files=len(files))
    return {"dataset_id": did, "files": len(files), "blobs": len(blobs)}


def manifest(db: DB, dataset_id: str) -> dict | None:
    d = db.one("SELECT * FROM datasets WHERE dataset_id=?", (dataset_id,))
    if not d:
        return None
    return {"dataset_id": dataset_id, "kind": d["kind"], "files": jl(d["files_json"], [])}


def list_by(db: DB, kind: str | None = None) -> list[dict]:
    rows = db.q("SELECT dataset_id, kind, module, meta_json FROM datasets" + (" WHERE kind=?" if kind else "")
                + " ORDER BY dataset_id", (kind,) if kind else ())
    return [{**r, "meta": jl(r.pop("meta_json"), {})} for r in rows]
