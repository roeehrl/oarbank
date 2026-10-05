"""A module's own files on the coordinator (module protocol: `host.files.*` callbacks, `files.*` effects).

Each module has a private namespace of relative paths. A path names a content-addressed blob, so a file is
written once, never edited in place, and is verified by digest wherever it travels (a coordinator move copies
blobs and checks every hash). Module code never touches this storage: verbs read through callbacks and write by
returning effects, which the core applies on its single writer together with the audit row.

- `files.write {path, content_b64}`: a small file (at most 1 MiB), stored as a new blob;
- `files.put {path, digest}`: name a blob the coordinator already holds (a job artifact, a dataset file);
- `files.delete {path}` or `{prefix}`.

Blobs are never deleted by this module: other rows (datasets, results) may name the same digest.
"""
import base64
import hashlib
import os
import re
from pathlib import Path

from ..platform import files
from . import clock
from .db import DB

WRITE_MAX = 1 << 20
READ_MAX = 1 << 20
PATH = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")
PREFIX = re.compile(r"^([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]*$")


class FileError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def check_path(path) -> str:
    if not isinstance(path, str) or len(path) > 512 or not PATH.match(path) or any(s in (".", "..") for s in path.split("/")):
        raise FileError("bad_file_path", f"{path!r} (relative, plain segments, no . or ..)")
    return path


def check_prefix(prefix) -> str:
    if not isinstance(prefix, str) or len(prefix) > 512 or not PREFIX.match(prefix) or any(s in (".", "..") for s in prefix.split("/")):
        raise FileError("bad_file_prefix", repr(prefix))
    return prefix


def blob_dir(db: DB) -> Path:
    return Path(db.path).parent / "blobs"


def store_bytes(db: DB, data: bytes) -> str:
    """Write bytes as a content-addressed blob (idempotent) and register it; returns the digest."""
    from .datasets import register_blob
    digest = hashlib.sha256(data).hexdigest()
    row = db.one("SELECT path FROM blobs WHERE digest=?", (digest,))
    if row and row["path"] and db.abs(row["path"]).is_file():
        return digest
    d = blob_dir(db) / digest[:2]
    d.mkdir(parents=True, exist_ok=True)
    final = d / digest
    if not final.is_file():
        tmp = d / f".{digest}.{os.getpid()}.part"
        tmp.write_bytes(data)
        files.seal(tmp)
        os.replace(tmp, final)
    register_blob(db, digest, str(final), len(data))
    return digest


def bind(db: DB, module: str, path: str, digest: str, size: int):
    db.x("INSERT INTO module_files(module,path,digest,size,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(module,path) DO UPDATE "
         "SET digest=excluded.digest, size=excluded.size, updated_at=excluded.updated_at",
         (module, path, digest, size, clock.now()))


def write(db: DB, module: str, path: str, content_b64: str) -> dict:
    check_path(path)
    try:
        data = base64.b64decode(content_b64 or "", validate=True)
    except (ValueError, TypeError):
        raise FileError("bad_file_content", f"{path}: content_b64 is not base64")
    if len(data) > WRITE_MAX:
        raise FileError("file_too_large", f"{path}: {len(data)} bytes > {WRITE_MAX} (upload it as a job artifact, then files.put)")
    digest = store_bytes(db, data)
    bind(db, module, path, digest, len(data))
    return {"path": path, "digest": digest, "size": len(data)}


def visible_blob(db: DB, module: str, digest: str) -> bool:
    """A module reaches a blob only through its own files, its own datasets (artifacts of its jobs included) or a
    dataset the operator registered for every module (no module). Another module's blobs do not exist for it."""
    if not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
        return False
    if db.one("SELECT 1 FROM module_files WHERE module=? AND digest=? LIMIT 1", (module, digest)):
        return True
    return bool(db.one("SELECT 1 FROM datasets WHERE (module=? OR module IS NULL OR module='') AND instr(files_json, ?) > 0 "
                       "LIMIT 1", (module, digest)))


def put(db: DB, module: str, path: str, digest: str) -> dict:
    check_path(path)
    b = db.one("SELECT size FROM blobs WHERE digest=?", (digest,))
    if not b or not visible_blob(db, module, digest):
        raise FileError("unknown_blob", f"{path}: {digest}")
    bind(db, module, path, digest, b["size"])
    return {"path": path, "digest": digest, "size": b["size"]}


def delete(db: DB, module: str, path: str | None = None, prefix: str | None = None) -> dict:
    if (path is None) == (prefix is None):
        raise FileError("bad_file_delete", "exactly one of path or prefix")
    if path is not None:
        n = db.x("DELETE FROM module_files WHERE module=? AND path=?", (module, check_path(path)))
    else:
        check_prefix(prefix)
        n = db.x("DELETE FROM module_files WHERE module=? AND substr(path, 1, ?) = ?", (module, len(prefix), prefix))
    return {"deleted": n}


def _entry(r) -> dict:
    return {"path": r["path"], "digest": r["digest"], "size": r["size"], "updated_at": r["updated_at"]}


def listing(db: DB, module: str, prefix: str = "", limit: int = 1000) -> list[dict]:
    check_prefix(prefix)
    rows = db.q("SELECT path, digest, size, updated_at FROM module_files WHERE module=? AND substr(path, 1, ?) = ? "
                "ORDER BY path LIMIT ?", (module, len(prefix), prefix, min(int(limit), 10000)))
    return [_entry(r) for r in rows]


def stat(db: DB, module: str, path: str) -> dict | None:
    r = db.one("SELECT path, digest, size, updated_at FROM module_files WHERE module=? AND path=?", (module, check_path(path)))
    return _entry(r) if r else None


def read(db: DB, module: str, path: str, offset: int = 0, length: int = READ_MAX) -> dict:
    f = stat(db, module, path)
    if not f:
        raise FileError("no_such_file", path)
    b = db.one("SELECT path FROM blobs WHERE digest=?", (f["digest"],))
    if not b or not b["path"] or not db.abs(b["path"]).is_file():
        raise FileError("blob_missing", f"{path}: {f['digest']}")
    offset, length = max(0, int(offset)), max(1, min(int(length), READ_MAX))
    with open(db.abs(b["path"]), "rb") as fh:
        fh.seek(offset)
        chunk = fh.read(length)
    size = db.abs(b["path"]).stat().st_size
    return {"content_b64": base64.b64encode(chunk).decode(), "size": size, "digest": f["digest"], "eof": offset + len(chunk) >= size}


def core_checks(db: DB, module: str, deep: bool = False, skip: set | None = None) -> list[dict]:
    """The core's own checks of a module's files: every named blob is present with its size (deep: and its hash).
    `skip`: digests a coordinator move left behind by the module's rules (checked on the target's copy)."""
    missing, wrong = [], []
    skip = skip or set()
    rows = db.q("SELECT f.path, f.digest, f.size, b.path AS blob FROM module_files f LEFT JOIN blobs b ON b.digest=f.digest "
                "WHERE f.module=? ORDER BY f.path", (module,))
    for r in rows:
        if r["digest"] in skip:
            continue
        p = db.abs(r["blob"])
        if not p or not p.is_file():
            missing.append(r["path"])
        elif p.stat().st_size != (r["size"] or 0):
            wrong.append(r["path"])
        elif deep:
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            if h.hexdigest() != r["digest"]:
                wrong.append(r["path"])
    return [{"name": "core/files_present", "ok": not missing, "severity": "error",
             "detail": f"{len(rows)} files" + (f"; missing {missing[:5]}" if missing else "")},
            {"name": "core/files_match" + ("_digests" if deep else "_sizes"), "ok": not wrong, "severity": "error",
             "detail": ", ".join(wrong[:5])}]
