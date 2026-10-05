"""Coordinator builds: what an enrolled node's agent installs to become a standby coordinator for a move
(coordinator-move.md; the release-readiness critical "install_coordinator runs an unsigned bundle").

A coordinator build is an archive for one platform (`.tar.gz`) whose top-level `oarbank-coordinator.json` says
`{"format": 1, "version", "platform"}`, and optionally `exec` (the coordinator's argv, its first element a path inside
the archive; default `["bin/oarbankd"]`) and `console` (the console's argv, likewise). The installing agent appends
the standby arguments. It is registered without being unpacked or run. In signing mode (the
default) a move hands a node only a build signed by the owner key set for the node's platform: the statement names
the build's sha256, version and platform, with a rising seq. With signing off (developer mode) the running checkout
is bundled instead (coordbundle), and the directive says so.
"""
import hashlib
import json
import os
import re
import shutil
import tarfile
from pathlib import Path

from ..platform import files
from . import clock
from . import config as C
from .db import DB

MAX_SIZE = 1024 * 1024 * 1024
MANIFEST = "oarbank-coordinator.json"
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]{1,40})?$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS coordinator_builds (
  sha256 TEXT PRIMARY KEY, version TEXT NOT NULL, platform TEXT NOT NULL, path TEXT NOT NULL, size INT,
  uploaded_at REAL, uploaded_by TEXT, seq INT, statement TEXT, signature TEXT);
"""


class BuildError(Exception):
    pass


def _dir(*parts) -> Path:
    d = C.HOME.joinpath("coordinator-builds", *parts)
    d.mkdir(parents=True, exist_ok=True)
    return d


def stage(data: bytes) -> dict:
    if not data or len(data) > MAX_SIZE:
        raise BuildError(f"send the coordinator build archive (at most {MAX_SIZE // 2**20} MB)")
    sha = hashlib.sha256(data).hexdigest()
    tmp = _dir("incoming") / f".{sha}.tmp"
    tmp.write_bytes(data)
    tmp.replace(_dir("incoming") / sha)
    return {"sha256": sha, "size": len(data)}


def inspect(path: Path) -> dict:
    """Read only the archive's manifest member; nothing is unpacked or run."""
    from oarbank_sdk import portable
    try:
        with tarfile.open(path, "r:gz") as t:
            m = t.getmember(MANIFEST)
            if not m.isfile() or m.size > 64 * 1024:
                raise BuildError(f"{MANIFEST} is not a small regular file")
            doc = json.loads(t.extractfile(m).read())
    except (tarfile.TarError, KeyError, OSError, ValueError, EOFError) as e:
        raise BuildError(f"not a coordinator build (a .tar.gz with {MANIFEST} at the top): {e}")
    if doc.get("format") != 1 or not VERSION_RE.fullmatch(str(doc.get("version") or "")) \
            or not portable.is_platform_token(str(doc.get("platform") or "")):
        raise BuildError(f"{MANIFEST} needs format 1, a semver version and a platform token")
    for k in ("exec", "console"):
        v = doc.get(k)
        if v is not None and not (isinstance(v, list) and v and all(isinstance(x, str) and x for x in v)
                                  and not v[0].startswith("/") and ".." not in Path(v[0]).parts):
            raise BuildError(f"{MANIFEST}: {k} must be an argv whose first element is a relative path inside the archive")
    return {"version": doc["version"], "platform": doc["platform"], "size": path.stat().st_size}


def register(db: DB, sha: str, actor: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
        raise BuildError("params.sha256: the uploaded archive's sha256 (POST /api/v1/coordinator/builds)")
    src = C.HOME / "coordinator-builds" / "incoming" / sha
    if not src.exists():
        raise BuildError(f"no uploaded archive {sha[:12]}")
    if hashlib.sha256(src.read_bytes()).hexdigest() != sha:
        raise BuildError("staged bytes do not match their sha256")
    info = inspect(src)
    if record(db, sha):
        return {**record(db, sha), "already": True}
    dst = _dir("builds") / f"{sha}.tar.gz"
    shutil.copyfile(src, dst.with_suffix(".tmp"))
    files.seal(dst.with_suffix(".tmp"))
    os.replace(dst.with_suffix(".tmp"), dst)
    src.unlink(missing_ok=True)
    db.x("INSERT INTO coordinator_builds(sha256, version, platform, path, size, uploaded_at, uploaded_by) VALUES(?,?,?,?,?,?,?)",
         (sha, info["version"], info["platform"], db.rel(dst), info["size"], clock.now(), actor))
    db.event("coordinator_build_uploaded", actor=actor, reason=f"{info['version']} {info['platform']} {sha[:12]}")
    return record(db, sha)


def record(db: DB, sha: str | None) -> dict | None:
    r = db.one("SELECT * FROM coordinator_builds WHERE sha256=?", (sha,)) if sha else None
    return {**r, "path": str(db.abs(r["path"]))} if r else None


def builds(db: DB) -> list[dict]:
    return [{k: v for k, v in r.items() if k != "path"} for r in db.q("SELECT * FROM coordinator_builds ORDER BY uploaded_at DESC")]


def for_platform(db: DB, platform: str) -> dict | None:
    """The newest signed build for a platform (the one a move installs in signing mode)."""
    r = db.one("SELECT sha256 FROM coordinator_builds WHERE platform=? AND signature IS NOT NULL ORDER BY seq DESC LIMIT 1",
               (platform,))
    return record(db, r["sha256"]) if r else None


def attach_signature(db: DB, sha: str, stmt: str, signature: str) -> dict:
    from .. import signing
    from . import owner
    from .releases import _verify_any
    pubs = owner.keys(db)
    if not pubs:
        raise BuildError("no owner key is pinned (oarbank release keygen, then releases.pin_key)")
    row = record(db, sha)
    if not row:
        raise BuildError(f"unknown coordinator build {sha[:12]}")
    try:
        s = _verify_any(signing.verify_coordinator, stmt, signature, pubs)
    except ValueError as e:
        raise BuildError(str(e))
    if s["coordinator_sha256"] != sha or s["version"] != row["version"] or s["platform"] != row["platform"]:
        raise BuildError("statement does not name this build's sha256, version and platform")
    top = db.one("SELECT MAX(seq) m FROM coordinator_builds WHERE signature IS NOT NULL AND sha256!=?", (sha,))["m"] or 0
    if int(s["seq"]) <= top:
        raise BuildError(f"seq {s['seq']} is not above the highest signed coordinator build seq {top}")
    db.x("UPDATE coordinator_builds SET seq=?, statement=?, signature=? WHERE sha256=?", (int(s["seq"]), stmt, signature, sha))
    db.event("coordinator_build_signed", reason=sha[:12], seq=int(s["seq"]))
    return {"sha256": sha, "seq": int(s["seq"])}


def directive_bundle(db: DB, platform: str | None) -> dict:
    """What install_coordinator carries for a node: a signed build for its platform (signing mode), or the running
    checkout (developer mode, signing off)."""
    if C.RELEASE_SIGNING:
        if not platform:
            raise BuildError("the target node has not reported its platform")
        b = for_platform(db, platform)
        if not b:
            raise BuildError(f"no signed coordinator build for {platform}: upload one (oarbank coordinator-build upload) "
                             "and sign it with the owner key")
        return {"kind": "build", "bundle_sha256": b["sha256"], "bundle_size": b["size"], "version": b["version"],
                "platform": platform, "bundle_url": f"/v1/move/bundle/{b['sha256']}",
                "statement": b["statement"], "signature": b["signature"]}
    from . import coordbundle
    try:
        return {"kind": "dev-checkout", **coordbundle.ensure(db)}
    except coordbundle.NotACheckout as e:
        raise BuildError(str(e))


def bundle_file(db: DB, sha: str) -> Path | None:
    r = record(db, sha)
    if r and Path(r["path"]).is_file():
        return Path(r["path"])
    from . import coordbundle
    return coordbundle.path(sha)
