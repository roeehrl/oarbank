"""Coordinator self-update, oarbankd's side (docs/design/fleet-updates.md, "The coordinator"; D58).

oarbankd prepares, unprivileged: it checks the stored release's coordinator build for this machine (sha256, size, the
owner's signature in signing mode), refuses while a move is on or an enrolled node's agent is older than the release's
`agent_min` (unless the node is held), takes a snapshot (`VACUUM INTO updates/snapshots/<from>-<ts>.sqlite3` and an
integrity check), runs the new build's own `oarbankd --self-test` on a scratch copy of it, then records
`coordinator_updates {state: requested}` and writes the spool request `updates/coordinator-request.json`. The root
runner (`python -m oarbank.coordupdate run`, coordupdate.py) takes it from there: it trusts nothing in the request.

The row moves on as oarbankd sees the spool: `running` once the runner took the request (it removes the file), then
whatever `updates/coordinator-result.json` says (`done`, `rolled_back`, `refused`), read at start and on every
background tick. While an update runs the coordinator grants no new leases: a probation that fails restores the
database copy taken before it, and work granted meanwhile would be lost with it.
"""
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from . import clock
from . import config as C
from .db import DB

SCHEMA = """
CREATE TABLE IF NOT EXISTS coordinator_updates (
  update_id TEXT PRIMARY KEY, version TEXT NOT NULL, from_version TEXT, sha256 TEXT,
  state TEXT NOT NULL,            -- requested|running|done|rolled_back|refused|failed
  snapshot TEXT, requested_at REAL, finished_at REAL, error TEXT, actor TEXT);
"""

REQUEST = "coordinator-request.json"
RESULT = "coordinator-result.json"
ACTIVE = ("requested", "running")
REQUEST_TTL_S = 900               # a request no runner took (no trigger installed): failed, and leases resume
RESULT_TTL_S = 3600               # running with no result: the runner's probation is minutes, never this long
TICK_FRESH_S = 30                 # /v1/health `ticking`: a background tick within this
SELFTEST_TIMEOUT_S = 600
KEEP_SNAPSHOTS = 3
_ticks: dict[str, float] = {}     # db path -> the background loop's last tick
_running: dict[str, bool] = {}    # db path -> an update is running (no new leases)


class UpdateError(Exception):
    pass


def home(db: DB) -> Path:
    return Path(db.path).parent


def spool(db: DB) -> Path:
    from ..platform import files
    d = home(db) / "updates"
    if not d.exists():
        files.private_dir(d)
    return d


def _row(r: dict | None) -> dict | None:
    if not r:
        return None
    return {k: r[k] for k in ("update_id", "version", "from_version", "state", "snapshot", "requested_at", "finished_at",
                              "error", "sha256", "actor")}


def state(db: DB) -> dict | None:
    """The latest coordinator update: {update_id, version, from_version, state, snapshot, requested_at, finished_at, error}."""
    return _row(db.one("SELECT * FROM coordinator_updates ORDER BY requested_at DESC, rowid DESC LIMIT 1"))


def history(db: DB, limit: int = 20) -> list[dict]:
    return [_row(r) for r in db.q("SELECT * FROM coordinator_updates ORDER BY requested_at DESC LIMIT ?", (limit,))]


# ------------------------------------------------------------------ health and the tick

def tick(db: DB):
    _ticks[str(db.path)] = time.time()


def health(db: DB, started_at: float) -> dict:
    """GET /v1/health: what the runner's probation waits for (the version, migrations done, the tick running)."""
    from .. import __version__
    from . import identity
    last = _ticks.get(str(db.path))
    return {"version": __version__, "started_at": started_at, "migrated": True,
            "ticking": bool(last and time.time() - last <= TICK_FRESH_S), "role": identity.role(db)}


def admitting(db: DB) -> bool:
    """Whether new leases may be granted (none while an update runs: D58, data written in probation may be lost)."""
    return not _running.get(str(db.path))


# ------------------------------------------------------------------ checks

def _version(v) -> tuple | None:
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", str(v or ""))
    return tuple(int(x) for x in m.groups()) if m else None


def moving(db: DB) -> str | None:
    """Why a coordinator move forbids an update now (D58, "Moves and D44"), or None."""
    from . import coordmove, identity
    role = identity.role(db)
    if role != "active":
        return f"this coordinator is {role.replace('_', ' ')}"
    if coordmove.phase(db) != "idle":
        return f"a coordinator move is in progress ({coordmove.phase(db)})"
    m = db.one("SELECT move_id, state FROM coordinator_moves WHERE state IN ('pending','cutover','awaiting_owner')")
    if m:
        return f"coordinator move {m['move_id']} is {m['state']}"
    p = db.one("SELECT plan_id, state FROM coordinator_plans WHERE state IN ('prepared','paired','moving')")
    if p:
        return f"move plan {p['plan_id']} is {p['state']}"
    return None


def busy(db: DB) -> dict | None:
    """The coordinator update in flight, if any (a move refuses to start during one)."""
    s = state(db)
    return s if s and s["state"] in ACTIVE else None


def _has(db: DB, table: str) -> bool:
    return bool(db.one("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)))


def release(db: DB, version: str) -> tuple[dict, dict, dict]:
    """(fleet_releases row, its manifest, the coordinator artifact for this machine's platform) of a ready release."""
    from oarbank_sdk import portable
    if not _has(db, "fleet_releases") or not _has(db, "fleet_artifacts"):
        raise UpdateError("no fleet release is stored (oarbank update import)")
    rel = db.one("SELECT * FROM fleet_releases WHERE version=?", (version,))
    if not rel:
        raise UpdateError(f"release {version} is not stored (oarbank update import or fetch)")
    if rel.get("state") != "ready":
        raise UpdateError(f"release {version} is {rel.get('state') or 'not ready'}")
    try:
        manifest = json.loads(rel["manifest"])
    except (TypeError, ValueError):
        raise UpdateError(f"release {version}: its manifest does not parse")
    platform = portable.host_platform()
    art = next((a for a in manifest.get("artifacts") or [] if isinstance(a, dict) and a.get("role") == "coordinator"
                and a.get("platform") == platform), None)
    if not art or not re.fullmatch(r"[0-9a-f]{64}", str(art.get("sha256") or "")):
        raise UpdateError(f"release {version} has no coordinator build for {platform}")
    row = db.one("SELECT * FROM fleet_artifacts WHERE sha256=?", (art["sha256"],))
    if not row or row.get("role") != "coordinator" or row.get("platform") != platform:
        raise UpdateError(f"release {version}: the coordinator build for {platform} is not stored")
    return rel, manifest, {**art, "path": row.get("path")}


def held(db: DB, snap, node: dict) -> bool:
    """`update_hold` resolves to a hold that has not expired (D60). The key may not exist yet: nothing is held."""
    from .settings import resolve as V
    try:
        v = V.resolve(snap, node, "update_hold")["value"]
    except Exception:
        return False
    if not v:
        return False
    until = v.get("until") if isinstance(v, dict) else None
    if until in (None, ""):
        return True
    try:
        t = float(until)
    except (TypeError, ValueError):
        from datetime import datetime
        try:
            t = datetime.fromisoformat(str(until).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return True
    return t > clock.now()


def too_old(db: DB, agent_min: str | None) -> list[dict]:
    """Enrolled, non-retired, non-held nodes whose agent is older than `agent_min` (an unknown version is not older)."""
    floor = _version(agent_min)
    if not floor:
        return []
    from .settings import resolve as V
    snap = V.snapshot(db)
    out = []
    for n in db.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname"):
        v = _version(n.get("agent_version"))
        if v and v < floor and not held(db, snap, n):
            out.append({"node_id": n["node_id"], "hostname": n.get("hostname") or n.get("label"), "agent_version": n["agent_version"]})
    return out


def _sha256(p: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _archive(db: DB, art: dict) -> Path:
    """The build where the runner reads it (`updates/artifacts/<sha256>`), checked."""
    want = spool(db) / "artifacts" / art["sha256"]
    if not want.exists() and art.get("path"):
        src = db.abs(art["path"])
        if src and src.is_file():
            want.parent.mkdir(parents=True, exist_ok=True)
            tmp = want.with_name(f".{want.name}.{secrets.token_hex(4)}")
            shutil.copyfile(src, tmp)
            os.replace(tmp, want)
    if not want.is_file():
        raise UpdateError(f"the coordinator build {art['sha256'][:12]} is not stored")
    if want.stat().st_size != int(art.get("size") or -1) or _sha256(want) != art["sha256"]:
        raise UpdateError(f"the stored coordinator build {art['sha256'][:12]} does not match its sha256 and size")
    return want


def _signature(db: DB, rel: dict, manifest: dict) -> dict | None:
    sig = rel.get("signature_json")
    sig = json.loads(sig) if isinstance(sig, str) and sig else (sig or None)
    if not C.RELEASE_SIGNING:
        return sig
    from .. import fleetsig
    from . import owner
    try:
        s = fleetsig.verify(sig, owner.keys(db), rel["manifest"])
    except (ValueError, TypeError) as e:
        raise UpdateError(f"release {rel['version']}: {e}")
    if s["version"] != manifest.get("version") or s["seq"] != manifest.get("seq"):
        raise UpdateError(f"release {rel['version']}: the signature names version {s['version']} seq {s['seq']}")
    return sig


# ------------------------------------------------------------------ snapshot and self-test

def integrity(path: Path) -> str:
    import sqlite3
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return c.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        c.close()


def snapshot(db: DB, from_version: str) -> Path:
    """VACUUM INTO updates/snapshots/<from>-<ts>.sqlite3, integrity-checked; the newest KEEP_SNAPSHOTS stay."""
    d = spool(db) / "snapshots"
    d.mkdir(parents=True, exist_ok=True)
    dst = d / f"{from_version}-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{secrets.token_hex(2)}.sqlite3"
    db.x("VACUUM INTO ?", (str(dst),))
    ok = integrity(dst)
    if ok != "ok":
        dst.unlink(missing_ok=True)
        raise UpdateError(f"the snapshot fails its integrity check: {ok}")
    for old in sorted(d.glob("*.sqlite3"), key=lambda p: p.stat().st_mtime)[:-KEEP_SNAPSHOTS]:
        old.unlink(missing_ok=True)
    return dst


def selftest_argv(build: Path, scratch: Path) -> list[str]:
    """The new build's `oarbankd --self-test` (its manifest's `exec`, coordbuilds.py). In developer mode
    (OARBANK_RELEASE_SIGNING=0) OARBANKD_SELFTEST=checkout runs the running checkout's own instead."""
    if not C.RELEASE_SIGNING and os.environ.get("OARBANKD_SELFTEST") == "checkout":
        return [sys.executable, "-m", "oarbank.coordinator", "--self-test", "--home", str(scratch)]
    from . import coordbuilds
    doc = json.loads((build / coordbuilds.MANIFEST).read_text(encoding="utf-8"))
    exe = doc.get("exec") or ["bin/oarbankd"]
    return [str(build / exe[0]), *exe[1:], "--self-test", "--home", str(scratch)]


def self_test_build(db: DB, archive: Path, snap: Path, uid: str) -> dict:
    """Unpack the build into updates/selftest/<id>/ and run its self-test on a copy of the snapshot (D58 step 3)."""
    from . import coordbuilds
    try:
        info = coordbuilds.inspect(archive)
    except coordbuilds.BuildError as e:
        raise UpdateError(str(e))
    work = spool(db) / "selftest" / uid
    try:
        build, scratch = work / "build", work / "home"
        build.mkdir(parents=True)
        scratch.mkdir()
        with tarfile.open(archive, "r:gz") as t:
            t.extractall(build, filter="data")
        shutil.copyfile(snap, scratch / "oarbank.sqlite3")
        argv = selftest_argv(build, scratch)
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=SELFTEST_TIMEOUT_S,
                               env={**os.environ, "OARBANKD_HOME": str(scratch)})
        except (OSError, subprocess.TimeoutExpired) as e:
            raise UpdateError(f"the new build's self-test did not run: {e}")
        lines = [x for x in (r.stdout or "").splitlines() if x.strip()]
        try:
            summary = json.loads(lines[-1]) if lines else {}
        except ValueError:
            summary = {}
        if r.returncode != 0 or not summary.get("ok"):
            why = summary.get("error") or "; ".join(summary.get("invariants") or []) or (r.stderr or "").strip()[-300:]
            raise UpdateError(f"the new build's self-test failed (exit {r.returncode}): {why or 'no summary'}")
        if summary.get("version") not in (None, info["version"]):
            raise UpdateError(f"the self-test ran version {summary.get('version')}, not {info['version']}")
        return summary
    finally:
        shutil.rmtree(work, ignore_errors=True)


def self_test(path: Path) -> dict:
    """`oarbankd --self-test --home <dir>`: open the home's database (every migration runs), check its integrity and
    the safety invariants. Never listens."""
    from .. import __version__
    out = {"version": __version__, "home": str(path), "ok": False}
    p = Path(path) / "oarbank.sqlite3"
    if not p.is_file():
        out["error"] = f"no oarbank.sqlite3 in {path}"
        return out
    try:
        db = DB(p)
    except Exception as e:
        out["error"] = f"migrations failed: {e!r}"[:500]
        return out
    try:
        from . import invariants
        out["integrity"] = db.one("PRAGMA integrity_check")["integrity_check"]
        bad = invariants.check_all(db)
        out["invariants"] = bad[:20]
        out["ok"] = out["integrity"] == "ok" and not bad
        if out["integrity"] != "ok":
            out["error"] = f"integrity check: {out['integrity']}"
    except Exception as e:
        out["error"] = f"checks failed: {e!r}"[:500]
    finally:
        db.conn.close()
    return out


# ------------------------------------------------------------------ request

def request(db: DB, version: str, actor: str) -> dict:
    """Prepare and request this coordinator's update to `version` (D58). Raises UpdateError with the reason."""
    from .. import __version__
    observe_result(db)
    why = moving(db)
    if why:
        raise UpdateError(f"no coordinator update while moving: {why}")
    b = busy(db)
    if b:
        raise UpdateError(f"coordinator update {b['update_id']} to {b['version']} is {b['state']}")
    if not _version(version) or not _version(__version__):
        raise UpdateError(f"not a release version: {version}")
    if _version(version) <= _version(__version__):
        raise UpdateError(f"this coordinator runs {__version__}; {version} is not newer")
    rel, manifest, art = release(db, version)
    sig = _signature(db, rel, manifest)
    archive = _archive(db, art)
    old = too_old(db, manifest.get("agent_min"))
    if old:
        raise UpdateError(f"{version} serves agents from {manifest.get('agent_min')}; update or hold first: "
                          + ", ".join(f"{n['hostname']} ({n['agent_version']})" for n in old))
    uid = "cu_" + secrets.token_hex(6)
    snap = snapshot(db, __version__)
    try:
        self_test_build(db, archive, snap, uid)
    except UpdateError:
        snap.unlink(missing_ok=True)
        raise
    t = clock.now()
    db.x("INSERT INTO coordinator_updates(update_id, version, from_version, sha256, state, snapshot, requested_at, actor) "
         "VALUES(?,?,?,?,?,?,?,?)", (uid, version, __version__, art["sha256"], "requested", db.rel(snap), t, actor))
    req = {"id": uid, "version": version, "sha256": art["sha256"], "size": int(art["size"]),
           "archive": f"updates/artifacts/{art['sha256']}", "manifest": rel["manifest"], "signature": sig,
           "snapshot": db.rel(snap), "from_version": __version__, "requested_at": t}
    try:
        from ..platform import files
        files.write_private(spool(db) / REQUEST, json.dumps(req))          # its appearance starts the root runner
    except OSError as e:
        _finish(db, uid, "failed", f"writing the spool request: {e}")
        raise UpdateError(f"could not write the update request: {e}")
    db.event("coordinator_update_requested", actor=actor, reason=f"{__version__} -> {version} ({uid})")
    return state(db)


# ------------------------------------------------------------------ result

def _finish(db: DB, uid: str, st: str, error: str | None):
    db.x("UPDATE coordinator_updates SET state=?, finished_at=?, error=? WHERE update_id=? AND state IN ('requested','running')",
         (st, clock.now(), error, uid))


def observe_result(db: DB) -> dict | None:
    """Read the runner's result (at start and on every background tick): record it, alert on a rollback or a refusal,
    archive the file. Also moves `requested` to `running` once the runner took the request, and fails a request no
    runner took."""
    d = spool(db)
    res = d / RESULT
    if res.exists():
        try:
            doc = json.loads(res.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("not an object")
        except (OSError, ValueError) as e:
            doc = {"state": "unreadable", "error": str(e)}
        uid, st = str(doc.get("id") or ""), doc.get("state")
        r = db.one("SELECT * FROM coordinator_updates WHERE update_id=?", (uid,)) if uid else None
        what = f"{r['from_version']} -> {r['version']} ({uid})" if r else f"{doc.get('version')} ({uid or 'unknown'})"
        if st in ("done", "rolled_back", "refused"):
            if r:
                _finish(db, uid, st, doc.get("error"))
            db.event(f"coordinator_update_{st}", reason=what + (f": {doc['error']}" if doc.get("error") else ""))
            if st != "done":
                from . import core
                core._alert(db, f"coordinator_update_{st}", "coordinator",
                            f"coordinator update {what} {st.replace('_', ' ')}: {doc.get('error') or 'no reason given'}",
                            priority="high")
        else:
            db.event("coordinator_update_result_ignored", reason=f"{what}: state {st!r}")
        hist = d / "results"
        hist.mkdir(exist_ok=True)
        try:
            os.replace(res, hist / f"{re.sub(r'[^A-Za-z0-9_-]', '_', uid) or 'unknown'}-{int(time.time())}.json")
        except OSError:
            res.unlink(missing_ok=True)
    s = state(db)
    if s and s["state"] == "requested":
        if not (d / REQUEST).exists():
            db.x("UPDATE coordinator_updates SET state='running' WHERE update_id=? AND state='requested'", (s["update_id"],))
            db.event("coordinator_update_running", reason=f"{s['from_version']} -> {s['version']} ({s['update_id']})")
        elif clock.now() - (s["requested_at"] or 0) > REQUEST_TTL_S:
            (d / REQUEST).unlink(missing_ok=True)
            _finish(db, s["update_id"], "failed", "no update runner took the request (is its trigger installed? "
                                                  "install-oarbankd --refresh, then `coordupdate trust`)")
            db.event("coordinator_update_failed", reason=f"{s['update_id']}: the request was not taken")
    elif s and s["state"] == "running" and clock.now() - (s["requested_at"] or 0) > RESULT_TTL_S:
        _finish(db, s["update_id"], "failed", "the update runner wrote no result")
        db.event("coordinator_update_failed", reason=f"{s['update_id']}: no result")
    s = state(db)
    _running[str(db.path)] = bool(s and s["state"] == "running")
    return s
