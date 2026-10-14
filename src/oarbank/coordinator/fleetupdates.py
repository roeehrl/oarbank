"""Fleet updates (docs/design/fleet-updates.md; PLAN D56, D60, D61): the signed fleet release, what each node is
assigned, the `node_update` directive and the agent's report.

A fleet release is one manifest per version, `oarbank-fleet-<v>.json`, naming every artifact of the release (node
packages per platform and format, agent binaries, coordinator builds) by sha256 and size. Its text is kept verbatim:
everyone hashes those exact bytes, and the owner's statement (signing.fleet_release_statement) signs that hash. An
import (a directory on this machine, files staged through the admin API, or a download from `update_source`) checks
every artifact's sha256 and size and stores it content-addressed under `<home>/updates/artifacts/<sha256>`;
artifacts for platforms no node runs are skipped and recorded as missing. A release is **ready** when every artifact
the current nodes and the coordinator need is present and, in signing mode, the owner's signature verifies.

A node's target (`assigned`) is its pin, else nothing while it is held, else the governing rollout's version once its
ring started (rollouts.py), else what it runs. It is never newer than this coordinator (S30), and a target past a
stop the node has not reached becomes that stop (D61). While the target differs from what the node runs, hello and
heartbeat replies carry `node_update`; the agent stages, drains when `go` says so, and hands the package to the root
update runner (docs/protocol.md, "Fleet updates").
"""
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import urllib.parse
import urllib.request
from pathlib import Path

from . import clock
from . import config as C
from .db import DB, jl

SCHEMA = """
-- Fleet releases (fleetupdates.py, docs/design/fleet-updates.md): the manifest's exact text and the owner's signature
CREATE TABLE IF NOT EXISTS fleet_releases (
  version TEXT PRIMARY KEY, seq INT NOT NULL, manifest TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, signature_json TEXT,
  source TEXT, imported_at REAL, imported_by TEXT, notes TEXT,
  state TEXT NOT NULL DEFAULT 'incomplete',          -- incomplete | ready | revoked
  missing_json TEXT DEFAULT '[]', ready_at REAL);
-- Its artifacts, stored content-addressed (path NULL: not imported, see fleet_releases.missing_json)
CREATE TABLE IF NOT EXISTS fleet_artifacts (
  sha256 TEXT NOT NULL, version TEXT NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL, platform TEXT NOT NULL,
  format TEXT NOT NULL, size INT NOT NULL, path TEXT, PRIMARY KEY (version, sha256));
"""
# what the agent reports of its update and its installation (docs/protocol.md, "Fleet updates")
NODE_COLUMNS = {"node_update_json": "TEXT", "install_json": "TEXT"}

MANIFEST_TYPE = "oarbank-fleet-release"
MANIFEST_MAX = 1024 * 1024
ARTIFACT_MAX = 2 * 1024 ** 3
ROLES = ("node", "agent", "coordinator")
FORMATS = ("pkg", "msi", "deb", "rpm", "tar", "binary")
PACKAGE_FORMATS = ("pkg", "msi", "deb", "rpm", "tar")       # what the node update runner installs
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]{1,40})?$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
REPORT_STATES = ("idle", "unsupported", "staging", "staged", "draining", "deferred", "installing", "confirming", "done",
                 "failed", "rolled_back", "refused")
DEFAULT_DRAIN_TIMEOUT_S = 1800
FETCH_TIMEOUT_S = 60


class UpdateError(Exception):
    pass


# ------------------------------------------------------------------ versions

def vkey(v) -> tuple | None:
    """A sortable key of a release version (a pre-release sorts before its release), or None."""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.+-]*)?", str(v or "").strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if m.group(4) else 1, m.group(4) or ""


def newer(a, b) -> bool:
    """`a` is a later release than `b` (False when either is unknown)."""
    ka, kb = vkey(a), vkey(b)
    return bool(ka and kb and ka > kb)


def coordinator_version() -> str:
    """The version this coordinator runs: nothing is ever assigned past it (S30)."""
    import oarbank
    return oarbank.__version__


def coordinator_platform() -> str:
    from oarbank_sdk import portable
    return portable.host_platform()


# ------------------------------------------------------------------ the manifest

def _expiry(v) -> float | None:
    if v is None:
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    if isinstance(v, str):
        try:
            t = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise UpdateError(f"manifest: expires {v!r} is not a time")
        return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).timestamp()
    raise UpdateError("manifest: expires is a time or null")


def parse(text: str) -> dict:
    """The manifest's document, checked (UpdateError names what is wrong). The text itself is what is kept and hashed;
    it is never re-serialized."""
    if not isinstance(text, str) or not text or len(text.encode()) > MANIFEST_MAX:
        raise UpdateError(f"manifest: the text of oarbank-fleet-<version>.json (at most {MANIFEST_MAX // 1024} KB)")
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise UpdateError(f"manifest: not JSON ({e})")
    if not isinstance(doc, dict) or doc.get("type") != MANIFEST_TYPE or doc.get("format") != 1:
        raise UpdateError(f"manifest: not an {MANIFEST_TYPE} of format 1")
    v = doc.get("version")
    if not isinstance(v, str) or not VERSION_RE.fullmatch(v):
        raise UpdateError(f"manifest: version {v!r} is not a release version")
    seq = doc.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
        raise UpdateError("manifest: seq is a positive integer")
    for k in ("agent_min",):
        if doc.get(k) is not None and not (isinstance(doc[k], str) and VERSION_RE.fullmatch(doc[k])):
            raise UpdateError(f"manifest: {k} {doc[k]!r} is not a release version")
    stops = doc.get("stops") or []
    if not isinstance(stops, list) or not all(isinstance(s, str) and VERSION_RE.fullmatch(s) and newer(v, s) for s in stops):
        raise UpdateError("manifest: stops are release versions older than the release")
    _expiry(doc.get("expires"))
    if doc.get("notes") is not None and not isinstance(doc["notes"], str):
        raise UpdateError("manifest: notes is a string")
    arts = doc.get("artifacts")
    if not isinstance(arts, list) or not arts:
        raise UpdateError("manifest: artifacts is a non-empty list")
    from oarbank_sdk import portable
    names, shas = set(), set()
    for i, a in enumerate(arts):
        where = f"manifest: artifacts[{i}]"
        if not isinstance(a, dict):
            raise UpdateError(f"{where} is not an object")
        if not isinstance(a.get("name"), str) or not NAME_RE.fullmatch(a["name"]) or ".." in a["name"]:
            raise UpdateError(f"{where}.name {a.get('name')!r} is not a plain file name")
        if a.get("role") not in ROLES:
            raise UpdateError(f"{where}.role: one of {', '.join(ROLES)}")
        if a.get("format") not in FORMATS:
            raise UpdateError(f"{where}.format: one of {', '.join(FORMATS)}")
        if not isinstance(a.get("platform"), str) or not portable.is_platform_token(a["platform"]):
            raise UpdateError(f"{where}.platform {a.get('platform')!r} is not a platform token")
        if not isinstance(a.get("sha256"), str) or not SHA_RE.fullmatch(a["sha256"]):
            raise UpdateError(f"{where}.sha256: 64 lowercase hex digits")
        size = a.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= ARTIFACT_MAX:
            raise UpdateError(f"{where}.size: a positive integer of at most {ARTIFACT_MAX} bytes")
        if a["name"] in names or a["sha256"] in shas:
            raise UpdateError(f"{where}: {a['name']} is listed twice")
        names.add(a["name"])
        shas.add(a["sha256"])
    return doc


def text_sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# ------------------------------------------------------------------ storage

def _home(db: DB) -> Path:
    return Path(db.path).parent


def _dir(db: DB, *parts) -> Path:
    d = _home(db).joinpath("updates", *parts)
    d.mkdir(parents=True, exist_ok=True)
    return d


def stage(db: DB, data: bytes) -> dict:
    """Store uploaded bytes (a manifest or an artifact) content-addressed for updates.import; nothing is registered."""
    if not data or len(data) > ARTIFACT_MAX:
        raise UpdateError(f"send one file of the release (at most {ARTIFACT_MAX // 2 ** 20} MB)")
    sha = hashlib.sha256(data).hexdigest()
    d = _dir(db, "incoming")
    tmp = d / f".{sha}.tmp"
    tmp.write_bytes(data)
    tmp.replace(d / sha)
    return {"sha256": sha, "size": len(data)}


def _hash_file(p: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def needed_platforms(db: DB) -> set:
    """The platforms whose artifacts this fleet needs: every node's that is not retired, and the coordinator's."""
    from . import platforms
    out = {coordinator_platform()}
    for n in db.q("SELECT platform, facts_json FROM nodes WHERE lifecycle!='retired'"):
        p = n["platform"] or platforms.facts_platform(jl(n["facts_json"], {}) or {})["platform"]
        if p:
            out.add(p)
    return out


def _import(db: DB, text: str, find, actor: str, source: str) -> dict:
    """Register a release from its manifest text; `find(artifact)` gives a local file with an artifact's bytes, or None.
    Every artifact found is checked (sha256, size) before anything is stored; a mismatch refuses the whole import."""
    doc = parse(text)
    v, msha = doc["version"], text_sha(text)
    old = db.one("SELECT * FROM fleet_releases WHERE version=?", (v,))
    if old and old["manifest_sha256"] != msha:
        raise UpdateError(f"release {v} is already imported with another manifest ({old['manifest_sha256'][:12]}); "
                          "a release's content never changes")
    for r in db.q("SELECT version, seq FROM fleet_releases WHERE version!=?", (v,)):
        if (newer(v, r["version"]) and doc["seq"] <= r["seq"]) or (newer(r["version"], v) and doc["seq"] >= r["seq"]):
            raise UpdateError(f"seq {doc['seq']} of {v} does not rise with the versions (release {r['version']} has seq {r['seq']})")
    exp = _expiry(doc.get("expires"))
    if exp is not None and exp < clock.now():
        raise UpdateError(f"release {v} expired at {doc['expires']}")
    want = needed_platforms(db)
    found, missing = {}, []
    for a in doc["artifacts"]:
        if a["platform"] not in want:
            missing.append({"name": a["name"], "platform": a["platform"], "why": f"no node runs {a['platform']}"})
            continue
        have = db.one("SELECT path FROM fleet_artifacts WHERE version=? AND sha256=? AND path IS NOT NULL", (v, a["sha256"]))
        if have and db.abs(have["path"]).exists():
            continue
        p = find(a)
        if p is None:
            missing.append({"name": a["name"], "platform": a["platform"], "why": "not provided"})
            continue
        sha, size = _hash_file(Path(p))
        if size != a["size"]:
            raise UpdateError(f"{a['name']}: {size} bytes, the manifest says {a['size']}")
        if sha != a["sha256"]:
            raise UpdateError(f"{a['name']}: sha256 {sha[:12]}… is not the manifest's {a['sha256'][:12]}…")
        found[a["sha256"]] = Path(p)
    store = _dir(db, "artifacts")
    for sha, p in found.items():
        dst = store / sha
        if not dst.exists():
            tmp = store / f".{sha}.tmp"
            shutil.copyfile(p, tmp)
            os.replace(tmp, dst)
    with db.tx():
        if not old:
            db.x("INSERT INTO fleet_releases(version, seq, manifest, manifest_sha256, source, imported_at, imported_by, notes, "
                 "state) VALUES(?,?,?,?,?,?,?,?, 'incomplete')",
                 (v, doc["seq"], text, msha, source, clock.now(), actor, doc.get("notes")))
        for a in doc["artifacts"]:
            p = store / a["sha256"]
            db.x("INSERT INTO fleet_artifacts(sha256, version, name, role, platform, format, size, path) VALUES(?,?,?,?,?,?,?,?) "
                 "ON CONFLICT(version, sha256) DO UPDATE SET path=COALESCE(excluded.path, fleet_artifacts.path)",
                 (a["sha256"], v, a["name"], a["role"], a["platform"], a["format"], a["size"], db.rel(p) if p.exists() else None))
        db.x("UPDATE fleet_releases SET missing_json=? WHERE version=?", (json.dumps(missing), v))
        db.event("fleet_release_imported", actor=actor, reason=f"{v} (seq {doc['seq']}) from {source}",
                 artifacts=len(doc["artifacts"]) - len(missing), missing=len(missing))
        refresh(db, v)
    return release(db, v)


def import_dir(db: DB, path, actor: str) -> dict:
    """`oarbank update import <dir>` on this machine: the directory holds oarbank-fleet-<v>.json and the artifacts."""
    d = Path(path)
    if not d.is_dir():
        raise UpdateError(f"{d} is not a directory")
    mans = sorted(d.glob("oarbank-fleet-*.json"))
    if len(mans) != 1:
        raise UpdateError(f"{d} holds {len(mans)} oarbank-fleet-<version>.json manifests (one is needed)")
    text = mans[0].read_text(encoding="utf-8")

    def find(a):
        p = d / a["name"]
        return p if p.is_file() else None
    return _import(db, text, find, actor, f"dir:{d}")


def import_staged(db: DB, manifest_sha: str, actor: str) -> dict:
    """An import whose files were staged first (POST /api/v1/updates/uploads): the manifest and the artifacts by sha256."""
    if not SHA_RE.fullmatch(manifest_sha or ""):
        raise UpdateError("params.manifest: the sha256 of the staged oarbank-fleet-<version>.json")
    inc = _dir(db, "incoming")
    m = inc / manifest_sha
    if not m.exists():
        raise UpdateError(f"no staged manifest {manifest_sha[:12]}")
    text = m.read_text(encoding="utf-8")

    def find(a):
        p = inc / a["sha256"]
        return p if p.exists() else None
    out = _import(db, text, find, actor, "upload")
    for a in parse(text)["artifacts"]:
        (inc / a["sha256"]).unlink(missing_ok=True)
    m.unlink(missing_ok=True)
    return out


# ------------------------------------------------------------------ fetching from the release source

def source(db: DB) -> str:
    from .settings import store
    return str(store.fleet_value(db, "update_source")).rstrip("/")


def _http_get(url: str, limit: int, dest: Path | None = None) -> bytes | None:
    """GET a URL (http, https or file) into memory, or into `dest` when given; at most `limit` bytes. Tests replace it."""
    req = urllib.request.Request(url, headers={"User-Agent": f"oarbankd/{coordinator_version()}",
                                               "Accept": "application/octet-stream, application/json"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_S) as r:        # noqa: S310 (the owner's configured source)
        if dest is None:
            data = r.read(limit + 1)
            if len(data) > limit:
                raise UpdateError(f"{url}: larger than {limit} bytes")
            return data
        n = 0
        with open(dest, "wb") as f:
            for chunk in iter(lambda: r.read(1 << 20), b""):
                n += len(chunk)
                if n > limit:
                    raise UpdateError(f"{url}: larger than {limit} bytes")
                f.write(chunk)
        return None


def asset_url(base: str, version: str, name: str) -> str:
    """A release asset under the source: GitHub's layout, <source>/download/v<version>/<name>."""
    return f"{base}/download/v{urllib.parse.quote(version)}/{urllib.parse.quote(name)}"


def latest(db: DB) -> str | None:
    """The newest version the release source offers: GitHub's `releases/latest` for a GitHub releases page, else
    `<source>/latest.json` ({"version"})."""
    base = source(db)
    m = re.fullmatch(r"https://github\.com/([^/]+)/([^/]+)/releases", base)
    if m:
        doc = json.loads(_http_get(f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}/releases/latest", 1 << 20))
        v = str(doc.get("tag_name") or "").lstrip("v")
    else:
        v = str(json.loads(_http_get(f"{base}/latest.json", 1 << 16)).get("version") or "")
    return v if VERSION_RE.fullmatch(v) else None


def fetch(db: DB, version: str, actor: str) -> dict:
    """Download a release from `update_source` (its manifest and the artifacts this fleet needs) and import it."""
    import tempfile
    if version in ("latest", "", None):
        version = latest(db)
        if not version:
            raise UpdateError("the release source names no latest release")
    if not VERSION_RE.fullmatch(version):
        raise UpdateError(f"{version!r} is not a release version")
    base = source(db)
    name = f"oarbank-fleet-{version}.json"
    try:
        text = _http_get(asset_url(base, version, name), MANIFEST_MAX).decode("utf-8")
    except (OSError, ValueError) as e:
        raise UpdateError(f"{asset_url(base, version, name)}: {e}")
    doc = parse(text)
    if doc["version"] != version:
        raise UpdateError(f"{name} describes release {doc['version']}")
    want = needed_platforms(db)
    tmp = Path(tempfile.mkdtemp(prefix="fetch-", dir=_dir(db)))
    try:
        got = {}
        for a in doc["artifacts"]:
            have = db.one("SELECT path FROM fleet_artifacts WHERE version=? AND sha256=? AND path IS NOT NULL", (version, a["sha256"]))
            if a["platform"] not in want or (have and db.abs(have["path"]).exists()):
                continue
            p = tmp / a["sha256"]
            try:
                _http_get(asset_url(base, version, a["name"]), a["size"], p)
            except (OSError, ValueError) as e:
                raise UpdateError(f"{asset_url(base, version, a['name'])}: {e}")
            got[a["sha256"]] = p
        return _import(db, text, lambda a: got.get(a["sha256"]), actor, base)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ signatures and readiness

def attach_signature(db: DB, version: str, stmt: str, signature: str, actor: str) -> dict:
    """The owner's statement over a release (made offline by `oarbank update sign`), checked against the owner key set."""
    from .. import signing
    from . import owner
    from .releases import _verify_any
    r = db.one("SELECT * FROM fleet_releases WHERE version=?", (version,))
    if not r:
        raise UpdateError(f"no release {version} is imported")
    pubs = owner.keys(db)
    if not pubs:
        raise UpdateError("no owner key is configured (oarbank release keygen, oarbank owner set)")
    try:
        s = _verify_any(signing.verify_fleet_release, stmt, signature, pubs)
    except ValueError as e:
        raise UpdateError(str(e))
    if s["version"] != version or int(s["seq"]) != r["seq"] or s["manifest_sha256"] != r["manifest_sha256"]:
        raise UpdateError("the statement does not name this release's version, seq and manifest sha256")
    db.x("UPDATE fleet_releases SET signature_json=? WHERE version=?",
         (json.dumps({"statement": stmt, "signature": signature}), version))
    db.event("fleet_release_signed", actor=actor, reason=f"{version} seq {r['seq']}")
    refresh(db, version)
    return release(db, version)


def _sig_ok(db: DB, r: dict) -> bool:
    from .. import signing
    from . import owner
    sig = jl(r.get("signature_json"))
    if not sig:
        return False
    for k in owner.keys(db):
        try:
            s = signing.verify_fleet_release(sig["statement"], sig["signature"], k)
        except ValueError:
            continue
        if s["manifest_sha256"] == r["manifest_sha256"] and s["version"] == r["version"] and int(s["seq"]) == r["seq"]:
            return True
    return False


def gaps(db: DB, version: str) -> list[str]:
    """What keeps a release from being ready: the artifacts the current nodes and the coordinator need that are not
    here, an expiry, and (signing mode) the owner's signature."""
    r = db.one("SELECT * FROM fleet_releases WHERE version=?", (version,))
    if not r:
        return [f"release {version} is not imported"]
    if r["state"] == "revoked":
        return ["revoked"]
    out = []
    doc = json.loads(r["manifest"])
    exp = _expiry(doc.get("expires"))
    if exp is not None and exp < clock.now():
        out.append(f"expired at {doc['expires']}")
    have = {a["sha256"]: a for a in db.q("SELECT * FROM fleet_artifacts WHERE version=?", (version,))}
    present = lambda a: bool(have.get(a["sha256"], {}).get("path")) and db.abs(have[a["sha256"]]["path"]).exists()
    wants = set()
    for n in nodes(db):
        inst = n["install"]
        if n["platform"] and inst.get("updater") and inst.get("format") in PACKAGE_FORMATS:
            wants.add(("node", n["platform"], inst["format"]))
    if newer(version, coordinator_version()):
        wants.add(("coordinator", coordinator_platform(), None))
    for role, plat, fmt in sorted(wants, key=str):
        arts = [a for a in doc["artifacts"] if a["role"] == role and a["platform"] == plat and (fmt is None or a["format"] == fmt)]
        if not arts:
            continue                       # the release has none for it: such nodes are skipped (unsupported), not waited for
        if not any(present(a) for a in arts):
            out.append(f"{arts[0]['name']} is not here (oarbank update import or fetch)")
    if C.RELEASE_SIGNING and not _sig_ok(db, r):
        out.append("the owner's signature (oarbank update sign)")
    return out


def refresh(db: DB, version: str | None = None) -> None:
    """Recompute ready/incomplete for one release or all (a node joining with a new platform can make one incomplete)."""
    for r in db.q("SELECT version, state FROM fleet_releases" + (" WHERE version=?" if version else ""),
                  (version,) if version else ()):
        if r["state"] == "revoked":
            continue
        st = "incomplete" if gaps(db, r["version"]) else "ready"
        if st != r["state"]:
            db.x("UPDATE fleet_releases SET state=?, ready_at=? WHERE version=?",
                 (st, clock.now() if st == "ready" else None, r["version"]))
            db.event(f"fleet_release_{st}", reason=r["version"])


def release(db: DB, version: str) -> dict | None:
    r = db.one("SELECT * FROM fleet_releases WHERE version=?", (version,))
    if not r:
        return None
    doc = json.loads(r["manifest"])
    arts = db.q("SELECT sha256, name, role, platform, format, size, path IS NOT NULL AS present FROM fleet_artifacts "
                "WHERE version=? ORDER BY role, platform, format", (version,))
    return {"version": version, "seq": r["seq"], "manifest_sha256": r["manifest_sha256"], "state": r["state"],
            "signed": bool(r["signature_json"]), "notes": r["notes"], "source": r["source"], "imported_at": r["imported_at"],
            "imported_by": r["imported_by"], "agent_min": doc.get("agent_min"), "stops": doc.get("stops") or [],
            "released_at": doc.get("released_at"), "expires": doc.get("expires"), "artifacts": arts,
            "missing": jl(r["missing_json"], []) or [], "gaps": gaps(db, version)}


def releases(db: DB) -> list[dict]:
    rows = db.q("SELECT version FROM fleet_releases")
    return [release(db, r["version"]) for r in sorted(rows, key=lambda r: vkey(r["version"]) or (), reverse=True)]


def manifest_doc(db: DB, version: str) -> dict | None:
    r = db.one("SELECT manifest FROM fleet_releases WHERE version=?", (version,))
    return json.loads(r["manifest"]) if r else None


def agent_min(db: DB) -> str | None:
    """The oldest agent this coordinator still serves: the `agent_min` of the release it runs, when imported."""
    doc = manifest_doc(db, coordinator_version())
    return (doc or {}).get("agent_min")


# ------------------------------------------------------------------ nodes

# The command that pins a node's update trust, per package format, exactly as a person types it (the agent's own
# oarbank_core::fleet::TRUST_REMEDY): the bare `update-trust` 2.10.0-2.10.4 agents name only prints its usage.
TRUST_REMEDY = {
    "pkg": "sudo /Library/Oarbank/bin/oarbank-launcher update-trust --from-agent",
    "msi": "oarbank-node update-trust --from-agent (in an elevated prompt)",
}
TRUST_REMEDY_OTHER = "sudo oarbank-launcher update-trust --from-agent"
NO_TRUST = "no update trust is pinned"


def install_of(node: dict) -> dict:
    """The agent's `install` facts ({format, scope, updater, why}); {} from an agent older than fleet updates. An older
    agent's "no update trust" names the command without `--from-agent`: shown with the one that pins."""
    inst = jl(node.get("install_json"), {}) or {}
    why = inst.get("why")
    if isinstance(why, str) and why.startswith(NO_TRUST) and "--from-agent" not in why:
        inst = {**inst, "why": f"{NO_TRUST}: {TRUST_REMEDY.get(inst.get('format'), TRUST_REMEDY_OTHER)}"}
    return inst


def nodes(db: DB) -> list[dict]:
    from . import platforms
    out = []
    for n in db.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname"):
        out.append({**n, "platform": platforms.node_platform(n), "install": install_of(n)})
    return out


def artifact_for(db: DB, version: str, node: dict) -> tuple[dict | None, str | None]:
    """(the release's package for this node, or None with why): its platform and installed format, imported here."""
    from . import platforms
    inst = install_of(node)
    if not inst:
        return None, "its agent reports no installation facts (older than fleet updates): it self-updates its agent only"
    if not inst.get("updater"):
        return None, f"no update runner on it: {inst.get('why') or 'a personal or developer install'}"
    fmt, plat = inst.get("format"), platforms.node_platform(node)
    if fmt not in PACKAGE_FORMATS:
        return None, f"installed as {fmt or 'unknown'}: no package format the runner installs"
    a = db.one("SELECT * FROM fleet_artifacts WHERE version=? AND role='node' AND platform=? AND format=?", (version, plat, fmt))
    if not a:
        return None, f"release {version} has no {fmt} package for {plat}"
    if not a["path"] or not db.abs(a["path"]).exists():
        return None, f"{a['name']} is not imported here"
    return a, None


def _setting(db: DB, node: dict, key: str, snap=None):
    from .settings import resolve
    snap = snap or resolve.snapshot(db)
    return resolve.resolve(snap, node, key)["value"]


def active_hold(db: DB, node: dict, now: float | None = None, snap=None) -> dict | None:
    """The node's update hold while it lasts (an expired one is ignored: the node rejoins)."""
    h = _setting(db, node, "update_hold", snap)
    t = clock.now() if now is None else now
    return h if isinstance(h, dict) and (h.get("until") is None or h["until"] > t) else None


def active_pin(db: DB, node: dict, now: float | None = None, snap=None) -> dict | None:
    p = _setting(db, node, "update_pin", snap)
    t = clock.now() if now is None else now
    return p if isinstance(p, dict) and (p.get("until") is None or p["until"] > t) else None


def _capped(db: DB, node: dict, version: str | None) -> str | None:
    """S30 and D61: never past this coordinator; the next stop the node has not reached comes first."""
    if not version:
        return None
    if newer(version, coordinator_version()):
        return None
    have = node.get("agent_version")
    doc = manifest_doc(db, version) or {}
    for s in sorted(doc.get("stops") or [], key=vkey):
        if have and newer(s, have) and newer(version, s):
            return s
    return version


def assigned(db: DB, node: dict, now: float | None = None, snap=None) -> dict | None:
    """The node's target ({version, rollback, rollout_id, why}) per the design's "Assignment": its pin; nothing while
    held; the governing rollout's version once the node's ring started (or it catches up); else none (it stays). Never
    newer than this coordinator; a stop the node has not reached comes first."""
    from . import rollouts
    from .settings import resolve
    snap = snap or resolve.snapshot(db)
    pin = active_pin(db, node, now, snap)
    if pin:
        v = _capped(db, node, pin["version"])
        return {"version": v, "rollback": bool(v and newer(node.get("agent_version"), v)), "rollout_id": None,
                "why": f"pinned: {pin['reason']}"} if v else None
    if active_hold(db, node, now, snap):
        return None
    g = rollouts.target(db, node)
    if not g:
        return None
    v = _capped(db, node, g["version"])
    return {**g, "version": v} if v else None


def directive(db: DB, node: dict, now: float | None = None) -> dict | None:
    """The heartbeat reply's `node_update` (docs/design/fleet-updates.md, "Interfaces"), or None while the node runs
    what it is assigned, or when the release has no package it can install."""
    if not db.one("SELECT 1 FROM fleet_releases LIMIT 1"):
        return None                                    # no fleet release imported: nothing to assign
    a = assigned(db, node, now)
    if not a or not a["version"] or a["version"] == node.get("agent_version"):
        return None
    r = db.one("SELECT * FROM fleet_releases WHERE version=?", (a["version"],))
    if not r or (r["state"] != "ready" and not a.get("rollback")):
        return None
    art, _why = artifact_for(db, a["version"], node)
    if not art:
        return None
    from . import owner, rollouts
    pol = rollouts.policy_of(db, a.get("rollout_id"))
    return {"release": a["version"], "seq": r["seq"], "go": rollouts.go(db, node, a), "rollback": bool(a.get("rollback")),
            "drain_timeout_s": int(pol.get("drain_timeout_s") or DEFAULT_DRAIN_TIMEOUT_S),
            "artifact": {"name": art["name"], "format": art["format"], "sha256": art["sha256"], "size": art["size"],
                         "url": f"/v1/updates/artifacts/{art['sha256']}"},
            "manifest": r["manifest"], "signature": jl(r["signature_json"]),
            "owner_anchors": owner.directives(db).get("owner_anchors")}


def artifact_file(db: DB, node: dict, sha: str) -> Path | None:
    """GET /v1/updates/artifacts/{sha256}: only the artifact of the node's current directive."""
    d = directive(db, node)
    if not d or d["artifact"]["sha256"] != sha:
        return None
    a = db.one("SELECT path FROM fleet_artifacts WHERE sha256=? AND path IS NOT NULL", (sha,))
    p = db.abs(a["path"]) if a else None
    return p if p and p.exists() else None


def _clean_report(rep) -> dict | None:
    if not isinstance(rep, dict) or rep.get("state") not in REPORT_STATES:
        return None
    out = {"state": rep["state"], "release": str(rep.get("release") or "")[:64] or None,
           "seq": rep["seq"] if isinstance(rep.get("seq"), int) and not isinstance(rep.get("seq"), bool) else None,
           "error": str(rep["error"])[:500] if rep.get("error") else None,
           "at": float(rep["at"]) if isinstance(rep.get("at"), (int, float)) and not isinstance(rep.get("at"), bool) else None}
    return out


def _clean_install(inst) -> dict | None:
    if not isinstance(inst, dict):
        return None
    fmt = inst.get("format") if inst.get("format") in (*PACKAGE_FORMATS, "dev") else None
    pv = inst.get("package_version")
    return {"format": fmt, "scope": inst.get("scope") if inst.get("scope") in ("system", "personal") else None,
            "updater": inst.get("updater") is True, "why": str(inst["why"])[:300] if inst.get("why") else None,
            # the installed package's agent (agents after 2.10.4), which the agent-only channel never goes below (agentbuilds.py)
            "package_version": pv if isinstance(pv, str) and len(pv) <= 64 and vkey(pv) else None}


def observe(db: DB, node: dict, body: dict, heartbeat: bool = True):
    """The agent's `node_update` and `install` (hello and heartbeat): stored on the node, transitions recorded, and the
    governing rollout's node row moved (rollouts.observe)."""
    rep, inst = _clean_report(body.get("node_update")), _clean_install(body.get("install"))
    if inst is not None and json.dumps(inst, sort_keys=True) != node.get("install_json"):
        db.x("UPDATE nodes SET install_json=? WHERE node_id=?", (json.dumps(inst, sort_keys=True), node["node_id"]))
        node = {**node, "install_json": json.dumps(inst, sort_keys=True)}
    old = jl(node.get("node_update_json"), {}) or {}
    if rep is not None:
        db.x("UPDATE nodes SET node_update_json=? WHERE node_id=?", (json.dumps(rep), node["node_id"]))
        node = {**node, "node_update_json": json.dumps(rep)}
        if (rep["state"], rep["release"]) != (old.get("state"), old.get("release")) and \
                rep["state"] in ("done", "failed", "rolled_back", "refused", "deferred"):
            db.event(f"node_update_{rep['state']}", node_id=node["node_id"], actor=node.get("hostname") or "agent",
                     reason=f"{rep['release'] or '?'}" + (f": {rep['error'][:300]}" if rep.get("error") else ""))
    from . import rollouts
    rollouts.observe(db, node, rep, heartbeat)


# ------------------------------------------------------------------ the console and `oarbank update status`

def view(db: DB) -> dict:
    from . import rollouts
    from .settings import resolve
    t = clock.now()
    snap = resolve.snapshot(db)
    rels = releases(db)
    out_nodes = []
    for n in nodes(db):
        a = assigned(db, n, t, snap)
        art, why = artifact_for(db, a["version"], n) if a and a.get("version") else (None, None)
        hold, pin = _setting(db, n, "update_hold", snap), _setting(db, n, "update_pin", snap)
        out_nodes.append({
            "node_id": n["node_id"], "hostname": n["hostname"], "platform": n["platform"], "version": n.get("agent_version"),
            "target": a["version"] if a else None, "rollback": bool(a and a.get("rollback")),
            "report": jl(n.get("node_update_json"), {}) or {}, "install": n["install"],
            "ring": _setting(db, n, "update_ring", snap), "window": _setting(db, n, "update_window", snap),
            "hold": hold, "hold_expired": bool(hold and hold.get("until") and hold["until"] <= t),
            "pin": pin, "pin_expired": bool(pin and pin.get("until") and pin["until"] <= t),
            "auto": _setting(db, n, "update_auto", snap), "unsupported": why if a and not art else None,
            "updater": bool(n["install"].get("updater")), "last_heartbeat_at": n.get("last_heartbeat_at"),
            "online": (n.get("last_heartbeat_at") or 0) >= t - rollouts.ONLINE_S})
    newest = next((r for r in rels if r["state"] == "ready"), None)
    return {"coordinator": {"version": coordinator_version(), "platform": coordinator_platform(),
                            "update": rollouts.coordinator_state(db), "agent_min": agent_min(db)},
            "releases": rels, "newest_ready": newest, "nodes": out_nodes, "signing": C.RELEASE_SIGNING,
            "source": source(db), "update_auto": resolve.resolve(snap, None, "update_auto")["value"],
            **rollouts.view(db)}
