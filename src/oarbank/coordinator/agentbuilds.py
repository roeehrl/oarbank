"""Agent self-update: the build store (oarbank-agent binaries by sha256, each for one or more platforms) and one
channel per platform (current, previous, canary on chosen nodes), the same shape as a module's channel.

Each node is assigned the build of its platform's channel: the canary on canary nodes, the current one everywhere
else, nothing before the first build is enabled. Hello and heartbeat replies carry an `agent_update` directive while
the build a node reports running differs from its assignment. The agent downloads it, checks the sha256 (and the
signature in signing mode), installs it side by side, drains (running jobs finish; no new claims), flips its launcher
pointer and restarts on it. It confirms itself after its first successful hello and heartbeat; the launcher flips back
when the new build fails to start or is not confirmed within 10 minutes (docs/protocol.md, "Agent self-update"). No
step needs ssh.

An uploaded binary is never executed here: its platform comes from its executable headers (Mach-O, ELF, PE) and its
version from the marker every agent build embeds, `oarbank-agent-version:<semver>` followed by a NUL byte.
"""
import hashlib
import json
import os
import re
import shutil
import struct
from pathlib import Path

from . import clock
from . import config as C
from .db import DB, jl

MAX_SIZE = 256 * 1024 * 1024
VERSION_MARK = re.compile(rb"oarbank-agent-version:([0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]{1,40})?)\x00")
HEALTHY_WITHIN_S = 120                                          # a canary node must have heartbeated this recently

MACHO_CPU = {0x0100000C: "arm64", 0x01000007: "amd64"}           # CPU_TYPE_ARM64, CPU_TYPE_X86_64
ELF_MACHINE = {0xB7: "arm64", 0x3E: "amd64"}                    # EM_AARCH64, EM_X86_64
PE_MACHINE = {0xAA64: "arm64", 0x8664: "amd64"}                 # IMAGE_FILE_MACHINE_ARM64, _AMD64


class BuildError(Exception):
    pass


def _dir(*parts) -> Path:
    d = C.HOME.joinpath("agent", *parts)
    d.mkdir(parents=True, exist_ok=True)
    return d


def stage(data: bytes) -> dict:
    """Store uploaded bytes content-addressed for agent.upload (registering is the audited operation)."""
    if not data or len(data) > MAX_SIZE:
        raise BuildError(f"send the oarbank-agent binary (at most {MAX_SIZE // 2**20} MB)")
    sha = hashlib.sha256(data).hexdigest()
    d = _dir("incoming")
    tmp = d / f".{sha}.tmp"
    tmp.write_bytes(data)
    tmp.replace(d / sha)
    return {"sha256": sha, "size": len(data)}


def incoming(sha: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
        raise BuildError("params.sha256: the uploaded binary's sha256 (POST /api/v1/agent/builds)")
    p = C.HOME / "agent" / "incoming" / sha
    if not p.exists():
        raise BuildError(f"no uploaded binary {sha[:12]}")
    return p


def platforms_of(data: bytes) -> tuple[str, list[str]]:
    """(format, platform tokens) from an executable's headers; BuildError for anything else."""
    if data[:4] == b"\xcf\xfa\xed\xfe" and len(data) >= 32:              # 64-bit Mach-O, little-endian
        cpu, ftype = struct.unpack_from("<I", data, 4)[0], struct.unpack_from("<I", data, 12)[0]
        if ftype == 2 and cpu in MACHO_CPU:                                 # MH_EXECUTE
            return "macho", [f"darwin-{MACHO_CPU[cpu]}"]
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):      # universal: big-endian fat header
        n = struct.unpack_from(">I", data, 4)[0]
        step = 20 if data[3] == 0xBE else 32
        if 0 < n <= 8 and len(data) >= 8 + n * step:
            cpus = [struct.unpack_from(">I", data, 8 + i * step)[0] for i in range(n)]
            arches = sorted({MACHO_CPU[c] for c in cpus if c in MACHO_CPU})
            if arches:
                return "macho-universal", [f"darwin-{a}" for a in arches]
    if data[:4] == b"\x7fELF" and len(data) >= 20 and data[4] == 2 and data[5] == 1:   # ELF64, little-endian
        etype, mach = struct.unpack_from("<HH", data, 16)
        if etype in (2, 3) and mach in ELF_MACHINE:                         # ET_EXEC or ET_DYN (PIE)
            return "elf", [f"linux-{ELF_MACHINE[mach]}"]
    if data[:2] == b"MZ" and len(data) >= 64:
        off = struct.unpack_from("<I", data, 0x3C)[0]
        if len(data) >= off + 24 and data[off:off + 4] == b"PE\x00\x00":
            mach, chars = struct.unpack_from("<H", data, off + 4)[0], struct.unpack_from("<H", data, off + 22)[0]
            if mach in PE_MACHINE and chars & 0x0002 and not chars & 0x2000:   # an executable image, not a DLL
                return "pe", [f"windows-{PE_MACHINE[mach]}"]
    raise BuildError("not a 64-bit arm64 or amd64 executable for macOS (Mach-O), Linux (ELF) or Windows (PE)")


def inspect(path: Path) -> dict:
    """The build's format, platforms and version, from its bytes alone."""
    data = path.read_bytes()
    fmt, plats = platforms_of(data)
    versions = {m.group(1).decode() for m in VERSION_MARK.finditer(data)}
    if len(versions) != 1:
        raise BuildError("the binary does not embed exactly one oarbank-agent-version marker" +
                         (f" (found {', '.join(sorted(versions))})" if versions else ""))
    return {"version": versions.pop(), "size": len(data), "format": fmt, "platforms": plats}


def register(db: DB, sha: str, actor: str) -> dict:
    src = incoming(sha)
    if hashlib.sha256(src.read_bytes()).hexdigest() != sha:
        raise BuildError("staged bytes do not match their sha256")
    info = inspect(src)
    if record(db, sha):
        return {**record(db, sha), "already": True}
    dst = _dir("builds") / sha
    tmp = dst.with_name(f".{sha}.tmp")
    shutil.copyfile(src, tmp)               # a stored copy is read-only: replace it through a rename, never write it
    os.chmod(tmp, 0o555)
    os.replace(tmp, dst)
    src.unlink(missing_ok=True)
    db.x("INSERT INTO agent_builds(sha256, version, path, size, uploaded_at, uploaded_by, platform, format) VALUES(?,?,?,?,?,?,?,?)",
         (sha, info["version"], db.rel(dst), info["size"], clock.now(), actor, ",".join(info["platforms"]), info["format"]))
    db.event("agent_build_uploaded", actor=actor, reason=f"{info['version']} {sha[:12]} ({', '.join(info['platforms'])})",
             size=info["size"])
    return record(db, sha)


def record(db: DB, sha: str | None) -> dict | None:
    r = db.one("SELECT * FROM agent_builds WHERE sha256=?", (sha,)) if sha else None
    return {**r, "path": str(db.abs(r["path"])), "platforms": r["platform"].split(",")} if r else None


def builds(db: DB) -> list[dict]:
    return [{**r, "path": str(db.abs(r["path"])), "platforms": r["platform"].split(",")}
            for r in db.q("SELECT * FROM agent_builds ORDER BY uploaded_at DESC")]


def resolve(db: DB, ref: str) -> str:
    """A full sha256, a unique prefix of at least 8 hex digits, or a version that names one build."""
    ref = (ref or "").strip().lower()
    rows = builds(db)
    hit = [r for r in rows if r["sha256"] == ref] or (
        [r for r in rows if r["sha256"].startswith(ref)] if re.fullmatch(r"[0-9a-f]{8,63}", ref) else []) or \
        [r for r in rows if r["version"] == ref]
    if len(hit) != 1:
        raise BuildError(f"{ref!r} names {len(hit)} agent builds (give the sha256 or a longer prefix)")
    return hit[0]["sha256"]


def channel(db: DB, platform: str) -> dict:
    r = db.one("SELECT * FROM agent_channel WHERE platform=?", (platform,)) or {}
    return {"platform": platform, "current": r.get("current"), "previous": r.get("previous"), "canary": r.get("canary"),
            "canary_nodes": jl(r.get("canary_nodes_json"), []) or [], "updated_at": r.get("updated_at")}


def channels(db: DB) -> dict:
    return {r["platform"]: channel(db, r["platform"]) for r in db.q("SELECT platform FROM agent_channel ORDER BY platform")}


def _save(db: DB, ch: dict):
    db.x("INSERT INTO agent_channel(platform, current, previous, canary, canary_nodes_json, updated_at) VALUES(?,?,?,?,?,?) "
         "ON CONFLICT(platform) DO UPDATE SET current=excluded.current, previous=excluded.previous, canary=excluded.canary, "
         "canary_nodes_json=excluded.canary_nodes_json, updated_at=excluded.updated_at",
         (ch["platform"], ch["current"], ch["previous"], ch["canary"], json.dumps(ch["canary_nodes"]), clock.now()))


def _needs_signature(db: DB, sha: str):
    if C.RELEASE_SIGNING and not (record(db, sha) or {}).get("signature"):
        raise BuildError(f"agent build {sha[:12]} is unsigned; in signing mode agents refuse it (oarbank agent sign)")


def _node_platform(db: DB, nid: str) -> str | None:
    from . import platforms
    n = db.one("SELECT node_id, platform, facts_json FROM nodes WHERE node_id=?", (nid,))
    return platforms.node_platform(dict(n)) if n else None


def canary(db: DB, sha: str, nodes: list[str]) -> dict:
    """Run a build on canary nodes: every node must be on one of the build's platforms; each of those platforms'
    channels gets the build as its canary on its own nodes."""
    rec = record(db, sha)
    if not rec:
        raise BuildError(f"unknown agent build {sha[:12]}")
    if not nodes:
        raise BuildError("name at least one canary node")
    _needs_signature(db, sha)
    by_plat = {}
    for nid in sorted(set(nodes)):
        plat = _node_platform(db, nid)
        if plat not in rec["platforms"]:
            raise BuildError(f"node {nid} is {plat or 'of unknown platform'}; build {sha[:12]} is for {', '.join(rec['platforms'])}")
        by_plat.setdefault(plat, []).append(nid)
    out = {}
    for plat, nids in by_plat.items():
        ch = channel(db, plat)
        ch.update(canary=sha, canary_nodes=nids)
        _save(db, ch)
        out[plat] = channel(db, plat)
    return out


def readiness(db: DB, platform: str) -> dict:
    """Promotable once every canary node reports running the canary build and has heartbeated since."""
    ch = channel(db, platform)
    t = clock.now()
    status = {}
    for nid in ch["canary_nodes"]:
        n = db.one("SELECT hostname, agent_build, agent_update_json, last_heartbeat_at FROM nodes WHERE node_id=?", (nid,))
        if not n:
            status[nid] = "unknown node"
            continue
        upd = jl(n["agent_update_json"], {}) or {}
        if n["agent_build"] == ch["canary"]:
            fresh = (n["last_heartbeat_at"] or 0) >= t - HEALTHY_WITHIN_S
            status[n["hostname"]] = "running it" if fresh else "running it, but no recent heartbeat"
        else:
            status[n["hostname"]] = upd.get("state") or "not updated yet"
            if upd.get("error"):
                status[n["hostname"]] += f": {upd['error'][:120]}"
    return {"platform": platform, "from": ch["current"], "to": ch["canary"], "canary_nodes": status,
            "ready": bool(ch["canary"]) and bool(status) and all(s == "running it" for s in status.values())}


def _platforms(db: DB, platform: str | None, want: str) -> list[str]:
    plats = [platform] if platform else [p for p, ch in channels(db).items() if ch[want]]
    if not plats:
        raise BuildError(f"no platform has {'a canary agent build' if want == 'canary' else 'anything to roll back'}")
    return plats


def promote(db: DB, platform: str | None = None) -> dict:
    """Make the canary current: on one platform, or on every platform that has a canary."""
    out = {}
    for plat in _platforms(db, platform, "canary"):
        ch = channel(db, plat)
        if not ch["canary"]:
            raise BuildError(f"no canary agent build to promote on {plat}")
        _needs_signature(db, ch["canary"])
        if ch["current"] != ch["canary"]:
            ch["previous"] = ch["current"]
        ch.update(current=ch["canary"], canary=None, canary_nodes=[])
        _save(db, ch)
        out[plat] = channel(db, plat)
    return out


def rollback(db: DB, platform: str | None = None) -> dict:
    """Abandon the canary (its nodes go back to current), or, with no canary, flip current back to previous; on one
    platform or on every platform that has either."""
    plats = [platform] if platform else [p for p, ch in channels(db).items() if ch["canary"] or ch["previous"]]
    if not plats:
        raise BuildError("nothing to roll back: no canary and no previous build")
    out = {}
    for plat in plats:
        ch = channel(db, plat)
        if ch["canary"]:
            ch.update(canary=None, canary_nodes=[])
        elif ch["previous"]:
            _needs_signature(db, ch["previous"])
            ch.update(current=ch["previous"], previous=ch["current"])
        else:
            raise BuildError(f"nothing to roll back on {plat}: no canary and no previous build")
        _save(db, ch)
        out[plat] = channel(db, plat)
    return out


def attach_signature(db: DB, sha: str, stmt: str, signature: str) -> dict:
    """An agent build statement signed offline by oarbank (anti-rollback: seq must rise across agent builds)."""
    if not C.RELEASE_SIGNING:
        raise BuildError("release signing is disabled (start oarbankd with OARBANK_RELEASE_SIGNING=1)")
    from .. import signing
    from . import owner
    from .releases import _verify_any
    pubs = owner.keys(db)
    if not pubs:
        raise BuildError("no release_pubkey configured (oarbank release keygen)")
    row = record(db, sha)
    if not row:
        raise BuildError(f"unknown agent build {sha[:12]}")
    try:
        s = _verify_any(signing.verify_agent, stmt, signature, pubs)
    except ValueError as e:
        raise BuildError(str(e))
    if s["agent_sha256"] != sha or s["version"] != row["version"] or sorted(s["platforms"]) != sorted(row["platforms"]):
        raise BuildError("statement does not name this build's sha256, version and platforms")
    top = db.one("SELECT MAX(seq) m FROM agent_builds WHERE signature IS NOT NULL AND sha256!=?", (sha,))["m"] or 0
    if int(s["seq"]) <= top:
        raise BuildError(f"seq {s['seq']} is not above the highest signed agent seq {top}")
    db.x("UPDATE agent_builds SET seq=?, statement=?, signature=? WHERE sha256=?", (int(s["seq"]), stmt, signature, sha))
    db.event("agent_build_signed", reason=sha[:12], seq=int(s["seq"]))
    return {"sha256": sha, "seq": int(s["seq"])}


def assigned(db: DB, node: dict) -> str | None:
    from . import platforms
    plat = platforms.node_platform(node)
    if not plat:
        return None
    ch = channel(db, plat)
    if ch["canary"] and node["node_id"] in ch["canary_nodes"]:
        return ch["canary"]
    return ch["current"]


def directive(db: DB, node: dict) -> dict | None:
    sha = assigned(db, node)
    if not sha or node.get("agent_build") == sha:
        return None
    r = record(db, sha)
    if not r:
        return None
    d = {"sha256": sha, "version": r["version"], "size": r["size"], "url": f"/v1/agent/builds/{sha}"}
    if C.RELEASE_SIGNING:
        d.update(statement=r["statement"], signature=r["signature"])
    return d


def observe(db: DB, node: dict, body: dict):
    """Store what a hello or heartbeat says about the agent's own build and its update; record transitions."""
    build, upd = body.get("agent_build"), body.get("agent_update")
    if build is None and upd is None:
        return
    old_build, old = node.get("agent_build"), jl(node.get("agent_update_json"), {}) or {}
    db.x("UPDATE nodes SET agent_build=COALESCE(?, agent_build), agent_update_json=COALESCE(?, agent_update_json) WHERE node_id=?",
         (build, json.dumps(upd) if upd is not None else None, node["node_id"]))
    if build and old_build and build != old_build:
        db.event("agent_updated", node_id=node["node_id"], actor=node["hostname"], reason=f"{old_build[:12]} -> {build[:12]}",
                 agent_version=body.get("agent_version"))
    if upd and upd.get("state") != old.get("state") and upd.get("state") in ("failed", "rolled_back", "blocked"):
        db.event(f"agent_update_{upd['state']}", node_id=node["node_id"], actor=node["hostname"],
                 reason=f"{(upd.get('target') or '')[:12]}: {(upd.get('error') or '')[:300]}")


def view(db: DB) -> dict:
    nodes = db.q("SELECT node_id, hostname, platform, facts_json, agent_version, agent_build, agent_update_json, "
                 "last_heartbeat_at, lifecycle FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    chs = channels(db)
    by_sha = {b["sha256"]: b for b in builds(db)}
    out = []
    for n in nodes:
        a = assigned(db, n)
        out.append({**{k: n[k] for k in ("node_id", "hostname", "platform", "agent_version", "agent_build", "last_heartbeat_at")},
                    "assigned": a, "assigned_version": (by_sha.get(a) or {}).get("version"),
                    "update": jl(n["agent_update_json"], {}) or {}, "up_to_date": a is None or n["agent_build"] == a})
    return {"builds": [{k: v for k, v in b.items() if k != "path"} for b in by_sha.values()], "channels": chs, "nodes": out,
            "readiness": {p: readiness(db, p) for p, ch in chs.items() if ch["canary"]}, "signing": C.RELEASE_SIGNING}
