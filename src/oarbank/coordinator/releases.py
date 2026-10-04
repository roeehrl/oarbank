"""Releases: what an agent installs. A release is per platform (spec/platforms.md) and composed from the module
store (modstore): for each module with a current version that supports the platform, the bundle of the version the
node runs (its pin, its canary, else the current version), under modules/<name>/, with only the files a node of the
platform receives ([bundle.platform_files]; wheels/ only the wheels that install there), plus modules.json (the
platform and every module's node-side entry, rendered for that platform) and MANIFEST.json (every file's sha256 and
mode).
release_id = "r_" + sha256(the file list)[:12], so equal compositions for one platform are one release, and the
platform is bound into the id and the signed sha256 through modules.json.

The default composition of each platform (every module at its current version) is that platform's release with
status 'current'. A node whose composition differs (a canary node, a pinned node) gets its own release through
`nodes.assigned_release`, built when the channels change (`sync`). Signed releases (D31) cover the whole
composition: the release is the signed lock of module digests.
"""
import json
import stat
import tarfile
import tempfile
from pathlib import Path

from ..common import sha256_file, sha256_hex
from . import clock
from . import config as C
from . import modimages, modstore, platforms
from .db import DB, jl

MODULES_FORMAT = 2       # modules.json: {format, platform, modules[]}


def _supports(path, platform: str) -> bool:
    from oarbank_sdk import manifest as mf
    return platform in mf.load(Path(path) / "oarbank-module.toml").requires.platforms


def composition(db: DB, node_id: str | None = None, platform: str | None = None) -> dict:
    """{name: {version, digest, path}} a node runs (None: the default composition). With a platform, only the modules
    whose version supports it."""
    out = {}
    for name, ch in modstore.channels(db).items():
        if not ch["current"]:
            continue
        ver = modstore.version_for_node(db, name, node_id)
        r = modstore.record(db, name, ver)
        if r and (platform is None or _supports(r["path"], platform)):
            out[name] = {"version": ver, "digest": r["content_digest"], "path": r["path"]}
    return out


def composition_key(comp: dict, platform: str = "") -> str:
    return sha256_hex(json.dumps({"platform": platform, "modules": {n: [c["version"], c["digest"]] for n, c in sorted(comp.items())}},
                                 sort_keys=True))


def _runner_requirements(bundle: Path, argv: list[str], m, platform: str) -> str | None:
    """The runner's requirements file, beside its script (oarbank-sdk spec/bundles.md, "Dependencies"), relative to the
    bundle, when nodes of `platform` receive it; they install it offline from the bundle's wheels."""
    script = next((a for a in argv[1:] if a.startswith("{bundle}/") and a.endswith(".py")), None)
    if not script:
        return None
    rel = (Path(script[len("{bundle}/"):]).parent / "requirements.txt").as_posix()
    return rel if (bundle / rel).is_file() and m.bundle.receives(rel, platform) else None


def node_files(m, files: list[dict], platform: str) -> list[dict]:
    """The bundle files (bundle.json entries) a node of `platform` receives: [bundle.platform_files] decides, and of the
    wheels only those that install on the platform (the coordinator and the CLI keep the whole bundle)."""
    from oarbank_sdk import bundle as B, deps
    return [f for f in B.subset(files, m, platform)
            if not (f["path"].startswith(deps.WHEELS_DIR + "/") and f["path"].endswith(".whl"))
            or deps.wheel_fits(f["path"].rsplit("/", 1)[1], platform)]


def module_entry(name: str, version: str, digest: str, path, platform: str = platforms.DEFAULT_PLATFORM,
                 tools: dict | None = None) -> dict:
    """modules.json entry for one platform: what the agent needs to run and serve the module generically. Execs stay
    unresolved argv (`python`, `{bundle}`; spec/manifest.md "Exec"): the agent substitutes its interpreter and the
    module's bundle directory, modules/<name>/. `tools` maps each approved tool id to its host paths on this platform's
    OS (from the operator's tool registry)."""
    from oarbank_sdk import manifest as mf
    path = Path(path)
    m = mf.load(path / "oarbank-module.toml")
    run = m.runner.for_platform(platform)
    on = lambda xs: [x for x in xs if not x.platforms or platform in x.platforms]
    # bootstrap: the agent runs the stage's jobs with the bootstrap grants (only when set, so other entries keep their bytes)
    stages = [{"name": st.name, "capabilities": list(st.requires.capabilities),
               "pools": sorted(set(st.requires.pools) | set(st.requires.needs_pools)),
               "platforms": list(st.requires.platforms), **({"bootstrap": True} if st.bootstrap else {})} for st in m.stages]
    every = set.intersection(*(set(s["capabilities"]) for s in stages)) if stages else set()
    sb = m.sandbox
    return {"name": name, "module_id": m.module.id, "version": version, "digest": digest, "bundle": f"modules/{name}",
            "requires": sorted(every), "stages": stages,
            "requirements": _runner_requirements(path, list(run.exec), m, platform),
            # env: [runner].env with the platform's variant merged (only when declared, so other entries keep their bytes)
            "runner": {"exec": list(run.exec), "runtime": run.runtime.kind, "capabilities": list(run.capabilities),
                       "stop_grace_s": run.stop_grace_s, "gpu": run.gpu.model_dump(),
                       **({"bandwidth_class": run.bandwidth_class} if run.bandwidth_class else {}),
                       **({"env": dict(run.env)} if run.env else {})},
            "services": [{"name": sv.name, "exec": list(sv.exec), "lifecycle": sv.lifecycle,
                          "idle_timeout_s": sv.idle_timeout_s, "start_timeout_s": sv.start_timeout_s,
                          "stop_timeout_s": sv.stop_timeout_s, "restart": sv.restart.model_dump(),
                          "provides": {"capabilities": list(sv.provides.capabilities), "pools": list(sv.provides.pools)},
                          "reserves_host_memory": sv.reserves_host_memory, "yieldable": sv.yieldable, "freeze_ok": sv.freeze_ok}
                         for sv in on(m.services)],
            "probes": [{"name": pr.name, "exec": list(pr.exec), "period_s": pr.period_s} for pr in on(m.probes)],
            # the module sandbox (spec/sandbox.md): the node-side grants, operator-approved before this version could
            # be enabled, canaried, pinned or promoted (modsandbox); the agent enforces exactly these
            "sandbox": {"contract": sb.contract, "net": {"mode": sb.net.mode, "allow": list(sb.net.allow)},
                        "tools": [{"id": t.id, "trust": t.trust, "paths": list((tools or {}).get(t.id) or [])} for t in sb.tools],
                        "devices": {"gpu": sb.devices.gpu}, "exec_writable": sb.exec_writable,
                        "containers": [{"image": c.image, "platform": c.platform} for c in sb.containers],
                        # image sets with their keys (only when declared, so other entries keep their bytes)
                        **({"container_sets": modimages.release_sets(m, path)} if sb.container_sets else {})}}


def build(db: DB, make_current: bool = True, comp: dict | None = None, platform: str = platforms.DEFAULT_PLATFORM) -> dict:
    """Compose a release for one platform from the module store (default: its default composition) and record it."""
    from oarbank_sdk import manifest as mf, portable
    comp = composition(db, platform=platform) if comp is None else comp
    os_ = portable.split_platform(platform)[0]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "bundle"
        root.mkdir()
        entries_mod = []
        for name, c in sorted(comp.items()):
            src = Path(c["path"])
            m = mf.load(src / "oarbank-module.toml")
            for f in node_files(m, json.loads((src / "bundle.json").read_text())["files"], platform):
                dst = root / "modules" / name / f["path"]
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes((src / f["path"]).read_bytes())
                dst.chmod(int(f["mode"], 8))
            ids = [t.id for t in m.sandbox.tools]
            tools = {i: platforms.tool_paths(db, [i], os_)[0] for i in ids}
            entries_mod.append(module_entry(name, c["version"], c["digest"], src, platform, tools))
        (root / "modules.json").write_text(json.dumps({"format": MODULES_FORMAT, "platform": platform, "modules": entries_mod},
                                                      indent=1, sort_keys=True))
        (root / "modules.json").chmod(0o644)          # modes are part of the release; never the coordinator's umask
        entries = []
        for p in sorted(root.rglob("*")):
            if p.is_file():
                mode = stat.S_IMODE(p.stat().st_mode)
                entries.append({"path": str(p.relative_to(root)), "sha256": sha256_file(p), "mode": oct(mode)})
        man = json.dumps({"files": entries}, sort_keys=True, indent=1)
        rid = "r_" + sha256_hex(json.dumps(entries, sort_keys=True))[:12]
        (root / "MANIFEST.json").write_text(man)
        C.RELEASE_DIR.mkdir(parents=True, exist_ok=True)
        out = C.RELEASE_DIR / f"{rid}.tar.gz"
        if not out.exists():
            with tarfile.open(out, "w:gz") as t:
                for p in sorted(root.rglob("*")):
                    t.add(p, arcname=str(p.relative_to(root)), recursive=False)
    digest = sha256_file(out)
    prev = db.one("SELECT status, seq, statement, signature FROM releases WHERE release_id=?", (rid,)) or {}
    comp_json = json.dumps({n: {"version": c["version"], "digest": c["digest"]} for n, c in comp.items()}, sort_keys=True)
    db.x("INSERT OR REPLACE INTO releases(release_id,created_at,path,sha256,manifest_json,status,seq,statement,signature,"
         "composition_json,platform) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
         (rid, clock.now(), db.rel(out), digest, man, prev.get("status") or "candidate", prev.get("seq"), prev.get("statement"),
          prev.get("signature"), comp_json, platform))
    signed_needed = C.RELEASE_SIGNING and bool(db.get_setting("release_pubkey")) and not prev.get("signature")
    if make_current and not signed_needed:
        promote(db, rid, actor="build")
    db.event("release_built", reason=f"{rid} ({platform})", sha256=digest, files=len(entries), modules=sorted(comp))
    return {"release_id": rid, "platform": platform, "sha256": digest, "path": str(out), "files": len(entries), "modules": sorted(comp),
            "composition": json.loads(comp_json), "needs_signature": signed_needed,
            **({"next": f"oarbank release sign {rid} --promote"} if signed_needed else {})}


def sync(db: DB) -> dict:
    """After a lifecycle change: for every platform in the fleet, build its default release (made current) and every
    node-specific one (canary and pinned nodes), and point each node at its release. Returns {default, defaults,
    assigned}: `default` is the first platform's release (a one-platform fleet has one)."""
    defaults, built, assigned = {}, {}, {}
    for plat in platforms.fleet_platforms(db):
        rel = build(db, make_current=True, platform=plat)
        defaults[plat] = rel["release_id"]
        built[composition_key(composition(db, platform=plat), plat)] = rel["release_id"]
    for n in db.q("SELECT node_id, platform, facts_json FROM nodes WHERE lifecycle NOT IN ('retired')"):
        plat = platforms.node_platform(dict(n))
        if not plat:
            continue
        comp = composition(db, n["node_id"], plat)
        key = composition_key(comp, plat)
        if built.get(key) == defaults.get(plat):
            db.x("UPDATE nodes SET assigned_release=NULL WHERE node_id=?", (n["node_id"],))
            continue
        if key not in built:
            built[key] = build(db, make_current=False, comp=comp, platform=plat)["release_id"]
        db.x("UPDATE nodes SET assigned_release=? WHERE node_id=?", (built[key], n["node_id"]))
        assigned[n["node_id"]] = built[key]
    return {"default": next(iter(defaults.values())), "defaults": defaults, "assigned": assigned}


def ensure(db: DB, platform: str | None):
    """Build the releases of a platform the fleet has none for yet (a node of a new platform enrolled)."""
    if not platform or db.one("SELECT 1 FROM releases WHERE status='current' AND platform=?", (platform,)):
        return
    if any(ch["current"] for ch in modstore.channels(db).values()):
        sync(db)


def assigned(db: DB, node: dict) -> str | None:
    """The release a node must run: its own (canary, pin) or the current one for its platform."""
    if node.get("assigned_release"):
        return node["assigned_release"]
    plat = platforms.node_platform(node)
    if not plat:
        return None
    r = db.one("SELECT release_id FROM releases WHERE status='current' AND platform=?", (plat,))
    return r["release_id"] if r else None


def composition_of(db: DB, release_id: str | None) -> dict:
    r = db.one("SELECT composition_json FROM releases WHERE release_id=?", (release_id,)) if release_id else None
    return jl(r["composition_json"], {}) if r else {}


class ReleaseRefused(Exception):
    pass


def _verify_any(fn, stmt, signature, pubs):
    """Any key of the owner set may sign (the primary, or the backup after a rotation)."""
    err = None
    for k in pubs:
        try:
            return fn(stmt, signature, k)
        except ValueError as e:
            err = e
    raise err or ValueError("no owner key")


def attach_signature(db: DB, release_id: str, stmt: str, signature: str) -> dict:
    """Verify a statement signed offline by oarbank and record it (anti-rollback: seq must rise)."""
    if not C.RELEASE_SIGNING:
        raise ReleaseRefused("release signing is disabled (start oarbankd with OARBANK_RELEASE_SIGNING=1)")
    from .. import signing
    from . import owner
    pubs = owner.keys(db)
    pub = pubs[0] if pubs else None
    if not pub:
        raise ReleaseRefused("no release_pubkey configured (oarbank release keygen)")
    row = db.one("SELECT * FROM releases WHERE release_id=?", (release_id,))
    if not row:
        raise ReleaseRefused(f"unknown release {release_id}")
    try:
        s = _verify_any(signing.verify, stmt, signature, pubs)
    except ValueError as e:
        raise ReleaseRefused(str(e))
    if s["release_id"] != release_id or s["sha256"] != row["sha256"]:
        raise ReleaseRefused("statement does not match this release's id and sha256")
    top = db.one("SELECT MAX(seq) m FROM releases WHERE signature IS NOT NULL AND release_id!=?", (release_id,))["m"] or 0
    if int(s["seq"]) <= top:
        raise ReleaseRefused(f"seq {s['seq']} is not above the highest signed seq {top}")
    db.x("UPDATE releases SET seq=?, statement=?, signature=? WHERE release_id=?", (int(s["seq"]), stmt, signature, release_id))
    db.event("release_signed", reason=release_id, seq=int(s["seq"]))
    return {"release_id": release_id, "seq": int(s["seq"])}


def promote(db: DB, release_id: str, actor: str):
    """Make a release current for its platform."""
    row = db.one("SELECT signature, platform FROM releases WHERE release_id=?", (release_id,))
    if not row:
        raise ReleaseRefused(f"unknown release {release_id}")
    if C.RELEASE_SIGNING and db.get_setting("release_pubkey") and not row["signature"]:
        raise ReleaseRefused(f"{release_id} is unsigned; agents pinned to the release key would refuse it")
    with db.tx():
        db.x("UPDATE releases SET status='retired' WHERE status='current' AND platform=?", (row["platform"],))
        db.x("UPDATE releases SET status='current' WHERE release_id=?", (release_id,))
    db.event("release_promoted", actor=actor, reason=release_id)
