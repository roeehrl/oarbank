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

With release signing on and an owner key pinned, a built release stays a candidate until the owner signs it offline
(`oarbank release sign <rid> --promote`): nothing reaches a node before that. `awaiting` lists those releases, the
console shows them as a banner and `note_awaiting` keeps one `release_awaiting_owner:<rid>` alert per release open
until it is signed and promoted or a newer build replaces it.
"""
import json
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


def composition_json(comp: dict) -> str:
    """The composition as a release row records it (releases.composition_json): equal compositions, equal text."""
    return json.dumps({n: {"version": c["version"], "digest": c["digest"]} for n, c in comp.items()}, sort_keys=True)


def contents(comp_json: str | None) -> list[str]:
    """What a release holds, as `module@version` (from its composition_json); empty: no module runs on its platform."""
    return [f"{n}@{c.get('version')}" for n, c in sorted((jl(comp_json, {}) or {}).items())]


def signature_required(db: DB) -> bool:
    """Releases need the owner's signature before a node may install them (signing on, an owner key pinned)."""
    return bool(C.RELEASE_SIGNING and db.get_state("release_pubkey"))


def any_module_enabled(db: DB) -> bool:
    return any(ch["current"] for ch in modstore.channels(db).values())


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


def module_entry(name: str, version: str, digest: str, path, platform: str = platforms.DEFAULT_PLATFORM) -> dict:
    """modules.json entry for one platform: what the agent needs to run and serve the module generically. Execs stay
    unresolved argv (`python`, `{bundle}`; spec/manifest.md "Exec"): the agent substitutes its interpreter and the
    module's bundle directory, modules/<name>/. Host tools are requests (id, version, arch, trust), never paths: the
    agent resolves each against what it detected (docs/design/host-tools.md)."""
    from oarbank_sdk import manifest as mf
    path = Path(path)
    m = mf.load(path / "oarbank-module.toml")
    run = m.runner.for_platform(platform)
    on = lambda xs: [x for x in xs if not x.platforms or platform in x.platforms]
    # bootstrap: the agent runs the stage's jobs with the bootstrap grants; checkpoint: the stage's checkpoint limits
    # (both only when set, so other entries keep their bytes)
    stages = [{"name": st.name, "capabilities": list(st.requires.capabilities),
               "pools": sorted(set(st.requires.pools) | set(st.requires.needs_pools)),
               "platforms": list(st.requires.platforms), **({"bootstrap": True} if st.bootstrap else {}),
               **({"checkpoint": {"max_mb": st.checkpoint.max_mb, "min_interval_s": st.checkpoint.min_interval_s}}
                  if st.checkpoint else {})} for st in m.stages]
    every = set.intersection(*(set(s["capabilities"]) for s in stages)) if stages else set()
    sb = m.sandbox
    keeps = any(st.checkpoint for st in m.stages)
    return {"name": name, "module_id": m.module.id, "version": version, "digest": digest, "bundle": f"modules/{name}",
            "requires": sorted(every), "stages": stages,
            # a job of the default stage names none: the agent finds its checkpoint limits by this name
            **({"default_stage": m.default_stage()} if keeps and m.default_stage() else {}),
            "requirements": _runner_requirements(path, list(run.exec), m, platform),
            # env: [runner].env with the platform's variant merged (only when declared, so other entries keep their bytes)
            "runner": {"exec": list(run.exec), "runtime": run.runtime.kind, "capabilities": list(run.capabilities),
                       "stop_grace_s": run.stop_grace_s, "gpu": run.gpu.model_dump(),
                       **({"checkpoint_grace_s": run.checkpoint_grace_s} if "checkpoint" in run.capabilities else {}),
                       **({"bandwidth_class": run.bandwidth_class} if run.bandwidth_class else {}),
                       **({"env": dict(run.env)} if run.env else {})},
            "services": [{"name": sv.name, "exec": list(sv.exec), "lifecycle": sv.lifecycle,
                          "idle_timeout_s": sv.idle_timeout_s, "start_timeout_s": sv.start_timeout_s,
                          "stop_timeout_s": sv.stop_timeout_s, "restart": sv.restart.model_dump(),
                          "provides": {"capabilities": list(sv.provides.capabilities), "pools": list(sv.provides.pools)},
                          "reserves_host_memory": sv.reserves_host_memory, "yieldable": sv.yieldable, "freeze_ok": sv.freeze_ok,
                          # endpoint and gpu only when set, so other entries keep their bytes
                          **({"endpoint": True} if sv.endpoint else {}),
                          # the inbound listeners whose connections it serves (only when set, so other entries keep their bytes)
                          **({"listeners": list(sv.listeners)} if getattr(sv, "listeners", None) else {}),
                          **({"gpu": sv.gpu.model_dump()} if sv.gpu.use != "none" or sv.gpu.apis_any else {})}
                         for sv in on(m.services)],
            "probes": [{"name": pr.name, "exec": list(pr.exec), "period_s": pr.period_s} for pr in on(m.probes)],
            # the module sandbox (spec/sandbox.md): the node-side grants, operator-approved before this version could
            # be enabled, canaried, pinned or promoted (modsandbox); the agent enforces exactly these
            "sandbox": {"contract": sb.contract,
                        # inbound listeners (docs/design/inbound-listeners.md; only when declared, so other entries keep
                        # their bytes): the module's ceilings; the owner's per-node entries are in the node statement
                        "net": {"mode": sb.net.mode, "allow": list(sb.net.allow),
                                **({"inbound": inbound_entries(sb)} if getattr(sb.net, "inbound", None) else {})},
                        "tools": [{"id": t.id, "trust": t.trust, "version": t.version, "arch": t.arch} for t in sb.tools],
                        "devices": {"gpu": sb.devices.gpu}, "exec_writable": sb.exec_writable,
                        "containers": [{"image": c.image, "platform": c.platform} for c in sb.containers],
                        # image sets with their keys (only when declared, so other entries keep their bytes)
                        **({"container_sets": modimages.release_sets(m, path)} if sb.container_sets else {}),
                        # folders: ids only; where they are on each node is the node's signed statement
                        **({"folders": [{"id": f.id, "access": f.access} for f in sb.folders]} if sb.folders else {})}}


def inbound_entries(sb) -> list[dict]:
    """`[sandbox].net.inbound` as the release (and the grant approval) carries it: every field explicit, `proxy_protocol`
    resolved (absent in the manifest: on for `listen_fd`, else off)."""
    return [{"name": x.name, "protocol": x.protocol, "port_hint": x.port_hint, "port_policy": x.port_policy, "tls": x.tls,
             "handover": getattr(x, "handover", "connections"),
             "proxy_protocol": x.proxy() if hasattr(x, "proxy") else bool(x.proxy_protocol),
             "max_conns": x.max_conns, "max_conns_per_ip": x.max_conns_per_ip,
             "new_conns_per_ip_per_s": x.new_conns_per_ip_per_s, "idle_timeout_s": x.idle_timeout_s,
             "max_bytes_per_s": x.max_bytes_per_s} for x in sb.net.inbound]


def _tar(out: Path, root: Path, modes: dict):
    """The release archive: its directories (0755) and files with the modes the release records, `/`-separated."""
    names = set(modes)
    for rel in modes:
        parts = rel.split("/")
        names.update("/".join(parts[:i]) for i in range(1, len(parts)))
    with tarfile.open(out, "w:gz") as t:
        for rel in sorted(names, key=lambda r: r.split("/")):
            info = t.gettarinfo(str(root / rel), arcname=rel)
            info.mode = modes.get(rel, 0o755)
            if info.isfile():
                with open(root / rel, "rb") as f:
                    t.addfile(info, f)
            else:
                t.addfile(info)


def build(db: DB, make_current: bool = True, comp: dict | None = None, platform: str = platforms.DEFAULT_PLATFORM) -> dict:
    """Compose a release for one platform from the module store (default: its default composition) and record it."""
    from oarbank_sdk import manifest as mf, portable
    comp = composition(db, platform=platform) if comp is None else comp
    os_ = portable.split_platform(platform)[0]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "bundle"
        root.mkdir()
        entries_mod, modes = [], {}               # modes are part of the release, recorded here, never read back
        for name, c in sorted(comp.items()):      # from the filesystem (Windows keeps no modes)
            src = Path(c["path"])
            m = mf.load(src / "oarbank-module.toml")
            for f in node_files(m, json.loads((src / "bundle.json").read_text(encoding="utf-8"))["files"], platform):
                rel = f"modules/{name}/{f['path']}"
                dst = root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes((src / f["path"]).read_bytes())
                modes[rel] = int(f["mode"], 8)
            entries_mod.append(module_entry(name, c["version"], c["digest"], src, platform))
        # the fleet's tool definitions for this OS (extra search patterns, executables' version commands): what the
        # agent detects, besides its built-in kinds (docs/design/host-tools.md); never a path to grant
        from . import tools as T
        (root / "modules.json").write_text(json.dumps({"format": MODULES_FORMAT, "platform": platform, "modules": entries_mod,
                                                       "tools": T.release_definitions(db, os_)},
                                                      indent=1, sort_keys=True), encoding="utf-8", newline="\n")
        modes["modules.json"] = 0o644
        entries = [{"path": rel, "sha256": sha256_file(root / rel), "mode": oct(modes[rel])}
                   for rel in sorted(modes, key=lambda r: r.split("/"))]
        man = json.dumps({"files": entries}, sort_keys=True, indent=1)
        rid = "r_" + sha256_hex(json.dumps(entries, sort_keys=True))[:12]
        (root / "MANIFEST.json").write_text(man, encoding="utf-8", newline="\n")
        modes["MANIFEST.json"] = 0o644
        C.RELEASE_DIR.mkdir(parents=True, exist_ok=True)
        out = C.RELEASE_DIR / f"{rid}.tar.gz"
        if not out.exists():
            _tar(out, root, modes)
    digest = sha256_file(out)
    prev = db.one("SELECT status, seq, statement, signature FROM releases WHERE release_id=?", (rid,)) or {}
    comp_json = composition_json(comp)
    db.x("INSERT OR REPLACE INTO releases(release_id,created_at,path,sha256,manifest_json,status,seq,statement,signature,"
         "composition_json,platform) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
         (rid, clock.now(), db.rel(out), digest, man, prev.get("status") or "candidate", prev.get("seq"), prev.get("statement"),
          prev.get("signature"), comp_json, platform))
    signed_needed = signature_required(db) and not prev.get("signature")
    if make_current and not signed_needed and prev.get("status") != "current":
        promote(db, rid, actor="build")
    if not prev:              # the same composition built again is the same release: only a new one is news
        db.event("release_built", reason=f"{rid} ({platform})", sha256=digest, files=len(entries), modules=sorted(comp),
                 **({"next": f"oarbank release sign {rid}" + (" --promote" if make_current else "")} if signed_needed else {}))
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
    # each platform's default release, for awaiting(): a newer build of a platform replaces (supersedes) its older one
    db.set_state(DEFAULTS, {**(db.get_state(DEFAULTS) or {}), **defaults})
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
    note_awaiting(db)
    return {"default": next(iter(defaults.values())), "defaults": defaults, "assigned": assigned}


def ensure(db: DB, platform: str | None):
    """Build the releases of a platform whose default composition has no release yet (a node of a new platform
    enrolled, or the composition changed). Every hello asks: a release of this composition that is current, or a
    candidate waiting for the owner's signature, is the answer, and building it again would change nothing."""
    if not platform or not any_module_enabled(db):
        return
    comp = composition_json(composition(db, platform=platform))
    rows = db.q("SELECT release_id, status FROM releases WHERE platform=? AND composition_json=? AND status IN ('current','candidate') "
                "ORDER BY status='current' DESC, created_at DESC", (platform, comp))
    if any(r["status"] == "current" for r in rows) or (rows and signature_required(db)):
        known = (db.get_state(DEFAULTS) or {}).get(platform)
        known_comp = (db.one("SELECT composition_json FROM releases WHERE release_id=?", (known,)) or {}).get("composition_json") \
            if known else None
        if known_comp != comp:     # built before awaiting() knew each platform's default (an upgrade): it is this one
            db.set_state(DEFAULTS, {**(db.get_state(DEFAULTS) or {}), platform: rows[0]["release_id"]})
            note_awaiting(db)
        return
    sync(db)


def ensure_fleet(db: DB):
    """ensure() for every platform of the fleet (oarbankd's background loop: also after an upgrade, before any hello)."""
    if any_module_enabled(db):
        for plat in platforms.fleet_platforms(db):
            ensure(db, plat)


DEFAULTS = "release_defaults"          # setting: {platform: the release_id sync last built as its default}
AWAITING = "releases_awaiting"         # setting: awaiting(), as the console shows it


def awaiting(db: DB) -> list[dict]:
    """The releases only the owner can let through: each platform's default release that is not current yet, and the
    node-specific releases (canary, pinned) nodes are assigned, while they lack the owner's signature. Each names the
    command that lets it through: `oarbank release sign <rid> --promote` for a platform's release, without `--promote`
    for a node's own (promoting it would make it every node's)."""
    if not signature_required(db):
        return []
    out = []
    fleet = set(platforms.fleet_platforms(db))
    for plat, rid in sorted((db.get_state(DEFAULTS) or {}).items()):
        row = db.one("SELECT status, signature, created_at, composition_json FROM releases WHERE release_id=?", (rid,))
        if plat not in fleet or not row or row["status"] == "current":
            continue
        nodes = [n for n in db.q("SELECT node_id, hostname, platform, facts_json FROM nodes WHERE lifecycle NOT IN ('retired') "
                                 "AND assigned_release IS NULL ORDER BY hostname") if platforms.node_platform(n) == plat]
        out.append({"release_id": rid, "platform": plat, "kind": "platform", "signed": bool(row["signature"]),
                    "since": row["created_at"], "modules": contents(row["composition_json"]), "nodes": [n["hostname"] for n in nodes], "node_ids": [n["node_id"] for n in nodes],
                    "command": f"oarbank release sign {rid} --promote"})
    by_rid = {}
    for n in db.q("SELECT n.node_id, n.hostname, n.assigned_release rid, r.platform, r.created_at, r.composition_json FROM nodes n "
                  "JOIN releases r "
                  "ON r.release_id=n.assigned_release WHERE n.lifecycle NOT IN ('retired') AND r.signature IS NULL ORDER BY n.hostname"):
        e = by_rid.setdefault(n["rid"], {"release_id": n["rid"], "platform": n["platform"], "kind": "node", "signed": False,
                                         "since": n["created_at"], "modules": contents(n["composition_json"]),
                                         "nodes": [], "node_ids": [],
                                         "command": f"oarbank release sign {n['rid']}"})
        e["nodes"].append(n["hostname"])
        e["node_ids"].append(n["node_id"])
    return out + list(by_rid.values())


def awaiting_text(a: dict) -> str:
    """One awaiting release as the alert and the console say it."""
    k = len(a["nodes"])
    held = (f"Until then the canary or pinned node{'s' if k != 1 else ''} {', '.join(a['nodes'])} stay{'' if k != 1 else 's'} "
            "on what they run." if a["kind"] == "node" else
            f"Until then its {k} node{'s' if k != 1 else ''} get{'' if k != 1 else 's'} nothing new." if k else "")
    holds = ", ".join(a.get("modules") or []) or "no module"
    none = ("" if a.get("modules") else f" None of the enabled modules runs on {a['platform']}, but its nodes need this "
            "release to become ready.")
    return (f"Release {a['release_id']} for {a['platform']} ({holds}) is waiting for the owner's signature: run "
            f"`{a['command']}` on the machine that holds the owner key.{none} {held}").rstrip()


def note_awaiting(db: DB) -> list[dict]:
    """Record awaiting() for the console (written only when it changed) and keep one `release_awaiting_owner:<rid>`
    alert open per awaiting release; the others resolve (signed and promoted, or replaced by a newer build)."""
    from .core import _alert, _resolve_alert
    items = awaiting(db)
    if (db.get_state(AWAITING) or []) != items:
        db.set_state(AWAITING, items)
    want = {f"release_awaiting_owner:{a['release_id']}": a for a in items}
    for al in db.q("SELECT rule, subject FROM alerts WHERE rule LIKE 'release_awaiting_owner:%' AND state IN ('open','pending')"):
        if al["rule"] not in want:
            _resolve_alert(db, al["rule"], al["subject"])
    for rule, a in want.items():
        subject, text = f"platform:{a['platform']}", awaiting_text(a)
        _alert(db, rule, subject, text)
        db.x("UPDATE alerts SET detail=? WHERE rule=? AND subject=? AND state IN ('open','pending') AND detail!=?",
             (text, rule, subject, text))         # the nodes it holds back change as machines join
    return items


def node_release(db: DB, node: dict) -> dict:
    """Where a node stands with its release, in words as well: {state, release, platform, text}. States: `installed`
    (it runs the release it is assigned), `installing` (assigned one it does not run yet), `unsigned` (the release it
    needs waits for the owner's signature), `none` (no release for its platform: no module is enabled yet)."""
    plat = platforms.node_platform(node)
    rid = assigned(db, node)
    runs = f" (runs {node['release_id']})" if node.get("release_id") and node.get("release_id") != rid else ""
    if rid:
        row = db.one("SELECT signature FROM releases WHERE release_id=?", (rid,)) or {}
        if signature_required(db) and not row.get("signature"):
            return {"state": "unsigned", "release": rid, "platform": plat, "text": f"waiting for signature: {rid}{runs}"}
        if node.get("release_id") == rid:
            return {"state": "installed", "release": rid, "platform": plat, "text": rid}
        return {"state": "installing", "release": rid, "platform": plat, "text": f"installing {rid}{runs}"}
    waiting = (db.get_state(DEFAULTS) or {}).get(plat) if plat else None
    row = db.one("SELECT status FROM releases WHERE release_id=?", (waiting,)) if waiting else None
    if row and row["status"] == "candidate" and signature_required(db):
        return {"state": "unsigned", "release": waiting, "platform": plat,
                "text": f"waiting for signature: {waiting}{runs}"}
    return {"state": "none", "release": None, "platform": plat,
            "text": "none yet (no module enabled)" if not any_module_enabled(db) else "none yet (building)"}


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
    note_awaiting(db)
    return {"release_id": release_id, "seq": int(s["seq"])}


def promote(db: DB, release_id: str, actor: str):
    """Make a release current for its platform."""
    row = db.one("SELECT signature, platform FROM releases WHERE release_id=?", (release_id,))
    if not row:
        raise ReleaseRefused(f"unknown release {release_id}")
    if C.RELEASE_SIGNING and db.get_state("release_pubkey") and not row["signature"]:
        raise ReleaseRefused(f"{release_id} is unsigned; agents pinned to the release key would refuse it")
    with db.tx():
        db.x("UPDATE releases SET status='retired' WHERE status='current' AND platform=?", (row["platform"],))
        db.x("UPDATE releases SET status='current' WHERE release_id=?", (release_id,))
    db.event("release_promoted", actor=actor, reason=release_id)
    if actor != "build":                  # a build in sync() notes once, after every platform
        note_awaiting(db)
