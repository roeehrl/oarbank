"""The module sandbox on the coordinator side, and the approval of a module version's sandbox grants
(oarbank-sdk spec/sandbox.md).

Every module coordinator process runs under a Seatbelt profile: its bundle (with its `.venv`), the interpreter and
the SDK read-only; `<home>/modules/data/<name>` and `<home>/tmp/modules/<name>` read-write; no network, no host
paths, no GPU (verbs are pure and reach state only through host callbacks). The module host refuses a process that
is not confined after its handshake.

Node-side grants (`[sandbox]`: network, host tools, GPU, written-file execution, containers) are approved per module version by an operator.
A version that requests anything cannot be enabled, canaried, pinned or promoted until its exact requests (by digest)
are approved. Releases then carry the approved grants to agents, which enforce them.
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from .db import DB


class GrantError(ValueError):
    pass


class NoBackend(RuntimeError):
    """This OS has no module sandbox backend in the coordinator yet: module processes do not run unconfined."""


def backend() -> str | None:
    """The coordinator's sandbox backend for module processes on this OS (spec/sandbox.md; sandboxexec.py); None:
    none here."""
    from . import sandboxexec
    return sandboxexec.backend()


def data_dir(home: Path, name: str) -> Path:
    return Path(home) / "modules" / "data" / name


def tmp_dir(home: Path, name: str) -> Path:
    return Path(home) / "tmp" / "modules" / name


def profile_dir(home: Path) -> Path:
    return Path(home) / "run" / "sandbox"


def coordinator_policy(home: Path, name: str, module_id: str, bundle: Path):
    """The coordinator process's policy. Creates its directories. Without a backend on this OS it returns a NoBackend,
    which the module host refuses to start: never unconfined."""
    if backend() is None:
        return NoBackend(f"no module sandbox backend on {sys.platform} yet: {module_id} cannot run on this coordinator")
    from oarbank_sdk import sandbox as S
    data, tmp = data_dir(home, name), tmp_dir(home, name)
    for d in (data, tmp, profile_dir(home)):
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
    from .modulehost import module_python
    py = module_python(bundle)                    # the bundle's .venv interpreter (a symlink chain) or the host's
    return S.Policy(module=module_id, ro=[str(bundle), *S.interpreter_roots(), py], rw=[str(data), str(tmp)],
                    kind="coordinator", exe=py)


def coordinator_env(home: Path, name: str) -> dict:
    from oarbank_sdk import portable
    data, tmp = data_dir(home, name), tmp_dir(home, name)
    return {"HOME": str(data), "TMPDIR": str(tmp) + "/", "OARBANK_MODULE_DATA": str(data), "OARBANK_MODULE_NAME": name,
            "OARBANK_PLATFORM": portable.host_platform(), "PYTHONDONTWRITEBYTECODE": "1"}


def coordinator_spec(home: Path, name: str, manifest, bundle: Path, key: str | None = None):
    """How the module host runs a module's coordinator side on this coordinator: [coordinator] with the variant for this
    platform applied (exec, runtime, timeouts, concurrency, env), the module's env under the host's own variables, in
    its sandbox. `key` is the process name (name@version for a version that is not current)."""
    from oarbank_sdk import portable
    from .modulehost import ModuleSpec
    c = manifest.coordinator.for_platform(portable.host_platform())
    return ModuleSpec(name=key or name, argv=list(c.exec), cwd=str(bundle), env={**c.env, **coordinator_env(home, name)},
                      timeouts_s=dict(c.timeouts_s), concurrency=c.concurrency, permissions=set(c.permissions),
                      sandbox=coordinator_policy(home, name, manifest.module.id, bundle), profile_dir=str(profile_dir(home)))


# ------------------------------------------------------------------ which nodes may run module jobs

REQUIRE_SANDBOXED_AGENTS = True        # the core's own test suite turns this off for its synthetic agents


def node_exclusions(db: DB, node: dict, offered: set) -> dict:
    """{module: reason code} for the modules this node must not get work for (spec/sandbox.md "Placement",
    spec/platforms.md): every module when its agent has no sandbox backend; a module whose version for the node does
    not support the node's platform or OS version, needs host tools the registry lacks for the node's OS, needs sandbox
    capabilities the node's backend does not enforce, or needs a newer agent (`requires.agent`)."""
    from . import modcalls, modstore, platforms
    facts = json.loads(node.get("facts_json") or "{}")
    if REQUIRE_SANDBOXED_AGENTS and not (facts.get("sandbox") or {}).get("backend"):
        return {m: "SANDBOX_BACKEND_MISSING" for m in offered}
    out = {}
    have = node.get("agent_version") or ""
    for name in offered:
        ver = modstore.version_for_node(db, name, node.get("node_id"))
        try:
            man = modcalls.info_for(name, ver).manifest
        except KeyError:
            continue
        why = platforms.unsupported(db, man, node)
        if not why and REQUIRE_SANDBOXED_AGENTS and platforms.sandbox_gaps(man, facts):
            why = "CAPABILITY_NOT_ENFORCED"
        if not why and man.requires.agent and (not have or not modstore.in_range(have, man.requires.agent)):
            why = "AGENT_TOO_OLD"
        if why:
            out[name] = why
    return out


BOOTSTRAP_GRANTS = "grants.bootstrap"    # spec/sandbox.md, "Bootstrap jobs": the agent narrows a bootstrap job's grants


def bootstrap_enforced(node: dict) -> bool:
    """Whether the node's agent runs bootstrap jobs with the bootstrap grants (its facts' sandbox.enforcement); an older
    agent would give them the module's full grants, so it never gets one."""
    if not REQUIRE_SANDBOXED_AGENTS:
        return True
    enf = ((json.loads(node.get("facts_json") or "{}").get("sandbox") or {}).get("enforcement") or {})
    return enf.get(BOOTSTRAP_GRANTS) == "enforced"


def exclusion_reasons(db: DB, node: dict, excluded: dict) -> dict:
    """{module: the module's own reason} for the PLATFORM_UNSUPPORTED exclusions it explains
    (requires.unsupported.runner, by the node's platform, then its OS)."""
    from oarbank_sdk import platform as pf
    from . import modcalls, modstore, platforms
    plat, out = platforms.node_platform(node), {}
    for name, code in excluded.items():
        try:
            man = modcalls.info_for(name, modstore.version_for_node(db, name, node.get("node_id"))).manifest
        except KeyError:
            continue
        why = pf.resolve(man.requires.unsupported.runner, plat) if code == "PLATFORM_UNSUPPORTED" and plat else None
        if why:
            out[name] = why
    return out


def node_excluded(db: DB, node: dict, offered: set) -> set:
    return set(node_exclusions(db, node, offered))


# ------------------------------------------------------------------ approvals of node-side grants

def requests(manifest, bundle) -> dict:
    """A manifest's sandbox requests, canonical (empty dict: nothing to approve). Container sets are approved by their
    prefix and their key's fingerprint (read from the bundle), never by a list of digests; GPU passthrough to containers
    (a stage reserving the agent's `gpu` pool) is a request of its own."""
    sb = getattr(manifest, "sandbox", None)
    if sb is None or not sb.requests():
        return {}
    from . import modimages
    out = {"contract": sb.contract, "net": {"mode": sb.net.mode, "allow": sorted(sb.net.allow)},
           "tools": sorted(({"id": t.id, "trust": t.trust} for t in sb.tools), key=lambda t: t["id"]),
           "devices": {"gpu": sb.devices.gpu}, "exec_writable": sb.exec_writable,
           "containers": sorted(({"image": c.image, "platform": c.platform} for c in sb.containers), key=lambda c: c["image"])}
    if sb.container_sets:
        out["container_sets"] = modimages.set_requests(manifest, bundle)
    if any("gpu" in s.requires.pools for s in manifest.stages):
        out["container_gpu"] = True
    return out


def digest(req: dict) -> str:
    return hashlib.sha256(json.dumps(req, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _manifest(db: DB, name: str, version: str):
    """(manifest, bundle directory) of an installed version."""
    from oarbank_sdk import manifest as mf
    r = db.one("SELECT path FROM modules WHERE name=? AND version=?", (name, version))
    if not r:
        raise GrantError(f"{name} {version} is not installed")
    return mf.load(db.abs(r["path"]) / "oarbank-module.toml"), db.abs(r["path"])


def approval(db: DB, name: str, version: str) -> dict | None:
    r = db.one("SELECT * FROM module_grants WHERE name=? AND version=?", (name, version))
    return {**r, "requests": json.loads(r["requests_json"])} if r else None


def status(db: DB, name: str, version: str) -> dict:
    """{requests, digest, approved} for one version (approved is True when nothing is requested)."""
    req = requests(*_manifest(db, name, version))
    a = approval(db, name, version)
    return {"requests": req, "digest": digest(req) if req else None,
            "approved": not req or bool(a and a["digest"] == digest(req)), "approval": a}


def require_approved(db: DB, name: str, version: str):
    st = status(db, name, version)
    if not st["approved"]:
        raise GrantError(f"{name} {version} requests sandbox grants that are not approved yet: "
                         f"{describe(st['requests'])} (oarbank module approve {name}@{version})")


def approve(db: DB, name: str, version: str, actor: str, reason: str | None) -> dict:
    st = status(db, name, version)
    if not st["requests"]:
        raise GrantError(f"{name} {version} requests no sandbox grants")
    db.x("INSERT INTO module_grants(name,version,requests_json,digest,approved_by,approved_at,reason) VALUES(?,?,?,?,?,?,?) "
         "ON CONFLICT(name,version) DO UPDATE SET requests_json=excluded.requests_json, digest=excluded.digest, "
         "approved_by=excluded.approved_by, approved_at=excluded.approved_at, reason=excluded.reason",
         (name, version, json.dumps(st["requests"], sort_keys=True), st["digest"], actor, time.time(), reason))
    db.event("module_grants_approved", actor=actor, reason=f"{name} {version}: {describe(st['requests'])}"[:300])
    return {"name": name, "version": version, "digest": st["digest"], "requests": st["requests"]}


def describe(req: dict) -> str:
    if not req:
        return "nothing"
    out = []
    net = req.get("net") or {}
    if net.get("mode") == "egress-allowlist":
        out.append("network egress to " + ", ".join(net.get("allow") or []))
    elif net.get("mode") == "egress-any":
        out.append("network egress to ANY public address (full trust)")
    elif net.get("mode") not in (None, "none"):
        out.append(f"network mode {net['mode']}")
    if req.get("tools"):
        out.append("host tools " + ", ".join(t["id"] + (" (runs code)" if t["trust"] == "code-exec" else "") for t in req["tools"]))
    if (req.get("devices") or {}).get("gpu", "none") != "none":
        out.append(f"GPU {req['devices']['gpu']}")
    if req.get("exec_writable"):
        out.append("execute written files")
    if req.get("containers"):
        out.append("containers " + ", ".join(f"{c['image'].split('@')[0]} ({c['platform']})" for c in req["containers"]))
    for s in req.get("container_sets") or []:
        out.append(f"container images under {s['registry']}/{s['repository']} ({s['platform']}) signed by key "
                   f"SHA256:{s['key_sha256'][:16]}" + (f", listed in index {s['index']}" if s.get("index") else ""))
    if req.get("container_gpu"):
        out.append("GPU passthrough to containers")
    return "; ".join(out)
