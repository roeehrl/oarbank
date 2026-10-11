"""The module sandbox on the coordinator side, and the approval of a module version's sandbox grants
(oarbank-sdk spec/sandbox.md).

Every module coordinator process runs under a Seatbelt profile: its bundle (with its `.venv`), the interpreter and
the SDK read-only; `<home>/modules/data/<name>` and `<home>/tmp/modules/<name>` read-write; no network, no host
paths, no GPU (verbs are pure and reach state only through host callbacks). The module host refuses a process that
is not confined after its handshake.

Node-side grants (`[sandbox]`: network, host tools, GPU, written-file execution, containers, folders) are approved per module version by an operator.
A version that requests anything cannot be enabled, canaried, pinned or promoted until its exact requests (by digest)
are approved. Releases then carry the approved grants to agents, which enforce them.
"""
import hashlib
import json
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
    from ..platform import files
    for d in (data, tmp, profile_dir(home)):
        if not d.is_dir():                        # once: on Windows the sandbox adds the module's own entry after
            files.private_dir(d)
    from .modulehost import module_python
    py = module_python(bundle)                    # the bundle's .venv interpreter (a symlink chain) or the host's
    return S.Policy(module=module_id, ro=[str(bundle), *S.interpreter_roots(), py], rw=[str(data), str(tmp)],
                    kind="coordinator", exe=py)


def coordinator_env(home: Path, name: str) -> dict:
    from oarbank_sdk import portable
    data, tmp = data_dir(home, name), tmp_dir(home, name)
    return {**portable.os_env(data, tmp), "OARBANK_MODULE_DATA": str(data), "OARBANK_MODULE_NAME": name,
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
    not support the node's platform or OS version, needs host tools that do not resolve on the node, needs sandbox
    capabilities the node's backend does not enforce, needs a newer agent (`requires.agent`), or whose runner needs a
    GPU API the node's host does not provide (its doctor's `gpu_apis`)."""
    from . import modcalls, modstore
    facts = json.loads(node.get("facts_json") or "{}")
    if REQUIRE_SANDBOXED_AGENTS and not (facts.get("sandbox") or {}).get("backend"):
        return {m: "SANDBOX_BACKEND_MISSING" for m in offered}
    out = {}
    for name in offered:
        ver = modstore.version_for_node(db, name, node.get("node_id"))
        try:
            man = modcalls.info_for(name, ver).manifest
        except KeyError:
            continue
        why = exclusion(db, man, node, name)
        if why:
            out[name] = why
    return out


def exclusion(db: DB, man, node: dict, name: str = "") -> str | None:
    """Why this module version (its manifest) must not get work on this node (a reason code), or None: node_exclusions
    for one manifest, also for a version the module host has not loaded (the readiness checklist)."""
    from . import modstore, platforms
    facts = json.loads(node.get("facts_json") or "{}")
    if REQUIRE_SANDBOXED_AGENTS and not (facts.get("sandbox") or {}).get("backend"):
        return "SANDBOX_BACKEND_MISSING"
    have = node.get("agent_version") or ""
    why = platforms.unsupported(db, man, node, name)
    if not why and REQUIRE_SANDBOXED_AGENTS and platforms.sandbox_gaps(man, facts):
        why = "CAPABILITY_NOT_ENFORCED"
    if not why and man.requires.agent and (not have or not modstore.in_range(have, man.requires.agent)):
        why = "AGENT_TOO_OLD"
    if not why and runner_gpu_unmet(man, node):
        why = "GPU_API_MISSING"
    return why


def runner_gpu_unmet(manifest, node: dict) -> dict | None:
    """The runner's GPU API group on the node's platform when the node's host provides none of its APIs (every stage
    needs it, so the module cannot run there at all), else None."""
    from oarbank_sdk import gpu
    from . import predicates
    need = manifest.runner_gpu_need(node["platform"]) if node.get("platform") else None
    if need is None or need["where"] != "host":
        return None
    return need if gpu.unmet([need], predicates.node_gpu_apis(node)) else None


BOOTSTRAP_GRANTS = "grants.bootstrap"    # spec/sandbox.md, "Bootstrap jobs": the agent narrows a bootstrap job's grants


def bootstrap_enforced(node: dict) -> bool:
    """Whether the node's agent runs bootstrap jobs with the bootstrap grants (its facts' sandbox.enforcement); an older
    agent would give them the module's full grants, so it never gets one."""
    if not REQUIRE_SANDBOXED_AGENTS:
        return True
    from . import platforms
    return platforms.enforcement(json.loads(node.get("facts_json") or "{}")).get(BOOTSTRAP_GRANTS) == "enforced"


def exclusion_reasons(db: DB, node: dict, excluded: dict) -> dict:
    """{module: words for the exclusion}: the module's own reason for PLATFORM_UNSUPPORTED (requires.unsupported.runner,
    by the node's platform, then its OS), for GPU_API_MISSING what its runner needs and what the node provides, and for
    TOOL_NOT_FOUND, TOOL_VERSION_UNMET and TOOL_REFUSED the tool and what the node found ("jdk >=17: found 11.0.2 at
    /usr/lib/jvm/java-11; needs >=17")."""
    from oarbank_sdk import gpu, platform as pf
    from . import modcalls, modstore, platforms, predicates, tools
    plat, out = platforms.node_platform(node), {}
    for name, code in excluded.items():
        try:
            man = modcalls.info_for(name, modstore.version_for_node(db, name, node.get("node_id"))).manifest
        except KeyError:
            continue
        why = pf.resolve(man.requires.unsupported.runner, plat) if code == "PLATFORM_UNSUPPORTED" and plat else None
        if code in tools.CODES.values():
            miss = tools.unmet(db, man, node, name)
            why = miss[1] if miss else None
        need = runner_gpu_unmet(man, node) if code == "GPU_API_MISSING" else None
        if need:
            have = predicates.node_gpu_apis(node)["host"]
            why = f"its runner needs {gpu.describe(need)}; this node provides {', '.join(have) or 'no GPU API'}"
        if why:
            out[name] = why
    return out


def node_excluded(db: DB, node: dict, offered: set) -> set:
    """The modules no job of which may run on this node: node_exclusions without those that spare some stages
    (predicates.SPARED: a host tool that does not resolve, an unmapped folder), which claim's predicates decide per job."""
    from .predicates import SPARED
    return {m for m, code in node_exclusions(db, node, offered).items() if code not in SPARED}


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
           "tools": sorted(({"id": t.id, "trust": t.trust, **({"version": t.version} if t.version else {}),
                             **({"arch": t.arch} if t.arch != "any" else {})} for t in sb.tools), key=lambda t: t["id"]),
           "devices": {"gpu": sb.devices.gpu}, "exec_writable": sb.exec_writable,
           "containers": sorted(({"image": c.image, "platform": c.platform} for c in sb.containers), key=lambda c: c["image"])}
    if sb.container_sets:
        out["container_sets"] = modimages.set_requests(manifest, bundle)
    if any("gpu" in s.requires.pools for s in manifest.stages):
        out["container_gpu"] = True
    if sb.folders:
        out["folders"] = sorted(({"id": f.id, "access": f.access} for f in sb.folders), key=lambda f: f["id"])
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
    db.event("module_grants_approved", actor=actor, reason=f"{name} {version}: {describe(st['requests'])}"[:300], module=name)
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
        out.append("host tools " + ", ".join(
            t["id"] + (f" {t['version']}" if t.get("version") else "") + "".join(
                f" ({w})" for w in ([t["arch"]] if t.get("arch") else []) + (["runs code"] if t["trust"] == "code-exec" else []))
            for t in req["tools"]))
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
    for f in req.get("folders") or []:
        out.append(f"reads folder {f['id']} (on Windows its files are executable)" if f["access"] == "read" else
                   f"writes into folder {f['id']} (files it creates may replace files there)")
    return "; ".join(out)
