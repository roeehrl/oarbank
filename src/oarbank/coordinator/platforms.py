"""Platforms in the coordinator (spec/platforms.md): which platform a node is, and whether a module version can run there.

A node reports its facts (format 2) in its hello: `platform {os, arch, os_version, os_build, kernel, distro, libc}`, `cpu`, `memory`,
`gpus`, `addresses`. The platform token is `<os>-<arch>`. A module version runs on a node only when its manifest lists
that platform (`requires.platforms`), the node's OS version is in `requires.os`, and every host tool it was approved
for is in the operator's tool registry for that OS, and the node provides every folder it asks for. Anything else is
refused with a reason code the explainer shows.
"""
import json
import re

from oarbank_sdk import portable

from .db import DB

DEFAULT_PLATFORM = "darwin-arm64"       # the release built before any node has said what it is
TOOL_REGISTRY = "tool_registry"          # setting: {id: {"paths": {os: [abs paths]}}} (trust is the module request's)


def facts_platform(facts: dict) -> dict:
    """{platform, os, arch, os_version} from hello facts (empty values when the agent did not say)."""
    p = (facts or {}).get("platform") or {}
    os_, arch = p.get("os"), p.get("arch")
    tok = f"{os_}-{arch}" if os_ and arch else None
    return {"platform": tok if tok and portable.is_platform_token(tok) else None, "os": os_, "arch": arch,
            "os_version": p.get("os_version")}


def cores(facts: dict) -> int:
    cpu = (facts or {}).get("cpu") or {}
    return int(cpu.get("logical") or (cpu.get("perf_cores") or 0) + (cpu.get("eff_cores") or 0))


def memory_gb(facts: dict) -> float:
    return float((facts or {}).get("memory_gb") or 0)


def os_version(facts: dict) -> str | None:
    return ((facts or {}).get("platform") or {}).get("os_version")


def node_platform(node: dict) -> str | None:
    if node.get("platform"):
        return node["platform"]
    return facts_platform(json.loads(node.get("facts_json") or "{}"))["platform"]


def _ver_in(version: str | None, spec: str | None) -> bool:
    if not spec:
        return True
    if not version:
        return False
    from .modstore import in_range
    try:
        return in_range(version, spec)
    except ValueError:
        return False


TOOL_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_WIN_ABS = re.compile(r"^[A-Za-z]:\\[^*?\"<>|]*$")


def check_tool(tool_id: str, entry: dict) -> dict:
    """A registry entry, normalized: {"paths": {os: [absolute paths]}}. Paths are whole directories or files (no globs),
    absolute for their OS; a path may not be a filesystem root. Trust is not the registry's: the module's request
    declares it, the owner approves it with the request set, and the release carries it."""
    if not TOOL_ID.fullmatch(tool_id or ""):
        raise ValueError(f"tool id {tool_id!r}: lower-case letters, digits, '_', '.', '-'")
    extra = set(entry) - {"paths"}
    if extra:
        raise ValueError(f"a tool entry has paths only, not {sorted(extra)} (trust is the module's request)")
    out = {}
    for os_, ps in (entry.get("paths") or {}).items():
        if os_ not in portable.OSES:
            raise ValueError(f"paths: unknown OS {os_!r} ({', '.join(portable.OSES)})")
        clean = []
        for p in ([ps] if isinstance(ps, str) else ps or []):
            p = (p or "").strip()
            if not p:
                continue
            ok = _WIN_ABS.fullmatch(p) if os_ == "windows" else p.startswith("/") and "\x00" not in p
            if not ok or any(c in p for c in "*?[") or p.rstrip("/\\") in ("", "/") or re.fullmatch(r"[A-Za-z]:\\?", p):
                raise ValueError(f"paths.{os_}: {p!r} is not an absolute path to a directory or file (no globs, not a root)")
            if "/../" in p + "/" or "\\..\\" in p + "\\":
                raise ValueError(f"paths.{os_}: {p!r} contains '..'")
            clean.append(p)
        if clean:
            out[os_] = sorted(set(clean))
    return {"paths": out}


def tool_registry(db: DB) -> dict:
    from .settings import fleet_value
    return fleet_value(db, TOOL_REGISTRY) or {}


def tool_paths(db: DB, tool_ids, os_: str) -> tuple[list[str], list[str]]:
    """(paths, missing ids) for the approved tools on one OS."""
    reg, paths, missing = tool_registry(db), [], []
    for t in tool_ids:
        p = ((reg.get(t) or {}).get("paths") or {}).get(os_) or []
        if p:
            paths += list(p)
        else:
            missing.append(t)
    return paths, missing


def sandbox_needs(manifest) -> list[str]:
    """The sandbox capabilities a module needs enforced where it runs (spec/sandbox.md, "Placement"). Every module needs
    the always-on rules; grants add their own capability names. Denying execution of written files
    (`exec_writable = false`) is best effort: Windows cannot enforce it without application control. A module with an
    endpoint service needs an agent that hands out service endpoints (`endpoints`, docs/design/service-endpoints.md)."""
    sb = manifest.sandbox
    need = ["filesystem", "ipc", f"net.{sb.net.mode}"]
    if sb.net.mode != "none":
        need.append("no_loopback")
    if sb.devices.gpu != "none":
        need.append(f"gpu.{sb.devices.gpu}")
    if any(s.endpoint for s in manifest.services):
        need.append("endpoints")
    return need + sorted({f"folders.{f.access}" for f in sb.folders})


def enforcement(facts: dict) -> dict:
    """The node's sandbox enforcement per capability, as its facts report it."""
    return ((facts or {}).get("sandbox") or {}).get("enforcement") or {}


def sandbox_gaps(manifest, facts: dict) -> list[str]:
    """Sandbox capabilities this module needs that the node's backend does not enforce."""
    enf = enforcement(facts)
    return [c for c in sandbox_needs(manifest) if enf.get(c) != "enforced"]


def unsupported(db: DB, manifest, node: dict) -> str | None:
    """Why this module version cannot run on this node (a reason code), or None."""
    facts = json.loads(node.get("facts_json") or "{}")
    fp = facts_platform(facts)
    plat = node.get("platform") or fp["platform"]
    if not plat or plat not in manifest.requires.platforms:
        return "PLATFORM_UNSUPPORTED"
    os_ = portable.split_platform(plat)[0]
    req = manifest.requires.os
    if req is not None:
        if os_ == "darwin" and not _ver_in(fp["os_version"], req.darwin):
            return "OS_VERSION_UNSUPPORTED"
        if os_ == "windows" and not _ver_in(fp["os_version"], req.windows):
            return "OS_VERSION_UNSUPPORTED"
        if os_ == "linux" and req.linux is not None:
            pf = facts.get("platform") or {}
            if not _ver_in(pf.get("kernel"), req.linux.kernel) or not _ver_in(pf.get("libc_version"), req.linux.glibc):
                return "OS_VERSION_UNSUPPORTED"
    _, missing = tool_paths(db, [t.id for t in manifest.sandbox.tools], os_)
    if missing:
        return "TOOL_UNAVAILABLE"
    from . import folders
    if folders.missing(manifest, node):
        return "FOLDER_UNAVAILABLE"
    return None


def fleet_platforms(db: DB) -> list[str]:
    """Platforms of the nodes that are not retired (the platforms releases are built for)."""
    out = set()
    for n in db.q("SELECT platform, facts_json FROM nodes WHERE lifecycle NOT IN ('retired')"):
        p = n["platform"] or facts_platform(json.loads(n["facts_json"] or "{}"))["platform"]
        if p:
            out.add(p)
    return sorted(out) or [DEFAULT_PLATFORM]
