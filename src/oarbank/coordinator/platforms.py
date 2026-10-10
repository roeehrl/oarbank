"""Platforms in the coordinator (spec/platforms.md): which platform a node is, and whether a module version can run there.

A node reports its facts (format 2) in its hello: `platform {os, arch, os_version, os_build, kernel, distro, libc}`, `cpu`, `memory`,
`gpus`, `addresses`. The platform token is `<os>-<arch>`. A module version runs on a node only when its manifest lists
that platform (`requires.platforms`), the node's OS version is in `requires.os`, every host tool it asks for resolves to
an installation the node detected (tools.py), and the node provides every folder it asks for. Anything else is
refused with a reason code the explainer shows.
"""
import json

from oarbank_sdk import portable

from .db import DB

DEFAULT_PLATFORM = "darwin-arm64"       # the release built before any node has said what it is


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


def unsupported(db: DB, manifest, node: dict, name: str = "") -> str | None:
    """Why this module version (of module `name`) cannot run on this node (a reason code), or None. A host tool that
    does not resolve there is TOOL_NOT_FOUND, TOOL_VERSION_UNMET or TOOL_REFUSED (tools.unmet)."""
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
    from . import tools
    miss = tools.unmet(db, manifest, node, name)
    if miss:
        return miss[0]
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
