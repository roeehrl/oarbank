"""Host tools (docs/design/host-tools.md): detected on the node, defined at the fleet, pinned per node, constrained per
module.

- **Definitions** are fleet objects: an id (`jdk`), a detector kind (`jdk`, `python`, or a generic `executable` with a
  version command and regex), the built-in search patterns per OS that ship with Oarbank (BUILTIN, mirrored from the
  agent's rust/crates/oarbank-agent/src/builtin_tools.json, which a test pins) and optional extra search patterns for
  every OS (`fleet`) or one platform group (`darwin`, `linux`, `windows`). `jdk` and `python` are built in; an admin
  adds extra patterns to them or defines more tools (`tools.define`). The release carries the definitions for its
  platform, never a path.
- **Detection** is the node's: the agent reports every installation it found (`tools_json`: canonical path, version,
  arch, vendor, source, status, detected_at), and is the source of truth for what exists.
- **Overrides** come in two kinds. Choosing among the installations the node found is an ordinary node-scope value
  `tool.<id>.path`, optionally module-qualified; it reaches the agent unsigned (`tool_pins` in its directives),
  because the agent grants only installations its own detector verified. Adding a path the node did not find is a
  grant decision: it travels in the node's signed statement (`oarbank.node/v1`, statements.py), where the agent
  applies its refusals and then the detector before it becomes an installation (source `override`).
- **Resolution** per node and module: a pin set for the module on the node, then one set for the node, then one for
  the node's platform group, then the fleet's, else the best detected match (native arch first, then the highest
  version satisfying the request). A tool that does not resolve keeps the module's jobs off the node, stage-scoped:
  TOOL_NOT_FOUND, TOOL_VERSION_UNMET or TOOL_REFUSED (predicates.SPARED: stages that need no certification get no
  tools and are spared).

The paths set for a tool are ordinary settings (docs/design/settings.md): the key family `tool.<id>.path`, at fleet,
group or node scope, optionally qualified by a module, written with `settings.apply` and resolved by the settings
resolver (`node_override`).
"""
import functools
import json
import re
import time

from oarbank_sdk import toolversion as tv

from .db import jl

KINDS = ("jdk", "python", "executable")
OSES = ("darwin", "linux", "windows")
OS_NAMES = {"darwin": "macOS", "linux": "Linux", "windows": "Windows"}
TOOL_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
CODES = {"not_found": "TOOL_NOT_FOUND", "version_unmet": "TOOL_VERSION_UNMET", "refused": "TOOL_REFUSED"}
REDETECT_EVERY_S = 3600               # the agent's slow timer (docs/design/host-tools.md)

# The built-in detector kinds with their search patterns per OS, as the agent ships them
# (rust/crates/oarbank-agent/src/builtin_tools.json, pinned by a test). Each is also a built-in tool of the same id; a
# tool an admin defines with kind jdk or python searches these patterns too, plus its own. Patterns: an absolute path
# whose components may hold `*` and `?`, or `$VAR` (optionally followed by a sub-path).
BUILTIN = {
    "jdk": {"kind": "jdk", "search": {
        "darwin": ["/opt/homebrew/opt/openjdk@*", "/opt/homebrew/opt/openjdk", "/usr/local/opt/openjdk@*", "/usr/local/opt/openjdk",
                   "/Library/Java/JavaVirtualMachines/*/Contents/Home", "$JAVA_HOME"],
        "linux": ["/usr/lib/jvm/*", "/usr/lib64/jvm/*", "/usr/java/*", "/opt/java/*", "/opt/jdk*",
                  "/home/linuxbrew/.linuxbrew/opt/openjdk@*", "$JAVA_HOME"],
        "windows": ["C:\\Program Files\\Eclipse Adoptium\\jdk-*", "C:\\Program Files\\Microsoft\\jdk-*",
                    "C:\\Program Files\\Zulu\\zulu-*", "C:\\Program Files\\Java\\jdk*", "C:\\Program Files\\Amazon Corretto\\jdk*",
                    "C:\\Program Files\\BellSoft\\LibericaJDK-*", "$JAVA_HOME"]}},
    "python": {"kind": "python", "version": {"args": ["--version"], "regex": "Python (\\d+(?:\\.\\d+)*)"}, "search": {
        "darwin": ["/opt/homebrew/bin/python3.?", "/opt/homebrew/bin/python3.??", "/usr/local/bin/python3.?",
                   "/usr/local/bin/python3.??", "/Library/Frameworks/Python.framework/Versions/3.*/bin/python3"],
        "linux": ["/usr/bin/python3.?", "/usr/bin/python3.??", "/usr/local/bin/python3.?", "/usr/local/bin/python3.??"],
        "windows": ["C:\\Program Files\\Python3*\\python.exe", "$LOCALAPPDATA\\Programs\\Python\\Python3*\\python.exe"]}},
}
JDK_LTS = (8, 11, 17, 21, 25)
PYTHONS = ("3.13", "3.12", "3.11", "3.10")


class ToolError(ValueError):
    pass


# ------------------------------------------------------------------------------------------------ definitions

_WIN_ABS = re.compile(r"^[A-Za-z]:\\")
_ENV = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*([/\\].*)?$")


def check_pattern(p: str) -> str:
    """A search pattern: an absolute path (POSIX or Windows) whose components may hold `*` and `?`, or `$VAR` with an
    optional sub-path. No `[`, `**` or `..`, no root, and the first directory is literal (no scan of a whole disk)."""
    p = (p or "").strip()
    if not p or "\x00" in p or "\n" in p:
        raise ToolError("a search pattern is a non-empty single line")
    if _ENV.fullmatch(p):
        rest = re.split(r"[/\\]", p, maxsplit=1)[1:] or [""]
        comps = [c for c in re.split(r"[/\\]", rest[0]) if c]
    elif p.startswith("/") or _WIN_ABS.match(p):
        comps = [c for c in re.split(r"[/\\]", p[3:] if _WIN_ABS.match(p) else p) if c]
        if not comps:
            raise ToolError(f"{p!r} is a filesystem root")
        if "*" in comps[0] or "?" in comps[0]:
            raise ToolError(f"{p!r}: its first directory must be literal (a pattern never scans a whole disk)")
    else:
        raise ToolError(f"{p!r} is neither an absolute path nor $VARIABLE[/sub/path]")
    if "[" in p or "**" in p:
        raise ToolError(f"{p!r}: only * and ? match (no [ ] or **)")
    if any(c == ".." for c in comps):
        raise ToolError(f"{p!r} contains '..'")
    return p


def _check_version_cmd(v) -> dict:
    if not isinstance(v, dict):
        raise ToolError("version: {args: [...], regex: \"...\"}")
    args = v.get("args") or []
    if not isinstance(args, list) or len(args) > 8 or not all(isinstance(a, str) and 0 < len(a) <= 64 and "\x00" not in a
                                                                 for a in args):
        raise ToolError("version.args: at most 8 arguments (strings up to 64 characters), e.g. [\"--version\"]")
    rx = v.get("regex") or ""
    if not isinstance(rx, str) or not 0 < len(rx) <= 200:
        raise ToolError("version.regex: a regular expression (up to 200 characters) whose first group is the version")
    if re.search(r"\(\?[=!]|\(\?<[=!]|\\[1-9]|\(\?P=", rx):
        raise ToolError("version.regex: no look-around or back-references (the agent's regex engine has none)")
    try:
        if re.compile(rx).groups > 1:
            raise ToolError("version.regex: at most one capture group (the version)")
    except re.error as e:
        raise ToolError(f"version.regex: {e}") from None
    return {"args": list(args), "regex": rx}


def check_definition(tool_id: str, params: dict) -> dict:
    """A definition as tools.define stores it: {kind, search: {fleet|darwin|linux|windows: [patterns]}, version?}."""
    if not TOOL_ID.fullmatch(tool_id or ""):
        raise ToolError(f"tool id {tool_id!r}: lower-case letters, digits, '_', '.', '-'")
    b = BUILTIN.get(tool_id)
    kind = params.get("kind") or (b["kind"] if b else "executable")
    if kind not in KINDS:
        raise ToolError(f"kind: {', '.join(KINDS)}")
    if b and kind != b["kind"]:
        raise ToolError(f"{tool_id} is built in (kind {b['kind']}): give it extra search paths only")
    search = {}
    for scope, ps in (params.get("search") or {}).items():
        if scope not in ("fleet", *OSES):
            raise ToolError(f"search: unknown scope {scope!r} (fleet, {', '.join(OSES)})")
        clean = sorted({check_pattern(p) for p in ([ps] if isinstance(ps, str) else ps or []) if (p or "").strip()})
        if len(clean) > 32:
            raise ToolError(f"search.{scope}: at most 32 patterns")
        if clean:
            search[scope] = clean
    out = {"kind": kind, "search": search}
    if kind == "executable":
        out["version"] = _check_version_cmd(params.get("version"))
        if not search:
            raise ToolError(f"{tool_id}: an executable tool needs search paths (where its file is on each OS)")
    return out


def definitions(r) -> dict:
    """{id: {id, kind, builtin, search (extras), builtin_search, version, updated_by, updated_at}}: the built-ins with
    their extras, and every tool an admin defined."""
    rows = {x["id"]: x for x in r.q("SELECT * FROM tool_defs ORDER BY id")}
    out = {}
    for tid in sorted(set(BUILTIN) | set(rows)):
        b, row = BUILTIN.get(tid), rows.get(tid)
        d = jl(row["detector_json"], {}) if row else {}
        kind = (b or {}).get("kind") or (row or {}).get("kind")
        k = BUILTIN.get(kind) or {}
        out[tid] = {"id": tid, "kind": kind, "builtin": bool(b),
                    "search": d.get("search") or {}, "builtin_search": k.get("search") or {},
                    "version": d.get("version") or k.get("version"),
                    "updated_by": (row or {}).get("updated_by"), "updated_at": (row or {}).get("updated_at")}
    return out


def define(db, tool_id: str, params: dict, actor: str) -> dict:
    entry = check_definition(tool_id, params)
    db.x("INSERT INTO tool_defs(id, kind, detector_json, updated_by, updated_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE "
         "SET kind=excluded.kind, detector_json=excluded.detector_json, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
         (tool_id, entry["kind"], json.dumps({k: v for k, v in entry.items() if k != "kind"}, sort_keys=True), actor, time.time()))
    return definitions(db)[tool_id]


def delete(db, tool_id: str) -> dict:
    if tool_id not in definitions(db):
        raise ToolError(f"no tool {tool_id!r}")
    db.x("DELETE FROM tool_defs WHERE id=?", (tool_id,))
    return {"tool": tool_id, "builtin": tool_id in BUILTIN}


def patterns(d: dict, os_: str) -> list[str]:
    """The extra patterns a definition adds on one OS (fleet-wide first, then the platform group's)."""
    return list(d["search"].get("fleet") or []) + list(d["search"].get(os_) or [])


def release_definitions(r, os_: str) -> dict:
    """The `tools` table of a release for one OS: every definition with its extra patterns there and, for an
    executable, its version command (the agent knows the built-in patterns and the jdk and python detectors itself)."""
    return {tid: {"kind": d["kind"], "search": patterns(d, os_), **({"version": d["version"]} if d["kind"] == "executable" else {})}
            for tid, d in definitions(r).items()}


# ------------------------------------------------------------------------------------------------ the node's report

def report(node: dict) -> dict:
    """The node's latest detection: {detected_at, native_arch, tools: {id: [installation]}} ({} before its first)."""
    return jl(node.get("tools_json"), {}) or {}


def native_arch(node: dict) -> str:
    rep = report(node)
    if rep.get("native_arch"):
        return tv.arch(rep["native_arch"])
    plat = node.get("platform") or ""
    return plat.split("-", 1)[1] if "-" in plat else ""


def installations(node: dict, tool_id: str) -> list[dict]:
    return list((report(node).get("tools") or {}).get(tool_id) or [])


def is_ok(inst: dict) -> bool:
    return inst.get("status") == "ok"


def requests(manifest) -> list[dict]:
    """[{id, version, arch, trust}] of a manifest (a Manifest, or the manifest dict the module store keeps)."""
    sb = manifest.get("sandbox") or {} if isinstance(manifest, dict) else manifest.sandbox
    ts = sb.get("tools") or [] if isinstance(sb, dict) else sb.tools
    out = []
    for t in ts:
        g = (lambda k, dflt=None: t.get(k, dflt)) if isinstance(t, dict) else (lambda k, dflt=None: getattr(t, k, dflt))
        v = g("version")
        out.append({"id": g("id"), "version": tv.describe(v) if v else None, "arch": g("arch") or "any",
                    "trust": g("trust") or "read"})
    return out


def need_text(req: dict) -> str:
    """`jdk >=17, <22 (native)`: a request in words."""
    return req["id"] + (f" {req['version']}" if req.get("version") else "") + \
        (f" ({req['arch']})" if req.get("arch") not in (None, "any") else "")


# ------------------------------------------------------------------------------------------------ overrides (settings)

def path_key(tool: str) -> str:
    return f"tool.{tool}.path"


def _snap(r, snap=None):
    from .settings import resolve as V
    return snap if snap is not None else V.snapshot(r)


def _path_rows(snap) -> list[dict]:
    from .settings import registry as R
    return [x for (scope, sid, m, k), x in snap.rows.items() if R.TOOL_PATH.fullmatch(k)]


def node_override(r, node: dict, tool: str, module: str = "", snap=None) -> dict | None:
    """The path set for `tool` (and `module`) where this node inherits it, or None: the settings resolver over
    `tool.<id>.path` (the module's chain above the plain one; within each the node, its groups, the fleet).
    {path, scope, scope_id, module, source}."""
    from .settings import resolve as V
    snap = _snap(r, snap)
    res = V.resolve(snap, node, path_key(tool), module)
    if not res["value"]:
        return None
    src = res["source"]
    return {"path": res["value"], "scope": src["scope"], "scope_id": src["id"], "module": src["module"],
            "source": V.badge(res)}


def found_paths(node: dict, tool: str) -> set:
    """The installations the node found itself (not the paths its statement adds): a path among them needs no
    signature."""
    return {i.get("path") for i in installations(node, tool) if is_ok(i) and i.get("source") != "override"}


def statement_tools(r, node_id: str, snap=None) -> list[dict]:
    """The tool paths set at node scope for one node that it did not find itself, as its signed statement carries them:
    [{id, module, path}]."""
    from .settings import registry as R
    snap = _snap(r, snap)
    node = r.one("SELECT node_id, tools_json FROM nodes WHERE node_id=?", (node_id,)) or {"node_id": node_id}
    out = []
    for x in _path_rows(snap):
        if x["scope"] != "node" or x["scope_id"] != node_id:
            continue
        tool = R.TOOL_PATH.fullmatch(x["key"]).group(1)
        if x["value"] and x["value"] not in found_paths(node, tool):
            out.append({"id": tool, "module": x["module"], "path": x["value"]})
    return sorted(out, key=lambda t: (t["id"], t["module"], t["path"]))


def node_values(r, node_id: str, snap=None) -> list[dict]:
    """The tool paths set on one node: [{tool, module, path, kind}] (kind: `choose`, an installation it found; `add`,
    in its signed statement)."""
    from .settings import registry as R
    snap = _snap(r, snap)
    node = r.one("SELECT node_id, tools_json FROM nodes WHERE node_id=?", (node_id,)) or {"node_id": node_id}
    out = []
    for x in _path_rows(snap):
        if x["scope"] == "node" and x["scope_id"] == node_id:
            tool = R.TOOL_PATH.fullmatch(x["key"]).group(1)
            out.append({"tool": tool, "module": x["module"], "path": x["value"], "key": x["key"],
                        "kind": "choose" if x["value"] in found_paths(node, tool) else "add"})
    return sorted(out, key=lambda v: (v["tool"], v["module"]))


def pins(r, node: dict, modules, snap=None) -> dict:
    """The `tool_pins` directive: {module: {tool: path}} with "" for a module without values of its own; the agent
    grants a pinned path only when it is an installation its detector verified."""
    from .settings import registry as R
    snap = _snap(r, snap)
    tools = sorted({R.TOOL_PATH.fullmatch(x["key"]).group(1) for x in _path_rows(snap)})
    out = {}
    for m in ["", *sorted(set(modules))]:
        got = {t: o["path"] for t in tools for o in [node_override(r, node, t, m, snap)] if o}
        if got and (m == "" or got != out.get("")):
            out[m] = got
    return out


# ------------------------------------------------------------------------------------------------ resolution

def _vcmp(a: dict, b: dict) -> int:
    """Compare two installations' versions (an unparseable version is the lowest)."""
    try:
        va = tv.version(a.get("version") or "")
    except ValueError:
        va = None
    try:
        vb = tv.version(b.get("version") or "")
    except ValueError:
        vb = None
    if va is None or vb is None:
        return (va is not None) - (vb is not None)
    return va.compare(vb)


def _order(insts: list[dict], native: str) -> list[dict]:
    """Best first: the node's native arch, then the highest version, then the path (ascending)."""
    def cmp(a, b):
        na, nb = tv.arch(a.get("arch")) == tv.arch(native), tv.arch(b.get("arch")) == tv.arch(native)
        if na != nb:
            return -1 if na else 1
        c = _vcmp(a, b)
        if c:
            return -c
        pa, pb = a.get("path") or "", b.get("path") or ""
        return (pa > pb) - (pa < pb)
    return sorted(insts, key=functools.cmp_to_key(cmp))


def _found(insts: list[dict], native: str, limit: int = 3) -> str:
    parts = [f"{i.get('version') or 'an unknown version'}"
             + (f" ({i['arch']})" if i.get("arch") and tv.arch(i["arch"]) != tv.arch(native) else "") + f" at {i.get('path')}"
             for i in sorted(insts, key=functools.cmp_to_key(lambda a, b: -_vcmp(a, b)))[:limit]]
    more = len(insts) - limit
    return ", ".join(parts) + (f" and {more} more" if more > 0 else "")


def _fits(inst: dict, req: dict, native: str) -> bool:
    return tv.satisfies(inst.get("version") or "", req.get("version")) and tv.arch_fits(inst.get("arch"), req.get("arch") or "any", native)


def _needs(req: dict, native: str) -> str:
    want = []
    if req.get("version"):
        want.append(req["version"])
    if req.get("arch") == "native":
        want.append(f"native {tv.arch(native) or 'arch'}")
    elif req.get("arch") not in (None, "any"):
        want.append(req["arch"])
    return ", ".join(want) or "any version"


def resolve(insts: list[dict], req: dict, native: str, pin: str | None = None) -> dict:
    """The installation a request resolves to on a node: {status: ok|not_found|version_unmet|refused, code (None when
    ok), installation, source (pinned|detected), detail}. Pure: the agent's rust implementation replays the same
    vectors (src/oarbank/contracts/vectors/tool-resolution.json). With a pin, only that installation counts; without,
    the node's native arch first, then the highest version that satisfies the request, then the path."""
    tid = req["id"]
    ok = [i for i in insts if is_ok(i)]

    def out(status, inst=None, detail="", source=None):
        return {"status": status, "code": CODES.get(status), "installation": inst, "source": source, "detail": detail}
    if pin:
        hit = next((i for i in insts if pin in (i.get("path"), i.get("given"))), None)
        if hit is None:
            return out("refused", detail=f"the path set for {tid} here, {pin}, is not an installation this node found "
                                         "(Re-detect, or set a path the node can verify)")
        if not is_ok(hit):
            return out("refused", hit, f"the path set for {tid} here, {pin}, was refused: "
                                       f"{(hit.get('status') or '').removeprefix('refused: ')}")
        if not _fits(hit, req, native):
            return out("version_unmet", hit, f"the path set for {tid} here is {hit.get('version') or 'an unknown version'}"
                                             f" at {hit.get('path')}; needs {_needs(req, native)}")
        return out("ok", hit, f"{hit.get('version') or 'an unknown version'} at {hit.get('path')} (set for this node)", "pinned")
    good = [i for i in ok if _fits(i, req, native)]
    if good:
        best = _order(good, native)[0]
        return out("ok", best, f"{best.get('version') or 'an unknown version'} at {best.get('path')}", "detected")
    if ok:
        return out("version_unmet", detail=f"found {_found(ok, native)}; needs {_needs(req, native)}")
    refused = [i for i in insts if not is_ok(i)]
    if refused:
        i = refused[0]
        return out("refused", i, f"{i.get('path')}: {(i.get('status') or '').removeprefix('refused: ')}")
    return out("not_found", detail=f"no {tid} found on this node")


def resolve_for(r, node: dict, module: str, req: dict, defs: dict | None = None) -> dict:
    """resolve() for one node and module: its report, the path set where it inherits one, an unknown tool id, a node
    that has not reported yet."""
    defs = definitions(r) if defs is None else defs
    if req["id"] not in defs:
        return {"status": "not_found", "code": "TOOL_NOT_FOUND", "installation": None, "source": None, "unknown": True,
                "detail": f"this fleet defines no tool {req['id']!r} (a module asking for it needs a new version, or an "
                          f"admin defines {req['id']})"}
    rep = report(node)
    if not rep:
        return {"status": "not_found", "code": "TOOL_NOT_FOUND", "installation": None, "source": None, "unreported": True,
                "detail": f"{req['id']} not reported yet (the node's agent reports its tools after it connects)"}
    o = node_override(r, node, req["id"], module)
    res = resolve(installations(node, req["id"]), req, native_arch(node), o["path"] if o else None)
    if o:
        res["override"] = o
    return res


def unmet(r, manifest, node: dict, module: str = "") -> tuple[str, str] | None:
    """(reason code, words) of the first tool request of a module version that does not resolve on a node, or None."""
    defs = definitions(r)
    for req in requests(manifest):
        res = resolve_for(r, node, module, req, defs)
        if res["status"] != "ok":
            return res["code"], f"{need_text(req)}: {res['detail']}"
    return None


# ------------------------------------------------------------------------------------------------ remediation

def install_command(kind: str | None, req: dict, os_: str | None) -> str | None:
    """A copyable command that installs a version the request accepts (the lowest JDK LTS, the newest Python), or None."""
    if kind == "jdk":
        major = next((v for v in JDK_LTS if tv.satisfies(str(v), req.get("version"))), None)
        if major is None:
            return None
        return {"darwin": f"brew install openjdk@{major}", "linux": f"sudo apt install openjdk-{major}-jdk-headless",
                "windows": f"winget install EclipseAdoptium.Temurin.{major}.JDK"}.get(os_ or "")
    if kind == "python":
        ver = next((v for v in PYTHONS if tv.satisfies(v, req.get("version"))), None)
        if ver is None:
            return None
        return {"darwin": f"brew install python@{ver}", "linux": f"sudo apt install python{ver}",
                "windows": f"winget install Python.Python.{ver}"}.get(os_ or "")
    return None


def fixes(r, node: dict, module: str, req: dict, res: dict, defs: dict | None = None) -> list[dict]:
    """What fixes a failed resolution on one node, most direct first: install a version it accepts (a command), re-detect,
    set a path on this node, add a search path for its OS. [{label, command?, op?, target?, params?, href?}]"""
    defs = definitions(r) if defs is None else defs
    d = defs.get(req["id"])
    os_ = (node.get("platform") or "").split("-")[0]
    out = []
    if res.get("unknown") or not d:
        return [{"label": f"Define {req['id']} in Settings → Tools", "href": f"/settings?tool={req['id']}#tools"}]
    cmd = install_command(d["kind"], req, os_)
    if res["status"] in ("not_found", "version_unmet") and cmd:
        out.append({"label": f"Install on {node.get('hostname') or node.get('node_id')}", "command": cmd})
    out.append({"label": "Re-detect", "op": "tools.detect", "target": node.get("node_id"),
                "command": f"oarbank tools detect {node.get('hostname') or node.get('node_id')}"})
    out.append({"label": "Set path on this node", "href": f"/nodes/{node.get('node_id')}#tools",
                "command": f"oarbank settings set {path_key(req['id'])} <path> --node {node.get('hostname') or node.get('node_id')}"
                           + (f" --module {module}" if module else "")})
    if os_:
        out.append({"label": f"Add a search path for {OS_NAMES.get(os_, os_)}", "href": f"/settings?tool={req['id']}#tools",
                    "command": f"oarbank tools define {req['id']} --search {os_}=<pattern>"})
    return out


# ------------------------------------------------------------------------------------------------ views

def _module_manifests(r, node: dict | None = None, module: str | None = None) -> dict:
    """{name: manifest dict} of the enabled modules (the node's version of each when a node is given)."""
    from . import modstore
    names = [module] if module else [x["name"] for x in r.q(
        "SELECT name FROM module_channels WHERE current IS NOT NULL AND disabled=0 ORDER BY name")]
    out = {}
    for name in names:
        ver = modstore.version_for_node(r, name, (node or {}).get("node_id")) if node else (modstore.channel(r, name)["current"])
        row = r.one("SELECT manifest_json FROM modules WHERE name=? AND version=?", (name, ver)) if ver else None
        if not row and module:
            row = r.one("SELECT manifest_json FROM modules WHERE name=? ORDER BY installed_at DESC LIMIT 1", (name,))
        if row:
            out[name] = jl(row["manifest_json"], {}) or {}
    return out


def node_view(r, node: dict, defs: dict | None = None) -> dict:
    """The node page's Tools section: what the node found (per tool), and each enabled module's resolution per tool
    request with its source, status and fixes."""
    defs = definitions(r) if defs is None else defs
    rep = report(node)
    mods = {}
    for name, man in _module_manifests(r, node=node).items():
        rows = []
        for req in requests(man):
            res = resolve_for(r, node, name, req, defs)
            rows.append({"request": req, "need": need_text(req), **res,
                         "fixes": [] if res["status"] == "ok" else fixes(r, node, name, req, res, defs)})
        if rows:
            mods[name] = rows
    overrides = node_values(r, node.get("node_id"))
    return {"reported": bool(rep), "detected_at": rep.get("detected_at"), "native_arch": native_arch(node),
            "tools": {tid: installations(node, tid) for tid in defs}, "extra": sorted(set(rep.get("tools") or {}) - set(defs)),
            "modules": mods, "overrides": overrides, "definitions": defs}


def module_matrix(r, module: str, nodes: list[dict], defs: dict | None = None) -> dict:
    """The module page's Nodes matrix: one row per node and tool request, with what the node found, the path set for it
    (an override; its placeholder is the detected match), the effective installation with its source, status and fix."""
    defs = definitions(r) if defs is None else defs
    out = {"module": module, "requests": [], "rows": []}
    mans = _module_manifests(r, module=module)
    man = mans.get(module)
    if man is None:
        return out
    out["requests"] = requests(man)
    for n in nodes:
        plat = n.get("platform") or ""
        man_n = _module_manifests(r, node=n, module=module).get(module, man)
        for req in requests(man_n):
            res = resolve_for(r, n, module, req, defs)
            detected = resolve(installations(n, req["id"]), req, native_arch(n)) if report(n) else None
            out["rows"].append({"node_id": n["node_id"], "hostname": n.get("hostname"), "platform": plat, "request": req,
                                "need": need_text(req), "found": installations(n, req["id"]),
                                "detected": (detected or {}).get("installation"), **res,
                                "fixes": [] if res["status"] == "ok" else fixes(r, n, module, req, res, defs)})
    return out


def resolution(r, module: str, manifest=None, nodes: list[dict] | None = None) -> list[dict]:
    """Per tool request of a module version (default: its current version), how many of `nodes` (default: every node
    that is not retired) resolve it and why the others do not (the readiness checklist's host tools step):
    [{request, need, unknown, ok: [hosts], failed: [(host, reason with its fix, code)]}]."""
    defs = definitions(r)
    if manifest is None:
        manifest = _module_manifests(r, module=module).get(module) or {}
    if nodes is None:
        nodes = r.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    out = []
    for req in requests(manifest):
        row = {"request": req, "need": need_text(req), "unknown": req["id"] not in defs, "ok": [], "failed": []}
        for n in nodes:
            res = resolve_for(r, n, module, req, defs)
            host = n.get("hostname") or n["node_id"]
            if res["status"] == "ok":
                row["ok"].append(host)
                continue
            fx = fixes(r, n, module, req, res, defs)
            cmd = next((f["command"] for f in fx if f.get("label", "").startswith("Install")), None)
            words = {"not_found": "not found", "version_unmet": "", "refused": "refused: "}[res["status"]]
            reason = res["detail"] if res["status"] != "not_found" or res.get("unknown") or res.get("unreported") else words
            row["failed"].append((host, reason + (f" → {cmd}" if cmd else ""), res["code"]))
        out.append(row)
    return out


def api(r, node_id: str | None = None, module: str | None = None) -> dict:
    """GET /api/v1/tools: the definitions, and the detection and resolution matrix (one node, one module, or both)."""
    defs = definitions(r)
    nodes = r.q("SELECT * FROM nodes WHERE lifecycle!='retired'" + (" AND (node_id=? OR hostname=?)" if node_id else "")
                + " ORDER BY hostname", (node_id, node_id) if node_id else ())
    from .settings import registry as R
    doc = {"definitions": list(defs.values()),
           "overrides": [{"scope": x["scope"], "scope_id": x["scope_id"], "module": x["module"],
                          "tool": R.TOOL_PATH.fullmatch(x["key"]).group(1), "path": x["value"]} for x in _path_rows(_snap(r))]}
    if module:
        doc["module"] = module_matrix(r, module, nodes, defs)
    else:
        doc["nodes"] = [{"node_id": n["node_id"], "hostname": n["hostname"], "platform": n.get("platform"), **node_view(r, n, defs)}
                        for n in nodes]
        for x in doc["nodes"]:
            x.pop("definitions", None)
    return doc


# ------------------------------------------------------------------------------------------------ migration

def convert_registry(db, reg: dict) -> list[str]:
    """The old per-OS tool registry ({id: {trust?, paths: {os: [abs paths]}}}) as tool definitions with fleet search
    paths per OS: an id named like a JDK becomes kind jdk, any other an executable read with `--version`; its `trust`
    (now the module request's) is dropped. Returns the converted ids."""
    done = []
    for tid, e in sorted((reg or {}).items()):
        if not TOOL_ID.fullmatch(tid or "") or tid in BUILTIN:
            continue
        search = {os_: sorted(set(ps)) for os_, ps in ((e or {}).get("paths") or {}).items() if os_ in OSES and ps}
        kind = "jdk" if re.match(r"^(java|jdk|openjdk)", tid) else "executable"
        det = {"search": search}
        if kind == "executable":
            det["version"] = {"args": ["--version"], "regex": "(\\d+(?:\\.\\d+)+)"}
        db.x("INSERT OR IGNORE INTO tool_defs(id, kind, detector_json, updated_by, updated_at) VALUES(?,?,?,?,?)",
             (tid, kind, json.dumps(det, sort_keys=True), "migration", time.time()))
        done.append(tid)
    return done


def migrate_registry(db) -> list[str]:
    """One-shot at upgrade (inside the caller's transaction): a fleet `tool_registry` value the settings model kept
    becomes tool definitions (convert_registry), and the value is deleted."""
    done = []
    for x in db.q("SELECT module, value_json FROM setting_values WHERE key='tool_registry'"):
        done += convert_registry(db, json.loads(x["value_json"] or "{}"))
    db.x("DELETE FROM setting_values WHERE key='tool_registry'")
    return done
