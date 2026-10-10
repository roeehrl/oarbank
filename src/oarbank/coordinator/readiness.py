"""A module's readiness checklist: "Getting this module running", computed from the fleet's real state.

An owner who installed, approved and enabled a module sees it "ready" while nothing can run: its releases wait for
the owner's signature, a host tool it asks for has no path in the tool registry, no node reports a capability or a
pool its stages need. This walks the whole path, one step after another, each with its status, the reason and the
exact action (an operation the console offers as a button or a link, and the command):

  installed -> sandbox grants approved -> enabled -> where it runs (the fleet's platforms it supports) -> release
  built per platform -> release signed and current per platform -> host tools mapped per OS -> nodes that can run
  each stage (and why the others cannot) -> certified nodes -> next: the module's own operations.

Statuses: `done`; `blocked` (the owner must act); `waiting` (the fleet is working on it, or an earlier step must be
done first); `next` (the operations to start work with). The console renders it on the module's page and, compact, on
the Modules page; `oarbank module ready <name>` prints it. Read-only: nothing here writes.
"""
import json
import time
from pathlib import Path

from oarbank_sdk import platform as pf
from oarbank_sdk import portable

from . import config as C
from . import modsandbox, modstore, platforms, predicates, releases
from .db import DB, jl

OS_NAMES = {"darwin": "macOS", "linux": "Linux", "windows": "Windows"}
# a tool's path on each OS, as an example for the mapping command (the Settings form shows the same placeholders)
TOOL_EXAMPLE = {"darwin": "/opt/homebrew/opt/openjdk@17", "linux": "/usr/lib/jvm/java-17-openjdk-amd64",
                "windows": "C:\\Program Files\\Eclipse Adoptium\\jdk-17"}
CONTAINER_FIX = {"darwin": "install Colima and Docker on it (`brew install colima docker`); the agent runs its own Colima profile",
                 "linux": "install rootless Podman (or Docker Engine) on it",
                 "windows": "enable WSL containers on it (the agent's WSL containers session)"}
EXCLUSION_WORDS = {
    "TOOL_UNAVAILABLE": "the tool registry has no {os} path for {tools}",
    "OS_VERSION_UNSUPPORTED": "{os} {os_version} is not a version it supports",
    "FOLDER_UNAVAILABLE": "it does not provide a folder the module asks for",
    "SANDBOX_BACKEND_MISSING": "its agent cannot sandbox module processes",
    "CAPABILITY_NOT_ENFORCED": "its sandbox cannot enforce {gaps}",
    "AGENT_TOO_OLD": "its agent {have} is older than the module needs ({need})",
    "GPU_API_MISSING": "its host has no GPU API the runner needs",
}
MODULE_STATES = {"certifying": "not certified yet: running goldens", "doctor_failed": "the module's doctor fails",
                 "golden_failed": "golden jobs failed", "undetected": "the node cannot run it (doctor: undetected)",
                 "revoked": "revoked after a golden mismatch", "no_golden": "no golden jobs for this node class"}


def _op_id(name: str, verb: str) -> str:
    return f"mod.{name.replace('-', '_')}.{verb}"


def _step(id_, title, status, reason, actions=(), items=()):
    return {"id": id_, "title": title, "status": status, "reason": reason, "actions": list(actions), "items": list(items)}


def _act(label, op=None, target=None, href=None, command=None, params=None):
    return {k: v for k, v in {"label": label, "op": op, "target": target, "href": href, "command": command,
                              "params": params}.items() if v is not None}


def _plural(n, word, many=None):
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _containers_why(facts: dict) -> str:
    """Why a node offers no `containers` pool, from its facts' `containers` report."""
    c = (facts or {}).get("containers") or {}
    if c.get("runtime"):
        state = c.get("state") or "not ready"
        missing = ", ".join(c.get("missing") or [])
        return f"no ready container runtime ({c['runtime']} {state}{': missing ' + missing if missing else ''})"
    return "no container runtime reported"


def _module_reasons(db: DB, man, node: dict, tool_ids: set) -> list[str]:
    """Why no stage of this module may run on this node (its exclusion, modsandbox.exclusion), with the fix; the node's
    platform is supported."""
    code = modsandbox.exclusion(db, man, node)
    if not code:
        return []
    plat = platforms.node_platform(node)
    os_ = portable.split_platform(plat)[0] if plat else None
    facts = json.loads(node.get("facts_json") or "{}")
    _, missing = platforms.tool_paths(db, sorted(tool_ids), os_) if os_ else ([], [])
    return [EXCLUSION_WORDS.get(code, code).format(
        os=OS_NAMES.get(os_, os_), tools=", ".join(missing) or "a tool", os_version=platforms.os_version(facts) or "?",
        gaps=", ".join(platforms.sandbox_gaps(man, facts)), have=node.get("agent_version") or "?", need=man.requires.agent or "?")
        + (": map it in Settings → Tools" if code == "TOOL_UNAVAILABLE" else "")]


def _stage_reasons(name: str, stage, node: dict, tool_ids: set, has_release: bool) -> list[str]:
    """Why this node cannot run this stage beyond the module's own exclusion (empty: it can), each with what fixes it."""
    out = []
    plat = platforms.node_platform(node)
    os_ = portable.split_platform(plat)[0] if plat else None
    facts = json.loads(node.get("facts_json") or "{}")
    if stage.requires.platforms and plat not in stage.requires.platforms:
        return [f"stage {stage.name} runs only on {', '.join(stage.requires.platforms)}"]
    have = predicates.node_capabilities(node, name)
    for cap in stage.requires.capabilities:
        if cap in have:
            continue
        hint = f"; install {cap} on the node (the host tool {cap}, mapped in Settings → Tools)" if cap in tool_ids else ""
        if not has_release:
            out.append(f"{cap} not reported yet (a node checks it once it runs the release with this module){hint}")
        else:
            out.append(f"{cap} not reported (the module's {cap} probe or service does not find it){hint}")
    pools = predicates_pools(node)
    need = {**{p: 1 for p in stage.requires.needs_pools}, **dict(stage.requires.pools)}
    for p, k in sorted(need.items()):
        if int(pools.get(p, 0)) >= int(k):
            continue
        if p == "containers":
            out.append(f"{_containers_why(facts)}: {CONTAINER_FIX.get(os_, 'install a container runtime on it')}")
        else:
            out.append(f"no {p} pool" + (f" ({k} needed)" if k > 1 else ""))
    res = stage.requires.resources
    mem = facts.get("memory_gb")
    if mem is not None and float(mem) < res.mem_gb:
        out.append(f"has {float(mem):g} GB of memory; the stage needs {res.mem_gb:g} GB")
    cores = platforms.cores(facts)
    if cores and cores < res.cpu:
        out.append(f"has {cores} cores; the stage needs {res.cpu:g}")
    return out


def predicates_pools(node: dict) -> dict:
    from . import core
    return core._node_pools(node)


def _group(rows: list[tuple[str, list[str]]]) -> list[dict]:
    """[(host, reasons)] -> [{reasons, nodes}], nodes with the same reasons together."""
    out = {}
    for host, reasons in rows:
        out.setdefault(tuple(reasons), []).append(host)
    return [{"reasons": list(r), "nodes": hosts} for r, hosts in out.items()]


def module(db: DB, name: str, now: float | None = None) -> dict | None:
    """The checklist of one installed module: {name, version, state, summary, needs, steps}."""
    from oarbank_sdk import manifest as mf
    now = now or time.time()
    rows = modstore.installed(db, name)
    if not rows:
        return None
    ch = modstore.channel(db, name)
    ver = ch["current"] or rows[-1]["version"]
    rec = next((r for r in rows if r["version"] == ver), rows[-1])
    man = mf.load(Path(rec["path"]) / "oarbank-module.toml")
    steps, needs = [], []

    # 1. installed
    steps.append(_step("installed", "Installed", "done", f"{name} {ver} installed by {rec['installed_by']}"))

    # 2. sandbox grants
    st = modsandbox.status(db, name, ver)
    if not st["requests"]:
        steps.append(_step("grants", "Sandbox grants approved", "done", "it requests no sandbox grants"))
    elif st["approved"]:
        steps.append(_step("grants", "Sandbox grants approved", "done", modsandbox.describe(st["requests"])))
    else:
        needs.append("approve its grants")
        steps.append(_step("grants", "Sandbox grants approved", "blocked",
                           f"it requests {modsandbox.describe(st['requests'])}; nothing of it runs on a node until you approve",
                           [_act("Review grants…", op="modules.approve", target=f"{name}@{ver}",
                                 command=f"oarbank module approve {name}@{ver}")]))
    granted = not st["requests"] or st["approved"]

    # 3. enabled
    enabled = bool(ch["current"]) and not ch["disabled"]
    if enabled:
        steps.append(_step("enabled", "Enabled", "done", f"{ver} is the current version on every node"))
    elif ch["current"] and ch["disabled"]:
        needs.append("re-enable it")
        steps.append(_step("enabled", "Enabled", "blocked", "the kill switch disabled it fleet-wide",
                           [_act("Re-enable", op="modules.enable", target=name, command=f"oarbank module enable {name}")]))
    else:
        needs.append("enable it")
        steps.append(_step("enabled", "Enabled", "blocked" if granted else "waiting",
                           "installing enables nothing" + ("" if granted else "; approve its grants first"),
                           [_act("Enable", op="modules.enable", target=f"{name}@{ver}", command=f"oarbank module enable {name}@{ver}")]))

    # 4. where it runs
    nodes = [n for n in db.q("SELECT * FROM nodes WHERE lifecycle NOT IN ('retired') ORDER BY hostname")]
    by_plat = {}
    for n in nodes:
        by_plat.setdefault(platforms.node_platform(n) or "?", []).append(n)
    supported = [p for p in sorted(by_plat) if p in man.requires.platforms]
    items = []
    for p in sorted(by_plat):
        hosts = [n["hostname"] for n in by_plat[p]]
        if p in supported:
            off = [n["hostname"] for n in by_plat[p] if not (n["last_heartbeat_at"] and now - n["last_heartbeat_at"] < C.OFFLINE_AFTER)]
            items.append({"status": "done", "text": f"{p}: {_plural(len(hosts), 'node')} ({', '.join(hosts)})"
                          + (f"; offline now: {', '.join(off)}" if off else "")})
        else:
            why = pf.resolve(man.requires.unsupported.runner, p) if p != "?" else None
            items.append({"status": "skipped", "text": f"{p}: not a platform it supports ({', '.join(hosts)})"
                          + (f": {why}" if why else "") + "; these nodes are not counted below"})
    if supported:
        steps.append(_step("platforms", "Where it runs", "done",
                           f"it runs on {', '.join(man.requires.platforms)}; the fleet has {', '.join(supported)}", items=items))
    else:
        needs.append(f"a node of {' or '.join(man.requires.platforms)}")
        steps.append(_step("platforms", "Where it runs", "blocked",
                           f"no node of a platform it supports ({', '.join(man.requires.platforms)}): add one",
                           [_act("Add machine…", href="/add-machine")], items))

    # 5. and 6. releases, per supported platform
    def has(row):
        return bool(row) and (jl(row["composition_json"], {}) or {}).get(name, {}).get("version") == ver
    built, signed, awaiting = [], [], releases.awaiting(db)
    rel_rows = {}
    for p in supported:
        cur = db.one("SELECT * FROM releases WHERE platform=? AND status='current'", (p,))
        cand = next((r for r in db.q("SELECT * FROM releases WHERE platform=? AND status IN ('current','candidate') "
                                     "ORDER BY created_at DESC", (p,)) if has(r)), None)
        rel_rows[p] = (cur, cand)
        if has(cur):
            built.append({"status": "done", "text": f"{p}: {cur['release_id']}"})
            signed.append({"status": "done", "text": f"{p}: {cur['release_id']} is current"})
        elif cand:
            built.append({"status": "done", "text": f"{p}: {cand['release_id']}"})
            if releases.signature_required(db) and not cand["signature"]:
                holds = ", ".join(releases.contents(cand["composition_json"]))
                signed.append({"status": "blocked", "sign": True, "text": f"{p}: {cand['release_id']} ({holds}) waits for your signature",
                               "command": f"oarbank release sign {cand['release_id']} --promote"})
            else:
                signed.append({"status": "blocked", "text": f"{p}: {cand['release_id']} is signed but not current",
                               "command": f"oarbank release promote {cand['release_id']}", "op": "releases.promote",
                               "target": cand["release_id"]})
        else:
            built.append({"status": "blocked" if enabled else "waiting", "text": f"{p}: no release with {name} {ver} yet"})
            signed.append({"status": "waiting", "text": f"{p}: after its release is built"})
    others = [a for a in awaiting if a["platform"] not in supported]
    for a in others:      # releases of the fleet's other platforms: their nodes need them to become ready at all
        signed.append({"status": "blocked", "sign": True, "text": f"{a['platform']}: {a['release_id']} "
                       f"({', '.join(a.get('modules') or []) or 'no module'}) waits for your signature too "
                       f"(its nodes need it to become ready; {name} does not run there)", "command": a["command"]})
    if not enabled:
        steps.append(_step("built", "Release built per platform", "waiting", "after it is enabled: a release is the bundle of the "
                           "enabled modules, built for each platform of the fleet", items=built))
    elif any(i["status"] != "done" for i in built):
        needs.append("build its releases")
        steps.append(_step("built", "Release built per platform", "blocked", "a platform has no release with this version",
                           [_act("Build releases", op="releases.build", target="release", command="oarbank release build")], built))
    else:
        steps.append(_step("built", "Release built per platform", "done", "every platform it runs on has its release", items=built))
    to_sign = [i for i in signed if i["status"] == "blocked"]
    if not enabled or not supported:
        steps.append(_step("signed", "Release signed and current per platform", "waiting", "after its releases are built",
                           items=signed))
    elif to_sign:
        n_sign = sum(1 for i in to_sign if i.get("sign"))
        needs.append(f"sign {_plural(n_sign, 'release')}" if n_sign else "promote its releases")
        steps.append(_step("signed", "Release signed and current per platform", "blocked",
                           "nothing reaches a node before the owner signs its release offline: run each command on the machine "
                           "that holds the owner key", [_act("Releases in Settings", href="/settings#releases",
                                                             command="oarbank release list")], signed))
    elif any(i["status"] != "done" for i in signed):
        steps.append(_step("signed", "Release signed and current per platform", "waiting", "its releases are being built",
                           items=signed))
    else:
        steps.append(_step("signed", "Release signed and current per platform", "done", "nodes install it on their next "
                           "heartbeat", items=signed))

    # 7. host tools
    tools = list(man.sandbox.tools)
    tool_ids = {t.id for t in tools}
    oses = sorted({portable.split_platform(p)[0] for p in supported})
    titems, unmapped = [], []
    for t in tools:
        for os_ in oses:
            paths, missing = platforms.tool_paths(db, [t.id], os_)
            if missing:
                unmapped.append(t.id)
                # the whole entry: the paths other OSes already have, plus an example for this one
                have = (platforms.tool_registry(db).get(t.id) or {}).get("paths") or {}
                cmd = ("oarbank op settings.tools.update " + t.id + " --json '" +
                       json.dumps({"paths": {**have, os_: [TOOL_EXAMPLE.get(os_, "/path/to/" + t.id)]}}) + "'")
                titems.append({"status": "blocked", "text": f"{t.id} ({t.trust}): no {OS_NAMES.get(os_, os_)} path in the tool "
                               f"registry, so no {OS_NAMES.get(os_, os_)} node can be granted it",
                               "href": f"/settings?tool={t.id}#tools", "command": cmd})
            else:
                titems.append({"status": "done", "text": f"{t.id} on {OS_NAMES.get(os_, os_)}: {', '.join(paths)}"})
    if not tools:
        steps.append(_step("tools", "Host tools mapped", "done", "it asks for no host tools"))
    elif unmapped:
        ids = sorted(set(unmapped))
        needs.append(f"map {', '.join(ids)}")
        steps.append(_step("tools", "Host tools mapped", "blocked",
                           "it asks for host tools by id; the tool registry says where each lives on each OS (install the tool on "
                           "the nodes too)", [_act(f"Map {i} in Settings → Tools", href=f"/settings?tool={i}#tools") for i in ids],
                           titems))
    else:
        steps.append(_step("tools", "Host tools mapped", "done", "every host tool it asks for has a path on each OS", items=titems))

    # 8. nodes that can run each stage, and 9. certified
    comp_of = {r["release_id"]: r for r in db.q("SELECT release_id, composition_json FROM releases")}
    capable_by_stage, sitems, citems = {}, [], []
    online = {n["node_id"]: bool(n["last_heartbeat_at"] and now - n["last_heartbeat_at"] < C.OFFLINE_AFTER) for n in nodes}
    mine = [n for n in nodes if platforms.node_platform(n) in supported]
    excluded = {n["node_id"]: _module_reasons(db, man, n, tool_ids) for n in mine}
    if any(excluded.values()):
        sitems.append({"status": "blocked", "stage": "", "needs": "", "text": "every stage: these nodes may run none of it",
                       "groups": _group([(n["hostname"], excluded[n["node_id"]]) for n in mine if excluded[n["node_id"]]])})
    for stg in man.stages:
        reasons, capable = [], []
        for n in mine:
            why = _stage_reasons(name, stg, n, tool_ids, has(comp_of.get(n.get("release_id") or "")))
            if why:
                reasons.append((n["hostname"], why))
            elif not excluded[n["node_id"]]:
                capable.append(n)
        capable_by_stage[stg.name] = capable
        req = [*stg.requires.capabilities, *(f"{p} pool" for p in sorted({**dict(stg.requires.pools),
                                                                          **{x: 1 for x in stg.requires.needs_pools}}))]
        cpu = stg.requires.resources.cpu
        req.append(f"{cpu:g} core{'' if cpu == 1 else 's'}, {stg.requires.resources.mem_gb:g} GB")
        off = [n["hostname"] for n in capable if not online[n["node_id"]]]
        sitems.append({"status": "done" if capable else "blocked", "stage": stg.name, "needs": ", ".join(req),
                       "text": f"{stg.name}{' (bootstrap)' if stg.bootstrap else ''}: {len(capable)} of {_plural(len(mine), 'node')}"
                       + (f" ({', '.join(n['hostname'] for n in capable)})" if capable else "")
                       + (f"; offline now: {', '.join(off)}" if off else "")
                       + ("; the nodes above may run none of it" if not capable and not reasons and any(excluded.values()) else ""),
                       "groups": _group(reasons)})
        cert, waiting_on = [], []
        for n in capable:
            s = (jl(n.get("modules_json"), {}) or {}).get(name, {}).get("state")
            ok = s == "certified" or (stg.bootstrap and s == "certifying")
            (cert if ok else waiting_on).append((n["hostname"], MODULE_STATES.get(s, "not doctored yet") if not ok else ""))
        citems.append({"status": "done" if cert else "waiting", "stage": stg.name,
                       "text": f"{stg.name}: {len(cert)} certified" + (f" ({', '.join(h for h, _ in cert)})" if cert else ""),
                       "groups": _group([(h, [w]) for h, w in waiting_on])})
    lacking = [s for s, c in capable_by_stage.items() if not c]
    if not supported:
        steps.append(_step("nodes", "Nodes that can run it", "waiting", "after the fleet has a node of a platform it supports",
                           items=sitems))
    elif lacking:
        needs.append("a node for every stage" if len(lacking) == len(man.stages) > 1 else f"a node for {', '.join(lacking)}")
        steps.append(_step("nodes", "Nodes that can run it", "blocked",
                           f"no node meets what {_plural(len(lacking), 'stage')} ({', '.join(lacking)}) require{'s' if len(lacking) == 1 else ''}: "
                           "the reasons per node say what to install or map", items=sitems))
    else:
        steps.append(_step("nodes", "Nodes that can run it", "done", "every stage has a node that meets its requirements",
                           items=sitems))
    uncert = [i["stage"] for i in citems if i["status"] != "done"]
    if lacking or not supported or not enabled:
        steps.append(_step("certified", "Certified nodes", "waiting", "after nodes can run it: they certify by running its "
                           "golden jobs", items=citems))
    elif uncert:
        steps.append(_step("certified", "Certified nodes", "waiting",
                           f"no certified node yet for {', '.join(uncert)}: the nodes run its golden jobs (a module whose "
                           "goldens need its datasets certifies after its bootstrap operation)", items=citems))
    else:
        steps.append(_step("certified", "Certified nodes", "done", "every stage has a certified node", items=citems))

    # 10. next: the module's own operations, in manifest order
    ops = [{"verb": o.verb, "title": o.title, "op": _op_id(name, o.verb), "tier": o.effective_tier(), "target": o.target,
            "min_role": o.min_role,
            "has_params": bool(o.params_schema),
            "command": f"oarbank op {_op_id(name, o.verb)}" + (" --json '{…}'" if o.params_schema else "")}
           for o in man.operations]
    first = [o for o in ops if o["target"] == "none"][:2]
    pages = [{"title": d.title, "href": f"/modules/{name}" if d.slot == "module.overview" else f"/m/{name}/{d.id}"}
             for d in man.ui.pages]
    if ops:
        steps.append(_step("next", "Start work", "next",
                           ("start with " + " then ".join(f"{o['title']} ({o['verb']})" for o in first) if first else
                            "its operations") + ": on its own pages, or with `oarbank op`",
                           [_act(p["title"], href=p["href"]) for p in pages][:4], items=ops))
    else:
        steps.append(_step("next", "Start work", "next", "it declares no operations: its pages and campaigns start its work",
                           [_act(p["title"], href=p["href"]) for p in pages][:4]))

    blocked = [s for s in steps if s["status"] == "blocked"]
    waiting = [s for s in steps if s["status"] == "waiting"]
    state = "blocked" if blocked else ("waiting" if waiting else "ready")
    summary = ("needs: " + ", ".join(needs) if needs else
               f"waiting: {waiting[0]['title'].lower()}" if waiting else
               "ready" + (f": start with {first[0]['title']}" if first else ""))
    return {"name": name, "version": ver, "state": state, "summary": summary, "needs": needs, "steps": steps,
            "operations": ops}


def all_modules(db: DB, now: float | None = None) -> list[dict]:
    """Every installed module's checklist."""
    names = [r["name"] for r in db.q("SELECT DISTINCT name FROM modules ORDER BY name")]
    return [m for m in (module(db, n, now) for n in names) if m]
