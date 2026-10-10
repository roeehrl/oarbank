"""Settings as pages and the API show them: one row per setting at one scope (the console's `setting_row` macro, the
API's effective view, `oarbank settings get`). Pure functions over a reader (anything with `q`).

A row carries the definition (label, unit, help, the raw key), the effective value and the badge naming its source,
whether this scope sets it ("overridden here"), what it would inherit without this scope's value, a lock above, the
merged values' errors on the node, the node's applied state, the whole chain for Explain and, at fleet scope, how many
nodes override it."""
import copy
import json
import time

from . import modkeys
from . import registry as R
from . import resolve as V
from .apply import applied_state

INPUT = {"boolean": "checkbox", "integer": "number", "number": "number", "string": "text", "array": "list",
         "object": "json"}


def _types(d: R.Setting) -> list:
    t = d.schema.get("type")
    return t if isinstance(t, list) else [t]


def input_of(d: R.Setting) -> dict:
    """How a form edits the value: {kind, step, min, max, choices}."""
    if d.schema.get("x-kind") == "schedule":
        return {"kind": "schedule"}
    t = next((t for t in _types(d) if t != "null"), "string")
    if "enum" in d.schema:
        return {"kind": "select", "choices": list(d.schema["enum"]), "numeric": t in ("integer", "number")}
    kind = INPUT.get(t, "text")
    if kind == "list" and ((d.schema.get("items") or {}).get("type") or "string") != "string":
        kind = "json"                                   # a list of numbers or objects is edited as JSON
    out = {"kind": kind, "nullable": d.nullable}
    if kind == "number":
        out["step"] = "1" if t == "integer" else "any"
        lo = d.schema.get("minimum", d.schema.get("exclusiveMinimum"))
        if lo is not None:
            out["min"] = lo
        if "maximum" in d.schema:
            out["max"] = d.schema["maximum"]
    if t == "string" and d.schema.get("format") == "uri":
        out["kind"] = "url"
    return out


def form_text(key: str, v, kind: str | None = None) -> str:
    """A value as a form field shows it (lists one entry per line for text areas, comma-separated in inputs)."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else ""
    if isinstance(v, (list, dict)) and kind == "json":
        return json.dumps(v, sort_keys=True)
    if isinstance(v, list):
        return "\n".join(map(str, v))
    if isinstance(v, dict):
        return json.dumps(v, sort_keys=True)
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _without(snap: V.Snap, scope: str, scope_id: str, key: str, module: str = "") -> V.Snap:
    out = copy.copy(snap)
    out.rows = {k: x for k, x in snap.rows.items() if k != (scope, scope_id, module, key)}
    return out


def row(snap: V.Snap, d: R.Setting, scope: str, node: dict | None, counts: dict | None = None,
        errors: dict | None = None, now: float | None = None, scope_id: str = "", module: str = "") -> dict:
    """One setting at one scope (fleet: node None; node: that node; group: `scope_id`, with `node` a stand-in member,
    group_sections), for a module when it names one (a module's own key, or a core key set for the module)."""
    sid = node["node_id"] if scope == "node" else scope_id
    res = V.resolve(snap, node, d.key, module)
    own = snap.get(scope, sid, module, d.key)
    inh = V.resolve(_without(snap, scope, sid, d.key, module), node, d.key, module) if own else res
    show = lambda v: R.show(d.key, v, d)
    for x in res["chain"]:
        x["value_text"] = show(x["value"]) if x["set"] or x["scope"] == "default" else "not set"
    inp = input_of(d)
    out = {"key": d.key, "label": d.label, "unit": d.unit, "help": d.help, "note": d.note, "advanced": d.advanced,
           "section": d.section, "input": inp, "scope": scope, "scope_id": sid, "lockable": d.lockable,
           "module": module, "dom": (f"{module}-" if module else "") + d.key.replace(".", "-"), "scopes": list(d.scopes),
           "merge": d.merge, "danger": d.danger, "value": res["value"], "value_text": show(res["value"]),
           "form_value": form_text(d.key, own["value"] if own else inh["value"], inp["kind"]),
           "badge": V.badge(res), "source": res["source"], "overridden_here": own is not None,
           "own": {"value": own["value"], "rev": own["rev"], "by": own["updated_by"], "at": own["updated_at"],
                   "comment": own["comment"], "enforced": bool(own["enforced"])} if own else None,
           "inherited": {"value": inh["value"], "text": show(inh["value"]), "badge": V.badge(inh)},
           "locked_by": res["locked_by"] if res["locked_by"] and res["locked_by"]["scope"] != scope else None,
           "lock_text": lock_text(res["locked_by"]) if res["locked_by"] and res["locked_by"]["scope"] != scope else None,
           "locked_here": bool(own and own["enforced"]), "own_text": show(own["value"]) if own else None,
           "chain": res["chain"], "default": {**res["default"], "text": show(res["default"]["value"])
                                              if modkeys.has_default(d) or not module else "none"},
           "errors": list((errors or {}).get(d.key, [])), "form_errors": [], "typed": False,
           "required": d.required, "missing": d.required and res["source"]["scope"] == "default",
           "override_count": (counts or {}).get(d.key, 0) if scope == "fleet" else None,
           "applied": applied_state(node, d.key, now) if scope == "node" and node is not None
           and (d.wire or d.applies != "coordinator") else None}
    if (node is None or scope == "group") and d.computed is not None:
        # fleet-wide, a computed default has no single value: say how each node gets its own
        per_node = "computed per node"
        for x in out["chain"]:
            if x["scope"] == "default":
                x["value_text"], x["reason"] = per_node, d.computed_how
        if res["source"]["scope"] == "default":
            out["value_text"], out["badge"] = per_node, f"Default · {d.computed_how}"
        if inh["source"]["scope"] == "default":
            out["inherited"] = {"value": None, "text": per_node, "badge": f"Default · {d.computed_how}"}
        out["default"] = {"value": None, "reason": d.computed_how, "text": per_node}
        if not own:
            out["form_value"] = form_text(d.key, d.default, inp["kind"])
    if d.merge == "min":
        out["merge_note"] = "every scope's cap applies; the lowest wins"
    if scope == "node" and node is not None and d.hardware:
        from ..platforms import cores, memory_gb
        f = V.facts_of(node)
        hw = memory_gb(f) if d.hardware == "ram" else cores(f)
        if hw:
            out["hw_note"] = f"this node has {hw:g} GB of RAM" if d.hardware == "ram" else f"this node has {hw} cores"
    return out


def lock_text(lock: dict) -> str:
    """"Locked by Fleet settings" or "Locked by the group Laptops" (the row's lock button and its popover)."""
    if lock["scope"] == "fleet":
        return "Locked by Fleet settings"
    return f"Locked by the group {lock['name'].removeprefix('Group: ')}"


def sections(snap: V.Snap, scope: str, node: dict | None, keys_by_section: tuple, counts: dict | None = None,
             errors: dict | None = None, scope_id: str = "") -> list[dict]:
    now = time.time()
    out = []
    for sec in keys_by_section:
        title, blurb = R.SECTIONS[sec]
        rows = [row(snap, d, scope, node, counts, errors, now, scope_id) for d in R.SETTINGS
                if d.section == sec and scope in d.scopes and not d.writer]
        if not rows:
            continue
        out.append({"id": sec, "title": title, "blurb": blurb, "rows": [x for x in rows if not x["advanced"]],
                    "advanced": [x for x in rows if x["advanced"]],
                    "changed": sum(1 for x in rows if x["overridden_here"]),
                    "advanced_changed": sum(1 for x in rows if x["advanced"] and x["overridden_here"])})
    return out


def node_page(r, nid: str) -> dict | None:
    """The node's Settings tab: its sections at node scope, the merged values' errors, its applied state."""
    n = r.q("SELECT * FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (nid, nid))
    if not n:
        return None
    node = n[0]
    snap = V.snapshot(r)
    eff = V.effective(snap, node)
    errors = {k: v["errors"] for k, v in eff.items() if v.get("errors")}
    return {"node": node, "sections": sections(snap, "node", node, R.NODE_SECTIONS, errors=errors),
            "modules": node_module_sections(snap, node), "applied": applied_state(node),
            "groups": [g["name"] for g in V.node_groups(snap, node)], "labels": snap.node_labels(node),
            "memberships": membership_rows(snap, node), "rev": node.get("settings_rev") or 0}


# ------------------------------------------------------------------ module settings (docs/design/settings.md)

def _module_defs(snap: V.Snap, module: str, scope: str, chain: bool = True) -> list[R.Setting]:
    """The keys a module's page or a node's module section shows at `scope`: the core keys every module has, then the
    module's own keys, in its schema's order."""
    core = [R.REGISTRY[k] for k in R.MODULE_CORE_KEYS if scope in R.REGISTRY[k].scopes and (k != "pipeline" or chain)]
    own = [d for k, d in snap.defs.items() if modkeys.split(k)[0] == module and scope in d.scopes]
    return core + own


def _has_chain(r, module: str) -> bool:
    """Whether the module's stages form a chain (`pipeline = split` applies to it)."""
    rows = r.q("SELECT manifest_json FROM modules WHERE name=? ORDER BY installed_at DESC LIMIT 1", (module,))
    man = json.loads(rows[0]["manifest_json"] or "{}") if rows else {}
    return any(s.get("after") for s in man.get("stages") or [])


def _module_section(sec_id: str, title: str, blurb: str, rows: list[dict], module: str) -> dict:
    return {"id": sec_id, "title": title, "blurb": blurb, "module": module,
            "rows": [x for x in rows if not x["advanced"]], "advanced": [x for x in rows if x["advanced"]],
            "changed": sum(1 for x in rows if x["overridden_here"]),
            "advanced_changed": sum(1 for x in rows if x["advanced"] and x["overridden_here"])}


def node_module_sections(snap: V.Snap, node: dict, errors: dict | None = None) -> list[dict]:
    """The node's Settings tab, one section per installed module: whether it runs here, the services it does not run,
    and its node-scoped keys, each at node scope for that module only."""
    now = time.time()
    out = []
    for m in snap.modules:
        rows = [row(snap, d, "node", node, errors=errors, now=now, module=m) for d in _module_defs(snap, m, "node")]
        sec = _module_section(f"module-{m}", m, f"What {m} does on this node: its settings here reach only {m}'s runners "
                              "and services.", rows, m)
        sec["unset"] = modkeys.unset(snap, node, m)
        out.append(sec)
    return out


def module_page(r, module: str) -> dict | None:
    """A module's Settings tab: its core keys and its own keys at fleet scope (with how many groups and nodes set each
    for it), the values set below the fleet, the required keys with no value, and values its version no longer
    declares."""
    snap = V.snapshot(r)
    if module not in snap.modules:
        return None
    counts: dict = {}
    below = []
    names = {n["node_id"]: n["hostname"] for n in r.q("SELECT node_id, hostname FROM nodes WHERE lifecycle!='retired'")}
    gnames = {g["id"]: g["name"] for g in snap.groups}
    defs = {d.key: d for d in _module_defs(snap, module, "fleet")} | {
        d.key: d for d in _module_defs(snap, module, "node")}
    for (scope, sid, m, k), x in sorted(snap.rows.items()):
        if m != module or scope not in ("group", "node") or k not in defs:
            continue
        counts[k] = counts.get(k, 0) + (scope == "node")
        d = defs[k]
        below.append({"scope": scope, "scope_id": sid, "name": names.get(sid, sid) if scope == "node" else gnames.get(sid, sid),
                      "key": k, "label": d.label, "value_text": R.show(k, x["value"], d), "rev": x["rev"],
                      "by": x["updated_by"], "at": x["updated_at"], "dom": f"{module}-{k.replace('.', '-')}"})
    now = time.time()
    chain = _has_chain(r, module)
    core = [row(snap, d, "fleet", None, counts, now=now, module=module) for d in _module_defs(snap, module, "fleet", chain)
            if not modkeys.split(d.key)[0]]
    own = [row(snap, d, "fleet", None, counts, now=now, module=module) for d in _module_defs(snap, module, "fleet")
           if modkeys.split(d.key)[0]]
    reg = modkeys.registration(r, module)
    sections = [_module_section("module", R.SECTIONS["module"][0], R.SECTIONS["module"][1], core, module)]
    if own:
        sections.append(_module_section("module_own", R.SECTIONS["module_own"][0],
                                        f"The settings {module} {reg['version'] if reg else ''} declares in its manifest: "
                                        "node settings reach its runners and services, the others its coordinator side.",
                                        own, module))
    unset_nodes = {}
    for n in r.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname"):
        miss = modkeys.unset(snap, n, module)
        if miss:
            unset_nodes[n["hostname"]] = miss
    return {"module": module, "sections": sections, "below": below, "registration": reg,
            "unset": modkeys.unset(snap, None, module), "unset_nodes": unset_nodes,
            "orphans": [{"key": x["key"], "name": modkeys.split(x["key"])[1], "scope": x["scope"], "scope_id": x["scope_id"],
                         "where": "Fleet" if x["scope"] == "fleet" else names.get(x["scope_id"], gnames.get(x["scope_id"], x["scope_id"])),
                         "value_text": R.show(x["key"], x["value"])} for x in modkeys.orphans(r, module)]}


def fleet_page(r) -> dict:
    """Fleet Settings' sections: node defaults (with how many nodes override each) and the fleet-wide keys."""
    snap = V.snapshot(r)
    counts = V.override_counts(snap)
    nodes = r.q("SELECT COUNT(*) n FROM nodes WHERE lifecycle!='retired'")[0]["n"]
    return {"node_defaults": sections(snap, "fleet", None, R.NODE_SECTIONS, counts),
            "fleet": sections(snap, "fleet", None, R.FLEET_SECTIONS), "nodes": nodes,
            "groups": snap.groups}


def _module_rows(snap: V.Snap, node: dict | None, module: str, now: float) -> list[dict]:
    """A module's keys (the core ones every module has, then its own) for a node or fleet-wide, with provenance."""
    out = []
    for d in _module_defs(snap, module, "node" if node else "fleet"):
        res = V.resolve(snap, node, d.key, module)
        out.append({"key": d.key, "module": module, "label": d.label, "value": res["value"],
                    "value_text": R.show(d.key, res["value"], d), "badge": V.badge(res), "source": res["source"],
                    "section": d.section, "required": d.required, "missing": d.required and res["source"]["scope"] == "default",
                    "errors": [], **({"applied": applied_state(node, d.key, now)} if node else {})})
    return out


def effective_doc(r, nid: str | None = None, module: str = "") -> dict:
    """GET /api/v1/settings/effective: every key for a node (or fleet-wide), with provenance and applied state; with a
    module, that module's keys (the core keys every module has, then its own)."""
    snap = V.snapshot(r)
    if module and module not in snap.modules:
        raise R.SettingError("unknown_setting", f"no module {module!r} is installed")
    if not nid:
        rows = []
        for d in R.SETTINGS:
            if "fleet" not in d.scopes or (d.qualifier == "required" and not module) or (module and d.key in R.MODULE_CORE_KEYS):
                continue
            res = V.resolve(snap, None, d.key, module)
            rows.append({"key": d.key, "module": res["module"], "label": d.label, "value": res["value"],
                         "value_text": R.show(d.key, res["value"]), "badge": V.badge(res), "source": res["source"],
                         "section": d.section, "writer": d.writer})
        if module:
            rows = _module_rows(snap, None, module, time.time()) + [x for x in rows if x["key"] not in R.MODULE_CORE_KEYS
                                                                   and R.REGISTRY[x["key"]].qualifier == "optional"]
        return {"node": None, "module": module or None, "settings": rows}
    n = r.q("SELECT * FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (nid, nid))
    if not n:
        return None
    node = n[0]
    eff = V.effective(snap, node)
    now = time.time()
    rows = [{"key": k, "module": "", "label": R.REGISTRY[k].label, "value": x["value"], "value_text": R.show(k, x["value"]),
             "badge": V.badge(x), "source": x["source"], "locked_by": x["locked_by"], "errors": x["errors"],
             "section": R.REGISTRY[k].section, "applied": applied_state(node, k, now)} for k, x in eff.items()]
    if module:
        rows = _module_rows(snap, node, module, now)
    return {"node": {"node_id": node["node_id"], "hostname": node["hostname"], "settings_rev": node.get("settings_rev"),
                     "settings_applied_rev": node.get("settings_applied_rev")},
            "applied": applied_state(node, None, now), "groups": [g["name"] for g in V.node_groups(snap, node)],
            "labels": snap.node_labels(node), "memberships": membership_rows(snap, node), "settings": rows}


def membership_rows(snap: V.Snap, node: dict) -> list[dict]:
    """The node's groups, highest rank first, each with why it is a member ("member because …")."""
    return [{"id": g["id"], "name": g["name"], "rank": g["rank"], "builtin": bool(g["builtin"]), "why": g["why"]}
            for g in reversed(V.memberships(snap, node)) if g["member"]]


def explain_doc(r, key: str, nid: str | None = None, module: str = "") -> dict | None:
    snap = V.snapshot(r)
    node = None
    if nid:
        n = r.q("SELECT * FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (nid, nid))
        if not n:
            return None
        node = n[0]
    key, module = modkeys.resolve_key(snap, key, module)
    d = snap.defn(key)
    return V.explain(snap, node, key, module, applied_state(node, key) if node is not None
                     and (d.wire or d.applies != "coordinator") else None)


def overrides_doc(r, key: str, module: str = "", scope: str = "") -> dict:
    snap = V.snapshot(r)
    key, module = modkeys.resolve_key(snap, key, module)
    nodes = r.q("SELECT node_id, hostname, os, arch, facts_json FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    out = V.overrides(snap, nodes, key, module)
    if scope:
        out["values"] = [v for v in out["values"] if v["scope"] == scope]
    return out


# ------------------------------------------------------------------ a group's settings (the group page)

STAND_IN = "__group_member__"


def group_sections(r, gid: str) -> dict | None:
    """A group's Settings: each node setting at the group's scope, as its members get it from the default, the fleet
    and this group (a stand-in member of this group alone resolves it), with the lock toggles and, for a value set
    here, Promote to fleet."""
    from .groups import find
    g = find(r, gid)
    if g is None:
        return None
    snap = V.snapshot(r)
    alone = copy.copy(snap)
    alone.groups = [{**g, "members": [STAND_IN], "selector": {}}]
    alone.labels = {}
    stand_in = {"node_id": STAND_IN, "hostname": f"a member of {g['name']}", "facts": {}}
    secs = sections(alone, "group", stand_in, R.NODE_SECTIONS, scope_id=g["id"])
    now = time.time()
    mods = []                       # per module: whether it runs on the group's members, its services, its node keys
    for m in snap.modules:
        rows = [row(alone, d, "group", stand_in, now=now, scope_id=g["id"], module=m) for d in _module_defs(snap, m, "group")]
        mods.append(_module_section(f"module-{m}", m, f"What {m} does on this group's members: its values here reach only "
                                    f"{m}'s runners and services there.", rows, m))
    for sec in secs + mods:
        for x in sec["rows"] + sec["advanced"]:
            x["chain"] = [c for c in x["chain"] if c["scope"] != "node"]
    return {"group": g, "sections": secs, "modules": mods}
