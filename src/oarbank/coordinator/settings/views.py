"""Settings as pages and the API show them: one row per setting at one scope (the console's `setting_row` macro, the
API's effective view, `oarbank settings get`). Pure functions over a reader (anything with `q`).

A row carries the definition (label, unit, help, the raw key), the effective value and the badge naming its source,
whether this scope sets it ("overridden here"), what it would inherit without this scope's value, a lock above, the
merged values' errors on the node, the node's applied state, the whole chain for Explain and, at fleet scope, how many
nodes override it."""
import copy
import json
import time

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
    if "enum" in d.schema:
        return {"kind": "select", "choices": list(d.schema["enum"])}
    t = next(t for t in _types(d) if t != "null")
    kind = INPUT.get(t, "text")
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


def form_text(key: str, v) -> str:
    """A value as a form field shows it (lists one entry per line for text areas, comma-separated in inputs)."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else ""
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
        errors: dict | None = None, now: float | None = None, scope_id: str = "") -> dict:
    """One setting at one scope (fleet: node None; node: that node; group: `scope_id`, with `node` a stand-in member,
    group_sections)."""
    sid = node["node_id"] if scope == "node" else scope_id
    res = V.resolve(snap, node, d.key)
    own = snap.get(scope, sid, "", d.key)
    inh = V.resolve(_without(snap, scope, sid, d.key), node, d.key) if own else res
    for x in res["chain"]:
        x["value_text"] = R.show(d.key, x["value"]) if x["set"] or x["scope"] == "default" else "not set"
    out = {"key": d.key, "label": d.label, "unit": d.unit, "help": d.help, "note": d.note, "advanced": d.advanced,
           "section": d.section, "input": input_of(d), "scope": scope, "scope_id": sid, "lockable": d.lockable,
           "merge": d.merge, "danger": d.danger, "value": res["value"], "value_text": R.show(d.key, res["value"]),
           "form_value": form_text(d.key, own["value"] if own else inh["value"]),
           "badge": V.badge(res), "source": res["source"], "overridden_here": own is not None,
           "own": {"value": own["value"], "rev": own["rev"], "by": own["updated_by"], "at": own["updated_at"],
                   "comment": own["comment"], "enforced": bool(own["enforced"])} if own else None,
           "inherited": {"value": inh["value"], "text": R.show(d.key, inh["value"]), "badge": V.badge(inh)},
           "locked_by": res["locked_by"] if res["locked_by"] and res["locked_by"]["scope"] != scope else None,
           "lock_text": lock_text(res["locked_by"]) if res["locked_by"] and res["locked_by"]["scope"] != scope else None,
           "locked_here": bool(own and own["enforced"]), "own_text": R.show(d.key, own["value"]) if own else None,
           "chain": res["chain"], "default": {**res["default"], "text": R.show(d.key, res["default"]["value"])},
           "errors": list((errors or {}).get(d.key, [])), "form_errors": [], "typed": False,
           "override_count": (counts or {}).get(d.key, 0) if scope == "fleet" else None,
           "applied": applied_state(node, d.key, now) if scope == "node" and node is not None and d.wire else None}
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
            out["form_value"] = form_text(d.key, d.default)
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
    modules = V.module_node_settings(snap, node["node_id"])
    return {"node": node, "sections": sections(snap, "node", node, R.NODE_SECTIONS, errors=errors),
            "applied": applied_state(node), "groups": [g["name"] for g in V.node_groups(snap, node)],
            "labels": snap.node_labels(node), "memberships": membership_rows(snap, node),
            "module_settings": modules, "rev": node.get("settings_rev") or 0}


def fleet_page(r) -> dict:
    """Fleet Settings' sections: node defaults (with how many nodes override each) and the fleet-wide keys."""
    snap = V.snapshot(r)
    counts = V.override_counts(snap)
    nodes = r.q("SELECT COUNT(*) n FROM nodes WHERE lifecycle!='retired'")[0]["n"]
    return {"node_defaults": sections(snap, "fleet", None, R.NODE_SECTIONS, counts),
            "fleet": sections(snap, "fleet", None, R.FLEET_SECTIONS), "nodes": nodes,
            "groups": snap.groups}


def effective_doc(r, nid: str | None = None, module: str = "") -> dict:
    """GET /api/v1/settings/effective: every key for a node (or fleet-wide), with provenance and applied state."""
    snap = V.snapshot(r)
    if not nid:
        rows = []
        for d in R.SETTINGS:
            if "fleet" not in d.scopes or (d.qualifier and not module):
                continue
            res = V.resolve(snap, None, d.key, module)
            rows.append({"key": d.key, "module": res["module"], "label": d.label, "value": res["value"],
                         "value_text": R.show(d.key, res["value"]), "badge": V.badge(res), "source": res["source"],
                         "section": d.section, "writer": d.writer})
        return {"node": None, "settings": rows}
    n = r.q("SELECT * FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (nid, nid))
    if not n:
        return None
    node = n[0]
    eff = V.effective(snap, node)
    now = time.time()
    rows = [{"key": k, "module": "", "label": R.REGISTRY[k].label, "value": x["value"], "value_text": R.show(k, x["value"]),
             "badge": V.badge(x), "source": x["source"], "locked_by": x["locked_by"], "errors": x["errors"],
             "section": R.REGISTRY[k].section, "applied": applied_state(node, k, now)} for k, x in eff.items()]
    for m, v in V.module_node_settings(snap, node["node_id"]).items():
        if not module or module == m:
            rows.append({"key": "module.node_settings", "module": m, "label": R.REGISTRY["module.node_settings"].label,
                         "value": v, "value_text": R.show("module.node_settings", v), "badge": "This node",
                         "source": {"scope": "node", "id": node["node_id"], "name": "This node", "module": m}, "errors": []})
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
    d = R.get(key)
    return V.explain(snap, node, key, module, applied_state(node, key) if node is not None and d.wire else None)


def overrides_doc(r, key: str, module: str = "", scope: str = "") -> dict:
    snap = V.snapshot(r)
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
    for sec in secs:
        for x in sec["rows"] + sec["advanced"]:
            x["chain"] = [c for c in x["chain"] if c["scope"] != "node"]
    return {"group": g, "sections": secs}
