"""The settings resolver (docs/design/settings.md, "Resolution"): pure functions over a reader (anything with `q`).

For one node and key the chain is: the default (static, or computed from the node's facts with its reason), the
fleet's value, each group the node belongs to by rank (lowest first), the node's own value. A lock (an enforced fleet
or group value) is found first and wins outright, fleet before groups, higher rank before lower. Otherwise the key's
merge rule decides: `replace` takes the most specific value set; `min` and `max` fold every value set (caps: the lowest
wins, so a lower scope can only tighten); `union` joins lists. A key a module owns (`qualifier = "required"`) resolves
for that module only. The result names its source, every layer with its role, the lock, the default and its reason,
and the errors of the merged values on this node (cross_checks)."""
import json

from . import registry as R
from . import store

SOURCE_NAMES = {"default": "Default", "fleet": "Fleet", "node": "This node"}


class Snap:
    """Every value row, group and label, read once for a batch of resolutions."""

    def __init__(self, r):
        self.groups = store.groups(r)
        self.labels = store.labels(r)
        self.rows: dict[tuple, dict] = {}
        for x in store.rows(r):
            self.rows[(x["scope"], x["scope_id"], x["module"], x["key"])] = x

    def get(self, scope, scope_id, module, key):
        return self.rows.get((scope, scope_id, module, key))

    def node_labels(self, node: dict) -> dict:
        """{"owner", "facts", "all"}: the owner's labels on the node and those derived from its facts (groups.py)."""
        from .groups import labels_of
        return labels_of(self.labels, node)


def snapshot(r) -> Snap:
    return Snap(r)


def facts_of(node: dict) -> dict:
    if "facts" in node and isinstance(node["facts"], dict):
        return node["facts"]
    try:
        return json.loads(node.get("facts_json") or "{}") or {}
    except ValueError:
        return {}


def memberships(snap: Snap, node: dict) -> list[dict]:
    """Every group with whether the node belongs to it and why (groups.membership), lowest rank first."""
    from .groups import membership
    labels = snap.node_labels(node)["all"]
    return [{**g, **membership(g, node, labels)} for g in snap.groups]


def node_groups(snap: Snap, node: dict) -> list[dict]:
    """The groups a node belongs to, lowest rank first (membership is evaluated now, from its facts and labels)."""
    return [g for g in memberships(snap, node) if g["member"]]


def _layer(scope, sid, name, module, row=None, value=None, reason=None, builtin=False) -> dict:
    out = {"scope": scope, "id": sid, "name": name, "module": module, "set": row is not None or builtin,
           "value": row["value"] if row is not None else value, "enforced": bool(row and row.get("enforced")),
           "rev": row.get("rev") if row else None, "by": row.get("updated_by") if row else ("system" if builtin else None),
           "at": row.get("updated_at") if row else None, "comment": row.get("comment") if row else None,
           "builtin": builtin, "reason": reason, "role": None}
    return out


def chain(snap: Snap, node: dict | None, d: R.Setting, module: str = "", campaign: str | None = None) -> list[dict]:
    """Every layer for the key, most general first. `node` None: the default and the fleet only (a fleet-wide key, or
    what a node with no group or value of its own would get). `campaign`: a campaign's value on top, for a key a
    campaign may override (a lock above still wins)."""
    if d.qualifier == "required" and not module:
        raise R.SettingError("module_required", f"{d.key} is a module's own setting: name the module", d.key)
    m = module if d.qualifier == "required" else ""
    dv, why = R.default(d, facts_of(node) if node else None)
    out = [_layer("default", "", "Default", m, value=dv, reason=why)]
    out[0]["set"] = False
    # a key a module may qualify (`optional`) resolves the plain chain, then the module's own chain above it: a value
    # set for the module beats a plain value at any scope (docs/design/settings.md, "Resolution")
    passes = [m] + ([module] if d.qualifier == "optional" and module else [])
    for mm in passes:
        tag = f" · {mm}" if mm and d.qualifier == "optional" else ""
        if "fleet" in d.scopes:
            out.append(_layer("fleet", "", "Fleet" + tag, mm, snap.get("fleet", "", mm, d.key)))
        if node is None:
            continue
        if "group" in d.scopes or d.key in {k for v in store.BUILTIN_VALUES.values() for k in v}:
            for g in node_groups(snap, node):
                row = snap.get("group", g["id"], mm, d.key) if "group" in d.scopes else None
                name = f"Group: {g['name']}" + tag
                if row is None and not mm and g["builtin"] and d.key in store.BUILTIN_VALUES.get(g["id"], {}):
                    v, reason = store.BUILTIN_VALUES[g["id"]][d.key]
                    out.append(_layer("group", g["id"], name, mm, value=json.loads(json.dumps(v)), reason=reason, builtin=True))
                else:
                    out.append(_layer("group", g["id"], name, mm, row))
                out[-1]["rank"] = g["rank"]
        if "node" in d.scopes:
            out.append(_layer("node", node["node_id"], "This node" + tag, mm, snap.get("node", node["node_id"], mm, d.key)))
    if campaign and d.campaign:
        out.append(_layer("campaign", campaign, f"Campaign {campaign}", m, snap.get("campaign", campaign, m, d.key)))
    return out


def _fold(d: R.Setting, layers: list[dict]) -> dict:
    """The winning layer of a min/max fold (ties: the most specific)."""
    rank = (lambda v: d.order.index(v) if v in d.order else -1) if d.order else (lambda v: v)
    best = None
    for lay in layers:
        v = lay["value"]
        if v is None:
            continue
        if best is None or (rank(v) < rank(best["value"]) if d.merge == "min" else rank(v) > rank(best["value"])) \
                or rank(v) == rank(best["value"]):
            best = lay
    return best or layers[-1]


def resolve(snap: Snap, node: dict | None, key: str, module: str = "", campaign: str | None = None) -> dict:
    """One key's effective value for a node (None: fleet-wide), with its provenance."""
    d = R.get(key)
    layers = chain(snap, node, d, module, campaign)
    set_ = [x for x in layers if x["set"]]
    lock = next((x for x in layers if x["scope"] == "fleet" and x["enforced"]), None) or next(
        (x for x in sorted((x for x in layers if x["scope"] == "group" and x["enforced"]), key=lambda x: -x.get("rank", 0))),
        None)
    value = None
    if lock is not None:
        winner, value = lock, lock["value"]
        below = False
        for x in layers:
            if x is lock:
                below = True
                x["role"] = "winner"
            elif x["set"]:
                x["role"] = "ignored" if below else "shadowed"
    elif not set_:
        winner, value = layers[0], layers[0]["value"]
        layers[0]["role"] = "winner"
    elif d.merge == "replace":
        winner, value = set_[-1], set_[-1]["value"]
    elif d.merge in ("min", "max"):
        winner = _fold(d, set_)
        value = winner["value"]
    else:                                         # union: every list set adds its entries
        value, winner = [], set_[-1]
        for x in set_:
            for v in x["value"] or []:
                if v not in value:
                    value.append(v)
    if lock is None:
        for x in set_:
            x["role"] = "winner" if x is winner else ("shadowed" if d.merge == "replace" else "merged")
    dv, why = layers[0]["value"], layers[0]["reason"]
    return {"key": key, "module": layers[0]["module"], "value": value,
            "source": {k: winner[k] for k in ("scope", "id", "name", "module", "rev", "by", "at", "comment", "builtin", "reason")},
            "chain": layers, "locked_by": {k: lock[k] for k in ("scope", "id", "name")} if lock else None,
            "default": {"value": dv, "reason": why}, "merge": d.merge}


def badge(res: dict) -> str:
    """The source badge as a person reads it: `Default · 24 GB RAM`, `Fleet`, `Group: macOS`, `This node`."""
    s = res["source"]
    if s["scope"] == "default":
        return "Default" + (f" · {s['reason']}" if s.get("reason") else "")
    if s.get("builtin") and s.get("reason"):
        return f"{s['name']} · {s['reason']}"
    return s["name"]


def effective(snap: Snap, node: dict) -> dict:
    """Every key a node takes (the agent's policy and caps), resolved, with the merged values' errors attached."""
    out = {d.key: resolve(snap, node, d.key) for d in R.SETTINGS if d.wire}
    for res in out.values():
        res["errors"] = []
    for e in cross_checks(node, {k: v["value"] for k, v in out.items()}, {k: v["source"]["scope"] for k, v in out.items()}):
        out[e["key"]]["errors"].append(e["message"])
    return out


def module_node_settings(snap: Snap, node_id: str) -> dict:
    """{module: settings} a node's runners get (module.node_settings, set per module on the node)."""
    return {m: x["value"] for (scope, sid, m, key), x in sorted(snap.rows.items())
            if scope == "node" and sid == node_id and key == "module.node_settings" and m}


def agent_sections(snap: Snap, node: dict, eff: dict | None = None) -> tuple[dict, dict]:
    """(policy, limits) as the agent gets them: every key present (a cap with no value is null: uncapped)."""
    eff = eff or effective(snap, node)
    policy = {k: eff[k]["value"] for k in R.WIRE_POLICY}
    policy["module_settings"] = module_node_settings(snap, node["node_id"])
    limits = {k: eff[k]["value"] for k in R.WIRE_LIMITS}
    return policy, limits


def cross_checks(node: dict, values: dict, sources: dict | None = None) -> list[dict]:
    """Errors of the merged values on this node: the reserves must leave memory for jobs, a job slot must fit in RAM,
    and a node's own cap may not exceed its hardware (a fleet or group cap above it simply does not bind there)."""
    from ..platforms import cores, memory_gb
    facts = facts_of(node)
    ram, ncores, sources = memory_gb(facts), cores(facts), sources or {}
    out = []
    num = lambda k: values.get(k) if isinstance(values.get(k), (int, float)) and not isinstance(values.get(k), bool) else None
    osr, usr, job = num("os_reserve_gb"), num("user_reserve_gb"), num("job_mem_gb")
    if ram and osr is not None and osr >= ram:
        out.append({"key": "os_reserve_gb", "message": f"{R.show('os_reserve_gb', osr)} kept for the system leaves no memory "
                                                       f"for jobs on this {ram:g} GB node"})
    elif ram and osr is not None and usr is not None and osr + usr >= ram:
        out.append({"key": "user_reserve_gb", "message": f"the two reserves ({osr:g} + {usr:g} GB) leave no memory for jobs "
                                                         f"while someone uses this {ram:g} GB node"})
    if ram and job is not None and job > ram:
        out.append({"key": "job_mem_gb", "message": f"a {job:g} GB job slot does not fit in this node's {ram:g} GB"})
    for d in R.SETTINGS:
        v = num(d.key)
        if not d.hardware or v is None or sources.get(d.key, "node") != "node":
            continue
        hw = ram if d.hardware == "ram" else ncores
        if hw and v > hw:
            what = f"{hw:g} GB of RAM" if d.hardware == "ram" else f"{hw:g} cores"
            out.append({"key": d.key, "message": f"{d.label.lower()} {R.show(d.key, v)} is more than this node's {what}"})
    return out


def explain(snap: Snap, node: dict | None, key: str, module: str = "", applied: dict | None = None) -> dict:
    """The whole chain for one key (GET /api/v1/settings/explain): each scope, its value or "not set", the winner, any
    lock, when and by whom, and the node's applied state."""
    res = resolve(snap, node, key, module)
    d = R.get(key)
    res["label"], res["unit"], res["help"] = d.label, d.unit, d.help
    res["value_text"] = R.show(key, res["value"])
    for x in res["chain"]:
        x["value_text"] = R.show(key, x["value"]) if x["set"] or x["scope"] == "default" else "not set"
    res["badge"] = badge(res)
    if node is not None:
        res["node"] = {"node_id": node["node_id"], "hostname": node.get("hostname")}
        if d.wire:
            res["errors"] = [e["message"] for e in cross_checks(node, {k: resolve(snap, node, k)["value"] for k in
                                                                      (*R.WIRE_POLICY, *R.WIRE_LIMITS)}) if e["key"] == key]
        res["applied"] = applied
    return res


def overrides(snap: Snap, nodes: list[dict], key: str, module: str = "") -> dict:
    """The reverse view (GET /api/v1/settings/overrides): every group and node value of a key, and the nodes whose
    effective value comes from somewhere below the fleet."""
    d = R.get(key)
    m = module if d.qualifier == "required" else ""
    rows = [x for (scope, sid, mm, k), x in snap.rows.items() if k == key and mm == m and scope in ("group", "node")]
    names = {n["node_id"]: n.get("hostname") for n in nodes}
    gnames = {g["id"]: g["name"] for g in snap.groups}
    vals = [{"scope": x["scope"], "id": x["scope_id"], "name": names.get(x["scope_id"]) if x["scope"] == "node"
             else gnames.get(x["scope_id"], x["scope_id"]), "value": x["value"], "value_text": R.show(key, x["value"]),
             "enforced": bool(x["enforced"]), "rev": x["rev"], "by": x["updated_by"], "at": x["updated_at"],
             "comment": x["comment"]} for x in rows]
    below = []
    if "node" in d.scopes or "group" in d.scopes:
        for n in nodes:
            res = resolve(snap, n, key, module)
            if res["source"]["scope"] in ("group", "node"):
                below.append({"node_id": n["node_id"], "hostname": n.get("hostname"), "value_text": R.show(key, res["value"]),
                              "source": badge(res)})
    fleet = resolve(snap, None, key, module)
    return {"key": key, "module": m, "label": d.label, "fleet": {"value": fleet["value"], "value_text": R.show(key, fleet["value"]),
                                                                 "source": badge(fleet)},
            "values": sorted(vals, key=lambda v: (v["scope"], v["name"] or "")), "nodes": sorted(below, key=lambda v: v["hostname"] or ""),
            "count": sum(1 for v in vals if v["scope"] == "node")}


def override_counts(snap: Snap, key: str | None = None) -> dict:
    """{key: number of node values} (the Fleet settings page's "Overridden on N nodes")."""
    out: dict = {}
    for (scope, _sid, m, k), _x in snap.rows.items():
        if scope == "node" and not m and (key is None or k == key):
            out[k] = out.get(k, 0) + 1
    return out
