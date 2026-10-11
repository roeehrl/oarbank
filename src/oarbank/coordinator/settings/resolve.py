"""The settings resolver (docs/design/settings.md, "Resolution"): pure functions over a reader (anything with `q`).

For one node and key the chain is: the default (static, or computed from the node's facts with its reason), the
fleet's value, each group the node belongs to by rank (lowest first), the node's own value. A lock (an enforced fleet
or group value) is found first and wins outright, fleet before groups, higher rank before lower. Otherwise the key's
merge rule decides: `replace` takes the most specific value set; `min` and `max` fold every value set (caps: the lowest
wins, so a lower scope can only tighten); `union` joins lists. A key a module owns (`qualifier = "required"`) resolves
for that module only. Two layers sit on top. A running campaign's value of a key it may override applies to that
campaign's jobs: a safety key (one with a `tighten` direction) only where it is stricter, any other key outright; a
lock ignores it. A machine's managed policy (MDM) may tighten a managed key on that machine, reported by its agent:
it applies where it is stricter, under a lock too. The result names its source, every layer with its role, the lock,
the default and its reason, and the errors of the merged values on this node (cross_checks)."""
import json

from . import registry as R
from . import store

SOURCE_NAMES = {"default": "Default", "fleet": "Fleet", "node": "This node", "managed": "On this machine (managed)"}
CAMPAIGN_ACTIVE = ("running", "paused")          # a campaign's overrides apply while it runs (paused: until it resumes)


class Snap:
    """Every value row, group and label, read once for a batch of resolutions, with the installed modules and their own
    keys."""

    def __init__(self, r):
        from . import modkeys
        self.groups = store.groups(r)
        self.labels = store.labels(r)
        self.rows: dict[tuple, dict] = {}
        for x in store.rows(r):
            self.rows[(x["scope"], x["scope_id"], x["module"], x["key"])] = x
        self.defs: dict[str, R.Setting] = modkeys.load(r)          # module.<module>.<key>: each module's own keys
        self.modules: list[str] = modkeys.module_names(r)
        # the running campaigns and those that set values: {campaign_id: {module, name, state}} (a campaign's layer
        # applies while it runs)
        ids = sorted({k[1] for k in self.rows if k[0] == "campaign"})
        self.campaigns: dict[str, dict] = {x["campaign_id"]: x for x in r.q(
            "SELECT campaign_id, module, name, state FROM campaigns WHERE state IN ('running','paused')"
            + (" OR campaign_id IN (%s)" % ",".join("?" * len(ids)) if ids else ""), tuple(ids))}

    def get(self, scope, scope_id, module, key):
        return self.rows.get((scope, scope_id, module, key))

    def defn(self, key: str) -> R.Setting:
        """A core key's definition, or a module's own key's (SettingError when neither)."""
        return R.get(key, self.defs)

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


def managed_of(node: dict | None) -> dict:
    """What a node's managed policy (MDM) sets, as its agent last reported: {"values": {key: value}, "by": organization,
    "refused": [{key, reason}]} (empty when nothing is managed)."""
    raw = (node or {}).get("settings_managed_json")
    if not raw:
        return {"values": {}, "by": None, "refused": []}
    try:
        doc = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return {"values": {}, "by": None, "refused": []}
    vals = {x["key"]: x.get("value") for x in doc.get("managed") or [] if isinstance(x, dict) and x.get("key")}
    return {"values": vals, "by": doc.get("managed_by"), "refused": list(doc.get("managed_refused") or [])}


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
                if row is None and mm == passes[-1] and g["builtin"] and d.key in store.BUILTIN_VALUES.get(g["id"], {}):
                    v, reason = store.BUILTIN_VALUES[g["id"]][d.key]
                    out.append(_layer("group", g["id"], name, mm, value=json.loads(json.dumps(v)), reason=reason, builtin=True))
                else:
                    out.append(_layer("group", g["id"], name, mm, row))
                out[-1]["rank"] = g["rank"]
        if "node" in d.scopes:
            out.append(_layer("node", node["node_id"], "This node" + tag, mm, snap.get("node", node["node_id"], mm, d.key)))
    if campaign and d.campaign:
        c = snap.campaigns.get(campaign) or {}
        lay = _layer("campaign", campaign, f"Campaign {c.get('name') or campaign}", m, snap.get("campaign", campaign, m, d.key))
        if lay["set"] and c.get("state") not in CAMPAIGN_ACTIVE:
            lay["set"], lay["inactive"] = False, True        # kept, shown, but a finished campaign's overrides apply nowhere
            lay["reason"] = f"the campaign is {c.get('state') or 'gone'}: its overrides apply while it runs"
        out.append(lay)
    if node is not None and d.managed:
        mg = managed_of(node)
        if d.key in mg["values"]:
            lay = _layer("managed", node["node_id"], SOURCE_NAMES["managed"], m, value=mg["values"][d.key],
                         reason="managed policy" + (f" of {mg['by']}" if mg["by"] else ""))
            lay["set"], lay["by"] = True, mg["by"] or "managed policy"
            out.append(lay)
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
    """One key's effective value for a node (None: fleet-wide), with its provenance; with `campaign`, as that campaign's
    jobs get it."""
    d = snap.defn(key)
    layers = chain(snap, node, d, module, campaign)
    top = [x for x in layers if x["scope"] in ("campaign", "managed")]
    layers_all, layers = layers, [x for x in layers if x["scope"] not in ("campaign", "managed")]
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
    for x in top:                                 # the campaign's value, then the machine's managed policy
        if not x["set"]:
            continue
        if x["scope"] == "campaign" and lock is not None:
            x["role"] = "ignored"                     # a lock binds campaigns too
            continue
        if d.tighten_dir is None and x["scope"] == "campaign":
            binds = True                              # a preference: the campaign's value is its jobs' value
        else:
            binds = R.loosens(d, value, x["value"])   # a safety key: only where it is stricter
        if binds:
            if winner.get("role") == "winner":
                winner["role"] = "shadowed"
            winner, value = x, x["value"]
            x["role"] = "winner"
        else:
            x["role"] = "looser"
    dv, why = layers[0]["value"], layers[0]["reason"]
    return {"key": key, "module": layers[0]["module"], "value": value,
            "source": {k: winner[k] for k in ("scope", "id", "name", "module", "rev", "by", "at", "comment", "builtin", "reason")},
            "chain": layers_all, "locked_by": {k: lock[k] for k in ("scope", "id", "name")} if lock else None,
            "default": {"value": dv, "reason": why}, "merge": d.merge}


def badge(res: dict) -> str:
    """The source badge as a person reads it: `Default · 24 GB RAM`, `Fleet`, `Group: macOS`, `This node`."""
    s = res["source"]
    if s["scope"] == "default":
        return "Default" + (f" · {s['reason']}" if s.get("reason") else "")
    if s["scope"] == "managed":
        return s["name"] + (f" · {s['by']}" if s.get("by") and s["by"] != "managed policy" else "")
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


def module_settings(snap: Snap, node: dict | None, module: str, scope: str | None = "node",
                    campaign: str | None = None) -> dict:
    """What one module's processes get: each of its own keys (of `scope`: `node` for its runners and services on `node`,
    None for every key, as its coordinator side gets them with `node` None) with its effective value, else its default;
    a key with neither is absent. Only this module's keys: another module's never reach it. With `campaign`: as that
    campaign's jobs get them."""
    from . import modkeys
    out = {}
    for key, d in snap.defs.items():
        m, name = modkeys.split(key)
        if m != module or (scope == "node" and "node" not in d.scopes):
            continue
        res = resolve(snap, node, key, module, campaign)
        if res["source"]["scope"] != "default" or modkeys.has_default(d):
            out[name] = res["value"]
    return out


# the keys a node applies that a campaign may override; the coordinator holds the campaign's jobs to them at claim
NODE_CAMPAIGN_KEYS = ("jobs", "run_on_battery", "user_present_slots")


def campaign_rules(snap: Snap, node: dict, campaign: str | None) -> dict:
    """{key: value} of the node-applied keys a running campaign holds its jobs to on this node: only where the
    campaign's own value is what applies (stricter than the node's; a lock above ignores it). Claim and explain check
    them (predicates: CAMPAIGN_SETTING_HOLDS); the agent's capacity already applies the node's own values."""
    if not campaign or (snap.campaigns.get(campaign) or {}).get("state") not in CAMPAIGN_ACTIVE:
        return {}
    keys = {k for (scope, sid, _m, k) in snap.rows if scope == "campaign" and sid == campaign and k in NODE_CAMPAIGN_KEYS}
    out = {}
    for k in sorted(keys):
        res = resolve(snap, node, k, "", campaign)
        if res["source"]["scope"] == "campaign":
            out[k] = res["value"]
    return out


def campaign_values(snap: Snap, campaign: str, module: str) -> dict:
    """A campaign's own values of its module's own keys, as they apply to its jobs: {short name: value} of the keys it
    sets while it runs (none once it is done). What a grant adds over the node's settings for a job of the campaign."""
    from . import modkeys
    c = snap.campaigns.get(campaign) or {}
    if c.get("state") not in CAMPAIGN_ACTIVE:
        return {}
    out = {}
    for (scope, sid, m, key), x in snap.rows.items():
        if scope == "campaign" and sid == campaign and m == module:
            mm, name = modkeys.split(key)
            d = snap.defs.get(key)
            if mm == module and d is not None and d.campaign:
                out[name] = x["value"]
    return out


def node_modules(snap: Snap, node: dict) -> dict:
    """Per installed module on this node: its node-scoped settings, the services it does not run, whether it runs here,
    and the required settings with no value here."""
    from . import modkeys
    out = {}
    for m in snap.modules:
        out[m] = {"settings": module_settings(snap, node, m),
                  "services_disabled": list(resolve(snap, node, "services.disabled", m)["value"] or []),
                  "enabled": bool(resolve(snap, node, "enabled", m)["value"]),
                  "unset": modkeys.unset(snap, node, m)}
    return out


def agent_sections(snap: Snap, node: dict, eff: dict | None = None, mods: dict | None = None) -> tuple[dict, dict]:
    """(policy, limits) as the agent gets them: every key present (a cap with no value is null: uncapped); per module
    its node settings (`module_settings`) and the services it does not run (`disabled_services`, as module/service)."""
    eff = eff or effective(snap, node)
    mods = node_modules(snap, node) if mods is None else mods
    policy = {k: eff[k]["value"] for k in R.WIRE_POLICY}
    policy["module_settings"] = {m: x["settings"] for m, x in mods.items() if x["settings"]}
    policy["disabled_services"] = sorted(f"{m}/{s}" for m, x in mods.items() for s in x["services_disabled"])
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


def explain(snap: Snap, node: dict | None, key: str, module: str = "", applied: dict | None = None,
            campaign: str | None = None) -> dict:
    """The whole chain for one key (GET /api/v1/settings/explain): each scope, its value or "not set", the winner, any
    lock, when and by whom, and the node's applied state; with `campaign`, as that campaign's jobs get it."""
    res = resolve(snap, node, key, module, campaign)
    d = snap.defn(key)
    res["label"], res["unit"], res["help"] = d.label, d.unit, d.help
    res["value_text"] = R.show(key, res["value"], d)
    for x in res["chain"]:
        x["value_text"] = R.show(key, x["value"], d) if x["set"] or x["scope"] == "default" or x.get("inactive") else "not set"
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
    d = snap.defn(key)
    m = module if d.qualifier == "required" else ""
    rows = [x for (scope, sid, mm, k), x in snap.rows.items() if k == key and mm == m and scope in ("group", "node")]
    names = {n["node_id"]: n.get("hostname") for n in nodes}
    gnames = {g["id"]: g["name"] for g in snap.groups}
    vals = [{"scope": x["scope"], "id": x["scope_id"], "name": names.get(x["scope_id"]) if x["scope"] == "node"
             else gnames.get(x["scope_id"], x["scope_id"]), "value": x["value"], "value_text": R.show(key, x["value"], d),
             "enforced": bool(x["enforced"]), "rev": x["rev"], "by": x["updated_by"], "at": x["updated_at"],
             "comment": x["comment"]} for x in rows]
    below = []
    if "node" in d.scopes or "group" in d.scopes:
        for n in nodes:
            res = resolve(snap, n, key, module)
            if res["source"]["scope"] in ("group", "node"):
                below.append({"node_id": n["node_id"], "hostname": n.get("hostname"), "value_text": R.show(key, res["value"], d),
                              "source": badge(res)})
    fleet = resolve(snap, None, key, module)
    return {"key": key, "module": m, "label": d.label, "fleet": {"value": fleet["value"], "value_text": R.show(key, fleet["value"], d),
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
