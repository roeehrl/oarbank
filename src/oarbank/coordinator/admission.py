"""What a node starts as when the owner approves it (docs/design/node-enrollment.md, "Admission").

An approval (`nodes.admit`, `nodes.admit_code`) may carry admission options:

    {"state": "active" | "paused" | "draining",
     "modules": {"<module>": false | true},            # the node's own `[module] enabled`
     "settings": [{"key", "value", "module"?}, ...],   # node-scoped settings, checked as settings.apply checks them
     "labels": ["<label>", ...], "groups": ["<owner group>", ...],
     "adopt_settings_from": "<node>"}                  # "the same machine": see below

They are written in the transaction that creates the node and issues its certificate, before the enrollment is marked
approved: the agent can fetch its certificate only after that transaction commits, so there is no moment at which the
node exists with the fleet's defaults and could be granted a job or a certification golden. A paused node is never
granted anything, and a module turned off on a node gets no golden there (core._lifecycle_step).

A new node with no choice of its own follows the fleet's onboarding policy: `new_node_state` (active | paused) and
`new_node_modules` (all | none). A re-enrolled node (it proved its key: nodeidentity.py) keeps its own settings; options
given for it change it like any other node.

`adopt_settings_from` is the owner's explicit statement that a request which looks like a known node but cannot prove
its key (a reinstalled machine) is that machine. It carries the old node's node-scoped settings (module switches,
protection, update holds and pins, caps, ...), its desired state, labels, explicit group memberships, module version
pins, site and owner-given name over to the new node, and retires the old record, in the same transaction. It is never
automatic, it is refused for a request that proves a node's key (that request keeps the node already) and for an old
node that is still online (a machine running it cannot be the one asking), and it carries no credential: secrets set
for the old node are dropped with it, and the new node keeps its own key and certificate."""
import json

from . import clock, config as C
from .core import ApiError
from .db import jl

STATES = ("active", "paused", "draining")
PARAMS = ("state", "modules", "settings", "labels", "groups", "adopt_settings_from")


class AdmissionError(ApiError):
    """A refused option; `errors` lists a settings refusal per change (as settings.apply returns them)."""

    def __init__(self, status: int, code: str, detail: str, errors: list | None = None):
        super().__init__(status, code, detail)
        self.errors = errors or []


def _names(v, what: str) -> list[str]:
    if v in (None, "", []):
        return []
    if isinstance(v, str):
        v = v.split(",")
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise AdmissionError(400, "bad_params", f"{what}: a list of names")
    return list(dict.fromkeys(x.strip() for x in v if x.strip()))


def parse(params: dict | None) -> dict:
    """The approval's admission options, checked for form; their values are checked when they are applied (the
    settings registry, the modules installed, the groups that exist)."""
    p = {k: v for k, v in (params or {}).items() if k != "user_code"}
    extra = sorted(set(p) - set(PARAMS))
    if extra:
        raise AdmissionError(400, "bad_params", f"an approval takes {', '.join(PARAMS)}, not {extra}")
    state = p.get("state") or None
    if state is not None and state not in STATES:
        raise AdmissionError(400, "bad_state", f"state: {' | '.join(STATES)}, not {state!r}")
    mods = p.get("modules") or {}
    if not isinstance(mods, dict) or not all(isinstance(k, str) and isinstance(v, bool) for k, v in mods.items()):
        raise AdmissionError(400, "bad_params", "modules: {module: true | false}")
    sets = p.get("settings") or []
    if isinstance(sets, dict):
        sets = [{"key": k, "value": v} for k, v in sets.items()]
    if not isinstance(sets, list):
        raise AdmissionError(400, "bad_params", "settings: a list of {key, value, module}")
    out_sets = []
    for i, c in enumerate(sets):
        if not isinstance(c, dict) or not isinstance(c.get("key"), str) or "value" not in c \
                or set(c) - {"key", "value", "module"}:
            raise AdmissionError(400, "bad_params", f"settings[{i}]: {{key, value, module}} (a node's own value; "
                                                    "scope and reset do not apply)")
        out_sets.append({"key": c["key"].strip(), "value": c["value"], "module": (c.get("module") or "").strip()})
    adopt = p.get("adopt_settings_from")
    if adopt is not None and (not isinstance(adopt, str) or not adopt.strip()):
        raise AdmissionError(400, "bad_params", "adopt_settings_from: the old node (its id or name)")
    return {"state": state, "modules": {k.strip(): v for k, v in mods.items()}, "settings": out_sets,
            "labels": _names(p.get("labels"), "labels"), "groups": _names(p.get("groups"), "groups"),
            "adopt": adopt.strip() if adopt else None}


def policy(r) -> dict:
    """The fleet's onboarding policy: {"state": active|paused, "modules": all|none}."""
    from .settings import store
    return {"state": store.fleet_value(r, "new_node_state"), "modules": store.fleet_value(r, "new_node_modules")}


def adopt_target(db, ident: dict, who: str) -> dict:
    """The old node an approval may carry over (a lookalike of this request that is offline), or AdmissionError."""
    if ident.get("node_id"):
        raise AdmissionError(409, "adopt_refused", f"this request proves the key of {ident['hostname']} "
                                                   f"({ident['node_id']}): approving it keeps that node, its settings and "
                                                   "history already; there is nothing to carry over")
    old = db.one("SELECT * FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired' ORDER BY node_id=? DESC",
                 (who, who, who))
    if not old:
        raise AdmissionError(404, "unknown_node", f"adopt_settings_from: no node {who!r} (a retired node cannot be "
                                                  "carried over)")
    if old["node_id"] not in {n["node_id"] for n in ident.get("lookalikes") or []}:
        raise AdmissionError(409, "adopt_refused", f"{old['hostname']} ({old['node_id']}) is not a node this machine "
                                                   "looks like (the same host name): only such a node's settings can be "
                                                   "carried over")
    hb = old.get("last_heartbeat_at")
    if hb and clock.now() - hb < C.OFFLINE_AFTER:
        raise AdmissionError(409, "adopt_refused", f"{old['hostname']} ({old['node_id']}) is still online: a machine that "
                                                   "runs it cannot be the one asking. Approve without carrying it over, "
                                                   "or wait until it is offline")
    return old


def _adopt(db, old: dict, nid: str, actor: str) -> list[str]:
    """Carry the old node's own settings, state, labels, groups, pins and site over to node `nid`, then retire the
    old record (inside the caller's transaction). Returns what it carried, as lines."""
    from . import core
    from .settings import store
    oid = old["node_id"]
    rows = db.q("SELECT module, key, value_json, enforced, comment FROM setting_values WHERE scope='node' AND scope_id=? "
                "ORDER BY module, key", (oid,))
    out = []
    if rows:
        rev = store.next_rev(db)
        for x in rows:
            store.put(db, "node", nid, x["module"], x["key"], json.loads(x["value_json"]), actor, rev,
                      x["comment"] or f"carried over from {oid}", bool(x["enforced"]))
        out.append("its own settings: " + ", ".join((f"[{x['module']}] " if x["module"] else "") + x["key"] for x in rows))
    db.x("UPDATE nodes SET desired_state=? WHERE node_id=?", (old["desired_state"], nid))
    out.append(f"desired state: {old['desired_state']}")
    if old.get("label"):
        db.x("UPDATE nodes SET label=?, hostname=? WHERE node_id=? AND label IS NULL", (old["label"], old["label"], nid))
    labels = [x["label"] for x in db.q("SELECT label FROM node_labels WHERE node_id=? ORDER BY label", (oid,))]
    for lab in labels:
        db.x("INSERT OR IGNORE INTO node_labels(node_id,label,set_by,set_at) VALUES(?,?,?,?)", (nid, lab, actor, clock.now()))
    if labels:
        out.append("labels: " + ", ".join(labels))
    joined = []
    for g in db.q("SELECT id, name, members_json FROM node_groups WHERE builtin=0"):
        members = jl(g["members_json"], []) or []
        if oid in members:
            members = [nid if m == oid else m for m in members]
            db.x("UPDATE node_groups SET members_json=? WHERE id=?", (json.dumps(list(dict.fromkeys(members))), g["id"]))
            joined.append(g["name"])
    if joined:
        out.append("listed in the groups: " + ", ".join(joined))
    pins = db.q("SELECT name, version FROM module_pins WHERE node_id=?", (oid,))
    for p in pins:
        db.x("INSERT OR REPLACE INTO module_pins(name,node_id,version) VALUES(?,?,?)", (p["name"], nid, p["version"]))
    if pins:
        out.append("module version pins: " + ", ".join(f"{p['name']}@{p['version']}" for p in pins))
    site = db.one("SELECT site_id FROM site_members WHERE node_id=?", (oid,))
    if site:
        db.x("INSERT OR REPLACE INTO site_members(node_id,site_id,added_by,added_at) VALUES(?,?,?,?)",
             (nid, site["site_id"], actor, clock.now()))
        db.x("DELETE FROM site_members WHERE node_id=?", (oid,))
        out.append(f"site: {site['site_id']}")
    from . import statements
    statements.refresh(db, [nid])                    # host tool paths and listeners its settings name
    pinned = core.retire_node(db, oid, actor, f"replaced by {nid}: the owner confirmed it is the same machine")
    out.append(f"retired {old['hostname']} ({oid})" + (f"; {pinned} jobs pinned to it cancelled" if pinned else ""))
    db.event("node_adopted", actor=actor, node_id=nid, reason=f"carried over from {oid} ({old['hostname']}), which is "
             "retired", old_node_id=oid, carried=out)
    return out


def apply(db, nid: str, adm: dict | None, ident: dict, actor: str, eid: str) -> dict:
    """Write the admission options (and, for a new node, the onboarding policy) on node `nid`, inside the approval's
    transaction. Returns what it did ({} when nothing), for the result, the event and the preview."""
    from .settings import apply as A, groups as G
    from .settings import resolve as V
    adm = adm or parse({})
    new = not ident.get("node_id")
    out: dict = {}
    if adm["adopt"]:
        out["carried_over"] = _adopt(db, adopt_target(db, ident, adm["adopt"]), nid, actor)
    pol = policy(db) if new and not adm["adopt"] else {"state": None, "modules": "all"}
    state = adm["state"] or (pol["state"] if pol["state"] != "active" else None)
    if state:
        db.x("UPDATE nodes SET desired_state=? WHERE node_id=?", (state, nid))
        db.event("node_state", actor=actor, node_id=nid, reason=f"{state} (at its approval)")
        out["state"] = state + ("" if adm["state"] else " (the fleet's new_node_state)")
    try:
        if adm["labels"]:
            out["labels"] = G.set_labels(db, nid, add=adm["labels"], actor=actor)["labels"]
        for gname in adm["groups"]:
            g = G.get_owner(db, gname)
            if nid not in g["members"]:
                db.x("UPDATE node_groups SET members_json=?, updated_by=?, updated_at=? WHERE id=?",
                     (json.dumps([*g["members"], nid]), actor, clock.now(), g["id"]))
            out.setdefault("groups", []).append(g["name"])
    except G.GroupError as e:
        raise AdmissionError(e.status, e.code, e.detail)
    changes = [{"scope": "node", "scope_id": nid, "module": m, "key": "enabled", "value": on}
               for m, on in sorted(adm["modules"].items())]
    if pol["modules"] == "none":                     # every installed module off here, unless a lock holds it on
        snap = V.snapshot(db)
        for m in [r["name"] for r in db.q("SELECT DISTINCT name FROM modules ORDER BY name")]:
            if m not in adm["modules"] and not A.lock_on(snap, db, "node", nid, m, "enabled"):
                changes.append({"scope": "node", "scope_id": nid, "module": m, "key": "enabled", "value": False})
                out.setdefault("policy_modules_off", []).append(m)
    changes += [{"scope": "node", "scope_id": nid, "module": c["module"], "key": c["key"], "value": c["value"]}
                for c in adm["settings"]]
    if changes:
        try:
            out["settings"] = A.plan(db, changes)["changes"]
            A.commit(db, changes, actor, f"set at the approval of {eid}")
        except A.ApplyError as e:
            raise AdmissionError(e.status, e.code, e.detail, e.errors)
    return out


class _Preview(Exception):
    pass


def preview(db, e: dict, adm: dict) -> dict:
    """What approving this enrollment with these options makes: the approval's own node creation and every option,
    run in a transaction that is rolled back (so the preview refuses exactly what the approval would). {} when there
    is nothing beyond a plain approval to say."""
    from . import core
    from .settings import apply as A
    seen: dict = {}
    try:
        with db.tx():
            nid, ident, out = core.admit_node(db, e, "preview", None, adm)
            n = db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))
            doc = A.node_values(n)
            seen = {"out": out, "state": n["desired_state"], "off": doc.get("modules_disabled") or [],
                    "new": not ident.get("node_id")}
            raise _Preview
    except _Preview:
        pass
    if not seen:
        return {}
    out = seen["out"]
    res = {"starts": seen["state"] + {"active": ": it takes work once its modules are certified",
                                      "paused": ": it takes no jobs (certification goldens included) and runs no "
                                                "workloads until you resume it",
                                      "draining": ": it takes no new work"}[seen["state"]]}
    if seen["off"]:
        res["modules_off_there"] = sorted(seen["off"])
    if out.get("policy_modules_off"):
        res["policy"] = "the fleet's new_node_modules is none: every installed module is off on it until you turn it on"
    for k in ("settings", "labels", "groups"):
        if out.get(k):
            res[k + ("_set" if k == "settings" else "")] = out[k]
    if out.get("carried_over"):
        res["same_machine"] = out["carried_over"]
    return res
