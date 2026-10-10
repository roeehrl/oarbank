"""Change sets and what nodes get (docs/design/settings.md, "Saving" and "What the agent gets").

`plan` checks a change set (`settings.apply {changes: [{scope, scope_id, module, key, value | reset, enforce}]}`)
against the registry, the scopes, locks and the merged values on every node it reaches, and says what it changes:
per node, old and new effective value, and the nodes that keep theirs (they override it, or a lock holds). The dry run
is the same call. `commit` writes the rows under one revision, runs the keys' effect hooks on the nodes whose effective
value changed, and refreshes those nodes' effective settings.

`sync_nodes` keeps each node's effective settings (`nodes.settings_json`: the complete policy and caps the agent gets)
and the revision at which they last changed (`settings_rev`); the agent reports the revision it applied and any key it
refused (`settings_applied_rev`, `settings_rejected_json`), which the console shows on each row."""
import copy
import hashlib
import json
import time

from ...common import canonical_json
from . import modcore, modkeys
from . import registry as R
from . import resolve as V
from . import store

class ApplyError(Exception):
    def __init__(self, status: int, code: str, detail: str, errors: list | None = None):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail, self.errors = status, code, detail, errors or []


def _nodes(r) -> list[dict]:
    return r.q("SELECT node_id, hostname, os, arch, platform, facts_json, last_heartbeat_at, settings_rev, "
               "settings_applied_rev, settings_rejected_json, agent_version FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")


def _node_id(db, ident: str) -> str | None:
    r = db.one("SELECT node_id FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (ident, ident))
    return r["node_id"] if r else None


def _group_id(db, ident: str) -> str | None:
    for g in store.groups(db):
        if ident and ident.lower() in (g["id"].lower(), g["name"].lower()):
            return g["id"]
    return None


def normalize(db, changes) -> list[dict]:
    """The change set, checked: each change's scope id resolved (a hostname or a group's name), its value checked against
    the registry, refused where its key may not be set, owns another operation, or a lock holds above. Every problem is
    collected (ApplyError 400 invalid_settings, one entry per change and field)."""
    if not isinstance(changes, list) or not changes:
        raise ApplyError(400, "bad_params", "changes: a non-empty list of {scope, scope_id, module, key, value | reset}")
    out, errors, seen = [], [], set()
    snap = V.snapshot(db)
    for i, c in enumerate(changes):
        if not isinstance(c, dict):
            errors.append({"index": i, "message": "a change is an object"})
            continue
        key, scope, module = c.get("key") or "", c.get("scope") or "", c.get("module") or ""
        err = lambda msg, code="bad_value": errors.append({"index": i, "key": key, "scope": scope, "module": module,
                                                          "scope_id": c.get("scope_id") or "", "code": code, "message": msg})
        extra = set(c) - {"scope", "scope_id", "module", "key", "value", "reset", "enforce"}
        if extra:
            err(f"unknown fields {sorted(extra)}", "bad_params")
            continue
        key, module = modkeys.resolve_key(snap, key, c.get("module") or "")
        d = R.lookup(key, snap.defs)
        if d is None and c.get("reset") and modkeys.split(key)[0]:
            d = _orphan(key)                           # a value its module no longer declares: it can be reset
        if d is None:
            err(f"no setting {key!r}" + (f" (the module {module} declares no such key)" if module else ""), "unknown_setting")
            continue
        if d.writer:
            err(f"{d.label} ({key}) is changed with {d.writer}, which checks it and applies its effects", "use_typed_operation")
            continue
        if scope not in R.SCOPES:
            err("scope: fleet, group or node", "bad_scope")
            continue
        if scope not in d.scopes:
            err(f"{d.label} can be set for: {', '.join(d.scopes)}", "not_settable_here")
            continue
        if d.qualifier == "required" and not module:
            err(f"{key} is a module's own setting: name the module", "module_required")
            continue
        if module and not d.qualifier:
            err(f"{key} is not set per module", "not_settable_here")
            continue
        if modkeys.split(key)[0] not in (None, module):
            err(f"{key} is {modkeys.split(key)[0]}'s own setting, not {module}'s", "not_settable_here")
            continue
        if module and not db.one("SELECT 1 FROM modules WHERE name=?", (module,)):
            err(f"no module {module!r} is installed", "unknown_module")
            continue
        sid = ""
        if scope == "node":
            sid = _node_id(db, c.get("scope_id") or "")
            if not sid:
                err(f"no node {c.get('scope_id')!r}", "unknown_node")
                continue
        elif scope == "group":
            sid = _group_id(db, c.get("scope_id") or "")
            if not sid:
                err(f"no group {c.get('scope_id')!r}", "unknown_group")
                continue
        reset, enforce = bool(c.get("reset")), bool(c.get("enforce"))
        if enforce and (not d.lockable or scope not in ("fleet", "group")):
            err(f"{d.label} cannot be locked at {scope} scope", "not_lockable")
            continue
        if not reset and "value" not in c:
            err("give a value, or reset", "bad_params")
            continue
        value = None
        if not reset:
            try:
                value = R.check(key, c["value"], d)
            except R.SettingError as e:
                err(e.detail.replace(key + ":", d.label + ":", 1) if e.detail.startswith(key) else e.detail, e.code)
                continue
            why = modcore.check(db, key, module, value) if module else None
            if why:
                err(why, "bad_value")
                continue
        ident = (scope, sid, module, key)
        if ident in seen:
            err("the change set names this setting twice for the same scope", "duplicate")
            continue
        seen.add(ident)
        if scope in ("group", "node") and not reset:
            lock = _lock_above(snap, db, scope, sid, module, key)
            if lock:
                err(f"locked by {lock}: change it there", "locked")
                continue
        out.append({"scope": scope, "scope_id": sid, "module": module, "key": key, "reset": reset,
                    "value": value, "enforce": enforce, **({"orphan": True} if d.section == "orphan" else {})})
    if errors:
        raise ApplyError(400, "invalid_settings", "; ".join(f"{e.get('key') or '#' + str(e['index'])}: {e['message']}"
                                                            for e in errors)[:800], errors)
    return out


def _orphan(key: str) -> R.Setting:
    """A stand-in definition for a value whose module no longer declares its key (modkeys.orphans): it can only be
    reset, and it reaches no node."""
    return R.Setting(key, modkeys.split(key)[1], "No longer declared by the module's registered version.", {},
                     applies="coordinator", qualifier="required", section="orphan", lockable=False)


def _defn(snap: V.Snap, c: dict) -> R.Setting:
    return _orphan(c["key"]) if c.get("orphan") else snap.defn(c["key"])


def _lock_above(snap, db, scope, sid, module, key) -> str | None:
    lock = lock_on(snap, db, scope, sid, module, key)
    return lock["text"] if lock else None


def lock_on(snap, db, scope, sid, module, key) -> dict | None:
    """The lock that refuses a value at this scope: the fleet's for a group, a node or a campaign; for a node also its
    groups' (the highest rank first). {scope, id, name, text} ("the group Laptops"), or None."""
    row = snap.get("fleet", "", module, key)
    if row and row.get("enforced"):
        return {"scope": "fleet", "id": "", "name": "Fleet", "text": "Fleet settings"}
    if scope == "node":
        node = db.one("SELECT node_id, hostname, os, arch, facts_json FROM nodes WHERE node_id=?", (sid,))
        for g in reversed(V.node_groups(snap, node)) if node else ():
            if (snap.get("group", g["id"], module, key) or {}).get("enforced"):
                return {"scope": "group", "id": g["id"], "name": g["name"], "text": f"the group {g['name']}"}
    return None


def campaign_refusals(db, campaign_id: str, key: str, module: str = "", node_ids=None) -> list[dict]:
    """The hook campaign overrides (docs/design/settings.md, "Locks") go through: a lock binds a campaign too, so a
    value a campaign would set is refused where a fleet lock, or a lock of a group any of its nodes is in, holds, naming
    the lock; then a key that is not campaign-overridable is refused. Empty: the override may be written."""
    snap = V.snapshot(db)
    key, module = modkeys.resolve_key(snap, key, module)
    d = snap.defn(key)
    out = []
    lock = lock_on(snap, db, "campaign", campaign_id, module, key)
    if lock:
        out.append({"key": key, "scope": "campaign", "scope_id": campaign_id, "code": "locked",
                    "message": f"{d.label}: locked by {lock['text']}: change it there"})
    else:
        ids = node_ids if node_ids is not None else [n["node_id"] for n in _nodes(db)]
        for nid in ids:
            lk = lock_on(snap, db, "node", nid, module, key)
            if lk:
                host = (db.one("SELECT hostname FROM nodes WHERE node_id=?", (nid,)) or {}).get("hostname") or nid
                out.append({"key": key, "scope": "campaign", "scope_id": campaign_id, "code": "locked",
                            "message": f"{d.label}: locked by {lk['text']} on {host}: change it there"})
    if not out and not d.campaign:
        out.append({"key": key, "scope": "campaign", "scope_id": campaign_id, "code": "not_campaign_overridable",
                    "message": f"{d.label} is not a setting a campaign may override"})
    return out


def _after(snap: V.Snap, changes: list[dict]) -> V.Snap:
    out = copy.copy(snap)
    out.rows = dict(snap.rows)
    for c in changes:
        ident = (c["scope"], c["scope_id"], c["module"], c["key"])
        if c["reset"]:
            out.rows.pop(ident, None)
        else:
            out.rows[ident] = {"scope": c["scope"], "scope_id": c["scope_id"], "module": c["module"], "key": c["key"],
                               "value": c["value"], "enforced": int(c["enforce"]), "rev": None, "comment": None,
                               "updated_by": "(this change)", "updated_at": None}
    return out


def _reaches(snap: V.Snap, node: dict, c: dict) -> bool:
    if c["scope"] == "fleet":
        return True
    if c["scope"] == "group":
        return any(g["id"] == c["scope_id"] for g in V.node_groups(snap, node))
    return node["node_id"] == c["scope_id"]


def _change_text(c: dict, names: dict, before: V.Snap) -> str:
    d = _defn(before, c)
    where = {"fleet": "Fleet", "group": f"group {names.get(c['scope_id'], c['scope_id'])}",
             "node": names.get(c["scope_id"], c["scope_id"])}[c["scope"]]
    old = before.get(c["scope"], c["scope_id"], c["module"], c["key"])
    was = R.show(c["key"], old["value"], d) if old else "not set"
    now = "reset (inherits)" if c["reset"] else R.show(c["key"], c["value"], d) + (" (locked)" if c["enforce"] else "")
    return f"{d.label}{' [' + c['module'] + ']' if c['module'] else ''} at {where}: {was} → {now}"


def plan(db, changes) -> dict:
    """The change set's impact: per node and key, old and new effective value; the nodes that keep theirs and why; new
    errors of the merged values (refused: ApplyError 400 with one entry per node and key)."""
    norm = normalize(db, changes)
    before = V.snapshot(db)
    after = _after(before, norm)
    nodes = _nodes(db)
    names = {n["node_id"]: n["hostname"] for n in nodes} | {g["id"]: g["name"] for g in before.groups}
    # keys a node takes: the agent's policy and caps, host tool paths (tool_pins and the node statement), protection, and
    # per module whether it runs there, its services and its node-scoped settings (everything not applied by the
    # coordinator alone)
    defn = before.defn
    wire_keys = sorted({c["key"] for c in norm if not c.get("orphan") and (
        defn(c["key"]).wire or defn(c["key"]).applies != "coordinator" or "statement" in defn(c["key"]).effects
        or "protection" in defn(c["key"]).effects)})
    prot_notes = []
    diff, unaffected, errors, changed_nodes = [], [], [], []
    for n in nodes:
        reach = [c for c in norm if _reaches(before, n, c) and c["key"] in wire_keys]
        if not reach:
            continue
        pairs = sorted({(c["key"], c["module"]) for c in reach})
        b = {p: V.resolve(before, n, *p) for p in pairs}
        a = {p: V.resolve(after, n, *p) for p in pairs}
        moved_pairs = [p for p in pairs if not R.same(b[p]["value"], a[p]["value"])]
        moved = sorted({k for k, _ in moved_pairs})
        for p in moved_pairs:
            k, m = p
            diff.append({"node_id": n["node_id"], "hostname": n["hostname"], "key": k, "module": m,
                         "label": defn(k).label + (f" [{m}]" if m else ""), "old": b[p]["value"], "new": a[p]["value"],
                         "old_text": R.show(k, b[p]["value"], defn(k)), "new_text": R.show(k, a[p]["value"], defn(k)),
                         "source": V.badge(a[p])})
        a = {p[0]: a[p] for p in pairs}
        if moved:
            changed_nodes.append(n)
        else:
            k = pairs[0][0]
            lk = a[k]["locked_by"]
            why = (("locked by Fleet settings" if lk["scope"] == "fleet" else f"locked by the group {lk['name'].removeprefix('Group: ')}")
                   if lk else
                   "overrides it" if a[k]["source"]["scope"] in ("group", "node") and not any(
                       c["scope"] == a[k]["source"]["scope"] and c["scope_id"] == a[k]["source"]["id"] for c in reach)
                   else "same value")
            unaffected.append({"node_id": n["node_id"], "hostname": n["hostname"], "key": k, "why": why,
                               "value_text": R.show(k, a[k]["value"], defn(k)), "source": V.badge(a[k])})
        if any("protection" in defn(c["key"]).effects for c in reach):
            from .. import protection as PR
            had = set(PR.chain_errors(before, n))
            aft = PR.assemble(after, n)
            for msg in aft["conflicts"]:
                if msg not in had:
                    errors.append({"key": "protection.rules", "scope": "node", "scope_id": n["node_id"], "node": n["hostname"],
                                   "code": "cross_check", "message": f"{n['hostname']}: {msg}"})
            for x in aft["skipped"]:
                if any(c["scope"] == "node" and c["key"] == "protection.rules" and c["scope_id"] == n["node_id"] for c in reach) \
                        and x["source"] == "This node":
                    errors.append({"key": "protection.rules", "scope": "node", "scope_id": n["node_id"], "node": n["hostname"],
                                   "code": "cross_check", "message": f"{n['hostname']} ({n['os']}): {x['why']}"})
                else:
                    prot_notes.append(f"rule {x['rule']} ({x['source']}) is skipped on {n['hostname']} ({n['os']}): {x['why']}")
        if any(defn(k).wire for k in moved):
            full_b = {k: V.resolve(before, n, k)["value"] for k in (*R.WIRE_POLICY, *R.WIRE_LIMITS)}
            full_a = {k: V.resolve(after, n, k)["value"] for k in (*R.WIRE_POLICY, *R.WIRE_LIMITS)}
            src_b = {k: V.resolve(before, n, k)["source"]["scope"] for k in (*R.WIRE_POLICY, *R.WIRE_LIMITS)}
            src_a = {k: V.resolve(after, n, k)["source"]["scope"] for k in (*R.WIRE_POLICY, *R.WIRE_LIMITS)}
            old = {(e["key"], e["message"]) for e in V.cross_checks(n, full_b, src_b)}
            for e in V.cross_checks(n, full_a, src_a):
                if (e["key"], e["message"]) not in old:
                    errors.append({"key": e["key"], "scope": "node", "scope_id": n["node_id"], "node": n["hostname"],
                                   "code": "cross_check", "message": f"{n['hostname']}: {e['message']}"})
    if errors:
        raise ApplyError(400, "invalid_settings", "; ".join(e["message"] for e in errors)[:800], errors)
    hosts = sorted({x["hostname"] for x in diff})
    keep = sorted({x["hostname"] for x in unaffected})
    if wire_keys:
        summary = (f"Changes the effective value on {len(hosts)} node{'s' if len(hosts) != 1 else ''}"
                   + (f" ({', '.join(hosts[:6])}{', …' if len(hosts) > 6 else ''})" if hosts else ""))
        if keep:
            summary += f"; {len(keep)} node{'s' if len(keep) != 1 else ''} keep{'s' if len(keep) == 1 else ''} theirs " \
                       f"({', '.join(keep[:6])}{', …' if len(keep) > 6 else ''})"
    else:
        summary = "Changes a fleet-wide setting the coordinator applies"
    fleetish = any(c["scope"] in ("fleet", "group") for c in norm)
    return {"summary": summary, "changes": [_change_text(c, names, before) for c in norm],
            "lock_notes": _lock_notes(before, nodes, norm, names), "protection_notes": sorted(set(prot_notes)),
            "nodes_changed": [f"{x['hostname']}: {x['label']} {x['old_text']} → {x['new_text']}" for x in diff],
            "nodes_unaffected": [f"{x['hostname']}: keeps {x['value_text']} ({x['why']}" + ("" if x["why"].startswith("locked")
                                 else f": {x['source']}") + ")" for x in unaffected],
            "then": ("each node gets its new settings at its next heartbeat and reports the revision it applied"
                     if wire_keys else "the coordinator applies it at once"),
            "_changes": norm, "_diff": diff, "_unaffected": unaffected, "_nodes": len(hosts),
            "_button_label": (f"Save for {len(hosts)} node{'s' if len(hosts) != 1 else ''}" if fleetish and wire_keys else "Save"),
            "_tier": R.change_tier(norm)}


def _lock_notes(snap: V.Snap, nodes: list[dict], norm: list[dict], names: dict) -> list[str]:
    """What a new lock overrides: the values set below it that it ignores while it holds (they are kept, and apply
    again when the lock goes)."""
    out = []
    for c in norm:
        if not c["enforce"] or c["reset"]:
            continue
        members = {n["node_id"] for n in nodes if _reaches(snap, n, c)}
        for (scope, sid, m, k), x in sorted(snap.rows.items()):
            if k != c["key"] or m != c["module"] or (scope, sid) == (c["scope"], c["scope_id"]):
                continue
            if scope == "node" and sid in members:
                out.append(f"{names.get(sid, sid)} sets its own value ({R.show(k, x['value'], snap.defn(k))}): ignored while "
                           "the lock holds")
            elif scope == "group" and c["scope"] == "fleet":
                out.append(f"group {names.get(sid, sid)} sets {R.show(k, x['value'], snap.defn(k))}: ignored while the lock "
                           "holds")
    return out


def commit(db, changes, actor: str, comment: str | None = None) -> dict:
    """Write a checked change set (inside the operation's transaction): one revision, effect hooks, node refresh."""
    p = plan(db, changes)
    norm = p["_changes"]
    defn = V.snapshot(db).defn
    n = store.next_rev(db)
    for c in norm:
        if c["reset"]:
            store.delete(db, c["scope"], c["scope_id"], c["module"], c["key"])
        else:
            store.put(db, c["scope"], c["scope_id"], c["module"], c["key"], c["value"], actor, n, comment, c["enforce"])
    touched = refresh(db, p["_diff"], n, statements=any(not c.get("orphan") and "statement" in defn(c["key"]).effects
                                                        for c in norm), actor=actor)
    modcore.after_commit(db, norm, actor)
    db.event("settings_changed", actor=actor, reason=f"rev {n}: " + "; ".join(p["changes"])[:400], rev=n,
             changes=[{k: c[k] for k in ("scope", "scope_id", "module", "key", "reset", "enforce")} for c in norm])
    now = time.time()
    online = {x["node_id"] for x in db.q("SELECT node_id FROM nodes WHERE last_heartbeat_at>?", (now - 30.0,))}
    pending = [x for x in touched if x not in online]
    live = len(touched) - len(pending)
    parts = ([f"{live} of {len(touched)} node{'s' if len(touched) != 1 else ''} get{'s' if len(touched) == 1 else ''} it at "
              f"the next heartbeat"] if live else []) + ([f"{len(pending)} pending (offline)"] if pending else [])
    return {"rev": n, "summary": p["summary"], "nodes": touched, "offline": pending,
            "message": " · ".join([f"Saved · rev {n}", *parts])}


def refresh(db, diff: list[dict], rev_: int | None, statements: bool = False, actor: str | None = None) -> list[str]:
    """After a change (a change set, or a group or label change that moved nodes between groups): run the effect hooks
    on the nodes whose effective value changed (`diff`: [{node_id, key, new}]), rebuild the node statements when host
    tool paths may have moved, and refresh the changed nodes' effective settings under `rev_`. Returns their ids."""
    effects = lambda k: (R.REGISTRY.get(k).effects if R.REGISTRY.get(k) else ())   # a module's own keys have none
    hooks: dict[str, set] = {}
    for x in diff:
        for e in effects(x["key"]):
            hooks.setdefault(e, set()).add(x["node_id"])
    if statements or "statement" in hooks:
        from .. import statements as st          # host tool paths: a path a node did not find goes into its statement
        st.refresh(db)
    for nid in sorted(hooks.get("redoctor", ())):
        _redoctor(db, nid, [x for x in diff if x["node_id"] == nid and "redoctor" in effects(x["key"])])
    for x in diff:                               # a module turned off on a node: its live attempts there are released
        if "module_enabled" in effects(x["key"]) and x.get("new") is False and x.get("old") is not False:
            modcore.release(db, x.get("module") or "", x["node_id"])
    touched = sorted({x["node_id"] for x in diff})
    sync_nodes(db, touched, rev_=rev_, actor=actor)
    return touched


def _redoctor(db, nid: str, diffs: list[dict]) -> None:
    """A module's services.disabled changed on a node: that module's role there changed, so it (and no other module) is
    re-doctored and re-certified."""
    from .. import core
    have = core.node_modules(db.one("SELECT modules_json FROM nodes WHERE node_id=?", (nid,)))
    for x in diffs:
        if x.get("module") in have:
            core._revoke_quiet(db, nid, x["module"], f"services.disabled -> {sorted(x.get('new') or [])}")
    db.x("UPDATE nodes SET want_doctor=1 WHERE node_id=?", (nid,))


# ------------------------------------------------------------------ what the agent gets

def node_document(snap: V.Snap, node: dict) -> dict:
    """{"policy", "limits", "modules_disabled", "settings_unset"}: the complete effective settings the agent gets
    (policy carries protection, assembled from its settings, each module's node settings and the services it does not
    run beside the registry's keys), the modules that do not run on the node, and per module the required settings with
    no value for it."""
    from .. import protection
    mods = V.node_modules(snap, node)
    policy, limits = V.agent_sections(snap, node, mods=mods)
    policy["protection"] = protection.effective(snap, node)
    return {"policy": policy, "limits": limits, "modules_disabled": sorted(m for m, x in mods.items() if not x["enabled"]),
            "settings_unset": {m: x["unset"] for m, x in mods.items() if x["unset"]}}


def sync_nodes(db, node_ids=None, rev_: int | None = None, snap: V.Snap | None = None, actor: str | None = None) -> dict:
    """Recompute nodes' effective settings; a node whose document changed gets it with a new revision (`rev_`, else
    one new revision for the batch), and a history row when its protection changed. Returns {node_id: rev} of the
    nodes that changed."""
    from .. import protection
    snap = snap or V.snapshot(db)
    sql = "SELECT * FROM nodes WHERE lifecycle!='retired'"
    rows = db.q(sql) if node_ids is None else [n for n in (db.one("SELECT * FROM nodes WHERE node_id=?", (x,)) for x in node_ids) if n]
    out = {}
    for n in rows:
        doc = node_document(snap, n)
        digest = hashlib.sha256(canonical_json(doc).encode()).hexdigest()
        if digest == n.get("settings_digest"):
            continue
        if rev_ is None:
            rev_ = store.next_rev(db)
        db.x("UPDATE nodes SET settings_json=?, settings_digest=?, settings_rev=? WHERE node_id=?",
             (json.dumps(doc), digest, rev_, n["node_id"]))
        protection.record_if_changed(db, n["node_id"], doc["policy"]["protection"], rev_, actor)
        out[n["node_id"]] = rev_
    return out


def directive(db, node: dict) -> dict:
    """The heartbeat's settings: {"policy", "limits", "settings_rev", "modules_disabled"} (refreshed first: facts and
    groups may have moved). `modules_disabled`: the modules whose `[module] enabled` is off for this node; their services
    stop there (the kill switch when the fleet's value is off)."""
    with db.tx():
        sync_nodes(db, [node["node_id"]])
        n = db.one("SELECT settings_json, settings_rev FROM nodes WHERE node_id=?", (node["node_id"],))
    doc = json.loads(n["settings_json"] or "{}") or {}
    return {"policy": doc.get("policy") or {}, "limits": doc.get("limits") or {}, "settings_rev": n["settings_rev"] or 0,
            "modules_disabled": list(doc.get("modules_disabled") or [])}


def observe(db, node: dict, report) -> None:
    """The agent's `settings` report in a heartbeat: the revision it applied and the keys it refused."""
    if not isinstance(report, dict):
        return
    rev_ = report.get("applied_rev")
    rev_ = int(rev_) if isinstance(rev_, (int, float)) and not isinstance(rev_, bool) else None
    rej = [{"key": str(x.get("key"))[:80], "reason": str(x.get("reason") or "")[:200]}
           for x in (report.get("rejected") or [])[:64] if isinstance(x, dict) and x.get("key")]
    old = json.loads(node.get("settings_rejected_json") or "[]")
    db.x("UPDATE nodes SET settings_applied_rev=?, settings_rejected_json=? WHERE node_id=?",
         (rev_, json.dumps(rej), node["node_id"]))
    if rej and rej != old:
        db.event("settings_rejected", node_id=node["node_id"], actor=node.get("hostname") or "agent",
                 reason="; ".join(f"{x['key']}: {x['reason']}" for x in rej)[:400])


def node_values(node: dict) -> dict:
    """The effective policy and caps the coordinator last computed for a node ({"policy", "limits"}): what hot paths
    (claim, placement, capacity explanations) read instead of resolving."""
    try:
        return json.loads(node.get("settings_json") or "{}") or {}
    except ValueError:
        return {}


def flat_values(node: dict) -> dict:
    """The node's effective policy and caps in one dict (the why line reads both)."""
    v = node_values(node)
    return {**(v.get("policy") or {}), **(v.get("limits") or {})}


def applied_state(node: dict, key: str | None = None, now: float | None = None) -> dict:
    """Whether the node applied its settings: "Applied on the node · rev N", "Pending: node offline", "Pending: at its
    next heartbeat", or the reason it refused this key."""
    now = now or time.time()
    rev_, done = node.get("settings_rev") or 0, node.get("settings_applied_rev")
    rej = {x["key"]: x["reason"] for x in json.loads(node.get("settings_rejected_json") or "[]")}
    online = bool(node.get("last_heartbeat_at") and now - node["last_heartbeat_at"] < 30.0)
    if key and key in rej:
        return {"state": "rejected", "text": f"Refused by the node: {rej[key]}", "tone": "bad"}
    if done is not None and done >= rev_:
        return {"state": "applied", "text": f"Applied on the node · rev {done}", "tone": "ok"}
    if not online:
        return {"state": "pending", "text": "Pending: node offline", "tone": "warn"}
    if done is None:
        return {"state": "unknown", "text": "Pending: this agent does not report what it applied (update it)", "tone": "warn"}
    return {"state": "pending", "text": f"Pending: the node applies rev {rev_} at its next heartbeat", "tone": "warn"}
