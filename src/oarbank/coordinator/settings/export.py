"""Settings as code (docs/design/settings.md, "Settings as code"): export a scope's settings to YAML, and import a file
as one change.

**Export** (`oarbank settings export [--scope fleet|group:<g>|node:<n>] [--module m]`, `GET /api/v1/settings/export`,
the console's Export download) writes what an owner set at that scope: values (a lock as `!locked <value>`), and for
the fleet also the groups (selector, listed members, rank, description), each node's owner labels, the host tool
definitions (kind, extra search paths per OS, an executable's version command) and protection (its settings). Secrets
appear only as fingerprints, never as values; the folder registry and dataset origins, which their own operations
write, are listed for reference. `--module` keeps one module's keys.

**Import** (`settings.import`, `oarbank settings import FILE [--dry-run]`, the console's Import page) compares the file
with this fleet and applies the differences as one operation: groups created or changed (and reordered when the file
lists every owner group), labels, tool definitions, then every value as one `settings.apply` change set, checked and
tiered as usual. Absence inherits: a key the file leaves out is never touched; `key: !reset` deletes a value. The dry
run is the same comparison, and the preview runs the whole change in a transaction it rolls back, so it names every
node's old and new value. Importing an export of the same fleet changes nothing."""
import json
import time

from . import groups as G
from . import modkeys
from . import registry as R
from . import resolve as V
from . import store
from . import yamlish as Y
from .apply import ApplyError

FORMAT = "settings/v1"
HEADER = ("Oarbank settings ({scope}{module}), exported {when}.\n"
          "oarbank settings import <file> --dry-run shows what importing it would change; importing it unchanged into\n"
          "the same fleet changes nothing. A key left out inherits (an import never deletes it); `key: !reset` deletes\n"
          "a value; `!locked <value>` locks it at its scope. Secrets are fingerprints only, never values.")
MODULE_CORE = set(R.MODULE_CORE_KEYS)


class ImportRefused(ApplyError):
    pass


# ------------------------------------------------------------------ export

def _short(snap: V.Snap, key: str, module: str) -> str:
    """A module key as the file names it under its module: its own key by its short name (unless a core key a module
    qualifies has that name: then the full module.<m>.<key>), a core key as it is."""
    m, name = modkeys.split(key)
    if m and m == module and (R.REGISTRY.get(name) is None or not R.REGISTRY[name].qualifier):
        return name
    return key


def _val(x: dict):
    v = Y.Flow(x["value"]) if isinstance(x["value"], dict) and x["value"] else x["value"]
    return Y.Locked(x["value"]) if x.get("enforced") else v


def _values(snap: V.Snap, scope: str, sid: str, module: str = "") -> dict:
    """{"settings": {key: value}, "modules": {module: {key: value}}} of one scope's own rows (writer-owned keys and keys
    their module no longer declares are left out)."""
    out: dict = {}
    for (sc, s, m, k), x in sorted(snap.rows.items()):
        if sc != scope or s != sid or (module and m != module):
            continue
        d = R.lookup(k, snap.defs)
        if d is None or d.writer:
            continue
        if m:
            out.setdefault("modules", {}).setdefault(m, {})[_short(snap, k, m)] = _val(x)
        else:
            out.setdefault("settings", {})[k] = _val(x)
    return out


def _secrets(r, module: str = "", scope: str = "fleet", sid: str = "") -> dict:
    """Fingerprints only: {"<module>/<name>" (or a core secret's name): {"fleet" | "group:<g>" | "node:<host>": fp}}."""
    names = {n["node_id"]: n["hostname"] for n in r.q("SELECT node_id, hostname FROM nodes")}
    out: dict = {}
    for x in r.q("SELECT module, name, node_id, fingerprint FROM secrets ORDER BY module, name, node_id"):
        if module and x["module"] != module:
            continue
        where = "fleet" if not x["node_id"] else x["node_id"] if x["node_id"].startswith("group:") else \
            f"node:{names.get(x['node_id'], x['node_id'])}"
        if scope == "group" and where != f"group:{sid}" or scope == "node" and where != f"node:{names.get(sid, sid)}":
            continue
        out.setdefault(f"{x['module']}/{x['name']}" if x["module"] else x["name"], {})[where] = x["fingerprint"]
    return out


def export_doc(r, scope: str = "fleet", module: str = "") -> dict:
    """The document for one scope: `fleet` (everything), `group:<id or name>` or `node:<id or hostname>`, optionally one
    module's keys only."""
    snap = V.snapshot(r)
    if module and module not in snap.modules:
        raise R.SettingError("unknown_module", f"no module {module!r} is installed")
    kind, _, ident = (scope or "fleet").partition(":")
    nodes = r.q("SELECT node_id, hostname FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    host = {n["node_id"]: n["hostname"] for n in nodes}
    doc: dict = {"oarbank": FORMAT}
    if kind == "fleet":
        doc["scope"] = "fleet"
    elif kind == "group":
        g = G.find(r, ident)
        if g is None:
            raise R.SettingError("unknown_group", f"no group {ident!r}")
        doc["scope"] = f"group:{g['id']}"
    elif kind == "node":
        n = next((n for n in nodes if ident in (n["node_id"], n["hostname"])), None)
        if n is None:
            raise R.SettingError("unknown_node", f"no node {ident!r}")
        doc["scope"] = f"node:{n['hostname']}"
    else:
        raise R.SettingError("bad_scope", "scope: fleet, group:<group> or node:<node>")
    if module:
        doc["module"] = module
    if kind == "fleet":
        doc["fleet"] = _values(snap, "fleet", "", module)
    groups: dict = {}
    for g in sorted(snap.groups, key=lambda g: g["rank"]):
        if kind == "group" and g["id"] != doc["scope"][6:]:
            continue
        vals = _values(snap, "group", g["id"], module)
        if g["builtin"]:
            if vals or kind == "group":
                groups[g["id"]] = {"builtin": True, "name": g["name"], **vals}
            continue
        entry = {} if module else {
            "name": g["name"], "rank": g["rank"], "selector": Y.Flow(g["selector"]) if g["selector"] else {},
            "members": sorted(host.get(m, m) for m in g["members"]),
            **({"description": g["description"]} if g.get("description") else {})}
        if entry or vals:
            groups[g["id"]] = {**entry, **vals}
    if groups or kind == "group":
        doc["groups"] = groups
    out_nodes: dict = {}
    for n in nodes:
        if kind == "node" and n["hostname"] != doc["scope"][5:]:
            continue
        if kind == "group":
            continue
        vals = _values(snap, "node", n["node_id"], module)
        labels = [] if module else list(snap.labels.get(n["node_id"], []))
        if vals or labels or kind == "node":
            out_nodes[n["hostname"]] = {"node_id": n["node_id"], **({"labels": labels} if labels or (kind == "node" and not module) else {}),
                                        **vals}
    if out_nodes or kind == "node":
        doc["nodes"] = out_nodes
    if kind == "fleet" and not module:
        from .. import tools
        defs = {}
        for tid, d in tools.definitions(r).items():
            if d["updated_at"] is None:
                continue                              # a built-in tool nobody extended
            defs[tid] = Y.Flow({"kind": d["kind"], "search": d["search"],
                                **({"version": d["version"]} if d["kind"] == "executable" and d.get("version") else {})})
        if defs:
            doc["tools"] = defs
        owned = {k: store.fleet_value(r, k) for k in ("folder_registry", "dataset_origins")}
        owned = {k: (Y.Flow(v) if isinstance(v, dict) and v else v) for k, v in owned.items() if v not in ({}, [], None)}
        if owned:
            doc["written_by_their_operations"] = owned
    sec = _secrets(r, module, kind, doc["scope"].partition(":")[2] if kind != "node" else
                   next(n["node_id"] for n in nodes if n["hostname"] == doc["scope"][5:]))
    if sec:
        doc["secrets"] = sec
    return doc


def export_yaml(r, scope: str = "fleet", module: str = "") -> str:
    doc = export_doc(r, scope, module)
    when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    return Y.dump(doc, HEADER.format(scope=doc["scope"], module=f", module {module}" if module else "", when=when))


# ------------------------------------------------------------------ import: the comparison

def parse(text) -> dict:
    """A file's document (its text, or an already parsed object), with its header checked."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8")
    if isinstance(text, str):
        try:
            doc = Y.load(text)
        except Y.YamlError as e:
            raise ImportRefused(400, "bad_yaml", str(e), [{"key": "", "code": "bad_yaml", "message": str(e)}])
    else:
        doc = text
    if not isinstance(doc, dict) or doc.get("oarbank") != FORMAT:
        raise ImportRefused(400, "bad_document", f"not an Oarbank settings export (it starts with `oarbank: {FORMAT}`)",
                            [{"key": "oarbank", "code": "bad_document", "message": f"expected oarbank: {FORMAT}"}])
    extra = set(doc) - {"oarbank", "scope", "module", "fleet", "groups", "nodes", "tools", "secrets",
                        "written_by_their_operations"}
    if extra:
        raise ImportRefused(400, "bad_document", f"unknown sections {sorted(extra)}",
                            [{"key": k, "code": "bad_document", "message": "unknown section"} for k in sorted(extra)])
    return doc


def _canon(v) -> str:
    return json.dumps(v, sort_keys=True)


def _plain(v):
    return v.value if isinstance(v, Y.Flow) else v


def _section_changes(snap: V.Snap, scope: str, sid: str, entry: dict, where: str, errors: list) -> list[dict]:
    """The changes that make one scope's own values what the file says: a key set to another value or lock, a
    `!reset` of a value that exists. Keys the file leaves out are not touched."""
    out = []
    if not isinstance(entry, dict):
        errors.append({"key": where, "code": "bad_document", "message": f"{where}: a mapping"})
        return out
    pairs = []
    for k, v in (entry.get("settings") or {}).items():
        pairs.append(("", k, v))
    mods = entry.get("modules") or {}
    if not isinstance(mods, dict):
        errors.append({"key": where, "code": "bad_document", "message": f"{where}.modules: a mapping of module: keys"})
        mods = {}
    for m, keys in mods.items():
        if not isinstance(keys, dict):
            errors.append({"key": where, "code": "bad_document", "message": f"{where}.modules.{m}: a mapping"})
            continue
        for k, v in keys.items():
            pairs.append((m, k, v))
    for m, k, v in pairs:
        key, module = modkeys.resolve_key(snap, str(k), m)
        d = R.lookup(key, snap.defs)
        mod = module if d is not None and d.qualifier else ""
        if m and d is not None and not d.qualifier:
            mod = m                                   # refused by the change set, which names the problem
        row = snap.get(scope, sid, mod, key)
        if isinstance(v, Y.Reset):
            if row is not None:
                out.append({"scope": scope, "scope_id": sid, "module": mod, "key": key, "reset": True})
            continue
        locked = isinstance(v, Y.Locked)
        value = Y.plain(v)
        if d is not None and row is not None:
            try:
                norm = R.check(key, value, d)
            except R.SettingError:
                norm = value
            if _canon(norm) == _canon(row["value"]) and bool(row["enforced"]) == locked:
                continue
        out.append({"scope": scope, "scope_id": sid, "module": mod, "key": key, "value": value,
                    **({"enforce": True} if locked else {})})
    return out


def compare(db, doc: dict) -> dict:
    """What importing `doc` changes here: {groups_create, groups_update, order, labels, tools, changes, notes, errors}."""
    from .. import tools as T
    snap = V.snapshot(db)
    nodes = db.q("SELECT node_id, hostname FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    by_host = {n["hostname"]: n["node_id"] for n in nodes} | {n["node_id"]: n["node_id"] for n in nodes}
    host = {n["node_id"]: n["hostname"] for n in nodes}
    errors, notes = [], []
    plan = {"groups_create": [], "groups_update": [], "order": None, "labels": {}, "tools": [], "changes": [],
            "notes": notes, "errors": errors}
    if doc.get("fleet") is not None:
        plan["changes"] += _section_changes(snap, "fleet", "", doc["fleet"], "fleet", errors)
    # groups: definitions first (new ones get their id now), then their values
    file_ranks = {}
    for gid, entry in (doc.get("groups") or {}).items():
        if not isinstance(entry, dict):
            errors.append({"key": f"groups.{gid}", "code": "bad_document", "message": f"groups.{gid}: a mapping"})
            continue
        g = G.find(db, str(gid))
        defn = {k: Y.plain(_plain(entry[k])) for k in ("name", "selector", "members", "description") if k in entry}
        if entry.get("builtin"):
            if g is None or not g["builtin"]:
                errors.append({"key": f"groups.{gid}", "code": "unknown_group", "message": f"no built-in group {gid!r} here"})
                continue
        elif g is None:
            if not defn.get("name"):
                errors.append({"key": f"groups.{gid}", "code": "unknown_group",
                               "message": f"no group {gid!r} here, and the file does not define it (name, selector)"})
                continue
            try:
                sp = G.spec(db, {**defn, "id": str(gid)})
            except G.GroupError as e:
                errors.append({"key": f"groups.{gid}", "code": e.code, "message": f"group {gid}: {e.detail}"})
                continue
            plan["groups_create"].append(sp)
            g = {**sp, "builtin": 0, "rank": None}
        elif defn:
            try:
                sp = G.spec(db, defn, g)
            except G.GroupError as e:
                errors.append({"key": f"groups.{gid}", "code": e.code, "message": f"group {gid}: {e.detail}"})
                continue
            what = [k for k in ("name", "selector", "members", "description") if _canon(sp[k]) != _canon(g.get(k) or
                                                                                                        ({} if k == "selector" else [] if k == "members" else ""))]
            if what:
                plan["groups_update"].append({"id": g["id"], "spec": sp, "fields": what})
        if not g.get("builtin") and isinstance(entry.get("rank"), int):
            file_ranks[g["id"]] = entry["rank"]
        plan["changes"] += _section_changes(snap, "group", g["id"], entry, f"groups.{gid}", errors)
    owner = [x["id"] for x in snap.groups if not x["builtin"]] + [s["id"] for s in plan["groups_create"]]
    if file_ranks and set(file_ranks) == set(owner):
        want = [gid for gid, _ in sorted(file_ranks.items(), key=lambda kv: -kv[1])]
        have = [x["id"] for x in sorted((x for x in snap.groups if not x["builtin"]), key=lambda x: -x["rank"])]
        projected = [s["id"] for s in reversed(plan["groups_create"])] + have      # a new group goes on top
        if want != projected:
            plan["order"] = want
    elif file_ranks and set(file_ranks) != set(owner) and plan["groups_create"]:
        notes.append("new groups go above every other owner group (the file does not list every group, so their ranks "
                     "are not copied: oarbank groups rank moves one)")
    for h, entry in (doc.get("nodes") or {}).items():
        if not isinstance(entry, dict):
            errors.append({"key": f"nodes.{h}", "code": "bad_document", "message": f"nodes.{h}: a mapping"})
            continue
        nid = by_host.get(str(entry.get("node_id") or "")) or by_host.get(str(h))
        if nid is None:
            errors.append({"key": f"nodes.{h}", "code": "unknown_node", "message": f"no node {h!r} here"})
            continue
        if "labels" in entry:
            want = entry["labels"] or []
            if not isinstance(want, list):
                errors.append({"key": f"nodes.{h}.labels", "code": "bad_document", "message": "labels: a list"})
            else:
                try:
                    want = sorted({G.check_label(x) for x in want})
                except G.GroupError as e:
                    errors.append({"key": f"nodes.{h}.labels", "code": e.code, "message": f"{h}: {e.detail}"})
                    want = None
                if want is not None:
                    have = sorted(snap.labels.get(nid, []))
                    add, remove = [x for x in want if x not in have], [x for x in have if x not in want]
                    if add or remove:
                        plan["labels"][nid] = {"add": add, "remove": remove, "host": host[nid]}
        plan["changes"] += _section_changes(snap, "node", nid, entry, f"nodes.{h}", errors)
    cur_defs = T.definitions(db)
    for tid, raw in (doc.get("tools") or {}).items():
        raw = Y.plain(_plain(raw)) or {}
        try:
            want = T.check_definition(str(tid), raw)
        except T.ToolError as e:
            errors.append({"key": f"tools.{tid}", "code": "bad_tool", "message": f"tool {tid}: {e}"})
            continue
        cur = cur_defs.get(tid)
        have = None
        if cur is not None and cur["updated_at"] is not None:
            try:
                have = T.check_definition(str(tid), {"kind": cur["kind"], "search": cur["search"],
                                                     **({"version": cur["version"]} if cur["kind"] == "executable" else {})})
            except T.ToolError:
                have = None
        if _canon(want) != _canon(have):
            plan["tools"].append({"id": tid, "params": raw, "new": cur is None})
    here = _secrets(db)
    for name, scopes in (doc.get("secrets") or {}).items():
        for where, fp in (scopes or {}).items():
            mine = (here.get(name) or {}).get(where)
            if mine != fp:
                notes.append(f"secret {name} ({where}): " + ("not set here" if mine is None else "set to another value here")
                             + " — secrets are never imported: set it with "
                             + ("oarbank settings set-secret " + name if "/" not in name else f"oarbank secret set {name.split('/')[0]} {name.split('/')[1]}"))
    for k, v in (doc.get("written_by_their_operations") or {}).items():
        if k in ("folder_registry", "dataset_origins") and _canon(Y.plain(_plain(v))) != _canon(store.fleet_value(db, k)):
            notes.append(f"{k} differs here: it is written by {R.REGISTRY[k].writer} (not by an import)")
    return plan


def _lines(db, plan: dict) -> dict:
    """The comparison in words (the preview's lists)."""
    host = {n["node_id"]: n["hostname"] for n in db.q("SELECT node_id, hostname FROM nodes")}
    out = {"groups": [], "labels": [], "tools": []}
    for s in plan["groups_create"]:
        out["groups"].append(f"create group {s['name']} ({G.describe(s, host)})")
    for u in plan["groups_update"]:
        out["groups"].append(f"change group {u['spec']['name']}: {', '.join(u['fields'])} ({G.describe(u['spec'], host)})")
    if plan["order"]:
        out["groups"].append("rank owner groups: " + " > ".join(plan["order"]) + " (highest first)")
    for nid, x in plan["labels"].items():
        out["labels"].append(f"{x['host']}: " + "; ".join(([f"add {', '.join(x['add'])}"] if x["add"] else [])
                                                         + ([f"remove {', '.join(x['remove'])}"] if x["remove"] else [])))
    for t in plan["tools"]:
        out["tools"].append(f"{'define' if t['new'] else 'change'} tool {t['id']} (the releases are rebuilt)")
    return out


class _Rollback(Exception):
    pass


def _write_structure(db, plan: dict, actor: str) -> None:
    """Groups, labels (inside the caller's transaction): what the values may name."""
    for s in plan["groups_create"]:
        G.create(db, s, actor)
    for u in plan["groups_update"]:
        G.update(db, u["id"], u["spec"], actor)
    if plan["order"]:
        G.write_order(db, plan["order"])
    for nid, x in plan["labels"].items():
        G.set_labels(db, nid, x["add"], x["remove"], actor)


def preview(db, text) -> dict:
    """The import's dry run: every difference, and the settings change set's per-node impact (the structure it needs is
    written in a transaction that is rolled back). Empty when the file matches this fleet."""
    from . import apply as A
    doc = parse(text)
    plan = compare(db, doc)
    if plan["errors"]:
        raise ImportRefused(400, "invalid_import", "; ".join(e["message"] for e in plan["errors"])[:800], plan["errors"])
    words = _lines(db, plan)
    sp = None
    if plan["changes"]:
        box = {}
        try:
            with db.tx():
                _write_structure(db, plan, "(preview)")
                box["plan"] = A.plan(db, plan["changes"])
                raise _Rollback()
        except _Rollback:
            sp = box["plan"]
    n = len(plan["changes"]) + len(plan["groups_create"]) + len(plan["groups_update"]) + bool(plan["order"]) + \
        len(plan["labels"]) + len(plan["tools"])
    tier = R.change_tier(plan["changes"]) if plan["changes"] else "T0"
    if plan["groups_create"] or plan["groups_update"] or plan["order"] or plan["tools"]:
        tier = max(tier, "T2", key=R.TIERS.index)
    summary = ("No changes: the file matches this fleet" if not n else
               f"{n} change{'s' if n != 1 else ''}" + (f": {sp['summary']}" if sp else ""))
    return {"summary": summary, "empty": not n, "scope": doc.get("scope"), "module": doc.get("module"),
            "changes": sp["changes"] if sp else [], "nodes_changed": sp["nodes_changed"] if sp else [],
            "nodes_unaffected": sp["nodes_unaffected"] if sp else [], "lock_notes": sp["lock_notes"] if sp else [],
            **words, "notes": plan["notes"],
            "then": "applied as one operation: groups, labels and tools first, then the values as one change set",
            "_plan": plan, "_tier": tier, "_count": n}


def commit(db, text, actor: str, comment: str | None = None) -> dict:
    """Apply an import (inside the operation's transaction): groups and labels, then tool definitions, then the values
    as one settings change set. Returns what it did; the caller rebuilds releases when tools changed."""
    from . import apply as A
    from .. import tools as T
    p = preview(db, text)
    plan = p["_plan"]
    if p["empty"]:
        return {"message": "No changes: the file matches this fleet", "changed": 0, "tools": 0}
    before = V.snapshot(db)
    _write_structure(db, plan, actor)
    moved = []
    if plan["groups_create"] or plan["groups_update"] or plan["order"] or plan["labels"]:
        rev = store.next_rev(db)
        imp = G.impact(db, before, V.snapshot(db))
        moved = A.refresh(db, imp["_diff"], rev, statements=True, actor=actor)
    for t in plan["tools"]:
        T.define(db, t["id"], t["params"], actor)
    res = A.commit(db, plan["changes"], actor, comment or "settings import") if plan["changes"] else None
    db.event("settings_imported", actor=actor, reason=f"{p['scope']}: {p['summary']}"[:400])
    parts = [f"Imported {p['_count']} change{'s' if p['_count'] != 1 else ''}"]
    if res:
        parts.append(res["message"])
    elif moved:
        parts.append(f"{len(moved)} node{'s' if len(moved) != 1 else ''} moved between groups")
    return {"message": " · ".join(parts), "changed": p["_count"], "tools": len(plan["tools"]),
            "rev": (res or {}).get("rev"), "nodes": sorted(set((res or {}).get("nodes") or []) | set(moved))}
