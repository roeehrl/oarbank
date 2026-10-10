"""Change sets that span many targets (docs/design/settings.md, "Bulk changes" and "Canary to a group").

- **Bulk**: one key set or reset on every selected node, as one `settings.apply` change set (one change per node), so
  the preview names each node's old and new value and the nodes that keep theirs, and the save is one revision. Nodes
  are selected by name, by group or by label.
- **Canary, then promote**: a change goes to one group first (an ordinary group value), and `settings.promote` moves it
  up: the value is set at the fleet (or a wider group) and the canary group's own value is deleted, in one change set,
  so the nodes that already run it see no change and the rest get it. A list that merges by union (protection rules)
  adds the group's entries to the target's instead of replacing it; an entry with the same id is the group's version
  (the one the canary tried). A lock moves with its value."""
from . import registry as R
from . import store

BULK_ESCALATE_ITEMS = 10                     # operations.BULK_ESCALATE_ITEMS: a bulk change above this is one tier up


class BulkError(ValueError):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail = status, code, detail


def select_nodes(db, nodes=None, group: str | None = None, label: str | None = None) -> list[dict]:
    """Nodes by name or id, the members of a group, or the nodes carrying a label (each may combine: the union)."""
    from . import groups as G, resolve as V
    rows = db.q("SELECT node_id, hostname, os, arch, facts_json FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    want: dict[str, dict] = {}
    for x in nodes or []:
        hit = [n for n in rows if str(x) in (n["node_id"], n["hostname"])]
        if not hit:
            raise BulkError(404, "unknown_node", f"no node {x!r}")
        want[hit[0]["node_id"]] = hit[0]
    if group or label:
        snap = V.snapshot(db)
        if group:
            g = G.find(db, group)
            if g is None:
                raise BulkError(404, "unknown_group", f"no group {group!r}")
            for n in rows:
                if any(x["id"] == g["id"] for x in V.node_groups(snap, n)):
                    want[n["node_id"]] = n
        if label:
            lab = G.check_label(label)
            for n in rows:
                if lab in snap.node_labels(n)["all"]:
                    want[n["node_id"]] = n
    return sorted(want.values(), key=lambda n: n["hostname"] or "")


def node_changes(nodes: list[dict], key: str, value=None, reset: bool = False, module: str = "") -> list[dict]:
    """One change per node: set `value`, or reset (the node inherits again)."""
    if not nodes:
        raise BulkError(400, "no_nodes", "select at least one node")
    base = {"scope": "node", "key": key, **({"module": module} if module else {})}
    return [{**base, "scope_id": n["node_id"], **({"reset": True} if reset else {"value": value})} for n in nodes]


def tier(changes) -> str:
    """A change set's tier (registry.change_tier), one up when it changes more than BULK_ESCALATE_ITEMS nodes' own
    values at once (admin-console.md, "Bulk")."""
    t = R.change_tier(changes)
    nodes = {(c or {}).get("scope_id") for c in changes or [] if isinstance(c, dict) and c.get("scope") == "node"}
    if len(nodes) > BULK_ESCALATE_ITEMS:
        t = R.TIERS[min(R.TIERS.index(t) + 1, 3)]
    return t


def _union(target: list, add: list) -> list:
    """`add`'s entries appended to `target`'s; an object entry with an `id` replaces the target's entry with that id."""
    out = list(target or [])
    for x in add or []:
        if isinstance(x, dict) and x.get("id") is not None:
            out = [y for y in out if not (isinstance(y, dict) and y.get("id") == x["id"])]
        if x not in out:
            out.append(x)
    return out


def promote_changes(db, key: str, group: str, module: str = "", to: str = "fleet") -> list[dict]:
    """The change set that promotes a group's value of `key` to the fleet (`to` = "fleet") or a wider group."""
    from . import groups as G
    d = R.get(key)
    g = G.find(db, group)
    if g is None:
        raise BulkError(404, "unknown_group", f"no group {group!r}")
    row = store.row(db, "group", g["id"], module, key)
    if row is None:
        raise BulkError(409, "nothing_to_promote", f"the group {g['name']} sets no value of {d.label} ({key}) to promote")
    if to in ("", "fleet"):
        scope, sid = "fleet", ""
    else:
        t = G.find(db, to)
        if t is None:
            raise BulkError(404, "unknown_group", f"no group {to!r}")
        if t["id"] == g["id"]:
            raise BulkError(400, "same_group", "promote to the fleet or another group")
        scope, sid = "group", t["id"]
    if scope not in d.scopes:
        raise BulkError(400, "not_settable_here", f"{d.label} can be set for: {', '.join(d.scopes)}")
    value = row["value"]
    if d.merge == "union":
        cur = store.row(db, scope, sid, module, key)
        value = _union(cur["value"] if cur else [], value)
    up = {"scope": scope, "scope_id": sid, "key": key, "value": value, **({"module": module} if module else {})}
    if row["enforced"]:
        up["enforce"] = True
    return [up, {"scope": "group", "scope_id": g["id"], "key": key, "reset": True, **({"module": module} if module else {})}]
