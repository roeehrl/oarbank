"""Module cleanup on the nodes (docs/protocol.md, "Module cleanup"): what each module keeps on a node, when the node
deletes what a module that left it put there, the owner's purge, and the record of each deletion.

The agent does the deleting (rust/crates/oarbank-agent/src/cleanup.rs): what a module turned off on the node left there
after `module_retention_days`, what a module no longer in the node's release left after at most a day, and at once what
the owner purges (`modules.purge`, never while the module is enabled there), each time after the module's cleanup stage.
Its heartbeat reports `module_storage` (per module what it keeps and, for one leaving, when it goes; and the dataset
cache) and `module_cleanup` (each deletion with how the cleanup stage went), which the coordinator records as events and
acknowledges (`module_cleanup_ack`)."""
import json

from . import clock
from .db import jl

NODE_COLUMNS = {"storage_json": "TEXT",          # the agent's latest `module_storage`
                "storage_at": "REAL",            # when it sent it
                "purge_json": "TEXT",            # the modules the owner purged there, until the agent reports them deleted
                "cleanup_acked_json": "TEXT"}    # the latest deletion ids recorded (a lost acknowledgement records none twice)

ACKED_KEEP = 200
FAILED_SHOWN_S = 7 * 86400.0                     # how long explain names a failed cleanup stage
# why a node deletes what a module left there (the agent's `reason`)
WHY = {"disabled": "turned off here", "removed": "no longer in the node's release", "retired": "the node was retired",
       "purge": "purged"}


def report(node: dict) -> dict:
    """The agent's latest `module_storage` ({} before it sent one)."""
    r = jl(node.get("storage_json"), {})
    return r if isinstance(r, dict) else {}


def purges(node: dict) -> list[str]:
    return [m for m in jl(node.get("purge_json"), []) or [] if isinstance(m, str)]


def enabled_here(db, node: dict, module: str) -> bool:
    """Whether the module runs on the node: it is in the node's release and turned on there."""
    from . import modstore, releases
    if node.get("lifecycle") == "retired" or module in modstore.disabled_names(db, node):
        return False
    return module in releases.composition_of(db, releases.assigned(db, node))


def _num(v) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0


def size(n) -> str:
    """Bytes for people: 0 B, 812 KB, 21.4 GB."""
    n = _num(n)
    for unit in ("B", "KB", "MB"):
        if n < 1024:
            return f"{n:.1f} MB" if unit == "MB" else f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _bounded(st: dict) -> dict:
    """What is kept of a `module_storage`: typed, at most 200 modules."""
    mods = []
    for m in (st.get("modules") or [])[:200]:
        if not isinstance(m, dict) or not isinstance(m.get("module"), str):
            continue
        mods.append({"module": m["module"][:80], "state": str(m.get("state") or "")[:20], "in_release": bool(m.get("in_release")),
                     **{k: int(_num(m.get(k))) for k in ("data_bytes", "cache_bytes", "datasets", "images")},
                     "image_bytes": int(_num(m["image_bytes"])) if isinstance(m.get("image_bytes"), (int, float)) else None,
                     "delete_at": _num(m["delete_at"]) if isinstance(m.get("delete_at"), (int, float)) else None})
    c = st.get("cache") if isinstance(st.get("cache"), dict) else {}
    return {"at": _num(st.get("at")), "retention_days": _num(st.get("retention_days")), "modules": mods,
            "unremoved_images": int(_num(st.get("unremoved_images"))),
            "cache": {"bytes": int(_num(c.get("bytes"))), "datasets": int(_num(c.get("datasets"))),
                      "cap_bytes": int(_num(c["cap_bytes"])) if isinstance(c.get("cap_bytes"), (int, float)) else None,
                      "over_cap": bool(c.get("over_cap"))}}


def observe(db, node: dict, body: dict) -> list[str] | None:
    """A heartbeat's `module_storage` and `module_cleanup`: keep the first; record each deletion not recorded yet as a
    `module_data_deleted` event (and a failed cleanup stage as `module_cleanup_failed`); a purge done leaves the node's
    purges. Returns the deletion ids to acknowledge (None: the agent sent none)."""
    nid, t = node["node_id"], clock.now()
    st = body.get("module_storage")
    if isinstance(st, dict):
        db.x("UPDATE nodes SET storage_json=?, storage_at=? WHERE node_id=?", (json.dumps(_bounded(st)), t, nid))
    done = body.get("module_cleanup")
    if not isinstance(done, list):
        return None
    acked = [x for x in jl(node.get("cleanup_acked_json"), []) or [] if isinstance(x, str)]
    left, ids = purges(node), []
    for rec in done[:100]:
        if not isinstance(rec, dict) or not isinstance(rec.get("id"), str) or not isinstance(rec.get("module"), str):
            continue
        rid, m = rec["id"][:120], rec["module"][:80]
        ids.append(rid)
        if rec.get("reason") == "purge" and m in left:
            left.remove(m)
        if rid in acked:
            continue
        acked.append(rid)
        why = WHY.get(str(rec.get("reason")), str(rec.get("reason"))[:40])
        st = rec.get("cleanup") if isinstance(rec.get("cleanup"), dict) else None
        text = (f"{m} ({why}): {size(rec.get('freed_bytes'))} deleted" +
                (f", {int(_num(rec.get('images_removed')))} images removed" if _num(rec.get("images_removed")) else "") +
                (f"; cleanup stage {st.get('stage')} {'ran' if st.get('ok') else 'failed'}" if st else "") +
                (f"; left: {str(rec['error'])[:200]}" if rec.get("error") else ""))
        db.event("module_data_deleted", node_id=nid, actor=node.get("hostname") or "agent", module=m, reason=text[:400])
        if st and not st.get("ok"):
            db.event("module_cleanup_failed", node_id=nid, actor=node.get("hostname") or "agent", module=m,
                     reason=f"{m}: cleanup stage {st.get('stage')}: {str(st.get('detail') or '')[:300]}")
    db.x("UPDATE nodes SET cleanup_acked_json=?, purge_json=? WHERE node_id=?",
         (json.dumps(acked[-ACKED_KEEP:]), json.dumps(left), nid))
    return ids


def directives(db, node: dict) -> dict:
    """The heartbeat's `module_purge`: the modules the owner purged on the node and not yet deleted there. One enabled
    there again since is dropped (a purge never deletes a module that runs)."""
    want = purges(node)
    keep = [m for m in want if not enabled_here(db, node, m)]
    if keep != want:
        db.x("UPDATE nodes SET purge_json=? WHERE node_id=?", (json.dumps(keep), node["node_id"]))
        for m in set(want) - set(keep):
            db.event("module_purge_dropped", node_id=node["node_id"], module=m, reason=f"{m} is enabled on the node again")
    return {"module_purge": keep}


def node_doc(node: dict, now: float | None = None) -> dict:
    """The node page's and `oarbank node show`'s module data: per module what it keeps there (its data directory, the
    cached datasets it uses, its container images) and, for one leaving, when it goes and why; the dataset cache; and
    the purges the node has not done yet."""
    st = report(node)
    rows = []
    for m in st.get("modules") or []:
        total = sum(int(m.get(k) or 0) for k in ("data_bytes", "cache_bytes")) + int(m.get("image_bytes") or 0)
        rows.append({**m, "total_bytes": total, "total_text": size(total), "data_text": size(m.get("data_bytes")),
                     "cache_text": size(m.get("cache_bytes")),
                     "images_text": (f"{m.get('images')} ({size(m['image_bytes'])})" if m.get("image_bytes") is not None
                                     else str(m.get("images") or 0)),
                     "leaving": m.get("state") not in (None, "", "enabled"), "why": WHY.get(m.get("state") or "", "")})
    c = st.get("cache") or {}
    return {"reported": bool(st), "at": st.get("at"), "retention_days": st.get("retention_days"), "modules": rows,
            "cache": {**c, "text": size(c.get("bytes")) + (f" of {size(c['cap_bytes'])}" if c.get("cap_bytes") else "")},
            "unremoved_images": st.get("unremoved_images") or 0, "purges": purges(node)}


def explain_rows(db, node: dict, now: float | None = None) -> list[dict]:
    """Node explain's module data conditions: each module whose data the node deletes and when (MODULE_DATA_SCHEDULED), a
    dataset cache over its cap (DISK_CACHE_OVER_CAP), and a cleanup stage that failed in the last week
    (MODULE_CLEANUP_FAILED)."""
    now = now or clock.now()
    st = report(node)
    out = []
    for m in st.get("modules") or []:
        if m.get("state") not in (None, "", "enabled") and m.get("delete_at") is not None:
            when = "now" if m["delete_at"] <= now else f"in {_ago(m['delete_at'] - now)}"
            out.append({"code": "MODULE_DATA_SCHEDULED", "detail": {
                "module": m["module"], "size": size(int(m.get("data_bytes") or 0) + int(m.get("cache_bytes") or 0)
                                                   + int(m.get("image_bytes") or 0)),
                "when": when, "why": WHY.get(m["state"], m["state"]), "at": m["delete_at"]}})
    c = st.get("cache") or {}
    if c.get("over_cap"):
        out.append({"code": "DISK_CACHE_OVER_CAP", "detail": {"used": size(c.get("bytes")), "cap": size(c.get("cap_bytes"))}})
    for e in db.q("SELECT module, reason, ts FROM events WHERE kind='module_cleanup_failed' AND node_id=? AND ts>? "
                  "ORDER BY event_id DESC LIMIT 5", (node["node_id"], now - FAILED_SHOWN_S)):
        out.append({"code": "MODULE_CLEANUP_FAILED", "detail": {"module": e["module"], "detail": e["reason"], "at": e["ts"]}})
    return out


def _ago(s: float) -> str:
    s = max(0.0, s)
    return f"{s / 86400:.1f} days" if s >= 86400 else f"{s / 3600:.1f} h" if s >= 3600 else f"{max(1, round(s / 60))} min"


class PurgeError(ValueError):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


def _known(db, module: str) -> bool:
    if db.one("SELECT 1 FROM modules WHERE name=? LIMIT 1", (module,)):
        return True
    return any(any(m.get("module") == module for m in report(n).get("modules") or [])
               for n in db.q("SELECT storage_json FROM nodes WHERE lifecycle!='retired' AND storage_json IS NOT NULL"))


def plan(db, module: str, node: str | None = None, everywhere: bool = False) -> dict:
    """What `modules.purge` would do: the nodes where the module's data goes at once (with what each keeps of it, as last
    reported) and those where the module is enabled (never purged). A named node where it is enabled refuses the whole
    purge, and so does `everywhere` with no node left."""
    if not module or not isinstance(module, str):
        raise PurgeError(422, "bad_target", "modules.purge takes a module name")
    if bool(node) == bool(everywhere):
        raise PurgeError(422, "bad_params", "give one node (params.node) or every node where it is turned off (params.all)")
    if not _known(db, module):
        raise PurgeError(404, "not_found", f"no module {module!r} is installed or reported on a node")
    rows = (db.q("SELECT * FROM nodes WHERE node_id=? OR hostname=?", (node, node)) if node
            else db.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname"))
    if node and not rows:
        raise PurgeError(404, "not_found", f"node {node}")
    targets, enabled = [], []
    for n in rows:
        if enabled_here(db, n, module):
            enabled.append(n["hostname"])
            continue
        row = next((m for m in report(n).get("modules") or [] if m.get("module") == module), None)
        keeps = (size(int(row.get("data_bytes") or 0) + int(row.get("cache_bytes") or 0) + int(row.get("image_bytes") or 0))
                 + f" ({row.get('images') or 0} images)" if row else "nothing reported")
        targets.append({"node_id": n["node_id"], "hostname": n["hostname"], "keeps": keeps})
    if node and enabled:
        raise PurgeError(409, "module_enabled", f"{module} is enabled on {enabled[0]}: turn it off there first (its `enabled` "
                         f"setting, or `oarbank module disable {module}`); a purge never deletes a module that runs")
    if not targets:
        raise PurgeError(409, "module_enabled", f"{module} is enabled on every node: nothing to purge")
    return {"module": module, "deletes_on": [f"{x['hostname']}: {x['keeps']}" for x in targets],
            "enabled_on": enabled or "none", "_targets": targets,
            "then": "each node runs the module's cleanup stage, if it declares one, and deletes its data directory, the "
                    "cached datasets no other module there uses and its container images, at its next heartbeat"}


def purge(db, module: str, targets: list[dict], actor: str) -> dict:
    """Ask each node to delete what the module left there at once (`module_purge` until it reports it done)."""
    for x in targets:
        n = db.one("SELECT purge_json FROM nodes WHERE node_id=?", (x["node_id"],))
        cur = purges(n or {})
        if module not in cur:
            db.x("UPDATE nodes SET purge_json=? WHERE node_id=?", (json.dumps(cur + [module]), x["node_id"]))
        db.event("module_purge_requested", node_id=x["node_id"], actor=actor, module=module,
                 reason=f"{module} on {x['hostname']} ({x['keeps']})")
    return {"module": module, "nodes": [x["hostname"] for x in targets]}
