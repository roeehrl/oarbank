"""The site operations (docs/design/sites.md; the registry entries are in oarbank.contracts.operations): create,
update, assign, unassign, delete and dismiss. Imported by ops.py, which owns the handler registry."""
from . import sites as S
from .ops import OpError, _admin_only, handler

VERSIONS = lambda db, r: ["sites"]           # noqa: E731 - one version for the whole site table


def _err(fn):
    try:
        return fn()
    except S.SiteError as e:
        raise OpError(e.status, e.code, e.detail)


def _snap(db, req):
    s = S.get(db, req.target or "") if req.target else None
    if not s:
        return None
    return {"site_id": s["site_id"], "name": s["name"], "uplink_mbps": s["uplink_mbps"], "max_transfers": s["max_transfers"],
            "max_heavy_jobs": s["max_heavy_jobs"], "members": S.members(db, s["site_id"])}


def _moves(db, site_id: str | None, nodes: list[dict]) -> list[str]:
    """Each node's move in words: from no site or another site to this one."""
    names = {r["site_id"]: r["name"] for r in db.q("SELECT site_id, name FROM sites")}
    out = []
    for n in nodes:
        cur = db.one("SELECT site_id FROM site_members WHERE node_id=?", (n["node_id"],))
        if cur and cur["site_id"] == site_id:
            out.append(f"{n['hostname']}: already here")
        elif cur:
            out.append(f"{n['hostname']}: moves from {names.get(cur['site_id'], cur['site_id'])}")
        else:
            out.append(f"{n['hostname']}: joins")
    return out


def _budget_words(b: dict) -> str:
    rate = f"{b['uplink_mbps']:g} Mbit/s shared ({b['uplink_mbps'] / b['max_transfers']:g} each)" if b.get("uplink_mbps") \
        else "no rate limit"
    return f"{b['max_transfers']} transfer(s) at once, {b['max_heavy_jobs']} network-heavy job(s) at once, {rate}"


def _create_impact(db, req) -> dict:
    p = req.params or {}
    name = _err(lambda: S.check_name(p.get("name") or req.target or ""))
    b = _err(lambda: S.budget(p))
    nodes = _err(lambda: S.resolve_nodes(db, p.get("nodes")))
    if S.get(db, name):
        raise OpError(409, "exists", f"a site named {name} exists")
    return {"site": name, "budget": _budget_words(b), "nodes": _moves(db, None, nodes) or ["none yet"],
            "summary": f"Creates site {name} with {len(nodes)} node(s): while a protected process at one of them is in an "
                       "uplink phase, network-heavy fleet work pauses on all of them"}


@handler("sites.create", target_type="site", snapshot=_snap, versions=VERSIONS, impact=_create_impact)
def _create(db, req):
    """A site: nodes that share one internet line, with its uplink budget (params: name, nodes, uplink_mbps,
    max_transfers, max_heavy_jobs, description; `suggestion` marks the suggestion it accepts)."""
    _admin_only(req, "a site")
    p = dict(req.params or {})
    out = _err(lambda: S.create(db, p.get("name") or req.target or "", p, req.actor))
    req.target = out["site_id"]
    out["message"] = f"Created site {out['name']}"
    return out


def _update_impact(db, req) -> dict:
    s = _err(lambda: S.must(db, req.target or ""))
    b = _err(lambda: S.budget(req.params or {}, s))
    if "name" in (req.params or {}):
        _err(lambda: S.check_name(req.params["name"]))
    return {"site": s["name"], "budget_before": _budget_words(s), "budget_after": _budget_words(b),
            "leases": f"{S.usage(db, s)['transfers']} live transfer lease(s) are renewed at the new terms"}


@handler("sites.update", target_type="site", snapshot=_snap, versions=VERSIONS, impact=_update_impact)
def _update(db, req):
    _admin_only(req, "a site")
    s = _err(lambda: S.must(db, req.target or ""))
    req.target = s["site_id"]
    out = _err(lambda: S.update(db, s, dict(req.params or {}), req.actor))
    out["message"] = f"Updated site {s['name']}: " + (", ".join(out["changed"]) or "nothing changed")
    return out


def _assign_impact(db, req) -> dict:
    s = _err(lambda: S.must(db, req.target or ""))
    nodes = _err(lambda: S.resolve_nodes(db, (req.params or {}).get("nodes")))
    if not nodes:
        raise OpError(400, "bad_params", "sites.assign names nodes (params.nodes)")
    return {"site": s["name"], "nodes": _moves(db, s["site_id"], nodes)}


@handler("sites.assign", target_type="site", snapshot=_snap, versions=VERSIONS, impact=_assign_impact)
def _assign(db, req):
    _admin_only(req, "a site")
    s = _err(lambda: S.must(db, req.target or ""))
    nodes = _err(lambda: S.resolve_nodes(db, (req.params or {}).get("nodes")))
    if not nodes:
        raise OpError(400, "bad_params", "sites.assign names nodes (params.nodes)")
    req.target = s["site_id"]
    moved = S.assign(db, s["site_id"], [n["node_id"] for n in nodes], req.actor)
    if (req.params or {}).get("suggestion"):
        db.x("INSERT OR REPLACE INTO site_dismissed(key, by, at, why) VALUES(?,?,?,'accepted')",
             (str(req.params["suggestion"])[:16], req.actor, S.now()))
    db.event("site_members_changed", actor=req.actor, reason=s["name"], site=s["site_id"], added=[n["hostname"] for n in nodes])
    S.refresh(db, s["site_id"])
    return {"site_id": s["site_id"], "nodes": [n["hostname"] for n in nodes], "moved": moved,
            "message": f"{len(nodes)} node(s) at site {s['name']}"}


def _unassign_impact(db, req) -> dict:
    nodes = _err(lambda: S.resolve_nodes(db, (req.params or {}).get("nodes") or ([req.target] if req.target else [])))
    out = []
    for n in nodes:
        s = S.site_of(db, n["node_id"])
        out.append(f"{n['hostname']}: leaves {s['name']}" if s else f"{n['hostname']}: is at no site")
    return {"nodes": out or ["none"]}


@handler("sites.unassign", target_type="node", snapshot=lambda db, r: None, versions=VERSIONS, impact=_unassign_impact)
def _unassign(db, req):
    _admin_only(req, "a site")
    nodes = _err(lambda: S.resolve_nodes(db, (req.params or {}).get("nodes") or ([req.target] if req.target else [])))
    if not nodes:
        raise OpError(400, "bad_params", "sites.unassign names nodes (params.nodes)")
    left = S.site_of(db, nodes[0]["node_id"])
    gone = S.unassign(db, [n["node_id"] for n in nodes])
    for s in {x["site_id"] for x in db.q("SELECT site_id FROM sites")}:
        S.refresh(db, s)
    db.event("site_members_changed", actor=req.actor, reason=(left or {}).get("name") or "", removed=gone)
    return {"nodes": gone, "message": f"{len(gone)} node(s) at no site now"}


def _delete_impact(db, req) -> dict:
    s = _err(lambda: S.must(db, req.target or ""))
    names = [r["hostname"] for r in db.q("SELECT n.hostname FROM site_members m JOIN nodes n ON n.node_id=m.node_id "
                                         "WHERE m.site_id=? ORDER BY n.hostname", (s["site_id"],))]
    return {"site": s["name"], "nodes_released": names or ["none"],
            "summary": f"Deletes site {s['name']}: its {len(names)} node(s) follow no site hold or budget afterwards"}


@handler("sites.delete", target_type="site", snapshot=_snap, versions=VERSIONS, impact=_delete_impact,
         name=lambda db, r: str(r.target))
def _delete(db, req):
    _admin_only(req, "a site")
    s = _err(lambda: S.must(db, req.target or ""))
    req.target = s["site_id"]
    out = S.delete(db, s, req.actor)
    out["message"] = f"Deleted site {s['name']}"
    return out


@handler("sites.dismiss", target_type="site_suggestion", snapshot=lambda db, r: None)
def _dismiss(db, req):
    _admin_only(req, "a site suggestion")
    out = _err(lambda: S.dismiss(db, req.target or (req.params or {}).get("key") or "", req.actor))
    out["message"] = "Suggestion dismissed"
    return out
