"""The workload operations (docs/design/workloads.md; the registry entries are in oarbank.contracts.operations):
assign (T2, previewed), unassign and restart. Imported by ops.py, which owns the handler registry."""
from . import workloads as W
from .ops import OpError, _node, handler


def _target(db, req) -> tuple[str, str]:
    try:
        module, name = W.split_key(req.target or "")
    except W.WorkloadError as e:
        raise OpError(e.status, e.code, e.detail)
    if W.decl(module, name) is None:
        raise OpError(404, "unknown_workload", f"{module} declares no workload {name}")
    return module, name


def _nodes(db, req, module: str, name: str) -> list[str]:
    """The nodes an operation names: params.node, or for a fleet seat params.count placed on eligible nodes."""
    extra = set(req.params) - {"node", "count"}
    if extra:
        raise OpError(400, "bad_params", f"{req.op} takes params node or count, not {sorted(extra)}")
    if req.params.get("node"):
        return [_node(db, str(req.params["node"]))["node_id"]]
    count = req.params.get("count")
    if req.op != "workloads.assign" or count is None:
        raise OpError(400, "bad_params", f"{req.op} names a node (params.node)")
    w = W.decl(module, name)
    if w.seat != "fleet":
        raise OpError(422, "bad_params", f"{module}/{name} has seat \"node\": assign it to a node (params.node)")
    try:
        count = int(count)
    except (TypeError, ValueError):
        raise OpError(400, "bad_params", "params.count is a number of seats")
    nodes = [n["node_id"] for n in W.eligible_nodes(db, module, name)][:max(0, count)]
    if len(nodes) < count:
        raise OpError(409, "not_enough_nodes", f"only {len(nodes)} node(s) can run {module}/{name} now; {count} asked")
    return nodes


def _snap(db, req):
    module, name = _target(db, req)
    return {"assignments": [a["node_id"] for a in W.assignments(db, module=module) if a["workload"] == name]}


def _impact(db, req):
    module, name = _target(db, req)
    return W.preview(db, module, name, _nodes(db, req, module, name))


def _wrap(fn):
    try:
        return fn()
    except W.WorkloadError as e:
        raise OpError(e.status, e.code, e.detail)


@handler("workloads.assign", target_type="workload", snapshot=_snap, impact=_impact)
def _assign(db, req):
    module, name = _target(db, req)
    nodes = _nodes(db, req, module, name)
    placed = "coordinator" if req.params.get("count") is not None else "owner"
    for nid in nodes:
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))
        why, detail = W.offered_reason(db, node, module, name)
        if why:
            raise OpError(409, why.lower(), detail)
        w = W.decl(module, name)
        _, sw, sd = W.seat_for(db, nid, module, w)
        if sw == "WORKLOAD_IDENTITY_SHARED":
            raise OpError(409, "workload_identity_shared", sd)
    return {"assigned": [_wrap(lambda: W.assign(db, module, name, nid, req.actor, placed)) for nid in nodes]}


@handler("workloads.unassign", target_type="workload", snapshot=_snap)
def _unassign(db, req):
    module, name = _target(db, req)
    nid = _nodes(db, req, module, name)[0]
    return _wrap(lambda: W.unassign(db, module, name, nid, req.actor))


@handler("workloads.restart", target_type="workload", snapshot=_snap)
def _restart(db, req):
    module, name = _target(db, req)
    nid = _nodes(db, req, module, name)[0]
    return _wrap(lambda: W.restart(db, module, name, nid, req.actor))
