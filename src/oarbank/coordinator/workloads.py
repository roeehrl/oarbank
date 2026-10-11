"""Workloads (docs/design/workloads.md; PLAN D45, D46): the owner's assignments of a module's workloads to nodes, seat
leases with fences for workloads whose identity belongs to one node, the directives that tell each agent what to run,
the agent's reports of what runs, the secrets a workload receives at each start, its report events on their way to the
module's `workload.report` verb, and invariant S26.

A seat of an `identity = "per_node"` workload is named by the keyed fingerprints of the secrets it receives on the node
(modsecrets.py), so two nodes given the same key compete for one seat. The coordinator grants the seat's lease to a node
that is assigned the workload when the seat is free, held by that node, or its lease ended more than the grace ago; a new
holder raises the fence. It frees a seat only on the holder's report that the workload stopped and gave the seat up
(`release`), carrying the current fence (specs/OarbankSeat.tla)."""
import hashlib
import json
import os

from . import clock, modcalls
from .db import DB, jl

SCHEMA = """
-- Workloads (workloads.py, docs/design/workloads.md): the owner's assignments, kept with unassigned_at when undone
CREATE TABLE IF NOT EXISTS workload_assignments (
  module TEXT NOT NULL, workload TEXT NOT NULL, node_id TEXT NOT NULL, desired TEXT NOT NULL DEFAULT 'running',
  assigned_at REAL, assigned_by TEXT, placed_by TEXT, restart_seq INT NOT NULL DEFAULT 0, unassigned_at REAL,
  version INT NOT NULL DEFAULT 1, PRIMARY KEY (module, workload, node_id));
-- Seat leases (D46): who holds each seat, under which fence, until when (coordinator clock)
CREATE TABLE IF NOT EXISTS workload_seats (
  seat_id TEXT PRIMARY KEY, module TEXT NOT NULL, workload TEXT NOT NULL, node_id TEXT, fence INT NOT NULL DEFAULT 0,
  lease_until REAL, granted_at REAL, released_at REAL);
-- Each node's latest report of each workload (the heartbeat's `workloads`)
CREATE TABLE IF NOT EXISTS workload_status (
  module TEXT NOT NULL, workload TEXT NOT NULL, node_id TEXT NOT NULL, running INT, seat_id TEXT, fence INT,
  report_json TEXT, at REAL, PRIMARY KEY (module, workload, node_id));
-- Report events on their way to the module's workload.report verb (idempotent by the agent's seq)
CREATE TABLE IF NOT EXISTS workload_reports (
  module TEXT NOT NULL, workload TEXT NOT NULL, node_id TEXT NOT NULL, seq INT NOT NULL, t REAL, seat_id TEXT, fence INT,
  data_json TEXT, state TEXT NOT NULL DEFAULT 'pending', error TEXT, received_at REAL,
  PRIMARY KEY (module, workload, node_id, seq));
"""

LEASE_S = float(os.environ.get("OARBANK_WORKLOAD_LEASE_S", "1800"))   # D46: 30 minutes (tests shorten it)
GRACE_S = 60.0                     # after a lease's end before another node may take the seat
REPORT_MAX_BYTES = 4096
REPORTS_PER_HEARTBEAT = 60
FRESH_S = 300.0                    # a report older than this no longer says what runs (S26 reads fresh ones)


class WorkloadError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status, self.code, self.detail = status, code, detail


# ------------------------------------------------------------------ declarations

def decl(module: str, name: str):
    """The workload the module's current version declares (None: no such module or workload)."""
    try:
        return modcalls.info(module).manifest.workload(name)
    except (KeyError, AttributeError):
        return None


def split_key(key: str) -> tuple[str, str]:
    module, _, name = (key or "").partition("/")
    if not module or not name:
        raise WorkloadError(400, "bad_target", f"a workload is <module>/<workload>, not {key!r}")
    return module, name


def _net_mode(module: str) -> str:
    try:
        return modcalls.info(module).manifest.sandbox.net.mode
    except KeyError:
        return "none"


def offered_reason(db: DB, node: dict, module: str, name: str) -> tuple[str | None, str]:
    """Why the node cannot run the workload at all (a reason code and its detail), or (None, '')."""
    if module not in modcalls.CATALOG or module not in modcalls.enabled(db):
        return "WORKLOAD_NOT_OFFERED", f"module {module} is not enabled"
    w = decl(module, name)
    if w is None:
        return "WORKLOAD_NOT_OFFERED", f"{module} declares no workload {name}"
    plat = node.get("platform") or ""
    m = modcalls.info(module).manifest
    if plat and plat not in m.requires.platforms:
        return "WORKLOAD_NOT_OFFERED", f"{module} does not run on {plat}"
    if plat and w.platforms and plat not in w.platforms:
        return "WORKLOAD_NOT_OFFERED", f"the workload runs on {', '.join(w.platforms)} only"
    if plat.startswith("linux") and _net_mode(module) == "egress-any":
        return "WORKLOAD_NOT_OFFERED", "Linux nodes cannot enforce the egress-any network mode"
    if node.get("lifecycle") in ("retired", "quarantined"):
        return "WORKLOAD_NOT_OFFERED", f"the node is {node.get('lifecycle')}"
    return None, ""


def seat_for(db: DB, node_id: str, module: str, w) -> tuple[str | None, str | None, str]:
    """The seat a node runs the workload under: (seat_id, reason code, detail). A workload without an identity has no
    seat (None, None, ''). A per-node identity's seat is named by the keyed fingerprints of its secrets on the node; a
    secret with no value, or one set for a group or the whole module, leaves it unstarted."""
    if w.identity != "per_node":
        return None, None, ""
    from . import modsecrets
    fps = []
    for s in w.secrets:
        src = modsecrets.source(db, module, s, node_id)
        if src["scope"] is None:
            return None, "WORKLOAD_SECRETS_NOT_SET", f"secret {s} has no value for this node"
        if src["scope"] != node_id:
            return None, "WORKLOAD_IDENTITY_SHARED", (f"secret {s} is set for {src['text']}: a per-node identity needs its "
                                                      "own value on each node")
        fps.append(f"{s}={src['fingerprint']}")
    h = hashlib.sha256("\0".join([module, w.name, *sorted(fps)]).encode()).hexdigest()[:16]
    return "s_" + h, None, ""


# ------------------------------------------------------------------ assignments

def assignments(db: DB, node_id: str | None = None, module: str | None = None) -> list[dict]:
    sql, args = "SELECT * FROM workload_assignments WHERE unassigned_at IS NULL", []
    if node_id:
        sql, args = sql + " AND node_id=?", [*args, node_id]
    if module:
        sql, args = sql + " AND module=?", [*args, module]
    return db.q(sql + " ORDER BY module, workload, node_id", tuple(args))


def _assigned(db: DB, module: str, name: str, node_id: str) -> bool:
    return bool(db.one("SELECT 1 FROM workload_assignments WHERE module=? AND workload=? AND node_id=? AND "
                       "unassigned_at IS NULL", (module, name, node_id)))


def assign(db: DB, module: str, name: str, node_id: str, actor: str, placed_by: str = "owner") -> dict:
    db.x("INSERT INTO workload_assignments(module, workload, node_id, desired, assigned_at, assigned_by, placed_by) "
         "VALUES(?,?,?,'running',?,?,?) ON CONFLICT(module, workload, node_id) DO UPDATE SET desired='running', "
         "unassigned_at=NULL, assigned_at=excluded.assigned_at, assigned_by=excluded.assigned_by, "
         "placed_by=excluded.placed_by, version=version+1", (module, name, node_id, clock.now(), actor, placed_by))
    db.event("workload_assigned", actor=actor, node_id=node_id, reason=f"{module}/{name}", module=module)
    return {"module": module, "workload": name, "node_id": node_id}


def unassign(db: DB, module: str, name: str, node_id: str, actor: str) -> dict:
    if not _assigned(db, module, name, node_id):
        raise WorkloadError(404, "not_assigned", f"{module}/{name} is not assigned to {node_id}")
    db.x("UPDATE workload_assignments SET unassigned_at=?, version=version+1 WHERE module=? AND workload=? AND "
             "node_id=? AND unassigned_at IS NULL", (clock.now(), module, name, node_id))
    db.event("workload_unassigned", actor=actor, node_id=node_id, reason=f"{module}/{name}", module=module)
    return {"module": module, "workload": name, "node_id": node_id}


def restart(db: DB, module: str, name: str, node_id: str, actor: str) -> dict:
    if not _assigned(db, module, name, node_id):
        raise WorkloadError(404, "not_assigned", f"{module}/{name} is not assigned to {node_id}")
    db.x("UPDATE workload_assignments SET restart_seq=restart_seq+1, version=version+1 WHERE module=? AND workload=? "
             "AND node_id=? AND unassigned_at IS NULL", (module, name, node_id))
    db.event("workload_restarted", actor=actor, node_id=node_id, reason=f"{module}/{name}", module=module)
    return {"module": module, "workload": name, "node_id": node_id}


def eligible_nodes(db: DB, module: str, name: str) -> list[dict]:
    """Nodes that could run the workload now, the most free memory first (a fleet seat's placement)."""
    out = []
    taken = {a["node_id"] for a in assignments(db, module=module) if a["workload"] == name}
    for n in db.q("SELECT * FROM nodes WHERE lifecycle='ready' ORDER BY node_id"):
        if n["node_id"] in taken or offered_reason(db, n, module, name)[0]:
            continue
        cap = jl(n.get("capacity_json"), {}) or {}
        out.append((-(cap.get("mem_gb_free") or 0.0), n["node_id"], n))
    return [n for _, _, n in sorted(out)]


def preview(db: DB, module: str, name: str, node_ids: list[str]) -> dict:
    """What an assignment would do on each node: the secrets it receives (by fingerprint, never values), its seat, the
    listeners it serves and the protection rules on the node that could act on it."""
    from . import modsecrets, protection
    w = decl(module, name)
    rows = []
    for nid in node_ids:
        node = db.one("SELECT * FROM nodes WHERE node_id=?", (nid,)) or {"node_id": nid}
        why, detail = offered_reason(db, node, module, name)
        seat, sw, sd = seat_for(db, nid, module, w) if w else (None, None, "")
        secrets = [{"name": s, **{k: v for k, v in modsecrets.source(db, module, s, nid).items() if k != "scope"}}
                   for s in (w.secrets if w else [])]
        try:
            rules = [r.get("id") for r in (protection.current(db, nid)[1] or {}).get("rule") or []]
        except Exception:                                      # a node without protection settings yet
            rules = []
        rows.append({"node_id": nid, "hostname": node.get("hostname"), "blocked": why or sw, "detail": detail or sd,
                     "seat_id": seat, "secrets": secrets, "listeners": list(w.listeners) if w else [],
                     "protection_rules": rules, "identity": w.identity if w else None})
    return {"workload": f"{module}/{name}", "nodes": rows}


# ------------------------------------------------------------------ directives and leases

def _lease(db: DB, seat_id: str, module: str, name: str, node_id: str, now: float) -> tuple[bool, int, float]:
    """Grant or renew the seat's lease to the node when it may hold it: (granted, fence, lease_s)."""
    row = db.one("SELECT * FROM workload_seats WHERE seat_id=?", (seat_id,))
    if not row:
        db.x("INSERT INTO workload_seats(seat_id, module, workload, fence) VALUES(?,?,?,0)", (seat_id, module, name))
        row = db.one("SELECT * FROM workload_seats WHERE seat_id=?", (seat_id,))
    holder, fence, until = row["node_id"], row["fence"] or 0, row["lease_until"] or 0.0
    if holder is not None and holder != node_id and until + GRACE_S >= now:
        return False, fence, 0.0
    if holder != node_id:
        fence += 1
        db.x("UPDATE workload_seats SET node_id=?, fence=?, lease_until=?, granted_at=?, released_at=NULL WHERE seat_id=?",
             (node_id, fence, now + LEASE_S, now, seat_id))
        db.event("workload_seat_granted", node_id=node_id, reason=f"{module}/{name} {seat_id} fence {fence}", module=module)
    else:
        db.x("UPDATE workload_seats SET lease_until=? WHERE seat_id=?", (now + LEASE_S, seat_id))
    return True, fence, LEASE_S


def directives(db: DB, node: dict) -> list[dict]:
    """The heartbeat reply's `workloads`: one entry per assignment of the node, `desired: running` with its seat, fence
    and lease (lease_s: the lease's end minus now) when it may run, else `stopped` with the reason."""
    nid, now = node["node_id"], clock.now()
    out = []
    active = node.get("desired_state") in (None, "active")
    with db.tx():
        for a in assignments(db, node_id=nid):
            module, name = a["module"], a["workload"]
            e = {"key": f"{module}/{name}", "module": module, "workload": name, "desired": "stopped", "seat_id": None,
                 "fence": 0, "lease_s": None, "restart_seq": a["restart_seq"], "reason": None}
            why, _ = offered_reason(db, node, module, name)
            w = decl(module, name)
            if why is None and not active:
                why = "WORKLOAD_NODE_NOT_ACTIVE"
            if why is None and a["desired"] != "running":
                why = "WORKLOAD_UNASSIGNED"
            seat = None
            if why is None:
                seat, why, _ = seat_for(db, nid, module, w)
            if why is None and seat is not None:
                ok, fence, lease_s = _lease(db, seat, module, name, nid, now)
                e.update(seat_id=seat, fence=fence)
                if ok:
                    e.update(desired="running", lease_s=round(lease_s, 3))
                else:
                    why = "WORKLOAD_SEAT_ELSEWHERE"
            elif why is None:
                e["desired"] = "running"
            e["reason"] = why
            out.append(e)
    return out


def observe(db: DB, node: dict, body: dict) -> dict | None:
    """The agent's `workloads` and `workload_reports` (inside the heartbeat's transaction): each workload's latest
    report, the release of a seat its holder gave up (with the current fence), and report events stored for the module.
    Returns `workload_reports_ack` ({key: highest seq stored}) or None."""
    nid, now = node["node_id"], clock.now()
    rows = body.get("workloads")
    if isinstance(rows, list):
        for r in rows[:200]:
            if not isinstance(r, dict) or not isinstance(r.get("key"), str) or "/" not in r["key"]:
                continue
            module, name = r["key"].split("/", 1)
            seat, fence = r.get("seat_id"), int(r.get("fence") or 0)
            running = bool(r.get("running"))
            prev = db.one("SELECT report_json FROM workload_status WHERE module=? AND workload=? AND node_id=?",
                          (module, name, nid))
            was_withdrawn = bool((jl(prev["report_json"], {}) or {}).get("withdrawn")) if prev else False
            db.x("INSERT OR REPLACE INTO workload_status VALUES(?,?,?,?,?,?,?,?)",
                 (module, name, nid, int(running), seat, fence, json.dumps(r)[:20000], now))
            rule = f"workload_withdrawn:{module}/{name}"
            if r.get("withdrawn") and not was_withdrawn:
                from .core import _alert
                tail = (r.get("log_tail") or "")[-600:]
                _alert(db, rule, f"node:{nid}", f"{module}/{name} on {node.get('hostname') or nid} was withdrawn after "
                       f"{r.get('failures')} failures: {r.get('error') or 'no error given'}" + (f"\n{tail}" if tail else ""))
            elif running and was_withdrawn:
                db.x("UPDATE alerts SET state='resolved', resolved_at=?, resolved_how='runs again' WHERE rule=? AND "
                     "subject=? AND state IN ('open','pending')", (now, rule, f"node:{nid}"))
            if seat and not running and r.get("release"):
                s = db.one("SELECT node_id, fence FROM workload_seats WHERE seat_id=?", (seat,))
                if s and s["node_id"] == nid and (s["fence"] or 0) == fence:
                    db.x("UPDATE workload_seats SET node_id=NULL, lease_until=NULL, released_at=? WHERE seat_id=?", (now, seat))
                    db.event("workload_seat_released", node_id=nid, reason=f"{module}/{name} {seat} fence {fence}", module=module)
    reps = body.get("workload_reports")
    if not isinstance(reps, list) or not reps:
        return None
    ack = {}
    for r in reps[:50]:
        if not isinstance(r, dict) or not isinstance(r.get("key"), str) or "/" not in r["key"]:
            continue
        module, name = r["key"].split("/", 1)
        w = decl(module, name)
        top = None
        for ev in (r.get("events") or [])[:REPORTS_PER_HEARTBEAT]:
            try:
                seq = int(ev["seq"])
            except (KeyError, TypeError, ValueError):
                continue
            data = ev.get("data")
            text = json.dumps(data, separators=(",", ":")) if isinstance(data, dict) else None
            top = seq if top is None else max(top, seq)
            if w is None or not w.reports or text is None or len(text) > REPORT_MAX_BYTES:
                continue                                   # acknowledged, never delivered
            db.x("INSERT OR IGNORE INTO workload_reports(module, workload, node_id, seq, t, seat_id, fence, data_json, "
                 "received_at) VALUES(?,?,?,?,?,?,?,?,?)", (module, name, nid, seq, ev.get("t"), r.get("seat_id"),
                                                            r.get("fence"), text, now))
        if top is not None:
            ack[r["key"]] = top
    return ack


def secrets(db: DB, node: dict, body: dict) -> dict:
    """`POST /v1/agent/workloads/secrets`: the workload's secrets for this node, only while it holds the seat with that
    fence and its lease runs (a workload without an identity: while it is assigned here)."""
    module, name = split_key(body.get("key") or "")
    nid = node["node_id"]
    w = decl(module, name)
    if w is None or not db.one("SELECT 1 FROM workload_assignments WHERE module=? AND workload=? AND node_id=? AND "
                               "unassigned_at IS NULL", (module, name, nid)):
        raise WorkloadError(409, "not_assigned", f"{module}/{name} is not assigned to this node")
    seat, why, detail = seat_for(db, nid, module, w)
    if why:
        raise WorkloadError(409, why.lower().removeprefix("workload_"), detail)
    if seat is not None:
        s = db.one("SELECT * FROM workload_seats WHERE seat_id=?", (seat,))
        if (not s or s["node_id"] != nid or s["fence"] != body.get("fence") or body.get("seat_id") != seat
                or (s["lease_until"] or 0) < clock.now()):
            raise WorkloadError(409, "seat_not_held", f"this node does not hold seat {body.get('seat_id')} with fence "
                                f"{body.get('fence')}")
    from . import modsecrets
    missing = modsecrets.missing_for(db, module, list(w.secrets), nid)
    if missing:
        raise WorkloadError(409, "secrets_not_set", f"secrets {missing} have no value for this node")
    db.event("workload_secrets_delivered", node_id=nid, reason=f"{module}/{name} {seat or ''}", module=module)
    return {"secrets": modsecrets.for_job(db, module, list(w.secrets), nid)}


# ------------------------------------------------------------------ workload reports to the module

def process_reports(db: DB, limit: int = 200) -> int:
    """Deliver pending report events to each module's `workload.report` verb (outside any transaction: module IPC),
    apply the effects it answers (limited to coordinator.workload_effects) with an audit row, and mark them done."""
    from . import audit, effects
    from .modulehost import ModuleError, ModuleUnavailable
    rows = db.q("SELECT * FROM workload_reports WHERE state='pending' ORDER BY received_at, seq LIMIT ?", (limit,))
    groups: dict[tuple, list] = {}
    for r in rows:
        groups.setdefault((r["module"], r["workload"], r["node_id"], r["seat_id"], r["fence"]), []).append(r)
    n = 0
    for (module, name, nid, seat, fence), evs in groups.items():
        seqs = [e["seq"] for e in evs]
        mark = lambda state, err=None: [db.x("UPDATE workload_reports SET state=?, error=? WHERE module=? AND workload=? AND "
                                             "node_id=? AND seq=?", (state, err, module, name, nid, s)) for s in seqs]
        if module not in modcalls.CATALOG or not modcalls.has_capability(module, "workload.report"):
            with db.tx():
                mark("dropped", "the module has no workload.report verb")
            continue
        params = {"workload": name, "node": nid, "seat_id": seat, "fence": fence,
                  "events": [{"seq": e["seq"], "t": e["t"] or 0.0, "data": jl(e["data_json"], {}) or {}} for e in evs]}
        try:
            res = modcalls.call(db, module, "workload.report", params)
        except (ModuleUnavailable, ModuleError) as e:
            db.event("module_fault", reason=f"{module} workload.report: {e}"[:300], module=module)
            continue                                   # stays pending: tried again on the next pass
        allowed = set(modcalls.info(module).manifest.coordinator.workload_effects)
        rid = audit.request_id()
        try:
            with db.tx():
                done = effects.apply(db, module, allowed, res.get("effects") or [], actor=f"module:{module}")
                mark("done")
                audit.append(db, actor=f"module:{module}", source="scheduler", operation="workload.report", category="modify",
                             target_type="workload", target_id=f"{module}/{name}", outcome="ok", request_id=rid,
                             reason=(res.get("message") or None), after={"node": nid, "events": seqs, "effects": done})
            n += 1
        except effects.EffectError as e:
            with db.tx():
                mark("rejected", f"{e.code}: {e.detail}"[:300])
                audit.append(db, actor=f"module:{module}", source="scheduler", operation="workload.report", category="modify",
                             target_type="workload", target_id=f"{module}/{name}", outcome="rejected", request_id=rid,
                             error=f"{e.code}: {e.detail}"[:300])
    db.x("DELETE FROM workload_reports WHERE state!='pending' AND received_at < ?", (clock.now() - 7 * 86400,))
    return n


# ------------------------------------------------------------------ reading

def listing(db: DB, node: str | None = None, module: str | None = None) -> list[dict]:
    """Every assignment with its seat and the node's latest report (the API, `oarbank workload list`, the console)."""
    out = []
    for a in assignments(db, node_id=node, module=module):
        st = db.one("SELECT * FROM workload_status WHERE module=? AND workload=? AND node_id=?",
                    (a["module"], a["workload"], a["node_id"]))
        rep = jl(st["report_json"], {}) if st else {}
        seat = db.one("SELECT * FROM workload_seats WHERE seat_id=?", (rep.get("seat_id"),)) if rep.get("seat_id") else None
        n = db.one("SELECT hostname FROM nodes WHERE node_id=?", (a["node_id"],))
        out.append({"key": f"{a['module']}/{a['workload']}", "module": a["module"], "workload": a["workload"],
                    "node_id": a["node_id"], "hostname": n["hostname"] if n else None, "assigned_at": a["assigned_at"],
                    "assigned_by": a["assigned_by"], "placed_by": a["placed_by"], "restart_seq": a["restart_seq"],
                    "state": rep.get("state") or "unknown", "running": bool(rep.get("running")),
                    "reason": rep.get("blocked") or rep.get("held_code") or rep.get("reason"),
                    "seat_id": rep.get("seat_id"), "fence": rep.get("fence"),
                    "seat_holder": seat["node_id"] if seat else None, "lease_until": seat["lease_until"] if seat else None,
                    "report": rep, "reported_at": st["at"] if st else None})
    return out


def logs(db: DB, key: str, node: str) -> dict:
    module, name = split_key(key)
    st = db.one("SELECT report_json, at FROM workload_status WHERE module=? AND workload=? AND node_id=?", (module, name, node))
    rep = jl(st["report_json"], {}) if st else {}
    return {"key": key, "node_id": node, "at": st["at"] if st else None, "log_tail": rep.get("log_tail") or ""}


def protection_actions(db: DB, key: str, node: str | None = None, since_s: float = 86400) -> list[dict]:
    """The protection actions journaled on a workload in the last day (the module page)."""
    out = []
    sql = "SELECT node_id, seq, t, kind, reason, record_json FROM protection_decisions WHERE t>? AND kind LIKE 'workload_%'"
    args = [clock.now() - since_s]
    if node:
        sql, args = sql + " AND node_id=?", [*args, node]
    for r in db.q(sql + " ORDER BY t DESC LIMIT 200", tuple(args)):
        rec = jl(r["record_json"], {}) or {}
        if rec.get("workload") == key:
            out.append({"node_id": r["node_id"], "t": r["t"], "kind": r["kind"], "reason": r["reason"]})
    return out


# ------------------------------------------------------------------ invariant S26

def s26_single_seat(db: DB) -> list[str]:
    """S26: at most one node runs a seat of a per-node identity at a time. From the nodes' fresh reports: no two nodes
    report one seat running, and a node that reports a seat running holds it with that fence (or reported before the
    seat last moved)."""
    out = []
    fresh = clock.now() - FRESH_S
    by_seat: dict[str, list] = {}
    for r in db.q("SELECT * FROM workload_status WHERE running=1 AND seat_id IS NOT NULL AND seat_id LIKE 's_%' AND at>?",
                  (fresh,)):
        by_seat.setdefault(r["seat_id"], []).append(r)
    for seat, rs in by_seat.items():
        nodes = sorted({r["node_id"] for r in rs})
        if len(nodes) > 1:
            out.append(f"S26 seat {seat} ({rs[0]['module']}/{rs[0]['workload']}) runs on {len(nodes)} nodes: {', '.join(nodes)}")
        s = db.one("SELECT node_id, fence, granted_at FROM workload_seats WHERE seat_id=?", (seat,))
        for r in rs:
            if s and (s["node_id"] != r["node_id"] or s["fence"] != r["fence"]) and r["at"] > (s["granted_at"] or 0) + GRACE_S:
                out.append(f"S26 node {r['node_id']} reports seat {seat} running with fence {r['fence']}, but "
                           f"{s['node_id'] or 'no node'} holds it with fence {s['fence']}")
    return out
