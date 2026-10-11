"""Rollouts (docs/design/fleet-updates.md, "Rollouts"; PLAN D59, D61; invariants S29-S31; TLA+ specs/OarbankRollout.tla).

A rollout takes the fleet to one release: the coordinator first (ring 0, coordself.py), then the node rings canary,
early and broad (each node's `update_ring`). The tick runs in oarbankd's background loop, one transaction per rollout:
it gates a ring's start on fleet health, grants `go` to staged, eligible nodes while fewer than the ring's
`max_unavailable` are between draining and confirming (S29), counts install failures against the ring's budget (halt,
and with `auto_rollback` a `rollback` rollout for the nodes it moved), and starts the next ring only once the ring
finished and baked: its bake time passed and every node it updated heartbeated at least 10 times on the new release,
healthy. A node offline when its ring runs waits (`waiting`, offline) and catches up when it returns; a node held,
pinned elsewhere or without a package it can install is skipped with the reason. Each grant records the node's
eligibility beside it (S31).

Rollout states: running, paused, halted, rolling_back, rolled_back, done, superseded (a newer release's rollout
started). Per node: pending, waiting, staging, staged, draining, installing, confirming, done; failed and
rolled_back count against the ring's budget; skipped(why).
"""
import datetime as dt
import json
import secrets
import threading

from . import clock
from .db import DB, jl

SCHEMA = """
-- Rollouts (rollouts.py, docs/design/fleet-updates.md): one release across the fleet, ring by ring
CREATE TABLE IF NOT EXISTS rollouts (
  rollout_id TEXT PRIMARY KEY, version TEXT NOT NULL, from_versions_json TEXT, state TEXT NOT NULL,
  ring TEXT, ring_started_at REAL, ring_finished_at REAL, policy_json TEXT, created_by TEXT, created_at REAL,
  updated_at REAL, halted_reason TEXT, kind TEXT NOT NULL DEFAULT 'update',   -- update | rollback
  rings_json TEXT DEFAULT '{}',                       -- per ring: started_at, finished_at, baked_at, skipped
  parent TEXT, auto INT DEFAULT 0);
-- Each node's part in a rollout; go_facts_json journals every grant with the node's eligibility then (S31)
CREATE TABLE IF NOT EXISTS rollout_nodes (
  rollout_id TEXT NOT NULL, node_id TEXT NOT NULL, ring TEXT NOT NULL, state TEXT NOT NULL, from_version TEXT,
  target TEXT, attempts INT DEFAULT 0, failures INT DEFAULT 0, go INT DEFAULT 0, go_at REAL, go_facts_json TEXT DEFAULT '[]',
  started_at REAL, finished_at REAL, error TEXT, state_at REAL, heartbeats INT DEFAULT 0, retry_at REAL,
  PRIMARY KEY (rollout_id, node_id));
"""

RINGS = ("canary", "early", "broad")
ORDER = ("coordinator", *RINGS)
LIVE = ("running", "paused", "halted", "rolling_back", "done")    # rollouts that may still govern a node
ACTIVE = ("running", "paused", "halted", "rolling_back")
BUSY = ("draining", "installing", "confirming")                   # between draining and confirmed (S29)
SETTLED = ("done", "skipped", "failed", "rolled_back")
ONLINE_S = 120.0                    # D59: online is a heartbeat within 120 s
UNHEALTHY_S = 300.0                 # the fleet-health gate: no heartbeat in 300 s, or quarantined
STUCK_S = 45 * 60.0                 # update_node_stuck
BAKE_HEARTBEATS = 10                # each updated node heartbeats this often on the new release before the next ring
RETRY_DEFERRED_S = 900.0            # a node whose drain timed out is offered the slot again after this
SEAT_MARGIN_S = 600.0               # a seat holder updates only with this much of its lease left (adopted after restart)
DRAIN_TIMEOUT_S = 1800


class RolloutError(Exception):
    pass


# ------------------------------------------------------------------ policy

def default_policy(params: dict | None, sizes: dict, canary_like: bool) -> dict:
    """The design's ring table, with an operation's overrides (`fast` for a critical release; `max_unavailable`,
    `bake_s` and `budget` as a number for every node ring or per ring; `rings` to run a subset, e.g. ["coordinator"])."""
    p = dict(params or {})
    fast = bool(p.get("fast"))
    rings = {"coordinator": {"bake_s": 600, "budget": 0},
             "canary": {"max_unavailable": 1, "bake_s": 600 if fast else 1800, "budget": 0},
             "early": {"max_unavailable": 1, "bake_s": 600 if fast else 7200, "budget": 1},
             "broad": {"max_unavailable": max(1, sizes.get("broad", 0) // 4), "bake_s": 0, "budget": 1,
                       "canary_like": canary_like and p.get("max_unavailable") is None and p.get("budget") is None}}
    for k in ("max_unavailable", "bake_s", "budget"):
        v = p.get(k)
        if v is None:
            continue
        per = v if isinstance(v, dict) else {r: v for r in RINGS}
        for ring, x in per.items():
            if ring not in rings or not isinstance(x, (int, float)) or isinstance(x, bool) or x < (1 if k == "max_unavailable" else 0):
                raise RolloutError(f"params.{k}: a number ({'at least 1' if k == 'max_unavailable' else '0 or more'}) "
                                   "or {ring: number}")
            rings[ring][k] = int(x)
    sel = p.get("rings") or list(ORDER)
    if not isinstance(sel, list) or not sel or any(r not in ORDER for r in sel):
        raise RolloutError(f"params.rings: a subset of {', '.join(ORDER)}")
    dto = p.get("drain_timeout_s", DRAIN_TIMEOUT_S)
    if not isinstance(dto, (int, float)) or isinstance(dto, bool) or dto <= 0:
        raise RolloutError("params.drain_timeout_s: seconds")
    return {"fast": fast, "rings": rings, "selected": [r for r in ORDER if r in sel], "drain_timeout_s": int(dto),
            "auto_rollback": p.get("auto_rollback", True) is not False}


def policy_of(db: DB, rollout_id: str | None) -> dict:
    r = db.one("SELECT policy_json FROM rollouts WHERE rollout_id=?", (rollout_id,)) if rollout_id else None
    return jl(r["policy_json"], {}) if r else {}


# ------------------------------------------------------------------ eligibility (D59)

def _hhmm(s: str) -> int:
    h, m = (int(x) for x in str(s).split(":")[:2])
    return h * 60 + m


def window_contains(sched: dict | None, t: float, offset_s: float) -> bool:
    """The `schedule` setting's rule (the agent's capacity::Schedule): days 0 = Monday; an overnight window belongs to
    the day it starts on; start == end is the whole day; no days is every day."""
    if not sched:
        return True
    local = t + offset_s
    minute, wd = int((local % 86400) // 60), (int(local // 86400) + 3) % 7
    days = set(sched.get("days") or []) or None
    day_ok = lambda d: days is None or d in days
    start, end = _hhmm(sched["start"]) % 1440, _hhmm(sched["end"])
    end = 1440 if end == 1440 else end % 1440
    if start == end or (start == 0 and end == 1440):
        return day_ok(wd)
    if start < end:
        return day_ok(wd) and start <= minute < end
    if minute >= start:
        return day_ok(wd)
    return minute < end and day_ok((wd + 6) % 7)


def utc_offset(node: dict, t: float) -> float:
    """The node's offset from UTC: what its facts say, else this machine's (a fleet in one zone)."""
    off = (jl(node.get("facts_json"), {}) or {}).get("utc_offset_s")
    if isinstance(off, (int, float)) and not isinstance(off, bool):
        return float(off)
    return dt.datetime.fromtimestamp(t).astimezone().utcoffset().total_seconds()


def eligibility(db: DB, node: dict, version: str, t: float, snap=None) -> dict:
    """Whether a node may be told `go` now (D59), fact by fact, with the first reason it may not."""
    from . import fleetupdates as F, protection
    from .settings import resolve
    snap = snap or resolve.snapshot(db)
    online = (node.get("last_heartbeat_at") or 0) >= t - ONLINE_S
    win = resolve.resolve(snap, node, "update_window")["value"]
    in_window = window_contains(win, t, utc_offset(node, t))
    held = F.active_hold(db, node, t, snap) is not None
    pin = F.active_pin(db, node, t, snap)
    pinned = bool(pin and pin["version"] != version)
    prot = protection.any_phase_on(db, [node["node_id"]], None, t)
    seats = db.q("SELECT lease_until FROM workload_seats WHERE node_id=? AND released_at IS NULL AND lease_until>?",
                 (node["node_id"], t))
    seat = any((s["lease_until"] or 0) - t < SEAT_MARGIN_S for s in seats)
    why = ("offline" if not online else "outside its update window" if not in_window else "held" if held else
           f"pinned to {pin['version']}" if pinned else "a protected phase is on: " + "; ".join(prot["why"])[:200]
           if prot["on"] else "a workload seat's lease is due for renewal" if seat else None)
    return {"online": online, "in_window": in_window, "held": held, "pinned": pinned, "protected": prot["on"],
            "seat": seat, "ok": why is None, "why": why}


def fleet_unhealthy(db: DB, t: float) -> tuple[bool, list[str]]:
    """D59 rule 8: more than a third of the fleet's nodes (those seen in the last day) are unhealthy: no heartbeat in
    300 s, or quarantined."""
    rows = db.q("SELECT hostname, lifecycle, last_heartbeat_at FROM nodes WHERE lifecycle!='retired' AND last_heartbeat_at>=?",
                (t - 86400,))
    bad = [n["hostname"] for n in rows if n["lifecycle"] == "quarantined" or (n["last_heartbeat_at"] or 0) < t - UNHEALTHY_S]
    return bool(rows) and 3 * len(bad) > len(rows), bad


# ------------------------------------------------------------------ rows

def row(db: DB, rid: str) -> dict | None:
    r = db.one("SELECT * FROM rollouts WHERE rollout_id=?", (rid,))
    if r:
        r["policy"], r["rings"] = jl(r["policy_json"], {}), jl(r["rings_json"], {}) or {}
    return r


def members(db: DB, rid: str, ring: str | None = None) -> list[dict]:
    q = "SELECT rn.*, n.hostname FROM rollout_nodes rn LEFT JOIN nodes n ON n.node_id=rn.node_id WHERE rn.rollout_id=?"
    return db.q(q + (" AND rn.ring=?" if ring else "") + " ORDER BY n.hostname", (rid, ring) if ring else (rid,))


def _save_rings(db: DB, r: dict):
    db.x("UPDATE rollouts SET rings_json=?, updated_at=? WHERE rollout_id=?", (json.dumps(r["rings"]), clock.now(), r["rollout_id"]))


def _set_node(db: DB, rid: str, nid: str, t: float, **cols):
    old = db.one("SELECT state FROM rollout_nodes WHERE rollout_id=? AND node_id=?", (rid, nid))
    if old and "state" in cols and cols["state"] != old["state"]:
        cols["state_at"] = t
    sets = ", ".join(f"{k}=?" for k in cols)
    db.x(f"UPDATE rollout_nodes SET {sets} WHERE rollout_id=? AND node_id=?", (*cols.values(), rid, nid))


def _node(db: DB, nid: str) -> dict | None:
    return db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))


def _coordself():
    try:
        from . import coordself
        return coordself
    except ImportError:
        return None


def coordinator_state(db: DB) -> dict | None:
    """The latest coordinator self-update (coordself.state), or None."""
    cs = _coordself()
    try:
        return cs.state(db) if cs else None
    except Exception:
        return None


# ------------------------------------------------------------------ membership and the plan

def _membership(db: DB, node: dict, version: str, pol: dict, auto: bool, t: float, snap) -> dict:
    from . import fleetupdates as F
    from .settings import resolve
    ring = resolve.resolve(snap, node, "update_ring")["value"] or "broad"
    have = node.get("agent_version")
    state, why = "pending", None
    hold, pin = F.active_hold(db, node, t, snap), F.active_pin(db, node, t, snap)
    if have and not F.newer(version, have):
        state, why = "done", "already runs it"
    elif ring not in pol["selected"]:
        state, why = "skipped", f"ring {ring} is not in this rollout"
    elif hold:
        state, why = "skipped", f"held: {hold['reason']}"
    elif pin and pin["version"] != version:
        state, why = "skipped", f"pinned to {pin['version']}: {pin['reason']}"
    elif auto and resolve.resolve(snap, node, "update_auto")["value"] != "on":
        state, why = "skipped", f"update_auto is {resolve.resolve(snap, node, 'update_auto')['value']} here"
    else:
        art, w = F.artifact_for(db, version, node)
        if not art:
            state, why = "skipped", w
    return {"node_id": node["node_id"], "hostname": node["hostname"], "ring": ring, "state": state, "why": why,
            "from_version": have, "window": resolve.resolve(snap, node, "update_window")["value"], "hold": hold, "pin": pin}


def plan(db: DB, version: str, params: dict | None = None, auto: bool = False) -> dict:
    """What updates.start would do (its T2 preview): the coordinator first when the release is newer, then each ring's
    nodes with their windows and holds, what is skipped and why, and what would stop it now."""
    from . import fleetupdates as F
    from .settings import resolve
    t, snap = clock.now(), resolve.snapshot(db)
    rel = F.release(db, version)
    if not rel:
        raise RolloutError(f"no release {version} is imported (oarbank update import or fetch)")
    rows = [_membership(db, n, version, default_policy(params, {}, False), auto, t, snap) for n in F.nodes(db)]
    sizes = {r: sum(1 for m in rows if m["ring"] == r and m["state"] == "pending") for r in RINGS}
    explicit = bool(db.one("SELECT 1 FROM setting_values WHERE key='update_ring'"))
    pol = default_policy(params, sizes, not explicit)
    cv = F.coordinator_version()
    doc = F.manifest_doc(db, version) or {}
    too_old = [n["hostname"] for n in F.nodes(db) if doc.get("agent_min") and F.newer(doc["agent_min"], n.get("agent_version"))
               and not F.active_hold(db, n, t, snap)]
    coord = {"from": cv, "to": version, "needed": F.newer(version, cv), "included": "coordinator" in pol["selected"],
             "blocked_by": too_old}
    unhealthy, bad = fleet_unhealthy(db, t)
    rings = [{"ring": r, **pol["rings"][r], "nodes": [m for m in rows if m["ring"] == r and m["state"] == "pending"]}
             for r in RINGS if r in pol["selected"]]
    stops = []
    if rel["gaps"]:
        stops.append(f"release {version} is not ready: {'; '.join(rel['gaps'])}")
    if unhealthy:
        stops.append(f"the fleet is unhealthy ({len(bad)} nodes: {', '.join(bad[:8])})")
    if coord["needed"] and coord["included"] and too_old:
        stops.append(f"the coordinator refuses its update while these nodes run an agent older than {doc['agent_min']}: "
                     f"{', '.join(too_old)} (update or hold them)")
    if coord["needed"] and not coord["included"]:
        stops.append(f"the release is newer than this coordinator ({cv}): no node gets it before the coordinator runs it")
    act = active(db)
    return {"version": version, "seq": rel["seq"], "notes": rel["notes"], "coordinator": coord, "rings": rings,
            "skipped": [{"hostname": m["hostname"], "ring": m["ring"], "why": m["why"]} for m in rows if m["state"] == "skipped"],
            "already": [m["hostname"] for m in rows if m["state"] == "done"], "policy": pol,
            "supersedes": act["rollout_id"] if act and act["version"] != version else None, "refused": stops}


def plan_impact(p: dict) -> dict:
    """The plan as a person reads it in a preview (the console's review page, `oarbank update plan`), with the whole plan
    under `_plan` for pages that draw it themselves."""
    from .settings import registry as R
    c = p["coordinator"]

    def who(m):
        return m["hostname"] + (f" (window {R.show('update_window', m['window'])})" if m.get("window") else "")
    rings = []
    for r in p["rings"]:
        if not r["nodes"]:
            continue
        rings.append(f"{r['ring']}: {', '.join(who(m) for m in r['nodes'])}; {r['max_unavailable']} at a time, bake "
                     f"{r['bake_s'] // 60} min, failure budget {r['budget']}")
    if c["needed"] and c["included"]:
        coord = f"{c['from']} to {c['to']} first: snapshot, self-test, install, probation"
    else:
        coord = f"runs {c['from']}" + (": not in this rollout" if c["needed"] else "")
    return {"release": f"{p['version']} (seq {p['seq']})", "notes": p.get("notes"), "coordinator": coord,
            "rings": rings or ["no node updates"], "skipped": [f"{m['hostname']}: {m['why']}" for m in p["skipped"]],
            "already": p["already"], "supersedes": p["supersedes"], "refused": p["refused"], "_plan": p}


def start(db: DB, version: str, actor: str, params: dict | None = None, auto: bool = False) -> dict:
    """Start a rollout (inside the caller's transaction): refused while the release is not ready, the fleet is unhealthy,
    or another rollout is halted or rolling back; a running or done rollout of an older release is superseded."""
    from . import fleetupdates as F
    t = clock.now()
    p = plan(db, version, params, auto)
    if p["refused"]:
        raise RolloutError("; ".join(p["refused"]))
    for r in db.q("SELECT * FROM rollouts WHERE state IN ('running','paused','halted','rolling_back','done')"):
        if r["state"] in ("halted", "rolling_back") or (r["state"] in ("running", "paused") and not F.newer(version, r["version"])):
            raise RolloutError(f"rollout {r['rollout_id']} ({r['version']}) is {r['state']}: "
                               + ("resume, roll back or let it finish first" if r["state"] != "rolling_back" else "wait for it"))
    for r in db.q("SELECT rollout_id FROM rollouts WHERE state IN ('running','paused','done')"):
        db.x("UPDATE rollouts SET state='superseded', updated_at=? WHERE rollout_id=?", (t, r["rollout_id"]))
        db.event("rollout_superseded", actor=actor, reason=f"{r['rollout_id']} by {version}")
    rid = "ro_" + secrets.token_hex(6)
    from_versions = sorted({n.get("agent_version") or "?" for n in F.nodes(db)})
    db.x("INSERT INTO rollouts(rollout_id, version, from_versions_json, state, ring, policy_json, created_by, created_at, "
         "updated_at, kind, rings_json, auto) VALUES(?,?,?, 'running', NULL, ?,?,?,?, 'update', '{}', ?)",
         (rid, version, json.dumps(from_versions), json.dumps({**p["policy"], "coord_needed": p["coordinator"]["needed"]}),
          actor, t, t, int(auto)))
    from .settings import resolve
    snap = resolve.snapshot(db)
    for n in F.nodes(db):
        _add_member(db, rid, _membership(db, n, version, p["policy"], auto, t, snap), version, t)
    db.event("rollout_started", actor=actor, reason=f"{rid}: {version}" + (" (automatic)" if auto else ""),
             rings=[r["ring"] for r in p["rings"] if r["nodes"]])
    from . import core
    core._resolve_alert(db, "update_available", f"release:{version}")
    _advance(db, row(db, rid), t)
    return view_rollout(db, rid)


def _add_member(db: DB, rid: str, m: dict, version: str, t: float):
    db.x("INSERT OR IGNORE INTO rollout_nodes(rollout_id, node_id, ring, state, from_version, target, error, state_at) "
         "VALUES(?,?,?,?,?,?,?,?)", (rid, m["node_id"], m["ring"], m["state"], m["from_version"], version, m["why"], t))


# ------------------------------------------------------------------ what governs a node

def governing(db: DB, nid: str) -> tuple[dict | None, dict | None]:
    """(the newest live rollout, the node's row in it or None)."""
    r = db.one("SELECT * FROM rollouts WHERE state IN ('running','paused','halted','rolling_back','done') "
               "ORDER BY created_at DESC, rowid DESC LIMIT 1")
    if not r:
        return None, None
    return r, db.one("SELECT * FROM rollout_nodes WHERE rollout_id=? AND node_id=?", (r["rollout_id"], nid))


def _started(r: dict, ring: str) -> bool:
    """The node ring has started in this rollout (every ring has once the rollout is done)."""
    if r["state"] == "done":
        return True
    cur = r.get("ring")
    return bool(cur) and cur != "coordinator" and ORDER.index(ring) <= ORDER.index(cur)


def target(db: DB, node: dict) -> dict | None:
    """The governing rollout's word on this node: {version, rollback, rollout_id, why}, or None (it stays as it is).
    A rollback rollout sends each node it moves back to the release it ran; while a rollout runs or is paused a node
    gets its version once its ring started; a halted rollout starts nothing new (only nodes already told `go`, or done,
    keep its version); a done rollout's release is every member's (nodes that missed it catch up)."""
    r, rn = governing(db, node["node_id"])
    if not r or not rn or rn["state"] == "skipped":
        return None
    if r["kind"] == "rollback":
        return {"version": rn["target"], "rollback": True, "rollout_id": r["rollout_id"], "why": "rolling back"}
    if r["state"] == "rolling_back":
        return None
    if r["state"] == "halted" and not (rn["go"] or rn["state"] in ("done", *BUSY)):
        return None
    if r["state"] in ("running", "paused") and not _started(r, rn["ring"]):
        return None
    if rn["state"] in ("failed", "rolled_back") and r["state"] != "done":
        return None
    return {"version": r["version"], "rollback": False, "rollout_id": r["rollout_id"], "why": f"rollout {r['rollout_id']}"}


def go(db: DB, node: dict, a: dict) -> bool:
    """The directive's `go`: granted by the tick (a rollout's node), or, for a pin, whenever the node is eligible."""
    if not a.get("rollout_id"):
        return eligibility(db, node, a["version"], clock.now())["ok"]
    rn = db.one("SELECT go FROM rollout_nodes WHERE rollout_id=? AND node_id=?", (a["rollout_id"], node["node_id"]))
    return bool(rn and rn["go"])


# ------------------------------------------------------------------ the agent's report

def observe(db: DB, node: dict, rep: dict | None, heartbeat: bool):
    """Move the node's row in the governing rollout by what its agent reports for the release it was sent; count
    heartbeats on the new release for the bake."""
    from . import fleetupdates as F
    r, rn = governing(db, node["node_id"])
    if not r or not rn:
        return
    t, rid, nid = clock.now(), r["rollout_id"], node["node_id"]
    if heartbeat and rn["state"] == "done" and node.get("agent_version") == rn["target"]:
        db.x("UPDATE rollout_nodes SET heartbeats=heartbeats+1 WHERE rollout_id=? AND node_id=?", (rid, nid))
    if rep is None or rn["state"] in ("done", "skipped"):
        return
    a = F.assigned(db, node)
    sent = a["version"] if a else None
    st = rep["state"]
    if st == "done" and node.get("agent_version") == rn["target"]:
        _set_node(db, rid, nid, t, state="done", go=0, finished_at=t, heartbeats=0, error=None)
        return
    if not sent or rep.get("release") not in (sent, rn["target"]):
        return                                         # a report about another release (stale, or before a stop)
    if st == "unsupported":
        _set_node(db, rid, nid, t, state="skipped", go=0, error=rep.get("error") or "the agent cannot install packages")
    elif st in ("staging", "staged") and rn["state"] in ("pending", "waiting", "staging", "staged"):
        _set_node(db, rid, nid, t, state=st)
    elif st in BUSY:
        _set_node(db, rid, nid, t, state=st, started_at=rn["started_at"] or t)
    elif st == "deferred" and rn["state"] != "staged":
        _set_node(db, rid, nid, t, state="staged", go=0, retry_at=t + RETRY_DEFERRED_S,
                  error="the drain timed out: running work is left to finish; retried later")
    elif st == "done":                                 # a stop on the way: the next directive needs its own grant
        _set_node(db, rid, nid, t, state="pending", go=0, error=f"passed stop {rep.get('release')}")
    elif st in ("failed", "refused", "rolled_back") and rn["state"] not in ("failed", "rolled_back"):
        _set_node(db, rid, nid, t, state="rolled_back" if st == "rolled_back" else "failed", go=0, finished_at=t,
                  failures=(rn["failures"] or 0) + 1, error=(rep.get("error") or st)[:500])


# ------------------------------------------------------------------ the tick

_check_lock = threading.Lock()


def tick(db: DB, now: float | None = None):
    """One pass over the live rollouts (oarbankd's background loop), then stuck nodes, expired holds and pins, and the
    update policy (auto start, the update_available notice, the periodic check)."""
    t = clock.now() if now is None else now
    for x in db.q("SELECT rollout_id FROM rollouts WHERE state IN ('running','done') ORDER BY created_at, rowid"):
        _coordinator_step(db, x["rollout_id"], t)     # outside a transaction: preparing snapshots the database
        with db.tx():
            _tick_one(db, x["rollout_id"], t)
    with db.tx():
        _stuck(db, t)
        _expired(db, t)
    auto(db, t)


_PREPARING: dict = {}                 # rollout id -> the coordinator update's prepare running on its thread


def _prepare(cs, path, version: str, actor: str, job: dict):
    try:
        cs.request(DB(path), version, actor)
    except Exception as e:                  # coordself.UpdateError, or a prepare that failed
        job["err"] = str(e)[:300] or type(e).__name__
    finally:
        job["done"].set()


def _coordinator_step(db: DB, rid: str, t: float):
    """Ring 0: ask coordself for the coordinator's own update, once per rollout (D58)."""
    from . import fleetupdates as F
    r = row(db, rid)
    if not r or r["state"] != "running" or r["ring"] != "coordinator" or r["policy"].get("coord_requested_at") \
            or not F.newer(r["version"], F.coordinator_version()):
        return
    doc = F.manifest_doc(db, r["version"]) or {}
    old = [n["hostname"] for n in F.nodes(db) if doc.get("agent_min") and F.newer(doc["agent_min"], n.get("agent_version"))
           and not F.active_hold(db, n, t)]
    cs = _coordself()
    err = None
    if old:
        err = f"nodes run an agent older than {doc['agent_min']}: {', '.join(old)} (update or hold them)"
    elif cs is None:
        err = "this coordinator cannot update itself (no coordself)"
    else:
        # the prepare (a snapshot, and the new build migrating a copy) can take minutes: it runs on a thread with a
        # connection of its own, so this loop (leases, the reaper, invariants) never waits for it
        job = _PREPARING.get(rid)
        if job is None:
            job = _PREPARING[rid] = {"err": None, "done": threading.Event()}
            threading.Thread(target=_prepare, args=(cs, db.path, r["version"], r["created_by"] or "system", job),
                             name=f"coordinator-update-{rid}", daemon=True).start()
            return
        if not job["done"].is_set():
            return
        _PREPARING.pop(rid, None)
        err = job["err"]
    with db.tx():
        r = row(db, rid)
        if err:
            halt(db, r, f"coordinator update refused: {err}", "system")
            return
        r["policy"]["coord_requested_at"] = t
        db.x("UPDATE rollouts SET policy_json=?, updated_at=? WHERE rollout_id=?", (json.dumps(r["policy"]), t, rid))
        db.event("rollout_coordinator_requested", reason=f"{rid}: {F.coordinator_version()} -> {r['version']}")


def _tick_one(db: DB, rid: str, t: float):
    from . import core, fleetupdates as F
    from .settings import resolve
    r = row(db, rid)
    if not r or r["state"] not in ("running", "done"):
        return
    snap = resolve.snapshot(db)
    if r["kind"] == "rollback":
        _tick_rollback(db, r, t, snap)
        return
    _sync(db, r, t, snap)
    if r["state"] == "done":                     # catch-up: nodes that missed it, under their window and the caps
        for ring in RINGS:
            _grant(db, r, ring, t, snap)
        return
    if r["ring"] is None:
        _advance(db, r, t)
        return
    if r["ring"] == "coordinator":
        if F.newer(r["version"], F.coordinator_version()):
            st = coordinator_state(db)
            if st and st.get("version") == r["version"] and st.get("state") in ("rolled_back", "refused", "failed"):
                halt(db, r, f"coordinator update {st['state']}: {st.get('error') or ''}".strip(), "system")
                if st["state"] in ("rolled_back", "failed"):
                    core._alert(db, "coordinator_update_rolled_back", "coordinator",
                                f"the coordinator's update to {r['version']} {st['state'].replace('_', ' ')}: "
                                f"{st.get('error') or 'see the coordinator card'}; rollout {rid} halted")
            return
        info = r["rings"].setdefault("coordinator", {})
        info.setdefault("finished_at", t)
        bake = r["policy"]["rings"]["coordinator"]["bake_s"] if r["policy"].get("coord_requested_at") else 0
        if t - info["finished_at"] >= bake:
            info["baked_at"] = t
            _save_rings(db, r)
            _advance(db, r, t)
        else:
            _save_rings(db, r)
        return
    for ring in RINGS:                           # earlier rings' late nodes catch up beside the current one
        if _started(r, ring):
            _grant(db, r, ring, t, snap)
            if _budget(db, r, ring, t):
                return
    ring = r["ring"]
    ms = members(db, rid, ring)
    info = r["rings"].setdefault(ring, {})
    settled = all(m["state"] in SETTLED or (m["state"] == "waiting" and m["error"] == "offline") for m in ms)
    # a ring widens the rollout only on evidence: before a later ring with nodes starts, one of this ring's nodes must
    # have updated, or the owner skipped them all; a ring whose nodes are all offline waits (inconclusive is a pause)
    later = any(members(db, rid, x) for x in RINGS[RINGS.index(ring) + 1:])
    evidence = any(m["state"] == "done" for m in ms) or all(m["state"] == "skipped" for m in ms)
    if settled and later and not evidence:
        away = [m["hostname"] or m["node_id"] for m in ms if m["state"] == "waiting"]
        why = f"no node of the {ring} ring has updated yet" + (f" ({', '.join(away)} offline: wait, or skip them)" if away else "")
        if info.get("waiting_for") != why:
            info["waiting_for"] = why
            db.event("rollout_ring_waiting", reason=f"{rid}: {why}")
        _save_rings(db, r)
        return
    info.pop("waiting_for", None)
    if settled:
        info.setdefault("finished_at", t)
        db.x("UPDATE rollouts SET ring_finished_at=? WHERE rollout_id=?", (info["finished_at"], rid))
        moved = [m for m in ms if m["state"] == "done" and m["from_version"] != r["version"]]
        for m in moved:                          # a node unhealthy during the bake counts as a failure
            n = _node(db, m["node_id"]) or {}
            if n.get("lifecycle") == "quarantined" or (n.get("last_heartbeat_at") or 0) < t - UNHEALTHY_S:
                _set_node(db, rid, m["node_id"], t, state="failed", failures=(m["failures"] or 0) + 1,
                          error="unhealthy during the bake")
        if _budget(db, r, ring, t):
            return
        moved = [m for m in members(db, rid, ring) if m["state"] == "done" and m["from_version"] != r["version"]]
        bake = r["policy"]["rings"][ring]["bake_s"] if moved else 0
        if t - info["finished_at"] >= bake and all((m["heartbeats"] or 0) >= BAKE_HEARTBEATS for m in moved):
            info["baked_at"] = t
            _save_rings(db, r)
            _advance(db, r, t)
            return
    _save_rings(db, r)


def _sync(db: DB, r: dict, t: float, snap):
    """Nodes that joined since the start join their ring; retired ones are skipped; holds and pins skip nodes not yet
    told `go`, and a node whose hold or pin ended rejoins; a node offline while its ring runs waits; a node without a
    package it can install is skipped with the reason."""
    from . import fleetupdates as F
    rid = r["rollout_id"]
    for n in F.nodes(db):
        if not db.one("SELECT 1 FROM rollout_nodes WHERE rollout_id=? AND node_id=?", (rid, n["node_id"])):
            m = _membership(db, n, r["version"], r["policy"], bool(r["auto"]), t, snap)
            _add_member(db, rid, m, r["version"], t)
            db.event("rollout_node_joined", node_id=n["node_id"], reason=f"{rid}: ring {m['ring']}, {m['state']}")
    for m in members(db, rid):
        n = _node(db, m["node_id"])
        if not n or n["lifecycle"] == "retired":
            if m["state"] != "skipped":
                _set_node(db, rid, m["node_id"], t, state="skipped", go=0, error="retired")
            continue
        if m["state"] not in SETTLED and n.get("agent_version") and not F.newer(r["version"], n["agent_version"]):
            _set_node(db, rid, m["node_id"], t, state="done", go=0, finished_at=t, error=None)   # its report got lost
            continue
        hold, pin = F.active_hold(db, n, t, snap), F.active_pin(db, n, t, snap)
        blocked = f"held: {hold['reason']}" if hold else (f"pinned to {pin['version']}: {pin['reason']}"
                                                          if pin and pin["version"] != r["version"] else None)
        if m["state"] == "skipped" and (m["error"] or "").startswith(("held", "pinned")) and not blocked:
            _set_node(db, rid, m["node_id"], t, state="pending", error=None)
            db.event("rollout_node_rejoined", node_id=m["node_id"], reason=f"{rid}: its hold or pin ended")
            continue
        if blocked and m["state"] in ("pending", "waiting", "staging", "staged", "draining"):
            _set_node(db, rid, m["node_id"], t, state="skipped", go=0, error=blocked)   # a drain is abandoned; an install
            continue                                                                    # under way is the runner's
        if m["state"] not in ("pending", "waiting", "staging", "staged") or m["go"]:
            continue
        if not _started(r, m["ring"]):
            continue
        art, why = F.artifact_for(db, r["version"], n)
        if not art and F.newer(r["version"], n.get("agent_version")):
            _set_node(db, rid, m["node_id"], t, state="skipped", error=why)
        elif (n.get("last_heartbeat_at") or 0) < t - ONLINE_S:
            if m["state"] != "waiting":
                _set_node(db, rid, m["node_id"], t, state="waiting", error="offline")
        elif m["state"] == "waiting":
            _set_node(db, rid, m["node_id"], t, state="pending", error=None)   # back: its next report says where it is


def _cap(r: dict, ring: str, ms: list[dict]) -> tuple[int, int]:
    """(max_unavailable, failure budget) of a ring now: with no update_ring set anywhere every node is broad, and the
    first broad node acts as the canary (one at a time, no failure allowed) until one finished."""
    cfg = r["policy"]["rings"][ring]
    if cfg.get("canary_like") and not any(m["state"] == "done" and m["from_version"] != r["version"] for m in ms):
        return 1, 0
    return int(cfg.get("max_unavailable") or 1), int(cfg.get("budget") or 0)


def _grant(db: DB, r: dict, ring: str, t: float, snap):
    """D59 rule 3: while fewer than max_unavailable of the ring's nodes are busy (draining to confirming, or staged with
    `go`), grant `go` to the next staged, eligible node: idle ones first, then by fewest running attempts and hostname.
    The grant journals the eligibility it was made on (S31)."""
    if r["state"] not in ("running", "done"):
        return
    ms = members(db, r["rollout_id"], ring)
    cap, _ = _cap(r, ring, ms)
    busy = sum(1 for m in ms if m["state"] in BUSY or (m["state"] == "staged" and m["go"]))
    cands = [m for m in ms if m["state"] == "staged" and not m["go"] and (m["retry_at"] or 0) <= t]
    live = {m["node_id"]: db.one("SELECT COUNT(*) n FROM attempts WHERE node_id=? AND state='live'", (m["node_id"],))["n"]
            for m in cands}
    for m in sorted(cands, key=lambda m: (live[m["node_id"]] > 0, live[m["node_id"]], m["hostname"] or "")):
        if busy >= cap:
            break
        n = _node(db, m["node_id"])
        if not n:
            continue
        facts = eligibility(db, n, m["target"] if r["kind"] == "rollback" else r["version"], t, snap)
        if not facts["ok"]:
            if m["error"] != f"waiting: {facts['why']}":
                _set_node(db, r["rollout_id"], m["node_id"], t, error=f"waiting: {facts['why']}")
            continue
        journal = (jl(m["go_facts_json"], []) or []) + [{"at": t, **{k: facts[k] for k in
                                                                       ("online", "in_window", "held", "pinned", "protected", "seat")}}]
        _set_node(db, r["rollout_id"], m["node_id"], t, go=1, go_at=t, go_facts_json=json.dumps(journal[-20:]),
                  attempts=(m["attempts"] or 0) + 1, error=None)
        db.event("rollout_go", node_id=m["node_id"], reason=f"{r['rollout_id']}: {r['version']} (ring {ring})")
        busy += 1


def _budget(db: DB, r: dict, ring: str, t: float) -> bool:
    """D59 rule 5: failures above the ring's budget halt the rollout; with auto_rollback the nodes it moved go back."""
    if r["state"] != "running":
        return False
    ms = members(db, r["rollout_id"], ring)
    _, budget = _cap(r, ring, ms)
    fails = sum(m["failures"] or 0 for m in ms)
    if fails <= budget:
        return False
    halt(db, r, f"{fails} install failure(s) in ring {ring} (budget {budget})", "system")
    if r["policy"].get("auto_rollback", True):
        rollback(db, row(db, r["rollout_id"]), "system", "automatic: the failure budget was exceeded")
    return True


def _advance(db: DB, r: dict, t: float):
    """Start the next ring (an empty one is skipped), gated on fleet health; past the last one the rollout is done."""
    from . import core, fleetupdates as F
    rid = r["rollout_id"]
    cur = r["ring"]
    nxt = ORDER[ORDER.index(cur) + 1:] if cur else ORDER
    for ring in nxt:
        if ring not in r["policy"]["selected"]:
            continue
        if ring == "coordinator":
            if not F.newer(r["version"], F.coordinator_version()):
                r["rings"]["coordinator"] = {"skipped": "the coordinator runs it already"}
                continue
        else:
            ms = members(db, rid, ring)
            if not any(m["state"] not in ("skipped", "done") or (m["state"] == "done" and m["from_version"] != r["version"])
                       for m in ms):
                r["rings"][ring] = {"skipped": "empty"}
                continue
        bad, who = fleet_unhealthy(db, t)
        if bad:
            _save_rings(db, r)
            halt(db, r, f"fleet unhealthy at the start of ring {ring}: {', '.join(who[:8])}", "system")
            return
        r["rings"][ring] = {"started_at": t}
        db.x("UPDATE rollouts SET ring=?, ring_started_at=?, ring_finished_at=NULL, rings_json=?, updated_at=? WHERE rollout_id=?",
             (ring, t, json.dumps(r["rings"]), t, rid))
        db.event("rollout_ring_started", reason=f"{rid}: {r['version']} ring {ring}")
        return
    db.x("UPDATE rollouts SET state='done', rings_json=?, updated_at=? WHERE rollout_id=?", (json.dumps(r["rings"]), t, rid))
    db.event("rollout_done", reason=f"{rid}: {r['version']}")
    core._resolve_alert(db, "rollout_halted", rid)


def _tick_rollback(db: DB, r: dict, t: float, snap):
    """A rollback rollout: every node it lists goes back to the release it ran, every ring at once under its cap; it is
    done when each has (or is skipped), and its parent is then rolled_back."""
    from . import fleetupdates as F
    rid = r["rollout_id"]
    for m in members(db, rid):
        n = _node(db, m["node_id"])
        if m["state"] in SETTLED:
            continue
        if not n or n["lifecycle"] == "retired":
            _set_node(db, rid, m["node_id"], t, state="skipped", go=0, error="retired")
        elif n.get("agent_version") == m["target"]:
            _set_node(db, rid, m["node_id"], t, state="done", go=0, finished_at=t, error=None)
        elif not F.release(db, m["target"]):
            _set_node(db, rid, m["node_id"], t, state="skipped", go=0,
                      error=f"release {m['target']} is not imported here: reinstall it by hand or import it")
        elif not F.artifact_for(db, m["target"], n)[0]:
            _set_node(db, rid, m["node_id"], t, state="skipped", go=0, error=F.artifact_for(db, m["target"], n)[1])
        elif (n.get("last_heartbeat_at") or 0) < t - ONLINE_S and not m["go"] and m["state"] != "waiting":
            _set_node(db, rid, m["node_id"], t, state="waiting", error="offline")
        elif m["state"] == "waiting" and (n.get("last_heartbeat_at") or 0) >= t - ONLINE_S:
            _set_node(db, rid, m["node_id"], t, state="pending", error=None)
    if r["state"] == "running":
        for ring in RINGS:
            _grant(db, r, ring, t, snap)
    if all(m["state"] in SETTLED for m in members(db, rid)) and r["state"] == "running":
        db.x("UPDATE rollouts SET state='done', updated_at=? WHERE rollout_id=?", (t, rid))
        if r["parent"]:
            db.x("UPDATE rollouts SET state='rolled_back', updated_at=? WHERE rollout_id=? AND state='rolling_back'", (t, r["parent"]))
        db.event("rollout_rolled_back", reason=f"{r['parent']}: back to {r['version']} ({rid})")


def _stuck(db: DB, t: float):
    from . import core
    stuck = set()
    for m in db.q("SELECT rn.*, n.hostname FROM rollout_nodes rn JOIN rollouts r ON r.rollout_id=rn.rollout_id "
                  "LEFT JOIN nodes n ON n.node_id=rn.node_id WHERE r.state IN ('running','paused','halted','rolling_back','done') "
                  "AND rn.state IN ('draining','installing','confirming') AND rn.state_at<?", (t - STUCK_S,)):
        stuck.add(m["node_id"])
        core._alert(db, "update_node_stuck", m["node_id"],
                    f"{m['hostname'] or m['node_id']} has been {m['state']} {m['target']} for {int((t - m['state_at']) // 60)} min "
                    f"(rollout {m['rollout_id']}); it still counts against max_unavailable")
    for a in db.q("SELECT subject FROM alerts WHERE rule='update_node_stuck' AND state IN ('open','pending')"):
        if a["subject"] not in stuck:
            core._resolve_alert(db, "update_node_stuck", a["subject"])


def _expired(db: DB, t: float):
    """An expired hold or pin is flagged once (an event; the Updates page shows it) and the node rejoins."""
    seen = set(map(tuple, db.get_state("update_expired_flagged") or []))
    fresh = set()
    for x in db.q("SELECT scope, scope_id, key, value_json FROM setting_values WHERE key IN ('update_hold','update_pin')"):
        v = jl(x["value_json"])
        if isinstance(v, dict) and v.get("until") and v["until"] <= t:
            k = (x["scope"], x["scope_id"], x["key"], v["until"])
            fresh.add(k)
            if k not in seen:
                db.event(f"{x['key']}_expired", node_id=x["scope_id"] if x["scope"] == "node" else None,
                         reason=f"{x['scope']} {x['scope_id']}: {v.get('reason') or ''}"[:300])
    if fresh != seen:
        db.set_state("update_expired_flagged", sorted(list(k) for k in fresh))


# ------------------------------------------------------------------ operator actions

def active(db: DB) -> dict | None:
    """The rollout an operator acts on: the newest that is running, paused, halted or rolling back."""
    r = db.one("SELECT rollout_id FROM rollouts WHERE kind='update' AND state IN ('running','paused','halted','rolling_back') "
               "ORDER BY created_at DESC, rowid DESC LIMIT 1")
    return row(db, r["rollout_id"]) if r else None


def resolve_target(db: DB, ref: str | None) -> dict:
    r = row(db, ref) if ref else active(db)
    if not r:
        raise RolloutError(f"no rollout {ref}" if ref else "no rollout is running, paused, halted or rolling back")
    return r


def pause(db: DB, r: dict, actor: str) -> dict:
    if r["state"] != "running":
        raise RolloutError(f"rollout {r['rollout_id']} is {r['state']}, not running")
    db.x("UPDATE rollouts SET state='paused', updated_at=? WHERE rollout_id=?", (clock.now(), r["rollout_id"]))
    db.event("rollout_paused", actor=actor, reason=r["rollout_id"])
    return view_rollout(db, r["rollout_id"])


def resume(db: DB, r: dict, actor: str) -> dict:
    from . import core
    if r["state"] not in ("paused", "halted"):
        raise RolloutError(f"rollout {r['rollout_id']} is {r['state']}: only a paused or halted rollout resumes")
    db.x("UPDATE rollouts SET state='running', halted_reason=NULL, updated_at=? WHERE rollout_id=?", (clock.now(), r["rollout_id"]))
    core._resolve_alert(db, "rollout_halted", r["rollout_id"])
    db.event("rollout_resumed", actor=actor, reason=r["rollout_id"])
    return view_rollout(db, r["rollout_id"])


def halt(db: DB, r: dict, reason: str, actor: str) -> dict:
    """No new `go` after a halt (nodes already told keep going; the runner owns an install)."""
    from . import core
    if r["state"] not in ("running", "paused"):
        raise RolloutError(f"rollout {r['rollout_id']} is {r['state']}: only a running or paused rollout halts")
    db.x("UPDATE rollouts SET state='halted', halted_reason=?, updated_at=? WHERE rollout_id=?",
         (reason[:500], clock.now(), r["rollout_id"]))
    db.event("rollout_halted", actor=actor, reason=f"{r['rollout_id']}: {reason}"[:500])
    core._alert(db, "rollout_halted", r["rollout_id"], f"rollout {r['rollout_id']} to {r['version']} halted: {reason}"[:500])
    return view_rollout(db, r["rollout_id"])


def rollback_plan(db: DB, r: dict) -> list[dict]:
    """The nodes a rollback moves: every node this rollout updated or is updating, back to the release it ran."""
    return [m for m in members(db, r["rollout_id"]) if m["from_version"] and m["from_version"] != r["version"]
            and (m["state"] in ("done", *BUSY) or (m["state"] == "staged" and m["go"]))]


def rollback(db: DB, r: dict, actor: str, reason: str) -> dict:
    """Send the nodes this rollout moved back (a `rollback` rollout through the same machinery); the rollout is
    rolling_back until they are, then rolled_back."""
    from . import core
    if r["kind"] != "update" or r["state"] not in ("running", "paused", "halted", "done"):
        raise RolloutError(f"rollout {r['rollout_id']} is {r['kind']} {r['state']}: nothing to roll back")
    t = clock.now()
    moved = rollback_plan(db, r)
    db.x("UPDATE rollouts SET state=?, halted_reason=COALESCE(halted_reason, ?), updated_at=? WHERE rollout_id=?",
         ("rolling_back" if moved else "rolled_back", reason[:500], t, r["rollout_id"]))
    core._alert(db, "rollout_rolled_back", r["rollout_id"],
                f"rollout {r['rollout_id']} to {r['version']} is rolled back ({reason}): {len(moved)} node(s) go back")
    if not moved:
        db.event("rollout_rolled_back", actor=actor, reason=f"{r['rollout_id']}: no node had moved")
        return view_rollout(db, r["rollout_id"])
    back = max({m["from_version"] for m in moved}, key=lambda v: sum(1 for m in moved if m["from_version"] == v))
    cid = "ro_" + secrets.token_hex(6)
    pol = {**r["policy"], "rings": {**r["policy"]["rings"]}, "auto_rollback": False}
    for ring in RINGS:
        pol["rings"][ring] = {**pol["rings"][ring], "budget": 10 ** 6, "bake_s": 0, "canary_like": False}
    db.x("INSERT INTO rollouts(rollout_id, version, from_versions_json, state, ring, policy_json, created_by, created_at, "
         "updated_at, kind, rings_json, parent) VALUES(?,?,?, 'running', 'broad', ?,?,?,?, 'rollback', '{}', ?)",
         (cid, back, json.dumps([r["version"]]), json.dumps(pol), actor, t, t, r["rollout_id"]))
    for m in moved:
        db.x("INSERT INTO rollout_nodes(rollout_id, node_id, ring, state, from_version, target, state_at) VALUES(?,?,?,?,?,?,?)",
             (cid, m["node_id"], m["ring"], "pending", r["version"], m["from_version"], t))
    db.event("rollout_rolling_back", actor=actor, reason=f"{r['rollout_id']}: {len(moved)} node(s) back ({cid}): {reason}"[:500])
    return view_rollout(db, r["rollout_id"])


def skip(db: DB, nid: str, actor: str) -> dict:
    r, rn = governing(db, nid)
    if not r or not rn or r["state"] not in ACTIVE + ("done",):
        raise RolloutError("the node is in no live rollout")
    if rn["state"] in ("done", "skipped") or rn["state"] in BUSY:
        raise RolloutError(f"the node is {rn['state']} in rollout {r['rollout_id']}: nothing to skip")
    _set_node(db, r["rollout_id"], nid, clock.now(), state="skipped", go=0, error=f"skipped by {actor}")
    db.event("rollout_node_skipped", actor=actor, node_id=nid, reason=r["rollout_id"])
    return {"rollout_id": r["rollout_id"], "node_id": nid, "state": "skipped"}


# ------------------------------------------------------------------ policy: auto start, the notice, the periodic check

def auto(db: DB, t: float):
    """D60: a ready release newer than what the fleet runs starts a rollout by itself where `update_auto` is on (no
    other rollout halted or rolling back), raises the P4 update_available notice where it is notify; every
    update_check_h hours the release source is asked for a newer release, which is fetched."""
    from . import core, fleetupdates as F
    from .settings import resolve
    rels = [r for r in F.releases(db) if r["state"] == "ready"]
    with db.tx():
        for a in db.q("SELECT subject FROM alerts WHERE rule='update_available' AND state IN ('open','pending')"):
            v = a["subject"].removeprefix("release:")
            if db.one("SELECT 1 FROM rollouts WHERE version=? AND kind='update'", (v,)) or not rels or rels[0]["version"] != v:
                core._resolve_alert(db, "update_available", a["subject"])
    if rels:
        v = rels[0]["version"]
        cv = F.coordinator_version()
        behind = F.newer(v, cv) or any(F.newer(v, n.get("agent_version")) for n in F.nodes(db) if n["install"].get("updater"))
        done_before = any(not F.newer(v, x["version"]) for x in db.q("SELECT version FROM rollouts WHERE kind='update'"))
        if behind and not done_before:
            snap = resolve.snapshot(db)
            fleet = resolve.resolve(snap, None, "update_auto")["value"]
            per_node = [resolve.resolve(snap, n, "update_auto")["value"] for n in F.nodes(db)]
            stuck = db.one("SELECT 1 FROM rollouts WHERE state IN ('halted','rolling_back')")
            with db.tx():
                if (fleet == "on" or ("on" in per_node and not F.newer(v, cv))) and not stuck:
                    try:
                        start(db, v, "system", {}, auto=True)
                    except RolloutError as e:
                        if db.get_state("update_auto_refused") != [v, str(e)]:
                            db.set_state("update_auto_refused", [v, str(e)])
                            db.event("rollout_auto_refused", reason=f"{v}: {e}"[:500])
                elif fleet != "off" or "notify" in per_node or "on" in per_node:
                    core._alert(db, "update_available", f"release:{v}",
                                f"Oarbank {v} is ready to install (this coordinator runs {cv}): start it on the Updates page "
                                f"or `oarbank update start {v}`")
    _periodic_check(db, t)


def _periodic_check(db: DB, t: float):
    from . import fleetupdates as F
    from .settings import store
    try:
        h = float(store.fleet_value(db, "update_check_h") or 0)
    except (TypeError, ValueError):
        h = 0
    if h <= 0:
        return
    last = db.get_state("update_checked_at")
    if last is None or t < float(last):
        db.set_state("update_checked_at", t)           # the first check comes one period after the start
        return
    if t - float(last) < h * 3600 or _check_lock.locked():
        return
    db.set_state("update_checked_at", t)

    def run():
        if not _check_lock.acquire(blocking=False):
            return                                     # a check is already running
        try:
            v = F.latest(db)
            have = [r["version"] for r in db.q("SELECT version FROM fleet_releases")]
            if v and v not in have and all(F.newer(v, x) for x in have + [F.coordinator_version()]):
                F.fetch(db, v, "system")
        except Exception as e:
            db.event("update_check_failed", reason=repr(e)[:300])
        finally:
            _check_lock.release()
    _spawn(run)


def _spawn(fn):
    """The periodic check downloads off the background loop's thread (tests run it inline)."""
    threading.Thread(target=fn, daemon=True, name="oarbankd-update-check").start()


# ------------------------------------------------------------------ views

def view_rollout(db: DB, rid: str) -> dict:
    """A rollout with its nodes and, per ring, its gates: progress, bake time left, heartbeats, failures and budget."""
    r = row(db, rid)
    if not r:
        return {}
    t = clock.now()
    ms = members(db, rid)
    rings = []
    for ring in ORDER:
        info = dict(r["rings"].get(ring) or {})
        cfg = (r["policy"].get("rings") or {}).get(ring) or {}
        rm = [m for m in ms if m["ring"] == ring]
        cap, budget = _cap(r, ring, rm) if ring != "coordinator" and cfg else (None, cfg.get("budget"))
        moved = [m for m in rm if m["state"] == "done" and m["from_version"] != r["version"]]
        left = None
        if info.get("finished_at") and not info.get("baked_at"):
            left = max(0.0, (info["finished_at"] + (cfg.get("bake_s") or 0)) - t)
        rings.append({"ring": ring, **info, "current": r["ring"] == ring, "policy": cfg, "max_unavailable": cap,
                      "budget": budget, "failures": sum(m["failures"] or 0 for m in rm), "bake_left_s": left,
                      "nodes": len(rm), "done": sum(1 for m in rm if m["state"] == "done"),
                      "busy": sum(1 for m in rm if m["state"] in BUSY or (m["state"] == "staged" and m["go"])),
                      "heartbeats_min": min((m["heartbeats"] or 0 for m in moved), default=None)})
    return {**{k: r[k] for k in ("rollout_id", "version", "state", "ring", "kind", "created_by", "created_at", "updated_at",
                                 "halted_reason", "parent", "auto")},
            "policy": r["policy"], "rings": rings,
            "nodes": [{k: m[k] for k in ("node_id", "hostname", "ring", "state", "from_version", "target", "attempts",
                                         "failures", "go", "go_at", "started_at", "finished_at", "error", "state_at",
                                         "heartbeats")} for m in ms]}


def view(db: DB) -> dict:
    a = active(db)
    child = db.one("SELECT rollout_id FROM rollouts WHERE parent=? ORDER BY created_at DESC LIMIT 1", (a["rollout_id"],)) if a else None
    hist = db.q("SELECT rollout_id, version, state, kind, created_by, created_at, updated_at, halted_reason, auto "
                "FROM rollouts ORDER BY created_at DESC, rowid DESC LIMIT 30")
    return {"active": view_rollout(db, a["rollout_id"]) if a else None,
            "rolling_back": view_rollout(db, child["rollout_id"]) if child else None, "history": hist}


# ------------------------------------------------------------------ invariants (coordinator/invariants.py)

def s29_violations(db: DB) -> list[str]:
    """S29: no ring of a live rollout has more nodes between draining and confirming, or staged with `go`, than its
    max_unavailable."""
    out = []
    for r in db.q("SELECT * FROM rollouts WHERE state IN ('running','paused','halted','rolling_back','done')"):
        pol = jl(r["policy_json"], {}) or {}
        for ring in RINGS:
            cap = ((pol.get("rings") or {}).get(ring) or {}).get("max_unavailable")
            if cap is None:
                continue
            n = db.one("SELECT COUNT(*) n FROM rollout_nodes WHERE rollout_id=? AND ring=? AND (state IN ('draining','installing',"
                       "'confirming') OR (state='staged' AND go=1))", (r["rollout_id"], ring))["n"]
            if n > cap:
                out.append(f"S29 rollout {r['rollout_id']} ring {ring}: {n} nodes busy, max_unavailable {cap}")
    return out


def s30_violations(db: DB) -> list[str]:
    """S30: no node is assigned, or was moved by a rollout to, a release newer than this coordinator, and no node of a
    later ring was told `go` before every earlier ring of its rollout (the coordinator's included) finished and baked."""
    from . import fleetupdates as F
    out, cv = [], F.coordinator_version()
    if not db.one("SELECT 1 FROM fleet_releases LIMIT 1"):
        return out                                     # nothing to assign, nothing moved
    from .settings import resolve
    snap = resolve.snapshot(db)
    for n in F.nodes(db):
        a = F.assigned(db, n, snap=snap)
        if a and F.newer(a["version"], cv):
            out.append(f"S30 node {n['hostname']} is assigned {a['version']}, newer than the coordinator's {cv}")
    for m in db.q("SELECT rn.node_id, rn.target, n.hostname FROM rollout_nodes rn JOIN rollouts r ON r.rollout_id=rn.rollout_id "
                  "LEFT JOIN nodes n ON n.node_id=rn.node_id WHERE r.kind='update' AND rn.state='done' "
                  "AND rn.from_version IS NOT NULL AND rn.from_version!=rn.target"):
        if F.newer(m["target"], cv):
            out.append(f"S30 node {m['hostname'] or m['node_id']} runs {m['target']}, newer than the coordinator's {cv}")
    for r in db.q("SELECT * FROM rollouts WHERE kind='update'"):
        rings, pol = jl(r["rings_json"], {}) or {}, jl(r["policy_json"], {}) or {}
        sel = pol.get("selected") or list(ORDER)
        for m in db.q("SELECT node_id, ring, go_facts_json FROM rollout_nodes WHERE rollout_id=?", (r["rollout_id"],)):
            grants = jl(m["go_facts_json"], []) or []
            if not grants or m["ring"] not in ORDER:
                continue
            first = min(g["at"] for g in grants)
            for ring in ORDER[:ORDER.index(m["ring"])]:
                info = rings.get(ring) or {}
                if ring not in sel or info.get("skipped") or (ring == "coordinator" and not pol.get("coord_needed")):
                    continue
                if ring != "coordinator" and not db.one("SELECT 1 FROM rollout_nodes WHERE rollout_id=? AND ring=? AND "
                                                        "state!='skipped'", (r["rollout_id"], ring)):
                    continue
                if not info.get("baked_at") or info["baked_at"] > first:
                    out.append(f"S30 rollout {r['rollout_id']}: node {m['node_id']} of ring {m['ring']} told go at {first:.0f} "
                               f"before ring {ring} finished and baked")
                    break
    return out


def s31_violations(db: DB) -> list[str]:
    """S31: every `go` was granted while the node was eligible (online, inside its window, not held, not pinned to
    another version), from the grants each rollout journals with the eligibility beside them."""
    out = []
    for m in db.q("SELECT rollout_id, node_id, go_facts_json FROM rollout_nodes WHERE go_facts_json IS NOT NULL "
                  "AND go_facts_json!='[]'"):
        for g in jl(m["go_facts_json"], []) or []:
            bad = [k for k, want in (("online", True), ("in_window", True), ("held", False), ("pinned", False)) if g.get(k) is not want]
            if bad:
                out.append(f"S31 rollout {m['rollout_id']}: node {m['node_id']} told go at {g.get('at')} while {', '.join(bad)} "
                           "said it was not eligible")
    return out
