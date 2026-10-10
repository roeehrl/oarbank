"""Operation execution (PLAN D14, D15, D21): the single path by which anything changes fleet state.

    POST /api/v1/ops/{op}   {"target": ..., "params": {...}, "reason": ..., "dry_run": bool,
                             "plan_id": ..., "confirm": ...}
    headers: If-Match (versioned resources), Idempotency-Key (creations)

`execute()` enforces the registry entry (oarbank.contracts.operations): role, reason
policy, preview-then-apply with plan ids for T2/T3 (409 with a fresh plan on drift), typed
confirmation at T3, If-Match (412 on mismatch, 428 when missing at T2+), idempotency keys (400 missing,
422 reused with another payload), and writes one audit row per request, accepted or refused, in the
same transaction as the mutation (atomic handlers) or right after it (handlers that call module code or
do long file work outside the lock).

The console and oarbank are both clients of this endpoint, so the GUI can do nothing the API cannot.
"""
import hashlib
import json
from pathlib import Path
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..common import canonical_json
from ..contracts import operations as registry
from . import audit, clock, core, effects, placement, protection, releases, settings
from .db import DB, jl

PLAN_TTL_S = 1800


@dataclass
class OpRequest:
    op: str
    actor: str
    source: str = "api"                     # gui | cli | api | system | scheduler
    target: str | None = None
    params: dict = field(default_factory=dict)
    reason: str | None = None
    dry_run: bool = False
    plan_id: str | None = None
    confirm: str | None = None
    if_match: int | None = None
    idempotency_key: str | None = None
    user_agent: str | None = None
    request_id: str = field(default_factory=audit.request_id)
    payload: str | None = None              # hash of (op, target, params) as received
    prepared: Any = None                    # Handler.prepare's result (computed outside the transaction)
    plan_impact: dict | None = None         # the reviewed plan's impact (T2/T3), for handlers that need it
    role: str | None = None                 # the caller's role (access.py); None: the coordinator itself
    scope: str | None = None                # a scoped token's scope ("module:<name>"), which limits the operations
    # secrets.set's value, beside params: never in the payload hash, a plan, an idempotency row, the audit or a repr
    secret: str | None = field(default=None, repr=False)

    def payload_hash(self) -> str:
        return hashlib.sha256(canonical_json({"op": self.op, "target": self.target, "params": self.params}).encode()).hexdigest()


@dataclass
class Handler:
    target_type: str
    apply: Callable[[DB, OpRequest], Any]
    snapshot: Callable[[DB, OpRequest], Any] = lambda db, r: None       # before/after state for the audit row
    impact: Callable[[DB, OpRequest], dict] = lambda db, r: {}         # preview: what would change
    versions: Callable[[DB, OpRequest], list[str]] = lambda db, r: []  # versioned resource keys read
    atomic: bool = True                     # False: runs outside the transaction (module IPC, long I/O)
    prepare: Callable[[DB, "OpRequest"], Any] | None = None   # outside the transaction (module IPC); result in req.prepared
    name: Callable[[DB, OpRequest], str] = lambda db, r: str(r.target)  # what a T3 confirmation must type
    target: Callable[[DB, OpRequest], None] | None = None   # checks the target's form (normalizing it) before anything reads it
    tier: Callable[[OpRequest], str] | None = None   # the request's own tier when it depends on what it changes (settings.apply)


def tier_of(req: OpRequest) -> str:
    """The friction tier of this request: the registry's, or the handler's own for an operation whose tier follows
    what it changes (settings.apply: each key's danger tier and scope)."""
    h = HANDLERS.get(req.op)
    return h.tier(req) if h is not None and h.tier is not None else registry.REGISTRY[req.op].tier


HANDLERS: dict[str, Handler] = {}


def handler(op_id: str, **kw):
    if op_id not in registry.REGISTRY:
        raise KeyError(f"no registry entry for {op_id}")

    def deco(fn):
        HANDLERS[op_id] = Handler(apply=fn, **kw)
        return fn
    return deco


# ------------------------------------------------------------------ versions and plans

def version(db: DB, key: str) -> int:
    r = db.one("SELECT version FROM resource_versions WHERE key=?", (key,))
    return r["version"] if r else 0


def bump(db: DB, key: str) -> int:
    v = version(db, key) + 1
    db.x("INSERT INTO resource_versions(key,version) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET version=excluded.version",
         (key, v))
    return v


def _make_plan(db: DB, req: OpRequest, h: Handler, impact: dict | None = None) -> dict:
    vers = {k: version(db, k) for k in h.versions(db, req)}
    impact = h.impact(db, req) if impact is None else impact
    pid = "pl_" + secrets.token_hex(8)
    now = time.time()
    db.x("INSERT INTO plans(plan_id,operation,request_json,versions_json,impact_json,actor,created_at,expires_at)"
         " VALUES(?,?,?,?,?,?,?,?)",
         (pid, req.op, json.dumps({"target": req.target, "params": req.params}), json.dumps(vers), json.dumps(impact, default=str),
          req.actor, now, now + PLAN_TTL_S))
    return {"plan_id": pid, "op": req.op, "target": req.target, "params": req.params, "impact": impact,
            "versions": vers, "expires_at": now + PLAN_TTL_S, "tier": tier_of(req),
            "confirm_required": tier_of(req) == "T3", "confirm_name": h.name(db, req)}


# ------------------------------------------------------------------ execution

class OpError(core.ApiError):
    def __init__(self, status, code, detail="", outcome=None, extra=None, headers=None):
        super().__init__(status, code, detail, headers=headers)
        self.outcome, self.extra = outcome, extra or {}


def identity_role(db) -> str:
    from . import identity
    return identity.role(db)


def execute(db: DB, req: OpRequest) -> dict:
    op = registry.REGISTRY.get(req.op)
    if op is None:
        raise OpError(404, "unknown_operation", req.op)
    h = HANDLERS[req.op]                      # every registered operation has one (tests/test_contracts.py)
    try:
        from . import coordmove
        if not coordmove.serving(db) and not req.op.startswith("coordinator."):
            raise core.ApiError(409, "coordinator_moving", f"this coordinator is {coordmove.phase(db)} "
                                f"({identity_role(db)}): only coordinator operations run now")
        return _execute(db, req, op, h)
    except core.ApiError as e:
        outcome = getattr(e, "outcome", None) or ("denied" if e.status == 403 else "conflict" if e.status in (409, 412)
                                                  else "error" if e.status >= 500 else "rejected")
        audit.append(db, actor=req.actor, source=req.source, operation=req.op, category=op.category,
                     target_type=h.target_type, target_id=str(req.target), outcome=outcome,
                     request_id=req.request_id, reason=req.reason, dry_run=req.dry_run, plan_id=req.plan_id,
                     idempotency_key=req.idempotency_key, user_agent=req.user_agent, error=f"{e.code}: {e.detail}"[:500])
        raise


ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


def _execute(db: DB, req: OpRequest, op: registry.Operation, h: Handler) -> dict:
    tier = tier_of(req)
    if req.role is not None and ROLE_RANK.get(req.role, -1) < ROLE_RANK[op.min_role]:
        raise OpError(403, "forbidden_role", f"{req.op} needs the {op.min_role} role; {req.actor} is {req.role}")
    if req.scope:
        mod = req.scope.split(":", 1)[1] if req.scope.startswith("module:") else ""
        if not mod or not req.op.startswith(f"mod.{mod.replace('-', '_')}."):
            raise OpError(403, "token_scope", f"this token may run only {req.scope}'s own operations, not {req.op}")
    if req.secret is not None and (req.op not in SECRET_OPS or req.dry_run or req.plan_id):
        raise OpError(400, "secret_not_accepted", f"only {' and '.join(SECRET_OPS)} take a secret value, and never as a "
                      "preview or a plan")
    req.payload = req.payload_hash()          # of the request as sent (handlers may fill in the target)
    # reason policy (from the request's tier: a settings change set may be T0 on a node and T2 for the fleet)
    reason_policy = op.reason if op.reason and tier == op.tier else registry.DEFAULT_REASON[tier]
    if reason_policy == "required" and not (req.reason and req.reason.strip()) and not req.dry_run:
        raise OpError(400, "reason_required", f"{req.op} ({tier}) needs a reason")
    # idempotency for creations
    ikey = None
    if op.idempotency == "key":
        if not req.idempotency_key and not req.dry_run:
            raise OpError(400, "idempotency_key_required", f"{req.op} creates something: send an Idempotency-Key")
        if req.idempotency_key:
            ikey = f"op:{req.op}:{req.idempotency_key}"
            prev = db.one("SELECT response_json FROM idempotency WHERE key=?", (ikey,))
            if prev:
                stored = json.loads(prev["response_json"])
                if stored.get("_payload") != req.payload:
                    raise OpError(422, "idempotency_key_reused", "the key was used for a different request")
                return {**stored["response"], "replayed": True}
    if h.target is not None and not req.plan_id:
        h.target(db, req)                     # a plan's target was checked when it was previewed
    # preview
    if req.dry_run:
        impact = h.impact(db, req)                    # outside the lock: may ask the module (op.plan)
        with db.tx():
            plan = _make_plan(db, req, h, impact)
            audit.append(db, actor=req.actor, source=req.source, operation=req.op, category="access",
                         target_type=h.target_type, target_id=str(req.target), outcome="ok", request_id=req.request_id,
                         reason=req.reason, dry_run=True, plan_id=plan["plan_id"], user_agent=req.user_agent)
        return {"ok": True, "plan": plan}
    # T2/T3: apply only a reviewed plan; any tier applies the plan it names exactly as previewed
    plan_row = None
    if tier in ("T2", "T3") and not req.plan_id:
        raise OpError(428, "plan_required", f"{req.op} is {tier}: preview with dry_run and apply the plan_id")
    if req.plan_id:
        plan_row = db.one("SELECT * FROM plans WHERE plan_id=?", (req.plan_id,))
        if not plan_row or plan_row["operation"] != req.op:
            raise OpError(404, "unknown_plan", req.plan_id)
        if plan_row["applied_at"]:
            raise OpError(409, "plan_used", req.plan_id)
        if plan_row["expires_at"] < time.time():
            raise OpError(409, "plan_expired", req.plan_id)
        planned = json.loads(plan_row["request_json"])
        req.target, req.params = planned["target"], planned["params"]
        req.plan_impact = json.loads(plan_row["impact_json"] or "{}")
        if h.tier is not None:                # the planned change decides the tier, and so the reason and confirmation
            tier = tier_of(req)
            if registry.DEFAULT_REASON[tier] == "required" and not (req.reason and req.reason.strip()):
                raise OpError(400, "reason_required", f"{req.op} ({tier}) needs a reason")
        if tier == "T3" and (req.confirm or "") != h.name(db, req):
            raise OpError(400, "confirmation_required", f"type the name {h.name(db, req)!r} to confirm")
    try:
        if h.prepare is not None:
            req.prepared = h.prepare(db, req)         # module IPC happens here, never under the lock
        if not h.atomic:
            return _apply_non_atomic(db, req, op, h, plan_row, ikey)
        return _apply_atomic(db, req, op, h, plan_row, ikey)
    except OpError as e:
        if e.code == "plan_drift":            # after the rollback: hand back a fresh plan to review
            fresh_req = OpRequest(**{**req.__dict__, "dry_run": True, "plan_id": None})
            impact = h.impact(db, fresh_req)
            with db.tx():
                e.extra["plan"] = _make_plan(db, fresh_req, h, impact)
        raise


def _apply_atomic(db, req, op, h, plan_row, ikey):
    with db.tx():
        _check_versions(db, req, op, h, plan_row)
        before = h.snapshot(db, req)
        result = h.apply(db, req)
        after = h.snapshot(db, req)
        new_versions = {k: bump(db, k) for k in h.versions(db, req)} if op.versioned else {}
        if plan_row:
            db.x("UPDATE plans SET applied_at=? WHERE plan_id=?", (time.time(), plan_row["plan_id"]))
        rec = audit.append(db, actor=req.actor, source=req.source, operation=req.op, category=op.category,
                           target_type=h.target_type, target_id=str(req.target), outcome="ok", request_id=req.request_id,
                           reason=req.reason, before=before, after=after, plan_id=req.plan_id,
                           idempotency_key=req.idempotency_key, user_agent=req.user_agent)
        resp = {"ok": True, "op": req.op, "target": req.target, "result": result, "versions": new_versions,
                "audit_event_id": rec.event_id, "request_id": req.request_id}
        if ikey:
            db.x("INSERT INTO idempotency(key,response_json,at) VALUES(?,?,?)",
                 (ikey, json.dumps({"_payload": req.payload, "response": resp}, default=str), time.time()))
    return resp


def _check_versions(db, req, op, h, plan_row):
    keys = h.versions(db, req)
    if not keys:
        return
    if plan_row:
        planned = json.loads(plan_row["versions_json"])
        drift = {k: (planned.get(k), version(db, k)) for k in keys if planned.get(k) != version(db, k)}
        if drift:
            raise OpError(409, "plan_drift", f"changed since the preview: {sorted(drift)}", outcome="conflict")
        return
    if req.if_match is None:
        if op.versioned and op.tier in ("T2", "T3"):
            raise OpError(428, "precondition_required", "send If-Match with the resource version")
        return
    cur = version(db, keys[0])
    if req.if_match != cur:
        raise OpError(412, "version_mismatch", f"{keys[0]} is at version {cur}, not {req.if_match}", outcome="conflict")


def _apply_non_atomic(db, req, op, h, plan_row, ikey):
    before = h.snapshot(db, req)
    if plan_row:
        with db.tx():
            _check_versions(db, req, op, h, plan_row)
            db.x("UPDATE plans SET applied_at=? WHERE plan_id=?", (time.time(), plan_row["plan_id"]))
    result = h.apply(db, req)                       # outside the lock: may call module code or take minutes
    after = h.snapshot(db, req)
    with db.tx():
        rec = audit.append(db, actor=req.actor, source=req.source, operation=req.op, category=op.category,
                           target_type=h.target_type, target_id=str(req.target), outcome="ok", request_id=req.request_id,
                           reason=req.reason, before=before, after=after, plan_id=req.plan_id,
                           idempotency_key=req.idempotency_key, user_agent=req.user_agent)
        resp = {"ok": True, "op": req.op, "target": req.target, "result": result, "audit_event_id": rec.event_id,
                "request_id": req.request_id}
        if ikey:
            db.x("INSERT OR REPLACE INTO idempotency(key,response_json,at) VALUES(?,?,?)",
                 (ikey, json.dumps({"_payload": req.payload, "response": resp}, default=str), time.time()))
    return resp


# ------------------------------------------------------------------ helpers for handlers

def _node(db, nid):
    n = db.one("SELECT * FROM nodes WHERE node_id=? OR hostname=?", (nid, nid))
    if not n:
        raise core.ApiError(404, "not_found", f"node {nid}")
    return n


def _node_snap(db, req):
    return db.one("SELECT node_id, hostname, lifecycle, desired_state, settings_rev, quarantine_reason, want_doctor "
                  "FROM nodes WHERE node_id=? OR hostname=?", (req.target, req.target))


def _nid(db, req):
    return _node(db, req.target)["node_id"]


def _live_on(db, nid):
    return db.one("SELECT COUNT(*) n FROM attempts WHERE node_id=? AND state='live'", (nid,))["n"]


def _job_snap(db, req):
    return db.one("SELECT job_id, state, priority, generation, exec_failures FROM jobs WHERE job_id=?", (req.target,))


def _campaign_snap(db, req):
    return db.one("SELECT campaign_id, module, name, state, weight, priority FROM campaigns WHERE campaign_id=?", (req.target,))


def _setting_snap(key):
    return lambda db, req: {key: db.get_state(key)}


# ------------------------------------------------------------------ fleet

def _fleet_snap(db, req):
    return {"fleet_state": db.get_state("fleet_state", "active")}


def _set_fleet(state):
    def apply(db, req):
        db.set_state("fleet_state", state)
        n = 0
        if state == "halted":
            for a in db.q("SELECT attempt_id, node_id FROM attempts WHERE state='live'"):
                core._end_attempt(db, a["attempt_id"], "released", "fleet_halt", count_failure=False)
                core._push(db, a["node_id"], "revoke", a["attempt_id"])
                n += 1
        db.event("fleet_state", actor=req.actor, reason=f"{state}: {req.reason or ''}".strip())
        return {"fleet_state": state, "attempts_released": n}
    return apply


for _op, _st in (("fleet.pause", "paused"), ("fleet.halt", "halted"), ("fleet.resume", "active")):
    HANDLERS[_op] = Handler(target_type="fleet", apply=_set_fleet(_st), snapshot=_fleet_snap,
                            impact=lambda db, r: {"live_attempts": db.one("SELECT COUNT(*) n FROM attempts WHERE state='live'")["n"],
                                                  "pending_jobs": db.one("SELECT COUNT(*) n FROM jobs WHERE state='pending'")["n"]})


# ------------------------------------------------------------------ nodes

@handler("nodes.admit", target_type="enrollment",
         snapshot=lambda db, r: db.one("SELECT enrollment_id, status, hostname FROM enrollments WHERE enrollment_id=?", (r.target,)),
         impact=lambda db, r: {"enrollment": db.one("SELECT enrollment_id, hostname, peer_ip, status FROM enrollments "
                                                    "WHERE enrollment_id=?", (r.target,))})
def _admit(db, req):
    return core.approve_enrollment(db, req.target, req.actor)


@handler("nodes.reject_enrollment", target_type="enrollment",
         snapshot=lambda db, r: db.one("SELECT enrollment_id, status FROM enrollments WHERE enrollment_id=?", (r.target,)))
def _reject(db, req):
    return core.reject_enrollment(db, req.target, req.actor)


def _state_handler(desired):
    def apply(db, req):
        core.set_node_state(db, _nid(db, req), desired, req.actor)
        return {"desired_state": desired}
    return apply


for _op, _st in (("nodes.pause", "paused"), ("nodes.resume", "active"), ("nodes.drain", "draining")):
    HANDLERS[_op] = Handler(target_type="node", apply=_state_handler(_st), snapshot=_node_snap,
                            impact=lambda db, r: {"live_attempts": _live_on(db, _nid(db, r))})


@handler("nodes.quarantine", target_type="node", snapshot=_node_snap,
         impact=lambda db, r: {"live_attempts_revoked": _live_on(db, _nid(db, r))})
def _quarantine(db, req):
    core.quarantine(db, _nid(db, req), req.reason or "manual", req.actor)
    return {"lifecycle": "quarantined"}


@handler("nodes.clear_quarantine", target_type="node", snapshot=_node_snap)
def _clear(db, req):
    core.clear_quarantine(db, _nid(db, req), req.actor)
    return {"lifecycle": "enrolled"}


@handler("nodes.run_doctor", target_type="node", snapshot=_node_snap)
def _doctor(db, req):
    nid = _nid(db, req)
    db.x("UPDATE nodes SET want_doctor=1 WHERE node_id=?", (nid,))
    db.event("doctor_requested", actor=req.actor, node_id=nid)
    return {"want_doctor": True}


@handler("nodes.recertify", target_type="node", snapshot=_node_snap)
def _recertify(db, req):
    core.recertify(db, _nid(db, req), req.actor)
    return {"recertify": True}


def _pinned_open(db, nid) -> list[int]:
    return [r["job_id"] for r in db.q("SELECT job_id FROM jobs WHERE target_node=? AND state IN ('pending','leased')", (nid,))]


@handler("nodes.retire", target_type="node", snapshot=_node_snap, name=lambda db, r: _node(db, r.target)["hostname"],
         impact=lambda db, r: {"live_attempts": _live_on(db, _nid(db, r)), "pinned_jobs_cancelled": len(_pinned_open(db, _nid(db, r)))})
def _retire(db, req):
    nid = _nid(db, req)
    db.x("UPDATE nodes SET lifecycle='retired', client_cert_fp=NULL, client_cert_prev_fp=NULL WHERE node_id=?", (nid,))
    # work pinned to this node (a run_all job, its golden jobs) can never run anywhere else: settle it, or its campaign
    # stays running for ever
    pinned = _pinned_open(db, nid)
    for jid in pinned:
        core.cancel_job(db, jid, req.actor)
    from . import modsecrets
    modsecrets.drop_node(db, nid)                    # the node's own secret values go with it
    db.event("node_retired", actor=req.actor, node_id=nid, reason=f"{len(pinned)} pinned jobs cancelled" if pinned else None)
    return {"lifecycle": "retired", "pinned_jobs_cancelled": len(pinned)}


# ------------------------------------------------------------------ protection

def _prot_keys(db, r):
    nid = _nid(db, r)
    return [protection.resource_key(nid), f"node:{nid}:policy"]


def _prot_config(db, req) -> dict:
    cfg = req.params.get("config")
    if cfg is None:
        raise core.ApiError(400, "missing_config", "params.config: the full protection section")
    try:
        return protection.validate(cfg, protection.node_os(db, _nid(db, req)))
    except protection.ProtectionError as e:
        raise core.ApiError(422, "bad_protection", str(e))


def _prot_version(db, req) -> dict:
    nid = _nid(db, req)
    try:
        v = int(req.params.get("version"))
    except (TypeError, ValueError):
        raise core.ApiError(400, "missing_version", "params.version")
    r = db.one("SELECT config_json FROM protection_versions WHERE node_id=? AND version=?", (nid, v))
    if not r:
        raise core.ApiError(404, "not_found", f"protection version {v} of {nid}")
    return json.loads(r["config_json"])


@handler("protection.rules.update", target_type="node", snapshot=_node_snap, versions=_prot_keys,
         impact=lambda db, r: protection.preview(db, _nid(db, r), _prot_config(db, r)))
def _prot_update(db, req):
    v = protection.write_version(db, _nid(db, req), _prot_config(db, req), req.actor, req.reason)
    return {"version": v}


@handler("protection.rules.restore", target_type="node", snapshot=_node_snap, versions=_prot_keys,
         impact=lambda db, r: {**protection.preview(db, _nid(db, r), _prot_version(db, r)), "restores": r.params.get("version")})
def _prot_restore(db, req):
    v = protection.write_version(db, _nid(db, req), _prot_version(db, req), req.actor, req.reason,
                                 source=f"rules.restore:{req.params.get('version')}")
    return {"version": v, "restored": int(req.params["version"])}


def _canary_impact(db, r):
    if r.params.get("promote"):
        h = protection.canary_health(db)
        c = db.get_state(protection.CANARY_KEY)
        targets, skipped = protection.promote_targets(db, c) if c else ([], {})
        return {**h, "targets": targets, "skipped": skipped}
    return {**protection.preview(db, _nid(db, r), _prot_config(db, r)), "canary": True,
            "then": "promote after a clean soak of %d s" % protection.CANARY_MIN_SOAK_S}


def _canary_target(db, req):
    """Promoting names no node: the running canary's node is the target."""
    if req.params.get("promote"):
        c = db.get_state(protection.CANARY_KEY)
        if not c:
            raise OpError(409, "no_canary", "no protection canary is running: oarbank protection canary <node> <file>")
        req.target = c["node_id"]


@handler("protection.rules.canary", target_type="node", impact=_canary_impact, target=_canary_target,
         snapshot=lambda db, r: {"canary": db.get_state(protection.CANARY_KEY)})
def _prot_canary(db, req):
    try:
        if req.params.get("promote"):
            return protection.promote(db, req.actor, req.reason, force=bool(req.params.get("force")))
        c = protection.start_canary(db, _nid(db, req), _prot_config(db, req), req.actor, req.reason)
        return {k: v for k, v in c.items() if k != "config"}
    except protection.ProtectionError as e:
        raise core.ApiError(409, "canary_not_promotable", str(e))


@handler("nodes.set_mode", target_type="node", snapshot=_node_snap, versions=_prot_keys,
         impact=lambda db, r: {"mode": {"from": ((protection.current(db, _nid(db, r))[1].get("node") or {}).get("mode")),
                                        "to": r.params.get("mode")}, "live_attempts": _live_on(db, _nid(db, r))})
def _set_mode(db, req):
    mode = req.params.get("mode")
    if mode not in ("fleet_first", "moderate", "strict_yield"):
        raise core.ApiError(400, "bad_mode", f"{mode!r}: fleet_first | moderate | strict_yield")
    try:
        return {"version": protection.set_mode(db, _nid(db, req), mode, req.actor, req.reason)}
    except protection.ProtectionError as e:
        raise core.ApiError(422, "bad_protection", str(e))


@handler("protection.probe_now", target_type="node", snapshot=_node_snap)
def _probe_now(db, req):
    protection.request_probe(db, _nid(db, req), req.actor)
    return {"run_probe": True}


# ------------------------------------------------------------------ alerts

def _alert_row(db, req):
    try:
        a = db.one("SELECT * FROM alerts WHERE alert_id=?", (int(req.target),))
    except (TypeError, ValueError):
        a = None
    if not a:
        raise core.ApiError(404, "not_found", f"alert {req.target}")
    return a


def _verdict(req):
    u = req.params.get("useful")
    return None if u is None else int(bool(u) if not isinstance(u, str) else u.lower() in ("1", "true", "yes", "useful"))


@handler("alerts.ack", target_type="alert", snapshot=lambda db, r: _alert_row(db, r))
def _ack(db, req):
    a = _alert_row(db, req)
    db.x("UPDATE alerts SET acked_by=?, acked_at=?, useful=COALESCE(?, useful) WHERE alert_id=?",
         (req.actor, clock.now(), _verdict(req), a["alert_id"]))
    db.event("alert_acked", actor=req.actor, reason=a["rule"])
    return {"acked": a["alert_id"]}


@handler("alerts.snooze", target_type="alert", snapshot=lambda db, r: _alert_row(db, r))
def _snooze(db, req):
    a = _alert_row(db, req)
    until = req.params.get("until") or (clock.now() + 60 * float(req.params.get("minutes") or 60))
    db.x("UPDATE alerts SET snoozed_until=?, acked_by=COALESCE(acked_by, ?) WHERE alert_id=?", (float(until), req.actor, a["alert_id"]))
    db.event("alert_snoozed", actor=req.actor, reason=a["rule"])
    return {"snoozed_until": float(until)}


@handler("alerts.resolve", target_type="alert", snapshot=lambda db, r: _alert_row(db, r))
def _aresolve(db, req):
    a = _alert_row(db, req)
    if a["rule"].startswith(("invariant:", "audit_chain_broken")) and not (req.reason or "").strip():
        raise core.ApiError(400, "reason_required", "a latched safety alert is resolved with a note (what was found)")
    db.x("UPDATE alerts SET state='resolved', resolved_at=?, resolved_how='manual', note=?, useful=COALESCE(?, useful), "
         "acked_by=COALESCE(acked_by, ?) WHERE alert_id=? AND state IN ('open','pending')",
         (clock.now(), req.reason, _verdict(req), req.actor, a["alert_id"]))
    db.event("alert_resolved", actor=req.actor, reason=a["rule"], detail=req.reason)
    return {"resolved": a["alert_id"]}


# ------------------------------------------------------------------ jobs

@handler("jobs.retry", target_type="job", snapshot=_job_snap)
def _retry(db, req):
    core.retry_job(db, int(req.target), req.actor)
    return {"retried": int(req.target)}


@handler("jobs.cancel", target_type="job", snapshot=_job_snap,
         impact=lambda db, r: db.one("SELECT COUNT(*) live, COALESCE(SUM(cpu_s),0) cpu_s FROM attempts WHERE job_id=? "
                                     "AND state='live'", (r.target,)))
def _cancel(db, req):
    core.cancel_job(db, int(req.target), req.actor)
    return {"cancelled": int(req.target)}


@handler("jobs.set_priority", target_type="job", snapshot=_job_snap, versions=lambda db, r: [f"job:{r.target}:priority"])
def _priority(db, req):
    db.x("UPDATE jobs SET priority=? WHERE job_id=?", (int(req.params["priority"]), int(req.target)))
    db.event("job_priority", actor=req.actor, job_id=int(req.target), reason=str(req.params["priority"]))
    return {"priority": int(req.params["priority"])}


# ------------------------------------------------------------------ campaigns (D22: the core's only grouping of work)

def _campaign_for(db, req) -> dict:
    """The target campaign, when the operation applies in its state (registry.CAMPAIGN_OPS)."""
    c = db.one("SELECT * FROM campaigns WHERE campaign_id=?", (req.target,))
    if not c:
        raise core.ApiError(404, "not_found", f"campaign {req.target}")
    if not registry.campaign_op_applies(c["state"], req.op):
        raise core.ApiError(409, f"campaign_{c['state']}", f"campaign {req.target} is {c['state']}: {req.op} does not apply")
    return c


def _campaign_state(action):
    def apply(db, req):
        _campaign_for(db, req)
        core.set_campaign_state(db, req.target, action, req.actor)
        return {"action": action}
    return apply


def _campaign_name(db, r):
    return (_campaign_snap(db, r) or {}).get("name") or str(r.target)


for _op, _act in (("campaigns.pause", "pause"), ("campaigns.resume", "resume"), ("campaigns.cancel", "cancel")):
    HANDLERS[_op] = Handler(target_type="campaign", apply=_campaign_state(_act), snapshot=_campaign_snap, name=_campaign_name,
                            impact=lambda db, r: db.one("SELECT COALESCE(SUM(state='pending'),0) pending, COALESCE(SUM(state='leased'),0) "
                                                        "leased FROM jobs WHERE campaign_id=?", (r.target,)))


@handler("campaigns.retry_failed", target_type="campaign", snapshot=_campaign_snap)
def _retry_failed(db, req):
    _campaign_for(db, req)
    ids = [j["job_id"] for j in db.q("SELECT job_id FROM jobs WHERE campaign_id=? AND state IN ('failed','quarantined')", (req.target,))]
    for jid in ids:
        core.retry_job(db, jid, req.actor)
    if ids:
        core.reopen_campaigns(db)
    return {"retried": ids}


@handler("campaigns.set_weight", target_type="campaign", snapshot=_campaign_snap, versions=lambda db, r: [f"campaign:{r.target}:weight"])
def _weight(db, req):
    _campaign_for(db, req)
    w = float(req.params["weight"])
    if not 0 < w <= 1000:
        raise core.ApiError(400, "bad_weight", "0 < weight <= 1000")
    db.x("UPDATE campaigns SET weight=? WHERE campaign_id=?", (w, req.target))
    return {"weight": w}


@handler("campaigns.set_priority", target_type="campaign", snapshot=_campaign_snap,
         versions=lambda db, r: [f"campaign:{r.target}:priority"],
         impact=lambda db, r: db.one("SELECT COUNT(*) pending FROM jobs WHERE campaign_id=? AND state='pending'", (r.target,)))
def _campaign_priority(db, req):
    """Moves the campaign's open jobs by the difference, so relative priorities inside it are kept."""
    c = _campaign_for(db, req)
    new = int(req.params["priority"])
    db.x("UPDATE jobs SET priority=priority+? WHERE campaign_id=? AND state IN ('pending','leased')",
         (new - int(c["priority"] or 0), req.target))
    db.x("UPDATE campaigns SET priority=? WHERE campaign_id=?", (new, req.target))
    return {"priority": new}


def _placement_snap(db, req):
    return {"placement": placement.summary(db, str(req.target)), "units": [
        {k: u[k] for k in ("unit", "mix", "class", "state", "source")} for u in placement.campaign_units(db, str(req.target))]}


def _placement_call(fn):
    """A placement operation: PlacementError answers as the API error it names."""
    def apply(db, req):
        _campaign_for(db, req)
        try:
            return fn(db, req)
        except placement.PlacementError as e:
            raise core.ApiError(e.status, e.code, e.detail)
    return apply


HANDLERS["campaigns.set_placement"] = Handler(
    target_type="campaign", snapshot=_placement_snap, name=_campaign_name,
    impact=lambda db, r: {"mix": r.params.get("mix"), "running": db.one(
        "SELECT COUNT(*) n FROM jobs WHERE campaign_id=? AND state='leased'", (r.target,))["n"]},
    apply=_placement_call(lambda db, req: placement.set_mix(db, req.target, str(req.params.get("mix") or ""))))


def _rebind_impact(db, req):
    """The plan of campaigns.rebind_platform: each top-level unit, the class it moves to and the finished jobs that run
    again there."""
    from oarbank_sdk import platform as pf
    plat = str(req.params.get("platform") or "")
    units = [u for u in placement.campaign_units(db, str(req.target)) if u["parent"] is None]
    rows = [{"unit": u["unit"], "from": u["class"], "to": pf.class_key(plat, u["mix"]) if "-" in plat else None,
             "requeue": placement.requeue_plan(db, u["unit"])} for u in units]
    return {"platform": plat, "units": rows, "requeue": sorted(i for r in rows for i in r["requeue"])}


HANDLERS["campaigns.rebind_platform"] = Handler(
    target_type="campaign", snapshot=_placement_snap, name=_campaign_name, impact=_rebind_impact,
    apply=_placement_call(lambda db, req: placement.rebind_campaign(db, req.target, str(req.params.get("platform") or ""))))


# ------------------------------------------------------------------ datasets

@handler("datasets.register", target_type="dataset", atomic=False,
         snapshot=lambda db, r: db.one("SELECT dataset_id, kind, module FROM datasets WHERE dataset_id=?", (r.target,)))
def _register_dataset(db, req):
    from . import datasets
    req.target = req.params.get("dataset_id")
    try:
        return datasets.register(db, req.params)
    except ValueError as e:
        raise core.ApiError(422, "bad_dataset", str(e))


# The forms of a module operation's target: a module's channel operations take its name, version operations
# <name>@<version>, and modules.promote either form (the version names its canary). A form an operation does not take
# is refused with the form it does take, never misread as a module name.

def _module_name(db, req):
    """Operations on a module, whatever version runs (rollback, disable, set_pipeline, restart_host, check, verify,
    cli_token): the target is its name."""
    t = req.target or ""
    if "@" in t:
        n = t.split("@", 1)[0]
        raise OpError(422, "bad_target", f"{req.op} takes a module name ({n}), not {t}: it acts on the module, whichever "
                      "version runs")


def _module_version(db, req):
    """Operations on one version (canary, pin, uninstall, approve): <name>@<version>, or the name with params.version."""
    n, v = _name_ver(req)
    if not v and not req.params.get("clear"):          # unpinning needs no version
        from . import modstore
        have = [r["version"] for r in modstore.installed(db, n)]
        raise OpError(422, "bad_target", f"{req.op} needs <name>@<version>, e.g. {n or 'bench'}@{have[-1] if have else '2.4.1'}"
                      + (f" (installed: {', '.join(have)})" if have else ""))


def _module_canary(db, req):
    """modules.promote: the module's name, or <name>@<version> naming its canary (the version that is promoted)."""
    from . import modstore
    n, _, v = (req.target or "").partition("@")
    if not modstore.installed(db, n):
        raise OpError(404, "not_found", f"no module {n!r} is installed (oarbank module list)")
    canary = modstore.channel(db, n)["canary"]
    if not canary:
        raise OpError(409, "no_canary", f"{n} has no canary to promote: oarbank module canary {n}@<version> --node <node>")
    if v and v != canary:
        raise OpError(409, "not_canary", f"{n}'s canary is {canary}, not {v}: promote {n} or {n}@{canary}")
    req.target = n


@handler("modules.set_pipeline", target_type="module", target=_module_name, snapshot=lambda db, r: {"pipeline": settings.fleet_value(db, "pipeline", r.target)},
         impact=lambda db, r: {"pending_eval_jobs": db.one("SELECT COUNT(*) n FROM jobs WHERE module=? AND kind='eval' "
                                                           "AND state='pending' AND depends_on IS NULL AND stage IS NULL", (r.target,))["n"]})
def _pipeline(db, req):
    return core.set_pipeline(db, req.target, req.params["mode"], req.actor)


@handler("modules.restart_host", target_type="module", target=_module_name)
def _restart_host(db, req):
    from . import modcalls
    modcalls.host(db).restart(req.target)
    db.event("module_restarted", actor=req.actor, reason=req.target, module=req.target)
    return {"restarted": req.target}


def _after_lifecycle(db):
    """The catalog, the module host and the releases follow the new channel state."""
    from . import modcalls
    modcalls.use(db)
    return releases.sync(db)


def _channel_snap(db, r):
    from . import modstore
    return {"channel": modstore.channel(db, r.target), "installed": [x["version"] for x in modstore.installed(db, r.target)]}


def _name_ver(req):
    t = req.target or ""
    if "@" in t:
        n, v = t.split("@", 1)
    else:
        n, v = t, req.params.get("version")
    return n, v


def _lifecycle(fn):
    def run(db, req):
        from . import modstore
        try:
            with db.tx():
                out = fn(db, req)
        except (modstore.LifecycleError, modstore.InstallError) as e:
            raise core.ApiError(409, "module_lifecycle", str(e))
        return {**(out or {}), "releases": _after_lifecycle(db)}
    return run


def _live_of(db, name):
    return db.one("SELECT COUNT(*) n FROM attempts a JOIN jobs j ON j.job_id=a.job_id WHERE a.state='live' AND j.module=?", (name,))["n"]


def _incoming(sha: str):
    from . import config as C
    if not re.fullmatch(r"[0-9a-f]{64}", sha or ""):
        raise core.ApiError(400, "bad_bundle", "params.sha256: the uploaded bundle's sha256 (POST /api/v1/modules/bundles)")
    p = C.HOME / "modules" / "incoming" / f"{sha}.mfb"
    if not p.exists():
        raise core.ApiError(404, "not_found", f"no uploaded bundle {sha}")
    return p


def _install_impact(db, r):
    from oarbank_sdk import bundle as B
    from . import modstore
    try:
        info = B.verify(_incoming(r.params.get("sha256")))
    except B.BundleError as e:
        raise core.ApiError(422, "bad_bundle", str(e))
    prev = modstore.installed(db, info.name)
    return {"module_id": info.module_id, "name": info.name, "version": info.version, "content_digest": info.content_digest,
            "files": len(info.files), "installed_versions": [x["version"] for x in prev],
            "requires": info.manifest.requires.model_dump(mode="json"),
            "permissions": list(info.manifest.coordinator.permissions), "enables": "nothing (enable, canary and promote are separate)"}


@handler("modules.install", target_type="module", atomic=False, impact=_install_impact,
         name=lambda db, r: r.params.get("sha256", "")[:12])
def _install(db, req):
    from . import modstore
    try:
        out = modstore.install(db, _incoming(req.params.get("sha256")), actor=req.actor)
    except modstore.InstallError as e:
        raise core.ApiError(409, "install_refused", str(e))
    req.target = f"{out['name']}@{out['version']}"
    return out


@handler("modules.uninstall", target_type="module", target=_module_version, impact=lambda db, r: {"removes": r.target})
def _uninstall(db, req):
    from . import modstore
    n, v = _name_ver(req)
    if (n, v) in modstore.active_versions(db) or modstore.channel(db, n)["previous"] == v:
        raise core.ApiError(409, "module_in_use", f"{n} {v} is current, previous, canary or pinned")
    r = modstore.record(db, n, v)
    if not r:
        raise core.ApiError(404, "not_found", f"{n} {v}")
    db.x("DELETE FROM modules WHERE name=? AND version=?", (n, v))
    import shutil
    shutil.rmtree(r["path"], ignore_errors=True)
    db.event("module_uninstalled", actor=req.actor, reason=f"{n} {v}", module=n)
    return {"uninstalled": f"{n}@{v}"}


@handler("modules.verify", target_type="module", target=_module_name)
def _mverify(db, req):
    from . import modstore
    out = modstore.verify_installed(db, req.target or None)
    return {"ok": all(x["ok"] for x in out), "bundles": out}


def _approve_impact(db, r):
    from . import modsandbox, platforms
    n, v = _name_ver(r)
    st = modsandbox.status(db, n, v)
    return {"module": f"{n} {v}", "grants": modsandbox.describe(st["requests"]),
            "net": (st["requests"].get("net") or {}).get("mode", "none"),
            "allow": (st["requests"].get("net") or {}).get("allow") or [],
            "tools": {t["id"]: {"trust": t["trust"], "paths": ((platforms.tool_registry(db).get(t["id"]) or {}).get("paths") or {})}
                      for t in st["requests"].get("tools") or []},
            "gpu": (st["requests"].get("devices") or {}).get("gpu", "none"),
            "exec_writable": bool(st["requests"].get("exec_writable")),
            "containers": [f"{c['image']} ({c['platform']})" for c in st["requests"].get("containers") or []],
            "already_approved": bool(st["approval"] and st["approved"]),
            "note": "Jobs of this version may use exactly these on every node; nothing else outside their own directories."}


@handler("modules.approve", target_type="module", target=_module_version, impact=_approve_impact)
def _approve(db, req):
    """Approve a module version's node-side sandbox grants (spec/sandbox.md), by the digest of its requests."""
    from . import modsandbox
    n, v = _name_ver(req)
    try:
        return modsandbox.approve(db, n, v, req.actor, req.reason)
    except modsandbox.GrantError as e:
        raise OpError(409, "nothing_to_approve" if "no sandbox" in str(e) else "not_found", str(e))


@handler("modules.check", target_type="module", target=_module_name, atomic=False)
def _mcheck(db, req):
    """Run module integrity checks: the module's own integrity.check plus the core's checks of its files."""
    from . import modcalls, modlife
    names = [req.target] if req.target else modcalls.enabled(db)
    unknown = [n for n in names if n not in modcalls.CATALOG]
    if unknown:
        raise OpError(404, "not_found", f"no enabled module {unknown[0]}")
    out = {n: modlife.check(db, n, "on_demand", deep=bool(req.params.get("deep")), actor=req.actor) for n in names}
    return {"ok": all(c["ok"] for c in out.values()), "modules": out}


@handler("modules.enable", target_type="module", atomic=False, snapshot=_channel_snap)
def _enable(db, req):
    def fn(db, req):
        from . import modstore
        n, v = _name_ver(req)
        ch = modstore.enable(db, n, v)
        db.event("module_enabled", actor=req.actor, reason=f"{n} {ch['current']}", module=n)
        req.target = n
        return {"channel": ch}
    return _lifecycle(fn)(db, req)


@handler("modules.enable_canary", target_type="module", target=_module_version, atomic=False, snapshot=_channel_snap,
         impact=lambda db, r: {"canary": _name_ver(r), "nodes": r.params.get("nodes") or [],
                               "then": "the canary nodes install it, re-doctor and re-certify on its goldens; promote when they pass"})
def _canary(db, req):
    def fn(db, req):
        from . import modstore
        n, v = _name_ver(req)
        nodes = [core_node_id(db, x) for x in (req.params.get("nodes") or [])]
        ch = modstore.canary(db, n, v, nodes)
        db.event("module_canary", actor=req.actor, reason=f"{n} {v} on {', '.join(nodes)}", module=n)
        req.target = n
        return {"channel": ch}
    return _lifecycle(fn)(db, req)


def _promote_impact(db, r):
    """Promotable once every canary node is certified on the canary's own digest (not merely certified). `canary_nodes`
    says, per node, where it stands."""
    from . import modstore
    ch = modstore.channel(db, r.target)
    rec = modstore.record(db, r.target, ch["canary"])
    want = (rec or {}).get("content_digest")
    rows = {n["node_id"]: n for n in db.q("SELECT node_id, hostname, lifecycle, release_id, modules_json FROM nodes WHERE node_id "
                                          "IN (%s)" % ",".join("?" * len(ch["canary_nodes"])), tuple(ch["canary_nodes"]))}
    cert = {}
    for nid in ch["canary_nodes"]:
        n = rows.get(nid)
        if n is None or n["lifecycle"] == "retired":
            cert[n["hostname"] if n else nid] = "retired: not a node any more (roll the canary back and start it again)"
            continue
        st = jl(n["modules_json"], {}).get(r.target) or {}
        runs = (releases.composition_of(db, n["release_id"]).get(r.target) or {}).get("digest")
        if want and st.get("state") == "certified" and st.get("digest") == want:
            cert[n["hostname"]] = "certified"
        elif not want or runs != want:
            cert[n["hostname"]] = (f"not on {ch['canary']} yet (installing its release; {st.get('state') or 'nothing reported'} "
                                   "on the previous version)")
        elif st.get("state") in ("certified", "certifying"):
            cert[n["hostname"]] = "certifying: its goldens have not all passed"
        else:
            cert[n["hostname"]] = (st.get("state") or "nothing reported") + (f" ({st['reason']})" if st.get("reason") else "")
    return {"from": ch["current"], "to": ch["canary"], "canary_nodes": cert,
            "ready": bool(cert) and all(s == "certified" for s in cert.values())}


@handler("modules.promote", target_type="module", target=_module_canary, atomic=False, snapshot=_channel_snap, impact=_promote_impact)
def _mpromote(db, req):
    def fn(db, req):
        from . import modstore
        imp = _promote_impact(db, req)
        if not imp["ready"] and not req.params.get("force"):
            waiting = "; ".join(f"{h}: {s}" for h, s in imp["canary_nodes"].items() if s != "certified")
            raise modstore.LifecycleError(f"{req.target} {imp['to']} is not certified on every canary node yet ({waiting}); "
                                          "promote once its goldens pass there")
        ch = modstore.promote(db, req.target)
        db.event("module_promoted", actor=req.actor, reason=f"{req.target} {ch['current']}", module=req.target)
        return {"channel": ch}
    return _lifecycle(fn)(db, req)


@handler("modules.rollback", target_type="module", target=_module_name, atomic=False, snapshot=_channel_snap)
def _mrollback(db, req):
    def fn(db, req):
        from . import modstore
        ch = modstore.rollback(db, req.target)
        db.event("module_rolled_back", actor=req.actor, reason=f"{req.target} -> {ch['current']}", module=req.target)
        return {"channel": ch}
    return _lifecycle(fn)(db, req)


@handler("modules.disable", target_type="module", target=_module_name, atomic=False, snapshot=_channel_snap,
         impact=lambda db, r: {"live_attempts": _live_of(db, r.target)})
def _disable(db, req):
    def fn(db, req):
        from . import modstore
        ch = modstore.disable(db, req.target)
        for a in db.q("SELECT a.attempt_id, a.node_id FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                      "WHERE a.state='live' AND j.module=?", (req.target,)):
            core._end_attempt(db, a["attempt_id"], "released", "module_disabled", count_failure=False)
            core._push(db, a["node_id"], "revoke", a["attempt_id"])
        db.event("module_disabled", actor=req.actor, reason=req.target, module=req.target)
        return {"channel": ch}
    return _lifecycle(fn)(db, req)


@handler("modules.pin", target_type="module", target=_module_version, atomic=False, snapshot=_channel_snap)
def _mpin(db, req):
    def fn(db, req):
        from . import modstore
        n, v = _name_ver(req)
        node = core_node_id(db, req.params.get("node") or "")
        out = modstore.pin(db, n, node, v if not req.params.get("clear") else None)
        db.event("module_pinned", actor=req.actor, node_id=node, reason=f"{n} {v or '(cleared)'}", module=n)
        req.target = n
        return out
    return _lifecycle(fn)(db, req)


# ------------------------------------------------------------------ coordinator move

def _coord(fn):
    def run(db, req):
        from . import coordmove
        try:
            return fn(db, req, coordmove)
        except coordmove.MoveError as e:
            raise core.ApiError(409, "move_refused", str(e))
    return run


def _coord_snap(db, r):
    from . import coordmove
    m = coordmove.move(db)
    return {"phase": coordmove.phase(db), "move": m["move_id"] if m else None, "state": m["state"] if m else None}


def _bundle_dirty() -> bool:
    try:
        from . import coordbundle
        return coordbundle.dirty()
    except Exception:
        return False


def _prepare_impact(db, r):
    from . import coordmove, identity, modlife, platforms
    t = r.target or r.params.get("to") or ""
    node = db.one("SELECT hostname, ts_ip, ts_node_id, facts_json, platform FROM nodes WHERE (node_id=? OR hostname=?) "
                  "AND lifecycle!='retired'", (t, t))
    facts = jl(node["facts_json"], {}) if node else {}
    plat = platforms.node_platform(dict(node)) if node else None
    return {"target": t, "kind": "enrolled node: its agent fetches and verifies the standby coordinator; its system service is "
                    "installed as root on the target (a node's agent is unprivileged: it names the command)" if node
                    else "a host where you install the standby as root (install-oarbankd.sh --pair)",
            "target_stable_id": node["ts_node_id"] if node else None,
            "target_platform": plat or "reported by the standby when it pairs",
            "blocking_modules": modlife.platform_blockers(db, plat) or "none",
            "warnings": [w for w in (
                "the target has FileVault on: after a power loss it serves nothing until someone unlocks its disk at the Mac "
                "(restarts with `fdesetup authrestart`, and macOS updates that unlock the disk, come back by themselves)"
                if facts.get("filevault") == "on" else None,
                "this coordinator's checkout has uncommitted changes: the bundle installed on the target carries tracked "
                "files as they are on disk and no untracked ones (commit first)" if node and _bundle_dirty() else None) if w],
            "this_coordinator": {"fingerprint": identity.key(coordmove.home(db)).fingerprint[:16], "epoch": identity.epoch(db)},
            "secrets_carried": _secrets_carried(db)}


@handler("coordinator.prepare", target_type="coordinator", atomic=False, impact=_prepare_impact,
         name=lambda db, r: r.target or r.params.get("to") or "")
def _coord_prepare(db, req):
    return _coord(lambda db, req, cm: cm.prepare(db, req.target or req.params.get("to") or "", req.actor))(db, req)


def _move_impact(db, r):
    from . import coordmove, identity
    p = coordmove.plan(db)
    tl = int(r.params.get("timelock_s") or coordmove.DEFAULT_TIMELOCK_S)
    live = db.one("SELECT COUNT(*) n FROM attempts WHERE state='live'")["n"]
    return {"to": p and p.get("b_url"), "to_fingerprint": p and p.get("b_cik") and identity.fingerprint(p["b_cik"])[:16],
            "to_stable_id": p and p.get("target_stable_id"), "paired": bool(p and p["state"] == "paired"),
            "epoch": f"{identity.epoch(db)} -> {identity.epoch(db) + 1}", "timelock_s": tl,
            "starts_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(time.time() + tl)),
            "signing": "owner-signed" if r.params.get("owner_sig") else "UNSIGNED move (release signing is off)",
            "live_attempts_carried": live, "secrets_carried": _secrets_carried(db),
            "frozen_window": "about a minute (dispatch paused; running work continues)", **_move_modules(db, p, tl, r)}


def _secrets_carried(db) -> list[str] | str:
    """Module secrets the move carries (by name and scope, never values), re-encrypted for the target."""
    from . import modsecrets
    return modsecrets.names_for_preview(db) or "none"


def _move_modules(db, p, tl, r) -> dict:
    """What modules say about the move: blockers now, and what their rules rebuild or drop."""
    from . import modlife
    try:
        pre = modlife.preflight(db, "preview", (p or {}).get("b_url") or "", time.time() + tl, "planned",
                                (p or {}).get("target_platform"))
        rules = modlife.move_plan(db)["items"]
    except Exception as e:
        return {"modules": f"could not ask modules: {e}"[:200]}
    out = {"target_platform": (p or {}).get("target_platform") or "not known until the target pairs",
           "module_blockers": modlife.blockers(pre) or "none",
           "module_rules": [f"{i['module']}: {i['kind']} {i['selector'] or '(all)'} {i['class']} ({i['count']} items, "
                            f"{i['bytes'] / 1e6:.1f} MB)" for i in rules] or "everything is carried"}
    if r.params.get("force"):
        out["force"] = ("module blockers and failed module checks will NOT stop this move; modules whose coordinator side "
                        "does not run on the target start disabled there")
    return out


@handler("coordinator.move", target_type="coordinator", atomic=False, impact=_move_impact, snapshot=_coord_snap,
         name=lambda db, r: "move")
def _coord_move(db, req):
    def fn(db, req, cm):
        tl = req.params.get("timelock_s")
        return cm.request_move(db, req.actor, req.reason, int(tl) if tl else None, req.params.get("canary"),
                               owner_sig=req.params.get("owner_sig"), force=bool(req.params.get("force")))
    out = _coord(fn)(db, req)
    return {k: v for k, v in out.items() if k not in ("statement",)}


@handler("coordinator.cancel", target_type="coordinator", atomic=False, snapshot=_coord_snap)
def _coord_cancel(db, req):
    out = _coord(lambda db, req, cm: cm.cancel(db, req.actor, req.reason))(db, req)
    return {k: v for k, v in out.items() if k not in ("statement",)}


@handler("coordinator.finalize", target_type="coordinator", atomic=False,
         impact=lambda db, r: {"effect": "this oarbankd stops and will not start here again; its data stays for you to archive"})
def _coord_finalize(db, req):
    out = _coord(lambda db, req, cm: cm.finalize(db, req.actor))(db, req)
    import threading
    from ..platform import service
    threading.Timer(2.0, lambda: service.exit_now(0)).start()    # exit 0: the service manager leaves it down
    return out


@handler("coordinator.sign_move", target_type="coordinator", atomic=False, snapshot=_coord_snap,
         impact=lambda db, r: {"effect": "the move is announced to agents and its time lock starts counting from its statement"})
def _coord_sign_move(db, req):
    out = _coord(lambda db, req, cm: cm.sign_move(db, req.params.get("owner_sig") or "", req.actor))(db, req)
    return {k: v for k, v in out.items() if k not in ("statement",)}


def _owner(fn):
    def run(db, req):
        from . import owner
        try:
            return fn(db, req, owner)
        except owner.OwnerError as e:
            raise core.ApiError(409, "owner_refused", str(e))
    return run


def _anchors_impact(db, r):
    from . import owner
    try:
        doc = owner.check_anchors(db, r.params.get("statement") or "", r.params.get("signatures") or [])
    except owner.OwnerError as e:
        return {"refused": str(e)}
    from . import identity
    return {"version": doc["version"], "keys": [identity.fingerprint(k)[:16] for k in doc["keys"]],
            "rescue": doc.get("rescue") or [], "replaces": [identity.fingerprint(k)[:16] for k in owner.keys(db)]}


@handler("owner.set_anchors", target_type="coordinator", impact=_anchors_impact, name=lambda db, r: "owner-keys")
def _owner_set(db, req):
    return _owner(lambda db, req, o: o.set_anchors(db, req.params.get("statement") or "", req.params.get("signatures") or [], req.actor))(db, req)


@handler("owner.disable_signing", target_type="coordinator", name=lambda db, r: "disable-signing",
         impact=lambda db, r: {"effect": "agents unpin the owner keys; releases, agent builds and moves no longer need the owner"})
def _owner_disable(db, req):
    return _owner(lambda db, req, o: o.disable(db, req.params.get("statement") or "", req.params.get("signatures") or [], req.actor))(db, req)


@handler("nodes.confirm_identity", target_type="node")
def _confirm_identity(db, req):
    from . import identity
    n = _node(db, req.target or "")
    fp = identity.key(Path(db.path).parent).fingerprint
    if n.get("cik_pinned") != fp:
        raise core.ApiError(409, "identity_mismatch",
                            f"{n['hostname']} pinned {(n.get('cik_pinned') or 'nothing')[:16]}, this coordinator is {fp[:16]}")
    db.x("UPDATE nodes SET cik_confirmed=?, cik_confirmed_by=?, cik_confirmed_at=? WHERE node_id=?",
         (fp, req.actor, time.time(), n["node_id"]))
    req.target = n["node_id"]
    return {"node": n["hostname"], "confirmed": fp[:16]}


# ------------------------------------------------------------------ agent self-update

def _agent_snap(db, r):
    from . import agentbuilds
    return {"channels": agentbuilds.channels(db)}


def _agent_op(fn):
    def run(db, req):
        from . import agentbuilds
        try:
            with db.tx():
                return fn(db, req, agentbuilds)
        except agentbuilds.BuildError as e:
            raise core.ApiError(409, "agent_build", str(e))
    return run


def _agent_ref(db, req):
    from . import agentbuilds
    try:
        return agentbuilds.resolve(db, req.target or req.params.get("build") or "")
    except agentbuilds.BuildError as e:
        raise core.ApiError(404, "not_found", str(e))


def _agent_upload_impact(db, r):
    from . import agentbuilds
    try:
        p = agentbuilds.incoming(r.params.get("sha256"))
        info = agentbuilds.inspect(p)
    except agentbuilds.BuildError as e:
        return {"refused": str(e)}
    known = agentbuilds.record(db, r.params.get("sha256"))
    return {"version": info["version"], "size": info["size"], "sha256": r.params.get("sha256"), "platforms": info["platforms"],
            "format": info["format"],
            "already_registered": bool(known), "then": "agent.canary on one node, then agent.promote",
            "signing": "this fleet runs in signing mode: sign it (oarbank agent sign) before canary" if _signing() else None}


def _signing() -> bool:
    from . import config as C
    return C.RELEASE_SIGNING


@handler("agent.upload", target_type="agent", atomic=False, impact=_agent_upload_impact,
         name=lambda db, r: (r.params.get("sha256") or "")[:12])
def _agent_upload(db, req):
    from . import agentbuilds
    try:
        out = agentbuilds.register(db, req.params.get("sha256"), actor=req.actor)
    except agentbuilds.BuildError as e:
        raise core.ApiError(409, "agent_build", str(e))
    req.target = out["sha256"]
    return {k: v for k, v in out.items() if k != "path"}


@handler("vendor.metadata.upload", target_type="agent", atomic=False, name=lambda db, r: "vendor-metadata")
def _vendor_metadata(db, req):
    from . import vendortuf
    try:
        names = vendortuf.store(C_HOME(), req.params.get("files") or {})
    except vendortuf.MetadataError as e:
        raise core.ApiError(409, "vendor_metadata", str(e))
    req.target = "vendor-metadata"
    return {"stored": names}


@handler("agent.canary", target_type="agent", atomic=False, snapshot=_agent_snap,
         impact=lambda db, r: {"canary": _agent_ref(db, r)[:12], "nodes": r.params.get("nodes") or [],
                               "then": "each canary node downloads it, drains (running jobs finish), swaps and restarts "
                                       "on it; promote when they all run it"})
def _agent_canary(db, req):
    def fn(db, req, ab):
        sha = _agent_ref(db, req)
        nodes = [core_node_id(db, x) for x in (req.params.get("nodes") or [])]
        chs = ab.canary(db, sha, nodes)
        db.event("agent_canary", actor=req.actor, reason=f"{sha[:12]} on {', '.join(nodes)}")
        req.target = sha
        return {"channels": chs}
    return _agent_op(fn)(db, req)


def _agent_promote_impact(db, r):
    from . import agentbuilds
    plats = [r.params["platform"]] if r.params.get("platform") else \
        [p for p, ch in agentbuilds.channels(db).items() if ch["canary"]]
    return {"platforms": {p: agentbuilds.readiness(db, p) for p in plats}}


@handler("agent.promote", target_type="agent", atomic=False, snapshot=_agent_snap, impact=_agent_promote_impact,
         name=lambda db, r: "agent")
def _agent_promote(db, req):
    def fn(db, req, ab):
        plat = req.params.get("platform")
        for p in ([plat] if plat else [p for p, ch in ab.channels(db).items() if ch["canary"]]):
            imp = ab.readiness(db, p)
            if not imp["ready"] and not req.params.get("force"):
                raise ab.BuildError(f"the {p} canary is not running on every canary node: {imp['canary_nodes']}")
        chs = ab.promote(db, plat)
        db.event("agent_promoted", actor=req.actor, reason=", ".join(f"{p} {(c['current'] or '')[:12]}" for p, c in chs.items()))
        req.target = ",".join(sorted({c["current"] for c in chs.values() if c["current"]})) or "agent"
        return {"channels": chs}
    return _agent_op(fn)(db, req)


@handler("agent.rollback", target_type="agent", atomic=False, snapshot=_agent_snap)
def _agent_rollback(db, req):
    def fn(db, req, ab):
        chs = ab.rollback(db, req.params.get("platform"))
        db.event("agent_rolled_back", actor=req.actor, reason=", ".join(f"{p} current {(c['current'] or '-')[:12]}" for p, c in chs.items()))
        req.target = "agent"
        return {"channels": chs}
    return _agent_op(fn)(db, req)


@handler("agent.sign", target_type="agent", atomic=False)
def _agent_sign(db, req):
    def fn(db, req, ab):
        sha = _agent_ref(db, req)
        req.target = sha
        return ab.attach_signature(db, sha, req.params.get("statement") or "", req.params.get("signature") or "")
    return _agent_op(fn)(db, req)


# ------------------------------------------------------------------ coordinator builds

def _cb_impact(db, r):
    from . import coordbuilds
    try:
        info = coordbuilds.inspect(C_HOME() / "coordinator-builds" / "incoming" / (r.params.get("sha256") or "x"))
    except coordbuilds.BuildError as e:
        return {"refused": str(e)}
    return {**info, "sha256": r.params.get("sha256"), "then": "sign it (oarbank coordinator-build sign) so moves can install it"}


def C_HOME():
    from . import config as C
    return C.HOME


@handler("coordinator.builds.upload", target_type="coordinator_build", atomic=False, impact=_cb_impact,
         name=lambda db, r: (r.params.get("sha256") or "")[:12])
def _cb_upload(db, req):
    from . import coordbuilds
    try:
        out = coordbuilds.register(db, req.params.get("sha256"), actor=req.actor)
    except coordbuilds.BuildError as e:
        raise core.ApiError(409, "coordinator_build", str(e))
    req.target = out["sha256"]
    return {k: v for k, v in out.items() if k != "path"}


@handler("coordinator.builds.sign", target_type="coordinator_build", atomic=False)
def _cb_sign(db, req):
    from . import coordbuilds
    try:
        rows = [b for b in coordbuilds.builds(db) if b["sha256"].startswith((req.target or "").lower())] if len(req.target or "") >= 8 else []
        if len(rows) != 1:
            raise coordbuilds.BuildError(f"{req.target!r} names {len(rows)} coordinator builds")
        req.target = rows[0]["sha256"]
        return coordbuilds.attach_signature(db, req.target, req.params.get("statement") or "", req.params.get("signature") or "")
    except coordbuilds.BuildError as e:
        raise core.ApiError(409, "coordinator_build", str(e))


def core_node_id(db, x: str) -> str:
    return _node(db, x)["node_id"]


# ------------------------------------------------------------------ releases

@handler("releases.build", target_type="release", atomic=False)
def _build(db, req):
    """Build every fleet platform's release (and the canary and pinned nodes' own), as a module change does. Nothing
    to build while no module is enabled: a release is the bundle of the enabled modules."""
    if not releases.any_module_enabled(db):
        raise core.ApiError(409, "no_module_enabled", "No module is enabled, so there is no release to build. Install a "
                            "module and enable it (Modules page, or `oarbank module enable <name>@<version>`): its release "
                            "is then built for every platform in the fleet.")
    out = releases.sync(db)
    need = releases.signature_required(db)
    rows = {r["release_id"]: r for r in db.q("SELECT release_id, status, sha256, signature, composition_json FROM releases "
                                             "WHERE release_id IN "
                                             f"({','.join('?' * len(out['defaults']))})", tuple(out["defaults"].values()))}
    built = []
    for plat, rid in out["defaults"].items():
        r = rows[rid]
        unsigned = need and not r["signature"]
        built.append({"platform": plat, "release_id": rid, "status": r["status"], "sha256": r["sha256"], "needs_signature": unsigned,
                      "modules": releases.contents(r["composition_json"]),
                      **({"next": f"oarbank release sign {rid} --promote"} if unsigned or r["status"] != "current" else {})})
    req.target = ",".join(out["defaults"].values())
    return {"releases": built, "assigned": out["assigned"], "awaiting": releases.awaiting(db)}


@handler("releases.attach_signature", target_type="release")
def _sign(db, req):
    try:
        return releases.attach_signature(db, req.target, req.params["statement"], req.params["signature"])
    except releases.ReleaseRefused as e:
        raise core.ApiError(409, "release_refused", str(e))


@handler("releases.promote", target_type="release",
         snapshot=lambda db, r: {"current": (db.one("SELECT release_id FROM releases WHERE status='current'") or {}).get("release_id")},
         impact=lambda db, r: {"nodes": db.one("SELECT COUNT(*) n FROM nodes WHERE lifecycle NOT IN ('retired')")["n"]})
def _promote(db, req):
    try:
        releases.promote(db, req.target, req.actor)
    except releases.ReleaseRefused as e:
        raise core.ApiError(409, "release_refused", str(e))
    return {"current": req.target}


@handler("releases.pin_key", target_type="release", snapshot=_setting_snap("release_pubkey"), name=lambda db, r: "release-key")
def _pin(db, req):
    import base64
    from . import config as C
    if not C.RELEASE_SIGNING:
        raise core.ApiError(409, "feature_disabled", "release signing is disabled (OARBANK_RELEASE_SIGNING=1)")
    cur = db.get_state("release_pubkey")
    pub = req.params["pubkey"]
    if cur and cur != pub and not req.params.get("rotate"):
        raise core.ApiError(409, "release_key_pinned", "a different release key is already pinned (rotate=true)")
    if len(base64.b64decode(pub)) != 32:
        raise core.ApiError(400, "bad_key", "expected a base64 raw Ed25519 public key")
    db.set_state("release_pubkey", pub)
    db.event("release_key_set", actor=req.actor, reason="rotated" if cur and cur != pub else "pinned")
    return {"pinned": True}


# ------------------------------------------------------------------ settings, audit

def _settings(fn):
    from .settings.apply import ApplyError
    try:
        return fn()
    except ApplyError as e:
        raise OpError(e.status, e.code, e.detail, extra={"errors": e.errors})


def _settings_changes(req) -> list:
    """The change set; an operator changes nodes, only an admin the fleet or a group (every node at once)."""
    extra = set(req.params) - {"changes", "comment"}
    if extra:
        raise OpError(400, "bad_params", f"settings.apply takes changes and comment, not {sorted(extra)}")
    changes = req.params.get("changes")
    wide = [c for c in changes or [] if isinstance(c, dict) and c.get("scope") in ("fleet", "group")]
    if wide and req.role not in (None, "admin"):
        raise OpError(403, "forbidden_role", f"a fleet or group setting needs the admin role; {req.actor} is {req.role}")
    return changes


def _settings_snap(db, req):
    """Each changed row as it is (the audit's before and after): {scope:scope_id:module:key: {value, enforced} | None}."""
    from .settings import store
    out = {}
    for c in req.params.get("changes") or []:
        if isinstance(c, dict) and c.get("key"):
            sid = c.get("scope_id") or ""
            if c.get("scope") == "node":
                n = db.one("SELECT node_id FROM nodes WHERE node_id=? OR hostname=?", (sid, sid))
                sid = n["node_id"] if n else sid
            x = store.row(db, c.get("scope") or "", sid, c.get("module") or "", c["key"])
            out[f"{c.get('scope')}:{sid}:{c.get('module') or ''}:{c['key']}"] = \
                {"value": x["value"], "enforced": bool(x["enforced"]), "rev": x["rev"]} if x else None
    return out


def _settings_confirm(db, req) -> str:
    cs = [c for c in req.params.get("changes") or [] if isinstance(c, dict)]
    return next((c.get("key") for c in cs if c.get("enforce")), None) or (cs[0].get("key") if cs else "") or ""


@handler("settings.apply", target_type="setting", snapshot=_settings_snap, versions=lambda db, r: ["settings"],
         impact=lambda db, r: _settings(lambda: settings.apply.plan(db, _settings_changes(r))),
         tier=lambda r: settings.change_tier(r.params.get("changes") if isinstance(r.params.get("changes"), list) else []),
         name=_settings_confirm)
def _settings_apply(db, req):
    """A change set of owner settings (docs/design/settings.md): values set or reset at the fleet, a group or a node,
    checked against the registry and the merged values on every node it reaches, written under one revision. Its tier
    follows the keys and scopes it changes."""
    changes = _settings_changes(req)
    return _settings(lambda: settings.apply.commit(db, changes, req.actor, req.params.get("comment") or req.reason))


def _core_secret(fn):
    from . import modsecrets
    try:
        return fn(modsecrets)
    except modsecrets.SecretError as e:
        raise OpError(e.status, e.code, e.detail)


@handler("settings.secrets.set", target_type="setting",
         snapshot=lambda db, r: _core_secret(lambda S: S.core_state(db, r.target or "")))
def _core_secret_set(db, req):
    """A core secret (the ntfy token): write-only, encrypted like module secrets, shown only as a fingerprint."""
    if set(req.params):
        raise OpError(400, "bad_params", "the value goes beside params, as `secret`")
    if not req.secret:
        raise OpError(400, "secret_required", "send the value beside params, as `secret`")
    out = _core_secret(lambda S: S.core_set(db, req.target or "", req.secret, req.actor))
    db.event("settings_changed", actor=req.actor, reason=f"core secret {req.target} set ({out['fingerprint']})")
    return out


@handler("settings.secrets.clear", target_type="setting",
         snapshot=lambda db, r: _core_secret(lambda S: S.core_state(db, r.target or "")))
def _core_secret_clear(db, req):
    out = _core_secret(lambda S: S.core_clear(db, req.target or ""))
    db.event("settings_changed", actor=req.actor, reason=f"core secret {req.target} cleared")
    return out


def _tools_impact(db, r):
    from . import platforms
    reg = platforms.tool_registry(db)
    try:
        new = platforms.check_tool(r.target or "", r.params) if r.params.get("paths") else None
    except ValueError as e:
        return {"refused": str(e)}
    users = sorted({f"{m['name']} {m['version']}" for m in db.q("SELECT name, version FROM module_grants")
                    if any(t.get("id") == r.target for t in (_grant_tools(db, m["name"], m["version"])))})
    return {"tool": r.target, "before": reg.get(r.target), "after": new, "approved_module_versions": users,
            "then": "releases are rebuilt so agents get the new paths"}


def _grant_tools(db, name, version):
    from . import modsandbox
    a = modsandbox.approval(db, name, version) or {}
    return (a.get("requests") or {}).get("tools") or []


@handler("settings.tools.update", target_type="setting", impact=_tools_impact,
         snapshot=lambda db, r: {"tool_registry": settings.fleet_value(db, "tool_registry")}, versions=lambda db, r: ["setting:tool_registry"])
def _tools(db, req):
    """The tool registry (oarbank-sdk spec/sandbox.md, `tools`): a logical tool id mapped to host paths per OS (the whole
    entry: every OS's paths, as the Settings form shows them prefilled). No paths removes the id. Releases are rebuilt so
    every agent gets the paths for its OS. Trust is the module request's, approved with it, never the registry's."""
    from . import modstore, platforms, releases
    reg = dict(platforms.tool_registry(db))
    try:
        entry = platforms.check_tool(req.target or "", req.params)
    except ValueError as e:
        raise core.ApiError(400, "bad_tool", str(e))
    if entry["paths"]:
        reg[req.target] = entry
    else:
        reg.pop(req.target, None)
    settings.write_fleet(db, platforms.TOOL_REGISTRY, reg, req.actor, comment=f"tool {req.target}")
    db.event("settings_changed", actor=req.actor, reason=f"tool_registry {req.target}: "
             + (", ".join(f"{o}={len(p)}" for o, p in entry["paths"].items()) or "removed"))
    if any(ch["current"] for ch in modstore.channels(db).values()):
        releases.sync(db)
    return {"tool": req.target, "entry": reg.get(req.target)}


def _folders_impact(db, r):
    from . import folders
    try:
        new = folders.check_entry(db, r.target or "", r.params)
    except folders.FolderError as e:
        return {"refused": str(e)}
    users = sorted({f"{m['name']} {m['version']}" for m in db.q("SELECT name, version, requests_json FROM module_grants")
                    if any(f.get("id") == r.target for f in (json.loads(m["requests_json"]).get("folders") or []))})
    return {"folder": r.target, "before": folders.registry(db).get(r.target), "after": new,
            "approved_module_versions": users,
            "then": "each changed node gets a new folder statement" + (" for the owner to sign (oarbank folders sign <node>)"
                                                                       if _signing() else "")}


@handler("settings.folders.update", target_type="setting", impact=_folders_impact,
         snapshot=lambda db, r: {"folder_registry": settings.fleet_value(db, "folder_registry")}, versions=lambda db, r: ["setting:folder_registry"])
def _folders(db, req):
    """The folder registry (oarbank-sdk spec/sandbox.md, "Folders"): a folder id mapped to a path on each node, with its
    access. `nodes` entries set to null remove the node; an entry with no nodes left removes the id. Every node whose
    mapping changed gets a new folder statement (signed by the owner in signing mode before nodes apply it)."""
    from . import folders
    try:
        entry = folders.check_entry(db, req.target or "", req.params)
    except folders.FolderError as e:
        raise core.ApiError(400, "bad_folder", str(e))
    reg = dict(folders.registry(db))
    before = set((reg.get(req.target) or {}).get("nodes") or {})
    if entry["nodes"]:
        reg[req.target] = entry
    else:
        reg.pop(req.target, None)
    settings.write_fleet(db, folders.REGISTRY, reg, req.actor, comment=f"folder {req.target}")
    changed = folders.refresh(db, sorted(before | set(entry["nodes"])))
    db.event("settings_changed", actor=req.actor, reason=f"folder_registry {req.target}: {entry['access']} on "
             f"{len(entry['nodes'])} nodes; new statements for {', '.join(changed) or 'none'}")
    return {"folder": req.target, "entry": reg.get(req.target), "statements": changed}


@handler("folders.sign", target_type="node", atomic=False)
def _folders_sign(db, req):
    from . import folders
    try:
        return folders.sign(db, req.target or "", req.params.get("statement") or "", req.params.get("signature") or "")
    except folders.FolderError as e:
        raise core.ApiError(422, "bad_folder_signature", str(e))


def _origins_impact(db, r):
    from oarbank_sdk import origins as O
    from . import blobstore
    hosts = [h.strip().lower() for h in r.params.get("hosts") or [] if h.strip()]
    bad = [h for h in hosts if not re.fullmatch(r"(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(:[0-9]{1,5})?", h)]
    if bad:
        return {"refused": f"not host patterns: {bad}"}
    refused = sorted({d["dataset_id"] for d in db.q("SELECT dataset_id, files_json FROM datasets")
                      for f in json.loads(d["files_json"] or "[]") for o in f.get("origins") or [] if not O.allowed(o, hosts)})
    return {"before": blobstore.origin_policy(db), "after": hosts, "datasets_losing_origins": refused[:50],
            "then": "agents get only the admitted origins of each dataset; files left without one come from the coordinator"}


@handler("settings.origins.update", target_type="setting", impact=_origins_impact,
         snapshot=lambda db, r: {"dataset_origins": settings.fleet_value(db, "dataset_origins")}, versions=lambda db, r: ["setting:dataset_origins"])
def _origins(db, req):
    """The origin host policy (docs/design/datasets-media-checkpoints.md): host patterns dataset origins must match
    (`example.org`, `*.example.org`, with an optional `:port`); none admits every public https host. It applies when a
    dataset is registered and whenever its files are served or fetched, so tightening it takes effect at once."""
    from . import blobstore
    imp = _origins_impact(db, req)
    if imp.get("refused"):
        raise core.ApiError(400, "bad_origin_policy", imp["refused"])
    settings.write_fleet(db, blobstore.ORIGIN_SETTING, imp["after"], req.actor)
    db.event("settings_changed", actor=req.actor, reason=f"dataset_origins: {', '.join(imp['after']) or 'any host'}")
    return {"hosts": imp["after"]}


# ------------------------------------------------------------------ access (accounts, tokens, sign-in links)

def _access(fn):
    def run(db, req):
        from . import access
        try:
            return fn(db, req, access)
        except access.AccessError as e:
            raise core.ApiError(e.status, e.code, e.detail)
    return run


def _self_or_admin(req, name: str):
    if name != req.actor and req.role not in (None, "admin"):
        raise core.ApiError(403, "forbidden_role", f"only an admin acts on another account ({name})")


@handler("access.accounts.create", target_type="account",
         impact=lambda db, r: {"account": r.target, "role": r.params.get("role") or "admin",
                               "password": "set" if r.params.get("password") else "none (sign in with a link or a passkey)",
                               "then": "the TOTP seed is shown once: add it to an authenticator app"})
def _acct_create(db, req):
    def fn(db, req, A):
        out = A.create_account(db, req.target or req.params.get("name") or "", req.params.get("role") or "admin",
                               req.params.get("password") or None, req.actor)
        db.event("account_created", actor=req.actor, reason=f"{out['account']} ({out['role']})")
        return out
    return _access(fn)(db, req)


@handler("access.accounts.update", target_type="account",
         impact=lambda db, r: {"account": r.target, **{k: v for k, v in r.params.items() if k in ("role", "disabled")}})
def _acct_update(db, req):
    def fn(db, req, A):
        if not A.account(db, req.target or ""):
            raise A.AccessError("no_account", req.target or "", 404)
        if "role" in req.params:
            if req.params["role"] not in A.ROLES:
                raise A.AccessError("bad_role", f"one of {', '.join(A.ROLES)}", 400)
            if req.params["role"] != "admin" and A.account(db, req.target)["role"] == "admin" and db.one(
                    "SELECT COUNT(*) n FROM accounts WHERE role='admin' AND disabled=0 AND name!=?", (req.target,))["n"] == 0:
                raise A.AccessError("last_admin", "keep at least one enabled admin account", 409)
            db.x("UPDATE accounts SET role=? WHERE name=?", (req.params["role"], req.target))
        if "disabled" in req.params:
            A.set_disabled(db, req.target, bool(req.params["disabled"]))
        db.event("account_updated", actor=req.actor, reason=f"{req.target}: {sorted(req.params)}")
        return {"account": req.target, **{k: v for k, v in A.account(db, req.target).items() if k in ("role", "disabled")}}
    return _access(fn)(db, req)


@handler("access.accounts.reset_totp", target_type="account",
         impact=lambda db, r: {"account": r.target, "then": "its sessions end; the new seed is shown once"})
def _acct_totp(db, req):
    def fn(db, req, A):
        out = A.reset_totp(db, req.target or "")
        db.event("account_totp_reset", actor=req.actor, reason=req.target)
        return out
    return _access(fn)(db, req)


@handler("access.accounts.set_password", target_type="account")
def _acct_pw(db, req):
    def fn(db, req, A):
        name = req.target or req.actor
        _self_or_admin(req, name)
        A.set_password(db, name, req.params.get("password") or "")
        db.event("account_password_set", actor=req.actor, reason=name)
        return {"account": name, "password_set": True}
    return _access(fn)(db, req)


@handler("access.tokens.create", target_type="account",
         impact=lambda db, r: {"account": r.target or r.actor, "role": r.params.get("role") or "viewer",
                               "days": r.params.get("days") or 90, "label": r.params.get("label") or "",
                               "then": "the token is shown once"})
def _tok_create(db, req):
    def fn(db, req, A):
        name = req.target or req.actor
        _self_or_admin(req, name)
        out = A.new_token(db, name, req.params.get("label") or "", req.params.get("role") or "viewer",
                          float(req.params.get("days") or 90))
        db.event("token_created", actor=req.actor, reason=f"{out['token_id']} for {name} ({out['role']})")
        return out
    return _access(fn)(db, req)


@handler("access.tokens.revoke", target_type="token")
def _tok_revoke(db, req):
    def fn(db, req, A):
        row = db.one("SELECT account FROM access_tokens WHERE token_id=?", (req.target or "",))
        if not row:
            raise A.AccessError("no_token", req.target or "", 404)
        _self_or_admin(req, row["account"])
        A.revoke_token(db, req.target)
        db.event("token_revoked", actor=req.actor, reason=req.target)
        return {"revoked": req.target}
    return _access(fn)(db, req)


@handler("access.login_link", target_type="account")
def _login_link(db, req):
    def fn(db, req, A):
        name = req.target or req.params.get("account") or _default_account(db)
        if not name:
            raise A.AccessError("no_account", "create one first: oarbank account create <name>", 404)
        t = A.new_login_link(db, name)
        from . import config as C
        base = (req.params.get("console") or f"http://127.0.0.1:{C.CONSOLE_PORT}").rstrip("/")
        db.event("login_link_issued", actor=req.actor, reason=name)
        return {"account": name, "url": f"{base}/login/link?t={t}", "expires_in_s": A.LINK_TTL_S}
    return _access(fn)(db, req)


def _default_account(db) -> str | None:
    r = db.one("SELECT name FROM accounts WHERE role='admin' AND disabled=0 ORDER BY created_at LIMIT 1")
    return r["name"] if r else None


def _join_urls(db) -> list[str]:
    from . import config as C
    urls = [u for u in [db.get_state("coordinator_url")] + list(db.get_state("join_urls") or []) if u]
    return list(dict.fromkeys(u.rstrip("/") for u in urls)) or [f"https://{C.AGENT_BIND}:{C.AGENT_PORT}"]


def _join_params(r) -> dict:
    p = r.params
    uses = int(p.get("uses") or 1)
    approve = p.get("approve")
    return {"label": (p.get("label") or "").strip(), "ttl_s": float(p.get("ttl_s") or joincodes_default_ttl()),
            "uses": uses, "approve": (uses == 1) if approve in (None, "") else _truthy(approve),
            "system": _truthy(p.get("system")), "containers": _truthy(p.get("containers"))}


def _truthy(v) -> bool:
    return v is True or str(v).lower() in ("1", "true", "yes", "on")


def joincodes_default_ttl() -> float:
    from . import joincodes
    return joincodes.DEFAULT_TTL_S


def _join_impact(db, r):
    p = _join_params(r)
    then = ("a machine that joins with this code is approved at once" if p["approve"]
            else "machines that join with this code wait for your approval on the Fleet page")
    return {"urls": _join_urls(db), "expires_in_s": p["ttl_s"], "label": p["label"], "uses": p["uses"],
            "then": then + (" (single use)" if p["uses"] == 1 else f" (up to {p['uses']} machines)")}


@handler("nodes.join_code", target_type="node", impact=_join_impact)
def _join_code(db, req):
    from pathlib import Path
    from . import identity, joincodes, tlsca
    p = _join_params(req)
    try:
        t = tlsca.pins(Path(db.path).parent)
        pins = [x for x in (t.get("ca_spki_sha256"), t.get("ca_next_spki_sha256")) if x]
        out = joincodes.create(db, urls=_join_urls(db), pins=pins, cik=identity.key(Path(db.path).parent).public_b64, actor=req.actor, **p)
    except (joincodes.JoinError, FileNotFoundError) as e:
        raise core.ApiError(409 if isinstance(e, FileNotFoundError) else 400, "join_code", str(e))
    db.event("join_code_created", actor=req.actor, reason=out["label"] or "", join_code_id=out["id"], uses=out["uses"])
    return {**out, "command": "oarbank-node join"}


@handler("nodes.revoke_join_code", target_type="join_code",
         snapshot=lambda db, r: db.one("SELECT code_id, revoked_at, uses, max_uses FROM join_codes WHERE code_id=?", (r.target,)))
def _revoke_join_code(db, req):
    from . import joincodes
    try:
        out = joincodes.revoke(db, req.target or "", req.actor)
    except joincodes.JoinError as e:
        raise core.ApiError(404, "not_found", str(e))
    db.event("join_code_revoked", actor=req.actor, join_code_id=req.target)
    return out


def _user_code_enrollment(db, r):
    code = core.normalize_user_code(r.params.get("user_code") or r.target)
    return db.one("SELECT enrollment_id, hostname, peer_ip, status, user_code FROM enrollments WHERE user_code=? AND "
                  "status='pending' ORDER BY created_at DESC", (code,)) if code else None


@handler("nodes.admit_code", target_type="enrollment",
         impact=lambda db, r: {"enrollment": _user_code_enrollment(db, r)})
def _admit_code(db, req):
    return core.admit_by_user_code(db, req.params.get("user_code") or req.target or "", req.actor)


@handler("modules.cli_token", target_type="module", target=_module_name)
def _cli_token(db, req):
    """A one-hour token for `oarbank cli <module>`: the caller's role (at most operator), only that module's own
    operations and reads."""
    def fn(db, req, A):
        name = req.target or ""
        if not modstore_channel_current(db, name):
            raise A.AccessError("not_found", f"{name} has no current version", 404)
        account = req.actor if A.account(db, req.actor) else _default_account(db)
        if not account:
            raise A.AccessError("no_account", "create an account first: oarbank account create <name>", 404)
        role = "operator" if (req.role or "admin") in ("admin", "operator") else "viewer"
        out = A.new_token(db, account, f"cli {name}", role, 1 / 24, scope=f"module:{name}")
        db.event("token_created", actor=req.actor, reason=f"{out['token_id']} cli {name}")
        return out
    return _access(fn)(db, req)


def modstore_channel_current(db, name):
    from . import modstore
    return modstore.channel(db, name)["current"]


@handler("access.passkeys.remove", target_type="passkey")
def _pk_remove(db, req):
    def fn(db, req, A):
        row = db.one("SELECT account FROM passkeys WHERE credential_id=?", (req.target or "",))
        if not row:
            raise A.AccessError("no_passkey", req.target or "", 404)
        _self_or_admin(req, row["account"])
        db.x("DELETE FROM passkeys WHERE credential_id=?", (req.target,))
        db.event("passkey_removed", actor=req.actor, reason=f"{row['account']}: {req.target[:12]}")
        return {"removed": req.target}
    return _access(fn)(db, req)


# ------------------------------------------------------------------ module secrets (write-only)

SECRET_OP = "secrets.set"
SECRET_OPS = (SECRET_OP, "settings.secrets.set")      # the operations that take a value beside params


def _secret_scope(db, req) -> tuple[str, str, str]:
    """(module, secret name, node id or '') from target (the module) and params {name, node?}; nothing else."""
    from . import modsecrets
    extra = set(req.params) - {"name", "node"}
    if extra:
        raise OpError(400, "bad_params", f"{req.op} takes params name and node only (the value goes beside params, as "
                      f"`secret`), not {sorted(extra)}")
    name = req.params.get("name")
    if not req.target or not isinstance(name, str) or not name:
        raise OpError(400, "bad_params", f"{req.op}: target is the module, params.name the secret")
    try:
        return req.target, name, modsecrets.node_id(db, req.params.get("node"))
    except modsecrets.SecretError as e:
        raise OpError(e.status, e.code, e.detail)


def _secret_snap(db, req):
    from . import modsecrets
    module, name, node = _secret_scope(db, req)
    return {"secret": name, "scope": node or "module", **modsecrets.state(db, module, name, node)}


@handler(SECRET_OP, target_type="module", target=_module_name, snapshot=_secret_snap)
def _secret_set(db, req):
    from . import modsecrets
    module, name, node = _secret_scope(db, req)
    if req.secret is None:
        raise OpError(400, "secret_required", "send the value as `secret`, beside params (never inside params)")
    try:
        out = modsecrets.put(db, module, name, node, req.secret, req.actor)
    except modsecrets.SecretError as e:
        raise OpError(e.status, e.code, e.detail)
    db.event("secret_set", actor=req.actor, node_id=node or None, reason=f"{module}/{name} {out['fingerprint']}", module=module)
    return {"module": module, "name": name, "node": node or None, **out}


@handler("secrets.clear", target_type="module", target=_module_name, snapshot=_secret_snap)
def _secret_clear(db, req):
    from . import modsecrets
    module, name, node = _secret_scope(db, req)
    try:
        out = modsecrets.clear(db, module, name, node)
    except modsecrets.SecretError as e:
        raise OpError(e.status, e.code, e.detail)
    db.event("secret_cleared", actor=req.actor, node_id=node or None, reason=f"{module}/{name}", module=module)
    return {"module": module, "name": name, "node": node or None, **out}


@handler("audit.verify", target_type="audit")
def _verify(db, req):
    out = audit.verify(db)
    if req.params.get("digests") is not None:          # an off-host copy to check this host's chain against
        ext = audit.verify_against(db, req.params["digests"])
        out = {**out, "off_host": ext, "ok": out["ok"] and ext["ok"]}
    return out


# ------------------------------------------------------------------ module operations (D23)



def apply_effects(db: DB, module: str, decl, effs: list[dict], actor: str = "system") -> list[dict]:
    """Apply a module operation's effects on the single writer (inside the caller's transaction); only the
    kinds the operation declares, only on what the module owns (oarbankd.effects)."""
    try:
        return effects.apply(db, module, set(decl.effects), effs, actor=actor)
    except effects.EffectError as e:
        raise OpError(e.status, e.code, e.detail)


def module_handler(module: str, decl) -> Handler:
    from . import modcalls
    from .modulehost import ModuleError, ModuleUnavailable
    info = modcalls.info(module)

    def validate(req):
        if not decl.params_schema:
            return
        import jsonschema
        schema = json.loads((info.path / decl.params_schema).read_text(encoding="utf-8"))
        try:
            jsonschema.validate(req.params, schema)
        except jsonschema.ValidationError as e:
            raise OpError(422, "invalid_params", f"{'/'.join(str(x) for x in e.absolute_path)}: {e.message}")

    def call(db, verb, params):
        try:
            return modcalls.host(db).call(module, verb, params)
        except ModuleUnavailable as e:
            raise OpError(503, "module_unavailable", str(e)[:300], headers={"Retry-After": str(max(1, int(e.retry_after)))})
        except ModuleError as e:
            raise OpError(502, "module_error", f"{e.code}: {e.message}"[:300])

    def impact(db, req):
        validate(req)
        if not decl.preview:
            return {"effects": list(decl.effects)}
        plan = call(db, "op.plan", {"verb": decl.verb, "target": req.target, "params": req.params, "actor": req.actor})
        return {"module_plan": plan, "effects": list(decl.effects)}

    def prepare(db, req):
        validate(req)
        plan = (req.plan_impact or {}).get("module_plan")
        res = call(db, "op.apply", {"verb": decl.verb, "target": req.target, "params": req.params, "actor": req.actor,
                                     **({"plan": plan} if plan else {})})
        if res.get("response") == "errors":
            raise OpError(422, "module_rejected", "; ".join(f"{e.get('path', '')} {e.get('message', '')}".strip()
                                                             for e in res.get("errors") or [])[:300],
                          extra={"errors": res.get("errors") or []})
        for e in res.get("effects") or []:                   # refuse undeclared effects before any write
            if e.get("kind") not in set(decl.effects):
                raise OpError(502, "undeclared_effect", f"{module} asked for {e.get('kind')!r}")
        return res

    def apply(db, req):
        res = req.prepared or {}
        if not req.target and (res.get("result") or {}).get("campaign_id"):
            req.target = res["result"]["campaign_id"]          # a creation is audited against what it created
        return {"response": res.get("response", "toast"), "message": res.get("message", ""),
                "effects": apply_effects(db, module, decl, res.get("effects") or [], actor=req.actor),
                "result": res.get("result") or {}}

    return Handler(target_type="module", apply=apply, prepare=prepare, impact=impact,
                   snapshot=lambda db, r: {"settings": effects.module_settings(db, module)})


def register_module(module: str) -> list[str]:
    """Register a catalogued module's operations (registry + handlers). Returns the op ids."""
    from . import modcalls
    decls = modcalls.info(module).manifest.operations
    ops_ = registry.register_module_operations(module, decls)
    for op, d in zip(ops_, decls):
        HANDLERS[op.id] = module_handler(module, d)
    return [o.id for o in ops_]


def _register_catalogue():
    from . import modcalls
    for name in modcalls.CATALOG:
        register_module(name)


_register_catalogue()
