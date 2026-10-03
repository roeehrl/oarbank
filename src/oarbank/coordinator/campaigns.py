"""The campaign ticker (D22): the core's only driver of module-owned work.

Every few seconds each running campaign whose module advertises `campaign.tick` is offered to its module
with the campaign and all its jobs (and their canonical results). The module answers with effects, limited
to the kinds its manifest declares in `coordinator.campaign_effects`; they are applied on the single writer
with one audit row per tick that changed something. The core never interprets what a campaign means: a
parameter search, a benchmark sweep or a backfill are all the owning module's business.

Module faults leave the campaign as it is (it is ticked again later) and are never charged to anyone.
"""
import time

from . import audit, clock, effects, modcalls, placement
from .db import DB, jl
from .modulehost import ModuleError, ModuleUnavailable

FAULT_EVENT_EVERY_S = 300.0
_last_fault: dict = {}


def campaign_row(db: DB, c: dict) -> dict:
    """A campaign as modules see it (CampaignTickParams.campaign) and the API returns it; `placement` is
    placement.summary (null: nothing is kept on one platform class)."""
    return {"campaign_id": c["campaign_id"], "module": c["module"], "name": c["name"], "state": c["state"],
            "priority": c["priority"], "weight": c["weight"], "labels": jl(c["labels_json"], {}) or {},
            "created_at": c["created_at"], "finished_at": c["finished_at"], "placement": placement.summary(db, c["campaign_id"])}


def campaign_jobs(db: DB, campaign_id: str) -> list[dict]:
    """The campaign's evaluations with their canonical results, as CampaignJob rows. A split evaluation is its tail
    job (kind 'eval'); the head stage's job (kind 'call') is an input to it, not an evaluation."""
    rows = db.q("SELECT j.job_id, j.job_key, j.state, j.kind, j.stage, j.dataset_id, j.labels_json, j.done_at, j.group_key, "
                "r.value, r.digest, r.fields_json, r.platform FROM jobs j LEFT JOIN results r ON r.result_id=j.canonical_result_id "
                "WHERE j.campaign_id=? AND j.kind='eval' "
                "ORDER BY j.job_id", (campaign_id,))
    return [{"job_id": r["job_id"], "job_key": r["job_key"], "state": r["state"], "kind": r["kind"], "stage": r["stage"],
             "dataset_id": r["dataset_id"], "labels": jl(r["labels_json"], {}) or {}, "done_at": r["done_at"],
             "value": r["value"] if r["state"] == "done" else None, "digest": r["digest"] if r["state"] == "done" else None,
             "fields": (jl(r["fields_json"], {}) or {}) if r["state"] == "done" else {},
             "platform": r["platform"] if r["state"] == "done" else None, "group": r["group_key"]} for r in rows]


def _fault(db: DB, cid: str, module: str, e: Exception):
    t = time.monotonic()
    if t - _last_fault.get(cid, -1e9) >= FAULT_EVENT_EVERY_S:
        _last_fault[cid] = t
        db.event("module_fault", campaign_id=cid, reason=f"{module} campaign.tick: {e}"[:300])


def tick_one(db: DB, c: dict, now: float | None = None) -> list[dict]:
    """Tick one campaign; returns the applied effect records (empty when the module had nothing to do)."""
    module, cid = c["module"], c["campaign_id"]
    try:
        res = modcalls.tick(db, module, campaign_row(db, c), campaign_jobs(db, cid), now or clock.now())
    except (ModuleUnavailable, ModuleError) as e:
        _fault(db, cid, module, e)
        return []
    effs = res.get("effects") or []
    if not effs:
        return []
    allowed = set(modcalls.info(module).manifest.coordinator.campaign_effects)
    rid = audit.request_id()
    try:
        with db.tx():
            cur = db.one("SELECT state FROM campaigns WHERE campaign_id=?", (cid,))
            if not cur or cur["state"] != "running":
                return []                           # paused or cancelled while the module was thinking
            done = effects.apply(db, module, allowed, effs, actor=f"module:{module}")
            db.x("UPDATE campaigns SET ticked_at=? WHERE campaign_id=?", (clock.now(), cid))
            audit.append(db, actor=f"module:{module}", source="scheduler", operation="campaign.tick", category="modify",
                         target_type="campaign", target_id=cid, outcome="ok", request_id=rid,
                         reason=(res.get("message") or None), after={"effects": done})
        return done
    except effects.EffectError as e:
        audit.append(db, actor=f"module:{module}", source="scheduler", operation="campaign.tick", category="modify",
                     target_type="campaign", target_id=cid, outcome="rejected", request_id=rid,
                     error=f"{e.code}: {e.detail}"[:300], after={"effects": [x.get("kind") for x in effs]})
        _fault(db, cid, module, e)
        return []


def tick_all(db: DB, now: float | None = None) -> int:
    """Tick every running campaign of a module that can tick. Call outside any transaction."""
    n = 0
    for c in db.q("SELECT * FROM campaigns WHERE state='running' ORDER BY priority DESC, created_at"):
        if c["module"] not in modcalls.CATALOG:
            continue
        if not modcalls.has_capability(c["module"], "campaign.tick"):
            n += _finish_if_drained(db, c)
            continue
        if tick_one(db, c, now):
            n += 1
    return n


def _finish_if_drained(db: DB, c: dict) -> int:
    """A campaign of a module that does not tick is done once it has jobs and none is open."""
    with db.tx():
        r = db.one("SELECT COUNT(*) n, COALESCE(SUM(state IN ('pending','leased')),0) open FROM jobs WHERE campaign_id=?",
                   (c["campaign_id"],))
        if not r["n"] or r["open"]:
            return 0
        db.x("UPDATE campaigns SET state='done', finished_at=? WHERE campaign_id=? AND state='running'", (clock.now(), c["campaign_id"]))
        db.event("campaign_done", campaign_id=c["campaign_id"], reason=f"{c['name']}: all {r['n']} jobs settled")
    return 1


def summary(db: DB, campaign_id: str) -> dict | None:
    """A campaign with its job counts (the generic view the console and oarbank show)."""
    c = db.one("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,))
    if not c:
        return None
    jobs = db.one("SELECT COUNT(*) n, SUM(state='done') d, SUM(state='pending') p, SUM(state='leased') l, "
                  "SUM(state IN ('failed','quarantined')) f, SUM(state='cancelled') x FROM jobs WHERE campaign_id=?",
                  (campaign_id,))
    return {**campaign_row(db, c), "ticked_at": c["ticked_at"], "created_by": c["created_by"],
            "jobs": {k: v or 0 for k, v in jobs.items()}}
