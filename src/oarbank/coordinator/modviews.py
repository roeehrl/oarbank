"""Module views (UI contract 1): oarbankd, never the console, asks modules to compute their declared views
(`ui.view.compute`) when the inputs' data version changes, validates the result against the declaration,
and stores it in `module_views`. The console reads the table like any other row, so a module is never on
the render path; when it is down the last values stay, marked stale.
"""
import json
import time
import zlib

from oarbank_sdk import ui as U

from . import modcalls
from .settings.store import fleet_value
from .db import DB, jl
from .modulehost import ModuleError, ModuleUnavailable

DEBOUNCE_S = 30.0
INPUT_ROWS = 5000
# the datasets a module sees (as host.datasets.query): its own and the operator's, never another module's
VISIBLE = "(module=? OR module IS NULL OR module='')"


def _crc(*parts) -> int:
    return zlib.crc32("|".join(str(p) for p in parts).encode())


def _data_version(db: DB, module: str, inputs: list[str], campaign: str | None = None) -> int:
    parts = []
    for inp in inputs:
        if inp == "results":
            r = db.one("SELECT COALESCE(MAX(result_id),0) m, COUNT(*) n FROM results WHERE module=?", (module,))
        elif inp == "jobs" and campaign:
            r = db.one("SELECT COALESCE(MAX(job_id),0) m, COALESCE(SUM(state='done'),0) || '/' || COALESCE(SUM(state IN "
                       "('pending','leased')),0) || '/' || COALESCE(MAX(canonical_result_id),0) n FROM jobs WHERE campaign_id=?",
                       (campaign,))
        elif inp == "jobs":
            r = db.one("SELECT COALESCE(MAX(job_id),0) m, SUM(state='done') n FROM jobs WHERE module=?", (module,))
        elif inp == "campaigns":
            r = db.one("SELECT COUNT(*) m, group_concat(campaign_id || state, ',') n FROM "
                       "(SELECT campaign_id, state FROM campaigns WHERE module=? ORDER BY campaign_id)", (module,))
            r = {"m": r["m"], "n": _crc(r["n"])}
        elif inp.startswith("store:"):
            coll = inp.split(":", 1)[1]
            if campaign:
                r = db.one("SELECT COUNT(*) m, COALESCE(MAX(updated_at),0) n FROM module_store WHERE module=? AND collection=? "
                           "AND json_extract(doc_json, '$.campaign_id')=?", (module, coll, campaign))
            else:
                r = db.one("SELECT COUNT(*) m, COALESCE(MAX(updated_at),0) n FROM module_store WHERE module=? AND collection=?",
                           (module, coll))
        elif inp.startswith("datasets:"):
            r = db.one("SELECT COUNT(*) m, COALESCE(MAX(created_at),0) || '/' || COALESCE(SUM(length(meta_json)),0) n FROM datasets "
                       "WHERE kind=? AND " + VISIBLE, (inp.split(":", 1)[1], module))
        elif inp == "module_settings":
            r = {"m": zlib.crc32(json.dumps((fleet_value(db, "module.settings", module) or {}), sort_keys=True).encode()), "n": 0}
        else:
            r = {"m": 0, "n": 0}
        parts.append(f"{inp}={r['m']}/{r['n']}")
    return _crc(campaign or "", *parts)


def _inputs(db: DB, module: str, inputs: list[str], campaign: str | None = None) -> dict:
    from .campaigns import campaign_jobs, campaign_row
    out = {}
    if campaign:
        c = db.one("SELECT * FROM campaigns WHERE campaign_id=?", (campaign,))
        out["campaign"] = campaign_row(db, c) if c else {"campaign_id": campaign}
    for inp in inputs:
        if inp == "results":
            rows = db.q("SELECT r.job_id, r.value, r.fields_json, r.at, r.node_id, j.spec_json FROM results r "
                        "JOIN jobs j ON j.job_id=r.job_id WHERE r.module=? AND r.accepted=1 ORDER BY r.result_id DESC LIMIT ?",
                        (module, INPUT_ROWS))
            out["results"] = [{"job_id": r["job_id"], "value": r["value"], "fields": jl(r["fields_json"], {}), "at": r["at"],
                               "node": r["node_id"], "key_inputs": (jl(r["spec_json"], {}) or {}).get("payload", jl(r["spec_json"], {}))}
                              for r in rows]
        elif inp == "jobs" and campaign:
            out["jobs"] = campaign_jobs(db, campaign)
        elif inp == "jobs":
            out["jobs"] = db.q("SELECT job_id, state, kind, dataset_id, created_at, done_at FROM jobs WHERE module=? "
                               "ORDER BY job_id DESC LIMIT ?", (module, INPUT_ROWS))
        elif inp == "campaigns":
            out["campaigns"] = [campaign_row(db, c) for c in db.q("SELECT * FROM campaigns WHERE module=? ORDER BY created_at DESC LIMIT ?",
                                                              (module, INPUT_ROWS))]
        elif inp.startswith("store:"):
            coll = inp.split(":", 1)[1]
            rows = db.q("SELECT key, doc_json FROM module_store WHERE module=? AND collection=?" +
                        (" AND json_extract(doc_json, '$.campaign_id')=?" if campaign else "") + " ORDER BY key LIMIT ?",
                        (module, coll, *( [campaign] if campaign else [] ), INPUT_ROWS))
            out[inp] = [{**json.loads(r["doc_json"]), "_key": r["key"]} for r in rows]
        elif inp.startswith("datasets:"):
            out[inp] = [{**d, "meta": jl(d.pop("meta_json", None), {}), "owner": "module" if d.pop("module") else "operator"}
                        for d in db.q("SELECT dataset_id, kind, module, meta_json, created_at FROM datasets WHERE kind=? AND "
                                      + VISIBLE + " ORDER BY created_at DESC LIMIT ?", (inp.split(":", 1)[1], module, INPUT_ROWS))]
        elif inp == "module_settings":
            out["module_settings"] = (fleet_value(db, "module.settings", module) or {})
    return out


CAMPAIGN_VIEW_LIMIT = 40          # campaign-scoped views are kept for the most recent campaigns (and every running one)


def _scopes(db: DB, module: str, decl: U.ViewDecl) -> list[str]:
    """params_hash values to materialize: '' for a module-wide view; one per campaign for a view with a
    `campaign` param (running campaigns, then the most recent others)."""
    if "campaign" not in decl.params:
        return [""]
    return [r["campaign_id"] for r in db.q(
        "SELECT campaign_id FROM campaigns WHERE module=? AND state!='cancelled' "
        "ORDER BY state='running' DESC, created_at DESC LIMIT ?", (module, CAMPAIGN_VIEW_LIMIT))]


def refresh(db: DB, force: bool = False, now: float | None = None) -> int:
    """Recompute views whose inputs changed (debounced) or whose refresh_s elapsed. Call outside any
    transaction. Returns the number of views written."""
    now = now or time.time()
    n = 0
    for name, info in modcalls.CATALOG.items():
        views = info.manifest.ui.views
        if not views:
            continue
        for vid, decl in views.items():
            for scope in _scopes(db, name, decl):
                n += _refresh_one(db, name, vid, decl, scope, force, now)
    return n


def _refresh_one(db: DB, name: str, vid: str, decl: U.ViewDecl, scope: str, force: bool, now: float) -> int:
    campaign = scope or None
    dv = _data_version(db, name, decl.inputs, campaign)
    row = db.one("SELECT * FROM module_views WHERE module=? AND view_id=? AND params_hash=?", (name, vid, scope))
    due = force or row is None or (row["data_version"] != dv and now - (row["computed_at"] or 0) >= DEBOUNCE_S) \
        or bool(decl.refresh_s and now - (row["computed_at"] or 0) >= decl.refresh_s)
    if row is not None and row["error_at"] and now - row["error_at"] < DEBOUNCE_S and not force:
        due = False
    if not due:
        return 0
    try:
        res = modcalls.host(db).call(name, "ui.view.compute",
                                     {"view_id": vid, "params": {"campaign": campaign} if campaign else {},
                                      "inputs": _inputs(db, name, decl.inputs, campaign), "data_version": dv})
        doc = U.validate_view(decl, res)
    except (ModuleUnavailable, ModuleError, ValueError) as e:
        with db.tx():
            db.x("INSERT INTO module_views(module,view_id,params_hash,data_version,computed_at,doc_json,error,error_at) "
                 "VALUES(?,?,?,NULL,NULL,NULL,?,?) ON CONFLICT(module,view_id,params_hash) DO UPDATE SET "
                 "error=excluded.error, error_at=excluded.error_at", (name, vid, scope, str(e)[:300], now))
        return 0
    with db.tx():
        db.x("INSERT INTO module_views(module,view_id,params_hash,data_version,computed_at,doc_json,error,error_at) "
             "VALUES(?,?,?,?,?,?,NULL,NULL) ON CONFLICT(module,view_id,params_hash) DO UPDATE SET "
             "data_version=excluded.data_version, computed_at=excluded.computed_at, doc_json=excluded.doc_json, "
             "error=NULL, error_at=NULL", (name, vid, scope, dv, now, json.dumps(doc)))
    return 1
