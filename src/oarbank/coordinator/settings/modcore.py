"""The core keys every module has, set as `[module] <key>` (docs/design/settings.md, "Module settings"): what
`settings.apply` checks beyond a key's type, and the effects a change has once it is written.

- `enabled`: off at fleet scope is the module's kill switch; off at a group or a node keeps the module's work and
  services off those nodes only. Live attempts on the nodes where it turned off are released (`module_disabled`), and
  each node's heartbeat lists the modules it must not run (`modules_disabled`), so their services stop.
- `services.disabled`: the module's services a node does not run; a change re-doctors and re-certifies that module (and
  only that module) on the nodes whose value changed (apply.py's `redoctor` hook).
- `pipeline`: `split` needs a module whose stages form a chain; switching to it splits the module's queued jobs.
- `replica_rate`: a module's own rate; the higher of the fleet's and the module's applies (merge max)."""
from . import resolve as V


def check(db, key: str, module: str, value) -> str | None:
    """Why a value of a module's core key cannot be set (None: it can)."""
    if key == "pipeline" and value == "split":
        from .. import modcalls
        if module not in modcalls.CATALOG or not modcalls.info(module).splittable:
            return f"{module} has no stage chain to split (split needs a module whose stages run one after another)"
    return None


def after_commit(db, changes: list[dict], actor: str) -> dict:
    """Run the fleet-wide effects of a committed change set's module core keys (inside its transaction); the per-node
    ones (releasing a module's attempts where it turned off) run in apply.refresh, for group moves too."""
    out = {"expanded": 0}
    snap = None
    for c in changes:
        if c["key"] == "enabled" and c["scope"] == "fleet":
            snap = snap or V.snapshot(db)
            on = V.resolve(snap, None, "enabled", c["module"])["value"]
            db.event("module_enabled" if on else "module_disabled", actor=actor, module=c["module"],
                     reason=f"{c['module']}: {'on' if on else 'off'} for the fleet")
        if c["key"] == "pipeline":
            snap = snap or V.snapshot(db)
            mode = V.resolve(snap, None, "pipeline", c["module"])["value"]
            n = split_queued(db, c["module"]) if mode == "split" else 0
            out["expanded"] += n
            db.event("pipeline_changed", actor=actor, reason=f"{c['module']}: {mode} ({n} queued jobs split)", module=c["module"])
    return out


def release(db, module: str, node_id: str | None = None) -> int:
    """End the module's live attempts (on one node, or everywhere) as released, not failed, and revoke them there."""
    from .. import core
    sql = ("SELECT a.attempt_id, a.node_id FROM attempts a JOIN jobs j ON j.job_id=a.job_id WHERE a.state='live' "
           "AND j.module=?" + (" AND a.node_id=?" if node_id else ""))
    rows = db.q(sql, (module, node_id) if node_id else (module,))
    for a in rows:
        core._end_attempt(db, a["attempt_id"], "released", "module_disabled", count_failure=False)
        core._push(db, a["node_id"], "revoke", a["attempt_id"])
    return len(rows)


def split_queued(db, module: str) -> int:
    """Split every queued (pending, never started) eval job of the module into its stage chain."""
    from .. import core
    n = 0
    for j in db.q("SELECT job_id FROM jobs WHERE module=? AND kind='eval' AND state='pending' AND depends_on IS NULL "
                  "AND stage IS NULL AND NOT EXISTS (SELECT 1 FROM attempts a WHERE a.job_id=jobs.job_id)", (module,)):
        if core.expand_pipeline(db, j["job_id"]):
            n += 1
    return n
