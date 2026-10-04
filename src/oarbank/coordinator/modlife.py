"""Module integrity checks and the module side of a coordinator move (module protocol: integrity.check,
move.preflight, move.postflight, move.cancelled; manifest `[coordinator.move]`).

- **Integrity.** `check(db, module, scope)` asks the module to verify its own state through host callbacks and adds
  the core's checks of the module's files. Every outcome is recorded in `module_checks`. The routine run (daily)
  opens an `integrity_failed:<module>` alert and resolves it when a later run passes.
- **Move rules.** `move_plan(db)` applies each module's rules: `carry` (the default) moves and is verified by digest,
  `rebuild` is not transferred (the module recreates it in move.postflight), `drop` is deleted on the target.
- **Coordinator platforms.** A module whose coordinator side does not run on the target's platform
  (requires.coordinator_platforms) blocks the move; a forced move disables it on the target, with an alert.
- **Move verbs.** The old coordinator calls `move.preflight` (blockers; effects while draining) and, after a cancel or
  an abort, `move.cancelled`. The target checks the copy with `integrity.check {scope: move_target}` before it reports
  ready (movepull.verify_modules); after taking over it calls `move.postflight` once per module.
Effects from the move verbs are limited to the module's `coordinator.move.effects` and are audited.
"""
import json

from . import audit, clock, effects, modcalls, modfiles, modstore
from .db import DB
from .modulehost import ModuleError, ModuleUnavailable

ROUTINE_EVERY_S = 24 * 3600
BLOCKER_WAIT_S = 600
PREFLIGHT_EVERY_S = 10
PLATFORM_BLOCKER = "core/coordinator_platform_unsupported"


def _caps(name: str) -> set:
    return set(modcalls.info(name).manifest.coordinator.capabilities)


def _move_section(name: str):
    return modcalls.info(name).manifest.coordinator.move


def modules_with(db: DB, cap: str) -> list[str]:
    return [n for n in modcalls.enabled(db) if cap in _caps(n)]


# ------------------------------------------------------------------ integrity

def _merge(module_res: dict | None, core: list[dict], error: str | None) -> dict:
    checks = list(core) + list((module_res or {}).get("checks") or [])
    if error:
        checks.append({"name": "module/answered", "ok": False, "severity": "error", "detail": error[:300]})
    ok = all(c.get("ok") or c.get("severity", "error") != "error" for c in checks)
    if module_res is not None and not module_res.get("ok", True):
        ok = False
    return {"ok": ok, "checks": checks, "fingerprint": (module_res or {}).get("fingerprint")}


def check(db: DB, name: str, scope: str = "on_demand", deep: bool = False, move_id: str | None = None,
          actor: str = "system", record: bool = True) -> dict:
    """Run one module's integrity check (when it has the capability) plus the core's file checks."""
    core = modfiles.core_checks(db, name, deep=deep)
    res, err = None, None
    if "integrity.check" in _caps(name):
        try:
            res = modcalls.call(db, name, "integrity.check", {"scope": scope, "deep": deep, "move_id": move_id, "now": clock.now()})
        except (ModuleUnavailable, ModuleError) as e:
            err = f"integrity.check: {e}"
    out = {"module": name, "version": modcalls.version_of(name), "scope": scope, **_merge(res, core, err)}
    if record:
        db.x("INSERT INTO module_checks(module,version,scope,move_id,at,ok,fingerprint,checks_json,actor) VALUES(?,?,?,?,?,?,?,?,?)",
             (name, out["version"], scope, move_id, clock.now(), int(out["ok"]), out["fingerprint"], json.dumps(out["checks"]), actor))
    return out


def check_all(db: DB, scope: str, deep: bool = False, move_id: str | None = None, actor: str = "system") -> dict:
    return {n: check(db, n, scope, deep, move_id, actor) for n in modcalls.enabled(db)}


def routine(db: DB) -> int:
    """The daily run (background loop): one check per enabled module that has not had a routine check for a day."""
    from .core import _alert, _resolve_alert
    n = 0
    for name in modcalls.enabled(db):
        last = db.one("SELECT at FROM module_checks WHERE module=? AND scope='routine' ORDER BY check_id DESC LIMIT 1", (name,))
        if last and clock.now() - last["at"] < ROUTINE_EVERY_S:
            continue
        r = check(db, name, "routine")
        n += 1
        if r["ok"]:
            _resolve_alert(db, f"integrity_failed:{name}", "coordinator")
        else:
            bad = "; ".join(f"{c['name']}: {c.get('detail', '')}" for c in r["checks"] if not c.get("ok") and c.get("severity", "error") == "error")
            _alert(db, f"integrity_failed:{name}", "coordinator", f"{name}: integrity check failed ({bad})"[:400], priority="high")
    return n


# ------------------------------------------------------------------ move rules

def _rule_for(rules, kind: str, key: str):
    for r in rules:
        if kind == "files" and r.files is not None and key.startswith(r.files):
            return r
        if kind == "store" and r.store is not None and key == r.store:
            return r
    return None


def move_plan(db: DB) -> dict:
    """What each module's rules leave behind: `items` (what is rebuilt or dropped, per rule) and `skip_blobs` (blobs
    named only by such files, so they are not transferred). Carry is the default for everything else."""
    items, skip, keep = [], set(), set()
    for name in modcalls.enabled(db):
        rules = [r for r in _move_section(name).rules if r.class_ != "carry"]
        files = db.q("SELECT path, digest, size FROM module_files WHERE module=?", (name,))
        for r in rules:
            if r.files is not None:
                hit = [f for f in files if _rule_for(rules, "files", f["path"]) is r]
                items.append({"module": name, "kind": "files", "selector": r.files, "class": r.class_,
                              "count": len(hit), "bytes": sum(f["size"] or 0 for f in hit)})
                skip |= {f["digest"] for f in hit}
            else:
                docs = db.q("SELECT LENGTH(doc_json) n FROM module_store WHERE module=? AND collection=?", (name, r.store))
                items.append({"module": name, "kind": "store", "selector": r.store, "class": r.class_,
                              "count": len(docs), "bytes": sum(d["n"] or 0 for d in docs)})
        keep |= {f["digest"] for f in files if not _rule_for(rules, "files", f["path"])}
    # a blob stays in the transfer if anything else names it
    for d in list(skip):
        if d in keep or db.one("SELECT 1 FROM module_files WHERE digest=? AND module NOT IN (%s)" %
                               ",".join("?" * len(modcalls.enabled(db))), (d, *modcalls.enabled(db))) \
                or db.one("SELECT 1 FROM datasets WHERE instr(files_json, ?)", (d,)) \
                or db.one("SELECT 1 FROM results WHERE instr(result_json, ?)", (d,)) \
                or db.one("SELECT 1 FROM jobs WHERE instr(spec_json, ?) OR instr(datasets_json, ?)", (d, d)):
            skip.discard(d)
    return {"items": items, "skip_blobs": sorted(skip)}


def apply_move_rules(db: DB, plan: dict) -> int:
    """On the new coordinator: remove what was rebuilt or dropped, and the rows of blobs that were not transferred."""
    n = 0
    for it in plan.get("items") or []:
        if it["class"] == "carry":
            continue
        if it["kind"] == "files":
            n += db.x("DELETE FROM module_files WHERE module=? AND substr(path, 1, ?) = ?", (it["module"], len(it["selector"]), it["selector"]))
        else:
            n += db.x("DELETE FROM module_store WHERE module=? AND collection=?", (it["module"], it["selector"]))
    from pathlib import Path
    for d in plan.get("skip_blobs") or []:
        b = db.one("SELECT path FROM blobs WHERE digest=?", (d,))
        if b and not (b["path"] and db.abs(b["path"]).is_file()):
            db.x("DELETE FROM blobs WHERE digest=?", (d,))
    return n


# ------------------------------------------------------------------ move verbs

def _apply(db: DB, name: str, verb: str, effs: list[dict], move_id: str, message: str = "") -> list[dict]:
    if not effs:
        return []
    allowed = set(_move_section(name).effects)
    rid = audit.request_id()
    try:
        with db.tx():
            done = effects.apply(db, name, allowed, effs, actor=f"module:{name}")
            audit.append(db, actor=f"module:{name}", source="system", operation=verb, category="modify", target_type="coordinator",
                         target_id=move_id, outcome="ok", request_id=rid, reason=message or None, after={"effects": done})
        return done
    except effects.EffectError as e:
        audit.append(db, actor=f"module:{name}", source="system", operation=verb, category="modify", target_type="coordinator",
                     target_id=move_id, outcome="rejected", request_id=rid, error=f"{e.code}: {e.detail}"[:300])
        db.event("module_fault", reason=f"{name} {verb}: {e.code}: {e.detail}"[:300])
        return []


def platform_blockers(db: DB, platform: str | None) -> dict:
    """{module: reason} for the enabled modules with an active version whose coordinator side does not run on
    `platform` (requires.coordinator_platforms); nothing while the target's platform is unknown."""
    return modstore.coordinator_blockers(db, platform) if platform else {}


def preflight(db: DB, move_id: str, to_url: str, not_before: float, phase: str, platform: str | None) -> dict:
    """Ask every module that can: {module: {blockers, checks, applied}}. A module that cannot answer blocks, and so does
    one whose coordinator side does not run on the target's `platform`."""
    out = {name: {"blockers": [{"code": PLATFORM_BLOCKER, "message": why}], "checks": [], "applied": []}
           for name, why in platform_blockers(db, platform).items()}
    for name in modules_with(db, "move.preflight"):
        entry = out.setdefault(name, {"blockers": [], "checks": [], "applied": []})
        try:
            r = modcalls.call(db, name, "move.preflight", {"move_id": move_id, "to_url": to_url, "not_before": not_before,
                                                            "phase": phase, "now": clock.now()})
        except (ModuleUnavailable, ModuleError) as e:
            entry["blockers"].append({"code": "core/module_unavailable", "message": str(e)[:300]})
            continue
        applied = _apply(db, name, "move.preflight", r.get("effects") or [], move_id, r.get("message", "")) if phase == "draining" else []
        entry["blockers"] += r.get("blockers") or []
        entry.update(checks=r.get("checks") or [], applied=applied, message=r.get("message", ""))
    return out


def disable_unsupported(db: DB) -> list[str]:
    """On a new coordinator: disable the enabled modules whose coordinator side does not run here (a forced move), each
    with an alert naming why. Returns their names."""
    from .core import _alert
    off = modstore.coordinator_blockers(db)
    for name, why in off.items():
        modstore.disable(db, name)
        _alert(db, f"coordinator_platform_unsupported:{name}", "coordinator", f"{name} was disabled: {why}"[:400], priority="high")
    return list(off)


def blockers(pre: dict) -> list[str]:
    return [f"{m}: {b.get('message') or b.get('code')}" for m, r in pre.items() for b in r.get("blockers") or []]


def cancelled(db: DB, move_id: str, reason: str) -> dict:
    out = {}
    for name in modules_with(db, "move.cancelled"):
        try:
            r = modcalls.call(db, name, "move.cancelled", {"move_id": move_id, "reason": reason, "now": clock.now()})
            out[name] = _apply(db, name, "move.cancelled", r.get("effects") or [], move_id, r.get("message", ""))
        except (ModuleUnavailable, ModuleError) as e:
            db.event("module_fault", reason=f"{name} move.cancelled: {e}"[:300])
    return out


def postflight(db: DB) -> dict:
    """On the new coordinator, once: every module with the capability gets what moved and what was skipped. A failed
    `error` check raises an alert (the move is committed; going back is a reverse move)."""
    from .core import _alert
    pend = db.get_setting("move_postflight_pending")
    if not pend:
        return {}
    out, left = {}, []
    for name in pend.get("modules") or []:
        if name not in modcalls.CATALOG or "move.postflight" not in _caps(name):
            continue
        skipped = [{k: v for k, v in it.items() if k != "module"} for it in pend.get("items") or [] if it["module"] == name]
        try:
            r = modcalls.call(db, name, "move.postflight", {"move_id": pend["move_id"], "from_url": pend.get("from_url") or "",
                                                             "epoch": int(pend.get("epoch") or 0), "skipped": skipped, "now": clock.now()})
        except (ModuleUnavailable, ModuleError) as e:
            left.append(name)                      # asked again on the next tick
            db.event("module_fault", reason=f"{name} move.postflight: {e}"[:300])
            continue
        applied = _apply(db, name, "move.postflight", r.get("effects") or [], pend["move_id"], r.get("message", ""))
        checks = r.get("checks") or []
        ok = all(c.get("ok") or c.get("severity", "error") != "error" for c in checks)
        db.x("INSERT INTO module_checks(module,version,scope,move_id,at,ok,fingerprint,checks_json,actor) VALUES(?,?,?,?,?,?,?,?,?)",
             (name, modcalls.version_of(name), "move_postflight", pend["move_id"], clock.now(), int(ok), None, json.dumps(checks), "oarbankd"))
        if not ok:
            _alert(db, f"integrity_failed:{name}", "coordinator", f"{name}: postflight after move {pend['move_id']} failed", priority="high")
        out[name] = {"ok": ok, "applied": applied}
    db.set_setting("move_postflight_pending", {**pend, "modules": left} if left else None)
    if not left:
        db.event("coordinator_move_postflight", reason=f"{pend['move_id']}: {len(out)} modules")
    return out


def runtimes_ok(db: DB) -> list[str]:
    """Rebuild the coordinator runtimes (module venvs) this coordinator cannot use: one whose interpreter does not
    resolve here (a moved venv points at the old machine's Python), or resolves to another interpreter than the
    running one (built by an earlier coordinator build: an in-place update leaves that build beside the new one, and
    the module sandbox grants only the running interpreter, so the module could not even start). Runs at every start.
    Returns the modules rebuilt; one that cannot be rebuilt is reported and left for its module host to fault."""
    from ..platform import files
    mine = files.running_interpreter()
    done = []
    for r in db.q("SELECT name, version, path FROM modules WHERE runtime IS NOT NULL"):
        p = db.abs(r["path"])
        if not (p / "requirements.txt").exists():
            continue
        if files.venv_interpreter(p / ".venv") == mine:
            continue
        try:
            files.remove_tree(p / ".venv")
            modstore._build_runtime(p)
        except (OSError, modstore.InstallError) as e:
            db.event("module_runtime_failed", reason=f"{r['name']}@{r['version']}: {e}"[:500])
            continue
        db.event("module_runtime_rebuilt", reason=f"{r['name']}@{r['version']}")
        done.append(f"{r['name']}@{r['version']}")
    return done
