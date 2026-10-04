"""Placement: each unit of work stays on one platform class (PLAN D33; docs/design/per-platform-modules.md 3.5;
oarbank-sdk spec/platforms.md, "Placement").

A **unit** is a campaign (`c:<cid>`), a job group in it (`c:<cid>/g:<group>`), the jobs of one dataset in it
(`c:<cid>/d:<dataset>`) or one pipeline (`c:<cid>/p:<tail job id>`: its head and tail, replicas and tie-breaks). Each
unit has one row in `placement_bindings`: its mix, the classes it may bind to (`feasible`: where every stage it runs, its
jobs' platforms and its datasets' platforms allow) and its binding: `unbound`, `soft`, `hard` or `pinned`. A split
pipeline whose stage placement is stricter than its unit's mix has a sub-unit under it (`parent`); a job is checked
against its unit and that parent.

- claim() binds an unbound unit to the claiming node's class (soft, `first_claim`); `bind = "capacity"` binds it when it
  is created to the feasible class with the most free certified CPU (soft, `capacity`); a pin binds it for good.
- The first accepted result, or a result-cache hit, makes a binding hard.
- The reaper releases a soft first-claim binding whose attempts all ended without a result, and handles a unit whose
  class has had no eligible node for `stranded_after_s`: a soft binding is released, `rebind = "never"` (and every
  pinned unit) raises the alert `placement_stranded:<unit>`, `rebind = "if-stranded"` rebinds to the best feasible class
  and runs the unit's finished jobs again there.

Everything a predicate needs is resolved here into plain data (`facts`), so claim() and explain decide alike.
"""
import json

from oarbank_sdk import manifest as mf
from oarbank_sdk import platform as pf

from . import clock, config as C, modcalls, predicates
from .db import DB, jl

UNIT_RANK = {"campaign": 2, "group": 1, "dataset": 1, "pipeline": 0}     # what a campaign may tighten (never loosen)
BINDS = ("capacity", "first-claim", "explicit")
GROUP_MAX = 64


class PlacementError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail = status, code, detail


# ---------------------------------------------------------------------------- policies

def manifest_policy(man: mf.Manifest) -> dict | None:
    """The module's [placement] as the scheduler applies it, or None (mix `any`: nothing to keep together)."""
    p = man.placement
    if p is None or pf.normalize(p.mix) == "any":
        return None
    return {"mix": pf.normalize(p.mix), "unit": p.unit, "bind": p.effective_bind(), "rebind": p.rebind,
            "stranded_after_s": p.stranded_after_s, "pin": None}


def campaign_policy(module: str, arg) -> dict | None:
    """A new campaign's placement: the manifest's, tightened by campaigns.create `placement {mix, unit, bind, pin}`,
    which may be stricter, never looser."""
    man = modcalls.info(module).manifest
    base = manifest_policy(man)
    if arg is None:
        return base
    if not isinstance(arg, dict) or not isinstance(arg.get("mix"), str) or set(arg) - {"mix", "unit", "bind", "pin"}:
        raise PlacementError(422, "bad_placement", "placement is {mix, unit?, bind?, pin?}")
    mix = pf.normalize(arg["mix"])
    unit = arg.get("unit") or (base or {}).get("unit") or "campaign"
    if unit not in UNIT_RANK or arg.get("bind") not in (None, *BINDS):
        raise PlacementError(422, "bad_placement", f"unit {unit!r}, bind {arg.get('bind')!r}")
    if base and (pf.looser(mix, base["mix"]) or UNIT_RANK[unit] < UNIT_RANK[base["unit"]]
                 or (UNIT_RANK[unit] == UNIT_RANK[base["unit"]] and unit != base["unit"])):
        raise PlacementError(422, "placement_looser_than_manifest",
                             f"{mix}/{unit} keeps less together than the module's [placement] {base['mix']}/{base['unit']}")
    pin = arg.get("pin")
    if mix == "any":
        if pin is not None:
            raise PlacementError(422, "bad_placement", "mix any has no class to pin")
        return None
    if pin is not None and pin not in pf.feasible_classes(man.requires.platforms, mix=mix):
        raise PlacementError(422, "placement_infeasible", f"pin {pin!r} is not a {mix} class of the module's platforms "
                             f"{pf.feasible_classes(man.requires.platforms, mix=mix)}")
    defaults = mf.Placement(mix=mix, unit=unit)
    return {"mix": mix, "unit": unit, "bind": arg.get("bind") or ((base or {}).get("bind") if base and base["unit"] == unit
                                                                     else defaults.effective_bind()),
            "rebind": (base or {}).get("rebind") or defaults.rebind,
            "stranded_after_s": (base or {}).get("stranded_after_s") or defaults.stranded_after_s, "pin": pin}


def check_item(module: str, item: dict) -> tuple[str | None, list[str]]:
    """A jobs.enqueue item's `group` and `platforms` (host capability placement.v1), validated."""
    group, plats = item.get("group"), item.get("platforms") or []
    if group is not None and not (isinstance(group, str) and 0 < len(group) <= GROUP_MAX):
        raise PlacementError(422, "bad_group", f"group {group!r}: 1-{GROUP_MAX} characters")
    if not isinstance(plats, list) or not all(pf.is_key(p) for p in plats):
        raise PlacementError(422, "bad_platforms", f"platforms {plats!r}: platform tokens or OS names")
    if plats and not any(pf.matches(p, plats) for p in modcalls.info(module).manifest.requires.platforms):
        raise PlacementError(422, "placement_infeasible", f"platforms {plats}: the module runs on none of them")
    return group, list(plats)


def check_stage(module: str, item: dict) -> str | None:
    """A jobs.enqueue item's `stage` (host capability jobs.stage): a standalone stage of the module, whose platforms
    leave one of the item's `platforms`. None: the item names no stage (the default stage, or the chain when split)."""
    stage = item.get("stage")
    if stage is None:
        return None
    man = modcalls.info(module).manifest
    if not isinstance(stage, str) or stage not in man.standalone_stages():
        raise PlacementError(422, "bad_stage", f"stage {stage!r}: one of the standalone stages {man.standalone_stages()} "
                             "(a chain stage cannot run alone)")
    plats = man.stage(stage).requires.platforms or man.requires.platforms
    if item.get("platforms") and not any(pf.matches(p, item["platforms"]) for p in plats):
        raise PlacementError(422, "placement_infeasible", f"platforms {item['platforms']}: stage {stage!r} runs on {plats}")
    return stage


def dataset_platform(module: str, kind: str | None, platform) -> str | None:
    """datasets.create `platform`: a token the module runs on; kinds in [datasets].platform_bound must give one."""
    man = modcalls.info(module).manifest
    if platform is None:
        if kind in man.datasets.platform_bound:
            raise PlacementError(422, "dataset_platform_required", f"datasets of kind {kind!r} are platform-bound: give `platform`")
        return None
    if platform not in man.requires.platforms:
        raise PlacementError(422, "bad_dataset_platform", f"{platform!r} is not one of the module's platforms")
    return platform


# ---------------------------------------------------------------------------- units

def _row(r: dict | None) -> dict | None:
    return {**r, "feasible": jl(r["feasible_json"], [])} if r else None


def binding(db: DB, unit: str | None, cache: dict | None = None) -> dict | None:
    if unit is None:
        return None
    if cache is not None and unit in cache:
        return cache[unit]
    r = _row(db.one("SELECT * FROM placement_bindings WHERE unit=?", (unit,)))
    if cache is not None:
        cache[unit] = r
    return r


def chain(db: DB, unit: str | None, cache: dict | None = None) -> list[dict]:
    """The job's unit and its parent, most specific first."""
    out = []
    b = binding(db, unit, cache)
    while b is not None:
        out.append(b)
        b = binding(db, b["parent"], cache)
    return out


def dataset_platforms(db: DB, j: dict, cache: dict | None = None) -> list[str]:
    """The platforms of the platform-bound datasets the job reads (each must be the node's)."""
    ids = sorted(set(jl(j.get("datasets_json"), []) or []) | ({j["dataset_id"]} if j.get("dataset_id") else set()))
    if not ids:
        return []
    key = ("datasets",) + tuple(ids)
    if cache is not None and key in cache:
        return cache[key]
    out = sorted({r["platform"] for r in db.q(f"SELECT platform FROM datasets WHERE platform IS NOT NULL AND dataset_id IN "
                                              f"({','.join('?' * len(ids))})", ids)})
    if cache is not None:
        cache[key] = out
    return out


def unregistered(db: DB, j: dict, cache: dict | None = None) -> list[str]:
    """The datasets the job names that are not registered (yet): a golden waits for the pinned datasets a bootstrap job
    brings."""
    ids = sorted(set(jl(j.get("datasets_json"), []) or []))
    if not ids:
        return []
    key = ("unregistered",) + tuple(ids)
    if cache is not None and key in cache:
        return cache[key]
    have = {r["dataset_id"] for r in db.q(f"SELECT dataset_id FROM datasets WHERE dataset_id IN ({','.join('?' * len(ids))})", ids)}
    out = [d for d in ids if d not in have]
    if cache is not None:
        cache[key] = out
    return out


def _ahead(j: dict) -> list[str]:
    """The stages the job and what it feeds still have to run: a head stage's job (kind call) runs its tail after it."""
    mi = modcalls.CATALOG.get(j["module"])
    if mi is None:
        return []
    if j["kind"] == "call" and mi.chain:
        return list(mi.chain)
    return [j["stage"] or mi.single_stage]


def _serving(module: str, stage: str | None):
    """Whether a node can serve the module for jobs of `stage`: certified, or certifying recently (core._can_serve); a
    bootstrap stage on any node whose module is certified or certifying and whose agent applies the bootstrap grants."""
    from . import core, modsandbox
    if modcalls.stage_bootstrap(module, stage):
        return lambda n, st: predicates.module_serves({"bootstrap": True}, st.get("state"), modsandbox.bootstrap_enforced(n))
    return lambda n, st: core._can_serve(st)


def classes_running(db: DB, module: str, stages, mix: str, online: bool = False, cache: dict | None = None) -> set:
    """The classes under `mix` where, for every one of `stages`, a ready node that can serve the module for that stage
    (_serving) runs it (its platforms) and holds its pools and capabilities. `online`: only active nodes that heartbeat
    recently (a unit's class able to take its work now). Binding, the capacity choice and the stranded check all use this
    one test, so a unit never binds where a stage of its work can never run."""
    from . import core
    stages = tuple(sorted(set(stages)))
    key = ("running", module, mix, stages, online)
    if cache is not None and key in cache:
        return cache[key]
    mi = modcalls.info(module)
    sql = ("SELECT node_id, platform, modules_json, capacity_json, policy_json, doctor_json, facts_json FROM nodes "
           "WHERE lifecycle='ready' AND platform IS NOT NULL")
    args: tuple = ()
    if online:
        sql += " AND desired_state='active' AND last_heartbeat_at>?"
        args = (clock.now() - C.OFFLINE_AFTER,)
    nodes = [(n, (jl(n["modules_json"], {}) or {}).get(module, {}), predicates.node_capabilities(n, module))
             for n in db.q(sql, args)]
    out = None
    for st in stages:
        res, plats = mi.stage_resources(st), modcalls.stage_platforms(module, st)
        caps, serves = set(modcalls.stage_capabilities(module, st)), _serving(module, st)
        here = {pf.class_key(n["platform"], mix) for n, state, have in nodes
                if serves(n, state) and (not plats or n["platform"] in plats) and core._pools_fit(n, res) and caps <= have}
        out = here if out is None else out & here
    out = out or set()
    if cache is not None:
        cache[key] = out
    return out


def _servable(db: DB, j: dict, mix: str, cache: dict | None) -> set:
    """The classes where every stage ahead of the job has a node to run it: an unbound unit binds only there, so a head
    never binds where its tail cannot run (the feasible set's "eligible certified nodes", per-platform-modules.md 3.1)."""
    return classes_running(db, j["module"], _ahead(j), mix, cache=cache)


def unit_stages(db: DB, b: dict) -> list[str]:
    """The stages still ahead of a unit's pending work (none pending: the stages its finished jobs ran)."""
    jobs = unit_jobs(db, b["unit"], ("pending",)) or unit_jobs(db, b["unit"], ("leased", "done"))
    return sorted({st for j in jobs for st in _ahead(j)})


def facts(db: DB, j: dict, cache: dict | None = None) -> dict:
    """What the placement predicates decide on (predicates.placement): the job's platforms, its datasets' platforms, the
    datasets it names that are not registered, and its unit chain {unit, mix, class, state, bind, feasible}. An unbound
    unit's `feasible` keeps only the classes where every stage ahead of the job has a node to run it (_servable)."""
    units = []
    for b in chain(db, j.get("placement_unit"), cache):
        u = {k: b[k] for k in ("unit", "mix", "class", "state", "bind", "feasible")}
        if u["class"] is None:
            u["feasible"] = sorted(set(u["feasible"]) & _servable(db, j, u["mix"], cache))
        units.append(u)
    return {"platforms": jl(j.get("platforms_json"), []) or [], "dataset_platforms": dataset_platforms(db, j, cache),
            "unregistered": unregistered(db, j, cache),
            "units": units}


def classes(man: mf.Manifest, stages: list[str], platforms: list[str], dataset_plats: list[str], mix: str) -> list[str]:
    """The classes a job may run in under `mix`: every stage it runs, its own platforms and each of its datasets'."""
    plats = [p for p in man.requires.platforms if all(p == d for d in dataset_plats)]
    by = {s.name: s for s in man.stages}
    return pf.feasible_classes(plats, [by[s].requires.platforms for s in stages if s in by], platforms, mix)


def _policy_of(db: DB, campaign_id: str) -> dict | None:
    c = db.one("SELECT placement_json FROM campaigns WHERE campaign_id=?", (campaign_id,))
    return jl(c["placement_json"]) if c else None


def _join(db: DB, unit: str, *, module: str, campaign_id: str, parent: str | None, pol: dict, feasible: list[str],
          stages: list[str], bound_platform: str | None = None) -> dict:
    """Create the unit's binding row or narrow its feasible classes by one more job's. A pinned campaign's units are
    created pinned; a unit whose datasets live on one platform is pinned there (source `dataset`)."""
    t = clock.now()
    b = binding(db, unit)
    if b is None:
        state, cls, source = "unbound", None, None
        if pol.get("pin"):
            state, cls, source = "pinned", pol["pin"], "pin"
        elif bound_platform:
            state, cls, source = "pinned", pf.class_key(bound_platform, pol["mix"]), "dataset"
        db.x("INSERT INTO placement_bindings(unit,module,campaign_id,parent,mix,class,state,source,bind,rebind,stranded_after_s,"
             "feasible_json,bound_at,generation) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
             (unit, module, campaign_id, parent, pol["mix"], cls, state, source, pol["bind"], pol["rebind"],
              pol["stranded_after_s"], json.dumps(feasible), t if cls else None))
        if cls:
            db.event("placement_bound", campaign_id=campaign_id, reason=f"{unit}: {cls} ({source})")
    else:
        feasible = sorted(set(b["feasible"]) & set(feasible))
        db.x("UPDATE placement_bindings SET feasible_json=? WHERE unit=?", (json.dumps(feasible), unit))
    b = binding(db, unit)
    if not b["feasible"]:
        raise PlacementError(422, "placement_infeasible", f"{unit}: no {pol['mix']} class can run all of its work")
    if b["class"] is not None and b["class"] not in b["feasible"] and b["state"] == "soft" \
            and not unit_jobs(db, unit, ("leased", "done")):
        _bind(db, b, None, "unbound", None)              # a soft binding nothing ran under yet follows the work it gets
    if b["class"] is not None and b["class"] not in b["feasible"]:
        raise PlacementError(422, "placement_infeasible", f"{unit} is bound to {b['class']}, where this job cannot run")
    if b["state"] == "unbound" and b["bind"] == "capacity":
        cls = capacity_class(db, module, b["mix"], b["feasible"], stages)
        if cls:
            _bind(db, b, cls, "soft", "capacity")
    return binding(db, unit)


def open_campaign_unit(db: DB, module: str, campaign_id: str, pol: dict) -> dict:
    """A new campaign whose unit is the campaign: its unit exists from the start, pinned or bound by capacity, with the
    classes of the module's platforms where its stages run (each enqueued job narrows them further)."""
    mi = modcalls.info(module)
    stages = list(mi.chain) if modcalls.split_enabled(db, module) else [mi.single_stage or mi.stages[0]]
    return _join(db, f"c:{campaign_id}", module=module, campaign_id=campaign_id, parent=None, pol=pol,
                 feasible=classes(mi.manifest, stages, [], [], pol["mix"]), stages=stages)


def assign(db: DB, job_id: int) -> str | None:
    """Derive an eval job's unit (and its head's, once split) and join it; sets jobs.placement_unit. Raises
    PlacementError when no class can run the job together with its unit."""
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (job_id,))
    if not j or j["kind"] != "eval" or not j["campaign_id"]:
        return None
    pol = _policy_of(db, j["campaign_id"])
    mi = modcalls.info(j["module"])
    split = j["depends_on"] is not None and mi.chain is not None
    stages = list(mi.chain) if split else [j["stage"] or mi.single_stage]
    jp, dps = jl(j["platforms_json"], []) or [], dataset_platforms(db, j)
    common = dict(module=j["module"], campaign_id=j["campaign_id"], bound_platform=dps[0] if len(dps) == 1 else None)
    cid, leaf, leaf_mix = j["campaign_id"], None, "any"
    if pol:
        leaf = {"campaign": f"c:{cid}", "group": f"c:{cid}/g:{j['group_key'] or ''}",
                "dataset": f"c:{cid}/d:{j['dataset_id'] or ''}", "pipeline": f"c:{cid}/p:{job_id}"}[pol["unit"]]
        _join(db, leaf, parent=None, pol=pol, feasible=classes(mi.manifest, stages, jp, dps, pol["mix"]), stages=stages, **common)
        leaf_mix = pol["mix"]
    tail = next((s for s in mi.manifest.stages if split and s.name == mi.chain[1]), None)
    if tail is not None and tail.placement is not None and pf.stricter(tail.placement.mix, leaf_mix) != leaf_mix:
        # the stage's placement keeps head and tail closer together than the unit does: a sub-unit for this pipeline
        mix = pf.stricter(tail.placement.mix, leaf_mix)
        defaults = mf.Placement(mix=mix)
        sub = f"{leaf}/s" if pol and pol["unit"] == "pipeline" else f"c:{cid}/p:{job_id}"
        _join(db, sub, parent=leaf, pol={"mix": mix, "bind": "first-claim", "rebind": (pol or {}).get("rebind") or defaults.rebind,
                                         "stranded_after_s": (pol or {}).get("stranded_after_s") or defaults.stranded_after_s},
              feasible=classes(mi.manifest, stages, jp, dps, mix), stages=stages, **common)
        leaf = sub
    db.x("UPDATE jobs SET placement_unit=? WHERE job_id=? OR (job_id=? AND kind='call')", (leaf, job_id, j["depends_on"]))
    return leaf


# ---------------------------------------------------------------------------- binding

def _bind(db: DB, b: dict, cls: str | None, state: str, source: str | None, job_id: int | None = None,
          node_id: str | None = None):
    db.x("UPDATE placement_bindings SET class=?, state=?, source=?, bound_at=?, bound_job=?, bound_node=?, stranded_since=NULL "
         "WHERE unit=?", (cls, state, source, clock.now() if cls else None, job_id, node_id, b["unit"]))
    b.update({"class": cls, "state": state, "source": source})
    db.event("placement_bound" if cls else "placement_released", campaign_id=b["campaign_id"],
             reason=f"{b['unit']}: {cls or 'unbound'} ({source or state})")


def bind_on_claim(db: DB, j: dict, node: dict, cache: dict):
    """claim() granted job `j` on `node`: its unbound units bind softly to the node's class (first claim; inside claim's
    transaction, so two nodes never bind one unit to two classes). `cache` is claim's binding map."""
    for b in chain(db, j.get("placement_unit"), cache):
        if b["state"] == "unbound":
            _bind(db, b, pf.class_key(node["platform"], b["mix"]), "soft", "first_claim", j["job_id"], node["node_id"])


def harden(db: DB, unit: str | None, platform: str | None):
    """An accepted canonical result from a node of `platform`: the unit's binding is final."""
    for b in chain(db, unit):
        if b["state"] in ("unbound", "soft") and platform:
            _bind(db, b, b["class"] or pf.class_key(platform, b["mix"]), "hard", b["source"] or "first_claim",
                  b["bound_job"], b["bound_node"])


def cache_hit(db: DB, j: dict) -> int | None:
    """A canonical result of this module for the job's key that the job may reuse (the result cache): one produced on its
    platforms, its datasets' platform and its unit's class (unbound: a feasible class, which the hit then binds, hard).
    A stage that does not compare (determinism none) neither takes nor serves a hit: its result belongs to its run."""
    if not modcalls.compares(j["module"], j["stage"]):
        return None
    f = facts(db, j)
    for r in db.q("SELECT r.result_id, r.platform, r.node_id, r.job_id, r.module_version, cj.stage FROM results r "
                  "JOIN jobs cj ON cj.job_id=r.job_id WHERE r.job_key=? AND r.canonical=1 AND cj.module=? "
                  "ORDER BY r.result_id DESC LIMIT 50", (j["job_key"], j["module"])):
        if not modcalls.compares(j["module"], r["stage"], r["module_version"]):
            continue
        p = r["platform"]
        if f["platforms"] or f["dataset_platforms"] or f["units"]:
            if not p or not pf.matches(p, f["platforms"]) or any(d != p for d in f["dataset_platforms"]):
                continue
            if not all((u["class"] == pf.class_key(p, u["mix"])) if u["class"] else
                       (u["bind"] != "explicit" and pf.class_key(p, u["mix"]) in u["feasible"]) for u in f["units"]):
                continue
            for b in chain(db, j.get("placement_unit")):
                if b["state"] in ("unbound", "soft"):
                    _bind(db, b, pf.class_key(p, b["mix"]), "hard", "cache_hit" if b["state"] == "unbound" else b["source"],
                          j["job_id"], r["node_id"])
        return r["result_id"]
    return None


def capacity_class(db: DB, module: str, mix: str, feasible: list[str], stages, exclude: str | None = None) -> str | None:
    """Among the feasible classes where every one of `stages` has a node to run it (classes_running), the one with the
    most free CPU on ready, active nodes certified for the module, or able to run its bootstrap stages when every one of
    `stages` is one (None: no such class)."""
    runs = classes_running(db, module, stages, mix)
    boot = bool(stages) and all(modcalls.stage_bootstrap(module, st) for st in stages)
    free: dict = {}
    live = {r["node_id"]: r["cpu"] or 0 for r in db.q(
        "SELECT a.node_id, SUM(COALESCE(json_extract(j.resources_json,'$.cpu'),1)) cpu FROM attempts a "
        "JOIN jobs j ON j.job_id=a.job_id WHERE a.state='live' GROUP BY a.node_id")}
    from . import modsandbox
    for n in db.q("SELECT node_id, platform, modules_json, capacity_json, facts_json FROM nodes WHERE lifecycle='ready' "
                  "AND desired_state='active' AND platform IS NOT NULL"):
        cls = pf.class_key(n["platform"], mix)
        state = (jl(n["modules_json"], {}) or {}).get(module, {}).get("state")
        if cls not in feasible or cls not in runs or cls == exclude \
                or not predicates.module_serves({"bootstrap": boot}, state, modsandbox.bootstrap_enforced(n)):
            continue
        slots = float((jl(n["capacity_json"], {}) or {}).get("cpu_slots") or 0)
        free[cls] = free.get(cls, 0.0) + max(0.0, slots - float(live.get(n["node_id"], 0)))
    return max(sorted(free), key=lambda c: free[c]) if free else None


# ---------------------------------------------------------------------------- rebinding

def _units_under(db: DB, unit: str) -> list[str]:
    return [unit] + [r["unit"] for r in db.q("SELECT unit FROM placement_bindings WHERE parent=?", (unit,))]


def unit_jobs(db: DB, unit: str, states: tuple) -> list[dict]:
    units = _units_under(db, unit)
    return db.q(f"SELECT * FROM jobs WHERE placement_unit IN ({','.join('?' * len(units))}) "
                f"AND state IN ({','.join('?' * len(states))}) ORDER BY job_id", (*units, *states))


def requeue_plan(db: DB, unit: str) -> list[int]:
    """The finished jobs a rebind of `unit` runs again (campaigns.rebind_platform's plan)."""
    return [j["job_id"] for j in unit_jobs(db, unit, ("done",)) if j["kind"] != "replica"]


def rebind(db: DB, b: dict, cls: str, *, state: str, source: str) -> dict:
    """Move a unit to class `cls`: its finished jobs run again (their own results stop being canonical, as with
    jobs.retry, and jobs elsewhere that reused those results through the cache run again too: a re-run job may have one
    canonical result only, S1); its running attempts are revoked; its replicas are dropped; every job's generation moves,
    so no late result from the old class is accepted. Sub-units start unbound."""
    from . import core
    t, requeued, revoked = clock.now(), [], 0
    for j in unit_jobs(db, b["unit"], ("pending", "leased", "done")):
        for a in db.q("SELECT attempt_id, node_id FROM attempts WHERE job_id=? AND state='live'", (j["job_id"],)):
            db.x("UPDATE attempts SET state='revoked', end_reason='placement_rebound', ended_at=? WHERE attempt_id=?",
                 (t, a["attempt_id"]))
            core._push(db, a["node_id"], "revoke", a["attempt_id"])
            revoked += 1
        if j["kind"] == "replica":
            db.x("UPDATE jobs SET state='cancelled', generation=generation+1 WHERE job_id=?", (j["job_id"],))
            db.x("UPDATE results SET canonical=0 WHERE job_id=?", (j["job_id"],))
            continue
        own = [r["result_id"] for r in db.q("SELECT result_id FROM results WHERE job_id=? AND canonical=1", (j["job_id"],))]
        db.x("UPDATE jobs SET state='pending', generation=generation+1, canonical_result_id=NULL, done_at=NULL, dispute_json=NULL, "
             "exec_failures=0, not_before=0 WHERE job_id=?", (j["job_id"],))
        if j["state"] == "done":
            requeued.append(j["job_id"])
            db.x("UPDATE results SET canonical=0 WHERE job_id=?", (j["job_id"],))
            core._requeue_cache_dependents(db, own, j["job_id"])
    for sub in _units_under(db, b["unit"])[1:]:
        _bind(db, binding(db, sub), None, "unbound", None)
    _bind(db, b, cls, state, source)
    db.x("UPDATE placement_bindings SET generation=generation+1 WHERE unit=?", (b["unit"],))
    core.reopen_campaigns(db)
    return {"unit": b["unit"], "class": cls, "requeued": requeued, "revoked": revoked}


def _release(db: DB, b: dict):
    """A soft binding goes: the unit is unbound again; its pending jobs' generations move (no late result binds it)."""
    for j in unit_jobs(db, b["unit"], ("pending",)):
        db.x("UPDATE jobs SET generation=generation+1 WHERE job_id=?", (j["job_id"],))
    _bind(db, b, None, "unbound", None)


def class_has_node(db: DB, b: dict) -> bool:
    """Can the unit's class take its pending work now: for every stage still ahead of it, an online, active node of the
    class that can serve the module runs the stage and holds its pools (classes_running)."""
    return b["class"] in classes_running(db, b["module"], unit_stages(db, b), b["mix"], online=True)


def reap(db: DB) -> list[tuple]:
    """The reaper's placement pass (inside its transaction). Returns the alerts to raise and resolve after it, as
    (open?, rule, subject, detail)."""
    from . import audit
    t, alerts = clock.now(), []
    for r in db.q("SELECT * FROM placement_bindings WHERE state='soft' AND source='first_claim'"):
        b = _row(r)
        if not unit_jobs(db, b["unit"], ("leased", "done")):
            _release(db, b)                                 # its first attempts ended without a result
    for r in db.q("SELECT unit FROM placement_bindings WHERE class IS NOT NULL"):
        b = binding(db, r["unit"])                      # read again: a parent's rebind earlier in this pass unbinds its sub-units
        if b["class"] is None:
            continue
        rule, subject = f"placement_stranded:{b['unit']}", f"campaign:{b['campaign_id']}"
        if not unit_jobs(db, b["unit"], ("pending",)) or class_has_node(db, b):
            if b["stranded_since"] is not None:
                db.x("UPDATE placement_bindings SET stranded_since=NULL WHERE unit=?", (b["unit"],))
            alerts.append((False, rule, subject, None))
            continue
        if b["stranded_since"] is None:
            db.x("UPDATE placement_bindings SET stranded_since=? WHERE unit=?", (t, b["unit"]))
            continue
        if t - b["stranded_since"] < (b["stranded_after_s"] or 1800):
            continue
        stages = unit_stages(db, b)
        if b["state"] == "soft":
            if not unit_jobs(db, b["unit"], ("leased", "done")):
                old = b["class"]
                _release(db, b)
                cls = capacity_class(db, b["module"], b["mix"], b["feasible"], stages) if b["bind"] == "capacity" else None
                if cls:
                    _bind(db, b, cls, "soft", "capacity")
                    alerts.append((False, rule, subject, None))
                elif b["bind"] == "capacity":
                    alerts.append((True, rule, subject,
                                   f"{b['unit']} ({b['module']}) was bound to {old} (soft), where no node has been able to run "
                                   f"its stages {stages} for {int((t - b['stranded_since']) // 60)} min, and no other class "
                                   "can run them all: bring back a node with what they need (pools, platforms)"))
            continue
        cls = capacity_class(db, b["module"], b["mix"], b["feasible"], stages, exclude=b["class"]) \
            if b["rebind"] == "if-stranded" and b["state"] == "hard" else None
        if cls is None:
            alerts.append((True, rule, subject,
                           f"{b['unit']} ({b['module']}) is bound to {b['class']} ({b['state']}) and no node of that class has "
                           f"been able to take its work for {int((t - b['stranded_since']) // 60)} min: bring one back, or "
                           f"move the campaign with campaigns.rebind_platform"))
            continue
        old = b["class"]
        out = rebind(db, b, cls, state="soft", source="rebind")
        audit.append(db, actor="system", source="scheduler", operation="campaigns.rebind_platform", category="modify",
                     target_type="campaign", target_id=b["campaign_id"], outcome="ok", request_id=audit.request_id(),
                     reason=f"stranded on {old} for {int(t - b['stranded_since'])} s (rebind = if-stranded)",
                     before={"unit": b["unit"], "class": old}, after=out)
        alerts.append((False, rule, subject, None))
        alerts.append((True, f"placement_rebound:{b['unit']}", subject,
                       f"{b['unit']} ({b['module']}) moved from {old} to {cls}: no node of {old} for "
                       f"{int((t - b['stranded_since']) // 60)} min; {len(out['requeued'])} finished jobs run again"))
    return alerts


# ---------------------------------------------------------------------------- operations

def campaign_units(db: DB, campaign_id: str) -> list[dict]:
    return [_row(r) for r in db.q("SELECT * FROM placement_bindings WHERE campaign_id=? ORDER BY unit", (campaign_id,))]


def summary(db: DB, campaign_id: str) -> dict | None:
    """A campaign's placement for the console, the CLI and campaign.tick: {mix, unit, bind, rebind, pin, class, state,
    units}. `class`/`state` are the campaign unit's (unit = campaign), else null; `units` counts units by state."""
    pol = _policy_of(db, campaign_id)
    units = campaign_units(db, campaign_id)
    if not pol and not units:
        return None
    top = next((u for u in units if u["unit"] == f"c:{campaign_id}"), None)
    counts: dict = {}
    for u in units:
        counts[u["state"]] = counts.get(u["state"], 0) + 1
    return {**{k: (pol or {}).get(k) for k in ("mix", "unit", "bind", "rebind", "pin")},
            "class": top["class"] if top else None, "state": top["state"] if top else None, "units": counts,
            "stranded": [u["unit"] for u in units if u["stranded_since"] is not None]}


def set_mix(db: DB, campaign_id: str, mix: str) -> dict:
    """campaigns.set_placement: a stricter mix, before the campaign's first result. Units are derived again; running
    attempts outside their unit's new class are revoked and their jobs queued again."""
    from . import core
    c = db.one("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,))
    pol = jl(c["placement_json"])
    new = pf.normalize(mix)
    if not pf.known_mix(mix):
        raise PlacementError(422, "bad_placement", f"mix {mix!r}: one of {', '.join(pf.MIXES)}")
    cur = pol["mix"] if pol else "any"
    if new == cur:
        return {"mix": new, "units": len(campaign_units(db, campaign_id)), "revoked": 0}
    if pf.stricter(new, cur) != new:
        raise PlacementError(422, "placement_looser", f"{new} is not stricter than the campaign's {cur}")
    if db.one("SELECT 1 FROM jobs WHERE campaign_id=? AND state='done'", (campaign_id,)):
        raise PlacementError(409, "campaign_has_results", "the placement may change only before the campaign's first result")
    if (pol or {}).get("pin"):
        raise PlacementError(409, "campaign_pinned", f"the campaign is pinned to {pol['pin']}: move it with campaigns.rebind_platform")
    base = manifest_policy(modcalls.info(c["module"]).manifest) or {}
    unit = (pol or {}).get("unit") or base.get("unit") or "campaign"
    defaults = mf.Placement(mix=new, unit=unit)
    pol = {"mix": new, "unit": unit, "bind": (pol or {}).get("bind") or base.get("bind") or defaults.effective_bind(),
           "rebind": base.get("rebind") or defaults.rebind, "stranded_after_s": base.get("stranded_after_s") or defaults.stranded_after_s,
           "pin": None}
    db.x("UPDATE campaigns SET placement_json=? WHERE campaign_id=?", (json.dumps(pol), campaign_id))
    db.x("UPDATE jobs SET placement_unit=NULL WHERE campaign_id=?", (campaign_id,))
    # pending jobs' generations move: a late result from an attempt that ended before (expired, released) must not land
    # in a unit the new mix binds elsewhere (as _release does)
    db.x("UPDATE jobs SET generation=generation+1 WHERE campaign_id=? AND state='pending'", (campaign_id,))
    db.x("DELETE FROM placement_bindings WHERE campaign_id=?", (campaign_id,))
    if unit == "campaign":
        open_campaign_unit(db, c["module"], campaign_id, pol)
    revoked = 0
    for j in db.q("SELECT job_id FROM jobs WHERE campaign_id=? AND kind='eval' AND state IN ('pending','leased') "
                  "ORDER BY job_id", (campaign_id,)):
        assign(db, j["job_id"])
    t = clock.now()
    for a in db.q("SELECT a.attempt_id, a.node_id, j.job_id, j.placement_unit, n.platform FROM attempts a JOIN jobs j "
                  "ON j.job_id=a.job_id JOIN nodes n ON n.node_id=a.node_id WHERE a.state='live' AND j.campaign_id=?", (campaign_id,)):
        units = chain(db, a["placement_unit"])
        if all(u["class"] is None or (a["platform"] and pf.class_key(a["platform"], u["mix"]) == u["class"]) for u in units):
            for u in units:
                if u["state"] == "unbound" and a["platform"]:
                    _bind(db, u, pf.class_key(a["platform"], u["mix"]), "soft", "first_claim", a["job_id"], a["node_id"])
            continue
        db.x("UPDATE attempts SET state='revoked', end_reason='placement_rebound', ended_at=? WHERE attempt_id=?", (t, a["attempt_id"]))
        core._push(db, a["node_id"], "revoke", a["attempt_id"])
        db.x("UPDATE jobs SET state='pending', generation=generation+1 WHERE job_id=? AND NOT EXISTS "
             "(SELECT 1 FROM attempts WHERE job_id=? AND state='live')", (a["job_id"], a["job_id"]))
        revoked += 1
    return {"mix": new, "units": len(campaign_units(db, campaign_id)), "revoked": revoked}


def rebind_campaign(db: DB, campaign_id: str, platform: str) -> dict:
    """campaigns.rebind_platform: every top-level unit of the campaign moves to `platform`'s class under its mix (pinned:
    the operator chose it)."""
    from oarbank_sdk import portable
    if not portable.is_platform_token(platform):
        raise PlacementError(422, "bad_platform", f"{platform!r} is not a platform token")
    units = [u for u in campaign_units(db, campaign_id) if u["parent"] is None]
    if not units:
        raise PlacementError(409, "no_placement", f"campaign {campaign_id} keeps no unit of work on one platform")
    out = []
    for b in units:
        cls = pf.class_key(platform, b["mix"])
        if cls not in b["feasible"]:
            raise PlacementError(422, "placement_infeasible", f"{b['unit']} cannot run on {cls} (feasible: {b['feasible']})")
    for b in units:
        cls = pf.class_key(platform, b["mix"])
        if b["class"] == cls and b["state"] == "pinned":
            continue
        out.append(rebind(db, b, cls, state="pinned", source="rebind"))
    return {"platform": platform, "units": out, "requeued": sorted(i for u in out for i in u["requeued"])}
