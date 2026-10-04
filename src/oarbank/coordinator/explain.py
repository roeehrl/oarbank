"""Explain for jobs and nodes (PLAN D16): one document for the CLI and the console, computed with the
same predicate functions claim() uses (coordinator/predicates.py), over every node, keeping every result.

Node capacity comes from the agent's last report (capacity_json) unless the caller passes the exact
claim inputs (the property test does); facts a node never reported are "unknown", never guessed.
"""
import collections
import time

from ..contracts import explain as X
from ..contracts import reason_codes as RC
from . import modstore, core, modcalls, predicates, protection
from .db import DB, jl


def _estimated_view(db: DB, node: dict, body: dict | None) -> predicates.NodeView:
    cap = jl(node["capacity_json"], {}) or {}
    if body is None:
        live_cpu = sum(float(modcalls.resources_on(jl(r["resources_json"], {}) or {}, node.get("platform")).get("cpu", 1))
                       for r in db.q("SELECT j.resources_json FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                                     "WHERE a.node_id=? AND a.state='live'", (node["node_id"],)))
        slots = cap.get("cpu_slots")
        body = {"free_cpu": (float(slots) - float(live_cpu)) if slots is not None else 1e9,
                "free_mem_gb": cap.get("mem_gb_free") if cap.get("mem_gb_free") is not None else 1e9,
                "ready_datasets": jl(node["ready_datasets_json"], []) or [],
                "pool_jobs_only": bool(cap.get("pool_jobs_only")), "gpu_jobs": cap.get("gpu_jobs")}
    offered = set(body.get("modules") or modcalls.enabled(db)) - modstore.disabled_names(db)
    free_cpu = float(body.get("free_cpu") if body.get("free_cpu") is not None else body.get("free_slots") or 0)
    free_mem = float(body.get("free_mem_gb") if body.get("free_mem_gb") is not None else 1e9)
    return core.node_view_for_claim(db, node, offered, set(body.get("ready_datasets") or []), free_cpu, free_mem, body)


def _job_on_node(db: DB, j: dict, nv: predicates.NodeView, now: float) -> list:
    campaign_state = (db.one("SELECT state FROM campaigns WHERE campaign_id=?", (j["campaign_id"],)) or {}).get("state") \
        if j["campaign_id"] else None
    dep_done = True
    if j["depends_on"]:
        d = db.one("SELECT state FROM jobs WHERE job_id=?", (j["depends_on"],))
        dep_done = bool(d and d["state"] == "done")
    res = modcalls.resources_on(jl(j["resources_json"], {}) or {"cpu": 1, "mem_gb": 1.0}, nv.node.get("platform"))

    def dep_ok():
        dep = core._dep_result(db, j)
        return bool(dep and (jl(dep["result_json"], {}) or {}).get("artifacts"))
    return predicates.admission(nv) + predicates.placement(
        core._job_facts(db, j), nv, now, dep_done=dep_done, campaign_state=campaign_state,
        other_can_take=lambda: core._other_node_can_take(db, j, nv.node["node_id"]),
        datasets=jl(j["datasets_json"], []), resources=res, dep_artifacts=dep_ok if j["depends_on"] else True,
        gpu=modcalls.job_uses_gpu(j["module"], res, nv.node.get("platform")))


def _remedies(codes, params) -> list[X.Remedy]:
    out, seen = [], set()
    for c in codes:
        rc = RC.REGISTRY.get(c)
        for op in (rc.remedies if rc else ()):
            if op not in seen:
                seen.add(op)
                out.append(X.Remedy(op=op, params=params, label=op.split(".", 1)[1].replace("_", " ").capitalize()))
    return out


def _checkpoint_actions(db: DB, j: dict) -> list[str]:
    """A job's portable checkpoint (checkpoints.py): what its next attempt resumes from, and what a running one did."""
    from . import checkpoints
    out = []
    c = checkpoints.for_job(db, j) if j["state"] in ("pending", "leased") else None
    if c:
        out.append(f"Keeps a checkpoint from attempt {c['attempt_id']} on {c['node_id']} ({c['size']:,} bytes, recorded at "
                   f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(c['at']))}): its next attempt resumes from it on any node")
    a = db.one("SELECT attempt_id, resume_json FROM attempts WHERE job_id=? AND state='live' ORDER BY attempt_id DESC LIMIT 1",
               (j["job_id"],))
    r = jl(a["resume_json"]) if a else None
    if r:
        out.append(f"Attempt {a['attempt_id']} resumed from attempt {r['from_attempt']}'s checkpoint (written on {r['node_id']}); "
                   "a result that resumed from another node's checkpoint is always replicated on a third node")
    return out


def job_doc(db: DB, job_id: int, bodies: dict | None = None, now: float | None = None) -> X.ExplainDocument | None:
    now = now or time.time()
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (job_id,))
    if not j:
        return None
    evidence = [X.Evidence(event_id=e["event_id"], kind=e["kind"])
                for e in db.q("SELECT event_id, kind FROM events WHERE job_id=? ORDER BY event_id DESC LIMIT 10", (job_id,))]
    as_of = X.AsOf(snapshot_version=db.one("SELECT COALESCE(MAX(event_id),0) m FROM events")["m"], evaluated_at=now)
    subj = X.Subject(kind="job", id=job_id)
    boot = modcalls.stage_bootstrap(j["module"], j["stage"])
    actions = [f"Runs as a bootstrap job (stage {j['stage']}): on nodes where {j['module']}'s doctor is healthy, before its "
               "goldens pass, with only the module's egress allowlist; its result must be exactly the module's pinned datasets, "
               "which the coordinator then registers, and it never counts toward certification"] if boot else []
    actions += _checkpoint_actions(db, j)
    if j["state"] != "pending":
        a = db.one("SELECT a.*, n.hostname FROM attempts a LEFT JOIN nodes n ON n.node_id=a.node_id WHERE a.job_id=? "
                   "ORDER BY a.attempt_id DESC LIMIT 1", (job_id,))
        if j["state"] == "leased" and a:
            head = X.Headline(code="OK", text=f"Running{' as a bootstrap job' if boot else ''} on {a['hostname']} "
                                              f"(attempt {a['attempt_id']}, phase {a['phase']})")
        elif j["state"] == "done":
            head = X.Headline(code="OK", text="Done")
        elif j["state"] == "cancelled":
            head = X.Headline(code="USER_CANCEL", text="Cancelled")
        else:
            er = (a or {}).get("end_reason") or ""
            code = RC.WIRE.get(er) or (er if "/" in er else "JOB_QUARANTINED")      # a module's own code renders as itself
            head = X.Headline(code=code, text=f"{j['state']}: last attempt ended {(a or {}).get('end_reason')}")
        return X.ExplainDocument(subject=subj, as_of=as_of, verdict=j["state"], headline=head, evidence=evidence,
                                 system_actions=actions, remedies=_remedies([head.code, "JOB_QUARANTINED" if j["state"] in ("failed", "quarantined") else ""],
                                                    {"job_id": job_id}))
    nodes = db.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    matrix, by_code, eligible_nodes = [], collections.defaultdict(list), []
    clause = collections.defaultdict(lambda: [0, 0])
    for n in nodes:
        nv = _estimated_view(db, n, (bodies or {}).get(n["node_id"]))
        results = _job_on_node(db, j, nv, now)
        matrix.append(X.MatrixRow(node=n["hostname"], results=results))
        for r in results:
            clause[r.predicate][1] += 1
            clause[r.predicate][0] += r.outcome == predicates.PASS
        ff = predicates.first_failure(results)
        if ff is None:
            eligible_nodes.append(n)
        else:
            by_code[ff.code].append(n["hostname"])
    summary = [X.SummaryRow(code=c, nodes=ns) for c, ns in sorted(by_code.items(), key=lambda kv: -len(kv[1]))]
    if eligible_nodes:
        ahead = db.one("SELECT COUNT(*) n FROM jobs WHERE state='pending' AND (priority>? OR (priority=? AND job_id<?))",
                       (j["priority"] or 0, j["priority"] or 0, job_id))["n"]
        summary.insert(0, X.SummaryRow(code="QUEUED_BEHIND", nodes=[n["hostname"] for n in eligible_nodes],
                                       detail={"best_position": ahead + 1}))
        head = X.Headline(code="QUEUED_BEHIND", text=RC.REGISTRY["QUEUED_BEHIND"].render(ahead=ahead))
    elif not nodes:
        head = X.Headline(code="NO_ELIGIBLE_NODE", text="There are no nodes")
    else:
        head = X.Headline(code="NO_ELIGIBLE_NODE", text=RC.REGISTRY["NO_ELIGIBLE_NODE"].template)
    return X.ExplainDocument(
        subject=subj, as_of=as_of, verdict="pending", headline=head, summary=summary,
        clauses=[X.Clause(predicate=p, matched=m, of=o) for p, (m, o) in clause.items()], matrix=matrix,
        next_trigger="Re-evaluated on every claim (agents claim each heartbeat)", system_actions=actions,
        remedies=_remedies([s.code for s in summary], {"job_id": job_id, **({"campaign_id": j["campaign_id"]} if j["campaign_id"] else {})}), evidence=evidence)


def node_doc(db: DB, node_id: str, body: dict | None = None, now: float | None = None) -> X.ExplainDocument | None:
    now = now or time.time()
    n = db.one("SELECT * FROM nodes WHERE node_id=? OR hostname=?", (node_id, node_id))
    if not n:
        return None
    nv = _estimated_view(db, n, body)
    adm = predicates.admission(nv)
    ff = predicates.first_failure(adm)
    by_code = collections.Counter()
    if ff is None:
        for j in db.q("SELECT * FROM jobs WHERE state='pending' ORDER BY priority DESC, job_id LIMIT 200"):
            r = predicates.first_failure(_job_on_node(db, j, nv, now)[len(adm):])
            by_code[r.code if r else "QUEUED_BEHIND"] += 1     # eligible here: waiting for a claim, as in job explain
    summary = [X.SummaryRow(code=c, detail={"pending_jobs": k}) for c, k in by_code.most_common()]
    if abs(n.get("clock_offset_s") or 0) > core.CLOCK_SKEW_S:
        summary.append(X.SummaryRow(code="CLOCK_SKEW", detail={"offset_s": n["clock_offset_s"]}))   # a condition: work goes on
    # what host protection cannot read or do there now, and the fail-safe default it applies instead
    summary += [X.SummaryRow(code=c["code"], detail=c["values"]) for c in protection.runtime_conditions(jl(n["telemetry_json"], {}) or {})]
    head = X.Headline(code="OK", text="Admitting work") if ff is None else \
        X.Headline(code=ff.code, text=f"Not admitting: {ff.predicate} (observed {ff.observed}, required {ff.required})")
    return X.ExplainDocument(
        subject=X.Subject(kind="node", id=n["node_id"]),
        as_of=X.AsOf(snapshot_version=db.one("SELECT COALESCE(MAX(event_id),0) m FROM events")["m"], evaluated_at=now),
        verdict="admitting" if ff is None else "blocked", headline=head, summary=summary,
        matrix=[X.MatrixRow(node=n["hostname"], results=adm)],
        remedies=_remedies([head.code] + [s.code for s in summary], {"node": n["node_id"]}),
        evidence=[X.Evidence(event_id=e["event_id"], kind=e["kind"]) for e in
                  db.q("SELECT event_id, kind FROM events WHERE node_id=? ORDER BY event_id DESC LIMIT 10", (n["node_id"],))])


def explain(db: DB, kind: str, ident: str) -> X.ExplainDocument | None:
    if kind == "job":
        return job_doc(db, int(ident))
    if kind == "node":
        return node_doc(db, ident)
    raise core.ApiError(404, "not_found", f"nothing to explain for {kind!r}: job or node")
