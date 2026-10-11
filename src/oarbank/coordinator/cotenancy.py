"""Co-tenancy on the coordinator (D50, D52; docs/design/gpu-cotenancy.md): the paired on/off harness runs it
schedules, the agents' reports of them, the frontier search over GPU duty levels, and the co-tenancy certificates a
passing run earns.

The harness itself runs in the agent (the windows must be timed on the node): the coordinator asks for a run in the
heartbeat reply (`ab_run`), aborts one (`ab_abort`), stores the agent's reports (`ab_runs` in the heartbeat) and,
when a run ends with "no slowdown shown", issues a certificate: node, rule, fleet configuration (`work`, `duty`),
`R` with its interval, the margin, the run and a validity of 14 days. The certificates in force go back to the node
(`certificates`), which checks each itself (expiry, hardware, OS major, agent version, the protected program's
identity) before `gpu_jobs = certified` uses one. Starting a run is an owner operation (T2: it deliberately runs
fleet work beside a protected process); modules can never start runs or read certificates.
"""
import json
import secrets
import time

from ..contracts import abstats, protection as P
from .db import DB, jl

CERT_VALID_S = 14 * 86400          # owner decision 13: 14 days (or until the node or the protected program changes)
DEFAULT_MARGIN = 0.02              # owner decision 13: 2 %
SWEEP_LEVELS = (0.1, 0.2, 0.35, 0.5, 0.65, 0.8, 1.0)
SPEC_KEYS = ("blocks", "window_s", "washout_s", "margin", "off", "pilot_blocks", "max_hours")


class CotenancyError(ValueError):
    pass


def now() -> float:
    return time.time()


def _node(db: DB, ident: str) -> dict:
    n = db.one("SELECT * FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (ident, ident))
    if not n:
        raise CotenancyError(f"no node {ident!r}")
    return n


def _rule(db: DB, node: dict, rule_id: str) -> dict:
    """The node's effective rule, which must protect a progress_rate source (what the harness measures)."""
    from . import protection
    from .settings import resolve as V
    cfg = protection.effective(V.snapshot(db), node)
    r = next((x for x in cfg.get("rule") or [] if x.get("id") == rule_id), None)
    if r is None:
        raise CotenancyError(f"node {node['hostname']} has no protection rule {rule_id!r}")
    p = r.get("protect") or {}
    if p.get("metric") != "progress_rate" or not p.get("source"):
        raise CotenancyError(f"rule {rule_id} has no protect.metric = progress_rate source: the harness measures the "
                             "protected process's own progress")
    return r


def spec_of(params: dict, run_id: str, rule: str) -> dict:
    """A run's spec from operation params, checked (the agent checks it again)."""
    params = {k: v for k, v in (params or {}).items() if v not in ("", None)}       # a console form's empty fields
    work = str(params.get("work") or "gpu")
    spec = {"run_id": run_id, "rule": rule, "work": work, "duty": params.get("duty"),
            "blocks": int(params.get("blocks") or 12), "window_s": float(params.get("window_s") or 300),
            "washout_s": float(params.get("washout_s") if params.get("washout_s") is not None else 60),
            "margin": float(params.get("margin") or DEFAULT_MARGIN), "off": str(params.get("off") or "paused"),
            "pilot_blocks": int(params.get("pilot_blocks") or 3), "max_hours": float(params.get("max_hours") or 8),
            "seed": int(params.get("seed") if params.get("seed") is not None else secrets.randbits(62))}
    if spec["duty"] is not None:
        spec["duty"] = float(spec["duty"])
        if not 0 < spec["duty"] <= 1:
            raise CotenancyError("duty must be in (0, 1]")
    if work in ("", "/") or work.startswith("/") or work.endswith("/"):
        raise CotenancyError("work: gpu | cpu | all | <module> | <module>/<workload>")
    if not (spec["window_s"] >= 30 and 0 <= spec["washout_s"] < spec["window_s"]):
        raise CotenancyError("window_s must be at least 30 and washout_s below it")
    if not 0 < spec["margin"] < 0.5:
        raise CotenancyError("margin must be in (0, 0.5)")
    if not 2 <= spec["blocks"] <= 1000 or spec["pilot_blocks"] < 2:
        raise CotenancyError("blocks must be 2..1000 and pilot_blocks at least 2")
    if spec["off"] not in ("paused", "evicted"):
        raise CotenancyError("off: paused | evicted")
    if not 0 < spec["max_hours"] <= 72:
        raise CotenancyError("max_hours must be in (0, 72]")
    return spec


def active_run(db: DB, nid: str) -> dict | None:
    return db.one("SELECT * FROM ab_runs WHERE node_id=? AND state IN ('requested','running') ORDER BY created_at LIMIT 1",
                  (nid,))


def plan(db: DB, ident: str, params: dict) -> dict:
    """What a run would do (the T2 preview): the node, the rule and its source, the work under test, the planned
    length and cap, and what it means for the owner."""
    n = _node(db, ident)
    r = _rule(db, n, str(params.get("rule") or ""))
    spec = spec_of(params, "preview", r["id"])
    cur = active_run(db, n["node_id"])
    block_s = 2 * spec["window_s"]
    gpu_jobs = _effective_node(db, n).get("gpu_jobs") or "when_no_gpu_protected"
    warnings = []
    if cur:
        warnings.append(f"run {cur['run_id']} is already {cur['state']} on this node: abort it first")
    if spec["work"] != "cpu" and gpu_jobs == "never":
        warnings.append("this node's owner set gpu_jobs = never: no GPU work runs there to measure")
    return {"node_id": n["node_id"], "hostname": n["hostname"], "rule": r["id"], "source": r["protect"]["source"],
            "work": spec["work"], "duty": spec["duty"], "blocks": spec["blocks"], "window_s": spec["window_s"],
            "washout_s": spec["washout_s"], "margin": spec["margin"], "off": spec["off"],
            "planned_hours": round(spec["blocks"] * block_s / 3600, 2), "cap_hours": spec["max_hours"],
            "gpu_jobs": gpu_jobs, "warnings": warnings,
            "effect": "Runs the selected fleet work beside the protected process in ON windows and holds it in OFF "
                      "windows, in random order, until the margin is decided; protection stays active and a collapse "
                      "of the protected process's progress aborts the run."}


def _effective_node(db: DB, node: dict) -> dict:
    from . import protection
    from .settings import resolve as V
    return protection.effective(V.snapshot(db), node).get("node") or {}


def start(db: DB, ident: str, params: dict, actor: str, reason: str | None, sweep_id: str | None = None) -> dict:
    """Ask the node for a run (inside the caller's transaction)."""
    n = _node(db, ident)
    if n["lifecycle"] not in ("enrolled", "ready"):
        raise CotenancyError(f"node {n['hostname']} is {n['lifecycle']}: no run there")
    cur = active_run(db, n["node_id"])
    if cur:
        raise CotenancyError(f"run {cur['run_id']} is already {cur['state']} on {n['hostname']}: abort it first")
    r = _rule(db, n, str(params.get("rule") or ""))
    run_id = "ab_" + secrets.token_hex(6)
    spec = spec_of(params, run_id, r["id"])
    if spec["work"] != "cpu" and _effective_node(db, n).get("gpu_jobs") == "never" and spec["work"] != "all":
        raise CotenancyError("this node's owner set gpu_jobs = never: no GPU work runs there to measure")
    t = now()
    db.x("INSERT INTO ab_runs(run_id,node_id,rule,work,duty,spec_json,state,sweep_id,actor,reason,created_at) "
         "VALUES(?,?,?,?,?,?,?,?,?,?,?)", (run_id, n["node_id"], r["id"], spec["work"], spec["duty"], json.dumps(spec),
                                            "requested", sweep_id, actor, reason, t))
    db.event("ab_run_requested", actor=actor, node_id=n["node_id"], reason=reason,
             run_id=run_id, rule=r["id"], work=spec["work"], duty=spec["duty"])
    return {"run_id": run_id, "node_id": n["node_id"], "spec": spec}


def sweep(db: DB, ident: str, params: dict, actor: str, reason: str | None) -> dict:
    """A frontier search: runs at rising GPU duty levels (0.1, 0.2, 0.35, 0.5, ...), stopping at the first level that
    is not "no slowdown shown"; the highest passing level is the node's certified duty for the rule."""
    n = _node(db, ident)
    levels = levels_of(params)
    if not levels or any(not 0 < x <= 1 for x in levels) or levels != sorted(levels):
        raise CotenancyError("levels: rising duty fractions in (0, 1]")
    work = str(params.get("work") or "gpu")
    if work == "cpu":
        raise CotenancyError("a sweep searches GPU duty levels: work gpu, all, <module> or <module>/<workload>")
    sweep_id = "sw_" + secrets.token_hex(6)
    base = {k: params[k] for k in SPEC_KEYS if params.get(k) is not None}
    t = now()
    db.x("INSERT INTO ab_sweeps(sweep_id,node_id,rule,work,levels_json,spec_json,state,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
         (sweep_id, n["node_id"], str(params.get("rule") or ""), work, json.dumps(levels), json.dumps(base), "running", actor, t))
    first = start(db, n["node_id"], {**base, "rule": params.get("rule"), "work": work, "duty": levels[0]}, actor, reason,
                  sweep_id=sweep_id)
    return {"sweep_id": sweep_id, "levels": levels, "first_run": first["run_id"]}


def levels_of(params: dict) -> list[float]:
    """A sweep's duty levels: a list, or a comma-separated string (a form field); the default ladder without one."""
    raw = params.get("levels") or SWEEP_LEVELS
    if isinstance(raw, str):
        raw = [x for x in raw.replace(" ", "").split(",") if x]
    try:
        return [float(x) for x in raw]
    except (TypeError, ValueError):
        raise CotenancyError("levels: rising duty fractions in (0, 1], comma-separated")


def abort(db: DB, run_id: str, actor: str, reason: str | None) -> dict:
    r = db.one("SELECT * FROM ab_runs WHERE run_id=?", (run_id,))
    if not r:
        raise CotenancyError(f"no run {run_id!r}")
    if r["state"] in ("done", "aborted"):
        return {"run_id": run_id, "state": r["state"], "message": "already ended"}
    if r["state"] == "requested":
        _end(db, r, "aborted", "aborted before it started", None)
    else:
        db.x("UPDATE ab_runs SET abort_requested=1 WHERE run_id=?", (run_id,))
    db.event("ab_run_aborted", actor=actor, node_id=r["node_id"], reason=reason, run_id=run_id)
    return {"run_id": run_id, "state": "aborting" if r["state"] == "running" else "aborted"}


def _end(db: DB, run: dict, state: str, why: str, report: dict | None):
    rep = report or jl(run["report_json"], {}) or {}
    if report is None:
        rep = {**rep, "outcome": rep.get("outcome") or {"decision": "aborted", "reason": why, "analysis": None,
                                                         "ended_at": now()}}
    decision = ((rep.get("outcome") or {}).get("decision")) or ("aborted" if state == "aborted" else None)
    db.x("UPDATE ab_runs SET state=?, ended_at=?, decision=?, report_json=? WHERE run_id=?",
         (state, now(), decision, json.dumps(rep)[:400_000], run["run_id"]))
    if run.get("sweep_id"):
        _sweep_step(db, run["sweep_id"])


def _sweep_step(db: DB, sweep_id: str):
    sw = db.one("SELECT * FROM ab_sweeps WHERE sweep_id=?", (sweep_id,))
    if not sw or sw["state"] != "running":
        return
    runs = db.q("SELECT * FROM ab_runs WHERE sweep_id=? ORDER BY created_at", (sweep_id,))
    if any(r["state"] in ("requested", "running") for r in runs):
        return
    levels = json.loads(sw["levels_json"])
    passed = [r["duty"] for r in runs if r["decision"] == "no_slowdown"]
    last = runs[-1] if runs else None
    nxt = len(runs)
    if last and last["decision"] == "no_slowdown" and nxt < len(levels):
        base = jl(sw["spec_json"], {}) or {}
        try:
            start(db, sw["node_id"], {**base, "rule": sw["rule"], "work": sw["work"], "duty": levels[nxt]}, sw["actor"],
                  f"sweep {sweep_id} level {levels[nxt]}", sweep_id=sweep_id)
            return
        except CotenancyError as e:
            db.event("ab_sweep_stopped", node_id=sw["node_id"], reason=str(e), sweep_id=sweep_id)
    best = max(passed) if passed else None
    db.x("UPDATE ab_sweeps SET state='done', certified_duty=?, ended_at=? WHERE sweep_id=?", (best, now(), sweep_id))
    db.event("ab_sweep_done", node_id=sw["node_id"], reason=f"certified duty {best}" if best else "no level passed",
             sweep_id=sweep_id)


def issue(db: DB, run: dict, report: dict, context: dict | None) -> str | None:
    """A certificate for a run that showed no slowdown (once)."""
    a = ((report.get("outcome") or {}).get("analysis")) or {}
    if run.get("cert_id") or not a:
        return run.get("cert_id")
    cid = "ct_" + secrets.token_hex(6)
    t = now()
    db.x("INSERT INTO certificates(cert_id,node_id,rule,work,duty,r,r_lo,r_hi,margin,run_id,issued_at,valid_until,identity,"
         "context_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
         (cid, run["node_id"], run["rule"], run["work"], run["duty"], a.get("r"), a.get("r_lo"), a.get("r_hi"),
          a.get("margin"), run["run_id"], t, t + CERT_VALID_S, report.get("identity") or "", json.dumps(context or {})))
    db.x("UPDATE ab_runs SET cert_id=? WHERE run_id=?", (cid, run["run_id"]))
    db.event("certificate_issued", node_id=run["node_id"], reason=f"{run['rule']} {run['work']} duty {run['duty']}",
             cert_id=cid, run_id=run["run_id"], r=a.get("r"), r_lo=a.get("r_lo"))
    return cid


def ingest(db: DB, node: dict, reports, tel: dict):
    """The heartbeat's `ab_runs` (inside the heartbeat's transaction): store each known run's report, end it when
    the agent says it ended, and issue a certificate for "no slowdown shown"."""
    if not isinstance(reports, list):
        return
    for rep in reports[:4]:
        if not isinstance(rep, dict):
            continue
        run = db.one("SELECT * FROM ab_runs WHERE run_id=? AND node_id=?", (str(rep.get("run_id")), node["node_id"]))
        if not run or run["state"] in ("done", "aborted"):
            continue
        state = rep.get("state")
        text = json.dumps(rep)[:400_000]
        if run["state"] == "requested":
            db.x("UPDATE ab_runs SET state='running', started_at=? WHERE run_id=?", (rep.get("started_at") or now(), run["run_id"]))
        db.x("UPDATE ab_runs SET report_json=?, identity=COALESCE(?, identity) WHERE run_id=?",
             (text, rep.get("identity"), run["run_id"]))
        if state in ("done", "aborted"):
            run = db.one("SELECT * FROM ab_runs WHERE run_id=?", (run["run_id"],))
            ctx = tel.get("cert_context") if isinstance(tel.get("cert_context"), dict) else None
            db.x("UPDATE ab_runs SET context_json=? WHERE run_id=?", (json.dumps(ctx or {}), run["run_id"]))
            decision = (rep.get("outcome") or {}).get("decision")
            if decision == "no_slowdown" and state == "done":
                issue(db, run, rep, ctx)
            _end(db, db.one("SELECT * FROM ab_runs WHERE run_id=?", (run["run_id"],)), state, "", rep)


def agent_restarted(db: DB, nid: str):
    """A hello: the agent restarted, and a run it held is gone with it."""
    for r in db.q("SELECT * FROM ab_runs WHERE node_id=? AND state='running'", (nid,)):
        _end(db, r, "aborted", "the agent restarted during the run", None)
        db.event("ab_run_aborted", node_id=nid, reason="the agent restarted during the run", run_id=r["run_id"])


def certificates(db: DB, nid: str, at: float | None = None) -> list[dict]:
    """The node's certificates in force, as the agent takes them (protection `Certificate`)."""
    t = now() if at is None else at
    out = []
    for c in db.q("SELECT * FROM certificates WHERE node_id=? AND revoked_at IS NULL AND valid_until>? ORDER BY issued_at",
                  (nid, t)):
        out.append({"id": c["cert_id"], "rule": c["rule"], "work": c["work"], "duty": c["duty"], "r": c["r"],
                    "r_lo": c["r_lo"], "r_hi": c["r_hi"], "margin": c["margin"], "run_id": c["run_id"],
                    "issued_at": c["issued_at"], "valid_until": c["valid_until"], "identity": c["identity"] or "",
                    "context": jl(c["context_json"], {}) or {}})
    return out


def directives(db: DB, node: dict) -> dict:
    """The heartbeat reply's harness and certificate directives."""
    nid = node["node_id"]
    run = active_run(db, nid)
    aborts = [r["run_id"] for r in db.q("SELECT run_id FROM ab_runs WHERE node_id=? AND state='running' AND abort_requested=1",
                                        (nid,))]
    done = db.one("SELECT run_id FROM ab_runs WHERE node_id=? AND state IN ('done','aborted') ORDER BY ended_at DESC LIMIT 1",
                  (nid,))
    return {"ab_run": json.loads(run["spec_json"]) if run and not run["abort_requested"] else None,
            "ab_abort": aborts, "ab_ack": done["run_id"] if done else None,
            "certificates": certificates(db, nid)}


def status_of(c: dict, node: dict) -> tuple[str, str]:
    """Whether a certificate holds on its node now, as the node would judge it (from its telemetry)."""
    if c.get("revoked_at"):
        return "revoked", c.get("revoked_why") or "revoked"
    if c["valid_until"] <= now():
        return "expired", "expired"
    tel = jl(node.get("telemetry_json"), {}) or {}
    ctx = tel.get("cert_context") or {}
    want = jl(c.get("context_json"), {}) if isinstance(c.get("context_json"), str) else c.get("context") or {}
    if ctx and want and ctx != want:
        return "stale", "the node's hardware, OS or agent changed"
    ident = ((tel.get("protection") or {}).get("identities") or {}).get(c["rule"])
    if ident and c.get("identity") and ident != c["identity"]:
        return "stale", "the protected program changed"
    return "valid", ""


def list_runs(db: DB, node: str | None = None, limit: int = 50) -> list[dict]:
    if node:
        n = _node(db, node)
        rows = db.q("SELECT * FROM ab_runs WHERE node_id=? ORDER BY created_at DESC LIMIT ?", (n["node_id"], limit))
    else:
        rows = db.q("SELECT * FROM ab_runs ORDER BY created_at DESC LIMIT ?", (limit,))
    return [_run_doc(db, r, full=False) for r in rows]


def _run_doc(db: DB, r: dict, full: bool = True) -> dict:
    rep = jl(r["report_json"], {}) or {}
    outcome = rep.get("outcome") or {}
    host = (db.one("SELECT hostname FROM nodes WHERE node_id=?", (r["node_id"],)) or {}).get("hostname")
    doc = {"run_id": r["run_id"], "node_id": r["node_id"], "hostname": host, "rule": r["rule"], "work": r["work"],
           "duty": r["duty"], "state": r["state"], "decision": r["decision"], "created_at": r["created_at"],
           "started_at": r["started_at"], "ended_at": r["ended_at"], "actor": r["actor"], "reason": r["reason"],
           "sweep_id": r["sweep_id"], "cert_id": r["cert_id"], "blocks_done": len(rep.get("blocks") or []),
           "target_blocks": rep.get("target_blocks"), "excluded": len(rep.get("excluded") or []),
           "summary": abstats.describe(outcome.get("analysis") or {}) if outcome.get("analysis") else
           (outcome.get("reason") or {"requested": "Waiting for the node to start it.",
                                      "running": "Running."}.get(r["state"], ""))}
    if full:
        doc.update(spec=jl(r["spec_json"], {}), report=rep, outcome=outcome)
    return doc


def run_detail(db: DB, run_id: str) -> dict | None:
    r = db.one("SELECT * FROM ab_runs WHERE run_id=?", (run_id,))
    return _run_doc(db, r) if r else None


def list_certificates(db: DB, node: str | None = None) -> list[dict]:
    rows = (db.q("SELECT c.*, n.hostname FROM certificates c LEFT JOIN nodes n ON n.node_id=c.node_id WHERE c.node_id=? "
                 "ORDER BY issued_at DESC", (_node(db, node)["node_id"],)) if node else
            db.q("SELECT c.*, n.hostname FROM certificates c LEFT JOIN nodes n ON n.node_id=c.node_id ORDER BY issued_at DESC"))
    out = []
    for c in rows:
        n = db.one("SELECT * FROM nodes WHERE node_id=?", (c["node_id"],)) or {}
        st, why = status_of(c, n)
        out.append({"cert_id": c["cert_id"], "node_id": c["node_id"], "hostname": c["hostname"], "rule": c["rule"],
                    "work": c["work"], "duty": c["duty"], "r": c["r"], "r_lo": c["r_lo"], "r_hi": c["r_hi"],
                    "margin": c["margin"], "run_id": c["run_id"], "issued_at": c["issued_at"],
                    "valid_until": c["valid_until"], "status": st, "why": why})
    return out


def node_card(db: DB, node: dict) -> dict:
    """The node page's Co-tenancy card: per protected rule the GPU budget, the latest certificate, the event path's
    latency, and the latest run."""
    tel = jl(node.get("telemetry_json"), {}) or {}
    prot = tel.get("protection") or {}
    certs = [c for c in list_certificates(db, node["node_id"])]
    last = db.one("SELECT * FROM ab_runs WHERE node_id=? ORDER BY created_at DESC LIMIT 1", (node["node_id"],))
    budget = prot.get("gpu_budget")
    if budget:
        budget = {**budget, "units": _units(db, budget)}
    return {"gpu_budget": budget, "event_latency": prot.get("event_latency"),
            "phases": prot.get("phases") or [], "progress": prot.get("progress") or [],
            "certificates": certs[:20], "last_run": _run_doc(db, last, full=False) if last else None}


def _units(db: DB, budget: dict) -> list[dict]:
    """The duty governor's units (`gpu_budget.units`, by attempt id) with the job, module and stage each one runs."""
    out = []
    for u in budget.get("units") or []:
        a = db.one("SELECT a.attempt_id, a.job_id, a.state, j.module, j.stage FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                   "WHERE a.attempt_id=?", (u.get("id"),)) or {}
        out.append({**u, "attempt_id": u.get("id"), "job_id": a.get("job_id"), "module": a.get("module"),
                    "stage": a.get("stage"), "attempt_state": a.get("state")})
    return out


def duty_view(db: DB, node: str | None = None) -> list[dict]:
    """The GPU duty governor on each node (one with `node`), as its agent last reported it (`telemetry.protection.
    gpu_budget`, D50): the budget against the certified ceiling and the governor's state, the gating rules, each GPU
    unit's requested and measured duty and its compliance state, the units it does not trust, and its journaled
    budget steps and compliance actions of the last 24 hours. Nodes that report no budget (gpu_jobs is not certified, or
    no protected group is using the GPU) are left out unless named."""
    rows = [_node(db, node)] if node else db.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    since = now() - 86400
    out = []
    for n in rows:
        prot = (jl(n.get("telemetry_json"), {}) or {}).get("protection") or {}
        b = prot.get("gpu_budget")
        if not b and not node:
            continue
        b = b or {}
        steps = db.q("SELECT t, reason, record_json FROM protection_decisions WHERE node_id=? AND kind IN "
                     "('gpu_duty','gpu_compliance') AND t>=? ORDER BY t DESC, seq DESC LIMIT 50", (n["node_id"], since))
        out.append({"node_id": n["node_id"], "hostname": n["hostname"], "duty": b.get("duty"), "ceiling": b.get("ceiling"),
                    "state": b.get("state") or ("not_certified" if b.get("not_certified") else None),
                    "rules": b.get("rules") or [], "not_certified": b.get("not_certified") or [],
                    "per_job": b.get("per_job"), "jobs": b.get("jobs"), "lockout_s": b.get("lockout_s"),
                    "baseline": b.get("baseline") or {}, "units": _units(db, b), "distrusted": b.get("distrusted") or [],
                    "events": [{"t": r["t"], "reason": r["reason"], **(jl(r["record_json"], {}) or {})} for r in steps]})
    return out


def gpu_jobs_values() -> tuple[str, ...]:
    import typing
    return typing.get_args(P.NodeSection.model_fields["gpu_jobs"].annotation)
