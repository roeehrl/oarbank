"""The placement predicates claim() and explain share (PLAN D16; admin-console.md "The claim path and the
explainer share one pure predicate function").

`admission(nv)` is the node-level checklist (is this node taking work at all?); `placement(job, nv)` is
the per-job checklist (does this job fit this node?). Both are pure functions of their inputs and return
PredicateResults carrying a reason code, pass/fail/unknown and the observed and required values.
claim() runs them in first-fail mode on the hot path; explain runs them in full over every node. A
property test (tests/test_explain.py) asserts that explain's verdict equals claim's decision.
"""
import json
from dataclasses import dataclass, field

from oarbank_sdk import platform as pf

from ..contracts.explain import PredicateResult

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"


def R(predicate, code, ok, observed=None, required=None, layer="placement", unknown=False) -> PredicateResult:
    return PredicateResult(predicate=predicate, code=code, outcome=UNKNOWN if unknown else (PASS if ok else FAIL),
                           observed=observed, required=required, layer=layer)


@dataclass
class NodeView:
    """Every node-level fact claim() decides on, read inside its transaction (TLA+ F1)."""
    node: dict
    states: dict                      # modules_json
    offered: set                      # modules the agent offers minus fleet-disabled ones
    disabled: set
    ready: set                        # datasets staged on the node
    free_cpu: float
    free_mem: float
    live: int
    limits: dict
    fleet_state: str
    current_release: str | None
    pool_cap: dict                    # pools the node offers (core._node_pools)
    pool_use: dict = field(default_factory=dict)
    failed_here: set = field(default_factory=set)
    pool_jobs_only: bool = False
    gpu_cap: int | None = None        # the agent's gpu_jobs ceiling (None: not limited)
    gpu_use: int = 0                  # live GPU attempts on the node
    excluded: dict = field(default_factory=dict)   # {module: reason}: platform, OS version, sandbox, agent (modsandbox)
    excluded_why: dict = field(default_factory=dict)   # {module: the module's own words}: requires.unsupported.runner
    capabilities: dict = field(default_factory=dict)   # {module: node_capabilities(node, module)} for the offered modules
    bootstrap_grants: bool = False    # the agent runs bootstrap jobs with the bootstrap grants (modsandbox.bootstrap_enforced)

    @property
    def certified(self) -> set:
        return {m for m, st in self.states.items() if st.get("state") == "certified"} & self.offered

    @property
    def certifying(self) -> set:
        return {m for m, st in self.states.items() if st.get("state") == "certifying"} & self.offered

    @property
    def max_new(self) -> int:
        return int(self.limits["jobs"]) - self.live if self.limits.get("jobs") is not None else 10 ** 6


def node_capabilities(node: dict, module: str) -> set:
    """The capabilities a node has for `module`, from its latest doctor report (docs/protocol.md "Doctor"): those its
    offered services and healthy probes provide, and the ones the module's own doctor reported."""
    doc = json.loads(node.get("doctor_json") or "null") or {}
    return set(doc.get("capabilities") or []) | set(((doc.get("modules") or {}).get(module) or {}).get("capabilities") or [])


def module_serves(job: dict, state: str | None, bootstrap_grants: bool) -> bool:
    """Could a node whose module is in `state` run the job (claim's module and bootstrap-grants checks, for the questions
    asked of every node): certified; for a bootstrap job, certified or certifying (a healthy doctor) on a node whose agent
    applies the bootstrap grants."""
    if job["bootstrap"]:
        return bootstrap_grants and state in ("certified", "certifying")
    return state == "certified"


def capabilities_fit(job: dict, have: set) -> bool:
    """Does a node with capabilities `have` (for the job's module) hold every one the job's stage needs?"""
    return set(job["stage_capabilities"]) <= have


def _no_module_code(nv: NodeView) -> str:
    """Why no module runs here: the commonest exclusion when modules are excluded (platform, sandbox, agent), else
    certification."""
    if nv.excluded and not (nv.offered & set(nv.states)):
        reasons = sorted(nv.excluded.values())
        return max(set(reasons), key=reasons.count)
    return "MODULE_NOT_CERTIFIED"


def admission(nv: NodeView, first_fail: bool = False) -> list[PredicateResult]:
    n = nv.node
    checks = [
        lambda: R("fleet_state = active", "OARBANK_PAUSED", nv.fleet_state == "active", nv.fleet_state, "active", "admission"),
        lambda: R("desired_state = active", "NODE_DRAINING" if n["desired_state"] == "draining" else "NODE_PAUSED_BY_ADMIN",
                  n["desired_state"] == "active", n["desired_state"], "active", "admission"),
        lambda: R("lifecycle = ready", {"quarantined": "NODE_QUARANTINED", "retired": "NODE_RETIRED"}.get(n["lifecycle"], "RELEASE_PENDING"),
                  n["lifecycle"] == "ready", n["lifecycle"], "ready", "admission"),
        lambda: R("release current", "RELEASE_PENDING", n["release_id"] == nv.current_release, n["release_id"],
                  nv.current_release, "admission"),
        lambda: R("free cpu > 0", "INSUFFICIENT_CPU", nv.free_cpu > 0, nv.free_cpu, "> 0", "admission"),
        lambda: R("a module certified (or certifying)", _no_module_code(nv), bool(nv.certified or nv.certifying),
                  sorted(nv.certified | nv.certifying), "non-empty", "admission"),
        lambda: R("jobs cap", "USER_CAP_BINDING", nv.max_new > 0, nv.live, nv.limits.get("jobs"), "admission"),
    ]
    return _run(checks, first_fail)


def retry_max(job: dict, platform: str | None) -> int:
    """The execution attempts the job's stage allows on a node of `platform` (stages[].retry, its variant applied)."""
    r = job["retry"]
    return int(pf.resolve(r["by_platform"], platform, default=r["max"]) if platform else r["max"])


def _cls(platform: str | None, mix: str | None) -> str | None:
    return pf.class_key(platform, mix) if platform else None


def platform_fits(job: dict, platform: str | None) -> bool:
    """Could a node of `platform` ever run the job (job facts, core._job_facts): its stage, its own and its datasets'
    platforms, its unit's class (bound, or a feasible one) and its comparison class. claim() and explain check each
    part as its own predicate below; the reaper and replication ask this question of every node."""
    pl, cmp = job["placement"], job["dispute"]
    if not platform:                                       # a node that reported no platform fits only unconstrained work
        return not (job["stage_platforms"] or pl["platforms"] or pl["dataset_platforms"] or pl["units"] or cmp.get("class"))
    return (not job["stage_platforms"] or platform in job["stage_platforms"]) \
        and pf.matches(platform, pl["platforms"]) and all(d == platform for d in pl["dataset_platforms"]) \
        and all(_cls(platform, u["mix"]) == u["class"] if u["class"] else _cls(platform, u["mix"]) in u["feasible"]
                for u in pl["units"]) \
        and (not cmp.get("class") or _cls(platform, cmp.get("scope")) == cmp["class"])


def placement(job: dict, nv: NodeView, now: float, *, dep_done: bool, campaign_state: str | None,
              other_can_take=lambda: True, datasets: list | None = None, resources: dict | None = None,
              dep_artifacts: bool = True, first_fail: bool = False, gpu: bool = False) -> list[PredicateResult]:
    """Does `job` fit `nv`? The order is claim()'s; `other_can_take` is evaluated only when needed."""
    nid = nv.node["node_id"]
    res = resources or {"cpu": 1, "mem_gb": 1.0}
    need_cpu, need_mem = float(res.get("cpu", 1)), float(res.get("mem_gb", 1.0))
    dispute_nodes = set((job.get("dispute") or {}).get("nodes", []))
    cmp = job.get("dispute") or {}                         # replicas and tie-breaks compare within {scope, class}
    stage_platforms = job["stage_platforms"]               # stages[].requires.platforms (empty: every platform)
    stage_caps = job["stage_capabilities"]                 # stages[].requires.capabilities
    plat, pl = nv.node.get("platform"), job["placement"]   # the job's platforms, its datasets' and its unit chain (D33)
    units = pl["units"]
    mod = job["module"]
    golden = job["kind"] == "golden"
    boot = job["bootstrap"]                                # a bootstrap stage's job: runs before the goldens pass

    def module_check():
        if mod in nv.excluded:
            return R(f"module_runs_here({mod})", nv.excluded[mod], False, nv.excluded_why.get(mod, nv.excluded[mod]), "supported")
        state = nv.states.get(mod, {}).get("state")
        code = "MODULE_DISABLED" if mod in nv.disabled else \
            "MODULE_NOT_READY" if state in ("doctor_failed", "undetected", "golden_failed") \
            else "MODULE_NOT_CERTIFIED"
        if boot:                                           # the doctor is healthy and the release current: certifying will do
            return R(f"module_ready_for_bootstrap({mod})", code, mod in (nv.certified | nv.certifying), state,
                     "certified or certifying")
        ok = mod in nv.certified or (golden and mod in (nv.certified | nv.certifying))
        return R(f"module_certified({mod})", code, ok, state, "certified")

    def pool_checks():
        if not (res.get("pools") or res.get("needs_pools")):
            return [R("pools", "POOL_EXHAUSTED", True, None, None)]
        out = []
        for p in res.get("needs_pools") or []:
            out.append(R(f"pool({p}) exists", "POOL_ABSENT", int(nv.pool_cap.get(p, 0)) > 0, nv.pool_cap.get(p, 0), "> 0"))
        for p, k in (res.get("pools") or {}).items():
            free = int(nv.pool_cap.get(p, 0)) - nv.pool_use.get(p, 0)
            out.append(R(f"pool({p}) >= {k}", "POOL_EXHAUSTED", free >= int(k), free, int(k)))
        return out

    checks = [
        lambda: R("state = pending", "QUEUED_BEHIND", job["state"] == "pending", job["state"], "pending"),
        lambda: R("not_before <= now", "BACKOFF", (job.get("not_before") or 0) <= now, job.get("not_before"), now),
        lambda: R("target node", "PINNED_ELSEWHERE", job.get("target_node") in (None, nid), job.get("target_node"), nid),
        lambda: R("dependency done", "DEPENDENCY_UNMET", not job.get("depends_on") or dep_done, dep_done, True),
        lambda: R("campaign running", "CAMPAIGN_PAUSED", golden or job.get("campaign_id") is None or campaign_state == "running",
                  campaign_state, "running"),
        lambda: R("golden only on its node", "PINNED_ELSEWHERE", not golden or job.get("target_node") == nid,
                  job.get("target_node"), nid),
        lambda: (lambda left: R("retries left (stage retry)", "RETRIES_EXHAUSTED", golden or left > 0, left, "> 0"))(
            retry_max(job, nv.node.get("platform")) - int(job.get("exec_failures") or 0)),
        lambda: R("not failed here (or no other node)", "FAILED_HERE",
                  not (job["job_id"] in nv.failed_here and other_can_take()), job["job_id"] in nv.failed_here, False),
        lambda: R("not a dispute party", "DISPUTE_PARTY", nid not in dispute_nodes, sorted(dispute_nodes), f"excludes {nid}"),
        lambda: R("comparison class", "COMPARED_ON_PLATFORM", not cmp.get("class") or _cls(plat, cmp.get("scope")) == cmp["class"],
                  _cls(plat, cmp.get("scope")), cmp.get("class")),
        module_check,
        lambda: R("stage platform", "STAGE_PLATFORM_UNSUPPORTED",
                  not stage_platforms or nv.node.get("platform") in stage_platforms, nv.node.get("platform"), stage_platforms),
        lambda: R("bootstrap grants enforced", "CAPABILITY_NOT_ENFORCED", not boot or nv.bootstrap_grants,
                  nv.bootstrap_grants if boot else None, True if boot else None),
        lambda: (lambda have: R("stage capabilities", "STAGE_CAPABILITY_MISSING", capabilities_fit(job, have),
                                sorted(have & set(stage_caps)), stage_caps))(nv.capabilities.get(mod, set())),
        lambda: R("job platforms", "STAGE_PLATFORM_UNSUPPORTED", bool(plat) and pf.matches(plat, pl["platforms"]) if pl["platforms"]
                  else True, plat, pl["platforms"]),
        lambda: R("a feasible class of its unit", "STAGE_PLATFORM_UNSUPPORTED",
                  all(_cls(plat, u["mix"]) in u["feasible"] for u in units), [_cls(plat, u["mix"]) for u in units],
                  [u["feasible"] for u in units]),
        lambda: R("dataset platform", "DATASET_PLATFORM_MISMATCH", all(d == plat for d in pl["dataset_platforms"]), plat,
                  pl["dataset_platforms"]),
        lambda: R("unit pinned", "PLACEMENT_UNPINNED", not any(u["bind"] == "explicit" and u["state"] == "unbound" for u in units),
                  [u["state"] for u in units], "pinned"),
        lambda: R("unit class", "PLATFORM_BOUND_ELSEWHERE", all(not u["class"] or _cls(plat, u["mix"]) == u["class"] for u in units),
                  [_cls(plat, u["mix"]) for u in units], [u["class"] for u in units]),
        lambda: R("datasets registered", "DATASETS_NOT_REGISTERED", not pl["unregistered"], pl["unregistered"], "[]"),
        lambda: R("datasets staged", "DATASETS_NOT_STAGED", set(datasets or []) <= nv.ready,
                  sorted(set(datasets or []) - nv.ready), "[]"),
        lambda: R(f"cpu({need_cpu:g}) <= free", "INSUFFICIENT_CPU", need_cpu <= nv.free_cpu, nv.free_cpu, need_cpu),
        lambda: R(f"mem_gb({need_mem:g}) <= free", "INSUFFICIENT_MEM", need_mem <= nv.free_mem, nv.free_mem, need_mem),
        pool_checks,
        lambda: R("gpu job allowed", "GPU_BLOCKED", not gpu or nv.gpu_cap is None or nv.gpu_use < nv.gpu_cap,
                  None if not gpu else nv.gpu_use, None if not gpu else nv.gpu_cap),
        lambda: R("pool jobs only (yielding)", "POOL_JOBS_ONLY", not (nv.pool_jobs_only and not res.get("pools")),
                  nv.pool_jobs_only, False),
        lambda: (lambda ok: R("dependency output usable", "DEPENDENCY_UNMET", ok, ok, True))(
            True if not job.get("depends_on") else (dep_artifacts() if callable(dep_artifacts) else bool(dep_artifacts))),
    ]
    return _run(checks, first_fail)


def _run(checks, first_fail):
    out = []
    for c in checks:
        r = c()
        rs = r if isinstance(r, list) else [r]
        out.extend(rs)
        if first_fail and any(x.outcome != PASS for x in rs):
            break
    return out


def eligible(results: list[PredicateResult]) -> bool:
    return all(r.outcome == PASS for r in results)


def first_failure(results: list[PredicateResult]) -> PredicateResult | None:
    return next((r for r in results if r.outcome != PASS), None)
