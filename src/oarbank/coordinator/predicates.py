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

from oarbank_sdk import gpu as gpuapi
from oarbank_sdk import platform as pf
from oarbank_sdk import runner_protocol as rp

from ..contracts.explain import PredicateResult

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"
# module states (core._lifecycle_step) in which a node runs a module's certification-exempt stages, given that its runner
# started (doctor_ran): every state the doctor decides, but not `revoked` (a breaker trip or a golden mismatch, until the
# doctor runs again) or none at all (no doctor report yet). docs/design/stage-gating.md
RUNNER_STATES = ("certified", "certifying", "doctor_failed", "undetected", "golden_failed")
# node exclusions (modsandbox.node_exclusions) that keep only some of a module's jobs off a node: a host tool the registry
# has no path for matters to no job of a stage that needs no certification (it needs no capability, which is what a tool
# serves, and a bootstrap job gets no tools at all), and an unmapped folder to no bootstrap job (it gets no folders)
SPARED = {"TOOL_UNAVAILABLE": "exempt", "FOLDER_UNAVAILABLE": "bootstrap"}


def spared(code: str | None, job: dict) -> bool:
    """Does a node exclusion with this code leave the job free to run there (SPARED)?"""
    who = SPARED.get(code or "")
    return bool(who) and bool(job.get("bootstrap") if who == "bootstrap" else (job.get("exempt") or job.get("bootstrap")))


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
    excluded: dict = field(default_factory=dict)   # {module: reason}: platform, OS version, tools, sandbox, agent (modsandbox)
    excluded_why: dict = field(default_factory=dict)   # {module: the module's own words}: requires.unsupported.runner
    capabilities: dict = field(default_factory=dict)   # {module: node_capabilities(node, module)} for the offered modules
    gpu_apis: dict = field(default_factory=lambda: {"host": [], "containers": []})   # node_gpu_apis(node)
    bootstrap_grants: bool = False    # the agent runs bootstrap jobs with the bootstrap grants (modsandbox.bootstrap_enforced)
    runner_ready: set = field(default_factory=set)   # offered modules whose runner started here (doctor_ran) in a RUNNER_STATE
    secrets_unset: dict = field(default_factory=dict)  # {module: declared secrets with no readable value for this node}
    release_of: object = None         # () -> releases.node_release(node): read only when a release check fails

    @property
    def certified(self) -> set:
        return {m for m, st in self.states.items() if st.get("state") == "certified"} & self.offered

    @property
    def certifying(self) -> set:
        return {m for m, st in self.states.items() if st.get("state") == "certifying"} & self.offered

    @property
    def serving(self) -> set:
        """Modules some job may run here: certified, certifying (goldens, bootstrap stages) or runner-ready (the stages
        that need no certification)."""
        return self.certified | self.certifying | (self.runner_ready & self.offered)

    @property
    def max_new(self) -> int:
        return int(self.limits["jobs"]) - self.live if self.limits.get("jobs") is not None else 10 ** 6


def doctor_report(node: dict, module: str) -> dict:
    """The module's entry in the node's latest doctor report ({} when there is none)."""
    doc = json.loads(node.get("doctor_json") or "null") or {}
    return (doc.get("modules") or {}).get(module) or {}


def doctor_ran(node: dict, module: str) -> bool:
    """Did the module's runner start on the node: its doctor printed a DoctorOutput, for the node's current release
    (docs/protocol.md "Doctor": the agent's `ran`; a report from an agent that predates it counts unless it is the
    agent's own failure, its `doctor` check)."""
    doc = json.loads(node.get("doctor_json") or "null") or {}
    rep = (doc.get("modules") or {}).get(module)
    if not rep or (doc.get("release_id") and node.get("release_id") and doc["release_id"] != node["release_id"]):
        return False
    if rep.get("ran") is not None:
        return bool(rep["ran"])
    return not any(c.get("name") == "doctor" and not c.get("ok") for c in rep.get("checks") or [] if isinstance(c, dict))


def doctor_failed_checks(node: dict, module: str) -> list[str]:
    """The names of the module's failed doctor checks on the node (explain's wording)."""
    return [c.get("name") for c in doctor_report(node, module).get("checks") or []
            if isinstance(c, dict) and not c.get("ok") and c.get("name")]


def node_capabilities(node: dict, module: str) -> set:
    """The capabilities a node has for `module`, from its latest doctor report (docs/protocol.md "Doctor"): those its
    offered services and healthy probes provide, and the ones the module's own doctor reported, less every capability a
    failed check of the module's doctor is named after (oarbank-sdk runner_protocol.disproved_capabilities)."""
    doc = json.loads(node.get("doctor_json") or "null") or {}
    rep = (doc.get("modules") or {}).get(module) or {}
    have = set(doc.get("capabilities") or []) | set(rep.get("capabilities") or [])
    return have - rp.disproved_capabilities(rep.get("checks"))


def node_gpu_apis(node: dict) -> dict:
    """The GPU APIs a node provides, {host, containers}, from its latest doctor report (docs/protocol.md "Doctor"); a
    node that has not reported provides none."""
    doc = json.loads(node.get("doctor_json") or "null") or {}
    g = doc.get("gpu_apis") or {}
    return {"host": sorted(g.get("host") or []), "containers": sorted(g.get("containers") or [])}


def gpu_unmet(job: dict, platform: str | None, have: dict) -> list[dict]:
    """The GPU API groups of the job's stage (modcalls.stage_gpu_apis, for the node's platform) that a node with `have`
    (node_gpu_apis) does not meet; empty: it may run the job here."""
    return gpuapi.unmet(job["gpu_apis"].get(platform, []) if platform else [], have)


def gpu_apis_fit(job: dict, platform: str | None, have: dict) -> bool:
    return not gpu_unmet(job, platform, have)


def module_serves(job: dict, state: str | None, bootstrap_grants: bool, ran: bool = False) -> bool:
    """Could a node whose module is in `state` run the job (claim's module and bootstrap-grants checks, for the questions
    asked of every node): certified; for a job of a stage that needs no certification (`exempt`: a bootstrap stage, or
    one that compares nothing and needs no capability or pool), any RUNNER_STATE on a node where the module's runner
    started (`ran`), and for a bootstrap job only where the agent applies the bootstrap grants."""
    if job.get("exempt"):
        return ran and state in RUNNER_STATES and (bootstrap_grants or not job.get("bootstrap"))
    return state == "certified"


def capabilities_fit(job: dict, have: set) -> bool:
    """Does a node with capabilities `have` (for the job's module) hold every one the job's stage needs?"""
    return set(job["stage_capabilities"]) <= have


def _no_module_code(nv: NodeView) -> str:
    """Why no module runs here: the commonest exclusion when modules are excluded (platform, sandbox, agent), else a
    doctor that failed or never ran (no runner started), else certification."""
    if nv.excluded and not (nv.offered & set(nv.states)):
        reasons = sorted(nv.excluded.values())
        return max(set(reasons), key=reasons.count)
    if any(nv.states.get(m, {}).get("state") in ("doctor_failed", "undetected", "golden_failed") for m in nv.offered):
        return "MODULE_NOT_READY"
    return "MODULE_NOT_CERTIFIED"


def release_code(nv: NodeView) -> str:
    """Why a node runs no current release: none exists for its platform yet (no module enabled), the one it needs waits
    for the owner's signature, or it is installing it."""
    st = (nv.release_of() if nv.release_of else {}).get("state")
    return {"none": "NO_RELEASE", "unsigned": "RELEASE_UNSIGNED"}.get(st, "RELEASE_PENDING")


def admission(nv: NodeView, first_fail: bool = False) -> list[PredicateResult]:
    n = nv.node
    checks = [
        lambda: R("fleet_state = active", "OARBANK_PAUSED", nv.fleet_state == "active", nv.fleet_state, "active", "admission"),
        lambda: R("desired_state = active", "NODE_DRAINING" if n["desired_state"] == "draining" else "NODE_PAUSED_BY_ADMIN",
                  n["desired_state"] == "active", n["desired_state"], "active", "admission"),
        lambda: R("lifecycle = ready", {"quarantined": "NODE_QUARANTINED", "retired": "NODE_RETIRED"}.get(n["lifecycle"])
                  or ("RELEASE_PENDING" if n["lifecycle"] == "ready" else release_code(nv)),
                  n["lifecycle"] == "ready", n["lifecycle"], "ready", "admission"),
        lambda: R("release current", "RELEASE_PENDING" if n["release_id"] == nv.current_release else release_code(nv),
                  n["release_id"] == nv.current_release, n["release_id"], nv.current_release, "admission"),
        lambda: R("free cpu > 0", "INSUFFICIENT_CPU", nv.free_cpu > 0, nv.free_cpu, "> 0", "admission"),
        lambda: R("a module certified, certifying or runner-ready", _no_module_code(nv), bool(nv.serving),
                  sorted(nv.serving), "non-empty", "admission"),
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
    exempt = job.get("exempt") or boot                     # a stage that needs no certification (docs/design/stage-gating.md)

    def module_check():
        if mod in nv.excluded and not spared(nv.excluded[mod], job):
            return R(f"module_runs_here({mod})", nv.excluded[mod], False, nv.excluded_why.get(mod, nv.excluded[mod]), "supported")
        state = nv.states.get(mod, {}).get("state")
        code = "MODULE_DISABLED" if mod in nv.disabled else \
            "MODULE_NOT_READY" if state in ("doctor_failed", "undetected", "golden_failed") \
            else "MODULE_NOT_CERTIFIED"
        if exempt:                                         # the runner started: the doctor's health does not matter
            if mod not in nv.disabled and state != "revoked":
                code = "MODULE_NOT_READY"                  # its doctor has not run, or its runner did not start
            ready = mod in nv.runner_ready and mod in nv.offered
            observed = f"{state}, runner started" if ready else f"{state or 'no doctor report'}, runner not started"
            return R(f"module_ready_for_bootstrap({mod})" if boot else f"module_runner_ready({mod})", code, ready, observed,
                     "runner started (a doctor report), not revoked")
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
        lambda: (lambda miss: R("gpu apis", "GPU_API_MISSING", not miss, nv.gpu_apis,
                                [f"{gpuapi.describe(g)} ({g['source']})" for g in miss] or None))(gpu_unmet(job, plat, nv.gpu_apis)),
        lambda: (lambda miss: R("secrets set for this node", "SECRETS_NOT_SET", not miss, miss, job["secrets"]))(
            sorted(set(job["secrets"]) & nv.secrets_unset.get(mod, set()))),
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
