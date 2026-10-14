"""A node's container runtime as placement sees it (docs/design/macos-containers.md, "When the runtime runs").

The owner's `containers` setting decides when a node's agent runs its container runtime (the Colima VM on macOS, the WSL
containers session on Windows, the host's engine on Linux):

- `always` (the default): from the first release that needs containers on; the agent reports its `containers` pool
  while the runtime is ready.
- `on_demand`: stopped until container work waits for the node. While stopped the agent reports the pool it would offer
  as *startable* (`container_runtime.startable` in its heartbeat's capacity): placement counts the node as able to run
  the work (readiness, goldens, retries and replicas), claim does not grant it there yet, and the heartbeat reply's
  `containers_wanted` tells the agent to start (`wanted`, below). The agent stops the runtime again after
  `containers_idle_stop_s` without container work or a `containers_wanted` hint, so a stopped VM holds no memory.
- `off`: never. The node offers no `containers` (or container `gpu`) pool whatever its agent reports, its jobs explain
  CONTAINERS_DISABLED with the fix, and it certifies only its stages that need no containers.

Waking is fleet-aware so one waiting job does not start every on-demand VM at once: a stopped node is told to start
when the waiting container work it could run needs more `containers` tokens than the fleet already has free on running
runtimes plus the startable tokens of nodes told to start in the last WAKE_TTL seconds, or at once for its own golden
jobs (its certification). A running on-demand runtime is told the work is still there (`containers_wanted`), which keeps
it from stopping while such work waits.
"""
from .db import DB, jl

MODES = ("always", "on_demand", "off")
POOLS = ("containers", "gpu")            # the agent's own pools: the container runtime's, and GPU passthrough to it
WAKE_TTL = 300.0                         # how long a node told to start counts as coming supply
WAKES = "container_wakes"                # system_state: {node_id: when it was told to start}
CANDIDATES = 200                         # waiting container jobs looked at per heartbeat


def mode(node: dict) -> str:
    """The node's effective `containers` setting, as the coordinator last computed it (always for an unknown value)."""
    from .settings.apply import flat_values
    m = flat_values(node).get("containers")
    return m if m in MODES else "always"


def runtime(node: dict) -> dict:
    """What the agent last reported of its runtime (its heartbeat's `containers`, kept in capacity_json as
    `container_runtime`): {mode, state, startable, start_s, idle_stop_s, vm}; {} from an agent that reports none."""
    rt = (jl(node.get("capacity_json"), {}) or {}).get("container_runtime")
    return rt if isinstance(rt, dict) else {}


def pools_off(node: dict) -> set:
    """The pools a node never offers because its owner turned containers off there."""
    return set(POOLS) if mode(node) == "off" else set()


def startable(node: dict) -> dict:
    """The pools a stopped on-demand runtime offers once started ({} unless it is stopped and could start)."""
    if mode(node) == "off":
        return {}
    rt = runtime(node)
    if rt.get("state") != "stopped":
        return {}
    out = {}
    for p, k in (rt.get("startable") or {}).items():
        if p in POOLS and isinstance(k, (int, float)) and not isinstance(k, bool) and k > 0:
            out[p] = int(k)
    return out


def start_s(node: dict) -> int:
    """How long the node's runtime takes to start, as its agent measured it (60 s before it has started once)."""
    v = runtime(node).get("start_s")
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 else 60


def needs_containers(res: dict | None) -> bool:
    res = res or {}
    return "containers" in (res.get("pools") or {}) or "containers" in (res.get("needs_pools") or [])


def _tokens(res: dict) -> int:
    return max(1, int((res.get("pools") or {}).get("containers") or 1))


def _waiting(db: DB, nid: str, t: float) -> list[dict]:
    """Pending jobs that need the containers pool and might run on node `nid` now (its own goldens included)."""
    rows = db.q("SELECT j.* FROM jobs j LEFT JOIN campaigns c ON c.campaign_id=j.campaign_id "
                "WHERE j.state='pending' AND j.not_before<=? AND j.resources_json LIKE '%\"containers\"%' "
                "AND (j.target_node IS NULL OR j.target_node=?) AND (j.kind!='golden' OR j.target_node=?) "
                "AND (j.kind='golden' OR c.state='running' OR j.campaign_id IS NULL) "
                "AND (j.depends_on IS NULL OR EXISTS (SELECT 1 FROM jobs d WHERE d.job_id=j.depends_on AND d.state='done')) "
                "ORDER BY j.priority DESC, j.job_id ASC LIMIT ?", (t, nid, nid, CANDIDATES))
    return [j for j in rows if needs_containers(jl(j["resources_json"], {}))]


def _could_run(db: DB, node: dict, j: dict) -> bool:
    """Whether the node could run the job once its runtime is up: what claim checks of the node, except the containers
    pool itself (a starting runtime offers none yet) and its free tokens and capacity now."""
    from . import core, predicates
    if j["kind"] == "golden":
        return j["target_node"] == node["node_id"]
    f = core._job_facts(db, j)
    return (core._module_serves(node, f) and predicates.platform_fits(f, node.get("platform"))
            and predicates.capabilities_fit(f, predicates.node_capabilities(node, j["module"]))
            and predicates.gpu_apis_fit(f, node.get("platform"), predicates.node_gpu_apis(node))
            and core._pools_fit(node, _without_containers(jl(j["resources_json"], {}))))


def _without_containers(res: dict) -> dict:
    return {**res, "pools": {p: k for p, k in (res.get("pools") or {}).items() if p != "containers"},
            "needs_pools": [p for p in res.get("needs_pools") or [] if p != "containers"]}


def _supply(db: DB, nid: str, modules: set, t: float, wakes: dict) -> int:
    """Free `containers` tokens elsewhere for these modules: on running runtimes (their pool less what live attempts hold),
    plus the startable tokens of nodes told to start within WAKE_TTL."""
    from . import core
    free = 0
    for n in db.q("SELECT * FROM nodes WHERE lifecycle='ready' AND node_id!=? AND desired_state='active'", (nid,)):
        states = core.node_modules(n)
        if not any(states.get(m, {}).get("state") == "certified" for m in modules):
            continue
        cap = int(core._node_pools(n).get("containers") or 0)
        if cap > 0:
            free += max(0, cap - int(core._pool_usage(db, n["node_id"]).get("containers", 0)))
        elif t - float(wakes.get(n["node_id"]) or 0) < WAKE_TTL:
            free += int(startable(n).get("containers") or 0)
    return free


def wanted(db: DB, node: dict, t: float) -> bool:
    """The heartbeat reply's `containers_wanted` for an on-demand node: container work it could run waits (a running
    runtime then stays up), and, for a stopped one, the fleet has too few free tokens for it, or it is its own golden
    work. Recording a wake makes it count as coming supply for the other nodes' replies."""
    if mode(node) != "on_demand" or node.get("lifecycle") != "ready" or node.get("desired_state") != "active":
        return False
    rt = runtime(node)
    state = rt.get("state")
    if state not in ("stopped", "starting", "running"):
        return False
    nid = node["node_id"]
    jobs = [j for j in _waiting(db, nid, t) if _could_run(db, node, j)]
    if not jobs:
        return False
    if state in ("starting", "running"):
        return True
    if not startable(node).get("containers"):
        return False
    wakes = {k: v for k, v in (db.get_state(WAKES, {}) or {}).items() if t - float(v or 0) < WAKE_TTL}
    own = any(j["kind"] == "golden" for j in jobs)
    demand = sum(_tokens(jl(j["resources_json"], {})) for j in jobs if j["kind"] != "golden")
    if not own and demand <= _supply(db, nid, {j["module"] for j in jobs}, t, wakes):
        return False
    if nid not in wakes:
        db.event("containers_wake", node_id=nid, actor="system",
                 reason=f"{len(jobs)} waiting container job{'s' if len(jobs) != 1 else ''}" + (" (its goldens)" if own else ""))
    wakes[nid] = t
    db.set_state(WAKES, wakes)
    return True


def shown(node: dict) -> bool:
    """Whether the node's container line says anything: the owner set the mode, or its agent reports a runtime a
    release needs."""
    rt = runtime(node)
    return mode(node) != "always" or bool(rt and rt.get("state") != "absent")


def line(node: dict) -> str:
    """The node's container runtime in one line: its mode, state and VM size (configured and running)."""
    m, rt = mode(node), runtime(node)
    facts = jl(node.get("facts_json"), {}) or {}
    ct = facts.get("containers") or {}
    state = rt.get("state") or ct.get("state") or "unknown"
    parts = [f"containers = {m}", state]
    vm = rt.get("vm") or ct.get("vm") or {}
    want = vm.get("mem_gb"), vm.get("cpus")
    have = vm.get("actual_mem_gb"), vm.get("actual_cpus")
    if want[0] is not None:
        size = f"VM {want[0]:g} GB, {want[1]} CPUs"
        if have[0] is not None and (abs(float(have[0]) - float(want[0])) > 0.3 or (have[1] and have[1] != want[1])):
            size += f" (running at {float(have[0]):g} GB, {have[1]} CPUs: restarts at the new size when idle)"
        elif have[0] is not None:
            size += " (running at that size)"
        parts.append(size)
    if m == "on_demand" and state == "stopped":
        parts.append(f"starts when container work waits (about {start_s(node)} s), {int(rt.get('idle_stop_s') or 600)} s idle stops it")
    return " · ".join(parts)
