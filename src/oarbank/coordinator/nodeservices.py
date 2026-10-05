"""Module services on nodes, as their agents report them (docs/protocol.md, "Services and probes"): every heartbeat
carries the agent's service report, kept in `nodes.services_json`. The node page, `oarbank node show` and the module
pages' `services` and `nodes` queries all read it through `rows`."""
from .db import jl


def row(s: dict, n: dict) -> dict:
    """One service of a node's report: its state and, when it is not running, why."""
    running, ready = bool(s.get("running")), bool(s.get("ready"))
    module, _, name = str(s.get("service", "")).partition("/")
    why = (f"held: {s['held']}" if s.get("held") else "disabled" if s.get("disabled") else
           "withdrawn" if s.get("withdrawn") else "gpu api missing" if s.get("gpu_api_missing") else "idle")
    return {"node_id": n["node_id"], "hostname": n["hostname"], "module": module, "service": name, "health": s.get("health"),
            "state": ("ready" if ready else "starting") if running else "stopped", "stopped_reason": None if running else why,
            "error": s.get("error"), "gpu_api_missing": s.get("gpu_api_missing"), "lifecycle": s.get("lifecycle"),
            "users": s.get("users"), "endpoint": bool(s.get("endpoint")), "reported_at": n.get("services_at")}


def rows(n: dict, module: str | None = None) -> list[dict]:
    """Every service in the node's latest report (only `module`'s with a module)."""
    out = [row(s, n) for s in (jl(n.get("services_json"), {}) or {}).get("services") or [] if isinstance(s, dict)]
    return [s for s in out if module is None or s["module"] == module]
