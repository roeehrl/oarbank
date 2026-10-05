"""Service endpoints end to end (docs/design/service-endpoints.md): the SDK's reference module `modelserver` on a real
agent. Its golden and two concurrent jobs reach one warm, sandboxed model server through their connectors, so the model is
loaded once; disabling the module stops the server."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from test_agent_jobs import node_modules  # noqa: E402
from test_agent_session import wait  # noqa: E402

MODELSERVER = REPO / "vendor" / "oarbank-sdk" / "examples" / "modelserver"


def node(c):
    return next(iter(c.api("GET", "/api/v1/fleet")["nodes"]), None)


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def test_jobs_share_one_warm_model_server_and_disabling_the_module_stops_it(agent_bin, coordinator, tmp_path):
    install_module(coordinator, MODELSERVER, tmp_path)
    home = tmp_path / "agent"
    data = home / "modules-data" / "modelserver"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        # the golden reaches the service through its endpoint: certification proves the whole path
        wait(lambda: node_modules(coordinator).get("modelserver", {}).get("state") == "certified", timeout=240)
        r = coordinator.api("POST", "/api/v1/ops/mod.modelserver.queue_prompts", json={
            "params": {"jobs": [["alpha", "beta", "gamma"], ["delta", "epsilon"]], "hold_s": 3}, "reason": "e2e"},
            headers={"idempotency-key": "e2e-endpoints"})
        cid = r["result"]["result"]["campaign_id"]
        jobs = wait(lambda: (lambda j: j if j["n"] == 2 and j["d"] == 2 else None)(
            coordinator.api("GET", f"/api/v1/campaigns/{cid}")["jobs"]), timeout=240)
        assert jobs["f"] == 0
        loads = (data / "model.loads").read_text().split()
        assert len(loads) == 1, loads                     # the golden and both jobs: one load
        daemon = int(loads[0])
        assert alive(daemon)
        tel = json.loads(node(coordinator)["telemetry_json"] or "{}")
        assert tel.get("services_running") == ["modelserver/model"] and tel.get("services_held") == {}
        # the agent's service report reaches the node (the node page, `oarbank node show`, the `services` host query)
        svc = node(coordinator)["services"]
        assert [(s["module"], s["service"], s["state"], s["endpoint"]) for s in svc] == [("modelserver", "model", "ready", True)]
        # disabling the module takes the service down with it
        coordinator.api("POST", "/api/v1/ops/modules.disable", json={"target": "modelserver", "reason": "e2e"})
        wait(lambda: not (data / "model.up").exists() and not alive(daemon), timeout=120)
        wait(lambda: json.loads(node(coordinator)["telemetry_json"] or "{}").get("services_running") == [], timeout=60)
        wait(lambda: [(s["state"], s["stopped_reason"]) for s in node(coordinator)["services"]] == [("stopped", "disabled")],
             timeout=60)
    finally:
        p.terminate()
        out = p.communicate(timeout=30)[0]
        print(out[-5000:])
