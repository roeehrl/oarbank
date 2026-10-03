"""The Rust agent runs module services: a toy variant whose jobs reserve a pool that an on-demand service provides.
The agent offers the pool while the service is healthy and stopped, starts the service when a job needs it, holds
the runner until the service is ready, and reports the service as running."""
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from test_agent_jobs import node_modules  # noqa: E402
from test_agent_session import wait  # noqa: E402

TOY = REPO / "vendor" / "oarbank-sdk" / "examples" / "toy"

SERVICE = r'''
import json, os, sys, time
d, op = os.environ["OARBANK_MODULE_DATA"], sys.argv[1]
up, ready = os.path.join(d, "scorer.up"), os.path.join(d, "scorer.ready")
with open(os.path.join(d, "scorer.calls"), "a") as f:
    f.write(op + "\n")
if op == "fingerprint":
    print(json.dumps({"service_protocol": {"supported": [1]}, "health": "healthy", "pools": {"scorer": 2},
                      "running": os.path.exists(up)}))
elif op == "start":
    open(up, "w").close()
    open(ready, "w").close()
    print(json.dumps({"ok": True}))
elif op == "stop":
    for p in (up, ready):
        if os.path.exists(p):
            os.remove(p)
    print(json.dumps({"ok": True}))
elif op == "status":
    print(json.dumps({"running": os.path.exists(up)}))
elif op == "ready":
    r = os.path.exists(ready)
    print(json.dumps({"running": os.path.exists(up), "ready": r}))
elif op == "list_owned":
    print(json.dumps({"objects": []}))
elif op == "destroy":
    print(json.dumps({"ok": True}))
else:
    sys.exit(64)
'''


def scored_toy(tmp):
    src = tmp / "toy"
    shutil.copytree(TOY, src)
    m = (src / "oarbank-module.toml").read_text()
    m = m.replace('runner_protocol = [1]', 'runner_protocol = [1]\nservice_protocol = [1]')
    m = m.replace('requires.resources = { cpu = 1, mem_gb = 0.1 }',
                  'requires.resources = { cpu = 1, mem_gb = 0.1 }\nrequires.pools = { scorer = 1 }')
    m += '''
[[services]]
name = "scorer"
exec = ["python", "-I", "{bundle}/scorer_service.py"]
lifecycle = "on_demand"
idle_timeout_s = 3600
provides = { pools = ["scorer"] }
'''
    (src / "oarbank-module.toml").write_text(m)
    (src / "scorer_service.py").write_text(SERVICE)
    mod = (src / "toy_module.py").read_text()
    (src / "toy_module.py").write_text(mod.replace('"resources": {"cpu": 1, "mem_gb": 0.1}}',
                                                   '"resources": {"cpu": 1, "mem_gb": 0.1, "pools": {"scorer": 1}}}'))
    return src


def node(c):
    return next(iter(c.api("GET", "/api/v1/fleet")["nodes"]), None)


def test_on_demand_service_starts_for_pool_jobs(agent_bin, coordinator, tmp_path):
    install_module(coordinator, scored_toy(tmp_path), tmp_path)
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        # the pool is offered while the service is healthy, before anything started it
        wait(lambda: (json.loads(node(coordinator)["capacity_json"] or "{}").get("pools") or {}).get("scorer") == 2,
             timeout=120)
        wait(lambda: node_modules(coordinator).get("toy", {}).get("state") == "certified", timeout=180)
        r = coordinator.api("POST", "/api/v1/ops/mod.toy.queue_sums", json={"params": {"ns": [10, 1000]}, "reason": "e2e"},
                           headers={"idempotency-key": "e2e-svc"})
        cid = r["result"]["result"]["campaign_id"]
        jobs = wait(lambda: (lambda j: j if j["n"] == 2 and j["d"] == 2 else None)(
            coordinator.api("GET", f"/api/v1/campaigns/{cid}")["jobs"]), timeout=180)
        assert jobs["f"] == 0
        calls = (home / "modules-data" / "toy" / "scorer.calls").read_text().split()
        assert "start" in calls and "ready" in calls
        tel = wait(lambda: (lambda t: t if t.get("services_running") else None)(
            json.loads(node(coordinator)["telemetry_json"] or "{}")), timeout=60)
        assert tel["services_running"] == ["toy/scorer"]
    finally:
        p.terminate()
        out = p.communicate(timeout=30)[0]
        print(out[-5000:])
