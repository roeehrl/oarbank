"""The Rust agent runs work: the module's golden jobs certify it on this node, then campaign jobs run in the sandbox,
their results are accepted and become canonical."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from test_agent_session import wait  # noqa: E402

TOY = REPO / "vendor" / "oarbank-sdk" / "examples" / "toy"
DEPOT = REPO / "tests" / "fixtures" / "modules" / "depot"


def node_modules(c):
    import json
    n = next(iter(c.api("GET", "/api/v1/fleet")["nodes"]), None)
    return json.loads(n["modules_json"] or "{}") if n else {}


def test_goldens_certify_then_campaign_jobs_complete(agent_bin, coordinator, tmp_path):
    install_module(coordinator, TOY, tmp_path)
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        wait(lambda: node_modules(coordinator).get("toy", {}).get("state") == "certified", timeout=120)
        r = coordinator.api("POST", "/api/v1/ops/mod.toy.queue_sums", json={"params": {"ns": [10, 1000, 20000]}, "reason": "e2e"},
                           headers={"idempotency-key": "e2e-1"})
        cid = r["result"]["result"]["campaign_id"]
        jobs = wait(lambda: (lambda j: j if j["n"] == 3 and j["d"] == 3 else None)(
            coordinator.api("GET", f"/api/v1/campaigns/{cid}")["jobs"]), timeout=120)
        assert jobs["f"] == 0
        # after a restart the agent runs its doctors again and keeps taking work
        p.terminate()
        out += p.communicate(timeout=20)[0]
        p = subprocess.Popen([str(agent_bin), "--home", str(home), "run"], env=agent_env(),
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        r = coordinator.api("POST", "/api/v1/ops/mod.toy.queue_sums", json={"params": {"ns": [5, 6]}, "reason": "e2e"},
                           headers={"idempotency-key": "e2e-2"})
        cid2 = r["result"]["result"]["campaign_id"]
        wait(lambda: (lambda j: j if j["d"] == 2 else None)(coordinator.api("GET", f"/api/v1/campaigns/{cid2}")["jobs"]), timeout=120)
    finally:
        p.terminate()
        out += p.communicate(timeout=10)[0]
        print(out[-5000:])
    assert "granted" in out and "completed" in out


def test_a_bootstrap_stage_provisions_what_the_goldens_mount_on_a_fresh_fleet(agent_bin, coordinator, tmp_path):
    """docs/design/bootstrap-stages.md on a real agent: the node is certifying and its golden waits for a dataset nobody
    registered; the bootstrap fetch job runs there anyway, sandboxed with the bootstrap grants (the depot runner fails
    otherwise), its uploaded files are exactly the pins, so the coordinator registers the dataset; the agent stages it,
    the golden passes, and the module's jobs run on the now certified node."""
    install_module(coordinator, DEPOT, tmp_path, approve=True)
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        node = wait(lambda: next(iter(coordinator.api("GET", "/api/v1/fleet")["nodes"]), None))
        coordinator.api("POST", "/api/v1/ops/nodes.set_policy", json={            # settings a bootstrap job must never see
            "target": node["node_id"], "params": {"patch": {"module_settings": {"depot": {"token": "secret"}}}}, "reason": "e2e"})
        wait(lambda: node_modules(coordinator).get("depot", {}).get("state") == "certifying", timeout=120)
        assert not [d for d in coordinator.api("GET", "/api/v1/datasets") if d["dataset_id"] == "tool:depot-1"]
        coordinator.api("POST", "/api/v1/ops/mod.depot.provision", json={"params": {"evals": 2}, "reason": "e2e"},
                        headers={"idempotency-key": "e2e-boot"})
        wait(lambda: node_modules(coordinator).get("depot", {}).get("state") == "certified", timeout=180)
        jobs = wait(lambda: (lambda j: j if j["d"] == 3 else None)(coordinator.api("GET", "/api/v1/campaigns/c_provision")["jobs"]),
                    timeout=120)
        assert jobs["f"] == 0
        (ds,) = [d for d in coordinator.api("GET", "/api/v1/datasets") if d["dataset_id"] == "tool:depot-1"]
        assert ds["module"] == "depot" and ds["kind"] == "tool"
    finally:
        p.terminate()
        out += p.communicate(timeout=10)[0]
        print(out[-5000:])
