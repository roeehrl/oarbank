"""Agent self-update through the launcher: a canary build is staged, verified and handed over; the launcher flips to
it on trial and it confirms itself; a build that cannot start is rolled back by the launcher and reported."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import agent_env, build_version, pointer  # noqa: E402
from test_agent_session import wait  # noqa: E402
from helpers import stop_tree  # noqa: E402


def upload_and_canary(c, binary, node_id):
    sha = c.api("POST", "/api/v1/agent/builds", content=binary.read_bytes())["sha256"]
    plan = c.api("POST", "/api/v1/ops/agent.upload", json={"params": {"sha256": sha}, "dry_run": True})["plan"]
    c.api("POST", "/api/v1/ops/agent.upload", json={"plan_id": plan["plan_id"], "reason": "e2e"})
    plan = c.api("POST", "/api/v1/ops/agent.canary", json={"target": sha, "params": {"nodes": [node_id]}, "dry_run": True})["plan"]
    c.api("POST", "/api/v1/ops/agent.canary", json={"plan_id": plan["plan_id"], "reason": "e2e"})
    return sha


def node(c):
    return next(iter(c.api("GET", "/api/v1/fleet")["nodes"]), None)


def test_canary_update_confirms_and_a_broken_build_rolls_back(coordinator, tmp_path):
    v1, launcher = build_version("1.0.0-alpha.1", tmp_path / "v1")
    v2, _ = build_version("1.0.0-alpha.2", tmp_path / "v2")
    v3, _ = build_version("1.0.0-alpha.3", tmp_path / "v3", {"OARBANK_AGENT_TEST_CRASH": "1"})
    home = tmp_path / "agent"
    home.mkdir()
    assert subprocess.run([str(launcher), "--home", str(home), "install", str(v1)], capture_output=True).returncode == 0
    p = subprocess.Popen([str(launcher), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        n = wait(lambda: (lambda x: x if x and x.get("agent_build") else None)(node(coordinator)), timeout=60)
        assert n["agent_version"] == "1.0.0-alpha.1"
        sha2 = upload_and_canary(coordinator, v2, n["node_id"])
        wait(lambda: node(coordinator)["agent_build"] == sha2, timeout=120)
        wait(lambda: json.loads(node(coordinator)["agent_update_json"] or "{}").get("state") == "confirmed", timeout=60)
        assert node(coordinator)["agent_version"] == "1.0.0-alpha.2"
        assert "1.0.0-alpha.2" in pointer(home / "current")
        sha3 = upload_and_canary(coordinator, v3, n["node_id"])
        upd = wait(lambda: (lambda u: u if u.get("state") == "rolled_back" else None)(
            json.loads(node(coordinator)["agent_update_json"] or "{}")), timeout=180)
        assert upd["target"] == sha3 and "failed to start" in upd["error"]
        assert node(coordinator)["agent_build"] == sha2 and "1.0.0-alpha.2" in pointer(home / "current")
    finally:
        stop_tree(p.pid)                      # the launcher and the agent it runs
        out = p.communicate(timeout=20)[0]
        print(out[-6000:])
