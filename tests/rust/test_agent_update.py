"""Agent self-update through the launcher: a canary build is staged, verified and handed over; the launcher flips to
it on trial and it confirms itself; a build that cannot start is rolled back by the launcher and reported."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import CARGO, REPO, agent_env  # noqa: E402
from test_agent_session import wait  # noqa: E402


def build(version, target, crash=False):
    env = {**os.environ, "PATH": f"{os.path.dirname(CARGO)}:{os.environ.get('PATH', '')}", "OARBANK_AGENT_VERSION": version}
    if crash:
        env["OARBANK_AGENT_TEST_CRASH"] = "1"
    r = subprocess.run([CARGO, "build", "-q", "-p", "oarbank-agent", "-p", "oarbank-launcher", "--target-dir", str(target)],
                       cwd=REPO / "rust", env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-2000:]
    return target / "debug" / "oarbank-agent", target / "debug" / "oarbank-launcher"


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
    t = REPO / "rust" / "target-e2e"
    v1, launcher = build("1.0.0-alpha.1", t / "v1")
    v2, _ = build("1.0.0-alpha.2", t / "v2")
    v3, _ = build("1.0.0-alpha.3", t / "v3", crash=True)
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
        assert "1.0.0-alpha.2" in os.readlink(home / "current")
        sha3 = upload_and_canary(coordinator, v3, n["node_id"])
        upd = wait(lambda: (lambda u: u if u.get("state") == "rolled_back" else None)(
            json.loads(node(coordinator)["agent_update_json"] or "{}")), timeout=180)
        assert upd["target"] == sha3 and "failed to start" in upd["error"]
        assert node(coordinator)["agent_build"] == sha2 and "1.0.0-alpha.2" in os.readlink(home / "current")
    finally:
        p.terminate()
        out = p.communicate(timeout=20)[0]
        print(out[-6000:])
