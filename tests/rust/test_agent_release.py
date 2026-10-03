"""The Rust agent installs its platform's release (verified, unpacked, environments built offline in the sandbox),
switches to it, runs every module's doctor under its sandbox, and the coordinator starts certifying."""
import json
import subprocess

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module
from test_agent_session import wait

TOY = REPO / "vendor" / "oarbank-sdk" / "examples" / "toy"


def test_release_install_and_doctor(agent_bin, coordinator, tmp_path):
    install_module(coordinator, TOY, tmp_path)
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        node = wait(lambda: next((n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"]
                                  if n.get("doctor_json") and n.get("release_id")), None), timeout=90)
        doc = json.loads(node["doctor_json"]) if isinstance(node["doctor_json"], str) else node["doctor_json"]
        assert doc["modules"]["toy"]["health"] == "healthy", doc
        assert (home / "releases" / "current").is_symlink()
        rel = home / "releases" / node["release_id"]
        assert (rel / "modules" / "toy" / "toy_runner.py").exists()
        mods = json.loads(node["modules_json"]) if isinstance(node["modules_json"], str) else node["modules_json"]
        wait(lambda: (json.loads(next(n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"])["modules_json"] or "{}")
                      .get("toy", {}).get("state") in ("certifying", "certified")), timeout=60)
    finally:
        p.terminate()
        out = p.communicate(timeout=10)[0]
        print(out[-6000:])
    assert "release installed" in out and "doctors ran" in out, out[-3000:]
