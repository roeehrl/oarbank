"""install_coordinator with the Rust agent: a move to an enrolled node. The agent downloads the old coordinator's
bundle (developer mode: its checkout), installs it, and starts the standby with the pairing code (here as a
supervised child instead of a launchd job); the standby pairs over pinned TLS, checks the module on its copy, the move
commits after the time lock, and the agent follows it to the coordinator it installed."""
import json
import os
import sqlite3
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, Coordinator, agent_env, free_port, install_module  # noqa: E402
from test_agent_move import LOCK, t3  # noqa: E402
from test_agent_session import wait  # noqa: E402
from helpers import stop_tree  # noqa: E402

TOY = REPO / "vendor" / "oarbank-sdk" / "examples" / "toy"


def test_the_agent_installs_the_standby_and_follows_the_move(agent_bin, tmp_path):
    a_home, b_home, install = tmp_path / "a", tmp_path / "b", tmp_path / "install"
    a_home.mkdir()
    b_port = free_port()
    env = {**agent_env(), **LOCK, "OARBANK_SERVICE_HOST": "process", "OARBANK_COORDINATOR_INSTALL_DIR": str(install),
           "OARBANK_COORDINATOR_HOME": str(b_home), "OARBANKD_ADMIN_PORT": str(free_port()),
           "OARBANKD_CONSOLE_PORT": str(free_port()), "OARBANK_RELEASE_SIGNING": "0",
           "OARBANK_SECRET_STORE": "file", "OARBANKD_TAILSCALE": "/nonexistent"}
    with Coordinator(a_home, extra_env={**LOCK, "OARBANKD_AGENT_PORT": str(b_port)}) as a:
        install_module(a, TOY, tmp_path)          # the standby checks it on its copy before the move can commit
        p = subprocess.Popen([str(agent_bin), "--home", str(tmp_path / "agent"), "run", "--coordinator", a.url], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out = ""
        try:
            pending = wait(lambda: [e for e in a.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
            a.admit(pending[0]["enrollment_id"])
            node_id = wait(lambda: next((n["node_id"] for n in a.api("GET", "/api/v1/fleet")["nodes"] if n.get("last_hello_at")), None), 60)
            with sqlite3.connect(a_home / "oarbank.sqlite3") as db:     # no tailnet in tests: its address by hand
                db.execute("UPDATE nodes SET ts_ip='127.0.0.1' WHERE node_id=?", (node_id,))
            plan = t3(a, "coordinator.prepare", target=node_id)["result"]
            assert plan["target_url"] == f"https://127.0.0.1:{b_port}" and plan["target_node"] == node_id
            # the agent installs the bundle (uv sync of the checkout) and the standby pairs
            st = lambda: (a.api("GET", "/api/v1/coordinator").get("plan") or {}).get("state")
            wait(lambda: st() == "paired", timeout=600)
            t3(a, "coordinator.move", params={"timelock_s": 3}, reason="e2e move")
            b_url = f"https://127.0.0.1:{b_port}"
            cfg = lambda: json.loads((tmp_path / "agent" / "agent.json").read_text(encoding="utf-8"))
            wait(lambda: cfg()["coordinator"] == b_url and cfg()["coordinator_trust"]["max_epoch"] == 2, timeout=240)
            with sqlite3.connect(b_home / "oarbank.sqlite3") as db:
                assert db.execute("SELECT current FROM module_channels WHERE name='toy'").fetchone() == ("0.1.0",)
        finally:
            for pid in install.glob("*/standby.pid"):           # first: on Windows it holds the agent's output pipe
                stop_tree(int(pid.read_text(encoding="utf-8")))
            p.terminate()
            out = p.communicate(timeout=30)[0]
            print(out[-6000:])
            try:                                                # the move's phases and why it stopped, if it did
                print(json.dumps(a.api("GET", "/api/v1/coordinator"), indent=1)[-6000:])
            except Exception as e:
                print(f"the old coordinator's status: {e}")
            for log in sorted(b_home.glob("logs/**/*.log")) + sorted(install.glob("*/*.log")):
                if log.is_file():
                    print(f"--- {log}\n" + log.read_text(encoding="utf-8", errors="replace")[-3000:])
    assert "standby coordinator installed" in out
