"""The install plan as an installer runs it: `oarbank-launcher setup` lays out the home with the plan's modes, installs
the agent as the current version and stores the join code (owner-only); the launcher then starts the agent, which
joins with the code from the file and deletes it. The service itself is not loaded (`--no-service`)."""
import json
import os
import stat
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import CARGO, REPO, agent_env  # noqa: E402
from test_agent_session import wait  # noqa: E402

LAUNCHER = REPO / "rust" / "target" / "debug" / "oarbank-launcher"


def test_setup_then_the_launcher_joins_with_the_code_file(agent_bin, coordinator, tmp_path):
    env = {**os.environ, "PATH": f"{os.path.dirname(CARGO)}:{os.environ.get('PATH', '')}"}
    assert subprocess.run([CARGO, "build", "-q", "-p", "oarbank-launcher"], cwd=REPO / "rust", env=env).returncode == 0
    plan = coordinator.api("POST", "/api/v1/ops/nodes.join_code", json={"params": {"label": "pkg"}, "dry_run": True})["plan"]
    code = coordinator.api("POST", "/api/v1/ops/nodes.join_code", json={"plan_id": plan["plan_id"], "reason": "e2e"})["result"]["code"]
    (tmp_path / "code.txt").write_text(code + "\n")
    home = tmp_path / "agent"
    r = subprocess.run([str(LAUNCHER), "--home", str(home), "setup", "--join-code-file", str(tmp_path / "code.txt"),
                        "--agent", str(agent_bin), "--no-service"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert f"run --join-file {home / 'state' / 'join-code'}" in r.stdout
    mode = lambda p: stat.S_IMODE(os.stat(p).st_mode)
    assert mode(home) == 0o700 and mode(home / "versions") == 0o755 and mode(home / "state" / "join-code") == 0o600
    assert os.path.islink(home / "current")
    p = subprocess.Popen([str(LAUNCHER), "--home", str(home), "run", "--join-file", str(home / "state" / "join-code")],
                         env=agent_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        node = wait(lambda: next((n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"] if n.get("last_hello_at")), None), 60)
        assert node["lifecycle"] != "pending"
        assert not (home / "state" / "join-code").exists()
        cfg = json.loads((home / "agent.json").read_text())
        assert cfg["coordinator"] == coordinator.url and "join_secret" not in cfg
    finally:
        p.terminate()
        out = p.communicate(timeout=30)[0]
        print(out[-4000:])


def test_bad_codes_and_missing_coordinators_are_refused(tmp_path):
    r = subprocess.run([str(LAUNCHER), "--home", str(tmp_path / "a"), "setup", "--join-code", "nope", "--agent", "/bin/sh",
                        "--no-service"], capture_output=True, text=True)
    assert r.returncode != 0
    r = subprocess.run([str(LAUNCHER), "--home", str(tmp_path / "b"), "setup", "--scope", "nowhere", "--dry-run"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "unknown scope" in r.stderr
