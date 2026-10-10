"""The install plan as an installer runs it: `oarbank-launcher setup` lays out the home with the plan's modes, installs
the agent as the current version and stores the join code (owner-only); the launcher then starts the agent, which
joins with the code from the file and deletes it. The service itself is not loaded (`--no-service`)."""
import json
import os
import stat
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
import agentbin  # noqa: E402
from conftest import agent_env, pointer  # noqa: E402
from helpers import stop_tree  # noqa: E402
from oarbank.platform import files  # noqa: E402
from test_agent_session import wait  # noqa: E402

LAUNCHER = agentbin.LAUNCHER_BIN    # built with the agent by the agent_bin fixture


def test_setup_then_the_launcher_joins_with_the_code_file(agent_bin, coordinator, tmp_path):
    plan = coordinator.api("POST", "/api/v1/ops/nodes.join_code", json={"params": {"label": "pkg"}, "dry_run": True})["plan"]
    code = coordinator.api("POST", "/api/v1/ops/nodes.join_code", json={"plan_id": plan["plan_id"], "reason": "e2e"})["result"]["code"]
    (tmp_path / "code.txt").write_text(code + "\n")
    home = tmp_path / "agent"
    r = subprocess.run([str(LAUNCHER), "--home", str(home), "setup", "--join-code-file", str(tmp_path / "code.txt"),
                        "--agent", str(agent_bin), "--no-service"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert f"run --join-file {home / 'state' / 'join-code'}" in r.stdout
    if os.name == "posix":                    # the plan's modes; Windows keeps none (its homes get DACLs: icacls)
        mode = lambda p: stat.S_IMODE(os.stat(p).st_mode)
        assert mode(home) == 0o700 and mode(home / "versions") == 0o755 and mode(home / "state" / "join-code") == 0o600
    assert files.owner_only(home / "state" / "join-code")
    assert "versions" in pointer(home / "current")
    p = subprocess.Popen([str(LAUNCHER), "--home", str(home), "run", "--join-file", str(home / "state" / "join-code")],
                         env=agent_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        node = wait(lambda: next((n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"] if n.get("last_hello_at")), None), 60)
        assert node["lifecycle"] != "pending"
        assert not (home / "state" / "join-code").exists()
        cfg = json.loads((home / "agent.json").read_text(encoding="utf-8"))
        assert cfg["coordinator"] == coordinator.url and "join_secret" not in cfg
    finally:
        stop_tree(p.pid)                      # the launcher and the agent it runs
        out = p.communicate(timeout=30)[0]
        print(out[-4000:])


def test_bad_codes_and_missing_coordinators_are_refused(tmp_path):
    r = subprocess.run([str(LAUNCHER), "--home", str(tmp_path / "a"), "setup", "--join-code", "nope", "--agent", "/bin/sh",
                        "--no-service"], capture_output=True, text=True)
    assert r.returncode != 0
    r = subprocess.run([str(LAUNCHER), "--home", str(tmp_path / "b"), "setup", "--scope", "nowhere", "--dry-run"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "unknown scope" in r.stderr


def test_or_wait_installs_a_waiting_node_when_the_code_is_wrong(agent_bin, tmp_path):
    """The Windows installer's setup: a wrong code pasted on its join page, or an unreadable code file, leaves the node
    installed and waiting with a warning instead of failing the whole install."""
    for args in (["--join-code", "OB2-NOTACODE"], ["--join-code-file", str(tmp_path / "missing.txt")]):
        home = tmp_path / f"agent-{args[0]}"
        r = subprocess.run([str(LAUNCHER), "--home", str(home), "setup", "--or-wait", *args, "--agent", str(agent_bin),
                            "--no-service"], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert "waits for a code" in r.stderr and not (home / "state" / "join-code").exists()
    r = subprocess.run([str(LAUNCHER), "--home", str(tmp_path / "strict"), "setup", "--join-code", "OB2-NOTACODE",
                        "--agent", str(agent_bin), "--no-service"], capture_output=True, text=True)
    assert r.returncode != 0                      # without --or-wait a wrong code is refused before anything changes
