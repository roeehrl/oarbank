"""install_coordinator in signing mode (the default posture): the owner key set is pinned by the agent, the move
target gets only a coordinator build signed by an owner key for its platform, the move itself waits for the owner's
signature, and the agent verifies all of it before following."""
import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, Coordinator, agent_env, free_port, venv_python  # noqa: E402
from test_agent_move import LOCK, t3  # noqa: E402
from test_agent_session import wait  # noqa: E402
from helpers import stop_tree  # noqa: E402

from oarbank import signing  # noqa: E402

SIGNED = {"OARBANK_RELEASE_SIGNING": "1"}


def synthetic_build(version, platform):
    """A coordinator build whose oarbankd is this checkout's (the compiled build is exercised by its own script)."""
    py = venv_python(REPO / ".venv")
    exe, script = ("bin/oarbankd.cmd", f'@"{py}" -m oarbank.coordinator %*\r\n') if os.name == "nt" else \
        ("bin/oarbankd", f'#!/bin/sh\nexec {py} -m oarbank.coordinator "$@"\n')
    files = {"oarbank-coordinator.json": json.dumps({"format": 1, "version": version, "platform": platform,
                                                     "exec": [exe]}).encode(), exe: script.encode()}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), 0o755
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_signed_build_and_owner_signed_move(agent_bin, tmp_path):
    a_home, b_home, install = tmp_path / "a", tmp_path / "b", tmp_path / "install"
    a_home.mkdir()
    b_port = free_port()
    pk, bk = tmp_path / "owner.key", tmp_path / "backup.key"
    p_pub, b_pub = signing.keygen(pk), signing.keygen(bk)
    env = {**agent_env(), **LOCK, **SIGNED, "OARBANK_SERVICE_HOST": "process", "OARBANK_COORDINATOR_INSTALL_DIR": str(install),
           "OARBANK_COORDINATOR_HOME": str(b_home), "OARBANKD_ADMIN_PORT": str(free_port()),
           "OARBANKD_CONSOLE_PORT": str(free_port()), "OARBANK_SECRET_STORE": "file",
           "OARBANKD_TAILSCALE": "/nonexistent", "OARBANKD_DISCOVERY": "0"}
    with Coordinator(a_home, extra_env={**LOCK, **SIGNED, "OARBANKD_AGENT_PORT": str(b_port)}) as a:
        fleet = a.api("GET", "/api/v1/coordinator")["fleet_id"]
        anchors = signing.owner_anchors_statement(fleet, 1, [p_pub, b_pub])
        t3(a, "owner.set_anchors", params={"statement": anchors, "signatures": [
            {"key": p_pub, "sig": signing.sign(anchors, pk)}, {"key": b_pub, "sig": signing.sign(anchors, bk)}]})
        p = subprocess.Popen([str(agent_bin), "--home", str(tmp_path / "agent"), "run", "--coordinator", a.url], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out = ""
        try:
            pending = wait(lambda: [e for e in a.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
            a.admit(pending[0]["enrollment_id"])
            node_id = wait(lambda: next((n["node_id"] for n in a.api("GET", "/api/v1/fleet")["nodes"] if n.get("last_hello_at")), None), 60)
            cfg = lambda: json.loads((tmp_path / "agent" / "agent.json").read_text(encoding="utf-8"))
            wait(lambda: cfg()["coordinator_trust"].get("owner_keys") == [p_pub, b_pub], timeout=60)
            # a signed build for the node's platform
            pf = json.loads(subprocess.run([str(agent_bin), "facts"], capture_output=True, text=True).stdout)["platform"]
            platform = f"{pf['os']}-{pf['arch']}"
            # OARBANK_TEST_COORDINATOR_BUILD: a real build from scripts/build-coordinator.sh instead of the stand-in
            real = os.environ.get("OARBANK_TEST_COORDINATOR_BUILD")
            data = open(real, "rb").read() if real else synthetic_build("0.1.0", platform)
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                version = json.load(t.extractfile("oarbank-coordinator.json"))["version"]
            sha = a.api("POST", "/api/v1/coordinator/builds", content=data)["sha256"]
            t3(a, "coordinator.builds.upload", params={"sha256": sha})
            stmt = signing.coordinator_statement(sha, version, platform, 1)
            # a T1 operation applied by its plan: the plan's target and params, as previewed
            t3(a, "coordinator.builds.sign", target=sha, params={"statement": stmt, "signature": signing.sign(stmt, pk)})
            with sqlite3.connect(a_home / "oarbank.sqlite3") as db:
                db.execute("UPDATE nodes SET ts_ip='127.0.0.1' WHERE node_id=?", (node_id,))
            t3(a, "coordinator.prepare", target=node_id)
            st = lambda: (a.api("GET", "/api/v1/coordinator").get("plan") or {}).get("state")
            wait(lambda: st() == "paired", timeout=240)
            t3(a, "coordinator.move", params={"timelock_s": 3}, reason="e2e signed move")
            m = wait(lambda: (lambda s: s if s["state"] == "awaiting_owner" else None)(a.api("GET", "/api/v1/coordinator/statement")), 60)
            t3(a, "coordinator.sign_move", params={"owner_sig": signing.sign(m["statement"], pk)})
            b_url = f"https://127.0.0.1:{b_port}"
            wait(lambda: cfg()["coordinator"] == b_url and cfg()["coordinator_trust"]["max_epoch"] == 2, timeout=240)
        finally:
            for pid in install.glob("*/standby.pid"):           # first: on Windows it holds the agent's output pipe
                stop_tree(int(pid.read_text(encoding="utf-8")))
            p.terminate()
            out = p.communicate(timeout=30)[0]
            print(out[-6000:])
            log = b_home / "logs" / "oarbankd.log"
            if log.exists():
                print(log.read_text(encoding="utf-8")[-3000:])
    assert "standby coordinator installed" in out

