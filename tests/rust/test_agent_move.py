"""A coordinator move with the Rust agent: the standby pairs with the old coordinator over pinned TLS (both CAs
pinned), seeds, and takes over after the time lock; the agent verifies the signed statement, follows it after the
time lock, and keeps working with the new coordinator (same CA, its certificate carried in the moved database)."""
import json
import os
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import Coordinator, agent_env  # noqa: E402
from test_agent_session import wait  # noqa: E402

LOCK = {"OARBANKD_MOVE_MIN_TIMELOCK_S": "3"}


def t3(c, op, target=None, params=None, reason="e2e"):
    plan = c.api("POST", f"/api/v1/ops/{op}", json={"target": target, "params": params or {}, "dry_run": True})["plan"]
    return c.api("POST", f"/api/v1/ops/{op}", json={"plan_id": plan["plan_id"], "reason": reason,
                                                    "confirm": plan.get("confirm_name")})


def supervise(c: Coordinator, stop: threading.Event):
    """launchd's KeepAlive for the standby: it exits 75 to restart on the installed copy."""
    while not stop.is_set():
        if c.proc.poll() is not None:
            if stop.is_set():
                return
            c.start()
        time.sleep(0.3)


@pytest.mark.parametrize("away", [False, True], ids=["online", "away_through_cutover"])
def test_the_agent_follows_a_coordinator_move(agent_bin, tmp_path, away):
    """away: the agent is down from before the move until the old coordinator handed off, so it never got the
    statement in a directive; it reads the chain from the handed-off coordinator when it comes back."""
    a_home, b_home = tmp_path / "a", tmp_path / "b"
    a_home.mkdir()
    b_home.mkdir()
    with Coordinator(a_home, extra_env=LOCK) as a:
        agent = lambda *extra: subprocess.Popen([str(agent_bin), "--home", str(tmp_path / "agent"), "run", *extra],
                                                env=agent_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        p = agent("--coordinator", a.url)
        stop = threading.Event()
        b = None
        out = ""
        try:
            pending = wait(lambda: [e for e in a.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
            a.admit(pending[0]["enrollment_id"])
            node_id = wait(lambda: next((n["node_id"] for n in a.api("GET", "/api/v1/fleet")["nodes"] if n.get("last_hello_at")), None), 60)
            b = Coordinator(b_home, extra_env=LOCK, wait_admin=False)
            plan = t3(a, "coordinator.prepare", target=f"https://127.0.0.1:{b.agent_port}")["result"]
            assert plan["from_ca"] and "--from-ca" in plan["install_command"]
            b.extra_args = ["--standby", "--pair", plan["pair_code"], "--from", a.url, "--from-ca", plan["from_ca"],
                            "--url", f"https://127.0.0.1:{b.agent_port}"]
            b.__enter__()
            threading.Thread(target=supervise, args=(b, stop), daemon=True).start()
            wait(lambda: a.api("GET", "/api/v1/coordinator")["plan"] and a.api("GET", "/api/v1/coordinator")["plan"]["state"] == "paired", 60)
            time.sleep(3)                                          # let the standby seed before the move is requested
            if away:
                p.terminate()
                out += p.communicate(timeout=10)[0]
            t3(a, "coordinator.move", params={"timelock_s": 3}, reason="e2e move")
            if away:
                wait(lambda: a.api("GET", "/api/v1/coordinator")["role"] == "handed_off", timeout=120)
                p = agent()
            cfg = lambda: json.loads((tmp_path / "agent" / "agent.json").read_text(encoding="utf-8"))
            wait(lambda: cfg()["coordinator"] == b.url and cfg()["coordinator_trust"]["max_epoch"] == 2, timeout=180)
            trust = cfg()["coordinator_trust"]
            assert trust["retired"] and trust["fallback"] == a.url
            # the new coordinator knows the node by its certificate and hears from it
            hb = lambda: next((n for n in b.api("GET", "/api/v1/fleet")["nodes"] if n["node_id"] == node_id), None)
            t0 = time.time()
            wait(lambda: (hb() or {}).get("last_heartbeat_at", 0) > t0, timeout=60)
        finally:
            stop.set()
            p.terminate()
            out += p.communicate(timeout=10)[0]
            print(out[-6000:])
            if b is not None:
                b.__exit__()
