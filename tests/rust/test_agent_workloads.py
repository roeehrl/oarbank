"""Workloads end to end (docs/design/workloads.md): a real agent against a real oarbankd runs a synthetic workload whose
daemon calls setsid and forks twice (leaving its leader's process group and session). The owner assigns it (T2), the
node's own secret reaches it under its seat lease, the daemon stays the workload's (tracked by sandbox identity on
macOS), a protection rule pauses it (daemon included) and, past its pause tolerance, stops and holds it until the rule
ends; an evict rule holds it too; a restart of the agent keeps it running and the new agent adopts it; unassigned,
everything of it ends."""
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from procguard import KILL, SpawnTree  # noqa: E402
from test_agent_session import wait  # noqa: E402

TOY = REPO / "vendor" / "oarbank-sdk" / "examples" / "toy"
SECRET = "e2e-signing-key-" + secrets.token_hex(4)

WORKLOAD = r'''
import hashlib, json, os, signal, sys, time
op = sys.argv[1]
run = os.environ.get("OARBANK_WORKLOAD_RUN", ".")
if op == "status":
    print(json.dumps({"healthy": True, "detail": "ok"}))
    sys.exit(0)
if op != "run":
    sys.exit(64)
sec = json.load(open(os.environ["OARBANK_SECRETS_FILE"]))
with open(os.path.join(run, "secret.sha256"), "w") as f:
    f.write(hashlib.sha256(sec["signing_key"].encode()).hexdigest())
# the third-party daemon: setsid and a double fork, so it leaves this process's group and session
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        with open(os.path.join(run, "daemon.pid.tmp"), "w") as f:
            f.write(str(os.getpid()))
        os.rename(os.path.join(run, "daemon.pid.tmp"), os.path.join(run, "daemon.pid"))
        while True:
            with open(os.path.join(run, "beats"), "a") as f:
                f.write(f"{time.time()}\n")
            time.sleep(0.5)
    os._exit(0)
os.wait()
signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
ctl = os.environ["OARBANK_CONTROL_FILE"]
while True:                                    # the leader stays in the foreground until asked to stop
    try:
        if json.load(open(ctl)).get("stop"):
            sys.exit(0)
    except (OSError, ValueError):
        pass
    time.sleep(0.3)
'''


def workload_toy(tmp: Path) -> Path:
    src = tmp / "toy"
    shutil.copytree(TOY, src)
    m = (src / "oarbank-module.toml").read_text(encoding="utf-8")
    m = m.replace('runner_protocol = [1]', 'runner_protocol = [1]\nworkload_protocol = [1]')
    import re
    m = re.sub(r'core = "[^"]*"', 'core = ">=2.10,<3"', m, count=1)
    m += '''
[[secrets]]
name = "signing_key"
description = "The key the worker signs with"

[[workloads]]
name = "worker"
exec = ["python", "-I", "{bundle}/worker.py"]
identity = "per_node"
secrets = ["signing_key"]
control = ["freeze_ok"]
pause_tolerance_s = 8
stop_timeout_s = 3
restart = { backoff_initial_s = 1, backoff_max_s = 5, max_failures = 5 }
health = { period_s = 5, timeout_s = 5 }
'''
    (src / "oarbank-module.toml").write_text(m, encoding="utf-8")
    (src / "worker.py").write_text(WORKLOAD, encoding="utf-8")
    return src


def planned(c, name, target, params):
    plan = c.api("POST", f"/api/v1/ops/{name}", json={"target": target, "params": params, "dry_run": True})["plan"]
    return c.api("POST", f"/api/v1/ops/{name}", json={"plan_id": plan["plan_id"], "reason": "e2e"})


def start_agent(agent_bin, coordinator, home):
    """The agent, its output appended to <home>.log (a file: a pipe nobody reads would fill and stall it)."""
    log = open(f"{home}.log", "ab")
    # the host runs other work: its OS-wide memory pressure is not this test's (the memory floors below still apply)
    env = {**agent_env(), "OARBANK_TEST_IGNORE_OS_MEMORY_PRESSURE": "1"}
    return subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=env,
                            stdout=log, stderr=subprocess.STDOUT)


def stopped(tree: SpawnTree, p):
    """Stop a process the test started (the guard checks it is the test's own, by pid and start time)."""
    if p.poll() is None:
        tree.signal(p.pid, signal.SIGTERM)
        try:
            p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            tree.signal(p.pid, KILL)
            p.wait()
    return ""


def row(c):
    rows = c.api("GET", "/api/v1/workloads")["workloads"]
    return rows[0] if rows else {}


def stat(pid: int) -> str:
    out = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True).stdout
    return out.strip()


@pytest.mark.skipif(os.name == "nt", reason="the synthetic daemon forks (POSIX); Windows contains workloads in a Job Object")
def test_a_double_forking_workload_is_assigned_paused_held_adopted_and_unassigned(agent_bin, coordinator, tmp_path):
    c = coordinator
    install_module(c, workload_toy(tmp_path), tmp_path)
    floors = {"soft_free_pct": 1, "hard_free_pct": 0.5, "swap_growth_soft_mb_min": 1e9, "swap_growth_hard_mb_min": 1e9}
    planned(c, "protection.rules.update", "fleet", {"config": {"schema": 1, "node": {"mode": "fleet_first", "memory": floors}}})
    home = tmp_path / "agent"
    log, owner = [], None
    tree = SpawnTree().__enter__()                       # every process this test starts, with its start time
    p = start_agent(agent_bin, c, home)
    try:
        pending = wait(lambda: [e for e in c.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"] or None)
        nid = c.admit(pending[0]["enrollment_id"])["result"]["node_id"]
        c.api("POST", "/api/v1/ops/secrets.set", json={"target": "toy", "params": {"name": "signing_key", "node": nid},
                                                        "secret": SECRET, "reason": "e2e"})
        plan = c.api("POST", "/api/v1/ops/workloads.assign", json={"target": "toy/worker", "params": {"node": nid},
                                                                     "dry_run": True})["plan"]
        assert plan["impact"]["nodes"][0]["seat_id"].startswith("s_") and SECRET not in json.dumps(plan)
        c.api("POST", "/api/v1/ops/workloads.assign", json={"plan_id": plan["plan_id"], "reason": "e2e"})
        r = wait(lambda: (lambda x: x if x.get("state") == "running" else None)(row(c)), timeout=240)
        assert r["seat_holder"] == nid and r["fence"] == 1
        runs = home / "modules-data" / "toy" / "workloads" / "worker"
        run_dir = wait(lambda: next(iter(sorted(runs.glob("run-*/daemon.pid"))), None), timeout=60).parent
        daemon = int((run_dir / "daemon.pid").read_text())
        leader = r["report"]["pid"]
        tree.add(daemon)
        tree.add(leader)
        assert os.getpgid(daemon) != leader and os.getsid(daemon) != os.getsid(leader)
        import hashlib
        assert (run_dir / "secret.sha256").read_text() == hashlib.sha256(SECRET.encode()).hexdigest()
        assert not (home / "run" / "workloads" / "toy" / "worker" / "secrets.json").stat().st_mode & 0o077
        if sys.platform == "darwin":                                  # tracked beyond its process group
            wait(lambda: row(c)["report"].get("members", 0) >= 1, timeout=60)
        # a protection rule for the owner's process pauses it, its daemon included
        tag = f"oarbank-e2e-owner-{secrets.token_hex(4)}"
        planned(c, "protection.rules.update", nid, {"config": {"schema": 1, "node": {
            "mode": "fleet_first", "memory": floors, "defaults": {"cooldown": {"base_s": 1, "max_s": 1}}},
            "rule": [{"id": "e2e-owner", "match": {"argv_regex": tag}, "active_when": {"for_s": 0}, "pause_fleet": {},
                      "exit_after_s": 0}]}})
        owner = subprocess.Popen(["/bin/sh", "-c", "sleep 600; :", tag])
        wait(lambda: stat(daemon).startswith("T") and stat(leader).startswith("T"), timeout=60)
        # past its pause tolerance (8 s) it is stopped and held: the daemon is gone with it
        wait(lambda: row(c)["state"] == "held", timeout=60)
        wait(lambda: not tree.alive(daemon), timeout=30)
        assert row(c)["report"]["held_code"] == "WORKLOAD_PAUSE_TOLERANCE"
        # the owner's process ends: the hold ends and it runs again (a new run, a new daemon)
        stopped(tree, owner)
        owner = None
        wait(lambda: row(c)["state"] == "running" and row(c)["report"].get("run", 0) >= 2, timeout=120)
        run_dir = wait(lambda: next(iter(sorted(runs.glob("run-*/daemon.pid"))), None), timeout=60).parent
        daemon = int((run_dir / "daemon.pid").read_text())
        leader = row(c)["report"]["pid"]
        tree.add(daemon)
        tree.add(leader)
        # the agent restarts: the workload keeps running and the new agent adopts it (the same leader and daemon)
        log.append(stopped(tree, p))
        assert tree.alive(leader) and tree.alive(daemon), "a stopped agent leaves its workloads running"
        p = start_agent(agent_bin, c, home)
        wait(lambda: row(c)["report"].get("adopted") and row(c)["report"].get("pid") == leader, timeout=120)
        assert tree.alive(daemon) and row(c)["fence"] == 1, row(c)
        # an evict rule holds it while it lasts
        planned(c, "protection.rules.update", nid, {"config": {"schema": 1, "node": {
            "mode": "fleet_first", "memory": floors, "defaults": {"cooldown": {"base_s": 1, "max_s": 1}}}, "rule": [
            {"id": "e2e-evict", "match": {"argv_regex": tag}, "active_when": {"for_s": 0}, "evict": {}, "exit_after_s": 0}]}})
        owner = subprocess.Popen(["/bin/sh", "-c", "sleep 600; :", tag])
        wait(lambda: row(c)["state"] == "held" and not tree.alive(daemon) and not tree.alive(leader), timeout=90)
        stopped(tree, owner)
        owner = None
        wait(lambda: row(c)["state"] == "running", timeout=120)
        leader = row(c)["report"]["pid"]
        run_dir = wait(lambda: next(iter(sorted(runs.glob("run-*/daemon.pid"))), None), timeout=60).parent
        daemon = int((run_dir / "daemon.pid").read_text())
        tree.add(daemon)
        tree.add(leader)
        # unassigned: everything of it ends, the seat is given back
        c.api("POST", "/api/v1/ops/workloads.unassign", json={"target": "toy/worker", "params": {"node": nid}, "reason": "e2e"})
        wait(lambda: not tree.alive(daemon) and not tree.alive(leader), timeout=60)
        # the agent cleans up once it has seen every process gone (its own process-table check can trail ps's)
        wait(lambda: not (home / "state" / "workloads" / "toy.worker.json").exists(), timeout=30)
        assert not (home / "run" / "workloads" / "toy" / "worker" / "secrets.json").exists()
        # the guard: the agent acted on nothing but this test's own processes
        assert tree.check_journal(home) > 0
    finally:
        if owner:
            stopped(tree, owner)
        log.append(stopped(tree, p))
        subprocess.run([str(agent_bin), "--home", str(home), "stop-workloads"], capture_output=True)
        tree.__exit__(None, None, None)
        text = Path(f"{home}.log").read_text(encoding="utf-8", errors="replace") if Path(f"{home}.log").exists() else ""
        assert SECRET not in text, "the secret reached the agent's log"
        print(text[-6000:])
