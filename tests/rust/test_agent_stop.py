"""No runner outlives its agent (docs/design/architecture.md, "Stopping the agent"), on a real agent running a reel
render:

- SIGTERM (what launchd's bootout and kickstart -k, systemd's stop and restart, the launcher and a test's terminate()
  send): the agent asks the runner to stop (it checkpoints first), releases the attempt as `agent_stop` (requeued, no
  charge) and exits within its stop budget, leaving no runner process and no runner record;
- SIGKILL: the agent's watchdog ends the runner as soon as the agent is gone;
- SIGKILL of the agent and its watchdog: the next agent ends the runner before it takes work, and the coordinator ends
  the attempt it no longer runs (`agent_restart`).
"""
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import install_module  # noqa: E402
from test_agent_files import REEL, admit_next, db_rows, module_state, op, planned, start_agent  # noqa: E402
from test_agent_session import wait  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX signals; on Windows a runner's Job Object ends with the agent "
                                                         "and the launcher asks the agent to stop through its stop event")


def processes(needle: str) -> list[int]:
    """The pids of the processes whose command line holds `needle`."""
    out = subprocess.run(["ps", "ax", "-o", "pid=,command="], capture_output=True, text=True, check=True).stdout
    return [int(line.split(None, 1)[0]) for line in out.splitlines() if needle in line and str(os.getpid()) != line.split(None, 1)[0]]


def runner(home: Path, aid: int) -> list[int]:
    return processes(str(home / "work" / str(aid)) + os.sep)


def running_render(c, nid, home: Path, after: int = 0) -> int:
    """The render's live attempt on the node (newer than `after`) once its runner runs."""
    def live():
        rows = db_rows(c, "SELECT t.attempt_id FROM attempts t JOIN jobs j ON j.job_id=t.job_id WHERE t.node_id=? AND "
                          "j.campaign_id='c_stop' AND t.state='live' AND t.attempt_id>?", (nid, after))
        return rows and runner(home, rows[0]["attempt_id"]) and rows[0]["attempt_id"]
    return wait(live, timeout=120)


def attempt(c, aid):
    (a,) = db_rows(c, "SELECT state, end_reason FROM attempts WHERE attempt_id=?", (aid,))
    return a["state"], a["end_reason"]


def test_a_stopped_or_killed_agent_leaves_no_runner_behind(agent_bin, coordinator, tmp_path):
    install_module(coordinator, REEL, tmp_path)
    # only rules may hold work back, never load: on a busy host moderate mode's budget could hold the render
    planned(coordinator, "protection.rules.update", "fleet", {"config": {"schema": 1, "node": {"mode": "fleet_first"}}})
    home = tmp_path / "agent"
    log, procs = [], []

    def start():
        p = start_agent(agent_bin, home, coordinator)
        procs.append(p)
        return p

    try:
        a = start()
        nid = admit_next(coordinator)
        wait(lambda: module_state(coordinator, nid, "reel") == "certified", timeout=180)
        op(coordinator, "mod.reel.queue_render", params={"renders": [{"frames": 240, "seed": 5, "step_ms": 2000, "every": 100}],
                                                          "campaign_id": "c_stop"})
        first = running_render(coordinator, nid, home)

        # SIGTERM: the runner stops (checkpointing first), the attempt is released, the agent exits in time
        t0 = time.monotonic()
        a.send_signal(signal.SIGTERM)
        log.append(a.communicate(timeout=45)[0])
        took = time.monotonic() - t0
        assert a.returncode == 0, log[-1][-3000:]
        assert took < 30, took
        assert runner(home, first) == [], "a runner outlived its stopped agent"
        assert attempt(coordinator, first) == ("released", "agent_stop")
        (job,) = db_rows(coordinator, "SELECT exec_failures FROM jobs WHERE campaign_id='c_stop'")
        assert job["exec_failures"] == 0                               # no charge to the job
        assert not list((home / "state" / "runners").glob("*.json"))   # nothing left for a later agent to end
        assert "SIGTERM: stopping" in log[-1] and "released" in log[-1], log[-1][-3000:]

        # SIGKILL: the agent cannot stop anything; its watchdog ends the runner once the agent is gone
        a = start()
        second = running_render(coordinator, nid, home, after=first)
        assert processes(f"reap-runners --agent-pid {a.pid} ")         # the agent's watchdog runs
        a.kill()
        log.append(a.communicate(timeout=30)[0])
        wait(lambda: not runner(home, second), timeout=15)

        # SIGKILL of the agent and its watchdog: the runner survives both, and the next agent ends it before it
        # takes work; the coordinator ends the attempt that agent does not run
        a = start()
        assert wait(lambda: attempt(coordinator, second)[0] != "live", timeout=60)
        assert attempt(coordinator, second) == ("released", "agent_restart")
        third = running_render(coordinator, nid, home, after=second)
        dogs = processes(f"reap-runners --agent-pid {a.pid} ")
        assert dogs
        for pid in dogs:
            os.kill(pid, signal.SIGKILL)
        a.kill()
        log.append(a.communicate(timeout=30)[0])
        time.sleep(2)
        orphans = runner(home, third)
        assert orphans, "the runner was expected to outlive an agent and a watchdog that were both killed"
        a = start()
        wait(lambda: not runner(home, third), timeout=30)
        wait(lambda: attempt(coordinator, third)[0] != "live", timeout=60)
        assert attempt(coordinator, third) == ("released", "agent_restart")
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    log.append(p.communicate(timeout=45)[0])
                except subprocess.TimeoutExpired:
                    p.kill()
                    log.append(p.communicate()[0])
        print("".join(log)[-8000:])
