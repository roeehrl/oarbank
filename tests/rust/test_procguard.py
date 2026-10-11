"""The end-to-end tests' signal guard (procguard.py): a test signals only processes of its own spawn tree, verified by
pid and start time, and an agent's journal that acted on any other process fails the test."""
import json
import os
import signal
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from procguard import SpawnTree, started, wait_until  # noqa: E402

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the guard reads the POSIX process table (ps)")


def test_only_the_tests_own_processes_are_ever_signalled(tmp_path):
    with SpawnTree() as tree:
        child = subprocess.Popen(["/bin/sleep", "60"])
        try:
            assert wait_until(lambda: tree.owns(child.pid), timeout=10), "a child of the test is in its tree"
            assert tree.alive(child.pid)
            # anything else is refused and never signalled: the test's parent, init, a pid nobody started here
            for foreign in (os.getppid(), 1):
                assert started(foreign) is not None
                assert not tree.owns(foreign) and not tree.signal(foreign, signal.SIGTERM)
            assert started(os.getppid()) is not None, "the parent still runs"
            # a recycled pid (the recorded start time differs) is refused too
            with tree.lock:
                real = tree.own[child.pid]
                tree.own[child.pid] = "Thu Jan  1 00:00:00 1970"
            assert not tree.signal(child.pid, signal.SIGTERM) and child.poll() is None
            with tree.lock:
                tree.own[child.pid] = real
            assert tree.signal(child.pid, signal.SIGTERM)
            assert child.wait(10) == -signal.SIGTERM
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


def test_an_agent_journal_that_acted_on_a_foreign_process_fails(tmp_path):
    with SpawnTree() as tree:
        child = subprocess.Popen(["/bin/sleep", "60"])
        try:
            assert wait_until(lambda: tree.owns(child.pid), timeout=10)
            journal = tmp_path / "state" / "journal"
            journal.mkdir(parents=True)
            own = {"kind": "actuation", "reason": "WORKLOAD_PAUSE", "pid": child.pid}
            (journal / "journal-1.jsonl").write_text(json.dumps(own) + "\n", encoding="utf-8")
            assert tree.check_journal(tmp_path) == 1
            foreign = {"kind": "actuation", "reason": "WORKLOAD_PAUSE", "pid": os.getppid()}
            (journal / "journal-2.jsonl").write_text(json.dumps(foreign) + "\n", encoding="utf-8")
            with pytest.raises(AssertionError, match="outside the test's spawn tree"):
                tree.check_journal(tmp_path)
        finally:
            child.kill()
            child.wait()
