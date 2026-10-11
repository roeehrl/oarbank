"""A test's own spawn tree, and the only way the end-to-end tests signal a process (POSIX).

`SpawnTree` samples the process table (`ps`) in the background and keeps every process that descends from the test
process, each with its start time, plus the processes the test names explicitly (a daemon that called setsid and forked
twice is reparented at once, so the test adds it from the pid file it wrote). `signal` refuses any process that is not
in the tree with the same start time, so a recycled pid is never signalled; `alive` asks `ps`, never `kill`. And
`check_journal` reads an agent's decision journal: every actuation it records must target a process of the tree."""
import json
import os
import signal as _signal
import subprocess
import threading
import time
from pathlib import Path


def table() -> dict[int, tuple[int, str]]:
    """{pid: (ppid, start time)} for every process (`ps -axo pid=,ppid=,lstart=`)."""
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,lstart="], capture_output=True, text=True).stdout
    rows = {}
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            rows[int(parts[0])] = (int(parts[1]), parts[2].strip())
    return rows


def started(pid: int) -> str | None:
    """A process's start time, or None when there is no such process."""
    out = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return out or None



# the hard stop: SIGKILL on POSIX; on Windows os.kill with SIGTERM is TerminateProcess, which is just as final
KILL = getattr(_signal, "SIGKILL", _signal.SIGTERM)

class SpawnTree:
    def __init__(self, root: int | None = None, period_s: float = 0.25):
        self.root = root or os.getpid()
        self.period_s = period_s
        self.own: dict[int, str] = {}
        self.lock = threading.Lock()
        self.stop_ev = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.sample()
        self.t.start()
        return self

    def __exit__(self, *exc):
        self.stop_ev.set()
        self.t.join(5)
        self.sample()

    def _run(self):
        while not self.stop_ev.wait(self.period_s):
            self.sample()

    def sample(self):
        rows = table()
        with self.lock:
            known = {p for p, s in self.own.items() if rows.get(p, (0, None))[1] == s}
            known.add(self.root)
            changed = True
            while changed:                     # the closure under "parent is ours" in this snapshot
                changed = False
                for pid, (ppid, _) in rows.items():
                    if pid not in known and ppid in known:
                        known.add(pid)
                        changed = True
            for pid in known - {self.root}:
                if pid in rows and pid not in self.own:
                    self.own[pid] = rows[pid][1]

    def add(self, pid: int) -> bool:
        """Name a process the test started (a daemon it knows from its pid file); False when it is gone."""
        s = started(pid)
        if s is None:
            return False
        with self.lock:
            self.own.setdefault(pid, s)
        return True

    def owns(self, pid: int) -> bool:
        """The process is in the tree and still the one recorded (same start time; a gone one counts as recorded)."""
        with self.lock:
            s = self.own.get(pid)
        if s is None:
            return False
        now = started(pid)
        return now is None or now == s

    def alive(self, pid: int) -> bool:
        """The recorded process still runs (asked of `ps`; nothing is signalled)."""
        with self.lock:
            s = self.own.get(pid)
        now = started(pid)
        return now is not None and (s is None or now == s)

    def signal(self, pid: int, sig: int = _signal.SIGTERM) -> bool:
        """Signal one of the test's own processes; anything else is refused and never signalled."""
        with self.lock:
            s = self.own.get(pid)
        if s is None or started(pid) != s:
            return False
        try:
            os.kill(pid, sig)
            return True
        except ProcessLookupError:
            return False

    def check_journal(self, home: Path) -> int:
        """Every `actuation` in the agent's decision journal targets a process of this tree; returns how many."""
        n = 0
        for f in sorted((Path(home) / "state" / "journal").glob("*.jsonl")):
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    v = json.loads(line)
                except ValueError:
                    continue
                if v.get("kind") == "actuation":
                    pid = int(v.get("pid") or 0)
                    with self.lock:
                        ok = pid in self.own
                    assert ok, f"the agent acted on a process outside the test's spawn tree: {v}"
                    n += 1
        return n


def wait_until(f, timeout: float = 30.0, step: float = 0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if f():
            return True
        time.sleep(step)
    return bool(f())
