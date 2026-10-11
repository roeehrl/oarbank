"""A test's own spawn tree, and the only way the end-to-end tests signal a process.

`SpawnTree` samples the process table (`ps`; a Toolhelp snapshot on Windows) in the background and keeps every
process that descends from the test process, each with its start time, plus the processes the test names explicitly
(a daemon that called setsid and forked twice is reparented at once, so the test adds it from the pid file it wrote).
`signal` refuses any process that is not in the tree with the same start time, so a recycled pid is never signalled;
`alive` asks the process table, never `kill`. And `check_journal` reads an agent's decision journal: every actuation
it records must target a process of the tree."""
import json
import os
import signal as _signal
import subprocess
import threading
import time
from pathlib import Path


def table() -> dict[int, tuple[int, str]]:
    """{pid: (ppid, start time)} for every process (`ps -axo pid=,ppid=,lstart=`; a Toolhelp snapshot on Windows)."""
    if os.name == "nt":
        return _nt_table()
    out = subprocess.run(["ps", "-axo", "pid=,ppid=,lstart="], capture_output=True, text=True).stdout
    rows = {}
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            rows[int(parts[0])] = (int(parts[1]), parts[2].strip())
    return rows


def started(pid: int) -> str | None:
    """A process's start time, or None when there is no such process."""
    if os.name == "nt":
        return _nt_started(pid)
    out = subprocess.run(["ps", "-o", "lstart=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return out or None


if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.OpenProcess.restype = wintypes.HANDLE
    _k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    _k32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4

    class _Entry(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]

    _k32.Process32FirstW.argtypes = _k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_Entry)]

    def _nt_started(pid: int) -> str | None:
        """The creation time (FILETIME ticks) of a running process; None when it is gone or has exited."""
        h = _k32.OpenProcess(0x1000, False, pid)            # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            code = wintypes.DWORD()
            if not _k32.GetExitCodeProcess(h, ctypes.byref(code)) or code.value != 259:     # STILL_ACTIVE
                return None
            t = [wintypes.FILETIME() for _ in range(4)]
            if not _k32.GetProcessTimes(h, *(ctypes.byref(x) for x in t)):
                return None
            return str(t[0].dwHighDateTime << 32 | t[0].dwLowDateTime)
        finally:
            _k32.CloseHandle(h)

    def _nt_table() -> dict[int, tuple[int, str]]:
        snap = _k32.CreateToolhelp32Snapshot(0x2, 0)       # TH32CS_SNAPPROCESS
        if snap in (None, wintypes.HANDLE(-1).value):
            return {}
        rows = {}
        try:
            e = _Entry()
            e.dwSize = ctypes.sizeof(_Entry)
            ok = _k32.Process32FirstW(snap, ctypes.byref(e))
            while ok:
                s = _nt_started(e.th32ProcessID) if e.th32ProcessID else None
                if s is not None:
                    rows[e.th32ProcessID] = (e.th32ParentProcessID, s)
                ok = _k32.Process32NextW(snap, ctypes.byref(e))
        finally:
            _k32.CloseHandle(snap)
        return rows


# the hard stop: SIGKILL on POSIX; on Windows os.kill with SIGTERM is TerminateProcess, which is just as final
KILL = getattr(_signal, "SIGKILL", _signal.SIGTERM)


def _after(child: str, parent: str | None) -> bool:
    """On Windows a parent pid may be a recycled one: a child counts only when it started after its parent (FILETIME
    ticks compare; `ps` times are not compared)."""
    return os.name != "nt" or parent is None or int(child) >= int(parent)


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
                for pid, (ppid, s) in rows.items():
                    if pid not in known and ppid in known and _after(s, rows.get(ppid, (0, None))[1]):
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
        except OSError:                        # gone (ProcessLookupError; on Windows, WinError 5 or 87)
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
