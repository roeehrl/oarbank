"""Run oarbankd with measurement hooks, without changing oarbankd's source.

    OARBANKD_HOME=/tmp/x python bench/coordinator_instrumented.py --agent-port 17443 --admin-port 17400 ...

Everything is monkeypatched at import time, before `oarbank.coordinator.__main__.main()` runs:

* `db._TimedLock` is replaced by a subclass that records, per outermost acquisition, the time spent
  **waiting** for the global DB lock and the time it was **held**, broken down by the top-level core
  operation running on that thread (hello, heartbeat, claim, complete, reap, tick, ...).
* core/campaign entry points are wrapped to record their server-side wall time (lock waits included),
  and a few inner helpers (prefetch_for, _lifecycle_step, _node_directives) are timed separately.
* `EventBus.bind` (called once inside the server's event loop) also starts an event-loop-lag ticker.
* `agent_app()` gains `GET /_bench/stats[?reset=1]` returning all of the above plus process CPU/RSS.

Histogram updates for lock wait/hold happen while the DB lock is held, so they are serialised by it.
"""
import asyncio
import math
import os
import sys
import threading
import time

from oarbank.coordinator import app as appmod
from oarbank.coordinator import campaigns, core
from oarbank.coordinator import db as dbmod


class Hist:
    """Log-bucketed histogram, 1 us .. 1000 s, 20 buckets per decade (~12% resolution)."""
    LO, PER = 1e-6, 20
    N = PER * 9 + 2

    def __init__(self):
        self.counts = [0] * self.N
        self.n, self.total, self.max = 0, 0.0, 0.0

    def add(self, v: float):
        i = 0 if v <= self.LO else min(self.N - 1, int(math.log10(v / self.LO) * self.PER) + 1)
        self.counts[i] += 1
        self.n += 1
        self.total += v
        if v > self.max:
            self.max = v

    def q(self, p: float):
        if not self.n:
            return None
        k, c = p * self.n, 0
        for i, x in enumerate(self.counts):
            c += x
            if c >= k:
                return min(self.max, self.LO * 10 ** (i / self.PER))
        return self.max

    def summary(self) -> dict:
        if not self.n:
            return {"n": 0}
        return {"n": self.n, "sum_s": round(self.total, 4), "mean_ms": round(self.total / self.n * 1e3, 4),
                "p50_ms": round(self.q(0.5) * 1e3, 4), "p95_ms": round(self.q(0.95) * 1e3, 4),
                "p99_ms": round(self.q(0.99) * 1e3, 4), "max_ms": round(self.max * 1e3, 4)}


class Stats:
    def __init__(self):
        self.t0 = time.time()
        self.cpu0 = os.times()
        self.wait = Hist()
        self.hold = Hist()
        self.wait_by_op: dict[str, Hist] = {}
        self.hold_by_op: dict[str, Hist] = {}
        self.op_wall: dict[str, Hist] = {}
        self.inner: dict[str, Hist] = {}
        self.loop_lag = Hist()
        self.sql: dict[str, Hist] = {}
        self.http: dict[str, Hist] = {}
        self.busy = 0


S = Stats()
STATS_LOCK = threading.Lock()      # guards op_wall / inner / busy (updated outside the DB lock)
_tl = threading.local()


def _op() -> str:
    return getattr(_tl, "op", None) or threading.current_thread().name.split("-")[0] or "other"


class InstrumentedLock(dbmod._TimedLock):
    def acquire(self, timeout=dbmod.LOCK_TIMEOUT):
        depth = getattr(_tl, "depth", 0)
        if depth:                                   # re-entrant: already ours, never waits
            super().acquire(timeout)
            _tl.depth = depth + 1
            return True
        t0 = time.perf_counter()
        try:
            super().acquire(timeout)
        except dbmod.DBBusy:
            with STATS_LOCK:
                S.busy += 1
            raise
        t1 = time.perf_counter()
        _tl.depth, _tl.t_acq = 1, t1
        st, op = S, _op()                           # serialised by the DB lock we now hold
        st.wait.add(t1 - t0)
        st.wait_by_op.setdefault(op, Hist()).add(t1 - t0)
        return True

    def release(self):
        d = _tl.depth - 1
        _tl.depth = d
        if d == 0:
            hold = time.perf_counter() - _tl.t_acq
            st, op = S, _op()
            st.hold.add(hold)
            st.hold_by_op.setdefault(op, Hist()).add(hold)
        super().release()


dbmod._TimedLock = InstrumentedLock


def _sql_kind(sql: str, in_tx: bool) -> str:
    head = sql.lstrip()[:8].upper()
    if head.startswith("COMMIT"):
        return "commit"
    if head.startswith(("BEGIN", "ROLLBACK")):
        return head.split()[0].lower()
    if head.startswith("SELECT"):
        return "select"
    if head.startswith("PRAGMA"):
        return "checkpoint" if "CHECKPOINT" in sql.upper() else "pragma"
    return "write_in_tx" if in_tx else "write_autocommit"     # autocommit = its own transaction + fsync


class ConnProxy:
    """Times every statement oarbankd runs on its one connection (all calls happen under the DB lock)."""

    def __init__(self, conn):
        self._c = conn

    def execute(self, sql, args=()):
        in_tx = self._c.in_transaction
        t0 = time.perf_counter()
        try:
            return self._c.execute(sql, args)
        finally:
            dt = time.perf_counter() - t0
            S.sql.setdefault(_sql_kind(sql, in_tx), Hist()).add(dt)

    def __getattr__(self, name):
        return getattr(self._c, name)


_orig_db_init = dbmod.DB.__init__


def _db_init(self, path):
    _orig_db_init(self, path)
    sync = os.environ.get("BENCH_SQLITE_SYNC")      # experiment knob only (A/B durability cost)
    if sync:
        self.conn.execute(f"PRAGMA synchronous={sync}")
    self.sync_mode = self.conn.execute("PRAGMA synchronous").fetchone()[0]
    self.conn = ConnProxy(self.conn)


dbmod.DB.__init__ = _db_init


def _wrap_top(mod, name, label=None):
    f = getattr(mod, name)
    label = label or name

    def w(*a, **k):
        if getattr(_tl, "op", None) is not None:
            return f(*a, **k)
        _tl.op = label
        t0 = time.perf_counter()
        try:
            return f(*a, **k)
        finally:
            _tl.op = None
            dt = time.perf_counter() - t0
            with STATS_LOCK:
                S.op_wall.setdefault(label, Hist()).add(dt)
    w.__wrapped__ = f
    setattr(mod, name, w)


def _wrap_inner(mod, name):
    f = getattr(mod, name)

    def w(*a, **k):
        t0 = time.perf_counter()
        try:
            return f(*a, **k)
        finally:
            dt = time.perf_counter() - t0
            with STATS_LOCK:
                S.inner.setdefault(name, Hist()).add(dt)
    w.__wrapped__ = f
    setattr(mod, name, w)


for _n in ("hello", "heartbeat", "claim", "complete", "release", "fail", "append_log", "auth_node",
           "enroll", "enroll_status", "approve_enrollment", "reap"):
    if hasattr(core, _n):
        _wrap_top(core, _n)
for _n in ("tick_all", "tick_one"):
    if hasattr(campaigns, _n):
        _wrap_top(campaigns, _n, "campaigns." + _n)
for _n in ("prefetch_for", "_lifecycle_step", "_node_directives"):
    if hasattr(core, _n):
        _wrap_inner(core, _n)


async def _lag_monitor(period=0.05):
    while True:
        t = time.perf_counter()
        await asyncio.sleep(period)
        S.loop_lag.add(max(0.0, time.perf_counter() - t - period))


_orig_bind = appmod.EventBus.bind


def _bind(self, loop):
    _orig_bind(self, loop)
    loop.create_task(_lag_monitor())


appmod.EventBus.bind = _bind



def peak_rss_mb() -> float:
    """This process's peak resident memory: ru_maxrss (bytes on macOS, KiB on Linux), the peak working set on Windows."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + \
                       [(n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                                                       "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                                                       "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
        c = Counters(cb=ctypes.sizeof(Counters))
        info = ctypes.WinDLL("psapi").GetProcessMemoryInfo
        info.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        info(wintypes.HANDLE(-1), ctypes.byref(c), c.cb)                   # -1: this process
        return round(c.PeakWorkingSetSize / 2 ** 20, 1)
    import resource
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(rss / (2 ** 20 if sys.platform == "darwin" else 2 ** 10), 1)

def snapshot(reset: bool) -> dict:
    global S
    with STATS_LOCK:
        st = S
        now, cpu = time.time(), os.times()
        wall = max(1e-9, now - st.t0)
        cpu_s = (cpu.user - st.cpu0.user) + (cpu.system - st.cpu0.system)
        ops = sorted(set(st.hold_by_op) | set(st.op_wall))
        out = {
            "window_s": round(wall, 3),
            "cpu_pct": round(100 * cpu_s / wall, 1),
            "maxrss_mb": peak_rss_mb(),
            "threads": threading.active_count(),
            "lock_wait": st.wait.summary(),
            "lock_hold": st.hold.summary(),
            "lock_util_pct": round(100 * st.hold.total / wall, 1),
            "db_busy_503": st.busy,
            "loop_lag": st.loop_lag.summary(),
            "by_op": {op: {"wall": st.op_wall.get(op, Hist()).summary(),
                           "lock_wait": st.wait_by_op.get(op, Hist()).summary(),
                           "lock_hold": st.hold_by_op.get(op, Hist()).summary(),
                           "hold_share_pct": round(100 * st.hold_by_op[op].total / max(1e-9, st.hold.total), 1)
                           if op in st.hold_by_op else 0.0} for op in ops},
            "inner": {k: v.summary() for k, v in st.inner.items()},
            "http": {k: v.summary() for k, v in st.http.items()},
            "sql": {k: {**v.summary(), "time_share_of_lock_hold_pct": round(100 * v.total / max(1e-9, st.hold.total), 1)}
                    for k, v in st.sql.items()},
        }
        if reset:
            S = Stats()
    return out


def _route(path: str) -> str:
    parts = path.strip("/").split("/")
    if len(parts) >= 3 and parts[:2] == ["v1", "agent"]:
        return parts[2] if parts[2] != "enroll" or len(parts) == 3 else "enroll_status"
    if len(parts) == 4 and parts[:2] == ["v1", "attempts"]:
        return parts[3]
    return path


class HttpTiming:
    """Raw ASGI middleware: time from request arrival in oarbankd to the last response byte (includes
    threadpool queueing, GIL contention, auth dependency and the core call; excludes the client side)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        t0 = time.perf_counter()
        try:
            await self.app(scope, receive, send)
        finally:
            S.http.setdefault(_route(scope["path"]), Hist()).add(time.perf_counter() - t0)


_orig_agent_app = appmod.agent_app


def _agent_app(db, *a, **kw):
    app = _orig_agent_app(db, *a, **kw)
    app.add_middleware(HttpTiming)

    @app.get("/_bench/stats")
    def bench_stats(reset: int = 0):
        out = snapshot(bool(reset))
        out["sqlite_synchronous"] = {0: "OFF", 1: "NORMAL", 2: "FULL", 3: "EXTRA"}.get(getattr(db, "sync_mode", -1), "?")
        for suffix in ("", "-wal"):
            p = str(db.path) + suffix
            out["db_bytes" + suffix.replace("-", "_")] = os.path.getsize(p) if os.path.exists(p) else 0
        return out

    return app


appmod.agent_app = _agent_app


if __name__ == "__main__":
    home = os.environ.get("OARBANKD_HOME", "")
    from oarbank import paths
    if not home or os.path.realpath(os.path.expanduser(home)) == os.path.realpath(paths.coordinator_home()):
        sys.exit("refusing to run: OARBANKD_HOME must point at a scratch directory, never the production ~/Library/Application Support/Oarbank/coordinator")
    for flag, prod in (("--agent-port", "7443"), ("--admin-port", "7401")):
        if flag not in sys.argv or sys.argv[sys.argv.index(flag) + 1] == prod:
            sys.exit(f"refusing to run: pass an explicit non-production {flag}")
    from oarbank.coordinator.__main__ import main
    main()
