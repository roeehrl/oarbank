"""oarbank-console state (PLAN D10; admin-console.md "Read-path isolation").

- One snapshot connection (PRAGMA query_only=1): every 250 ms it checks PRAGMA data_version; when the
  database changed it rebuilds the hot snapshot (at most once a second) in one short read transaction.
- oarbankd's /internal/state is polled once a second for in-memory facts (writer lock, module health,
  fleet state); a failed poll marks the console "coordinator unreachable" but history keeps rendering.
- Drill-down pages use a separate 2-connection read pool behind a limiter, with a per-query time budget
  (progress handler), so no query can hold a snapshot long enough to starve WAL checkpoints.
- Each snapshot version is rendered once per fragment and shared by every viewer (see app.py).
"""
import asyncio
import json
import queue
import sqlite3
import threading
import time
import uuid

import httpx

from .views import fleet_data

QUERY_BUDGET_S = 0.25


def wait_for_schema(db_path, poll_s: float = 0.5, log=print) -> None:
    """Return once oarbankd has created its database. The console starts beside oarbankd and may be first (a fresh
    install): it waits, read-only, and never creates the file itself."""
    from pathlib import Path
    uri = Path(db_path).resolve().as_uri() + "?mode=ro"
    told = False
    while True:
        try:
            conn = sqlite3.connect(uri, uri=True)
            try:
                if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='settings'").fetchone():
                    return                    # oarbankd creates the whole schema in one transaction (db.py)
            finally:
                conn.close()
        except sqlite3.OperationalError:
            pass                              # no file yet
        if not told:
            log(f"oarbank-console: waiting for oarbankd to create {db_path}", flush=True)
            told = True
        time.sleep(poll_s)


class Reader:
    """A read-only SQLite connection with q/one/get_setting (the views' interface)."""

    def __init__(self, path: str, budget_s: float | None = None):
        self.conn = sqlite3.connect(str(path), check_same_thread=False, timeout=5.0)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA query_only=1")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.budget_s = budget_s
        self._deadline = None
        if budget_s:
            self.conn.set_progress_handler(self._check, 10000)

    def _check(self):
        return 1 if self._deadline and time.monotonic() > self._deadline else 0

    def _exec(self, sql, args):
        self._deadline = time.monotonic() + self.budget_s if self.budget_s else None
        return self.conn.execute(sql, args)

    def q(self, sql, args=()):
        rows = self._exec(sql, args).fetchall()
        self._deadline = None
        return [dict(r) for r in rows]

    def one(self, sql, args=()):
        r = self._exec(sql, args).fetchone()
        self._deadline = None
        return dict(r) if r else None

    def get_setting(self, key, default=None):
        r = self.one("SELECT value_json FROM settings WHERE key=?", (key,))
        return json.loads(r["value_json"]) if r else default

    def data_version(self) -> int:
        return self.conn.execute("PRAGMA data_version").fetchone()[0]

    def snapshot_tx(self):
        return _ReadTx(self.conn)


class _ReadTx:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.conn.execute("BEGIN")
        return self

    def __exit__(self, *a):
        self.conn.execute("COMMIT")
        return False


class ReadPool:
    """Two budgeted readers for drill-down pages; `with pool.get() as r:`."""

    def __init__(self, path: str, size: int = 2):
        self._q = queue.Queue()
        for _ in range(size):
            self._q.put(Reader(path, budget_s=QUERY_BUDGET_S))

    def get(self, timeout: float = 5.0):
        pool = self

        class _Lease:
            def __enter__(self):
                try:
                    self.r = pool._q.get(timeout=timeout)
                except queue.Empty:
                    raise TimeoutError("console read pool exhausted")
                return self.r

            def __exit__(self, *a):
                pool._q.put(self.r)
                return False
        return _Lease()


class ConsoleState:
    def __init__(self, db_path: str, coordinator_url: str, secret_path=None, secret: str | None = None,
                 poll_s: float = 0.25, min_rebuild_s: float = 1.0):
        self.db_path, self.coordinator_url = str(db_path), coordinator_url.rstrip("/")
        self._secret_path, self._secret = secret_path, secret
        self.reader = Reader(self.db_path)
        self.pool = ReadPool(self.db_path)
        self.poll_s, self.min_rebuild_s = poll_s, min_rebuild_s
        self.boot_id = uuid.uuid4().hex[:12]
        self.version = 0
        self.snapshot: dict = {}
        self.built_at = 0.0
        self.oarbankd: dict | None = None
        self.coordinator_error: str | None = None
        self.coordinator_down_since: float | None = None
        self._last_dv = None
        self._stop = threading.Event()
        self._subs: set = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self.renders = 0                 # fragment renders (the gate: one per fragment, version and session)
        self.render_cache: dict = {}
        self.rebuild()

    # ------------------------------------------------------------------ secret / oarbankd
    def secret(self) -> str | None:
        if self._secret:
            return self._secret
        try:
            return open(self._secret_path).read().strip() if self._secret_path else None
        except OSError:
            return None

    def coordinator_headers(self, actor: str) -> dict:
        h = {"x-oarbank-actor": actor, "x-oarbank-source": "gui"}
        s = self.secret()
        if s:
            h["x-oarbank-console-secret"] = s
        return h

    def poll_fleetd(self, client: httpx.Client):
        try:
            r = client.get(self.coordinator_url + "/internal/state", headers=self.coordinator_headers("console"), timeout=2.0)
            r.raise_for_status()
            new = r.json()
            changed = (self.oarbankd or {}).get("boot_id") != new.get("boot_id") or self.coordinator_error is not None
            self.oarbankd, self.coordinator_error, self.coordinator_down_since = new, None, None
            return changed
        except Exception as e:
            was_ok = self.coordinator_error is None
            self.coordinator_error = f"{type(e).__name__}: {e}"[:200]
            self.coordinator_down_since = self.coordinator_down_since or time.time()
            return was_ok

    # ------------------------------------------------------------------ snapshot
    def rebuild(self):
        with self._lock:
            with self.reader.snapshot_tx():
                data = fleet_data(self.reader)
            self.version += 1
            self.snapshot, self.built_at = data, time.time()
            self.render_cache = {k: v for k, v in self.render_cache.items() if k[1] == self.version}
        self._notify()

    def stale(self) -> bool:
        return self.coordinator_error is not None

    def meta(self) -> dict:
        return {"version": self.version, "built_at": self.built_at, "boot_id": self.boot_id,
                "coordinator_ok": self.coordinator_error is None, "coordinator_error": self.coordinator_error,
                "coordinator_down_since": self.coordinator_down_since, "oarbankd": self.oarbankd}

    def run(self):
        """Background thread: data_version watch + oarbankd poll."""
        client = httpx.Client()
        last_poll = 0.0
        while not self._stop.is_set():
            try:
                changed = False
                dv = self.reader.data_version()
                if dv != self._last_dv and time.time() - self.built_at >= self.min_rebuild_s:
                    self._last_dv = dv
                    changed = True
                if time.monotonic() - last_poll >= 1.0:
                    last_poll = time.monotonic()
                    if self.poll_fleetd(client):
                        changed = True
                if changed:
                    self.rebuild()
            except Exception:
                pass
            self._stop.wait(self.poll_s)
        client.close()

    def start(self):
        threading.Thread(target=self.run, name="console-state", daemon=True).start()
        return self

    def stop(self):
        self._stop.set()

    # ------------------------------------------------------------------ SSE subscribers
    def bind_loop(self, loop):
        self._loop = loop

    def subscribe(self, maxsize: int = 32) -> asyncio.Queue:
        q = asyncio.Queue(maxsize=maxsize)
        self._subs.add(q)
        return q

    def unsubscribe(self, q):
        self._subs.discard(q)

    def _notify(self):
        if not self._loop:
            return
        v = self.version

        def push():
            for q in list(self._subs):
                try:
                    q.put_nowait(v)
                except asyncio.QueueFull:
                    self._subs.discard(q)        # a slow client is dropped; it reconnects and resyncs
                    q.dropped = True
        self._loop.call_soon_threadsafe(push)
