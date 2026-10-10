"""SQLite state for oarbankd: one file, WAL mode, one process, writes serialised by a lock."""
import collections
import json
import os
import sqlite3
import threading
import time

from . import clock
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_json TEXT);

CREATE TABLE IF NOT EXISTS enrollments (
  enrollment_id TEXT PRIMARY KEY, hostname TEXT, facts_json TEXT, peer_ip TEXT,
  ts_node_id TEXT, status TEXT NOT NULL,            -- pending|approved|claimed|rejected
  node_id TEXT, created_at REAL, decided_at REAL, decided_by TEXT,
  csr_pem TEXT, cert_json TEXT,                     -- the agent's CSR; the issued certificate until claimed
  join_code_id TEXT,                                -- the join code it presented (a multi-use code's machines wait here)
  user_code TEXT,                                   -- the device code the node shows (node-enrollment.md, "Device code")
  requested_name TEXT);                             -- the name the node asked for (`oarbank-node join --name`)

CREATE TABLE IF NOT EXISTS nodes (
  node_id TEXT PRIMARY KEY, ts_node_id TEXT, hostname TEXT, ts_ip TEXT, facts_json TEXT,
  label TEXT,                     -- the join code's label: the node's name (hostname), which the agent's reported name then never changes
  lifecycle TEXT NOT NULL,        -- enrolled|ready|quarantined|retired  (per-module state in modules_json)
  desired_state TEXT NOT NULL,    -- active|paused|draining
  agent_version TEXT, release_id TEXT, boot_id TEXT,
  cert_generation INT DEFAULT 0, cert_release TEXT, cert_os_version TEXT, cert_at REAL,
  platform TEXT, os TEXT, arch TEXT, os_version TEXT,   -- from the agent's facts (spec/platforms.md)
  limits_json TEXT DEFAULT '{}', policy_json TEXT DEFAULT '{}',
  last_heartbeat_at REAL, last_hello_at REAL, capacity_json TEXT, telemetry_json TEXT,
  ready_datasets_json TEXT DEFAULT '[]', doctor_json TEXT, doctor_at REAL,
  breaker_failures INT DEFAULT 0, quarantine_reason TEXT, created_at REAL,
  pending_cancel_json TEXT DEFAULT '[]', pending_revoke_json TEXT DEFAULT '[]',
  want_doctor INT DEFAULT 1, want_recertify INT DEFAULT 0, want_probe INT DEFAULT 0, want_processes INT DEFAULT 0,
  modules_json TEXT DEFAULT '{}',   -- {module: {state: doctor_failed|certifying|certified|revoked, generation, release, os_version, at, reason}}
  processes_json TEXT, processes_at REAL,          -- the agent's process summary (the rule editor's picker and preview)
  assigned_release TEXT,
  client_cert_fp TEXT, client_cert_prev_fp TEXT, client_cert_not_after REAL,   -- D29: the current (and, renewing, previous) certificate
  agent_build TEXT, agent_update_json TEXT,         -- agent self-update: the binary the agent runs, and its update state
  cik_pinned TEXT, cik_confirmed TEXT, cik_confirmed_by TEXT, cik_confirmed_at REAL,   -- the coordinator key the agent pinned
  install_coordinator_json TEXT, coordinator_move_json TEXT,
  folders_json TEXT,              -- the folders of the statement the agent applied: {id: {access, status}} (folders.py)
  tools_json TEXT,                -- the host tools the agent detected: {detected_at, native_arch, tools: {id: [...]}} (tools.py)
  want_detect INT DEFAULT 0,      -- tools.detect: ask the agent to detect its host tools again (the next directive)
  services_json TEXT, services_at REAL,   -- the agent's service report: {services: [...], probes: [...]} (protocol.md)
  clock_offset_s REAL);           -- the node's wall clock minus oarbankd's, at its last hello or heartbeat (protocol.md, "Clocks")

-- host tool definitions an admin made or extended (tools.py; jdk and python are built in)
CREATE TABLE IF NOT EXISTS tool_defs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, detector_json TEXT NOT NULL,
  updated_by TEXT, updated_at REAL);

CREATE TABLE IF NOT EXISTS node_samples (
  node_id TEXT, ts REAL, telemetry_json TEXT, capacity_json TEXT, busy INT,
  PRIMARY KEY (node_id, ts));

CREATE TABLE IF NOT EXISTS releases (
  release_id TEXT PRIMARY KEY, created_at REAL, path TEXT, sha256 TEXT,
  manifest_json TEXT, status TEXT,                  -- candidate|current|retired (one current per platform)
  platform TEXT NOT NULL DEFAULT 'darwin-arm64',
  seq INTEGER, statement TEXT, signature TEXT, composition_json TEXT);

CREATE TABLE IF NOT EXISTS blobs (digest TEXT PRIMARY KEY, path TEXT, size INT);

CREATE TABLE IF NOT EXISTS datasets (
  dataset_id TEXT PRIMARY KEY, kind TEXT, module TEXT, meta_json TEXT, files_json TEXT, created_at REAL,
  platform TEXT);                 -- a platform-bound dataset's platform (datasets.create `platform`, D33): its jobs run only there

-- D22: the core's only job grouping. A campaign belongs to one module, which owns its meaning
-- (e.g. a parameter search) in its own store and pages; the core schedules by priority and weight.
CREATE TABLE IF NOT EXISTS campaigns (
  campaign_id TEXT PRIMARY KEY, module TEXT NOT NULL, name TEXT, state TEXT NOT NULL,   -- running|paused|done|cancelled
  priority INT DEFAULT 0, weight REAL DEFAULT 1, labels_json TEXT DEFAULT '{}', created_by TEXT,
  created_at REAL, finished_at REAL, ticked_at REAL, tick_version INT,
  placement_json TEXT);           -- {mix, unit, bind, rebind, stranded_after_s, pin}: what stays on one platform class (D33)
CREATE INDEX IF NOT EXISTS campaigns_state ON campaigns(state);

-- D33: one row per unit of work (placement.py): its mix, the classes it may bind to and its binding
CREATE TABLE IF NOT EXISTS placement_bindings (
  unit TEXT PRIMARY KEY, module TEXT NOT NULL, campaign_id TEXT, parent TEXT,   -- parent: a pipeline sub-unit's unit
  mix TEXT NOT NULL, class TEXT, state TEXT NOT NULL,                         -- unbound|soft|hard|pinned
  source TEXT,                                                                -- first_claim|capacity|cache_hit|pin|rebind|dataset
  bind TEXT, rebind TEXT, stranded_after_s REAL, feasible_json TEXT,
  bound_at REAL, bound_job INT, bound_node TEXT, generation INT DEFAULT 0, stranded_since REAL);
CREATE INDEX IF NOT EXISTS placement_bindings_campaign ON placement_bindings(campaign_id);

-- D22: module-owned documents (a module's own records, e.g. a search's evaluations); written only through effects
CREATE TABLE IF NOT EXISTS module_store (
  module TEXT NOT NULL, collection TEXT NOT NULL, key TEXT NOT NULL, doc_json TEXT NOT NULL, updated_at REAL,
  PRIMARY KEY (module, collection, key));

CREATE TABLE IF NOT EXISTS jobs (
  job_id INTEGER PRIMARY KEY, job_key TEXT, campaign_id TEXT, labels_json TEXT DEFAULT '{}',
  dataset_id TEXT, kind TEXT, target_node TEXT, priority INT DEFAULT 0, subpriority INT DEFAULT 0,
  generation INT DEFAULT 1, state TEXT,   -- pending|leased|done|failed|quarantined|cancelled
  spec_json TEXT, datasets_json TEXT, exec_failures INT DEFAULT 0, expirations INT DEFAULT 0,
  not_before REAL DEFAULT 0, canonical_result_id INT, created_at REAL, done_at REAL,
  module TEXT, resources_json TEXT, name TEXT, stage TEXT, depends_on INTEGER,
  dispute_json TEXT,    -- {"nodes": [...], "results": [...], "scope", "class"}: replicas disagreed, awaiting a tie-break
  spec_version INT,
  placement_unit TEXT, platforms_json TEXT, group_key TEXT,   -- D33: its unit of work, its platforms, its group
  images_json TEXT);    -- the container set images its runner may run (jobs.enqueue images)
CREATE INDEX IF NOT EXISTS jobs_state ON jobs(state, priority);
CREATE INDEX IF NOT EXISTS jobs_dispatch ON jobs(state, priority DESC, subpriority DESC, job_id);
CREATE INDEX IF NOT EXISTS jobs_target ON jobs(target_node, state) WHERE target_node IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_key ON jobs(job_key);
CREATE INDEX IF NOT EXISTS jobs_campaign ON jobs(campaign_id, state);
CREATE INDEX IF NOT EXISTS jobs_depends ON jobs(depends_on) WHERE depends_on IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_unit ON jobs(placement_unit, state) WHERE placement_unit IS NOT NULL;

CREATE TABLE IF NOT EXISTS attempts (
  attempt_id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INT, node_id TEXT, generation INT,
  release_id TEXT, cert_generation INT, state TEXT,  -- live|completed|released|expired|failed|revoked|killed
  granted_at REAL, expires_at REAL, hard_deadline REAL, phase TEXT, cpu_s REAL DEFAULT 0,
  log_bytes INT DEFAULT 0, rss_gb REAL, end_reason TEXT, ended_at REAL, last_progress_at REAL, module_version TEXT,
  resume_json TEXT);              -- the checkpoint the attempt resumed from: {from_attempt, node_id, digest}
CREATE INDEX IF NOT EXISTS attempts_live ON attempts(state, node_id);
CREATE INDEX IF NOT EXISTS attempts_job ON attempts(job_id);

CREATE TABLE IF NOT EXISTS results (
  result_id INTEGER PRIMARY KEY, job_key TEXT, job_id INT, attempt_id INT UNIQUE,
  node_id TEXT, accepted INT, canonical INT, reason TEXT, at REAL,
  module TEXT, module_version TEXT, value REAL, digest TEXT, digest_version INT,
  fields_json TEXT, result_json TEXT,
  platform TEXT);                 -- the producing node's platform when the result was recorded (D33)
CREATE INDEX IF NOT EXISTS results_key ON results(job_key, canonical);
CREATE INDEX IF NOT EXISTS results_job ON results(job_id);

-- a job's latest portable checkpoint (docs/design/datasets-media-checkpoints.md): valid for one generation of an open job
CREATE TABLE IF NOT EXISTS checkpoints (
  job_id INTEGER PRIMARY KEY, generation INT NOT NULL, attempt_id INT NOT NULL, node_id TEXT NOT NULL, seq INT NOT NULL,
  digest TEXT NOT NULL, files_json TEXT NOT NULL, data_json TEXT, size INT NOT NULL, at REAL);
CREATE INDEX IF NOT EXISTS checkpoints_node ON checkpoints(node_id);

CREATE TABLE IF NOT EXISTS events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, actor TEXT, node_id TEXT,
  campaign_id TEXT, job_id INT, attempt_id INT, reason TEXT, payload_json TEXT,
  module TEXT);                   -- the module an event is about (its pages' module_events and its Health tab read it)

CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_module ON events(module, event_id) WHERE module IS NOT NULL;

CREATE TABLE IF NOT EXISTS idempotency (key TEXT PRIMARY KEY, response_json TEXT, at REAL);

-- D13: the audit log. Never pruned; hash-chained (hash = sha256(prev_hash || canonical row)).
CREATE TABLE IF NOT EXISTS audit (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, source TEXT, user_agent TEXT,
  request_id TEXT, idempotency_key TEXT, operation TEXT, category TEXT, target_type TEXT, target_id TEXT,
  dry_run INT, plan_id TEXT, before_json TEXT, after_json TEXT, reason TEXT, outcome TEXT, error TEXT,
  parent_event_id INT, prev_hash TEXT, hash TEXT);
CREATE INDEX IF NOT EXISTS audit_target ON audit(target_type, target_id);
CREATE INDEX IF NOT EXISTS audit_op ON audit(operation);
CREATE TABLE IF NOT EXISTS audit_digests (last_event_id INT PRIMARY KEY, hash TEXT, ts REAL, prev_sig TEXT, sig TEXT,
  pubkey TEXT, next_pubkey TEXT);
-- attempt phase transitions (waterfall): granted, each agent-reported phase, completion_received, verdict
CREATE TABLE IF NOT EXISTS attempt_phases (attempt_id INT, phase TEXT, at REAL, PRIMARY KEY(attempt_id, phase));
-- module-computed views (UI contract 1): materialized per input data version, read by the console
CREATE TABLE IF NOT EXISTS module_views (module TEXT, view_id TEXT, params_hash TEXT, data_version INT, computed_at REAL,
  doc_json TEXT, error TEXT, error_at REAL, PRIMARY KEY(module, view_id, params_hash));
-- D15: versions of editable resources (If-Match) and preview plans (plan id, 409 on drift)
CREATE TABLE IF NOT EXISTS resource_versions (key TEXT PRIMARY KEY, version INT NOT NULL);
CREATE TABLE IF NOT EXISTS plans (plan_id TEXT PRIMARY KEY, operation TEXT, request_json TEXT, versions_json TEXT,
  impact_json TEXT, actor TEXT, created_at REAL, expires_at REAL, applied_at REAL);

-- The agents' protection decision journals (shipped in heartbeats), for the node decision timeline
-- and the S16 checker. Pruned with events (30 days).
CREATE TABLE IF NOT EXISTS protection_decisions (
  node_id TEXT NOT NULL, seq INT NOT NULL, t REAL, kind TEXT, reason TEXT, rule TEXT, record_json TEXT,
  PRIMARY KEY (node_id, seq));
CREATE INDEX IF NOT EXISTS protection_decisions_t ON protection_decisions(node_id, t);
-- The module store (bundles by digest), which version runs where, and per-node pins
CREATE TABLE IF NOT EXISTS modules (
  name TEXT NOT NULL, version TEXT NOT NULL, module_id TEXT NOT NULL, compat TEXT, content_digest TEXT NOT NULL,
  path TEXT NOT NULL, manifest_json TEXT, installed_at REAL, installed_by TEXT, runtime TEXT,
  bundle_files INT, bundle_bytes INT,             -- the bundle's files and their total size, as installed
  PRIMARY KEY (name, version));
CREATE TABLE IF NOT EXISTS module_channels (
  name TEXT PRIMARY KEY, current TEXT, previous TEXT, canary TEXT, canary_nodes_json TEXT DEFAULT '[]',
  disabled INT DEFAULT 0, updated_at REAL);
CREATE TABLE IF NOT EXISTS module_pins (name TEXT NOT NULL, node_id TEXT NOT NULL, version TEXT NOT NULL,
  PRIMARY KEY (name, node_id));
-- Module secrets (modsecrets.py): write-only values, encrypted under the coordinator's secrets key; node_id '' is the
-- module scope; sealed = 1 while a move's copy holds them sealed to this coordinator's transport key
CREATE TABLE IF NOT EXISTS secrets (module TEXT NOT NULL, name TEXT NOT NULL, node_id TEXT NOT NULL DEFAULT '',
  ciphertext BLOB NOT NULL, fingerprint TEXT, set_at REAL, set_by TEXT, sealed INT NOT NULL DEFAULT 0,
  PRIMARY KEY(module, name, node_id));
-- The first run of each container set image digest per module (audited; spec/sandbox.md "Image sets")
CREATE TABLE IF NOT EXISTS module_images (module TEXT NOT NULL, digest TEXT NOT NULL, image TEXT NOT NULL,
  set_name TEXT NOT NULL, key_sha256 TEXT, first_run_at REAL, node_id TEXT, attempt_id INT, PRIMARY KEY(module, digest));
-- Operator approvals of a module version's node-side sandbox grants (spec/sandbox.md), by digest of the requests
CREATE TABLE IF NOT EXISTS module_grants (
  name TEXT NOT NULL, version TEXT NOT NULL, requests_json TEXT NOT NULL, digest TEXT NOT NULL, approved_by TEXT,
  approved_at REAL, reason TEXT, PRIMARY KEY (name, version));
-- A module's own files on the coordinator (module protocol: host.files.*, files.* effects): names bound to blobs
CREATE TABLE IF NOT EXISTS module_files (
  module TEXT NOT NULL, path TEXT NOT NULL, digest TEXT NOT NULL, size INT, updated_at REAL, PRIMARY KEY (module, path));
-- The outcome of each module integrity check (integrity.check, plus the core's own checks of the module's files)
CREATE TABLE IF NOT EXISTS module_checks (
  check_id INTEGER PRIMARY KEY, module TEXT NOT NULL, version TEXT, scope TEXT, move_id TEXT, at REAL, ok INT,
  fingerprint TEXT, checks_json TEXT, actor TEXT);
-- Agent self-update: oarbank-agent binaries by sha256 (each for one platform), and one channel per platform
-- (current, previous, canary on chosen nodes)
CREATE TABLE IF NOT EXISTS agent_builds (
  sha256 TEXT PRIMARY KEY, version TEXT NOT NULL, path TEXT NOT NULL, size INT, uploaded_at REAL, uploaded_by TEXT,
  seq INT, statement TEXT, signature TEXT, platform TEXT NOT NULL, format TEXT);
CREATE TABLE IF NOT EXISTS agent_channel (
  platform TEXT PRIMARY KEY, current TEXT, previous TEXT, canary TEXT, canary_nodes_json TEXT DEFAULT '[]',
  updated_at REAL);
-- Coordinator moves (coordinator-move.md): one plan (target, pairing) and the signed move statements
CREATE TABLE IF NOT EXISTS coordinator_plans (
  plan_id TEXT PRIMARY KEY, target_url TEXT, target_stable_id TEXT, target_node_id TEXT, code_sha TEXT, expires_at REAL,
  state TEXT, created_at REAL, actor TEXT, b_url TEXT, b_cik TEXT, b_audit_pub TEXT, b_secrets_pub TEXT, move_token_sha TEXT, paired_at REAL,
  b_tls_ca TEXT,                                    -- the standby's TLS CA, learned at pairing: calls to it pin it
  target_platform TEXT);                            -- the target's platform: the enrolled node's, then what the standby reports
CREATE TABLE IF NOT EXISTS coordinator_moves (
  move_id TEXT PRIMARY KEY, plan_id TEXT, epoch INT, statement TEXT, sig_from TEXT, sig_to TEXT, sig_owner TEXT, state TEXT,
  created_at REAL, not_before REAL, ended_at REAL, actor TEXT, reason TEXT, final_snapshot_json TEXT, report_json TEXT,
  cancel_payload TEXT, cancel_sig TEXT,
  modules_json TEXT, force INT DEFAULT 0);          -- what modules said about the move; the operator's override of blockers
-- Immutable versions of each node's protection section (restore writes a new version)
CREATE TABLE IF NOT EXISTS protection_versions (
  node_id TEXT NOT NULL, version INT NOT NULL, config_json TEXT NOT NULL, config_hash TEXT, actor TEXT, reason TEXT,
  source TEXT, created_at REAL, PRIMARY KEY (node_id, version));

CREATE TABLE IF NOT EXISTS alerts (
  alert_id INTEGER PRIMARY KEY, rule TEXT, subject TEXT, state TEXT, detail TEXT,
  opened_at REAL, resolved_at REAL, last_notified_at REAL,
  acked_by TEXT, acked_at REAL, resolved_how TEXT, useful INT, snoozed_until REAL, note TEXT);   -- useful: the owner's verdict
"""


class DBBusy(Exception):
    """The single writer lock was not obtained in time; HTTP layer maps this to 503 + Retry-After."""


LOCK_TIMEOUT = 10.0


class _TimedLock:
    """RLock whose `with` form gives up after LOCK_TIMEOUT instead of stalling every client."""

    def __init__(self):
        self._l = threading.RLock()
        self.acquisitions, self.waits_ms = 0, collections.deque(maxlen=1024)

    def acquire(self, timeout=LOCK_TIMEOUT):
        t0 = time.monotonic()
        if not self._l.acquire(timeout=timeout):
            raise DBBusy(f"db lock not acquired in {timeout}s")
        self.acquisitions += 1
        self.waits_ms.append((time.monotonic() - t0) * 1000)
        return True

    def stats(self) -> dict:
        w = sorted(self.waits_ms)
        p = lambda q: round(w[min(len(w) - 1, int(q * len(w)))], 2) if w else None
        return {"acquisitions": self.acquisitions, "wait_p50_ms": p(0.5), "wait_p99_ms": p(0.99), "wait_max_ms": p(1.0)}

    def release(self):
        self._l.release()

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *a):
        self.release()


# Columns added after a table first shipped: a home made by an earlier version gets them when it opens.
ADDED_COLUMNS = {"enrollments": {"join_code_id": "TEXT", "user_code": "TEXT", "requested_name": "TEXT"},
                 "nodes": {"tools_json": "TEXT", "want_detect": "INT DEFAULT 0"}}


def _ensure_columns(conn, table: str, cols: dict) -> None:
    have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    for name, decl in cols.items():
        if name not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


class DB:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = _TimedLock()
        self._local = threading.local()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            # NORMAL in WAL mode: durable across process crashes; a power loss can roll back only the last
            # commits, which the protocol absorbs (an unrecorded completion's attempt expires and re-runs).
            # FULL fsyncs every commit under the global lock and stalled all agents for seconds whenever the
            # disk was busy (bench/README.md, bottleneck 1). OARBANKD_SYNC=FULL restores it.
            self.conn.execute(f"PRAGMA synchronous={os.environ.get('OARBANKD_SYNC', 'NORMAL').upper()}")
            self.conn.execute("PRAGMA journal_size_limit=67108864")   # cap WAL at 64 MB after checkpoints
            self.conn.execute("PRAGMA busy_timeout=5000")
            self.conn.execute("PRAGMA foreign_keys=OFF")
            from .access import SCHEMA as ACCESS_SCHEMA
            from .coordbuilds import SCHEMA as COORD_BUILDS_SCHEMA
            from .joincodes import SCHEMA as JOIN_SCHEMA
            from .joincodes import migrate as join_migrate
            join_migrate(self.conn)
            # one transaction: a reader (the console) sees the whole schema or none of it
            self.conn.executescript("BEGIN;" + SCHEMA + ACCESS_SCHEMA + COORD_BUILDS_SCHEMA + JOIN_SCHEMA + "COMMIT;")
            for table, cols in ADDED_COLUMNS.items():
                _ensure_columns(self.conn, table, cols)
            # one-shot conversions at upgrade (docs/design/host-tools.md, "Migration")
            from .statements import migrate as statements_migrate
            from .tools import migrate_registry
            self.conn.execute("BEGIN")
            migrate_registry(self.conn)
            statements_migrate(self.conn)
            self.conn.execute("COMMIT")
        self.event_listeners = []   # callables(event_id) for SSE wakeups

    # -- low level ---------------------------------------------------------
    # Stored file paths are relative to the coordinator's home (the database's directory) whenever the file is inside
    # it, so the home can move to another machine or directory without rewriting rows; files outside it stay absolute.
    @property
    def root(self) -> Path:
        return getattr(self, "_root", None) or self.path.parent

    @root.setter
    def root(self, p):
        self._root = Path(p) if p else None

    def rel(self, p) -> str | None:
        """The stored form of a path: `/`-separated and relative to the home when inside it, else absolute."""
        if p is None:
            return None
        ap = Path(p).resolve()
        try:
            return ap.relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return str(ap)

    def abs(self, s) -> Path | None:
        """A stored path as a usable absolute path."""
        if s is None or s == "":
            return None
        p = Path(s)
        return p if p.is_absolute() else self.root / p

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        with self.lock:
            r = self.conn.execute(sql, args).fetchone()
            return dict(r) if r else None

    def x(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            return cur.lastrowid

    def tx(self):
        return _Tx(self)

    # -- maintenance -------------------------------------------------------
    def prune(self, events_days: float = 30, idempotency_days: float = 14) -> dict:
        """Retention: old events and idempotency keys (agents retry for minutes, not weeks)."""
        t = clock.now()
        with self.lock:
            e = self.conn.execute("DELETE FROM events WHERE ts < ?", (t - events_days * 86400,)).rowcount
            self.conn.execute("DELETE FROM protection_decisions WHERE t < ?", (t - events_days * 86400,))
            i = self.conn.execute("DELETE FROM idempotency WHERE at < ?", (t - idempotency_days * 86400,)).rowcount
        return {"events": e, "idempotency": i}

    def checkpoint(self) -> tuple:
        """TRUNCATE checkpoint; returns (busy, wal_frames, checkpointed). busy=1 means readers blocked it."""
        with self.lock:
            return tuple(self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())

    def backup(self, dest: Path):
        """Online, consistent copy (sqlite3 backup API) — safe while oarbankd is running."""
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".tmp")
        with self.lock:
            out = sqlite3.connect(str(tmp))
            try:
                self.conn.backup(out)
            finally:
                out.close()
        tmp.replace(dest)
        return dest

    # -- settings ----------------------------------------------------------
    def get_setting(self, key, default=None):
        r = self.one("SELECT value_json FROM settings WHERE key=?", (key,))
        return json.loads(r["value_json"]) if r else default

    def set_setting(self, key, value):
        self.x("INSERT INTO settings(key,value_json) VALUES(?,?) "
               "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json", (key, json.dumps(value)))

    # -- events ------------------------------------------------------------
    def event(self, kind, actor="system", node_id=None, campaign_id=None, job_id=None,
              attempt_id=None, reason=None, module=None, **payload):
        eid = self.x("INSERT INTO events(ts,kind,actor,node_id,campaign_id,job_id,attempt_id,reason,payload_json,module)"
                     " VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (clock.now(), kind, actor, node_id, campaign_id, job_id, attempt_id, reason,
                      json.dumps(payload) if payload else None, module))
        for cb in list(self.event_listeners):
            try:
                cb(eid)
            except Exception:
                pass
        return eid


class _Tx:
    """BEGIN IMMEDIATE ... COMMIT under the process lock. Nested use (an operation that audits in the same
    transaction as the core function it calls) becomes a SAVEPOINT, so an inner failure rolls back only
    the inner part and the outer transaction still decides."""

    def __init__(self, db):
        self.db = db
        self.sp = None

    def __enter__(self):
        self.db.lock.acquire()
        depth = getattr(self.db._local, "depth", 0)
        try:
            if depth:
                self.sp = f"sp{depth}"
                self.db.conn.execute(f"SAVEPOINT {self.sp}")
            else:
                self.db.conn.execute("BEGIN IMMEDIATE")      # raises when another process holds the write lock
        except BaseException:
            self.db.lock.release()                          # __exit__ never runs for a failed __enter__
            raise
        self.db._local.depth = depth + 1
        return self.db

    def __exit__(self, et, ev, _tb):
        try:
            self.db._local.depth -= 1
            if self.sp:
                if et is not None:
                    self.db.conn.execute(f"ROLLBACK TO {self.sp}")
                self.db.conn.execute(f"RELEASE {self.sp}")
            elif et is None:
                self.db.conn.execute("COMMIT")
            else:
                self.db.conn.execute("ROLLBACK")
        finally:
            self.db.lock.release()
        return False


def jl(s, default=None):
    """json.loads that tolerates NULL columns."""
    if s is None or s == "":
        return default
    return json.loads(s)
