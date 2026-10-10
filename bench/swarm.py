#!/usr/bin/env python3
"""Load / scalability harness for oarbankd: a swarm of simulated agents over the real mTLS agent API.

    .venv/bin/python bench/swarm.py run   --agents 200 --duration 60
    .venv/bin/python bench/swarm.py sweep --ns 10,50,200,500,1000 --duration 60   # writes bench/results.md and results/

What one run does (see bench/README.md for the metrics):
 1. starts a private, instrumented oarbankd (bench/coordinator_instrumented.py) with OARBANKD_HOME in a temp dir,
    bound to 127.0.0.1 on non-production ports (default 17443 agent / 17400 admin);
 2. seeds it through the admin API only: installs and enables the SDK's toy module from its bundle, the release composed from
    module files (offline, no downloads), and later `bench`-module campaigns (one job per seed);
 3. runs N fake agents (asyncio, spread over worker processes) that enroll with a CSR (admin approves) and from
    then on present their client certificate, hello,
    heartbeat every H s, pass doctor + the bench golden job to certify, claim, "run" jobs for a sampled
    time while reporting cpu_s progress, then complete with a valid bench result through an outbox
    with idempotency keys (retries on 5xx/timeouts, plus deliberate lost-ack replays). A few attempts
    are failed (each job at most once) or released (non-failure reasons);
 4. keeps a queue of pending jobs topped up for the steady window, then drains it to zero;
 5. measures per-endpoint rate/latency/errors, completions/s, lease expiries (false = expired while
    the agent was still heartbeating it), heartbeat gaps, DB lock wait/hold, server loop lag;
 6. stops oarbankd and checks invariants: oarbank.coordinator.invariants.check_all (if present) plus
    harness checks (every job done exactly once canonically, client ack history agrees with the DB).
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import hashlib
import json
import math
import multiprocessing as mp
import os
import platform
import random
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[1]
BENCH = REPO / "bench"
TOY = REPO / "vendor" / "oarbank-sdk" / "examples" / "toy"

PROD_PORTS = {7400, 7401, 7443}
DOCTOR_OK = {"modules": {"toy": {"health": "healthy", "checks": [{"name": "python", "ok": True}]}}}
NON_FAILURE = ("preempt_memory", "preempt_protection", "limit_cpu", "transient")
RUN, FLUSH, EXIT = 0, 1, 2
LEASE_TTL = 60.0


@dataclasses.dataclass
class Cfg:
    agents: int = 50
    slots: int = 2                    # concurrent jobs per agent (cpu 1 each; bench jobs need 1 cpu, 0.2 GB)
    heartbeat_s: float = 1.0
    duration_s: float = 60.0          # steady window (after warmup) with the queue kept topped up
    warmup_s: float = 5.0
    job_min_s: float = 2.0
    job_max_s: float = 6.0
    queue_depth: int = 0              # pending jobs kept in the queue; 0 = auto (3 x agents x slots, >= 200)
    study_size: int = 500             # jobs per seeded study
    total_jobs: int = 0               # >0: seed exactly this many jobs, no refill, run until all are done
    fail_rate: float = 0.01           # fraction of jobs whose first run fails (exit_nonzero); never twice
    release_rate: float = 0.02        # fraction of attempts released mid-run with a non-failure reason
    dup_rate: float = 0.02            # fraction of completions replayed as if the ack was lost
    abandon_rate: float = 0.0         # fraction of attempts silently dropped (true lease expiry, 60 s)
    procs: int = 0                    # agent worker processes; 0 = auto, -1 = in-process thread
    agent_port: int = 17443
    admin_port: int = 17400
    seed: int = 1
    max_drain_s: float = 240.0
    fleet_poll_s: float = 0.0           # >0: also poll GET /api/v1/fleet like an open dashboard
    console_viewers: int = 0          # >0: run oarbank-console and this many hostile viewers (SSE + a page GET every
                                      #     second each) plus a /metrics scraper: the console load gate
    console_port: int = 17410
    sqlite_sync: str = ""             # experiment knob: force PRAGMA synchronous (e.g. NORMAL) in the bench oarbankd
    home: str | None = None           # OARBANKD_HOME (default: fresh temp dir, removed afterwards)
    keep_home: bool = False
    label: str = ""

    def depth(self) -> int:
        return self.queue_depth or max(200, 3 * self.agents * self.slots)


# ============================================================================ oarbankd process
def loadavg() -> list | None:
    """The 1, 5 and 15 minute load averages; None on Windows, which keeps none."""
    return [round(x, 1) for x in os.getloadavg()] if hasattr(os, "getloadavg") else None


def load1(r: dict) -> str:
    return str(r["loadavg_start"][0]) if r.get("loadavg_start") else "n/a"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Coordinator:
    """A private oarbankd in a scratch OARBANKD_HOME. Refuses production ports and the real coordinator home."""

    def __init__(self, home: Path, agent_port: int, admin_port: int, sqlite_sync: str = ""):
        self.sqlite_sync = sqlite_sync
        home = Path(home).resolve()
        from oarbank import paths
        if home == paths.coordinator_home().resolve() or {agent_port, admin_port} & PROD_PORTS:
            raise SystemExit("refusing to touch the production oarbankd (ports 7400/7443, the real coordinator home)")
        self.home, self.agent_port, self.admin_port = home, agent_port, admin_port
        self.agent_url = f"https://127.0.0.1:{agent_port}"
        self.admin_url = f"http://127.0.0.1:{admin_port}"
        self.proc = None

    @property
    def db_path(self) -> Path:
        return self.home / "oarbank.sqlite3"

    def start(self, timeout=30.0):
        self.home.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, OARBANKD_HOME=str(self.home), OARBANKD_TAILSCALE="/usr/bin/false",
                   OARBANKD_TAILSCALE_SOCKET="", PYTHONUNBUFFERED="1")
        if self.sqlite_sync:
            env["BENCH_SQLITE_SYNC"] = self.sqlite_sync
        env["PYTHONPATH"] = os.pathsep.join([str(REPO / "src")] + [p for p in [env.get("PYTHONPATH")] if p])
        self.log = open(self.home / "oarbankd.out", "ab")
        self.proc = subprocess.Popen(
            [sys.executable, str(BENCH / "coordinator_instrumented.py"), "--agent-bind", "127.0.0.1",
             "--agent-port", str(self.agent_port), "--admin-bind", "127.0.0.1", "--admin-port", str(self.admin_port)],
            env=env, stdout=self.log, stderr=subprocess.STDOUT, cwd=str(self.home))
        t_end = time.time() + timeout
        while time.time() < t_end:
            if self.proc.poll() is not None:
                raise RuntimeError(f"oarbankd exited early; see {self.home / 'oarbankd.out'}")
            try:
                if ca_file(self.home).exists() and \
                        httpx.get(self.agent_url + "/healthz", timeout=1, verify=tls(self.home)).status_code == 200 and \
                        httpx.get(self.admin_url + "/api/v1/modules", timeout=1, headers=admin_auth(self.home)).status_code == 200:
                    return self
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        self.stop()
        raise RuntimeError("oarbankd did not come up")

    def stats(self, reset=False) -> dict:
        return httpx.get(self.agent_url + "/_bench/stats", params={"reset": int(reset)}, timeout=30, verify=tls(self.home)).json()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
            if os.name == "nt" and self.db_path.exists():
                self._locks_released()
        if getattr(self, "log", None):
            self.log.close()

    def _locks_released(self, within=10.0):
        """Windows terminates a process outright and releases its file locks a little later ("the time it takes depends
        upon available system resources", LockFileEx); until then opening the database reports a disk I/O error. The
        probe does what opening it as the coordinator's DB does, setting the journal mode and taking the write lock: a
        plain read can pass while a lock the terminated oarbankd or console held still refuses those."""
        end = time.monotonic() + within
        while True:
            c = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
            try:
                c.execute("PRAGMA journal_mode=WAL")
                c.execute("BEGIN IMMEDIATE")
                c.execute("ROLLBACK")
                return
            except sqlite3.OperationalError:
                if time.monotonic() > end:
                    raise
                time.sleep(0.2)
            finally:
                c.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()


def ca_file(home) -> Path:
    return Path(home) / "tls" / "ca.pem"


def tls(home, cert: Path | None = None, key: Path | None = None) -> ssl.SSLContext:
    """Trust the scratch coordinator's CA, read from its home (a real agent pins it from the CIK-signed identity),
    optionally presenting an agent's client certificate."""
    ctx = ssl.create_default_context(cafile=str(ca_file(home)))
    if cert:
        ctx.load_cert_chain(str(cert), str(key))
    return ctx


def node_csr(idx: int, out: Path) -> str:
    """A P-256 key for agent `idx` (written beside its certificate) and the CSR it enrolls with."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{idx}.key").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"sim-{idx}")])).sign(k, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


# ============================================================================ admin seeding
def admin_auth(home) -> dict:
    """The swarm's oarbankd writes its owner admin token into its scratch home; admin calls send it."""
    p = Path(home) / "admin.token"
    return {"authorization": f"Bearer {p.read_text(encoding="utf-8").strip()}"} if p.exists() else {}



def admin_setup(admin: httpx.Client) -> str:
    """A toy-only fleet, set up the way an operator does it: upload the bundle, review and apply the
    install (T2), enable (T1). Enabling composes the release. Returns the current release id."""
    import tempfile
    import uuid
    from oarbank_sdk import bundle as B
    out, _ = B.build(TOY, Path(tempfile.mkdtemp()) / "toy.mfb")
    sha = admin.post("/api/v1/modules/bundles", content=out.read_bytes(), timeout=60).json()["sha256"]
    plan = admin.post("/api/v1/ops/modules.install", json={"params": {"sha256": sha}, "dry_run": True}, timeout=60).json()["plan"]
    admin.post("/api/v1/ops/modules.install", json={"plan_id": plan["plan_id"], "reason": "swarm setup"},
             headers={"idempotency-key": str(uuid.uuid4())}, timeout=120).raise_for_status()
    r = admin.post("/api/v1/ops/modules.enable", json={"target": "toy@0.1.0", "reason": "swarm setup"}, timeout=120)
    r.raise_for_status()
    return r.json()["result"]["releases"]["default"]


def add_study(admin: httpx.Client, tag: str, start: int, n: int) -> tuple[str, float]:
    """One toy campaign = n jobs, each with a unique n (unique job_key): the toy module's `queue_sums` operation."""
    import uuid
    base = int(hashlib.sha256(tag.encode()).hexdigest()[:4], 16) * 10_000       # toy accepts n <= 1e9
    body = {"params": {"name": f"swarm {tag} {start}", "ns": [base + i for i in range(start, start + n)],
                       "campaign_id": f"c_swarm_{hashlib.sha256(f'{tag}{start}'.encode()).hexdigest()[:10]}"}}
    t0 = time.perf_counter()
    r = admin.post("/api/v1/ops/mod.toy.queue_sums", json=body, headers={"idempotency-key": str(uuid.uuid4())}, timeout=600)
    r.raise_for_status()
    return r.json()["result"]["result"]["campaign_id"], time.perf_counter() - t0


def ro(db_path: Path) -> sqlite3.Connection:
    c = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def job_counts(db_path: Path) -> dict:
    c = ro(db_path)
    try:
        return {r["state"]: r["n"] for r in c.execute("SELECT state, COUNT(*) n FROM jobs GROUP BY state")}
    finally:
        c.close()


# ============================================================================ simulated agent
class Shared:
    """Phase + ready counter, backed by multiprocessing.Value (processes) or plain lists (thread)."""

    def __init__(self, ctx=None):
        self.mp = ctx is not None
        if self.mp:
            self._pv, self._rv = ctx.Value("i", RUN), ctx.Value("i", 0)
        else:
            self._lock, self._p, self._r = threading.Lock(), [RUN], [0]

    def phase(self) -> int:
        return self._pv.value if self.mp else self._p[0]

    def ready(self) -> int:
        return self._rv.value if self.mp else self._r[0]

    def set_phase(self, p):
        if self.mp:
            self._pv.value = p
        else:
            self._p[0] = p

    def inc_ready(self):
        if self.mp:
            with self._rv.get_lock():
                self._rv.value += 1
        else:
            with self._lock:
                self._r[0] += 1


class Worker:
    """One asyncio loop running a slice of the agents; records every request."""

    def __init__(self, cfg: Cfg, wid: int, nworkers: int, indices: list[int], shared: Shared, agent_url, admin_url):
        self.cfg, self.wid, self.nworkers, self.indices, self.shared = cfg, wid, nworkers, indices, shared
        self.agent_url, self.admin_url = agent_url, admin_url
        self.samples = []            # (endpoint, t_start, latency_s, status, error)
        self.canonical = []          # (job_id, attempt_id, t_ack)
        self.attempts = {}           # attempt_id -> [job_id, node_id, granted_t, stopped_reporting_t, outcome]
        self.violations = []
        self.failed_jobs = set()
        self.hb_gaps = []            # (t, gap_s) between consecutive successful heartbeats of one agent
        self.loop_lag = []
        self.counters = {"retries": 0, "replays": 0, "lease_lost": 0, "revoked": 0, "fails": 0, "releases": 0,
                         "abandoned": 0, "recertified": 0, "attempt_closed": 0}

    def should_fail(self, job_id: int) -> bool:
        """Each job fails at most once: only the worker owning job_id % nworkers may fail it."""
        if job_id % self.nworkers != self.wid or job_id in self.failed_jobs:
            return False
        h = ((job_id * 2654435761) % 2 ** 32) / 2 ** 32
        if h < min(1.0, self.cfg.fail_rate * self.nworkers):
            self.failed_jobs.add(job_id)
            return True
        return False

    async def req(self, ep, method, url, client=None, **kw):
        t0 = time.time()
        p0 = time.perf_counter()
        try:
            r = await (client or self.client).request(method, url, **kw)
            dt = time.perf_counter() - p0
            err = None
            if r.status_code >= 400:
                try:
                    err = r.json().get("error")
                except Exception:
                    err = "http"
            self.samples.append((ep, t0, dt, r.status_code, err))
            return r
        except (httpx.HTTPError, OSError) as e:
            self.samples.append((ep, t0, time.perf_counter() - p0, 0, type(e).__name__))
            return None

    async def _lag(self):
        while True:
            t = time.perf_counter()
            await asyncio.sleep(0.1)
            self.loop_lag.append(time.perf_counter() - t - 0.1)

    async def run(self):
        n = max(1, len(self.indices))
        lim = httpx.Limits(max_connections=3 * n + 10, max_keepalive_connections=3 * n + 10)
        # the enrollment client presents no certificate; each agent gets its own client once enrolled
        async with httpx.AsyncClient(base_url=self.agent_url, timeout=30.0, limits=lim, verify=tls(self.cfg.home)) as self.client, \
                httpx.AsyncClient(base_url=self.admin_url, timeout=60.0, headers=admin_auth(self.cfg.home)) as self.admin:
            lag = asyncio.create_task(self._lag())
            rel = sqlite3.connect(f"file:{self.cfg.home}/oarbank.sqlite3?mode=ro", uri=True)
            self.release_id = rel.execute("SELECT release_id FROM releases WHERE status='current'").fetchone()[0]
            rel.close()
            sem = asyncio.Semaphore(32)
            agents = [SimAgent(self, i, sem) for i in self.indices]
            await asyncio.gather(*(a.main() for a in agents))
            lag.cancel()

    def dump(self) -> dict:
        return {"samples": self.samples, "canonical": self.canonical, "attempts": self.attempts,
                "violations": self.violations, "hb_gaps": self.hb_gaps, "loop_lag": self.loop_lag,
                "counters": self.counters}


class Att:
    __slots__ = ("aid", "job_id", "kind", "spec", "t0", "task", "done")

    def __init__(self, g):
        self.aid, self.job_id, self.kind, self.spec = g["attempt_id"], g["job_id"], g["kind"], g["spec"]
        self.t0, self.task, self.done = time.time(), None, False


class SimAgent:
    def __init__(self, w: Worker, idx: int, sem: asyncio.Semaphore):
        self.w, self.cfg, self.idx, self.sem = w, w.cfg, idx, sem
        self.rng = random.Random(w.cfg.seed * 1_000_003 + idx)
        ram = (24.0, 36.0, 64.0, 128.0)[idx % 4]
        enforced = {c: "enforced" for c in ("filesystem", "ipc", "net.none", "net.egress-allowlist", "net.egress-any",
                                            "no_loopback", "gpu.compute")}
        self.facts = {"facts": 2, "hostname": f"sim-{idx:04d}",
                      "platform": {"os": "darwin", "arch": "arm64", "os_version": "27.0", "os_build": "26A123"},
                      "cpu": {"model": "Apple M5 Pro", "perf_cores": 5, "eff_cores": 10, "logical": 15}, "memory_gb": ram,
                      "disk_free_gb": 400.0, "sandbox": {"backend": "seatbelt", "enforcement": enforced}}
        self.client = self.node_id = None
        self.running: dict[int, Att] = {}
        self.outbox: asyncio.Queue = asyncio.Queue()
        self.pending_doctor = DOCTOR_OK
        self.need_hello, self.certified = True, False
        self.next_hb = self.next_claim = 0.0
        self.last_hb_ok = None
        self.seq = 0
        self.wake = asyncio.Event()
        self.boot_id = f"boot-{idx}-{w.cfg.seed}"

    def free(self) -> int:
        return self.cfg.slots - len(self.running)

    # ---------------------------------------------------------------- enrollment
    async def enroll(self):
        w = self.w
        async with self.sem:
            for k in range(50):
                certs = Path(self.cfg.home) / "swarm-out" / "certs"
                r = await w.req("enroll", "POST", "/v1/agent/enroll", json={"hostname": self.facts["hostname"],
                                                                            "facts": self.facts, "csr": node_csr(self.idx, certs)})
                if r is None or r.status_code != 200:
                    await asyncio.sleep(0.2 * (k + 1))
                    continue
                eid = r.json()["enrollment_id"]
                a = await w.req("admin_preview", "POST", "/api/v1/ops/nodes.admit", client=w.admin,
                                json={"target": eid, "dry_run": True})
                if a is not None and a.status_code == 200:
                    a = await w.req("admin_approve", "POST", "/api/v1/ops/nodes.admit", client=w.admin,
                                    json={"plan_id": a.json()["plan"]["plan_id"], "reason": "swarm"})
                if a is None or a.status_code != 200:
                    await asyncio.sleep(0.2 * (k + 1))
                    continue
                for j in range(50):
                    s = await w.req("enroll_status", "GET", f"/v1/agent/enroll/{eid}")
                    if s is not None and s.status_code == 200 and s.json().get("status") == "approved":
                        d = s.json()
                        self.node_id = d["node_id"]
                        (certs / f"{self.idx}.pem").write_text(d["cert_pem"])
                        self.client = httpx.AsyncClient(
                            base_url=w.agent_url, timeout=30.0, limits=httpx.Limits(max_connections=4),
                            verify=tls(self.cfg.home, certs / f"{self.idx}.pem", certs / f"{self.idx}.key"))
                        return
                    await asyncio.sleep(0.2)
            raise RuntimeError(f"agent {self.idx} could not enroll")

    # ---------------------------------------------------------------- main loop
    async def main(self):
        await self.enroll()
        sender = asyncio.create_task(self.outbox_loop())
        while True:
            ph = self.w.shared.phase()
            if ph >= EXIT or (ph == FLUSH and not self.running and self.outbox.empty() and not self.sending):
                break
            if self.need_hello:
                await self.hello()
                if self.need_hello:
                    await asyncio.sleep(self.cfg.heartbeat_s)
                continue
            now = time.time()
            if now >= self.next_hb:
                await self.heartbeat()
            if ph == RUN and self.free() > 0 and time.time() >= self.next_claim:
                await self.claim()
            now = time.time()
            nxt = self.next_hb
            if ph == RUN and self.free() > 0:
                nxt = min(nxt, self.next_claim)
            try:
                await asyncio.wait_for(self.wake.wait(), max(0.02, nxt - now))
            except asyncio.TimeoutError:
                pass
            self.wake.clear()
        self.outbox.put_nowait(None)
        await sender
        for a in list(self.running.values()):
            if a.task:
                a.task.cancel()
        await self.client.aclose()

    sending = False

    async def hello(self):
        body = {"agent_version": "0.1.0-sim", "boot_id": self.boot_id, "facts": self.facts,
                "live_attempts": sorted(self.running), "release_id": self.w.release_id, "ready_datasets": []}
        r = await self.w.req("hello", "POST", "/v1/agent/hello", json=body, client=self.client)
        if r is None or r.status_code != 200:
            return
        d = r.json()
        for aid in d.get("kill") or []:
            self.drop(aid, "killed")
        self.need_hello = False
        self.next_hb = time.time()

    def telemetry(self):
        return {"mem_used_gb": 10.0, "mem_pressure": 0, "thermal": 0,
                "on_battery": False, "hid_idle_s": 900.0, "screen_sharing": False,
                "fleet_rss_gb": 0.2 * len(self.running), "disk_free_gb": 390.0}

    async def heartbeat(self):
        self.seq += 1
        t = time.time()
        atts = [{"attempt_id": a.aid, "phase": "staging" if t - a.t0 < 0.3 else "run",
                 "cpu_s": round((t - a.t0) * 0.95, 3), "log_bytes": int((t - a.t0) * 120), "rss_gb": 0.2}
                for a in self.running.values() if not a.done]
        sent_doctor = self.pending_doctor
        body = {"seq": self.seq, "telemetry": self.telemetry(),
                "capacity": {"cpu_slots": self.cfg.slots, "mem_gb_free": 16.0, "pools": {}, "auto_cpu_slots": self.cfg.slots,
                             "binding_limit": "auto", "admit": True},
                "attempts": atts, "ready_datasets": [], "doctor": sent_doctor}
        self.next_hb = t + self.cfg.heartbeat_s
        r = await self.w.req("heartbeat", "POST", "/v1/agent/heartbeat", json=body, client=self.client)
        if r is None or r.status_code != 200:
            if r is not None and r.status_code == 401:
                self.need_hello = True
            return
        now = time.time()
        if self.last_hb_ok is not None:
            self.w.hb_gaps.append((now, now - self.last_hb_ok))
        self.last_hb_ok = now
        if sent_doctor is not None and self.pending_doctor is sent_doctor:
            self.pending_doctor = None
        d = r.json()
        for aid in d.get("revoke") or []:
            self.drop(aid, "revoked")
        for aid in d.get("cancel") or []:
            a = self.running.get(aid)
            if a:
                self.finish(a, "release", reason="user_cancel")
        if d.get("run_doctor") and self.pending_doctor is None:
            self.pending_doctor = DOCTOR_OK
            self.next_hb = time.time()
            self.w.counters["recertified"] += self.certified
            self.certified = False
        if d.get("recertify"):
            self.need_hello = True

    async def claim(self):
        free = self.free()
        body = {"free_cpu": free, "free_mem_gb": 16.0, "modules": ["toy"], "free_slots": free,
                "release_id": self.w.release_id, "cert_generation": None, "ready_datasets": []}
        r = await self.w.req("claim", "POST", "/v1/agent/claim", json=body, client=self.client)
        if r is None or r.status_code != 200:
            self.next_claim = time.time() + self.cfg.heartbeat_s
            return
        grants = r.json().get("grants") or []
        self.next_claim = time.time() + (1.0 if grants else self.cfg.heartbeat_s)
        for g in grants:
            a = Att(g)
            self.running[a.aid] = a
            self.w.attempts[a.aid] = [a.job_id, self.node_id, a.t0, None, "running"]
            a.task = asyncio.create_task(self.run_attempt(a))

    # ---------------------------------------------------------------- attempts
    def drop(self, aid, why):
        a = self.running.pop(aid, None)
        if a is None:
            return
        if a.task:
            a.task.cancel()
        self.w.counters["revoked"] += 1
        rec = self.w.attempts.get(aid)
        if rec:
            rec[3], rec[4] = time.time(), why
        self.wake.set()

    def finish(self, a: Att, outcome: str, reason=None):
        """The job process ended: stop reporting it in heartbeats and hand the report to the outbox."""
        a.done = True
        self.running.pop(a.aid, None)
        rec = self.w.attempts.get(a.aid)
        if rec:
            rec[3], rec[4] = time.time(), outcome
        if outcome == "complete":
            n = int(a.spec["payload"]["n"])
            res = {"envelope": 1, "schema": "toy/result@1", "module_version": "0.1.0", "protocol": 1,
                   "effective": {"n": n}, "payload": {"sum": str(n * (n - 1) // 2)}}
            self.outbox.put_nowait(("complete", a, {"idempotency_key": f"att-{a.aid}-complete", "result": res}))
        elif outcome == "fail":
            self.w.counters["fails"] += 1
            self.outbox.put_nowait(("fail", a, {"reason": "exit_nonzero", "exit_code": 1, "stderr_tail": "sim"}))
        elif outcome == "release":
            self.w.counters["releases"] += 1
            self.outbox.put_nowait(("release", a, {"reason": reason or self.rng.choice(NON_FAILURE)}))
        elif outcome == "abandon":
            self.w.counters["abandoned"] += 1
        self.wake.set()

    async def run_attempt(self, a: Att):
        cfg, rng = self.cfg, self.rng
        outcome, dur = "complete", 0.2
        if a.kind != "golden":
            dur = rng.uniform(cfg.job_min_s, cfg.job_max_s)
            r = rng.random()
            if self.w.should_fail(a.job_id):
                outcome, dur = "fail", dur * rng.uniform(0.2, 1.0)
            elif r < cfg.release_rate:
                outcome, dur = "release", dur * rng.uniform(0.1, 0.9)
            elif r < cfg.release_rate + cfg.abandon_rate:
                outcome = "abandon"
        try:
            await asyncio.sleep(dur)
        except asyncio.CancelledError:
            return
        if a.aid in self.running:
            self.finish(a, outcome)

    # ---------------------------------------------------------------- outbox
    async def outbox_loop(self):
        while True:
            item = await self.outbox.get()
            if item is None:
                return
            self.sending = True
            try:
                await self.deliver(*item)
            finally:
                self.sending = False
                self.wake.set()

    async def deliver(self, kind, a: Att, body):
        w, url = self.w, f"/v1/attempts/{a.aid}/{kind}"
        k = 0
        while True:
            r = await w.req(kind if k == 0 else kind + "_retry", "POST", url, json=body, client=self.client)
            if r is not None and r.status_code < 500:
                break
            if w.shared.phase() >= EXIT:
                return
            k += 1
            w.counters["retries"] += 1
            await asyncio.sleep(min(5.0, 0.25 * 2 ** k) * (0.5 + self.rng.random()))
        if r.status_code == 404:
            w.counters["lease_lost"] += 1
            return
        if r.status_code >= 400 or kind != "complete":
            return
        resp = r.json()
        if resp.get("reason") == "attempt_closed":
            w.counters["attempt_closed"] += 1
        if resp.get("canonical"):
            w.canonical.append((a.job_id, a.aid, time.time()))
            if a.kind == "golden" and not self.certified:
                self.certified = True
                if not getattr(self, "_counted_ready", False):
                    self._counted_ready = True
                    w.shared.inc_ready()
        if self.rng.random() < self.cfg.dup_rate:        # the ack was "lost": the outbox replays the same report
            w.counters["replays"] += 1
            r2 = await w.req("complete_replay", "POST", url, json=body, client=self.client)
            if r2 is not None and r2.status_code == 200:
                r2j = r2.json()
                if {k: r2j.get(k) for k in ("accepted", "canonical", "reason")} != \
                        {k: resp.get(k) for k in ("accepted", "canonical", "reason")}:
                    w.violations.append(f"idempotent replay of attempt {a.aid} got {r2j}, first {resp}")


def _worker_entry(cfg_d, wid, nworkers, indices, shared, agent_url, admin_url, out_path):
    cfg = Cfg(**cfg_d)
    w = Worker(cfg, wid, nworkers, indices, shared, agent_url, admin_url)
    try:
        asyncio.run(w.run())
    except Exception as e:  # report instead of dying silently
        w.violations.append(f"worker {wid} crashed: {e!r}")
    Path(out_path).write_text(json.dumps(w.dump()))


# ============================================================================ metrics
def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, max(0, math.ceil(p * len(xs)) - 1))]


def endpoint_table(samples, t_lo, t_hi):
    win = max(1e-9, t_hi - t_lo)
    by = {}
    for ep, t0, dt, st, err in samples:
        if t_lo <= t0 <= t_hi:
            by.setdefault(ep, []).append((dt, st, err))
    out = {}
    for ep, rows in sorted(by.items()):
        lat = [r[0] for r in rows]
        n = len(rows)
        out[ep] = {"n": n, "rps": round(n / win, 2), "p50_ms": round(pct(lat, .5) * 1e3, 2),
                   "p95_ms": round(pct(lat, .95) * 1e3, 2), "p99_ms": round(pct(lat, .99) * 1e3, 2),
                   "max_ms": round(max(lat) * 1e3, 2),
                   "err": sum(1 for r in rows if r[1] == 0 or (r[1] >= 400 and r[1] != 404)),
                   "http503": sum(1 for r in rows if r[1] == 503), "conn_err": sum(1 for r in rows if r[1] == 0),
                   "http404": sum(1 for r in rows if r[1] == 404)}
    return out


def harness_invariants(db_path: Path, canonical_acks, attempts, expected_jobs: int | None) -> tuple[list, dict]:
    """Exactly-once checks from the DB and from the clients' ack history, plus check_all if available. A read-only
    connection beside a writing coordinator can see a transient error (Windows: "disk I/O error" while the WAL index is
    remapped); the checks are read-only, so they are retried briefly."""
    for attempt in range(10):
        try:
            return _harness_invariants(db_path, canonical_acks, attempts, expected_jobs)
        except sqlite3.OperationalError:
            if attempt == 9:
                raise
            time.sleep(0.5)


def _harness_invariants(db_path: Path, canonical_acks, attempts, expected_jobs: int | None) -> tuple[list, dict]:
    v, info = [], {}
    c = ro(db_path)
    try:
        states = {r["state"]: r["n"] for r in c.execute("SELECT state, COUNT(*) n FROM jobs GROUP BY state")}
        info["jobs"] = states
        for r in c.execute("SELECT job_id, state, kind FROM jobs WHERE state!='done' LIMIT 20"):
            v.append(f"H1 job {r['job_id']} ({r['kind']}) ended in state {r['state']}, not done")
        for r in c.execute("SELECT job_id, COUNT(*) n FROM results WHERE canonical=1 GROUP BY job_id HAVING n!=1 LIMIT 20"):
            v.append(f"H2 job {r['job_id']} has {r['n']} canonical results")
        for r in c.execute("SELECT j.job_id FROM jobs j WHERE j.state='done' AND NOT EXISTS (SELECT 1 FROM results r "
                           "WHERE r.job_id=j.job_id AND r.canonical=1 AND r.result_id=j.canonical_result_id) LIMIT 20"):
            v.append(f"H3 done job {r['job_id']} does not point at its canonical result")
        for r in c.execute("SELECT job_key, COUNT(*) n FROM results WHERE canonical=1 GROUP BY job_key HAVING n>1 LIMIT 20"):
            v.append(f"H4 job_key {r['job_key'][:12]} has {r['n']} canonical results (duplicate work)")
        n_live = c.execute("SELECT COUNT(*) FROM attempts WHERE state='live'").fetchone()[0]
        if n_live:
            v.append(f"H5 {n_live} attempts still live after drain")
        for r in c.execute("SELECT node_id, quarantine_reason FROM nodes WHERE lifecycle='quarantined'"):
            v.append(f"H6 node {r['node_id']} quarantined: {r['quarantine_reason']}")
        if expected_jobs is not None:
            n_eval = c.execute("SELECT COUNT(*) FROM jobs WHERE kind='eval'").fetchone()[0]
            if n_eval != expected_jobs:
                v.append(f"H7 {n_eval} eval jobs in DB, harness seeded {expected_jobs}")
        canon = {r["job_id"]: r["attempt_id"] for r in
                 c.execute("SELECT job_id, attempt_id FROM results WHERE canonical=1")}
        info["expired"] = [dict(r) for r in c.execute(
            "SELECT attempt_id, job_id, node_id, granted_at, ended_at FROM attempts WHERE end_reason='lease_expired'")]
        info["eval_done"] = c.execute("SELECT COUNT(*) FROM jobs WHERE kind='eval' AND state='done'").fetchone()[0]
        info["db_rows"] = {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                           for t in ("jobs", "attempts", "results", "events", "idempotency", "node_samples")}
    finally:
        c.close()
    acked = {}
    for job_id, aid, _t in canonical_acks:
        if job_id in acked and acked[job_id] != aid:
            v.append(f"H8 job {job_id} acknowledged canonical to two attempts ({acked[job_id]}, {aid})")
        acked[job_id] = aid
    for job_id, aid in acked.items():
        if canon.get(job_id) != aid:
            v.append(f"H9 client got canonical for job {job_id} attempt {aid}, DB says {canon.get(job_id)}")
    missing = set(canon) - set(acked)
    if missing:
        v.append(f"H10 {len(missing)} canonical results never acknowledged to any agent, e.g. {sorted(missing)[:5]}")
    try:
        from oarbank.coordinator import invariants
        from oarbank.coordinator.db import DB
        viol = invariants.check_all(DB(db_path))
        info["check_all"] = f"oarbank.coordinator.invariants.check_all: {len(viol)} violations"
        v.extend(viol if isinstance(viol, list) else [str(viol)])
    except ImportError:
        info["check_all"] = "oarbank.coordinator.invariants not available; harness SQL checks only"
    return v[:200], info


def classify_expiries(expired, attempts):
    """false = the agent was still running (and heartbeating) the attempt when the lease expired."""
    out = {"total": len(expired), "false": 0, "after_finish": 0, "abandoned": 0, "other": 0}
    for e in expired:
        rec = attempts.get(str(e["attempt_id"])) or attempts.get(e["attempt_id"])
        if not rec:
            out["other"] += 1
            continue
        _job, _node, t_grant, t_stop, outcome = rec
        if outcome == "abandon":
            out["abandoned"] += 1
        elif t_stop is None or e["ended_at"] <= t_stop:
            out["false"] += 1
        else:
            out["after_finish"] += 1     # finished, report still in the outbox when the lease ran out
    return out


# ============================================================================ orchestration
def start_iostat():
    """Background disk activity on the machine during the window (it may run other work too)."""
    try:
        return subprocess.Popen(["iostat", "-d", "-w", "1", "disk0"], stdout=subprocess.PIPE, text=True)
    except OSError:
        return None


def stop_iostat(p) -> dict:
    if p is None:
        return {}
    p.terminate()
    try:
        out = p.communicate(timeout=5)[0]
    except subprocess.TimeoutExpired:
        p.kill()
        return {}
    rows = []
    for line in out.splitlines()[3:]:          # 2 header lines + the since-boot average
        parts = line.split()
        if len(parts) == 3:
            try:
                rows.append((float(parts[1]), float(parts[2])))
            except ValueError:
                pass
    if not rows:
        return {}
    return {"disk0_tps_mean": round(sum(r[0] for r in rows) / len(rows)), "disk0_mb_s_mean": round(sum(r[1] for r in rows) / len(rows), 1),
            "disk0_mb_s_max": max(r[1] for r in rows)}


def start_console(fd, port: int, timeout: float = 30.0):
    """oarbank-console as its own process against the private oarbankd (the production layout)."""
    if port in PROD_PORTS:
        raise SystemExit("refusing a production console port")
    env = dict(os.environ, OARBANKD_HOME=str(fd.home), PYTHONUNBUFFERED="1")
    env["PYTHONPATH"] = os.pathsep.join([str(REPO / "src")] + [p for p in [env.get("PYTHONPATH")] if p])
    proc = subprocess.Popen([sys.executable, "-m", "oarbank.console", "--bind", "127.0.0.1", "--port", str(port),
                             "--db", str(fd.db_path), "--oarbankd", fd.admin_url, "--secret-file", str(fd.home / "console.secret"),
                             "--frames-port", str(port + 1)],
                            env=env, stdout=open(fd.home / "console.out", "ab"), stderr=subprocess.STDOUT)
    t_end = time.time() + timeout
    while time.time() < t_end:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=1).status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.2)
    proc.kill()
    raise RuntimeError("oarbank-console did not come up")


def console_viewer(port: int, stop: threading.Event, samples: list):
    """A hostile viewer: one SSE stream held open plus a full page GET every second."""
    base = f"http://127.0.0.1:{port}"

    def stream():
        while not stop.is_set():
            try:
                with httpx.stream("GET", base + "/sse", timeout=httpx.Timeout(30, read=30)) as r:
                    for _ in r.iter_lines():
                        if stop.is_set():
                            return
            except httpx.HTTPError:
                time.sleep(0.5)
    threading.Thread(target=stream, daemon=True).start()
    c = httpx.Client(base_url=base, timeout=60)
    while not stop.is_set():
        for path in ("/", "/frag/fleet"):
            t0, p0 = time.time(), time.perf_counter()
            try:
                st = c.get(path).status_code
            except httpx.HTTPError:
                st = 0
            samples.append(("console_page", t0, time.perf_counter() - p0, st, None))
        stop.wait(1.0)


def run(cfg: Cfg, log=print) -> dict:
    tmp = None
    if not cfg.home:
        tmp = tempfile.mkdtemp(prefix="oarbankd-swarm-")
        cfg.home = tmp
    home = Path(cfg.home)
    fd = Coordinator(home, cfg.agent_port, cfg.admin_port, cfg.sqlite_sync)
    nprocs = cfg.procs if cfg.procs else min(8, max(1, math.ceil(cfg.agents / 60)))   # >~100 agents/proc starves the client loop
    inproc = nprocs < 0
    nworkers = 1 if inproc else nprocs
    out_dir = home / "swarm-out"
    out_dir.mkdir(parents=True, exist_ok=True)
    res = {"cfg": dataclasses.asdict(cfg), "workers": nworkers, "inproc": inproc,
           "loadavg_start": loadavg()}
    tag = f"r{cfg.seed}n{cfg.agents}"
    seeded = 0
    admin_calls = []
    poll_samples = []
    stop_polls = threading.Event()
    console = None
    try:
        fd.start()
        admin = httpx.Client(base_url=fd.admin_url, timeout=120, headers=admin_auth(home))
        res["release_id"] = admin_setup(admin)
        ctx = None if inproc else mp.get_context("spawn")
        shared = Shared(ctx)
        slices = [list(range(cfg.agents))[k::nworkers] for k in range(nworkers)]
        procs = []
        t_setup = time.time()
        for k, idx in enumerate(slices):
            args = (dataclasses.asdict(cfg), k, nworkers, idx, shared, fd.agent_url, fd.admin_url, str(out_dir / f"w{k}.json"))
            p = (threading.Thread(target=_worker_entry, args=args, daemon=True) if inproc
                 else ctx.Process(target=_worker_entry, args=args, daemon=True))
            p.start()
            procs.append(p)
        deadline = time.time() + 60 + 0.5 * cfg.agents
        while shared.ready() < cfg.agents:
            if time.time() > deadline or not any(p.is_alive() for p in procs):
                raise RuntimeError(f"only {shared.ready()}/{cfg.agents} agents certified")
            time.sleep(0.2)
        res["setup_s"] = round(time.time() - t_setup, 2)
        log(f"[{cfg.label or tag}] {cfg.agents} agents enrolled+certified in {res['setup_s']} s ({nworkers} workers)")

        def seed(n):
            nonlocal seeded
            while n > 0:
                k = min(n, cfg.study_size)
                _sid, dt = add_study(admin, tag, seeded, k)
                admin_calls.append((time.time(), dt, k))
                seeded += k
                n -= k

        t_seed = time.perf_counter()
        seed(cfg.total_jobs or cfg.depth())
        res["initial_seed"] = {"jobs": seeded, "s": round(time.perf_counter() - t_seed, 2)}
        fd.stats(reset=True)
        iostat = start_iostat()
        t_go = time.time()
        if cfg.fleet_poll_s > 0:
            def poll():
                c = httpx.Client(base_url=fd.admin_url, timeout=60, headers=admin_auth(home))
                while not stop_polls.is_set():
                    t0 = time.time()
                    p0 = time.perf_counter()
                    try:
                        st = c.get("/api/v1/fleet").status_code
                    except httpx.HTTPError:
                        st = 0
                    poll_samples.append(("admin_fleet", t0, time.perf_counter() - p0, st, None))
                    stop_polls.wait(cfg.fleet_poll_s)
            threading.Thread(target=poll, daemon=True).start()
        if cfg.console_viewers > 0:
            console = start_console(fd, cfg.console_port)
            for i in range(cfg.console_viewers):
                threading.Thread(target=console_viewer, args=(cfg.console_port, stop_polls, poll_samples), daemon=True).start()

            def scrape():
                c = httpx.Client(base_url=fd.admin_url, timeout=60, headers=admin_auth(home))
                while not stop_polls.is_set():
                    t0, p0 = time.time(), time.perf_counter()
                    try:
                        st = c.get("/metrics").status_code
                    except httpx.HTTPError:
                        st = 0
                    poll_samples.append(("metrics_scrape", t0, time.perf_counter() - p0, st, None))
                    stop_polls.wait(1.0)
            threading.Thread(target=scrape, daemon=True).start()
        timeline = []
        t_end = t_go + cfg.warmup_s + cfg.duration_s
        while True:
            now = time.time()
            counts = job_counts(fd.db_path)
            timeline.append((round(now - t_go, 1), counts.get("pending", 0), counts.get("leased", 0), counts.get("done", 0)))
            if cfg.total_jobs:
                if counts.get("pending", 0) + counts.get("leased", 0) == 0 or now > t_go + cfg.max_drain_s:
                    break
            else:
                if now >= t_end:
                    break
                if counts.get("pending", 0) < cfg.depth() * 0.6:
                    seed(cfg.depth() - counts.get("pending", 0))
            time.sleep(1.0)
        t_win_end = time.time()
        res["server"] = fd.stats(reset=False)
        res["disk"] = stop_iostat(iostat)
        # drain: no more refills; wait until every job is done
        while True:
            counts = job_counts(fd.db_path)
            if counts.get("pending", 0) + counts.get("leased", 0) == 0:
                break
            if time.time() > t_win_end + cfg.max_drain_s:
                log(f"drain timeout: {counts}")
                res["drain_timed_out"] = counts
                break
            timeline.append((round(time.time() - t_go, 1), counts.get("pending", 0), counts.get("leased", 0),
                             counts.get("done", 0)))
            time.sleep(0.5)
        t_drained = time.time()
        stop_polls.set()
        shared.set_phase(FLUSH)
        for p in procs:
            p.join(60)
        shared.set_phase(EXIT)
        for p in procs:
            p.join(30)
            if not inproc and p.is_alive():
                p.terminate()
        res["server_final"] = fd.stats(reset=False)
    finally:
        stop_polls.set()
        if console is not None:
            console.terminate()
            try:
                console.wait(5)
            except subprocess.TimeoutExpired:
                console.kill()
        fd.stop()
    # ------------------------------------------------------------------ collect
    samples, canonical, attempts, viol, gaps, lag = [], [], {}, [], [], []
    counters = {}
    for f in sorted(out_dir.glob("w*.json")):
        d = json.loads(f.read_text(encoding="utf-8"))
        samples += [tuple(s) for s in d["samples"]]
        canonical += [tuple(c) for c in d["canonical"]]
        attempts.update(d["attempts"])
        viol += d["violations"]
        gaps += d["hb_gaps"]
        lag += d["loop_lag"]
        for k, v in d["counters"].items():
            counters[k] = counters.get(k, 0) + v
    samples += poll_samples
    t_lo = t_go if cfg.total_jobs else t_go + cfg.warmup_s
    t_hi = t_drained if cfg.total_jobs else t_win_end
    win = max(1e-9, t_hi - t_lo)
    inv, info = harness_invariants(fd.db_path, canonical, attempts, seeded)
    if res.get("drain_timed_out"):
        # liveness was cut short by --max-drain-s: unsettled jobs / live attempts are expected, not safety bugs
        res["unsettled_at_timeout"] = [x for x in inv if x.startswith(("H1 ", "H5 "))]
        inv = [x for x in inv if not x.startswith(("H1 ", "H5 "))]
    exp = classify_expiries(info.pop("expired"), attempts)
    eval_acks = [c for c in canonical if t_lo <= c[2] <= t_hi]
    g = [x[1] for x in gaps if t_lo <= x[0] <= t_hi]
    res.update({
        "window_s": round(win, 1), "drain_s": round(t_drained - t_win_end, 1),
        "jobs_seeded": seeded, "endpoints": endpoint_table(samples, t_lo, t_hi),
        "setup_endpoints": endpoint_table(samples, 0, t_go),
        "completions_per_s": round(len(eval_acks) / win, 2),
        "jobs_per_hour": round(len(eval_acks) / win * 3600),
        "total_jobs_done": info["jobs"].get("done", 0), "eval_jobs_done": info.get("eval_done"),
        "overall_jobs_per_s": round(info["jobs"].get("done", 0) / max(1e-9, t_drained - t_go), 2),
        "expiries": exp, "hb_gap_p99_s": round(pct(g, .99) or 0, 2), "hb_gap_max_s": round(max(g) if g else 0, 2),
        "harness_loop_lag_p99_ms": round((pct(lag, .99) or 0) * 1e3, 1),
        "harness_loop_lag_max_ms": round((max(lag) if lag else 0) * 1e3, 1),
        "admin_add_study": [{"t": round(t - t_go, 1), "s": round(dt, 2), "jobs": k} for t, dt, k in admin_calls],
        "counters": counters, "invariant_violations": viol + inv, "db": info,
        "timeline": timeline[::max(1, len(timeline) // 120)],
        "loadavg_end": loadavg(),
    })
    if res["invariant_violations"] or any(v["http503"] or (v["err"] - v["conn_err"]) for v in res["endpoints"].values()):
        try:   # keep the evidence: oarbankd's own stderr (tracebacks) from the scratch home
            lines = (home / "oarbankd.out").read_text(errors="replace").splitlines()
            res["coordinator_log_tail"] = [l for l in lines if not l.startswith("INFO")][-60:]
        except OSError:
            pass
    if tmp and not cfg.keep_home:
        shutil.rmtree(tmp, ignore_errors=True)
    return res


# ============================================================================ reporting
def machine_info() -> dict:
    def sh(*cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            return ""
    commit = sh("git", "-C", str(REPO), "rev-parse", "--short", "HEAD")
    dirty = sh("git", "-C", str(REPO), "status", "--porcelain", "src/oarbank/coordinator")
    return {"model": sh("sysctl", "-n", "hw.model"),
            "cpu": sh("sysctl", "-n", "machdep.cpu.brand_string"), "ncpu": os.cpu_count(),
            "ram_gb": round(int(sh("sysctl", "-n", "hw.memsize") or 0) / 2 ** 30),
            "os": platform.platform(terse=True), "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
            "httpx": httpx.__version__, "coordinator_commit": commit + (" (+uncommitted oarbankd changes)" if dirty else "")}


def summary_row(r: dict) -> dict:
    ep, sv = r["endpoints"], r.get("server", {})
    get = lambda e, k: ep.get(e, {}).get(k, "–")
    err = sum(v["err"] for v in ep.values())
    n = sum(v["n"] for v in ep.values())
    return {"N": r["cfg"]["agents"], "req/s": round(n / max(1e-9, r["window_s"]), 1), "compl/s": r["completions_per_s"],
            "jobs/h": r["jobs_per_hour"], "hb p50/p99 ms": f"{get('heartbeat', 'p50_ms')} / {get('heartbeat', 'p99_ms')}",
            "claim p50/p99 ms": f"{get('claim', 'p50_ms')} / {get('claim', 'p99_ms')}",
            "complete p50/p99 ms": f"{get('complete', 'p50_ms')} / {get('complete', 'p99_ms')}",
            "err %": round(100 * err / max(1, n), 3), "503": sum(v["http503"] for v in ep.values()),
            "expiries (false)": f"{r['expiries']['total']} ({r['expiries']['false']})",
            "hb gap max s": r["hb_gap_max_s"],
            "in-oarbankd hb/claim/complete p99 ms": "/".join(str(sv.get("http", {}).get(k, {}).get("p99_ms", "–"))
                                                          for k in ("heartbeat", "claim", "complete")),
            "lock wait p99 ms": sv.get("lock_wait", {}).get("p99_ms", "–"),
            "lock util %": sv.get("lock_util_pct", "–"), "oarbankd CPU %": sv.get("cpu_pct", "–"),
            "loop lag p99 ms": sv.get("loop_lag", {}).get("p99_ms", "–"),
            "violations": len(r["invariant_violations"])}


def _fmt(v):
    """3 significant-ish digits for tables (server-side values are log-histogram bucket bounds, ~12% resolution)."""
    if isinstance(v, float):
        return str(round(v)) if abs(v) >= 100 else str(round(v, 1)) if abs(v) >= 10 else str(round(v, 2))
    if isinstance(v, str) and "/" in v:
        return " / ".join(_fmt(float(x)) if x.strip().replace(".", "", 1).isdigit() else x.strip() for x in v.split("/"))
    return str(v)


def md_table(rows: list[dict]) -> str:
    if not rows:
        return ""
    keys = list(rows[0])
    out = ["| " + " | ".join(keys) + " |", "|" + "---|" * len(keys)]
    out += ["| " + " | ".join(_fmt(r[k]) for k in keys) + " |" for r in rows]
    return "\n".join(out)


def write_results(runs: list[dict], path: Path, extra_md: str = ""):
    mi = machine_info()
    lines = ["# oarbankd swarm results", "",
             f"Generated {time.strftime('%Y-%m-%d %H:%M %Z')} by `bench/swarm.py sweep` / `report`. Raw data: `bench/results/*.json`.", "",
             "## Machine", "", md_table([mi]), "",
             f"Load average at the start of each run: " +
             ", ".join(f"N={r['cfg']['agents']}: {load1(r)}" for r in runs) +
             ".", "",
             "## Settings", "",
             f"slots/agent {runs[0]['cfg']['slots']}, heartbeat {runs[0]['cfg']['heartbeat_s']} s, "
             f"jobs {runs[0]['cfg']['job_min_s']}–{runs[0]['cfg']['job_max_s']} s, steady window "
             f"{runs[0]['cfg']['duration_s']} s after {runs[0]['cfg']['warmup_s']} s warmup, fail {runs[0]['cfg']['fail_rate']}, "
             f"release {runs[0]['cfg']['release_rate']}, lost-ack replay {runs[0]['cfg']['dup_rate']}. "
             "Queue kept at 3 x agents x slots pending jobs (min 200). Client latencies include HTTP, oarbankd queueing "
             "and host scheduling; `in-oarbankd` is measured server-side from request arrival to response. "
             f"Client worker processes: {runs[0]['workers']}.", "",
             "## Summary", "", md_table([summary_row(r) for r in runs]), ""]
    lines += ["## Per-endpoint detail (steady window)", ""]
    for r in runs:
        rows = [{"endpoint": k, **v} for k, v in r["endpoints"].items()]
        lines += [f"### N = {r['cfg']['agents']}{(' — ' + r['cfg']['label']) if r['cfg']['label'] else ''}", "",
                  md_table(rows), ""]
        sv = r.get("server") or {}
        ops = sv.get("by_op", {})
        orow = [{"op": k, "calls": v["wall"].get("n", 0), "wall p50 ms": v["wall"].get("p50_ms", "–"),
                 "wall p99 ms": v["wall"].get("p99_ms", "–"), "lock wait p99 ms": v["lock_wait"].get("p99_ms", "–"),
                 "lock hold p50 ms": v["lock_hold"].get("p50_ms", "–"), "lock hold p99 ms": v["lock_hold"].get("p99_ms", "–"),
                 "hold share %": v["hold_share_pct"]} for k, v in sorted(ops.items(), key=lambda kv: -kv[1]["hold_share_pct"])
                if v["wall"].get("n") or v["hold_share_pct"] >= 0.5]
        if orow:
            lines += ["Server side (instrumented oarbankd): time per core operation and its share of DB-lock hold time.", "",
                      md_table(orow), ""]
        inner = sv.get("inner", {})
        if inner:
            lines += ["Inner helpers: " + "; ".join(f"`{k}` n={v.get('n')} p50 {v.get('p50_ms')} ms p99 {v.get('p99_ms')} ms"
                                                    for k, v in inner.items()), ""]
        sql = sv.get("sql", {})
        if sql:
            lines += ["SQL statements on oarbankd's connection (under the lock): " + "; ".join(
                f"`{k}` n={v.get('n')} p99 {_fmt(v.get('p99_ms'))} ms max {_fmt(v.get('max_ms'))} ms "
                f"({v.get('time_share_of_lock_hold_pct')}% of lock hold)"
                for k, v in sorted(sql.items(), key=lambda kv: -kv[1].get("sum_s", 0))[:4]), ""]
        if sv.get("http"):
            lines += ["In-oarbankd request time (arrival to response): " + "; ".join(
                f"`{k}` p50 {_fmt(v.get('p50_ms'))} / p99 {_fmt(v.get('p99_ms'))} ms"
                for k, v in sv["http"].items() if k in ("heartbeat", "claim", "complete", "hello")) +
                f". Host disk during window: {r.get('disk') or 'n/a'}; load avg {load1(r)}.", ""]
        lines += [f"Setup (enroll + certify) {r['setup_s']} s; initial seed {r['initial_seed']['jobs']} jobs in "
                  f"{r['initial_seed']['s']} s; drain {r['drain_s']} s; jobs done {r['total_jobs_done']}; "
                  f"counters {r['counters']}; expiries {r['expiries']}; harness loop lag p99 "
                  f"{r['harness_loop_lag_p99_ms']} ms (max {r['harness_loop_lag_max_ms']}); DB rows {r['db']['db_rows']}; "
                  f"{r['db']['check_all']}; violations: {r['invariant_violations'][:5] or 'none'}", ""]
    if extra_md:
        lines += [extra_md, ""]
    path.write_text("\n".join(lines))


def experiment_row(r: dict) -> dict:
    sv, ep, c = r.get("server") or {}, r["endpoints"], r["cfg"]
    g = lambda d, *ks: (lambda v: "–" if v is None else v)(
        __import__("functools").reduce(lambda x, k: (x or {}).get(k) if isinstance(x, dict) else None, ks, d))
    return {"run": c.get("label") or f"N={c['agents']}", "N": c["agents"],
            "sync": sv.get("sqlite_synchronous", "FULL"), "queue": c.get("queue_depth") or max(200, 3 * c["agents"] * c["slots"]),
            "fleet poll s": c.get("fleet_poll_s") or "–", "compl/s": r["completions_per_s"],
            "client hb p50/p99 ms": f"{g(ep, 'heartbeat', 'p50_ms')} / {g(ep, 'heartbeat', 'p99_ms')}",
            "core claim p50/p99 ms": f"{g(sv, 'by_op', 'claim', 'wall', 'p50_ms')} / {g(sv, 'by_op', 'claim', 'wall', 'p99_ms')}",
            "prefetch_for p50/p99 ms": f"{g(sv, 'inner', 'prefetch_for', 'p50_ms')} / {g(sv, 'inner', 'prefetch_for', 'p99_ms')}",
            "COMMIT p99/max ms": f"{g(sv, 'sql', 'commit', 'p99_ms')} / {g(sv, 'sql', 'commit', 'max_ms')}",
            "lock util %": g(sv, "lock_util_pct"), "lock wait max ms": g(sv, "lock_wait", "max_ms"),
            "disk MB/s (host)": g(r, "disk", "disk0_mb_s_mean"), "load avg": load1(r),
            "harness lag p99 ms": r["harness_loop_lag_p99_ms"], "violations": len(r["invariant_violations"])}


def report(results_dir: Path, out: Path, intro_md: str = ""):
    """Rebuild results.md from bench/results/*.json: sweep-n*.json is the main table, every other run an experiment."""
    load = lambda f: json.loads(f.read_text(encoding="utf-8"))
    sweep = sorted((load(f) for f in results_dir.glob("sweep-n*.json")), key=lambda r: r["cfg"]["agents"])
    other = sorted((f for f in results_dir.glob("*.json") if not f.name.startswith("sweep-n")), key=lambda f: f.stat().st_mtime)
    md = [intro_md] if intro_md else []
    if other:
        md += ["## Experiments", "", md_table([{**experiment_row(load(f)), "run": f.stem} for f in other]), ""]
    write_results(sweep, out, "\n".join(md))


# ============================================================================ CLI
def cfg_from_args(a) -> Cfg:
    c = Cfg()
    for f in dataclasses.fields(Cfg):
        v = getattr(a, f.name, None)
        if v is not None:
            setattr(c, f.name, v)
    return c


def add_cfg_args(p):
    for f in dataclasses.fields(Cfg):
        if f.name in ("home", "label"):
            p.add_argument("--" + f.name.replace("_", "-"), dest=f.name, type=str, default=None)
        elif f.type in ("bool",) or isinstance(f.default, bool):
            p.add_argument("--" + f.name.replace("_", "-"), dest=f.name, action="store_true", default=None)
        else:
            p.add_argument("--" + f.name.replace("_", "-"), dest=f.name, type=type(f.default), default=None)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="one swarm run; prints a JSON summary")
    add_cfg_args(r)
    r.add_argument("--json-out", default=None)
    s = sub.add_parser("sweep", help="runs N in --ns, writes bench/results.md and bench/results/*.json")
    add_cfg_args(s)
    s.add_argument("--ns", default="10,50,200,500,1000")
    s.add_argument("--out", default=str(BENCH / "results.md"))
    rp = sub.add_parser("report", help="rebuild bench/results.md from bench/results/*.json")
    rp.add_argument("--out", default=str(BENCH / "results.md"))
    rp.add_argument("--intro", default=None, help="markdown file to insert before the experiments")
    a = ap.parse_args()
    if a.cmd == "report":
        report(BENCH / "results", Path(a.out), Path(a.intro).read_text(encoding="utf-8") if a.intro else "")
        return
    if a.cmd == "run":
        res = run(cfg_from_args(a))
        if a.json_out:
            Path(a.json_out).write_text(json.dumps(res, indent=1))
        print(json.dumps({k: v for k, v in res.items() if k not in ("timeline", "setup_endpoints")}, indent=1))
        print(md_table([summary_row(res)]))
        sys.exit(1 if res["invariant_violations"] else 0)
    runs = []
    (BENCH / "results").mkdir(exist_ok=True)
    for n in [int(x) for x in a.ns.split(",")]:
        c = cfg_from_args(a)
        c.agents = n
        res = run(c)
        (BENCH / "results" / f"sweep-n{n}.json").write_text(json.dumps(res, indent=1))
        runs.append(res)
        print(md_table([summary_row(res)]), flush=True)
        write_results(runs, Path(a.out))


if __name__ == "__main__":
    main()
