"""Chaos (admin-console.md "Chaos"; nightly: `pytest -m chaos`). Real oarbankd processes on scratch homes and ports;
agents are simulated over the mTLS agent API with the SDK's toy module. Each fault's expected outcome is asserted. A
running coordinator (its home, ports 7400/7401/7443) is never touched."""
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
pytestmark = pytest.mark.chaos


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Fleet:
    """A scratch oarbankd with toy and relay installed and one enrolled, certified node with its client certificate."""

    def __init__(self, tmp: Path):
        import ssl
        from cryptography.hazmat.primitives import serialization
        from helpers import admin_headers, certify, enroll_agent, make_db
        from oarbank.coordinator import tlsca
        self.home = tmp
        self.db_path = tmp / "oarbank.sqlite3"
        db = make_db(self.db_path)
        key, pem, node = enroll_agent(db, "chaos-mac")
        certify(db, node)
        self.node_id = node["node_id"]
        self.admin_auth = admin_headers(db)
        db.conn.close()
        (tmp / "agent.pem").write_text(pem)
        (tmp / "agent.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
        self.tls = ssl.create_default_context(cadata=tlsca.ca_pem(tmp))
        self.tls.load_cert_chain(str(tmp / "agent.pem"), str(tmp / "agent.key"))
        self.agent_port, self.admin_port = free_port(), free_port()
        self.proc = None

    def start(self):
        env = dict(os.environ, OARBANKD_HOME=str(self.home), OARBANKD_TAILSCALE="/usr/bin/false", OARBANKD_TAILSCALE_SOCKET="")
        self.proc = subprocess.Popen([sys.executable, "-m", "oarbank.coordinator", "--agent-bind", "127.0.0.1", "--agent-port",
                                      str(self.agent_port), "--admin-bind", "127.0.0.1", "--admin-port", str(self.admin_port)],
                                     env=env, stdout=open(self.home / "oarbankd.log", "ab"), stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                if httpx.get(f"{self.agent}/healthz", timeout=0.5, verify=self.tls).status_code == 200:
                    return self
            except httpx.HTTPError:
                time.sleep(0.1)
        raise RuntimeError("oarbankd did not start")

    def stop(self, sig=signal.SIGTERM):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(sig)
            self.proc.wait(15)

    @property
    def agent(self):
        return f"https://127.0.0.1:{self.agent_port}"

    @property
    def admin(self):
        return f"http://127.0.0.1:{self.admin_port}"

    def call(self, method, path, body=None, timeout=10):
        return httpx.request(method, self.agent + path, json=body, verify=self.tls, timeout=timeout)

    def op(self, name, params=None, target=None, reason="chaos"):
        import uuid
        r = httpx.post(f"{self.admin}/api/v1/ops/{name}", json={"target": target, "params": params or {}, "reason": reason},
                       headers={**self.admin_auth, "idempotency-key": uuid.uuid4().hex}, timeout=30)
        r.raise_for_status()
        return r.json()

    def db(self):
        from oarbank.coordinator.db import DB
        return DB(self.db_path)


def toy_result(n):
    return {"result": {"envelope": 1, "schema": "toy/result@1", "module_version": "0.1.0", "payload": {"sum": str(n * (n - 1) // 2)}}}


def agent_loop(f: Fleet, stop: threading.Event, stats: dict):
    """A simulated agent: claim toy jobs, complete them, heartbeat; count outcomes (5xx/connection errors retried)."""
    while not stop.is_set():
        try:
            r = f.call("POST", "/v1/agent/claim", {"free_cpu": 4, "free_mem_gb": 8, "modules": ["toy"], "ready_datasets": []})
            if r.status_code >= 500:
                stats["5xx"] = stats.get("5xx", 0) + 1
                time.sleep(0.2)
                continue
            for g in r.json().get("grants", []):
                while not stop.is_set():
                    c = f.call("POST", f"/v1/attempts/{g['attempt_id']}/complete", toy_result(g["spec"]["payload"]["n"]))
                    if c.status_code < 500:
                        stats["done"] = stats.get("done", 0) + 1
                        break
                    stats["5xx"] = stats.get("5xx", 0) + 1
                    time.sleep(0.2)
            f.call("POST", "/v1/agent/heartbeat", {"attempts": [], "telemetry": {}, "capacity": {}})
        except httpx.HTTPError:
            stats["conn"] = stats.get("conn", 0) + 1
            time.sleep(0.2)
        time.sleep(0.05)


def queue(f: Fleet, n: int, start: int):
    f.op("mod.toy.queue_sums", {"ns": list(range(start, start + n)), "campaign_id": f"c_chaos_{start}"})


@pytest.fixture
def fleet(tmp_path):
    f = Fleet(tmp_path).start()
    yield f
    f.stop(signal.SIGKILL)


def test_kill_9_mid_write_leaves_a_consistent_database(fleet):
    from oarbank.coordinator import invariants
    queue(fleet, 200, 10)
    stop, stats = threading.Event(), {}
    t = threading.Thread(target=agent_loop, args=(fleet, stop, stats), daemon=True)
    t.start()
    time.sleep(2.0)
    fleet.stop(signal.SIGKILL)                                       # mid-write, no shutdown path
    fleet.start()
    time.sleep(3.0)
    stop.set()
    t.join(10)
    db = fleet.db()
    assert db.one("PRAGMA integrity_check")["integrity_check"] == "ok"
    assert invariants.check_all(db) == []
    assert stats.get("done", 0) > 0


def test_a_held_write_lock_answers_503_with_retry_after_and_agents_recover(fleet):
    hold = sqlite3.connect(fleet.db_path, timeout=1)
    hold.execute("BEGIN IMMEDIATE")
    t0 = time.time()
    seen = []
    while time.time() - t0 < 10:
        r = fleet.call("POST", "/v1/agent/heartbeat", {"attempts": [], "telemetry": {}, "capacity": {}}, timeout=40)
        seen.append((r.status_code, r.headers.get("retry-after")))
        if r.status_code == 503:
            break
    hold.rollback()
    hold.close()
    assert any(code == 503 and ra for code, ra in seen), seen
    for _ in range(10):                                              # an agent honours Retry-After and retries
        r = fleet.call("POST", "/v1/agent/heartbeat", {"attempts": [], "telemetry": {}, "capacity": {}}, timeout=40)
        if r.status_code != 503:
            break
        time.sleep(float(r.headers.get("retry-after", 2)))
    assert r.status_code == 200


def test_killing_the_module_process_during_completions_is_a_module_fault_never_charged(fleet):
    queue(fleet, 3, 1000)
    grants = fleet.call("POST", "/v1/agent/claim", {"free_cpu": 4, "free_mem_gb": 8, "modules": ["toy"], "ready_datasets": []}).json()["grants"]
    assert grants
    out = subprocess.run(["pgrep", "-f", "toy_module.py"], capture_output=True, text=True).stdout.split()
    pids = [int(p) for p in out if p]
    for p in pids:                                                   # the coordinator-side module dies
        os.kill(p, signal.SIGKILL)
    codes = []
    for g in grants:
        for _ in range(50):
            r = fleet.call("POST", f"/v1/attempts/{g['attempt_id']}/complete", toy_result(g["spec"]["payload"]["n"]))
            codes.append(r.status_code)
            if r.status_code < 500:
                assert r.json()["accepted"]
                break
            time.sleep(0.3)
    db = fleet.db()
    assert db.one("SELECT COUNT(*) n FROM attempts WHERE state='failed'")["n"] == 0          # S15: nobody charged
    assert db.one("SELECT breaker_failures FROM nodes WHERE node_id=?", (fleet.node_id,))["breaker_failures"] == 0
    from oarbank.coordinator import invariants
    assert invariants.check_all(db) == []


def test_ntfy_down_queues_nothing_and_breaks_nothing(fleet):
    db = fleet.db()
    db.set_setting("ntfy", {"url": "http://127.0.0.1:9/unreachable"})
    from oarbank.coordinator import core
    core._alert(db, "invariant:S0", "fleet", "chaos: ntfy is down", priority="max")
    time.sleep(1.5)
    assert db.one("SELECT state FROM alerts WHERE rule='invariant:S0'")["state"] == "open"        # the inbox has it
    assert db.one("SELECT 1 FROM events WHERE kind='notify_failed'")
    r = fleet.call("POST", "/v1/agent/heartbeat", {"attempts": [], "telemetry": {}, "capacity": {}})
    assert r.status_code == 200


def test_a_hand_edited_audit_row_fails_verification_and_raises_p5(fleet):
    fleet.op("nodes.run_doctor", target=fleet.node_id)
    fleet.stop()
    c = sqlite3.connect(fleet.db_path)
    c.execute("UPDATE audit SET reason='edited by hand' WHERE event_id=(SELECT MAX(event_id) FROM audit)")
    c.commit()
    c.close()
    from oarbank.coordinator import app as coord_app
    db = fleet.db()
    coord_app._audit_hourly(db)
    a = db.one("SELECT state, rule FROM alerts WHERE rule='audit_chain_broken'")
    assert a and a["state"] == "open"
    from oarbank.contracts.alert_rules import policy
    assert policy(a["rule"])["severity"] == "P5"
    fleet.start()                                                    # so the fixture's stop has a process


def test_killing_the_console_leaves_the_agent_path_untouched(fleet, tmp_path):
    secret = tmp_path / "console.secret"
    secret.write_text((fleet.home / "console.secret").read_text())
    port = free_port()
    con = subprocess.Popen([sys.executable, "-m", "oarbank.console", "--port", str(port), "--oarbankd", fleet.admin,
                            "--db", str(fleet.db_path), "--secret-file", str(secret), "--frames-port", str(free_port())],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=0.5).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        queue(fleet, 300, 5000)
        stop, before = threading.Event(), {}
        t = threading.Thread(target=agent_loop, args=(fleet, stop, before), daemon=True)
        t.start()
        time.sleep(2)
        con.send_signal(signal.SIGKILL)                              # the console dies mid-flight
        con.wait(5)
        mid = dict(before)
        time.sleep(2)
        stop.set()
        t.join(10)
        assert before.get("done", 0) > mid.get("done", 0) and not before.get("conn")
    finally:
        if con.poll() is None:
            con.kill()
