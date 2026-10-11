"""Coordinator self-update (docs/design/fleet-updates.md, "The coordinator"; D58): oarbankd's prepare and request
(coordself.py: refusals, the snapshot, the new build's self-test, the spool request), `oarbankd --self-test`,
GET /v1/health, the result's transitions, and the root runner (coordupdate.py) end to end against a recording service
layer and a real local health server: commit, a probation that fails (the database copy restored, `current` flipped
back), refusals (a bad signature, tampering, replays), and recovery from a crash after every journaled step."""
import base64
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from oarbank_sdk import portable

import oarbank
from oarbank import coordupdate, fleetsig
from oarbank.coordinator import clock, coordmove, coordself
from oarbank.coordinator import config as C
from oarbank.coordinator.db import DB

from helpers import agent_client

PLATFORM = portable.host_platform()
FLEET_SCHEMA = """
CREATE TABLE IF NOT EXISTS fleet_releases (version TEXT PRIMARY KEY, seq INT, manifest TEXT, manifest_sha256 TEXT,
  signature_json TEXT, source TEXT, imported_at REAL, imported_by TEXT, notes TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS fleet_artifacts (sha256 TEXT PRIMARY KEY, version TEXT, name TEXT, role TEXT, platform TEXT,
  format TEXT, size INT, path TEXT);
"""
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="the test builds' oarbankd is a shell script")


def keypair():
    k = Ed25519PrivateKey.generate()
    return k, base64.b64encode(k.public_key().public_bytes_raw()).decode()


def sign(key, manifest: str, version: str, seq: int) -> dict:
    stmt = fleetsig.statement(version, seq, manifest)
    return {"statement": stmt, "signature": base64.b64encode(key.sign(stmt.encode())).decode()}


def archive(path: Path, version: str, platform: str = PLATFORM, behavior: str = "healthy", selftest_ok: bool = True) -> Path:
    """A coordinator build (coordbuilds.py format 1): its oarbankd answers --self-test with a summary, and `behavior`
    tells the fake service layer how the build does once started."""
    summary = json.dumps({"ok": selftest_ok, "version": version, "error": None if selftest_ok else "migration 7 failed"})
    members = {"oarbank-coordinator.json": (json.dumps({"format": 1, "version": version, "platform": platform,
                                                        "exec": ["bin/oarbankd"]}), 0o644),
               "bin/oarbankd": (f"#!/bin/sh\necho '{summary}'\nexit {0 if selftest_ok else 1}\n", 0o755),
               "behavior": (behavior, 0o644)}
    with tarfile.open(path, "w:gz") as t:
        for name, (text, mode) in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            t.addfile(info, io.BytesIO(data))
    return path


def manifest_for(version: str, seq: int, art: Path, agent_min: str = "2.9.0", platform: str = PLATFORM) -> str:
    data = art.read_bytes()
    return json.dumps({"type": "oarbank-fleet-release", "format": 1, "version": version, "seq": seq,
                       "released_at": "2026-10-20T00:00:00Z", "expires": None, "agent_min": agent_min, "stops": [],
                       "artifacts": [{"name": art.name, "role": "coordinator", "platform": platform, "format": "tar",
                                      "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}]},
                      sort_keys=True, separators=(",", ":"))


def store(db: DB, version: str, art: Path, seq: int = 21100, agent_min: str = "2.9.0", signature: dict | None = None,
          state: str = "ready", copy: bool = True) -> str:
    """A stored release as the rollout engine stores it (fleet_releases, fleet_artifacts, updates/artifacts/<sha>)."""
    db.conn.executescript(FLEET_SCHEMA)
    text = manifest_for(version, seq, art, agent_min)
    sha = hashlib.sha256(art.read_bytes()).hexdigest()
    dest = Path(db.path).parent / "updates" / "artifacts" / sha
    if copy:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(art.read_bytes())
    db.x("INSERT INTO fleet_releases(version, seq, manifest, manifest_sha256, signature_json, state) VALUES(?,?,?,?,?,?)",
         (version, seq, text, fleetsig.manifest_sha256(text), json.dumps(signature) if signature else None, state))
    db.x("INSERT INTO fleet_artifacts(sha256, version, name, role, platform, format, size, path) VALUES(?,?,?,?,?,?,?,?)",
         (sha, version, art.name, "coordinator", PLATFORM, "tar", art.stat().st_size, f"updates/artifacts/{sha}"))
    return text


def node(db: DB, name: str, version: str | None, lifecycle: str = "ready"):
    db.x("INSERT INTO nodes(node_id, hostname, lifecycle, desired_state, agent_version) VALUES(?,?,?,?,?)",
         (f"n_{name}", name, lifecycle, "active", version))


@pytest.fixture
def db(tmp_path):
    d = DB(tmp_path / "home" / "oarbank.sqlite3")
    yield d
    d.conn.close()


@pytest.fixture
def v(monkeypatch):
    """This coordinator runs 2.10.0; the release is 2.11.0."""
    monkeypatch.setattr(oarbank, "__version__", "2.10.0")
    return "2.11.0"


# ------------------------------------------------------------------ request: refusals

def test_no_update_while_a_move_is_on_or_after_a_hand_off(db, v, tmp_path):
    store(db, v, archive(tmp_path / "b.tar.gz", v))
    db.set_state("move_phase", "draining")
    with pytest.raises(coordself.UpdateError, match="move is in progress"):
        coordself.request(db, v, "test")
    db.set_state("move_phase", "idle")
    db.x("INSERT INTO coordinator_plans(plan_id, state, created_at) VALUES('pl_1', 'paired', 0)")
    with pytest.raises(coordself.UpdateError, match="move plan pl_1 is paired"):
        coordself.request(db, v, "test")
    db.x("UPDATE coordinator_plans SET state='done'")
    db.set_state("coordinator_role", "standby")
    with pytest.raises(coordself.UpdateError, match="this coordinator is standby"):
        coordself.request(db, v, "test")
    assert coordself.state(db) is None and not (Path(db.path).parent / "updates" / coordself.REQUEST).exists()


def test_no_update_without_a_ready_stored_build_for_this_platform(db, v, tmp_path):
    db.conn.executescript(FLEET_SCHEMA)          # a no-op where fleetupdates already made the tables
    with pytest.raises(coordself.UpdateError, match="not stored"):
        coordself.request(db, v, "test")
    with pytest.raises(coordself.UpdateError, match="is not newer"):
        coordself.request(db, "2.10.0", "test")
    art = archive(tmp_path / "b.tar.gz", v)
    store(db, v, art, state="incomplete")
    with pytest.raises(coordself.UpdateError, match="is incomplete"):
        coordself.request(db, v, "test")
    db.x("UPDATE fleet_releases SET state='ready'")
    sha = hashlib.sha256(art.read_bytes()).hexdigest()
    stored = Path(db.path).parent / "updates" / "artifacts" / sha
    stored.write_bytes(b"tampered")
    with pytest.raises(coordself.UpdateError, match="does not match its sha256"):
        coordself.request(db, v, "test")
    stored.unlink()
    db.x("UPDATE fleet_artifacts SET path=NULL")
    with pytest.raises(coordself.UpdateError, match="is not stored"):
        coordself.request(db, v, "test")
    db.x("DELETE FROM fleet_artifacts")
    with pytest.raises(coordself.UpdateError, match=f"coordinator build for {PLATFORM} is not stored"):
        coordself.request(db, v, "test")
    assert coordself.state(db) is None


@posix_only
def test_old_agents_block_the_update_unless_held_or_retired(db, v, tmp_path, monkeypatch):
    from oarbank.coordinator.settings import resolve as V
    store(db, v, archive(tmp_path / "b.tar.gz", v), agent_min="2.9.0")
    node(db, "old-one", "2.8.4")
    node(db, "gone", "2.1.0", lifecycle="retired")
    node(db, "unknown", None)
    node(db, "fresh", "2.10.0")
    with pytest.raises(coordself.UpdateError, match=r"update or hold first: old-one \(2\.8\.4\)$"):
        coordself.request(db, v, "test")
    real = V.resolve
    holds = {"n_old-one": {"reason": "on a trip", "until": clock.now() - 60}}       # expired: no hold

    def resolve(snap, n, key, *a, **kw):
        if key == "update_hold":
            return {"value": holds.get((n or {}).get("node_id"))}
        return real(snap, n, key, *a, **kw)
    monkeypatch.setattr(V, "resolve", resolve)
    with pytest.raises(coordself.UpdateError, match="old-one"):
        coordself.request(db, v, "test")
    holds["n_old-one"] = {"reason": "on a trip", "until": None}
    assert coordself.request(db, v, "test")["state"] == "requested"


@posix_only
def test_a_snapshot_that_fails_its_integrity_check_stops_the_update(db, v, tmp_path, monkeypatch):
    store(db, v, archive(tmp_path / "b.tar.gz", v))
    monkeypatch.setattr(coordself, "integrity", lambda p: "*** in database main ***\nPage 7: btreeInitPage() returns error code 11")
    with pytest.raises(coordself.UpdateError, match="integrity check"):
        coordself.request(db, v, "test")
    assert not list((Path(db.path).parent / "updates" / "snapshots").glob("*.sqlite3"))
    assert coordself.state(db) is None


@posix_only
def test_a_build_whose_self_test_fails_is_never_requested(db, v, tmp_path):
    store(db, v, archive(tmp_path / "b.tar.gz", v, selftest_ok=False))
    with pytest.raises(coordself.UpdateError, match="self-test failed.*migration 7 failed"):
        coordself.request(db, v, "test")
    up = Path(db.path).parent / "updates"
    assert coordself.state(db) is None and not (up / coordself.REQUEST).exists()
    assert not list((up / "snapshots").glob("*")) and not list((up / "selftest").iterdir())


# ------------------------------------------------------------------ request: the spool request

@posix_only
def test_a_request_snapshots_self_tests_and_writes_the_spool_request(db, v, tmp_path):
    db.x("CREATE TABLE marker (x)")
    db.x("INSERT INTO marker VALUES (42)")
    art = archive(tmp_path / "b.tar.gz", v)
    text = store(db, v, art)
    s = coordself.request(db, v, "alice")
    assert s["state"] == "requested" and s["version"] == v and s["from_version"] == "2.10.0" and s["finished_at"] is None
    up = Path(db.path).parent / "updates"
    req = json.loads((up / coordself.REQUEST).read_text())
    sha = hashlib.sha256(art.read_bytes()).hexdigest()
    assert req == {"id": s["update_id"], "version": v, "sha256": sha, "size": art.stat().st_size,
                   "archive": f"updates/artifacts/{sha}", "manifest": text, "signature": None, "snapshot": s["snapshot"],
                   "from_version": "2.10.0", "requested_at": req["requested_at"]}
    snap = db.abs(s["snapshot"])
    assert snap.parent == up / "snapshots" and snap.name.startswith("2.10.0-") and coordself.integrity(snap) == "ok"
    assert sqlite3.connect(snap).execute("SELECT x FROM marker").fetchone() == (42,)
    if os.name == "posix":
        assert (up / coordself.REQUEST).stat().st_mode & 0o777 == 0o600
    assert not list((up / "selftest").iterdir())                  # the unpacked build and its scratch home are gone
    assert db.one("SELECT reason FROM events WHERE kind='coordinator_update_requested'")["reason"].startswith("2.10.0 -> 2.11.0")
    # one at a time, and a move waits for it
    with pytest.raises(coordself.UpdateError, match="is requested"):
        coordself.request(db, v, "alice")
    with pytest.raises(coordmove.MoveError, match="a move waits for it"):
        coordmove.prepare(db, "https://100.64.0.9:7443", "alice")


def test_the_running_checkout_self_tests_in_developer_mode(db, monkeypatch, tmp_path):
    """OARBANKD_SELFTEST=checkout (signing off): the build is the running checkout, whose own --self-test runs."""
    version = oarbank.__version__                                  # what the checkout's self-test reports
    monkeypatch.setattr(oarbank, "__version__", "2.9.5")
    store(db, version, archive(tmp_path / "b.tar.gz", version))
    monkeypatch.setenv("OARBANKD_SELFTEST", "checkout")
    assert coordself.request(db, version, "test")["state"] == "requested"


@posix_only
def test_signing_mode_needs_the_owner_signature_over_the_manifest(db, v, tmp_path, monkeypatch):
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    key, pub = keypair()
    other, _ = keypair()
    db.set_state("release_pubkey", pub)
    art = archive(tmp_path / "b.tar.gz", v)
    text = store(db, v, art)
    with pytest.raises(coordself.UpdateError, match="no owner signature"):
        coordself.request(db, v, "test")
    db.x("UPDATE fleet_releases SET signature_json=?", (json.dumps(sign(other, text, v, 21100)),))
    with pytest.raises(coordself.UpdateError, match="does not verify"):
        coordself.request(db, v, "test")
    db.x("UPDATE fleet_releases SET signature_json=?", (json.dumps(sign(key, text, v, 21099)),))
    with pytest.raises(coordself.UpdateError, match="seq 21099"):
        coordself.request(db, v, "test")
    good = sign(key, text, v, 21100)
    db.x("UPDATE fleet_releases SET signature_json=?", (json.dumps(good),))
    coordself.request(db, v, "test")
    assert json.loads((Path(db.path).parent / "updates" / coordself.REQUEST).read_text())["signature"] == good


# ------------------------------------------------------------------ oarbankd --self-test

def _self_test(home: Path):
    r = subprocess.run([sys.executable, "-m", "oarbank.coordinator", "--self-test", "--home", str(home)],
                       capture_output=True, text=True, timeout=300)
    return r.returncode, json.loads(r.stdout.strip().splitlines()[-1])


def test_oarbankd_self_test_migrates_a_copy_and_checks_it(tmp_path):
    home = tmp_path / "scratch"
    home.mkdir()
    DB(home / "oarbank.sqlite3").conn.close()
    old = sqlite3.connect(home / "oarbank.sqlite3")             # as an earlier version left it: columns to add
    old.execute("ALTER TABLE nodes DROP COLUMN tools_json")
    old.execute("DROP TABLE coordinator_updates")
    old.commit()
    old.close()
    code, out = _self_test(home)
    assert code == 0 and out["ok"] and out["integrity"] == "ok" and out["invariants"] == [], out
    assert out["version"] == oarbank.__version__
    con = sqlite3.connect(home / "oarbank.sqlite3")
    cols = {r[1] for r in con.execute("PRAGMA table_info(nodes)")}
    con.close()                                                     # Windows: an open file cannot be rewritten
    assert "tools_json" in cols                                     # the migrations ran on the copy
    assert sorted(p.name for p in home.iterdir() if not p.name.startswith("oarbank.sqlite3")) == []   # never served
    (home / "oarbank.sqlite3").write_bytes(b"not a database" * 100)
    for suffix in ("-wal", "-shm"):
        (home / f"oarbank.sqlite3{suffix}").unlink(missing_ok=True)
    code, out = _self_test(home)
    assert code == 1 and not out["ok"] and "migrations failed" in out["error"]
    code, out = _self_test(tmp_path / "empty")
    assert code == 1 and "no oarbank.sqlite3" in out["error"]


# ------------------------------------------------------------------ GET /v1/health

def test_health_says_version_migrations_and_the_tick(db):
    c = agent_client(db)
    h = c.get("/v1/health").json()
    assert h["version"] == oarbank.__version__ and h["migrated"] is True and h["ticking"] is False and h["role"] == "active"
    assert abs(h["started_at"] - clock.now()) < 60
    coordself.tick(db)
    assert c.get("/v1/health").json()["ticking"] is True
    coordself._ticks[str(db.path)] = time.time() - coordself.TICK_FRESH_S - 1
    assert c.get("/v1/health").json()["ticking"] is False
    db.set_state("coordinator_role", "standby")                    # answered in every role, without a certificate
    r = c.get("/v1/health")
    assert r.status_code == 200 and r.json()["role"] == "standby"


# ------------------------------------------------------------------ the result

def _requested(db, version="2.11.0") -> dict:
    uid = "cu_" + os.urandom(3).hex()
    db.x("INSERT INTO coordinator_updates(update_id, version, from_version, state, requested_at) VALUES(?,?,?,?,?)",
         (uid, version, "2.10.0", "requested", clock.now()))
    up = coordself.spool(db)
    (up / coordself.REQUEST).write_text("{}")
    return {"id": uid, "up": up}


def _result(up: Path, uid: str, state: str, error=None):
    (up / coordself.RESULT).write_text(json.dumps({"id": uid, "version": "2.11.0", "state": state, "error": error, "at": 1}))


def test_the_result_moves_the_update_on_and_holds_leases_while_it_runs(db):
    r = _requested(db)
    assert coordself.observe_result(db)["state"] == "requested" and coordself.admitting(db)
    (r["up"] / coordself.REQUEST).unlink()                          # the runner took it
    assert coordself.observe_result(db)["state"] == "running" and not coordself.admitting(db)
    from oarbank.coordinator import core
    assert core.claim(db, {"node_id": "n_x"}, {"free_cpu": 8}) == {"grants": []}
    _result(r["up"], r["id"], "done")
    s = coordself.observe_result(db)
    assert s["state"] == "done" and s["finished_at"] and s["error"] is None and coordself.admitting(db)
    assert not (r["up"] / coordself.RESULT).exists() and len(list((r["up"] / "results").iterdir())) == 1
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='coordinator_update_done'")["n"] == 1
    assert coordself.observe_result(db)["state"] == "done"          # read once


def test_a_rollback_or_a_refusal_is_recorded_and_alerted(db):
    for st, why in (("rolled_back", "probation: version 2.10.0, not 2.11.0 after 300 s"), ("refused", "owner signature: bad")):
        r = _requested(db)
        _result(r["up"], r["id"], st, why)
        s = coordself.observe_result(db)
        assert s["state"] == st and s["error"] == why and coordself.admitting(db)
        assert db.one("SELECT reason FROM events WHERE kind=? ORDER BY event_id DESC", (f"coordinator_update_{st}",))["reason"].endswith(why)
        assert db.one("SELECT detail FROM alerts WHERE rule=?", (f"coordinator_update_{st}",))
    (r["up"] / coordself.RESULT).write_text("{not json")
    coordself.observe_result(db)
    assert not (r["up"] / coordself.RESULT).exists()
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='coordinator_update_result_ignored'")["n"] == 1


def test_a_request_no_runner_takes_fails_and_leases_resume(db, monkeypatch):
    r = _requested(db)
    monkeypatch.setattr(coordself, "REQUEST_TTL_S", -1)
    s = coordself.observe_result(db)
    assert s["state"] == "failed" and "trigger" in s["error"] and not (r["up"] / coordself.REQUEST).exists()
    r = _requested(db)
    (r["up"] / coordself.REQUEST).unlink()
    assert coordself.observe_result(db)["state"] == "running"
    monkeypatch.setattr(coordself, "RESULT_TTL_S", -1)
    s = coordself.observe_result(db)
    assert s["state"] == "failed" and "no result" in s["error"] and coordself.admitting(db)


# ------------------------------------------------------------------ the runner

class Health:
    """A coordinator's agent listener as far as probation sees it: GET /v1/health."""

    def __init__(self, doc):
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(outer.doc).encode()
                self.send_response(200 if self.path == "/v1/health" else 404)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        self.doc = doc
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


class FakeServices(coordupdate.Services):
    """The service manager, recorded: `install(root)` starts a health server for the build at root, healthy or not as
    the build's `behavior` says; a healthy new version also writes to the database (its migrations), so a rollback has
    something to undo."""

    def __init__(self, home, programs, root):
        super().__init__(home, programs)
        self.root, self.calls, self.server = Path(root), [], None

    def current_root(self):
        return self.root

    def stop(self):
        self.calls.append("stop")
        if self.server:
            self.server.close()
            self.server = None

    def install(self, root):
        root = Path(root)
        self.calls.append(("install", root.name))
        self.root = root
        if self.server:
            self.server.close()
        m = json.loads((root / "oarbank-coordinator.json").read_text())
        behavior = (root / "behavior").read_text() if (root / "behavior").exists() else "healthy"
        db = sqlite3.connect(self.home / "oarbank.sqlite3")
        db.execute("CREATE TABLE IF NOT EXISTS started (version TEXT)")
        db.execute("INSERT INTO started VALUES (?)", (m["version"],))
        db.commit()
        db.close()
        self.server = Health({"version": m["version"], "started_at": time.time(), "migrated": True,
                              "ticking": behavior == "healthy", "role": "active"})

    def health_url(self):
        return f"http://127.0.0.1:{self.server.port if self.server else 9}/v1/health"

    def ssl_context(self):
        return None

    def close(self):
        if self.server:
            self.server.close()


class Machine:
    """A coordinator machine in a scratch tree: the home (its database, spool and artifacts), the programs with 2.10.0
    installed as `current`, the runner's state, and the recorded services."""

    def __init__(self, tmp: Path, trust: str = "unsigned", keys: list | None = None):
        self.tmp, self.home, self.state, self.programs = tmp, tmp / "home", tmp / "state", tmp / "programs"
        for d in (self.home / "updates" / "artifacts", self.programs):
            d.mkdir(parents=True)
        old = self.programs / "2.10.0-000000000000"
        with tarfile.open(archive(tmp / "old.tar.gz", "2.10.0")) as t:
            t.extractall(old, filter="data")
        os.symlink(old.name, self.programs / "current")
        db = sqlite3.connect(self.home / "oarbank.sqlite3")
        db.execute("CREATE TABLE jobs (job_id INTEGER PRIMARY KEY, name TEXT)")
        db.executemany("INSERT INTO jobs(name) VALUES (?)", [(f"j{i}",) for i in range(50)])
        db.commit()
        db.close()
        self.svc = FakeServices(self.home, self.programs, old)
        self.svc.install(old)                                       # 2.10.0 runs
        self.svc.calls.clear()
        self.before = self.dump()
        if trust == "unsigned":
            coordupdate.pin_trust(self.state, self.home, True, "test")
        elif trust == "signed":
            self.state.mkdir(mode=0o700)
            coordupdate.write_atomic(self.state / "trust.json", json.dumps(
                {"format": 1, "mode": "signed", "fleet_id": "fleet_t", "owner_version": 1, "owner_keys": keys}))

    def dump(self) -> list:
        c = sqlite3.connect(self.home / "oarbank.sqlite3")
        try:
            return list(c.iterdump())
        finally:
            c.close()

    def request(self, version="2.11.0", behavior="healthy", seq=21100, signature=None, uid="cu_1", platform=PLATFORM,
                claims=None, **over):
        """The spool request for a build of `version`; `claims` is the version the request says (default the same)."""
        art = archive(self.tmp / f"b-{version}-{behavior}-{platform}.tar.gz", version, platform=platform, behavior=behavior)
        data = art.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        (self.home / "updates" / "artifacts" / sha).write_bytes(data)
        text = manifest_for(version, seq, art, platform=platform)
        req = {"id": uid, "version": claims or version, "sha256": sha, "size": len(data), "archive": f"updates/artifacts/{sha}",
               "manifest": text, "signature": signature(text) if callable(signature) else signature,
               "snapshot": "updates/snapshots/x.sqlite3", "from_version": "2.10.0", "requested_at": time.time(), **over}
        (self.home / "updates" / coordupdate.REQUEST).write_text(json.dumps(req))
        self.sha = sha
        return req

    def runner(self, **kw):
        return coordupdate.Runner(self.home, self.state, self.programs, svc=self.svc, probation_s=kw.pop("probation_s", 6.0),
                                  hold_s=kw.pop("hold_s", 0.3), poll_s=0.05, platform=PLATFORM, log=lambda line: None, **kw)

    def result(self) -> dict:
        return json.loads((self.home / "updates" / coordupdate.RESULT).read_text())

    def journal(self) -> dict:
        return json.loads((self.state / "journal.json").read_text())

    def current(self) -> str:
        return coordupdate.link_name(self.programs / "current", self.programs)


@pytest.fixture
def machine(tmp_path):
    made = []

    def make(**kw):
        m = Machine(tmp_path / f"m{len(made)}", **kw)
        made.append(m)
        return m
    yield make
    for m in made:
        m.svc.close()


def test_a_healthy_new_version_is_committed(machine):
    m = machine()
    req = m.request()
    assert m.runner().once() == "done", m.result()
    new = f"2.11.0-{m.sha[:12]}"
    assert m.result()["state"] == "done" and m.result()["id"] == "cu_1" and m.result()["error"] is None
    assert m.svc.calls == ["stop", ("install", new)] and m.current() == new
    j = m.journal()
    assert j["active"] is None and j["committed_seq"] == 21100 and j["committed_version"] == "2.11.0" and "cu_1" in j["finished"]
    assert (m.programs / "2.10.0-000000000000").is_dir()            # the previous programs stay (14 days)
    assert (m.state / "db-cu_1.sqlite3").is_file() and not list((m.state / "incoming").iterdir())
    assert not (m.home / "updates" / coordupdate.REQUEST).exists()
    if os.name == "posix":
        assert (m.state / "journal.json").stat().st_mode & 0o777 == 0o600
        assert not any(os.stat(os.path.join(d, f)).st_mode & 0o022 for d, _, fs in os.walk(m.programs / new) for f in fs)
    # the same request again is ignored; nothing to do is nothing
    (m.home / "updates" / coordupdate.REQUEST).write_text(json.dumps(req))
    assert m.runner().once() == "ignored" and m.runner().once() is None and len(m.svc.calls) == 2


def test_a_version_that_never_becomes_healthy_is_rolled_back(machine):
    m = machine()
    m.request(behavior="never")
    assert m.runner().once() == "rolled_back"
    new = f"2.11.0-{m.sha[:12]}"
    assert m.svc.calls == ["stop", ("install", new), "stop", ("install", "2.10.0-000000000000")]
    r = m.result()
    assert r["state"] == "rolled_back" and "the background tick is not running" in r["error"] and "probation" in r["error"]
    assert m.current() == "2.10.0-000000000000"
    # the database is the root's copy again: what the new version wrote is gone (the old one's start wrote its row)
    copy = sqlite3.connect(m.state / "db-cu_1.sqlite3")
    assert [r for r in copy.iterdump()] == m.before
    copy.close()
    after = m.dump()
    assert [x for x in after if "2.11.0" in x] == [] and after.count("INSERT INTO \"started\" VALUES('2.10.0');") == 2
    assert not (m.home / "oarbank.sqlite3-wal").exists() and m.journal()["committed_seq"] == 0


def test_refusals_change_nothing(machine):
    key, pub = keypair()
    other, _ = keypair()
    m = machine(trust="signed", keys=[pub])
    cases = [
        (dict(signature=lambda text: sign(other, text, "2.11.0", 21100)), "does not verify under the owner keys"),
        (dict(signature=None), "no owner signature"),
        (dict(signature=lambda text: sign(key, text, "2.11.0", 21099)), "another version or seq"),
        (dict(signature=lambda text: sign(key, text, "2.11.0", 21100), platform="plan9-mips"), "names no coordinator build"),
        (dict(signature=lambda text: sign(key, text, "2.11.0", 21100), size=7), "names no coordinator build"),
        (dict(signature=lambda text: sign(key, text, "2.11.0", 21100), claims="2.12.0"), "not a fleet release of this version"),
        (dict(signature=lambda text: sign(key, text, "2.11.0", 21100), id="../../etc"), "id is invalid"),
    ]
    for i, (kw, why) in enumerate(cases):
        kw = {"uid": f"cu_r{i}", **kw}
        m.request(**kw)
        assert m.runner().once() == "refused", why
        assert why in m.result()["error"], (why, m.result())
        assert not (m.home / "updates" / coordupdate.REQUEST).exists()
    # tampered bytes: the copy is checked, never the spool's file
    m.request(uid="cu_t", signature=lambda text: sign(key, text, "2.11.0", 21100))
    (m.home / "updates" / "artifacts" / m.sha).write_bytes(b"x" * 10)
    assert m.runner().once() == "refused" and "does not match its sha256 and size" in m.result()["error"]
    assert m.svc.calls == [] and m.current() == "2.10.0-000000000000" and m.dump() == m.before
    # a signed release passes; a replay of an older seq afterwards does not
    m.request(uid="cu_ok", signature=lambda text: sign(key, text, "2.11.0", 21100))
    assert m.runner().once() == "done"
    m.request(uid="cu_old", version="2.10.5", seq=21050, signature=lambda text: sign(key, text, "2.10.5", 21050))
    assert m.runner().once() == "refused" and "below the committed 21100" in m.result()["error"]
    # no trust at all
    (m.state / "trust.json").unlink()
    m.request(uid="cu_nt")
    assert m.runner().once() == "refused" and "no update trust" in m.result()["error"]


@pytest.mark.parametrize("step", ["verified", "stopped", "copied", "installed", "probation", "committing"])
def test_a_runner_that_dies_resumes_from_its_journal(machine, step):
    m = machine()
    m.request()
    with pytest.raises(coordupdate.Crash):
        m.runner(crash_at=step).once()
    assert m.journal()["active"]["step"] == step and not (m.home / "updates" / coordupdate.REQUEST).exists()
    assert m.runner().once() == ("done" if step == "committing" else "rolled_back")
    r = m.result()
    j = m.journal()
    assert j["active"] is None
    if step == "committing":
        assert r["state"] == "done" and m.current() == f"2.11.0-{m.sha[:12]}" and j["committed_seq"] == 21100
        return
    assert r["state"] == "rolled_back" and f"stopped during {step}" in r["error"] and "not healthy" not in r["error"]
    assert m.current() == "2.10.0-000000000000" and m.svc.root.name == "2.10.0-000000000000" and j["committed_seq"] == 0
    restored = [x for x in m.dump() if "started" not in x]
    assert restored == [x for x in m.before if "started" not in x]
    if step in ("copied", "installed", "probation"):                # the copy was complete: it is what runs now
        assert not [x for x in m.dump() if "2.11.0" in x]


def test_the_trust_pin_comes_from_the_home_once(tmp_path):
    home, state = tmp_path / "home", tmp_path / "state"
    d = DB(home / "oarbank.sqlite3")
    with pytest.raises(SystemExit, match="no owner keys"):
        coordupdate.pin_trust(state, home, False, "test")
    _, pub = keypair()
    d.set_state("release_pubkey", pub)
    d.set_state("fleet_id", "fleet_abc")
    d.conn.close()
    assert coordupdate.main(["trust", "--from-home", "--home", str(home), "--state", str(state)]) == 0
    t = json.loads((state / "trust.json").read_text())
    assert t["mode"] == "signed" and t["owner_keys"] == [pub] and t["fleet_id"] == "fleet_abc" and t["pinned_by"]
    if os.name == "posix":
        assert state.stat().st_mode & 0o777 == 0o700 and (state / "trust.json").stat().st_mode & 0o777 == 0o600
    assert coordupdate.pin_trust(state, home, False, "again") is None              # only when none exists
    assert coordupdate.pin_trust(state, home, True, "admin")["mode"] == "unsigned"  # an explicit choice replaces it


@posix_only
def test_coordself_and_the_runner_end_to_end(db, v, tmp_path, machine):
    """oarbankd's request, the runner's swap (recorded services), the result read back by oarbankd."""
    m = machine()
    store(db, v, archive(tmp_path / "b.tar.gz", v))
    s = coordself.request(db, v, "alice")
    r = coordupdate.Runner(Path(db.path).parent, m.state, m.programs, svc=m.svc, probation_s=1.5, hold_s=0.2, poll_s=0.05,
                           platform=PLATFORM, log=lambda line: None)
    m.svc.home = Path(db.path).parent
    assert r.once() == "done"
    assert coordself.observe_result(db)["state"] == "done" and coordself.state(db)["update_id"] == s["update_id"]


@posix_only
def test_links_planted_in_the_spool_send_no_write_or_read_elsewhere(machine):
    """The coordinator's account owns the spool: a link where the runner reads or writes is refused, never followed."""
    m = machine()
    victim = m.tmp / "victim"
    victim.write_text("root's file\n")
    up = m.home / "updates"
    os.symlink(victim, up / f".{coordupdate.RESULT}.tmp")              # where the result's temporary file goes
    m.request(uid="cu_l1")
    os.unlink(up / "artifacts" / m.sha)
    os.symlink("/dev/zero", up / "artifacts" / m.sha)                  # an endless "build"
    assert m.runner().once() == "refused" and "no build at" in m.result()["error"]          # O_NOFOLLOW
    assert victim.read_text() == "root's file\n" and not (up / f".{coordupdate.RESULT}.tmp").exists()
    os.symlink("/dev/zero", up / coordupdate.REQUEST)                  # an endless request
    assert m.runner().once() == "refused" and "cannot read" in m.result()["error"]
    os.symlink(victim, up / coordupdate.REQUEST)
    assert m.runner().once() == "refused" and victim.read_text() == "root's file\n"
    for side in ("-wal", "-shm"):                                      # never chowned through
        os.symlink(victim, m.home / f"oarbank.sqlite3{side}")
    coordupdate._fix_sidecars(m.home / "oarbank.sqlite3", {"uid": 0, "gid": 0, "mode": 0o600})
    assert victim.read_text() == "root's file\n" and m.svc.calls == []
