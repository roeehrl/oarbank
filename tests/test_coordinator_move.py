"""Moving the coordinator (docs/design/coordinator-move.md), the oarbankd side: the identity proof, the epoch fence,
frozen gating, the move statement, cancel and abort, the audit key handover, and a whole move between two
coordinators in process (A and B are two databases joined by test clients)."""
import base64
import hashlib
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from oarbank.coordinator import audit, coordmove, core, identity, movepull, ops
from oarbank.coordinator import app as fapp

from helpers import agent_client, enrolled_node, fresh, make_db, node_headers


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "a" / "oarbank.sqlite3")


@pytest.fixture(autouse=True)
def file_audit_keys(monkeypatch, tmp_path):
    """Never touch the login Keychain in tests: the default audit signer uses a file key per home."""
    real = audit.Signer

    class FileSigner(real):
        def __init__(self, private_key_b64=None):
            if private_key_b64 is None:
                k = tmp_path / f"audit-{id(self) % 7}.key"
                identity.Key(k)
                private_key_b64 = k.read_text().strip()
            real.__init__(self, private_key_b64)
    monkeypatch.setattr(audit, "Signer", FileSigner)
    monkeypatch.setattr(coordmove, "MIN_TIMELOCK_S", 1)


def op(db, name, target=None, **kw):
    return ops.execute(db, ops.OpRequest(op=name, actor="test", target=target, **kw))


def planned(db, name, target, params=None, confirm=None, reason="test"):
    plan = op(db, name, target, params=params or {}, dry_run=True)["plan"]
    return op(db, name, plan_id=plan["plan_id"], reason=reason, idempotency_key=plan["plan_id"], confirm=confirm)


# ------------------------------------------------------------------ identity

def test_identity_proof_is_signed_over_the_nonce_and_responses_carry_the_epoch(db):
    c = TestClient(fapp.agent_app(db))
    r = c.get("/v1/identity", params={"nonce": "n-123"})
    assert r.status_code == 200 and r.headers["x-oarbank-epoch"] == "1" and r.headers["x-oarbank-role"] == "active"
    d = r.json()
    p = json.loads(d["payload"])
    assert p["nonce"] == "n-123" and p["epoch"] == 1 and p["role"] == "active" and p["fleet_id"].startswith("fleet_")
    assert identity.verify(p["cik"], d["payload"], d["sig"])
    assert not identity.verify(p["cik"], d["payload"].replace("n-123", "n-124"), d["sig"])
    assert c.get("/v1/identity", params={"nonce": "x" * 200}).status_code == 400
    _, node = enrolled_node(db)
    assert core.hello(db, node, {"live_attempts": []})["coordinator"]["cik"] == p["cik"]     # what the agent pins


def test_agent_reports_the_key_it_pinned_and_the_owner_confirms_it(db):
    _, node = enrolled_node(db, "mini")
    fp = identity.key(Path(db.path).parent).fingerprint
    core.heartbeat(db, fresh(db, node), {"attempts": [], "cik_pinned": "f" * 64})
    with pytest.raises(core.ApiError, match="identity_mismatch|pinned"):
        op(db, "nodes.confirm_identity", "mini", reason="t")
    core.heartbeat(db, fresh(db, node), {"attempts": [], "cik_pinned": fp})
    op(db, "nodes.confirm_identity", "mini", reason="t")
    assert fresh(db, node)["cik_confirmed"] == fp


# ------------------------------------------------------------------ a whole move, in process

def setup_move(tmp_path, db):
    a_client = agent_client(db, base_url="http://testserver")
    db_b = make_db(tmp_path / "b" / "oarbank.sqlite3", modules=())
    identity.ensure(db_b)
    identity.set_role(db_b, "standby")
    plan = coordmove.prepare(db, "http://testclient:7443", "test")
    puller = movepull.Puller(db_b, tmp_path / "b", from_url="http://testserver", code=plan["pair_code"],
                             my_url="http://testclient:7443", client=a_client)
    b_app = fapp.agent_app(db_b, puller)
    b_client = TestClient(b_app)
    return a_client, db_b, puller, b_client, plan


def test_a_whole_move_hands_the_fleet_to_b_with_identical_data(tmp_path, db, monkeypatch):
    der, node = enrolled_node(db, "mini")
    # a dataset registered from a file outside the coordinator's home (as a module's archive is)
    ext = tmp_path / "outside" / "archive.bin"
    ext.parent.mkdir()
    ext.write_bytes(b"archive bytes" * 1000)
    ext_digest = hashlib.sha256(ext.read_bytes()).hexdigest()
    db.x("INSERT INTO blobs(digest,path,size) VALUES(?,?,?)", (ext_digest, str(ext), ext.stat().st_size))
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    puller.tick()                                   # pair, then seed: files and a seed snapshot of every database
    assert puller.st["phase"] == "seeded" and coordmove.plan(db)["state"] == "paired"
    assert (tmp_path / "b" / "move" / "staging" / "databases" / "oarbank.sqlite3").exists()

    # the statement: signed by A and by B (B checks it names itself, the paired A and the next epoch)
    def sign_b(stmt):
        return puller.sign_statement(stmt)
    m = coordmove.request_move(db, "test", "test move", timelock_s=1, sign_b=sign_b)
    doc = json.loads(m["statement"])
    assert doc["epoch"] == 2 and doc["to"]["cik"] == identity.key(tmp_path / "b").public_b64
    assert identity.verify(doc["from"]["cik"], m["statement"], m["sig_from"])
    assert identity.verify(doc["to"]["cik"], m["statement"], m["sig_to"])
    d = core.heartbeat(db, fresh(db, node), {"attempts": []})
    assert d["coordinator_move"]["statement"] == m["statement"]          # agents see it as pending

    # A->B calls (sign-statement was local above; promote goes to B's app with A's signature)
    def to_b(p, path, body, db_, timeout=60):
        payload = identity.canonical({**body, "ts": int(time.time()), "plan_id": p["plan_id"]})
        r = b_client.post(path, content=payload, headers={"x-oarbank-move-sig": identity.key(Path(db_.path).parent).sign(payload)})
        assert r.status_code == 200, r.text
        return r.json()
    monkeypatch.setattr(coordmove, "_signed_post", to_b)
    exits = []
    monkeypatch.setattr(movepull.os, "_exit", lambda code: exits.append(code))
    import threading
    started = []
    real_thread = threading.Thread

    def fake_thread(*a, **kw):                      # only B's promote thread is captured; module hosts run for real
        if kw.get("name") != "oarbankd-promote":
            return real_thread(*a, **kw)
        started.append((kw["target"], kw["args"]))
        return type("T", (), {"start": lambda self: None})()
    monkeypatch.setattr(threading, "Thread", fake_thread)

    time.sleep(1.1)
    coordmove.driver_tick(db)                       # -> draining (leases carried)
    assert coordmove.phase(db) == "draining" and not coordmove.accepting_leases(db)
    assert core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32})["grants"] == []
    coordmove.driver_tick(db)                       # -> frozen -> final snapshot -> final_ready
    assert coordmove.phase(db) == "final_ready"
    assert a_client.post("/v1/agent/hello", json={}, headers=node_headers(der)).status_code == 503
    with pytest.raises(core.ApiError, match="coordinator_moving"):
        op(db, "fleet.pause", reason="t")
    puller.tick()                                   # B: final copy, verify, ready -> A tells B to promote
    assert coordmove.phase(db) == "promoting" and started
    target, args = started[0]
    target(*args)                                   # B asks A for the commit decision, installs, "restarts"
    assert exits == [movepull.RESTART_EXIT]
    assert identity.role(db) == "handed_off" and (Path(db.path).parent / identity.MARKER).exists()
    # A only redirects now, with the signed statement
    r = a_client.post("/v1/agent/hello", json={}, headers=node_headers(der))
    assert r.status_code == 410 and r.json()["coordinator_move"]["statement"] == m["statement"]
    assert a_client.get("/v1/coordinator/moves", params={"since_epoch": 1}).json()["moves"][0]["statement"] == m["statement"]

    # B restarts on the installed copy: active at epoch 2, same data
    db_b2 = make_db_plain(tmp_path / "b" / "oarbank.sqlite3")
    assert movepull.finish_install(db_b2, tmp_path / "b")
    assert identity.role(db_b2) == "active" and identity.epoch(db_b2) == 2
    a_counts = coordmove.invariants(Path(db.path).parent / "move" / "snapshots" /
                                    json.loads(coordmove.move(db)["final_snapshot_json"])["databases"]["oarbank.sqlite3"]["file"])["counts"]
    b_counts = {t: db_b2.one(f'SELECT COUNT(*) n FROM "{t}"')["n"] for t in a_counts}
    assert {t: n for t, n in a_counts.items() if t not in ("settings", "events", "coordinator_moves")} == \
           {t: n for t, n in b_counts.items() if t not in ("settings", "events", "coordinator_moves")}
    assert db_b2.one("SELECT state FROM coordinator_moves WHERE move_id=?", (m["move_id"],))["state"] == "committed"
    assert audit.verify(db_b2)["ok"]               # the chain continues across the move (handoff record included)
    # stored paths inside the home are relative, so they hold on B unchanged; the external blob moved in
    home_b = (tmp_path / "b").resolve()
    assert db_b2.one("SELECT path FROM blobs WHERE digest=?", (ext_digest,))["path"] == "external/" + ext_digest
    assert hashlib.sha256(db_b2.abs("external/" + ext_digest).read_bytes()).hexdigest() == ext_digest
    home_a = str(Path(db.path).parent.resolve())
    for table in ("blobs", "modules", "agent_builds"):
        stale = db_b2.q(f"SELECT path FROM {table} WHERE path LIKE ?", (home_a + "/%",))
        assert not stale, (table, stale[:2])       # nothing points into A's home
    for r in db_b2.q("SELECT path FROM modules"):
        assert not Path(r["path"]).is_absolute() and (home_b / r["path"]).is_dir()
    assert db_b2.one("SELECT operation FROM audit WHERE operation='coordinator.handoff'")


def make_db_plain(path):
    from oarbank.coordinator.db import DB
    return DB(path)


def test_cancel_thaws_and_agents_get_a_signed_cancel(tmp_path, db):
    _, node = enrolled_node(db, "mini")
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    puller.tick()
    m = coordmove.request_move(db, "test", "t", timelock_s=3600, sign_b=puller.sign_statement)
    op(db, "coordinator.cancel", reason="changed my mind")
    d = core.heartbeat(db, fresh(db, node), {"attempts": []})
    assert "coordinator_move" not in d
    c = d["coordinator_move_cancel"]
    assert json.loads(c["payload"])["move_id"] == m["move_id"]
    assert identity.verify(identity.key(Path(db.path).parent).public_b64, c["payload"], c["sig"])
    assert coordmove.phase(db) == "idle" and identity.role(db) == "active"


def test_a_copy_that_differs_aborts_the_move_and_a_keeps_serving(tmp_path, db, monkeypatch):
    enrolled_node(db, "mini")
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    puller.tick()
    puller.tick()
    coordmove.request_move(db, "test", "t", timelock_s=1, sign_b=puller.sign_statement)
    time.sleep(1.1)
    coordmove.driver_tick(db)
    coordmove.driver_tick(db)
    p = coordmove.plan(db)
    with pytest.raises(coordmove.MoveError, match="verification failed"):
        coordmove.ready(db, {"databases": {"oarbank.sqlite3": {"sha256": "bad", "integrity": "ok"}}, "files": {}}, p)
    assert coordmove.phase(db) == "idle" and identity.role(db) == "active"
    assert coordmove.move(db)["state"] == "aborted"


def test_the_time_lock_has_a_floor_and_short_locks_need_a_reason(tmp_path, db, monkeypatch):
    monkeypatch.setattr(coordmove, "MIN_TIMELOCK_S", 900)
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    puller.tick()
    with pytest.raises(coordmove.MoveError, match="at least 900"):
        coordmove.request_move(db, "test", "r", timelock_s=60, sign_b=puller.sign_statement)
    with pytest.raises(coordmove.MoveError, match="needs a reason"):
        coordmove.request_move(db, "test", None, timelock_s=900, sign_b=puller.sign_statement)


def test_b_refuses_to_sign_a_statement_that_does_not_name_it(tmp_path, db):
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    puller.tick()
    bad = identity.canonical({"type": identity.MOVE_TYPE, "fleet_id": puller.st["fleet_id"], "epoch": 2,
                              "from": {"cik": puller.st["a_cik"]}, "to": {"cik": identity.Key(raw=b"\x01" * 32).public_b64}})
    with pytest.raises(movepull.PullError):
        puller.sign_statement(bad)


def test_audit_key_handover_only_at_a_digest_naming_the_next_key(tmp_path):
    from oarbank.coordinator.db import DB
    d = DB(tmp_path / "x" / "oarbank.sqlite3")
    ka, kb, kc = (identity.Key(raw=bytes([i]) * 32) for i in (1, 2, 3))
    sa, sb, sc = (audit.Signer(base64.b64encode(bytes([i]) * 32).decode()) for i in (1, 2, 3))

    def row():
        audit.append(d, actor="t", source="cli", operation="x", category="modify", target_type="t", target_id="1",
                     outcome="ok", request_id=audit.request_id())
    row(); audit.write_digest(d, sa)
    row(); audit.write_digest(d, sa, next_pubkey=sb.public_b64)
    row(); audit.write_digest(d, sb)
    assert audit.verify(d)["ok"]
    row(); audit.write_digest(d, sc)                  # a key nobody handed over to
    assert not audit.verify(d)["ok"]


def test_finalize_waits_out_probation(tmp_path, db, monkeypatch):
    identity.set_role(db, "handed_off")
    db.x("INSERT INTO coordinator_moves(move_id,epoch,statement,state,created_at,ended_at) VALUES('m',2,'{}','committed',?,?)",
         (time.time(), time.time()))
    with pytest.raises(coordmove.MoveError, match="probation"):
        coordmove.finalize(db, "test")
    monkeypatch.setenv("OARBANKD_MOVE_SKIP_PROBATION", "1")
    assert coordmove.finalize(db, "test")["finalized"]


# ------------------------------------------------------------------ owner authority (signing mode)

def owner_keys(tmp_path):
    from oarbank import signing
    files = [tmp_path / f"owner{i}.key" for i in range(3)]
    pubs = [signing.keygen(f) for f in files]
    return files, pubs


def test_owner_key_sets_follow_the_root_rotation_rule(tmp_path, db, monkeypatch):
    pytest.importorskip("cryptography")
    from oarbank import signing
    from oarbank.coordinator import config as C, owner
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    (pk, bk, nk), (p, b, n) = owner_keys(tmp_path)
    fid = identity.fleet_id(db)
    db.set_setting("release_pubkey", p)                       # a fleet already pinned to a release key
    v1 = signing.owner_anchors_statement(fid, 1, [p, b], ["http://100.64.0.9:8080/move.json"])
    sigs = lambda st, *fs: [{"key": signing.public_key_of(f), "sig": signing.sign(st, f)} for f in fs]
    with pytest.raises(core.ApiError, match="every new key"):
        planned(db, "owner.set_anchors", None, {"statement": v1, "signatures": sigs(v1, pk)}, confirm="owner-keys")
    planned(db, "owner.set_anchors", None, {"statement": v1, "signatures": sigs(v1, pk, bk)}, confirm="owner-keys")
    assert owner.keys(db) == [p, b] and owner.required(db)
    # the primary is lost: v2 = {backup, new}, signed by its keys and by the backup (a key of v1)
    v2 = signing.owner_anchors_statement(fid, 2, [b, n])
    lone = signing.owner_anchors_statement(fid, 2, [n])
    with pytest.raises(owner.OwnerError, match="current owner set"):
        owner.check_anchors(db, lone, sigs(lone, nk))
    planned(db, "owner.set_anchors", None, {"statement": v2, "signatures": sigs(v2, bk, nk)}, confirm="owner-keys")
    assert owner.keys(db) == [b, n]
    d = core.heartbeat(db, fresh(db, enrolled_node(db, "mini")[1]), {"attempts": []})
    assert json.loads(d["owner_anchors"]["statement"])["version"] == 2


def test_a_key_outside_the_set_cannot_rotate_it(tmp_path, db, monkeypatch):
    pytest.importorskip("cryptography")
    from oarbank import signing
    from oarbank.coordinator import config as C, owner
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    (pk, bk, nk), (p, b, n) = owner_keys(tmp_path)
    fid = identity.fleet_id(db)
    v1 = signing.owner_anchors_statement(fid, 1, [p, b])
    owner.set_anchors(db, v1, [{"key": k, "sig": signing.sign(v1, f)} for k, f in ((p, pk), (b, bk))], "t")
    v2 = signing.owner_anchors_statement(fid, 2, [n])
    with pytest.raises(owner.OwnerError, match="current owner set"):
        owner.check_anchors(db, v2, [{"key": n, "sig": signing.sign(v2, nk)}])
    with pytest.raises(owner.OwnerError, match="version"):
        owner.check_anchors(db, v1, [{"key": k, "sig": signing.sign(v1, f)} for k, f in ((p, pk), (b, bk))])


def test_in_signing_mode_a_move_waits_for_the_owner(tmp_path, db, monkeypatch):
    pytest.importorskip("cryptography")
    from oarbank import signing
    from oarbank.coordinator import config as C, owner
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    (pk, bk, nk), (p, b, n) = owner_keys(tmp_path)
    fid = identity.fleet_id(db)
    v1 = signing.owner_anchors_statement(fid, 1, [p, b])
    owner.set_anchors(db, v1, [{"key": k, "sig": signing.sign(v1, f)} for k, f in ((p, pk), (b, bk))], "t")
    _, node = enrolled_node(db, "mini")
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    puller.tick()
    m = coordmove.request_move(db, "test", "t", timelock_s=3600, sign_b=puller.sign_statement)
    assert m["state"] == "awaiting_owner"
    assert "coordinator_move" not in core.heartbeat(db, fresh(db, node), {"attempts": []})     # not announced yet
    with pytest.raises(core.ApiError, match="not from an owner key"):
        planned(db, "coordinator.sign_move", None, {"owner_sig": signing.sign(m["statement"], nk)})
    planned(db, "coordinator.sign_move", None, {"owner_sig": signing.sign(m["statement"], bk)})   # the backup works too
    d = core.heartbeat(db, fresh(db, node), {"attempts": []})
    assert d["coordinator_move"]["signatures"]["owner"] and coordmove.move(db)["state"] == "pending"


def test_disabling_signing_needs_an_owner_signed_statement(tmp_path, db, monkeypatch):
    pytest.importorskip("cryptography")
    from oarbank import signing
    from oarbank.coordinator import config as C, owner
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    (pk, bk, nk), (p, b, n) = owner_keys(tmp_path)
    fid = identity.fleet_id(db)
    v1 = signing.owner_anchors_statement(fid, 1, [p, b])
    owner.set_anchors(db, v1, [{"key": k, "sig": signing.sign(v1, f)} for k, f in ((p, pk), (b, bk))], "t")
    dis = signing.owner_disable_statement(fid, 2)
    with pytest.raises(owner.OwnerError, match="owner key"):
        owner.disable(db, dis, [{"key": n, "sig": signing.sign(dis, nk)}], "t")
    owner.disable(db, dis, [{"key": b, "sig": signing.sign(dis, bk)}], "t")
    assert owner.keys(db) == [] and not owner.required(db)
    assert core.heartbeat(db, fresh(db, enrolled_node(db, "mini")[1]), {"attempts": []})["owner_security"]["statement"] == dis


def test_signing_mode_moves_install_only_a_signed_build_for_the_targets_platform(tmp_path, db, monkeypatch):
    """The release-readiness critical: install_coordinator never hands a node an unsigned bundle in signing mode."""
    import io
    import tarfile
    pytest.importorskip("cryptography")
    from oarbank import signing
    from oarbank.coordinator import config as C, coordbuilds
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    key = tmp_path / "owner.key"
    db.set_setting("release_pubkey", signing.keygen(key))
    _, node = enrolled_node(db, "mini")
    with pytest.raises(coordmove.MoveError, match="no signed coordinator build for darwin-arm64"):
        coordmove.prepare(db, "mini", "test")

    def archive(version, platform):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz") as t:
            doc = json.dumps({"format": 1, "version": version, "platform": platform}).encode()
            ti = tarfile.TarInfo("oarbank-coordinator.json")
            ti.size = len(doc)
            t.addfile(ti, io.BytesIO(doc))
        return raw.getvalue()
    linux = coordbuilds.register(db, coordbuilds.stage(archive("1.0.0", "linux-amd64"))["sha256"], "t")
    mac = coordbuilds.register(db, coordbuilds.stage(archive("1.0.0", "darwin-arm64"))["sha256"], "t")
    with pytest.raises(coordmove.MoveError, match="no signed"):
        coordmove.prepare(db, "mini", "test")                             # registered, but not signed
    wrong = signing.coordinator_statement(mac["sha256"], "1.0.0", "linux-amd64", 1)
    with pytest.raises(coordbuilds.BuildError, match="does not name"):
        coordbuilds.attach_signature(db, mac["sha256"], wrong, signing.sign(wrong, key))
    stmt = signing.coordinator_statement(mac["sha256"], "1.0.0", "darwin-arm64", 1)
    coordbuilds.attach_signature(db, mac["sha256"], stmt, signing.sign(stmt, key))
    st_l = signing.coordinator_statement(linux["sha256"], "1.0.0", "linux-amd64", 2)
    coordbuilds.attach_signature(db, linux["sha256"], st_l, signing.sign(st_l, key))
    coordmove.prepare(db, "mini", "test")
    d = json.loads(db.one("SELECT install_coordinator_json FROM nodes WHERE node_id=?", (node["node_id"],))["install_coordinator_json"])
    assert (d["kind"], d["bundle_sha256"], d["platform"]) == ("build", mac["sha256"], "darwin-arm64")
    assert signing.verify_coordinator(d["statement"], d["signature"], db.get_setting("release_pubkey"))["platform"] == "darwin-arm64"
    with pytest.raises(coordbuilds.BuildError):
        coordbuilds.register(db, coordbuilds.stage(b"not an archive")["sha256"], "t")


def test_developer_mode_moves_to_a_node_only_from_a_checkout(tmp_path, db, monkeypatch):
    """Signing off, a node installs the running checkout; a coordinator not run from one refuses the plan."""
    from oarbank.coordinator import config as C, coordbundle
    monkeypatch.setattr(C, "RELEASE_SIGNING", False)
    monkeypatch.setattr(coordbundle, "REPO", tmp_path)
    enrolled_node(db, "mini")
    with pytest.raises(coordmove.MoveError, match="does not run from a git checkout"):
        coordmove.prepare(db, "mini", "test")
    assert coordmove.plan(db) is None


# ------------------------------------------------------------------ coordinator platforms (D33)

def coordinator_here_only(tmp_path) -> Path:
    """The relay fixture, its coordinator side declared for this coordinator's platform only."""
    import shutil
    from oarbank_sdk import portable
    from helpers import RELAY_DIR
    d = tmp_path / "relay-here"
    shutil.copytree(RELAY_DIR, d, ignore=shutil.ignore_patterns("__pycache__", "dist"))
    m = (d / "oarbank-module.toml").read_text().replace(
        'core = ">=2.3,<3"', f'core = ">=2.3,<3"\ncoordinator_platforms = ["{portable.host_platform()}"]')
    (d / "oarbank-module.toml").write_text(m)
    return d


def elsewhere() -> str:
    from oarbank_sdk import portable
    return "windows-arm64" if portable.host_platform() != "windows-arm64" else "linux-amd64"


def test_a_move_to_a_platform_a_modules_coordinator_side_does_not_run_on_needs_force(tmp_path, monkeypatch):
    from helpers import TOY_DIR
    from oarbank.coordinator import modlife
    from oarbank_sdk import portable
    db = make_db(tmp_path / "a" / "oarbank.sqlite3", modules=(TOY_DIR, coordinator_here_only(tmp_path)))
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    assert plan["target_platform"] is None and plan["blocking_modules"] == {}      # a URL target: known when it pairs
    other = elsewhere()
    with monkeypatch.context() as mp:
        mp.setattr(portable, "host_platform", lambda: other)                        # the standby runs on another platform
        puller.tick()
    assert coordmove.plan(db)["target_platform"] == other
    with pytest.raises(coordmove.MoveError, match=f"modules whose coordinator side does not run on {other}: relay \\(its coordinator"):
        coordmove.request_move(db, "test", "t", timelock_s=3600, sign_b=puller.sign_statement)
    impact = op(db, "coordinator.move", params={"timelock_s": 3600}, dry_run=True)["plan"]["impact"]
    assert impact["target_platform"] == other and any(b.startswith("relay: its coordinator side does not run on")
                                                      for b in impact["module_blockers"])
    m = coordmove.request_move(db, "test", "t", timelock_s=3600, sign_b=puller.sign_statement, force=True)
    assert [b["code"] for b in m["modules"]["planned"]["relay"]["blockers"]] == [modlife.PLATFORM_BLOCKER]


def test_pairing_reports_the_standbys_platform(tmp_path, db):
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    body = {"code": plan["pair_code"], "b_url": "http://testclient:7443", "b_cik": "k", "b_audit_pub": "a"}
    with pytest.raises(coordmove.MoveError, match="pairing needs b_platform"):
        coordmove.pair(db, body, "testclient")
    with pytest.raises(coordmove.MoveError, match="not a platform token"):
        coordmove.pair(db, {**body, "b_platform": "plan9"}, "testclient")


def test_preparing_a_move_to_a_node_names_the_modules_it_blocks(tmp_path, monkeypatch):
    from helpers import TOY_DIR, facts_for
    db = make_db(tmp_path / "a" / "oarbank.sqlite3", modules=(TOY_DIR, coordinator_here_only(tmp_path)))
    enrolled_node(db, "box", facts=facts_for(elsewhere()))
    impact = op(db, "coordinator.prepare", "box", dry_run=True)["plan"]["impact"]
    assert impact["target_platform"] == elsewhere() and list(impact["blocking_modules"]) == ["relay"]
    enrolled_node(db, "twin")                                       # the fixture's facts: darwin-arm64
    from oarbank_sdk import portable
    if portable.host_platform() == "darwin-arm64":
        assert op(db, "coordinator.prepare", "twin", dry_run=True)["plan"]["impact"]["blocking_modules"] == "none"


def test_a_forced_move_disables_what_cannot_run_on_the_new_coordinator(tmp_path, monkeypatch):
    from helpers import TOY_DIR
    from oarbank.coordinator import modlife, modstore
    from oarbank_sdk import portable
    db = make_db(tmp_path / "a" / "oarbank.sqlite3", modules=(TOY_DIR, coordinator_here_only(tmp_path)))
    assert modlife.disable_unsupported(db) == []
    other = elsewhere()
    monkeypatch.setattr(portable, "host_platform", lambda: other)
    with db.tx():
        assert modlife.disable_unsupported(db) == ["relay"]
    assert modstore.channel(db, "relay")["disabled"] and not modstore.channel(db, "toy")["disabled"]
    a = db.one("SELECT * FROM alerts WHERE rule='coordinator_platform_unsupported:relay' AND state='open'")
    assert a and f"does not run on {other}" in a["detail"]
