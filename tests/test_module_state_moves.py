"""Module files, integrity checks and the module side of a coordinator move (the toy module shows each:
`notes/` files are carried, `cache/` is rebuilt, the `toy_scratch` store collection is dropped, a `toy_block/now`
document blocks the cutover)."""
import base64
import hashlib
import json
import time
from pathlib import Path

import pytest

from oarbank.coordinator import coordmove, effects, modcalls, modfiles, modlife, movepull, ops

from helpers import enrolled_node, make_db
from test_coordinator_move import file_audit_keys, make_db_plain, op  # noqa: F401 (autouse fixture)
from test_coordinator_move import setup_move as _setup_move


def setup_move(tmp_path, db):
    out = _setup_move(tmp_path, db)
    modcalls.use(db)                                   # one process plays both sides: the catalog is A's
    return out

ALL = {"store.write", "store.delete", "files.write", "files.put", "files.delete"}


@pytest.fixture
def db(tmp_path):
    from oarbank.coordinator import identity
    d = make_db(tmp_path / "a" / "oarbank.sqlite3")
    identity.ensure(d)
    return d


def fx(db, *effs, module="toy"):
    with db.tx():
        return effects.apply(db, module, ALL, list(effs), actor="test")


def write(path, data: bytes):
    return {"kind": "files.write", "args": {"path": path, "content_b64": base64.b64encode(data).decode()}}


def store(coll, key, doc):
    return {"kind": "store.write", "args": {"collection": coll, "key": key, "doc": doc}}


# ------------------------------------------------------------------ files

def test_files_are_named_blobs_read_through_callbacks(db):
    fx(db, write("notes/a.txt", b"alpha"), write("notes/b.txt", b"beta" * 1000))
    cb = modcalls.host_callbacks(db)
    ls = cb["host.files.list"]("toy", {"prefix": "notes/"})["files"]
    assert [f["path"] for f in ls] == ["notes/a.txt", "notes/b.txt"]
    assert ls[0]["digest"] == hashlib.sha256(b"alpha").hexdigest()
    r = cb["host.files.read"]("toy", {"path": "notes/b.txt", "offset": 4, "length": 8})
    assert base64.b64decode(r["content_b64"]) == b"betabeta" and r["size"] == 4000 and not r["eof"]
    assert cb["host.files.stat"]("relay", {"path": "notes/a.txt"})["exists"] is False      # a module sees only its own
    # put names a blob the coordinator holds; delete by prefix
    fx(db, {"kind": "files.put", "args": {"path": "copy/a.txt", "digest": ls[0]["digest"]}})
    assert modfiles.stat(db, "toy", "copy/a.txt")["size"] == 5
    fx(db, {"kind": "files.delete", "args": {"prefix": "notes/"}})
    assert [f["path"] for f in modfiles.listing(db, "toy")] == ["copy/a.txt"]


@pytest.mark.parametrize("eff,code", [
    (write("../escape", b"x"), "bad_file_path"),
    (write("/abs", b"x"), "bad_file_path"),
    (write("big", b"x" * (modfiles.WRITE_MAX + 1)), "file_too_large"),
    ({"kind": "files.put", "args": {"path": "a", "digest": "0" * 64}}, "unknown_blob"),
])
def test_bad_file_effects_are_refused(db, eff, code):
    with pytest.raises(effects.EffectError) as e:
        fx(db, eff)
    assert e.value.code == code


def test_an_undeclared_file_effect_is_refused(db):
    with pytest.raises(effects.EffectError, match="did not declare"):
        with db.tx():
            effects.apply(db, "toy", {"store.write"}, [write("a", b"x")])


# ------------------------------------------------------------------ integrity

def test_integrity_check_runs_the_module_and_the_core_checks(db):
    fx(db, write("notes/a.txt", b"alpha"))
    r = op(db, "modules.check", "toy", reason="t", params={"deep": True})["result"]
    assert r["ok"]
    names = {c["name"] for c in r["modules"]["toy"]["checks"]}
    assert {"core/files_present", "core/files_match_digests", "notes_are_text", "notes_match_digests"} <= names
    assert r["modules"]["toy"]["fingerprint"]
    assert db.one("SELECT ok, scope FROM module_checks WHERE module='toy' ORDER BY check_id DESC LIMIT 1")["scope"] == "on_demand"


def test_routine_check_alerts_on_a_missing_file_and_resolves_when_fixed(db):
    fx(db, write("notes/a.txt", b"alpha"))
    blob = db.abs(db.one("SELECT path FROM blobs WHERE digest=?", (hashlib.sha256(b"alpha").hexdigest(),))["path"])
    blob.chmod(0o644)
    blob.unlink()
    assert modlife.routine(db) >= 1
    a = db.one("SELECT * FROM alerts WHERE rule='integrity_failed:toy' AND state='open'")
    assert a and "files_present" in a["detail"]
    assert modlife.routine(db) == 0                    # at most once a day per module
    modfiles.store_bytes(db, b"alpha")                 # the blob is back
    db.x("DELETE FROM module_checks")
    modlife.routine(db)
    assert not db.one("SELECT 1 FROM alerts WHERE rule='integrity_failed:toy' AND state='open'")


# ------------------------------------------------------------------ the module side of a move

def _to_b(monkeypatch, b_client):
    from oarbank.coordinator import identity

    def to_b(p, path, body, db_, timeout=60):
        payload = identity.canonical({**body, "ts": int(time.time()), "plan_id": p["plan_id"]})
        r = b_client.post(path, content=payload, headers={"x-oarbank-move-sig": identity.key(Path(db_.path).parent).sign(payload)})
        assert r.status_code == 200, r.text
        return r.json()
    monkeypatch.setattr(coordmove, "_signed_post", to_b)
    import threading
    real, started = threading.Thread, []

    def fake(*a, **kw):
        if kw.get("name") != "oarbankd-promote":
            return real(*a, **kw)
        started.append((kw["target"], kw["args"]))
        return type("T", (), {"start": lambda self: None})()
    monkeypatch.setattr(threading, "Thread", fake)
    monkeypatch.setattr(movepull.os, "_exit", lambda code: None)
    return started


def test_modules_block_shape_and_finish_a_move(tmp_path, db, monkeypatch):
    enrolled_node(db, "mini")
    big = b"cache bytes " * 50000                       # rebuilt after the move: never transferred
    fx(db, write("notes/a.txt", b"alpha"), write("cache/big.bin", big), store("toy_scratch", "k", {"x": 1}),
       store("toy_block", "now", {"reason": "mid-round"}))
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    started = _to_b(monkeypatch, b_client)
    puller.tick()
    m = coordmove.request_move(db, "test", "t", timelock_s=1, sign_b=puller.sign_statement)
    mods = coordmove.move(db, m["move_id"])["modules"]
    assert mods["planned"]["toy"]["blockers"][0]["code"] == "toy/blocked"          # shown when the move is requested
    assert {(i["selector"], i["class"]) for i in mods["rules"]} == {("cache/", "rebuild"), ("toy_scratch", "drop")}

    time.sleep(1.1)
    coordmove.driver_tick(db)                           # draining; the toy blocks
    coordmove.driver_tick(db)
    assert coordmove.phase(db) == "draining" and db.get_setting("move_blockers") == ["toy: mid-round"]
    fx(db, {"kind": "store.delete", "args": {"collection": "toy_block", "key": "now"}})
    db.set_setting("move_preflight_at", 0)
    coordmove.driver_tick(db)                           # unblocked -> frozen -> final snapshot
    assert coordmove.phase(db) == "final_ready"
    snap = json.loads(coordmove.move(db)["final_snapshot_json"])
    assert snap["modules"]["toy"]["ok"] and snap["modules"]["toy"]["fingerprint"]
    big_digest = hashlib.sha256(big).hexdigest()
    assert not any(big_digest in f["path"] for f in coordmove.manifest(db)["files"])

    puller.tick()                                       # B verifies the module state on its copy, reports ready
    assert coordmove.phase(db) == "promoting"
    rep = coordmove.move(db)["report"]["modules"]["toy"]
    assert rep["a"]["fingerprint"] == rep["b"]["fingerprint"]
    target, args = started[0]
    target(*args)

    db_b2 = make_db_plain(tmp_path / "b" / "oarbank.sqlite3")
    assert movepull.finish_install(db_b2, tmp_path / "b")
    assert [f["path"] for f in modfiles.listing(db_b2, "toy")] == ["notes/a.txt"]
    assert not db_b2.one("SELECT 1 FROM module_store WHERE module='toy' AND collection='toy_scratch'")
    assert not db_b2.one("SELECT 1 FROM blobs WHERE digest=?", (big_digest,))
    assert db_b2.get_setting("move_postflight_pending")["move_id"] == m["move_id"]
    modcalls.use(db_b2)
    out = modlife.postflight(db_b2)                     # the toy rebuilds its cache and records the move
    assert out["toy"]["ok"] and db_b2.get_setting("move_postflight_pending") is None
    doc = json.loads(db_b2.one("SELECT doc_json FROM module_store WHERE module='toy' AND collection='toy_moves' AND key=?",
                               (m["move_id"],))["doc_json"])
    assert doc["postflight"] and doc["rebuilt"] == ["cache/"]
    assert base64.b64decode(modfiles.read(db_b2, "toy", "cache/rebuilt.txt")["content_b64"]).startswith(b"rebuilt after")
    assert modlife.check(db_b2, "toy", deep=True)["ok"]
    modcalls.use(db)


def test_a_module_state_mismatch_aborts_and_modules_hear_the_cancel(tmp_path, db, monkeypatch):
    enrolled_node(db, "mini")
    fx(db, write("notes/a.txt", b"alpha"))
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    _to_b(monkeypatch, b_client)
    puller.tick()
    m = coordmove.request_move(db, "test", "t", timelock_s=1, sign_b=puller.sign_statement)
    time.sleep(1.1)
    coordmove.driver_tick(db)
    coordmove.driver_tick(db)
    real = movepull.verify_modules
    monkeypatch.setattr(movepull, "verify_modules", lambda s, mid=None: {**real(s, mid), "toy": {"ok": True, "fingerprint": "f" * 64}})
    with pytest.raises(movepull.PullError, match="module verification failed"):
        puller.tick()                                   # B reports a different fingerprint: A aborts and thaws
    assert coordmove.phase(db) == "idle" and coordmove.move(db, m["move_id"])["state"] == "aborted"
    doc = db.one("SELECT doc_json FROM module_store WHERE module='toy' AND collection='toy_moves' AND key=?", (m["move_id"],))
    assert "differs" in json.loads(doc["doc_json"])["cancelled"]


@pytest.mark.parametrize("force", [False, True])
def test_a_blocker_that_outlasts_the_wait_aborts_unless_forced(tmp_path, db, monkeypatch, force):
    enrolled_node(db, "mini")
    fx(db, store("toy_block", "now", {"reason": "busy"}))
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    _to_b(monkeypatch, b_client)
    puller.tick()
    monkeypatch.setattr(modlife, "BLOCKER_WAIT_S", 0)
    m = coordmove.request_move(db, "test", "t", timelock_s=1, sign_b=puller.sign_statement, force=force)
    time.sleep(1.1)
    coordmove.driver_tick(db)
    time.sleep(0.01)
    coordmove.driver_tick(db)
    if force:
        assert coordmove.phase(db) == "final_ready" and coordmove.move(db, m["move_id"])["force"] == 1
    else:
        assert coordmove.move(db, m["move_id"])["state"] == "aborted" and coordmove.phase(db) == "idle"


def test_the_move_preview_shows_module_blockers_and_rules(tmp_path, db, monkeypatch):
    enrolled_node(db, "mini")
    fx(db, store("toy_block", "now", {"reason": "busy"}), write("cache/x", b"x"))
    a_client, db_b, puller, b_client, plan = setup_move(tmp_path, db)
    puller.tick()
    impact = ops._move_modules(db, coordmove.plan(db), 3600, type("R", (), {"params": {}})())
    assert impact["module_blockers"] == ["toy: busy"]
    assert any("cache/ rebuild" in x for x in impact["module_rules"])


# ------------------------------------------------------------------ isolation between modules (release-readiness high)

def fx_any(db, *effs, module="toy"):
    with db.tx():
        return effects.apply(db, module, ALL | {"datasets.create"}, list(effs), actor="test")


def test_a_module_cannot_reach_another_modules_blobs_or_datasets(db):
    fx(db, write("secret.txt", b"relay's secret"), module="relay")
    digest = hashlib.sha256(b"relay's secret").hexdigest()
    with pytest.raises(effects.EffectError, match="unknown_blob"):
        fx(db, {"kind": "files.put", "args": {"path": "stolen.txt", "digest": digest}}, module="toy")
    with pytest.raises(effects.EffectError, match="unknown_blob"):
        fx_any(db, {"kind": "datasets.create", "args": {"dataset_id": "toy:x", "kind": "practice",
                                                    "files": [{"path": "s", "digest": digest, "size": 14}]}}, module="toy")
    with pytest.raises(effects.EffectError, match="dataset_owned"):        # relay's (and the operator's) datasets
        fx_any(db, {"kind": "datasets.create", "args": {"dataset_id": "demo:atrium", "kind": "practice", "files": []}}, module="toy")
    cb = modcalls.host_callbacks(db)
    assert cb["host.blobs.stat"]("toy", {"digest": digest}) == {"exists": False, "size": None}
    assert cb["host.blobs.stat"]("relay", {"digest": digest})["exists"]
    assert not [d for d in cb["host.datasets.query"]("toy", {"limit": 100})["datasets"] if d["id"] == "demo:atrium"]
    assert [d for d in cb["host.datasets.query"]("relay", {"limit": 100})["datasets"] if d["id"] == "demo:atrium"]
    fx(db, {"kind": "files.put", "args": {"path": "copy.txt", "digest": digest}}, module="relay")   # its own: fine
