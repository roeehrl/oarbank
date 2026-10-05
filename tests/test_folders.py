"""Folder grants on the coordinator (docs/design/datasets-media-checkpoints.md, #10 "Folder grants"): a module version asks
for folders by id and an operator approves them; the folder registry maps each id to a path per node; each node gets a
folder statement with a rising seq (signed by the owner in signing mode); placement follows what the node reports for
the statement it applied (FOLDER_UNAVAILABLE otherwise); releases carry only the ids."""
import base64
import json
import shutil
import tomllib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oarbank.coordinator import core, explain, folders, modsandbox, modstore, ops, releases

from helpers import FACTS, SEATBELT, enrolled_node, fresh, install, make_db, run_op

REEL_DIR = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "reel"
FOLDERS = [{"id": "inputs", "access": "read"}, {"id": "outbox", "access": "write"}]


@pytest.fixture
def reel_with_folders(tmp_path):
    """reel, asking for an input folder and an outbox."""
    d = tmp_path / "reel"
    shutil.copytree(REEL_DIR, d, ignore=shutil.ignore_patterns("__pycache__"))
    text = (d / "oarbank-module.toml").read_text(encoding="utf-8")
    text += '\n[sandbox]\nfolders = [{ id = "inputs", access = "read" }, { id = "outbox", access = "write" }]\n'
    (d / "oarbank-module.toml").write_text(text)
    assert tomllib.loads(text)["sandbox"]["folders"] == FOLDERS
    return d


@pytest.fixture
def db(tmp_path, reel_with_folders):
    d = make_db(tmp_path / "oarbank.sqlite3")
    r = install(d, reel_with_folders, enable=False)
    modsandbox.approve(d, "reel", r["version"], "test", None)
    modstore.enable(d, "reel", r["version"])
    from oarbank.coordinator import modcalls
    modcalls.use(d)
    releases.sync(d)
    return d


FACTS_FOLDERS = {**FACTS, "sandbox": {"backend": "seatbelt", "enforcement": {**SEATBELT, "folders.read": "enforced",
                                                                               "folders.write": "enforced"}}}


def test_the_approval_names_each_folder_and_its_access(db):
    st = modsandbox.status(db, "reel", "0.1.0")
    assert st["requests"]["folders"] == FOLDERS and st["approved"]
    text = modsandbox.describe(st["requests"])
    assert "reads folder inputs" in text and "writes into folder outbox (files it creates may replace files there)" in text


def test_the_release_carries_folder_ids_never_paths(db):
    rid = db.one("SELECT release_id FROM releases WHERE status='current'")["release_id"]
    manifest = json.loads(db.one("SELECT manifest_json FROM releases WHERE release_id=?", (rid,))["manifest_json"] or "{}")
    entry = releases.module_entry("reel", "0.1.0", "h2:x", modstore.record(db, "reel", "0.1.0")["path"])
    assert entry["sandbox"]["folders"] == FOLDERS and entry["default_stage"] == "render"
    assert entry["stages"][0]["checkpoint"] == {"max_mb": 64, "min_interval_s": 30.0}
    assert entry["runner"]["checkpoint_grace_s"] == 30
    assert manifest is not None


def test_the_registry_makes_one_statement_per_node_with_a_rising_seq(db):
    _, a = enrolled_node(db, "a", FACTS_FOLDERS)
    _, b = enrolled_node(db, "b", FACTS_FOLDERS)
    r = run_op(db, "settings.folders.update", "inputs", params={"access": "read", "nodes": {a["node_id"]: "/Users/me/in/"}})
    assert r["result"]["statements"] == [a["node_id"]]
    st = json.loads(folders.statement(db, a["node_id"])["statement"])
    assert st["type"] == "oarbank.folders/v1" and st["seq"] == 1 and st["folders"] == {"inputs": {"access": "read", "path": "/Users/me/in"}}
    assert folders.statement(db, b["node_id"]) is None
    run_op(db, "settings.folders.update", "outbox", params={"access": "write", "nodes": {a["node_id"]: "/Users/me/out", b["node_id"]: "/srv/out"}})
    assert json.loads(folders.statement(db, a["node_id"])["statement"])["seq"] == 2
    run_op(db, "settings.folders.update", "outbox", params={"access": "write", "nodes": {a["node_id"]: None}})
    assert json.loads(folders.statement(db, a["node_id"])["statement"])["folders"] == {"inputs": {"access": "read", "path": "/Users/me/in"}}
    d = core.heartbeat(db, fresh(db, a), {"attempts": [], "ready_datasets": []})
    assert json.loads(d["folders"]["statement"])["seq"] == 3 and d["folders"]["signature"] is None
    for bad in [{"access": "exec", "nodes": {}}, {"access": "read", "nodes": {a["node_id"]: "relative/path"}},
                {"access": "read", "nodes": {a["node_id"]: "/"}}, {"access": "read", "nodes": {a["node_id"]: "/x/../etc"}},
                {"access": "read", "nodes": {"n_nobody": "/x"}}]:
        with pytest.raises(core.ApiError):
            run_op(db, "settings.folders.update", "inputs", params=bad)


def test_signing_attaches_an_owner_signature_verified_against_the_release_key(db):
    _, a = enrolled_node(db, "a", FACTS_FOLDERS)
    run_op(db, "settings.folders.update", "inputs", params={"access": "read", "nodes": {a["node_id"]: "/data/in"}})
    stmt = folders.statement(db, a["node_id"])["statement"]
    owner = Ed25519PrivateKey.generate()
    db.set_setting("release_pubkey", base64.b64encode(owner.public_key().public_bytes_raw()).decode())
    forged = base64.b64encode(Ed25519PrivateKey.generate().sign(stmt.encode())).decode()
    with pytest.raises(core.ApiError, match="signature"):
        run_op(db, "folders.sign", a["node_id"], params={"statement": stmt, "signature": forged})
    with pytest.raises(core.ApiError, match="current folder statement"):
        run_op(db, "folders.sign", a["node_id"], params={"statement": stmt.replace("/data/in", "/etc"), "signature": forged})
    good = base64.b64encode(owner.sign(stmt.encode())).decode()
    run_op(db, "folders.sign", a["node_id"], params={"statement": stmt, "signature": good})
    assert folders.directive(db, a["node_id"]) == {"statement": stmt, "signature": good}


def test_a_job_runs_only_where_the_node_reports_every_folder_ok_with_its_access(db):
    der, node = enrolled_node(db, "a", FACTS_FOLDERS)
    nid = node["node_id"]
    excluded = lambda: modsandbox.node_exclusions(db, fresh(db, node), {"reel"}).get("reel")
    assert excluded() == "FOLDER_UNAVAILABLE"                        # nothing mapped, nothing reported
    run_op(db, "settings.folders.update", "inputs", params={"access": "read", "nodes": {nid: "/data/in"}})
    run_op(db, "settings.folders.update", "outbox", params={"access": "write", "nodes": {nid: "/data/out"}})
    report = lambda rep: core.heartbeat(db, fresh(db, node), {"attempts": [], "ready_datasets": [], "folders": rep})
    report({"inputs": {"access": "read", "status": "ok"}, "outbox": {"access": "write", "status": "not a directory"}})
    assert excluded() == "FOLDER_UNAVAILABLE"
    report({"inputs": {"access": "read", "status": "ok"}, "outbox": {"access": "read", "status": "ok"}})
    assert excluded() == "FOLDER_UNAVAILABLE"                        # another access than the module asks for
    report({"inputs": {"access": "read", "status": "ok"}, "outbox": {"access": "write", "status": "ok"}})
    assert excluded() is None
    # a node whose sandbox does not enforce folders gets none (CAPABILITY_NOT_ENFORCED with sandboxed agents)
    from oarbank.coordinator import modcalls, platforms
    man = modcalls.info("reel").manifest
    assert platforms.sandbox_gaps(man, FACTS) == ["folders.read", "folders.write"]
    assert platforms.sandbox_gaps(man, FACTS_FOLDERS) == []


def test_the_settings_page_shows_folders_and_their_state(db, tmp_path):
    from fastapi.testclient import TestClient
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from helpers import sign_in
    _, a = enrolled_node(db, "mini", FACTS_FOLDERS)
    run_op(db, "settings.folders.update", "outbox", params={"access": "write", "nodes": {a["node_id"]: "/data/out"}})
    core.heartbeat(db, fresh(db, a), {"attempts": [], "ready_datasets": [], "folders": {"outbox": {"access": "write", "status": "ok"}}})
    c = TestClient(console_app(ConsoleState(db.path, "http://127.0.0.1:1", secret="s")), base_url="http://127.0.0.1:7400")
    sign_in(c, db)
    html = c.get("/settings").text
    assert "outbox (write)" in html and "mini: /data/out" in html and 'name="nodes"' in html
