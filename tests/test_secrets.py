"""Module secrets (docs/design/secrets-and-signed-images.md, #14): a module stores an API key that no console page, API
read, plan, audit row or log shows; only the declaring stage's runner receives it (resolved per node), the coordinator
side only with secrets:read:self, and a coordinator move carries it re-encrypted for the target."""
import base64
import json
import shutil
import sqlite3

import pytest

from oarbank.coordinator import core, explain, modcalls, modsandbox, modsecrets, modstore, ops, releases
from oarbank.coordinator.db import DB

from helpers import FACTS, FIXTURES, admin_headers, enrolled_node, fresh, install, make_db, run_op

VAULT_DIR = FIXTURES / "vault"
KEY = "sk-live-4f1c9a7e2b8d4f60a1c3"          # the value under test: it must never show anywhere but a grant
NODE_KEY = "sk-node-only-77aa19c0e3"
DOCTOR = {"modules": {"vault": {"health": "healthy", "checks": []}}}


@pytest.fixture
def db(tmp_path):
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    r = install(d, VAULT_DIR, enable=False)
    modsandbox.approve(d, "vault", r["version"], "test", None)
    modstore.enable(d, "vault", r["version"])
    modcalls.use(d)
    releases.sync(d)
    return d


def node(db, name="mini"):
    """A node certified for vault (its golden passed), offering the containers pool."""
    _, n = enrolled_node(db, name, FACTS)
    core.hello(db, n, {"release_id": releases.assigned(db, fresh(db, n)), "facts": FACTS, "live_attempts": [], "ready_datasets": []})
    core.heartbeat(db, fresh(db, n), {"doctor": DOCTOR, "attempts": [], "ready_datasets": [], "capacity": {"pools": {"containers": 2}}})
    for g in claim(db, n):
        core.complete(db, fresh(db, n), g["attempt_id"], {"result": {"envelope": 1, "schema": "vault/result@1",
                      "module_version": "1.0.0", "protocol": 1, "payload": {"digest": "vault-golden-1"}}})
    assert core.node_modules(fresh(db, n))["vault"]["state"] == "certified"
    return fresh(db, n)


def claim(db, n):
    return core.claim(db, fresh(db, n), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": []})["grants"]


def set_secret(db, value=KEY, node_id=None, actor="test"):
    return run_op(db, "secrets.set", "vault", {"name": "api_key", **({"node": node_id} if node_id else {})}, actor=actor,
                  secret=value)["result"]


def everything_stored(db) -> bytes:
    """Every byte the coordinator's database holds, as SQLite dumps it (secrets' ciphertexts included)."""
    c = sqlite3.connect(db.path)
    try:
        return "\n".join(c.iterdump()).encode()
    finally:
        c.close()


def test_a_secret_is_write_only_and_never_stored_in_the_clear(db):
    out = set_secret(db)
    assert out["set"] and out["fingerprint"].startswith("fp:") and KEY not in json.dumps(out)
    listing = modsecrets.listing(db, "vault")
    assert listing == [{"name": "api_key", "description": "The provider key the call stage uses", "stages": ["call"],
                        "coordinator": True, "set": True, "nodes": [],
                        "module": {"node_id": None, "hostname": None, "fingerprint": out["fingerprint"],
                                   "set_at": out["set_at"], "set_by": "test", "readable": True}}]
    dump = everything_stored(db)
    assert KEY.encode() not in dump and base64.b64encode(KEY.encode()) not in dump
    a = db.one("SELECT * FROM audit WHERE operation='secrets.set'")
    assert KEY not in json.dumps(a) and out["fingerprint"] in a["after_json"]
    # the same value gives the same fingerprint; another value another one
    assert set_secret(db)["fingerprint"] == out["fingerprint"] != set_secret(db, KEY + "x")["fingerprint"]


def test_the_value_goes_beside_params_and_nowhere_else(db):
    with pytest.raises(ops.OpError, match="secret_required"):
        run_op(db, "secrets.set", "vault", {"name": "api_key"})
    with pytest.raises(ops.OpError, match="bad_params"):                      # never inside params
        run_op(db, "secrets.set", "vault", {"name": "api_key", "value": KEY}, secret=KEY)
    with pytest.raises(ops.OpError, match="secret_not_accepted"):            # no other operation takes one
        run_op(db, "fleet.pause", reason="t", secret=KEY)
    with pytest.raises(ops.OpError, match="secret_not_accepted"):            # never a preview (a plan would hold it)
        ops.execute(db, ops.OpRequest(op="secrets.set", actor="t", target="vault", params={"name": "api_key"},
                                      secret=KEY, dry_run=True))
    with pytest.raises(ops.OpError, match="unknown_secret"):
        run_op(db, "secrets.set", "vault", {"name": "other"}, secret=KEY)
    with pytest.raises(ops.OpError, match="forbidden_role"):
        run_op(db, "secrets.set", "vault", {"name": "api_key"}, secret=KEY, role="operator")
    assert "secret=" not in repr(ops.OpRequest(op="secrets.set", actor="t", secret=KEY)) and KEY not in repr(
        ops.OpRequest(op="secrets.set", actor="t", secret=KEY))
    assert KEY.encode() not in everything_stored(db)                          # refusals are audited without it


def test_only_the_declaring_stage_gets_it_resolved_for_its_node(db):
    n, other = node(db, "mini"), node(db, "desk")
    run_op(db, "mod.vault.call", params={})
    # unset: the call job waits (SECRETS_NOT_SET, in claim and explain alike); the probe job runs without any secret
    grants = claim(db, n)
    assert [g["spec"]["stage"] for g in grants] == ["probe"] and "secrets" not in grants[0]
    job = db.one("SELECT job_id FROM jobs WHERE stage='call'")["job_id"]
    doc = explain.explain(db, "job", str(job))
    assert [r.code for r in doc.summary] == ["SECRETS_NOT_SET"], doc
    assert "secrets.set" in [r.op for r in doc.remedies]
    set_secret(db)
    set_secret(db, NODE_KEY, node_id=other["node_id"])
    g = claim(db, n)
    assert [x["spec"]["stage"] for x in g] == ["call"] and g[0]["secrets"] == {"api_key": KEY}
    assert KEY not in json.dumps(g[0]["spec"])                                 # never in spec.json
    run_op(db, "mod.vault.call", params={"campaign_id": "c_second"})
    g2 = [x for x in claim(db, other) if x["spec"]["stage"] == "call"]
    assert g2[0]["secrets"] == {"api_key": NODE_KEY}                            # the node's own value wins
    run_op(db, "secrets.clear", "vault", {"name": "api_key", "node": other["node_id"]})
    assert modsecrets.for_job(db, "vault", ["api_key"], other["node_id"]) == {"api_key": KEY}
    run_op(db, "secrets.clear", "vault", {"name": "api_key"})
    assert modsecrets.missing_for(db, "vault", ["api_key"], n["node_id"]) == ["api_key"]
    assert KEY.encode() not in everything_stored(db) and NODE_KEY.encode() not in everything_stored(db)


def test_a_retired_node_takes_its_own_values_with_it(db):
    n = node(db)
    set_secret(db, NODE_KEY, node_id=n["node_id"])
    run_op(db, "nodes.retire", n["node_id"], reason="gone")
    assert not db.one("SELECT 1 FROM secrets WHERE node_id=?", (n["node_id"],))


def test_the_coordinator_side_reads_it_only_with_the_permission_and_its_log_is_redacted(db, tmp_path):
    import hashlib
    set_secret(db)
    r = run_op(db, "mod.vault.key_check", params={"log": True})
    assert r["result"]["result"]["key_sha256"] == hashlib.sha256(KEY.encode()).hexdigest()
    import time
    log = db.root / "logs" / "modules" / "vault.log"
    for _ in range(100):                                  # the host drains the module's stderr on its own thread
        if log.exists() and "using key" in log.read_text():
            break
        time.sleep(0.05)
    text = log.read_text()
    assert "vault: using key [secret:api_key]" in text and KEY not in text
    # a module without secrets:read:self is refused the callback (-32002)
    src = tmp_path / "vault2"
    shutil.copytree(VAULT_DIR, src)
    m = (src / "oarbank-module.toml").read_text()
    (src / "oarbank-module.toml").write_text(m.replace('permissions = ["secrets:read:self"]', 'permissions = []'))
    d2 = make_db(tmp_path / "other" / "oarbank.sqlite3", modules=())
    v = install(d2, src, enable=False)
    modsandbox.approve(d2, "vault", v["version"], "test", None)
    modstore.enable(d2, "vault", v["version"])
    modcalls.use(d2)
    set_secret(d2)
    with pytest.raises(ops.OpError, match="needs permission secrets:read:self"):
        run_op(d2, "mod.vault.key_check", params={})


def test_no_api_read_or_console_page_shows_it(db):
    from fastapi.testclient import TestClient
    from oarbank.coordinator import app as coord_app
    set_secret(db)
    n = node(db)
    set_secret(db, NODE_KEY, node_id=n["node_id"])
    c = TestClient(coord_app.admin_app(db, console_secret="x"))
    h = admin_headers(db)
    r = c.get("/api/v1/modules/vault/secrets", headers=h)
    assert r.status_code == 200 and r.json()["secrets"][0]["set"] and len(r.json()["secrets"][0]["nodes"]) == 1
    for path in ("/api/v1/modules/vault/secrets", "/api/v1/audit", "/api/v1/alerts", "/api/v1/modules", "/api/v1/fleet",
                 "/api/v1/modules/store", "/api/v1/campaigns", "/api/v1/events", "/api/v1/verify"):
        r = c.get(path, headers=h)
        assert r.status_code == 200 and KEY not in r.text and NODE_KEY not in r.text, path
    # set over the API, as the CLI does: the value travels beside params
    r = c.post("/api/v1/ops/secrets.set", json={"target": "vault", "params": {"name": "api_key"}, "secret": KEY + "2"}, headers=h)
    assert r.status_code == 200 and KEY not in r.text


def test_console_pages_show_state_and_fingerprints_never_the_value(tmp_path):
    from test_console import Server, SECRET
    from fastapi.testclient import TestClient
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from oarbank.coordinator import app as coord_app
    from helpers import sign_in
    path = tmp_path / "oarbank.sqlite3"
    d = make_db(path, modules=())
    r = install(d, VAULT_DIR, enable=False)
    modsandbox.approve(d, "vault", r["version"], "test", None)
    modstore.enable(d, "vault", r["version"])
    modcalls.use(d)
    releases.sync(d)
    n = node(d)
    with Server(coord_app.admin_app(d, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(path, f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        state.poll_fleetd(__import__("httpx").Client())
        with TestClient(console_app(state), client=("127.0.0.1", 50001)) as c:
            sign_in(c, d)
            page = c.get("/modules/vault/secrets")
            assert page.status_code == 200 and "not set" in page.text and 'type="password"' in page.text
            r = c.post("/do/secrets.set", data={"target": "vault", "p.name": "api_key", "secret": KEY, "return_to": "/",
                                                "idem": ""}, follow_redirects=False)
            assert r.status_code == 303 and "kind=ok" in r.headers["location"], r.headers.get("location")
            r = c.post("/do/secrets.set", data={"target": "vault", "p.name": "api_key", "p.node": n["node_id"],
                                                "secret": NODE_KEY, "return_to": "/", "idem": ""}, follow_redirects=False)
            assert "kind=ok" in r.headers["location"]
            fp = modsecrets.listing(d, "vault")[0]["module"]["fingerprint"]
            for p in ("/modules/vault/secrets", f"/nodes/{n['node_id']}", "/audit", "/events", "/modules/vault/health",
                      "/modules", "/"):
                body = c.get(p).text
                assert KEY not in body and NODE_KEY not in body, p
            assert fp in c.get("/modules/vault/secrets").text and "api_key" in c.get(f"/nodes/{n['node_id']}").text
            # the node reports GPU passthrough to containers (#13): a Mac cannot
            d.x("UPDATE nodes SET facts_json=? WHERE node_id=?", (json.dumps({**FACTS, "containers": {"gpu": "undetected"}}),
                                                                   n["node_id"]))
            assert "GPU in containers</span><span>undetected: krunkit is not installed" in \
                c.get(f"/nodes/{n['node_id']}").text
    assert KEY.encode() not in everything_stored(d)


def test_an_unreadable_value_alerts_and_counts_as_not_set(db):
    n = node(db)
    set_secret(db)
    (db.root / "keys" / f"{modsecrets.KEY_NAME}.key").unlink()          # a home copied without its key
    assert modsecrets.missing_for(db, "vault", ["api_key"], n["node_id"]) == ["api_key"]
    assert not modsecrets.listing(db, "vault")[0]["module"]["readable"]
    modsecrets.check_readable(db)
    a = db.one("SELECT * FROM alerts WHERE rule='secret_unreadable:vault/api_key' AND state='open'")
    assert a and "oarbank secret set vault api_key" in a["detail"]
    set_secret(db)
    assert not db.one("SELECT 1 FROM alerts WHERE rule='secret_unreadable:vault/api_key' AND state='open'")


def test_a_move_seals_secrets_to_the_target_and_it_adopts_them(db, tmp_path):
    n = node(db)
    a = set_secret(db)
    set_secret(db, NODE_KEY, node_id=n["node_id"])
    home_b = tmp_path / "b"
    home_b.mkdir()
    snap = tmp_path / "snap.sqlite3"
    db.x("VACUUM INTO ?", (str(snap),))
    names = modsecrets.seal_snapshot(db, snap, modsecrets.transport_public(home_b))
    assert names == ["vault/api_key (module)", f"vault/api_key (node {n['node_id']})"]
    assert set(ops._secrets_carried(db)) == {"vault/api_key (module)", "vault/api_key (node mini)"}
    assert KEY.encode() not in snap.read_bytes()
    shutil.copy(snap, home_b / "oarbank.sqlite3")
    db_b = DB(home_b / "oarbank.sqlite3")
    assert modsecrets.module_value(db_b, "vault", "api_key") is None            # sealed: B opens it only by adopting it
    assert modsecrets.adopt_sealed(db_b) == 3                                   # both values and the fingerprint key
    assert modsecrets.module_value(db_b, "vault", "api_key") == KEY
    assert modsecrets.for_job(db_b, "vault", ["api_key"], n["node_id"]) == {"api_key": NODE_KEY}
    assert modsecrets.fingerprint(db_b, KEY.encode()) == a["fingerprint"]      # fingerprints travel unchanged
    assert modsecrets.module_value(db, "vault", "api_key") == KEY               # the source's own database is untouched
    # a third machine cannot open what was sealed for B
    other = tmp_path / "c"
    other.mkdir()
    shutil.copy(snap, other / "oarbank.sqlite3")
    db_c = DB(other / "oarbank.sqlite3")
    assert modsecrets.adopt_sealed(db_c) == 0 and modsecrets.module_value(db_c, "vault", "api_key") is None


def test_the_cli_reads_the_value_from_stdin_never_argv(db):
    import os
    import subprocess
    import sys
    from oarbank.coordinator import access
    from oarbank.coordinator import app as coord_app
    from test_console import Server
    with Server(coord_app.admin_app(db)) as oarbankd:
        env = {**os.environ, "OARBANKD_URL": f"http://127.0.0.1:{oarbankd.port}", "OARBANK_REASON": "cli test",
               "OARBANK_TOKEN": access.ensure_admin_token(db.root)}
        cli = lambda *args, stdin=None: subprocess.run([sys.executable, "-m", "oarbank.cli.main", "secret", *args],
                                                       input=stdin, capture_output=True, text=True, env=env, timeout=120)
        r = cli("set", "vault", "api_key", stdin=KEY + "\n")
        assert r.returncode == 0, r.stderr
        fp = modsecrets.listing(db, "vault")[0]["module"]["fingerprint"]
        assert fp in r.stdout and KEY not in r.stdout + r.stderr
        assert modsecrets.module_value(db, "vault", "api_key") == KEY            # the trailing newline is not part of it
        r = cli("list", "vault")
        assert "api_key" in r.stdout and "set" in r.stdout and fp in r.stdout and KEY not in r.stdout
        r = cli("clear", "vault", "api_key", "--yes")
        assert r.returncode == 0, r.stderr
        assert "NOT SET" in cli("list", "vault").stdout


def test_the_secrets_key_stays_in_the_secret_store(tmp_path, monkeypatch):
    """The key that encrypts module secrets is never in the database: an owner-only file here (Linux, and tests), the
    Keychain on macOS, a DPAPI-wrapped file on Windows (checked on the Windows VM: docs/design/secrets-and-signed-images.md)."""
    import os
    import stat
    from oarbank.platform import secrets as store
    monkeypatch.setenv("OARBANK_SECRET_STORE", "file")
    k = store.get_or_create(modsecrets.KEY_NAME, tmp_path)
    assert len(k) == 32 and store.get_or_create(modsecrets.KEY_NAME, tmp_path) == k
    f = tmp_path / "keys" / f"{modsecrets.KEY_NAME}.key"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600 and stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    monkeypatch.delenv("OARBANK_SECRET_STORE")
    assert store.backend() == {"darwin": "keychain", "win32": "dpapi"}.get(os.sys.platform, "file")
