"""HTTP-level tests of both listeners through FastAPI's TestClient: authentication, the agent
protocol end to end over JSON, idempotent replays, lock-timeout back-pressure (503 + Retry-After),
and the admin API's identity and CSRF rules. The agent's client certificate stands in for the TLS layer
(helpers.agent_client); tests/test_mtls.py runs the real TLS listener."""
import pytest
from fastapi.testclient import TestClient

from oarbank.coordinator import app as coord_app
from oarbank.coordinator import clock, core, tlsca
from oarbank.coordinator.db import DBBusy

from helpers import (CAPACITY, admin_headers, agent_client, api_op, node_headers, node_key_and_csr, release_id,
                     create_study, SCENES, DOCTOR_OK, FACTS, PARAMS, READY, golden_result, make_db, relay_result)
from helpers import enrolled_node

LOCAL = ("127.0.0.1", 50000)
TAILNET = ("100.64.0.9", 50000)


@pytest.fixture
def db(tmp_path):
    clock.set_fake(None)
    d = make_db(tmp_path / "oarbank.sqlite3")
    yield d
    d.conn.close()


@pytest.fixture
def agent(db):
    return agent_client(db)


@pytest.fixture
def gui(db):
    return TestClient(coord_app.admin_app(db, coord_app.EventBus()), client=LOCAL, headers=admin_headers(db))


def enroll_over_http(agent, db, name="mini"):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    _, csr = node_key_and_csr()
    assert agent.post("/v1/agent/enroll", json={"hostname": name, "facts": FACTS}).status_code == 400   # no CSR
    r = agent.post("/v1/agent/enroll", json={"hostname": name, "facts": {**FACTS, "hostname": name}, "csr": csr})
    assert r.status_code == 200
    eid = r.json()["enrollment_id"]
    assert "cert_pem" not in agent.get(f"/v1/agent/enroll/{eid}").json()        # not before approval
    core.approve_enrollment(db, eid, "test")
    pem = agent.get(f"/v1/agent/enroll/{eid}").json()["cert_pem"]
    assert "cert_pem" not in agent.get(f"/v1/agent/enroll/{eid}").json()        # issued exactly once
    return node_headers(x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER))


# ------------------------------------------------------------------ agent API
def test_agent_requires_its_client_certificate(agent, db):
    r = agent.post("/v1/agent/hello", json={})
    assert r.status_code == 401 and r.json()["error"] == "client_certificate_required"
    other = tlsca.issue_client(db.root, node_key_and_csr()[1], "n_unknown")        # our CA, but no such node
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    der = x509.load_pem_x509_certificate(other["cert_pem"].encode()).public_bytes(serialization.Encoding.DER)
    r = agent.post("/v1/agent/hello", json={}, headers=node_headers(der))
    assert r.status_code == 401 and r.json()["error"] == "unauthorized"
    assert agent.get("/healthz").status_code == 200


def test_full_protocol_over_http_with_idempotent_replay(agent, db):
    h = enroll_over_http(agent, db)
    assert agent.post("/v1/agent/hello", headers=h, json={"release_id": release_id(db), "facts": FACTS,
                                                         "live_attempts": [], "ready_datasets": READY}).status_code == 200
    hb = agent.post("/v1/agent/heartbeat", headers=h, json={"doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY, "capacity": CAPACITY})
    assert hb.status_code == 200
    body = {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY}
    grants = agent.post("/v1/agent/claim", headers=h, json=body).json()["grants"]
    assert grants and {g["kind"] for g in grants} == {"golden"}
    for g in grants:
        res = golden_result(g)
        first = agent.post(f"/v1/attempts/{g['attempt_id']}/complete", headers=h, json=res)
        again = agent.post(f"/v1/attempts/{g['attempt_id']}/complete", headers=h, json=res)   # lost ack, outbox retry
        assert first.status_code == again.status_code == 200 and first.json() == again.json()
        assert first.json()["canonical"]
        create_study(db, "t", [{"label": "c1", "params": {**PARAMS, "samples": 25}}], SCENES[:1],
                         {"label": "base", "params": PARAMS})
    evals = agent.post("/v1/agent/claim", headers=h, json=body).json()["grants"]
    assert evals and all(g["kind"] == "eval" for g in evals)
    r = agent.post(f"/v1/attempts/{evals[0]['attempt_id']}/release", headers=h, json={"reason": "preempt_protection"})
    assert r.status_code == 200


def test_node_cannot_touch_another_nodes_attempt(agent, db):
    h1, h2 = enroll_over_http(agent, db, "a"), enroll_over_http(agent, db, "b")
    for h in (h1, h2):
        agent.post("/v1/agent/hello", headers=h, json={"release_id": release_id(db), "facts": FACTS, "live_attempts": [],
                                                      "ready_datasets": READY})
        agent.post("/v1/agent/heartbeat", headers=h, json={"doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY, "capacity": CAPACITY})
    g = agent.post("/v1/agent/claim", headers=h1, json={"free_cpu": 1, "free_mem_gb": 8,
                                                         "ready_datasets": READY}).json()["grants"][0]
    r = agent.post(f"/v1/attempts/{g['attempt_id']}/complete", headers=h2, json=relay_result())
    assert r.status_code == 404 and r.json()["error"] == "lease_lost"


def test_retired_node_is_refused(agent, db):
    h = enroll_over_http(agent, db)
    db.x("UPDATE nodes SET lifecycle='retired'")
    assert agent.post("/v1/agent/hello", headers=h, json={}).status_code == 403


def test_lock_timeout_is_503_with_retry_after(agent, db, monkeypatch):
    """A saturated coordinator sheds load explicitly; agents back off instead of piling up."""
    h = enroll_over_http(agent, db)

    def busy(*a, **k):
        raise DBBusy("database lock not acquired within 10s")
    monkeypatch.setattr(core, "claim", busy)
    r = agent.post("/v1/agent/claim", headers=h, json={"free_cpu": 1})
    assert r.status_code == 503 and r.headers["retry-after"] == "2" and r.json()["error"] == "busy"


# ------------------------------------------------------------------ GUI / admin API
def test_gui_identity(db):
    """Nothing is admin for being local, and identity headers are never trusted (the readiness critical)."""
    from oarbank.coordinator import access
    local = TestClient(coord_app.admin_app(db, coord_app.EventBus()), client=LOCAL)
    assert local.get("/api/v1/fleet").status_code == 401                                       # loopback alone: nothing
    assert local.get("/api/v1/fleet", headers={"tailscale-user-login": "alice@example.com"}).status_code == 401
    assert local.get("/api/v1/fleet", headers={"authorization": "Bearer nope"}).status_code == 401
    assert local.get("/api/v1/fleet", headers=admin_headers(db)).status_code == 200            # the owner's admin token
    access.create_account(db, "vic", "viewer", None, "test")
    tok = access.new_token(db, "vic", "ci", "viewer", 1)["token"]
    remote = TestClient(coord_app.admin_app(db, coord_app.EventBus()), client=TAILNET, headers={"authorization": f"Bearer {tok}"})
    assert remote.get("/api/v1/fleet").status_code == 200                                      # a personal access token
    r = remote.post("/api/v1/ops/fleet.pause", json={"reason": "x"})
    assert r.status_code == 403 and r.json()["error"] == "forbidden_role"                   # a viewer cannot mutate
    access.revoke_token(db, access.token_identity(db, tok)["token_id"])
    assert remote.get("/api/v1/fleet").status_code == 401
    funnel = {**admin_headers(db), "tailscale-funnel-request": "?1"}
    assert local.get("/api/v1/fleet", headers=funnel).status_code == 403
    evil = {**admin_headers(db), "host": "evil.example"}                                    # DNS rebinding
    assert local.get("/api/v1/fleet", headers=evil).status_code == 421


@pytest.mark.parametrize("headers", [
    {"origin": "https://evil.example"},
    {"sec-fetch-site": "cross-site"},
    {"sec-fetch-site": "same-site"},
])
def test_csrf_blocks_cross_origin_mutations(gui, headers):
    r = gui.post("/api/v1/ops/settings.apply", json={"params": {"changes": [{"scope": "fleet", "key": "replica_rate", "value": 0.5}]},
                                                     "dry_run": True}, headers=headers)
    assert r.status_code == 403 and r.json()["error"] == "csrf"


@pytest.mark.parametrize("headers", [
    {},                                                                              # local CLI (oarbank)
    {"sec-fetch-site": "same-origin"},
    {"origin": "http://testserver"},
])
def test_same_origin_mutations_pass(gui, db, headers):
    node = enrolled_node(db)[1]
    change = {"changes": [{"scope": "node", "scope_id": node["node_id"], "key": "jobs", "value": 2}]}     # T0: applied at once
    assert api_op(gui, "settings.apply", node["node_id"], change, headers=headers).status_code == 200
    from oarbank.coordinator.core import node_limits
    assert node_limits(db.one("SELECT * FROM nodes WHERE node_id=?", (node["node_id"],)))["jobs"] == 2


def test_metrics_requires_identity(db):
    remote = TestClient(coord_app.admin_app(db, coord_app.EventBus()), client=TAILNET)
    assert remote.get("/metrics").status_code == 401


def test_an_external_sqlite_lock_is_503_not_500(agent, db, monkeypatch):
    """A chaos finding: another process holding SQLite's write lock surfaced as a 500."""
    import sqlite3
    h = enroll_over_http(agent, db)

    def locked(*a, **k):
        raise sqlite3.OperationalError("database is locked")
    monkeypatch.setattr(core, "claim", locked)
    r = agent.post("/v1/agent/claim", headers=h, json={"free_cpu": 1})
    assert r.status_code == 503 and r.headers["retry-after"] == "2" and r.json()["error"] == "busy"
