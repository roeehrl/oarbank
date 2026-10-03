"""The operation layer (PLAN D13-D15): one audited path for every mutation, over HTTP."""
import base64
import os
import uuid

import pytest

from fastapi.testclient import TestClient

from helpers import create_study, PARAMS, READY, certify, enrolled_node, fresh, make_db, admin_headers
from oarbank.coordinator import app as coord_app
from oarbank.coordinator import audit, core
from oarbank.coordinator.audit import Signer

LOCAL = ("127.0.0.1", 50000)


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


@pytest.fixture
def api(db):
    return TestClient(coord_app.admin_app(db, coord_app.EventBus()), client=LOCAL, headers=admin_headers(db))


def op(api, name, body=None, **headers):
    return api.post(f"/api/v1/ops/{name}", json=body or {}, headers={k.replace("_", "-"): v for k, v in headers.items()})


def last_audit(db):
    return db.one("SELECT * FROM audit ORDER BY event_id DESC LIMIT 1")


def test_t0_operation_is_applied_and_audited_with_before_and_after(db, api):
    node = certify(db, enrolled_node(db)[1])
    r = op(api, "nodes.pause", {"target": node["hostname"]}, x_oarbank_source="cli")
    assert r.status_code == 200 and r.json()["ok"]
    assert fresh(db, node)["desired_state"] == "paused"
    a = last_audit(db)
    assert (a["operation"], a["outcome"], a["source"], a["target_type"]) == ("nodes.pause", "ok", "cli", "node")
    assert '"active"' in a["before_json"] and '"paused"' in a["after_json"]
    assert audit.verify(db)["ok"]


def test_reason_required_at_t2_and_refusals_are_audited(db, api):
    r = op(api, "releases.promote", {"target": "r_test", "dry_run": False})
    assert r.status_code == 400 and r.json()["error"] == "reason_required"
    a = last_audit(db)
    assert (a["operation"], a["outcome"]) == ("releases.promote", "rejected")


def test_preview_then_apply_bound_to_a_plan(db, api):
    node = certify(db, enrolled_node(db)[1])
    r = op(api, "nodes.retire", {"target": node["node_id"], "reason": "sold"})
    assert r.status_code == 428 and r.json()["error"] == "plan_required"
    plan = op(api, "nodes.retire", {"target": node["node_id"], "dry_run": True}).json()["plan"]
    assert plan["confirm_required"] and plan["confirm_name"] == "mini" and plan["tier"] == "T3"
    assert fresh(db, node)["lifecycle"] == "ready"                        # a preview changes nothing
    r = op(api, "nodes.retire", {"plan_id": plan["plan_id"], "reason": "sold", "confirm": "wrong"})
    assert r.status_code == 400 and r.json()["error"] == "confirmation_required"
    r = op(api, "nodes.retire", {"plan_id": plan["plan_id"], "reason": "sold", "confirm": "mini"})
    assert r.status_code == 200 and fresh(db, node)["lifecycle"] == "retired"
    r = op(api, "nodes.retire", {"plan_id": plan["plan_id"], "reason": "sold", "confirm": "mini"})
    assert r.status_code == 409 and r.json()["error"] == "plan_used"


def test_plan_drift_returns_409_with_a_fresh_plan(db, api):
    p1 = op(api, "settings.notifications.update", {"target": "ntfy", "params": {"url": "https://a"}, "dry_run": True}).json()["plan"]
    p2 = op(api, "settings.notifications.update", {"target": "ntfy", "params": {"url": "https://b"}, "dry_run": True}).json()["plan"]
    assert op(api, "settings.notifications.update", {"plan_id": p2["plan_id"], "reason": "b first"}).status_code == 200
    r = op(api, "settings.notifications.update", {"plan_id": p1["plan_id"], "reason": "stale"})
    assert r.status_code == 409 and r.json()["error"] == "plan_drift"
    fresh_plan = r.json()["plan"]
    assert fresh_plan["versions"]["setting:ntfy"] == 1 and fresh_plan["params"]["url"] == "https://a"
    assert op(api, "settings.notifications.update", {"plan_id": fresh_plan["plan_id"], "reason": "reviewed"}).status_code == 200
    assert db.get_setting("ntfy")["url"] == "https://a"


def test_if_match_on_versioned_resources(db, api):
    node = certify(db, enrolled_node(db)[1])
    r = op(api, "nodes.set_caps", {"target": node["node_id"], "params": {"patch": {"jobs": 2}}}, if_match="7")
    assert r.status_code == 412 and r.json()["error"] == "version_mismatch"
    r = op(api, "nodes.set_caps", {"target": node["node_id"], "params": {"patch": {"jobs": 2}}}, if_match="0")
    assert r.status_code == 200 and r.json()["versions"] == {f"node:{node['node_id']}:limits": 1}
    r = op(api, "nodes.set_caps", {"target": node["node_id"], "params": {"patch": {"jobs": 3}}})   # T0: If-Match optional
    assert r.status_code == 200 and r.json()["versions"][f"node:{node['node_id']}:limits"] == 2


def test_idempotency_keys_for_creations(db, api):
    """A module operation that creates work (mod.relay.create_study enqueues jobs) needs a key."""
    body = {"params": {"name": "s", "configs": [], "datasets": ["scene:s1"], "baseline": {"label": "b", "params": PARAMS}}}
    r = op(api, "mod.relay.create_study", body)
    assert r.status_code == 400 and r.json()["error"] == "idempotency_key_required"
    key = str(uuid.uuid4())
    r1 = op(api, "mod.relay.create_study", body, idempotency_key=key)
    r2 = op(api, "mod.relay.create_study", body, idempotency_key=key)     # a double click / 5G retry
    assert r1.status_code == r2.status_code == 200 and r2.json()["replayed"]
    assert r1.json()["result"]["result"]["campaign_id"] == r2.json()["result"]["result"]["campaign_id"]
    assert db.one("SELECT COUNT(*) n FROM campaigns")["n"] == 1
    assert r1.json()["target"] == r1.json()["result"]["result"]["campaign_id"]          # audited against what it created
    r3 = op(api, "mod.relay.create_study", {"params": {**body["params"], "name": "other"}}, idempotency_key=key)
    assert r3.status_code == 422 and r3.json()["error"] == "idempotency_key_reused"


def test_fleet_pause_stops_leasing_and_resume_needs_a_reason(db, api):
    node = certify(db, enrolled_node(db)[1])
    create_study(db, "s", [], ["scene:s1"], {"label": "b", "params": PARAMS})
    assert op(api, "fleet.pause", {"target": "fleet"}).status_code == 200
    assert core.claim(db, fresh(db, node), {"free_slots": 2, "ready_datasets": READY})["grants"] == []
    r = op(api, "fleet.resume", {"target": "fleet"})
    assert r.status_code == 400 and r.json()["error"] == "reason_required"
    assert op(api, "fleet.resume", {"target": "fleet", "reason": "maintenance done"}).status_code == 200
    assert core.claim(db, fresh(db, node), {"free_slots": 2, "ready_datasets": READY})["grants"]


def test_audit_tamper_and_digest_verification(db, api):
    node = certify(db, enrolled_node(db)[1])
    for name in ("nodes.pause", "nodes.resume", "nodes.pause"):
        assert op(api, name, {"target": node["node_id"]}).status_code == 200
    signer = Signer(base64.b64encode(os.urandom(32)).decode())
    assert audit.write_digest(db, signer)["last_event_id"] == 3
    assert audit.write_digest(db, signer) is None                          # nothing new to sign
    v = audit.verify(db)
    assert v["ok"] and v["rows"] == 3 and v["digests"] == 1
    db.x("UPDATE audit SET reason='edited later' WHERE event_id=2")         # a careless sqlite3 session
    v = audit.verify(db)
    assert not v["ok"] and v["broken_at"] == 2
    db.x("UPDATE audit SET reason=NULL WHERE event_id=2")
    db.x("UPDATE audit_digests SET hash=(CASE WHEN substr(hash, 1, 1)='0' THEN '1' ELSE '0' END) || substr(hash, 2)")
    assert audit.verify(db)["bad_digest"] == 3


def test_ops_listing_carries_the_reason_policy(api):
    rows = {r["id"]: r for r in api.get("/api/v1/ops").json()}
    assert rows["fleet.resume"]["reason_policy"] == "required" and rows["nodes.pause"]["tier"] == "T0"


def test_off_host_digest_copy_detects_a_rewritten_and_resigned_chain(db, api, tmp_path):
    """Digests go to audit/digests.jsonl and an owner-set copy command; an attacker (or a careless
    session) who edits a row and re-signs the whole chain passes the local check but not the off-host one."""
    import json as _json
    node = certify(db, enrolled_node(db)[1])
    for name in ("nodes.pause", "nodes.resume"):
        assert op(api, name, {"target": node["node_id"]}).status_code == 200
    signer = Signer(base64.b64encode(os.urandom(32)).decode())
    dest = tmp_path / "offhost"
    dest.mkdir()
    db.set_setting("audit_digest_copy", ["cp", "{file}", str(dest / "digests.jsonl")])
    d = audit.write_digest(db, signer)
    audit.export_digest(db, d)
    assert audit.copy_off_host(db)["ok"]
    copy = [_json.loads(l) for l in (dest / "digests.jsonl").read_text().splitlines()]
    r = op(api, "audit.verify", {"target": "audit", "params": {"digests": copy}}).json()["result"]
    assert r["ok"] and r["off_host"] == {"ok": True, "checked": 1, "missing": [], "mismatched": []}
    # rewrite history: edit a row, recompute the chain, re-sign a fresh digest table
    db.x("UPDATE audit SET reason='rewritten' WHERE event_id=1")
    prev = audit.GENESIS
    for row in db.q("SELECT * FROM audit ORDER BY event_id"):
        rec = audit.row_to_record(row)
        h = audit.row_hash(prev, {**rec.model_dump(), "prev_hash": prev})
        db.x("UPDATE audit SET prev_hash=?, hash=? WHERE event_id=?", (prev, h, rec.event_id))
        prev = h
    db.x("DELETE FROM audit_digests")
    audit.write_digest(db, signer)
    assert audit.verify(db)["ok"]                                            # locally it all checks out again
    r = op(api, "audit.verify", {"target": "audit", "params": {"digests": copy}}).json()["result"]
    assert not r["ok"] and d["last_event_id"] in r["off_host"]["missing"] + r["off_host"]["mismatched"]


def test_cli_questions_without_a_terminal_name_the_flag(monkeypatch, capsys):
    # over ssh or in a script stdin is closed: an unanswerable question once ended in an EOFError traceback
    import io
    from oarbank.cli import main as cli
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    with pytest.raises(SystemExit) as e:
        cli.ask("reason: ", "--reason")
    assert "pass --reason" in str(e.value.code)
    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))           # a piped answer still answers
    assert cli.ask("apply? [y/N] ", "--yes") == "y"
