"""Rescue moves (coordinator/rescue.py): a fresh coordinator takes a signing-mode fleet over from a copy of the lost
coordinator's home with the owner's signature. Agents find a coordinator they will follow there: the fleet, the next
epoch, the key the move names, and their client certificates from the old CA still accepted over real TLS, then renewed
under the new CA. The audit chain verifies across the change of key."""
import base64
import json

import pytest

from oarbank import signing
from oarbank.coordinator import audit, config as C, coordmove, identity, owner, rescue, tlsca
from oarbank.coordinator.db import DB

from helpers import FACTS, enroll_agent, make_db, node_key_and_csr
from test_mtls import TLSServer, client

URL = "https://127.0.0.1:7443"


@pytest.fixture
def lost(tmp_path, monkeypatch):
    """The lost coordinator's home: signing mode, an owner key set with a rescue location, a node, a signed digest."""
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    db = make_db(tmp_path / "old" / "oarbank.sqlite3")
    identity.ensure(db)
    pk = tmp_path / "owner.key"
    pub = signing.keygen(pk)
    st = signing.owner_anchors_statement(identity.fleet_id(db), 1, [pub], ["https://rescue.example/move.json"])
    owner.set_anchors(db, st, [{"key": pub, "sig": signing.sign(st, pk)}], "t")
    key, pem, node = enroll_agent(db, "mini")
    audit.append(db, actor="t", source="cli", operation="nodes.admit", category="create", target_type="enrollment",
                 target_id="e", outcome="ok", request_id=audit.request_id())
    audit.write_digest(db, audit.Signer(base64.b64encode(bytes([7]) * 32).decode()))
    return {"db": db, "home": db.root, "owner_key": pk, "node_key": key, "node_pem": pem, "node": node}


def owner_signed(req, key, path):
    stmt = signing.rescue_move_statement(req)
    path.write_text(json.dumps({"coordinator_move": {"statement": stmt, "signatures": {"owner": signing.sign(stmt, key)}}}))
    return path


def test_a_rescued_fleet_follows_to_the_new_coordinator(lost, tmp_path, monkeypatch):
    old_cik, fid = identity.key(lost["home"]).public_b64, identity.fleet_id(lost["db"])
    new = tmp_path / "new"
    req = rescue.adopt(lost["home"], URL, home=new)
    assert (req["fleet_id"], req["epoch"], req["from_cik"]) == (fid, 2, old_cik) and req["to"]["cik"] != old_cik
    db = DB(new / "oarbank.sqlite3")
    assert identity.role(db) == "standby" and not (new / "coordinator_key").read_bytes() == (lost["home"] / "coordinator_key").read_bytes()
    with pytest.raises(rescue.RescueError, match="already holds"):
        rescue.adopt(lost["home"], URL, home=new)

    rogue = tmp_path / "rogue.key"
    signing.keygen(rogue)
    with pytest.raises(rescue.RescueError, match="owner key set"):
        rescue.sign(owner_signed(req, rogue, tmp_path / "rogue.json"), home=new)
    move = tmp_path / "move.json"                  # the owner signs where the owner key is: the CLI, offline
    monkeypatch.setattr("sys.argv", ["oarbank", "owner", "rescue-move", "--request", str(new / rescue.REQUEST), "--out", str(move),
                                     "--key", str(lost["owner_key"])])
    from oarbank.cli import main as cli
    cli.main()
    rescue.sign(move, home=new)

    # what an agent checks before it records the move (moves.rs): the next epoch, from its key, signed by both
    mv = json.loads(move.read_text(encoding="utf-8"))["coordinator_move"]
    doc = json.loads(mv["statement"])
    assert doc["rescue"] and doc["epoch"] == 2 and doc["from"]["cik"] == old_cik
    assert identity.verify(doc["to"]["cik"], mv["statement"], mv["signatures"]["to"])
    assert owner.verify_any(db, mv["statement"], mv["signatures"]["owner"])
    assert coordmove.chain(db, 1)[0]["statement"] == mv["statement"]

    # then follows it: the identity proof names the fleet, the epoch and the new key; its old certificate works over
    # TLS and is renewed under the new CA, after which the old one is refused
    with TLSServer(db) as s:
        boot = client(tmp_path, tlsca.ca_pem(new), name="boot")
        proof = json.loads(boot.get(f"{s.url}/v1/identity", params={"nonce": "n"}).json()["payload"])
        assert (proof["fleet_id"], proof["epoch"], proof["role"], proof["cik"]) == (fid, 2, "active", req["to"]["cik"])
        old = client(tmp_path, tlsca.ca_pem(new), lost["node_pem"], lost["node_key"], name="old")
        r = old.post(f"{s.url}/v1/agent/hello", json={"agent_version": "1.0.0", "boot_id": "b", "facts": FACTS, "live_attempts": []})
        assert r.status_code == 200 and r.json()["node_id"] == lost["node"]["node_id"] and r.json()["renew_cert"]
        k2, csr = node_key_and_csr()
        renewed = old.post(f"{s.url}/v1/agent/cert", json={"csr": csr}).json()
        c2 = client(tmp_path, tlsca.ca_pem(new), renewed["cert_pem"], k2, name="new")
        assert c2.post(f"{s.url}/v1/agent/heartbeat", json={"attempts": []}).status_code == 200
        assert old.post(f"{s.url}/v1/agent/heartbeat", json={"attempts": []}).status_code == 401

    assert audit.write_digest(db, audit.Signer()) and audit.verify(db)["ok"]


def test_a_fleet_without_owner_keys_cannot_be_rescued(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    db = make_db(tmp_path / "old" / "oarbank.sqlite3")
    tlsca.ensure_ca(db.root, identity.fleet_id(db))
    with pytest.raises(rescue.RescueError, match="owner key set"):
        rescue.adopt(db.root, URL, home=tmp_path / "new")
