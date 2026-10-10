"""Join codes (docs/design/node-enrollment.md): the OB2 format against the vectors the Rust codec shares, and what the
coordinator does with a code: single use approves at once, multi-use waits for the owner, refusals say why, device
codes approve a waiting machine, revoking a code leaves the machines that joined with it."""
import base64
import json
import time
from pathlib import Path

import pytest

from oarbank.coordinator import core, joincodes as J

from helpers import FACTS, make_db, node_key_and_csr

VECTORS = json.loads((Path(J.__file__).parents[1] / "contracts" / "vectors" / "joincode.json").read_text())
CIK = base64.b64encode(bytes(range(32))).decode()


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3", modules=())


def make(db, **kw):
    kw = {"urls": ["https://127.0.0.1:7443"], "pins": ["ab" * 32], "cik": CIK, "actor": "owner", **kw}
    out = J.create(db, **kw)
    return out, J.decode(out["code"])


def enroll(db, token, host="mini", **kw):
    return core.enroll(db, host, {**FACTS, "hostname": host}, "192.0.2.7", node_key_and_csr()[1], join=token, **kw)


@pytest.mark.parametrize("v", VECTORS["codes"], ids=lambda v: v["text"][:12])
def test_the_vectors_decode_and_encode_back(v):
    d = J.decode(v["text"])
    assert {k: d[k] for k in ("flags", "expires_at", "cik", "pins", "urls", "id", "secret")} == \
        {k: v[k] for k in ("flags", "expires_at", "cik", "pins", "urls", "id", "secret")}
    again = J.encode(urls=v["urls"], pins=v["pins"], cik=v["cik"], code_id=bytes.fromhex(v["id"]),
                     secret=bytes.fromhex(v["secret"]), expires_at=v["expires_at"], flags=v["flags"])
    assert again == v["text"]


@pytest.mark.parametrize("v", VECTORS["equivalent"], ids=range(len(VECTORS["equivalent"])))
def test_spacing_case_dashes_and_lookalikes_do_not_matter(v):
    assert J.decode(v["text"])["token"] == J.decode(VECTORS["codes"][v["same_as"]]["text"])["token"]


@pytest.mark.parametrize("v", VECTORS["invalid"], ids=lambda v: v["why"])
def test_broken_codes_are_refused_offline(v):
    with pytest.raises(J.JoinError):
        J.decode(v["text"])


def test_a_code_carries_what_the_console_chose(db):
    out, d = make(db, label="mini-2", system=True, containers=True)
    assert out["code"].startswith("OB2-") and len(out["code"]) < 260
    assert (d["approve"], d["system"], d["containers"], d["multi"]) == (True, True, True, False)
    assert d["urls"] == ["https://127.0.0.1:7443"] and d["pins"] == ["ab" * 32] and d["cik"] == CIK
    assert abs(d["expires_at"] - out["expires_at"]) < 60 and out["expires_at"] - time.time() == pytest.approx(J.DEFAULT_TTL_S, abs=5)
    row = db.one("SELECT * FROM join_codes WHERE code_id=?", (out["id"],))
    assert d["secret"] not in json.dumps(dict(row)), "only the secret's hash is stored"


def test_a_single_use_code_approves_once_and_then_says_used(db):
    _, d = make(db, label="mini-2")
    first = enroll(db, d["token"])
    assert (first["status"], first["join"]) == ("approved", "approved")
    second = enroll(db, d["token"], host="other")
    assert (second["status"], second["join"], second["join_error"]) == ("rejected", "refused", "used")
    ev = db.one("SELECT reason FROM events WHERE kind='join_code_refused'")
    assert ev["reason"].startswith("used") and "192.0.2.7" in ev["reason"]


@pytest.mark.parametrize("why", ["unknown", "expired", "revoked"])
def test_refusals_name_their_reason(db, why):
    out, d = make(db)
    token = d["token"]
    if why == "unknown":
        token = d["id"] + "." + "00" * 16
    elif why == "expired":
        db.x("UPDATE join_codes SET expires_at=? WHERE code_id=?", (time.time() - 1, out["id"]))
    else:
        J.revoke(db, out["id"], "owner")
    r = enroll(db, token)
    assert (r["join"], r["join_error"]) == ("refused", why)
    pending = db.q("SELECT * FROM enrollments WHERE status='pending'")
    assert pending == [], "a refused code leaves no request waiting on the Fleet page"


def test_a_multi_use_code_leaves_machines_pending_until_the_owner_approves(db):
    out, d = make(db, uses=3, ttl_s=86400, label="ignored-for-many")
    assert out["approve"] is False and d["multi"]
    rs = [enroll(db, d["token"], host=f"lab-{i}", name=f"lab-{i}") for i in range(3)]
    assert all((r["status"], r["join"]) == ("pending", "pending_approval") for r in rs)
    assert enroll(db, d["token"], host="lab-4")["join_error"] == "used"
    listed = J.listing(db)[0]
    assert (listed["uses"], listed["max_uses"], listed["state"]) == (3, 3, "used")
    assert [e["status"] for e in listed["enrollments"]] == ["pending"] * 3, "a refused attempt is not one of the code's machines"
    node = core.approve_enrollment(db, rs[1]["enrollment_id"], "owner")
    assert db.one("SELECT hostname FROM nodes WHERE node_id=?", (node["node_id"],))["hostname"] == "lab-1"


def test_a_multi_use_code_can_approve_automatically(db):
    _, d = make(db, uses=2, ttl_s=3600, approve=True, label="not-a-name")
    r = enroll(db, d["token"], host="lab-a")
    assert r["status"] == "approved"
    nid = db.one("SELECT node_id FROM enrollments WHERE enrollment_id=?", (r["enrollment_id"],))["node_id"]
    assert db.one("SELECT hostname FROM nodes WHERE node_id=?", (nid,))["hostname"] == "lab-a", \
        "a shared code's label never names every machine"


def test_limits_are_enforced(db):
    with pytest.raises(J.JoinError):
        make(db, uses=0)
    with pytest.raises(J.JoinError):
        make(db, ttl_s=60)
    with pytest.raises(J.JoinError):
        make(db, ttl_s=10 * 86400)                       # single-use: at most 7 days
    make(db, uses=5, ttl_s=10 * 86400)                   # multi-use: up to 30


def test_revoking_keeps_the_machines_that_joined(db):
    out, d = make(db, uses=2, ttl_s=3600, approve=True)
    r = enroll(db, d["token"])
    J.revoke(db, out["id"], "owner")
    nid = db.one("SELECT node_id FROM enrollments WHERE enrollment_id=?", (r["enrollment_id"],))["node_id"]
    assert db.one("SELECT lifecycle FROM nodes WHERE node_id=?", (nid,))["lifecycle"] == "enrolled"
    assert enroll(db, d["token"], host="b")["join_error"] == "revoked"
    assert J.listing(db)[0]["state"] == "revoked"


def test_a_device_code_approves_the_machine_that_shows_it(db):
    r = core.enroll(db, "kvm-box", FACTS, "192.0.2.9", node_key_and_csr()[1], user_code="wdjb mjht", name="rack-3")
    assert r["status"] == "pending"
    assert db.one("SELECT user_code FROM enrollments")["user_code"] == "WDJB-MJHT"
    with pytest.raises(core.ApiError):
        core.admit_by_user_code(db, "BCDF-GHJK", "owner")             # nobody shows that one
    with pytest.raises(core.ApiError):
        core.admit_by_user_code(db, "AEIO-UAEI", "owner")             # not in the alphabet
    out = core.admit_by_user_code(db, "WDJB-MJHT", "owner")
    assert db.one("SELECT hostname FROM nodes WHERE node_id=?", (out["node_id"],))["hostname"] == "rack-3"


def test_an_ob1_table_is_replaced(tmp_path):
    import sqlite3
    p = tmp_path / "oarbank.sqlite3"
    c = sqlite3.connect(p)
    c.execute("CREATE TABLE join_codes (code_hash TEXT PRIMARY KEY, label TEXT, created_by TEXT, created_at REAL,"
              " expires_at REAL, used_at REAL, node_id TEXT)")
    c.execute("CREATE TABLE enrollments (enrollment_id TEXT PRIMARY KEY, hostname TEXT, facts_json TEXT, peer_ip TEXT,"
              " ts_node_id TEXT, status TEXT NOT NULL, node_id TEXT, created_at REAL, decided_at REAL, decided_by TEXT,"
              " csr_pem TEXT, cert_json TEXT)")
    c.commit()
    c.close()
    db = make_db(p, modules=())
    assert "code_id" in [r[1] for r in db.conn.execute("PRAGMA table_info(join_codes)")]
    assert {"join_code_id", "user_code", "requested_name"} <= {r[1] for r in db.conn.execute("PRAGMA table_info(enrollments)")}
