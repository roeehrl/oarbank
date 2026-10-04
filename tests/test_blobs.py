"""The blob transport (docs/design/datasets-media-checkpoints.md, "The blob transport"): the resumable, digest-checked
upload on the agent and admin APIs (after tus 1.0, the digest as the upload's id), per-uploader partials, the limits,
the download route, and releasing blobs nothing names any more."""
import hashlib
import os
import time

import pytest
from fastapi.testclient import TestClient

from oarbank.coordinator import app as coord_app
from oarbank.coordinator import blobstore, clock

from helpers import admin_headers, agent_client, enrolled_node, make_db, node_headers

BODY = os.urandom(3 * 1024 * 1024 + 17)
DIGEST = hashlib.sha256(BODY).hexdigest()


@pytest.fixture
def db(tmp_path):
    clock.set_fake(None)
    d = make_db(tmp_path / "oarbank.sqlite3")
    yield d
    d.conn.close()


@pytest.fixture
def agent(db):
    der, _ = enrolled_node(db, "w")
    c = agent_client(db)
    c.headers.update(node_headers(der))
    return c


@pytest.fixture
def gui(db):
    return TestClient(coord_app.admin_app(db, coord_app.EventBus()), client=("127.0.0.1", 50000), headers=admin_headers(db))


def patch(c, base, digest, offset, chunk):
    return c.patch(f"{base}/uploads/{digest}", content=chunk, headers={"upload-offset": str(offset)})


@pytest.mark.parametrize("base", ["/v1", "/api/v1"])
def test_an_upload_resumes_from_the_coordinators_offset_and_becomes_a_blob_once_its_digest_matches(db, agent, gui, base):
    c = agent if base == "/v1" else gui
    assert c.post(f"{base}/uploads/{DIGEST}", json={"size": len(BODY)}).json() == {"offset": 0, "complete": False}
    r = patch(c, base, DIGEST, 0, BODY[:1_000_000])
    assert r.status_code == 204 and r.headers["upload-offset"] == "1000000" and "upload-complete" not in r.headers
    # a cut: the client asks again where the upload stands and goes on from there
    assert c.post(f"{base}/uploads/{DIGEST}", json={"size": len(BODY)}).json()["offset"] == 1_000_000
    stale = patch(c, base, DIGEST, 0, BODY[:10])                      # an earlier attempt's chunk arrives late
    assert stale.status_code == 409 and stale.headers["upload-offset"] == "1000000"
    blobstore._hashers.clear()                                         # as after a coordinator restart: rehashed from disk
    r = patch(c, base, DIGEST, 1_000_000, BODY[1_000_000:])
    assert r.status_code == 204 and r.headers["upload-complete"] == "1"
    assert blobstore.path(db, DIGEST).read_bytes() == BODY and db.one("SELECT size FROM blobs WHERE digest=?", (DIGEST,))["size"] == len(BODY)
    assert c.post(f"{base}/uploads/{DIGEST}", json={"size": len(BODY)}).json() == {"offset": len(BODY), "complete": True}
    assert not list(blobstore.upload_dir(db).glob("*.partial"))
    assert db.one("SELECT 1 FROM events WHERE kind='blob_uploaded'")


def test_bytes_that_do_not_hash_to_the_digest_are_dropped(db, agent):
    wrong = hashlib.sha256(b"something else").hexdigest()
    agent.post(f"/v1/uploads/{wrong}", json={"size": len(BODY)})
    r = patch(agent, "/v1", wrong, 0, BODY)
    assert r.status_code == 422 and r.json()["error"] == "digest_mismatch"
    assert blobstore.path(db, wrong) is None and not list(blobstore.upload_dir(db).glob("*.partial"))
    agent.post(f"/v1/uploads/{DIGEST}", json={"size": 10})
    assert patch(agent, "/v1", DIGEST, 0, BODY[:11]).json()["error"] == "too_long"


def test_partials_are_per_uploader(db, agent, gui):
    """Two parties uploading the same blob never write into each other's partial: neither can spoil the other's."""
    agent.post(f"/v1/uploads/{DIGEST}", json={"size": len(BODY)})
    gui.post(f"/api/v1/uploads/{DIGEST}", json={"size": len(BODY)})
    patch(agent, "/v1", DIGEST, 0, b"garbage" * 10)
    assert gui.post(f"/api/v1/uploads/{DIGEST}", json={"size": len(BODY)}).json()["offset"] == 0
    assert patch(gui, "/api/v1", DIGEST, 0, BODY).headers["upload-complete"] == "1"
    assert len(list(blobstore.upload_dir(db).glob("*.partial"))) == 1          # the node's, until it gives up or ages out


def test_limits_and_bad_requests(db, agent, gui, monkeypatch):
    assert agent.post("/v1/uploads/NOTHEX", json={"size": 1}).json()["error"] == "bad_digest"
    assert agent.post(f"/v1/uploads/{DIGEST}", json={"size": -1}).json()["error"] == "bad_size"
    monkeypatch.setattr(blobstore, "BLOB_MAX_BYTES", 100)
    assert agent.post(f"/v1/uploads/{DIGEST}", json={"size": 101}).status_code == 413
    monkeypatch.setattr(blobstore, "BLOB_MAX_BYTES", 1 << 40)
    monkeypatch.setattr(blobstore, "UPLOAD_PARTIAL_MAX_BYTES", 1000)
    assert agent.post(f"/v1/uploads/{DIGEST}", json={"size": 1001}).json()["error"] == "upload_space"
    assert patch(agent, "/v1", DIGEST, 0, b"x").json()["error"] == "no_upload"
    assert agent.patch(f"/v1/uploads/{DIGEST}", content=b"x").json()["error"] == "bad_offset"


def test_admin_uploads_need_an_operator_with_a_full_token(db, gui):
    from oarbank.coordinator import access
    access.create_account(db, "watcher", "viewer", None, "test")
    tok = access.new_token(db, "watcher", "t", "viewer", 1)["token"]
    r = gui.post(f"/api/v1/uploads/{DIGEST}", json={"size": 1}, headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 403 and r.json()["error"] == "forbidden_role"


def test_stale_partials_age_out(db, agent):
    agent.post(f"/v1/uploads/{DIGEST}", json={"size": len(BODY)})
    assert blobstore.sweep_partials(db) == 0
    assert blobstore.sweep_partials(db, now=time.time() + blobstore.PARTIAL_MAX_AGE_S + 60) == 1
    assert not list(blobstore.upload_dir(db).glob("*"))


def test_downloads_are_attachments_of_dataset_files_and_results_only(db, agent, gui):
    agent.post(f"/v1/uploads/{DIGEST}", json={"size": len(BODY)})
    patch(agent, "/v1", DIGEST, 0, BODY)
    assert gui.get(f"/api/v1/blobs/{DIGEST}").status_code == 404           # nothing names it yet
    from oarbank.coordinator import datasets
    datasets.register(db, {"dataset_id": "scene:up", "kind": "scene", "files": [{"path": "a.bin", "digest": DIGEST, "size": len(BODY)}]})
    r = gui.get(f"/api/v1/blobs/{DIGEST}", headers={"range": "bytes=10-19"})
    assert r.status_code == 206 and r.content == BODY[10:20]
    full = gui.get(f"/api/v1/blobs/{DIGEST}")
    assert full.content == BODY and full.headers["content-type"] == "application/octet-stream"
    assert full.headers["x-content-type-options"] == "nosniff" and "attachment" in full.headers["content-disposition"]
    assert full.headers["content-security-policy"].startswith("sandbox")
    d = gui.get("/api/v1/datasets/scene:up").json()
    assert d["files"][0]["held"] and d["size"] == len(BODY) and d["module"] is None


def test_release_deletes_only_blobs_nothing_names(db, agent):
    from oarbank.coordinator import datasets
    other = os.urandom(100)
    od = hashlib.sha256(other).hexdigest()
    for body, dig in ((BODY, DIGEST), (other, od)):
        agent.post(f"/v1/uploads/{dig}", json={"size": len(body)})
        patch(agent, "/v1", dig, 0, body)
    datasets.register(db, {"dataset_id": "scene:keep", "kind": "scene", "files": [{"path": "a", "digest": DIGEST, "size": len(BODY)}]})
    p = blobstore.path(db, od)
    assert blobstore.release(db, [DIGEST, od]) == 1
    assert blobstore.path(db, DIGEST) is not None and blobstore.path(db, od) is None and not p.exists()
