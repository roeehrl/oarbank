"""Datasets by origin (docs/design/datasets-media-checkpoints.md, #10): datasets.create and datasets.register name files
by digest and size with https origins for blobs the coordinator does not hold; the operator's origin host policy applies
at registration and whenever files are served; agents stage origin first, and the coordinator fetches a blob from its
origins only when a node asks for it (every origin failed there), once, streaming it while it writes it, adopting it only
when the digest matches, and never from a non-public address."""
import asyncio
import datetime
import hashlib
import http.server
import ipaddress
import os
import ssl
import threading
from pathlib import Path

import httpx
import pytest
from oarbank_sdk import effects as fx

from oarbank.coordinator import blobstore, clock, core, effects, ops

from helpers import FIXTURES, agent_client, enrolled_node, install, make_db, node_headers, run_op

REEL_DIR = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "reel"
MODEL = os.urandom(2 * 1024 * 1024 + 123)
MODEL_SHA = hashlib.sha256(MODEL).hexdigest()
HOST = "origin.example.org"


@pytest.fixture
def db(tmp_path):
    clock.set_fake(None)
    d = make_db(tmp_path / "oarbank.sqlite3")
    install(d, REEL_DIR)
    from oarbank.coordinator import modcalls
    modcalls.use(d)
    yield d
    d.conn.close()


def import_asset(db, url, digest=MODEL_SHA, size=len(MODEL), did="asset:model-1"):
    return run_op(db, "mod.reel.import_asset", params={"dataset_id": did, "url": url, "sha256": digest, "size": size,
                                                       "name": "model.bin"})


def test_a_module_registers_a_large_file_by_url_and_digest_without_the_coordinator_holding_it(db):
    import_asset(db, f"https://{HOST}/models/model.bin")
    d = db.one("SELECT * FROM datasets WHERE dataset_id='asset:model-1'")
    assert d["module"] == "reel" and d["kind"] == "asset"
    assert not db.one("SELECT 1 FROM blobs WHERE digest=?", (MODEL_SHA,))            # nothing passed through the coordinator
    der, _ = enrolled_node(db, "w")
    m = agent_client(db).get("/v1/datasets/asset:model-1", headers=node_headers(der)).json()
    assert m["files"] == [{"path": "model.bin", "digest": MODEL_SHA, "size": len(MODEL), "origins": [f"https://{HOST}/models/model.bin"]}]


@pytest.mark.parametrize("url,why", [("http://origin.example.org/m.bin", "https"), ("https://10.1.2.3/m.bin", "IP"),
                                     ("https://localhost/m.bin", "public"), ("https://nas.local/m.bin", "public")])
def test_origins_that_are_not_https_to_a_public_name_are_refused(db, url, why):
    with db.tx():
        with pytest.raises(effects.EffectError) as e:
            effects.apply(db, "reel", {"datasets.create"}, [{"kind": "datasets.create", "args": {
                "dataset_id": "asset:x", "kind": "asset", "meta": {},
                "files": [{"path": "m.bin", "digest": MODEL_SHA, "size": 1, "origins": [url]}]}}])
    assert e.value.code == "bad_dataset_file" and why in e.value.detail


def test_digest_and_size_are_mandatory_and_a_held_blob_must_match_its_size(db):
    for f, code in [({"path": "m.bin", "digest": MODEL_SHA, "origins": [f"https://{HOST}/m"]}, "bad_dataset_file"),
                    ({"path": "m.bin", "digest": MODEL_SHA, "size": 5}, "unknown_blob")]:
        with db.tx():
            with pytest.raises(effects.EffectError) as e:
                effects.apply(db, "reel", {"datasets.create"}, [{"kind": "datasets.create", "args": {
                    "dataset_id": "asset:y", "kind": "asset", "files": [f]}}])
        assert e.value.code == code
    db.x("INSERT INTO blobs(digest,path,size) VALUES(?,?,?)", (MODEL_SHA, "/dev/null", len(MODEL)))
    with db.tx():
        with pytest.raises(effects.EffectError) as e:
            effects.apply(db, "reel", {"datasets.create"}, [{"kind": "datasets.create", "args": {
                "dataset_id": "asset:z", "kind": "asset",
                "files": [{"path": "m.bin", "digest": MODEL_SHA, "size": 7, "origins": [f"https://{HOST}/m"]}]}}])
    assert e.value.code == "size_mismatch"


def test_the_origin_host_policy_applies_at_registration_and_whenever_files_are_served(db):
    import_asset(db, f"https://{HOST}/m.bin")
    imp = run_op(db, "settings.origins.update", "dataset_origins", params={"hosts": ["*.huggingface.co"]})
    assert imp["result"]["hosts"] == ["*.huggingface.co"]
    with pytest.raises(ops.OpError) as e:
        import_asset(db, f"https://{HOST}/other.bin", did="asset:model-2")
    assert "origin host policy" in str(e.value.detail)
    import_asset(db, "https://cdn-lfs.huggingface.co/m.bin", did="asset:model-3")
    der, _ = enrolled_node(db, "w")
    agent = agent_client(db)
    old = agent.get("/v1/datasets/asset:model-1", headers=node_headers(der)).json()
    assert old["files"][0]["origins"] == []                        # no longer admitted: the coordinator is the only source
    with pytest.raises(core.ApiError, match="not host patterns"):
        run_op(db, "settings.origins.update", "dataset_origins", params={"hosts": ["not a host"]})


def test_the_operators_register_takes_origins_and_a_modules_kinds(db):
    from oarbank.coordinator import datasets
    r = datasets.register(db, {"dataset_id": "asset:op", "kind": "asset", "module": "reel",
                               "files": [{"path": "w.bin", "digest": MODEL_SHA, "size": len(MODEL), "origins": [f"https://{HOST}/w"]}]})
    assert r["module"] == "reel"
    with pytest.raises(ValueError, match="kinds"):
        datasets.register(db, {"dataset_id": "x:1", "kind": "weights", "module": "reel", "files": []})
    with pytest.raises(ValueError, match="origin"):
        datasets.register(db, {"dataset_id": "x:2", "kind": "weights",
                               "files": [{"path": "w", "digest": MODEL_SHA, "size": 1, "origins": ["http://x.org/w"]}]})


# ---------------------------------------------------------------------------- the coordinator's fallback fetch

def _cert(tmp: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    (tmp / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
    return tmp / "cert.pem", tmp / "key.pem"


@pytest.fixture
def origin(tmp_path, monkeypatch):
    """A local https origin for HOST: /m.bin (ranges), /moved (a redirect to /m.bin), /bad (other bytes)."""
    cert, key = _cert(tmp_path)
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append(self.path)
            if self.path == "/moved":
                self.send_response(302)
                self.send_header("Location", "/m.bin")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = MODEL if self.path == "/m.bin" else os.urandom(len(MODEL))
            start = int(self.headers["Range"][6:-1]) if self.headers.get("Range") else 0
            self.send_response(206 if start else 200)
            self.send_header("Content-Length", str(len(body) - start))
            self.end_headers()
            self.wfile.write(body[start:])

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    async def resolve(host, port):
        assert host == HOST
        return "127.0.0.1"
    monkeypatch.setattr(blobstore, "_resolve", resolve)
    monkeypatch.setattr(blobstore, "ssl_context", lambda: ssl.create_default_context(cafile=str(cert)))
    yield f"https://{HOST}:{srv.server_address[1]}", hits
    srv.shutdown()


def _agent(db):
    der, _ = enrolled_node(db, "w")
    c = agent_client(db)
    c.headers.update(node_headers(der))
    return c


def test_a_node_whose_origins_failed_gets_the_blob_from_the_coordinator_which_fetches_it_once(db, origin):
    base, hits = origin
    import_asset(db, f"{base}/moved")                          # the origin answers with a redirect to its file
    agent = _agent(db)
    r = agent.get(f"/v1/blobs/{MODEL_SHA}")
    assert r.status_code == 200 and r.content == MODEL
    assert blobstore.path(db, MODEL_SHA).read_bytes() == MODEL and db.one("SELECT 1 FROM events WHERE kind='origin_fetched'")
    assert hits == ["/moved", "/m.bin"]
    r = agent.get(f"/v1/blobs/{MODEL_SHA}", headers={"range": "bytes=1000-"})
    assert r.status_code == 206 and r.content == MODEL[1000:]
    assert hits == ["/moved", "/m.bin"]                        # served from the coordinator's copy from now on


def test_concurrent_nodes_share_one_fetch_and_a_resuming_node_gets_the_rest(db, origin):
    base, hits = origin
    import_asset(db, f"{base}/m.bin")
    from oarbank.coordinator import app as coord_app
    der, _ = enrolled_node(db, "w")
    app = coord_app.agent_app(db)

    async def as_peer(scope, receive, send):
        if scope["type"] == "http":
            scope = {**scope, "state": {**scope.get("state", {}), "tls_peer_der": der}}
        await app(scope, receive, send)

    async def both():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=as_peer), base_url="http://t") as c:
            return await asyncio.gather(c.get(f"/v1/blobs/{MODEL_SHA}"), c.get(f"/v1/blobs/{MODEL_SHA}", headers={"range": "bytes=500-"}))
    a, b = asyncio.run(both())
    assert a.content == MODEL and (b.status_code, b.content) == (206, MODEL[500:])
    assert hits == ["/m.bin"]


def test_an_origin_serving_other_bytes_is_never_adopted(db, origin):
    base, _ = origin
    import_asset(db, f"{base}/bad")
    r = _agent(db).get(f"/v1/blobs/{MODEL_SHA}")
    assert r.content != MODEL                                  # the node's own digest check refuses it
    assert blobstore.path(db, MODEL_SHA) is None and db.one("SELECT 1 FROM events WHERE kind='origin_fetch_failed'")


def test_no_origin_answering_is_a_502_and_unknown_blobs_a_404(db, origin):
    import_asset(db, f"https://{HOST}:1/m.bin")
    agent = _agent(db)
    r = agent.get(f"/v1/blobs/{MODEL_SHA}")
    assert r.status_code == 502 and r.json()["error"] == "origin_failed"
    assert agent.get(f"/v1/blobs/{'ab' * 32}").status_code == 404


def test_a_name_resolving_to_a_private_address_is_never_fetched(monkeypatch):
    """SSRF: every address a name resolves to must be public, and the connection goes to the checked address."""
    for ip, ok in [("127.0.0.1", False), ("10.0.0.5", False), ("169.254.169.254", False), ("192.168.1.1", False),
                   ("100.64.0.1", False), ("::1", False), ("fd00::1", False), ("::ffff:127.0.0.1", False),
                   ("1.1.1.1", True), ("2606:4700:4700::1111", True)]:
        assert blobstore.public(ip) is ok, ip

    async def lookup(host, port, type=0):
        return [(2, 1, 6, "", ("93.184.216.34", port)), (2, 1, 6, "", ("10.0.0.7", port))]

    async def run():
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(loop, "getaddrinfo", lookup)
        with pytest.raises(blobstore.OriginError, match="not a public address"):
            await blobstore._resolve("mixed.example.org", 443)
    asyncio.run(run())
    assert ipaddress.ip_address("93.184.216.34").is_global
