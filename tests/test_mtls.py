"""The TLS agent listener (D29): an agent learns the CA pin from the CIK-signed identity, enrolls with a CSR, and is
then identified only by its client certificate; renewal rotates it; retiring the node revokes it."""
import base64
import json
import socket
import ssl
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID

from helpers import FACTS, make_db, node_key_and_csr
from oarbank.coordinator import app as coord_app, core, identity, tlsca
from oarbank.coordinator.tlsproto import PeerCertH11


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TLSServer:
    def __init__(self, db):
        home = db.root
        tlsca.ensure_ca(home, identity.fleet_id(db))
        self.port = free_port()
        cfg = uvicorn.Config(coord_app.agent_app(db), host="127.0.0.1", port=self.port, http=PeerCertH11,
                             log_level="error", **tlsca.server_context(home, ["127.0.0.1"]))
        self.server = uvicorn.Server(cfg)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.url = f"https://127.0.0.1:{self.port}"

    def __enter__(self):
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return self
            time.sleep(0.025)
        raise RuntimeError("server did not start")

    def __exit__(self, *a):
        self.server.should_exit = True
        self.thread.join(5)


def client(tmp_path, ca_pem, cert_pem=None, key=None, name="n"):
    (tmp_path / f"{name}-ca.pem").write_text(ca_pem)
    ctx = ssl.create_default_context(cafile=str(tmp_path / f"{name}-ca.pem"))
    if cert_pem:
        (tmp_path / f"{name}.pem").write_text(cert_pem)
        (tmp_path / f"{name}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                                 serialization.NoEncryption()))
        ctx.load_cert_chain(str(tmp_path / f"{name}.pem"), str(tmp_path / f"{name}.key"))
    # no keep-alive: uvicorn closes idle connections after 5 s, and a reused closed one is a broken pipe on a slow run
    return httpx.Client(verify=ctx, timeout=10, limits=httpx.Limits(max_keepalive_connections=0))


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "home" / "oarbank.sqlite3")


def test_enroll_by_csr_then_the_node_is_its_certificate(db, tmp_path):
    with TLSServer(db) as s:
        # 1. before trusting anything: the identity proof, over TLS without verification, names the CA pin it signs
        boot = httpx.Client(verify=False, timeout=10)
        proof = boot.get(f"{s.url}/v1/identity", params={"nonce": "n1"}).json()
        doc = json.loads(proof["payload"])
        Ed25519PublicKey.from_public_bytes(base64.b64decode(doc["cik"])).verify(base64.b64decode(proof["sig"]),
                                                                                proof["payload"].encode())
        ca_pem = tlsca.ca_pem(db.root)
        assert doc["tls"]["ca_spki_sha256"] == tlsca.spki_sha256(x509.load_pem_x509_certificate(ca_pem.encode()))
        pinned = client(tmp_path, ca_pem)                                      # from now on: verified against the pin
        # 2. enroll with a CSR; an enrollment without one is refused
        assert pinned.post(f"{s.url}/v1/agent/enroll", json={"hostname": "mini", "facts": FACTS}).status_code == 400
        key, csr = node_key_and_csr()
        eid = pinned.post(f"{s.url}/v1/agent/enroll", json={"hostname": "mini", "facts": FACTS, "csr": csr}).json()["enrollment_id"]
        core.approve_enrollment(db, eid, "test")
        st = pinned.get(f"{s.url}/v1/agent/enroll/{eid}").json()
        assert st["status"] == "approved" and "BEGIN CERTIFICATE" in st["cert_pem"]
        assert pinned.get(f"{s.url}/v1/agent/enroll/{eid}").json() == {"status": "claimed"}          # issued once
        node_id = st["node_id"]
        assert db.one("SELECT client_cert_fp FROM nodes WHERE node_id=?", (node_id,))["client_cert_fp"]
        # 3. the certificate is the credential; nothing else is accepted here
        c = client(tmp_path, ca_pem, st["cert_pem"], key)
        r = c.post(f"{s.url}/v1/agent/hello", json={"agent_version": "1.0.0", "boot_id": "b", "facts": FACTS, "live_attempts": []})
        assert r.status_code == 200 and r.json()["node_id"] == node_id and r.headers["x-oarbank-epoch"] == "1"
        r = pinned.post(f"{s.url}/v1/agent/hello", json={}, headers={"authorization": "Bearer whatever"})
        assert r.status_code == 401 and r.json()["error"] == "client_certificate_required"
        # 4. renewal: the old certificate works until the new one is used, then never again
        key2, csr2 = node_key_and_csr()
        new = c.post(f"{s.url}/v1/agent/cert", json={"csr": csr2}).json()
        c2 = client(tmp_path, ca_pem, new["cert_pem"], key2, name="n2")
        assert c.post(f"{s.url}/v1/agent/heartbeat", json={"attempts": []}).status_code == 200
        assert c2.post(f"{s.url}/v1/agent/heartbeat", json={"attempts": []}).status_code == 200
        assert c.post(f"{s.url}/v1/agent/heartbeat", json={"attempts": []}).status_code == 401
        # 5. a certificate from another CA never gets through the TLS layer
        other = tmp_path / "other"
        other.mkdir()
        tlsca.ensure_ca(other, "fleet_other")
        stray_key, stray_csr = node_key_and_csr()
        stray = tlsca.issue_client(other, stray_csr, node_id)
        with pytest.raises(httpx.HTTPError):
            client(tmp_path, ca_pem, stray["cert_pem"], stray_key, name="stray").post(f"{s.url}/v1/agent/heartbeat",
                                                                                       json={"attempts": []}).json()
        # 6. retiring the node revokes its certificate
        db.x("UPDATE nodes SET lifecycle='retired', client_cert_fp=NULL, client_cert_prev_fp=NULL WHERE node_id=?", (node_id,))
        assert c2.post(f"{s.url}/v1/agent/heartbeat", json={"attempts": []}).status_code == 401


def test_certificates_are_p256_with_strict_extensions(db, tmp_path):
    tlsca.ensure_ca(db.root, "fleet_x")
    with pytest.raises(tlsca.CAError, match="P-256"):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        k = ed25519.Ed25519PrivateKey.generate()
        bad = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])).sign(k, None)
        tlsca.issue_client(db.root, bad.public_bytes(serialization.Encoding.PEM).decode(), "n_1")
    _, csr = node_key_and_csr()
    cert = x509.load_pem_x509_certificate(tlsca.issue_client(db.root, csr, "n_1")["cert_pem"].encode())
    for ext in (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage, x509.SubjectKeyIdentifier,
                x509.AuthorityKeyIdentifier, x509.SubjectAlternativeName):
        cert.extensions.get_extension_for_class(ext)
    assert tlsca.node_of(cert.public_bytes(serialization.Encoding.DER)) == "n_1"
    assert (db.root / "tls" / "ca.key").stat().st_mode & 0o077 == 0
