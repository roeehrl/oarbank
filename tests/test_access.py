"""Who may administer the coordinator (access.py): the admin token, accounts with password + TOTP, passkeys, sessions,
personal access tokens, roles, the Host allowlist and owner-only files."""
import base64
import hashlib
import json
import os
import struct
import time

import pytest

from helpers import loosen, make_db
from oarbank.coordinator import access as A


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def test_totp_matches_rfc_6238_and_refuses_replays():
    seed = base64.b32encode(b"12345678901234567890").decode()
    assert A.totp_at(seed, 59 // 30) == "287082"                    # RFC 6238 appendix B, SHA-1, 6 digits
    assert A.totp_at(seed, 1111111109 // 30) == "081804"
    step = A.totp_step(seed, "287 082", 0, now=59)
    assert step == 1 and A.totp_step(seed, "287082", step, now=59) is None          # used once
    assert A.totp_step(seed, "000000", 0, now=59) is None and A.totp_step(seed, "12ab56", 0, now=59) is None


def test_password_login_needs_both_factors_and_locks_after_failures(db):
    seed = A.create_account(db, "ana", "operator", "correct horse battery", "t")["totp_secret"]
    with pytest.raises(A.AccessError):
        A.create_account(db, "bob", "viewer", "short", "t")                         # 12+ characters
    now = time.time()
    code = A.totp_at(seed, int(now // 30))
    with pytest.raises(A.AccessError, match="bad_login"):
        A.password_login(db, "ana", "correct horse battery", "000000", now)
    a = A.password_login(db, "ana", "correct horse battery", code, now)
    assert a["name"] == "ana" and A.account(db, "ana")["totp_last_step"] == int(now // 30)
    for _ in range(A.LOCK_AFTER):
        with pytest.raises(A.AccessError):
            A.password_login(db, "ana", "wrong password here", code, now + 60)
    with pytest.raises(A.AccessError):                                               # locked, even with both right
        A.password_login(db, "ana", "correct horse battery", A.totp_at(seed, int((now + 60) // 30) + 1), now + 61)
    assert A.account(db, "ana")["pw_hash"].startswith("scrypt$")


def test_sessions_tokens_and_links_are_stored_only_as_hashes(db):
    A.create_account(db, "owner", "admin", None, "t")
    s = A.new_session(db, "owner", "test")
    tok = A.new_token(db, "owner", "ci", "viewer", 1)
    link = A.new_login_link(db, "owner")
    dump = "\n".join(db.conn.iterdump())
    assert s["sid"] not in dump and tok["token"] not in dump and link not in dump
    assert A.session_for(db, s["sid"])["account"] == "owner" and A.token_identity(db, tok["token"])["role"] == "viewer"
    assert A.session_for(db, s["sid"], now=time.time() + A.SESSION_TTL_S + 1) is None
    A.use_login_link(db, link)
    with pytest.raises(A.AccessError):
        A.use_login_link(db, link)
    with pytest.raises(A.AccessError, match="exceed"):
        A.create_account(db, "vic", "viewer", None, "t") and A.new_token(db, "vic", "x", "admin", 1)


def test_the_last_admin_cannot_be_disabled_and_disabling_ends_access(db):
    A.create_account(db, "owner", "admin", None, "t")
    with pytest.raises(A.AccessError, match="last_admin"):
        A.set_disabled(db, "owner", True)
    A.create_account(db, "ops", "admin", None, "t")
    s = A.new_session(db, "ops", "test")
    tok = A.new_token(db, "ops", "x", "admin", 1)["token"]
    A.set_disabled(db, "ops", True)
    assert A.session_for(db, s["sid"]) is None and A.token_identity(db, tok) is None


def test_admin_token_and_secrets_are_owner_only(tmp_path):
    from oarbank.platform import files
    tok = A.ensure_admin_token(tmp_path)
    assert A.check_admin_token(tmp_path, tok) and not A.check_admin_token(tmp_path, tok + "x")
    assert files.owner_only(tmp_path / "admin.token")
    assert A.ensure_admin_token(tmp_path) == tok != A.rotate_admin_token(tmp_path)
    (tmp_path / "oarbank.sqlite3").write_text("x")
    loosen(tmp_path / "oarbank.sqlite3")
    loosen(tmp_path)
    assert not files.owner_only(tmp_path / "oarbank.sqlite3") and not files.owner_only(tmp_path)
    changed = files.tighten_home(tmp_path)
    assert str(tmp_path / "oarbank.sqlite3") in changed and files.owner_only(tmp_path)
    assert files.owner_only(tmp_path / "oarbank.sqlite3") and files.owner_only(tmp_path / "admin.token")


def test_hosts_and_funnel():
    allowed = A.allowed_hosts(7401, ["oarbank.example.ts.net"])
    assert A.host_ok("127.0.0.1:7401", allowed) and A.host_ok("localhost:7401", allowed)
    assert A.host_ok("oarbank.example.ts.net", allowed) and not A.host_ok("evil.example", allowed)
    assert not A.host_ok("127.0.0.1:7400", allowed) and not A.host_ok(None, allowed)
    assert A.via_funnel({"tailscale-funnel-request": "?1"}) and not A.via_funnel({})


def test_a_real_listener_answers_only_to_allowed_hosts(db):
    import httpx
    from helpers import admin_headers
    from oarbank.coordinator import app as coord_app
    from test_console import Server
    A.TEST_HOSTS.discard("testserver")
    try:
        with Server(coord_app.admin_app(db)) as s:
            url = f"http://127.0.0.1:{s.port}/api/v1/fleet"
            assert httpx.get(url, headers=admin_headers(db)).status_code == 200
            assert httpx.get(url, headers={**admin_headers(db), "host": f"rebind.example:{s.port}"}).status_code == 421
            from helpers import set_fleet
            set_fleet(db, "console_hosts", ["rebind.example"])
            assert httpx.get(url, headers={**admin_headers(db), "host": f"rebind.example:{s.port}"}).status_code == 200
    finally:
        A.TEST_HOSTS.add("testserver")


def test_passkey_rp_needs_a_host_name_and_a_secure_context():
    assert A.rp_for("localhost:7400", "http") == ("localhost", "http://localhost:7400")
    assert A.rp_for("oarbank.example.ts.net", "https") == ("oarbank.example.ts.net", "https://oarbank.example.ts.net")
    for host, scheme in (("127.0.0.1:7400", "http"), ("[::1]:7400", "http"), ("oarbank.example.ts.net", "http"),
                         ("100.64.0.10", "https")):
        with pytest.raises(A.AccessError):
            A.rp_for(host, scheme)


# ------------------------------------------------------------------ a software authenticator for the ceremonies

class SoftAuthenticator:
    """Just enough of a platform authenticator: one P-256 key, `none` attestation, user verified."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.count = 0

    @staticmethod
    def b64u(b):
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    def _cose(self):
        import cbor2
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def _client_data(self, typ, challenge_b64u, origin):
        return json.dumps({"type": typ, "challenge": challenge_b64u, "origin": origin, "crossOrigin": False}).encode()

    def create(self, options, origin):
        import cbor2
        rp_hash = hashlib.sha256(options["rp"]["id"].encode()).digest()
        attested = b"\0" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose()
        auth = rp_hash + bytes([0x45]) + struct.pack(">I", self.count) + attested       # UP | UV | AT
        cd = self._client_data("webauthn.create", options["challenge"], origin)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": self.b64u(self.cred_id), "rawId": self.b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": self.b64u(cd), "attestationObject": self.b64u(att)},
                "clientExtensionResults": {}}

    def get(self, options, origin):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        self.count += 1
        auth = hashlib.sha256(options["rpId"].encode()).digest() + bytes([0x05]) + struct.pack(">I", self.count)
        cd = self._client_data("webauthn.get", options["challenge"], origin)
        sig = self.key.sign(auth + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": self.b64u(self.cred_id), "rawId": self.b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": self.b64u(cd), "authenticatorData": self.b64u(auth),
                             "signature": self.b64u(sig), "userHandle": None}, "clientExtensionResults": {}}


def test_passkey_registration_and_sign_in(db):
    A.create_account(db, "owner", "admin", None, "t")
    rp, origin = A.rp_for("localhost:7400", "http")
    dev = SoftAuthenticator()
    o = A.passkey_register_options(db, "owner", rp)
    assert o["options"]["authenticatorSelection"]["residentKey"] == "required"
    out = A.passkey_register(db, "owner", o["challenge_id"], dev.create(o["options"], origin), origin, "laptop")
    assert out["account"] == "owner" and A.passkeys(db, "owner")[0]["label"] == "laptop"
    with pytest.raises(A.AccessError, match="bad_challenge"):                        # a challenge works once
        A.passkey_register(db, "owner", o["challenge_id"], dev.create(o["options"], origin), origin)
    lo = A.passkey_login_options(db, rp)
    assert A.passkey_login(db, lo["challenge_id"], dev.get(lo["options"], origin), origin)["name"] == "owner"
    lo = A.passkey_login_options(db, rp)
    with pytest.raises(A.AccessError):                                               # another origin: phishing
        A.passkey_login(db, lo["challenge_id"], dev.get(lo["options"], "http://evil.localhost:7400"), origin)
    lo = A.passkey_login_options(db, rp)
    stolen = dev.get(lo["options"], origin)
    dev.count = 0                                                                     # a cloned key's counter goes back
    lo2 = A.passkey_login_options(db, rp)
    A.passkey_login(db, lo["challenge_id"], stolen, origin)
    with pytest.raises(A.AccessError):
        A.passkey_login(db, lo2["challenge_id"], dev.get(lo2["options"], origin), origin)


def test_a_module_scoped_token_runs_only_that_modules_operations(db):
    from fastapi.testclient import TestClient
    from oarbank.coordinator import app as coord_app
    A.create_account(db, "owner", "admin", None, "t")
    tok = A.new_token(db, "owner", "cli toy", "operator", 1 / 24, scope="module:toy")["token"]
    c = TestClient(coord_app.admin_app(db), headers={"authorization": f"Bearer {tok}"})
    assert c.get("/api/v1/fleet").status_code == 200                                    # reads are fine
    r = c.post("/api/v1/ops/fleet.pause", json={"reason": "x"})
    assert r.status_code == 403 and r.json()["error"] == "token_scope"
    r = c.post("/api/v1/ops/mod.toy.set_favorite", json={"params": {"n": 3}, "reason": "x"})
    assert r.status_code != 403, r.text                                              # its own operation is allowed
    assert c.post("/api/v1/modules/bundles", content=b"x").status_code == 403         # uploads need admin


def test_module_cli_runs_sandboxed_with_its_scoped_token(db, tmp_path):
    import shutil
    import subprocess
    import sys
    from helpers import TOY_DIR, admin_headers, bundle
    from oarbank.coordinator import app as coord_app, modstore
    from test_console import Server
    src = tmp_path / "toy"
    shutil.copytree(TOY_DIR, src)
    m = (src / "oarbank-module.toml").read_text(encoding="utf-8").replace('version = "0.1.0"', 'version = "0.5.0"', 1)
    (src / "oarbank-module.toml").write_text(m + '\n[cli]\nexec = ["python", "-I", "{bundle}/toy_cli.py"]\n')
    (src / "toy_cli.py").write_text(
        "import json, os, sys, urllib.request\n"
        "u, t = os.environ['OARBANKD_URL'], os.environ['OARBANK_TOKEN']\n"
        "def call(path, body=None):\n"
        "    req = urllib.request.Request(u + path, data=json.dumps(body).encode() if body is not None else None,\n"
        "                                 headers={'authorization': 'Bearer ' + t, 'content-type': 'application/json'})\n"
        "    try:\n"
        "        return urllib.request.urlopen(req, timeout=10).status\n"
        "    except urllib.error.HTTPError as e:\n"
        "        return e.code\n"
        "try:\n"
        f"    open({str(tmp_path / 'escape')!r}, 'w'); escaped = True\n"
        "except OSError:\n"
        "    escaped = False\n"
        "print(json.dumps({'args': sys.argv[1:], 'fleet': call('/api/v1/fleet'), 'pause': call('/api/v1/ops/fleet.pause', {'reason': 'x'}),\n"
        "                  'escaped': escaped, 'platform': os.environ.get('OARBANK_PLATFORM')}))\n")
    from oarbank_sdk import bundle as B
    out, _ = B.build(src, tmp_path / "toy-0.5.0.mfb")
    r = modstore.install(db, out, actor="t", self_test=False)
    modstore.canary(db, "toy", "0.5.0", ["n_none"])
    modstore.promote(db, "toy")
    A.create_account(db, "owner", "admin", None, "t")
    with Server(coord_app.admin_app(db)) as s:
        env = {**__import__("os").environ, "OARBANKD_URL": f"http://127.0.0.1:{s.port}",
               "OARBANK_TOKEN": admin_headers(db)["authorization"].split()[1]}
        p = subprocess.run([sys.executable, "-c",
                            "import sys; sys.argv = ['oarbank', 'cli', 'toy', 'hello']; from oarbank.cli.main import main; main()"],
                           capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout.strip().splitlines()[-1])
    assert doc["args"] == ["hello"] and doc["fleet"] == 200 and doc["pause"] == 403 and doc["escaped"] is False
    assert doc["platform"] == __import__("oarbank_sdk.portable", fromlist=["x"]).host_platform()
