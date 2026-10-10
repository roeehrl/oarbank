"""Real loopback HTTP tests; installer/browser actions are always stubbed.

Every coordinator file, credential and signing key lives under tmp_path. The
integration backend runs the real CLI operations against the real admin app.
"""
import base64
import io
from urllib.parse import parse_qs, urlparse

import zxingcpp
from PIL import Image

import contextlib
import http.client
import json
import os
import socket
import subprocess
import threading
import time
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from helpers import admin_headers, make_db
from oarbank import setup, signing
from oarbank.cli import main as cli
from oarbank.coordinator import access, app, config as C, owner
from oarbank.platform import service


PASSWORD = "correct horse battery staple"
FORM = {"address": "127.0.0.1", "name": "admin", "password": PASSWORD, "confirmation": PASSWORD}


class TestBackend(setup.Backend):
    __test__ = False

    def __init__(self, db, monkeypatch):
        self.db = db
        self.home = C.HOME
        self.cli = cli
        self.console = "http://127.0.0.1:7400/login"
        self.installs = []
        self.running = False
        self.fail_install = False
        self.fail_signing = False
        self._addresses = []
        self.client = TestClient(app.admin_app(db, console_secret="test-console"), client=("127.0.0.1", 45678))
        monkeypatch.setattr(cli, "URL", "http://testserver")
        monkeypatch.setattr(cli, "auth_headers", lambda: admin_headers(db))
        def request(method, url, **kwargs):
            kwargs.pop("timeout", None)  # TestClient has no network timeout.
            return self.client.request(method, url, **kwargs)
        monkeypatch.setattr(cli, "http_request", request)

    def ready(self):
        return self.snapshot() if self.running else None

    def install(self, root, address):
        self.installs.append((root, address))
        if self.fail_install:
            raise setup.SetupError("The service installer failed (exit 9).", 503)
        self.running = True

    def signing(self, primary, backup):
        if self.fail_signing:
            raise SystemExit("owner.set_anchors: 409 signing refused")
        return super().signing(primary, backup)

    def confirm(self, name, password, code):
        try:
            access.password_login(self.db, name, password, code)
        except access.AccessError as e:
            raise setup.SetupError("Wrong password or authenticator code, or the account is locked.", e.status) from None


@pytest.fixture
def wizard(tmp_path, monkeypatch):
    home = tmp_path / "state"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("OARBANKD_HOME", str(home))
    monkeypatch.setenv("OARBANK_RELEASE_KEY", str(tmp_path / "keys" / "release-ed25519.key"))
    monkeypatch.setattr(C, "HOME", home)
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)
    monkeypatch.setattr(service, "state", lambda name: {"name": name, "installed": False, "pid": None})
    root = tmp_path / "installed root"
    root.mkdir()
    (root / "oarbank-coordinator.json").write_text('{"format":1,"version":"2.6.0"}')
    (root / "install-oarbankd.sh").write_text("exit 99")
    (root / "install-oarbankd.ps1").write_text("exit 99")
    backend = TestBackend(make_db(home / "oarbank.sqlite3"), monkeypatch)
    # The fixture's DB exists for real API tests, but is initially an empty new
    # installation. Production would create it only when the helper is submitted.
    result = setup.Wizard(root, backend=backend, home=home, primary=tmp_path / "keys" / "release-ed25519.key", ready_timeout=.01)
    monkeypatch.setattr(result, "_disk_configured", lambda: False)
    # A forgotten stub must fail rather than install or inspect anything on host.
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("Unstubbed subprocess"))
    monkeypatch.setattr(setup.webbrowser, "open", lambda *a, **kw: pytest.fail("Unstubbed browser launch"))
    yield result
    backend.client.close()
    backend.db.conn.close()


@contextlib.contextmanager
def serving(wizard):
    with setup.SetupServer(wizard) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=2)


def post(server, path="/start", body=None, headers=None):
    base = {"Origin": server.origin, "X-Oarbank-Setup": server.wizard.capability}
    base.update(headers or {})
    return httpx.post(server.origin + path, json=FORM if body is None else body, headers=base, trust_env=False, timeout=10)


def code(wizard):
    return access.totp_at(wizard.pending["enrollment"]["totp_secret"], int(time.time() // 30))


def test_no_install_on_get_and_secret_headers(wizard, capsys):
    with serving(wizard) as server:
        assert server.server_address[0] == "127.0.0.1"
        response = httpx.get(server.origin, trust_env=False)
        assert response.status_code == 200 and "Install and set up" in response.text
        assert wizard.capability not in response.text
        assert not wizard.backend.installs and not wizard.pending_path.exists()
        assert response.headers["Cache-Control"].startswith("no-store")
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert "img-src data:;" in response.headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert "'nonce-" in response.headers["Content-Security-Policy"]
        assert not capsys.readouterr().err


@pytest.mark.parametrize("headers,status", [
    ({"Host": "evil.example"}, 421),
    ({"Host": "localhost:7400"}, 421),
    ({"Origin": "https://evil.example"}, 403),
    ({"Origin": "null"}, 403),
    ({"Origin": ""}, 403),
    ({"Sec-Fetch-Site": "cross-site"}, 403),
    ({"Sec-Fetch-Site": "same-site"}, 403),
    ({"X-Oarbank-Setup": "forged"}, 403),
    ({"X-Oarbank-Setup": ""}, 403),
])
def test_forged_posts_have_no_effect(wizard, headers, status):
    with serving(wizard) as server:
        assert post(server, headers=headers).status_code == status
    assert not wizard.backend.installs and not wizard.pending_path.exists()
    assert not access.accounts(wizard.backend.db)


@pytest.mark.parametrize("forged,status", [("Host", 421), ("Origin", 403), ("X-Oarbank-Setup", 403), ("Sec-Fetch-Site", 403)])
def test_early_rejection_waits_for_bounded_body_then_delivers_http_error(wizard, monkeypatch, forged, status):
    rejected = threading.Event()
    original = setup.Handler._guard
    def guard(handler, write=False):
        try:
            return original(handler, write)
        except setup.SetupError:
            rejected.set()
            raise
    monkeypatch.setattr(setup.Handler, "_guard", guard)
    # Invalid JSON containing a credential-like string must only be discarded,
    # never parsed, reflected, logged or acted on after authentication fails.
    body = (PASSWORD.encode() + b"\x00not-json") * 300
    assert len(body) <= 16384
    with serving(wizard) as server, socket.create_connection(server.server_address, timeout=3) as connection:
        headers = {"Host": server.host, "Origin": server.origin, "X-Oarbank-Setup": wizard.capability,
                   "Content-Type": "application/json", "Content-Length": str(len(body))}
        headers[forged] = "same-site" if forged == "Sec-Fetch-Site" else "forged"
        request = "POST /start HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
        connection.sendall(request.encode())
        assert rejected.wait(timeout=1)
        connection.settimeout(.05)
        # The old handler sent/closed here, before the body reached its socket.
        with pytest.raises(socket.timeout):
            connection.recv(1)
        connection.settimeout(3)
        connection.sendall(body)
        response = http.client.HTTPResponse(connection)
        response.begin()
        assert response.status == status
        payload = response.read()
        assert PASSWORD.encode() not in payload
        assert response.getheader("Connection") == "close"
        assert connection.recv(1) == b""
    assert not wizard.backend.installs and not wizard.pending_path.exists()
    assert not access.accounts(wizard.backend.db)


def test_incomplete_rejected_body_has_absolute_timeout_and_server_recovers(wizard, monkeypatch):
    monkeypatch.setattr(setup.Handler, "REJECT_BODY_TIMEOUT", .15)
    with serving(wizard) as server, socket.create_connection(server.server_address, timeout=2) as connection:
        start = time.monotonic()
        connection.sendall((f"POST /start HTTP/1.1\r\nHost: {server.host}\r\nOrigin: {server.origin}\r\n"
                            "X-Oarbank-Setup: forged\r\nContent-Length: 16384\r\n\r\nx").encode())
        response = http.client.HTTPResponse(connection)
        response.begin()
        assert response.status == 403 and response.read()
        assert .1 <= time.monotonic() - start < 1
        assert post(server, "/state", {}).status_code == 200
    assert not wizard.backend.installs


@pytest.mark.parametrize("framing", ["Content-Length: 16385", "Content-Length: -1", "Content-Length: +5",
                                      "Content-Length: 5\r\nContent-Length: 5", "Transfer-Encoding: chunked",
                                      "Content-Length: 5\r\nTransfer-Encoding:"])
def test_ambiguous_or_oversized_rejected_framing_is_not_drained(wizard, framing):
    with serving(wizard) as server, socket.create_connection(server.server_address, timeout=2) as connection:
        start = time.monotonic()
        # No body is sent: waiting for it would be an unbounded framing mistake.
        connection.sendall((f"POST /start HTTP/1.1\r\nHost: {server.host}\r\nOrigin: {server.origin}\r\n"
                            f"X-Oarbank-Setup: forged\r\n{framing}\r\n\r\n").encode())
        response = http.client.HTTPResponse(connection)
        response.begin()
        assert response.status == 403 and response.read()
        assert time.monotonic() - start < .75
        assert connection.recv(1) == b""
    assert not wizard.backend.installs


def test_duplicate_host_origin_token_and_missing_origin(wizard):
    with serving(wizard) as server:
        data = json.dumps(FORM).encode()
        for duplicate in ("Host", "Origin", "X-Oarbank-Setup", "Content-Length"):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.putrequest("POST", "/start", skip_host=True)
            values = {"Host": server.host, "Origin": server.origin, "X-Oarbank-Setup": wizard.capability,
                      "Content-Type": "application/json", "Content-Length": str(len(data))}
            for key, value in values.items():
                connection.putheader(key, value)
                if key == duplicate:
                    connection.putheader(key, value)
            connection.endheaders(data)
            assert connection.getresponse().status in (400, 403, 421)
            connection.close()
        assert httpx.post(server.origin + "/start", json=FORM, headers={"X-Oarbank-Setup": wizard.capability}, trust_env=False).status_code == 403
    assert not wizard.backend.installs


@pytest.mark.parametrize("address", ["", "localhost", "http://127.0.0.1", "127.0.0.1:7443", "--help", "0.0.0.0", "::",
                                         "224.0.0.1", "ff02::1", "255.255.255.255", "fe80::1", "fe80::1%en0", "::ffff:127.0.0.1"])
def test_bad_addresses_refused_before_installer(wizard, address):
    with serving(wizard) as server:
        assert post(server, body={**FORM, "address": address}).status_code == 400
    assert not wizard.backend.installs and not wizard.pending_path.exists()


def test_unassigned_address_and_ipv6(wizard, monkeypatch):
    def unavailable(_):
        raise setup.SetupError("That address is not assigned to this computer.")
    monkeypatch.setattr(setup, "check_local_address", unavailable)
    with serving(wizard) as server:
        response = post(server, body={**FORM, "address": "192.0.2.42"})
        assert response.status_code == 400 and "not assigned" in response.text
    assert not wizard.backend.installs
    monkeypatch.setattr(setup, "check_local_address", lambda _: None)
    with serving(wizard) as server:
        assert post(server, body={**FORM, "address": "fd00:0:0::20"}).status_code == 200
    assert wizard.backend.installs[0][1] == "fd00::20"


@pytest.mark.parametrize("changes", [{"password": "short", "confirmation": "short"}, {"confirmation": "different"},
                                      {"password": None}, {"name": "Admin"}, {"name": "a"}, {"root": "/tmp/evil"},
                                      {"command": "whoami"}])
def test_bad_password_name_or_extra_fields_do_not_install(wizard, changes):
    with serving(wizard) as server:
        response = post(server, body={**FORM, **changes})
        assert response.status_code == 400 and PASSWORD not in response.text
    assert not wizard.backend.installs and not wizard.pending_path.exists()


def test_http_payload_limits_and_routes(wizard):
    with serving(wizard) as server:
        assert post(server, body=[]).status_code == 400
        try:
            assert post(server, body={**FORM, "password": "a" * 17000}).status_code == 400
        except httpx.ReadError:
            # Oversized framing is deliberately not drained. Windows can reset
            # that connection before the HTTP rejection reaches the client.
            # Subsequent requests below prove the server remains available.
            pass
        assert post(server, headers={"Content-Type": "text/plain"}).status_code == 415
        assert post(server, path="/run").status_code == 404
        assert post(server, path="/start?root=evil").status_code == 404
        assert httpx.get(server.origin + "/finish", trust_env=False).status_code == 404
        assert httpx.options(server.origin + "/start", trust_env=False).status_code == 501
    assert not wizard.backend.installs


def test_real_cli_setup_totp_completion_and_private_recovery(wizard, capsys):
    with serving(wizard) as server:
        response = post(server)
        assert response.status_code == 200, response.text
        seed = response.json()["totp_secret"]
        uri = response.json()["otpauth"]
        qr = response.json()["totp_qr"]
        assert qr.startswith("data:image/png;base64,")
        picture = Image.open(io.BytesIO(base64.b64decode(qr.split(",", 1)[1]))).convert("RGB")
        decoded = zxingcpp.read_barcode(picture)
        assert decoded is not None and decoded.format == zxingcpp.BarcodeFormat.QRCode
        assert decoded.text == uri
        account = urlparse(decoded.text)
        params = parse_qs(account.query)
        assert account.scheme == "otpauth" and account.netloc == "totp" and account.path == "/Oarbank:admin"
        assert params == {"secret": [seed], "issuer": ["Oarbank"], "algorithm": ["SHA1"], "digits": ["6"], "period": ["30"]}
        # A phone scans an opaque, high-contrast code with a four-module quiet zone.
        assert picture.getpixel((24, 24)) == (0, 0, 0)
        assert picture.crop((0, 0, picture.width, 24)).getextrema() == ((255, 255),) * 3
        assert "totp_qr" not in wizard.pending_path.read_text()
        for private_response in (post(server, "/state", {}), post(server, headers={"X-Oarbank-Setup": "wrong"}),
                                 httpx.get(server.origin + "/qr", trust_env=False)):
            assert seed not in private_response.text and qr not in private_response.text

        assert files_private(wizard.pending_path)
        assert files_private(wizard.primary) and files_private(wizard.backup)
        assert PASSWORD not in wizard.pending_path.read_text()
        assert not wizard.marker.exists()
        anchors = owner.anchors(wizard.backend.db)["doc"]
        assert anchors["keys"] == [signing.public_key_of(wizard.primary), signing.public_key_of(wizard.backup)]
        assert access.verify_password(access.account(wizard.backend.db, "admin")["pw_hash"], PASSWORD)
        assert post(server, "/finish", {"code": "invalid"}).status_code == 400
        assert not wizard.marker.exists()
        response = post(server, "/finish", {"code": code(wizard)})
        assert response.status_code == 200, response.text
        assert "/login/link?t=" in response.json()["console"]
        assert wizard.marker.exists() and files_private(wizard.marker)
        assert not wizard.pending_path.exists() and wizard.password is None
        assert seed not in wizard.marker.read_text()
        assert access.account(wizard.backend.db, "admin")["totp_last_step"] > 0
    captured = capsys.readouterr()
    assert PASSWORD not in captured.out + captured.err and seed not in captured.out + captured.err


def files_private(path):
    from oarbank.platform import files
    return files.owner_only(path)


def restarted(wizard, monkeypatch):
    result = setup.Wizard(wizard.root, wizard.backend, home=wizard.home, primary=wizard.primary, ready_timeout=.01)
    monkeypatch.setattr(result, "_disk_configured", lambda: False)
    return result


def test_partial_retry_preserves_admin_seed_and_keys(wizard, monkeypatch):
    with serving(wizard) as server:
        first = post(server).json()
    old = {p: p.read_bytes() for p in (wizard.primary, wizard.backup)}
    new = restarted(wizard, monkeypatch)
    with serving(new) as server:
        state = post(server, "/state", {}).json()
        assert state["pending"] == {"name": FORM["name"], "address": FORM["address"]}
        assert "totp_secret" not in json.dumps(state) and "totp_qr" not in json.dumps(state)
        # A new page/refresh cannot reset the journal or terminate the local server.
        assert httpx.get(server.origin, trust_env=False).status_code == 200
        assert post(server, "/state", {}).json()["pending"] == state["pending"]
        assert not server.finished
        assert post(server, "/finish", {"code": code(new)}).status_code == 409
        response = post(server)
        assert response.status_code == 200 and response.json()["totp_secret"] == first["totp_secret"]
        assert response.json()["totp_qr"] == first["totp_qr"]
        assert post(server, "/finish", {"code": code(new)}).status_code == 200
    assert len(wizard.backend.installs) == 1
    assert len(access.accounts(wizard.backend.db)) == 1
    assert all(p.read_bytes() == value for p, value in old.items())


def test_wrong_password_on_resume_cannot_complete_or_change_admin(wizard, monkeypatch):
    wizard.start(FORM)
    original = access.account(wizard.backend.db, "admin")["pw_hash"]
    new = restarted(wizard, monkeypatch)
    with serving(new) as server:
        changed = {**FORM, "password": "a different long password", "confirmation": "a different long password"}
        assert post(server, body=changed).status_code == 200
        assert post(server, "/finish", {"code": code(new)}).status_code == 403
    assert not wizard.marker.exists()
    assert access.account(wizard.backend.db, "admin")["pw_hash"] == original


def test_installer_failure_and_reentry(wizard, monkeypatch):
    wizard.backend.fail_install = True
    with serving(wizard) as server:
        response = post(server)
        assert response.status_code == 503 and "exit 9" in response.text
    assert not wizard.marker.exists() and not access.accounts(wizard.backend.db)
    wizard.backend.fail_install = False
    new = restarted(wizard, monkeypatch)
    with serving(new) as server:
        assert post(server, body={**FORM, "address": "::1"}).status_code == 409
        assert post(server).status_code == 200
    assert len(wizard.backend.installs) == 2


def test_signing_systemexit_after_admin_creation_recovers_without_reset(wizard, monkeypatch):
    wizard.backend.fail_signing = True
    with serving(wizard) as server:
        response = post(server)
        assert response.status_code == 502 and "owner.set_anchors: 409 signing refused" in response.text
    seed = wizard.pending["enrollment"]["totp_secret"]
    original = access.account(wizard.backend.db, "admin")["pw_hash"]
    wizard.backend.fail_signing = False
    new = restarted(wizard, monkeypatch)
    with serving(new) as server:
        assert post(server).json()["totp_secret"] == seed
        assert post(server, "/finish", {"code": code(new)}).status_code == 200
    assert access.account(wizard.backend.db, "admin")["pw_hash"] == original


def test_commit_journal_gap_never_resets_existing_admin(wizard, monkeypatch):
    wizard.start(FORM)
    wizard.pending.pop("enrollment")
    wizard._save()
    new = restarted(wizard, monkeypatch)
    with serving(new) as server:
        response = post(server)
        assert response.status_code == 409 and "will not replace" in response.text
    assert len(access.accounts(wizard.backend.db)) == 1 and not wizard.marker.exists()


def test_old_installation_routes_to_login_and_completion_refreshes_stable_root(wizard, monkeypatch):
    access.create_account(wizard.backend.db, "existing", "admin", PASSWORD, "test")
    wizard.backend.running = True
    with serving(wizard) as server:
        assert post(server, "/state", {}).json()["existing"]
        assert post(server).json()["existing"]
    assert not wizard.pending_path.exists() and not wizard.backend.installs


def test_completed_ordinary_reopen_does_not_restart_or_change_credentials(wizard, monkeypatch):
    wizard.start(FORM)
    wizard.finish({"code": code(wizard)})
    old_admin = access.account(wizard.backend.db, "admin")
    old_keys = [p.read_bytes() for p in (wizard.primary, wizard.backup)]
    new = restarted(wizard, monkeypatch)
    assert new.existing()
    assert "/login/link?t=" in new.reopen()
    assert wizard.backend.installs[-1] == (wizard.root, "127.0.0.1")
    assert len(wizard.backend.installs) == 1
    marker = json.loads(wizard.marker.read_text())
    assert marker["root"] == str(wizard.root) and marker["version"] == "2.6.0"
    assert access.account(wizard.backend.db, "admin") == old_admin
    assert [p.read_bytes() for p in (wizard.primary, wizard.backup)] == old_keys


@pytest.mark.parametrize("change", ["version", "root", "old_marker", "stopped"])
def test_completed_reopen_refreshes_only_changed_or_stopped_install(wizard, monkeypatch, change):
    wizard.start(FORM)
    wizard.finish({"code": code(wizard)})
    initial = json.loads(wizard.marker.read_text())
    original_keys = [p.read_bytes() for p in (wizard.primary, wizard.backup)]
    original_account = access.account(wizard.backend.db, "admin")
    if change == "version":
        (wizard.root / "oarbank-coordinator.json").write_text('{"format":1,"version":"2.6.1"}')
    elif change == "root":
        root = wizard.root.with_name("relocated root")
        root.mkdir()
        for path in wizard.root.iterdir():
            (root / path.name).write_bytes(path.read_bytes())
        wizard.root = root.resolve()
    elif change == "old_marker":
        initial.pop("version")
        initial.pop("root")
        wizard.marker.write_text(json.dumps(initial))
    else:
        wizard.backend.running = False
    new = restarted(wizard, monkeypatch)
    assert "/login/link?t=" in new.reopen()
    # stopped services are reinstalled everywhere; an upgrade or a relocation only on Windows (the macOS and Linux
    # packages refresh the system services themselves: coordinator-system-service.md, decision 8)
    installs = 2 if change == "stopped" or sys.platform == "win32" else 1
    assert len(wizard.backend.installs) == installs and wizard.backend.installs[-1] == (wizard.root if installs == 2 else wizard.backend.installs[-1][0], "127.0.0.1")
    marker = json.loads(wizard.marker.read_text())
    assert marker["root"] == str(wizard.root) and marker["version"] == new.version
    assert marker["fleet"] == initial["fleet"] and marker["address"] == initial["address"]
    assert [p.read_bytes() for p in (wizard.primary, wizard.backup)] == original_keys
    assert access.account(wizard.backend.db, "admin") == original_account
    assert "/login/link?t=" in new.reopen()
    assert len(wizard.backend.installs) == installs


def test_readiness_timeout_is_bounded_and_does_not_create_account(wizard, monkeypatch):
    monkeypatch.setattr(wizard.backend, "install", lambda *_: None)
    start = time.monotonic()
    with serving(wizard) as server:
        response = post(server)
        assert response.status_code == 503 and "not ready" in response.text
    assert time.monotonic() - start < 2 and not access.accounts(wizard.backend.db)


def test_totp_attempts_throttled_and_no_premature_marker(wizard):
    with serving(wizard) as server:
        assert post(server).status_code == 200
        for _ in range(5):
            assert post(server, "/finish", {"code": "bad"}).status_code == 400
        assert post(server, "/finish", {"code": code(wizard)}).status_code == 429
    assert not wizard.marker.exists()


@pytest.mark.parametrize("platform", ["darwin", "linux", "win32"])
def test_helper_fixed_argv_no_password(wizard, monkeypatch, platform):
    recorded = []
    monkeypatch.setattr(setup.sys, "platform", platform)
    monkeypatch.setattr(subprocess, "run", lambda command, **kw: recorded.append((command, kw)) or SimpleNamespace(returncode=0))
    monkeypatch.setattr(setup.sys, "stdin", io.StringIO())             # launched by the app: no terminal
    setup.Backend.install(wizard.backend, wizard.root, "127.0.0.1")
    argv, kwargs = recorded[0]
    if platform == "win32":
        assert argv == ["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(wizard.root / "install-oarbankd.ps1"), "-Installed", str(wizard.root), "-AgentBind", "127.0.0.1"]
    else:
        # the system services are root's: the installer runs through the system's administrator prompt
        import getpass
        tail = ["/bin/bash", str(wizard.root / "install-oarbankd.sh"), "--installed", str(wizard.root), "--agent-bind", "127.0.0.1",
                "--owner", getpass.getuser()]
        if getattr(os, "geteuid", lambda: -1)() == 0:                    # (no geteuid on a Windows runner)
            assert argv == tail
        elif platform == "darwin":
            assert argv[0] == "/usr/bin/osascript" and argv[-len(tail):] == tail
            assert "quoted form of (a as text)" in " ".join(argv) and "with administrator privileges" in " ".join(argv)
        else:
            assert argv[0] in ("pkexec", "sudo") and argv[1:] == tail
    assert PASSWORD not in str(recorded) and kwargs["stdin"] == subprocess.DEVNULL and kwargs["capture_output"]


def test_real_subprocess_errors_never_echo_output(wizard, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=7, stdout=PASSWORD, stderr=PASSWORD))
    with pytest.raises(setup.SetupError, match="exit 7") as error:
        setup.Backend.install(wizard.backend, wizard.root, "127.0.0.1")
    assert PASSWORD not in str(error.value)
    def timeout(*_, **__):
        raise subprocess.TimeoutExpired("helper", 180)
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(setup.SetupError, match="timed out"):
        setup.Backend.install(wizard.backend, wizard.root, "127.0.0.1")


def test_discovery_fixed_commands_filters_addresses(wizard, monkeypatch):
    calls = []
    monkeypatch.setattr(setup.sys, "platform", "darwin")
    monkeypatch.setattr(C, "TAILSCALE", "/trusted/tailscale")
    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=(
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet 192.168.1.4 netmask 0xffffff00 broadcast 192.168.1.255\n"
            "\tinet 10.0.0.4 netmask 255.255.255.0 broadcast 10.0.0.255\n"
            "\tinet6 fd00::4 prefixlen 64\n\tinet6 fe80::4%en0 prefixlen 64 scopeid 0x6\n"
            "\tstatus: active 192.0.2.42\n\tinet 127.0.0.1 netmask 0xff000000\n"
        ) if command[0] == "/sbin/ifconfig" else "100.64.1.4\n")
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(setup, "check_local_address", lambda _: None)
    choices = setup.local_addresses()
    assert {c["address"] for c in choices} == {"192.168.1.4", "10.0.0.4", "fd00::4", "100.64.1.4"}
    assert calls == [["/sbin/ifconfig"], ["/trusted/tailscale", "ip", "-4"]]


def test_macos_broadcast_rejected_even_when_socket_bind_would_succeed(wizard, monkeypatch):
    monkeypatch.setattr(setup.sys, "platform", "darwin")
    commands, bound = [], []
    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="\tinet 192.168.1.4 netmask 0xffffff00 broadcast 192.168.1.255\n")
    monkeypatch.setattr(subprocess, "run", run)
    class BindableSocket:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def bind(self, address):
            bound.append(address)
    monkeypatch.setattr(socket, "socket", lambda *_: BindableSocket())
    with pytest.raises(setup.SetupError, match="broadcast address"):
        setup.check_local_address("192.168.1.255")
    assert not bound
    setup.check_local_address("192.168.1.4")
    assert bound == [("192.168.1.4", 0)]
    assert commands == [["/sbin/ifconfig"], ["/sbin/ifconfig"]]


@pytest.mark.parametrize("platform", ["linux", "win32"])
def test_non_macos_address_check_still_only_probes_bind(wizard, monkeypatch, platform):
    monkeypatch.setattr(setup.sys, "platform", platform)
    # The fixture forbids subprocess.run: these platforms must keep their
    # existing behavior and never query macOS interface metadata.
    setup.check_local_address("127.0.0.1")


def test_close_has_no_marker_and_requires_capability(wizard):
    with serving(wizard) as server:
        assert post(server, "/close", {}, {"X-Oarbank-Setup": "forged"}).status_code == 403
        assert not server.finished
        assert post(server, "/close", {}).status_code == 200 and server.finished
    assert not wizard.marker.exists()


def test_main_exits_when_browser_is_gone_without_installing(wizard, monkeypatch):
    monkeypatch.setattr(setup, "Wizard", lambda _: wizard)
    real_server = setup.SetupServer
    monkeypatch.setattr(setup, "SetupServer", lambda w, port: real_server(w, port, idle_timeout=.01))
    start = time.monotonic()
    assert setup.main(["--root", str(wizard.root), "--no-browser"]) == 0
    assert time.monotonic() - start < 2
    assert not wizard.backend.installs and not wizard.marker.exists()


def test_main_completed_open_exits_and_does_not_restart(wizard, monkeypatch):
    wizard.start(FORM)
    wizard.finish({"code": code(wizard)})
    monkeypatch.setattr(setup, "Wizard", lambda _: wizard)
    opened = []
    monkeypatch.setattr(setup.webbrowser, "open", lambda url: opened.append(url))
    assert setup.main(["--root", str(wizard.root)]) == 0
    assert len(wizard.backend.installs) == 1
    assert len(opened) == 1 and "/login/link?t=" in opened[0]


def test_disk_configured_stopped_install_never_recreates_account(wizard, monkeypatch):
    monkeypatch.setattr(wizard, "_disk_configured", lambda: setup.Wizard._disk_configured(wizard))
    assert wizard.existing()  # fixture's temporary DB is enough, even with API down
    with serving(wizard) as server:
        assert post(server).json()["existing"]
    assert not wizard.backend.installs and not wizard.pending_path.exists()


def test_two_setup_processes_cannot_create_same_keys(wizard):
    with setup.setup_lock(wizard.home):
        with pytest.raises(setup.SetupError, match="already running"):
            with setup.setup_lock(wizard.home):
                pytest.fail("second setup acquired lock")


def test_changed_fleet_reopen_does_not_restart_or_update_marker(wizard, monkeypatch):
    wizard.start(FORM)
    wizard.finish({"code": code(wizard)})
    marker = wizard.marker.read_bytes()
    real_ready = wizard.backend.ready
    monkeypatch.setattr(wizard.backend, "ready", lambda: {**real_ready(), "fleet": "another-fleet"})
    with pytest.raises(setup.SetupError, match="fleet changed"):
        wizard.reopen()
    assert len(wizard.backend.installs) == 1 and wizard.marker.read_bytes() == marker


def test_existing_signing_files_are_reused(wizard):
    for path in (wizard.primary, wizard.backup):
        signing.keygen(path)
    originals = [path.read_bytes() for path in (wizard.primary, wizard.backup)]
    with serving(wizard) as server:
        assert post(server).status_code == 200
    assert [path.read_bytes() for path in (wizard.primary, wizard.backup)] == originals


def test_cli_systemexit_error_retains_detail_and_redacts_password(wizard, monkeypatch):
    def refused(*_, **__):
        raise SystemExit("access.accounts.create: 409 refused " + PASSWORD)
    monkeypatch.setattr(wizard.backend, "create_admin", refused)
    with serving(wizard) as server:
        response = post(server)
        assert response.status_code == 502 and "access.accounts.create: 409 refused" in response.text
        assert PASSWORD not in response.text and "[redacted]" in response.text


def test_upgraded_marker_written_only_after_successful_refresh(wizard, monkeypatch):
    wizard.start(FORM)
    wizard.finish({"code": code(wizard)})
    before = wizard.marker.read_bytes()
    (wizard.root / "oarbank-coordinator.json").write_text('{"format":1,"version":"2.6.1"}')
    new = restarted(wizard, monkeypatch)
    wizard.backend.fail_install = True
    wizard.backend.running = False                      # the services stopped: reopening reinstalls them
    with pytest.raises(setup.SetupError, match="exit 9"):
        new.reopen()
    assert wizard.marker.read_bytes() == before


def test_help_before_root_io_and_bad_ports(monkeypatch):
    monkeypatch.setattr(setup, "Wizard", lambda *_: pytest.fail("Help must not inspect root"))
    with pytest.raises(SystemExit) as result:
        setup.main(["--help"])
    assert result.value.code == 0
    with pytest.raises(SystemExit) as result:
        setup.main(["--root", "/missing", "--port", "65536"])
    assert result.value.code == 2


def test_real_backend_with_temporary_coordinator_and_console_children(tmp_path, monkeypatch):
    """Golden flow over the actual owner channel and TCP sign-in ceremony.

    These are disposable Python children, never registered OS services. Every
    path and listener is temporary, and the installer is forbidden throughout.
    """
    sockets = []
    for _ in range(4):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        sockets.append(listener)
    admin_port, console_port, agent_port, frames_port = [s.getsockname()[1] for s in sockets]
    for listener in sockets:
        listener.close()
    home = tmp_path / "home"
    root = tmp_path / "build"
    root.mkdir()
    (root / "oarbank-coordinator.json").write_text('{"format":1,"version":"2.6.0"}')
    (root / "install-oarbankd.sh").write_text("exit 99")
    (root / "install-oarbankd.ps1").write_text("exit 99")
    primary = tmp_path / "keys" / "release-ed25519.key"
    for name, value in {
        "OARBANKD_HOME": str(home), "OARBANK_RELEASE_KEY": str(primary), "OARBANK_RELEASE_SIGNING": "1",
        "OARBANKD_ADMIN_PORT": str(admin_port), "OARBANKD_CONSOLE_PORT": str(console_port),
        "HOME": str(tmp_path / "user"), "XDG_DATA_HOME": str(tmp_path / "data"),
        "XDG_CONFIG_HOME": str(tmp_path / "config"), "OARBANK_SECRET_STORE": "file",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("OARBANKD_URL", raising=False)
    monkeypatch.delenv("OARBANK_TOKEN", raising=False)
    monkeypatch.setattr(C, "HOME", home)
    monkeypatch.setattr(C, "ADMIN_PORT", admin_port)
    monkeypatch.setattr(C, "CONSOLE_PORT", console_port)
    monkeypatch.setattr(cli, "URL", cli.URL)
    monkeypatch.setattr(cli, "http_request", cli.http_request)
    monkeypatch.setattr(setup.Backend, "install", lambda *_: pytest.fail("Golden flow must never install services"))
    monkeypatch.setattr(setup.Backend, "addresses", lambda _: [])
    processes = []
    env = os.environ.copy()
    # Include the source under test even if pytest uses an installed interpreter.
    repo = Path(__file__).resolve().parents[1]
    env["PYTHONPATH"] = os.pathsep.join([str(repo / "src"), str(repo / "vendor/oarbank-sdk/src")])
    try:
        for arguments in (
            ["-m", "oarbank.coordinator", "--agent-bind", "127.0.0.1", "--agent-port", str(agent_port), "--admin-port", str(admin_port)],
            ["-m", "oarbank.console", "--port", str(console_port), "--frames-port", str(frames_port), "--oarbankd", f"http://127.0.0.1:{admin_port}"],
        ):
            processes.append(subprocess.Popen([sys.executable, *arguments], env=env, cwd=repo,
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        wizard = setup.Wizard(root, home=home, primary=primary, ready_timeout=15)
        monkeypatch.setattr(wizard, "_disk_configured", lambda: False)
        wizard._wait()
        assert all(p.poll() is None for p in processes)
        with httpx.Client(trust_env=False) as client:
            assert client.get(f"http://127.0.0.1:{console_port}/healthz").json()["ok"]
        with serving(wizard) as server:
            response = post(server)
            assert response.status_code == 200, response.text
            secret = response.json()["totp_secret"]
            assert post(server, "/finish", {"code": "bad"}).status_code == 400
            response = post(server, "/finish", {"code": code(wizard)})
            assert response.status_code == 200, response.text
            assert "/login/link?t=" in response.json()["console"]
            state = wizard.backend.snapshot()
            assert len(state["accounts"]) == 1 and state["accounts"][0]["role"] == "admin"
            assert state["owner"]["version"] == 1 and len(state["owner"]["keys"]) == 2
            with httpx.Client(trust_env=False, follow_redirects=False) as client:
                login = client.get(response.json()["console"])
                assert login.status_code == 303 and "oarbank_session" in login.headers.get("set-cookie", "")
        assert wizard.marker.exists() and not wizard.pending_path.exists()
        logs = "\n".join(path.read_text() for path in home.rglob("*.log"))
        assert PASSWORD not in logs and secret not in logs
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
