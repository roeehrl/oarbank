"""Release signing and anti-rollback (oarbankd side): the private key stays with oarbank; oarbankd only
verifies statements against the pinned public key, refuses unsigned promotion once a key is pinned,
and refuses any seq that does not rise. The feature is off by default (OARBANK_RELEASE_SIGNING);
these tests switch it on, except the ones that pin the default-off behaviour."""
import json
import os

import pytest
from fastapi.testclient import TestClient

from oarbank import signing
from oarbank.coordinator import app as coord_app
from oarbank.coordinator import clock, core, invariants, releases
from oarbank.coordinator import config as C

from helpers import admin_headers, api_op, release_id, make_db


@pytest.fixture(autouse=True)
def signing_on(monkeypatch):
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)


@pytest.fixture
def db(tmp_path):
    clock.set_fake(None)
    d = make_db(tmp_path / "oarbank.sqlite3")
    for rid, sha in (("r_a", "a" * 64), ("r_b", "b" * 64), ("r_c", "c" * 64)):
        d.x("INSERT INTO releases(release_id,created_at,path,sha256,manifest_json,status) VALUES(?,?,?,?,?,?)",
            (rid, clock.now(), "/dev/null", sha, "{}", "candidate"))
    yield d
    d.conn.close()


@pytest.fixture
def key(tmp_path, db):
    k = tmp_path / "keys" / "release.key"
    db.set_setting("release_pubkey", signing.keygen(k))
    return k


def signed(db, key, rid, seq):
    sha = db.one("SELECT sha256 FROM releases WHERE release_id=?", (rid,))["sha256"]
    stmt = signing.statement(rid, sha, seq)
    return stmt, signing.sign(stmt, key)


def test_keygen_writes_a_private_0600_key_and_refuses_overwrite(tmp_path):
    k = tmp_path / "k" / "release.key"
    pub = signing.keygen(k)
    assert oct(os.stat(k).st_mode & 0o777) == "0o600" and len(pub) == 44
    with pytest.raises(FileExistsError):
        signing.keygen(k)
    os.chmod(k, 0o644)
    with pytest.raises(PermissionError):
        signing.load_key(k)


def test_unsigned_release_cannot_be_promoted_once_a_key_is_pinned(db, key):
    with pytest.raises(releases.ReleaseRefused):
        releases.promote(db, "r_a", "test")
    releases.attach_signature(db, "r_a", *signed(db, key, "r_a", 1))
    releases.promote(db, "r_a", "test")
    assert db.one("SELECT status FROM releases WHERE release_id='r_a'")["status"] == "current"


def test_forged_or_mismatched_statements_are_refused(db, key, tmp_path):
    other = tmp_path / "other.key"
    signing.keygen(other)
    stmt = signing.statement("r_a", "a" * 64, 1)
    with pytest.raises(releases.ReleaseRefused, match="signature"):
        releases.attach_signature(db, "r_a", stmt, signing.sign(stmt, other))          # wrong key
    stmt_b = signing.statement("r_a", "b" * 64, 1)
    with pytest.raises(releases.ReleaseRefused, match="match"):
        releases.attach_signature(db, "r_a", stmt_b, signing.sign(stmt_b, key))        # wrong sha256
    s, sig = signed(db, key, "r_a", 1)
    with pytest.raises(releases.ReleaseRefused):
        releases.attach_signature(db, "r_a", s.replace('"seq":1', '"seq":9'), sig)     # tampered statement


def test_seq_must_strictly_rise(db, key):
    releases.attach_signature(db, "r_a", *signed(db, key, "r_a", 1))
    releases.attach_signature(db, "r_b", *signed(db, key, "r_b", 2))
    with pytest.raises(releases.ReleaseRefused, match="not above"):
        releases.attach_signature(db, "r_c", *signed(db, key, "r_c", 2))
    releases.attach_signature(db, "r_c", *signed(db, key, "r_c", 3))


def test_directives_carry_the_signed_statement_and_the_pubkey(db, key):
    releases.attach_signature(db, "r_b", *signed(db, key, "r_b", 1))
    releases.promote(db, "r_b", "test")
    from helpers import enrolled_node
    _, node = enrolled_node(db)
    d = core._node_directives(db, node)
    assert d["release_pubkey"] == db.get_setting("release_pubkey")
    assert json.loads(d["release"]["statement"])["release_id"] == "r_b" and d["release"]["signature"]
    signing.verify(d["release"]["statement"], d["release"]["signature"], d["release_pubkey"])


def test_release_key_endpoint_refuses_silent_rotation(db, key, tmp_path):
    gui = TestClient(coord_app.admin_app(db, coord_app.EventBus()), client=("127.0.0.1", 5), headers=admin_headers(db))
    new = signing.keygen(tmp_path / "new.key")
    assert api_op(gui, "releases.pin_key", "release-key", {"pubkey": new}).status_code == 409
    assert api_op(gui, "settings.update", "release_pubkey", {"value": new}).status_code == 400
    assert api_op(gui, "releases.pin_key", "release-key", {"pubkey": new, "rotate": True}).status_code == 200
    assert api_op(gui, "releases.promote", "r_a").status_code == 409          # unsigned


# ---------------------------------------------------------------- default: feature off
def test_default_is_on(monkeypatch):
    """Signing is on by default (D31); OARBANK_RELEASE_SIGNING=0 is developer mode."""
    monkeypatch.delenv("OARBANK_RELEASE_SIGNING", raising=False)
    import importlib
    import oarbank.coordinator.config as cfg
    try:
        assert importlib.reload(cfg).RELEASE_SIGNING is True
        monkeypatch.setenv("OARBANK_RELEASE_SIGNING", "0")
        assert importlib.reload(cfg).RELEASE_SIGNING is False
    finally:
        monkeypatch.delenv("OARBANK_RELEASE_SIGNING", raising=False)
        importlib.reload(cfg).RELEASE_SIGNING = False          # the suite runs in developer mode (conftest)


def test_when_off_nothing_is_advertised_gated_or_accepted(db, key, monkeypatch):
    """Even with a key left in the settings, a oarbankd without the feature ignores it entirely."""
    monkeypatch.setattr(C, "RELEASE_SIGNING", False)
    releases.promote(db, "r_a", "test")                                   # unsigned promotion allowed
    from helpers import enrolled_node
    _, node = enrolled_node(db)
    d = core._node_directives(db, node)
    assert d["release_pubkey"] is None and "signature" not in (d["release"] or {})
    with pytest.raises(releases.ReleaseRefused, match="disabled"):
        releases.attach_signature(db, "r_b", *signed(db, key, "r_b", 1))
    gui = TestClient(coord_app.admin_app(db, coord_app.EventBus()), client=("127.0.0.1", 5), headers=admin_headers(db))
    assert gui.get("/api/v1/features").json() == {"release_signing": False}
    assert api_op(gui, "releases.pin_key", "release-key", {"pubkey": db.get_setting("release_pubkey")}).status_code == 409


def test_every_key_option_names_the_key_keygen_writes(tmp_path):
    # the docs and the --help texts once named ~/.config/oarbank/release-ed25519.key while keygen wrote keys/…: an owner
    # following them pinned one key and signed with another
    import subprocess
    import sys
    env = {**os.environ, "XDG_CONFIG_HOME": str(tmp_path), "HOME": str(tmp_path), "COLUMNS": "500"}
    env.pop("OARBANK_RELEASE_KEY", None)
    run = lambda *a: subprocess.run([sys.executable, *a], env=env, capture_output=True, text=True, check=True).stdout
    key = run("-c", "from oarbank import signing; print(signing.DEFAULT_KEY)").strip()
    assert key.endswith("keys/release-ed25519.key") and key.startswith(str(tmp_path))
    for cmd in ("release", "owner", "agent", "coordinator-build"):
        assert f"default {key})" in run("-m", "oarbank.cli.main", cmd, "--help"), cmd
