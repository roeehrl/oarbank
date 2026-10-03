"""Release signing (Ed25519) shared by oarbank (signs) and oarbankd (verifies).

The private key never enters oarbankd: `oarbank release keygen` writes it outside oarbankd's state
directory (default paths.release_key(): <config root>/keys/release-ed25519.key, mode 0600; it can live on any
machine that runs oarbank), and `oarbank release sign` signs locally and uploads only the statement and the
signature. oarbankd verifies both against the pinned public key (setting `release_pubkey`) before it
accepts or promotes a release; agents verify again and pin the key on first sight.

A statement is canonical JSON: {"release_id", "sha256", "seq", "signed_at"}. `seq` strictly
increases across signed releases; agents refuse any release whose seq is not above the one they
have installed (anti-rollback). Rolling back means re-releasing old content under a new seq.
"""
import base64
import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import paths

DEFAULT_KEY = paths.release_key()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def keygen(path: Path = DEFAULT_KEY, overwrite: bool = False) -> str:
    """Create a signing key; returns the base64 raw public key."""
    path = Path(path)
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} exists (refusing to overwrite a signing key)")
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    k = Ed25519PrivateKey.generate()
    raw = k.private_bytes_raw()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(b64(raw) + "\n")
    return b64(k.public_key().public_bytes_raw())


def load_key(path: Path = DEFAULT_KEY) -> Ed25519PrivateKey:
    path = Path(path)
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(f"{path} is mode {oct(mode)}; a signing key must be 0600")
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(path.read_text().strip()))


def public_key_of(path: Path = DEFAULT_KEY) -> str:
    return b64(load_key(path).public_key().public_bytes_raw())


def statement(release_id: str, sha256: str, seq: int) -> str:
    return json.dumps({"release_id": release_id, "sha256": sha256, "seq": int(seq), "signed_at": int(time.time())},
                      sort_keys=True, separators=(",", ":"))


def agent_statement(sha256: str, version: str, seq: int, platforms: list[str]) -> str:
    """An agent build statement: agents in signing mode run only binaries named by one, for their own platform, with a
    rising seq."""
    return json.dumps({"agent_sha256": sha256, "version": version, "platforms": sorted(platforms), "seq": int(seq),
                       "signed_at": int(time.time())}, sort_keys=True, separators=(",", ":"))


def _verify_fields(stmt: str, signature: str, pubkey_b64: str, what: str, fields: set) -> dict:
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64)).verify(base64.b64decode(signature), stmt.encode())
    except (InvalidSignature, ValueError) as e:
        raise ValueError(f"bad {what} signature: {e!r}")
    s = json.loads(stmt)
    if not fields <= set(s):
        raise ValueError(f"{what} statement missing fields {sorted(fields - set(s))}")
    return s


def verify_agent(stmt: str, signature: str, pubkey_b64: str) -> dict:
    return _verify_fields(stmt, signature, pubkey_b64, "agent build", {"agent_sha256", "version", "platforms", "seq"})


def coordinator_statement(sha256: str, version: str, platform: str, seq: int) -> str:
    """A coordinator build statement: an agent installs a standby coordinator (a move) only from a build named by
    one, for its own platform."""
    return json.dumps({"coordinator_sha256": sha256, "version": version, "platform": platform, "seq": int(seq),
                       "signed_at": int(time.time())}, sort_keys=True, separators=(",", ":"))


def verify_coordinator(stmt: str, signature: str, pubkey_b64: str) -> dict:
    return _verify_fields(stmt, signature, pubkey_b64, "coordinator build", {"coordinator_sha256", "version", "platform", "seq"})


def owner_anchors_statement(fleet_id: str, version: int, keys: list[str], rescue: list[str] | None = None) -> str:
    """The owner key set (coordinator-move.md): every key in it, and a key of the current set, sign it."""
    return json.dumps({"type": "oarbank.owner-anchors/v1", "fleet_id": fleet_id, "version": int(version), "threshold": 1,
                       "keys": keys, "rescue": rescue or [], "signed_at": int(time.time())}, sort_keys=True, separators=(",", ":"))


def rescue_move_statement(request: dict, stable_id: str | None = None, days: float = 30) -> str:
    """An owner-signed move from a lost or compromised coordinator to the coordinator that wrote `request`
    (python -m oarbank.coordinator.rescue adopt): no signature from the old coordinator is needed (coordinator-move.md)."""
    import secrets
    now = int(time.time())
    to = request["to"]
    return json.dumps({"type": "oarbank.coordinator-move/v1", "rescue": True, "fleet_id": request["fleet_id"],
                       "move_id": "mv_rescue_" + secrets.token_hex(4), "epoch": int(request["epoch"]),
                       "from": {"url": None, "cik": request["from_cik"]},
                       "to": {"url": to["url"], "cik": to["cik"], "audit_pubkey": to["audit_pubkey"],
                              "ts_stable_node_id": stable_id, "required_tag": None},
                       "issued_at": now, "not_before": now, "expires": now + int(days * 86400), "canary": [], "prev": None},
                      sort_keys=True, separators=(",", ":"))


def owner_disable_statement(fleet_id: str, version: int) -> str:
    return json.dumps({"type": "oarbank.owner-security/v1", "fleet_id": fleet_id, "version": int(version),
                       "action": "disable_signing", "signed_at": int(time.time())}, sort_keys=True, separators=(",", ":"))


def sign(stmt: str, path: Path = DEFAULT_KEY) -> str:
    return b64(load_key(path).sign(stmt.encode()))


def verify(stmt: str, signature: str, pubkey_b64: str) -> dict:
    """Returns the parsed statement, or raises ValueError."""
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64)).verify(base64.b64decode(signature), stmt.encode())
    except (InvalidSignature, ValueError) as e:
        raise ValueError(f"bad release signature: {e!r}")
    s = json.loads(stmt)
    if not {"release_id", "sha256", "seq"} <= set(s):
        raise ValueError("release statement missing fields")
    return s
