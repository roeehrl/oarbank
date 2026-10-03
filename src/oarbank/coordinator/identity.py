"""The coordinator's identity (docs/design/coordinator-move.md): agents trust a key, not a URL.

- The **coordinator identity key (CIK)** is an Ed25519 key generated on first start, kept in
  `<home>/coordinator_key` (0600). It never leaves the machine: a move gives the new coordinator its own key,
  which the old one endorses in the signed move statement.
- `fleet_id` names the fleet across moves; the **epoch** rises with every change of coordinator (moves,
  rollbacks); agents refuse any coordinator at a lower epoch than the highest they have seen.
- The **role** is `active` (serves agents), `standby` (a move target: identity and pairing only) or
  `handed_off` (redirect only). `handed_off` is also written to a marker file, so a restarted old coordinator
  can never come back active.

Signed documents are strings (canonical JSON) signed as bytes: verifiers check the signature over the exact
bytes received, then parse, so the coordinator and the agent never need to agree on a canonicalization.
"""
import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from . import config as C
from .db import DB

ROLES = ("active", "standby", "handed_off")
IDENTITY_TYPE = "oarbank.coordinator-identity/v1"
MOVE_TYPE = "oarbank.coordinator-move/v1"
CANCEL_TYPE = "oarbank.coordinator-move-cancel/v1"
MARKER = "HANDED_OFF"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def fingerprint(pub_b64: str) -> str:
    """SHA-256 of the raw public key, hex; what people compare (the first 16 hex digits are shown)."""
    return hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()


class Key:
    """An Ed25519 key from a file (created 0600 on first use), or from raw bytes (tests, pairing)."""

    def __init__(self, path: Path | None = None, raw: bytes | None = None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if raw is None:
            assert path is not None
            if path.exists():
                raw = base64.b64decode(path.read_text().strip())
            else:
                raw = os.urandom(32)
                path.parent.mkdir(parents=True, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(b64(raw) + "\n")
        self._k = Ed25519PrivateKey.from_private_bytes(raw)
        from cryptography.hazmat.primitives import serialization
        self.public_b64 = b64(self._k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.fingerprint = fingerprint(self.public_b64)

    def sign(self, data: str | bytes) -> str:
        return b64(self._k.sign(data.encode() if isinstance(data, str) else data))


def verify(pub_b64: str, data: str | bytes, sig_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(
            base64.b64decode(sig_b64), data.encode() if isinstance(data, str) else data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


_KEY: dict[str, Key] = {}


def key(home: Path | None = None) -> Key:
    home = Path(home or C.HOME)
    k = _KEY.get(str(home))
    if k is None:
        k = _KEY[str(home)] = Key(home / "coordinator_key")
    return k


def fleet_id(db: DB) -> str:
    fid = db.get_setting("fleet_id")
    if not fid:
        fid = "fleet_" + secrets.token_hex(8)
        db.set_setting("fleet_id", fid)
    return fid


def epoch(db: DB) -> int:
    return int(db.get_setting("coordinator_epoch", 1) or 1)


def role(db: DB) -> str:
    if marker_path(db).exists():
        return "handed_off"
    r = db.get_setting("coordinator_role", os.environ.get("OARBANKD_ROLE", "active"))
    return r if r in ROLES else "active"


def marker_path(db: DB) -> Path:
    return Path(db.path).parent / MARKER


def set_role(db: DB, r: str):
    assert r in ROLES
    if r == "handed_off":
        # the marker first: from here on a restarted oarbankd comes back redirect-only whatever the database says
        p = marker_path(db)
        p.write_text(json.dumps({"at": time.time(), "epoch": epoch(db)}) + "\n")
        os.chmod(p, 0o444)
    db.set_setting("coordinator_role", r)


def ensure(db: DB) -> dict:
    """Called at start: the key and fleet id exist; the CIK fingerprint is published as a setting."""
    k = key(Path(db.path).parent)
    db.set_setting("coordinator_cik", k.public_b64)
    return {"fleet_id": fleet_id(db), "cik": k.public_b64, "fingerprint": k.fingerprint, "epoch": epoch(db), "role": role(db)}


def identity_proof(db: DB, nonce: str, url: str | None = None) -> dict:
    """The answer to GET /v1/identity: a payload naming this coordinator, signed with the CIK over the agent's
    nonce (a fresh challenge, so a recorded answer cannot be replayed by another host)."""
    if not nonce or len(nonce) > 128:
        raise ValueError("nonce: 1..128 characters")
    k = key(Path(db.path).parent)
    doc = {"type": IDENTITY_TYPE, "fleet_id": fleet_id(db), "epoch": epoch(db), "role": role(db),
           "cik": k.public_b64, "url": url, "nonce": nonce, "ts": int(time.time())}
    from . import tlsca
    if (Path(db.path).parent / "tls" / "ca.pem").exists():
        doc["tls"] = tlsca.pins(Path(db.path).parent)       # the agent pins the CA through the key it trusts
    payload = canonical(doc)
    return {"payload": payload, "sig": k.sign(payload)}
