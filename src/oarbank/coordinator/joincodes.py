"""Join codes (architecture.md, "Network and access": a join code counts as the owner's approval).

A join code is what the owner hands a new machine: `oarbank-agent run --join <code>`. It carries the coordinator's
candidate addresses, the SHA-256 of its TLS CA's public key (so the very first connection is authenticated, no trust
on first use) and a one-time secret. An enrollment that presents a valid secret is approved at once. Codes expire
(default 1 hour), work once, and are stored only as hashes. A code's label names the node it enrolls: the node keeps
that name whatever host name its agent reports (core.approve_enrollment, core.hello).

Encoding: `OB1-` + base32 (no padding) of compact JSON `{"u": [urls], "p": "<spki hex>", "t": "<secret>"}` + `-` + a
4-character CRC-32 check, so a mistyped code is refused before it is used.
"""
import base64
import hashlib
import json
import secrets
import time
import zlib

from .db import DB

PREFIX = "OB1-"
DEFAULT_TTL_S = 3600
SCHEMA = """
CREATE TABLE IF NOT EXISTS join_codes (
  code_hash TEXT PRIMARY KEY, label TEXT, created_by TEXT, created_at REAL, expires_at REAL, used_at REAL, node_id TEXT);
"""


class JoinError(ValueError):
    pass


def _check(body: str) -> str:
    return base64.b32encode(zlib.crc32(body.encode()).to_bytes(4, "big")).decode()[:4]


def encode(urls: list[str], ca_spki: str, secret: str) -> str:
    raw = json.dumps({"u": urls, "p": ca_spki, "t": secret}, separators=(",", ":"))
    body = base64.b32encode(raw.encode()).decode().rstrip("=")
    return f"{PREFIX}{body}-{_check(body)}"


def decode(code: str) -> dict:
    code = "".join(code.split()).upper()
    if not code.startswith(PREFIX) or "-" not in code[len(PREFIX):]:
        raise JoinError("not an Oarbank join code")
    body, chk = code[len(PREFIX):].rsplit("-", 1)
    if _check(body) != chk:
        raise JoinError("the join code is mistyped (check characters do not match)")
    raw = base64.b32decode(body + "=" * (-len(body) % 8)).decode()
    d = json.loads(raw)
    if not isinstance(d.get("u"), list) or not d.get("p") or not d.get("t"):
        raise JoinError("incomplete join code")
    return d


def create(db: DB, urls: list[str], ca_spki: str, actor: str, label: str = "", ttl_s: float = DEFAULT_TTL_S) -> dict:
    if not urls:
        raise JoinError("the coordinator has no address agents can reach (set coordinator_url)")
    secret = secrets.token_urlsafe(24)
    now = time.time()
    label = (label or "").strip()[:63]                  # the node's name (a node name is at most 63 characters)
    db.x("INSERT INTO join_codes(code_hash, label, created_by, created_at, expires_at) VALUES(?,?,?,?,?)",
         (hashlib.sha256(secret.encode()).hexdigest(), label, actor, now, now + float(ttl_s)))
    return {"code": encode(urls, ca_spki, secret), "expires_at": now + float(ttl_s), "label": label}


def redeem(db: DB, secret: str) -> dict | None:
    """The code's record when the secret is valid (unused, unexpired); marks it used. None otherwise."""
    if not secret:
        return None
    h = hashlib.sha256(secret.encode()).hexdigest()
    with db.tx():
        r = db.one("SELECT * FROM join_codes WHERE code_hash=?", (h,))
        if not r or r["used_at"] or r["expires_at"] < time.time():
            return None
        db.x("UPDATE join_codes SET used_at=? WHERE code_hash=?", (time.time(), h))
    return r
