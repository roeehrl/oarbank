"""Join codes (docs/design/node-enrollment.md, "Join code format (OB2)"; a code counts as the owner's approval).

A join code is what the owner hands a new machine (`oarbank-node join`). It names the coordinator's agent URLs, pins its
identity key and the SHA-256 of its TLS CA's public key (so the very first connection is authenticated: no trust on
first use), says when it expires and how the console suggests the node be installed, and carries a secret. Codes are
single-use and approved at once by default; multi-use codes (MDM, images) have a use cap and leave each machine pending
unless the owner chose "approve automatically". Only the secret's hash is stored. A code's label names the node it
enrolls: the node keeps that name whatever host name its agent reports (core.approve_enrollment, core.hello).

Text form: `OB2-` + Crockford base32 of
  version(1)=2 | flags(1) | expires(4, Unix minutes) | cik(32) | n_pins(1) pins(32 each) | n_urls(1) (len(1) url)... |
  id(8) | secret(16) | crc32(4, of everything before it)
Parsing ignores whitespace and dashes, folds case and reads I/L as 1 and O as 0 (Crockford), so a pasted code that
picked up spaces or line breaks still works and a truncated or mistyped one is refused before anything is sent.
"""
import base64
import hashlib
import secrets
import time
import zlib

from .db import DB

PREFIX = "OB2-"
VERSION = 2
DEFAULT_TTL_S = 4 * 3600
MIN_TTL_S, MAX_TTL_S, MAX_MULTI_TTL_S = 600, 7 * 86400, 30 * 86400
MAX_USES = 10000
F_APPROVE, F_SYSTEM, F_CONTAINERS, F_MULTI = 1, 2, 4, 8
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE = {c: i for i, c in enumerate(ALPHABET)} | {"I": 1, "L": 1, "O": 0}
# Refusal reasons, as the agent sees them in an enrollment answer (`join_error`) and the event log records them.
REFUSALS = ("unknown", "expired", "used", "revoked")

SCHEMA = """
CREATE TABLE IF NOT EXISTS join_codes (
  code_id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, label TEXT, created_by TEXT, created_at REAL, expires_at REAL,
  max_uses INT NOT NULL DEFAULT 1, uses INT NOT NULL DEFAULT 0, approve INT NOT NULL DEFAULT 1, flags INT NOT NULL DEFAULT 0,
  revoked_at REAL, revoked_by TEXT, last_used_at REAL);
"""


class JoinError(ValueError):
    pass


def migrate(conn) -> None:
    """Before the schema runs: an OB1-era table (keyed by the secret's hash) is dropped; its codes expired within the
    hour they were made, and OB1 agents no longer exist."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(join_codes)")]
    if cols and "code_id" not in cols:
        conn.execute("DROP TABLE join_codes")


# ---------------------------------------------------------------- codec
def b32encode(data: bytes) -> str:
    out, buf, bits = [], 0, 0
    for b in data:
        buf, bits = (buf << 8) | b, bits + 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(buf >> bits) & 31])
    if bits:
        out.append(ALPHABET[(buf << (5 - bits)) & 31])
    return "".join(out)


def b32decode(s: str) -> bytes:
    out, buf, bits = bytearray(), 0, 0
    for c in s:
        if c not in _DECODE:
            raise JoinError(f"the join code has a character that is not in it ({c!r}): copy it again from the console")
        buf, bits = (buf << 5) | _DECODE[c], bits + 5
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
            buf &= (1 << bits) - 1
    return bytes(out)


def encode(*, urls: list[str], pins: list[str], cik: str, code_id: bytes, secret: bytes, expires_at: float,
           flags: int = F_APPROVE) -> str:
    """The text form. `pins` are hex SHA-256 SPKI hashes (current first), `cik` the base64 raw Ed25519 public key."""
    if not urls or not pins:
        raise JoinError("a join code needs at least one coordinator URL and one CA pin")
    raw = bytearray([VERSION, flags & 0xFF])
    raw += int(expires_at // 60).to_bytes(4, "big")
    key = base64.b64decode(cik)
    if len(key) != 32:
        raise JoinError("the coordinator identity key is not a 32-byte Ed25519 key")
    raw += key
    raw.append(len(pins))
    for p in pins:
        raw += bytes.fromhex(p)
    raw.append(len(urls))
    for u in urls:
        b = u.encode()
        if len(b) > 255:
            raise JoinError(f"coordinator URL too long for a join code: {u}")
        raw.append(len(b))
        raw += b
    if len(code_id) != 8 or len(secret) != 16:
        raise JoinError("a join code's id is 8 bytes and its secret 16")
    raw += code_id + secret
    raw += zlib.crc32(bytes(raw)).to_bytes(4, "big")
    return PREFIX + b32encode(bytes(raw))


def decode(code: str) -> dict:
    """The fields of a join code, or JoinError naming what is wrong (no network, no database)."""
    s = "".join(code.split()).upper()
    if not s.startswith("OB2"):
        if s.startswith("OB1"):
            raise JoinError("that is a join code from an older coordinator: make a new one in the console")
        raise JoinError("that is not an Oarbank join code (they start with OB2-)")
    raw = b32decode(s[3:].replace("-", ""))
    if len(raw) < 1 + 1 + 4 + 32 + 1 + 1 + 8 + 16 + 4:
        raise JoinError("the join code is incomplete: copy it again from the console")
    body, crc = raw[:-4], raw[-4:]
    if zlib.crc32(body).to_bytes(4, "big") != crc:
        raise JoinError("the join code is mistyped or incomplete (its check digits do not match): copy it again")
    if body[0] != VERSION:
        raise JoinError(f"join code format {body[0]} is not supported by this version")
    try:
        i = 2
        flags = body[1]
        expires_at = int.from_bytes(body[i:i + 4], "big") * 60
        i += 4
        cik = base64.b64encode(body[i:i + 32]).decode()
        i += 32
        n = body[i]
        i += 1
        pins = [body[i + 32 * k:i + 32 * (k + 1)].hex() for k in range(n)]
        i += 32 * n
        n = body[i]
        i += 1
        urls = []
        for _ in range(n):
            ln = body[i]
            urls.append(body[i + 1:i + 1 + ln].decode())
            i += 1 + ln
        code_id, secret = body[i:i + 8], body[i + 8:i + 24]
        if len(secret) != 16 or i + 24 != len(body) or not pins or not urls or any(len(p) != 64 for p in pins):
            raise IndexError
    except (IndexError, UnicodeDecodeError):
        raise JoinError("the join code is malformed")
    return {"flags": flags, "expires_at": expires_at, "cik": cik, "pins": pins, "urls": urls,
            "id": code_id.hex(), "secret": secret.hex(), "token": f"{code_id.hex()}.{secret.hex()}",
            "approve": bool(flags & F_APPROVE), "system": bool(flags & F_SYSTEM),
            "containers": bool(flags & F_CONTAINERS), "multi": bool(flags & F_MULTI)}


def _hash(secret_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(secret_hex)).hexdigest()


# ---------------------------------------------------------------- records
def create(db: DB, *, urls: list[str], pins: list[str], cik: str, actor: str, label: str = "",
           ttl_s: float = DEFAULT_TTL_S, uses: int = 1, approve: bool | None = None, system: bool = False,
           containers: bool = False) -> dict:
    if not urls:
        raise JoinError("the coordinator has no address agents can reach (set coordinator_url)")
    uses = int(uses)
    if not 1 <= uses <= MAX_USES:
        raise JoinError(f"uses: 1..{MAX_USES}")
    ttl_s = float(ttl_s)
    if not MIN_TTL_S <= ttl_s <= (MAX_MULTI_TTL_S if uses > 1 else MAX_TTL_S):
        raise JoinError(f"ttl_s: {MIN_TTL_S}..{MAX_MULTI_TTL_S if uses > 1 else MAX_TTL_S} seconds")
    approve = (uses == 1) if approve is None else bool(approve)
    flags = (F_APPROVE if approve else 0) | (F_SYSTEM if system else 0) | (F_CONTAINERS if containers else 0) | \
            (F_MULTI if uses > 1 else 0)
    code_id, secret = secrets.token_bytes(8), secrets.token_bytes(16)
    now = time.time()
    expires_at = now + ttl_s
    label = (label or "").strip()[:63]                  # the node's name (a node name is at most 63 characters)
    db.x("INSERT INTO join_codes(code_id, secret_hash, label, created_by, created_at, expires_at, max_uses, approve, flags)"
         " VALUES(?,?,?,?,?,?,?,?,?)",
         (code_id.hex(), _hash(secret.hex()), label, actor, now, expires_at, uses, int(approve), flags))
    code = encode(urls=urls, pins=pins, cik=cik, code_id=code_id, secret=secret, expires_at=expires_at, flags=flags)
    return {"code": code, "id": code_id.hex(), "expires_at": expires_at, "label": label, "uses": uses,
            "approve": approve, "system": system, "containers": containers}


def redeem(db: DB, token: str) -> tuple[dict | None, str | None]:
    """(the code's record, None) when `<id>.<secret>` is valid, counting one use; (None, reason) otherwise, reason one
    of REFUSALS."""
    code_id, _, secret = (token or "").partition(".")
    try:
        h = _hash(secret)
    except ValueError:
        return None, "unknown"
    with db.tx():
        r = db.one("SELECT * FROM join_codes WHERE code_id=?", (code_id,))
        if not r or not secrets.compare_digest(r["secret_hash"], h):
            return None, "unknown"
        if r["revoked_at"]:
            return None, "revoked"
        if r["expires_at"] < time.time():
            return None, "expired"
        if r["uses"] >= r["max_uses"]:
            return None, "used"
        db.x("UPDATE join_codes SET uses=uses+1, last_used_at=? WHERE code_id=?", (time.time(), code_id))
    return dict(r), None


def revoke(db: DB, code_id: str, actor: str) -> dict:
    r = db.one("SELECT code_id, revoked_at FROM join_codes WHERE code_id=?", (code_id,))
    if not r:
        raise JoinError(f"no join code {code_id}")
    if not r["revoked_at"]:
        db.x("UPDATE join_codes SET revoked_at=?, revoked_by=? WHERE code_id=?", (time.time(), actor, code_id))
    return {"id": code_id, "revoked": True}


def state_of(r, now: float | None = None) -> str:
    now = time.time() if now is None else now
    return "revoked" if r["revoked_at"] else "expired" if r["expires_at"] < now else \
        "used" if r["uses"] >= r["max_uses"] else "active"


def listing(db: DB, include_spent: bool = False, code_id: str | None = None) -> list[dict]:
    """Codes with their state and the enrollments made with them (newest first). Spent codes (expired, revoked or used
    up) more than a day old are left out unless asked for, or unless one code is asked for by id."""
    now = time.time()
    out = []
    rows = db.q("SELECT * FROM join_codes WHERE code_id=?", (code_id,)) if code_id else \
        db.q("SELECT * FROM join_codes ORDER BY created_at DESC LIMIT 500")
    for r in rows:
        state = state_of(r, now)
        ended = r["revoked_at"] or (r["expires_at"] if state == "expired" else r["last_used_at"] if state == "used" else None)
        if state != "active" and not (include_spent or code_id) and ended and ended < now - 86400:
            continue
        enr = [dict(e) for e in db.q(
            "SELECT e.enrollment_id, e.hostname, e.peer_ip, e.status, e.node_id, e.created_at, e.user_code,"
            " n.hostname AS node_name, n.lifecycle, n.last_heartbeat_at FROM enrollments e"
            " LEFT JOIN nodes n ON n.node_id=e.node_id WHERE e.join_code_id=? ORDER BY e.created_at", (r["code_id"],))]
        out.append({"id": r["code_id"], "label": r["label"] or "", "created_by": r["created_by"],
                    "created_at": r["created_at"], "expires_at": r["expires_at"], "uses": r["uses"],
                    "max_uses": r["max_uses"], "approve": bool(r["approve"]), "system": bool(r["flags"] & F_SYSTEM),
                    "containers": bool(r["flags"] & F_CONTAINERS), "state": state, "revoked_at": r["revoked_at"],
                    "enrollments": enr})
    return out
