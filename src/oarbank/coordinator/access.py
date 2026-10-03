"""Who may administer the coordinator (architecture.md, "Network and access").

Nothing is trusted for being local, and no identity header is trusted:
- **The local owner** proves itself with the admin token: a random secret in `<home>/admin.token`, readable only by the
  account that runs oarbankd (owner-only file mode). The CLI on the coordinator reads it.
- **People** sign in to the console with an account: a password (scrypt) plus a TOTP code, or a passkey. A session is
  an HttpOnly, SameSite=Strict cookie with its own CSRF token. `oarbank console login` mints a one-time sign-in link
  for the local owner.
- **Scripts elsewhere** use personal access tokens (`oak_…`), stored hashed, with an expiry.
- Every listener checks the Host header against an allowlist (DNS rebinding), and requests that arrive through
  Tailscale Funnel are refused.

Secrets are stored only as hashes (tokens, links, sessions) or encrypted at rest by file mode (the TOTP seed lives in
the database, which is owner-only).
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
from pathlib import Path

from .db import DB

SESSION_TTL_S = 12 * 3600
SESSION_IDLE_S = 2 * 3600
LINK_TTL_S = 120
TOKEN_PREFIX = "oak_"
ACCOUNT_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,31}$")
ROLES = ("admin", "operator", "viewer")
LOCK_AFTER = 5                      # failed sign-ins in LOCK_WINDOW_S lock the account for LOCK_FOR_S
LOCK_WINDOW_S, LOCK_FOR_S = 900, 900
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1, "maxmem": 64 * 2 ** 20}

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
  name TEXT PRIMARY KEY, role TEXT NOT NULL, pw_hash TEXT, totp_secret TEXT, totp_last_step INT DEFAULT 0,
  created_at REAL, created_by TEXT, disabled INT DEFAULT 0, failed_json TEXT DEFAULT '[]', locked_until REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (
  sid_hash TEXT PRIMARY KEY, account TEXT NOT NULL, csrf TEXT NOT NULL, created_at REAL, last_seen REAL, expires_at REAL,
  method TEXT, user_agent TEXT);
CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash TEXT PRIMARY KEY, token_id TEXT UNIQUE, account TEXT NOT NULL, label TEXT, role TEXT NOT NULL,
  created_at REAL, expires_at REAL, last_used_at REAL, revoked INT DEFAULT 0, scope TEXT);
CREATE TABLE IF NOT EXISTS login_links (link_hash TEXT PRIMARY KEY, account TEXT NOT NULL, expires_at REAL, used INT DEFAULT 0);
CREATE TABLE IF NOT EXISTS passkey_challenges (
  challenge_id TEXT PRIMARY KEY, challenge TEXT NOT NULL, purpose TEXT NOT NULL, account TEXT, rp_id TEXT, expires_at REAL);
CREATE TABLE IF NOT EXISTS passkeys (
  credential_id TEXT PRIMARY KEY, account TEXT NOT NULL, public_key TEXT NOT NULL, sign_count INT DEFAULT 0,
  label TEXT, rp_id TEXT, created_at REAL, last_used_at REAL);
"""


class AccessError(Exception):
    def __init__(self, code: str, detail: str = "", status: int = 403):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail, self.status = code, detail, status


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ------------------------------------------------------------------ the local owner's admin token

def admin_token_path(home: Path) -> Path:
    return Path(home) / "admin.token"


def ensure_admin_token(home: Path) -> str:
    """The local owner's credential: created once, owner-only; rotated with `oarbankd rotate-admin-token`."""
    p = admin_token_path(home)
    if p.exists():
        return p.read_text().strip()
    return rotate_admin_token(home)


def rotate_admin_token(home: Path) -> str:
    from ..platform import files
    tok = "oarbank-admin-" + secrets.token_urlsafe(32)
    files.write_private(admin_token_path(home), tok + "\n")
    return tok


def check_admin_token(home: Path, presented: str) -> bool:
    p = admin_token_path(home)
    if not presented or not p.exists():
        return False
    return hmac.compare_digest(p.read_text().strip().encode(), presented.encode())


# ------------------------------------------------------------------ passwords and TOTP

def hash_password(pw: str) -> str:
    if len(pw or "") < 12:
        raise AccessError("weak_password", "at least 12 characters", 400)
    salt = os.urandom(16)
    d = hashlib.scrypt(pw.encode(), salt=salt, dklen=32, **SCRYPT)
    return f"scrypt${SCRYPT['n']}${SCRYPT['r']}${SCRYPT['p']}${base64.b64encode(salt).decode()}${base64.b64encode(d).decode()}"


def verify_password(stored: str | None, pw: str) -> bool:
    try:
        _, n, r, p, salt, want = (stored or "").split("$")
        d = hashlib.scrypt((pw or "").encode(), salt=base64.b64decode(salt), dklen=32, n=int(n), r=int(r), p=int(p),
                           maxmem=SCRYPT["maxmem"])
    except (ValueError, TypeError):
        hashlib.scrypt(b"x", salt=b"0" * 16, dklen=32, **SCRYPT)       # same cost on unknown accounts
        return False
    return hmac.compare_digest(d, base64.b64decode(want))


def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def totp_at(secret: str, step: int, digits: int = 6) -> str:
    """RFC 6238 (HMAC-SHA1, 30 s steps), as every authenticator app implements it."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    return str((struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** digits).zfill(digits)


def totp_step(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """The matching step within ±1 of now, never one already used (replay); None when the code is wrong."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    t = int((now or time.time()) // 30)
    for step in (t - 1, t, t + 1):
        if step > last_step and hmac.compare_digest(totp_at(secret, step), code):
            return step
    return None


def otpauth_uri(account: str, secret: str, issuer: str = "Oarbank") -> str:
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


# ------------------------------------------------------------------ accounts

def account(db: DB, name: str) -> dict | None:
    return db.one("SELECT * FROM accounts WHERE name=?", (name,))


def accounts(db: DB) -> list[dict]:
    return [{k: v for k, v in a.items() if k not in ("pw_hash", "totp_secret", "failed_json")}
            for a in db.q("SELECT * FROM accounts ORDER BY name")]


def create_account(db: DB, name: str, role: str, password: str | None, actor: str) -> dict:
    """A new account with a fresh TOTP seed. Without a password the account signs in only with a one-time link or a
    passkey (the owner's usual setup). Returns the seed once."""
    if not ACCOUNT_RE.fullmatch(name or ""):
        raise AccessError("bad_name", "lower-case letters, digits, '.', '_', '-'; 2-32 characters", 400)
    if role not in ROLES:
        raise AccessError("bad_role", f"one of {', '.join(ROLES)}", 400)
    if account(db, name):
        raise AccessError("exists", name, 409)
    seed = new_totp_secret()
    db.x("INSERT INTO accounts(name, role, pw_hash, totp_secret, created_at, created_by) VALUES(?,?,?,?,?,?)",
         (name, role, hash_password(password) if password else None, seed, time.time(), actor))
    return {"account": name, "role": role, "totp_secret": seed, "otpauth": otpauth_uri(name, seed),
            "password_set": bool(password)}


def set_password(db: DB, name: str, password: str):
    if not account(db, name):
        raise AccessError("no_account", name, 404)
    db.x("UPDATE accounts SET pw_hash=? WHERE name=?", (hash_password(password), name))
    end_sessions(db, name)


def reset_totp(db: DB, name: str) -> dict:
    if not account(db, name):
        raise AccessError("no_account", name, 404)
    seed = new_totp_secret()
    db.x("UPDATE accounts SET totp_secret=?, totp_last_step=0 WHERE name=?", (seed, name))
    end_sessions(db, name)
    return {"account": name, "totp_secret": seed, "otpauth": otpauth_uri(name, seed)}


def set_disabled(db: DB, name: str, disabled: bool):
    if not account(db, name):
        raise AccessError("no_account", name, 404)
    if disabled and account(db, name)["role"] == "admin" and \
            db.one("SELECT COUNT(*) n FROM accounts WHERE role='admin' AND disabled=0 AND name!=?", (name,))["n"] == 0:
        raise AccessError("last_admin", "keep at least one enabled admin account", 409)
    db.x("UPDATE accounts SET disabled=? WHERE name=?", (1 if disabled else 0, name))
    if disabled:
        end_sessions(db, name)
        db.x("UPDATE access_tokens SET revoked=1 WHERE account=?", (name,))


def _locked(a: dict, now: float) -> bool:
    return (a.get("locked_until") or 0) > now


def _record_failure(db: DB, a: dict, now: float):
    import json
    fails = [t for t in json.loads(a.get("failed_json") or "[]") if t > now - LOCK_WINDOW_S] + [now]
    lock = now + LOCK_FOR_S if len(fails) >= LOCK_AFTER else (a.get("locked_until") or 0)
    db.x("UPDATE accounts SET failed_json=?, locked_until=? WHERE name=?", (json.dumps(fails[-LOCK_AFTER:]), lock, a["name"]))


def password_login(db: DB, name: str, password: str, code: str, now: float | None = None) -> dict:
    """Password and TOTP code: both must be right. The same answer for every failure (no account enumeration)."""
    now = now or time.time()
    a = account(db, (name or "").strip().lower())
    ok_pw = verify_password(a["pw_hash"] if a else None, password)
    if not a or a["disabled"] or _locked(a, now) or not a["pw_hash"] or not ok_pw:
        if a and not _locked(a, now):
            _record_failure(db, a, now)
        raise AccessError("bad_login", "wrong account, password or code, or the account is locked")
    step = totp_step(a["totp_secret"], code, a["totp_last_step"] or 0, now)
    if step is None:
        _record_failure(db, a, now)
        raise AccessError("bad_login", "wrong account, password or code, or the account is locked")
    db.x("UPDATE accounts SET totp_last_step=?, failed_json='[]', locked_until=0 WHERE name=?", (step, a["name"]))
    return a


# ------------------------------------------------------------------ sessions

def new_session(db: DB, name: str, method: str, user_agent: str = "") -> dict:
    sid, csrf, now = secrets.token_urlsafe(32), secrets.token_urlsafe(24), time.time()
    db.x("INSERT INTO sessions(sid_hash, account, csrf, created_at, last_seen, expires_at, method, user_agent) "
         "VALUES(?,?,?,?,?,?,?,?)", (_h(sid), name, csrf, now, now, now + SESSION_TTL_S, method, (user_agent or "")[:200]))
    db.x("DELETE FROM sessions WHERE expires_at<? OR last_seen<?", (now, now - SESSION_IDLE_S))
    return {"sid": sid, "csrf": csrf, "account": name, "expires_at": now + SESSION_TTL_S}


def session_for(reader, sid: str | None, now: float | None = None) -> dict | None:
    """The live session for a cookie value ({account, role, csrf, last_seen}), read-only (the console's reader works)."""
    if not sid:
        return None
    now = now or time.time()
    rows = reader.q("SELECT s.account, s.csrf, s.expires_at, s.last_seen, a.role, a.disabled FROM sessions s "
                    "JOIN accounts a ON a.name=s.account WHERE s.sid_hash=?", (_h(sid),))
    s = rows[0] if rows else None
    if not s or s["disabled"] or s["expires_at"] < now or s["last_seen"] < now - SESSION_IDLE_S:
        return None
    return {"account": s["account"], "role": s["role"], "csrf": s["csrf"], "last_seen": s["last_seen"]}


def touch_session(db: DB, sid: str):
    """The session is in use: its idle timeout (SESSION_IDLE_S) starts again."""
    db.x("UPDATE sessions SET last_seen=? WHERE sid_hash=?", (time.time(), _h(sid)))


def end_session(db: DB, sid: str):
    db.x("DELETE FROM sessions WHERE sid_hash=?", (_h(sid),))


def end_sessions(db: DB, name: str):
    db.x("DELETE FROM sessions WHERE account=?", (name,))


# ------------------------------------------------------------------ one-time sign-in links

def new_login_link(db: DB, name: str) -> str:
    a = account(db, name)
    if not a or a["disabled"]:
        raise AccessError("no_account", name, 404)
    t = secrets.token_urlsafe(32)
    db.x("INSERT INTO login_links(link_hash, account, expires_at) VALUES(?,?,?)", (_h(t), name, time.time() + LINK_TTL_S))
    return t


def use_login_link(db: DB, t: str) -> dict:
    with db.tx():
        r = db.one("SELECT * FROM login_links WHERE link_hash=?", (_h(t or ""),))
        if not r or r["used"] or r["expires_at"] < time.time():
            raise AccessError("bad_link", "this sign-in link is used or expired")
        db.x("UPDATE login_links SET used=1 WHERE link_hash=?", (r["link_hash"],))
        db.x("DELETE FROM login_links WHERE expires_at<?", (time.time() - 3600,))
    a = account(db, r["account"])
    if not a or a["disabled"]:
        raise AccessError("bad_link", "the account is disabled")
    return a


# ------------------------------------------------------------------ personal access tokens

def new_token(db: DB, name: str, label: str, role: str, days: float, scope: str | None = None) -> dict:
    """A personal access token. `scope` "module:<name>" limits it to that module's own operations and reads (the module
    CLI passthrough)."""
    a = account(db, name)
    if not a or a["disabled"]:
        raise AccessError("no_account", name, 404)
    if role not in ROLES or (role == "admin" and a["role"] != "admin") or (role == "operator" and a["role"] == "viewer"):
        raise AccessError("bad_role", f"a token cannot exceed its account's role ({a['role']})", 400)
    if not 0 < float(days) <= 366:
        raise AccessError("bad_expiry", "1 to 366 days", 400)
    tid = secrets.token_hex(4)
    tok = f"{TOKEN_PREFIX}{tid}_{secrets.token_urlsafe(32)}"
    now = time.time()
    db.x("INSERT INTO access_tokens(token_hash, token_id, account, label, role, created_at, expires_at, scope) VALUES(?,?,?,?,?,?,?,?)",
         (_h(tok), tid, name, (label or "")[:80], role, now, now + float(days) * 86400, scope))
    return {"token": tok, "token_id": tid, "account": name, "role": role, "expires_at": now + float(days) * 86400,
            **({"scope": scope} if scope else {})}


def token_identity(reader, tok: str) -> dict | None:
    if not (tok or "").startswith(TOKEN_PREFIX):
        return None
    rows = reader.q("SELECT t.account, t.role, t.expires_at, t.revoked, t.token_id, t.scope, a.disabled FROM access_tokens t "
                    "JOIN accounts a ON a.name=t.account WHERE t.token_hash=?", (_h(tok),))
    t = rows[0] if rows else None
    if not t or t["revoked"] or t["disabled"] or t["expires_at"] < time.time():
        return None
    return {"account": t["account"], "role": t["role"], "token_id": t["token_id"], "scope": t["scope"]}


def revoke_token(db: DB, token_id: str):
    if not db.x("UPDATE access_tokens SET revoked=1 WHERE token_id=?", (token_id,)):
        raise AccessError("no_token", token_id, 404)


def tokens(db: DB) -> list[dict]:
    return db.q("SELECT token_id, account, label, role, scope, created_at, expires_at, last_used_at, revoked FROM access_tokens "
                "ORDER BY created_at DESC")


# ------------------------------------------------------------------ passkeys (WebAuthn)

CHALLENGE_TTL_S = 300
_IP = re.compile(r"^[0-9.]+$|^\[?[0-9a-fA-F:]+\]?$")


def rp_for(host_header: str, scheme: str) -> tuple[str, str]:
    """(RP ID, origin) for a console request. Passkeys need a secure context and a domain RP ID: https with a host
    name, or http://localhost. An IP address never qualifies."""
    host = (host_header or "").strip().lower()
    name = host.rsplit(":", 1)[0] if not host.startswith("[") else host
    if _IP.match(name) or not name:
        raise AccessError("passkey_needs_hostname", "open the console as http://localhost:<port> or through its https "
                          "host name; passkeys never work on an IP address", 400)
    if scheme != "https" and name != "localhost":
        raise AccessError("passkey_needs_https", "passkeys need https (or http://localhost)", 400)
    return name, f"{scheme}://{host}"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _challenge(db: DB, purpose: str, account: str | None, rp_id: str) -> tuple[str, bytes]:
    cid, ch = secrets.token_urlsafe(16), os.urandom(32)
    db.x("DELETE FROM passkey_challenges WHERE expires_at<?", (time.time(),))
    db.x("INSERT INTO passkey_challenges(challenge_id, challenge, purpose, account, rp_id, expires_at) VALUES(?,?,?,?,?,?)",
         (cid, _b64u(ch), purpose, account, rp_id, time.time() + CHALLENGE_TTL_S))
    return cid, ch


def _take_challenge(db: DB, cid: str, purpose: str) -> dict:
    with db.tx():
        r = db.one("SELECT * FROM passkey_challenges WHERE challenge_id=?", (cid or "",))
        db.x("DELETE FROM passkey_challenges WHERE challenge_id=?", (cid or "",))
    if not r or r["purpose"] != purpose or r["expires_at"] < time.time():
        raise AccessError("bad_challenge", "the passkey prompt expired; try again")
    return r


def passkey_register_options(db: DB, name: str, rp_id: str) -> dict:
    import json
    import webauthn
    from webauthn.helpers import structs
    a = account(db, name)
    if not a or a["disabled"]:
        raise AccessError("no_account", name, 404)
    cid, ch = _challenge(db, "register", name, rp_id)
    have = [structs.PublicKeyCredentialDescriptor(id=_unb64u(r["credential_id"]))
            for r in db.q("SELECT credential_id FROM passkeys WHERE account=?", (name,))]
    opts = webauthn.generate_registration_options(
        rp_id=rp_id, rp_name="Oarbank", user_name=name, user_id=hashlib.sha256(name.encode()).digest()[:16],
        challenge=ch, exclude_credentials=have,
        authenticator_selection=structs.AuthenticatorSelectionCriteria(
            resident_key=structs.ResidentKeyRequirement.REQUIRED,
            user_verification=structs.UserVerificationRequirement.REQUIRED))
    return {"challenge_id": cid, "options": json.loads(webauthn.options_to_json(opts))}


def passkey_register(db: DB, name: str, cid: str, credential: dict, origin: str, label: str = "") -> dict:
    import webauthn
    c = _take_challenge(db, cid, "register")
    if c["account"] != name:
        raise AccessError("bad_challenge", "the prompt was for another account")
    try:
        v = webauthn.verify_registration_response(credential=credential, expected_challenge=_unb64u(c["challenge"]),
                                                  expected_rp_id=c["rp_id"], expected_origin=origin,
                                                  require_user_verification=True)
    except Exception as e:                       # the library raises several exception types for a bad ceremony
        raise AccessError("passkey_rejected", str(e)[:200], 400)
    cred = _b64u(v.credential_id)
    db.x("INSERT INTO passkeys(credential_id, account, public_key, sign_count, label, rp_id, created_at) VALUES(?,?,?,?,?,?,?)",
         (cred, name, _b64u(v.credential_public_key), v.sign_count, (label or "passkey")[:60], c["rp_id"], time.time()))
    return {"credential_id": cred, "account": name, "rp_id": c["rp_id"]}


def passkey_login_options(db: DB, rp_id: str) -> dict:
    import json
    import webauthn
    from webauthn.helpers import structs
    cid, ch = _challenge(db, "login", None, rp_id)
    opts = webauthn.generate_authentication_options(rp_id=rp_id, challenge=ch,
                                                    user_verification=structs.UserVerificationRequirement.REQUIRED)
    return {"challenge_id": cid, "options": json.loads(webauthn.options_to_json(opts))}


def passkey_login(db: DB, cid: str, credential: dict, origin: str) -> dict:
    import webauthn
    c = _take_challenge(db, cid, "login")
    pk = db.one("SELECT * FROM passkeys WHERE credential_id=?", (str((credential or {}).get("id") or ""),))
    if not pk or pk["rp_id"] != c["rp_id"]:
        raise AccessError("bad_login", "unknown passkey")
    try:
        v = webauthn.verify_authentication_response(
            credential=credential, expected_challenge=_unb64u(c["challenge"]), expected_rp_id=c["rp_id"],
            expected_origin=origin, credential_public_key=_unb64u(pk["public_key"]),
            credential_current_sign_count=pk["sign_count"] or 0, require_user_verification=True)
    except Exception as e:
        raise AccessError("bad_login", str(e)[:200])
    a = account(db, pk["account"])
    if not a or a["disabled"]:
        raise AccessError("bad_login", "the account is disabled")
    db.x("UPDATE passkeys SET sign_count=?, last_used_at=? WHERE credential_id=?", (v.new_sign_count, time.time(), pk["credential_id"]))
    return a


def passkeys(db: DB, name: str | None = None) -> list[dict]:
    return db.q("SELECT credential_id, account, label, rp_id, created_at, last_used_at FROM passkeys "
                "WHERE ? IS NULL OR account=? ORDER BY created_at", (name, name))


# ------------------------------------------------------------------ Host allowlist

TEST_HOSTS: set[str] = set()      # the core's test suite adds its test client's host name


def allowed_hosts(port: int, extra: list[str] | None = None) -> set[str]:
    """Host header values a listener answers to: loopback names on its port, plus the operator's console hostnames
    (setting `console_hosts`, for the remote mode)."""
    out = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    for h in extra or []:
        h = h.strip().lower()
        if h:
            out |= {h, f"{h}:{port}"} if ":" not in h.rsplit("]", 1)[-1] else {h}
    return out


def host_ok(host_header: str | None, allowed: set[str]) -> bool:
    return (host_header or "").strip().lower() in allowed


def via_funnel(headers) -> bool:
    """Tailscale Funnel marks public-internet requests; the coordinator never serves them."""
    return bool(headers.get("tailscale-funnel-request"))
