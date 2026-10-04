"""Module secrets (oarbank-sdk spec/manifest.md, "Secrets"; docs/design/secrets-and-signed-images.md).

A module declares secrets by name (`[[secrets]]`); the owner sets each value, for the module or for one node, with
`secrets.set`. Values are write-only: they are stored encrypted (AES-256-GCM under the coordinator's secrets key, which
the secret store keeps outside the database: the Keychain on macOS, an owner-only file on Linux, a DPAPI-wrapped file on
Windows), shown only as "set" with a keyed fingerprint, and decrypted only to deliver them: in the grant of a job whose
stage lists them (resolved for the node: its own value, else the module's), and through `host.secrets.get` to a module
whose coordinator side has `secrets:read:self` (the module's value).

A coordinator move seals every value to the target's transport key (X25519) in the snapshot it sends; the target opens
them with its key the first time it starts active and re-encrypts them under its own secrets key (`adopt_sealed`).
"""
import base64
import hashlib
import hmac
import os
import sqlite3
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..platform import secrets as store
from .db import DB

KEY_NAME = "module-secrets"            # the at-rest key in the secret store
TRANSPORT_NAME = "move-transport"      # the X25519 key a standby receives sealed secrets with
FP_ROW = ("", "fingerprint-key", "")   # the fleet's fingerprint key, kept and moved like a secret
MAX_VALUE = 64 * 1024
REDACT_MIN = 6                         # shorter values are not redacted (they would mangle ordinary text)
SEAL_INFO = b"oarbank-move-secret/v1"


class SecretError(ValueError):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail = status, code, detail


def _home(db: DB) -> Path:
    return Path(db.path).parent


def _key(db: DB) -> bytes:
    return store.get_or_create(KEY_NAME, _home(db))


def _aad(module: str, name: str, node: str) -> bytes:
    return b"oarbank-secret/v1\0" + "\0".join((module, name, node)).encode()


def _encrypt(key: bytes, module: str, name: str, node: str, value: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, value, _aad(module, name, node))


def _decrypt(key: bytes, module: str, name: str, node: str, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], _aad(module, name, node))


def _row_value(db: DB, r: dict, key: bytes | None = None) -> bytes | None:
    """A row's plaintext, or None when this coordinator cannot open it (another machine's key, or still sealed)."""
    if r["sealed"]:
        return None
    try:
        return _decrypt(key or _key(db), r["module"], r["name"], r["node_id"], bytes(r["ciphertext"]))
    except Exception:                                       # noqa: BLE001 (InvalidTag: not this coordinator's key)
        return None


def _fp_key(db: DB) -> bytes:
    """The fleet's fingerprint key: created once, stored encrypted like a secret, carried by moves."""
    m, n, node = FP_ROW
    r = db.one("SELECT * FROM secrets WHERE module=? AND name=? AND node_id=?", FP_ROW)
    if r:
        v = _row_value(db, r)
        if v is not None:
            return v
    raw = os.urandom(32)
    db.x("INSERT INTO secrets(module,name,node_id,ciphertext,fingerprint,set_at,set_by,sealed) VALUES(?,?,?,?,NULL,?,?,0) "
         "ON CONFLICT(module,name,node_id) DO UPDATE SET ciphertext=excluded.ciphertext, sealed=0",
         (m, n, node, _encrypt(_key(db), m, n, node, raw), time.time(), "system"))
    return raw


def fingerprint(db: DB, value: bytes) -> str:
    return "fp:" + hmac.new(_fp_key(db), value, hashlib.sha256).hexdigest()[:16]


# ------------------------------------------------------------------ declarations

def declared(module: str) -> dict:
    """{name: Secret} the module's current version declares (none: an unknown or uninstalled module)."""
    from . import modcalls
    try:
        return {s.name: s for s in modcalls.info(module).manifest.secrets}
    except KeyError:
        return {}


def _check(db: DB, module: str, name: str, node: str):
    if name not in declared(module):
        raise SecretError(404, "unknown_secret", f"{module} declares no secret {name!r}")
    if node and not db.one("SELECT 1 FROM nodes WHERE node_id=? AND lifecycle!='retired'", (node,)):
        raise SecretError(404, "unknown_node", f"no node {node}")


def node_id(db: DB, node: str | None) -> str:
    """A node id from an id or a hostname ('' for the module scope)."""
    if not node:
        return ""
    r = db.one("SELECT node_id FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (node, node))
    if not r:
        raise SecretError(404, "unknown_node", f"no node {node}")
    return r["node_id"]


# ------------------------------------------------------------------ write-only operations

def put(db: DB, module: str, name: str, node: str, value: str, actor: str) -> dict:
    """Store a value (inside the caller's transaction). Returns what may be shown: {set, fingerprint, set_at}."""
    _check(db, module, name, node)
    raw = value.encode("utf-8") if isinstance(value, str) else b""
    if not raw or len(raw) > MAX_VALUE or not isinstance(value, str):
        raise SecretError(422, "bad_secret", f"a secret is a string of 1 byte to {MAX_VALUE} bytes")
    fp, t = fingerprint(db, raw), time.time()
    db.x("INSERT INTO secrets(module,name,node_id,ciphertext,fingerprint,set_at,set_by,sealed) VALUES(?,?,?,?,?,?,?,0) "
         "ON CONFLICT(module,name,node_id) DO UPDATE SET ciphertext=excluded.ciphertext, fingerprint=excluded.fingerprint, "
         "set_at=excluded.set_at, set_by=excluded.set_by, sealed=0",
         (module, name, node, _encrypt(_key(db), module, name, node, raw), fp, t, actor))
    db.x("UPDATE alerts SET state='resolved', resolved_at=?, resolved_how='secret set again' WHERE rule=? AND subject=? "
         "AND state IN ('open','pending')", (t, f"secret_unreadable:{module}/{name}", f"module:{module}"))
    return {"set": True, "fingerprint": fp, "set_at": t}


def clear(db: DB, module: str, name: str, node: str) -> dict:
    if name not in declared(module) and not db.one("SELECT 1 FROM secrets WHERE module=? AND name=?", (module, name)):
        raise SecretError(404, "unknown_secret", f"{module} declares no secret {name!r}")
    had = db.one("SELECT 1 FROM secrets WHERE module=? AND name=? AND node_id=?", (module, name, node))
    db.x("DELETE FROM secrets WHERE module=? AND name=? AND node_id=?", (module, name, node))
    return {"set": False, "cleared": bool(had)}


def state(db: DB, module: str, name: str, node: str) -> dict:
    """What an audit row or a page may show about one scope: never the value."""
    r = db.one("SELECT * FROM secrets WHERE module=? AND name=? AND node_id=?", (module, name, node))
    if not r:
        return {"set": False}
    return {"set": True, "fingerprint": r["fingerprint"], "set_at": r["set_at"], "set_by": r["set_by"],
            "readable": _row_value(db, r) is not None}


def listing(db: DB, module: str) -> list[dict]:
    """Per declared secret: its description, the stages that receive it, whether the coordinator side may read it, and
    each scope's state (module, and every node with its own value). No value, ever."""
    from . import modcalls
    try:
        man = modcalls.info(module).manifest
    except KeyError:
        return []
    key = _key(db)
    out = []
    for s in man.secrets:
        rows = db.q("SELECT * FROM secrets WHERE module=? AND name=? ORDER BY node_id", (module, s.name))
        scopes = []
        for r in rows:
            host = db.one("SELECT hostname FROM nodes WHERE node_id=?", (r["node_id"],)) if r["node_id"] else None
            scopes.append({"node_id": r["node_id"] or None, "hostname": host["hostname"] if host else None,
                           "fingerprint": r["fingerprint"], "set_at": r["set_at"], "set_by": r["set_by"],
                           "readable": _row_value(db, r, key) is not None})
        module_scope = next((x for x in scopes if x["node_id"] is None), None)
        out.append({"name": s.name, "description": s.description,
                    "stages": [st.name for st in man.stages if s.name in st.secrets],
                    "coordinator": "secrets:read:self" in man.coordinator.permissions,
                    "set": module_scope is not None, "module": module_scope,
                    "nodes": [x for x in scopes if x["node_id"] is not None]})
    return out


# ------------------------------------------------------------------ delivery

def _readable(db: DB, module: str, name: str, node: str, key: bytes) -> bytes | None:
    for scope in ((node, "") if node else ("",)):
        r = db.one("SELECT * FROM secrets WHERE module=? AND name=? AND node_id=?", (module, name, scope))
        if r:
            v = _row_value(db, r, key)
            if v is not None:
                return v
    return None


def missing_for(db: DB, module: str, names: list[str], node: str) -> list[str]:
    """The listed secrets with no readable value for this node (its own, else the module's)."""
    if not names:
        return []
    key = _key(db)
    return [n for n in names if _readable(db, module, n, node, key) is None]


def for_job(db: DB, module: str, names: list[str], node: str) -> dict:
    """{name: value} for a grant: each listed secret resolved for the node. Callers checked missing_for first."""
    key = _key(db)
    out = {}
    for n in names:
        v = _readable(db, module, n, node, key)
        if v is not None:
            out[n] = v.decode("utf-8")
    return out


def module_value(db: DB, module: str, name: str) -> str | None:
    """The module scope's value, for host.secrets.get."""
    r = db.one("SELECT * FROM secrets WHERE module=? AND name=? AND node_id=''", (module, name))
    v = _row_value(db, r) if r else None
    return v.decode("utf-8") if v is not None else None


def module_values(db: DB, module: str) -> dict:
    """Every readable module-scope value, for redacting the module process's log."""
    key = _key(db)
    out = {}
    for r in db.q("SELECT * FROM secrets WHERE module=? AND node_id=''", (module,)):
        v = _row_value(db, r, key)
        if v is not None:
            out[r["name"]] = v.decode("utf-8")
    return out


def redact(text: str, values: dict) -> str:
    """Replace every exact occurrence of a value (at least REDACT_MIN bytes) with `[secret:<name>]`. A safety net:
    an encoded or split value passes through."""
    for name, v in sorted(values.items(), key=lambda kv: -len(kv[1])):
        if len(v.encode()) >= REDACT_MIN and v in text:
            text = text.replace(v, f"[secret:{name}]")
    return text


def unreadable(db: DB) -> list[tuple[str, str]]:
    """(module, name) of declared secrets this coordinator holds but cannot open; each raises secret_unreadable."""
    key, out = _key(db), set()
    for r in db.q("SELECT * FROM secrets WHERE module!=''"):
        if _row_value(db, r, key) is None:
            out.add((r["module"], r["name"]))
    return sorted(out)


def check_readable(db: DB):
    """Open the P3 alert secret_unreadable:<module>/<name> for each value this coordinator cannot open (a restored
    backup, a home copied without its key)."""
    from .core import _alert
    for module, name in unreadable(db):
        _alert(db, f"secret_unreadable:{module}/{name}", f"module:{module}",
               f"{module}: secret {name} is stored but this coordinator cannot decrypt it (its key is on another machine): "
               f"set it again with `oarbank secret set {module} {name}`; jobs needing it wait (SECRETS_NOT_SET)")


def drop_node(db: DB, node: str):
    """A retired node's own values go with it."""
    db.x("DELETE FROM secrets WHERE node_id=? AND module!=''", (node,))


# ------------------------------------------------------------------ coordinator moves

def transport_public(home) -> str:
    """This coordinator's X25519 public key for receiving sealed secrets in a move (base64)."""
    priv = X25519PrivateKey.from_private_bytes(store.get_or_create(TRANSPORT_NAME, home))
    return base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def _seal_key(shared: bytes, eph: bytes, target: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=SEAL_INFO + eph + target).derive(shared)


def seal_snapshot(db: DB, path: Path, target_pub_b64: str) -> list[str]:
    """Rewrite a database snapshot's secrets so only the target opens them: each value this coordinator can open is
    sealed to `target_pub_b64` (ephemeral X25519, HKDF-SHA256, AES-256-GCM with the row's associated data). A value it
    cannot open goes as it is (it stays unreadable on the target too). Returns `module/name (scope)` for the preview."""
    target = base64.b64decode(target_pub_b64)
    tpub = X25519PublicKey.from_public_bytes(target)
    key = _key(db)
    c = sqlite3.connect(str(path))
    try:
        rows = c.execute("SELECT module, name, node_id, ciphertext, sealed FROM secrets").fetchall()
        for module, name, node, blob, sealed in rows:
            if sealed:
                continue
            try:
                value = _decrypt(key, module, name, node, bytes(blob))
            except Exception:                               # noqa: BLE001 (not this coordinator's: leave it)
                continue
            eph = X25519PrivateKey.generate()
            epub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            sk = _seal_key(eph.exchange(tpub), epub, target)
            nonce = os.urandom(12)
            sealed_blob = epub + nonce + AESGCM(sk).encrypt(nonce, value, _aad(module, name, node))
            c.execute("UPDATE secrets SET ciphertext=?, sealed=1 WHERE module=? AND name=? AND node_id=?",
                      (sealed_blob, module, name, node))
        c.commit()
    finally:
        c.close()
    return [f"{m}/{n} ({'node ' + nd if nd else 'module'})" for m, n, nd, _, _ in rows if m]


def adopt_sealed(db: DB) -> int:
    """On a coordinator that just became active after a move: open every sealed value with this coordinator's transport
    key and re-encrypt it under its own secrets key. A value it cannot open stays sealed (unreadable). Returns how many
    were adopted."""
    rows = db.q("SELECT * FROM secrets WHERE sealed=1")
    if not rows:
        return 0
    home = _home(db)
    priv = X25519PrivateKey.from_private_bytes(store.get_or_create(TRANSPORT_NAME, home))
    me = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key, n = _key(db), 0
    with db.tx():
        for r in rows:
            blob = bytes(r["ciphertext"])
            epub, nonce, ct = blob[:32], blob[32:44], blob[44:]
            try:
                sk = _seal_key(priv.exchange(X25519PublicKey.from_public_bytes(epub)), epub, me)
                value = AESGCM(sk).decrypt(nonce, ct, _aad(r["module"], r["name"], r["node_id"]))
            except Exception:                               # noqa: BLE001 (sealed for another machine)
                continue
            db.x("UPDATE secrets SET ciphertext=?, sealed=0 WHERE module=? AND name=? AND node_id=?",
                 (_encrypt(key, r["module"], r["name"], r["node_id"], value), r["module"], r["name"], r["node_id"]))
            n += 1
    if n:
        db.event("secrets_adopted", reason=f"{n} module secrets re-encrypted under this coordinator's key")
    return n


def names_for_preview(db: DB) -> list[str]:
    """`module/name (scope)` of every stored secret, for a move's preview."""
    out = []
    for r in db.q("SELECT module, name, node_id FROM secrets WHERE module!='' ORDER BY module, name, node_id"):
        host = db.one("SELECT hostname FROM nodes WHERE node_id=?", (r["node_id"],)) if r["node_id"] else None
        out.append(f"{r['module']}/{r['name']} ({'node ' + (host['hostname'] if host else r['node_id']) if r['node_id'] else 'module'})")
    return out
