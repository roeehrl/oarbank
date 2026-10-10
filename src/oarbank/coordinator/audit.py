"""The audit log (PLAN D13): every operation, accepted or refused, as a hash-chained row written in the
same transaction as the mutation; never pruned.

- `append()` must run inside the caller's `db.tx()` (the single writer makes the chain serial).
- `verify()` recomputes the whole chain and checks every signed digest.
- `write_digest()` (hourly, from the background loop) signs {last_event_id, hash, ts, prev_sig} with an
  Ed25519 key kept in the secret store ("oarbank-audit-key"), not in the database. An owner-set command copies the
  digests off the host, so a rewrite of the chain is detectable.
This detects edits and truncation; it does not prevent them (anyone with the coordinator's account and its secret
store could re-sign). The threat model is bugs and careless sqlite3 sessions.
"""
import base64
import json
import subprocess
import time
import uuid
from typing import Any

from ..contracts.audit import GENESIS, AuditRecord, canonical, row_hash
from .db import DB, jl

KEYCHAIN_SERVICE = "oarbank-audit-key"


def request_id() -> str:
    return uuid.uuid4().hex


def append(db: DB, *, actor: str, source: str, operation: str, category: str, target_type: str, target_id: str,
           outcome: str, request_id: str, reason: str | None = None, before: Any = None, after: Any = None,
           dry_run: bool = False, plan_id: str | None = None, idempotency_key: str | None = None,
           user_agent: str | None = None, error: str | None = None, parent_event_id: int | None = None) -> AuditRecord:
    with db.tx():
        last = db.one("SELECT event_id, hash FROM audit ORDER BY event_id DESC LIMIT 1")
        prev, eid = (last["hash"], last["event_id"] + 1) if last else (GENESIS, 1)
        fields = dict(event_id=eid, ts=time.time(), actor=actor, source=source, user_agent=user_agent,
                      request_id=request_id, idempotency_key=idempotency_key, operation=operation, category=category,
                      target_type=target_type, target_id=str(target_id), dry_run=dry_run, plan_id=plan_id,
                      before=before, after=after, patch=None, reason=reason, outcome=outcome, error=error,
                      parent_event_id=parent_event_id, prev_hash=prev)
        rec = AuditRecord(**fields, hash=GENESIS)
        rec = rec.model_copy(update={"hash": row_hash(prev, rec.model_dump())})
        db.x("INSERT INTO audit(event_id,ts,actor,source,user_agent,request_id,idempotency_key,operation,category,"
             "target_type,target_id,dry_run,plan_id,before_json,after_json,reason,outcome,error,parent_event_id,"
             "prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
             (rec.event_id, rec.ts, rec.actor, rec.source, rec.user_agent, rec.request_id, rec.idempotency_key,
              rec.operation, rec.category, rec.target_type, rec.target_id, int(rec.dry_run), rec.plan_id,
              json.dumps(rec.before), json.dumps(rec.after), rec.reason, rec.outcome, rec.error,
              rec.parent_event_id, rec.prev_hash, rec.hash))
        db.event("audit", actor=actor, reason=f"{operation} {target_type}:{target_id} {outcome}", audit_event_id=eid)
    return rec


def row_to_record(r: dict) -> AuditRecord:
    return AuditRecord(event_id=r["event_id"], ts=r["ts"], actor=r["actor"], source=r["source"], user_agent=r["user_agent"],
                       request_id=r["request_id"], idempotency_key=r["idempotency_key"], operation=r["operation"],
                       category=r["category"], target_type=r["target_type"], target_id=r["target_id"],
                       dry_run=bool(r["dry_run"]), plan_id=r["plan_id"], before=jl(r["before_json"]),
                       after=jl(r["after_json"]), patch=None, reason=r["reason"], outcome=r["outcome"], error=r["error"],
                       parent_event_id=r["parent_event_id"], prev_hash=r["prev_hash"], hash=r["hash"])


# ------------------------------------------------------------------ digests and verification

class Signer:
    """Ed25519 signer. Default: the key in the SecretStore (created on first use). Tests pass a key."""

    def __init__(self, private_key_b64: str | None = None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        raw = base64.b64decode(private_key_b64) if private_key_b64 else _keychain_key()
        self.key = Ed25519PrivateKey.from_private_bytes(raw)
        self.public_b64 = base64.b64encode(self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self.key.sign(data)).decode()


def _keychain_key() -> bytes:
    """The audit key from the SecretStore: the login Keychain on macOS, else an owner-only file in the home."""
    from ..platform import secrets
    from . import config as C
    return secrets.get_or_create(KEYCHAIN_SERVICE, C.HOME)


def _digest_body(last_event_id: int, h: str, ts: float, prev_sig: str | None, next_pubkey: str | None = None) -> bytes:
    body = {"last_event_id": last_event_id, "hash": h, "ts": ts, "prev_digest_sig": prev_sig}
    if next_pubkey:                         # a coordinator move: this digest hands the chain to the next machine's key
        body["next_pubkey"] = next_pubkey
    return canonical(body)


def write_digest(db: DB, signer: Signer, next_pubkey: str | None = None) -> dict | None:
    """Sign the chain head if it moved since the last digest (or always, when handing over to `next_pubkey`).
    Returns the digest written, or None."""
    head = db.one("SELECT event_id, hash FROM audit ORDER BY event_id DESC LIMIT 1")
    last = db.one("SELECT * FROM audit_digests ORDER BY last_event_id DESC LIMIT 1")
    if not head or (last and last["last_event_id"] == head["event_id"] and not next_pubkey):
        return None
    if not db.get_state("audit_pubkey_first"):
        # the key that signed every digest so far: verification starts from it, even after moves change the signer
        db.set_state("audit_pubkey_first", db.get_state("audit_pubkey") or signer.public_b64)
    ts, prev_sig = time.time(), last["sig"] if last else None
    sig = signer.sign(_digest_body(head["event_id"], head["hash"], ts, prev_sig, next_pubkey))
    with db.tx():
        db.x("INSERT OR REPLACE INTO audit_digests(last_event_id,hash,ts,prev_sig,sig,pubkey,next_pubkey) VALUES(?,?,?,?,?,?,?)",
             (head["event_id"], head["hash"], ts, prev_sig, sig, signer.public_b64, next_pubkey))
    db.set_state("audit_pubkey", signer.public_b64)
    return {"last_event_id": head["event_id"], "hash": head["hash"], "ts": ts, "prev_sig": prev_sig, "sig": sig,
            "next_pubkey": next_pubkey}


def _rescue_key(db: DB) -> tuple | None:
    """(last digest before the rescue, the audit key the owner-signed rescue move names) after a rescue, else None."""
    r = db.get_state("audit_rescue")
    if not r:
        return None
    from . import owner
    if not owner.verify_any(db, r["statement"], r.get("owner_sig")):
        return None
    return r.get("after"), json.loads(r["statement"])["to"]["audit_pubkey"]


def verify(db: DB, public_b64: str | None = None) -> dict:
    """Recompute the chain and check every digest. {ok, rows, broken_at, digests, bad_digest}."""
    prev, n, broken = GENESIS, 0, None
    hashes = {}
    for r in db.q("SELECT * FROM audit ORDER BY event_id"):
        rec = row_to_record(r)
        n += 1
        if rec.prev_hash != prev or row_hash(prev, rec.model_dump()) != rec.hash:
            broken = rec.event_id
            break
        hashes[rec.event_id] = rec.hash
        prev = rec.hash
    bad_digest, nd = None, 0
    pub = public_b64 or db.get_state("audit_pubkey_first") or db.get_state("audit_pubkey")
    if pub:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        def ok(k: str, d: dict) -> bool:
            try:
                Ed25519PublicKey.from_public_bytes(base64.b64decode(k)).verify(
                    base64.b64decode(d["sig"]), _digest_body(d["last_event_id"], d["hash"], d["ts"], d["prev_sig"], d.get("next_pubkey")))
                return True
            except (InvalidSignature, ValueError):
                return False
        prev_sig, cur, handover, prev_last = None, pub, None, None
        rescue = _rescue_key(db)
        for d in db.q("SELECT * FROM audit_digests ORDER BY last_event_id"):
            nd += 1
            ok_link = d["prev_sig"] == prev_sig
            # the signer may change only right after a digest, signed by the current key, that named the next key,
            # or where an owner-signed rescue move took the fleet over (rescue.py), to the key that move names
            if ok(cur, d):
                ok_sig = True
            elif handover and ok(handover, d):
                ok_sig, cur = True, handover
            elif rescue and prev_last == rescue[0] and ok(rescue[1], d):
                ok_sig, cur = True, rescue[1]
            else:
                ok_sig = False
            if not (ok_link and ok_sig and (broken is not None or hashes.get(d["last_event_id"]) == d["hash"])):
                bad_digest = d["last_event_id"]
                break
            handover = d.get("next_pubkey")
            prev_sig, prev_last = d["sig"], d["last_event_id"]
    return {"ok": broken is None and bad_digest is None, "rows": n, "broken_at": broken, "digests": nd, "bad_digest": bad_digest}


# ------------------------------------------------------------------ off-host digest copies

def digest_log(db: DB):
    from pathlib import Path
    return Path(db.path).parent / "audit" / "digests.jsonl"


def export_digest(db: DB, d: dict) -> "Path":
    """Append a digest to <home>/audit/digests.jsonl (the file copied off the host)."""
    p = digest_log(db)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps({k: d[k] for k in ("last_event_id", "hash", "ts", "prev_sig", "sig")}, sort_keys=True) + "\n")
    return p


def copy_off_host(db: DB) -> dict | None:
    """Run the owner's copy command (setting `audit_digest_copy`: an argv with `{file}`, e.g.
    ["scp", "-q", "{file}", "backup-host:oarbank-audit/"]) so a rewrite of this host's chain is detectable later."""
    import subprocess
    argv = db.get_state("audit_digest_copy")
    p = digest_log(db)
    if not argv or not p.exists():
        return None
    cmd = [a.replace("{file}", str(p)) for a in argv]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    return {"ok": r.returncode == 0, "detail": (r.stderr or r.stdout)[-300:]}


def verify_against(db: DB, lines: list[dict]) -> dict:
    """Check an off-host copy of the digests: every copied digest must still be in this host's table with
    the same hash and signature, and the chain must still hash to it. A rewritten and re-signed chain fails."""
    have = {d["last_event_id"]: d for d in db.q("SELECT * FROM audit_digests")}
    chain = {}
    prev = GENESIS
    for r in db.q("SELECT * FROM audit ORDER BY event_id"):
        rec = row_to_record(r)
        prev = row_hash(prev, rec.model_dump()) if rec.prev_hash == prev else None
        if prev is None:
            break
        chain[rec.event_id] = prev
    missing, mismatched = [], []
    for d in lines:
        h = have.get(d["last_event_id"])
        if not h:
            missing.append(d["last_event_id"])
        elif h["hash"] != d["hash"] or h["sig"] != d["sig"] or chain.get(d["last_event_id"]) != d["hash"]:
            mismatched.append(d["last_event_id"])
    return {"ok": not missing and not mismatched, "checked": len(lines), "missing": missing[:20], "mismatched": mismatched[:20]}
