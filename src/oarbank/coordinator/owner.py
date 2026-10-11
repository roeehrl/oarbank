"""The owner's authority in signing mode (docs/design/coordinator-move.md, "The owner anchor set").

The owner key set is `{version, threshold: 1, keys: [primary, backup], rescue: [urls]}`, as a statement signed by
every key it names (each proves possession). A new set is accepted only at version + 1 and only if a key of the
current set also signs it, so a lost primary is replaced with the backup and no node is touched (TUF's root
rotation). With no set yet, the pinned release key counts as the current set, so the first set continues it.

Agents built with release signing pin the set and accept releases, agent builds and coordinator moves signed by
any of its keys; a move then needs the owner's signature as well as both coordinators'. Turning signing off needs an
owner-signed security statement (an attacker cannot downgrade a signed fleet). A **rescue move** is an
owner-signed move from a compromised coordinator: agents fetch it from the rescue locations named in the set.
None of the owner's private keys ever reach oarbankd.
"""
import base64
import json

from . import config as C
from . import identity
from .db import DB

ANCHORS_TYPE = "oarbank.owner-anchors/v1"
SECURITY_TYPE = "oarbank.owner-security/v1"


class OwnerError(Exception):
    pass


def anchors(db: DB) -> dict | None:
    a = db.get_state("owner_anchors")
    if not a:
        return None
    return {**a, "doc": json.loads(a["statement"])}


def keys(db: DB) -> list[str]:
    """The keys that may sign for the owner: the anchor set, else the pinned release key."""
    a = anchors(db)
    if a:
        return list(a["doc"]["keys"])
    k = db.get_state("release_pubkey")
    return [k] if k else []


def required(db: DB) -> bool:
    """Coordinator moves need the owner's signature (agents that pinned the keys would refuse one without)."""
    return C.RELEASE_SIGNING and bool(keys(db))


def verify_any(db: DB, data: str, sig: str | None) -> bool:
    return bool(sig) and any(identity.verify(k, data, sig) for k in keys(db))


def _sigs(signatures) -> list[dict]:
    if not isinstance(signatures, list) or not all(isinstance(s, dict) and s.get("key") and s.get("sig") for s in signatures):
        raise OwnerError("signatures: a list of {key, sig}")
    return signatures


def check_anchors(db: DB, statement: str, signatures: list) -> dict:
    """The TUF rule: version exactly +1, signed by every new key, and by a key of the current set (or the pinned
    release key) when there is one."""
    if not C.RELEASE_SIGNING:
        raise OwnerError("release signing is disabled (start oarbankd with OARBANK_RELEASE_SIGNING=1)")
    try:
        doc = json.loads(statement)
    except ValueError:
        raise OwnerError("the statement is not JSON")
    sigs = _sigs(signatures)
    if doc.get("type") != ANCHORS_TYPE or doc.get("fleet_id") != identity.fleet_id(db) or doc.get("threshold") != 1:
        raise OwnerError(f"not an owner key set for this fleet ({identity.fleet_id(db)}), threshold 1")
    new = doc.get("keys") or []
    if not (1 <= len(new) <= 4) or len(set(new)) != len(new) or any(len(base64.b64decode(k)) != 32 for k in new):
        raise OwnerError("keys: 1 to 4 distinct base64 raw Ed25519 public keys")
    cur = anchors(db)
    want = (cur["doc"]["version"] + 1) if cur else 1
    if doc.get("version") != want:
        raise OwnerError(f"version {doc.get('version')} is not {want}")
    by_key = {s["key"]: s["sig"] for s in sigs}
    missing = [k[:12] for k in new if not identity.verify(k, statement, by_key.get(k, ""))]
    if missing:
        raise OwnerError(f"every new key must sign the set (missing or bad: {missing})")
    old = keys(db)
    if old and not any(identity.verify(k, statement, by_key.get(k, "")) for k in old):
        raise OwnerError("a key of the current owner set must sign the new set")
    for u in doc.get("rescue") or []:
        if not isinstance(u, str) or not u.startswith(("http://", "https://")):
            raise OwnerError(f"rescue location {u!r} is not a URL")
    return doc


def set_anchors(db: DB, statement: str, signatures: list, actor: str) -> dict:
    doc = check_anchors(db, statement, signatures)
    db.set_state("owner_anchors", {"statement": statement, "signatures": signatures})
    db.set_state("release_pubkey", doc["keys"][0])        # the primary keeps signing releases as before
    db.event("owner_anchors_set", actor=actor, reason=f"version {doc['version']}: {len(doc['keys'])} keys")
    return {"version": doc["version"], "keys": [identity.fingerprint(k)[:16] for k in doc["keys"]], "rescue": doc.get("rescue") or []}


def disable(db: DB, statement: str, signatures: list, actor: str) -> dict:
    """Turn owner signing off: an owner-signed security statement at the next version; agents unpin on it."""
    try:
        doc = json.loads(statement)
    except ValueError:
        raise OwnerError("the statement is not JSON")
    cur = anchors(db)
    if doc.get("type") != SECURITY_TYPE or doc.get("action") != "disable_signing" or doc.get("fleet_id") != identity.fleet_id(db):
        raise OwnerError("not a disable-signing statement for this fleet")
    if doc.get("version") != ((cur["doc"]["version"] + 1) if cur else 1):
        raise OwnerError("version is not the next one")
    if not any(identity.verify(k, statement, s["sig"]) for s in _sigs(signatures) for k in keys(db) if s["key"] == k):
        raise OwnerError("not signed by an owner key")
    db.set_state("owner_security", {"statement": statement, "signatures": signatures})
    db.set_state("owner_anchors", None)
    db.set_state("release_pubkey", None)
    db.event("owner_signing_disabled", actor=actor)
    return {"disabled": True}


def directives(db: DB) -> dict:
    out = {}
    if C.RELEASE_SIGNING:
        a = db.get_state("owner_anchors")
        if a:
            out["owner_anchors"] = a
    s = db.get_state("owner_security")
    if s:
        out["owner_security"] = s
    return out
