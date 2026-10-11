"""Owner signatures over fleet releases (docs/design/fleet-updates.md, "Signatures"; D56).

The statement is canonical JSON (sorted keys, `(",", ":")`): {"type": "oarbank.fleet-release/v1", "version", "seq",
"manifest_sha256", "signed_at"}, `manifest_sha256` the hex sha256 of the manifest's exact text, signed with Ed25519
over its UTF-8 bytes like every other owner statement (signing.py). A signature object is {"statement", "signature"}.
Self-contained (stdlib and cryptography only): the root coordinator update runner imports it.
"""
import base64
import hashlib
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

TYPE = "oarbank.fleet-release/v1"


def manifest_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def statement(version: str, seq: int, manifest_text: str, signed_at: int | None = None) -> str:
    return json.dumps({"type": TYPE, "version": version, "seq": int(seq), "manifest_sha256": manifest_sha256(manifest_text),
                       "signed_at": int(time.time() if signed_at is None else signed_at)}, sort_keys=True, separators=(",", ":"))


def verify(sig: dict | None, keys: list[str], manifest_text: str) -> dict:
    """The parsed statement when `sig` ({statement, signature}) is a key's signature over a fleet-release statement
    naming this manifest; ValueError otherwise."""
    if not isinstance(sig, dict) or not isinstance(sig.get("statement"), str) or not isinstance(sig.get("signature"), str):
        raise ValueError("no owner signature ({statement, signature})")
    stmt = sig["statement"]
    for k in keys or []:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(k)).verify(base64.b64decode(sig["signature"]), stmt.encode())
            break
        except (InvalidSignature, ValueError, TypeError):
            continue
    else:
        raise ValueError("the fleet release signature does not verify under the owner keys")
    s = json.loads(stmt)
    if not isinstance(s, dict) or s.get("type") != TYPE:
        raise ValueError(f"not a {TYPE} statement")
    if s.get("manifest_sha256") != manifest_sha256(manifest_text):
        raise ValueError("the signed statement names another manifest")
    if not isinstance(s.get("seq"), int) or not isinstance(s.get("version"), str):
        raise ValueError("the signed statement has no version and seq")
    return s
