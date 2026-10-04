"""Media for module pages (oarbank-sdk spec/ui-contract.md, "Media"; docs/design/datasets-media-checkpoints.md).

The console renders a `media`, `gallery` or `compare` component only after it checked that each artifact reference
belongs to the module: a file of one of the module's jobs' canonical results, or a blob the module can see (its files, its
datasets with its jobs' artifacts, the operator's datasets). For a reference that passes, it mints a capability URL on
the module origin, `<module origin>/b/<token>`: the module, the digest, the kind and an expiry, signed with a key this
process holds in memory and shares only with its frames listener. The console origin never serves a media byte.

The frames listener serves `/b/<token>` only as an allowed type for the token's kind, sniffed from the bytes
(oarbank_sdk.media), with `nosniff`, a sandboxing CSP and single `Range` requests; SVG, HTML and anything else are
refused.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time

from oarbank_sdk import media as M
from oarbank_sdk import ui as U

TOKEN_TTL_S = 3600


class Tokens:
    """Signs and checks capability URLs for media bytes (one key per console process)."""

    def __init__(self, key: bytes | None = None, ttl_s: float = TOKEN_TTL_S):
        self.key, self.ttl_s = key or secrets.token_bytes(32), ttl_s

    def mint(self, module: str, digest: str, kind: str, now: float | None = None) -> str:
        body = base64.urlsafe_b64encode(json.dumps({"m": module, "d": digest, "k": kind,
                                                    "x": int((now or time.time()) + self.ttl_s)},
                                                   separators=(",", ":")).encode()).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(hmac.new(self.key, body.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        return f"{body}.{sig}"

    def check(self, token: str, now: float | None = None) -> dict | None:
        """The token's {m, d, k, x}, or None when it is forged, malformed or expired."""
        body, _, sig = (token or "").partition(".")
        want = base64.urlsafe_b64encode(hmac.new(self.key, body.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        if not body or not hmac.compare_digest(sig, want):
            return None
        try:
            doc = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except ValueError:
            return None
        if doc.get("x", 0) < (now or time.time()) or doc.get("k") not in M.CAPS:
            return None
        return doc


def _held(r, digest: str) -> bool:
    return bool(r.one("SELECT 1 FROM blobs WHERE digest=?", (digest,)))


def _visible(r, module: str, digest: str) -> bool:
    """A blob the module can see (coordinator/modfiles.visible_blob): its files, its datasets (its jobs' artifact datasets
    among them) or the operator's."""
    if r.one("SELECT 1 FROM module_files WHERE module=? AND digest=? LIMIT 1", (module, digest)):
        return True
    return bool(r.one("SELECT 1 FROM datasets WHERE (module=? OR module IS NULL OR module='') AND instr(files_json, ?) > 0 "
                      "LIMIT 1", (module, digest)))


def resolve(r, module: str, ref) -> dict | None:
    """{digest, thumbnail, job} for an artifact reference that belongs to `module`, or None (refused)."""
    try:
        ref = U.ArtifactRef.model_validate(ref)
    except Exception:                                      # noqa: BLE001 - not a reference: refused
        return None
    if ref.digest:
        if not _visible(r, module, ref.digest) or not _held(r, ref.digest):
            return None
        thumb = ref.thumbnail if ref.thumbnail and _visible(r, module, ref.thumbnail) and _held(r, ref.thumbnail) else None
        return {"digest": ref.digest, "thumbnail": thumb, "job": None}
    row = r.one("SELECT r.result_json FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id "
                "WHERE j.job_id=? AND j.module=? AND j.state='done'", (ref.job, module))
    if not row:
        return None
    for a in (json.loads(row["result_json"] or "{}") or {}).get("artifacts") or []:
        if a.get("name") != ref.artifact:
            continue
        for f in a.get("files") or []:
            if f.get("path") == ref.path and f.get("digest") and _held(r, f["digest"]):
                t = (f.get("thumbnail") or {}).get("digest")
                return {"digest": f["digest"], "thumbnail": t if t and _held(r, t) else None, "job": ref.job}
    return None


def urls(r, tokens: Tokens, module: str, module_origin: str, ref, kind: str) -> dict | None:
    """What the renderer's Host.media returns: {src, thumb, job} on the module origin, or None."""
    hit = resolve(r, module, ref)
    if hit is None or kind not in M.KINDS:
        return None
    src = f"{module_origin}/b/{tokens.mint(module, hit['digest'], kind)}"
    thumb = f"{module_origin}/b/{tokens.mint(module, hit['thumbnail'], M.THUMBNAIL)}" if hit["thumbnail"] else None
    return {"src": src, "thumb": thumb, "job": hit["job"]}
