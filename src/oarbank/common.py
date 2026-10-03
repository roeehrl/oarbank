"""Helpers shared by oarbankd, oarbank and module code (stdlib only)."""
import hashlib
import json
import math
from pathlib import Path


def canonical_json(obj) -> str:
    """Deterministic JSON for hashing: sorted keys, no whitespace, floats normalised."""
    return json.dumps(_normalise(obj), sort_keys=True, separators=(",", ":"))


def _normalise(obj):
    if isinstance(obj, dict):
        return {str(k): _normalise(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalise(v) for v in obj]
    if isinstance(obj, float):
        if math.isfinite(obj) and obj == int(obj) and abs(obj) < 1e15:
            return float(int(obj))
        return float(repr(obj))
    return obj


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, bufsize: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(bufsize), b""):
            h.update(chunk)
    return h.hexdigest()
