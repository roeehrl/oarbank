"""The vendor's TUF metadata, mirrored for agents (PLAN D31; architecture.md, "Updates and trust"). The coordinator never signs or
checks it: agents verify it against the vendor root compiled into them (rust/crates/oarbank-agent/src/tuf.rs) before
installing an agent build. The owner uploads what the vendor publishes (`oarbank vendor-metadata upload <dir>`):
`root.json` and its versions `N.root.json`, `timestamp.json`, `snapshot.json`, `targets.json`.
"""
import json
import re
from pathlib import Path

NAME = re.compile(r"^(?:[1-9][0-9]{0,5}\.root|root|timestamp|snapshot|targets)\.json$")
TYPES = {"timestamp.json": "timestamp", "snapshot.json": "snapshot", "targets.json": "targets"}
MAX = 4 * 1024 * 1024


class MetadataError(ValueError):
    pass


def directory(home) -> Path:
    from ..platform import files
    return files.private_dir(Path(home) / "vendor-tuf")


def store(home, items: dict) -> list[str]:
    """Check each file's name, size and `_type`, then write them all (or none)."""
    checked = {}
    for name, text in (items or {}).items():
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise MetadataError(f"{name!r} is not a TUF metadata file name")
        if not isinstance(text, str) or len(text) > MAX:
            raise MetadataError(f"{name}: send the file's JSON text (at most {MAX // 2**20} MB)")
        try:
            doc = json.loads(text)
        except ValueError as e:
            raise MetadataError(f"{name}: not JSON ({e})")
        want = TYPES.get(name, "root")
        if not isinstance(doc, dict) or (doc.get("signed") or {}).get("_type") != want or not doc.get("signatures"):
            raise MetadataError(f"{name}: not signed {want} metadata")
        checked[name] = text
    if not checked:
        raise MetadataError("no metadata files")
    d = directory(home)
    for name, text in checked.items():
        tmp = d / f".{name}.tmp"
        tmp.write_text(text, encoding="utf-8", newline="\n")
        tmp.replace(d / name)
    return sorted(checked)


def path(home, name: str) -> Path | None:
    if not NAME.fullmatch(name or ""):
        return None
    p = Path(home) / "vendor-tuf" / name
    return p if p.is_file() else None


def listing(home) -> list[dict]:
    d = Path(home) / "vendor-tuf"
    out = []
    for p in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            s = json.loads(p.read_text(encoding="utf-8")).get("signed") or {}
        except ValueError:
            s = {}
        out.append({"name": p.name, "type": s.get("_type"), "version": s.get("version"), "expires": s.get("expires")})
    return out
