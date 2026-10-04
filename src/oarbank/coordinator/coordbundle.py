"""The coordinator bundle: what an enrolled node's agent installs to become a standby coordinator for a move
(docs/design/coordinator-move.md, "B pairs with A instead of using SSH").

It is the tracked files of the running checkout (and of the vendored SDK), as a gzipped tar, content-addressed.
The agent downloads it (sha256 checked), unpacks it under ~/oarbank-coordinator/<sha12>, runs `uv sync --frozen`,
writes the oarbankd and console LaunchAgents with `--standby --pair <code> --from <url>`, and bootstraps them. Only
the node named in a T3 `coordinator.prepare` is told to; the coordinator can already run code on its nodes through
releases, so this adds no power.
"""
import hashlib
import io
import subprocess
import tarfile
from pathlib import Path

from . import config as C
from .db import DB

REPO = Path(__file__).resolve().parents[3]


class NotACheckout(Exception):
    pass


def _tracked(root: Path) -> list[str]:
    r = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True)
    if r.returncode:
        raise NotACheckout(f"this coordinator does not run from a git checkout ({root}), so there is no checkout bundle "
                           "for a node to install: move with a signed coordinator build (release signing on), or start "
                           "the standby by hand and prepare the move with its URL")
    return [p for p in r.stdout.decode().split("\0") if p]


def build(repo: Path = REPO) -> bytes:
    """Reproducible: sorted members, fixed mtimes and owners."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        members = [(p, repo / p) for p in _tracked(repo)]
        sdk = repo / "vendor" / "oarbank-sdk"
        if (sdk / ".git").exists():
            members += [(f"vendor/oarbank-sdk/{p}", sdk / p) for p in _tracked(sdk)]
        for name, path in sorted(members):
            if not path.is_file() or path.is_symlink():
                continue
            info = tar.gettarinfo(str(path), arcname=f"oarbank/{name}")
            info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, "", ""
            with open(path, "rb") as f:
                tar.addfile(info, f)
    return buf.getvalue()


def ensure(db: DB) -> dict:
    """Build (or reuse) the bundle for the running checkout; returns {bundle_sha256, bundle_size, bundle_url}."""
    data = build(REPO)
    sha = hashlib.sha256(data).hexdigest()
    d = C.HOME / "move" / "bundles"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{sha}.tar.gz"
    if not p.exists():
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(p)
    return {"bundle_sha256": sha, "bundle_size": len(data), "bundle_url": f"/v1/move/bundle/{sha}", "bundle_dirty": dirty()}


def dirty(repo: Path = REPO) -> bool:
    """Uncommitted changes: the bundle carries tracked files as they are on disk, but no untracked ones."""
    r = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=normal"], capture_output=True, text=True)
    return bool(r.stdout.strip())


def path(sha: str) -> Path | None:
    p = C.HOME / "move" / "bundles" / f"{sha}.tar.gz"
    return p if len(sha) == 64 and p.exists() else None
