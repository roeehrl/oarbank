"""Owner-only files and directories. On POSIX: modes 0600/0700. On Windows: the per-user data roots
(%LOCALAPPDATA%) are already private to the account; system-scope installs get no protected DACL here yet."""
import os
import sys
import tempfile
from pathlib import Path

POSIX = os.name == "posix"


def private_dir(p) -> Path:
    """Create (or tighten) a directory only its owner can enter."""
    p = Path(p)
    p.mkdir(parents=True, exist_ok=True)
    if POSIX:
        os.chmod(p, 0o700)
    return p


def write_private(p, data: str | bytes):
    """Write a file atomically with owner-only access from the first byte (never world-readable, even briefly)."""
    p = Path(p)
    if not p.parent.exists():
        private_dir(p.parent)
    fd, tmp = tempfile.mkstemp(prefix=f".{p.name}.", dir=p.parent)
    try:
        if POSIX:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode() if isinstance(data, str) else data)
        os.replace(tmp, p)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def tighten_home(home) -> list[str]:
    """Make the coordinator's home owner-only: the directory 0700, databases, keys, tokens and backups 0600. Returns
    what it changed (the readiness review found the home 0755 and the database 0644)."""
    if not POSIX:
        return []
    home, changed = Path(home), []
    if home.exists() and (home.stat().st_mode & 0o077):
        os.chmod(home, 0o700)
        changed.append(str(home))
    secret = (".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".key", ".token", ".secret", ".pem")
    for root, dirs, names in os.walk(home):
        for n in names:
            f = Path(root) / n
            if n.endswith(secret) or "backups" in f.parts:
                try:
                    if not f.is_symlink() and f.stat().st_mode & 0o077:
                        os.chmod(f, 0o600)
                        changed.append(str(f))
                except OSError:
                    pass
    return changed


def venv_python(venv) -> Path:
    """The interpreter inside a virtual environment on this OS."""
    return Path(venv) / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
