"""Where Oarbank keeps its files on each platform (the coordinator side; the agent follows the same rules).

| Platform | Data root | Config root |
|---|---|---|
| macOS | ~/Library/Application Support/Oarbank | same |
| Linux | $XDG_DATA_HOME/oarbank (~/.local/share/oarbank) | $XDG_CONFIG_HOME/oarbank (~/.config/oarbank) |
| Windows | %LOCALAPPDATA%\\Oarbank | %APPDATA%\\Oarbank |

The coordinator lives in `<data root>/coordinator`, the agent in `<data root>/agent`. OARBANKD_HOME overrides the
coordinator's home.
"""
import os
import sys
from pathlib import Path


def data_root() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Oarbank"
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "Oarbank"
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "oarbank"


def config_root() -> Path:
    if sys.platform == "darwin":
        return data_root()
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "Oarbank"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "oarbank"


def release_key() -> Path:
    """The owner's release (primary) signing key: OARBANK_RELEASE_KEY, else <config root>/keys/release-ed25519.key."""
    return Path(os.environ.get("OARBANK_RELEASE_KEY") or config_root() / "keys" / "release-ed25519.key")


def coordinator_home() -> Path:
    return data_root() / "coordinator"


def runtime_socket(home, name: str) -> "Path":
    """Where a Unix socket for `home` lives: `<home>/run/<name>`, unless that path exceeds the 104-byte limit (macOS),
    then a short owner-only directory under /tmp named after the home. A directory someone else created is refused,
    so another account cannot pre-create it to intercept the socket."""
    import hashlib
    from pathlib import Path
    p = Path(home) / "run" / name
    if len(str(p).encode()) <= 100:
        return p
    d = Path("/tmp") / f"oarbank-{os.getuid()}" / hashlib.sha256(str(Path(home).resolve()).encode()).hexdigest()[:12]
    for x in (d.parent, d):
        x.mkdir(mode=0o700, exist_ok=True)
        st = x.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise PermissionError(f"{x} is not this account's private directory")
    return d / name
