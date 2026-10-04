"""Where Oarbank keeps its files on each platform (the coordinator side; the agent follows the same rules).

| Platform | Data root | Config root |
|---|---|---|
| macOS | ~/Library/Application Support/Oarbank | same |
| Linux | $XDG_DATA_HOME/oarbank (~/.local/share/oarbank) | $XDG_CONFIG_HOME/oarbank (~/.config/oarbank) |
| Windows | %LOCALAPPDATA%\\Oarbank | %APPDATA%\\Oarbank |

The coordinator lives in `<data root>/coordinator`, the agent in `<data root>/agent`, except that on Windows the
coordinator is always a system service with its home in %ProgramData%\\Oarbank\\coordinator (the CLI in an elevated
prompt finds it there). OARBANKD_HOME overrides the coordinator's home.
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
    if sys.platform == "win32":
        return Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "Oarbank" / "coordinator"
    return data_root() / "coordinator"

