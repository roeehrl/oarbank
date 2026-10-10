"""Where Oarbank keeps its files on each platform (the coordinator side; the agent follows the same rules).

| Platform | Data root (a person's) | Config root (a person's) | System data root |
|---|---|---|---|
| macOS | ~/Library/Application Support/Oarbank | same | /Library/Application Support/Oarbank |
| Linux | $XDG_DATA_HOME/oarbank (~/.local/share/oarbank) | $XDG_CONFIG_HOME/oarbank (~/.config/oarbank) | /var/lib/oarbank |
| Windows | %LOCALAPPDATA%\\Oarbank | %APPDATA%\\Oarbank | %ProgramData%\\Oarbank |

The coordinator is a system service on every OS (docs/design/coordinator-system-service.md): its home is
`<system data root>/coordinator`, so every owner's CLI finds the same one. OARBANKD_HOME overrides it (tests,
development). A person's own roots keep what is theirs: the owner signing keys and the setup wizard's journal.
"""
import os
import sys
from pathlib import Path

# the coordinator's service account and the group whose members may use its local admin channel (macOS, Linux)
SERVICE_ACCOUNT = "_oarbankd" if sys.platform == "darwin" else "oarbankd"
ADMIN_GROUP = "_oarbankadmin" if sys.platform == "darwin" else "oarbank-admin"


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


def system_data_root() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Application Support/Oarbank")
    if sys.platform == "win32":
        return Path(os.environ.get("ProgramData") or r"C:\ProgramData") / "Oarbank"
    return Path("/var/lib/oarbank")


def release_key() -> Path:
    """The owner's release (primary) signing key: OARBANK_RELEASE_KEY, else <config root>/keys/release-ed25519.key.
    The person's, never the service's (coordinator-system-service.md, decision 6)."""
    return Path(os.environ.get("OARBANK_RELEASE_KEY") or config_root() / "keys" / "release-ed25519.key")


def coordinator_home() -> Path:
    """The coordinator's home: the system service's, on every OS."""
    return system_data_root() / "coordinator"


def admin_socket() -> Path:
    """The system service's local admin channel on macOS and Linux: a socket in a directory of its own (the service
    account's, mode 0750, group ADMIN_GROUP), outside the home that only the service account may enter."""
    if sys.platform == "darwin":
        return system_data_root() / "coordinator-run" / "admin.sock"
    return Path("/run/oarbank-coordinator/admin.sock")


def service_record() -> Path:
    """What the installer recorded about the system services (agent address, port, URL, programs), root's, readable by
    all: install-oarbankd.sh --refresh writes the services again from it."""
    if sys.platform == "darwin":
        return system_data_root() / "coordinator-service.json"
    return Path("/etc/oarbank/coordinator-service.json")


def setup_dir() -> Path:
    """The setup wizard's own journal, a person's: the pending enrollment, its lock, its live link, its completion
    record (on Windows the elevated wizard keeps them in the coordinator's home)."""
    return data_root() / "setup"
