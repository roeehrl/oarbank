"""SecretStore (architecture.md, "The coordinator"): small secrets the coordinator keeps outside its database.

- macOS: the login Keychain (a generic password per name), the default there;
- elsewhere, or with OARBANK_SECRET_STORE=file: an owner-only file under <home>/keys/ (systemd-creds and DPAPI arrive
  with the Linux and Windows backends).

Secrets are raw bytes, created on first use.
"""
import base64
import os
import subprocess
import sys
from pathlib import Path

from . import files

ACCOUNT = "oarbank"


def backend() -> str:
    want = os.environ.get("OARBANK_SECRET_STORE")
    if want in ("file", "keychain"):
        return want
    return "keychain" if sys.platform == "darwin" else "file"


def get_or_create(name: str, home, size: int = 32) -> bytes:
    if backend() == "keychain":
        r = subprocess.run(["security", "find-generic-password", "-s", name, "-a", ACCOUNT, "-w"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return base64.b64decode(r.stdout.strip())
        raw = os.urandom(size)
        subprocess.run(["security", "add-generic-password", "-s", name, "-a", ACCOUNT, "-w", base64.b64encode(raw).decode(), "-U"],
                       check=True, capture_output=True)
        return raw
    p = Path(home) / "keys" / f"{name}.key"
    if p.exists():
        return base64.b64decode(p.read_text().strip())
    files.private_dir(p.parent)
    raw = os.urandom(size)
    files.write_private(p, base64.b64encode(raw).decode() + "\n")
    return raw
