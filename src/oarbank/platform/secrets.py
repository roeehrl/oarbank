"""SecretStore (architecture.md, "The coordinator"): small secrets the coordinator keeps outside its database.

- macOS and Linux (the default there, `file`): an owner-only file (0600) under <home>/keys/ (0700), in the system
  service's home that only its account may enter (coordinator-system-service.md, decision 5);
- Windows (`dpapi`): a file under <home>/keys/ holding the secret wrapped with DPAPI for the current user
  (`CryptProtectData`), in a directory private to the account;
- `keychain`, only when OARBANK_SECRET_STORE names it: the person's login Keychain, a generic password per name. A
  per-user coordinator of an earlier release kept its keys there; its migration pins it to the Keychain until the
  person exports them (`read_keychain`, sysmigrate.py) into the file store the system service reads.

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
    if want in ("file", "keychain", "dpapi"):
        return want
    return "dpapi" if sys.platform == "win32" else "file"


def read_keychain(name: str, keychain: str | None = None) -> bytes | None:
    """The secret `name` from a login Keychain (the person's search list, or the keychain file `keychain`), None when
    it holds no such item. Run as the person, in their session: the Keychain is theirs."""
    argv = ["security", "find-generic-password", "-s", name, "-a", ACCOUNT, "-w"] + ([keychain] if keychain else [])
    r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return base64.b64decode(r.stdout.strip())


def file_path(name: str, home) -> Path:
    """Where the file store keeps `name` in `home`."""
    return Path(home) / "keys" / f"{name}.key"


def write_file_secret(name: str, home, raw: bytes, exclusive: bool = True):
    """Put `raw` into the file store of `home`, in its own format (base64 and a newline, 0600)."""
    p = file_path(name, home)
    files.private_dir(p.parent)
    files.write_private(p, base64.b64encode(raw).decode() + "\n", exclusive=exclusive)


def read_file_secret(name: str, home) -> bytes | None:
    p = file_path(name, home)
    return base64.b64decode(p.read_text(encoding="utf-8").strip()) if p.exists() else None


def get_or_create(name: str, home, size: int = 32) -> bytes:
    if backend() == "keychain":
        r = subprocess.run(["security", "find-generic-password", "-s", name, "-a", ACCOUNT, "-w"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return base64.b64decode(r.stdout.strip())
        raw = os.urandom(size)
        subprocess.run(["security", "add-generic-password", "-s", name, "-a", ACCOUNT, "-w", base64.b64encode(raw).decode(), "-U"],
                       check=True, capture_output=True)
        return raw
    if backend() == "dpapi":
        p = Path(home) / "keys" / f"{name}.dpapi"
        if p.exists():
            return _dpapi(p.read_bytes(), protect=False)
        files.private_dir(p.parent)
        raw = os.urandom(size)
        files.write_private(p, _dpapi(raw, protect=True))
        return raw
    existing = read_file_secret(name, home)
    if existing is not None:
        return existing
    raw = os.urandom(size)
    write_file_secret(name, home, raw, exclusive=False)
    return raw


def _dpapi(data: bytes, protect: bool) -> bytes:
    """CryptProtectData / CryptUnprotectData for the current user, no UI (Windows only)."""
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    src, out = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), Blob()
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out))
    if not ok:
        raise OSError(ctypes.get_last_error() or kernel32.GetLastError(), "DPAPI refused the secret")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)
