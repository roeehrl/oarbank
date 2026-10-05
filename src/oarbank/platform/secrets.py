"""SecretStore (architecture.md, "The coordinator"): small secrets the coordinator keeps outside its database.

- macOS: the login Keychain (a generic password per name), the default there;
- Windows: a file under <home>/keys/ holding the secret wrapped with DPAPI for the current user (`CryptProtectData`), in
  a directory private to the account;
- Linux, or with OARBANK_SECRET_STORE=file: an owner-only file (0600) under <home>/keys/ (0700).

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
    return {"darwin": "keychain", "win32": "dpapi"}.get(sys.platform, "file")


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
    p = Path(home) / "keys" / f"{name}.key"
    if p.exists():
        return base64.b64decode(p.read_text(encoding="utf-8").strip())
    files.private_dir(p.parent)
    raw = os.urandom(size)
    files.write_private(p, base64.b64encode(raw).decode() + "\n")
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
