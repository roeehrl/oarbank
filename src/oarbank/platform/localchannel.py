"""The local admin channel (architecture.md, "Network and access"): oarbankd's admin API for the accounts that may run
the coordinator, without a token. Reaching the channel is the credential, so the caller is the owner.

- POSIX: a Unix socket in `<home>/run` (or a short owner-only directory under /tmp when that path would pass the
  socket path limit), whose owner-only directory admits only the coordinator's account.
- Windows: the named pipe `\\\\.\\pipe\\oarbank-admin-<home id>`, created with the owner-only security descriptor
  (files.trusted_sids: SYSTEM, the Administrators group, which an elevated prompt carries, and the coordinator's
  accounts), as its first instance (so no other process can have created the name first), refusing remote clients.
  Without the right to create instances, nobody else can add one to listen in.

`server(app, home)` is a uvicorn server for the channel, `transport(home)` an httpx transport to it and
`reachable(home)` whether this account can use it.
"""
import hashlib
import os
import sys
from pathlib import Path

WINDOWS = sys.platform == "win32"


def _home_id(home) -> str:
    return hashlib.sha256(str(Path(home).resolve()).encode()).hexdigest()[:12]


def address(home) -> str:
    """Where the channel for `home` is: a socket path, or a pipe name on Windows."""
    if WINDOWS:
        return rf"\\.\pipe\oarbank-admin-{_home_id(home)}"
    p = Path(home) / "run" / "admin.sock"
    if len(str(p).encode()) <= 100:
        return str(p)
    # the path would pass the socket limit (104 bytes on macOS): a directory someone else created is refused, so
    # another account cannot pre-create it to intercept the socket
    d = Path("/tmp") / f"oarbank-{os.getuid()}" / _home_id(home)
    for x in (d.parent, d):
        x.mkdir(mode=0o700, exist_ok=True)
        st = x.stat()
        if st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise PermissionError(f"{x} is not this account's private directory")
    return str(d / "admin.sock")


def reachable(home) -> bool:
    """This account can use the channel: the socket exists and its directory let us reach it, or the pipe exists and
    its security descriptor admits us (a connection that is closed again at once tells)."""
    try:
        a = address(home)
    except OSError:
        return False
    if not WINDOWS:
        return os.path.exists(a) and os.access(a, os.R_OK | os.W_OK)
    from . import _winpipe
    return _winpipe.reachable(a)


# ---------------------------------------------------------------------------- server and client

def server(app, home, **config):
    """A uvicorn server for `app` on the channel of `home`."""
    import uvicorn
    from . import files
    files.private_dir(Path(home) / "run")
    a = address(home)
    if WINDOWS:
        from . import _winpipe
        return _winpipe.PipeServer(uvicorn.Config(app, **config), a, home)
    Path(a).unlink(missing_ok=True)
    return uvicorn.Server(uvicorn.Config(app, uds=a, **config))


def transport(home):
    """An httpx transport to the channel of `home` (the request's host and port are ignored)."""
    a = address(home)
    if WINDOWS:
        from . import _winpipe
        return _winpipe.PipeTransport(a)
    import httpx
    return httpx.HTTPTransport(uds=a)
