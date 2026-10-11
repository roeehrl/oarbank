"""The local admin channel (architecture.md, "Network and access"): oarbankd's admin API for the accounts that may run
the coordinator, without a token. Reaching the channel is the credential, so the caller is the owner.

- POSIX, the system service (coordinator-system-service.md, decision 4): a Unix socket in a directory of its own outside
  the home (paths.admin_socket(); OARBANKD_ADMIN_SOCKET in the service definition), owned by the service account,
  mode 0750, group OARBANKD_ADMIN_GROUP (`_oarbankadmin`, `oarbank-admin`): the service account and the owners' group
  reach it, nobody else can even see it. uvicorn makes the socket itself 0666, so the directory is the credential.
- POSIX, any other home (tests, development): a Unix socket in `<home>/run` (or a short owner-only directory under
  /tmp when that path would pass the socket path limit), whose owner-only directory admits only the coordinator's
  account.
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


def _system_socket(home) -> str | None:
    """The system service's socket when `home` is the system service's home (or the service definition names one)."""
    explicit = os.environ.get("OARBANKD_ADMIN_SOCKET")
    if explicit:
        return explicit
    from .. import paths
    try:
        if Path(home).resolve() == paths.coordinator_home().resolve():
            return str(paths.admin_socket())
    except OSError:
        pass
    return None


def address(home) -> str:
    """Where the channel for `home` is: a socket path, or a pipe name on Windows."""
    if WINDOWS:
        return rf"\\.\pipe\oarbank-admin-{_home_id(home)}"
    system = _system_socket(home)
    if system:
        return system
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
        try:
            return os.path.exists(a) and os.access(a, os.R_OK | os.W_OK)
        except OSError:
            return False
    from . import _winpipe
    return _winpipe.reachable(a)


# ---------------------------------------------------------------------------- server and client

def server(app, home, **config):
    """A uvicorn server for `app` on the channel of `home`."""
    import uvicorn
    from . import files
    files.private_dir(Path(home) / "run")
    a = address(home)
    if not WINDOWS and _system_socket(home):
        group_dir(Path(a).parent, os.environ.get("OARBANKD_ADMIN_GROUP"))
    if WINDOWS:
        from . import _winpipe
        return _winpipe.PipeServer(uvicorn.Config(app, **config), a, home)
    Path(a).unlink(missing_ok=True)
    return uvicorn.Server(uvicorn.Config(app, uds=a, **config))


def group_dir(d: Path, group: str | None):
    """The system service's socket directory: this account's, mode 0750, its group `group` (the owners'), which the
    service account belongs to (a group it is not in is refused by chown and leaves the directory owner-only)."""
    d.mkdir(parents=True, exist_ok=True)
    st = d.stat()
    if st.st_uid != os.getuid():
        raise PermissionError(f"{d} is not this account's directory")
    if group:
        import grp
        gid = grp.getgrnam(group).gr_gid
        if st.st_gid != gid:
            os.chown(d, -1, gid)
        os.chmod(d, 0o750)
    else:
        os.chmod(d, 0o700)


def unreachable_reason(home) -> str | None:
    """Why this account cannot use the system service's channel although the service runs: a person outside the
    owners' group, or one just added whose processes do not carry the group yet (Linux reads groups at login)."""
    if WINDOWS or not _system_socket(home):
        return None
    import grp
    import pwd
    from .. import paths
    a = Path(address(home))
    try:
        members = grp.getgrnam(paths.ADMIN_GROUP).gr_mem
    except KeyError:
        return None
    me = pwd.getpwuid(os.getuid()).pw_name
    if me not in members:
        return (f"{me} is not in the group {paths.ADMIN_GROUP} of the coordinator's owners: "
                + ("sudo dseditgroup -o edit -a " if sys.platform == "darwin" else "sudo usermod -aG ")
                + (f"{me} -t user {paths.ADMIN_GROUP}" if sys.platform == "darwin" else f"{paths.ADMIN_GROUP} {me}"))
    if not reachable(home) and a.parent.exists():
        return f"you were added to {paths.ADMIN_GROUP} after this session started: log in again (or run `newgrp {paths.ADMIN_GROUP}`)"
    return None


def transport(home):
    """An httpx transport to the channel of `home` (the request's host and port are ignored)."""
    a = address(home)
    if WINDOWS:
        from . import _winpipe
        return _winpipe.PipeTransport(a)
    import httpx
    return httpx.HTTPTransport(uds=a)
