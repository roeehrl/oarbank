"""Owner-only files and directories.

- POSIX: modes 0600 and 0700.
- Windows: a protected DACL (nothing inherited from the parent) granting full control to SYSTEM, the Administrators
  group and this process's account only; inside the coordinator's home also the coordinator's two service accounts
  (`NT SERVICE\\dev.codonic.oarbank.oarbankd` and `…console`: the console reads the database and its per-boot secret),
  as the two run as one account on macOS and Linux. Directories pass the entries on to what is created inside them.

`seal` marks a stored, content-addressed file read-only on POSIX. On Windows it leaves the file as it is: there the
read-only attribute is no access control (the DACL is) and would stop the file being replaced by a rename or
deleted, which is how every stored file is renewed or collected.
"""
import hashlib
import os
import struct
import sys
import tempfile
from pathlib import Path

POSIX = os.name == "posix"
COORDINATOR_SERVICES = ("dev.codonic.oarbank.oarbankd", "dev.codonic.oarbank.console")


def service_sid(name: str) -> str:
    """The SID of a service's virtual account, `NT SERVICE\\<name>`: S-1-5-80 and the SHA-1 of the upper-cased name in
    UTF-16LE as five 32-bit sub-authorities (how Windows derives it, so it is known before the service exists)."""
    d = hashlib.sha1(name.upper().encode("utf-16-le")).digest()
    return "S-1-5-80-" + "-".join(str(x) for x in struct.unpack("<5I", d))


def trusted_sids(p=None) -> list[str]:
    """Who an owner-only object admits on Windows, as S-1-… strings: SYSTEM, Administrators and this account (which may
    be one of the two), and in the coordinator's home (`p` inside it) the coordinator's two service accounts, whichever
    account writes it (an owner running a rescue in an elevated prompt writes files the service must read)."""
    from . import _win32 as W
    out = [W.canonical_sid("SY"), W.canonical_sid("BA")]
    out += [s for s in [W.current_user_sid()] if s not in out]
    if p is not None:
        from ..coordinator import config as C
        try:
            Path(p).resolve().relative_to(C.HOME.resolve())
        except ValueError:
            return out
        out += [s for s in (service_sid(n) for n in COORDINATOR_SERVICES) if s not in out]
    return out


def _sddl(p, directory: bool) -> str:
    inherit = "OICI" if directory else ""
    return "D:P" + "".join(f"(A;{inherit};FA;;;{s})" for s in trusted_sids(p))


def _protect(p: Path, directory: bool):
    from . import _win32 as W
    sd = W.SecurityDescriptor(_sddl(p, directory))
    err = W.SetNamedSecurityInfoW(str(p), W.SE_FILE_OBJECT, W.DACL_SECURITY_INFORMATION | W.PROTECTED_DACL_SECURITY_INFORMATION,
                                  None, None, sd.dacl(), None)
    if err:
        raise W.ctypes.WinError(err, f"making {p} owner-only")


def private_dir(p) -> Path:
    """Create (or tighten) a directory only its owner can enter."""
    p = Path(p)
    p.mkdir(parents=True, exist_ok=True)
    if POSIX:
        os.chmod(p, 0o700)
    else:
        _protect(p, directory=True)
    return p


def write_private(p, data: str | bytes, exclusive: bool = False):
    """Write a file atomically with owner-only access from the first byte (never readable by others, even briefly).
    `exclusive`: fail with FileExistsError when the file exists (a key made once)."""
    p = Path(p)
    if not p.parent.exists():
        private_dir(p.parent)
    if POSIX:
        fd, tmp = tempfile.mkstemp(prefix=f".{p.name}.", dir=p.parent)
        os.fchmod(fd, 0o600)
    else:
        fd, tmp = _create_private(p.parent, f".{p.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            fd = None
            f.write(data.encode() if isinstance(data, str) else data)
        if not exclusive:
            os.replace(tmp, p)
        elif POSIX:
            os.link(tmp, p)                       # refuses an existing name, as O_EXCL does
            os.unlink(tmp)
        else:
            os.rename(tmp, p)                     # Windows: a rename never replaces
    except BaseException:
        if fd is not None:
            os.close(fd)
        Path(tmp).unlink(missing_ok=True)
        raise


def _create_private(d: Path, prefix: str) -> tuple[int, str]:
    """Windows: a new file in `d` created with the owner-only descriptor (not one inherited from `d`), open for writing."""
    import msvcrt
    import secrets
    from . import _win32 as W
    sd = W.SecurityDescriptor(_sddl(d, directory=False))
    sa = sd.attributes()
    GENERIC_WRITE, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, ERROR_FILE_EXISTS = 0x40000000, 1, 0x80, 80
    for _ in range(100):
        tmp = str(d / f"{prefix}{secrets.token_hex(6)}")
        h = W.CreateFileW(tmp, GENERIC_WRITE, 0, W.ctypes.byref(sa), CREATE_NEW, FILE_ATTRIBUTE_NORMAL, None)
        if h != W.INVALID_HANDLE_VALUE:
            return msvcrt.open_osfhandle(h, os.O_WRONLY | os.O_BINARY), tmp
        if W.ctypes.get_last_error() != ERROR_FILE_EXISTS:
            raise W.ctypes.WinError(W.ctypes.get_last_error(), f"creating {tmp}")
    raise FileExistsError(f"no free temporary name in {d}")


def owner_only(p) -> bool:
    """Only the owner can read `p`: no group or other bits on POSIX; on Windows every entry that allows anything names
    a trusted account (trusted_sids)."""
    p = Path(p)
    if POSIX:
        return not (p.stat().st_mode & 0o077)
    from . import _win32 as W
    # and OWNER RIGHTS: the file's owner, which CPython's mkdir(mode=0o700) grants
    return W.allowed_sids(str(p)) <= set(trusted_sids(p)) | {"S-1-3-4"}


def access(p) -> str:
    """Who can read `p`, for an error message: its mode on POSIX, its DACL on Windows."""
    if POSIX:
        return f"mode {oct(Path(p).stat().st_mode & 0o777)}"
    from . import _win32 as W
    return f"ACL {W.dacl_sddl(str(p))}"


def _inherit_only(p: Path):
    """Windows: drop a file's own entries so it carries only what its (owner-only) directory passes on."""
    from . import _win32 as W
    empty = W.SecurityDescriptor("D:")
    UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
    err = W.SetNamedSecurityInfoW(str(p), W.SE_FILE_OBJECT, W.DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                                  None, None, empty.dacl(), None)
    if err:
        raise W.ctypes.WinError(err, f"resetting the ACL of {p}")


def tighten_home(home) -> list[str]:
    """Make the coordinator's home owner-only: the directory, and its databases, keys, tokens and backups. Returns what
    it changed (the readiness review found the home 0755 and the database 0644)."""
    home, changed = Path(home), []
    if home.exists() and not owner_only(home):
        private_dir(home)
        changed.append(str(home))
    secret = (".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".key", ".token", ".secret", ".pem")
    for root, dirs, names in os.walk(home):
        for n in names:
            f = Path(root) / n
            if n.endswith(secret) or "backups" in f.parts:
                try:
                    if not f.is_symlink() and not owner_only(f):
                        if POSIX:
                            os.chmod(f, 0o600)
                        else:
                            _inherit_only(f)
                        changed.append(str(f))
                except OSError:
                    pass
    return changed


def seal(p, executable: bool = False):
    """A stored file nobody writes again: read-only (and executable for an agent build) on POSIX; see the module notes
    for Windows."""
    if POSIX:
        os.chmod(p, 0o555 if executable else 0o444)


def venv_python(venv) -> Path:
    """The interpreter inside a virtual environment on this OS."""
    return Path(venv) / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")


def venv_interpreter(venv) -> Path | None:
    """The interpreter a virtual environment runs, None when it does not exist: on POSIX where its `bin/python` symlink
    chain ends; on Windows the base interpreter its pyvenv.cfg names (`Scripts\\python.exe` is a launcher that starts
    that one)."""
    if POSIX:
        py = venv_python(venv)
        return py.resolve() if py.exists() else None
    try:
        cfg = (Path(venv) / "pyvenv.cfg").read_text(encoding="utf-8")
    except OSError:
        return None
    home = next((v.strip() for k, _, v in (line.partition("=") for line in cfg.splitlines()) if k.strip() == "home"), None)
    py = Path(home) / "python.exe" if home else None
    return py.resolve() if py and py.exists() else None


def running_interpreter() -> Path:
    """This process's interpreter as venv_interpreter names it: the base interpreter of a virtual environment."""
    return Path(sys.executable if POSIX else getattr(sys, "_base_executable", sys.executable)).resolve()


def remove_tree(p, within: float = 60.0):
    """Delete a directory tree that must be gone before the next step (a module environment rebuilt in its place).
    Windows refuses to delete an executable, or rename its directory, while the antivirus scanner holds it after it was
    written or run: a tenth of a second on an idle machine, half a minute when every core is busy (Defender, measured on
    a 4-core VM), and nothing to wait on; each refused entry is retried until `within` seconds have passed, then the
    error is raised. POSIX has no such hold."""
    import shutil
    import time
    if not os.path.lexists(p):
        return
    if POSIX:
        return shutil.rmtree(p)
    end = time.monotonic() + within

    def again(fn, path, exc):
        while isinstance(exc, PermissionError) and time.monotonic() < end:
            time.sleep(0.05)
            try:
                return fn(path)
            except PermissionError as e:
                exc = e
        raise exc
    shutil.rmtree(p, onexc=again)
