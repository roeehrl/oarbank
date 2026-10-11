"""The coordinator update runner, as root (docs/design/fleet-updates.md, "The coordinator"; D58).

    python -m oarbank.coordupdate run   [--home P] [--state P] [--programs P] [--probation-s N] [--once]
    python -m oarbank.coordupdate trust (--from-home | --unsigned) [--home P] [--state P]

(A coordinator build runs it as `bin/oarbank-coordupdate`: its compiled core has no code objects for `-m`.)

oarbankd, unprivileged, writes `<home>/updates/coordinator-request.json` (coordself.py). A trigger of root's starts this
runner on it: the launchd job `dev.codonic.oarbank.oarbankd.update` (WatchPaths), the systemd unit
`dev.codonic.oarbank.oarbankd.update.path` (PathExists), or the SYSTEM task `\\Oarbank\\CoordinatorUpdate` (every minute).
The request is data, never trusted: the build is read from `<home>/updates/artifacts/<sha256>` (no path comes from the
request), copied into the runner's own root-only state directory (`<system data>/coordinator-update/`) and the copy is
verified: its sha256 and size, the manifest naming it as the coordinator build for this platform, the owner's
signature against `trust.json` (unless an administrator chose `unsigned`), the seq against the committed one.

Then, each step journaled (fsynced) in `journal.json`: stop both services, copy the database with SQLite's backup API
to `db-<id>.sqlite3` (root's: the coordinator account cannot alter its own restore point), unpack into
`PROGRAMS/<v>-<sha12>` (the layout `install-oarbankd --build` uses), flip `current`, write the services again for it
(`install-oarbankd --refresh`) and start them. Probation: `GET /v1/health` on the agent port must report the new
version, `migrated` and `ticking` within 300 s, and hold for 60 s. Commit keeps the previous programs and the copy for
14 days; a failed probation stops the new version, restores the copy, flips `current` back, starts the old version and
checks its health. Either way `<home>/updates/coordinator-result.json` (the coordinator account's) says how it ended.

A runner that starts with an active journal (a crash, a reboot) rolls back unless it was committing. Every OS action
goes through a `Services` layer, so the tests run the whole thing against a recorder and a local health server.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

from . import paths

FORMAT = 1
PROBATION_S = 300
HOLD_S = 60
KEEP_DAYS = 14
POLL_S = 2.0
REQUEST = "coordinator-request.json"
RESULT = "coordinator-result.json"
LABELS = ("dev.codonic.oarbank.oarbankd", "dev.codonic.oarbank.console")
MANIFEST = "oarbank-coordinator.json"             # coordbuilds.MANIFEST
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]{1,40})?$")     # coordbuilds.VERSION_RE
MAX_REQUEST = 16 * 1024 * 1024
STEPS = ("verified", "stopped", "copied", "installing", "installed", "probation", "committing", "rolling_back")   # journal.active.step


class Refused(Exception):
    pass


class ServiceError(Exception):
    pass


class Crash(BaseException):
    """Tests: the runner dies right after journaling a step."""


def default_programs() -> Path:
    if sys.platform == "darwin":
        return Path("/Library/Oarbank/Coordinator")
    if sys.platform == "win32":
        return Path(os.environ.get("ProgramW6432") or os.environ.get("ProgramFiles") or r"C:\Program Files") / "Oarbank" / "Coordinator"
    return Path("/opt/oarbank/coordinator-builds")


def default_state() -> Path:
    return paths.system_data_root() / "coordinator-update"


def _fsync_dir(d: Path):
    if os.name == "posix":
        fd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
POSIX = os.name == "posix"


class _Dir:
    """A directory held open, never through a link: in the coordinator's home (its account's to change) every name is
    created exclusively, renamed and chowned relative to it, so a planted link or a swapped directory sends none of
    root's writes elsewhere. Plain paths on Windows, where the home is not another account's."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW) if POSIX else None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        if self.fd is not None:
            os.close(self.fd)

    def _kw(self, **kw) -> dict:
        return {"dir_fd": self.fd, **kw} if self.fd is not None else {}

    def _p(self, name: str):
        return name if self.fd is not None else str(self.path / name)

    def create(self, name: str, mode: int = 0o600) -> int:
        """A new file, replacing whatever had that name (a link is removed, never followed)."""
        self.unlink(name)
        return os.open(self._p(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | getattr(os, "O_BINARY", 0), mode,
                       **self._kw())

    def unlink(self, name: str):
        try:
            os.unlink(self._p(name), **self._kw())
        except FileNotFoundError:
            pass

    def replace(self, src: str, dst: str):
        os.replace(self._p(src), self._p(dst), **({"src_dir_fd": self.fd, "dst_dir_fd": self.fd} if self.fd is not None else {}))
        if self.fd is not None:
            os.fsync(self.fd)

    def chown(self, name: str, owner: dict | None):
        """Give a file (never what a link names) to the coordinator's account, as root."""
        if not (owner and POSIX):
            return
        st = os.stat(self._p(name), follow_symlinks=False, **self._kw())
        import stat as S
        if not S.S_ISREG(st.st_mode):
            return
        if os.geteuid() == 0:
            os.chown(self._p(name), owner["uid"], owner["gid"], follow_symlinks=False, **self._kw())

    def write(self, name: str, data: bytes, owner: dict | None = None):
        """Atomically: an exclusive temporary file, fsynced, chowned, renamed over `name`."""
        tmp = f".{name}.tmp"
        fd = self.create(tmp, (owner or {}).get("mode") or 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.chown(tmp, owner)
        self.replace(tmp, name)


def write_atomic(p: Path, data: str, owner: dict | None = None):
    with _Dir(p.parent) as d:
        d.write(p.name, data.encode("utf-8"), owner)


def read_regular(p: Path, limit: int) -> bytes:
    """A regular file's bytes, never through a link, at most `limit` (Refused otherwise): the spool is untrusted."""
    import stat as S
    try:
        fd = os.open(p, os.O_RDONLY | NOFOLLOW | getattr(os, "O_BINARY", 0))
    except OSError as e:
        raise Refused(f"cannot read {p.name}: {e}")
    with os.fdopen(fd, "rb") as f:
        if not S.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused(f"{p.name} is not a regular file")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise Refused(f"{p.name} is larger than {limit} bytes")
    return data


def _owner_of(p: Path) -> dict:
    st = p.stat()
    return {"uid": getattr(st, "st_uid", 0), "gid": getattr(st, "st_gid", 0), "mode": st.st_mode & 0o777}


def _fix_sidecars(db: Path, owner: dict):
    """The WAL and shared-memory files SQLite made beside the database while root read it stay the account's."""
    with _Dir(db.parent) as d:
        for suffix in ("-wal", "-shm"):
            try:
                d.chown(db.name + suffix, owner)
            except FileNotFoundError:
                pass


# ------------------------------------------------------------------ the service layer

class Services:
    """The OS actions on the coordinator's two services. `install(root)` writes their definitions to run the build at
    `root` and starts them."""

    def __init__(self, home: Path, programs: Path):
        self.home, self.programs = Path(home), Path(programs)

    def run(self, argv, check=True, timeout=300, env=None) -> subprocess.CompletedProcess:
        r = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout, env=env)
        if check and r.returncode != 0:
            raise ServiceError(f"{' '.join(map(str, argv))}: exit {r.returncode}: {(r.stderr or r.stdout).strip()[-400:]}")
        return r

    def current_root(self) -> Path | None:
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError

    def install(self, root: Path):
        raise NotImplementedError

    def endpoint(self) -> tuple[str, int]:
        raise NotImplementedError

    def health_url(self) -> str:
        host, port = self.endpoint()
        if host in ("", "0.0.0.0", "::", "[::]"):
            host = "127.0.0.1"
        host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        return f"https://{host}:{port}/v1/health"

    def ssl_context(self) -> ssl.SSLContext | None:
        """The fleet's own CA pins the listener (its certificate names the agent address, not localhost)."""
        ca = self.home / "tls" / "ca.pem"
        if not ca.exists():
            return None
        ctx = ssl.create_default_context(cafile=str(ca))
        ctx.check_hostname = False
        return ctx


class PosixServices(Services):
    """launchd (macOS) or systemd (Linux): the definitions are install-oarbankd.sh's, from its record."""

    def __init__(self, home: Path, programs: Path, record: Path | None = None):
        super().__init__(home, programs)
        self.record = Path(record or paths.service_record())

    def _rec(self) -> dict:
        try:
            return json.loads(self.record.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def current_root(self) -> Path | None:
        r = self._rec().get("root")
        return Path(os.path.realpath(r)) if r and Path(r).exists() else None

    def stop(self):
        if sys.platform == "darwin":
            for label in LABELS:
                self.run(["/bin/launchctl", "bootout", f"system/{label}"], check=False)
            deadline = time.time() + 60
            while time.time() < deadline and any(
                    self.run(["/bin/launchctl", "print", f"system/{label}"], check=False).returncode == 0 for label in LABELS):
                time.sleep(0.5)
        else:
            self.run(["systemctl", "stop", *(f"{label}.service" for label in LABELS)])

    def install(self, root: Path):
        script = Path(root) / "install-oarbankd.sh"
        if not script.is_file():
            raise ServiceError(f"{root} has no install-oarbankd.sh")
        # the runner's own trigger stays loaded: it is this process's job
        self.run(["/bin/bash", script, "--refresh", "--installed", root],
                 env={**os.environ, "OARBANK_COORDUPDATE_RUNNING": "1"}, timeout=600)

    def endpoint(self) -> tuple[str, int]:
        rec = self._rec()
        return rec.get("agent_bind") or "127.0.0.1", int(rec.get("agent_port") or 7443)


class WindowsServices(Services):
    """The service control manager: the services run `PROGRAMS\\current` (a junction), so a flip and a start are the
    whole refresh (install-oarbankd.ps1)."""

    def current_root(self) -> Path | None:
        name = link_name(self.programs / "current", self.programs)
        return None if name is None else self.programs / name if not Path(name).is_absolute() else Path(name)

    def _state(self, name: str) -> str:
        out = self.run(["sc.exe", "query", name], check=False).stdout
        m = re.search(r"STATE\s*:\s*\d+\s+(\w+)", out)
        return m[1] if m else "MISSING"

    def stop(self):
        for name in LABELS:
            if self._state(name) not in ("STOPPED", "MISSING"):
                self.run(["sc.exe", "stop", name], check=False)
        deadline = time.time() + 60
        while time.time() < deadline and any(self._state(n) not in ("STOPPED", "MISSING") for n in LABELS):
            time.sleep(0.5)

    def install(self, root: Path):
        for name in LABELS:
            if self._state(name) != "RUNNING":
                self.run(["sc.exe", "start", name])

    def endpoint(self) -> tuple[str, int]:
        import shlex
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{LABELS[0]}") as k:
            cmd = winreg.QueryValueEx(k, "ImagePath")[0]
        argv = shlex.split(cmd, posix=False)
        val = lambda flag, d: argv[argv.index(flag) + 1].strip('"') if flag in argv and argv.index(flag) + 1 < len(argv) else d
        return val("--agent-bind", "127.0.0.1"), int(val("--agent-port", "7443"))


def services(home: Path, programs: Path) -> Services:
    return WindowsServices(home, programs) if sys.platform == "win32" else PosixServices(home, programs)


# ------------------------------------------------------------------ the journal and the lock

class Journal:
    def __init__(self, path: Path):
        self.path = path
        try:
            self.doc = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self.doc = {"format": FORMAT, "committed_seq": 0, "committed_version": None, "active": None, "finished": []}

    @property
    def active(self) -> dict | None:
        return self.doc.get("active")

    def step(self, step: str, **kw):
        self.doc["active"].update(step=step, at=time.time(), **kw)
        self.save()

    def save(self):
        write_atomic(self.path, json.dumps(self.doc, indent=1, sort_keys=True))


class Lock:
    """One runner at a time (the Windows task fires every minute, a probation lasts longer)."""

    def __init__(self, path: Path):
        self.path, self.f = path, None

    def __enter__(self):
        self.f = open(self.path, "a+")
        try:
            if os.name == "posix":
                import fcntl
                fcntl.flock(self.f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.f.close()
            self.f = None
        return self.f is not None

    def __exit__(self, *a):
        if self.f:
            self.f.close()


# ------------------------------------------------------------------ the runner

def fetch_health(url: str, ctx: ssl.SSLContext | None, timeout: float = 5) -> dict:
    handlers = [urllib.request.ProxyHandler({})]                   # never through a proxy: this machine's own listener
    if ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    with urllib.request.build_opener(*handlers).open(url, timeout=timeout) as r:
        return json.loads(r.read(65536))


class Runner:
    def __init__(self, home: Path, state: Path, programs: Path, svc: Services | None = None, probation_s: float = PROBATION_S,
                 hold_s: float = HOLD_S, poll_s: float = POLL_S, platform: str | None = None, crash_at: str | None = None,
                 log=None):
        self.home, self.state, self.programs = Path(home), Path(state), Path(programs)
        self.svc = svc or services(self.home, self.programs)
        self.probation_s, self.hold_s, self.poll_s = probation_s, hold_s, poll_s
        if platform is None:
            from oarbank_sdk import portable
            platform = portable.host_platform()
        self.platform, self.crash_at, self._log = platform, crash_at, log

    # -- plumbing
    @property
    def spool(self) -> Path:
        return self.home / "updates"

    def log(self, msg: str):
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}"
        if self._log:
            self._log(line)
        else:
            print(line, flush=True)
        try:
            d = self.state / "logs"
            d.mkdir(exist_ok=True)
            with open(d / "coordupdate.log", "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def _crash(self, step: str):
        if self.crash_at == step:
            raise Crash(step)

    def _ensure_state(self):
        if not self.state.exists():
            from .platform import files
            files.private_dir(self.state)
        elif os.name == "posix":
            os.chmod(self.state, 0o700)

    def trust(self) -> dict | None:
        try:
            t = json.loads((self.state / "trust.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return t if isinstance(t, dict) and t.get("format") == 1 and t.get("mode") in ("signed", "unsigned") else None

    def result(self, uid: str | None, version: str | None, state: str, error: str | None):
        """`<home>/updates/coordinator-result.json`, the coordinator account's (it reads and removes it)."""
        if not self.spool.is_dir() or self.spool.is_symlink():
            self.log(f"no spool {self.spool}: result {state} not written")
            return
        doc = {"id": uid, "version": version, "state": state, "error": error, "at": time.time()}
        try:
            with _Dir(self.spool) as d:
                d.write(RESULT, json.dumps(doc).encode("utf-8"), _owner_of(self.spool) | {"mode": 0o600})
        except OSError as e:
            self.log(f"{uid}: writing the result: {e}")
        self.log(f"{uid}: {state}{': ' + error if error else ''}")

    # -- entry points
    def once(self) -> str | None:
        """Handle an active journal or one request, if any. Returns what happened (None: nothing to do)."""
        self._ensure_state()
        with Lock(self.state / "lock") as got:
            if not got:
                return "busy"
            j = Journal(self.state / "journal.json")
            if j.active:
                return self.recover(j)
            req = self.spool / REQUEST
            if not os.path.lexists(req):
                return None
            return self.take(j, req)

    def watch(self, interval: float = 1.0):
        while True:
            self.once()
            time.sleep(interval)

    # -- taking a request
    def parse(self, req: Path) -> dict:
        try:
            r = json.loads(read_regular(req, MAX_REQUEST).decode("utf-8"))
        except (OSError, ValueError) as e:
            raise Refused(f"the request does not parse: {e}")
        if not isinstance(r, dict):
            raise Refused("the request is not an object")
        bad = [k for k, ok in (("id", isinstance(r.get("id"), str) and ID_RE.match(r["id"])),
                               ("version", isinstance(r.get("version"), str) and VERSION_RE.match(r["version"])),
                               ("sha256", isinstance(r.get("sha256"), str) and SHA_RE.match(r["sha256"])),
                               ("size", isinstance(r.get("size"), int) and r["size"] > 0),
                               ("manifest", isinstance(r.get("manifest"), str)),
                               ("signature", r.get("signature") is None or isinstance(r.get("signature"), dict))) if not ok]
        if bad:
            raise Refused(f"the request's {', '.join(bad)} {'is' if len(bad) == 1 else 'are'} invalid")
        return r

    def take(self, j: Journal, req: Path) -> str:
        try:
            r = self.parse(req)
        except Refused as e:
            uid = None
            try:
                uid = json.loads(read_regular(req, MAX_REQUEST).decode("utf-8")).get("id")
                uid = uid if isinstance(uid, str) and ID_RE.match(uid) else None
            except (Refused, OSError, ValueError, AttributeError):
                pass
            req.unlink(missing_ok=True)
            self.result(uid, None, "refused", str(e))
            return "refused"
        if r["id"] in j.doc.get("finished", []):
            req.unlink(missing_ok=True)
            self.log(f"{r['id']}: already handled; request ignored")
            return "ignored"
        try:
            copy, seq, prev_version = self.verify(r, j)
        except (Refused, OSError) as e:
            req.unlink(missing_ok=True)
            self._finished(j, r["id"])
            j.save()
            self.result(r["id"], r["version"], "refused", str(e))
            return "refused"
        cur = self.programs / "current"
        prev_root = self.svc.current_root()
        j.doc["active"] = {"id": r["id"], "version": r["version"], "seq": seq, "sha256": r["sha256"], "archive": str(copy),
                           "from_version": prev_version or (r.get("from_version") if isinstance(r.get("from_version"), str) else None),
                           "previous_root": str(prev_root) if prev_root else None,
                           "previous_current": link_name(cur, self.programs),
                           "started_at": time.time(), "step": "verified"}
        j.save()
        req.unlink(missing_ok=True)                    # journaled first: a crash from here on resumes from the journal
        self.log(f"{r['id']}: {prev_version} -> {r['version']} verified")
        self._crash("verified")
        return self.proceed(j)

    def verify(self, r: dict, j: Journal) -> tuple[Path, int, str | None]:
        trust = self.trust()
        if not trust:
            raise Refused(f"no update trust on this machine: run `coordupdate trust --from-home` as an administrator "
                          f"({self.state / 'trust.json'})")
        try:
            m = json.loads(r["manifest"])
        except ValueError:
            raise Refused("the manifest does not parse")
        if not isinstance(m, dict) or m.get("type") != "oarbank-fleet-release" or m.get("version") != r["version"] \
                or not isinstance(m.get("seq"), int):
            raise Refused("the manifest is not a fleet release of this version")
        exp = m.get("expires")
        if exp:
            from datetime import datetime
            try:
                t = float(exp) if isinstance(exp, (int, float)) else datetime.fromisoformat(str(exp).replace("Z", "+00:00")).timestamp()
            except ValueError:
                raise Refused("the manifest's expiry does not parse")
            if t < time.time():
                raise Refused(f"the release expired at {exp}")
        art = next((a for a in m.get("artifacts") or [] if isinstance(a, dict) and a.get("role") == "coordinator"
                    and a.get("platform") == self.platform and a.get("sha256") == r["sha256"]), None)
        if not art or art.get("size") != r["size"]:
            raise Refused(f"the manifest names no coordinator build {r['sha256'][:12]} of this size for {self.platform}")
        if trust["mode"] == "signed":
            from . import fleetsig
            try:
                s = fleetsig.verify(r.get("signature"), trust.get("owner_keys") or [], r["manifest"])
            except (ValueError, TypeError) as e:
                raise Refused(f"owner signature: {e}")
            if s["version"] != m["version"] or s["seq"] != m["seq"]:
                raise Refused("the owner signature names another version or seq")
        if m["seq"] < int(j.doc.get("committed_seq") or 0):
            raise Refused(f"seq {m['seq']} is below the committed {j.doc['committed_seq']}")
        src = self.spool / "artifacts" / r["sha256"]
        import stat as S
        try:
            fd = os.open(src, os.O_RDONLY | NOFOLLOW | getattr(os, "O_BINARY", 0))
        except OSError as e:
            raise Refused(f"no build at {src}: {e}")
        inc = self.state / "incoming"
        inc.mkdir(exist_ok=True)
        part, copy = inc / f".{r['sha256']}.part", inc / f"{r['sha256']}.tar.gz"
        h, n = hashlib.sha256(), 0
        with os.fdopen(fd, "rb") as f, open(part, "wb") as out:      # the copy is what is verified and installed
            if not S.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise Refused(f"{src} is not a regular file")
            for chunk in iter(lambda: f.read(min(1 << 20, r["size"] + 1 - n)), b""):
                h.update(chunk)
                n += len(chunk)
                out.write(chunk)
                if n > r["size"]:
                    break
            out.flush()
            os.fsync(out.fileno())
        if n != r["size"] or h.hexdigest() != r["sha256"]:
            part.unlink(missing_ok=True)
            raise Refused("the build does not match its sha256 and size")
        try:
            with tarfile.open(part, "r:gz") as t:
                mem = t.getmember(MANIFEST)
                if not mem.isfile() or mem.size > 64 * 1024:
                    raise ValueError(f"{MANIFEST} is not a small file")
                doc = json.loads(t.extractfile(mem).read())
        except (tarfile.TarError, KeyError, OSError, ValueError, EOFError) as e:
            part.unlink(missing_ok=True)
            raise Refused(f"not a coordinator build: {e}")
        if doc.get("format") != 1 or doc.get("version") != r["version"] or doc.get("platform") != self.platform:
            part.unlink(missing_ok=True)
            raise Refused(f"the build says {doc.get('version')} for {doc.get('platform')}, not {r['version']} for {self.platform}")
        os.replace(part, copy)
        return copy, m["seq"], self._version_of(self.svc.current_root())

    @staticmethod
    def _version_of(root: Path | None) -> str | None:
        try:
            return json.loads((Path(root) / MANIFEST).read_text(encoding="utf-8")).get("version") if root else None
        except (OSError, ValueError):
            return None

    # -- the swap
    def proceed(self, j: Journal) -> str:
        a = j.active
        try:
            self.svc.stop()
            j.step("stopped")
            self._crash("stopped")
            db = self.home / "oarbank.sqlite3"
            copy = self.state / f"db-{a['id']}.sqlite3"
            if db.exists():
                owner = _owner_of(db)
                self.backup(db, copy)
                _fix_sidecars(db, owner)
                j.step("copied", db_copy=str(copy), db_owner=owner)
            else:
                j.step("copied", db_copy=None)
            self._crash("copied")
            j.step("installing")
            app = self.unpack(Path(a["archive"]), a["version"], a["sha256"])
            j.step("installing", app=str(app))
            self.flip(app)
            self.svc.install(app)
            j.step("installed")
            self._crash("installed")
            j.step("probation", deadline=time.time() + self.probation_s)
            self._crash("probation")
            ok, why = self.probation(a["version"])
        except Exception as e:                       # noqa: BLE001 - any failure of the swap rolls it back
            ok, why = False, f"{type(e).__name__}: {e}"
        if ok:
            return self.commit(j)
        return self.rollback(j, why)

    def backup(self, db: Path, dest: Path):
        tmp = dest.with_name(dest.name + ".part")
        tmp.unlink(missing_ok=True)
        src = sqlite3.connect(str(db), timeout=30)
        try:
            out = sqlite3.connect(str(tmp))
            try:
                src.backup(out)
            finally:
                out.close()
        finally:
            src.close()
        with open(tmp, "rb") as f:
            os.fsync(f.fileno())
        os.replace(tmp, dest)
        if os.name == "posix":
            os.chmod(dest, 0o600)

    def unpack(self, archive: Path, version: str, sha: str) -> Path:
        """PROGRAMS/<v>-<sha12>, root's and not writable by others (install-oarbankd.sh --build)."""
        app = self.programs / f"{version}-{sha[:12]}"
        if (app / MANIFEST).is_file():
            return app
        self.programs.mkdir(parents=True, exist_ok=True)
        tmp = self.programs / f".{app.name}.unpack"
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir()
        with tarfile.open(archive, "r:gz") as t:
            t.extractall(tmp, filter="data")
        if os.name == "posix":
            for d, dirs, fs in os.walk(tmp):
                for name in [*dirs, *fs]:
                    p = os.path.join(d, name)
                    if not os.path.islink(p):
                        os.chmod(p, os.stat(p).st_mode & ~0o022)
            os.chmod(tmp, 0o755)
        shutil.rmtree(app, ignore_errors=True)
        os.replace(tmp, app)
        return app

    def flip(self, target: str | Path | None):
        """Point PROGRAMS/current at `target` (a sibling by name, else an absolute path); None removes it."""
        cur = self.programs / "current"
        if target is not None:
            target = Path(target)
            if target.parent == self.programs:
                target = Path(target.name)
        if sys.platform == "win32":
            if cur.exists() or _is_junction(cur):
                os.rmdir(cur) if _is_junction(cur) else os.unlink(cur)
            if target is not None:
                import _winapi
                _winapi.CreateJunction(str(self.programs / target if not target.is_absolute() else target), str(cur))
            return
        if target is None:
            if cur.is_symlink():
                cur.unlink()
            return
        tmp = self.programs / ".current.flip"
        tmp.unlink(missing_ok=True)
        os.symlink(str(target), tmp)
        os.replace(tmp, cur)
        _fsync_dir(self.programs)

    def healthy(self, version: str | None) -> tuple[bool, str]:
        try:
            h = fetch_health(self.svc.health_url(), self.svc.ssl_context())
        except Exception as e:                       # noqa: BLE001 - not answering is the answer
            return False, f"no answer ({type(e).__name__}: {e})"[:300]
        if not isinstance(h, dict):
            return False, "the health answer is not an object"
        if version and h.get("version") != version:
            return False, f"version {h.get('version')}, not {version}"
        if h.get("migrated") is not True:
            return False, "migrations not done"
        if h.get("ticking") is not True:
            return False, "the background tick is not running"
        return True, "healthy"

    def probation(self, version: str | None) -> tuple[bool, str | None]:
        """Healthy within probation_s, then for hold_s without a break."""
        deadline = time.time() + self.probation_s
        good_since, last = None, "no answer"
        while True:
            ok, last = self.healthy(version)
            t = time.time()
            if ok:
                good_since = good_since or t
                if t - good_since >= self.hold_s:
                    return True, None
            else:
                good_since = None
                if t >= deadline:
                    return False, f"probation: {last} after {self.probation_s:.0f} s"
            time.sleep(self.poll_s)

    def commit(self, j: Journal) -> str:
        a = j.active
        j.step("committing")
        self._crash("committing")
        j.doc["committed_seq"] = max(int(j.doc.get("committed_seq") or 0), int(a["seq"]))
        j.doc["committed_version"] = a["version"]
        Path(a["archive"]).unlink(missing_ok=True)
        self.prune(keep={a.get("app"), a.get("previous_root")}, keep_db=a.get("db_copy"))
        self.result(a["id"], a["version"], "done", None)
        self._end(j, "done")
        return "done"

    def rollback(self, j: Journal, why: str) -> str:
        a = j.active
        copied = bool(a.get("db_copy"))                 # set once the copy is complete (the step "copied")
        j.step("rolling_back", why=a.get("why") or why)
        why = a["why"]
        self.log(f"{a['id']}: rolling back: {why}")
        errors = []
        try:
            self.svc.stop()
        except (ServiceError, OSError, subprocess.SubprocessError) as e:
            errors.append(f"stop: {e}")
        if copied and a.get("db_copy") and Path(a["db_copy"]).is_file():
            try:
                self.restore(Path(a["db_copy"]), a.get("db_owner"))
            except OSError as e:
                errors.append(f"restoring the database: {e}")
        try:
            self.flip(a.get("previous_current"))
        except OSError as e:
            errors.append(f"flipping current back: {e}")
        prev = a.get("previous_root")
        if prev:
            try:
                self.svc.install(Path(prev))
            except (ServiceError, OSError, subprocess.SubprocessError) as e:
                errors.append(f"starting the previous version: {e}")
            ok, h = self.healthy_within(a.get("from_version"))
            if not ok:
                errors.append(f"the previous version is not healthy: {h}")
        else:
            errors.append("no previous programs recorded: start the coordinator by hand")
        Path(a["archive"]).unlink(missing_ok=True)
        self.result(a["id"], a["version"], "rolled_back", why + ("; " + "; ".join(errors) if errors else ""))
        self._end(j, "rolled_back")
        return "rolled_back"

    def healthy_within(self, version: str | None) -> tuple[bool, str]:
        deadline = time.time() + self.probation_s
        while True:
            ok, h = self.healthy(version)
            if ok or time.time() >= deadline:
                return ok, h
            time.sleep(self.poll_s)

    def restore(self, copy: Path, owner: dict | None):
        """The root copy over oarbank.sqlite3, its WAL and shared memory removed, the account's again."""
        with _Dir(self.home) as d:
            tmp = ".oarbank.sqlite3.restore"
            fd = d.create(tmp, (owner or {}).get("mode") or 0o600)
            try:
                with open(copy, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        os.write(fd, chunk)
                os.fsync(fd)
            finally:
                os.close(fd)
            d.chown(tmp, owner)
            for suffix in ("-wal", "-shm"):
                d.unlink("oarbank.sqlite3" + suffix)
            d.replace(tmp, "oarbank.sqlite3")

    def recover(self, j: Journal) -> str:
        a = j.active
        self.log(f"{a['id']}: resuming at {a.get('step')}")
        if a.get("step") == "committing":
            return self.commit(j)
        return self.rollback(j, f"the update runner stopped during {a.get('step')} (a crash or a reboot)")

    def prune(self, keep: set, keep_db: str | None):
        cutoff = time.time() - KEEP_DAYS * 86400
        keep = {os.path.realpath(k) for k in keep if k}
        cur = self.programs / "current"
        if cur.exists():
            keep.add(os.path.realpath(cur))
        for d in self.programs.iterdir() if self.programs.is_dir() else []:
            if d.name == "current" or d.is_symlink() or not d.is_dir() or os.path.realpath(d) in keep:
                continue
            if re.match(r"^[0-9]+\.[0-9]+\.[0-9]+.*-[0-9a-f]{12}$", d.name) and d.stat().st_mtime < cutoff:
                shutil.rmtree(d, ignore_errors=True)
        for f in self.state.glob("db-*.sqlite3"):
            if str(f) != keep_db and f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)

    def _finished(self, j: Journal, uid: str):
        j.doc["finished"] = (j.doc.get("finished") or [])[-49:] + [uid]

    def _end(self, j: Journal, how: str):
        a = j.active
        self._finished(j, a["id"])
        j.doc.setdefault("history", [])
        j.doc["history"] = j.doc["history"][-19:] + [{"id": a["id"], "version": a["version"], "from_version": a.get("from_version"),
                                                       "state": how, "why": a.get("why"), "at": time.time()}]
        j.doc["active"] = None
        j.save()


def link_name(cur: Path, programs: Path) -> str | None:
    """Where PROGRAMS/current points, as the flip wrote it: a sibling build by its name, else the absolute path. A
    Windows junction holds an absolute target that os.readlink returns in its `\\\\?\\` form; a POSIX symlink holds the
    name. None when it is no link."""
    try:
        t = os.readlink(cur)
    except OSError:
        return None
    for prefix in ("\\\\?\\", "\\??\\"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    p = Path(t)
    if p.is_absolute():
        try:
            if os.path.normcase(os.path.realpath(p.parent)) == os.path.normcase(os.path.realpath(programs)):
                return p.name
        except OSError:
            pass
        return str(p)
    return t


def _is_junction(p: Path) -> bool:
    try:
        return bool(getattr(p, "is_junction", lambda: False)())
    except OSError:
        return False


# ------------------------------------------------------------------ trust

def read_anchors(home: Path) -> dict:
    """The owner anchors the coordinator pinned (owner.py): the anchor set, else the pinned release key."""
    db = Path(home) / "oarbank.sqlite3"
    if not db.is_file():
        raise SystemExit(f"coordupdate: no coordinator database at {db}")
    owner = _owner_of(db)
    c = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=30)
    try:
        state = {k: json.loads(v) for k, v in c.execute(
            "SELECT key, value_json FROM system_state WHERE key IN ('owner_anchors','release_pubkey','fleet_id')")}
    finally:
        c.close()
        _fix_sidecars(db, owner)
    a = state.get("owner_anchors")
    if a:
        doc = json.loads(a["statement"])
        return {"fleet_id": doc.get("fleet_id") or state.get("fleet_id"), "owner_version": int(doc.get("version") or 0),
                "owner_keys": list(doc.get("keys") or [])}
    if state.get("release_pubkey"):
        return {"fleet_id": state.get("fleet_id"), "owner_version": 0, "owner_keys": [state["release_pubkey"]]}
    raise SystemExit("coordupdate: the coordinator has no owner keys yet (oarbank release keygen and pin, or the owner key "
                     "set); pin them later, or choose --unsigned for a test fleet")


def pin_trust(state: Path, home: Path, unsigned: bool, by: str) -> dict | None:
    """Write trust.json: from the home's owner anchors only when none exists; `unsigned` always (an explicit choice)."""
    from .platform import files
    if not state.exists():
        files.private_dir(state)
    p = state / "trust.json"
    if p.exists() and not unsigned:
        return None
    if unsigned:
        doc = {"format": 1, "mode": "unsigned", "fleet_id": None, "owner_version": None, "owner_keys": []}
    else:
        doc = {"format": 1, "mode": "signed", **read_anchors(home)}
    doc.update(pinned_at=time.time(), pinned_by=by)
    write_atomic(p, json.dumps(doc, indent=1, sort_keys=True))
    return doc


# ------------------------------------------------------------------ CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="coordupdate", description="The coordinator's root update runner (fleet-updates.md, D58)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="take the coordinator's update request and install it, or resume an interrupted one")
    trust = sub.add_parser("trust", help="pin what the runner trusts (root's trust.json)")
    for p in (run, trust):
        p.add_argument("--home", type=Path, default=paths.coordinator_home(), help="the coordinator's home")
        p.add_argument("--state", type=Path, default=default_state(), help="the runner's root-only state directory")
    run.add_argument("--programs", type=Path, default=default_programs(), help="where builds are unpacked beside each other")
    run.add_argument("--probation-s", type=float, default=PROBATION_S)
    run.add_argument("--once", action="store_true", help="handle at most one request and exit (the triggers)")
    g = trust.add_mutually_exclusive_group(required=True)
    g.add_argument("--from-home", action="store_true", help="the owner anchors the coordinator pinned, if no trust exists")
    g.add_argument("--unsigned", action="store_true", help="accept unsigned releases (a test fleet; an explicit choice)")
    a = ap.parse_args(argv)
    if a.cmd == "trust":
        doc = pin_trust(a.state, a.home, a.unsigned, "coordupdate trust " + ("--unsigned" if a.unsigned else "--from-home"))
        if doc is None:
            print(f"coordupdate: {a.state / 'trust.json'} exists; left as it is")
        else:
            print(f"coordupdate: trust pinned ({doc['mode']}, {len(doc['owner_keys'])} owner keys)")
        return 0
    r = Runner(a.home, a.state, a.programs, probation_s=a.probation_s)
    if a.once:
        r.once()
    else:
        r.watch()
    return 0


if __name__ == "__main__":
    sys.exit(main())
