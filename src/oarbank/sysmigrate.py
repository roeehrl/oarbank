"""Move a per-user coordinator (an earlier release's LaunchAgents or systemd user units) to the system service
(docs/design/coordinator-system-service.md, "Migration from the per-user form").

Two halves:
- `export_keys(old_home)`, as the person, in their session (macOS only): the audit, module-secrets and transport keys
  from their login Keychain into the old home's file store, the format the system service reads. Linux kept its keys
  in that file store already.
- `Migration(...).run()`, as root: preflight (the keys are there and match the database), stop the per-user
  services, clone the old home into the system home, install and start the system services, verify them, then retire
  the per-user services and rename the old home. Any failure after the stop rolls back: the new services go, the new
  home is set aside, the per-user services start again on the untouched old home. Each step is journaled in the
  migration record (root-owned, readable by all, no secrets), which the app, the console and `oarbank coordinator
  status` read.

Every system path comes from a `Layout` and every OS action goes through `Ops`, so the tests run the whole thing on a
copy of a real home with recorded service-manager calls.
"""
import base64
import json
import os
import plistlib
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import paths
from .platform import files, secrets

LABELS = ("dev.codonic.oarbank.oarbankd", "dev.codonic.oarbank.console")
AUDIT_KEY = "oarbank-audit-key"            # coordinator/audit.py KEYCHAIN_SERVICE
MODULE_KEY = "module-secrets"              # coordinator/modsecrets.py KEY_NAME
TRANSPORT_KEY = "move-transport"           # coordinator/modsecrets.py TRANSPORT_NAME
KEY_NAMES = (AUDIT_KEY, MODULE_KEY, TRANSPORT_KEY)
# per-process files a copy must not carry (the new services make their own), and the wizard's, which are the person's
TRANSIENT = ("run", "console.secret", "setup.lock", "setup.active.json")
VERIFY_S = 120.0


class MigrationError(Exception):
    pass


class NeedsPerson(MigrationError):
    """The keys are in the person's login Keychain and only their session can export them."""


# ------------------------------------------------------------------------------------------------- where things are

@dataclass
class Layout:
    """The system paths a migration touches (the tests point them into a scratch directory)."""
    os: str = sys.platform                                      # "darwin" or "linux"
    system_data: Path = field(default_factory=paths.system_data_root)
    new_home: Path = field(default_factory=paths.coordinator_home)
    record: Path | None = None                                  # default <system data>/coordinator-migration.json

    def __post_init__(self):
        self.system_data, self.new_home = Path(self.system_data), Path(self.new_home)
        self.record = Path(self.record) if self.record else self.system_data / "coordinator-migration.json"

    def old_default_home(self, home: Path) -> Path:
        if self.os == "darwin":
            return home / "Library/Application Support/Oarbank/coordinator"
        return home / ".local/share/oarbank/coordinator"

    def setup_dir(self, home: Path) -> Path:
        """A person's setup journal (paths.setup_dir, for another account)."""
        if self.os == "darwin":
            return home / "Library/Application Support/Oarbank/setup"
        return home / ".local/share/oarbank/setup"


@dataclass
class Install:
    """A per-user coordinator: whose, its service definitions, its home and how oarbankd was started."""
    user: str
    uid: int
    gid: int
    person_home: Path
    definitions: list[Path]
    old_home: Path
    program: str
    agent_bind: str
    agent_port: str | None = None
    url: str | None = None
    signing: str = "1"
    standby: bool = False
    keychain_pinned: bool = False

    def summary(self) -> dict:
        return {"user": self.user, "uid": self.uid, "old_home": str(self.old_home), "agent_bind": self.agent_bind,
                "definitions": [str(p) for p in self.definitions], "program": self.program}


def accounts(layout: Layout) -> list[tuple[str, int, int, Path]]:
    """(name, uid, gid, home) of the people on this machine: macOS's local accounts (uid ≥ 500), Linux's NSS accounts."""
    out = []
    if layout.os == "darwin":
        r = subprocess.run(["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) >= 500:
                import pwd
                try:
                    pw = pwd.getpwnam(parts[0])
                except KeyError:
                    continue
                out.append((pw.pw_name, pw.pw_uid, pw.pw_gid, Path(pw.pw_dir)))
        return out
    import pwd
    return [(p.pw_name, p.pw_uid, p.pw_gid, Path(p.pw_dir)) for p in pwd.getpwall() if p.pw_dir.startswith("/")]


def _args(argv: list[str]) -> dict:
    out = {"standby": "--standby" in argv}
    for flag, key in (("--agent-bind", "agent_bind"), ("--agent-port", "agent_port"), ("--url", "url")):
        if flag in argv and argv.index(flag) + 1 < len(argv):
            out[key] = argv[argv.index(flag) + 1]
    return out


def _from_plist(layout: Layout, user, uid, gid, home: Path) -> Install | None:
    la = home / "Library/LaunchAgents"
    main = la / f"{LABELS[0]}.plist"
    if not main.is_file():
        return None
    doc = plistlib.loads(main.read_bytes())
    argv = [str(a) for a in doc.get("ProgramArguments") or []]
    env = doc.get("EnvironmentVariables") or {}
    a = _args(argv)
    if not argv or not a.get("agent_bind"):
        raise MigrationError(f"{main}: no --agent-bind in ProgramArguments")
    defs = [p for p in (la / f"{label}.plist" for label in LABELS) if p.exists()]
    return Install(user, uid, gid, home, defs, Path(env.get("OARBANKD_HOME") or layout.old_default_home(home)), argv[0],
                   a["agent_bind"], a.get("agent_port"), a.get("url"), str(env.get("OARBANK_RELEASE_SIGNING", "1")),
                   a["standby"], env.get("OARBANK_SECRET_STORE") == "keychain")


def _unit_dirs(home: Path) -> list[Path]:
    dirs = [home / ".config/systemd/user", home / ".local/share/systemd/user"]
    reg = home / ".local/share/oarbank/coordinator-package.json"
    try:
        d = json.loads(reg.read_text()).get("unit_dir")
        if isinstance(d, str) and d.startswith("/"):
            dirs.insert(0, Path(d))
    except (OSError, ValueError):
        pass
    return dirs


def parse_unit(text: str) -> tuple[list[str], dict]:
    """ExecStart's argv and the Environment= assignments of a systemd unit (systemd's double-quote rules)."""
    argv, env = [], {}
    for line in text.replace("\\\n", " ").splitlines():
        k, _, v = line.partition("=")
        if k.strip() == "ExecStart":
            argv = shlex.split(v.replace("%%", "%"))
        elif k.strip() == "Environment":
            for item in shlex.split(v):
                ek, _, ev = item.partition("=")
                env[ek] = ev
    return argv, env


def _from_units(layout: Layout, user, uid, gid, home: Path) -> Install | None:
    for d in _unit_dirs(home):
        main = d / f"{LABELS[0]}.service"
        if main.is_file():
            argv, env = parse_unit(main.read_text())
            a = _args(argv)
            if not argv or not a.get("agent_bind"):
                raise MigrationError(f"{main}: no --agent-bind in ExecStart")
            defs = [p for p in (d / f"{label}.service" for label in LABELS) if p.exists()]
            return Install(user, uid, gid, home, defs, Path(env.get("OARBANKD_HOME") or layout.old_default_home(home)),
                           argv[0], a["agent_bind"], a.get("agent_port"), a.get("url"),
                           env.get("OARBANK_RELEASE_SIGNING", "1"), a["standby"])
    return None


def find_installs(layout: Layout, people=None) -> list[Install]:
    """Every per-user coordinator on this machine (`people`: (name, uid, gid, home) tuples, default accounts())."""
    found = []
    for user, uid, gid, home in people if people is not None else accounts(layout):
        try:
            inst = (_from_plist if layout.os == "darwin" else _from_units)(layout, user, uid, gid, Path(home))
        except PermissionError:
            continue
        if inst:
            found.append(inst)
    return found


# ------------------------------------------------------------------------------------------------- the key export

def export_keys(old_home: Path, keychain: str | None = None) -> list[str]:
    """As the person: each coordinator key their login Keychain holds, into `old_home`'s file store (0600). Idempotent;
    a file that already holds other bytes stops it. Returns the names exported or already in place."""
    old_home = Path(old_home)
    if not (old_home / "oarbank.sqlite3").exists():
        raise MigrationError(f"{old_home} holds no coordinator")
    done = []
    for name in KEY_NAMES:
        raw = secrets.read_keychain(name, keychain)
        if raw is None:
            continue
        have = secrets.read_file_secret(name, old_home)
        if have is not None and have != raw:
            raise MigrationError(f"{secrets.file_path(name, old_home)} holds another key than the Keychain's {name}: "
                                 "this coordinator already made a new key; keep the file that matches its database")
        if have is None:
            secrets.write_file_secret(name, old_home, raw)
        done.append(name)
    return done


def check_keys(old_home: Path) -> list[str]:
    """The keys in `old_home`'s file store match its database: the audit key's public key is the one the audit chain
    names, and the module-secrets key opens the stored secrets. Returns what was checked; raises NeedsPerson when a key
    the database needs is missing, MigrationError when one does not match."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from .coordinator import modsecrets
    # read-write, not read-only: a read-only connection cannot rebuild a WAL index a stopped or copied coordinator left
    # behind, and would read the database without its WAL (SQLite gives files it creates as root the database's owner)
    con = sqlite3.connect(f"file:{old_home / 'oarbank.sqlite3'}?mode=rw", uri=True)
    con.row_factory = sqlite3.Row
    try:
        state = _state(con, ("audit_pubkey", "fleet_id"))
        rows = [dict(r) for r in con.execute("SELECT * FROM secrets WHERE sealed=0")] if con.execute(
            "SELECT 1 FROM sqlite_master WHERE name='secrets'").fetchone() else []
    finally:
        con.close()
    checked = []
    pub = state.get("audit_pubkey")
    if pub:
        raw = secrets.read_file_secret(AUDIT_KEY, old_home)
        if raw is None:
            raise NeedsPerson(f"the audit key ({AUDIT_KEY}) is not in {old_home}/keys: export it first")
        mine = base64.b64encode(Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        if mine != pub:
            raise MigrationError("the audit key in the file store is not the one the audit chain names")
        checked.append(AUDIT_KEY)
    if rows:
        key = secrets.read_file_secret(MODULE_KEY, old_home)
        if key is None:
            raise NeedsPerson(f"the module secrets key ({MODULE_KEY}) is not in {old_home}/keys: export it first")
        opened = 0
        for r in rows:
            try:
                modsecrets._decrypt(key, r["module"], r["name"], r["node_id"], bytes(r["ciphertext"]))
                opened += 1
            except Exception:                                    # noqa: BLE001 (InvalidTag: another key)
                pass
        if not opened:
            raise MigrationError("the module secrets key in the file store opens none of the stored secrets")
        checked.append(f"{MODULE_KEY} ({opened}/{len(rows)} secrets open)")
    return checked


def _state(con, keys) -> dict:
    """Machine state from a coordinator database of this release (`system_state`) or of an earlier one, whose schema the
    new oarbankd upgrades when it opens it (`settings`, coordinator/settings/migrate.py)."""
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    table = "system_state" if "system_state" in tables else "settings"
    marks = ",".join("?" * len(keys))
    return {k: json.loads(v) for k, v in con.execute(f"SELECT key, value_json FROM {table} WHERE key IN ({marks})", tuple(keys))}


def fleet_of(home: Path) -> str | None:
    con = sqlite3.connect(f"file:{Path(home) / 'oarbank.sqlite3'}?mode=rw", uri=True)
    try:
        return _state(con, ("fleet_id",)).get("fleet_id")
    finally:
        con.close()


# ------------------------------------------------------------------------------------------------- the record

def read_record(layout: Layout | None = None) -> dict | None:
    p = (layout or Layout()).record
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


class Record:
    def __init__(self, layout: Layout, install: Install | None):
        self.path = layout.record
        prev = read_record(layout) or {}
        self.doc = {"format": 1, "state": "started", "started_at": time.time(), "steps": [],
                    **({"install": install.summary()} if install else {})}
        self.previous = prev

    def step(self, name: str, detail: str = "", state: str | None = None, **extra):
        self.doc["steps"].append({"at": time.time(), "step": name, "detail": detail})
        if state:
            self.doc["state"] = state
        self.doc.update(extra, updated_at=time.time())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}")
        tmp.write_text(json.dumps(self.doc, indent=1), encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.path)
        print(f"oarbank migrate: {name}" + (f": {detail}" if detail else ""), flush=True)


# ------------------------------------------------------------------------------------------------- what the OS does

class Ops:
    """The OS actions of a migration, as root. Tests replace it with a recorder."""

    def __init__(self, layout: Layout, build: Path):
        self.layout, self.build = layout, Path(build)

    def run(self, argv, timeout=120, check=True, **kw):
        r = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout, **kw)
        if check and r.returncode != 0:
            raise MigrationError(f"{' '.join(map(str, argv))}: {(r.stderr or r.stdout).strip()[-400:]}")
        return r

    # the person's services
    def _session(self, inst: Install) -> bool:
        if self.layout.os == "darwin":
            return self.run(["/bin/launchctl", "print", f"gui/{inst.uid}"], check=False).returncode == 0
        return Path(f"/run/user/{inst.uid}/systemd/private").exists()

    def _systemctl_user(self, inst: Install, *args, check=True):
        return self.run(["systemctl", "--user", f"--machine={inst.user}@.host", *args], check=check)

    def user_pid(self, inst: Install) -> int | None:
        if self.layout.os == "darwin":
            r = self.run(["/bin/launchctl", "print", f"gui/{inst.uid}/{LABELS[0]}"], check=False)
            for line in r.stdout.splitlines():
                k, _, v = line.strip().partition(" = ")
                if k == "pid" and v.isdigit():
                    return int(v)
            return None
        if not self._session(inst):
            return None
        r = self._systemctl_user(inst, "show", f"{LABELS[0]}.service", "-p", "MainPID", "--value", check=False)
        v = r.stdout.strip()
        return int(v) if v.isdigit() and v != "0" else None

    def stop_user(self, inst: Install):
        pid = self.user_pid(inst)
        if self.layout.os == "darwin":
            for label in LABELS:
                self.run(["/bin/launchctl", "bootout", f"gui/{inst.uid}/{label}"], check=False)
        elif self._session(inst):
            self._systemctl_user(inst, "stop", *(f"{label}.service" for label in LABELS), check=False)
        deadline = time.monotonic() + 60
        while pid and time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            except PermissionError:
                pass
            time.sleep(0.5)
        if pid:
            raise MigrationError(f"the per-user oarbankd (pid {pid}) did not stop within 60 s")

    def start_user(self, inst: Install):
        if not self._session(inst):
            return                                               # they start at the person's next login
        if self.layout.os == "darwin":
            for p in inst.definitions:
                self.run(["/bin/launchctl", "bootstrap", f"gui/{inst.uid}", p], check=False)
        else:
            self._systemctl_user(inst, "start", *(f"{label}.service" for label in LABELS), check=False)

    def retire_user(self, inst: Install, keep: Path):
        """Disable the per-user services for good; their definitions are kept in `keep`."""
        keep.mkdir(parents=True, exist_ok=True)
        if self.layout.os != "darwin" and self._session(inst):
            self._systemctl_user(inst, "disable", *(f"{label}.service" for label in LABELS), check=False)
        for p in inst.definitions:
            if p.exists():
                shutil.copy2(p, keep / p.name)
                p.unlink()
            for w in p.parent.glob(f"*.wants/{p.name}"):
                w.unlink()
        if self.layout.os != "darwin" and self._session(inst):
            self._systemctl_user(inst, "daemon-reload", check=False)

    def pin_keychain(self, inst: Install):
        """Keep the per-user coordinator on its Keychain keys until its owner exports them: OARBANK_SECRET_STORE=keychain
        in its LaunchAgents, reloaded so a restart on this release's code (whose default is the file store) does not
        make new keys."""
        for p in inst.definitions:
            st = p.stat()
            doc = plistlib.loads(p.read_bytes())
            doc.setdefault("EnvironmentVariables", {})["OARBANK_SECRET_STORE"] = "keychain"
            p.write_bytes(plistlib.dumps(doc))
            os.chown(p, st.st_uid, st.st_gid)
            os.chmod(p, st.st_mode & 0o777)
        if self._session(inst):
            for label, p in zip(LABELS, inst.definitions):
                self.run(["/bin/launchctl", "bootout", f"gui/{inst.uid}/{label}"], check=False)
                self.run(["/bin/launchctl", "bootstrap", f"gui/{inst.uid}", p], check=False)

    def export_in_session(self, inst: Install) -> bool:
        """macOS: the key export as the person, inside their login session (their Keychain is unlocked there)."""
        if self.layout.os != "darwin" or not self._session(inst):
            return False
        cli = self.build / "bin" / "oarbank"
        # -H: the person's HOME, where `security` finds their keychain search list (root's HOME finds none)
        r = self.run(["/bin/launchctl", "asuser", str(inst.uid), "/usr/bin/sudo", "-H", "-u", inst.user, cli, "coordinator",
                      "migrate", "--export-keys", "--home", str(inst.old_home)], check=False, timeout=90)
        return r.returncode == 0

    # the copy
    def clone(self, src: Path, dst: Path):
        """`src` into the new directory `dst`, entry by entry, leaving out the per-process ones (TRANSIENT: the old
        socket directory holds a socket cp cannot copy): APFS clones on macOS (instant, no space until written), reflinks
        where Linux's file system has them."""
        dst.mkdir(mode=0o700)
        for entry in sorted(src.iterdir()):
            if entry.name in TRANSIENT:
                continue
            if sys.platform == "darwin":
                if self.run(["/bin/cp", "-Rpc", entry, dst], check=False).returncode != 0:
                    shutil.rmtree(dst / entry.name, ignore_errors=True)
                    self.run(["/bin/cp", "-Rp", entry, dst])
            else:
                self.run(["cp", "-a", "--reflink=auto", entry, dst])

    def chown_tree(self, path: Path):
        account = "_oarbankd" if self.layout.os == "darwin" else "oarbankd"
        self.run(["chown", "-R", f"{account}:{account}", path])

    def give(self, path: Path, inst: Install):
        os.chown(path, inst.uid, inst.gid)

    # the system services
    def prepare_system(self, inst: Install):
        """The service account, the owners' group (with the person) and the directories, before the copy is theirs."""
        self.run(["/bin/bash", self.build / "install-oarbankd.sh", "--prepare", "--owner", inst.user], timeout=120)

    def install_system(self, inst: Install):
        argv = ["/bin/bash", self.build / "install-oarbankd.sh", "--installed", self.build, "--agent-bind", inst.agent_bind,
                "--owner", inst.user]
        if inst.agent_port:
            argv += ["--agent-port", inst.agent_port]
        if inst.url:
            argv += ["--url", inst.url]
        self.run(argv, timeout=300, env={**os.environ, "OARBANK_RELEASE_SIGNING": inst.signing})

    def uninstall_system(self):
        self.run(["/bin/bash", self.build / "install-oarbankd.sh", "--uninstall", "--keep-programs"], check=False, timeout=120)

    def verify(self, fleet: str | None, timeout: float = VERIFY_S) -> str:
        """Both services run as the service account, the admin channel answers with the old fleet id, the console its
        health check."""
        import httpx
        from .platform import service
        deadline = time.monotonic() + timeout
        last = "not started"
        while time.monotonic() < deadline:
            states = [service.state(n) for n in LABELS]
            ok = all(s["installed"] and s["domain"] == "system" and s["account"] == paths.SERVICE_ACCOUNT and s["pid"]
                     for s in states)
            if not ok:
                last = f"services: {states}"
                time.sleep(1)
                continue
            try:
                with httpx.Client(transport=httpx.HTTPTransport(uds=str(paths.admin_socket())), base_url="http://oarbank") as c:
                    got = c.get("/api/v1/coordinator", timeout=5).json().get("fleet_id")
                with httpx.Client(trust_env=False) as c:
                    console = c.get("http://127.0.0.1:7400/healthz", timeout=5).json().get("ok")
            except (httpx.HTTPError, ValueError, OSError) as e:
                last = f"not answering yet: {e}"
                time.sleep(1)
                continue
            if fleet and got != fleet:
                raise MigrationError(f"the system service serves fleet {got}, the per-user coordinator was {fleet}")
            if console:
                return f"fleet {got}; oarbankd pid {states[0]['pid']}, console pid {states[1]['pid']}, as {paths.SERVICE_ACCOUNT}"
            last = "console not healthy yet"
            time.sleep(1)
        raise MigrationError(f"the system service did not come up within {timeout:.0f} s ({last})")


# ------------------------------------------------------------------------------------------------- the migration

class Migration:
    def __init__(self, layout: Layout, ops: Ops, install: Install, from_installer: bool = False):
        self.layout, self.ops, self.inst, self.from_installer = layout, ops, install, from_installer
        self.record = Record(layout, install)
        self.stamp = time.strftime("%Y%m%d-%H%M%S")

    def preflight(self):
        inst, new = self.inst, self.layout.new_home
        if inst.standby:
            raise MigrationError("the per-user coordinator is a move's standby: finish or cancel the move first")
        if not (inst.old_home / "oarbank.sqlite3").exists():
            raise MigrationError(f"{inst.old_home} holds no coordinator")
        if (inst.old_home / "setup.pending.json").exists():
            raise MigrationError("the coordinator's setup is unfinished: finish it in the setup wizard first")
        if (new / "oarbank.sqlite3").exists():
            prev = self.record.previous
            ours = prev.get("state") in ("started", "rolled-back") and prev.get("install", {}).get("old_home") == str(inst.old_home)
            if not ours:
                raise MigrationError(f"{new} already holds a coordinator; the per-user one at {inst.old_home} stays as it is")
            aside = new.with_name(f"{new.name}.partial-{self.stamp}")
            new.rename(aside)
            self.record.step("preflight", f"an interrupted copy was set aside as {aside}")
        try:
            return check_keys(inst.old_home)
        except NeedsPerson:
            if not (self.from_installer and self.ops.export_in_session(inst)):
                raise
            checked = check_keys(inst.old_home)              # NeedsPerson again when the export found nothing
            self.record.step("export", f"the keys were exported in {inst.user}'s session")
            return checked

    def run(self) -> dict:
        inst, new = self.inst, self.layout.new_home
        try:
            checked = self.preflight()
        except NeedsPerson as e:
            if self.from_installer and self.layout.os == "darwin" and not inst.keychain_pinned:
                self.ops.pin_keychain(inst)
                self.record.step("pinned", "the per-user coordinator keeps its Keychain keys until its owner moves it")
            self.record.step("waiting", str(e), state="needs-person")
            raise
        except MigrationError as e:
            self.record.step("refused", str(e), state="refused", error=str(e))
            raise
        self.record.step("preflight", "keys match the database: " + (", ".join(checked) or "no keys needed"))
        fleet = fleet_of(inst.old_home)
        stopped = False
        try:
            self.ops.stop_user(inst)
            stopped = True
            self.record.step("stopped", f"the per-user services of {inst.user}")
            partial = new.with_name(f"{new.name}.copying")
            if partial.exists():
                shutil.rmtree(partial)
            self.ops.clone(inst.old_home, partial)
            for name in TRANSIENT:
                p = partial / name
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p)
                else:
                    p.unlink(missing_ok=True)
            for venv in (partial / "modules").rglob(".venv") if (partial / "modules").exists() else []:
                if venv.is_dir():
                    shutil.rmtree(venv)            # its scripts name the old path; oarbankd rebuilds it at start
            marker = partial / "setup.complete.json"
            if marker.exists():
                sd = self.layout.setup_dir(inst.person_home)
                sd.mkdir(parents=True, exist_ok=True)
                shutil.copy2(marker, sd / marker.name)
                self.ops.give(sd, inst)
                self.ops.give(sd / marker.name, inst)
                marker.unlink()
            self.ops.prepare_system(inst)
            self.ops.chown_tree(partial)
            os.chmod(partial, 0o700)
            if new.exists() and not (new / "oarbank.sqlite3").exists():
                shutil.rmtree(new)                # the empty home the installer made
            partial.rename(new)
            self.record.step("copied", f"{inst.old_home} -> {new}")
            self.ops.install_system(inst)
            self.record.step("installed", f"system services, agents at {inst.agent_bind}")
            got = self.ops.verify(fleet)
            self.record.step("verified", got)
        except Exception as e:                                   # noqa: BLE001 (every failure rolls back)
            self.rollback(e, stopped)
            raise MigrationError(f"the migration failed and was rolled back: {e}") from e
        migrated = inst.old_home.with_name(f"{inst.old_home.name}.migrated-{self.stamp}")
        warnings = []
        try:
            inst.old_home.rename(migrated)
            keep = migrated / "per-user-services"
            self.ops.retire_user(inst, keep)
            files.write_private(migrated / "FINALIZED", f"moved to the system service at {new} on {self.stamp}\n")
            for p in (keep, *keep.iterdir(), migrated / "FINALIZED"):
                self.ops.give(p, inst)             # the person's to read and delete, like the rest of the old home
        except OSError as e:
            warnings.append(f"retiring the per-user form: {e}")
        self.record.step("done", f"the old home is kept as {migrated}"
                         + (f"; the old Keychain items stay in {inst.user}'s Keychain" if self.layout.os == "darwin" else "")
                         + (f" (warnings: {'; '.join(warnings)})" if warnings else ""),
                         state="done", migrated_home=str(migrated), finished_at=time.time())
        return self.record.doc

    def rollback(self, error: Exception, stopped: bool):
        new = self.layout.new_home
        notes = []
        try:
            self.ops.uninstall_system()
            notes.append("system services removed")
        except Exception as e:                                   # noqa: BLE001
            notes.append(f"removing the system services failed: {e}")
        for p in (new, new.with_name(f"{new.name}.copying")):
            if p.exists() and (p / "oarbank.sqlite3").exists():
                aside = self.layout.system_data / f"coordinator.failed-{self.stamp}"
                p.rename(aside)
                notes.append(f"the copy was set aside as {aside}")
        if stopped:
            try:
                self.ops.start_user(self.inst)
                notes.append(f"the per-user services of {self.inst.user} started again")
            except Exception as e:                               # noqa: BLE001
                notes.append(f"restarting the per-user services failed: {e}")
        self.record.step("rolled-back", f"{error}; " + "; ".join(notes), state="rolled-back", error=str(error))


# ------------------------------------------------------------------------------------------------- entry points

def this_build() -> Path | None:
    """The coordinator build this code runs from (its interpreter is <build>/python/bin/python3.12)."""
    root = Path(sys.executable).resolve().parents[2]
    return root if (root / "oarbank-coordinator.json").exists() and (root / "install-oarbankd.sh").exists() else None


def pick(installs: list[Install], user: str | None) -> Install | None:
    if user:
        mine = [i for i in installs if i.user == user]
        if not mine:
            raise MigrationError(f"{user} has no per-user coordinator")
        return mine[0]
    if len(installs) > 1:
        raise MigrationError("more than one per-user coordinator on this machine (" + ", ".join(i.user for i in installs)
                             + "): choose one with --user")
    return installs[0] if installs else None


def run_as_root(user: str | None = None, build: Path | None = None, from_installer: bool = False,
                dry_run: bool = False, layout: Layout | None = None, out=print) -> int:
    """`oarbank coordinator migrate --run`: 0 migrated or nothing to do, 3 waiting for the person, 1 failed."""
    layout = layout or Layout()
    inst = pick(find_installs(layout), user)
    if not inst:
        out("no per-user coordinator on this machine: nothing to migrate")
        return 0
    if dry_run:
        out(json.dumps({"would_migrate": inst.summary(), "to": str(layout.new_home)}, indent=1))
        return 0
    if os.geteuid() != 0:
        raise MigrationError("the migration's second half runs as root (sudo)")
    build = Path(build) if build else this_build()
    if not build:
        raise MigrationError("give --build <coordinator build directory> (this is not a coordinator build)")
    try:
        Migration(layout, Ops(layout, build), inst, from_installer=from_installer).run()
    except NeedsPerson as e:
        out(f"waiting for {inst.user}: {e}. Open Oarbank Coordinator and choose Move the coordinator to a system service, "
            "or run `oarbank coordinator migrate` as that person")
        return 3
    return 0


def run_as_person(dry_run: bool = False, out=print) -> int:
    """`oarbank coordinator migrate`: export this person's keys (macOS), then the root half through sudo, or the
    system's administrator prompt when there is no terminal."""
    import getpass
    layout = Layout()
    inst = pick(find_installs(layout, [(getpass.getuser(), os.getuid(), os.getgid(), Path.home())]), None)
    if not inst:
        out("this account has no per-user coordinator: nothing to migrate")
        return 0
    if layout.os == "darwin":
        names = export_keys(inst.old_home)
        out("keys in the file store: " + (", ".join(names) or "none in the Keychain"))
    build = this_build()
    if not build:
        raise MigrationError("run the coordinator build's own oarbank (this is not a coordinator build)")
    argv = [str(build / "bin" / "oarbank"), "coordinator", "migrate", "--run", "--user", inst.user, "--build", str(build)]
    if dry_run:
        argv.append("--dry-run")
    return elevate(argv, "Oarbank Coordinator needs an administrator to move the coordinator to a system service.")


def elevated(argv: list[str], prompt: str, terminal: bool | None = None) -> list[str]:
    """`argv` run as root: itself when root; with no terminal, through the system's administrator prompt on a Mac
    (AppleScript's `do shell script … with administrator privileges`, every argument through `quoted form of`, so
    nothing is interpreted by a shell) or pkexec on Linux; else sudo."""
    if os.geteuid() == 0:
        return list(argv)
    terminal = sys.stdin.isatty() if terminal is None else terminal
    if sys.platform == "darwin" and not terminal:
        script = ['on run argv', 'set cmd to ""', 'repeat with a in argv',
                  'set cmd to cmd & quoted form of (a as text) & " "', 'end repeat',
                  'do shell script cmd with prompt "' + prompt.replace('"', "'") + '" with administrator privileges',
                  'end run']
        return ["/usr/bin/osascript"] + [x for line in script for x in ("-e", line)] + [str(a) for a in argv]
    if sys.platform != "darwin" and not terminal and shutil.which("pkexec"):
        return ["pkexec", *map(str, argv)]
    return ["sudo", *map(str, argv)]


def elevate(argv: list[str], prompt: str) -> int:
    return subprocess.run(elevated(argv, prompt)).returncode


def status(layout: Layout | None = None) -> dict:
    layout = layout or Layout()
    try:
        found = [i.summary() for i in find_installs(layout)]
    except MigrationError as e:
        found = [{"error": str(e)}]
    return {"record": read_record(layout), "per_user": found}
