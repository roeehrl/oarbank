"""Moving a per-user coordinator to the system service (oarbank/sysmigrate.py, docs/design/coordinator-system-service.md,
"Migration from the per-user form").

Everything runs on scratch copies: a per-user home made by the coordinator's own code (or, with
OARBANK_MIGRATION_HOME_COPY, a copy of a real one), its LaunchAgent or user unit, a throwaway keychain file in the test's
directory holding the keys under their real item names (macOS), and a recorder in place of the service managers. No
login Keychain, no launchd or systemd job, no account is touched.
"""
import base64
import json
import os
import plistlib
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import make_db
from oarbank import sysmigrate
from oarbank.coordinator import audit, modsecrets
from oarbank.platform import secrets

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the per-user form existed on macOS and Linux only")
USER = os.environ.get("USER") or "owner"


class Recorder(sysmigrate.Ops):
    """The OS actions, recorded: the copy and the file moves are real (in the scratch tree), the service managers not."""

    def __init__(self, layout, build, fail_verify=False, running=True):
        super().__init__(layout, build)
        self.calls, self.fail_verify, self.running = [], fail_verify, running

    def _session(self, inst):
        return self.running

    def user_pid(self, inst):
        return None

    def stop_user(self, inst):
        self.calls.append(("stop_user", inst.user))

    def start_user(self, inst):
        self.calls.append(("start_user", inst.user))

    def export_in_session(self, inst):
        self.calls.append(("export_in_session", inst.user))
        return False

    def pin_keychain(self, inst):
        self.calls.append(("pin_keychain", inst.user))
        for p in inst.definitions:                       # the real plist edit, without launchctl
            doc = plistlib.loads(p.read_bytes())
            doc.setdefault("EnvironmentVariables", {})["OARBANK_SECRET_STORE"] = "keychain"
            p.write_bytes(plistlib.dumps(doc))

    def retire_user(self, inst, keep):
        self.calls.append(("retire_user", inst.user))
        running, self.running = self.running, False      # no systemctl or launchctl, the file moves only
        try:
            super().retire_user(inst, keep)
        finally:
            self.running = running

    def prepare_system(self, inst):
        self.calls.append(("prepare_system", inst.user))
        (self.layout.new_home / "logs").mkdir(parents=True, exist_ok=True)     # as install-oarbankd.sh --prepare does

    def chown_tree(self, path):
        self.calls.append(("chown_tree", str(path)))

    def install_system(self, inst):
        self.calls.append(("install_system", inst.agent_bind, inst.agent_port, inst.url, inst.signing, inst.user))

    def uninstall_system(self):
        self.calls.append(("uninstall_system",))

    def verify(self, fleet, timeout=0):
        if self.fail_verify:
            raise sysmigrate.MigrationError("the system service did not come up within 120 s (simulated)")
        new = self.layout.new_home
        got = sysmigrate.fleet_of(new)
        assert got == fleet
        return f"fleet {got}"


def per_user_home(tmp_path, os_name=sys.platform, keys_in_files=True, secret=True):
    """A per-user coordinator as an earlier release left it: its home (database, audit digest, a module secret, a module
    environment, the wizard's completion record, the live socket directory), its keys and its service definition."""
    person = tmp_path / "Users" / USER
    old = person / ("Library/Application Support/Oarbank/coordinator" if os_name == "darwin" else ".local/share/oarbank/coordinator")
    old.mkdir(parents=True)
    db = make_db(old / "oarbank.sqlite3", modules=())
    audit.append(db, actor="owner", source="cli", operation="fleet.pause", category="modify", target_type="fleet",
                 target_id="fleet", outcome="ok", request_id="r1")
    audit.write_digest(db, audit.Signer(base64.b64encode(secrets.get_or_create(sysmigrate.AUDIT_KEY, old)).decode()))
    if secret:
        db.x("INSERT INTO secrets(module,name,node_id,ciphertext,fingerprint,set_at,set_by,sealed) VALUES(?,?,?,?,?,?,?,0)",
             ("vault", "api_key", "", modsecrets._encrypt(modsecrets._key(db), "vault", "api_key", "", b"hunter2"), "fp", 1.0, "owner"))
    fleet = sysmigrate.fleet_of(old)
    (old / "modules/store/m/1.0.0/.venv/bin").mkdir(parents=True)
    (old / "modules/store/m/1.0.0/.venv/bin/tool").write_text(f"#!{old}/modules/store/m/1.0.0/.venv/bin/python\n")
    (old / "modules/store/m/1.0.0/requirements.txt").write_text("")
    (old / "run").mkdir()
    (old / "run/admin.sock").write_text("")
    (old / "console.secret").write_text("per-boot\n")
    (old / "setup.complete.json").write_text(json.dumps({"format": 1, "fleet": fleet, "address": "100.64.0.1"}))
    keys = {}
    for name in (sysmigrate.AUDIT_KEY, sysmigrate.MODULE_KEY):
        if secrets.file_path(name, old).exists():
            keys[name] = secrets.read_file_secret(name, old)
            if not keys_in_files:
                secrets.file_path(name, old).unlink()
    program = "/Applications/Oarbank Coordinator.app/Contents/Resources/coordinator/bin/oarbankd"
    if os_name == "darwin":
        la = person / "Library/LaunchAgents"
        la.mkdir(parents=True)
        for label, args in (("dev.codonic.oarbank.oarbankd", [program, "--agent-bind", "100.64.0.1"]),
                            ("dev.codonic.oarbank.console", [program.replace("oarbankd", "oarbank-console")])):
            (la / f"{label}.plist").write_bytes(plistlib.dumps({
                "Label": label, "ProgramArguments": args, "KeepAlive": True,
                "EnvironmentVariables": {"OARBANKD_HOME": str(old), "OARBANK_RELEASE_SIGNING": "1", "PATH": "/usr/bin:/bin"}}))
    else:
        units = person / ".config/systemd/user"
        units.mkdir(parents=True)
        (units / "default.target.wants").mkdir()
        for name, args in (("oarbankd", [program, "--agent-bind", "10.0.0.5", "--agent-port", "7444"]),
                           ("console", [program.replace("oarbankd", "oarbank-console")])):
            q = " ".join(f'"{a}"' for a in args)
            unit = units / f"dev.codonic.oarbank.{name}.service"
            unit.write_text(f'[Service]\nExecStart={q}\nEnvironment="OARBANKD_HOME={old}" "OARBANK_RELEASE_SIGNING=0"\n')
            (units / "default.target.wants" / unit.name).symlink_to(unit)
    return person, old, fleet, keys


def layout(tmp_path, os_name=sys.platform):
    system = tmp_path / "system"
    system.mkdir(exist_ok=True)
    (system / "coordinator").mkdir(exist_ok=True)           # the empty home the package made
    return sysmigrate.Layout(os=os_name, system_data=system, new_home=system / "coordinator")


def people(person):
    return [(USER, os.getuid(), os.getgid(), person)]


def scratch_keychain(tmp_path, keys: dict) -> str:
    """A keychain file of the test's own (never added to any search list), holding `keys` as the earlier release's
    coordinator stored them: a generic password per name, account `oarbank`, base64 value."""
    path = str(tmp_path / "scratch.keychain-db")
    subprocess.run(["security", "create-keychain", "-p", "scratch", path], check=True, capture_output=True)
    for name, raw in keys.items():
        subprocess.run(["security", "add-generic-password", "-s", name, "-a", "oarbank", "-w", base64.b64encode(raw).decode(),
                        path], check=True, capture_output=True)
    return path


# ------------------------------------------------------------------------------------------------- detection

@pytest.mark.parametrize("os_name", ["darwin", "linux"])
def test_detection_reads_the_per_user_definition(tmp_path, os_name):
    person, old, _, _ = per_user_home(tmp_path, os_name)
    lay = layout(tmp_path, os_name)
    [inst] = sysmigrate.find_installs(lay, people(person))
    assert inst.user == USER and inst.old_home == old and inst.program.endswith("/bin/oarbankd")
    if os_name == "darwin":
        assert inst.agent_bind == "100.64.0.1" and inst.agent_port is None and inst.signing == "1"
        assert [p.name for p in inst.definitions] == ["dev.codonic.oarbank.oarbankd.plist", "dev.codonic.oarbank.console.plist"]
    else:
        assert (inst.agent_bind, inst.agent_port, inst.signing) == ("10.0.0.5", "7444", "0")
    assert sysmigrate.find_installs(lay, [(USER, os.getuid(), os.getgid(), tmp_path / "nobody")]) == []
    with pytest.raises(sysmigrate.MigrationError, match="choose one with --user"):
        sysmigrate.pick([inst, inst], None)


# ------------------------------------------------------------------------------------------------- keys

def test_keys_must_be_in_the_file_store_and_match_the_database(tmp_path):
    person, old, _, keys = per_user_home(tmp_path, keys_in_files=False)
    with pytest.raises(sysmigrate.NeedsPerson, match="audit key"):
        sysmigrate.check_keys(old)
    secrets.write_file_secret(sysmigrate.AUDIT_KEY, old, os.urandom(32))
    with pytest.raises(sysmigrate.MigrationError, match="not the one the audit chain names"):
        sysmigrate.check_keys(old)
    secrets.file_path(sysmigrate.AUDIT_KEY, old).unlink()
    secrets.write_file_secret(sysmigrate.AUDIT_KEY, old, keys[sysmigrate.AUDIT_KEY])
    with pytest.raises(sysmigrate.NeedsPerson, match="module secrets key"):
        sysmigrate.check_keys(old)
    secrets.write_file_secret(sysmigrate.MODULE_KEY, old, os.urandom(32))
    with pytest.raises(sysmigrate.MigrationError, match="opens none"):
        sysmigrate.check_keys(old)
    secrets.file_path(sysmigrate.MODULE_KEY, old).unlink()
    secrets.write_file_secret(sysmigrate.MODULE_KEY, old, keys[sysmigrate.MODULE_KEY])
    assert sysmigrate.check_keys(old) == [sysmigrate.AUDIT_KEY, "module-secrets (1/1 secrets open)"]


@pytest.mark.skipif(sys.platform != "darwin", reason="the login Keychain was the macOS per-user store")
def test_the_export_copies_the_keychain_items_into_the_file_store(tmp_path):
    person, old, _, keys = per_user_home(tmp_path, "darwin", keys_in_files=False)
    chain = scratch_keychain(tmp_path, keys)
    assert sorted(sysmigrate.export_keys(old, chain)) == sorted(keys)
    for name, raw in keys.items():
        f = secrets.file_path(name, old)
        assert secrets.read_file_secret(name, old) == raw and f.stat().st_mode & 0o777 == 0o600
    assert sorted(sysmigrate.export_keys(old, chain)) == sorted(keys)          # idempotent
    sysmigrate.check_keys(old)
    secrets.file_path(sysmigrate.AUDIT_KEY, old).unlink()
    secrets.write_file_secret(sysmigrate.AUDIT_KEY, old, os.urandom(32))       # a coordinator that made a new key
    with pytest.raises(sysmigrate.MigrationError, match="already made a new key"):
        sysmigrate.export_keys(old, chain)
    # the keychain file is the test's: nothing reached the person's search list
    listed = subprocess.run(["security", "list-keychains"], capture_output=True, text=True).stdout
    assert chain not in listed


# ------------------------------------------------------------------------------------------------- the migration

@pytest.mark.parametrize("os_name", ["darwin", "linux"])
def test_a_migration_copies_installs_verifies_and_retires(tmp_path, os_name):
    person, old, fleet, keys = per_user_home(tmp_path, os_name)
    lay = layout(tmp_path, os_name)
    [inst] = sysmigrate.find_installs(lay, people(person))
    ops = Recorder(lay, tmp_path / "build")
    doc = sysmigrate.Migration(lay, ops, inst).run()
    new = lay.new_home
    assert doc["state"] == "done" and [s["step"] for s in doc["steps"]] == [
        "preflight", "stopped", "copied", "installed", "verified", "done"]
    assert [c[0] for c in ops.calls] == ["stop_user", "prepare_system", "chown_tree", "install_system", "retire_user"]
    assert ops.calls[2] == ("chown_tree", str(new.with_name("coordinator.copying")))
    assert ops.calls[3][1:] == (("100.64.0.1", None, None, "1", USER) if os_name == "darwin" else ("10.0.0.5", "7444", None, "0", USER))
    # the new home: the database, the keys in the file store, nothing per-process, no module environment
    assert sysmigrate.fleet_of(new) == fleet and new.stat().st_mode & 0o777 == 0o700
    for name, raw in keys.items():
        assert secrets.read_file_secret(name, new) == raw
    for gone in ("run", "console.secret", "setup.complete.json", "modules/store/m/1.0.0/.venv"):
        assert not (new / gone).exists(), gone
    assert (new / "modules/store/m/1.0.0/requirements.txt").exists()
    # the coordinator's own code reads the moved secrets and signs with the same audit key from the new store
    os.environ["OARBANK_SECRET_STORE"] = "file"
    from oarbank.coordinator.db import DB
    db = DB(new / "oarbank.sqlite3")
    assert modsecrets.unreadable(db) == []
    assert audit.Signer(base64.b64encode(secrets.get_or_create(sysmigrate.AUDIT_KEY, new)).decode()).public_b64 == db.get_state("audit_pubkey")
    assert audit.verify(db)["ok"]
    # the person keeps the old home (renamed, finalized), the wizard's record and copies of the retired definitions
    migrated = Path(doc["migrated_home"])
    assert not old.exists() and migrated.name.startswith("coordinator.migrated-") and (migrated / "FINALIZED").exists()
    assert (migrated / "oarbank.sqlite3").exists()
    assert json.loads((lay.setup_dir(person) / "setup.complete.json").read_text())["fleet"] == fleet
    assert sorted(p.name for p in (migrated / "per-user-services").iterdir()) == sorted(p.name for p in inst.definitions)
    assert not any(p.exists() for p in inst.definitions)
    if os_name == "linux":
        assert not list((person / ".config/systemd/user/default.target.wants").iterdir())
    record = sysmigrate.read_record(lay)
    assert record["state"] == "done" and "hunter2" not in lay.record.read_text()
    assert lay.record.stat().st_mode & 0o777 == 0o644
    # a second run finds nothing to migrate
    assert sysmigrate.find_installs(lay, people(person)) == []


def test_a_failed_start_rolls_back_to_the_untouched_per_user_coordinator(tmp_path):
    person, old, fleet, _ = per_user_home(tmp_path)
    files = lambda: sorted(p.relative_to(old) for p in old.rglob("*") if not p.name.endswith(("-wal", "-shm")))   # noqa: E731
    before = files()
    lay = layout(tmp_path)
    [inst] = sysmigrate.find_installs(lay, people(person))
    ops = Recorder(lay, tmp_path / "build", fail_verify=True)
    with pytest.raises(sysmigrate.MigrationError, match="rolled back"):
        sysmigrate.Migration(lay, ops, inst).run()
    assert [c[0] for c in ops.calls] == ["stop_user", "prepare_system", "chown_tree", "install_system", "uninstall_system", "start_user"]
    assert files() == before
    assert all(p.exists() for p in inst.definitions)
    assert not (lay.new_home / "oarbank.sqlite3").exists()
    [aside] = lay.system_data.glob("coordinator.failed-*")
    assert sysmigrate.fleet_of(aside) == fleet                      # kept for diagnosis
    rec = sysmigrate.read_record(lay)
    assert rec["state"] == "rolled-back" and "simulated" in rec["error"]
    # the next run starts over and succeeds
    lay.new_home.mkdir(exist_ok=True)
    doc = sysmigrate.Migration(lay, Recorder(lay, tmp_path / "build"), inst).run()
    assert doc["state"] == "done"


def test_an_interrupted_copy_of_the_same_migration_is_set_aside_another_coordinator_never(tmp_path):
    person, old, _, _ = per_user_home(tmp_path)
    lay = layout(tmp_path)
    [inst] = sysmigrate.find_installs(lay, people(person))
    shutil.rmtree(lay.new_home)
    shutil.copytree(old, lay.new_home)                            # a stray coordinator in the system home
    with pytest.raises(sysmigrate.MigrationError, match="already holds a coordinator"):
        sysmigrate.Migration(lay, Recorder(lay, tmp_path / "build"), inst).run()
    assert sysmigrate.read_record(lay)["state"] == "refused" and old.exists()
    rec = json.loads(lay.record.read_text())
    rec["state"] = "started"                                      # as if this migration was interrupted after its copy
    lay.record.write_text(json.dumps(rec))
    doc = sysmigrate.Migration(lay, Recorder(lay, tmp_path / "build"), inst).run()
    assert doc["state"] == "done" and list(lay.system_data.glob("coordinator.partial-*"))


def test_a_coordinator_waiting_for_its_owner_keeps_its_keychain_keys(tmp_path):
    person, old, _, _ = per_user_home(tmp_path, "darwin", keys_in_files=False)
    lay = layout(tmp_path, "darwin")
    [inst] = sysmigrate.find_installs(lay, people(person))
    ops = Recorder(lay, tmp_path / "build")
    with pytest.raises(sysmigrate.NeedsPerson):
        sysmigrate.Migration(lay, ops, inst, from_installer=True).run()
    assert [c[0] for c in ops.calls] == ["export_in_session", "pin_keychain"]
    assert sysmigrate.read_record(lay)["state"] == "needs-person"
    [again] = sysmigrate.find_installs(lay, people(person))
    assert again.keychain_pinned                                  # not pinned twice
    assert old.exists() and all(p.exists() for p in inst.definitions)


def test_refusals(tmp_path):
    person, old, _, _ = per_user_home(tmp_path)
    lay = layout(tmp_path)
    [inst] = sysmigrate.find_installs(lay, people(person))
    (old / "setup.pending.json").write_text("{}")
    with pytest.raises(sysmigrate.MigrationError, match="setup is unfinished"):
        sysmigrate.Migration(lay, Recorder(lay, tmp_path / "b"), inst).run()
    (old / "setup.pending.json").unlink()
    inst.standby = True
    with pytest.raises(sysmigrate.MigrationError, match="standby"):
        sysmigrate.Migration(lay, Recorder(lay, tmp_path / "b"), inst).run()


def test_the_elevation_quotes_every_argument_for_applescript(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    if os.geteuid() == 0:
        pytest.skip("root runs it directly")
    argv = sysmigrate.elevated(["/x/oarbank", "a b", "it's", '"q"'], 'Say "hi"', terminal=False)
    assert argv[0] == "/usr/bin/osascript" and argv[-4:] == ["/x/oarbank", "a b", "it's", '"q"']
    script = [argv[i + 1] for i in range(1, len(argv) - 4, 2)]
    assert "set cmd to cmd & quoted form of (a as text) & \" \"" in script
    assert "do shell script cmd with prompt \"Say 'hi'\" with administrator privileges" in script
    assert sysmigrate.elevated(["/x"], "p", terminal=True) == ["sudo", "/x"]


# ------------------------------------------------------------------------------------------------- a real home's copy

@pytest.mark.skipif(not os.environ.get("OARBANK_MIGRATION_HOME_COPY"),
                    reason="set OARBANK_MIGRATION_HOME_COPY to a COPY of a per-user coordinator home (it is changed)")
def test_a_copy_of_a_real_home_migrates(tmp_path):
    """On a copy of a real per-user home: its keys were in a login Keychain this test cannot read, so a scratch key
    stands in for the audit key (the copy's database is pointed at it) and secrets the copy holds are dropped; every
    other byte is the real layout: modules and their environments, releases, backups, TLS, the audit log."""
    src = Path(os.environ["OARBANK_MIGRATION_HOME_COPY"])
    person = tmp_path / "Users" / USER
    old = person / "Library/Application Support/Oarbank/coordinator"
    old.parent.mkdir(parents=True)
    subprocess.run(["cp", "-Rpc", str(src), str(old)], check=True)
    with pytest.raises(sysmigrate.NeedsPerson):                   # the real keys are in its owner's Keychain
        sysmigrate.check_keys(old)
    fake = os.urandom(32)
    con = sqlite3.connect(old / "oarbank.sqlite3")
    secrets_rows = con.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]
    con.execute("DELETE FROM secrets")
    table = "system_state" if con.execute("SELECT 1 FROM sqlite_master WHERE name='system_state'").fetchone() else "settings"
    con.execute(f"UPDATE {table} SET value_json=? WHERE key='audit_pubkey'",
                (json.dumps(audit.Signer(base64.b64encode(fake).decode()).public_b64),))
    con.commit()
    con.close()
    chain = scratch_keychain(tmp_path, {sysmigrate.AUDIT_KEY: fake})
    assert sysmigrate.export_keys(old, chain) == [sysmigrate.AUDIT_KEY]
    la = person / "Library/LaunchAgents"
    la.mkdir(parents=True)
    for label in sysmigrate.LABELS:
        (la / f"{label}.plist").write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": [
            "/Applications/Oarbank Coordinator.app/Contents/Resources/coordinator/bin/oarbankd", "--agent-bind", "100.64.0.1"],
            "EnvironmentVariables": {"OARBANKD_HOME": str(old), "OARBANK_RELEASE_SIGNING": "1"}}))
    lay = layout(tmp_path, "darwin")
    [inst] = sysmigrate.find_installs(lay, people(person))
    fleet = sysmigrate.fleet_of(old)
    venvs = list((old / "modules").rglob(".venv"))
    doc = sysmigrate.Migration(lay, Recorder(lay, tmp_path / "build"), inst).run()
    new = lay.new_home
    assert doc["state"] == "done" and sysmigrate.fleet_of(new) == fleet
    assert not list((new / "modules").rglob(".venv")) and all(v.exists() for v in (Path(doc["migrated_home"]) / v.relative_to(old) for v in venvs))
    # nothing the coordinator works from names the old home: the paths it keeps are relative to its home. Only history
    # may (an event's reason, such as a backup's path then) and what agents report about their own hosts (node facts).
    con = sqlite3.connect(new / "oarbank.sqlite3")
    homes = ("Library/Application Support/Oarbank/coordinator", str(src))
    named = []
    for (table,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('events', 'nodes')"):
        cols = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]
        for col in cols:
            for h in homes:
                if con.execute(f'SELECT COUNT(*) FROM "{table}" WHERE CAST("{col}" AS TEXT) LIKE ?', (f"%{h}%",)).fetchone()[0]:
                    named.append(f"{table}.{col}")
    assert not named, named
    assert all(not p.startswith("/") for (p,) in con.execute("SELECT path FROM modules"))
    con.close()
    print(f"\nmigrated a copy of {src}: fleet {fleet}, {len(venvs)} module environment(s) dropped for rebuild, "
          f"{secrets_rows} secret row(s) set aside, steps {[s['step'] for s in doc['steps']]}")


def test_the_export_in_the_person_s_session_runs_with_their_home(tmp_path, monkeypatch):
    """`security` finds a person's keychains through their HOME: sudo without -H kept root's, found none and exported
    nothing (seen on a macOS VM's package upgrade)."""
    person, old, _, _ = per_user_home(tmp_path, "darwin")
    lay = layout(tmp_path, "darwin")
    [inst] = sysmigrate.find_installs(lay, people(person))
    calls = []
    ops = sysmigrate.Ops(lay, tmp_path / "build")
    monkeypatch.setattr(ops, "run", lambda argv, **kw: calls.append([str(a) for a in argv]) or subprocess.CompletedProcess(argv, 0, "", ""))
    assert ops.export_in_session(inst)
    export = calls[-1]
    assert export[:7] == ["/bin/launchctl", "asuser", str(os.getuid()), "/usr/bin/sudo", "-H", "-u", USER]
    assert export[7:] == [str(tmp_path / "build/bin/oarbank"), "coordinator", "migrate", "--export-keys", "--home", str(old)]
