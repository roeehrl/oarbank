"""The coordinator as a system service on macOS and Linux (docs/design/coordinator-system-service.md): the local admin
channel outside the home with the owners' group, the setup journal in the person's own directory, the paths. Scratch
directories only: the system paths are pointed into pytest's temporary directory."""
import os
import socket
import sys
from pathlib import Path

import httpx
import pytest

from oarbank import paths, setup
from oarbank.platform import localchannel

if sys.platform != "win32":
    import grp

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the macOS and Linux system service")


def test_the_system_home_is_the_same_for_everyone_and_the_owner_keys_stay_with_the_person(monkeypatch):
    monkeypatch.delenv("OARBANK_RELEASE_KEY", raising=False)
    assert paths.coordinator_home() == paths.system_data_root() / "coordinator"
    assert str(paths.coordinator_home()) in ("/Library/Application Support/Oarbank/coordinator", "/var/lib/oarbank/coordinator")
    assert paths.release_key().is_relative_to(Path.home())
    assert paths.setup_dir().is_relative_to(Path.home())
    assert paths.SERVICE_ACCOUNT in ("_oarbankd", "oarbankd") and paths.ADMIN_GROUP in ("_oarbankadmin", "oarbank-admin")
    assert not str(paths.admin_socket()).startswith(str(paths.coordinator_home()) + "/")


def test_the_system_home_uses_the_system_socket_any_other_home_its_own(tmp_path, monkeypatch):
    monkeypatch.delenv("OARBANKD_ADMIN_SOCKET", raising=False)
    system = tmp_path / "system" / "coordinator"
    system.mkdir(parents=True)
    monkeypatch.setattr(paths, "coordinator_home", lambda: system)
    monkeypatch.setattr(paths, "admin_socket", lambda: tmp_path / "run" / "admin.sock")
    assert localchannel.address(system) == str(tmp_path / "run" / "admin.sock")
    other = tmp_path / "h"
    other.mkdir()
    own = localchannel.address(other)                        # <home>/run, or a short private directory past the limit
    assert own in (str(other / "run" / "admin.sock"), ) or own.startswith(f"/tmp/oarbank-{os.getuid()}/")
    monkeypatch.setenv("OARBANKD_ADMIN_SOCKET", str(tmp_path / "x.sock"))           # the service definition names it
    assert localchannel.address(other) == str(tmp_path / "x.sock")


def test_the_socket_directory_admits_the_owners_group(tmp_path, monkeypatch):
    """The directory is the credential: this account's, mode 0750, its group the owners' (here this account's own
    group, which it belongs to), so a member reaches the socket and anyone else cannot see it."""
    group = grp.getgrgid(os.getgid()).gr_name
    run = tmp_path / "r"
    localchannel.group_dir(run, group)
    st = run.stat()
    assert st.st_mode & 0o777 == 0o750 and st.st_gid == os.getgid() and st.st_uid == os.getuid()
    localchannel.group_dir(run, None)
    assert run.stat().st_mode & 0o777 == 0o700
    other = tmp_path / "theirs"
    other.mkdir()
    if os.geteuid() != 0:
        os.chmod(other, 0o755)
    with pytest.raises(KeyError):
        localchannel.group_dir(tmp_path / "s", "no-such-group-oarbank")


def test_a_server_on_the_system_socket_answers_through_the_group_directory(tmp_path, monkeypatch):
    """oarbankd's local channel server on a socket outside its home (OARBANKD_ADMIN_SOCKET, OARBANKD_ADMIN_GROUP)."""
    import threading
    import time
    from fastapi import FastAPI
    group = grp.getgrgid(os.getgid()).gr_name
    short = Path(f"/tmp/oarbank-test-{os.getpid()}")          # socket paths are limited to 104 bytes
    monkeypatch.setenv("OARBANKD_ADMIN_SOCKET", str(short / "admin.sock"))
    monkeypatch.setenv("OARBANKD_ADMIN_GROUP", group)
    app = FastAPI()
    app.get("/ping")(lambda: {"ok": True})
    home = tmp_path / "home"
    home.mkdir()
    server = localchannel.server(app, home, log_level="warning")
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        for _ in range(100):
            if (short / "admin.sock").exists():
                break
            time.sleep(0.05)
        assert short.stat().st_mode & 0o777 == 0o750 and short.stat().st_gid == os.getgid()
        assert localchannel.reachable(home)
        with httpx.Client(transport=localchannel.transport(home), base_url="http://oarbank") as c:
            assert c.get("/ping").json() == {"ok": True}
    finally:
        server.should_exit = True
        t.join(timeout=10)
        import shutil
        shutil.rmtree(short, ignore_errors=True)


def test_the_wizard_keeps_its_journal_with_the_person_for_the_system_home(tmp_path, monkeypatch):
    system = tmp_path / "system" / "coordinator"
    system.mkdir(parents=True)
    monkeypatch.setattr(paths, "coordinator_home", lambda: system)
    monkeypatch.setattr(paths, "setup_dir", lambda: tmp_path / "person" / "setup")
    assert setup.journal_dir(system) == tmp_path / "person" / "setup"
    assert setup.journal_dir(tmp_path / "dev-home") == tmp_path / "dev-home"


def test_the_desktop_status_reads_the_person_s_journal_before_the_unreadable_home(tmp_path, monkeypatch):
    from oarbank import desktop
    system = tmp_path / "system" / "coordinator"
    system.mkdir(parents=True)
    journal = tmp_path / "person" / "setup"
    journal.mkdir(parents=True)
    monkeypatch.setattr(paths, "coordinator_home", lambda: system)
    monkeypatch.setattr(paths, "setup_dir", lambda: journal)
    (journal / "setup.pending.json").write_text("{}")
    assert desktop.setup_state(system) == {"configured": False, "pending": True}
    (journal / "setup.pending.json").unlink()
    (system / "oarbank.sqlite3").write_text("")
    assert desktop.setup_state(system) == {"configured": True, "pending": False}
    form = desktop.service_form()
    assert form["form"] in ("system", "per-user", "none") and set(form) >= {"per_user", "migration"}


def test_an_account_outside_the_owners_group_is_told_how_to_join(tmp_path, monkeypatch):
    system = tmp_path / "system" / "coordinator"
    system.mkdir(parents=True)
    monkeypatch.setattr(paths, "coordinator_home", lambda: system)
    monkeypatch.setattr(paths, "admin_socket", lambda: tmp_path / "run" / "admin.sock")
    mine = grp.getgrgid(os.getgid()).gr_name
    monkeypatch.setattr(paths, "ADMIN_GROUP", "no-such-group-oarbank")
    assert localchannel.unreachable_reason(system) is None             # no such group: nothing to say
    import pwd
    me = pwd.getpwuid(os.getuid()).pw_name

    class G:
        def __init__(self, members):
            self.gr_mem = members
    monkeypatch.setattr(grp, "getgrnam", lambda name: G([]))
    why = localchannel.unreachable_reason(system)
    assert f"{me} is not in the group no-such-group-oarbank" in why and ("dseditgroup" in why or "usermod -aG" in why)
    monkeypatch.setattr(grp, "getgrnam", lambda name: G([me]))
    (tmp_path / "run").mkdir()
    assert "log in again" in localchannel.unreachable_reason(system)
    assert mine                                                        # (this account's own group exists)
    assert socket                                                      # noqa: B018
