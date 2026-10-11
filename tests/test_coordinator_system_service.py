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


@pytest.mark.parametrize("os_name", ["Linux", "Darwin"])
def test_the_installer_adds_root_s_update_runner_and_a_refresh_can_name_the_build(tmp_path, os_name):
    """install-oarbankd.sh (dry run): the trigger of the coordinator update runner (fleet-updates.md, D58) runs
    PROGRAMS/current, which names the installed build however it was installed; `--refresh --installed` points the
    services at another build (a package upgrade, a self-update); --uninstall removes the trigger."""
    import json
    import re
    import subprocess
    repo = Path(__file__).resolve().parents[1]
    tools = tmp_path / "tools"
    tools.mkdir()
    arch = "arm64" if os_name == "Darwin" else "x86_64"
    (tools / "uname").write_text(f'#!/bin/sh\ncase "$1" in -s) echo {os_name} ;; -m) echo {arch} ;; esac\n')
    (tools / "uname").chmod(0o755)
    root = tmp_path / "root"
    darwin = os_name == "Darwin"

    def build(name):
        b = tmp_path / name
        (b / "bin").mkdir(parents=True)
        plat = "darwin-arm64" if darwin else "linux-amd64"
        (b / "oarbank-coordinator.json").write_text(json.dumps({"format": 1, "version": "2.10.0", "platform": plat}))
        for n in ("oarbankd", "oarbank-console", "oarbank-coordupdate"):
            (b / "bin" / n).write_text("#!/bin/sh\n")
            (b / "bin" / n).chmod(0o755)
        return b

    def installer(*argv, **env):
        return subprocess.run(["bash", str(repo / "deploy/oarbankd/install-oarbankd.sh"), *argv, "--dry-run"],
                              capture_output=True, text=True,
                              env={"PATH": f"{tools}:/usr/bin:/bin", "HOME": str(tmp_path), "OARBANK_INSTALL_ROOT": str(root), **env})
    a, b = build("a"), build("b")
    r = installer("--installed", str(a), "--agent-bind", "10.0.0.1")
    assert r.returncode == 0, r.stderr
    data = root / ("Library/Application Support/Oarbank" if darwin else "var/lib/oarbank")
    programs = root / ("Library/Oarbank/Coordinator" if darwin else "opt/oarbank/coordinator-builds")
    runner, request = f"{programs}/current/bin/oarbank-coordupdate", f"{data}/coordinator/updates/coordinator-request.json"
    assert f"ln -sfn {a} {programs}/current" in r.stdout
    assert f"{a}/bin/oarbank-coordupdate trust --from-home --home {data}/coordinator --state {data}/coordinator-update" in r.stdout
    assert f"install -d -m 0700 {data}/coordinator-update {data}/coordinator-update/logs" in r.stdout
    if darwin:
        plist = r.stdout.split(f"# {root}/Library/LaunchDaemons/dev.codonic.oarbank.oarbankd.update.plist\n")[1].split("</plist>")[0]
        for want in ("<key>Label</key><string>dev.codonic.oarbank.oarbankd.update</string>",
                     f"<key>ProgramArguments</key><array><string>{runner}</string><string>run</string><string>--once</string></array>",
                     f"<key>WatchPaths</key><array><string>{request}</string></array>",
                     "<key>RunAtLoad</key><true/>", "<key>AbandonProcessGroup</key><true/>"):
            assert want in plist, want
        assert "UserName" not in plist                                           # root's
        assert f"/bin/launchctl bootstrap system {root}/Library/LaunchDaemons/dev.codonic.oarbank.oarbankd.update.plist" in r.stdout
        # the runner's own refresh leaves its job loaded
        r2 = installer("--installed", str(a), "--agent-bind", "10.0.0.1", OARBANK_COORDUPDATE_RUNNING="1")
        assert "bootout system/dev.codonic.oarbank.oarbankd.update" not in r2.stdout and "update.plist" in r2.stdout
    else:
        units = root / "etc/systemd/system"
        path = r.stdout.split(f"# {units}/dev.codonic.oarbank.oarbankd.update.path\n")[1]
        assert f"\n[Path]\nPathExists={request}\nUnit=dev.codonic.oarbank.oarbankd.update.service\n" in path
        svc = r.stdout.split(f"# {units}/dev.codonic.oarbank.oarbankd.update.service\n")[1]
        assert f'\nType=oneshot\nExecStart="{runner}" run --once\n' in svc and "\nWantedBy=multi-user.target" in svc
        assert "User=" not in svc.split("[Install]")[0]                          # root's
        assert ("systemctl enable dev.codonic.oarbank.oarbankd.service dev.codonic.oarbank.console.service "
                "dev.codonic.oarbank.oarbankd.update.path dev.codonic.oarbank.oarbankd.update.service") in r.stdout
        assert "systemctl start dev.codonic.oarbank.oarbankd.update.path" in r.stdout
        assert "systemctl start dev.codonic.oarbank.oarbankd.update.service" not in r.stdout   # never from here
    # a refresh from the record, or on the build it names
    rec = re.search(r'^\{"format": "1".*$', r.stdout, re.M).group(0)
    record = root / ("Library/Application Support/Oarbank" if darwin else "etc/oarbank") / "coordinator-service.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(rec + "\n")
    r = installer("--refresh")
    assert r.returncode == 0 and f"{a}/bin/oarbankd" in r.stdout and f"{b}/bin/oarbankd" not in r.stdout, r.stderr
    r = installer("--refresh", "--installed", str(b))
    assert r.returncode == 0 and f"{b}/bin/oarbankd" in r.stdout and f"{a}/bin/oarbankd" not in r.stdout, r.stderr
    assert f'"root": "{b}"' in r.stdout and f"ln -sfn {b} {programs}/current" in r.stdout
    assert installer("--refresh", "--agent-bind", "10.0.0.2").returncode == 2
    r = installer("--uninstall", "--keep-programs")
    assert r.returncode == 0
    if darwin:
        assert f"rm -f {root}/Library/LaunchDaemons/dev.codonic.oarbank.oarbankd.update.plist" in r.stdout
    else:
        assert "systemctl disable --now dev.codonic.oarbank.oarbankd.update.path" in r.stdout
        assert f"rm -f {root}/etc/systemd/system/dev.codonic.oarbank.oarbankd.update.service" in r.stdout
    assert [p for p in root.rglob("*") if not p.is_dir()] == [record]           # a dry run writes nothing
