"""Where and how the coordinator runs (coordinator/hostinfo.py, platform/service.py): its platform, the service
manager's view of its services (launchd, systemd, the Windows service control manager) and, on Windows, the elevated
helper module CLIs need; shown by the admin API, `oarbank coordinator status` and the console's Coordinator page."""
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from oarbank_sdk import portable

from helpers import admin_headers, make_db, sign_in
from oarbank.coordinator import app as coord_app, hostinfo
from oarbank.platform import service

LAUNCHCTL = """gui/501/dev.codonic.oarbank.oarbankd = {
\tactive count = 1
\tpath = /Users/owner/Library/LaunchAgents/dev.codonic.oarbank.oarbankd.plist
\ttype = LaunchAgent
\tstate = running

\tprogram = /Users/owner/Library/Application Support/Oarbank/coordinator-app/current/bin/oarbankd
\tpid = 4242
}
"""

SYSTEMCTL = "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=777\n"


def test_launchd_and_systemd_answers_become_one_shape():
    assert service.parse_launchctl("dev.codonic.oarbank.oarbankd", 0, LAUNCHCTL, "owner") == {
        "name": "dev.codonic.oarbank.oarbankd", "installed": True, "state": "running", "start": "at login",
        "account": "owner", "pid": 4242}
    assert service.parse_launchctl("x", 113, "Could not find service", "owner")["installed"] is False
    assert service.parse_systemctl("dev.codonic.oarbank.console", SYSTEMCTL, "owner") == {
        "name": "dev.codonic.oarbank.console", "installed": True, "state": "active (running)", "start": "enabled",
        "account": "owner", "pid": 777}
    gone = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nMainPID=0\n"
    assert service.parse_systemctl("x", gone, "owner")["installed"] is False


def test_the_host_document_names_the_platform_the_services_and_the_sandbox(tmp_path):
    db = make_db(tmp_path / "oarbank.sqlite3", modules=())
    h = hostinfo.refresh(db)
    assert h["platform"] == portable.host_platform() and h["manager"] == service.manager()
    assert [s["name"] for s in h["services"]] == list(service.SERVICES) and h["pid"] == os.getpid()
    assert h["managed"] is False                                  # the suite is no service of anything
    assert h["sandbox"]["backend"] and ("helper" in h["sandbox"]) == (sys.platform == "win32")
    assert db.get_state(hostinfo.SETTING)["at"] == h["at"]


def test_the_api_the_cli_and_the_console_show_it(tmp_path):
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from test_console import SECRET, Server
    db = make_db(tmp_path / "oarbank.sqlite3", modules=())
    api = TestClient(coord_app.admin_app(db), headers=admin_headers(db))
    host = api.get("/api/v1/coordinator").json()["host"]
    assert host["platform"] == portable.host_platform() and len(host["services"]) == 2
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        env = {**os.environ, "OARBANKD_URL": f"http://127.0.0.1:{oarbankd.port}",
               "OARBANK_TOKEN": admin_headers(db)["authorization"].split()[1]}
        out = subprocess.run([sys.executable, "-m", "oarbank.cli.main", "coordinator", "status"], env=env,
                             capture_output=True, text=True, timeout=60)
        assert out.returncode == 0, out.stderr
        assert f"platform {portable.host_platform()}  {service.manager()}" in out.stdout
        assert "(not run by the service manager)" in out.stdout and "dev.codonic.oarbank.console" in out.stdout
        state = ConsoleState(tmp_path / "oarbank.sqlite3", f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        with TestClient(console_app(state), client=("127.0.0.1", 50001)) as c:
            sign_in(c, db)
            page = c.get("/coordinator").text
    assert "Where it runs" in page and portable.host_platform() in page and "dev.codonic.oarbank.oarbankd" in page
    assert "not run by the service manager" in page


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows service control manager")
def test_the_scm_reports_a_service_s_state_start_type_and_account():
    """A service every Windows machine has: the event log, automatic, running, as LocalService."""
    s = service.state("EventLog")
    assert s["installed"] and s["state"] == "running" and s["start"].startswith("automatic") and s["pid"]
    assert s["account"].lower().endswith("localservice")
    assert service.state("oarbank-no-such-service")["installed"] is False
