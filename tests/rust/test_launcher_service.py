"""`oarbank-launcher service`: the service definitions it would install (dry run only; tests never load services), and
how `run` keeps the agent going."""
import os
import plistlib
import shutil
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
import agentbin  # noqa: E402
from agentbin import EXE  # noqa: E402
from conftest import CARGO, REPO  # noqa: E402

LAUNCHER = REPO / "rust" / "target" / "debug" / f"oarbank-launcher{EXE}"


@pytest.fixture(scope="module")
def launcher():
    if not os.path.exists(CARGO):
        pytest.skip("no Rust toolchain")
    r = subprocess.run([CARGO, "build", "-q", "-p", "oarbank-launcher"], cwd=REPO / "rust", env=agentbin.cargo_env(),
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-3000:]
    return LAUNCHER


def run(launcher, *args):
    r = subprocess.run([str(launcher), *args], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


macos = pytest.mark.skipif(sys.platform != "darwin", reason="launchd")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="systemd")
windows = pytest.mark.skipif(sys.platform != "win32", reason="the Windows service manager")


@macos
def test_user_agent_definition(launcher, tmp_path):
    out = run(launcher, "--home", str(tmp_path / "a b"), "service", "install", "--label", "dev.example.test", "--dry-run",
              "--", "--coordinator", "https://c.example:7443")
    head, body = out.split("\n", 1)
    assert head.endswith("Library/LaunchAgents/dev.example.test.plist")
    xml = body[:body.index("</plist>") + len("</plist>")]
    p = plistlib.loads(xml.encode())
    assert p["Label"] == "dev.example.test" and p["KeepAlive"] is True and p["ProcessType"] == "Standard"
    assert p["ProgramArguments"][1:] == ["--home", str(tmp_path / "a b"), "run", "--coordinator", "https://c.example:7443"]
    assert p["StandardOutPath"] == str(tmp_path / "a b" / "logs" / "launcher.log") and "UserName" not in p
    assert f"launchctl bootstrap gui/{os.getuid()} " in out
    if shutil.which("plutil"):
        f = tmp_path / "x.plist"
        f.write_text(xml)
        assert subprocess.run(["plutil", "-lint", str(f)], capture_output=True).returncode == 0


@macos
def test_system_daemon_runs_as_the_named_user(launcher, tmp_path):
    out = run(launcher, "--home", str(tmp_path), "service", "install", "--system", "--user", "oarbank", "--dry-run")
    assert out.startswith("# /Library/LaunchDaemons/dev.codonic.oarbank.agent.plist")
    assert "<key>UserName</key><string>oarbank</string>" in out and "launchctl bootstrap system " in out
    out = run(launcher, "--home", str(tmp_path), "service", "uninstall", "--system", "--dry-run")
    assert "launchctl bootout system/dev.codonic.oarbank.agent" in out


def test_bad_label_is_refused(launcher, tmp_path):
    r = subprocess.run([str(launcher), "--home", str(tmp_path), "service", "install", "--label", "x/../y", "--dry-run"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "bad label" in r.stderr


@linux
def test_systemd_units(launcher, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    out = run(launcher, "--home", str(tmp_path / "a b"), "service", "install", "--label", "dev.example.test", "--dry-run",
              "--", "--coordinator", "https://c.example:7443")
    assert out.startswith(f"# {tmp_path}/cfg/systemd/user/dev.example.test.service")
    assert f'ExecStart="{LAUNCHER}" "--home" "{tmp_path / "a b"}" "run" "--coordinator" "https://c.example:7443"' in out
    assert "Restart=always" in out and "Delegate=yes" in out and "WantedBy=default.target" in out and "User=" not in out
    assert "systemctl --user enable --now dev.example.test.service" in out
    out = run(launcher, "--home", str(tmp_path), "service", "install", "--system", "--user", "oarbank", "--dry-run")
    assert out.startswith("# /etc/systemd/system/dev.codonic.oarbank.agent.service") and "User=oarbank" in out
    assert "WantedBy=multi-user.target" in out and "systemctl enable --now" in out


@windows
def test_windows_services_start_delayed_and_recover_from_any_failure(launcher, tmp_path):
    # after a cold boot the agent's service sat Stopped: it must start by itself and be restarted when it stops with an
    # error, not only when it crashes
    out = run(launcher, "--home", str(tmp_path), "service", "install", "--system", "--dry-run")
    assert "sc.exe create dev.codonic.oarbank.agent " in out and " start= delayed-auto " in out
    assert "sc.exe failure dev.codonic.oarbank.agent reset= 86400 actions= restart/10000/restart/10000/restart/60000" in out
    assert "sc.exe failureflag dev.codonic.oarbank.agent 1" in out
    assert out.index("sc.exe failureflag") < out.index("sc.exe start")
    out = run(launcher, "helper-config", "--dry-run")                     # the MSI runs it for the helper's service
    assert out.splitlines() == ["sc.exe config OarbankHelper start= delayed-auto",
                                "sc.exe failure OarbankHelper reset= 86400 actions= restart/10000/restart/10000/restart/60000",
                                "sc.exe failureflag OarbankHelper 1"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_run_retries_an_agent_that_cannot_start_and_stops_at_once(launcher, tmp_path):
    # a start failure (at boot: a file still locked, a disk not ready) ended `run`, and with it the service
    r = subprocess.run([str(launcher), "--home", str(tmp_path / "empty"), "run"], capture_output=True, text=True)
    assert r.returncode != 0 and "install a version first" in r.stderr     # nothing installed: no point retrying
    version = tmp_path / "home" / "versions" / "1.0.0-x"
    version.mkdir(parents=True)
    (version / "oarbank-agent").write_text("not a program\n")             # there, but it cannot be started
    (tmp_path / "home" / "current").symlink_to("versions/1.0.0-x/oarbank-agent")
    p = subprocess.Popen([str(launcher), "--home", str(tmp_path / "home"), "run"], stderr=subprocess.PIPE, text=True)
    time.sleep(2.5)                                                         # tries at 0 s and 1 s, then waits 2 s
    assert p.poll() is None, p.stderr.read()
    p.terminate()
    t0 = time.monotonic()
    assert p.wait(timeout=10) == 0 and time.monotonic() - t0 < 2           # the backoff wait ends at a stop
    assert p.stderr.read().count("could not start the agent") >= 2
