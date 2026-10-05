"""Discovery is a hint: an active coordinator announces itself (on a test-only service type here) and
`oarbank-agent discover` finds its URL and fleet id."""
import json
import os
import secrets
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import Coordinator  # noqa: E402
from test_agent_session import wait  # noqa: E402


@pytest.mark.skipif(sys.platform.startswith("linux") and not shutil.which("avahi-publish-service"),
                    reason="Linux announces and browses through Avahi, which is not installed")
def test_agent_finds_the_announcing_coordinator(agent_bin, tmp_path):
    ty = f"_oarbt{secrets.token_hex(3)}._tcp"
    home = tmp_path / "c"
    home.mkdir()
    with Coordinator(home, extra_env={"OARBANKD_DISCOVERY": "1", "OARBANK_DISCOVERY_TYPE": ty}) as c:
        fleet = c.api("GET", "/api/v1/coordinator")["fleet_id"]
        env = {**os.environ, "OARBANK_DISCOVERY_TYPE": ty}
        found = wait(lambda: json.loads(subprocess.run([str(agent_bin), "--home", str(tmp_path / "a"), "discover", "--wait", "2"],
                                                       env=env, capture_output=True, text=True).stdout or "[]"), timeout=30)
        assert len(found) == 1
        assert found[0]["url"].endswith(f":{c.agent_port}") and found[0]["fleet_id"] == fleet


@pytest.mark.skipif(sys.platform.startswith("linux") and not shutil.which("avahi-publish-service"),
                    reason="Linux announces and browses through Avahi, which is not installed")
def test_a_killed_coordinator_stops_announcing_itself(agent_bin, tmp_path):
    # the announcement belongs to the coordinator's process (on macOS a `dns-sd -R` child went on announcing a killed
    # coordinator, for as long as the machine ran)
    ty = f"_oarbt{secrets.token_hex(3)}._tcp"
    home = tmp_path / "c"
    home.mkdir()
    env = {**os.environ, "OARBANK_DISCOVERY_TYPE": ty}

    def found():
        return json.loads(subprocess.run([str(agent_bin), "--home", str(tmp_path / "a"), "discover", "--wait", "2"],
                                         env=env, capture_output=True, text=True).stdout or "[]")
    with Coordinator(home, extra_env={"OARBANKD_DISCOVERY": "1", "OARBANK_DISCOVERY_TYPE": ty}) as c:
        assert wait(found, timeout=30)
        c.proc.kill()
        c.proc.wait(30)
        assert wait(lambda: found() == [], timeout=30), "the killed coordinator is still announced"


@pytest.mark.skipif(sys.platform != "darwin", reason="Local Network privacy is macOS's")
def test_the_agent_and_the_launcher_carry_their_local_network_usage(agent_bin):
    # built as the packages build them: the Info.plist embedded in each binary (__TEXT,__info_plist)
    import plistlib
    for b in (agent_bin, agent_bin.with_name("oarbank-launcher")):
        out = subprocess.run(["/usr/bin/otool", "-X", "-s", "__TEXT", "__info_plist", str(b)], capture_output=True, text=True)
        # otool prints the section as little-endian 32-bit words after each address
        raw = b"".join(bytes.fromhex(w)[::-1] for line in out.stdout.splitlines() for w in line.split()[1:])
        info = plistlib.loads(raw.rstrip(b"\0"))
        assert info["NSBonjourServices"] == ["_oarbank._tcp"] and info["NSLocalNetworkUsageDescription"], b
