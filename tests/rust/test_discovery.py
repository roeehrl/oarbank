"""Discovery is a hint: an active coordinator announces itself (on a test-only service type here) and
`oarbank-agent discover` finds its URL and fleet id."""
import json
import os
import secrets
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import Coordinator  # noqa: E402
from test_agent_session import wait  # noqa: E402


@pytest.mark.skipif(sys.platform != "darwin", reason="the system responder (dns-sd)")
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
