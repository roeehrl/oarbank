"""The local admin channel: oarbankd's admin API on <home>/run/admin.sock, whose owner-only directory is the
credential; the CLI on the coordinator's own account uses it without a token. The TCP listener still needs one."""
import os
import stat
import subprocess
import sys

import httpx


def test_cli_uses_the_owner_only_socket(coordinator):
    from oarbank.paths import runtime_socket
    sock = runtime_socket(coordinator.home, "admin.sock")
    assert sock.exists() and stat.S_IMODE(sock.parent.stat().st_mode) == 0o700
    env = {k: v for k, v in os.environ.items() if k not in ("OARBANKD_URL", "OARBANK_TOKEN")}
    env.update(OARBANKD_HOME=str(coordinator.home))
    r = subprocess.run([sys.executable, "-m", "oarbank.cli.main", "fleet"], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-2000:]
    with httpx.Client(transport=httpx.HTTPTransport(uds=str(sock)), base_url="http://oarbank") as c:
        assert c.get("/api/v1/fleet").status_code == 200
    assert httpx.get(f"{coordinator.admin}/api/v1/fleet").status_code == 401        # TCP: a credential is still required
