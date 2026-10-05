"""The local admin channel: oarbankd's admin API on <home>/run/admin.sock, whose owner-only directory is the
credential (a named pipe with an owner-only security descriptor on Windows); the CLI on the coordinator's own account
uses it without a token. The TCP listener still needs one."""
import os
import subprocess
import sys
from pathlib import Path

import httpx


def test_cli_uses_the_owner_only_channel(coordinator):
    from oarbank.platform import files, localchannel
    assert localchannel.reachable(coordinator.home)
    if os.name == "posix":
        assert files.owner_only(Path(localchannel.address(coordinator.home)).parent)
    else:                                       # the pipe's own descriptor admits only the trusted accounts
        import msvcrt
        from oarbank.platform import _win32 as W
        with open(localchannel.address(coordinator.home), "r+b", buffering=0) as pipe:
            sddl = W.dacl_sddl(handle=msvcrt.get_osfhandle(pipe.fileno()))
            sids = W.allowed_sids(handle=msvcrt.get_osfhandle(pipe.fileno()))
        assert sddl.startswith("D:P") and W.current_user_sid() in sids and sids <= set(files.trusted_sids()) | {
            files.service_sid(n) for n in files.COORDINATOR_SERVICES}, sddl
    env = {k: v for k, v in os.environ.items() if k not in ("OARBANKD_URL", "OARBANK_TOKEN")}
    env.update(OARBANKD_HOME=str(coordinator.home))
    r = subprocess.run([sys.executable, "-m", "oarbank.cli.main", "fleet"], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-2000:]
    with httpx.Client(transport=localchannel.transport(coordinator.home), base_url="http://oarbank") as c:
        assert c.get("/api/v1/fleet").status_code == 200
    assert httpx.get(f"{coordinator.admin}/api/v1/fleet").status_code == 401        # TCP: a credential is still required
