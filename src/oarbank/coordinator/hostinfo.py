"""Where and how this coordinator runs, for the Coordinator page and `oarbank coordinator status`: its platform, what its
service manager says about the coordinator's services (launchd, systemd or the Windows service control manager:
installed, state, start type, account, process), whether this process is the one the manager runs, and its module
sandbox, on Windows with the elevated helper module CLIs need (docs/design/windows-coordinator.md).

oarbankd takes it at start and whenever the admin API is asked for the coordinator's status, and keeps the last one in
the setting `coordinator_host`, which the console (a separate, read-only process) shows with its time.
"""
import os
import time

from .db import DB

SETTING = "coordinator_host"


def refresh(db: DB) -> dict:
    from oarbank_sdk import portable
    from ..platform import service
    from . import sandboxexec
    services = [service.state(n) for n in service.SERVICES]
    sandbox = {"backend": sandboxexec.backend()}
    if service.manager() == "windows-service":
        helper = service.state(service.HELPER)
        sandbox["helper"] = {**helper, "allowlist": "enforced" if sandboxexec.enforced("net.egress-allowlist") else "unavailable"}
    doc = {"platform": portable.host_platform(), "manager": service.manager(), "pid": os.getpid(),
           "managed": any(s["pid"] == os.getpid() for s in services), "services": services, "sandbox": sandbox,
           "at": time.time()}
    db.set_state(SETTING, doc)
    return doc
