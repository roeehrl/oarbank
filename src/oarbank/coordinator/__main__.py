"""Run oarbankd: agent API + admin API (loopback) in one process, plus the reaper/campaign/discovery loops.
Pages are served by the separate oarbank-console process (python -m oarbank.console)."""
import argparse
import asyncio
import os
import secrets
import threading
import time

import uvicorn

from . import config as C
from .app import EventBus, admin_app, agent_app, background, campaign_loop
from .db import DB


def main():
    ap = argparse.ArgumentParser(prog="oarbankd")
    ap.add_argument("--agent-bind", default=C.AGENT_BIND, help="the agent listener's address: an interface the nodes reach")
    ap.add_argument("--agent-port", type=int, default=C.AGENT_PORT, help="the TLS agent listener (client certificates)")
    ap.add_argument("--admin-bind", default=C.ADMIN_BIND)
    ap.add_argument("--admin-port", type=int, default=C.ADMIN_PORT)
    ap.add_argument("--standby", action="store_true", help="start as a move target (docs/design/coordinator-move.md)")
    ap.add_argument("--pair", help="the pairing code from coordinator.prepare on the old coordinator")
    ap.add_argument("--from", dest="from_url", help="the old coordinator's agent URL, e.g. https://100.64.0.10:7443")
    ap.add_argument("--from-ca", dest="from_ca", help="the old coordinator's TLS CA pin (SPKI SHA-256; coordinator.prepare prints it)")
    ap.add_argument("--url", help="this coordinator's agent URL as agents reach it (default http://<agent-bind>:<agent-port>)")
    ap.add_argument("--archive-home", action="store_true",
                    help="with --standby: move an existing home aside first (a reverse move back to this machine)")
    a = ap.parse_args()
    os.umask(0o077)                           # every file oarbankd creates is owner-only
    my_url = (a.url or f"https://{a.agent_bind}:{a.agent_port}").rstrip("/")

    if (C.HOME / "FINALIZED").exists():
        print(f"oarbankd: {C.HOME} was finalized after a coordinator move; not starting (remove FINALIZED to override)")
        return
    if a.standby and a.archive_home and C.DB_PATH.exists():
        dest = C.HOME.with_name(C.HOME.name + "-archive-" + time.strftime("%Y%m%d-%H%M%S"))
        C.HOME.rename(dest)
        print(f"oarbankd: archived the old home to {dest}")
    from ..platform import files
    files.private_dir(C.HOME)
    tightened = files.tighten_home(C.HOME)
    from . import access, identity, movepull
    access.ensure_admin_token(C.HOME)
    mstate = movepull.load(C.HOME)
    if a.standby and C.DB_PATH.exists() and not mstate and DB(C.DB_PATH).one("SELECT COUNT(*) n FROM nodes")["n"]:
        raise SystemExit(f"oarbankd: {C.HOME} holds a coordinator; a standby starts empty (add --archive-home)")
    db = DB(C.DB_PATH)
    identity.ensure(db)
    completed_move = movepull.finish_install(db, C.HOME)
    puller = None
    if not completed_move and (a.standby or mstate.get("phase") in ("paired", "seeding", "seeded", "ready", "promoting")):
        if identity.role(db) == "active" and not db.one("SELECT COUNT(*) n FROM nodes")["n"]:
            identity.set_role(db, "standby")
        from . import tlsca as standby_tls
        standby_tls.ensure_ca(C.HOME, identity.fleet_id(db))      # the standby's own CA until the move brings the fleet's
        puller = movepull.Puller(db, C.HOME, from_url=a.from_url, code=a.pair, my_url=my_url, from_ca=a.from_ca)
        threading.Thread(target=puller.run, daemon=True, name="oarbankd-standby").start()
    elif identity.role(db) == "active" and not db.get_setting("coordinator_url"):
        db.set_setting("coordinator_url", my_url)
    from . import modcalls, modlife
    modlife.runtimes_ok(db)                   # module venvs an earlier coordinator build made run on its interpreter
    modcalls.use(db)                          # the module catalog comes from the store (oarbank module install)
    if tightened:
        db.event("home_tightened", reason=f"{len(tightened)} paths made owner-only")
    secret = secrets.token_hex(24)
    files.write_private(C.CONSOLE_SECRET_PATH, secret)
    bus = EventBus()
    db.event_listeners.append(bus.notify)
    # A coordinator restart must not mass-expire healthy work: extend live leases by the outage.
    last = db.get_setting("alive_at") or db.one("SELECT MAX(ts) m FROM events")["m"]
    if last:
        outage = max(0.0, time.time() - last)
        n = db.one("SELECT COUNT(*) n FROM attempts WHERE state='live'")["n"]
        db.x("UPDATE attempts SET expires_at=expires_at+?, hard_deadline=hard_deadline+? WHERE state='live'",
             (outage + C.LEASE_TTL, outage))
        if n:
            db.event("leases_extended", reason=f"{n} live attempts extended by {outage:.0f}s after restart")
    stop = threading.Event()
    threading.Thread(target=background, args=(db, stop), daemon=True, name="oarbankd-bg").start()
    threading.Thread(target=campaign_loop, args=(db, stop), daemon=True, name="oarbankd-campaigns").start()

    from . import tlsca
    from .tlsproto import PeerCertH11
    tlsca.ensure_ca(C.HOME, identity.fleet_id(db))
    import socket
    from urllib.parse import urlsplit
    names = [a.agent_bind, socket.gethostname(), urlsplit(my_url).hostname or "",
             urlsplit(db.get_setting("coordinator_url") or "").hostname or ""]
    ssl_opts = tlsca.server_context(C.HOME, names)
    from . import discovery
    announce = discovery.advertise(identity.fleet_id(db), a.agent_port, tlsca.pins(C.HOME)["ca_spki_sha256"], a.agent_bind) \
        if identity.role(db) == "active" else None

    async def serve():
        bus.bind(asyncio.get_running_loop())
        agent = uvicorn.Server(uvicorn.Config(agent_app(db, puller), host=a.agent_bind, port=a.agent_port, http=PeerCertH11,
                                              log_level="warning", access_log=False, **ssl_opts))
        servers = [agent.serve()]
        admin = uvicorn.Server(uvicorn.Config(admin_app(db, bus, console_secret=secret), host=a.admin_bind,
                                              port=a.admin_port, log_level="warning", access_log=False))
        from ..paths import runtime_socket
        files.private_dir(C.HOME / "run")
        sock = runtime_socket(C.HOME, "admin.sock")
        sock.unlink(missing_ok=True)
        local = uvicorn.Server(uvicorn.Config(admin_app(db, bus, console_secret=secret, local_socket=True), uds=str(sock),
                                              log_level="warning", access_log=False))
        servers.append(local.serve())
        db.event("coordinator_started", reason=f"agent https://{a.agent_bind}:{a.agent_port} admin {a.admin_bind}:{a.admin_port}")
        await asyncio.gather(*servers, admin.serve())

    try:
        asyncio.run(serve())
    finally:
        stop.set()
        if announce:
            announce.terminate()


if __name__ == "__main__":
    main()
