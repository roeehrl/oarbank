"""Run oarbank-console: python -m oarbank.console [--port 7400] [--oarbankd http://127.0.0.1:7401]."""
import argparse
import asyncio
import os
import sys
from pathlib import Path

import uvicorn

from .app import console_app
from .frames import frames_app
from .state import ConsoleState, Reader, wait_for_schema


def main():
    from ..coordinator import config as C
    home = C.HOME
    ap = argparse.ArgumentParser(prog="oarbank-console")
    ap.add_argument("--bind", default=C.CONSOLE_BIND)
    ap.add_argument("--port", type=int, default=C.CONSOLE_PORT)
    ap.add_argument("--db", default=str(home / "oarbank.sqlite3"))
    ap.add_argument("--oarbankd", default=os.environ.get("OARBANKD_ADMIN_URL", "http://127.0.0.1:7401"))
    ap.add_argument("--secret-file", default=str(home / "console.secret"))
    ap.add_argument("--frames-port", type=int, default=int(os.environ.get("OARBANKD_FRAMES_PORT", "7402")),
                    help="the module origin for sandboxed module frames (a separate origin from the console)")
    ap.add_argument("--module-origin", default=os.environ.get("OARBANKD_MODULE_ORIGIN"),
                    help="public origin of the frames listener (default http://127.0.0.1:<frames-port>)")
    ap.add_argument("--console-origin", default=os.environ.get("OARBANKD_CONSOLE_ORIGIN"),
                    help="public origin of the console (frame-ancestors); default http://127.0.0.1:<port>")
    ap.add_argument("--service", action="store_true",
                    help="run as a Windows service (the service control manager starts it so: platform/service.py)")
    a = ap.parse_args()
    if a.service:
        if sys.platform != "win32":
            ap.error("--service is for the Windows service control manager; launchd and systemd run the console as it is")
        from ..platform import service
        return service.run(lambda: run(a, home), stop_servers)
    return run(a, home)


_SERVERS: list = []           # the uvicorn servers of this process, for a stop from the service manager


def stop_servers():
    for s in _SERVERS:
        s.should_exit = True


def run(a, home):
    from ..platform import service
    service.log_to(home / "logs" / "console.log")
    wait_for_schema(a.db)
    state = ConsoleState(a.db, a.oarbankd, secret_path=a.secret_file).start()
    module_origin = a.module_origin or f"http://127.0.0.1:{a.frames_port}"
    console_origin = a.console_origin or f"http://127.0.0.1:{a.port}"
    app = console_app(state, home / "attempt-logs", module_origin=module_origin)
    frames = frames_app(app.state.catalog, console_origin, refresh=app.state.refresh_catalog_sync, tokens=app.state.media_tokens,
                        reader=Reader(a.db), home=Path(a.db).parent)

    async def serve():
        _SERVERS[:] = [uvicorn.Server(uvicorn.Config(app, host=a.bind, port=a.port, log_level="warning", access_log=False)),
                       uvicorn.Server(uvicorn.Config(frames, host=a.bind, port=a.frames_port, log_level="warning", access_log=False))]
        await asyncio.gather(*(s.serve() for s in _SERVERS))
    asyncio.run(serve())


if __name__ == "__main__":
    main()
