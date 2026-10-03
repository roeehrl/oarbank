"""Run oarbank-console: python -m oarbank.console [--port 7400] [--oarbankd http://127.0.0.1:7401]."""
import argparse
import asyncio
import os

import uvicorn

from .app import console_app
from .frames import frames_app
from .state import ConsoleState, wait_for_schema


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
    a = ap.parse_args()
    wait_for_schema(a.db)
    state = ConsoleState(a.db, a.oarbankd, secret_path=a.secret_file).start()
    module_origin = a.module_origin or f"http://127.0.0.1:{a.frames_port}"
    console_origin = a.console_origin or f"http://127.0.0.1:{a.port}"
    app = console_app(state, home / "attempt-logs", module_origin=module_origin)
    frames = frames_app(app.state.catalog, console_origin, refresh=app.state.refresh_catalog_sync)

    async def serve():
        await asyncio.gather(
            uvicorn.Server(uvicorn.Config(app, host=a.bind, port=a.port, log_level="warning", access_log=False)).serve(),
            uvicorn.Server(uvicorn.Config(frames, host=a.bind, port=a.frames_port, log_level="warning", access_log=False)).serve())
    asyncio.run(serve())


if __name__ == "__main__":
    main()
