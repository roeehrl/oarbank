"""Run oarbank-console: python -m oarbank.console [--port 7400] [--oarbankd http://127.0.0.1:7401]."""
import argparse
import asyncio
import os
import sys
from pathlib import Path

from .app import console_app
from .frames import frames_app
from .state import ConsoleState, Reader, wait_for_schema


def main():
    from ..coordinator import config as C
    home = C.HOME
    ap = argparse.ArgumentParser(prog="oarbank-console")
    ap.add_argument("--bind", default=C.CONSOLE_BIND,
                    help="listen targets added to the setting console_listen (comma-separated: localhost, tailscale, all "
                         "or IP addresses); the setting is the place to choose them (Settings → Access)")
    ap.add_argument("--port", type=int, default=C.CONSOLE_PORT)
    ap.add_argument("--db", default=str(home / "oarbank.sqlite3"))
    ap.add_argument("--oarbankd", default=os.environ.get("OARBANKD_ADMIN_URL", "http://127.0.0.1:7401"))
    ap.add_argument("--secret-file", default=str(home / "console.secret"))
    ap.add_argument("--frames-port", type=int, default=int(os.environ.get("OARBANKD_FRAMES_PORT", "7402")),
                    help="the module origin for sandboxed module frames (a separate origin from the console)")
    ap.add_argument("--module-origin", default=os.environ.get("OARBANKD_MODULE_ORIGIN"),
                    help="public origin of the frames listener (default: the host the console was opened at, on <frames-port>)")
    ap.add_argument("--console-origin", default=os.environ.get("OARBANKD_CONSOLE_ORIGIN"),
                    help="public origin of the console (frame-ancestors); default: the host the frame was opened at, on <port>")
    ap.add_argument("--service", action="store_true",
                    help="run as a Windows service (the service control manager starts it so: platform/service.py)")
    a = ap.parse_args()
    if a.service:
        if sys.platform != "win32":
            ap.error("--service is for the Windows service control manager; launchd and systemd run the console as it is")
        from ..platform import service
        return service.run(lambda: run(a, home), stop_servers)
    return run(a, home)


_LISTENERS: list = []         # this process's Listeners, for a stop from the service manager


def stop_servers():
    for x in _LISTENERS:
        x.stop()


def origins(a, https_name=lambda: None) -> tuple:
    """(module origin, console origin) for a request: fixed when --module-origin / --console-origin (or their
    environment variables) say so; through the console's https name (setting console_https: tailscale serve terminates
    TLS on 443 for the console and 8443 for the frames) the https origins; else the host the browser used, on the other
    listener's port (consolelisten.other_origin)."""
    from ..coordinator import consolelisten as L
    module_default, console_default = f"http://127.0.0.1:{a.frames_port}", f"http://127.0.0.1:{a.port}"

    def via_https(request, port):
        n = https_name()
        if not n or getattr(getattr(request, "url", None), "scheme", "http") != "https":
            return False
        host, p = L.split_host(request.headers.get("host"))
        return host == n and (p or 443) == port

    def module(request):
        if a.module_origin:
            return a.module_origin
        if via_https(request, L.CONSOLE_HTTPS_PORT):
            return L.https_origin(https_name(), L.FRAMES_HTTPS_PORT)
        return L.other_origin(request.headers.get("host"), a.port, a.frames_port, module_default)

    def console(request):
        if a.console_origin:
            return a.console_origin
        if via_https(request, L.FRAMES_HTTPS_PORT):
            return L.https_origin(https_name(), L.CONSOLE_HTTPS_PORT)
        return L.other_origin(request.headers.get("host"), a.frames_port, a.port, console_default)
    return module, console


def run(a, home):
    from ..coordinator.settings.store import fleet_value
    from ..platform import service
    from .serve import HttpsServe, Listeners, install_signals
    service.log_to(home / "logs" / "console.log")
    wait_for_schema(a.db)
    state = ConsoleState(a.db, a.oarbankd, secret_path=a.secret_file).start()
    listen = {}
    module_origin, console_origin = origins(a, https_name=lambda: listen["x"].https_name() if listen.get("x") else None)
    app = console_app(state, home / "attempt-logs", module_origin=module_origin, listening=lambda: listen.get("x"))
    extra_hosts = [h for h in [(a.module_origin or "").split("://", 1)[-1].split("/", 1)[0]] if h]
    frames = frames_app(app.state.catalog, console_origin, refresh=app.state.refresh_catalog_sync, tokens=app.state.media_tokens,
                        reader=Reader(a.db), home=Path(a.db).parent, listening=lambda: listen.get("x"),
                        extra_hosts=extra_hosts)
    extra = [("all" if x.strip() in ("0.0.0.0", "::") else x.strip()) for x in (a.bind or "").split(",")
             if x.strip() and x.strip() != "127.0.0.1"]          # the legacy single address, now an extra target
    https = HttpsServe(lambda: fleet_value(state.reader, "console_https"), a.port, a.frames_port)
    listeners = Listeners({"console": (app, a.port), "frames": (frames, a.frames_port)},
                          targets=lambda: fleet_value(state.reader, "console_listen"), extra=extra, https=https)
    listen["x"] = listeners
    _LISTENERS[:] = [listeners]
    install_signals(listeners.stop)

    async def serve():
        async with app.router.lifespan_context(app):
            await listeners.run()
    asyncio.run(serve())


if __name__ == "__main__":
    main()
