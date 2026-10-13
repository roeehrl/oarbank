"""The console process's listeners (setting `console_listen`; coordinator/consolelisten.py).

One uvicorn server per (listener, address): the console and the module origin each listen on every address the setting
resolves to. A supervisor re-reads the setting every few seconds (and this machine's Tailscale addresses every 30 s),
starts the servers for new addresses and stops the ones for addresses that left, so the owner changes where the console
listens from Settings or `oarbank settings set console_listen ...` with no service file edited and no restart, on
launchd, systemd and the Windows service alike. An address that cannot be bound now (Tailscale not up yet at boot) is
retried at the next pass; the first pass ends the process when it cannot bind the console on localhost (the service
manager restarts it, as before).

The apps' lifespan runs once, around the supervisor (each server runs with lifespan off), and the servers install no
signal handlers of their own: SIGINT and SIGTERM (or the Windows service manager's stop) stop the supervisor, which
stops every server."""
import asyncio
import contextlib
import os
import signal
import socket
import sys
import threading
import time
from typing import Any, Callable

import uvicorn

from ..coordinator import consolelisten as L

POLL_S = 5.0
TAILSCALE_S = 30.0
GRACE_S = 3                       # an open stream (SSE) on an address that leaves gets this long to end


def log(msg: str):
    print(f"oarbank-console: {msg}", file=sys.stderr, flush=True)


class _Server(uvicorn.Server):
    """A uvicorn server that leaves signals to the supervisor (several servers start and stop in one process)."""

    def capture_signals(self):
        return contextlib.nullcontext()

    def install_signal_handlers(self):            # uvicorn before capture_signals
        pass


def bind_socket(addr: str, port: int) -> socket.socket:
    """A TCP socket bound to exactly `addr` (IPv6 only for an IPv6 address: never the IPv4 side too)."""
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    try:
        if os.name == "nt":
            with contextlib.suppress(AttributeError):         # no other process may take over the port
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if fam == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.bind((addr, port))
    except OSError:
        s.close()
        raise
    return s


def tailscale_cli(args: list[str], timeout: float = 20.0) -> tuple[int, str]:
    """Run this machine's `tailscale` CLI: (exit code, output); 127 when it cannot be run."""
    import subprocess
    from ..coordinator import config as C
    cmd = [C.TAILSCALE] + (["--socket", C.TAILSCALE_SOCKET] if C.TAILSCALE_SOCKET else []) + list(args)
    try:
        out = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        return 127, f"{type(e).__name__}: {e}"
    return out.returncode, (out.stdout or "") + (out.stderr or "")


class HttpsServe:
    """Setting `console_https` (coordinator/consolelisten.py): keeps `tailscale serve` proxying https://<MagicDNS name>/
    to the console and :8443 to the module origin while it is `tailscale`, and removes those two entries when it turns
    off while this process watches (an entry Oarbank did not make, pointing elsewhere, is never touched). What it cannot
    do itself (the service account is not Tailscale's operator on Linux, HTTPS certificates off in the tailnet) it
    reports with the commands for the owner to run once. `cli(args) -> (code, output)` is injected in tests."""

    def __init__(self, mode: Callable[[], Any], console_port: int, frames_port: int, cli: Callable = tailscale_cli,
                 every_s: float = TAILSCALE_S, clock: Callable[[], float] = time.monotonic):
        self.mode_of, self.cli, self.every_s, self.clock = mode, cli, every_s, clock
        self.wanted = L.serve_wanted(console_port, frames_port)
        self.mode, self.name, self.error, self.commands = L.HTTPS_OFF, None, None, []
        self.served = self.frames_served = False
        self._at, self._last_mode = float("-inf"), None

    def _json(self, args):
        import json
        code, out = self.cli(args)
        if code:
            return None
        try:
            return json.loads(out or "{}")
        except ValueError:
            return None

    def _cmd(self, args) -> str:
        import shlex
        from ..coordinator import config as C
        return shlex.join([C.TAILSCALE, *args])

    def check(self):
        """One pass (blocking: run it in a thread)."""
        try:
            mode = self.mode_of() or L.HTTPS_OFF
        except Exception:
            mode = self.mode
        was, self.mode = self._last_mode, mode
        self._last_mode = mode
        self.error, self.commands = None, []
        self.name = L.magicdns_name(self._json(["status", "--json"]))
        if not self.name:
            self.served = self.frames_served = False
            if mode == L.HTTPS_TAILSCALE:
                self.error = "Tailscale is not running or signed in on this machine, or MagicDNS is off: no host name"
            return
        cur = L.serve_targets(self._json(["serve", "status", "--json"]), self.name)
        if mode == L.HTTPS_TAILSCALE:
            for (port, target), args in zip(self.wanted.items(), L.serve_commands(self.wanted, True)):
                if L.same_target(cur.get(port), target):
                    continue
                if cur.get(port):
                    self.error = (f"https://{self.name}:{port}/ already serves {cur[port]} (set outside Oarbank): free that "
                                  f"port (tailscale serve --https={port} off) or leave console_https off")
                    break
                code, out = self.cli(args)
                if code:
                    self.error = f"tailscale serve failed: {out.strip()[:300] or f'exit {code}'}"
                    self.commands = [self._cmd(a) for a in L.serve_commands(self.wanted, True)]
                    break
                log(f"https: https://{self.name}:{port}/ -> {target} (tailscale serve)")
            cur = L.serve_targets(self._json(["serve", "status", "--json"]), self.name) if not self.error else cur
        elif was == L.HTTPS_TAILSCALE:                         # turned off while we watch: remove our two entries only
            for (port, target), args in zip(self.wanted.items(), L.serve_commands(self.wanted, False)):
                if L.same_target(cur.get(port), target):
                    code, out = self.cli(args)
                    if code:
                        self.error = f"tailscale serve could not remove https port {port}: {out.strip()[:300]}"
                        self.commands = [self._cmd(a) for a in L.serve_commands(self.wanted, False)]
                    else:
                        cur[port] = None
                        log(f"https: removed https://{self.name}:{port}/ (tailscale serve)")
        self.served = L.same_target(cur.get(L.CONSOLE_HTTPS_PORT), self.wanted[L.CONSOLE_HTTPS_PORT])
        self.frames_served = L.same_target(cur.get(L.FRAMES_HTTPS_PORT), self.wanted[L.FRAMES_HTTPS_PORT])

    async def reconcile(self, force: bool = False):
        try:
            mode = self.mode_of() or L.HTTPS_OFF
        except Exception:
            mode = self.mode
        if force or mode != self._last_mode or self.clock() - self._at >= self.every_s:
            self._at = self.clock()
            await asyncio.to_thread(self.check)

    def https_name(self) -> str | None:
        """The console's https host name while tailscale serve proxies it to this console (whoever set it up)."""
        return self.name if self.served else None

    def status(self) -> dict:
        n = self.https_name()
        return {"mode": self.mode, "name": self.name, "url": L.https_origin(n, 443) + "/" if n else None,
                "frames": L.https_origin(n, L.FRAMES_HTTPS_PORT) if n and self.frames_served else None,
                "error": self.error, "commands": self.commands}


class Listeners:
    """The console's listeners. `apps`: {name: (ASGI app, port)}, the console first; `targets()`: the setting's value
    (read each pass); `extra`: entries from --bind / OARBANKD_CONSOLE_BIND, added to it; `tailscale()`: this machine's
    Tailscale addresses (injected in tests); `bind`: the socket factory (injected in tests)."""

    def __init__(self, apps: dict[str, tuple[Any, int]], targets: Callable[[], Any], extra=(),
                 tailscale: Callable[[], list[str]] = L.tailscale_ips, bind: Callable = bind_socket,
                 poll_s: float = POLL_S, tailscale_s: float = TAILSCALE_S, clock: Callable[[], float] = time.monotonic,
                 https: HttpsServe | None = None):
        self.apps, self.targets, self.extra, self.https = apps, targets, list(extra or []), https
        self.tailscale, self.bind, self.poll_s, self.tailscale_s, self.clock = tailscale, bind, poll_s, tailscale_s, clock
        self.servers: dict[tuple[str, str], tuple[Any, socket.socket, asyncio.Task]] = {}
        self.wanted: list[str] = []
        self.notes: list[str] = []
        self.errors: dict[tuple[str, str], str] = {}
        self.value: list[str] = [L.LOCALHOST]
        self._ts: tuple[float, list[str] | None] = (float("-inf"), None)
        self._stop = threading.Event()
        self._wake: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self.passes = 0

    # ------------------------------------------------------------------ what to bind
    def _value(self) -> list[str]:
        try:
            v = self.targets()
        except Exception as e:                  # the database busy or moving: keep what was read last
            log(f"console_listen: cannot read the setting now ({type(e).__name__}); keeping {', '.join(self.value)}")
            return self.value
        try:
            return L.normalize([*(v if isinstance(v, list) else [v] if v else []), *self.extra])
        except L.ListenError as e:
            log(f"console_listen: {e}; listening on localhost only")
            return [L.LOCALHOST]

    async def _tailscale(self, value) -> list[str] | None:
        if L.TAILSCALE not in value:
            return None
        at, ips = self._ts
        if ips is None or self.clock() - at >= self.tailscale_s or not ips and self.clock() - at >= self.poll_s:
            ips = await asyncio.to_thread(self.tailscale)
            self._ts = (self.clock(), ips)
        return ips

    async def resolve(self) -> list[str]:
        self.value = self._value()
        self.wanted, self.notes = L.resolve(self.value, await self._tailscale(self.value))
        return self.wanted

    # ------------------------------------------------------------------ what is bound
    def addresses(self, name: str | None = None) -> list[str]:
        """The addresses `name` (the console by default) listens on now."""
        name = name or next(iter(self.apps))
        return [a for a in self.wanted if (name, a) in self.servers]

    def everywhere(self) -> bool:
        return any(a in L.WILDCARDS for a in self.addresses())

    def hosts(self, name: str | None = None) -> list[str]:
        """The listen addresses as the Host allowlist takes them (wildcards out: host_ok's any_ip_port covers them)."""
        return [a for a in self.addresses(name) if a not in L.WILDCARDS]

    def https_name(self) -> str | None:
        return self.https.https_name() if self.https else None

    def names(self, name: str | None = None) -> list[str]:
        """Host names (with the port the browser uses) a listener answers to besides its addresses: the https name."""
        n = self.https_name()
        if not n:
            return []
        return [n, f"{n}:443"] if (name or next(iter(self.apps))) == next(iter(self.apps)) else [f"{n}:{L.FRAMES_HTTPS_PORT}"]

    def status(self) -> dict:
        """For /healthz and the Settings page: the setting's value, each listener's URLs, and why an address is not bound."""
        out = {"value": self.value, "listeners": {}, "notes": list(self.notes),
               "https": self.https.status() if self.https else None,
               "errors": [f"{n} {L.url_host(a)}:{self.apps[n][1]}: {e}" for (n, a), e in sorted(self.errors.items())]}
        for n, (_, port) in self.apps.items():
            out["listeners"][n] = [f"http://{L.url_host(a)}:{port}" for a in self.addresses(n)]
        return out

    # ------------------------------------------------------------------ binding
    async def _start(self, name: str, addr: str):
        app, port = self.apps[name]
        try:
            sock = self.bind(addr, port)
        except OSError as e:
            if self.errors.get((name, addr)) != str(e):
                log(f"{name}: cannot listen on {L.url_host(addr)}:{port} now ({e}); retrying")
            self.errors[(name, addr)] = str(e)
            return
        self.errors.pop((name, addr), None)
        server = _Server(uvicorn.Config(app, lifespan="off", log_level="warning", access_log=False,
                                        proxy_headers=True, forwarded_allow_ips="127.0.0.1",   # tailscale serve only
                                        timeout_graceful_shutdown=GRACE_S))
        task = asyncio.get_running_loop().create_task(server.serve(sockets=[sock]), name=f"{name}@{addr}")
        self.servers[(name, addr)] = (server, sock, task)
        task.add_done_callback(lambda t, k=(name, addr): self._ended(k, t))
        log(f"{name}: listening on http://{L.url_host(addr)}:{port}")

    def _ended(self, key, task: asyncio.Task):
        """A server that ended on its own (not stopped by the supervisor) is dropped, and rebound at the next pass."""
        hit = self.servers.get(key)
        if hit is not None and hit[2] is task and not hit[0].should_exit:
            self.servers.pop(key, None)
            err = None if task.cancelled() else task.exception()
            self.errors[key] = f"stopped ({type(err).__name__ if err else 'ended'})"

    async def _stop_one(self, key):
        server, sock, task = self.servers.pop(key)
        server.should_exit = True
        try:
            await asyncio.wait_for(asyncio.shield(task), GRACE_S + 2)
        except (asyncio.TimeoutError, Exception):
            task.cancel()
        with contextlib.suppress(OSError):
            sock.close()
        if key[1] not in self.wanted:
            log(f"{key[0]}: stopped listening on {L.url_host(key[1])}:{self.apps[key[0]][1]}")

    async def reconcile(self):
        """One pass: resolve the setting, stop the servers of addresses that left (first: a wildcard and a specific address
        on one port collide), start the missing ones."""
        wanted = await self.resolve()
        gone = [k for k in self.servers if k[1] not in wanted]
        if gone:
            await asyncio.gather(*(self._stop_one(k) for k in gone))
        self.errors = {k: e for k, e in self.errors.items() if k[1] in wanted}
        for name in self.apps:
            for addr in wanted:
                if (name, addr) not in self.servers:
                    await self._start(name, addr)
        if self.https is not None:
            await self.https.reconcile()
        self.passes += 1

    async def run(self, until: Callable[[], bool] | None = None):
        """Reconcile until stopped. The first pass must bind the console on its first address (localhost, or every
        interface under `all`), else the process ends with 1."""
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        await self.reconcile()
        first = next(iter(self.apps))
        if (first, self.wanted[0]) not in self.servers:
            await self.close()
            log(f"cannot listen on {L.url_host(self.wanted[0])}:{self.apps[first][1]}: "
                f"{self.errors.get((first, self.wanted[0]))}")
            raise SystemExit(1)
        while not self._stop.is_set() and not (until and until()):
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._wake.wait(), self.poll_s)
            self._wake.clear()
            if self._stop.is_set():
                break
            try:
                await self.reconcile()
            except Exception as e:                   # never let one bad pass end the console
                log(f"console_listen: pass failed ({type(e).__name__}: {e})")
        await self.close()

    def stop(self):
        """Thread-safe (signal handlers, the Windows service manager's thread)."""
        self._stop.set()
        if self._loop is not None and self._wake is not None:
            with contextlib.suppress(RuntimeError):
                self._loop.call_soon_threadsafe(self._wake.set)

    async def close(self):
        if self.servers:
            await asyncio.gather(*(self._stop_one(k) for k in list(self.servers)))


def install_signals(stop: Callable[[], None]):
    """SIGINT and SIGTERM stop the supervisor (main thread only; the Windows service stops it through stop_servers)."""
    if threading.current_thread() is not threading.main_thread():
        return
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, lambda *_: stop())
