"""The local admin channel on Windows (localchannel.py): a named pipe served by uvicorn on asyncio's proactor, and an
httpx transport that reaches it. Imported only on Windows."""
import asyncio
import os
import time
from asyncio import windows_utils

import httpcore
import httpx
import uvicorn

from . import _win32 as W
from . import files

PIPE_ACCESS_DUPLEX, FILE_FLAG_OVERLAPPED, FILE_FLAG_FIRST_PIPE_INSTANCE = 0x3, 0x40000000, 0x00080000
PIPE_TYPE_BYTE, PIPE_READMODE_BYTE, PIPE_WAIT, PIPE_REJECT_REMOTE_CLIENTS = 0x0, 0x0, 0x0, 0x8
ERROR_PIPE_BUSY = 231
CreateNamedPipeW = W._fn(W.kernel32, "CreateNamedPipeW", W.HANDLE, W.wintypes.LPCWSTR, W.DWORD, W.DWORD, W.DWORD, W.DWORD,
                         W.DWORD, W.DWORD, W.ctypes.POINTER(W.SECURITY_ATTRIBUTES))
WaitNamedPipeW = W._fn(W.kernel32, "WaitNamedPipeW", W.BOOL, W.wintypes.LPCWSTR, W.DWORD)


class Listener:
    """One pipe name served on the proactor: an instance waits for a client, each client gets its own duplex transport,
    and the next instance is made as each is taken (asyncio's start_serving_pipe, with the owner-only security
    descriptor, byte mode and no remote clients). Has what uvicorn needs of a server: close() and wait_closed()."""

    def __init__(self, name: str, factory, home):
        self.name, self.factory = name, factory
        self.sd = W.SecurityDescriptor("D:P" + "".join(f"(A;;GA;;;{s})" for s in files.trusted_sids(home)))
        self.loop = asyncio.get_running_loop()
        self.pending = self._instance(first=True)             # fails if the name exists: someone made it first
        self.task = self.loop.create_task(self._accept())

    def _instance(self, first: bool):
        sa = self.sd.attributes()
        flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0)
        h = CreateNamedPipeW(self.name, flags, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                             255, 65536, 65536, 0, W.ctypes.byref(sa))
        if h == W.INVALID_HANDLE_VALUE or not h:
            raise W.ctypes.WinError(W.ctypes.get_last_error(), f"creating the pipe {self.name}")
        return windows_utils.PipeHandle(h)

    async def _accept(self):
        while True:
            pipe = self.pending
            try:
                await self.loop._proactor.accept_pipe(pipe)
            except (BrokenPipeError, ConnectionError):
                pipe.close()                                   # the client left before it was served
                self.pending = self._instance(first=False)
                continue
            self.pending = self._instance(first=False)
            self.loop._make_duplex_pipe_transport(pipe, self.factory(), extra={"addr": self.name})

    def close(self):
        self.task.cancel()
        self.pending.close()

    async def wait_closed(self):
        try:
            await self.task
        except asyncio.CancelledError:
            pass


class PipeServer(uvicorn.Server):
    """uvicorn on a named pipe: its startup, with the pipe listener where it would bind a socket."""

    def __init__(self, config, name: str, home):
        super().__init__(config)
        self.pipe_name, self.home = name, home

    async def startup(self, sockets=None):
        await self.lifespan.startup()
        if self.lifespan.should_exit:
            raise SystemExit(3)
        config = self.config

        def create_protocol(_loop=None):
            return config.http_protocol_class(config=config, server_state=self.server_state, app_state=self.lifespan.state,
                                              _loop=_loop)
        self.servers = [Listener(self.pipe_name, create_protocol, self.home)]
        self.started = True


def open_pipe(name: str):
    """A client end of the pipe, waiting while every instance is taken (other clients are being served)."""
    for _ in range(50):
        try:
            return open(name, "r+b", buffering=0)
        except OSError as e:
            if getattr(e, "winerror", None) != ERROR_PIPE_BUSY:
                raise
            WaitNamedPipeW(name, 2000)
    raise TimeoutError(f"{name}: every instance stays busy")


def reachable(name: str) -> bool:
    """The pipe exists and admits this account (a connection, closed again at once, tells)."""
    if name.rsplit("\\", 1)[1] not in os.listdir("\\\\.\\pipe\\"):
        return False
    try:
        open_pipe(name).close()
    except OSError:
        return False
    return True


class _Stream(httpcore.NetworkStream):
    def __init__(self, f):
        self.f = f

    def read(self, max_bytes, timeout=None):
        return self.f.read(max_bytes) or b""

    def write(self, buffer, timeout=None):
        view = memoryview(buffer)
        while view:
            view = view[self.f.write(view):]

    def close(self):
        self.f.close()


class _Backend(httpcore.NetworkBackend):
    def __init__(self, name: str):
        self.name = name

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        return _Stream(open_pipe(self.name))

    def sleep(self, seconds):
        time.sleep(seconds)


class _Body(httpx.SyncByteStream):
    def __init__(self, resp):
        self.resp = resp

    def __iter__(self):
        yield from self.resp.stream

    def close(self):
        self.resp.close()


class PipeTransport(httpx.BaseTransport):
    """HTTP/1.1 to the pipe: every connection httpcore makes opens a client end of it."""

    def __init__(self, name: str):
        self.pool = httpcore.ConnectionPool(network_backend=_Backend(name))

    def handle_request(self, request):
        url = httpcore.URL(scheme=request.url.raw_scheme, host=request.url.raw_host, port=request.url.port,
                           target=request.url.raw_path)
        resp = self.pool.handle_request(httpcore.Request(method=request.method, url=url, headers=request.headers.raw,
                                                         content=request.stream, extensions=request.extensions))
        return httpx.Response(status_code=resp.status, headers=resp.headers, stream=_Body(resp), extensions=resp.extensions)

    def close(self):
        self.pool.close()
