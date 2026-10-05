"""The module host (PLAN D1, D2): every module's coordinator side runs in its own process and
oarbankd talks to it over module protocol 1 (newline-delimited JSON-RPC on stdio).

Supervision per module:
- lazy spawn, `initialize` handshake, `initialized`;
- per-verb timeouts (manifest `coordinator.timeouts_s`) with `$/cancel`;
- respawn with exponential backoff after a crash; after `FAULT_AFTER` consecutive failures the module
  is in **fault** until the backoff expires, and calls fail fast with `ModuleUnavailable` (they never
  wait on a dead module);
- stderr captured to `<home>/logs/modules/<name>.log` (size-capped, one rotation);
- health counters for the console (state, pid, restarts, last error, calls, errors, latency p99).

Errors are split by blame. `ModuleUnavailable` (spawn failure, crash, timeout, fault) and `ModuleError`
(the module answered with a JSON-RPC error) are both *module faults*: the caller must never charge them
to a node or a job (invariant S15). Callers on the completion path answer the agent with 503 and
Retry-After, so the agent's outbox redelivers the result later.
"""
import collections
import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from oarbank_sdk import MODULE_PROTOCOL
from oarbank_sdk import module_protocol as mp
from oarbank_sdk.ui import UI_CONTRACT
from oarbank_sdk.rpc import ConnectionClosed, Peer, Request, RpcError

log = logging.getLogger("oarbank.modulehost")

BACKOFF_INITIAL_S, BACKOFF_MAX_S = 1.0, 60.0
FAULT_AFTER = 3                       # consecutive failures (crash, handshake failure, timeouts) -> fault
TIMEOUTS_BEFORE_RESTART = 3           # consecutive timeouts on one process -> kill and respawn
HANDSHAKE_TIMEOUT_S = 15.0
LOG_MAX_BYTES = 8 * 1024 * 1024


class ModuleUnavailable(Exception):
    """The module could not answer: not startable, crashed, timed out, or in fault. Never a node/job fault."""

    def __init__(self, module: str, kind: str, detail: str = "", retry_after: float = 5.0):
        super().__init__(f"module {module} unavailable ({kind}): {detail}")
        self.module, self.kind, self.detail, self.retry_after = module, kind, detail, retry_after


class ModuleError(Exception):
    """The module answered with an error (a module bug or invalid input). Never a node/job fault."""

    def __init__(self, module: str, method: str, err: RpcError):
        super().__init__(f"module {module} {method}: {err}")
        self.module, self.method, self.code, self.message, self.data = module, method, err.code, err.message, err.data


@dataclass
class ModuleSpec:
    name: str                                     # the module's name in the store (modstore)
    argv: list[str]
    # the module sandbox (spec/sandbox.md): a oarbank_sdk.sandbox.Policy and the directory its profile is written to,
    # or a modsandbox.NoBackend on an OS without a backend, which the host refuses to start
    sandbox: Any
    profile_dir: str
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    timeouts_s: dict[str, float] = field(default_factory=lambda: {"default": 10.0})
    concurrency: int = 1
    permissions: set[str] = field(default_factory=set)
    settings: dict = field(default_factory=dict)

    def timeout(self, method: str) -> float:
        return float(self.timeouts_s.get(method, self.timeouts_s.get("default", 10.0)))


@dataclass
class Health:
    state: str = "stopped"                        # stopped | starting | ready | fault | closed
    pid: int | None = None
    restarts: int = 0
    consecutive_failures: int = 0
    last_error: str | None = None
    last_error_at: float | None = None
    fault_until: float = 0.0
    calls: int = 0
    errors: int = 0
    timeouts: int = 0
    alerting: bool = False                        # a fault/crash was reported and no call has succeeded since
    protocol_version: int | None = None
    module_version: str | None = None
    capabilities: list[str] = field(default_factory=list)
    latencies_ms: collections.deque = field(default_factory=lambda: collections.deque(maxlen=512))

    def snapshot(self) -> dict:
        lat = sorted(self.latencies_ms)
        p = lambda q: round(lat[min(len(lat) - 1, int(q * len(lat)))], 2) if lat else None
        return {"state": self.state, "pid": self.pid, "restarts": self.restarts, "last_error": self.last_error,
                "last_error_at": self.last_error_at, "fault_until": self.fault_until or None, "calls": self.calls,
                "errors": self.errors, "timeouts": self.timeouts, "protocol_version": self.protocol_version,
                "module_version": self.module_version, "capabilities": list(self.capabilities),
                "latency_p50_ms": p(0.5), "latency_p99_ms": p(0.99)}


# what this host implements of the optional host features (module_protocol.HOST_CAPABILITIES), and the UI contract it renders
HOST_CAPABILITIES = (mp.HOST_PLACEMENT, mp.HOST_COORDINATOR_VARIANTS, mp.HOST_NODES_PLATFORM, mp.HOST_GOLDENS_BY_PLATFORM,
                     mp.HOST_JOBS_STAGE, mp.HOST_DATASETS_ORIGINS, f"ui_contract:{UI_CONTRACT}")


def host_info() -> dict:
    """The `host` of the initialize handshake (module_protocol.HostInfo): the core's version, the host features it
    implements and this coordinator's platform (also OARBANK_PLATFORM in the module's environment)."""
    from oarbank_sdk import portable
    from .modstore import CORE_VERSION
    return {"name": "oarbank", "version": CORE_VERSION, "capabilities": list(HOST_CAPABILITIES),
            "platform": portable.host_platform()}


def sandboxed_argv(spec: "ModuleSpec", argv: list[str]) -> list[str]:
    """Write the module's sandbox policy and wrap argv in this OS's launcher (sandboxexec.py)."""
    from . import sandboxexec
    safe = spec.name.replace("@", "_").replace("/", "_")
    return sandboxexec.wrap(spec.sandbox, Path(spec.profile_dir) / f"{safe}.sb", argv)


def module_python(bundle) -> str:
    """The module environment's interpreter: the bundle's own `.venv` when its requirements were installed, else the
    coordinator's (which carries the SDK)."""
    if bundle:
        v = Path(bundle) / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        if v.exists():
            return str(v)
    return sys.executable


def resolve_argv(spec: "ModuleSpec") -> list[str]:
    """spec.argv with the `python` token and `{bundle}` resolved (oarbank-sdk spec/manifest.md, "Exec"); the bundle is
    the spec's cwd. Manifest validation already checked the argv's shape."""
    from oarbank_sdk.manifest import BUNDLE_TOKEN
    py, bundle = module_python(spec.cwd), os.path.abspath(spec.cwd or ".")
    return [py if i == 0 and a == "python" else a.replace(BUNDLE_TOKEN, bundle) for i, a in enumerate(spec.argv)]


class _Proc:
    """One running module process and its peer."""

    def __init__(self, spec: ModuleSpec, callbacks: dict[str, Callable[[str, dict], Any]], log_path: Path | None):
        self.spec = spec
        env = {"OARBANK_MODULE": spec.name, **spec.env}         # spec.env carries the OS's variables (coordinator_env)
        argv = resolve_argv(spec)
        if isinstance(spec.sandbox, Exception):          # no sandbox backend on this OS: refuse, never run unconfined
            raise OSError(str(spec.sandbox))
        argv = sandboxed_argv(spec, argv)
        from ..platform import procs
        self.box = procs.Contained(argv, cwd=spec.cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        self.proc = self.box.proc
        self.callbacks = callbacks
        self.consecutive_timeouts = 0
        self.peer = Peer(self.proc.stdout, self.proc.stdin, self._on_request, self._on_notification,
                         max_workers=4, name=f"mod-{spec.name}").start()
        self._log_path = log_path
        self.delivered: dict[str, str] = {}        # secret values this process received (host.secrets.get)
        threading.Thread(target=self._drain_stderr, name=f"mod-{spec.name}-stderr", daemon=True).start()

    def _on_request(self, req: Request):
        entry = mp.HOST_CALLBACKS.get(req.method)
        if entry is None or req.method not in self.callbacks:
            raise RpcError(mp.ERR_METHOD_NOT_FOUND, f"host does not provide {req.method}")
        if entry[2] not in self.spec.permissions:
            raise RpcError(mp.ERR_PERMISSION_DENIED, f"{req.method} needs permission {entry[2]}")
        try:
            out = self.callbacks[req.method](self.spec.name.split("@", 1)[0], req.params)   # name@version: the module is the name
        except ValueError as e:                    # bad input (a file path, a missing file): the module's to handle
            raise RpcError(mp.ERR_INVALID_PARAMS, str(e)[:300])
        if req.method == "host.secrets.get" and out.get("set"):
            self.delivered[str(req.params.get("name"))] = out["value"]     # redacted from this process's log from now on
        return out

    def _on_notification(self, method: str, params: dict):
        if method == "log":
            self._write_log(f"[{params.get('level', 'info')}] {params.get('msg', '')} {params.get('data') or ''}")

    def _write_log(self, line: str):
        if not self._log_path:
            return
        try:
            if self._log_path.exists() and self._log_path.stat().st_size > LOG_MAX_BYTES:
                self._log_path.replace(self._log_path.with_suffix(".log.1"))
            if self.delivered:                     # a safety net: an encoded or split value passes through
                from .modsecrets import redact
                line = redact(line, self.delivered)
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%dT%H:%M:%S ") + line.rstrip("\n") + "\n")
        except OSError:
            pass

    def _drain_stderr(self):
        for raw in iter(self.proc.stderr.readline, b""):
            self._write_log(raw.decode(errors="replace"))

    def alive(self) -> bool:
        return self.proc.poll() is None and not self.peer.closed

    def kill(self, grace: float = 2.0):
        try:
            if not self.peer.closed:
                self.peer.notify("shutdown")
        except Exception:
            pass
        self.peer.close()
        try:
            self.proc.wait(grace)
        except subprocess.TimeoutExpired:
            self.box.kill()
            self.proc.wait()
        self.box.close()


class ModuleHost:
    def __init__(self, specs: list[ModuleSpec] | None = None, home: str | Path | None = None,
                 callbacks: dict[str, Callable[[str, dict], Any]] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 on_state: Callable[[str, str, str | None], None] | None = None):
        self.specs: dict[str, ModuleSpec] = {s.name: s for s in (specs or [])}
        self.callbacks = callbacks or {}
        self.clock = clock
        self.log_dir = Path(home) / "logs" / "modules" if home else None
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        self.on_state = on_state            # (module, "fault" | "crash" | "recovered", detail): alerting hook
        self._procs: dict[str, _Proc] = {}
        self._health: dict[str, Health] = collections.defaultdict(Health)
        self._locks: dict[str, threading.Lock] = collections.defaultdict(threading.Lock)
        self._closed = False

    def register(self, spec: ModuleSpec):
        self.specs[spec.name] = spec

    def health(self, name: str | None = None) -> dict:
        if name is not None:
            return self._health[name].snapshot()
        return {n: self._health[n].snapshot() for n in self.specs}

    # ------------------------------------------------------------------ process management
    def _fail(self, name: str, kind: str, detail: str) -> ModuleUnavailable:
        h = self._health[name]
        h.consecutive_failures += 1
        h.last_error, h.last_error_at = f"{kind}: {detail}"[:500], time.time()
        backoff = min(BACKOFF_MAX_S, BACKOFF_INITIAL_S * 2 ** (h.consecutive_failures - 1))
        if h.consecutive_failures >= FAULT_AFTER:
            h.state, h.fault_until = "fault", self.clock() + backoff
            log.warning("module %s in fault for %.0f s after %d failures: %s", name, backoff, h.consecutive_failures, detail)
        else:
            log.warning("module %s %s (%d in a row): %s", name, kind, h.consecutive_failures, detail)
        h.alerting = True
        self._emit(name, "fault" if h.state == "fault" else "crash", h.last_error)
        return ModuleUnavailable(name, kind, detail, retry_after=backoff)

    def _emit(self, name: str, what: str, detail: str | None):
        if self.on_state:
            try:
                self.on_state(name, what, detail)
            except Exception:
                log.exception("module state hook failed")

    def _ensure(self, name: str) -> _Proc:
        if self._closed:
            raise ModuleUnavailable(name, "closed", "host is shut down")
        spec = self.specs.get(name)
        if spec is None:
            raise ModuleUnavailable(name, "unknown", "no such module registered")
        h = self._health[name]
        with self._locks[name]:
            p = self._procs.get(name)
            if p and p.alive():
                return p
            if p:                                            # died since the last call
                p.kill(0.5)
                self._procs.pop(name, None)
                h.restarts += 1
            if h.state == "fault" and self.clock() < h.fault_until:
                raise ModuleUnavailable(name, "fault", h.last_error or "", retry_after=h.fault_until - self.clock())
            h.state = "starting"
            try:
                p = _Proc(spec, self.callbacks, self.log_dir / f"{name}.log" if self.log_dir else None)
            except OSError as e:
                raise self._fail(name, "spawn", str(e))
            try:
                r = p.peer.request("initialize", {"protocol_versions": [MODULE_PROTOCOL], "host": host_info(),
                                                  "settings": spec.settings}, timeout=HANDSHAKE_TIMEOUT_S)
                info = mp.InitializeResult.model_validate(r)
                p.peer.notify("initialized")
            except Exception as e:
                p.kill(0.5)
                raise self._fail(name, "handshake", f"{type(e).__name__}: {e}")
            from . import sandboxexec
            if not sandboxexec.is_confined(p.box):       # it answered, so it is past exec: it must be confined
                p.kill(0.5)
                raise self._fail(name, "sandbox_missing", "the module process is not sandboxed")
            h.state, h.pid = "ready", p.proc.pid
            h.protocol_version, h.module_version, h.capabilities = info.protocol_version, info.module.version, info.capabilities
            self._procs[name] = p
            return p

    # ------------------------------------------------------------------ calls
    def call(self, name: str, method: str, params: dict, timeout: float | None = None) -> Any:
        spec = self.specs.get(name)
        if spec is None:
            raise ModuleUnavailable(name, "unknown", "no such module registered")
        p = self._ensure(name)
        h = self._health[name]
        t0 = time.monotonic()
        h.calls += 1
        try:
            out = p.peer.request(method, params, timeout=timeout or spec.timeout(method))
        except RpcError as e:
            h.errors += 1
            h.last_error, h.last_error_at = f"{method}: {e}"[:500], time.time()
            p.consecutive_timeouts = 0
            raise ModuleError(name, method, e) from e
        except TimeoutError:
            h.errors += 1
            h.timeouts += 1
            p.consecutive_timeouts += 1
            if p.consecutive_timeouts >= TIMEOUTS_BEFORE_RESTART:
                p.kill(0.5)
            raise self._fail(name, "timeout", f"{method} exceeded {timeout or spec.timeout(method):.1f} s")
        except ConnectionClosed as e:
            h.errors += 1
            raise self._fail(name, "crash", f"{method}: {e}")
        p.consecutive_timeouts = 0
        h.consecutive_failures = 0
        if h.alerting:
            h.alerting = False
            self._emit(name, "recovered", None)
        h.latencies_ms.append((time.monotonic() - t0) * 1000)
        return out

    def stop(self, name: str):
        with self._locks[name]:
            p = self._procs.pop(name, None)
            if p:
                p.kill()
            self._health[name].state = "stopped"

    def restart(self, name: str):
        """Operator action modules.restart_host: clears fault and backoff."""
        self.stop(name)
        h = self._health[name]
        h.consecutive_failures, h.fault_until = 0, 0.0
        h.restarts += 1

    def close(self):
        self._closed = True
        for name in list(self._procs):
            self.stop(name)
        for h in self._health.values():
            h.state = "closed"
