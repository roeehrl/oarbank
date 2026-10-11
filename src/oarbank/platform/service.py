"""Running under the OS's service manager.

On macOS and Linux oarbankd and the console are launchd daemons or systemd system units run by the coordinator's own
account (docs/design/coordinator-system-service.md): the service manager starts the process, SIGTERM stops it (uvicorn's handlers), its output goes to the log file the unit names, and its exit code
decides (`exit`): 0 stays down (a finalized old coordinator), anything else is restarted (75: a standby restarts on
the copy a move installed).

On Windows they are services of the service control manager, started with `--service`: `run` hands the process to
the dispatcher, reports running, sends a stop or shutdown control to the `stop` callback and reports the exit code
when the process ends; `log_to` sends the output to `<home>\\logs\\<log>` (as launchd's StandardOutPath does; set
aside as `.1` past 16 MB) once the home is settled (oarbankd may first move an old home aside, which an open log file
inside it would stop on Windows). A nonzero code is a service-specific error, which the recovery actions the installer sets
(`sc failure`, `sc failureflag 1`) answer with a restart, as launchd and systemd restart after a failed exit.
"""
import os
import sys
import threading
from pathlib import Path

_STATUS: dict = {}            # the running service's status handle, while there is one


def run(main, stop):
    """Windows: run `main()` as this process's service (its return value or SystemExit code is the exit code);
    `stop()` is called on the service manager's thread when it asks the service to stop."""
    import ctypes
    from ctypes import wintypes
    from . import _win32 as W
    advapi32 = W.advapi32
    main_fn = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
    handler_fn = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p)

    class Entry(ctypes.Structure):
        _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", main_fn)]
    register = W._fn(advapi32, "RegisterServiceCtrlHandlerExW", ctypes.c_void_p, wintypes.LPCWSTR, handler_fn, ctypes.c_void_p)
    dispatcher = W._fn(advapi32, "StartServiceCtrlDispatcherW", W.BOOL, ctypes.POINTER(Entry))
    SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_INTERROGATE = 1, 5, 4
    outcome = {"code": 0}

    def on_control(code, event, data, ctx):
        if code in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
            _report(STOP_PENDING)
            threading.Thread(target=stop, name="service-stop", daemon=True).start()
        return 0                                                   # NO_ERROR, also for SERVICE_CONTROL_INTERROGATE

    def service_main(argc, argv):
        h = register("oarbank", handler, None)                     # the name is ignored for an own-process service
        if not h:
            return
        _STATUS["handle"] = h
        _report(RUNNING)
        try:
            r = main()
            outcome["code"] = r if isinstance(r, int) else 0
        except SystemExit as e:
            outcome["code"] = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        except BaseException:
            import traceback
            traceback.print_exc()
            outcome["code"] = 1
        sys.stdout.flush()
        _report(STOPPED, outcome["code"])

    handler, entry = handler_fn(on_control), main_fn(service_main)
    table = (Entry * 2)(Entry("oarbank", entry), Entry(None, main_fn()))
    if not dispatcher(table):
        raise SystemExit(f"--service: not started by the service control manager ({ctypes.FormatError(ctypes.get_last_error())})")
    return outcome["code"]


RUNNING, STOP_PENDING, STOPPED = 4, 3, 1


def _report(state: int, code: int = 0):
    import ctypes
    from ctypes import wintypes
    from . import _win32 as W
    h = _STATUS.get("handle")
    if not h:
        return

    class Status(ctypes.Structure):
        _fields_ = [(n, wintypes.DWORD) for n in ("dwServiceType", "dwCurrentState", "dwControlsAccepted", "dwWin32ExitCode",
                                                   "dwServiceSpecificExitCode", "dwCheckPoint", "dwWaitHint")]
    SERVICE_WIN32_OWN_PROCESS, ACCEPT_STOP_AND_SHUTDOWN, ERROR_SERVICE_SPECIFIC_ERROR = 0x10, 0x1 | 0x4, 1066
    st = Status(SERVICE_WIN32_OWN_PROCESS, state, ACCEPT_STOP_AND_SHUTDOWN if state == RUNNING else 0,
                ERROR_SERVICE_SPECIFIC_ERROR if code else 0, code, 0, 30000 if state == STOP_PENDING else 0)
    W._fn(W.advapi32, "SetServiceStatus", W.BOOL, ctypes.c_void_p, ctypes.POINTER(Status))(h, ctypes.byref(st))


def log_to(log: Path):
    """Under the Windows service control manager (which gives a service no console): send this process's output to
    `log`, set aside as `<log>.1` once it passes 16 MB. Elsewhere the service manager already did."""
    if not _STATUS.get("handle"):
        return
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    if log.exists() and log.stat().st_size > 16 << 20:
        os.replace(log, log.with_name(log.name + ".1"))
    f = open(log, "a", buffering=1, encoding="utf-8", errors="replace")
    os.dup2(f.fileno(), 1)
    os.dup2(f.fileno(), 2)
    sys.stdout = sys.stderr = f


def exit_now(code: int):
    """End the process now with `code`, which the service manager acts on (the module notes): under the Windows
    service control manager the exit code is reported first, as a service that ends without reporting one counts as
    crashed and is restarted whatever the code."""
    if _STATUS.get("handle"):
        sys.stdout.flush()
        _report(STOPPED, code)
    os._exit(code)


# ---------------------------------------------------------------------------- what the service manager says

SERVICES = ("dev.codonic.oarbank.oarbankd", "dev.codonic.oarbank.console")   # launchd labels, systemd units, Windows services
HELPER = "OarbankHelper"                                                      # the agent MSI's elevated helper (Windows)


def manager() -> str:
    """The service manager the coordinator runs under on this OS."""
    return {"darwin": "launchd", "win32": "windows-service"}.get(sys.platform, "systemd")


def state(name: str) -> dict:
    """One service as its manager reports it: {name, installed, domain, state, start, account, pid}; `installed` False
    when the manager does not know it (a coordinator run by hand, a test). `domain` is "system" (a launchd daemon, a
    systemd system unit, a Windows service) or "user" (a per-user coordinator of an earlier release, until its
    migration). The fields a manager has no answer for are None."""
    if sys.platform == "win32":
        d = _scm_state(name)
        return {**d, "domain": "system" if d["installed"] else None}
    import getpass
    import subprocess
    if sys.platform == "darwin":
        r = subprocess.run(["launchctl", "print", f"system/{name}"], capture_output=True, text=True)
        if r.returncode == 0:
            return parse_launchctl(name, r.returncode, r.stdout, None)
        r = subprocess.run(["launchctl", "print", f"gui/{os.getuid()}/{name}"], capture_output=True, text=True)
        return parse_launchctl(name, r.returncode, r.stdout, getpass.getuser())
    props = ["-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState", "-p", "MainPID", "-p", "User"]
    r = subprocess.run(["systemctl", "show", f"{name}.service", *props], capture_output=True, text=True)
    sysstate = parse_systemctl(name, r.stdout if r.returncode == 0 else "", None)
    if sysstate["installed"]:
        return sysstate
    r = subprocess.run(["systemctl", "--user", "show", f"{name}.service", *props], capture_output=True, text=True)
    return parse_systemctl(name, r.stdout if r.returncode == 0 else "", getpass.getuser())


def _absent(name: str) -> dict:
    return {"name": name, "installed": False, "domain": None, "state": None, "start": None, "account": None, "pid": None}


def parse_launchctl(name: str, code: int, out: str, user: str | None) -> dict:
    """`launchctl print system/<label>` (a daemon: it starts at boot, as its `username`) or `gui/<uid>/<label>` (a
    LaunchAgent: it runs as the person who loaded it, from that person's login; `user` names them)."""
    if code != 0:
        return _absent(name)
    f: dict = {}
    for k, sep, v in (line.partition(" = ") for line in out.splitlines()):
        if sep:
            f.setdefault(k.strip(), v.strip())        # the job's own fields come first; nested sections repeat `state`
    pid = f.get("pid")
    system = f.get("domain") == "system" or f.get("type") == "LaunchDaemon" or user is None
    return {"name": name, "installed": True, "domain": "system" if system else "user", "state": f.get("state"),
            "start": "at boot" if system else "at login", "account": f.get("username") or (None if system else user) or "root",
            "pid": int(pid) if pid and pid.isdigit() else None}


def parse_systemctl(name: str, out: str, user: str | None) -> dict:
    """`systemctl show <unit> -p …` (a system unit: `User` names its account, root when empty) or `systemctl --user show`
    (a user unit, run as `user`); UnitFileState says whether it starts."""
    f = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if f.get("LoadState") != "loaded":
        return _absent(name)
    pid = f.get("MainPID", "0")
    return {"name": name, "installed": True, "domain": "user" if user else "system",
            "state": f"{f.get('ActiveState')} ({f.get('SubState')})", "start": f.get("UnitFileState") or None,
            "account": user or f.get("User") or "root", "pid": int(pid) if pid.isdigit() and pid != "0" else None}


def form(services: list[dict]) -> str:
    """How the coordinator is installed: "system" (system services, from boot), "per-user" (an earlier release's
    LaunchAgents or user units, until migrated) or "none" (run by hand, a test)."""
    domains = {s.get("domain") for s in services if s.get("installed")}
    if "user" in domains:
        return "per-user"
    return "system" if "system" in domains else "none"


def _scm_state(name: str) -> dict:
    """The service control manager's view of a service: its state and process, its start type and account."""
    import ctypes
    from ctypes import wintypes
    from . import _win32 as W
    absent = {k: v for k, v in _absent(name).items() if k != "domain"}
    open_scm = W._fn(W.advapi32, "OpenSCManagerW", W.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, W.DWORD)
    open_svc = W._fn(W.advapi32, "OpenServiceW", W.HANDLE, W.HANDLE, wintypes.LPCWSTR, W.DWORD)
    close = W._fn(W.advapi32, "CloseServiceHandle", W.BOOL, W.HANDLE)
    status_ex = W._fn(W.advapi32, "QueryServiceStatusEx", W.BOOL, W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD,
                      ctypes.POINTER(W.DWORD))
    config = W._fn(W.advapi32, "QueryServiceConfigW", W.BOOL, W.HANDLE, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD))
    config2 = W._fn(W.advapi32, "QueryServiceConfig2W", W.BOOL, W.HANDLE, W.DWORD, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD))
    SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS = 0x1, 0x1, 0x4
    scm = open_scm(None, None, SC_MANAGER_CONNECT)
    if not scm:
        return absent
    try:
        svc = open_svc(scm, name, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS)
        if not svc:
            return absent
        try:
            st = (W.DWORD * 9)()                                       # SERVICE_STATUS_PROCESS
            need = W.DWORD()
            ok = status_ex(svc, 0, st, ctypes.sizeof(st), ctypes.byref(need))
            states = {1: "stopped", 2: "start pending", 3: "stop pending", 4: "running", 5: "continue pending",
                      6: "pause pending", 7: "paused"}
            config(svc, None, 0, ctypes.byref(need))
            buf = ctypes.create_string_buffer(max(need.value, 64))
            start, account = None, None
            if config(svc, buf, len(buf), ctypes.byref(need)):

                class Config(ctypes.Structure):
                    _fields_ = [("type", W.DWORD), ("start", W.DWORD), ("error", W.DWORD), ("binary", wintypes.LPWSTR),
                                ("group", wintypes.LPWSTR), ("tag", W.DWORD), ("deps", wintypes.LPWSTR),
                                ("account", wintypes.LPWSTR), ("display", wintypes.LPWSTR)]
                c = Config.from_buffer(buf)
                delayed = W.BOOL()
                config2(svc, 3, ctypes.byref(delayed), ctypes.sizeof(delayed), ctypes.byref(need))   # DELAYED_AUTO_START_INFO
                start = {0: "boot", 1: "system", 2: "automatic (delayed)" if delayed.value else "automatic", 3: "manual",
                         4: "disabled"}.get(c.start, str(c.start))
                account = c.account
            return {"name": name, "installed": True, "state": states.get(st[1], str(st[1])) if ok else None,
                    "start": start, "account": account, "pid": (st[7] or None) if ok else None}
        finally:
            close(svc)
    finally:
        close(scm)
