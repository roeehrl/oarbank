"""Running under the OS's service manager.

On macOS and Linux oarbankd and the console are a LaunchAgent or a systemd unit: the service manager starts the
process, SIGTERM stops it (uvicorn's handlers), its output goes to the log file the unit names, and its exit code
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
