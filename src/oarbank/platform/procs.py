"""Process containers for the coordinator's module processes (oarbank-sdk spec/platforms.md, "Process containers";
architecture.md, "Job control"). A module process and everything it starts live and die together:

- POSIX: a new session (its own process group), killed as a group.
- Windows: a Job Object the process is born in (started suspended, assigned, then resumed, so it never runs a line
  outside it), kill-on-close and without breakaway. Only oarbankd holds the job's handle, so the whole tree also dies
  when oarbankd does. The process starts with no console at all: a console, even a hidden one, puts a conhost.exe in
  the job outside the module's AppContainer.

The sandbox launcher (`sandboxexec.wrap`) is the container's first process; on Windows it is the unconfined shim that
starts the module in its AppContainer, and `app_container_members` is what the coordinator's confinement check reads.
"""
import os
import signal
import subprocess
import sys

WINDOWS = sys.platform == "win32"


class Contained:
    """A process started in a container of its own. `proc` is its Popen. `detach=False` (Windows) keeps the caller's
    console, for a program a person runs at a terminal (a module CLI)."""

    def __init__(self, argv: list[str], detach: bool = True, **popen):
        self._job = None
        if not WINDOWS:
            self.proc = subprocess.Popen(argv, start_new_session=True, **popen)
            return
        from . import _win32 as W
        job = W.check(W.CreateJobObjectW(None, None), "CreateJobObject")
        try:
            info = W.JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = W.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            W.check(W.SetInformationJobObject(job, W.JobObjectExtendedLimitInformation, W.ctypes.byref(info),
                                              W.ctypes.sizeof(info)), "SetInformationJobObject")
            flags = popen.pop("creationflags", 0) | W.CREATE_SUSPENDED | W.CREATE_NEW_PROCESS_GROUP
            if detach:
                flags |= W.DETACHED_PROCESS
            self.proc = subprocess.Popen(argv, creationflags=flags, **popen)
            try:
                h = W.check(W.OpenProcess(W.PROCESS_SET_QUOTA | W.PROCESS_TERMINATE, False, self.proc.pid), "OpenProcess")
                try:
                    W.check(W.AssignProcessToJobObject(job, h), "AssignProcessToJobObject")
                finally:
                    W.CloseHandle(h)
                _resume(self.proc.pid)
            except BaseException:
                self.proc.kill()
                raise
        except BaseException:
            W.CloseHandle(job)
            raise
        self._job = job

    @property
    def pid(self) -> int:
        return self.proc.pid

    def kill(self):
        """Kill every process in the container."""
        if WINDOWS:
            from . import _win32 as W
            if self._job:
                W.TerminateJobObject(self._job, 1)
            return
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except OSError:
            self.proc.kill()

    def members(self) -> list[int]:
        """The ids of the processes in the container now (Windows: its job's; POSIX: the leader's process group is not
        listed, nothing here needs it)."""
        if not WINDOWS:
            return [self.proc.pid] if self.proc.poll() is None else []
        from . import _win32 as W
        n = 1024
        buf = (W.ctypes.c_size_t * (2 + n))()
        if not self._job or not W.QueryInformationJobObject(self._job, W.JobObjectBasicProcessIdList, buf,
                                                            W.ctypes.sizeof(buf), None):
            return []
        count = W.ctypes.cast(buf, W.ctypes.POINTER(W.DWORD))[1]   # NumberOfProcessIdsInList, after NumberOfAssigned
        return [int(p) for p in buf[1:1 + min(count, n)]]

    def close(self):
        """Release the container. On Windows whatever still runs in it is killed, and close returns once it has
        ended (a running process holds its files and working directory)."""
        if WINDOWS and self._job:
            from . import _win32 as W
            left = self.members()
            if left:
                W.TerminateJobObject(self._job, 1)
                for pid in left:
                    h = W.OpenProcess(W.SYNCHRONIZE, False, pid)
                    if h:
                        W.WaitForSingleObject(h, 10_000)
                        W.CloseHandle(h)
            W.CloseHandle(self._job)
            self._job = None

    def __del__(self):
        self.close()


def _resume(pid: int):
    """Resume the threads of a process started suspended (it has one, its first)."""
    from . import _win32 as W
    snap = W.CreateToolhelp32Snapshot(W.TH32CS_SNAPTHREAD, 0)
    if snap == W.INVALID_HANDLE_VALUE or not snap:
        raise W.ctypes.WinError(W.ctypes.get_last_error())
    resumed = 0
    try:
        e = W.THREADENTRY32()
        e.dwSize = W.ctypes.sizeof(e)
        more = W.Thread32First(snap, W.ctypes.byref(e))
        while more:
            if e.th32OwnerProcessID == pid:
                t = W.OpenThread(W.THREAD_SUSPEND_RESUME, False, e.th32ThreadID)
                if t:
                    if W.ResumeThread(t) != 0xFFFFFFFF:
                        resumed += 1
                    W.CloseHandle(t)
            more = W.Thread32Next(snap, W.ctypes.byref(e))
    finally:
        W.CloseHandle(snap)
    if not resumed:
        raise OSError(f"no thread of process {pid} to resume")


def in_app_container(pid: int) -> bool | None:
    """Whether process `pid` runs with an AppContainer token (Windows); None when it cannot be read (it ended)."""
    from . import _win32 as W
    h = W.OpenProcess(W.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        tok = W.HANDLE()
        if not W.OpenProcessToken(h, W.TOKEN_QUERY, W.ctypes.byref(tok)):
            return None
        try:
            return bool(W.ctypes.cast(W.token_info(tok, W.TokenIsAppContainer), W.ctypes.POINTER(W.DWORD))[0])
        finally:
            W.CloseHandle(tok)
    finally:
        W.CloseHandle(h)


def app_container_members(c: Contained) -> bool:
    """Windows: the container's first process is the sandbox shim; it is confined when every other member runs in an
    AppContainer, and there is one (oarbank-agent's sandbox_windows.rs `is_confined`, for the coordinator's containers)."""
    others = [p for p in c.members() if p != c.pid]
    return bool(others) and all(in_app_container(p) is True for p in others)


def run(argv: list[str], timeout: float | None = None, detach: bool = True, **popen) -> subprocess.CompletedProcess:
    """subprocess.run in a container: on a timeout the whole tree is killed, not just the first process."""
    if popen.pop("capture_output", False):
        popen.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    c = Contained(argv, detach=detach, **popen)
    try:
        out, err = c.proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        c.kill()
        c.proc.communicate()
        raise
    finally:
        c.close()
    return subprocess.CompletedProcess(argv, c.proc.returncode, out, err)
