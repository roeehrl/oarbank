"""The Win32 calls the coordinator's Windows backends make (ctypes; imported only on Windows): Job Objects and process
tokens (procs.py), security descriptors (files.py, localchannel.py), named pipes (localchannel.py), the service
control manager (service.py) and DNS-SD registration (dnssd.py)."""
import ctypes
import re
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

HANDLE, DWORD, BOOL, LPVOID = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, wintypes.LPVOID
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def check(ok, what: str):
    """Raise the thread's last error when a call returned FALSE or NULL."""
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error(), f"{what}: {ctypes.FormatError(ctypes.get_last_error())}")
    return ok


def _fn(dll, name, res, *args):
    f = getattr(dll, name)
    f.restype, f.argtypes = res, list(args)
    return f


CloseHandle = _fn(kernel32, "CloseHandle", BOOL, HANDLE)
CreateFileW = _fn(kernel32, "CreateFileW", HANDLE, wintypes.LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE)
LocalFree = _fn(kernel32, "LocalFree", LPVOID, LPVOID)

# ---------------------------------------------------------------------------- processes and Job Objects

PROCESS_TERMINATE, PROCESS_SET_QUOTA, PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZE = 0x0001, 0x0100, 0x1000, 0x00100000
THREAD_SUSPEND_RESUME = 0x0002
TOKEN_QUERY = 0x0008
TH32CS_SNAPTHREAD = 0x4
CREATE_SUSPENDED, DETACHED_PROCESS, CREATE_NEW_PROCESS_GROUP = 0x4, 0x8, 0x200
JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation = 3, 9
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
TokenUser, TokenIsAppContainer = 1, 29


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                                  "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t), ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", DWORD), ("Affinity", ctypes.c_size_t), ("PriorityClass", DWORD),
                ("SchedulingClass", DWORD)]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION), ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", DWORD), ("cntUsage", DWORD), ("th32ThreadID", DWORD), ("th32OwnerProcessID", DWORD),
                ("tpBasePri", wintypes.LONG), ("tpDeltaPri", wintypes.LONG), ("dwFlags", DWORD)]


CreateJobObjectW = _fn(kernel32, "CreateJobObjectW", HANDLE, LPVOID, wintypes.LPCWSTR)
SetInformationJobObject = _fn(kernel32, "SetInformationJobObject", BOOL, HANDLE, ctypes.c_int, LPVOID, DWORD)
QueryInformationJobObject = _fn(kernel32, "QueryInformationJobObject", BOOL, HANDLE, ctypes.c_int, LPVOID, DWORD, LPVOID)
AssignProcessToJobObject = _fn(kernel32, "AssignProcessToJobObject", BOOL, HANDLE, HANDLE)
TerminateJobObject = _fn(kernel32, "TerminateJobObject", BOOL, HANDLE, wintypes.UINT)
OpenProcess = _fn(kernel32, "OpenProcess", HANDLE, DWORD, BOOL, DWORD)
OpenThread = _fn(kernel32, "OpenThread", HANDLE, DWORD, BOOL, DWORD)
ResumeThread = _fn(kernel32, "ResumeThread", DWORD, HANDLE)
WaitForSingleObject = _fn(kernel32, "WaitForSingleObject", DWORD, HANDLE, DWORD)
CreateToolhelp32Snapshot = _fn(kernel32, "CreateToolhelp32Snapshot", HANDLE, DWORD, DWORD)
Thread32First = _fn(kernel32, "Thread32First", BOOL, HANDLE, ctypes.POINTER(THREADENTRY32))
Thread32Next = _fn(kernel32, "Thread32Next", BOOL, HANDLE, ctypes.POINTER(THREADENTRY32))
OpenProcessToken = _fn(advapi32, "OpenProcessToken", BOOL, HANDLE, DWORD, ctypes.POINTER(HANDLE))
GetTokenInformation = _fn(advapi32, "GetTokenInformation", BOOL, HANDLE, ctypes.c_int, LPVOID, DWORD, ctypes.POINTER(DWORD))
GetCurrentProcess = _fn(kernel32, "GetCurrentProcess", HANDLE)
IsWow64Process2 = _fn(kernel32, "IsWow64Process2", BOOL, HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT))

# ---------------------------------------------------------------------------- security descriptors

SDDL_REVISION_1 = 1
SE_FILE_OBJECT = 1
DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION = 0x4, 0x80000000


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", DWORD), ("lpSecurityDescriptor", LPVOID), ("bInheritHandle", BOOL)]


ConvertStringSecurityDescriptorToSecurityDescriptorW = _fn(
    advapi32, "ConvertStringSecurityDescriptorToSecurityDescriptorW", BOOL, wintypes.LPCWSTR, DWORD,
    ctypes.POINTER(LPVOID), ctypes.POINTER(DWORD))
ConvertSecurityDescriptorToStringSecurityDescriptorW = _fn(
    advapi32, "ConvertSecurityDescriptorToStringSecurityDescriptorW", BOOL, LPVOID, DWORD, DWORD,
    ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(DWORD))
ConvertSidToStringSidW = _fn(advapi32, "ConvertSidToStringSidW", BOOL, LPVOID, ctypes.POINTER(wintypes.LPWSTR))
ConvertStringSidToSidW = _fn(advapi32, "ConvertStringSidToSidW", BOOL, wintypes.LPCWSTR, ctypes.POINTER(LPVOID))
GetSecurityDescriptorDacl = _fn(advapi32, "GetSecurityDescriptorDacl", BOOL, LPVOID, ctypes.POINTER(BOOL),
                                ctypes.POINTER(LPVOID), ctypes.POINTER(BOOL))
SetNamedSecurityInfoW = _fn(advapi32, "SetNamedSecurityInfoW", DWORD, wintypes.LPWSTR, ctypes.c_int, DWORD, LPVOID, LPVOID,
                            LPVOID, LPVOID)
SetSecurityInfo = _fn(advapi32, "SetSecurityInfo", DWORD, HANDLE, ctypes.c_int, DWORD, LPVOID, LPVOID, LPVOID, LPVOID)
GetSecurityInfo = _fn(advapi32, "GetSecurityInfo", DWORD, HANDLE, ctypes.c_int, DWORD, ctypes.POINTER(LPVOID),
                      ctypes.POINTER(LPVOID), ctypes.POINTER(LPVOID), ctypes.POINTER(LPVOID), ctypes.POINTER(LPVOID))
GetNamedSecurityInfoW = _fn(advapi32, "GetNamedSecurityInfoW", DWORD, wintypes.LPCWSTR, ctypes.c_int, DWORD,
                            ctypes.POINTER(LPVOID), ctypes.POINTER(LPVOID), ctypes.POINTER(LPVOID), ctypes.POINTER(LPVOID),
                            ctypes.POINTER(LPVOID))


def token_info(token, cls: int) -> ctypes.Array:
    n = DWORD(0)
    GetTokenInformation(token, cls, None, 0, ctypes.byref(n))
    buf = ctypes.create_string_buffer(max(n.value, 4))
    check(GetTokenInformation(token, cls, buf, n.value or 4, ctypes.byref(n)), "GetTokenInformation")
    return buf


def canonical_sid(s: str) -> str:
    """A SID as its S-1-… string, whichever way SDDL wrote it: SDDL names well-known accounts by alias (`SY`, `BA`, and
    `LA` for the built-in Administrator, the account CI runners use), so comparing SDDL text compares spellings."""
    sid = LPVOID()
    check(ConvertStringSidToSidW(s, ctypes.byref(sid)), f"the SID {s}")
    try:
        out = wintypes.LPWSTR()
        check(ConvertSidToStringSidW(sid, ctypes.byref(out)), "ConvertSidToStringSidW")
        try:
            return out.value
        finally:
            LocalFree(out)
    finally:
        LocalFree(sid)


_ALLOW = re.compile(r"\((?:A|OA);[^;]*;[^;]*;[^;]*;[^;]*;([^;)]*)[^)]*\)")


def allowed_sids(path: str | None = None, handle=None) -> set[str]:
    """Every account an entry of a file's (or an open handle's) DACL allows anything, as S-1-… strings."""
    sddl = dacl_sddl(path, handle)
    dacl = sddl.split("D:", 1)[1] if "D:" in sddl else ""
    return {canonical_sid(sid) for sid in _ALLOW.findall(dacl)}


def current_user_sid() -> str:
    """This process's account as a SID string (S-1-5-80-… for a service's virtual account)."""
    tok = HANDLE()
    check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(tok)), "OpenProcessToken")
    try:
        buf = token_info(tok, TokenUser)
        sid = ctypes.cast(buf, ctypes.POINTER(LPVOID))[0]          # TOKEN_USER.User.Sid
        s = wintypes.LPWSTR()
        check(ConvertSidToStringSidW(sid, ctypes.byref(s)), "ConvertSidToStringSidW")
        try:
            return s.value
        finally:
            LocalFree(s)
    finally:
        CloseHandle(tok)


class SecurityDescriptor:
    """A self-relative security descriptor made from SDDL, freed with the object."""

    def __init__(self, sddl: str):
        self.ptr = LPVOID()
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, ctypes.byref(self.ptr), None),
              f"security descriptor {sddl}")

    def dacl(self) -> LPVOID:
        present, dacl, defaulted = BOOL(), LPVOID(), BOOL()
        check(GetSecurityDescriptorDacl(self.ptr, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)),
              "GetSecurityDescriptorDacl")
        return dacl

    def attributes(self) -> SECURITY_ATTRIBUTES:
        return SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), self.ptr, False)

    def __del__(self):
        if self.ptr:
            LocalFree(self.ptr)
            self.ptr = LPVOID()


def dacl_sddl(path: str | None = None, handle=None) -> str:
    """A file's DACL as SDDL (`D:P(A;OICI;FA;;;SY)…`), by path or from an open handle (a pipe: opening it by name
    would connect to it)."""
    sd = LPVOID()
    if handle is not None:
        err = GetSecurityInfo(handle, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, None, None, ctypes.byref(sd))
    else:
        err = GetNamedSecurityInfoW(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, None, None, ctypes.byref(sd))
    if err:
        raise ctypes.WinError(err, f"reading the ACL of {path or 'a handle'}")
    try:
        s = wintypes.LPWSTR()
        check(ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION,
                                                                   ctypes.byref(s), None), "SDDL")
        try:
            return s.value
        finally:
            LocalFree(s)
    finally:
        LocalFree(sd)
