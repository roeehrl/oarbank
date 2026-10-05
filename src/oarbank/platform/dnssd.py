"""Announcing a DNS-SD service on the local network (coordinator/discovery.py says what and when): macOS through the
system responder (`dns-sd -R`), Linux through Avahi when it is installed, Windows through its own DNS-SD API
(`DnsServiceRegister`, Windows 10 1903 and later), the one the agent browses with. `announce` returns an object whose
`terminate()` withdraws the announcement, or None when there is no way to announce here."""
import os
import shutil
import socket
import subprocess
import sys
import threading


def announce(name: str, service_type: str, port: int, txt: list[str]):
    if sys.platform == "win32":
        try:
            return _Registration(name, service_type, port, txt)
        except AttributeError:                    # before Windows 10 1903 dnsapi has no DNS-SD registration
            return None
    if sys.platform == "darwin" and os.path.exists("/usr/bin/dns-sd"):
        argv = ["/usr/bin/dns-sd", "-R", name, service_type, "local", str(port), *txt]
    elif shutil.which("avahi-publish-service"):
        argv = [shutil.which("avahi-publish-service"), name, service_type, str(port), *txt]
    else:
        return None
    try:
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return None


class _Registration:
    """A service registered with DnsServiceRegister until terminate() deregisters it. Both complete on the API's own
    thread, which calls back; the instance is freed only after the deregistration's call."""

    def __init__(self, name: str, service_type: str, port: int, txt: list[str]):
        import ctypes
        from ctypes import wintypes
        from . import _win32 as W
        dnsapi = ctypes.WinDLL("dnsapi", use_last_error=True)
        self._ct, self._dnsapi = ctypes, dnsapi
        callback = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p)

        class Request(ctypes.Structure):
            _fields_ = [("Version", wintypes.ULONG), ("InterfaceIndex", wintypes.ULONG), ("pServiceInstance", ctypes.c_void_p),
                        ("pRegisterCompletionCallback", callback), ("pQueryContext", ctypes.c_void_p),
                        ("hCredentials", W.HANDLE), ("unicastEnabled", W.BOOL)]
        construct = dnsapi.DnsServiceConstructInstance
        construct.restype = ctypes.c_void_p
        construct.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.WORD,
                              wintypes.WORD, wintypes.WORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR),
                              ctypes.POINTER(wintypes.LPCWSTR)]
        self._register, self._deregister = dnsapi.DnsServiceRegister, dnsapi.DnsServiceDeRegister
        for f in (self._register, self._deregister):
            f.restype, f.argtypes = wintypes.DWORD, [ctypes.POINTER(Request), ctypes.c_void_p]
        pairs = [kv.split("=", 1) for kv in txt]
        keys = (wintypes.LPCWSTR * len(pairs))(*[k for k, _ in pairs])
        values = (wintypes.LPCWSTR * len(pairs))(*[v for _, v in pairs])
        host = socket.gethostname().split(".")[0] + ".local"
        self._instance = construct(f"{name}.{service_type}.local", host, None, None, port, 0, 0, len(pairs), keys, values)
        if not self._instance:
            raise ctypes.WinError(ctypes.get_last_error(), "DnsServiceConstructInstance")
        self._called = threading.Event()
        self._done = callback(lambda status, ctx, inst: self._called.set())     # kept alive with the request
        self._req = Request(1, 0, self._instance, self._done, None, None, False)
        err = self._register(ctypes.byref(self._req), None)
        if err != 9506:                                               # DNS_REQUEST_PENDING
            dnsapi.DnsServiceFreeInstance(ctypes.c_void_p(self._instance))
            raise ctypes.WinError(err, "DnsServiceRegister")

    def terminate(self):
        if not self._instance:
            return
        self._called.clear()
        if self._deregister(self._ct.byref(self._req), None) != 9506 or self._called.wait(10):
            self._dnsapi.DnsServiceFreeInstance(self._ct.c_void_p(self._instance))
        self._instance = None
