"""Announcing a DNS-SD service on the local network (coordinator/discovery.py says what and when): macOS through the
system responder's API in this process (`DNSServiceRegister`), Linux through Avahi when it is installed, Windows through
its own DNS-SD API (`DnsServiceRegister`, Windows 10 1903 and later), the one the agent browses with. `announce` returns
an object whose `terminate()` withdraws the announcement, or None when there is no way to announce here.

On macOS the registration belongs to this process: it ends with it however it ends (a `dns-sd -R` child outlived a
killed coordinator and went on announcing it), and Local Network privacy judges this program, whose refusal
(`kDNSServiceErr_PolicyDenied`) is logged as such (docs/design/architecture.md, "Local Network privacy")."""
import logging
import os
import select
import shutil
import socket
import subprocess
import sys
import threading

log = logging.getLogger("oarbank.dnssd")


def announce(name: str, service_type: str, port: int, txt: list[str]):
    if sys.platform == "win32":
        try:
            return _Registration(name, service_type, port, txt)
        except AttributeError:                    # before Windows 10 1903 dnsapi has no DNS-SD registration
            return None
    if sys.platform == "darwin":
        return _Responder(name, service_type, port, txt)
    if not shutil.which("avahi-publish-service"):
        return None
    argv = [shutil.which("avahi-publish-service"), name, service_type, str(port), *txt]
    try:
        # it ends with this process however that ends (PR_SET_PDEATHSIG: with the thread that starts it, the coordinator's
        # main thread), or it would go on announcing a dead one
        return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                preexec_fn=_die_with_parent)
    except OSError:
        return None


def _die_with_parent():
    import ctypes
    import signal
    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)           # PR_SET_PDEATHSIG


POLICY_DENIED = -65570                  # kDNSServiceErr_PolicyDenied: macOS refused this program local network access


class _Responder:
    """A service registered with the macOS system responder until terminate() deregisters it. The responder's replies
    are handled on a thread of its own as they arrive; `error` is the responder's refusal, if any."""

    def __init__(self, name: str, service_type: str, port: int, txt: list[str]):
        import ctypes
        from ctypes import POINTER, byref, c_char_p, c_int32, c_uint16, c_uint32, c_void_p
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        reply = ctypes.CFUNCTYPE(None, c_void_p, c_uint32, c_int32, c_char_p, c_char_p, c_char_p, c_void_p)
        lib.DNSServiceRegister.argtypes = [POINTER(c_void_p), c_uint32, c_uint32, c_char_p, c_char_p, c_char_p, c_char_p,
                                           c_uint16, c_uint16, c_char_p, reply, c_void_p]
        lib.DNSServiceRegister.restype = c_int32
        lib.DNSServiceRefSockFD.argtypes, lib.DNSServiceRefSockFD.restype = [c_void_p], ctypes.c_int
        lib.DNSServiceProcessResult.argtypes, lib.DNSServiceProcessResult.restype = [c_void_p], c_int32
        lib.DNSServiceRefDeallocate.argtypes, lib.DNSServiceRefDeallocate.restype = [c_void_p], None
        self._lib, self.error, self.name = lib, None, name
        self._reply = reply(self._on_reply)                       # kept alive while the responder may call it
        record = b"".join(bytes([len(kv)]) + kv for kv in (t.encode() for t in txt))
        self._ref = c_void_p()
        err = lib.DNSServiceRegister(byref(self._ref), 0, 0, name.encode(), service_type.encode(), None, None,
                                     socket.htons(port), len(record), record, self._reply, None)
        if err:
            self._refused(err)
            raise OSError(f"DNSServiceRegister refused {name}: {err}")
        self._wake_r, self._wake_w = os.pipe()
        self._thread = threading.Thread(target=self._serve, name="dnssd", daemon=True)
        self._thread.start()

    def _refused(self, err: int):
        self.error = err
        if err == POLICY_DENIED:
            log.warning("macOS refuses this program local network access, so agents cannot find the coordinator by "
                        "DNS-SD: allow it in System Settings, Privacy & Security, Local Network, or enroll agents with "
                        "a join code or --coordinator <url>")
        else:
            log.warning("announcing %s on the local network failed (DNS-SD error %s)", self.name, err)

    def _on_reply(self, ref, flags, err, name, regtype, domain, ctx):
        if err:
            self._refused(err)

    def _serve(self):
        fd = self._lib.DNSServiceRefSockFD(self._ref)
        while True:
            ready, _, _ = select.select([fd, self._wake_r], [], [])
            if self._wake_r in ready or self._lib.DNSServiceProcessResult(self._ref):
                return

    def terminate(self):
        if self._ref is None:
            return
        os.write(self._wake_w, b"x")
        self._thread.join()
        self._lib.DNSServiceRefDeallocate(self._ref)
        self._ref = None
        os.close(self._wake_r)
        os.close(self._wake_w)


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
