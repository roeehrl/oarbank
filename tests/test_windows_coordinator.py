"""The coordinator's OS backends (docs/design/windows-coordinator.md): process containers on every OS, and on Windows the
Job Object a module process is born in, the confinement check that reads it, owner-only descriptors and the service
host under the real service control manager."""
import ctypes
import os
import subprocess
import sys
import textwrap
import time
import uuid
from pathlib import Path

import pytest

from helpers import alive
from oarbank.platform import files, procs

windows = pytest.mark.skipif(sys.platform != "win32", reason="a Windows backend (Job Objects, DACLs, the service manager)")

TREE = """
import subprocess, sys, time
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
print(child.pid, flush=True)
time.sleep(120)
"""


def wait_for(cond, timeout=20.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def test_killing_a_container_ends_everything_its_process_started():
    c = procs.Contained([sys.executable, "-c", TREE], stdout=subprocess.PIPE)
    child = int(c.proc.stdout.readline())
    assert alive(c.pid) and alive(child)
    if sys.platform == "win32":
        assert set(c.members()) >= {c.pid, child}
    c.kill()
    c.proc.wait(10)
    c.close()
    assert wait_for(lambda: not alive(child))


@windows
def test_closing_a_container_ends_what_still_runs_in_it():
    c = procs.Contained([sys.executable, "-c", TREE], stdout=subprocess.PIPE)
    child = int(c.proc.stdout.readline())
    c.close()                                                 # the job's last handle: kill-on-close, and close waits
    assert not alive(c.pid) and not alive(child)


@windows
def test_a_process_outside_the_appcontainer_in_a_module_job_fails_the_check(tmp_path):
    from oarbank.coordinator import modsandbox, sandboxexec
    from oarbank.coordinator.modulehost import ModuleHost, ModuleSpec
    from oarbank.platform import _win32 as W
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "m.py").write_text(textwrap.dedent("""
        from oarbank_sdk.server import Module
        m = Module("dev.test.m", "0.0.1")
        for verb in ("job.plan", "spec.build", "golden.list", "result.evaluate", "params.check"):
            m.verb(verb)(lambda p, ctx: {"ok": True, "normalized_params": {}})
        m.run()
    """), encoding="utf-8")
    spec = ModuleSpec(name="m", argv=["python", str(bundle / "m.py")], cwd=str(bundle), env=modsandbox.coordinator_env(tmp_path, "m"),
                      sandbox=modsandbox.coordinator_policy(tmp_path, "m", "dev.test.m", bundle),
                      profile_dir=str(modsandbox.profile_dir(tmp_path)))
    h = ModuleHost([spec], home=tmp_path)
    try:
        h.call("m", "params.check", {"params": {}})
        box = h._procs["m"].box
        others = [p for p in box.members() if p != box.pid]
        assert others and all(procs.in_app_container(p) for p in others) and sandboxexec.is_confined(box)
        assert procs.in_app_container(box.pid) is False      # the shim itself is not confined: it starts the module
        # an unconfined process joins the job (as a breakaway or a planted helper would be): no longer confined
        intruder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        hp = W.OpenProcess(W.PROCESS_SET_QUOTA | W.PROCESS_TERMINATE, False, intruder.pid)
        assert W.AssignProcessToJobObject(box._job, hp)
        W.CloseHandle(hp)
        assert not sandboxexec.is_confined(box)
    finally:
        h.close()
    assert wait_for(lambda: intruder.poll() is not None)      # it was in the job: closing the host ended it


@windows
def test_owner_only_files_carry_their_own_protected_descriptor(tmp_path, monkeypatch):
    from oarbank.coordinator import config as C
    from oarbank.platform import _win32 as W
    from helpers import loosen
    me = W.current_user_sid()
    loosen(tmp_path)                                          # a parent anyone may read: nothing is inherited from it
    f = tmp_path / "secret.key"
    files.write_private(f, "k")
    # exactly SYSTEM, Administrators and this account (CI runs as the built-in Administrator, which SDDL writes `LA`)
    assert W.dacl_sddl(str(f)).startswith("D:P") and W.allowed_sids(str(f)) == {"S-1-5-18", "S-1-5-32-544", me}
    assert files.owner_only(f)
    loose = tmp_path / "loose.key"
    files.write_private(loose, "k")
    loosen(loose)                                             # Everyone may read it: no longer owner-only
    assert "S-1-1-0" in W.allowed_sids(str(loose)) and not files.owner_only(loose)
    with pytest.raises(FileExistsError):
        files.write_private(f, "again", exclusive=True)
    # inside the coordinator's home the two service accounts are trusted too, whoever writes the file
    monkeypatch.setattr(C, "HOME", tmp_path / "home")
    g = C.HOME / "keys" / "audit.key"
    files.write_private(g, "k")
    sids = {files.service_sid(n) for n in files.COORDINATOR_SERVICES}
    assert W.allowed_sids(str(g)) == {"S-1-5-18", "S-1-5-32-544", me, *sids} and files.owner_only(g)
    files.write_private(f, "k")
    assert W.allowed_sids(str(f)) == {"S-1-5-18", "S-1-5-32-544", me}               # outside the home: no service
    assert files.service_sid("dev.codonic.oarbank.oarbankd") == files.service_sid("DEV.CODONIC.OARBANK.OARBANKD")


@windows
def test_descriptors_are_compared_by_sid_not_by_how_sddl_spells_it(tmp_path):
    """SDDL writes well-known accounts by alias: `LA` is the built-in Administrator (RID 500), the account GitHub's
    Windows runners run as, so an owner-only file of theirs reads (A;;FA;;;LA), not their S-1-5-21-… SID."""
    from oarbank.platform import _win32 as W
    me = W.current_user_sid()
    assert W.canonical_sid("SY") == "S-1-5-18" and W.canonical_sid("BA") == "S-1-5-32-544" and W.canonical_sid(me) == me
    admin = W.canonical_sid("LA")
    assert admin.startswith("S-1-5-21-") and admin.endswith("-500")
    f = tmp_path / "f"
    f.write_text("x", encoding="utf-8")
    sd = W.SecurityDescriptor("D:P(A;;FA;;;SY)(A;;FA;;;LA)(A;;FA;;;OW)")
    assert not W.SetNamedSecurityInfoW(str(f), W.SE_FILE_OBJECT, W.DACL_SECURITY_INFORMATION |
                                       W.PROTECTED_DACL_SECURITY_INFORMATION, None, None, sd.dacl(), None)
    assert ";;;LA)" in W.dacl_sddl(str(f)) and W.allowed_sids(str(f)) == {"S-1-5-18", admin, "S-1-3-4"}
    assert files.owner_only(f) == (me == admin)          # the built-in Administrator is trusted only when it is the owner


@windows
def test_the_admin_pipe_stays_reachable_while_clients_come_and_go(tmp_path):
    """Checks in a row (the CLI deciding how to reach oarbankd) each find the pipe: one that comes while the last
    client's instance is taken and the next not made yet waits for it. open() could not, as the C runtime reports a
    busy pipe as EINVAL; on CI the CLI then took a running coordinator for gone."""
    import asyncio
    import threading
    import httpx
    from fastapi import FastAPI
    from oarbank.platform import _winpipe, localchannel
    app = FastAPI()
    app.get("/ping")(lambda: {"ok": True})
    srv = localchannel.server(app, tmp_path, log_level="warning")
    t = threading.Thread(target=lambda: asyncio.run(srv.serve()), daemon=True)
    t.start()
    try:
        assert wait_for(lambda: localchannel.reachable(tmp_path), 20)
        why = [_winpipe.unreachable(localchannel.address(tmp_path)) for _ in range(300)]
        assert not any(why), sorted({w for w in why if w})
        with httpx.Client(transport=localchannel.transport(tmp_path), base_url="http://oarbank") as c:
            assert c.get("/ping").json() == {"ok": True}
    finally:
        srv.should_exit = True
        t.join(20)


def _elevated() -> bool:
    return sys.platform == "win32" and bool(ctypes.windll.shell32.IsUserAnAdmin())


SERVICE = """
import sys, threading
sys.path[:0] = {paths!r}
from oarbank.platform import service
done = threading.Event()
def main():
    service.log_to(__import__("pathlib").Path({log!r}))
    if sys.argv[1] == "exit75":
        service.exit_now(75)
    print("running", flush=True)
    done.wait(60)
    return 0
sys.exit(service.run(main, done.set))
"""


def _sc(*args) -> str:
    return subprocess.run(["sc.exe", *args], capture_output=True, text=True).stdout


def _state(name: str) -> dict:
    out = {}
    for line in _sc("queryex", name).splitlines():
        k, _, v = line.strip().partition(":")
        out[k.strip()] = v.strip()
    return out


@windows
@pytest.mark.skipif(sys.platform == "win32" and not _elevated(),
                    reason="creating a service needs an elevated account (CI runners and the VM's ssh are)")
@pytest.mark.parametrize("mode", ["stop", "exit75"])
def test_the_service_host_reports_running_stops_and_reports_exit_codes(tmp_path, mode):
    """A real service of the service control manager runs the host: it reports running, a stop control ends main and
    reports exit 0, and exit_now(75) reports the service-specific code the recovery actions restart on."""
    name = f"oarbank-test-{uuid.uuid4().hex[:8]}"
    script, log = tmp_path / "svc.py", tmp_path / "svc.log"
    src = str(Path(__file__).resolve().parents[1] / "src")
    script.write_text(SERVICE.format(paths=[src, *[p for p in sys.path if "site-packages" in p]], log=str(log)), encoding="utf-8")
    subprocess.run(["icacls", str(tmp_path), "/grant", "*S-1-5-18:(OI)(CI)F"], check=True, capture_output=True)
    bin_path = f'"{sys._base_executable}" -I "{script}" {mode}'
    assert "SUCCESS" in _sc("create", name, "binPath=", bin_path, "obj=", "LocalSystem", "start=", "demand")
    try:
        _sc("start", name)
        if mode == "stop":
            assert wait_for(lambda: "RUNNING" in _state(name).get("STATE", ""), 30), _state(name)
            assert wait_for(lambda: log.exists() and "running" in log.read_text(encoding="utf-8"), 30)
            _sc("stop", name)
            assert wait_for(lambda: "STOPPED" in _state(name).get("STATE", ""), 30), _state(name)
            st = _state(name)
            assert st["WIN32_EXIT_CODE"].startswith("0") and st["SERVICE_EXIT_CODE"].startswith("0"), st
        else:
            assert wait_for(lambda: "STOPPED" in _state(name).get("STATE", ""), 30), _state(name)
            st = _state(name)
            assert st["WIN32_EXIT_CODE"].startswith("1066") and st["SERVICE_EXIT_CODE"].startswith("75"), st
    finally:
        _sc("stop", name)
        wait_for(lambda: "STOPPED" in _state(name).get("STATE", "STOPPED"), 30)
        _sc("delete", name)


@windows
def test_the_secret_store_wraps_keys_with_dpapi_in_an_owner_only_file(tmp_path, monkeypatch):
    from oarbank.platform import secrets as store
    monkeypatch.setenv("OARBANK_SECRET_STORE", "dpapi")
    k = store.get_or_create("audit-signing", tmp_path)
    f = tmp_path / "keys" / "audit-signing.dpapi"
    assert len(k) == 32 and store.get_or_create("audit-signing", tmp_path) == k
    assert files.owner_only(f) and k not in f.read_bytes()            # wrapped, never the raw key
    monkeypatch.delenv("OARBANK_SECRET_STORE")
    assert store.backend() == "dpapi"
