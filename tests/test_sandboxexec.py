"""The coordinator's per-OS launch of confined module processes (sandboxexec.py): the policy JSON is what the Rust
core's Policy reads, and the Linux/Windows argv runs through the agent's launcher."""
import json
import sys

import pytest
from oarbank_sdk import sandbox as S

from oarbank.coordinator import sandboxexec

RUST_FIELDS = {"module", "ro", "rw", "net", "proxy_port", "broker_socket", "gpu", "exec_rw", "kind", "exe"}


def test_policy_json_has_the_rust_fields():
    pol = S.Policy(module="dev.x", ro=["/a"], rw=["/b"], net="egress-allowlist", proxy_port=4123, kind="coordinator", exe="/py")
    d = json.loads(sandboxexec.policy_json(pol))
    assert set(d) == RUST_FIELDS and d["proxy_port"] == 4123 and d["ro"] == ["/a"]


def test_linux_and_windows_wrap_with_the_agent_launcher(tmp_path, monkeypatch):
    launcher = tmp_path / "oarbank-sandbox"
    launcher.write_text("")
    monkeypatch.setenv("OARBANK_SANDBOX_EXEC", str(launcher))
    monkeypatch.setattr(sys, "platform", "linux")
    argv = sandboxexec.wrap(S.Policy(module="m", rw=[str(tmp_path)]), tmp_path / "p.json", ["/usr/bin/python3", "-I", "x.py"])
    assert argv[:4] == [str(launcher), "sandbox-exec", str(tmp_path / "p.json"), "--"] and argv[4:] == ["/usr/bin/python3", "-I", "x.py"]
    assert json.loads((tmp_path / "p.json").read_text(encoding="utf-8"))["module"] == "m"


@pytest.mark.parametrize("interpreter", ["python/bin/python3.12", "python/python.exe"])
def test_a_coordinator_build_finds_its_own_launcher(tmp_path, monkeypatch, interpreter):
    """bin/oarbank-sandbox beside python/, whose interpreter is python/bin/python3.x on POSIX and python\\python.exe on
    Windows (a Windows build once looked for it in the wrong place and refused every module process)."""
    exe = ".exe" if sys.platform == "win32" else ""
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / f"oarbank-sandbox{exe}").write_text("")
    (tmp_path / interpreter).parent.mkdir(parents=True)
    (tmp_path / interpreter).write_text("")
    monkeypatch.delenv("OARBANK_SANDBOX_EXEC", raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / interpreter))
    assert sandboxexec.launcher() == str((tmp_path / "bin" / f"oarbank-sandbox{exe}").resolve())


def test_no_launcher_is_no_backend(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("OARBANK_SANDBOX_EXEC", str(tmp_path / "missing"))
    assert sandboxexec.backend() is None
    with pytest.raises(RuntimeError):
        sandboxexec.wrap(S.Policy(module="m"), tmp_path / "p.json", ["/bin/true"])


@pytest.mark.skipif(sys.platform != "darwin", reason="Seatbelt")
def test_macos_still_uses_seatbelt(tmp_path):
    assert sandboxexec.backend() == "seatbelt"
    argv = sandboxexec.wrap(S.Policy(module="m", rw=[str(tmp_path)]), tmp_path / "p.sb", ["/bin/echo", "hi"])
    assert "--" in argv and argv[-2:] == ["/bin/echo", "hi"] and (tmp_path / "p.sb").read_text(encoding="utf-8").startswith("(version 1)")
