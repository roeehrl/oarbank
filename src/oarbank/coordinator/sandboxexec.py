"""Starting module processes confined on the coordinator, per OS (oarbank-sdk spec/sandbox.md; architecture.md, "The
module sandbox"). macOS uses the SDK's Seatbelt launcher. Linux and Windows use the agent's launcher, `oarbank-agent
sandbox-exec POLICY.json -- argv` (Landlock and seccomp; an AppContainer), which the coordinator build ships as
`bin/oarbank-sandbox`; `OARBANK_SANDBOX_EXEC` names another copy. The policy is the SDK's `Policy` as JSON, the same
fields the Rust core reads. With no launcher, or one that reports no backend, there is no backend: module processes
are refused, never run unconfined.
"""
import dataclasses
import functools
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def launcher() -> str | None:
    """The agent binary that confines module processes on Linux and Windows."""
    env = os.environ.get("OARBANK_SANDBOX_EXEC")
    if env:
        return env if Path(env).is_file() else None
    exe = ".exe" if sys.platform == "win32" else ""
    here = Path(sys.executable).resolve().parent                     # a coordinator build: python/bin/ beside bin/
    for cand in (here.parent.parent / "bin" / f"oarbank-sandbox{exe}", here / f"oarbank-sandbox{exe}"):
        if cand.is_file():
            return str(cand)
    return shutil.which("oarbank-agent")


@functools.lru_cache(maxsize=4)
def _status(path: str) -> dict:
    try:
        r = subprocess.run([path, "sandbox-status"], capture_output=True, text=True, timeout=20)
        return json.loads(r.stdout) if r.returncode == 0 else {}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {}


def backend() -> str | None:
    """`seatbelt` on macOS; on Linux and Windows the agent launcher's backend (`landlock`, `appcontainer`); else None."""
    if sys.platform == "darwin":
        return "seatbelt"
    path = launcher()
    return _status(path).get("backend") if path else None


def enforced(capability: str) -> bool:
    """This coordinator's sandbox enforces `capability` (spec/sandbox.md, "Enforcement"): Seatbelt every one it is asked
    for; elsewhere what the launcher reports (on Windows `net.egress-allowlist` needs the elevated helper)."""
    if sys.platform == "darwin":
        return True
    path = launcher()
    return bool(path) and (_status(path).get("enforcement") or {}).get(capability) == "enforced"


def policy_json(policy) -> str:
    """The SDK Policy as the launcher reads it."""
    d = dataclasses.asdict(policy) if dataclasses.is_dataclass(policy) else dict(policy)
    keep = ("module", "ro", "rw", "net", "proxy_port", "broker_socket", "gpu", "exec_rw", "kind", "exe")
    return json.dumps({k: d.get(k) for k in keep if k in d}, sort_keys=True)


def wrap(policy, path: Path, argv: list[str]) -> list[str]:
    """Write what the launcher needs for `policy` to `path` and return the argv that runs `argv` confined."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "darwin":
        from oarbank_sdk import sandbox as S
        text, params = S.render(policy)
        return S.launch_argv(S.write_profile(text, path), params, argv)
    exe = launcher()
    if not exe:
        raise RuntimeError("no module sandbox launcher (oarbank-sandbox) on this coordinator")
    tmp = path.with_suffix(".tmp")
    tmp.write_text(policy_json(policy), encoding="utf-8", newline="\n")
    tmp.replace(path)
    return [exe, "sandbox-exec", str(path), "--", *argv]


def is_confined(box) -> bool:
    """The process started through `wrap` in `box` (a platform.procs.Contained) is confined (checked after it answered,
    so it is past its exec): Seatbelt says so on macOS, no_new_privs and a seccomp filter on Linux, and on Windows every
    member of its job but the launcher's shim runs in an AppContainer."""
    pid = box.pid
    if sys.platform == "darwin":
        from oarbank_sdk import sandbox as S
        return S.is_sandboxed(pid)
    if sys.platform.startswith("linux"):
        try:
            st = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
        except OSError:
            return False
        fields = dict(line.split(":", 1) for line in st.splitlines() if ":" in line)
        return fields.get("NoNewPrivs", "").strip() == "1" and fields.get("Seccomp", "").strip() == "2"
    from ..platform import procs
    return procs.app_container_members(box)
