"""End-to-end tests of the Rust agent (rust/crates/oarbank-agent) against a real oarbankd subprocess."""
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

import agentbin
from agentbin import CARGO, REPO
from oarbank.platform.files import venv_python


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def agent_bin():
    if not CARGO:
        pytest.skip("no Rust toolchain")
    return agentbin.build()


class Coordinator:
    def __init__(self, home: Path, extra_args=(), extra_env=None, wait_admin=True):
        self.home, self.agent_port, self.admin_port = home, free_port(), free_port()
        self.extra_args, self.extra_env, self.wait_admin = list(extra_args), dict(extra_env or {}), wait_admin
        self.url = f"https://127.0.0.1:{self.agent_port}"
        self.admin = f"http://127.0.0.1:{self.admin_port}"

    def __enter__(self):
        self.start()
        if not self.wait_admin:
            return self
        for _ in range(300):
            if self.proc.poll() is not None:
                raise RuntimeError((self.home.parent / f"{self.home.name}.log").read_text(encoding="utf-8")[-3000:])
            try:
                if (self.home / "admin.token").exists() and httpx.get(f"{self.admin}/api/v1/fleet", headers=self.auth(), timeout=1).status_code == 200:
                    return self
            except httpx.HTTPError:
                pass
            time.sleep(0.1)
        raise RuntimeError("oarbankd did not start")

    def start(self):
        env = {**os.environ, "OARBANKD_HOME": str(self.home), "OARBANK_RELEASE_SIGNING": "0", "OARBANK_SECRET_STORE": "file",
               "OARBANKD_TAILSCALE": "/nonexistent", "PYTHONUNBUFFERED": "1", "OARBANKD_DISCOVERY": "0", **self.extra_env}
        self.log = open(self.home.parent / f"{self.home.name}.log", "ab")
        self.proc = subprocess.Popen([sys.executable, "-m", "oarbank.coordinator", "--agent-bind", "127.0.0.1",
                                      "--agent-port", str(self.agent_port),
                                      "--admin-port", str(self.admin_port), *self.extra_args],
                                     env=env, stdout=self.log, stderr=subprocess.STDOUT)

    def auth(self):
        return {"authorization": f"Bearer {(self.home / 'admin.token').read_text(encoding="utf-8").strip()}"}

    def api(self, method, path, headers=None, **kw):
        r = httpx.request(method, f"{self.admin}{path}", headers={**self.auth(), **(headers or {})}, timeout=30, **kw)
        assert r.status_code < 400, (path, r.status_code, r.text)
        return r.json() if r.text else None

    def admit(self, eid):
        """nodes.admit as the owner does it: previewed (T2), then the plan applied with a reason. The node then reserves
        no memory for the OS or a person (nodes.set_policy): these tests drive the agent's work, not host protection, so
        the test machine's memory (an 8 GB VM) and whether someone seems to be using it never decide whether work runs."""
        plan = self.api("POST", "/api/v1/ops/nodes.admit", json={"target": eid, "dry_run": True})["plan"]
        out = self.api("POST", "/api/v1/ops/nodes.admit", json={"plan_id": plan["plan_id"], "reason": "e2e"})
        self.api("POST", "/api/v1/ops/nodes.set_policy", json={"target": out["result"]["node_id"], "reason": "e2e",
                                                               "params": {"patch": {"os_reserve_gb": 0, "user_reserve_gb": 0}}})
        return out

    def __exit__(self, *a):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture
def coordinator(tmp_path):
    home = tmp_path / "coordinator"
    home.mkdir()
    with Coordinator(home) as c:
        yield c


def install_module(c: "Coordinator", src: Path, tmp: Path, version_note: str = "test", approve: bool = False) -> dict:
    """Build a module bundle with the SDK and install + enable it through the admin API (the operator's path); `approve`:
    approve its sandbox grants first, as a version that asks for any needs."""
    from oarbank_sdk import bundle as B
    out, info = B.build(src, tmp / f"{src.name}.mfb")
    sha = c.api("POST", "/api/v1/modules/bundles", content=out.read_bytes())["sha256"]
    plan = c.api("POST", "/api/v1/ops/modules.install", json={"params": {"sha256": sha}, "dry_run": True})["plan"]
    c.api("POST", "/api/v1/ops/modules.install", json={"plan_id": plan["plan_id"], "reason": version_note})
    name = info.name
    if approve:
        plan = c.api("POST", "/api/v1/ops/modules.approve", json={"target": f"{name}@{info.version}", "dry_run": True})["plan"]
        c.api("POST", "/api/v1/ops/modules.approve", json={"plan_id": plan["plan_id"], "reason": version_note})
    c.api("POST", "/api/v1/ops/modules.enable", json={"target": f"{name}@{info.version}", "reason": version_note})
    return {"name": name, "version": info.version}


def agent_env():
    return {**os.environ, "OARBANK_LOG": "info", "OARBANK_RUNTIME_PYTHON": str(venv_python(REPO / ".venv")),
            "OARBANK_UV": shutil.which("uv") or ""}


def build_version(version: str, dest: Path, extra_env=None) -> tuple[Path, Path]:
    """The agent and launcher built as `version` (and `extra_env`, e.g. a vendor TUF root), copied into `dest`. Every
    version builds in one target directory (`rust/target-e2e`), so each build after the first only rebuilds what the
    variables change, and a run keeps one copy of the build tree, not one per version."""
    env = {**agentbin.cargo_env(), "OARBANK_AGENT_VERSION": version, **(extra_env or {})}
    r = subprocess.run([CARGO, "build", "-q", "-p", "oarbank-agent", "-p", "oarbank-launcher", "--target-dir",
                        str(REPO / "rust" / "target-e2e")], cwd=REPO / "rust", env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-2000:]
    dest.mkdir(parents=True, exist_ok=True)
    out = []
    for name in ("oarbank-agent", "oarbank-launcher"):
        exe = f"{name}{agentbin.EXE}"
        shutil.copy2(REPO / "rust" / "target-e2e" / "debug" / exe, dest / exe)
        out.append(dest / exe)
    return out[0], out[1]


def pointer(link: Path) -> str:
    """What a `current` link names: a symlink's target on POSIX, a pointer file's content on Windows (fsutil.rs `point`)."""
    return os.readlink(link) if os.name == "posix" else link.read_text(encoding="utf-8").strip()
