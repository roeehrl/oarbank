"""Vendor update trust (D31): an agent built with the vendor's TUF root installs only agent builds the vendor's
metadata lists, as mirrored by its coordinator; a build the vendor did not list is refused before it is installed."""
import importlib.util
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import CARGO, REPO, agent_env  # noqa: E402
from test_agent_session import wait  # noqa: E402
from test_agent_update import node, upload_and_canary  # noqa: E402

spec = importlib.util.spec_from_file_location("tuf_vendor", REPO / "scripts" / "tuf_vendor.py")
tuf_vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tuf_vendor)


def build(version, target, extra=None):
    env = {**os.environ, "PATH": f"{os.path.dirname(CARGO)}:{os.environ.get('PATH', '')}", "OARBANK_AGENT_VERSION": version,
           **(extra or {})}
    r = subprocess.run([CARGO, "build", "-q", "-p", "oarbank-agent", "-p", "oarbank-launcher", "--target-dir", str(target)],
                       cwd=REPO / "rust", env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-2000:]
    return target / "debug" / "oarbank-agent", target / "debug" / "oarbank-launcher"


def test_only_vendor_listed_builds_install(coordinator, tmp_path):
    keys, repo = tmp_path / "vendor-keys", tmp_path / "vendor-repo"
    tuf_vendor.init(keys, repo)
    t = REPO / "rust" / "target-e2e"
    v1, launcher = build("1.0.0-alpha.1", t / "tuf1", {"OARBANK_TUF_ROOT": str(repo / "root.json")})
    v2, _ = build("1.0.0-alpha.2", t / "v2")
    v3, _ = build("1.0.0-alpha.3", t / "tuf3", {"OARBANK_TUF_ROOT": str(repo / "root.json")})
    platform = json.loads(subprocess.run([str(v1), "facts"], capture_output=True, text=True).stdout)["platform"]
    plat = f"{platform['os']}-{platform['arch']}"
    tuf_vendor.add(keys, repo, f"oarbank-agent-1.0.0-alpha.2-{plat}", v2)
    # a root rotation on the way: the agent follows it from the root it was built with
    tuf_vendor.rotate_root(keys, repo, "timestamp")
    files = {p.name: p.read_text() for p in sorted(repo.glob("*.json"))}
    coordinator.api("POST", "/api/v1/ops/vendor.metadata.upload", json={"params": {"files": files}, "reason": "e2e"},
                    headers={"idempotency-key": "tuf-1"})
    home = tmp_path / "agent"
    home.mkdir()
    assert subprocess.run([str(launcher), "--home", str(home), "install", str(v1)], capture_output=True).returncode == 0
    p = subprocess.Popen([str(launcher), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        n = wait(lambda: (lambda x: x if x and x.get("agent_build") else None)(node(coordinator)), timeout=60)
        # not listed by the vendor: refused before anything is installed
        sha3 = upload_and_canary(coordinator, v3, n["node_id"])
        upd = wait(lambda: (lambda u: u if u.get("state") == "failed" and u.get("target") == sha3 else None)(
            json.loads(node(coordinator)["agent_update_json"] or "{}")), timeout=120)
        assert "vendor" in upd["error"], upd
        assert not any("1.0.0-alpha.3" in str(x) for x in (home / "versions").iterdir())
        # listed: installed and confirmed
        sha2 = upload_and_canary(coordinator, v2, n["node_id"])
        wait(lambda: node(coordinator)["agent_build"] == sha2, timeout=120)
        wait(lambda: json.loads(node(coordinator)["agent_update_json"] or "{}").get("state") == "confirmed", timeout=60)
        assert json.loads((home / "tuf" / "root.json").read_text())["signed"]["version"] == 2
    finally:
        p.terminate()
        out = p.communicate(timeout=20)[0]
        print(out[-5000:])
