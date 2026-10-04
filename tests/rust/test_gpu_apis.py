"""GPU placement by API with the real agent (docs/design/gpu-placement.md): `oarbank-agent gpu-apis` detects what the
SDK's probes detect on this host, the doctor report carries it, and the SDK's gpuinfo example (Metal on macOS; CUDA,
ROCm, Vulkan, OpenCL elsewhere, DirectML too on Windows) is certified where this host provides one of its APIs and
excluded, with GPU_API_MISSING, where it does not."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from test_agent_jobs import node_modules  # noqa: E402
from test_agent_session import wait  # noqa: E402

from oarbank_sdk import gpu, manifest as mf, portable  # noqa: E402

GPUINFO = REPO / "vendor" / "oarbank-sdk" / "examples" / "gpuinfo"


def agent_report(agent_bin, home) -> dict:
    out = subprocess.run([str(agent_bin), "--home", str(home), "gpu-apis"], capture_output=True, text=True, timeout=120,
                         env=agent_env())
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_the_agent_detects_what_the_sdk_detects(agent_bin, tmp_path):
    """One answer from both implementations on this host (the parity a crowd-sourced detection matrix relies on)."""
    a, s = agent_report(agent_bin, tmp_path / "agent"), gpu.detect()
    assert a["host"] == s["host"], (a, s)
    assert set(gpu.KNOWN_APIS) <= set(a["evidence"]) and "containers" in a["evidence"]
    assert a["platform"] == portable.host_platform() and a["agent_version"]
    assert set(a["containers"]) <= set(gpu.KNOWN_APIS)
    if portable.host_platform() == "darwin-arm64":
        assert "metal" in a["host"]


def test_a_real_agent_reports_its_gpu_apis_and_the_module_is_placed_by_them(agent_bin, coordinator, tmp_path):
    install_module(coordinator, GPUINFO, tmp_path, approve=True)          # devices.gpu = "compute" is a grant to approve
    host = portable.host_platform()
    need = mf.load(GPUINFO / "oarbank-module.toml").runner_gpu_need(host)
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        node = lambda: next(iter(coordinator.api("GET", "/api/v1/fleet")["nodes"]))
        doc = wait(lambda: (node().get("doctor") or {}).get("gpu_apis") and node()["doctor"], timeout=180)
        have = doc["gpu_apis"]["host"]
        assert have == gpu.detect()["host"], doc["gpu_apis"]
        if gpu.fits(need["apis"], have):
            # the runner reaches its API from its sandbox: certified on golden evidence
            wait(lambda: node_modules(coordinator).get("gpuinfo", {}).get("state") == "certified", timeout=240)
        else:
            mod = wait(lambda: (node().get("doctor") or {}).get("modules", {}).get("gpuinfo"), timeout=120)
            assert mod["health"] == "undetected"
            assert any(c["name"] == "gpu_apis" and not c["ok"] for c in mod["checks"]), mod
            ex = coordinator.api("GET", f"/api/v1/explain/node/{node()['node_id']}")
            assert ex["headline"]["code"] == "GPU_API_MISSING", ex
    finally:
        p.terminate()
        print(p.communicate(timeout=30)[0][-5000:])
