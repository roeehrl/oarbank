"""Host tools on a real agent (docs/design/host-tools.md): the agent detects a JDK from its `release` file in a search
path the fleet defines, reports it, and the coordinator places a job that needs jdk >=17 only where one resolves:

- with only a JDK 11 found, the module's work waits with TOOL_VERSION_UNMET, naming what the node found;
- once a JDK 17 is installed and the node re-detects, the module certifies there and the job runs with exactly that
  JDK in its tools file, whose `release` file it can read inside the sandbox.
"""
import json
import os
import platform
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, install_module  # noqa: E402
from test_agent_files import admit_next, campaign_done, db_rows, module_state, op, planned, start_agent, stop  # noqa: E402
from test_agent_session import wait  # noqa: E402

JAVELIN = REPO / "tests" / "fixtures" / "modules" / "javelin"


def fake_jdk(home: Path, version: str):
    """A JDK home as the detector reads it: a `release` file and bin/java (never run)."""
    (home / "bin").mkdir(parents=True)
    (home / "bin" / ("java.exe" if os.name == "nt" else "java")).write_bytes(b"#!/bin/sh\nexit 1\n")
    arch = "aarch64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
    (home / "release").write_text(f'JAVA_VERSION="{version}"\nOS_ARCH="{arch}"\nIMPLEMENTOR="Oarbank test"\n', encoding="utf-8")


def node_row(c, nid):
    return next(n for n in c.api("GET", "/api/v1/fleet")["nodes"] if n["node_id"] == nid)


def found(c, nid):
    return [i["version"] for i in (json.loads(node_row(c, nid).get("tools_json") or "{}").get("tools") or {}).get("jdk") or []
            if i.get("status") == "ok"]


def test_a_job_needing_jdk_17_waits_on_a_jdk_11_node_and_runs_once_17_is_detected(agent_bin, coordinator, tmp_path):
    jdks = tmp_path / "jdks"
    fake_jdk(jdks / "jdk-11", "11.0.2")
    install_module(coordinator, JAVELIN, tmp_path, approve=True)
    log = []
    # only the fleet's search path: the machine running the test may have JDKs of its own
    p = start_agent(agent_bin, tmp_path / "agent", coordinator, {"OARBANK_TOOLS_BUILTIN_SEARCH": "0"})
    try:
        nid = admit_next(coordinator)
        os_ = node_row(coordinator, nid)["platform"].split("-")[0]
        planned(coordinator, "tools.define", "jdk", {"search": {os_: [str(jdks.resolve() / "*")]}})
        # the release carries the definition; the agent detects the JDK 11 there and reports it
        wait(lambda: found(coordinator, nid) == ["11.0.2"], timeout=120)
        op(coordinator, "mod.javelin.inspect", params={"n": 2})
        (job,) = db_rows(coordinator, "SELECT job_id FROM jobs WHERE campaign_id='c_javelin'")
        why = wait(lambda: (lambda d: d if "TOOL_VERSION_UNMET" in json.dumps(d) else None)(
            coordinator.api("GET", f"/api/v1/explain/job/{job['job_id']}")), timeout=60)
        text = json.dumps(why)
        assert "found 11.0.2 at" in text and "jdk-11" in text and "needs >=17" in text, text
        assert module_state(coordinator, nid, "javelin") != "certified"
        matrix = coordinator.api("GET", "/api/v1/tools?module=javelin")["module"]["rows"]
        assert matrix[0]["code"] == "TOOL_VERSION_UNMET" and matrix[0]["fixes"][0]["label"].startswith("Install on")
        # a JDK 17 arrives; Re-detect
        fake_jdk(jdks / "jdk-17", "17.0.12")
        op(coordinator, "tools.detect", nid)
        wait(lambda: sorted(found(coordinator, nid)) == ["11.0.2", "17.0.12"], timeout=120)
        wait(lambda: module_state(coordinator, nid, "javelin") == "certified", timeout=180)
        assert campaign_done(coordinator, "c_javelin")["f"] == 0
        (res,) = db_rows(coordinator, "SELECT r.result_json FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id "
                                      "WHERE j.campaign_id='c_javelin'")
        payload = json.loads(res["result_json"])["payload"]
        (inst,) = payload["tools"]["jdk"]
        assert inst["version"] == "17.0.12" and Path(inst["path"]) == (jdks / "jdk-17").resolve(), payload
        assert payload["release"] == 'JAVA_VERSION="17.0.12"'          # read inside the sandbox from the granted JDK
    finally:
        stop(p, log)
        print("".join(log)[-6000:])
