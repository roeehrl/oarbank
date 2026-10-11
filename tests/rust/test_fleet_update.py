"""Fleet updates end to end (docs/design/fleet-updates.md; D56, D57, D59): a real oarbankd, a real agent under a real
launcher, and the node's update runner (`oarbank-launcher update-run`, unprivileged here with the tar format a Linux
tarball install uses). A release is imported from its manifest and artifacts and rolled out with one operation: the
agent downloads and verifies the package, drains and hands it to the runner; the runner installs it, points
`current` at its agent and commits once the new agent confirmed. A release whose agent cannot start is rolled back by
the runner to the package it kept, and the rollout halts on the failure."""
import hashlib
import json
import os
import subprocess
import sys
import tarfile

sys.path.insert(0, os.path.dirname(__file__))
from conftest import agent_env, build_version, pointer  # noqa: E402
from test_agent_session import wait  # noqa: E402
from helpers import stop_tree  # noqa: E402

def release_dir(binary, version, seq, dest):
    """A release's tarball for this machine (the format a Linux tarball install uses; the runner's tar install is the
    same on every OS) and its manifest, canonical JSON as scripts/fleet-manifest.py writes it."""
    from oarbank_sdk import portable
    dest.mkdir(parents=True)
    plat = portable.host_platform()
    name = f"oarbank-agent-{version}-{plat}.tar.gz"
    with tarfile.open(dest / name, "w:gz") as t:
        t.add(binary, arcname=binary.name)                          # oarbank-agent, oarbank-agent.exe on Windows
    data = (dest / name).read_bytes()
    manifest = {"type": "oarbank-fleet-release", "format": 1, "version": version, "seq": seq, "agent_min": "0.0.1",
                "stops": [], "released_at": "2026-10-11T00:00:00Z", "expires": None, "notes": None,
                "artifacts": [{"name": name, "role": "node", "platform": plat, "format": "tar",
                               "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "agent_version": version}]}
    (dest / f"oarbank-fleet-{version}.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    return dest


def op(c, name, target=None, params=None, plan=False):
    body = {"params": params or {}, **({"target": target} if target else {})}
    if plan:
        p = c.api("POST", f"/api/v1/ops/{name}", json={**body, "dry_run": True})["plan"]
        return c.api("POST", f"/api/v1/ops/{name}", json={"plan_id": p["plan_id"], "reason": "e2e"})
    return c.api("POST", f"/api/v1/ops/{name}", json={**body, "reason": "e2e"})


def node(c):
    return next(iter(c.api("GET", "/api/v1/fleet")["nodes"]), None)


def updates(c):
    return c.api("GET", "/api/v1/updates")


def unode(c):
    """The node as the Updates page sees it: version, install, the agent's update report."""
    return next(iter(updates(c)["nodes"]), {})


def report(c):
    return unode(c).get("report") or {}


def last_rollout(c):
    return (updates(c)["history"] or [{}])[0]


def test_a_rollout_updates_the_package_and_a_release_that_cannot_start_is_rolled_back(coordinator, tmp_path):
    v1, launcher = build_version("1.0.0-alpha.1", tmp_path / "v1")
    v2, _ = build_version("1.0.0-alpha.2", tmp_path / "v2")
    v3, _ = build_version("1.0.0-alpha.3", tmp_path / "v3", {"OARBANK_AGENT_TEST_CRASH": "1"})
    home, state, prefix = tmp_path / "agent", tmp_path / "update", tmp_path / "prefix"
    home.mkdir()
    assert subprocess.run([str(launcher), "--home", str(home), "install", str(v1)], capture_output=True).returncode == 0
    trust = subprocess.run([str(launcher), "update-trust", "--unsigned", "--agent-home", str(home), "--state", str(state)],
                           capture_output=True, text=True)
    assert trust.returncode == 0, trust.stderr
    env = {**agent_env(), "OARBANK_INSTALL_FORMAT": "tar", "OARBANK_UPDATE_TRIGGER": "external"}
    agent = subprocess.Popen([str(launcher), "--home", str(home), "run", "--coordinator", coordinator.url], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    runner = subprocess.Popen([str(launcher), "update-run", "--agent-home", str(home), "--state", str(state),
                               "--prefix", str(prefix), "--probation-s", "45"],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        n = wait(lambda: (lambda x: x if x and x.get("agent_version") else None)(node(coordinator)), timeout=60)
        assert n["agent_version"] == "1.0.0-alpha.1"
        inst = wait(lambda: unode(coordinator).get("install") or None, timeout=60)
        assert inst["format"] == "tar" and inst["updater"] is True, inst

        # 1.0.0-alpha.2: imported, rolled out with one operation, installed by the runner and confirmed
        op(coordinator, "updates.import", params={"dir": str(release_dir(v2, "1.0.0-alpha.2", 2, tmp_path / "r2"))})
        op(coordinator, "updates.start", target="1.0.0-alpha.2", plan=True)
        wait(lambda: report(coordinator).get("state") == "done", timeout=240)
        assert node(coordinator)["agent_version"] == "1.0.0-alpha.2"
        assert "1.0.0-alpha.2" in pointer(home / "current")
        assert json.loads((state / "journal.json").read_text())["committed_release"] == "1.0.0-alpha.2"
        # the last ring bakes too: 10 heartbeats on the new release (10 s apart) before the rollout is done
        wait(lambda: last_rollout(coordinator).get("state") == "done", timeout=240)

        # 1.0.0-alpha.3 never starts: the runner reinstalls the alpha.2 package it kept; the rollout halts
        op(coordinator, "updates.import", params={"dir": str(release_dir(v3, "1.0.0-alpha.3", 3, tmp_path / "r3"))})
        op(coordinator, "updates.start", target="1.0.0-alpha.3", plan=True)
        rep = wait(lambda: (lambda r: r if r.get("state") == "rolled_back" else None)(report(coordinator)), timeout=300)
        assert rep["release"] == "1.0.0-alpha.3"
        wait(lambda: node(coordinator)["agent_version"] == "1.0.0-alpha.2", timeout=120)
        assert "1.0.0-alpha.2" in pointer(home / "current")
        result = json.loads((home / "updates" / "result.json").read_text())
        assert result["state"] == "rolled_back" and result["release"] == "1.0.0-alpha.3"
        wait(lambda: any(r["version"] == "1.0.0-alpha.3" and r["state"] in ("halted", "rolling_back", "rolled_back")
                         for r in updates(coordinator)["history"]), timeout=60)
    finally:
        out = ""
        for p in (agent, runner):
            stop_tree(p.pid)
            out += p.communicate(timeout=20)[0][-4000:]
        print(out)
