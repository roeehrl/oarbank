"""Module cleanup on a real agent (docs/protocol.md, "Module cleanup"): a module turned off on the node runs nothing there
any more and the node reports when its data goes; the owner's purge deletes it at once and the coordinator records the
deletion; turned on again, the module runs as before."""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from test_agent_session import read_json, wait  # noqa: E402

TOY = REPO / "vendor" / "oarbank-sdk" / "examples" / "toy"
DAY = 86400.0


def node_of(c):
    return next(iter(c.api("GET", "/api/v1/fleet")["nodes"]), None)


def storage_row(c, nid, module):
    s = c.api("GET", f"/api/v1/nodes/{nid}")["storage"]
    return next((m for m in s["modules"] if m["module"] == module), None) if s["reported"] else None


def events_of(c, kind):
    out, after = [], 0
    while True:
        page = c.api("GET", f"/api/v1/events?after={after}")
        out += [e for e in page if e["kind"] == kind]
        if len(page) < 500:
            return out
        after = page[-1]["event_id"]


def deletions(home, module):
    """The deletions the agent recorded for `module` (state/module-cleanup.json, `done`): it records one after it logged
    it, and after the module's directory is gone, so a recorded deletion is in the agent's output too."""
    f = home / "state" / "module-cleanup.json"
    return [d for d in read_json(f).get("done", []) if d.get("module") == module] if f.exists() else []


def setting(c, nid, key, value=None, module="", reset=False):
    c.api("POST", "/api/v1/ops/settings.apply", json={"target": nid, "reason": "e2e", "params": {"changes": [
        {"scope": "node", "scope_id": nid, "key": key, "module": module, **({"reset": True} if reset else {"value": value})}]}})


def test_a_module_turned_off_keeps_its_data_until_purged_and_runs_again_when_turned_on(agent_bin, coordinator, tmp_path):
    install_module(coordinator, TOY, tmp_path)
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    data = home / "modules-data" / "toy"
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        nid = wait(lambda: node_of(coordinator))["node_id"]
        wait(lambda: storage_row(coordinator, nid, "toy"), timeout=120)                       # the doctor made its data
        assert data.is_dir() and storage_row(coordinator, nid, "toy")["state"] == "enabled"
        (data / "cache.bin").write_bytes(b"x" * 4096)

        # turned off on this node: nothing of it runs, and it waits out the retention (7 days)
        setting(coordinator, nid, "enabled", False, module="toy")
        row = wait(lambda: (lambda r: r if r and r["state"] == "disabled" else None)(storage_row(coordinator, nid, "toy")),
                   timeout=90)
        assert abs(row["delete_at"] - (time.time() + 7 * DAY)) < 600 and row["data_bytes"] >= 4096
        wait(lambda: "toy" not in {m["module"] for m in (coordinator.api("GET", f"/api/v1/nodes/{nid}")["doctor"] or {})
                                   .get("modules", [])}, timeout=90)
        assert data.is_dir()

        # purged: deleted at once, and recorded
        plan = coordinator.api("POST", "/api/v1/ops/modules.purge", json={"target": "toy", "params": {"node": nid},
                                                                           "dry_run": True})["plan"]
        coordinator.api("POST", "/api/v1/ops/modules.purge", json={"plan_id": plan["plan_id"], "reason": "e2e"})
        wait(lambda: not data.exists(), timeout=90)
        ev = wait(lambda: events_of(coordinator, "module_data_deleted"), timeout=60)
        assert ev[0]["reason"].startswith("toy (purged): ") and ev[0]["node_id"] == nid
        wait(lambda: not coordinator.api("GET", f"/api/v1/nodes/{nid}")["storage"]["purges"], timeout=60)

        # turned on again: it is doctored again, and keeps its data
        setting(coordinator, nid, "enabled", module="toy", reset=True)
        wait(lambda: data.is_dir() and (storage_row(coordinator, nid, "toy") or {}).get("state") == "enabled", timeout=120)
    finally:
        p.terminate()
        out += p.communicate(timeout=20)[0]
        print(out[-5000:])
    assert "deleted what the module left on this node" in out


def test_a_retired_node_is_told_so_stops_and_deletes_what_its_modules_left(agent_bin, coordinator, tmp_path):
    """Retiring clears the node's certificate; the agent learns it was retired (403 node_retired), deletes what its modules
    left (here at once: the node's retention is 0) and waits until it is stopped, instead of asking to join again."""
    install_module(coordinator, TOY, tmp_path)
    home = tmp_path / "agent"
    status = tmp_path / "status.json"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url,
                          "--status-file", str(status)], env=agent_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    data = home / "modules-data" / "toy"
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        nid = wait(lambda: node_of(coordinator))["node_id"]
        setting(coordinator, nid, "module_retention_days", 0)
        wait(lambda: storage_row(coordinator, nid, "toy"), timeout=120)
        assert data.is_dir()
        plan = coordinator.api("POST", "/api/v1/ops/nodes.retire", json={"target": nid, "dry_run": True})["plan"]
        coordinator.api("POST", "/api/v1/ops/nodes.retire", json={"plan_id": plan["plan_id"], "reason": "e2e",
                                                                  "confirm": plan["confirm_name"]})
        # done once recorded: the directory goes first, and Windows ends the agent at once, before a line not yet written
        wait(lambda: [d for d in deletions(home, "toy") if d["reason"] == "retired"], timeout=90)
        assert not data.exists()
        assert read_json(status)["error"]["code"] == "E_RETIRED"
        assert p.poll() is None, "it waits instead of exiting"
        assert not [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"]
    finally:
        p.terminate()
        out += p.communicate(timeout=20)[0]
        print(out[-5000:])
    assert "the coordinator says this node was retired" in out and 'why="retired"' in out
