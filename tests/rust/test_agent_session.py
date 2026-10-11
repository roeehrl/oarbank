"""The Rust agent's session: identity first, enrollment by CSR, approval, then hello and heartbeats over mTLS."""
import json
import os
import subprocess
import time

from oarbank.platform import files


def run_agent(agent_bin, home, *args, timeout=60, **kw):
    env = {**os.environ, "OARBANK_LOG": "info"}
    return subprocess.Popen([str(agent_bin), "--home", str(home), *args], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, **kw)


def read_json(path, timeout=5):
    """A JSON file the agent replaces while it is read: Windows refuses the open during the rename, and a read can see
    it half written nowhere else, so retry briefly."""
    end = time.time() + timeout
    while True:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (PermissionError, json.JSONDecodeError):
            if time.time() > end:
                raise
            time.sleep(0.05)


def wait(pred, timeout=30, step=0.2):
    end = time.time() + timeout
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(step)
    raise AssertionError("timed out")


def test_enroll_approve_hello_over_mtls(agent_bin, coordinator, tmp_path):
    home = tmp_path / "agent"
    p = run_agent(agent_bin, home, "run", "--coordinator", coordinator.url)
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        node = wait(lambda: next((n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"] if n.get("last_hello_at")), None),
                    timeout=60)
        facts = json.loads(node["facts_json"]) if isinstance(node.get("facts_json"), str) else node.get("facts") or {}
        assert node["platform"] == "darwin-arm64" or node.get("platform"), node
        cfg = json.loads((home / "agent.json").read_text(encoding="utf-8"))
        trust = cfg["coordinator_trust"]
        assert trust["cik"] and trust["ca_spki_sha256"] and cfg["node_id"] == node["node_id"]
        assert files.owner_only(home / "keys" / "node.key")
        hb0 = node.get("last_heartbeat_at") or 0
        wait(lambda: next((n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"]
                           if (n.get("last_heartbeat_at") or 0) > hb0), None), timeout=40)
    finally:
        p.terminate()
        out = p.communicate(timeout=10)[0]
    assert "enrolled" in out, out[-2000:]


def test_the_agent_applies_its_complete_settings_and_reports_the_revision(agent_bin, coordinator, tmp_path):
    """docs/design/settings.md: every heartbeat reply carries the node's complete effective policy and caps with a
    revision; the agent reports the revision it applied, and a change reaches it at its next heartbeat."""
    home = tmp_path / "agent"
    p = run_agent(agent_bin, home, "run", "--coordinator", coordinator.url)
    node = lambda: next(iter(coordinator.api("GET", "/api/v1/fleet")["nodes"]), None)
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        n = wait(lambda: (lambda x: x if x and x.get("settings_applied_rev") is not None
                          and x["settings_applied_rev"] == x["settings_rev"] else None)(node()), timeout=60)
        nid, rev = n["node_id"], n["settings_rev"]
        coordinator.api("POST", "/api/v1/ops/settings.apply", json={"target": nid, "reason": "e2e", "params": {"changes": [
            {"scope": "node", "scope_id": nid, "key": "job_mem_gb", "value": 2.5}]}})
        n = wait(lambda: (lambda x: x if x["settings_rev"] > rev and x["settings_applied_rev"] == x["settings_rev"] else None)(node()),
                 timeout=40)
        assert json.loads(n["settings_rejected_json"] or "[]") == []
        eff = coordinator.api("GET", f"/api/v1/settings/effective?node={nid}")
        row = next(x for x in eff["settings"] if x["key"] == "job_mem_gb")
        assert row["value"] == 2.5 and row["applied"]["text"] == f"Applied on the node · rev {n['settings_rev']}"
    finally:
        p.terminate()
        p.communicate(timeout=10)


def test_a_join_code_names_the_coordinator_pins_its_ca_and_approves_the_node(agent_bin, coordinator, tmp_path):
    plan = coordinator.api("POST", "/api/v1/ops/nodes.join_code", json={"params": {"label": "mini-2"}, "dry_run": True})["plan"]
    code = coordinator.api("POST", "/api/v1/ops/nodes.join_code", json={"plan_id": plan["plan_id"], "reason": "e2e"})["result"]["code"]
    home = tmp_path / "agent"
    p = run_agent(agent_bin, home, "run", "--join", code)
    try:
        node = wait(lambda: next((n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"] if n.get("last_hello_at")), None), 60)
        assert not coordinator.api("GET", "/api/v1/fleet")["enrollments"]            # never waited for the owner
        assert node["hostname"] == "mini-2"                                             # the label names it, after hello too
        cfg = json.loads((home / "agent.json").read_text(encoding="utf-8"))
        assert cfg["coordinator"] == coordinator.url and "join_secret" not in cfg
    finally:
        p.terminate()
        p.communicate(timeout=10)
    # the code works once: a second machine is told so (E_CODE_USED) and leaves nothing waiting on the Fleet page
    status = tmp_path / "status2" / "node.json"
    p2 = run_agent(agent_bin, tmp_path / "agent2", "run", "--join", code, "--status-file", str(status))
    try:
        st = wait(lambda: status.exists() and json.loads(status.read_text()).get("error") and json.loads(status.read_text()), 40)
        assert (st["state"], st["error"]["code"]) == ("error", "E_CODE_USED")
        assert not [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"]
    finally:
        p2.terminate()
        p2.communicate(timeout=10)
