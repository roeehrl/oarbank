"""Co-tenancy on a real agent (docs/design/gpu-cotenancy.md): a synthetic protected process writes a progress source
and a phase source; the node's protection protects it with an immediate rule; the agent reports the phase (with its
tags) and journals each change with the time it was seen; a paired on/off harness run requested through the owner
operation runs on the agent and ends in a decision, and a "no slowdown shown" earns a certificate that goes back to
the node. Synthetic processes and files only (no real protected program, no GPU)."""
import json
import os
import subprocess
import sys
import textwrap
import time
import uuid

sys.path.insert(0, os.path.dirname(__file__))
from conftest import agent_env  # noqa: E402
from test_agent_session import wait  # noqa: E402

TRAINER = textwrap.dedent("""
    import json, sys, time
    events, phase, tag = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(events, "a", buffering=1) as ev:
        while True:
            ev.write(json.dumps({"event": "backward_complete", "wall_time": time.time()}) + "\\n")
            time.sleep(0.05)
""")


def op(c, name, target, params, reason="e2e"):
    from oarbank.contracts import operations as registry
    if registry.REGISTRY[name].tier in ("T2", "T3"):
        plan = c.api("POST", f"/api/v1/ops/{name}", json={"target": target, "params": params, "dry_run": True})["plan"]
        return c.api("POST", f"/api/v1/ops/{name}", json={"plan_id": plan["plan_id"], "reason": reason,
                                                           "confirm": plan["confirm_name"]})
    return c.api("POST", f"/api/v1/ops/{name}", json={"target": target, "params": params, "reason": reason})


def test_phases_harness_and_certificates_on_a_real_agent(agent_bin, coordinator, tmp_path):
    tag = f"fake-trainer-{uuid.uuid4().hex[:8]}"
    data = tmp_path / "trainer"
    data.mkdir()
    events, phase = data / "events-1.jsonl", data / "phase-1.jsonl"
    phase.write_text(json.dumps({"event": "heartbeat_response", "response": {"phase": "training"}}) + "\n")
    script = tmp_path / "trainer.py"
    script.write_text(TRAINER)
    trainer = subprocess.Popen([sys.executable, str(script), str(events), str(phase), tag])
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        nid = coordinator.admit(pending[0]["enrollment_id"])["result"]["node_id"]
        config = {"schema": 1, "node": {"mode": "moderate", "gpu_jobs": "certified"}, "rule": [{
            "id": "trainer", "match": {"argv_regex": tag}, "active_when": "present", "enter_for_s": 0, "immediate": True,
            "protect": {"metric": "progress_rate", "max_slowdown": 0.2,
                        "source": {"jsonl": str(data / "events-*.jsonl"), "event": "backward_complete"}},
            "during": [{"source": {"jsonl": str(data / "phase-*.jsonl"), "event": "heartbeat_response",
                                   "field": "response.phase", "on": ["weights_uploading"]},
                        "pause_fleet": {"scope": "gpu"}, "tags": ["uplink"]}]}]}
        op(coordinator, "protection.rules.update", nid, {"config": config})

        def prot():
            return coordinator.api("GET", f"/api/v1/nodes/{nid}/protection")

        # the agent reports the phase it reads (off), with its tags, read by the agent itself (a personal install)
        wait(lambda: any(x["key"] == "trainer#0" for x in prot()["live"].get("phases") or []), timeout=90)
        ph = next(x for x in prot()["live"]["phases"] if x["key"] == "trainer#0")
        assert (ph["on"], ph["readable"], ph["reader"], ph["tags"], ph["immediate"]) == (False, True, "agent", ["uplink"], True)
        wait(lambda: (prot()["live"].get("progress") or [{}])[0].get("rate"), timeout=60)
        # the phase begins: the agent journals it with the time its watcher saw the change
        with open(phase, "a") as f:
            f.write(json.dumps({"event": "heartbeat_response", "response": {"phase": "weights_uploading"}}) + "\n")
        wait(lambda: next((x["on"] for x in prot()["live"]["phases"] if x["key"] == "trainer#0"), False), timeout=60)

        def phase_records():
            import sqlite3
            con = sqlite3.connect(f"file:{coordinator.home / 'oarbank.sqlite3'}?mode=ro", uri=True)
            try:
                return [json.loads(r[0]) for r in con.execute(
                    "SELECT record_json FROM protection_decisions WHERE node_id=? AND reason='PROTECTION_PHASE_ON'", (nid,))]
            finally:
                con.close()
        recs = wait(phase_records, timeout=60)
        assert recs[-1]["rule"] == "trainer" and recs[-1]["tags"] == ["uplink"] and recs[-1]["event_t"] > 0
        assert recs[-1]["via"] in ("watch", "poll")
        with open(phase, "a") as f:
            f.write(json.dumps({"event": "heartbeat_response", "response": {"phase": "training"}}) + "\n")
        wait(lambda: not next((x["on"] for x in prot()["live"]["phases"] if x["key"] == "trainer#0"), True), timeout=60)
        # a harness run: short windows; no fleet work runs, so ON and OFF are alike and no slowdown is shown
        run = op(coordinator, "protection.ab.start", nid, {"rule": "trainer", "work": "all", "blocks": 2, "pilot_blocks": 2,
                                                           "window_s": 30, "washout_s": 4, "margin": 0.2, "max_hours": 1})
        rid = run["result"]["run_id"]

        def detail():
            return coordinator.api("GET", f"/api/v1/protection/ab/runs/{rid}")
        d = wait(lambda: (lambda x: x if x["state"] in ("done", "aborted") else None)(detail()), timeout=600, step=2)
        assert d["state"] == "done", d
        assert d["blocks_done"] >= 2 and d["decision"] in ("no_slowdown", "inconclusive"), d
        assert d["report"]["identity"], "the run carries the protected program's identity"
        if d["decision"] == "no_slowdown":
            certs = coordinator.api("GET", f"/api/v1/protection/certificates?node={nid}")["certificates"]
            assert certs and certs[0]["status"] == "valid" and certs[0]["run_id"] == rid
        listing = coordinator.api("GET", f"/api/v1/protection/ab/runs?node={nid}")["runs"]
        assert listing[0]["run_id"] == rid
    finally:
        trainer.terminate()
        p.terminate()
        out += p.communicate(timeout=20)[0]
        print(out[-4000:])
