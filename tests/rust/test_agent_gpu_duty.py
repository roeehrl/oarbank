"""GPU duty on a real agent (docs/design/gpu-cotenancy.md, "The duty governor"; SDK docs/gpu-duty.md): the SDK's GPU
reference module `llmserve` is certified by its selftest golden, a `batch` job runs on its CPU stand-in backend, and a
paired on/off harness run with `gpu_duty` 0.3 measures it beside a synthetic protected process. In ON windows the agent
writes the duty into the job's control document and nudges it, and the runner's duty governor holds it: its
`gpu_duty` reports say 0.3 asked and at most 0.4 held. In OFF windows the job is paused. Synthetic processes only (no
real protected program, no GPU)."""
import json
import os
import signal
import subprocess
import sys
import textwrap
import uuid

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from procguard import SpawnTree  # noqa: E402
from test_agent_cotenancy import op  # noqa: E402
from test_agent_jobs import node_modules  # noqa: E402
from test_agent_session import wait  # noqa: E402

LLMSERVE = REPO / "vendor" / "oarbank-sdk" / "examples" / "llmserve"

TRAINER = textwrap.dedent("""
    import json, sys, time
    events = sys.argv[1]
    with open(events, "a", buffering=1) as ev:
        while True:
            ev.write(json.dumps({"event": "step", "wall_time": time.time()}) + "\\n")
            time.sleep(0.05)
""")


def test_a_cooperative_runner_holds_the_duty_the_agent_writes(agent_bin, coordinator, tmp_path):
    install_module(coordinator, LLMSERVE, tmp_path, approve=True)
    tag = f"fake-trainer-{uuid.uuid4().hex[:8]}"
    data = tmp_path / "trainer"
    data.mkdir()
    script = tmp_path / "trainer.py"
    script.write_text(TRAINER)
    tree = SpawnTree().__enter__()                       # every process this test starts: the only ones it signals
    trainer = subprocess.Popen([sys.executable, str(script), str(data / "events-1.jsonl"), tag])
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        nid = coordinator.admit(pending[0]["enrollment_id"])["result"]["node_id"]
        op(coordinator, "protection.rules.update", nid, {"config": {"schema": 1, "node": {"mode": "moderate"}, "rule": [{
            "id": "trainer", "match": {"argv_regex": tag}, "active_when": "present", "enter_for_s": 0,
            "protect": {"metric": "progress_rate", "max_slowdown": 0.5,
                        "source": {"jsonl": str(data / "events-*.jsonl"), "event": "step"}}}]}})
        # the selftest golden (the deterministic stand-in) certifies the module on the node
        wait(lambda: node_modules(coordinator).get("llmserve", {}).get("state") == "certified", timeout=300, step=1)
        r = coordinator.api("POST", "/api/v1/ops/mod.llmserve.queue_prompts", json={"params": {
            "prompts": [f"prompt {i}: the fleet runs work beside the programs its owner protects" for i in range(20)],
            "per_job": 20, "max_tokens": 4096, "backend": "stub", "work": 384, "mem_gb": 0.3}, "reason": "e2e"},
            headers={"idempotency-key": "e2e-duty"})                        # minutes of work: longer than the test
        cid = r["result"]["result"]["campaign_id"]

        def control_docs():
            return [(f, json.loads(f.read_text())) for f in (home / "work").rglob("control.json")]
        wait(lambda: control_docs(), timeout=240, step=1)               # the batch job runs
        run = op(coordinator, "protection.ab.start", nid, {"rule": "trainer", "work": "llmserve",
                                                           "duty": 0.3, "blocks": 2, "pilot_blocks": 2, "window_s": 30,
                                                           "washout_s": 4, "margin": 0.3, "max_hours": 1})
        rid = run["result"]["run_id"]
        # an ON window: the duty reaches the job's control document
        f, doc = wait(lambda: next(((f, d) for f, d in control_docs() if d.get("gpu_duty") == 0.3 and not d.get("pause")),
                                   None), timeout=240, step=0.5)
        events = f.parent / "events.ndjson"

        def held():
            if not events.exists():
                return None
            lines = [json.loads(x) for x in events.read_text().splitlines() if x.strip()]
            got = [x for x in lines if x.get("kind") == "metric" and x.get("name") == "gpu_duty"
                   and (x.get("data") or {}).get("asked") == 0.3]
            return got[1:] or None                                      # the first may straddle the change
        reports = wait(held, timeout=60, step=0.5)
        assert all(x["value"] <= 0.4 for x in reports), reports
        assert all(x["data"]["device"] == "cpu" for x in reports)
        # an OFF window pauses the job (cooperative pause in its control document)
        wait(lambda: any(d.get("pause") for _, d in control_docs()), timeout=240, step=0.5)
        coordinator.api("POST", "/api/v1/ops/protection.ab.abort", json={"target": rid, "reason": "e2e"})
        assert coordinator.api("GET", f"/api/v1/campaigns/{cid}")["jobs"]["f"] == 0
    finally:
        tree.signal(trainer.pid, signal.SIGTERM)
        tree.signal(p.pid, signal.SIGTERM)
        try:
            out += p.communicate(timeout=30)[0]
        except subprocess.TimeoutExpired:
            tree.signal(p.pid, signal.SIGKILL)
            out += p.communicate(timeout=10)[0]
        trainer.wait(10)
        print(out[-4000:])
        tree.check_journal(home)                         # every actuation the agent journaled was on the test's own tree
        tree.__exit__(None, None, None)
