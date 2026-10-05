"""The Rust agent runs work: the module's golden jobs certify it on this node, then campaign jobs run in the sandbox,
their results are accepted and become canonical."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from test_agent_session import wait  # noqa: E402

TOY = REPO / "vendor" / "oarbank-sdk" / "examples" / "toy"
DEPOT = REPO / "tests" / "fixtures" / "modules" / "depot"


def node_modules(c):
    import json
    n = next(iter(c.api("GET", "/api/v1/fleet")["nodes"]), None)
    return json.loads(n["modules_json"] or "{}") if n else {}


def test_goldens_certify_then_campaign_jobs_complete(agent_bin, coordinator, tmp_path):
    install_module(coordinator, TOY, tmp_path)
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        wait(lambda: node_modules(coordinator).get("toy", {}).get("state") == "certified", timeout=120)
        r = coordinator.api("POST", "/api/v1/ops/mod.toy.queue_sums", json={"params": {"ns": [10, 1000, 20000]}, "reason": "e2e"},
                           headers={"idempotency-key": "e2e-1"})
        cid = r["result"]["result"]["campaign_id"]
        jobs = wait(lambda: (lambda j: j if j["n"] == 3 and j["d"] == 3 else None)(
            coordinator.api("GET", f"/api/v1/campaigns/{cid}")["jobs"]), timeout=120)
        assert jobs["f"] == 0
        # after a restart the agent runs its doctors again and keeps taking work
        p.terminate()
        out += p.communicate(timeout=20)[0]
        p = subprocess.Popen([str(agent_bin), "--home", str(home), "run"], env=agent_env(),
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        r = coordinator.api("POST", "/api/v1/ops/mod.toy.queue_sums", json={"params": {"ns": [5, 6]}, "reason": "e2e"},
                           headers={"idempotency-key": "e2e-2"})
        cid2 = r["result"]["result"]["campaign_id"]
        wait(lambda: (lambda j: j if j["d"] == 2 else None)(coordinator.api("GET", f"/api/v1/campaigns/{cid2}")["jobs"]), timeout=120)
    finally:
        p.terminate()
        out += p.communicate(timeout=10)[0]
        print(out[-5000:])
    assert "granted" in out and "completed" in out


def test_a_bootstrap_stage_provisions_what_the_goldens_mount_on_a_fresh_fleet(agent_bin, coordinator, tmp_path):
    """docs/design/bootstrap-stages.md on a real agent: the node is certifying and its golden waits for a dataset nobody
    registered; the bootstrap fetch job runs there anyway, sandboxed with the bootstrap grants (the depot runner fails
    otherwise), its uploaded files are exactly the pins, so the coordinator registers the dataset; the agent stages it,
    the golden passes, and the module's jobs run on the now certified node."""
    install_module(coordinator, DEPOT, tmp_path, approve=True)
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        node = wait(lambda: next(iter(coordinator.api("GET", "/api/v1/fleet")["nodes"]), None))
        coordinator.api("POST", "/api/v1/ops/nodes.set_policy", json={            # settings a bootstrap job must never see
            "target": node["node_id"], "params": {"patch": {"module_settings": {"depot": {"token": "secret"}}}}, "reason": "e2e"})
        wait(lambda: node_modules(coordinator).get("depot", {}).get("state") == "certifying", timeout=120)
        assert not [d for d in coordinator.api("GET", "/api/v1/datasets") if d["dataset_id"] == "tool:depot-1"]
        coordinator.api("POST", "/api/v1/ops/mod.depot.provision", json={"params": {"evals": 2}, "reason": "e2e"},
                        headers={"idempotency-key": "e2e-boot"})
        wait(lambda: node_modules(coordinator).get("depot", {}).get("state") == "certified", timeout=180)
        jobs = wait(lambda: (lambda j: j if j["d"] == 3 else None)(coordinator.api("GET", "/api/v1/campaigns/c_provision")["jobs"]),
                    timeout=120)
        assert jobs["f"] == 0
        (ds,) = [d for d in coordinator.api("GET", "/api/v1/datasets") if d["dataset_id"] == "tool:depot-1"]
        assert ds["module"] == "depot" and ds["kind"] == "tool"
    finally:
        p.terminate()
        out += p.communicate(timeout=10)[0]
        print(out[-5000:])


VAULT = REPO / "tests" / "fixtures" / "modules" / "vault"


def test_a_secret_reaches_only_its_stage_runner_and_no_log_shows_it(agent_bin, coordinator, tmp_path):
    """docs/design/secrets-and-signed-images.md (#14) on a real agent: the call stage's runner finds the secret in an
    owner-only file inside its work directory; the probe stage's runner gets no file; a runner that prints the key has it
    redacted from the log the agent streams and from its failure; the coordinator's database never holds it."""
    import hashlib
    import json
    import sqlite3
    install_module(coordinator, VAULT, tmp_path, approve=True)
    key = "sk-e2e-6d0b1f2a9c8e7d34"
    coordinator.api("POST", "/api/v1/ops/secrets.set", json={"target": "vault", "params": {"name": "api_key"}, "secret": key,
                                                             "reason": "e2e"})
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = ""
    db = coordinator.home / "oarbank.sqlite3"

    def q(sql, *args):
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            return c.execute(sql, args).fetchall()
        finally:
            c.close()
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        try:
            wait(lambda: node_modules(coordinator).get("vault", {}).get("state") == "certified", timeout=120)
        except AssertionError:
            # say why the goldens failed: the agent's reason and the runner's (or the agent's own) stderr
            for (pj,) in q("SELECT payload_json FROM events WHERE kind='attempt_failed' ORDER BY event_id DESC LIMIT 3"):
                print("golden failed:", (json.loads(pj or "{}").get("stderr_tail") or "")[-1500:])
            raise
        coordinator.api("POST", "/api/v1/ops/mod.vault.call", json={"params": {}, "reason": "e2e"},
                        headers={"idempotency-key": "e2e-call"})
        wait(lambda: (lambda j: j if j["d"] == 2 else None)(coordinator.api("GET", "/api/v1/campaigns/c_call")["jobs"]), timeout=120)
        seen = {stage: json.loads(r)["payload"]["secrets"] for stage, r in q(
            "SELECT j.stage, r.result_json FROM results r JOIN jobs j ON j.job_id=r.job_id WHERE j.campaign_id='c_call'")}
        assert seen["probe"] == {"file": False}
        call = seen["call"]
        assert call["file"] and call["names"] == ["api_key"] and call["inside_workdir"]
        assert call["key_sha256"] == hashlib.sha256(key.encode()).hexdigest()
        if os.name == "posix":
            assert call["mode"] == "0o600"
        coordinator.api("POST", "/api/v1/ops/mod.vault.call", json={"params": {"leak": True, "campaign_id": "c_leak"},
                                                                    "reason": "e2e"}, headers={"idempotency-key": "e2e-leak"})
        wait(lambda: q("SELECT 1 FROM attempts a JOIN jobs j ON j.job_id=a.job_id WHERE j.campaign_id='c_leak' "
                       "AND j.stage='call' AND a.state='failed'"), timeout=120)
        tails = " ".join(json.loads(pj or "{}").get("stderr_tail") or "" for (pj,) in q(
            "SELECT payload_json FROM events WHERE kind='attempt_failed'"))
        assert key not in tails
        logs = " ".join(f.read_text(errors="replace") for f in (coordinator.home / "attempt-logs").glob("*.log"))
        assert key not in logs and "[secret:api_key]" in logs
        assert key.encode() not in db.read_bytes()
        assert not list((home / "work").glob("*/.grants/secrets.json"))         # deleted with the work directory
    finally:
        p.terminate()
        out += p.communicate(timeout=10)[0]
        print(out[-5000:])
    assert key not in out                                                        # nor in the agent's own log


def test_a_runner_s_home_and_temporary_files_are_its_work_directory_s_and_go_with_it(agent_bin, coordinator, tmp_path):
    """docs/design/module-sandbox.md, "A runner's home": every per-user location a runner's environment names (HOME or
    USERPROFILE, the XDG directories or APPDATA and LOCALAPPDATA, the temporary directory) lies in its work directory;
    the temporary directory the OS gives programs exists and takes files (on Windows inside the AppContainer, whose
    start moves TEMP into the container's folder); and the work directory is removed with the attempt."""
    import json
    import sqlite3
    from pathlib import Path
    install_module(coordinator, VAULT, tmp_path, approve=True)
    home = tmp_path / "agent"
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", coordinator.url], env=agent_env(),
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    db = coordinator.home / "oarbank.sqlite3"

    def q(sql, *args):
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            return c.execute(sql, args).fetchall()
        finally:
            c.close()
    try:
        pending = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"])
        coordinator.admit(pending[0]["enrollment_id"])
        wait(lambda: node_modules(coordinator).get("vault", {}).get("state") == "certified", timeout=120)
        coordinator.api("POST", "/api/v1/ops/mod.vault.home", json={"params": {}, "reason": "e2e"}, headers={"idempotency-key": "e2e-home"})
        wait(lambda: coordinator.api("GET", "/api/v1/campaigns/c_home")["jobs"]["d"] == 1, timeout=120)
        (r,), = q("SELECT r.result_json FROM results r JOIN jobs j ON j.job_id=r.job_id WHERE j.campaign_id='c_home'")
        seen = json.loads(r)["payload"]["home"]
        assert seen["outside"] == [] and seen["user_home_inside"], seen
        assert seen["temp_dir_inside"] and seen["temp_dir_writable"], seen
        assert wait(lambda: not Path(seen["workdir"]).exists()), "the work directory goes with the attempt"
    finally:
        p.terminate()
        print(p.communicate(timeout=10)[0][-5000:])
