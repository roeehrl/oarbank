"""Sites on real agents (docs/design/sites.md): two agents at one site. A synthetic protected process on the first node
writes a phase source; its rule tags the phase `uplink`. The second node stages a large dataset from a slow https origin
under a transfer lease. When the protected process's phase source enters the upload phase, the first agent reports it
at once, the coordinator holds the site and revokes the lease, and the second agent pauses its staging within
SITE_HOLD_BOUND_S of the source write; when the phase ends the staging resumes and finishes. Synthetic processes,
loopback and a scratch origin only."""
import hashlib
import http.server
import json
import os
import ssl
import subprocess
import sys
import textwrap
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from test_agent_files import HOST, admit_next, db_rows, module_state, op, origin_cert, start_agent, stop  # noqa: E402
from test_agent_session import wait  # noqa: E402

from oarbank.coordinator import sites  # noqa: E402

REEL = REPO / "vendor" / "oarbank-sdk" / "examples" / "reel"
SIZE = 24 << 20                       # 24 MiB at ~1.5 MiB/s: the staging lasts long enough to be caught in the middle
RATE = 1.5 * (1 << 20)

PROTECTED = textwrap.dedent("""
    import sys, time
    tag = sys.argv[1]
    while True:
        time.sleep(0.5)
""")


def slow_origin(tmp, body: bytes):
    """An https origin for HOST on loopback that sends at RATE and honours ranges; `served` counts the bytes sent."""
    ca, cert, key = origin_cert(tmp)
    served = {"bytes": 0}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            start = int(self.headers["Range"][6:].split("-")[0]) if self.headers.get("Range") else 0
            self.send_response(206 if start else 200)
            self.send_header("Content-Length", str(len(body) - start))
            self.end_headers()
            step = 64 << 10
            try:
                for i in range(start, len(body), step):
                    self.wfile.write(body[i:i + step])
                    served["bytes"] += len(body[i:i + step])
                    time.sleep(step / RATE)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, ca, served


def planned(c, name, target, params):
    plan = c.api("POST", f"/api/v1/ops/{name}", json={"target": target, "params": params, "dry_run": True})["plan"]
    return c.api("POST", f"/api/v1/ops/{name}", json={"plan_id": plan["plan_id"], "reason": "e2e",
                                                       "confirm": plan["confirm_name"]})


def records(c, nid, kind):
    return [json.loads(r["record_json"]) for r in db_rows(c, "SELECT record_json FROM protection_decisions WHERE node_id=? "
                                                             "AND kind=? ORDER BY seq", (nid, kind))]


def test_a_protected_upload_on_one_node_pauses_staging_on_the_other_within_the_bound(agent_bin, coordinator, tmp_path):
    body = os.urandom(SIZE)
    digest = hashlib.sha256(body).hexdigest()
    srv, ca, served = slow_origin(tmp_path, body)
    tag = f"fake-uploader-{uuid.uuid4().hex[:8]}"
    data = tmp_path / "uploader"
    data.mkdir()
    phase = data / "phase-1.jsonl"
    phase.write_text(json.dumps({"event": "status", "phase": "working"}) + "\n")
    script = tmp_path / "uploader.py"
    script.write_text(PROTECTED)
    protected = subprocess.Popen([sys.executable, str(script), tag])
    install_module(coordinator, REEL, tmp_path)
    env = {"OARBANK_TEST_ORIGIN_CA": str(ca), "OARBANK_TEST_ORIGIN_HOSTS": HOST}
    log, procs = [], []
    try:
        procs.append(start_agent(agent_bin, tmp_path / "a", coordinator, env))
        a = admit_next(coordinator)
        procs.append(start_agent(agent_bin, tmp_path / "b", coordinator, env))
        b = admit_next(coordinator, known=(a,))
        # the first node only runs the protected program: no module work there
        coordinator.api("POST", "/api/v1/ops/settings.apply", json={"target": a, "reason": "e2e", "params": {"changes": [
            {"scope": "node", "scope_id": a, "module": "reel", "key": "enabled", "value": False}]}})
        planned(coordinator, "sites.create", "home", {"nodes": [a, b], "max_transfers": 1})
        config = {"schema": 1, "node": {"mode": "fleet_first"}, "rule": [{
            "id": "uploader", "match": {"argv_regex": tag}, "active_when": "present", "enter_for_s": 0, "immediate": True,
            "during": [{"source": {"jsonl": str(data / "phase-*.jsonl"), "event": "status",
                                   "field": "phase", "on": ["uploading"]},
                        "cap_fleet": {"staging_mbps": 0}, "tags": ["uplink"]}]}]}
        planned(coordinator, "protection.rules.update", a, {"config": config})

        def site():
            return coordinator.api("GET", "/api/v1/sites/home")
        # the first node reports its uplink phase (off), the second node its transfers
        wait(lambda: any(p["key"] == "uploader#0" for m in site()["member_rows"] for p in m["phases"]), timeout=120)
        wait(lambda: module_state(coordinator, b, "reel") == "certified", timeout=300)
        op(coordinator, "mod.reel.import_asset", params={"dataset_id": "asset:big-1", "url": f"https://{HOST}:{srv.server_address[1]}/big",
                                                          "sha256": digest, "size": SIZE, "name": "big.bin"})
        op(coordinator, "mod.reel.queue_render", params={"renders": [{"frames": 1, "seed": 5, "asset": "asset:big-1"}],
                                                          "campaign_id": "c_big"})
        # the second node is staging under a lease
        wait(lambda: served["bytes"] > (2 << 20), timeout=180, step=0.2)
        lease = wait(lambda: site()["leases"], timeout=30, step=0.5)
        assert lease[0]["kind"] == "staging" and lease[0]["dir"] == "down"
        # the protected program's upload begins
        before = served["bytes"]
        t0 = time.time()
        with open(phase, "a") as f:
            f.write(json.dumps({"event": "status", "phase": "uploading"}) + "\n")
        paused = wait(lambda: records(coordinator, b, "transfer_paused"), timeout=60, step=0.5)
        latency = paused[0]["paused_at"] - t0
        print(f"phase source write to the other node's staging pause: {latency:.2f} s (bound {sites.SITE_HOLD_BOUND_S} s)")
        assert latency <= sites.SITE_HOLD_BOUND_S, paused[0]
        assert "site home" in paused[0]["why"] or "lease" in paused[0]["why"], paused[0]
        st = site()
        assert st["hold"] and "uploader" in st["why"] and st["state"].startswith("paused because ")
        assert not st["leases"]
        # while the phase lasts the transfer stays paused (only what TCP had buffered arrives)
        held_at = served["bytes"]
        time.sleep(4)
        assert served["bytes"] - held_at < (4 << 20), (before, held_at, served["bytes"])
        # the phase ends: the staging resumes and the dataset is staged with its digest
        with open(phase, "a") as f:
            f.write(json.dumps({"event": "status", "phase": "working"}) + "\n")
        wait(lambda: records(coordinator, b, "transfer_resumed"), timeout=90, step=0.5)
        wait(lambda: "asset:big-1" in json.loads(db_rows(coordinator, "SELECT ready_datasets_json FROM nodes WHERE node_id=?",
                                                       (b,))[0]["ready_datasets_json"] or "[]"), timeout=240, step=1)
        assert not site()["hold"]
        assert not [v for v in coordinator.api("GET", "/api/v1/verify")["violations"] if v.startswith("S27")]
    finally:
        protected.terminate()
        for p in procs:
            stop(p, log)
        srv.shutdown()
        print("".join(log)[-6000:])


