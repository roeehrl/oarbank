"""Files, folders and checkpoints on a real agent (docs/design/datasets-media-checkpoints.md, "Tests"):

- a module registers an asset by URL and digest, and the agent fetches it from an https origin (through a redirect)
  while the coordinator never holds it;
- folder grants: a job reads a file from a read-only folder and writes one into a write-only outbox; the sandbox
  refuses reading or listing the outbox and writing into the read folder;
- a reel render paused past its node's limit is checkpointed and released, moves to a second agent and finishes from
  the checkpoint with the digest of an uninterrupted render.
"""
import hashlib
import http.server
import json
import os
import secrets
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, install_module  # noqa: E402
from test_agent_session import wait  # noqa: E402

REEL = REPO / "vendor" / "oarbank-sdk" / "examples" / "reel"
FERRY = REPO / "tests" / "fixtures" / "modules" / "ferry"
HOST = "assets.example.org"
sys.path.insert(0, str(REEL))
import reel_frames as F  # noqa: E402


def start_agent(agent_bin, home: Path, c, extra_env=None):
    return subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", c.url],
                            env={**agent_env(), **(extra_env or {})}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def admit_next(c, known=()):
    """Admit the next pending enrollment; the new node's id."""
    pending = wait(lambda: [e for e in c.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"], timeout=60)
    c.admit(pending[0]["enrollment_id"])
    return wait(lambda: next((n["node_id"] for n in c.api("GET", "/api/v1/fleet")["nodes"] if n["node_id"] not in known), None))


def module_state(c, nid, module):
    n = next((n for n in c.api("GET", "/api/v1/fleet")["nodes"] if n["node_id"] == nid), None)
    return json.loads((n or {}).get("modules_json") or "{}").get(module, {}).get("state")


def op(c, name, target=None, params=None, key=None):
    body = {"params": params or {}, "reason": "e2e", **({"target": target} if target else {})}
    return c.api("POST", f"/api/v1/ops/{name}", json=body, headers={"idempotency-key": key or secrets.token_hex(8)})


def planned(c, name, target, params):
    plan = c.api("POST", f"/api/v1/ops/{name}", json={"target": target, "params": params, "dry_run": True})["plan"]
    return c.api("POST", f"/api/v1/ops/{name}", json={"plan_id": plan["plan_id"], "reason": "e2e"})


def campaign_done(c, cid, n=1):
    return wait(lambda: (lambda j: j if j["d"] == n else None)(c.api("GET", f"/api/v1/campaigns/{cid}")["jobs"]), timeout=240)


def stop(p, log):
    p.terminate()
    try:
        log.append(p.communicate(timeout=20)[0])
    except subprocess.TimeoutExpired:
        p.kill()
        log.append(p.communicate()[0])


def db_rows(c, sql, args=()):
    with sqlite3.connect(f"file:{c.home / 'oarbank.sqlite3'}?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        return [dict(r) for r in db.execute(sql, args)]


# ---------------------------------------------------------------------------- an asset from its origin

def origin_cert(tmp: Path):
    """A CA and a server certificate for HOST signed by it (webpki takes no CA certificate as a server's)."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "e2e origin CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (tmp / "ca.pem").write_bytes(ca.public_bytes(pem))
    (tmp / "cert.pem").write_bytes(leaf.public_bytes(pem))
    (tmp / "key.pem").write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return tmp / "ca.pem", tmp / "cert.pem", tmp / "key.pem"


def origin_server(tmp: Path, body: bytes):
    """An https origin for HOST on loopback, with its own CA: /moved redirects to /clip.webm (ranges honoured)."""
    ca, cert, key = origin_cert(tmp)
    hits = []

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append(self.path)
            if self.path == "/moved":
                self.send_response(302)
                self.send_header("Location", "/clip.webm")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            start = int(self.headers["Range"][6:-1]) if self.headers.get("Range") else 0
            self.send_response(206 if start else 200)
            self.send_header("Content-Length", str(len(body) - start))
            self.end_headers()
            self.wfile.write(body[start:])

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, ca, hits


def test_an_asset_registered_by_url_is_fetched_by_the_agent_from_its_origin(agent_bin, coordinator, tmp_path):
    clip = os.urandom(200_000)                                    # bytes no job of reel uploads itself
    digest = hashlib.sha256(clip).hexdigest()
    srv, cert, hits = origin_server(tmp_path, clip)
    url = f"https://{HOST}:{srv.server_address[1]}/moved"
    install_module(coordinator, REEL, tmp_path)
    log = []
    p = start_agent(agent_bin, tmp_path / "agent", coordinator,
                    {"OARBANK_TEST_ORIGIN_CA": str(cert), "OARBANK_TEST_ORIGIN_HOSTS": HOST})
    try:
        nid = admit_next(coordinator)
        wait(lambda: module_state(coordinator, nid, "reel") == "certified", timeout=180)
        op(coordinator, "mod.reel.import_asset", params={"dataset_id": "asset:clip-1", "url": url, "sha256": digest,
                                                          "size": len(clip), "name": "clip.webm"})
        r = op(coordinator, "mod.reel.queue_render", params={"renders": [{"frames": 2, "seed": 3, "asset": "asset:clip-1"}],
                                                              "campaign_id": "c_asset"})
        assert r["result"]["result"]["campaign_id"] == "c_asset"
        assert campaign_done(coordinator, "c_asset")["f"] == 0
        (job,) = coordinator.api("GET", "/api/v1/campaigns/c_asset/artifacts")
        (listing,) = [f for a in job["artifacts"] if a["name"] == "asset" for f in a["files"]]
        text = httpx.get(f"{coordinator.admin}/api/v1/blobs/{listing['digest']}", headers=coordinator.auth()).text
        assert text == f"{digest}  clip.webm\n"                      # the job read exactly the origin's bytes
        ds = coordinator.api("GET", "/api/v1/datasets/asset:clip-1")
        assert ds["files"][0]["held"] is False                       # and the coordinator never held them
        assert hits[:2] == ["/moved", "/clip.webm"]                  # through the redirect
    finally:
        stop(p, log)
        srv.shutdown()
        print("".join(log)[-5000:])


# ---------------------------------------------------------------------------- folder grants

def test_a_job_reads_its_read_folder_and_writes_only_into_its_outbox(agent_bin, coordinator, tmp_path):
    inbox, outbox = tmp_path / "inbox", tmp_path / "outbox"
    inbox.mkdir()
    outbox.mkdir()
    (inbox / "input.txt").write_bytes(b"ferry me\n")
    install_module(coordinator, FERRY, tmp_path, approve=True)
    log = []
    p = start_agent(agent_bin, tmp_path / "agent", coordinator)
    try:
        nid = admit_next(coordinator)
        planned(coordinator, "settings.folders.update", "inbox", {"access": "read", "nodes": {nid: str(inbox)}})
        planned(coordinator, "settings.folders.update", "outbox", {"access": "write", "nodes": {nid: str(outbox)}})
        wait(lambda: module_state(coordinator, nid, "ferry") == "certified", timeout=180)
        op(coordinator, "mod.ferry.carry", params={"n": 2})
        assert campaign_done(coordinator, "c_ferry")["f"] == 0
        (res,) = db_rows(coordinator, "SELECT r.result_json FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id "
                                      "WHERE j.campaign_id='c_ferry'")
        payload = json.loads(res["result_json"])["payload"]
        want = hashlib.sha256(b"ferry me\n2").hexdigest()
        assert payload["digest"] == want                              # read from the read-only folder
        assert (outbox / "ferried-2.txt").read_text(encoding="utf-8") == want + "\n"  # written into the outbox
        assert payload["probes"] == {"read_outbox": "refused", "list_outbox": "refused", "write_inbox": "refused",
                                     "list_inbox": "allowed"}, payload["probes"]
        assert not (inbox / "planted.txt").exists()
        node = next(n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"] if n["node_id"] == nid)
        assert json.loads(node["folders_json"]) == {"inbox": {"access": "read", "status": "ok"},
                                                    "outbox": {"access": "write", "status": "ok"}}
    finally:
        stop(p, log)
        print("".join(log)[-5000:])


# ---------------------------------------------------------------------------- checkpoint, release, resume elsewhere

def windows_session() -> int:
    import ctypes
    sid = ctypes.c_ulong()
    ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
    return sid.value


def test_a_render_paused_past_the_limit_moves_to_another_node_and_finishes_from_its_checkpoint(agent_bin, coordinator, tmp_path):
    """The acceptance test of #15: protection pauses the render on node A (a rule for a process the test starts), the
    pause outlasts A's max_pause_s, so A asks the runner for a checkpoint, uploads it and releases the job; node B takes
    the job with the checkpoint and finishes it with the digest an uninterrupted render has."""
    if os.name == "nt" and windows_session() == 0:
        pytest.skip("on Windows the agent counts every process in session 0 (services: where ssh and CI runners start "
                    "the suite) as no person's, so a rule for a process the test starts there never matches; it runs in "
                    "a person's session (docs/design/windows-coordinator.md)")
    frames, seed = 40, 5
    install_module(coordinator, REEL, tmp_path)
    # every node only yields to rules, never to load: on a busy host, moderate mode's budget would hold A's
    # certification or B's resume back for as long as the owner's other work runs
    planned(coordinator, "protection.rules.update", "fleet", {"config": {"schema": 1, "node": {"mode": "fleet_first"}}})
    log, procs = [], []
    app_tag = f"oarbank-e2e-app-{secrets.token_hex(4)}"
    try:
        a = start_agent(agent_bin, tmp_path / "agent-a", coordinator)
        procs.append(a)
        nid_a = admit_next(coordinator)
        wait(lambda: module_state(coordinator, nid_a, "reel") == "certified", timeout=180)
        planned(coordinator, "protection.rules.update", nid_a, {"config": {
            "schema": 1, "node": {"mode": "fleet_first", "max_pause_s": 10},    # only the rule pauses, never load
            "rule": [{"id": "e2e-app", "match": {"argv_regex": app_tag}, "active_when": {"for_s": 0}, "pause_fleet": {}}]}})

        def telemetry():
            n = next(n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"] if n["node_id"] == nid_a)
            return json.loads(n.get("telemetry_json") or "{}").get("protection") or {}

        def rule():
            return next((r for r in telemetry().get("rules") or [] if r.get("id") == "e2e-app"), None)
        # A runs the rule before the render is queued: nothing of the render depends on when the policy arrives
        wait(lambda: telemetry().get("mode") == "fleet_first" and rule(), timeout=60)
        op(coordinator, "mod.reel.queue_render", params={"renders": [{"frames": frames, "seed": seed, "step_ms": 1000,
                                                                       "every": 100}], "campaign_id": "c_move"})
        # the render is under way on A (frames on disk, so its checkpoint will hold some), and nothing has paused it:
        # the rule matches no process until the protected app starts (not one of the owner's processes exiting under
        # load, whose arguments can no longer be read)
        render = wait(lambda: db_rows(coordinator, "SELECT t.attempt_id FROM attempts t JOIN jobs j ON j.job_id=t.job_id "
                                                   "WHERE t.node_id=? AND j.campaign_id='c_move' ORDER BY t.attempt_id",
                                      (nid_a,)), timeout=120)[0]
        out = tmp_path / "agent-a" / "work" / str(render["attempt_id"]) / "out" / "frames"
        wait(lambda: len(list(out.glob("*.png"))) >= 2, timeout=120)
        assert not rule()["active"], rule()
        (live,) = db_rows(coordinator, "SELECT state, phase FROM attempts WHERE attempt_id=?", (render["attempt_id"],))
        assert live["state"] == "live" and live["phase"] != "paused", live
        app_started = time.time()
        app = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(900)", app_tag])
        procs.append(app)
        try:
            wait(lambda: any(r.get("id") == "e2e-app" and r.get("active") for r in telemetry().get("rules") or []), timeout=60)
        except AssertionError:
            raise AssertionError(f"the rule never became active: {telemetry()}") from None
        ckpt = wait(lambda: db_rows(coordinator, "SELECT * FROM checkpoints"), timeout=120)[0]
        first = wait(lambda: [r for r in db_rows(coordinator, "SELECT * FROM attempts WHERE node_id=?", (nid_a,))
                              if r["state"] != "live" and r["attempt_id"] == ckpt["attempt_id"]], timeout=120)[0]
        assert first["attempt_id"] == render["attempt_id"] and first["end_reason"] == "preempt_protection", first
        # the rule came on only once the app ran
        on = wait(lambda: db_rows(coordinator, "SELECT min(t) AS t FROM protection_decisions WHERE node_id=? AND "
                                               "kind='rule_active' AND rule='e2e-app'", (nid_a,))[0]["t"])
        assert on >= app_started - 1, (on, app_started)
        stop(a, log)                                                  # A is gone: only B can take the job now
        b = start_agent(agent_bin, tmp_path / "agent-b", coordinator)
        procs.append(b)
        nid_b = admit_next(coordinator, known={nid_a})
        assert campaign_done(coordinator, "c_move")["f"] == 0
        (job,) = db_rows(coordinator, "SELECT j.job_id, r.fields_json, r.node_id, r.attempt_id FROM jobs j JOIN results r "
                                      "ON r.result_id=j.canonical_result_id WHERE j.campaign_id='c_move'")
        assert job["node_id"] == nid_b
        assert json.loads(job["fields_json"])["digest"] == F.expected(seed, frames)     # an uninterrupted render's digest
        (resumed,) = db_rows(coordinator, "SELECT resume_json FROM attempts WHERE attempt_id=?", (job["attempt_id"],))
        resume = json.loads(resumed["resume_json"])
        assert resume["from_attempt"] == ckpt["attempt_id"] and resume["node_id"] == nid_a and resume["digest"] == ckpt["digest"]
        (arts,) = coordinator.api("GET", "/api/v1/campaigns/c_move/artifacts")
        (log_file,) = [f for x in arts["artifacts"] if x["name"] == "log" for f in x["files"]]
        text = httpx.get(f"{coordinator.admin}/api/v1/blobs/{log_file['digest']}", headers=coordinator.auth()).text
        at = int(text.rsplit("resumed at frame ", 1)[1])
        assert 0 < at < frames, text                                  # B rendered only the frames after the checkpoint
        assert not db_rows(coordinator, "SELECT 1 FROM checkpoints")   # done: the checkpoint is dropped
    finally:
        for p in procs:
            if p.poll() is None:
                if p.stdout is not None:
                    stop(p, log)
                else:
                    p.kill()
                    p.wait()
        print("".join(log)[-8000:])
