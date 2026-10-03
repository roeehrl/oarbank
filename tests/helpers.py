"""Shared test fixtures: a coordinator DB with modules installed from bundles (the SDK's reference module
`toy`, and `relay`, the core suite's fixture module in tests/fixtures/modules, a two-stage render-and-score parameter
search), scene datasets, a composed release and certified nodes. The core itself ships no module."""
import json
import tempfile
import uuid
from pathlib import Path

from oarbank.coordinator import campaigns, clock, core, identity, modcalls, modstore, ops, releases, tlsca
from oarbank.coordinator.db import DB

FIXTURES = Path(__file__).parent / "fixtures" / "modules"
TOY_DIR = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "toy"
RELAY_DIR = FIXTURES / "relay"

SEATBELT = {"filesystem": "enforced", "ipc": "enforced", "net.none": "enforced", "net.egress-allowlist": "enforced",
            "net.egress-any": "enforced", "no_loopback": "enforced", "gpu.compute": "enforced", "exec_writable_deny": "enforced",
            "no_link_local": "unavailable"}
FACTS = {"facts": 2, "platform": {"os": "darwin", "arch": "arm64", "os_version": "27.0", "os_build": "27A100"},
         "cpu": {"model": "Apple M5 Pro", "perf_cores": 5, "eff_cores": 10, "logical": 15}, "memory_gb": 24.0,
         "gpus": [{"vendor": "apple", "model": "Apple M5 Pro", "apis": ["metal"], "unified": True}],
         "sandbox": {"backend": "seatbelt", "enforcement": SEATBELT}}


def facts_for(platform: str, **kw) -> dict:
    """FACTS for another platform (spec/platforms.md), e.g. facts_for("linux-amd64", os_version="6.8")."""
    os_, arch = platform.split("-")
    return {**FACTS, "platform": {"os": os_, "arch": arch, "os_version": kw.get("os_version", "1.0"), **kw}}
PARAMS = {"samples": 10, "light_clamp": 30.0}
MODE = {"runtime": "native-arm64", "sampler": "sobol-owen", "filter": "blackman-harris"}
SCENES = [f"scene:s{i}" for i in range(1, 7)]
READY = ["demo:atrium"] + SCENES
GOLDEN_IMAGE = "v1"
GOLDEN = {"name": "G1", "params": PARAMS, "dataset": "demo:atrium",
          "expected": {"score": "0.947512", "tiles": 1536, "image_sha256": GOLDEN_IMAGE}}
DOCTOR_OK = {"modules": {"relay": {"health": "healthy", "checks": []}, "toy": {"health": "healthy", "checks": []}}}

_BUNDLES: dict = {}


def bundle(src: Path) -> Path:
    """Each fixture module's bundle, built once per test session."""
    if src not in _BUNDLES:
        from oarbank_sdk import bundle as B
        out, _ = B.build(src, Path(tempfile.mkdtemp(prefix="bundle-")) / f"{src.name}.mfb")
        _BUNDLES[src] = out
    return _BUNDLES[src]


def install(db: DB, src: Path, enable: bool = True) -> dict:
    r = modstore.install(db, bundle(src), actor="test", self_test=False)
    if enable and not modstore.channel(db, r["name"])["current"]:
        modstore.enable(db, r["name"], r["version"])
    return r


def make_db(path, modules=(TOY_DIR, RELAY_DIR)) -> DB:
    d = DB(path)
    tlsca.ensure_ca(d.root, identity.fleet_id(d))         # oarbankd's start does this; approvals issue certificates
    for m in modules:
        install(d, m)
    modcalls.use(d)
    d.set_setting("module_settings:relay", {"goldens": [GOLDEN]})
    for did in READY:
        d.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?)",
            (did, did.split(":")[0], "relay", json.dumps({"frames": "1-24", "scene": "atrium"}), "[]", clock.now()))
    releases.sync(d)
    return d


def release_id(db: DB, platform: str = "darwin-arm64") -> str:
    return db.one("SELECT release_id FROM releases WHERE status='current' AND platform=?", (platform,))["release_id"]


def relay_result(score="0.947512", tiles=1536, mode=MODE, image=GOLDEN_IMAGE, stage=None, artifacts=None):
    """A relay runner's result envelope, as the agent posts it ({"result": envelope})."""
    payload = {"tiles": tiles, "image_sha256": image}
    if stage != "render" and score is not None:
        payload["score"] = score
    env = {"envelope": 1, "schema": "relay/result@1", "module_version": "1.0.0", "protocol": 1,
           "effective": {"mode": mode}, "payload": payload}
    if artifacts is not None:
        env["artifacts"] = artifacts
    return {"result": env}



def toy_result(n: int):
    return {"result": {"envelope": 1, "schema": "toy/result@1", "module_version": "0.1.0", "protocol": 1,
                       "effective": {"n": n}, "payload": {"sum": str(n * (n - 1) // 2)}}}


def render_artifacts(db, image=GOLDEN_IMAGE) -> list:
    """Pretend the agent uploaded a render stage's frame (PUT /v1/artifacts) and return the artifact list."""
    import hashlib
    body = f"frame-{image}"
    d = hashlib.sha256(body.encode()).hexdigest()
    db.x("INSERT OR IGNORE INTO blobs(digest,path,size) VALUES(?,?,?)", (d, "/dev/null", len(body)))
    return [{"name": "frame", "files": [{"path": "frame.exr", "digest": d, "size": len(body)}]}]


def golden_result(grant, db=None):
    spec = grant["spec"]
    if grant["module"] == "toy":
        return toy_result(spec["payload"]["n"])
    if spec.get("stage") == "render":
        return relay_result(stage="render", artifacts=render_artifacts(db) if db is not None else None)
    return relay_result()


def fresh(db, node):
    return db.one("SELECT * FROM nodes WHERE node_id=?", (node["node_id"],))


def node_key_and_csr():
    """An agent's P-256 key and the CSR it enrolls with."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pending")])).sign(key, hashes.SHA256())
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


def enroll_agent(db, name="mini", facts=None):
    """(private key, client certificate PEM, node row) of a node enrolled with a CSR and approved, as an agent is."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    key, csr = node_key_and_csr()
    e = core.enroll(db, name, {**(facts or FACTS), "hostname": name}, "127.0.0.1", csr)
    core.approve_enrollment(db, e["enrollment_id"], "test")
    pem = core.enroll_status(db, e["enrollment_id"])["cert_pem"]
    der = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
    return key, pem, core.auth_cert(db, der, "127.0.0.1")


def enrolled_node(db, name="mini", facts=None):
    """(client certificate DER, node row): the certificate is what the TLS layer hands the agent API."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    _, pem, node = enroll_agent(db, name, facts)
    return x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER), node


def agent_client(db, puller=None, **kw):
    """A TestClient of the agent API. The TLS layer is not in the loop, so a request names its client certificate in the
    test-only header x-test-peer-cert (base64 DER: node_headers), which stands in for the verified peer certificate
    uvicorn's PeerCertH11 puts in the request state."""
    import base64
    from fastapi.testclient import TestClient
    from oarbank.coordinator import app as coord_app
    app = coord_app.agent_app(db, puller)

    async def as_peer(scope, receive, send):
        if scope["type"] == "http":
            cert = dict(scope["headers"]).get(b"x-test-peer-cert")
            scope = {**scope, "state": {**scope.get("state", {}), "tls_peer_der": base64.b64decode(cert) if cert else None}}
        await app(scope, receive, send)
    return TestClient(as_peer, **kw)


def node_headers(der: bytes) -> dict:
    import base64
    return {"x-test-peer-cert": base64.b64encode(der).decode()}


POOLS = {"scorer": 4}          # what the relay fixture's scorer service provides on a node that runs it
CAPACITY = {"pools": POOLS}    # the capacity every heartbeat reports


def certify(db, node, doctor=DOCTOR_OK, pools=POOLS):
    facts = {k: v for k, v in json.loads(fresh(db, node)["facts_json"] or "{}").items() if k != "hostname"}
    core.hello(db, node, {"release_id": releases.assigned(db, fresh(db, node)), "facts": facts or FACTS, "live_attempts": [],
                          "ready_datasets": READY})
    node = fresh(db, node)
    core.heartbeat(db, node, {"doctor": doctor, "attempts": [], "ready_datasets": READY, "capacity": {"pools": pools}})
    node = fresh(db, node)
    for x in core.claim(db, node, {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]:
        core.complete(db, node, x["attempt_id"], golden_result(x, db))
    return fresh(db, node)


def certified_fleet(db, names=("mini", "desk", "laptop")):
    return [certify(db, enrolled_node(db, n)[1]) for n in names]


def create_study(db, name: str, configs: list, datasets: list, baseline: dict, actor: str = "test", **kw) -> str:
    """A comparison campaign through the relay module's own operation (mod.relay.create_study)."""
    r = ops.execute(db, ops.OpRequest(op="mod.relay.create_study", actor=actor, source="system", idempotency_key=uuid.uuid4().hex,
                                      params={"name": name, "configs": configs, "datasets": datasets, "baseline": baseline, **kw}))
    return r["result"]["result"]["campaign_id"]


def run_op(db, op, target=None, params=None, reason="test", actor="test", **kw):
    """An operation sent the way a client sends it: T2/T3 previewed first and the plan applied (confirmed at T3), a
    creation with an Idempotency-Key."""
    from oarbank.contracts import operations as registry
    o = registry.REGISTRY[op]
    req = dict(op=op, actor=actor, source="system", target=target, params=params or {}, reason=reason, **kw)
    if o.tier in ("T2", "T3"):
        plan = ops.execute(db, ops.OpRequest(**req, dry_run=True))["plan"]
        req.update(plan_id=plan["plan_id"], confirm=plan["confirm_name"])
    if o.idempotency == "key":
        req.setdefault("idempotency_key", uuid.uuid4().hex)
    return ops.execute(db, ops.OpRequest(**req))


def api_op(client, op, target=None, params=None, reason="test", headers=None):
    """run_op over the admin API: POST /api/v1/ops/<op>, previewed and confirmed for T2/T3."""
    from oarbank.contracts import operations as registry
    body, h = {"target": target, "params": params or {}, "reason": reason}, dict(headers or {})
    if registry.REGISTRY[op].idempotency == "key":
        h["idempotency-key"] = uuid.uuid4().hex
    if registry.REGISTRY[op].tier in ("T2", "T3"):
        r = client.post(f"/api/v1/ops/{op}", json={**body, "dry_run": True}, headers=h)
        if r.status_code != 200:
            return r
        plan = r.json()["plan"]
        body = {"plan_id": plan["plan_id"], "reason": reason, "confirm": plan["confirm_name"]}
    return client.post(f"/api/v1/ops/{op}", json=body, headers=h)


def tick(db):
    """One pass of oarbankd's campaign loop (the modules advance their campaigns)."""
    return campaigns.tick_all(db)


def admin_headers(db) -> dict:
    """The local owner's credential for direct admin API calls (what `oarbank` on the coordinator sends)."""
    from oarbank.coordinator import access
    return {"authorization": f"Bearer {access.ensure_admin_token(db.root)}"}


def sign_in(client, db, name: str = "owner", role: str = "admin") -> dict:
    """A console session for a test client: an account, a session cookie and the CSRF header every form sends."""
    from oarbank.coordinator import access
    if not access.account(db, name):
        access.create_account(db, name, role, None, "test")
    s = access.new_session(db, name, "test")
    client.cookies.set("oarbank_session", s["sid"])
    client.headers["x-csrf-token"] = s["csrf"]
    return s
