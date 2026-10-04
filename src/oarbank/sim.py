"""Deterministic, seeded, fault-injecting simulation of a whole oarbank (coordinator + agents).

One process, a fake clock, the REAL coordinator core, and simulated agents whose every random
choice comes from `random.Random(seed)`. A failing seed replays exactly. The fleet is mixed: nodes take turns among
darwin-arm64, linux-amd64 and linux-arm64, and a study may keep its units of work on one platform class each
(`placement`, D33; invariant S20). Faults injected:
lost requests, lost responses (agent retries from its outbox), silent sleeps followed by late
results, agent crashes/restarts, coordinator outages, execution failures, wrong-mode runs and one
deliberately nondeterministic node. Every `check_every` ticks the invariant catalogue is checked;
at the end every job must be settled (liveness) and the canonical results must be consistent.

  python -m oarbank.sim --seeds 200            # sweep
  python -m oarbank.sim --seed 1234 -v         # replay one
"""
import argparse
import dataclasses
import hashlib
import json
import random
import sys
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .coordinator import campaigns, clock, core, identity, invariants, modcalls, modstore, ops, releases, tlsca
from .coordinator.db import DB

# the simulated fleet runs the SDK's reference module and the core suite's relay fixture module
REPO = Path(__file__).resolve().parents[2]
SIM_MODULES = (REPO / "vendor" / "oarbank-sdk" / "examples" / "toy", REPO / "tests" / "fixtures" / "modules" / "relay")

MODE = {"runtime": "native-arm64", "sampler": "sobol-owen", "filter": "blackman-harris"}
PLATFORMS = ("darwin-arm64", "linux-amd64", "linux-arm64")          # node i runs PLATFORMS[i % 3]
PARAMS = {"samples": 10, "light_clamp": 30.0}
# what a healthy agent's sandbox backend reports (spec/sandbox.md): oarbankd gives module work only to sandboxed agents
SANDBOX_ENFORCED = {c: "enforced" for c in ("filesystem", "ipc", "net.none", "net.egress-allowlist", "net.egress-any",
                                            "no_loopback", "gpu.compute", "exec_writable_deny", "grants.bootstrap")}
def create_study(db, name: str, configs: list, datasets: list, baseline: dict, actor: str = "sim", **kw) -> str:
    """A comparison study, created as the console and the CLI do: the relay module's own operation
    (mod.relay.create_study). Returns the campaign id."""
    r = ops.execute(db, ops.OpRequest(op="mod.relay.create_study", actor=actor, source="system", idempotency_key=uuid.uuid4().hex,
                                      params={"name": name, "configs": configs, "datasets": datasets, "baseline": baseline, **kw}))
    return r["result"]["result"]["campaign_id"]


def _csr() -> str:
    """A simulated agent's CSR for a fresh P-256 key (the key itself is not needed: no TLS in the simulation)."""
    k = ec.generate_private_key(ec.SECP256R1())
    return x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sim")])) \
        .sign(k, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def _cfg(spec_json: str | None) -> str:
    """A short stable id for a job's parameter set (the sim's stand-in for 'which config')."""
    opts = (json.loads(spec_json or "{}") or {}).get("params")
    return hashlib.sha256(json.dumps(opts, sort_keys=True).encode()).hexdigest()[:8] if opts is not None else "golden"


def envelope(payload: dict, mode: dict | None = None, artifacts: list | None = None) -> dict:
    """A relay runner's result envelope (as the agent posts it)."""
    env = {"envelope": 1, "schema": "relay/result@1", "module_version": "1.0.0", "protocol": 1, "payload": payload}
    if mode is not None:
        env["effective"] = {"mode": mode}
    if artifacts is not None:
        env["artifacts"] = artifacts
    return {"result": env}


def toy_envelope(n: int) -> dict:
    return {"result": {"envelope": 1, "schema": "toy/result@1", "module_version": "0.1.0", "protocol": 1,
                       "payload": {"sum": str(n * (n - 1) // 2)}}}


@dataclass
class Faults:
    p_lost_request: float = 0.03
    p_lost_response: float = 0.03
    p_sleep_per_min: float = 0.02     # per agent per simulated minute
    p_crash_per_min: float = 0.01
    p_coord_outage_per_hour: float = 2.0
    p_exec_fail: float = 0.05
    p_wrong_mode: float = 0.01
    nondeterministic_node: bool = True
    replica_rate: float = 0.03
    bad_mode: str = "random"          # "random": a new wrong answer each run; "consistent": the same wrong answer
    split: bool = False               # staged pipeline: node0 scores (VM pool), the others only render
    p_module_kill_per_min: float = 0.05     # a module process dies (respawned on the next call)
    p_module_outage_per_hour: float = 1.0   # a module cannot start for 60-600 s (then it is fixed and restarted)
    placement: dict | None = None     # the study's campaigns.create placement (D33), e.g. {"mix": "same-os", "unit": "group"}
    group_by: str | None = None       # the study's job groups: "trial" or "dataset"


PROFILES = {
    "mild": Faults(),
    # everything goes wrong often: the adaptive replication must still catch the bad node,
    # quorum must never convict a good one, and every job must still settle
    "harsh": Faults(p_lost_request=0.08, p_lost_response=0.08, p_sleep_per_min=0.2, p_crash_per_min=0.05,
                    p_coord_outage_per_hour=6.0, p_exec_fail=0.1, p_wrong_mode=0.02, replica_rate=0.3,
                    p_module_kill_per_min=0.5, p_module_outage_per_hour=4.0),
}


@dataclass
class Agent:
    name: str
    cert: bytes                       # its client certificate (DER): what the TLS layer hands oarbankd
    node_id: str
    release: str                      # the release its platform runs
    slots: int
    bad: bool = False                 # returns nondeterministic results
    pools: int = 4                    # scorer tokens (0 = render-only worker in split mode)
    asleep_until: float = 0.0
    live: dict = field(default_factory=dict)      # attempt_id -> (finish_time, job_id)
    outbox: list = field(default_factory=list)    # (attempt_id, kind, body)
    next_hb: float = 0.0
    cpu: dict = field(default_factory=dict)


class Simulation:
    def __init__(self, seed: int, n_nodes=4, n_configs=3, n_datasets=6, faults: Faults | None = None,
                 max_hours=12.0, check_every=5, verbose=False):
        self.rng = random.Random(seed)
        self.seed, self.faults, self.verbose = seed, faults or Faults(), verbose
        self.max_t = max_hours * 3600
        self.check_every = check_every
        self.tmp = tempfile.TemporaryDirectory()
        clock.set_fake(1_900_000_000.0)
        self.t0 = clock.now()
        self.db = self._make_db(n_datasets)
        self.db.set_setting("replica_rate", self.faults.replica_rate)
        if self.faults.split:
            self.db.set_setting("pipeline:relay", "split")
        self.agents = [self._make_agent(f"node{i}", PLATFORMS[i % len(PLATFORMS)],
                                        bad=(self.faults.nondeterministic_node and i == n_nodes - 1)) for i in range(n_nodes)]
        if self.faults.split:
            for i, ag in enumerate(self.agents):
                ag.pools = 4 if i == 0 else 0
                self.db.x("UPDATE nodes SET policy_json=?, capacity_json=? WHERE node_id=?",
                          (json.dumps({"disabled_services": [] if i == 0 else ["relay/scorer"]}), json.dumps({"pools": {"scorer": ag.pools}}), ag.node_id))
        configs = [{"label": f"c{k}", "params": {**PARAMS, "samples": 15 + k}} for k in range(n_configs)]
        extra = {k: v for k, v in (("placement", self.faults.placement), ("group_by", self.faults.group_by)) if v}
        self.sid = create_study(self.db, f"sim-{seed}", configs, self.datasets, {"label": "base", "params": PARAMS}, **extra)
        self.coord_down_until = 0.0
        self.module_broken_until, self.module_good_argv = 0.0, {}
        self.stats = {"lost_req": 0, "lost_resp": 0, "sleeps": 0, "crashes": 0, "outages": 0, "fails": 0,
                      "wrong_mode": 0, "late_results": 0, "checks": 0, "retryable_5xx": 0, "module_kills": 0,
                      "module_outages": 0}

    # ------------------------------------------------------------------ setup
    def _make_db(self, n_datasets):
        db = DB(Path(self.tmp.name) / "oarbank.sqlite3")
        tlsca.ensure_ca(db.root, identity.fleet_id(db))
        for m in SIM_MODULES:
            modstore.dev_install_dir(db, m, actor="sim")
        modcalls.use(db)
        # render-only nodes certify on the golden frame digest
        db.set_setting("module_settings:relay", {"goldens": [{"name": "G1", "params": PARAMS, "dataset": "demo:atrium",
                                                              "expected": {"score": "0.947512", "tiles": 1536, "image_sha256": "g"}}]})
        self.datasets = [f"scene:s{i}" for i in range(n_datasets)]
        for did in self.datasets + ["demo:atrium"]:
            db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?)",
                 (did, did.split(":")[0], "relay", json.dumps({"frames": "1-24", "scene": "atrium"}), "[]", clock.now()))
        releases.sync(db)
        self.ready = ["demo:atrium"] + self.datasets
        return db

    def _make_agent(self, name, platform, bad=False):
        os_, arch = platform.split("-")
        facts = {"facts": 2, "hostname": name, "platform": {"os": os_, "arch": arch, "os_version": "27.0" if os_ == "darwin" else "6.8"},
                 "cpu": {"perf_cores": 8, "eff_cores": 4, "logical": 12}, "memory_gb": 64.0,
                 "sandbox": {"backend": "seatbelt" if os_ == "darwin" else "landlock", "enforcement": SANDBOX_ENFORCED}}
        e = core.enroll(self.db, name, facts, "127.0.0.1", _csr())
        core.approve_enrollment(self.db, e["enrollment_id"], "sim")
        pem = core.enroll_status(self.db, e["enrollment_id"])["cert_pem"]
        cert = x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
        node = core.auth_cert(self.db, cert, "127.0.0.1")
        release = releases.assigned(self.db, node)                  # its platform's release (each platform has its own)
        core.hello(self.db, node, {"release_id": release, "facts": facts, "live_attempts": [], "ready_datasets": self.ready})
        core.heartbeat(self.db, self._node(node["node_id"]), {"doctor": {"modules": {
            "relay": {"health": "healthy", "checks": []}, "toy": {"health": "healthy", "checks": []}}}, "ready_datasets": self.ready,
            "capacity": {"pools": {"scorer": 4}}})
        for g in core.claim(self.db, self._node(node["node_id"]), {"free_cpu": 8, "free_mem_gb": 64,
                                                                     "ready_datasets": self.ready})["grants"]:
            core.complete(self.db, self._node(node["node_id"]), g["attempt_id"], self._golden(g["module"], g["spec"]))
        return Agent(name, cert, node["node_id"], release, slots=self.rng.randint(2, 6), bad=bad, next_hb=clock.now())

    def _golden(self, module: str, spec: dict) -> dict:
        if module == "toy":
            return toy_envelope(spec["payload"]["n"])
        if spec.get("stage") == "render":
            digest = hashlib.sha256(b"g").hexdigest()
            self.db.x("INSERT OR IGNORE INTO blobs(digest,path,size) VALUES(?,?,?)", (digest, "/dev/null", 1))
            return envelope({"tiles": 1536, "image_sha256": "g"}, MODE,
                            [{"name": "frame", "files": [{"path": "frame.exr", "digest": digest, "size": 1}]}])
        return envelope({"score": "0.947512", "tiles": 1536, "image_sha256": "g"}, MODE)

    def _node(self, nid):
        return self.db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))

    # ------------------------------------------------------------------ transport
    def _call(self, agent, fn, *args):
        """Deliver an agent->coordinator call through a lossy network. Returns (delivered, response)."""
        if clock.now() < self.coord_down_until:
            return False, None
        if self.rng.random() < self.faults.p_lost_request:
            self.stats["lost_req"] += 1
            return False, None
        try:
            node = core.auth_cert(self.db, agent.cert, "127.0.0.1")
        except core.ApiError:
            return True, None
        try:
            resp = fn(self.db, node, *args)
        except core.ApiError as e:
            if e.status >= 500:          # the real agent retries every 5xx (e.g. 503 module_unavailable)
                self.stats["retryable_5xx"] += 1
                return False, None
            resp = {"error": e.code}
        if self.rng.random() < self.faults.p_lost_response:
            self.stats["lost_resp"] += 1
            return False, None          # processed, but the agent never hears back
        return True, resp

    def _result_for(self, agent, attempt_id):
        a = self.db.one("SELECT j.spec_json, j.dataset_id, j.kind, j.module, j.stage, j.depends_on FROM attempts a "
                        "JOIN jobs j ON j.job_id=a.job_id WHERE a.attempt_id=?", (attempt_id,))
        a["config_key"] = _cfg(a["spec_json"]) if a["kind"] != "golden" else None
        if a["stage"] in ("render", "score"):
            return self._stage_result(agent, a)
        if a["kind"] == "golden":
            return self._golden(a["module"], {"payload": json.loads(a["spec_json"]), "stage": a["stage"]})
        base = int.from_bytes(f"{a['config_key']}{a['dataset_id']}".encode()[:6], "big") % 99999
        score = f"0.{800000 + base:06d}"
        image = f"v-{a['config_key'][:8]}-{a['dataset_id']}"
        mode = dict(MODE)
        if agent.bad and self.faults.bad_mode == "consistent":
            score, image = f"0.{700000 + base:06d}", f"bad-{a['config_key'][:8]}-{a['dataset_id']}"
        elif agent.bad:
            score, image = f"0.{700000 + self.rng.randint(0, 99999):06d}", f"bad-{self.rng.random()}"
        if self.rng.random() < self.faults.p_wrong_mode:
            mode["sampler"] = "random"
            self.stats["wrong_mode"] += 1
        return envelope({"score": score, "tiles": 1000, "image_sha256": image}, mode)

    def _stage_result(self, agent, a):
        """Split pipeline. render: a frame (bad nodes produce a wrong one) uploaded as an artifact; score: the
        grade of whatever frame the render produced (the scorer itself is honest)."""
        good_image = f"v-{(a['config_key'] or 'golden')[:8]}-{a['dataset_id']}"
        if a["stage"] == "render":
            if a["kind"] == "golden":
                image = "g"                                # the golden frame (errors in the sim are data-dependent)
            elif agent.bad:
                image = f"bad-{(a['config_key'] or 'golden')[:8]}-{a['dataset_id']}" if self.faults.bad_mode == "consistent" \
                    else f"bad-{self.rng.random()}"
            else:
                image = good_image
            mode = dict(MODE)
            if self.rng.random() < self.faults.p_wrong_mode:
                mode["sampler"] = "random"
                self.stats["wrong_mode"] += 1
            digest = hashlib.sha256(image.encode()).hexdigest()
            self.db.x("INSERT OR IGNORE INTO blobs(digest,path,size) VALUES(?,?,?)", (digest, "/dev/null", 1))   # uploaded
            return envelope({"tiles": 1536 if a["kind"] == "golden" else 1000, "image_sha256": image}, mode,
                            [{"name": "frame", "files": [{"path": "frame.exr", "digest": digest, "size": 1}]}])
        dep = self.db.one("SELECT r.digest FROM jobs d JOIN results r ON r.result_id=d.canonical_result_id WHERE d.job_id=?",
                          (a["depends_on"],))
        image = dep["digest"] if dep else "missing"
        base = int.from_bytes(image.encode()[:6], "big") % 99999
        return envelope({"score": f"0.{800000 + base:06d}", "image_sha256": image})

    # ------------------------------------------------------------------ agent step
    def _agent_step(self, ag: Agent, now: float, dt: float):
        f = self.faults
        if now < ag.asleep_until:
            return
        # faults
        if self.rng.random() < f.p_sleep_per_min * dt / 60:
            ag.asleep_until = now + self.rng.uniform(30, 400)     # silent sleep: no release, results come late
            self.stats["sleeps"] += 1
            return
        if self.rng.random() < f.p_crash_per_min * dt / 60:
            ag.live.clear()                                       # process gone; outbox survives on disk
            self.stats["crashes"] += 1
            self._call(ag, core.hello, {"release_id": ag.release, "live_attempts": [], "ready_datasets": self.ready})
        # outbox first (idempotent retries)
        pending, ag.outbox = ag.outbox, []
        for aid, kind, body in pending:
            fn = core.complete if kind == "complete" else core.fail
            ok, resp = self._call(ag, fn, aid, body)
            if not ok:
                ag.outbox.append((aid, kind, body))
        # finished work
        for aid, (fin, _jid) in list(ag.live.items()):
            if fin <= now:
                del ag.live[aid]
                if fin + 60 < now:
                    self.stats["late_results"] += 1
                if self.rng.random() < f.p_exec_fail:
                    self.stats["fails"] += 1
                    ag.outbox.append((aid, "fail", {"reason": "exit_nonzero"}))
                else:
                    body = self._result_for(ag, aid) | {"idempotency_key": f"att-{aid}-complete"}
                    ag.outbox.append((aid, "complete", body))
        # heartbeat
        if now >= ag.next_hb:
            ag.next_hb = now + 10
            rep = []
            for aid in ag.live:
                ag.cpu[aid] = ag.cpu.get(aid, 0) + 10
                rep.append({"attempt_id": aid, "phase": "running", "cpu_s": ag.cpu[aid], "log_bytes": 0})
            hb = {"attempts": rep, "ready_datasets": self.ready, "capacity": {"pools": {"scorer": ag.pools}, "cpu_slots": ag.slots}}
            ok, resp = self._call(ag, core.heartbeat, hb)
            if ok and resp and "error" not in resp:
                for aid in (resp.get("revoke") or []) + (resp.get("cancel") or []):
                    ag.live.pop(aid, None)
            # claim
            free = ag.slots - len(ag.live)
            if free > 0:
                ok, resp = self._call(ag, core.claim, {"free_cpu": free, "free_mem_gb": 64, "ready_datasets": self.ready})
                if ok and resp and "grants" in resp:
                    for g in resp["grants"]:
                        ag.live[g["attempt_id"]] = (now + self.rng.uniform(20, 180), g["job_id"])

    # ------------------------------------------------------------------ module faults (S15)
    def _module_faults(self, now: float, dt: float):
        h = modcalls.host(self.db)
        f = self.faults
        if self.module_broken_until and now >= self.module_broken_until:
            for name, argv in self.module_good_argv.items():
                h.specs[name].argv = argv
                h.restart(name)
            self.module_broken_until = 0.0
        if self.rng.random() < f.p_module_kill_per_min * dt / 60:
            for p in list(h._procs.values()):
                p.proc.kill()
            self.stats["module_kills"] += 1
        if not self.module_broken_until and self.rng.random() < f.p_module_outage_per_hour * dt / 3600:
            self.module_good_argv = {n: list(sp.argv) for n, sp in h.specs.items()}
            for name in h.specs:
                h.stop(name)
                h.specs[name].argv = ["python", "-c", "import sys; sys.exit(1)"]
            self.module_broken_until = now + self.rng.uniform(60, 600)
            self.stats["module_outages"] += 1

    # ------------------------------------------------------------------ main loop
    def run(self, keep: bool = False) -> dict:
        """keep=True leaves the database open (self.db) for post-mortem inspection."""
        dt, tick = 5.0, 0
        violations = []
        while clock.now() - self.t0 < self.max_t:
            now = clock.now()
            if self.rng.random() < self.faults.p_coord_outage_per_hour * dt / 3600:
                outage = self.rng.uniform(30, 180)
                self.coord_down_until = now + outage
                self.stats["outages"] += 1
                # on restart oarbankd extends live leases by the outage (see __main__.py)
                self.db.x("UPDATE attempts SET expires_at=expires_at+?, hard_deadline=hard_deadline+? WHERE state='live'",
                          (outage + 60, outage))
            self._module_faults(now, dt)
            for ag in self.rng.sample(self.agents, len(self.agents)):
                self._agent_step(ag, now, dt)
            if now >= self.coord_down_until:
                core.reap(self.db)          # the coordinator's background loops: reaper + campaign ticks
                campaigns.tick_all(self.db)
            tick += 1
            if tick % self.check_every == 0:
                self.stats["checks"] += 1
                v = invariants.check_all(self.db)
                if v:
                    violations = v
                    break
            if not self.db.one("SELECT COUNT(*) n FROM jobs WHERE campaign_id=? AND state NOT IN ('done','cancelled','quarantined')",
                               (self.sid,))["n"]:
                break
            clock.advance(dt)
        v_final = invariants.check_all(self.db)
        live = invariants.l1_all_settled(self.db, self.sid)
        jobs = {r["state"]: r["n"] for r in self.db.q("SELECT state, COUNT(*) n FROM jobs WHERE campaign_id=? GROUP BY state",
                                                       (self.sid,))}
        bad_q = [a.name for a in self.agents if a.bad and self._node(a.node_id)["lifecycle"] == "quarantined"]
        good_q = [a.name for a in self.agents if not a.bad and self._node(a.node_id)["lifecycle"] == "quarantined"]
        # no job may end with a canonical result from the convicted node (its results are recomputed)
        wrong = []
        bad_ids = [a.node_id for a in self.agents if a.bad and self._node(a.node_id)["lifecycle"] == "quarantined"]
        if bad_ids:
            wrong = [r["job_id"] for r in self.db.q(
                "SELECT j.job_id FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id "
                "WHERE j.campaign_id=? AND j.state='done' AND r.node_id IN (%s)" % ",".join("?" * len(bad_ids)),
                (self.sid, *bad_ids))]
        if self.faults.split and bad_ids:
            wrong += [r["job_id"] for r in self.db.q(
                "SELECT j.job_id FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id "
                "WHERE j.campaign_id=? AND j.kind='eval' AND j.state='done' AND r.digest LIKE 'bad-%'", (self.sid,))]
        out = {"seed": self.seed, "ok": not violations and not v_final and not live and not good_q and not wrong,
               "violations": violations or v_final, "liveness": live, "sim_hours": round((clock.now() - self.t0) / 3600, 2),
               "jobs": jobs, "stats": self.stats, "bad_node_quarantined": bad_q,
               "good_nodes_quarantined": good_q, "canonical_from_convicted_node": wrong,
               "replicas": self.db.one("SELECT COUNT(*) n FROM jobs WHERE kind='replica'")["n"],
               "units": {r["state"]: r["n"] for r in self.db.q("SELECT state, COUNT(*) n FROM placement_bindings GROUP BY state")},
               "classes": sorted({r["class"] for r in self.db.q("SELECT class FROM placement_bindings WHERE class IS NOT NULL")}),
               "disputes": self.db.one("SELECT COUNT(*) n FROM events WHERE kind='dispute_resolved'")["n"]}
        clock.set_fake(None)
        if not keep:
            self.close()
        return out

    def close(self):
        """End the run's module processes, then remove its database and files (a running process holds its files)."""
        from .coordinator import modcalls
        modcalls.close_host(self.db)
        self.db.conn.close()
        self.tmp.cleanup()


def main():
    ap = argparse.ArgumentParser(prog="oarbank.sim")
    ap.add_argument("--seeds", type=int, default=0, help="sweep seeds 0..N-1")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--profile", choices=sorted(PROFILES), default="mild")
    ap.add_argument("--bad-mode", choices=["random", "consistent"], default="random")
    ap.add_argument("--split", action="store_true", help="staged pipeline: node0 scores, the rest only render")
    ap.add_argument("--nodes", type=int, default=4)
    ap.add_argument("--configs", type=int, default=3)
    ap.add_argument("--datasets", type=int, default=6)
    ap.add_argument("--placement", help='a study placement as JSON, e.g. {"mix": "same-os", "unit": "group"}')
    ap.add_argument("--group-by", choices=["trial", "dataset"])
    ap.add_argument("-v", action="store_true")
    a = ap.parse_args()
    seeds = [a.seed] if a.seed is not None else range(a.seeds or 20)
    fails, agg, caught = [], {}, 0
    for s in seeds:
        r = Simulation(s, n_nodes=a.nodes, n_configs=a.configs, n_datasets=a.datasets,
                       faults=dataclasses.replace(PROFILES[a.profile], bad_mode=a.bad_mode, split=a.split, group_by=a.group_by,
                                                  placement=json.loads(a.placement) if a.placement else None), verbose=a.v).run()
        caught += bool(r["bad_node_quarantined"])
        for k, v in r["stats"].items():
            agg[k] = agg.get(k, 0) + v
        if not r["ok"]:
            fails.append(r)
            print(json.dumps(r, indent=1))
        elif a.v or a.seed is not None:
            print(json.dumps(r, indent=1))
    print(json.dumps({"seeds": len(list(seeds)), "profile": a.profile, "failed": [f["seed"] for f in fails],
                      "bad_node_caught": caught, "faults_injected": agg}))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
