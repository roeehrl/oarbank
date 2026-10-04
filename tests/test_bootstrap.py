"""Bootstrap stages (docs/design/bootstrap-stages.md): on a fresh fleet a module's bootstrap stage provisions the
datasets its goldens mount, on doctor-healthy nodes before any is certified, and the coordinator registers a bootstrap
job's output only when it is exactly the module's pinned datasets."""
import hashlib
import json
import shutil

import pytest

from oarbank.coordinator import core, effects, explain, invariants, modcalls, modsandbox, modstore, releases
from oarbank.coordinator.db import jl

from helpers import FACTS, FIXTURES, enrolled_node, fresh, install, make_db, run_op

DEPOT_DIR = FIXTURES / "depot"
TOOL = "tool:depot-1"
FILES = {"bin/tool.txt": b"depot tool v1\n", "README": b"depot: the core test suite's bootstrap fixture\n"}
DOCTOR_OK = {"modules": {"depot": {"health": "healthy", "checks": []}}}


@pytest.fixture
def db(tmp_path):
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    r = install(d, DEPOT_DIR, enable=False)
    modsandbox.approve(d, "depot", r["version"], "test", None)        # depot asks for an egress allowlist
    modstore.enable(d, "depot", r["version"])
    modcalls.use(d)
    releases.sync(d)
    return d


def ok(db):
    v = invariants.check_all(db)
    assert not v, v
    return True


def blob(db, body: bytes) -> str:
    """A file the agent uploaded (PUT /v1/artifacts): the coordinator records the size it measured."""
    d = hashlib.sha256(body).hexdigest()
    db.x("INSERT OR IGNORE INTO blobs(digest,path,size) VALUES(?,?,?)", (d, "/dev/null", len(body)))
    return d


def fetch_result(db, files=FILES, payload=None, extra=()):
    arts = [{"name": "tool", "files": [{"path": p, "digest": blob(db, b), "size": len(b)} for p, b in files.items()]}]
    arts += [{"name": n, "files": [{"path": p, "digest": blob(db, b), "size": len(b)}]} for n, p, b in extra]
    return {"result": {"envelope": 1, "schema": "depot/result@1", "module_version": "1.0.0", "protocol": 1,
                       "effective": {"proxy": "on"}, "provenance": {"host": "mini"}, "payload": payload or {}, "artifacts": arts}}


def eval_result(digest):
    return {"result": {"envelope": 1, "schema": "depot/result@1", "module_version": "1.0.0", "protocol": 1,
                       "payload": {"digest": digest}}}


def fresh_node(db, name="mini", facts=FACTS, doctor=DOCTOR_OK):
    """A node that enrolled, installed the release and reported its doctor: certifying, its golden queued."""
    _, node = enrolled_node(db, name, facts)
    core.hello(db, node, {"release_id": releases.assigned(db, fresh(db, node)), "facts": facts, "live_attempts": [],
                          "ready_datasets": []})
    core.heartbeat(db, fresh(db, node), {"doctor": doctor, "attempts": [], "ready_datasets": [], "capacity": {}})
    return fresh(db, node)


def claim(db, node, ready=()):
    return core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": list(ready)})["grants"]


def state(db, node) -> str | None:
    return core.node_modules(fresh(db, node)).get("depot", {}).get("state")


def provision(db, evals=0):
    run_op(db, "mod.depot.provision", params={"evals": evals})
    return db.one("SELECT * FROM jobs WHERE stage='fetch'")


def test_a_fresh_fleet_provisions_its_datasets_with_a_bootstrap_job_and_then_certifies(db):
    db.set_setting("replica_rate", 1.0)                 # every comparing job would get a replica
    node = fresh_node(db)
    golden = db.one("SELECT * FROM jobs WHERE kind='golden'")
    assert state(db, node) == "certifying" and json.loads(golden["datasets_json"]) == [TOOL]
    assert claim(db, node) == []                         # the golden waits for a dataset nobody registered yet
    doc = explain.job_doc(db, golden["job_id"])
    assert [s.code for s in doc.summary] == ["DATASETS_NOT_REGISTERED"]
    assert core.heartbeat(db, fresh(db, node), {"attempts": [], "ready_datasets": []})["prefetch"] == []

    fetch = provision(db, evals=2)
    assert fetch["kind"] == "eval" and fetch["stage"] == "fetch"
    doc = explain.job_doc(db, fetch["job_id"])
    assert doc.headline.code == "QUEUED_BEHIND" and "bootstrap job" in doc.system_actions[0]
    check = next(r for r in doc.matrix[0].results if r.predicate == "module_ready_for_bootstrap(depot)")
    assert (check.outcome, check.observed, check.required) == ("pass", "certifying", "certified or certifying")
    g = claim(db, node)
    assert [(x["job_id"], x["spec"]["stage"]) for x in g] == [(fetch["job_id"], "fetch")]      # the evals need certification
    assert "Running as a bootstrap job on mini" in explain.job_doc(db, fetch["job_id"]).headline.text
    assert ok(db)

    r = core.complete(db, fresh(db, node), g[0]["attempt_id"], fetch_result(db))
    assert r == {"accepted": True, "canonical": True, "reason": "ok"}
    ds = db.one("SELECT * FROM datasets WHERE dataset_id=?", (TOOL,))
    assert (ds["kind"], ds["module"], jl(ds["meta_json"]), ds["platform"]) == ("tool", "depot", {"version": "1"}, None)
    assert sorted((f["path"], f["size"]) for f in jl(ds["files_json"])) == [("README", 47), ("bin/tool.txt", 14)]
    assert db.one("SELECT COUNT(*) n FROM datasets WHERE dataset_id LIKE 'art:%'")["n"] == 0
    res = db.one("SELECT * FROM results WHERE job_id=?", (fetch["job_id"],))
    stored = jl(res["result_json"])
    assert stored["payload"] == {} and "effective" not in stored and "provenance" not in stored and jl(res["fields_json"]) == {}
    assert not db.one("SELECT 1 FROM jobs WHERE kind='replica'")                    # determinism none: never a replica
    assert state(db, node) == "certifying"                                          # a bootstrap result never certifies

    assert core.heartbeat(db, fresh(db, node), {"attempts": [], "ready_datasets": []})["prefetch"] == [TOOL]
    g = claim(db, node, ready=[TOOL])
    assert [x["kind"] for x in g] == ["golden"]
    core.complete(db, fresh(db, node), g[0]["attempt_id"], eval_result("depot-golden-1"))
    assert state(db, node) == "certified"
    g = claim(db, node, ready=[TOOL])
    assert sorted(x["kind"] for x in g) == ["eval", "eval"]
    for x in g:
        assert core.complete(db, fresh(db, node), x["attempt_id"], eval_result(f"d{x['job_id']}"))["canonical"]
    assert ok(db)


def test_a_bootstrap_result_survives_its_node_being_certified_meanwhile(db):
    node = fresh_node(db)
    pinned = [{"path": p, "digest": blob(db, b), "size": len(b), "origins": []} for p, b in FILES.items()]
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?)",
         (TOOL, "tool", "depot", json.dumps({"version": "1"}), json.dumps(pinned), 0))     # already there, as pinned
    fetch = provision(db)
    grants = claim(db, node, ready=[TOOL])
    g = next(x for x in grants if x["job_id"] == fetch["job_id"])
    ga = next(x for x in grants if x["kind"] == "golden")
    core.complete(db, fresh(db, node), ga["attempt_id"], eval_result("depot-golden-1"))
    assert state(db, node) == "certified"                # a new certification generation while the fetch ran
    assert core.complete(db, fresh(db, node), g["attempt_id"], fetch_result(db))["canonical"]   # its pins decide
    assert jl(db.one("SELECT files_json FROM datasets WHERE dataset_id=?", (TOOL,))["files_json"]) == pinned
    assert not db.one("SELECT 1 FROM alerts WHERE rule LIKE 'pinned_dataset_conflict:%'")
    assert ok(db)


@pytest.mark.parametrize("bad, why", [
    (lambda db: fetch_result(db, files={**FILES, "README": b"depot: a different readme!!!!!!!!!!!!!!!!!!!!!\n"}),
     "artifact 'tool': README is sha256 "),
    (lambda db: fetch_result(db, payload={"note": "hi"}), "a bootstrap result carries no payload"),
    (lambda db: fetch_result(db, extra=[("other", "x.bin", b"x")]), "artifact 'other': its files ['x.bin'] are no pinned dataset's"),
    (lambda db: fetch_result(db, files={"bin/tool.txt": FILES["bin/tool.txt"]}),
     "pinned dataset tool:depot-1 has README, which the artifact lacks"),
])
def test_a_result_that_is_not_exactly_the_pins_is_refused_as_the_jobs_fault(db, bad, why):
    node = fresh_node(db)
    fetch = provision(db)
    (g,) = claim(db, node)
    r = core.complete(db, fresh(db, node), g["attempt_id"], bad(db))
    assert r == {"accepted": False, "canonical": False, "reason": "pin_mismatch"}
    assert not db.one("SELECT 1 FROM datasets WHERE dataset_id=?", (TOOL,))
    a = db.one("SELECT * FROM attempts WHERE attempt_id=?", (g["attempt_id"],))
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (fetch["job_id"],))
    assert (a["state"], a["end_reason"], j["state"], j["exec_failures"]) == ("failed", "pin_mismatch", "pending", 1)
    assert fresh(db, node)["breaker_failures"] == 0 and state(db, node) == "certifying"    # never the node's breaker
    ev = db.one("SELECT * FROM events WHERE kind='pin_mismatch'")
    assert why in ev["reason"]
    assert ok(db)
    db.x("UPDATE jobs SET not_before=0 WHERE job_id=?", (fetch["job_id"],))
    (g,) = claim(db, node)                               # the only node may try again; retry.max_attempts = 2 is then spent
    core.complete(db, fresh(db, node), g["attempt_id"], bad(db))
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (fetch["job_id"],))["state"] == "quarantined"
    assert explain.job_doc(db, fetch["job_id"]).headline.code == "BOOTSTRAP_PIN_MISMATCH"


def test_an_artifact_never_uploaded_is_the_nodes_and_registers_nothing(db):
    node = fresh_node(db)
    provision(db)
    (g,) = claim(db, node)
    body = fetch_result(db)
    db.x("DELETE FROM blobs WHERE digest=?", (body["result"]["artifacts"][0]["files"][0]["digest"],))
    assert core.complete(db, fresh(db, node), g["attempt_id"], body)["reason"] == "artifact_missing"
    assert not db.one("SELECT 1 FROM datasets WHERE dataset_id=?", (TOOL,))


def test_a_pinned_id_registered_with_other_contents_is_never_overwritten(db):
    node = fresh_node(db)
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?)",
         (TOOL, "tool", None, "{}", json.dumps([{"path": "gatk.jar", "digest": "aa" * 32, "size": 1}]), 0))
    provision(db)
    (g,) = claim(db, node)
    assert core.complete(db, fresh(db, node), g["attempt_id"], fetch_result(db))["canonical"]
    assert jl(db.one("SELECT files_json FROM datasets WHERE dataset_id=?", (TOOL,))["files_json"])[0]["path"] == "gatk.jar"
    a = db.one("SELECT * FROM alerts WHERE rule=?", (f"pinned_dataset_conflict:{TOOL}",))
    assert a["state"] == "open" and "the operator" in a["detail"]


def test_bootstrap_jobs_run_only_where_the_doctor_is_healthy_and_the_agent_applies_the_bootstrap_grants(db, monkeypatch):
    sick = fresh_node(db, "sick", doctor={"modules": {"depot": {"health": "unhealthy", "checks": [{"name": "disk", "ok": False}]}}})
    assert state(db, sick) == "doctor_failed"
    monkeypatch.setattr(modsandbox, "REQUIRE_SANDBOXED_AGENTS", True)
    old = fresh_node(db, "old")                                      # FACTS: a sandbox, but no grants.bootstrap
    new = fresh_node(db, "new", facts={**FACTS, "sandbox": {**FACTS["sandbox"], "enforcement": {
        **FACTS["sandbox"]["enforcement"], modsandbox.BOOTSTRAP_GRANTS: "enforced"}}})
    fetch = provision(db)
    assert claim(db, sick) == [] and claim(db, old) == []
    matrix = {r.node: r.results for r in explain.job_doc(db, fetch["job_id"]).matrix}
    check = next(r for r in matrix["sick"] if r.predicate == "module_ready_for_bootstrap(depot)")
    assert (check.outcome, check.code, check.observed) == ("fail", "MODULE_NOT_READY", "doctor_failed")
    assert predicates_first_failure(matrix["old"]) == ("CAPABILITY_NOT_ENFORCED", "bootstrap grants enforced")
    assert predicates_first_failure(matrix["new"]) is None
    assert [x["job_id"] for x in claim(db, new)] == [fetch["job_id"]]


def predicates_first_failure(results):
    bad = next((r for r in results if r.outcome != "pass"), None)
    return (bad.code, bad.predicate) if bad else None


def test_a_failed_fetch_is_retried_on_another_uncertified_node(db):
    a, b = fresh_node(db, "a"), fresh_node(db, "b")
    fetch = provision(db)
    (g,) = claim(db, a)
    core.complete(db, fresh(db, a), g["attempt_id"], fetch_result(db, payload={"x": 1}))
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (fetch["job_id"],))
    assert j["state"] == "pending"                       # not quarantined: b, certifying too, can still run it
    db.x("UPDATE jobs SET not_before=0 WHERE job_id=?", (fetch["job_id"],))
    assert claim(db, a) == []                            # FAILED_HERE: another node can take it
    (g,) = claim(db, b)
    assert core.complete(db, fresh(db, b), g["attempt_id"], fetch_result(db))["canonical"]


def test_the_release_marks_the_bootstrap_stage(db):
    entry = releases.module_entry("depot", "1.0.0", "d", modcalls.info("depot").path)
    assert entry["stages"] == [{"name": "eval", "capabilities": [], "pools": [], "platforms": []},
                               {"name": "fetch", "capabilities": [], "pools": [], "platforms": [], "bootstrap": True}]


def test_datasets_create_of_a_pinned_id_needs_the_pinned_contents(db):
    files = [{"path": p, "digest": blob(db, b), "size": len(b)} for p, b in FILES.items()]
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?)",
         ("tool:held", "tool", "depot", "{}", json.dumps(files), 0))                 # makes the blobs the module's
    allowed = {"datasets.create"}
    with db.tx(), pytest.raises(effects.EffectError, match="pin_mismatch: tool:depot-1 is pinned"):
        effects.apply(db, "depot", allowed, [{"kind": "datasets.create", "args": {
            "dataset_id": TOOL, "kind": "tool", "files": files[:1], "meta": {"version": "1"}}}])
    with db.tx(), pytest.raises(effects.EffectError, match="pin_mismatch"):
        effects.apply(db, "depot", allowed, [{"kind": "datasets.create", "args": {
            "dataset_id": TOOL, "kind": "tool", "files": files, "meta": {"version": "2"}}}])
    with db.tx():
        effects.apply(db, "depot", allowed, [{"kind": "datasets.create", "args": {
            "dataset_id": TOOL, "kind": "tool", "files": list(reversed(files)), "meta": {"version": "1"}}}])
    assert db.one("SELECT module FROM datasets WHERE dataset_id=?", (TOOL,))["module"] == "depot"


@pytest.mark.parametrize("edit, why", [
    (lambda t: t.replace('determinism = "none"\n', ""), "a bootstrap stage has determinism none"),
    (lambda t: t[:t.index("\n[[datasets.pinned]]")] + "\n" + t[t.index("[[operations]]"):], r"need \[\[datasets.pinned\]\]"),
    (lambda t: t.replace('core = ">=2.4,<3"', 'core = ">=2.3,<3"'), "need requires.core >= 2.4"),
])
def test_install_refuses_a_bootstrap_stage_the_sdk_refuses(tmp_path, db, monkeypatch, edit, why):
    from oarbank_sdk import bundle as B, manifest as mf
    src = tmp_path / "depot"
    shutil.copytree(DEPOT_DIR, src, ignore=shutil.ignore_patterns("__pycache__"))
    (src / "oarbank-module.toml").write_text(edit((src / "oarbank-module.toml").read_text()))
    with pytest.raises(ValueError, match=why):
        B.build(src, tmp_path / "refused.mfb")                          # the SDK refuses to build it
    with monkeypatch.context() as m:                                    # a bundle made by a tool that skips the rules
        m.setattr(mf.Manifest, "_bootstrap_rules", lambda self, chain: None)
        m.setattr(mf.Manifest, "core_keys_used", lambda self: [])
        out, _ = B.build(src, tmp_path / "d.mfb")
    with pytest.raises(modstore.InstallError, match=why):
        modstore.install(db, out, actor="test", self_test=False)        # the core refuses to install it


def test_s22_names_a_bootstrap_result_that_is_not_exactly_the_pins(db):
    node = fresh_node(db)
    provision(db)
    (g,) = claim(db, node)
    core.complete(db, fresh(db, node), g["attempt_id"], fetch_result(db))
    assert ok(db)
    r = db.one("SELECT result_id, result_json FROM results WHERE canonical=1")
    broken = {**jl(r["result_json"]), "payload": {"smuggled": True}}
    db.x("UPDATE results SET result_json=? WHERE result_id=?", (json.dumps(broken), r["result_id"]))
    v = invariants.s22_bootstrap_results_are_pinned(db)
    assert len(v) == 1 and "carries no payload" in v[0]


def test_certifying_stuck_names_the_pinned_datasets_the_goldens_wait_for(db):
    node = fresh_node(db)
    st = core.node_modules(fresh(db, node))["depot"]
    core._set_module_state(db, node["node_id"], "depot", certifying_since=st["certifying_since"] - core.CERTIFYING_GRACE_S - 1)
    core.reap(db)
    a = db.one("SELECT detail FROM alerts WHERE rule='certifying_stuck:depot'")
    assert a["detail"].endswith(f"its goldens wait for unregistered datasets {TOOL} ({TOOL} pinned: a job of bootstrap "
                                "stage fetch brings them)")
