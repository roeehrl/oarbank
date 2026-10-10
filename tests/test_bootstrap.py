"""Bootstrap stages (docs/design/bootstrap-stages.md): on a fresh fleet a module's bootstrap stage provisions the
datasets its goldens mount, on doctor-healthy nodes before any is certified, and the coordinator registers a bootstrap
job's output only when it is exactly the module's pinned datasets."""
import hashlib
import json
import shutil

import pytest

from oarbank.coordinator import core, datasets, effects, explain, invariants, modcalls, modsandbox, modstore, releases
from oarbank.coordinator.db import jl

from helpers import FACTS, FIXTURES, enrolled_node, fresh, install, make_db, run_op
from helpers import set_fleet

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
    set_fleet(db, "replica_rate", 1.0)                 # every comparing job would get a replica
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
    assert (check.outcome, check.observed, check.required) == ("pass", "certifying, runner started",
                                                               "runner started (a doctor report), not revoked")
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
    (pin,) = datasets.pin_states(db, "depot", modcalls.info("depot").manifest)      # the module health page's pins card
    assert (pin["state"], pin["held_by"], pin["detail"]) == ("conflict", "the operator's dataset of kind tool with 1 file(s)",
                                                             a["detail"])


def test_pinned_datasets_are_waiting_until_a_bootstrap_job_registers_them(db):
    man = modcalls.info("depot").manifest
    (pin,) = datasets.pin_states(db, "depot", man)
    assert (pin["dataset_id"], pin["kind"], pin["state"], pin["files"], pin["detail"]) == (TOOL, "tool", "waiting", 2, None)
    assert pin["bytes"] == sum(len(b) for b in FILES.values())
    node = fresh_node(db)
    provision(db)
    (g,) = claim(db, node)
    core.complete(db, fresh(db, node), g["attempt_id"], fetch_result(db))
    (pin,) = datasets.pin_states(db, "depot", man)
    assert pin["state"] == "registered" and pin["held_by"] is None and pin["registered_at"]


GRANTS = {**FACTS, "sandbox": {**FACTS["sandbox"], "enforcement": {**FACTS["sandbox"]["enforcement"],
                                                                    modsandbox.BOOTSTRAP_GRANTS: "enforced"}}}


def test_bootstrap_jobs_run_where_the_runner_starts_and_the_agent_applies_the_bootstrap_grants(db, monkeypatch):
    """docs/design/stage-gating.md: a bootstrap job needs the module's runner to start on the node (its doctor printed a
    DoctorOutput, whatever its health) and the bootstrap grants; a failed check that proves no capability the stage needs
    does not keep it off the node."""
    monkeypatch.setattr(modsandbox, "REQUIRE_SANDBOXED_AGENTS", True)
    sick = fresh_node(db, "sick", facts=GRANTS, doctor={"modules": {"depot": {"health": "undetected", "ran": True, "checks": [
        {"name": "java17", "ok": False}, {"name": "pysam_import", "ok": False, "detail": "dlopen(...)"}]}}})
    broken = fresh_node(db, "broken", facts=GRANTS, doctor={"modules": {"depot": {"health": "unhealthy", "ran": False, "checks": [
        {"name": "doctor", "ok": False, "detail": "not a DoctorOutput: Traceback ..."}]}}})
    legacy = fresh_node(db, "legacy", facts=GRANTS, doctor={"modules": {"depot": {"health": "unhealthy", "checks": [
        {"name": "doctor", "ok": False, "detail": "doctor did not finish within 60 s"}]}}})   # an agent without `ran`
    old = fresh_node(db, "old")                                      # FACTS: a sandbox, but no grants.bootstrap
    assert (state(db, sick), state(db, broken), state(db, legacy)) == ("undetected", "doctor_failed", "doctor_failed")
    fetch = provision(db)
    assert claim(db, broken) == [] and claim(db, legacy) == [] and claim(db, old) == []
    doc = explain.job_doc(db, fetch["job_id"])
    matrix = {r.node: r.results for r in doc.matrix}
    for name in ("broken", "legacy"):
        check = next(r for r in matrix[name] if r.predicate == "module_ready_for_bootstrap(depot)")
        assert (check.outcome, check.code, check.observed) == ("fail", "MODULE_NOT_READY", "doctor_failed, runner not started")
    assert predicates_first_failure(matrix["old"]) == ("CAPABILITY_NOT_ENFORCED", "bootstrap grants enforced")
    assert predicates_first_failure(matrix["sick"]) is None          # undetected, but its runner starts
    ready = next(s for s in doc.summary if s.code == "MODULE_NOT_READY")
    assert sorted(ready.nodes) == ["broken", "legacy"] and "its runner did not start" in ready.detail["text"]
    assert [x["job_id"] for x in claim(db, sick)] == [fetch["job_id"]]
    assert ok(db)


def depot_fetch_requires(monkeypatch, *capabilities):
    """depot's fetch stage requiring node capabilities (patched in the catalog)."""
    import dataclasses
    info = modcalls.info("depot")
    stages = [st.model_copy(update={"requires": st.requires.model_copy(update={"capabilities": list(capabilities)})})
              if st.name == "fetch" else st for st in info.manifest.stages]
    monkeypatch.setitem(modcalls.CATALOG, "depot", dataclasses.replace(info, manifest=info.manifest.model_copy(update={"stages": stages})))


def test_a_failed_check_named_after_a_capability_keeps_off_only_the_stages_that_need_it(db, monkeypatch):
    """A doctor check named after a capability proves it for the module (oarbank-sdk DoctorCheck.name): when it fails the
    node lacks the capability whatever its probes say, so a stage that requires it waits there; one that does not runs."""
    from oarbank.coordinator import predicates
    with_probe = lambda checks, health="healthy": {"capabilities": ["netcheck"], "modules": {"depot": {
        "health": health, "ran": True, "checks": checks}}}
    good = fresh_node(db, "good", facts=GRANTS, doctor=with_probe([{"name": "netcheck", "ok": True}]))
    healthy_but = fresh_node(db, "healthy-but", facts=GRANTS, doctor=with_probe([{"name": "netcheck", "ok": False, "detail": "x"}]))
    sick = fresh_node(db, "sick", facts=GRANTS, doctor=with_probe([{"name": "netcheck", "ok": False}, {"name": "disk", "ok": False}],
                                                                 "unhealthy"))
    assert predicates.node_capabilities(fresh(db, good), "depot") == {"netcheck"}
    assert predicates.node_capabilities(fresh(db, sick), "depot") == set()
    fetch = provision(db)
    depot_fetch_requires(monkeypatch, "netcheck")
    assert claim(db, healthy_but) == [] and claim(db, sick) == []
    doc = explain.job_doc(db, fetch["job_id"])
    matrix = {r.node: r.results for r in doc.matrix}
    assert predicates_first_failure(matrix["healthy-but"]) == ("STAGE_CAPABILITY_MISSING", "stage capabilities")
    assert predicates_first_failure(matrix["sick"]) == ("STAGE_CAPABILITY_MISSING", "stage capabilities")
    row = next(r for r in doc.summary if r.code == "STAGE_CAPABILITY_MISSING")
    assert row.detail["text"] == ("Its stage needs netcheck; this node's services, probes and module doctor do not provide "
                                  "netcheck (2 nodes: 2 darwin-arm64)") and row.detail["platforms"] == {"darwin-arm64": 2}
    depot_fetch_requires(monkeypatch)                          # the stage needs nothing: the unrelated failures do not matter
    assert [x["job_id"] for x in claim(db, sick)] == [fetch["job_id"]]
    assert ok(db)


def test_explain_says_which_capability_no_node_has(db, monkeypatch):
    nodes = [fresh_node(db, n, facts=GRANTS, doctor={"modules": {"depot": {"health": "undetected", "ran": True, "checks": [
        {"name": "netcheck", "ok": False, "detail": "no route"}]}}}) for n in ("a", "b")]
    fetch = provision(db)
    depot_fetch_requires(monkeypatch, "netcheck")
    assert all(claim(db, n) == [] for n in nodes)
    head = explain.job_doc(db, fetch["job_id"]).headline
    assert head.code == "NO_ELIGIBLE_NODE"
    assert head.text == ("No node can run this job right now: Its stage needs netcheck; this node's services, probes and "
                         "module doctor do not provide netcheck (2 nodes: 2 darwin-arm64)")


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
    (src / "oarbank-module.toml").write_text(edit((src / "oarbank-module.toml").read_text(encoding="utf-8")))
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


def test_depot_passes_the_conformance_kit_its_fetch_proven_against_the_pins(tmp_path):
    """`oarbank-sdk conform` runs depot's golden on the tool and its bootstrap runner spec with the bootstrap grants (the
    fixture settings never reach it), checking the fetched files against [[datasets.pinned]]."""
    from oarbank_sdk.conformance import conform
    for path, body in FILES.items():
        (tmp_path / "tool" / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "tool" / path).write_bytes(body)
    rep = conform(DEPOT_DIR, {"datasets": {TOOL: {"kind": "tool", "attrs": {"version": "1"}, "dir": str(tmp_path / "tool")}},
                              "settings": {"mirror": "https://mirror.example/secret"},
                              "runner_specs": [{"name": "fetch", "stage": "fetch", "payload": {"fetch": TOOL},
                                                "expect": {"artifacts": ["tool"]}}]})
    assert rep.ok, rep.text()
    passed = {c.name for c in rep.checks if c.status == "pass"}
    assert {"runner spec fetch: artifacts match the pinned datasets", "golden G1 (eval): matches the golden"} <= passed
