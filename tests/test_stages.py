"""Stage forms (docs/design/sdk-1.3.md): a stage that does not compare (determinism none) is never replicated, compared,
cached or golden-tested, and still fenced; one that also needs no capability or pool runs before certification, wherever
the module's runner starts (docs/design/stage-gating.md); jobs.enqueue items may name a standalone stage."""
import dataclasses
import json
import time

import pytest

from oarbank.coordinator import core, invariants, modcalls
from oarbank_sdk.keys import job_key

from helpers import READY, PARAMS, SCENES, certified_fleet, create_study, fresh, make_db, relay_result


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def ok(db):
    v = invariants.check_all(db)
    assert not v, v
    return True


def relay_stages(monkeypatch, **determinism):
    """relay with some stages' determinism replaced (patched in the catalog)."""
    info = modcalls.info("relay")
    stages = [s.model_copy(update={"determinism": determinism[s.name]}) if s.name in determinism else s for s in info.manifest.stages]
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=info.manifest.model_copy(update={"stages": stages})))


def grants(db, node, free=4):
    return core.claim(db, fresh(db, node), {"free_slots": free, "ready_datasets": READY})["grants"]


def study(db, datasets=SCENES[:1]):
    return create_study(db, "s", [], list(datasets), {"label": "base", "params": PARAMS})


# ---------------------------------------------------------------------------- #2 stages that do not compare

def test_a_stage_that_does_not_compare_is_never_replicated_disputed_or_cached(db):
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    db.set_setting("replica_rate", 1.0)                       # every comparable job would be replicated
    sid = study(db)
    enqueue(db, sid, sync_item())
    jid = db.one("SELECT job_id FROM jobs WHERE job_key=?", (SYNC_KEY,))["job_id"]
    g1 = [g for g in grants(db, n1) if g["job_id"] == jid][0]
    db.x("UPDATE attempts SET expires_at=? WHERE attempt_id=?", (time.time() - 1, g1["attempt_id"]))
    core.reap(db)                                             # n1 goes silent; n2 runs the job
    g2 = [g for g in grants(db, n2) if g["job_id"] == jid][0]
    assert core.complete(db, fresh(db, n2), g2["attempt_id"], sync_result(("r1",), "A"))["canonical"]
    assert not db.q("SELECT 1 FROM jobs WHERE kind='replica' AND job_key LIKE 'sync-1%'")
    late = core.complete(db, fresh(db, n1), g1["attempt_id"], sync_result(("r1", "r2"), "B"))   # the feed moved on
    assert (late["accepted"], late["reason"]) == (False, "job_done")            # recorded, never compared
    assert {fresh(db, n)["lifecycle"] for n in (n1, n2)} == {"ready"}
    assert db.one("SELECT dispute_json FROM jobs WHERE job_id=?", (jid,))["dispute_json"] is None
    sid2 = study(db, datasets=SCENES[1:2])
    enqueue(db, sid2, sync_item())                            # the same key in another campaign: no cache hit
    assert db.one("SELECT state FROM jobs WHERE campaign_id=? AND job_key=?", (sid2, SYNC_KEY))["state"] == "pending"
    assert ok(db)


def test_results_never_cross_between_stages_that_compare_and_that_do_not(db):
    n1, = certified_fleet(db, ("n1",))
    sid = study(db)
    ev = grants(db, n1, free=1)[0]
    assert core.complete(db, fresh(db, n1), ev["attempt_id"], relay_result())["canonical"]
    enqueue(db, sid, sync_item(ev["job_key"]))                # a sync job with a done evaluation's key
    assert db.one("SELECT state FROM jobs WHERE stage='sync'")["state"] == "pending"
    g = [x for x in grants(db, n1) if x["job_key"] == ev["job_key"]][0]
    assert core.complete(db, fresh(db, n1), g["attempt_id"], sync_result())["canonical"]
    sid2 = study(db, datasets=SCENES[1:2])
    enqueue(db, sid2, {**sync_item(SYNC_KEY), "stage": "eval", "spec": {"params": PARAMS}})
    enqueue(db, sid, sync_item(SYNC_KEY))
    done = [x for x in grants(db, n1) if x["job_key"] == SYNC_KEY and x["spec"]["stage"] == "sync"][0]
    assert core.complete(db, fresh(db, n1), done["attempt_id"], sync_result())["canonical"]
    sid3 = study(db, datasets=SCENES[2:3])
    enqueue(db, sid3, {**sync_item(SYNC_KEY), "stage": "eval", "spec": {"params": PARAMS}})   # a done sync job's key
    assert db.one("SELECT state FROM jobs WHERE campaign_id=? AND job_key=?", (sid3, SYNC_KEY))["state"] == "pending"
    assert ok(db)


def test_jobs_of_such_a_stage_stay_fenced_and_need_a_node_that_runs_the_module(db):
    from helpers import enrolled_node
    n1, = certified_fleet(db, ("n1",))
    _, enrolled = enrolled_node(db, "new")
    sid = study(db)
    enqueue(db, sid, sync_item())
    g = [x for x in grants(db, n1) if x["job_key"] == SYNC_KEY][0]
    db.x("UPDATE jobs SET generation=generation+1 WHERE job_id=?", (g["job_id"],))
    assert core.complete(db, fresh(db, n1), g["attempt_id"], sync_result())["reason"] == "stale_generation"
    assert not grants(db, enrolled)                           # no release installed, no doctor: nothing to claim
    assert ok(db)


# ---------------------------------------------------------------------------- stages that need no certification

SICK = {"modules": {"relay": {"health": "unhealthy", "ran": True, "checks": [
            {"name": "python_312", "ok": True}, {"name": "pysam_import", "ok": False, "detail": "dlopen(libchtslib.so): "
                                                 + "x" * 400 + " (mach-o file, but is an incompatible architecture)"}]},
                    "toy": {"health": "healthy", "checks": []}}}


def doctored(db, name, doctor):
    """A node that installed the release and reported `doctor` (toy certified on it; relay as its doctor says)."""
    from helpers import certify, enrolled_node
    return certify(db, enrolled_node(db, name)[1], doctor=doctor)


def relay_state(db, node):
    return core.node_modules(fresh(db, node)).get("relay", {}).get("state")


def test_a_stage_that_compares_nothing_and_needs_nothing_runs_where_the_runner_starts_before_certification(db):
    from oarbank.coordinator import explain
    sick = doctored(db, "sick", SICK)
    assert relay_state(db, sick) == "doctor_failed"           # no goldens: relay is not certified there
    sid = study(db)
    enqueue(db, sid, sync_item())
    ev = db.one("SELECT job_id FROM jobs WHERE stage IS NULL AND kind='eval'")["job_id"]
    sync = db.one("SELECT job_id FROM jobs WHERE job_key=?", (SYNC_KEY,))["job_id"]
    doc = explain.job_doc(db, sync)
    assert doc.headline.code == "QUEUED_BEHIND" and doc.system_actions[0].startswith("Needs no certification (stage sync")
    check = next(r for r in doc.matrix[0].results if r.predicate == "module_runner_ready(relay)")
    assert (check.outcome, check.observed) == ("pass", "doctor_failed, runner started")
    # the evaluation needs certification, and explain says why no node has it
    head = explain.job_doc(db, ev).headline
    assert head.code == "NO_ELIGIBLE_NODE" and ("Module relay is not ready on this node (doctor: doctor_failed; failed checks "
                                                "pysam_import) (1 node: 1 darwin-arm64)") in head.text, head.text
    g = grants(db, sick)
    assert [(x["job_id"], x["spec"]["stage"]) for x in g] == [(sync, "sync")]
    r = core.complete(db, fresh(db, sick), g[0]["attempt_id"], sync_result())
    assert r == {"accepted": True, "canonical": True, "reason": "ok"}   # no certification fence
    assert relay_state(db, sick) == "doctor_failed"           # and it never certifies anything
    assert ok(db)


def test_a_stage_that_compares_waits_for_certification_and_a_revoked_module_runs_nothing(db, monkeypatch):
    from oarbank.coordinator import explain
    sick = doctored(db, "sick", SICK)
    sid = study(db)
    enqueue(db, sid, sync_item())
    sync = db.one("SELECT job_id FROM jobs WHERE job_key=?", (SYNC_KEY,))["job_id"]
    with monkeypatch.context() as m:
        relay_stages(m, sync="exact")                         # compared, cached and replicated: certified nodes only
        assert grants(db, sick) == []
        first = next(r for r in explain.job_doc(db, sync).matrix[0].results if r.outcome != "pass")
        assert (first.predicate, first.code) == ("module_certified(relay)", "MODULE_NOT_READY")
    core.revoke_module(db, sick["node_id"], "relay", "breaker: test")
    assert grants(db, sick) == []                             # revoked: not until its doctor runs again
    first = next(r for r in explain.job_doc(db, sync).matrix[0].results if r.outcome != "pass")
    assert (first.predicate, first.code) == ("module_runner_ready(relay)", "MODULE_NOT_CERTIFIED")
    assert ok(db)


def test_s8_names_an_uncertified_attempt_of_a_stage_that_needs_certification(db, monkeypatch):
    sick = doctored(db, "sick", SICK)
    sid = study(db)
    enqueue(db, sid, sync_item())
    (g,) = grants(db, sick)
    assert ok(db)
    relay_stages(monkeypatch, sync="exact")
    v = invariants.s8_live_module_certified(db)
    assert v and f"S8 attempt {g['attempt_id']} runs relay" in v[0]


def test_goldens_never_run_a_stage_that_does_not_compare(db, monkeypatch):
    from helpers import enrolled_node
    relay_stages(monkeypatch, eval="none")                    # relay's goldens name no stage: the default one
    _, node = enrolled_node(db, "fresh")
    with pytest.raises(modcalls.ModuleError, match="determinism none"):
        modcalls.goldens(db, "relay", fresh(db, node))


def test_s21_names_a_replica_of_a_stage_that_does_not_compare(db):
    n1, = certified_fleet(db, ("n1",))
    sid = study(db)
    enqueue(db, sid, sync_item())
    g = [x for x in grants(db, n1) if x["job_key"] == SYNC_KEY][0]
    core.complete(db, fresh(db, n1), g["attempt_id"], sync_result())
    assert ok(db)
    db.x("INSERT INTO jobs(job_key,kind,state,module,stage,dispute_json) VALUES(?,'replica','pending','relay','sync',?)",
         (SYNC_KEY + ":replica", json.dumps({"nodes": [n1["node_id"]], "replica_of": g["job_id"]})))
    v = invariants.s21_unreplicated_never_compared(db)
    assert v and "re-runs stage sync, which does not compare" in v[0]


# ---------------------------------------------------------------------------- #5 jobs that name their stage

def enqueue(db, sid, *items):
    from oarbank.coordinator import effects
    with db.tx():
        return effects.apply(db, "relay", {"jobs.enqueue"}, [{"kind": "jobs.enqueue", "args": {"campaign_id": sid, "jobs": list(items)}}])


SYNC_KEY = job_key("dev.codonic.oarbank.relay", "relay1", {"task": "sync", "cursor": 7}, "sync")
DEFAULT_KEY = job_key("dev.codonic.oarbank.relay", "relay1", {"params": PARAMS}, "eval")


def sync_item(key=SYNC_KEY, **kw):
    from oarbank_sdk import effects as fx
    return fx.job(key, {"task": "sync", "cursor": 7}, stage="sync", **kw)


def sync_result(items=("r1", "r2"), feed="f1"):
    return {"result": {"envelope": 1, "schema": "relay/result@1", "module_version": "1.0.0", "protocol": 1,
                       "payload": {"items": list(items), "feed_sha": feed}}}


def test_a_staged_job_runs_its_stage_and_never_the_chain(db):
    n1, = certified_fleet(db, ("n1",))
    db.set_setting("pipeline:relay", "split")
    sid = study(db)
    assert db.one("SELECT COUNT(*) n FROM jobs WHERE campaign_id=? AND kind='call'", (sid,))["n"] == 1   # evaluations split
    enqueue(db, sid, sync_item(), {**sync_item(DEFAULT_KEY), "stage": "eval", "spec": {"params": PARAMS}})
    sync = db.one("SELECT * FROM jobs WHERE job_key=?", (SYNC_KEY,))
    assert (sync["kind"], sync["stage"], sync["depends_on"]) == ("eval", "sync", None)
    assert json.loads(sync["resources_json"]) == {"cpu": 0.5, "mem_gb": 0.5}      # the sync stage's own reservation
    dflt = db.one("SELECT * FROM jobs WHERE job_key=?", (DEFAULT_KEY,))
    assert (dflt["stage"], dflt["depends_on"]) == ("eval", None)                  # named: not split either
    assert core.set_pipeline(db, "relay", "split", "test")["expanded"] == 0
    g = {x["job_id"]: x for x in grants(db, n1, free=8)}
    assert g[sync["job_id"]]["spec"]["stage"] == "sync" and g[sync["job_id"]]["spec"]["resources"]["cpu"] == 0.5
    assert g[dflt["job_id"]]["spec"]["stage"] is None                             # the default stage stays absent
    r = core.complete(db, fresh(db, n1), g[sync["job_id"]]["attempt_id"], sync_result())
    assert r["canonical"], r
    assert ok(db)


@pytest.mark.parametrize("key", ["k1", SYNC_KEY.upper(), SYNC_KEY[:63], SYNC_KEY.split(":")[0] + ":Sync", SYNC_KEY + ":", None, 7])
def test_jobs_enqueue_refuses_a_key_that_keys_job_key_did_not_make(db, key):
    """A job key is oarbank_sdk.keys.job_key's (spec/envelopes.md): 64 lowercase hex digits, then :<stage>. Replica
    sampling reads its first 8 digits as a number and the result cache matches it exactly, so anything else is refused
    at enqueue, before any of the effect's jobs exist."""
    from oarbank.coordinator import effects
    sid = study(db)
    before = db.one("SELECT COUNT(*) n FROM jobs")["n"]
    with pytest.raises(effects.EffectError) as e:
        enqueue(db, sid, sync_item(), {**sync_item(), "job_key": key})
    assert (e.value.status, e.value.code) == (422, "bad_job_key") and repr(key) in e.value.detail
    assert db.one("SELECT COUNT(*) n FROM jobs")["n"] == before


def test_every_enqueued_job_can_be_sampled_for_a_replica(db):
    """At replica rate 1 every comparing job a node finishes is sampled by its key's digits: an enqueued staged key
    (`<digest>:<stage>`) and an unstaged one both sample, so no key that passed enqueue can break completion."""
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    db.set_setting("replica_rate", 1.0)
    sid = study(db)
    enqueue(db, sid, {**sync_item(DEFAULT_KEY), "stage": "eval", "spec": {"params": PARAMS}},
            {**sync_item(DEFAULT_KEY.split(":")[0]), "stage": "eval", "spec": {"params": {**PARAMS, "samples": 11}},
             "labels": {"unstaged": 1}})
    mine = {r["job_id"] for r in db.q("SELECT job_id FROM jobs WHERE job_key IN (?, ?)", (DEFAULT_KEY, DEFAULT_KEY.split(":")[0]))}
    done = 0
    for g in grants(db, n1, free=16):
        if g["job_id"] in mine:
            assert core.complete(db, fresh(db, n1), g["attempt_id"], relay_result())["accepted"]
            done += 1
    assert done == 2
    assert db.one("SELECT COUNT(*) n FROM jobs WHERE kind='replica' AND json_extract(dispute_json,'$.replica_of') IN (%s)"
                  % ",".join(map(str, mine)))["n"] == 2
    assert ok(db)


@pytest.mark.parametrize("stage, code", [("score", "bad_stage"), ("render", "bad_stage"), ("nope", "bad_stage")])
def test_only_a_standalone_stage_can_be_named(db, stage, code):
    from oarbank.coordinator import effects
    sid = study(db)
    with pytest.raises(effects.EffectError) as e:
        enqueue(db, sid, {**sync_item(), "stage": stage})
    assert (e.value.status, e.value.code) == (422, code)


def test_a_staged_job_runs_only_where_its_stage_runs(db, monkeypatch):
    from oarbank.coordinator import effects
    from test_placement import BODY, beat, codes
    from helpers import certify, enrolled_node, facts_for
    info = modcalls.info("relay")
    stages = [s.model_copy(update={"requires": s.requires.model_copy(update={"platforms": ["linux-amd64"]})}) if s.name == "sync"
              else s for s in info.manifest.stages]
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=info.manifest.model_copy(update={"stages": stages})))
    mini = certify(db, enrolled_node(db, "mini")[1])
    box = certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1])
    for n in (mini, box):
        beat(db, n)
    sid = study(db)
    with pytest.raises(effects.EffectError) as e:
        enqueue(db, sid, sync_item(platforms=["darwin"]))
    assert (e.value.status, e.value.code) == (422, "placement_infeasible")
    enqueue(db, sid, sync_item())
    jid = db.one("SELECT job_id FROM jobs WHERE job_key=?", (SYNC_KEY,))["job_id"]
    assert "STAGE_PLATFORM_UNSUPPORTED" in codes(db, jid, mini) and not codes(db, jid, box)    # explain, as claim decides
    assert jid not in [g["job_id"] for g in core.claim(db, fresh(db, mini), BODY)["grants"]]
    assert jid in [g["job_id"] for g in core.claim(db, fresh(db, box), BODY)["grants"]]
    assert ok(db)


def test_a_staged_job_joins_its_campaigns_unit_with_its_stages_classes(db, monkeypatch):
    """With [placement] same-platform per campaign, a sync job binds the campaign unit like any job: its stage's
    platforms narrow the unit's feasible classes."""
    from oarbank_sdk import manifest as mf
    from oarbank.coordinator import placement
    from test_placement import relay_with
    relay_with(monkeypatch, placement=mf.Placement(mix="same-platform", unit="campaign", bind="first-claim"))
    info = modcalls.info("relay")
    stages = [s.model_copy(update={"requires": s.requires.model_copy(update={"platforms": ["linux-arm64"]})}) if s.name == "sync"
              else s for s in info.manifest.stages]
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=info.manifest.model_copy(update={"stages": stages})))
    sid = study(db)
    enqueue(db, sid, sync_item())
    assert placement.binding(db, f"c:{sid}")["feasible"] == ["linux-arm64"]


def test_a_host_tool_too_old_keeps_off_only_the_stages_that_need_certification(db, monkeypatch):
    """A host tool serves a capability, which a stage that needs no certification never requires: such a job runs
    (with no tools: docs/design/host-tools.md); the stages that compare, and the goldens, wait with TOOL_VERSION_UNMET,
    naming the tool, what the node found and what the module needs."""
    from oarbank.coordinator import explain, modsandbox
    from oarbank_sdk import manifest as mf
    sick = doctored(db, "sick", SICK)
    db.x("UPDATE nodes SET tools_json=? WHERE node_id=?", (json.dumps({"detected_at": 1.0, "native_arch": "arm64", "tools": {"jdk": [
        {"path": "/Library/Java/JavaVirtualMachines/zulu-11.jdk/Contents/Home", "version": "11.0.2", "arch": "aarch64",
         "source": "detected", "status": "ok"}]}}), sick["node_id"]))
    info = modcalls.info("relay")
    sandbox = info.manifest.sandbox.model_copy(update={"tools": [mf.ToolGrant(id="jdk", version=">=17", trust="code-exec")]})
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=info.manifest.model_copy(
        update={"sandbox": sandbox})))
    assert modsandbox.node_exclusions(db, fresh(db, sick), {"relay"}) == {"relay": "TOOL_VERSION_UNMET"}
    assert modsandbox.node_excluded(db, fresh(db, sick), {"relay"}) == set()
    sid = study(db)
    enqueue(db, sid, sync_item())
    ev = db.one("SELECT job_id FROM jobs WHERE stage IS NULL AND kind='eval'")["job_id"]
    head = explain.job_doc(db, ev).headline
    assert ("Module relay needs another version of a host tool: jdk >=17: found 11.0.2 at "
            "/Library/Java/JavaVirtualMachines/zulu-11.jdk/Contents/Home; needs >=17 (1 node: 1 darwin-arm64)" in head.text), head.text
    assert [x["spec"]["stage"] for x in grants(db, sick)] == ["sync"]
    assert ok(db)


def test_which_node_exclusions_spare_which_jobs():
    from oarbank.coordinator import predicates
    exempt, boot, plain = {"exempt": True, "bootstrap": False}, {"exempt": True, "bootstrap": True}, {"exempt": False}
    for code in ("TOOL_NOT_FOUND", "TOOL_VERSION_UNMET", "TOOL_REFUSED"):
        assert [predicates.spared(code, j) for j in (exempt, boot, plain)] == [True, True, False]
    assert [predicates.spared("FOLDER_UNAVAILABLE", j) for j in (exempt, boot, plain)] == [False, True, False]
    assert not any(predicates.spared(c, boot) for c in ("PLATFORM_UNSUPPORTED", "CAPABILITY_NOT_ENFORCED", "AGENT_TOO_OLD", None))
