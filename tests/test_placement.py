"""Placement (PLAN D33; docs/design/per-platform-modules.md 3.5 and 3.8): each unit of work of a campaign stays on one
platform class while other units use other classes. Mixed fleets of darwin-arm64, linux-amd64 and linux-arm64 nodes run
the relay fixture module with campaign placements (campaigns.create `placement`) and patched manifests."""
import dataclasses
import json

import pytest

from oarbank.coordinator import clock, core, effects, explain, invariants, modcalls, placement
from oarbank_sdk.keys import job_key

from helpers import (PARAMS, READY, SCENES, certify, create_study, enrolled_node, facts_for, fresh, make_db, relay_result,
                     render_artifacts, run_op)
from helpers import set_fleet

RIGHT = relay_result(score="0.850000", image="A")
BODY = {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY}


@pytest.fixture
def db(tmp_path):
    clock.set_fake(1_900_000_000.0)
    d = make_db(tmp_path / "oarbank.sqlite3")
    yield d
    clock.set_fake(None)
    d.conn.close()


@pytest.fixture
def fleet(db):
    """mini (darwin-arm64), box (linux-amd64), arm (linux-arm64), each certified, online and reporting CPU slots."""
    out = {"mini": certify(db, enrolled_node(db, "mini")[1]),
           "box": certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1]),
           "arm": certify(db, enrolled_node(db, "arm", facts=facts_for("linux-arm64", os_version="6.8"))[1])}
    for name, slots in (("mini", 4), ("box", 16), ("arm", 8)):
        beat(db, out[name], slots)
    return out


def beat(db, node, slots=8):
    core.heartbeat(db, fresh(db, node), {"capacity": {"pools": {"scorer": 4}, "cpu_slots": slots}, "attempts": [],
                                         "ready_datasets": READY})


def ok(db):
    v = invariants.check_all(db)
    assert not v, v
    return True


def study(db, datasets=SCENES[:2], configs=1, **kw):
    return create_study(db, "p", [{"label": f"c{i}", "params": {**PARAMS, "samples": 20 + i}} for i in range(configs)],
                        list(datasets), {"label": "base", "params": PARAMS}, **kw)


def grants(db, node, free=8):
    return [g for g in core.claim(db, fresh(db, node), {**BODY, "free_cpu": free})["grants"] if g["module"] == "relay"]


def unit(db, u):
    return placement.binding(db, u)


def codes(db, job_id, node):
    doc = explain.job_doc(db, job_id, bodies={node["node_id"]: BODY}, now=clock.now())
    return {r.code for r in next(m for m in doc.matrix if m.node == node["hostname"]).results if r.outcome != "pass"}


def pending(db, sid):
    return db.q("SELECT * FROM jobs WHERE campaign_id=? AND state='pending' ORDER BY job_id", (sid,))


def relay_with(monkeypatch, **upd):
    """relay with manifest sections replaced (patched in the catalog): placement, stages, datasets."""
    info = modcalls.info("relay")
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=info.manifest.model_copy(update=upd)))


def test_first_claim_binds_a_campaign_and_same_os_mixes_arm64_and_amd64(db, fleet):
    sid = study(db, placement={"mix": "same-os", "bind": "first-claim"})
    assert unit(db, f"c:{sid}")["state"] == "unbound"
    g = grants(db, fleet["box"], free=1)[0]
    b = unit(db, f"c:{sid}")
    assert (b["class"], b["state"], b["source"]) == ("linux", "soft", "first_claim")
    j = pending(db, sid)[0]
    assert "PLATFORM_BOUND_ELSEWHERE" in codes(db, j["job_id"], fleet["mini"]) and not grants(db, fleet["mini"])
    assert grants(db, fleet["arm"], free=1)                               # linux-arm64 is in the same OS class
    assert core.complete(db, fresh(db, fleet["box"]), g["attempt_id"], RIGHT)["canonical"]
    assert unit(db, f"c:{sid}")["state"] == "hard"
    assert ok(db)


def test_capacity_binds_a_campaign_at_creation_to_the_class_with_most_free_cpu(db, fleet):
    sid = study(db, placement={"mix": "same-platform"})                  # a campaign binds by capacity by default
    b = unit(db, f"c:{sid}")
    assert (b["class"], b["state"], b["source"]) == ("linux-amd64", "soft", "capacity")
    assert not grants(db, fleet["mini"]) and not grants(db, fleet["arm"]) and grants(db, fleet["box"])
    assert ok(db)


def test_a_pin_binds_now_and_explicit_waits_for_one(db, fleet):
    sid = study(db, placement={"mix": "same-platform", "pin": "linux-arm64"})
    assert (unit(db, f"c:{sid}")["state"], unit(db, f"c:{sid}")["class"]) == ("pinned", "linux-arm64")
    assert not grants(db, fleet["box"]) and grants(db, fleet["arm"])
    sid2 = study(db, SCENES[2:4], placement={"mix": "same-os", "bind": "explicit"})
    j = pending(db, sid2)[0]
    assert "PLACEMENT_UNPINNED" in codes(db, j["job_id"], fleet["mini"]) and not grants(db, fleet["mini"])
    run_op(db, "campaigns.rebind_platform", sid2, params={"platform": "darwin-arm64"})
    assert (unit(db, f"c:{sid2}")["state"], unit(db, f"c:{sid2}")["class"]) == ("pinned", "darwin")
    assert grants(db, fleet["mini"])
    assert ok(db)


def test_groups_spread_across_platforms_but_stay_together(db, fleet):
    sid = study(db, SCENES[:2], configs=2, group_by="dataset",
                placement={"mix": "same-platform", "unit": "group", "bind": "first-claim"})
    s1 = grants(db, fleet["mini"], free=1)[0]
    g1 = db.one("SELECT group_key FROM jobs WHERE job_id=?", (s1["job_id"],))["group_key"]
    assert unit(db, f"c:{sid}/g:{g1}")["class"] == "darwin-arm64"
    other = grants(db, fleet["box"])
    assert other and {db.one("SELECT group_key FROM jobs WHERE job_id=?", (g["job_id"],))["group_key"] for g in other} != {g1}
    assert all(db.one("SELECT group_key FROM jobs WHERE job_id=?", (g["job_id"],))["group_key"] != g1 for g in other)
    assert {u["class"] for u in placement.campaign_units(db, sid)} == {"darwin-arm64", "linux-amd64"}
    assert ok(db)


def test_a_pipeline_stays_in_one_class_and_its_head_never_binds_where_its_tail_cannot_run(db, fleet, monkeypatch):
    from oarbank_sdk import manifest as mf
    info = modcalls.info("relay")
    stages = [s.model_copy(update={"requires": s.requires.model_copy(update={"platforms": ["darwin-arm64", "linux-amd64"]}),
                                   "placement": mf.StagePlacement(mix="same-platform")}) if s.name == "score" else s for s in info.manifest.stages]
    relay_with(monkeypatch, stages=stages)
    set_fleet(db, "pipeline", "split", "relay")
    sid = study(db, SCENES[:1], placement={"mix": "same-os", "bind": "first-claim"})
    head = db.one("SELECT * FROM jobs WHERE campaign_id=? AND kind='call'", (sid,))
    tail = db.one("SELECT * FROM jobs WHERE campaign_id=? AND kind='eval' AND depends_on=?", (sid, head["job_id"]))
    assert head["placement_unit"] == tail["placement_unit"] == f"c:{sid}/p:{tail['job_id']}"
    assert unit(db, head["placement_unit"])["parent"] == f"c:{sid}"
    assert "STAGE_PLATFORM_UNSUPPORTED" in codes(db, head["job_id"], fleet["arm"])     # its tail cannot run on linux-arm64
    assert not [g for g in grants(db, fleet["arm"]) if g["job_id"] == head["job_id"]]
    g = [g for g in grants(db, fleet["box"]) if g["job_id"] == head["job_id"]][0]
    assert unit(db, head["placement_unit"])["class"] == "linux-amd64" and unit(db, f"c:{sid}")["class"] == "linux"
    core.complete(db, fresh(db, fleet["box"]), g["attempt_id"], relay_result(stage="render", artifacts=render_artifacts(db)))
    assert not [x for x in grants(db, fleet["mini"]) if x["job_id"] == tail["job_id"]]
    assert "PLATFORM_BOUND_ELSEWHERE" in codes(db, tail["job_id"], fleet["mini"])
    assert [x for x in grants(db, fleet["box"]) if x["job_id"] == tail["job_id"]]
    assert ok(db)


def test_a_platform_bound_dataset_keeps_its_jobs_on_its_platform(db, fleet, monkeypatch):
    relay_with(monkeypatch, datasets=modcalls.info("relay").manifest.datasets.model_copy(update={"platform_bound": ["scene"]}))
    with db.tx(), pytest.raises(effects.EffectError, match="dataset_platform_required"):
        effects.apply(db, "relay", {"datasets.create"}, [{"kind": "datasets.create", "args": {
            "dataset_id": "scene:idx", "kind": "scene", "files": []}}])
    with db.tx():
        effects.apply(db, "relay", {"datasets.create"}, [{"kind": "datasets.create", "args": {
            "dataset_id": "scene:idx", "kind": "scene", "files": [], "platform": "linux-amd64"}}])
    assert db.one("SELECT platform FROM datasets WHERE dataset_id='scene:idx'")["platform"] == "linux-amd64"
    ready = {**BODY, "ready_datasets": READY + ["scene:idx"]}
    sid = study(db, ["scene:idx"])                                        # no placement: the dataset alone decides
    j = pending(db, sid)[0]
    doc = explain.job_doc(db, j["job_id"], bodies={n["node_id"]: ready for n in fleet.values()}, now=clock.now())
    assert {s.code: s.nodes for s in doc.summary}["DATASET_PLATFORM_MISMATCH"] == ["arm", "mini"], doc.summary
    assert not core.claim(db, fresh(db, fleet["mini"]), ready)["grants"]
    assert core.claim(db, fresh(db, fleet["box"]), ready)["grants"]
    beat(db, fleet["mini"], 64)              # capacity binds the new campaign to darwin, until its job reads the dataset
    sid2 = study(db, ["scene:idx"], placement={"mix": "same-os"})
    b = unit(db, f"c:{sid2}")
    assert (b["class"], b["state"], b["source"], b["feasible"]) == ("linux", "soft", "capacity", ["linux"])
    assert ok(db)


def test_the_result_cache_is_filtered_by_class(db, fleet):
    a = study(db, SCENES[:1], placement={"mix": "same-platform", "pin": "darwin-arm64"})
    for g in grants(db, fleet["mini"]):
        core.complete(db, fresh(db, fleet["mini"]), g["attempt_id"], RIGHT)
    assert not pending(db, a)
    b = study(db, SCENES[:1], placement={"mix": "same-platform", "pin": "linux-amd64"})
    assert len(pending(db, b)) == 2                                      # darwin results never satisfy a Linux campaign
    c = study(db, SCENES[:1], placement={"mix": "same-platform", "pin": "darwin-arm64"})
    assert not pending(db, c)                                            # its own class: cache hits
    d = study(db, SCENES[:1], placement={"mix": "same-platform", "bind": "first-claim"})
    assert not pending(db, d)
    bd = unit(db, f"c:{d}")
    assert (bd["class"], bd["state"], bd["source"]) == ("darwin-arm64", "hard", "cache_hit")
    plain = study(db, SCENES[:1])                                        # no placement: any canonical result, as before
    assert not pending(db, plain)
    assert ok(db)


def test_a_soft_binding_is_released_after_a_failed_first_attempt(db, fleet):
    sid = study(db, SCENES[:1], placement={"mix": "same-platform", "bind": "first-claim"})
    gs = grants(db, fleet["box"])
    assert unit(db, f"c:{sid}")["class"] == "linux-amd64"
    for g in gs:
        core.fail(db, fresh(db, fleet["box"]), g["attempt_id"], {"reason": "exit_nonzero"})
    core.reap(db)
    assert unit(db, f"c:{sid}")["state"] == "unbound"
    clock.advance(700)
    assert grants(db, fleet["mini"]) and unit(db, f"c:{sid}")["class"] == "darwin-arm64"
    assert ok(db)


def _stranded_on_box(db, fleet, **placement_kw):
    """A campaign hard-bound to linux-amd64 (one job done on box) whose only linux-amd64 node then goes away."""
    sid = study(db, SCENES[:2], **placement_kw)
    g = grants(db, fleet["box"], free=1)[0]
    core.complete(db, fresh(db, fleet["box"]), g["attempt_id"], RIGHT)
    assert unit(db, f"c:{sid}")["state"] in ("hard", "pinned")
    db.x("UPDATE nodes SET last_heartbeat_at=? WHERE node_id=?", (clock.now() - 3600, fleet["box"]["node_id"]))
    return sid, g["job_id"]


def test_a_stranded_unit_raises_the_alert_and_rebind_requeues_its_finished_jobs(db, fleet):
    sid, done_job = _stranded_on_box(db, fleet, placement={"mix": "same-platform", "pin": "linux-amd64"})
    core.reap(db)
    assert unit(db, f"c:{sid}")["stranded_since"] is not None
    assert not db.one("SELECT 1 FROM alerts WHERE rule=? AND state='open'", (f"placement_stranded:c:{sid}",))
    clock.advance(1801)
    beat(db, fleet["mini"], 4)
    core.reap(db)
    a = db.one("SELECT * FROM alerts WHERE rule=? AND state='open'", (f"placement_stranded:c:{sid}",))
    assert a and "campaigns.rebind_platform" in a["detail"] and a["subject"] == f"campaign:{sid}"
    out = run_op(db, "campaigns.rebind_platform", sid, params={"platform": "darwin-arm64"})
    assert out["result"]["requeued"] == [done_job]
    b = unit(db, f"c:{sid}")
    assert (b["class"], b["state"], b["source"]) == ("darwin-arm64", "pinned", "rebind")
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (done_job,))["state"] == "pending"
    assert ok(db)
    core.reap(db)
    assert not db.one("SELECT 1 FROM alerts WHERE rule=? AND state='open'", (f"placement_stranded:c:{sid}",))
    for _ in range(3):
        for g in grants(db, fleet["mini"]):
            core.complete(db, fresh(db, fleet["mini"]), g["attempt_id"], RIGHT)
    assert not pending(db, sid) and ok(db)
    assert {r["platform"] for r in db.q("SELECT r.platform FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id "
                                         "WHERE j.campaign_id=?", (sid,))} == {"darwin-arm64"}


def test_rebind_if_stranded_moves_a_unit_by_itself(db, fleet, monkeypatch):
    from oarbank_sdk import manifest as mf
    relay_with(monkeypatch, placement=mf.Placement(mix="same-platform", rebind="if-stranded", stranded_after_s=600))
    sid, done_job = _stranded_on_box(db, fleet)
    assert unit(db, f"c:{sid}")["rebind"] == "if-stranded"
    core.reap(db)
    clock.advance(601)
    beat(db, fleet["mini"], 4)
    beat(db, fleet["arm"], 8)
    core.reap(db)
    b = unit(db, f"c:{sid}")
    assert (b["class"], b["state"], b["source"]) == ("linux-arm64", "soft", "rebind")        # the most free CPU left
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (done_job,))["state"] == "pending"
    assert db.one("SELECT 1 FROM audit WHERE operation='campaigns.rebind_platform' AND actor='system' AND target_id=?", (sid,))
    assert db.one("SELECT 1 FROM alerts WHERE rule=? AND state='open'", (f"placement_rebound:c:{sid}",))
    assert ok(db)


def test_a_looser_campaign_placement_is_refused(db, monkeypatch):
    from oarbank_sdk import manifest as mf
    relay_with(monkeypatch, placement=mf.Placement(mix="same-platform"))
    with pytest.raises(core.ApiError) as e:
        study(db, placement={"mix": "same-os"})
    assert (e.value.status, e.value.code) == (422, "placement_looser_than_manifest")
    with pytest.raises(core.ApiError) as e:
        study(db, placement={"mix": "same-platform", "unit": "group"})
    assert e.value.code == "placement_looser_than_manifest"
    with pytest.raises(core.ApiError) as e:
        study(db, placement={"mix": "same-platform", "pin": "linux-riscv64"})
    assert e.value.code == "placement_infeasible"


def test_set_placement_is_stricter_only_and_before_the_first_result(db, fleet):
    sid = study(db, SCENES[:2])
    assert db.one("SELECT placement_json FROM campaigns WHERE campaign_id=?", (sid,))["placement_json"] is None
    g = grants(db, fleet["box"], free=1)[0]
    run_op(db, "campaigns.set_placement", sid, params={"mix": "same-os"})
    b = unit(db, f"c:{sid}")
    assert b["class"] == "linux"                       # the attempt running on box keeps the campaign there
    with pytest.raises(core.ApiError) as e:
        run_op(db, "campaigns.set_placement", sid, params={"mix": "any"})
    assert e.value.code == "placement_looser"
    core.complete(db, fresh(db, fleet["box"]), g["attempt_id"], RIGHT)
    with pytest.raises(core.ApiError) as e:
        run_op(db, "campaigns.set_placement", sid, params={"mix": "same-platform"})
    assert e.value.code == "campaign_has_results"
    assert ok(db)


def test_toy_and_relay_without_placement_behave_as_before(db, fleet):
    """A module without [placement] and a campaign without `placement`: no unit, no binding, every platform takes work."""
    sid = study(db, SCENES[:3])
    assert not placement.campaign_units(db, sid)
    assert {j["placement_unit"] for j in db.q("SELECT placement_unit FROM jobs WHERE campaign_id=?", (sid,))} == {None}
    taken = {n: len(grants(db, fleet[n], free=2)) for n in ("mini", "box", "arm")}
    assert all(taken.values()), taken
    r = run_op(db, "mod.toy.queue_sums", params={"ns": [3, 4]})
    assert not placement.campaign_units(db, r["result"]["result"]["campaign_id"])
    from oarbank.coordinator import campaigns
    assert campaigns.summary(db, sid)["placement"] is None
    assert ok(db)


def test_s20_names_a_job_that_ran_outside_its_units_class(db, fleet):
    sid = study(db, SCENES[:1], placement={"mix": "same-platform", "pin": "linux-amd64"})
    g = grants(db, fleet["box"], free=1)[0]
    assert ok(db)
    db.x("UPDATE attempts SET node_id=? WHERE attempt_id=?", (fleet["mini"]["node_id"], g["attempt_id"]))
    v = invariants.s20_units_stay_in_their_class(db)
    assert v and "bound to linux-amd64" in v[0]


def test_campaign_tick_and_jobs_carry_placement_and_group(db, fleet):
    from oarbank.coordinator import campaigns
    sid = study(db, SCENES[:1], group_by="trial", placement={"mix": "same-os", "unit": "group", "bind": "first-claim"})
    row = campaigns.campaign_row(db, db.one("SELECT * FROM campaigns WHERE campaign_id=?", (sid,)))
    assert row["placement"]["mix"] == "same-os" and row["placement"]["unit"] == "group" and row["placement"]["units"] == {"unbound": 2}
    assert {j["group"] for j in campaigns.campaign_jobs(db, sid)} == {"t0", "t1"}
    assert json.loads(db.one("SELECT placement_json FROM campaigns WHERE campaign_id=?", (sid,))["placement_json"])["bind"] == "first-claim"


def test_cli_shows_placement_sets_it_and_rebinds(db, fleet):
    """`oarbank campaign show|placement|rebind` against a real oarbankd, as an operator runs them."""
    import os
    import subprocess
    import sys
    from oarbank.coordinator import access, app as coord_app
    from test_console import Server
    sid = study(db, SCENES[:1])
    with Server(coord_app.admin_app(db)) as oarbankd:
        env = {**os.environ, "OARBANKD_URL": f"http://127.0.0.1:{oarbankd.port}", "OARBANK_REASON": "cli test",
               "OARBANK_TOKEN": access.ensure_admin_token(db.root)}
        run = lambda *args: subprocess.run([sys.executable, "-m", "oarbank.cli.main", "campaign", *args], capture_output=True,
                                           text=True, env=env, timeout=300)
        assert run("show", sid).stdout.startswith("placement: any")
        r = run("placement", sid, "--mix", "same-platform", "--yes")
        assert r.returncode == 0, r.stderr
        r = run("rebind", sid, "--platform", "linux-arm64", "--yes")
        assert r.returncode == 0, r.stderr
        out = run("show", sid).stdout
        assert out.startswith("placement: same-platform per campaign") and "bound to linux-arm64 (pinned)" in out, out
        assert run("rebind", sid).returncode != 0                           # --platform is required


@pytest.mark.parametrize("item, code", [
    ({"group": "x" * 65}, "bad_group"), ({"platforms": ["linux_amd64!"]}, "bad_platforms"),
    ({"platforms": ["plan9"]}, "placement_infeasible"),
])
def test_jobs_enqueue_refuses_bad_groups_and_platforms(db, item, code):
    sid = study(db, SCENES[:1])
    with db.tx(), pytest.raises(effects.EffectError) as e:
        effects.apply(db, "relay", {"jobs.enqueue"}, [{"kind": "jobs.enqueue", "args": {"campaign_id": sid, "jobs": [
            {"job_key": job_key("dev.codonic.oarbank.relay", "relay1", {"k": 1}), "spec": {}, **item}]}}])
    assert (e.value.status, e.value.code) == (422, code)


def test_job_platforms_keep_a_job_on_them(db, fleet):
    sid = study(db, SCENES[:1], platforms=["linux"])
    j = pending(db, sid)[0]
    assert "STAGE_PLATFORM_UNSUPPORTED" in codes(db, j["job_id"], fleet["mini"]) and not grants(db, fleet["mini"])
    assert grants(db, fleet["arm"], free=1) and grants(db, fleet["box"], free=1)
    assert ok(db)


def test_a_pipeline_unit_binds_only_where_a_node_can_run_its_tail(db, fleet, monkeypatch):
    """Only mini holds the scorer pool the score stage reserves: a render head claimed on box would bind the pipeline to
    a class where its tail can never run, so box is not offered it (found by the placement sweep: split pipelines with
    unit = "pipeline" stranded)."""
    from oarbank_sdk import manifest as mf
    relay_with(monkeypatch, placement=mf.Placement(mix="same-arch", unit="pipeline"))
    set_fleet(db, "pipeline", "split", "relay")
    for name in ("box", "arm"):
        core.heartbeat(db, fresh(db, fleet[name]), {"capacity": {"pools": {"scorer": 0}, "cpu_slots": 8}, "attempts": [],
                                                    "ready_datasets": READY})
    sid = study(db, SCENES[:1])
    head = db.one("SELECT * FROM jobs WHERE campaign_id=? AND kind='call' ORDER BY job_id LIMIT 1", (sid,))
    assert "STAGE_PLATFORM_UNSUPPORTED" in codes(db, head["job_id"], fleet["box"])
    assert not [g for g in grants(db, fleet["box"]) if g["job_id"] == head["job_id"]]
    assert [g for g in grants(db, fleet["arm"]) if g["job_id"] == head["job_id"]]       # arm64, the scorer's arch
    assert unit(db, head["placement_unit"])["class"] == "arm64"
    assert ok(db)


def pools(db, node, scorer, slots):
    core.heartbeat(db, fresh(db, node), {"capacity": {"pools": {"scorer": scorer}, "cpu_slots": slots}, "attempts": [],
                                         "ready_datasets": READY})


def test_capacity_binds_a_unit_only_where_every_stage_has_a_node(db, fleet):
    """box (linux-amd64) has the most free CPU but no scorer pool, which the split pipeline's score stage reserves:
    the campaign binds by capacity to arm (linux-arm64), the only class whose nodes can run both stages."""
    set_fleet(db, "pipeline", "split", "relay")
    pools(db, fleet["box"], 0, 64)
    pools(db, fleet["mini"], 0, 32)
    pools(db, fleet["arm"], 4, 8)
    sid = study(db, SCENES[:1], placement={"mix": "same-platform", "bind": "capacity"})
    b = unit(db, f"c:{sid}")
    assert (b["class"], b["state"], b["source"]) == ("linux-arm64", "soft", "capacity")
    assert ok(db)


def test_a_unit_whose_classes_lose_a_pool_its_work_needs_is_reported_stranded(db, fleet):
    """Bound by capacity to arm, the only scorer node; then arm loses the pool too. Before the fix the unit was never
    stranded (class_has_node ignored pools) and hung silently."""
    set_fleet(db, "pipeline", "split", "relay")
    pools(db, fleet["box"], 0, 64)
    pools(db, fleet["mini"], 0, 32)
    pools(db, fleet["arm"], 4, 8)
    sid = study(db, SCENES[:1], placement={"mix": "same-platform", "bind": "capacity"})
    assert unit(db, f"c:{sid}")["class"] == "linux-arm64"
    pools(db, fleet["arm"], 0, 8)                                   # the pool is gone
    core.reap(db)
    assert unit(db, f"c:{sid}")["stranded_since"] is not None
    clock.advance(1801)
    for name, slots in (("box", 64), ("mini", 32), ("arm", 8)):
        pools(db, fleet[name], 0, slots)
    core.reap(db)
    a = db.one("SELECT * FROM alerts WHERE rule=? AND state='open'", (f"placement_stranded:c:{sid}",))
    assert a and "no other class can run them all" in a["detail"] and unit(db, f"c:{sid}")["state"] == "unbound"
    pools(db, fleet["mini"], 2, 32)                                 # a scorer comes back on mini
    core.reap(db)
    assert unit(db, f"c:{sid}")["state"] == "unbound"               # rebinds when work is claimed, where it can run
    assert ok(db)


def test_a_stricter_mix_fences_a_late_result_from_an_attempt_that_already_ended(db, fleet):
    """Found by the Hypothesis machine: box's attempt expires, campaigns.set_placement binds the campaign to darwin by
    capacity, then box delivers late; its generation is fenced, so no result lands outside the unit's class (S20)."""
    sid = study(db, SCENES[:1])
    g = grants(db, fleet["box"], free=1)[0]
    db.x("UPDATE attempts SET expires_at=? WHERE attempt_id=?", (clock.now() - 1, g["attempt_id"]))
    core.reap(db)
    pools(db, fleet["mini"], 4, 64)                                 # darwin has the most free CPU now
    run_op(db, "campaigns.set_placement", sid, params={"mix": "same-os"})
    assert unit(db, f"c:{sid}")["class"] == "darwin"
    r = core.complete(db, fresh(db, fleet["box"]), g["attempt_id"], RIGHT)
    assert (r["canonical"], r["reason"]) == (False, "stale_generation")
    assert ok(db)


# ---------------------------------------------------------------------------- stages[].requires.capabilities

def needs_capabilities(monkeypatch, stage, caps):
    """relay's `stage` requires node capabilities `caps` (stages[].requires.capabilities)."""
    info = modcalls.info("relay")
    relay_with(monkeypatch, stages=[s.model_copy(update={"requires": s.requires.model_copy(update={"capabilities": caps})})
                                    if s.name == stage else s for s in info.manifest.stages])


def report(db, node, services=(), relay=(), toy=()):
    """The node's doctor report (docs/protocol.md "Doctor"): what its offered services and healthy probes provide, and
    each module doctor's own capabilities."""
    doc = {"modules": {"relay": {"health": "healthy", "checks": [], "capabilities": list(relay)},
                       "toy": {"health": "healthy", "checks": [], "capabilities": list(toy)}}, "capabilities": list(services)}
    n = fresh(db, node)
    core.heartbeat(db, n, {"doctor": doc, "attempts": [], "ready_datasets": READY, "capacity": json.loads(n["capacity_json"])})


def test_a_stage_needing_a_capability_runs_only_where_the_node_reports_it(db, fleet, monkeypatch):
    """eval needs `java17`: mini has it from a probe, box from relay's own doctor; arm has it only for another module, which
    does not count. claim and explain agree, and a node that stops reporting it stops getting the work."""
    needs_capabilities(monkeypatch, "eval", ["java17"])
    report(db, fleet["mini"], services=["java17"])
    report(db, fleet["box"], relay=["java17"])
    report(db, fleet["arm"], toy=["java17"])
    sid = study(db, SCENES[:1], configs=2)
    jobs = pending(db, sid)
    assert len(jobs) == 3
    j = jobs[0]
    assert "STAGE_CAPABILITY_MISSING" in codes(db, j["job_id"], fleet["arm"]), "explain names the missing capability"
    assert "STAGE_CAPABILITY_MISSING" not in codes(db, j["job_id"], fleet["mini"]) | codes(db, j["job_id"], fleet["box"])
    row = next(r for m in explain.job_doc(db, j["job_id"], bodies={fleet["arm"]["node_id"]: BODY}, now=clock.now()).matrix
               if m.node == "arm" for r in m.results if r.code == "STAGE_CAPABILITY_MISSING")
    assert (row.outcome, row.observed, row.required) == ("fail", [], ["java17"])
    assert not grants(db, fleet["arm"])
    assert len(grants(db, fleet["mini"], free=1)) == 1 and len(grants(db, fleet["box"], free=1)) == 1
    report(db, fleet["box"])                                             # box's doctor no longer reports it
    assert "STAGE_CAPABILITY_MISSING" in codes(db, pending(db, sid)[0]["job_id"], fleet["box"]) and not grants(db, fleet["box"])
    assert grants(db, fleet["mini"], free=1)
    assert ok(db)


def test_capacity_binds_a_unit_only_where_a_node_has_its_stages_capabilities(db, fleet, monkeypatch):
    """box (linux-amd64) has the most free CPU, but only arm (linux-arm64) reports the capability eval needs: the campaign
    binds by capacity to arm, and once the capability goes away there the unit's class has no node for its work."""
    needs_capabilities(monkeypatch, "eval", ["java17"])
    report(db, fleet["arm"], services=["java17"])
    sid = study(db, SCENES[:1], placement={"mix": "same-platform"})
    b = unit(db, f"c:{sid}")
    assert (b["class"], b["state"], b["source"]) == ("linux-arm64", "soft", "capacity")
    assert placement.class_has_node(db, b)
    assert not grants(db, fleet["box"]) and grants(db, fleet["arm"], free=1)
    report(db, fleet["arm"])
    assert not placement.class_has_node(db, unit(db, f"c:{sid}"))
    assert ok(db)


def test_first_claim_never_binds_a_pipeline_where_its_tail_lacks_a_capability(db, fleet, monkeypatch):
    """Split pipeline, unit = pipeline, same-arch: the score stage needs `scorer-gpu`, which only arm reports. A render head
    claimed on box would bind the pipeline to amd64, where its tail can never run, so box is not offered it."""
    from oarbank_sdk import manifest as mf
    needs_capabilities(monkeypatch, "score", ["scorer-gpu"])
    relay_with(monkeypatch, placement=mf.Placement(mix="same-arch", unit="pipeline"))
    assert modcalls.stage_capabilities("relay", "score") == ["scorer-gpu"]
    set_fleet(db, "pipeline", "split", "relay")
    report(db, fleet["arm"], services=["scorer-gpu"])
    sid = study(db, SCENES[:1])
    head = db.one("SELECT * FROM jobs WHERE campaign_id=? AND kind='call' ORDER BY job_id LIMIT 1", (sid,))
    assert "STAGE_PLATFORM_UNSUPPORTED" in codes(db, head["job_id"], fleet["box"])        # no feasible class for its unit
    assert not [g for g in grants(db, fleet["box"]) if g["job_id"] == head["job_id"]]
    assert [g for g in grants(db, fleet["arm"]) if g["job_id"] == head["job_id"]]
    assert unit(db, head["placement_unit"])["class"] == "arm64"
    assert ok(db)


def test_a_replica_needs_another_node_with_the_stages_capabilities(db, fleet, monkeypatch):
    """Adaptive replication queues a replica only when another node could run it: with the capability on mini alone,
    nobody could (it would sit pending forever, TLA+ F3); once box reports it too, the replica is queued."""
    needs_capabilities(monkeypatch, "eval", ["java17"])
    set_fleet(db, "replica_rate", 1.0)
    report(db, fleet["mini"], services=["java17"])
    sid = study(db, SCENES[:2])
    first, second = grants(db, fleet["mini"], free=2)
    assert core.complete(db, fresh(db, fleet["mini"]), first["attempt_id"], RIGHT)["canonical"]
    assert not db.q("SELECT 1 FROM jobs WHERE kind='replica'")
    report(db, fleet["box"], services=["java17"])
    assert core.complete(db, fresh(db, fleet["mini"]), second["attempt_id"], relay_result(score="0.850000", image="B"))["canonical"]
    assert db.one("SELECT json_extract(dispute_json,'$.replica_of') o FROM jobs WHERE kind='replica'")["o"] == second["job_id"]
    assert ok(db)
