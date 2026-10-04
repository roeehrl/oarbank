"""campaign.tick sees structured results (docs/design/sdk-1.3.md, #3): with the campaign.tick.results capability every
evaluation's payload is checked against results.schema and max_inline_kb at acceptance, and the tick gets each done
job's payload and artifact files, newest first within a budget."""
import dataclasses

import pytest
from oarbank_sdk import effects as fx
from oarbank_sdk import module_protocol as mp
from oarbank_sdk.keys import job_key

from oarbank.coordinator import campaigns, core, effects, invariants, modcalls

from helpers import PARAMS, READY, SCENES, certified_fleet, create_study, fresh, make_db, render_artifacts


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def with_tick_results(monkeypatch, **results):
    """relay declaring campaign.tick and campaign.tick.results (patched in the catalog); `results` replaces [results]
    fields."""
    info = modcalls.info("relay")
    man = info.manifest
    co = man.coordinator.model_copy(update={"capabilities": [*man.coordinator.capabilities, "campaign.tick", mp.CAP_TICK_RESULTS]})
    upd = {"coordinator": co, **({"results": man.results.model_copy(update=results)} if results else {})}
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=man.model_copy(update=upd)))


def ok(db):
    v = invariants.check_all(db)
    assert not v, v
    return True


def sync(db, sid, cursor):
    payload = {"task": "sync", "cursor": cursor}
    with db.tx():
        effects.apply(db, "relay", {"jobs.enqueue"}, [fx.jobs_enqueue(sid, [
            fx.job(job_key("dev.codonic.oarbank.relay", "relay1", payload, "sync"), payload, stage="sync")]).model_dump()])
    return db.one("SELECT job_id FROM jobs WHERE campaign_id=? AND stage='sync' ORDER BY job_id DESC LIMIT 1", (sid,))["job_id"]


def run(db, node, job_id, payload, artifacts=None):
    """Complete the job's live attempt on `node`, claiming first if it has none."""
    a = db.one("SELECT attempt_id FROM attempts WHERE job_id=? AND node_id=? AND state='live'", (job_id, node["node_id"]))
    if a is None:
        core.claim(db, fresh(db, node), {"free_slots": 8, "ready_datasets": READY})
        a = db.one("SELECT attempt_id FROM attempts WHERE job_id=? AND node_id=? AND state='live'", (job_id, node["node_id"]))
    g = {"attempt_id": a["attempt_id"]}
    env = {"envelope": 1, "schema": "relay/result@1", "module_version": "1.0.0", "protocol": 1, "payload": payload}
    if artifacts is not None:
        env["artifacts"] = artifacts
    return core.complete(db, fresh(db, node), g["attempt_id"], {"result": env})


def study(db):
    return create_study(db, "s", [], SCENES[:1], {"label": "base", "params": PARAMS})


def test_the_tick_sees_each_done_jobs_payload_and_artifact_files(db, monkeypatch):
    n1, = certified_fleet(db, ("n1",))
    with_tick_results(monkeypatch)
    sid = study(db)
    jid = sync(db, sid, 1)
    arts = render_artifacts(db, image="feed")
    assert run(db, n1, jid, {"items": ["r1", "r2"], "feed_sha": "f1"}, arts)["canonical"]
    seen = {}
    monkeypatch.setattr(modcalls, "tick", lambda db_, name, campaign, jobs, now: seen.update(jobs=jobs) or {"effects": []})
    campaigns.tick_one(db, db.one("SELECT * FROM campaigns WHERE campaign_id=?", (sid,)))
    rows = {j["job_id"]: j for j in seen["jobs"]}
    assert rows[jid]["result"] == {"payload": {"items": ["r1", "r2"], "feed_sha": "f1"},
                                   "artifacts": [{"name": "frame", "files": [{k: arts[0]["files"][0][k] for k in ("path", "digest", "size")}]}]}
    assert mp.CampaignJob.model_validate(rows[jid]).result.artifacts[0].files[0].digest == arts[0]["files"][0]["digest"]
    assert all("result" not in j for j in seen["jobs"] if j["job_id"] != jid)         # pending evaluations
    assert ok(db)


def test_without_the_capability_the_tick_sees_fields_only(db):
    n1, = certified_fleet(db, ("n1",))
    sid = study(db)
    jid = sync(db, sid, 1)
    assert run(db, n1, jid, {"items": [], "feed_sha": "f"})["canonical"]
    row = {j["job_id"]: j for j in campaigns.campaign_jobs(db, sid, "relay")}[jid]
    assert "result" not in row, row


def test_one_tick_carries_the_newest_results_within_its_budget(db, monkeypatch):
    n1, = certified_fleet(db, ("n1",))
    with_tick_results(monkeypatch)
    sid = study(db)
    old, new = sync(db, sid, 1), sync(db, sid, 2)
    assert run(db, n1, old, {"items": ["a" * 300], "feed_sha": "o"})["canonical"]
    db.x("UPDATE jobs SET done_at=done_at-60 WHERE job_id=?", (old,))
    assert run(db, n1, new, {"items": ["b" * 300], "feed_sha": "n"})["canonical"]
    monkeypatch.setattr(mp, "TICK_RESULTS_BUDGET", 500)                      # room for one of the two
    rows = {j["job_id"]: j for j in campaigns.campaign_jobs(db, sid, "relay")}
    assert rows[new]["result"]["payload"]["feed_sha"] == "n" and "result_omitted" not in rows[new]
    assert "result" not in rows[old] and rows[old]["result_omitted"] is True


def test_results_accepted_without_the_capability_are_not_delivered(db, monkeypatch):
    n1, = certified_fleet(db, ("n1",))
    sid = study(db)
    jid = sync(db, sid, 1)
    assert run(db, n1, jid, {"items": ["r1"], "feed_sha": "f"})["canonical"]
    db.x("UPDATE results SET module_version='0.9.0' WHERE job_id=?", (jid,))       # accepted (unvalidated) by an older version
    with_tick_results(monkeypatch)
    row = {j["job_id"]: j for j in campaigns.campaign_jobs(db, sid, "relay")}[jid]
    assert "result" not in row and "result_omitted" not in row


@pytest.mark.parametrize("payload, results, why", [
    ({"items": [1, 2], "feed_sha": "f"}, {}, "results.schema: items/0"),
    ({"items": ["x" * 2000], "feed_sha": "f"}, {"max_inline_kb": 1}, "results.max_inline_kb 1"),
])
def test_an_invalid_payload_is_never_canonical_spends_the_jobs_retries_and_never_the_breaker(db, monkeypatch, payload, results, why):
    nodes = certified_fleet(db, ("n1", "n2", "n3"))
    with_tick_results(monkeypatch, **results)
    sid = study(db)
    jid = sync(db, sid, 1)
    for i, n in enumerate(nodes, 1):
        r = run(db, n, jid, payload)
        assert (r["accepted"], r["reason"]) == (False, "result_invalid")
        assert fresh(db, n)["breaker_failures"] == 0
        assert db.one("SELECT exec_failures FROM jobs WHERE job_id=?", (jid,))["exec_failures"] == i
        db.x("UPDATE jobs SET not_before=0 WHERE job_id=?", (jid,))                # past the retry backoff
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (jid,))["state"] == "quarantined"     # stage retry spent
    assert why in db.one("SELECT reason FROM events WHERE kind='result_invalid' ORDER BY event_id DESC LIMIT 1")["reason"]
    assert ok(db)
