"""A runner's declared failure (runner protocol, "Exit codes"; failure.json `{reason, detail, fault?, retryable?}`).

A job fault (`fault: "job"`: the job can never succeed) or `retryable: false` ends the job `failed` at once: it is not
retried on other nodes and not quarantined. Transient and host faults behave as before. The failure's reason and
detail stay on the job, for its views, explain, the campaign view and the module's campaign.tick and host.jobs.query.
A golden job its runner declares can never succeed fails the module's certification on that node at once."""
import pytest

from oarbank.coordinator import campaigns, clock, core, detail, explain, invariants, modcalls

from helpers import DOCTOR_OK, FACTS, PARAMS, READY, SCENES, certified_fleet, create_study, enrolled_node, fresh, golden_result
from helpers import relay_result
from helpers import releases

CONFIG_CRASH = {"reason": "relay/bad_config", "detail": "unknown key 'gamma' in config.toml"}


@pytest.fixture
def db(tmp_path):
    from helpers import make_db
    clock.set_fake(1_900_000_000.0)
    d = make_db(tmp_path / "oarbank.sqlite3")
    yield d
    clock.set_fake(None)
    d.conn.close()


def ok(db):
    v = invariants.check_all(db)
    assert not v, v
    return True


def study(db, n=1):
    return create_study(db, "t", [{"label": "c1", "params": {**PARAMS, "samples": 25}}], SCENES[:n],
                        {"label": "base", "params": PARAMS})


def claim(db, node, job_id):
    gs = core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY})["grants"]
    return [g for g in gs if g["job_id"] == job_id]


def first_eval(db):
    return db.one("SELECT job_id FROM jobs WHERE module='relay' AND kind='eval' ORDER BY job_id LIMIT 1")["job_id"]


def fail(db, node, job_id, **body):
    """One attempt of the job on `node`, failed as the agent reports it; the job after it (past any backoff)."""
    g = claim(db, node, job_id)[0]
    core.fail(db, fresh(db, node), g["attempt_id"], {"reason": "exit_nonzero", "exit_code": 1, **body})
    clock.advance(700)
    return db.one("SELECT * FROM jobs WHERE job_id=?", (job_id,))


def breaker(db, node):
    return fresh(db, node)["breaker_failures"]


@pytest.mark.parametrize("declared", [
    {"fault": "job", "failure": CONFIG_CRASH},                                   # fault: job (exit 2, or failure.fault)
    {"retryable": False, "failure": {**CONFIG_CRASH, "retryable": False}},       # retryable: false, no fault
    {"fault": "job", "retryable": False, "failure": {**CONFIG_CRASH, "retryable": False}},
])
def test_a_job_that_can_never_succeed_ends_failed_at_once(db, declared):
    """The live gap: a module's deterministic config crash (identical on every host) was retried on other machines until
    the stage's retry was spent, then quarantined. Now the first such failure ends the job: failed, not quarantined,
    never granted again, and never charged to the node's breaker."""
    n1, n2, n3 = certified_fleet(db, ("n1", "n2", "n3"))
    study(db)
    jid = first_eval(db)
    j = fail(db, n1, jid, **declared)
    assert (j["state"], j["exec_failures"]) == ("failed", 1)
    assert not claim(db, n2, jid) and not claim(db, n3, jid) and not claim(db, n1, jid)
    assert breaker(db, n1) == 0
    ev = db.one("SELECT reason FROM events WHERE kind='job_failed' AND job_id=?", (jid,))
    assert ev and "relay/bad_config" in ev["reason"]
    assert not db.one("SELECT 1 FROM events WHERE kind='job_quarantined' AND job_id=?", (jid,))
    assert ok(db)


def test_an_older_agent_reports_the_reason_only_in_its_stderr_tail(db):
    """An agent that predates `failure` heads its stderr tail with `"<reason>": <detail>`: the reason is still kept."""
    n1, _ = certified_fleet(db, ("n1", "n2"))
    study(db)
    jid = first_eval(db)
    j = fail(db, n1, jid, fault="job", stderr_tail='"relay/bad_config": "unknown key \'gamma\'"\nTraceback ...\n')
    assert j["state"] == "failed"
    f = detail.job(db, jid)["failure"]
    assert (f["code"], f["detail"], f["fault"], f["final"]) == ("relay/bad_config", "unknown key 'gamma'", "job", True)


def test_transient_failures_are_unchanged(db):
    """fault: transient, or retryable: true with no fault, is no failure: released, retried, nothing spent."""
    n1, _ = certified_fleet(db, ("n1", "n2"))
    study(db)
    jid = first_eval(db)
    for body in ({"fault": "transient"}, {"retryable": True, "failure": {"reason": "relay/busy", "retryable": True}}):
        j = fail(db, n1, jid, **body)
        assert (j["state"], j["exec_failures"]) == ("pending", 0)
    assert breaker(db, n1) == 0 and not db.one("SELECT failure_json FROM jobs WHERE job_id=?", (jid,))["failure_json"]
    assert ok(db)


def test_host_faults_are_unchanged(db):
    """fault: host re-doctors the node and sends the job elsewhere without spending its retries."""
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db)
    jid = first_eval(db)
    j = fail(db, n1, jid, fault="host", failure={"reason": "relay/no_tool", "detail": "tool missing"})
    assert (j["state"], j["exec_failures"]) == ("pending", 0)
    assert fresh(db, n1)["want_doctor"] == 1
    assert claim(db, n2, jid)
    assert ok(db)


def test_retryable_job_faults_and_undeclared_failures_keep_the_stages_retry(db):
    """fault: job with retryable: true, the agent's own job attributions (an OOM kill) and a plain crash with no
    failure.json all spend one retry and leave the job pending, as before."""
    n1, n2, n3 = certified_fleet(db, ("n1", "n2", "n3"))
    study(db)
    jid = first_eval(db)
    j = fail(db, n1, jid, fault="job", retryable=True, failure={"reason": "relay/flaky", "retryable": True})
    assert (j["state"], j["exec_failures"]) == ("pending", 1)
    j = fail(db, n2, jid, reason="oom", fault="job")
    assert (j["state"], j["exec_failures"]) == ("pending", 2)
    assert breaker(db, n1) == 0
    j = fail(db, n3, jid)                                    # no failure.json: the breaker rules, as before
    assert j["state"] == "quarantined" and j["exec_failures"] == 3
    assert ok(db)


def test_the_reason_and_detail_are_visible_in_the_job_explain_and_campaign_views(db):
    n1, _ = certified_fleet(db, ("n1", "n2"))
    cid = study(db, 2)
    jid = first_eval(db)
    fail(db, n1, jid, fault="job", failure=CONFIG_CRASH)
    f = detail.job(db, jid)["failure"]
    assert f["code"] == "relay/bad_config" and f["detail"] == CONFIG_CRASH["detail"]
    assert (f["fault"], f["final"], f["reason"], f["node_id"]) == ("job", True, "exit_nonzero", n1["node_id"])
    doc = explain.job_doc(db, jid)
    assert doc.verdict == "failed" and doc.headline.code == "relay/bad_config"
    assert "not retried" in doc.headline.text and CONFIG_CRASH["detail"] in doc.headline.text
    s = campaigns.summary(db, cid)
    assert s["jobs"]["f"] == 1
    assert s["failures"] == [{"state": "failed", "code": "relay/bad_config", "jobs": 1, "job_id": jid,
                              "detail": CONFIG_CRASH["detail"]}]
    import io
    from contextlib import redirect_stdout
    from oarbank.cli import main as cli
    out = io.StringIO()
    with redirect_stdout(out):
        cli.print_job({**detail.job(db, jid), "explain": doc.model_dump(mode="json")})
    assert "failure: relay/bad_config (fault job) - not retried" in out.getvalue()
    assert CONFIG_CRASH["detail"] in out.getvalue()


def test_the_campaign_tick_and_host_jobs_query_carry_the_failure(db, monkeypatch):
    """The module sees why a job failed, not only that it did: campaign.tick's job rows and host.jobs.query."""
    n1, _ = certified_fleet(db, ("n1", "n2"))
    cid = study(db, 2)
    jid = first_eval(db)
    fail(db, n1, jid, fault="job", failure=CONFIG_CRASH)
    seen = {}
    monkeypatch.setattr(modcalls, "tick", lambda db_, name, campaign, jobs, now: seen.setdefault("jobs", jobs) and {})
    campaigns.tick_one(db, db.one("SELECT * FROM campaigns WHERE campaign_id=?", (cid,)))
    rows = {j["job_id"]: j for j in seen["jobs"]}
    f = rows[jid]["failure"]
    assert rows[jid]["state"] == "failed"
    assert (f["code"], f["detail"], f["fault"], f["retryable"], f["final"]) == \
        ("relay/bad_config", CONFIG_CRASH["detail"], "job", None, True)
    assert all("failure" not in j for k, j in rows.items() if k != jid)       # only failed / quarantined jobs carry one
    q = {j["job_id"]: j for j in modcalls.host_callbacks(db)["host.jobs.query"]("relay", {"campaign_id": cid})["jobs"]}
    assert q[jid]["failure"]["code"] == "relay/bad_config" and "failure" not in q[next(k for k in q if k != jid)]


def test_a_late_result_does_not_revive_a_failed_job_and_retry_clears_its_failure(db):
    n1, n2 = certified_fleet(db, ("n1", "n2"))
    study(db)
    jid = first_eval(db)
    g = claim(db, n1, jid)[0]
    core.fail(db, fresh(db, n1), g["attempt_id"], {"reason": "exit_nonzero", "fault": "job", "failure": CONFIG_CRASH})
    r = core.complete(db, fresh(db, n1), g["attempt_id"], relay_result())
    assert not r.get("canonical")
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (jid,))["state"] == "failed"
    core.retry_job(db, jid, "test")
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (jid,))
    assert (j["state"], j["exec_failures"], j["failure_json"]) == ("pending", 0, None)
    assert claim(db, n2, jid)
    assert ok(db)


# ---------------------------------------------------------------- golden jobs (certification)
def goldens(db, name="mini"):
    """A node whose doctor passed, with its golden jobs granted (it is certifying relay)."""
    node = enrolled_node(db, name)[1]
    core.hello(db, node, {"release_id": releases.assigned(db, fresh(db, node)), "facts": FACTS, "live_attempts": [],
                          "ready_datasets": READY})
    core.heartbeat(db, fresh(db, node), {"doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY,
                                         "capacity": {"pools": {"scorer": 4}}})
    gs = core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]
    return node, [g for g in gs if g["module"] == "relay" and g["kind"] == "golden"]


def relay_state(db, node):
    return core.node_modules(fresh(db, node)).get("relay", {})


def test_a_golden_that_can_never_succeed_fails_certification_at_once(db):
    """A module cannot dodge its goldens by declaring them failed jobs: a golden whose runner says it can never succeed
    fails the module's certification on that node at once (golden_failed, with its alert), instead of ending quietly."""
    node, gs = goldens(db)
    assert gs and relay_state(db, node)["state"] == "certifying"
    core.fail(db, fresh(db, node), gs[0]["attempt_id"], {"reason": "exit_nonzero", "fault": "job", "failure": CONFIG_CRASH})
    st = relay_state(db, node)
    assert st["state"] == "golden_failed" and "relay/bad_config" in st["reason"]
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (gs[0]["job_id"],))["state"] == "failed"
    assert db.one("SELECT 1 FROM alerts WHERE rule='golden_failed:relay' AND state IN ('open','pending')")
    assert breaker(db, node) == 0
    assert ok(db)


def test_transient_and_undeclared_golden_failures_are_unchanged(db):
    node, gs = goldens(db)
    core.fail(db, fresh(db, node), gs[0]["attempt_id"], {"reason": "exit_nonzero", "fault": "transient"})
    assert relay_state(db, node)["state"] == "certifying" and not relay_state(db, node).get("golden_failures")
    clock.advance(700)
    g = [x for x in core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]
         if x["job_id"] == gs[0]["job_id"]][0]
    core.fail(db, fresh(db, node), g["attempt_id"], {"reason": "exit_nonzero"})
    st = relay_state(db, node)
    assert st["state"] == "certifying" and st["golden_failures"] == 1
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (gs[0]["job_id"],))["state"] == "pending"
    for x in core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]:
        core.complete(db, fresh(db, node), x["attempt_id"], golden_result(x, db))
    assert ok(db)
