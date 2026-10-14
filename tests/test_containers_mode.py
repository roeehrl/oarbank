"""The `containers` setting (containers.py; docs/design/macos-containers.md, "When the runtime runs"): off keeps container
work off a node and certifies its other stages only; on_demand lets a stopped runtime be placed against its startable
pool and wakes it, fleet-aware, when container work waits; the node's line shows its VM size configured and running."""
import pytest

from oarbank.contracts import reason_codes as RC
from oarbank.coordinator import containers, core, explain, modcalls, modsandbox, modstore, readiness, releases
from oarbank.coordinator.settings import registry as R
from oarbank.coordinator.settings.apply import node_document
from oarbank.coordinator.settings import resolve as V

from helpers import FIXTURES, fresh, install, make_db, run_op, set_fleet, set_node, settings_apply
from test_secrets import DOCTOR, claim, node

SET = "registry.example.org/bench/tasks"


@pytest.fixture
def db(tmp_path):
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    r = install(d, FIXTURES / "vault", enable=False)
    modsandbox.approve(d, "vault", r["version"], "test", None)
    modstore.enable(d, "vault", r["version"])
    modcalls.use(d)
    releases.sync(d)
    return d


def certify(db, n):
    """Run the node's golden jobs (vault's are its eval stage: no containers) and pass them."""
    for g in claim(db, n):
        assert g["kind"] == "golden", g
        core.complete(db, fresh(db, n), g["attempt_id"], {"result": {"envelope": 1, "schema": "vault/result@1",
                      "module_version": "1.0.0", "protocol": 1, "payload": {"digest": "vault-golden-1"}}})
    assert core.node_modules(fresh(db, n))["vault"]["state"] == "certified"


def heartbeat(db, n, pools=None, runtime=None):
    body = {"doctor": DOCTOR, "attempts": [], "ready_datasets": [], "capacity": {"pools": pools or {}}}
    if runtime is not None:
        body["containers"] = runtime
    return core.heartbeat(db, fresh(db, n), body)


def task_job(db, k: int = 1) -> int:
    """Queue `k` container jobs (vault's task stage reserves one containers token each), in a campaign of their own."""
    n = db.one("SELECT COUNT(*) n FROM campaigns")["n"]
    run_op(db, "mod.vault.queue_tasks", params={"images": [f"{SET}/t{i}@sha256:" + f"{i + 1:064x}" for i in range(k)],
                                               "campaign_id": f"c_tasks_{n}"})
    return db.one("SELECT job_id FROM jobs WHERE stage='task' ORDER BY job_id DESC")["job_id"]


def codes(db, job_id) -> list[str]:
    return [s.code for s in explain.explain(db, "job", str(job_id)).summary]


STOPPED = {"mode": "on_demand", "state": "stopped", "startable": {"containers": 2}, "start_s": 45, "idle_stop_s": 600,
           "vm": {"mem_gb": 6.5, "cpus": 6}}


def test_the_settings_are_declared_sent_to_agents_and_off_is_the_strictest(db):
    d = R.REGISTRY["containers"]
    assert d.default == "always" and d.schema["enum"] == ["always", "on_demand", "off"] and d.wire == "policy"
    assert d.managed and d.tighten_dir == "higher" and R.tighter(d, "always", "off") == "off"
    assert R.tighter(d, "on_demand", "always") == "on_demand"
    assert "on_demand (recommended)" in d.help
    i = R.REGISTRY["containers_idle_stop_s"]
    assert (i.default, i.schema["minimum"], i.unit, i.section) == (600, 60, "s", "containers")
    assert "containers" in R.NODE_SECTIONS
    with pytest.raises(R.SettingError, match="not one of"):
        R.check("containers", "sometimes")
    with pytest.raises(R.SettingError, match="below 60"):
        R.check("containers_idle_stop_s", 10)
    n = node(db)
    set_node(db, n, "containers", "on_demand")
    set_node(db, n, "containers_idle_stop_s", 300)
    doc = node_document(V.snapshot(db), fresh(db, n))
    assert (doc["policy"]["containers"], doc["policy"]["containers_idle_stop_s"]) == ("on_demand", 300)
    assert containers.mode(fresh(db, n)) == "on_demand"


def test_containers_off_keeps_container_work_off_the_node_with_the_fix(db):
    n = node(db)                                              # certified, its runtime offers containers 2
    job = task_job(db)
    set_node(db, n, "containers", "off")
    heartbeat(db, n, pools={"containers": 2})                 # an agent that has not applied it yet still reports the pool
    certify(db, n)                                            # certified again: its goldens differ now
    assert core._node_pools(fresh(db, n))["containers"] == 0
    assert not core._pools_fit(fresh(db, n), {"pools": {"containers": 1}})
    assert claim(db, n) == []
    assert "CONTAINERS_DISABLED" in codes(db, job)
    doc = explain.explain(db, "job", str(job))
    assert "settings.apply" in [r.op for r in doc.remedies]
    assert "containers = off" in RC.REGISTRY["CONTAINERS_DISABLED"].template
    # the module's checklist says why, and that its other stages still certify
    run = next(i for i in readiness.module(db, "vault")["steps"] if i["id"] == "nodes")
    task = next(i for i in run["items"] if i.get("stage") == "task")
    assert any("containers are off on this node" in r for g in task["groups"] for r in g["reasons"])
    # golden.list sees no containers pool: such a node gets only its goldens that need none
    assert "containers" not in modcalls.node_class(fresh(db, n), "vault")["pools"]


def test_turning_containers_off_or_back_on_certifies_the_node_again(db):
    n = node(db)
    assert not core.node_modules(fresh(db, n))["vault"].get("containers_off")
    set_node(db, n, "containers", "off")
    heartbeat(db, n)
    st = core.node_modules(fresh(db, n))["vault"]
    assert st["state"] == "certifying"
    assert db.one("SELECT reason FROM events WHERE kind='recertify' ORDER BY event_id DESC")["reason"] == "vault: containers"
    certify(db, n)
    st = core.node_modules(fresh(db, n))["vault"]
    assert st["state"] == "certified" and st["containers_off"] is True
    heartbeat(db, n)
    assert core.node_modules(fresh(db, n))["vault"]["state"] == "certified", "unchanged: not again"
    set_node(db, n, "containers", "on_demand")
    heartbeat(db, n)
    assert core.node_modules(fresh(db, n))["vault"]["state"] == "certifying"


def test_a_stopped_on_demand_runtime_is_placed_against_its_startable_pool_and_woken(db):
    n = node(db)
    set_node(db, n, "containers", "on_demand")
    heartbeat(db, n, runtime=STOPPED)
    job = task_job(db)
    assert core.node_modules(fresh(db, n))["vault"]["state"] == "certified", "always to on_demand: the same goldens"
    nd = fresh(db, n)
    assert core._node_pools(nd).get("containers", 0) == 0 and core._node_pools_possible(nd)["containers"] == 2
    assert core._pools_fit(nd, {"pools": {"containers": 1}}), "it could run it: retries and replicas count it"
    assert modcalls.node_class(nd, "vault")["pools"]["containers"] == 1, "its goldens may run containers"
    assert claim(db, n) == [], "nothing is granted to a stopped runtime"
    assert "CONTAINERS_STOPPED" in codes(db, job)
    text = " ".join(s.detail.get("text", "") for s in explain.explain(db, "job", str(job)).summary)
    assert "in about 45 s" in text
    d = heartbeat(db, n, runtime=STOPPED)
    assert d["containers_wanted"] is True, "no other runtime has room: start"
    assert db.one("SELECT COUNT(*) n FROM events WHERE kind='containers_wake' AND node_id=?", (n["node_id"],))["n"] == 1
    # starting, then running: still wanted while the work waits; once the pool is there the job is granted
    assert heartbeat(db, n, runtime={**STOPPED, "state": "starting", "startable": {}})["containers_wanted"] is True
    heartbeat(db, n, pools={"containers": 2}, runtime={**STOPPED, "state": "running", "startable": {}})
    assert [g["job_id"] for g in claim(db, n)] == [job]
    assert heartbeat(db, n, pools={"containers": 2}, runtime={**STOPPED, "state": "running", "startable": {}})["containers_wanted"] is False


def test_one_waiting_job_wakes_one_stopped_runtime_not_every_one(db):
    a, b = node(db, "mini-a"), node(db, "mini-b")
    for n in (a, b):
        set_node(db, n, "containers", "on_demand")
        heartbeat(db, n, runtime=STOPPED)
    task_job(db)
    assert heartbeat(db, a, runtime=STOPPED)["containers_wanted"] is True
    assert heartbeat(db, b, runtime=STOPPED)["containers_wanted"] is False, "a's start covers it"
    task_job(db, 2)                                           # 3 tokens wanted, a brings 2
    assert heartbeat(db, b, runtime=STOPPED)["containers_wanted"] is True


def test_a_running_runtime_with_room_keeps_stopped_ones_stopped(db):
    a, b = node(db, "mini-a"), node(db, "mini-b")
    heartbeat(db, a, pools={"containers": 2}, runtime={"mode": "always", "state": "running", "startable": {}})
    set_node(db, b, "containers", "on_demand")
    heartbeat(db, b, runtime=STOPPED)
    task_job(db)
    assert heartbeat(db, b, runtime=STOPPED)["containers_wanted"] is False
    assert "containers_wanted" not in heartbeat(db, a, pools={"containers": 2})
    # a stopped node that could not start (missing prerequisites) is not woken
    set_node(db, a, "containers", "off")
    assert heartbeat(db, b, runtime={**STOPPED, "state": "missing", "startable": {}})["containers_wanted"] is False


def test_the_node_line_shows_the_mode_and_the_vm_size_configured_and_running(db):
    n = node(db)
    heartbeat(db, n, runtime={"mode": "always", "state": "running", "startable": {},
                              "vm": {"mem_gb": 2.0, "cpus": 6, "actual_mem_gb": 8.0, "actual_cpus": 6}})
    line = containers.line(fresh(db, n))
    assert line.startswith("containers = always · running · VM 2 GB, 6 CPUs (running at 8 GB, 6 CPUs")
    heartbeat(db, n, runtime={"mode": "always", "state": "running", "startable": {},
                              "vm": {"mem_gb": 2.0, "cpus": 6, "actual_mem_gb": 2.0, "actual_cpus": 6}})
    assert "(running at that size)" in containers.line(fresh(db, n))
    set_node(db, n, "containers", "on_demand")
    heartbeat(db, n, runtime=STOPPED)
    assert containers.line(fresh(db, n)) == ("containers = on_demand · stopped · VM 6.5 GB, 6 CPUs · starts when container "
                                             "work waits (about 45 s), 600 s idle stops it")
    from oarbank.coordinator import detail
    assert detail.node(db, n["node_id"], 0, lambda m: None)["containers_line"] == containers.line(fresh(db, n))


def test_a_fleet_value_reaches_every_node(db):
    a = node(db, "mini-a")
    set_fleet(db, "containers", "on_demand")
    assert containers.mode(fresh(db, a)) == "on_demand"
    settings_apply(db, {"scope": "node", "scope_id": a["node_id"], "key": "containers", "value": "off"})
    assert containers.mode(fresh(db, a)) == "off"
