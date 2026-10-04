"""GPU placement by API (docs/design/gpu-placement.md, PLAN D38): a job's stage needs the GPU APIs its runner (with the
node's platform variant) and the GPU services it reserves name, checked against the APIs the node's doctor reports on
the host and in containers, by claim, explain, the module exclusions, capacity binding, the stranded check, replicas
and failure anti-affinity. A fleet of mini (darwin-arm64), box (linux-amd64) and arm (linux-arm64) runs the relay
fixture with its manifest patched."""
import dataclasses
import json

import pytest

from oarbank.coordinator import clock, core, explain, invariants, modcalls, modsandbox, placement
from oarbank_sdk import manifest as mf

from helpers import PARAMS, READY, SCENES, certify, create_study, enrolled_node, facts_for, fresh, make_db, relay_result

BODY = {"free_cpu": 8, "free_mem_gb": 64, "ready_datasets": READY}
METAL = {"host": ["metal", "opencl"], "containers": ["vulkan"]}
CUDA = {"host": ["cuda", "opencl", "vulkan"], "containers": ["cuda"]}
NONE = {"host": [], "containers": []}


@pytest.fixture
def db(tmp_path):
    clock.set_fake(1_900_000_000.0)
    d = make_db(tmp_path / "oarbank.sqlite3")
    yield d
    clock.set_fake(None)
    d.conn.close()


@pytest.fixture
def fleet(db):
    """mini (darwin-arm64, Metal), box (linux-amd64, CUDA), arm (linux-arm64, no GPU API), each certified and reporting
    its GPU APIs in its doctor report."""
    out = {"mini": certify(db, enrolled_node(db, "mini")[1]),
           "box": certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1]),
           "arm": certify(db, enrolled_node(db, "arm", facts=facts_for("linux-arm64", os_version="6.8"))[1])}
    for name, apis, slots in (("mini", METAL, 4), ("box", CUDA, 16), ("arm", NONE, 8)):
        report(db, out[name], apis, slots=slots)
    return out


def report(db, node, apis, slots=8, pools=None):
    """A heartbeat whose doctor report names the node's GPU APIs (docs/protocol.md "Doctor")."""
    doc = {"modules": {"relay": {"health": "healthy", "checks": []}, "toy": {"health": "healthy", "checks": []}},
           "capabilities": [], "gpu_apis": {**apis, "evidence": {}}}
    core.heartbeat(db, fresh(db, node), {"doctor": doc, "attempts": [], "ready_datasets": READY,
                                         "capacity": {"pools": pools or {"scorer": 4}, "cpu_slots": slots}})


def relay_with(monkeypatch, **upd):
    info = modcalls.info("relay")
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=info.manifest.model_copy(update=upd)))


def runner_gpu(monkeypatch, variants=None, **gpu):
    """relay's runner with `gpu` (and runner variants {key: gpu})."""
    run = modcalls.info("relay").manifest.runner
    relay_with(monkeypatch, runner=run.model_copy(update={
        "gpu": mf.GPUNeed(**gpu), "variants": {k: mf.RunnerVariant(gpu=mf.GPUNeed(**v)) for k, v in (variants or {}).items()}}))


def study(db, datasets=SCENES[:2], configs=1, **kw):
    return create_study(db, "p", [{"label": f"c{i}", "params": {**PARAMS, "samples": 20 + i}} for i in range(configs)],
                        list(datasets), {"label": "base", "params": PARAMS}, **kw)


def grants(db, node, free=8, body=None):
    return [g for g in core.claim(db, fresh(db, node), {**(body or BODY), "free_cpu": free})["grants"] if g["module"] == "relay"]


def rows(db, job_id, node):
    doc = explain.job_doc(db, job_id, bodies={node["node_id"]: BODY}, now=clock.now())
    return [r for m in doc.matrix if m.node == node["hostname"] for r in m.results if r.outcome != "pass"]


def codes(db, job_id, node):
    return {r.code for r in rows(db, job_id, node)}


def pending(db, sid):
    return db.q("SELECT * FROM jobs WHERE campaign_id=? AND state='pending' ORDER BY job_id", (sid,))


def ok(db):
    v = invariants.check_all(db)
    assert not v, v
    return True


def test_a_stage_needing_cuda_never_lands_on_a_mac_and_explain_says_why(db, fleet, monkeypatch):
    runner_gpu(monkeypatch, use="shared", apis_any=["cuda"])
    sid = study(db)
    jobs = pending(db, sid)
    j = jobs[0]
    assert not grants(db, fleet["mini"]) and not grants(db, fleet["arm"])
    why = {r.code: r for r in rows(db, j["job_id"], fleet["mini"])}
    assert set(why) >= {"GPU_API_MISSING"}
    # the module is excluded on the Mac, in the module's own words, and the stage's need is named with the node's list
    module_row = next(r for r in rows(db, j["job_id"], fleet["mini"]) if r.predicate.startswith("module_runs_here"))
    assert (module_row.code, module_row.observed) == ("GPU_API_MISSING", "its runner needs cuda on the host; this node "
                                                                         "provides metal, opencl")
    api_row = next(r for r in rows(db, j["job_id"], fleet["mini"]) if r.predicate == "gpu apis")
    assert api_row.observed == {"host": ["metal", "opencl"], "containers": ["vulkan"]}
    assert api_row.required == ["cuda on the host (runner)"]
    assert modsandbox.node_exclusions(db, fresh(db, fleet["mini"]), {"relay", "toy"}) == {"relay": "GPU_API_MISSING"}
    assert "GPU_API_MISSING" not in codes(db, j["job_id"], fleet["box"])
    assert len(grants(db, fleet["box"])) == len(jobs)
    assert ok(db)


def test_a_stage_needing_metal_or_vulkan_lands_on_a_mac(db, fleet, monkeypatch):
    runner_gpu(monkeypatch, use="shared", apis_any=["metal", "vulkan"])
    sid = study(db, configs=2)
    assert len(grants(db, fleet["mini"], free=1)) == 1                   # Metal
    assert len(grants(db, fleet["box"], free=1)) == 1                    # Vulkan on the host
    assert not grants(db, fleet["arm"])
    assert "GPU_API_MISSING" in codes(db, pending(db, sid)[0]["job_id"], fleet["arm"])
    report(db, fleet["arm"], {"host": ["vulkan"], "containers": []})     # a driver installed, the doctor run again
    assert grants(db, fleet["arm"], free=1)
    assert ok(db)


def test_each_node_is_held_to_its_own_platforms_variant(db, fleet, monkeypatch):
    """CUDA everywhere but macOS, which needs Metal; linux-arm64 has a variant without a GPU at all."""
    runner_gpu(monkeypatch, use="shared", apis_any=["cuda"],
               variants={"darwin": {"use": "shared", "apis_any": ["metal"]}, "linux-arm64": {"use": "none"}})
    assert modcalls.stage_gpu_apis("relay", "eval")["darwin-arm64"] == [{"apis": ["metal"], "where": "host", "source": "runner"}]
    assert modcalls.stage_gpu_apis("relay", "eval")["linux-arm64"] == []
    study(db, SCENES[:3], configs=2)
    assert grants(db, fleet["mini"], free=1) and grants(db, fleet["box"], free=1) and grants(db, fleet["arm"], free=1)
    report(db, fleet["mini"], {"host": ["opencl"], "containers": []})    # no Metal: macOS no longer qualifies
    assert not grants(db, fleet["mini"])
    assert ok(db)


def test_a_container_gpu_stage_is_held_to_the_containers_apis(db, fleet, monkeypatch):
    """The eval stage runs GPU containers needing Vulkan: the Mac's krunkit VM gives containers Vulkan, box's CDI spec only
    CUDA. The runner's container need binds only stages that reserve the gpu pool, and never excludes the module."""
    runner_gpu(monkeypatch, use="exclusive", in_container=True, apis_any=["vulkan"])
    info = modcalls.info("relay")
    relay_with(monkeypatch, stages=[s.model_copy(update={"requires": s.requires.model_copy(update={
        "pools": {"containers": 1, "gpu": 1}, "needs_pools": []})}) if s.name == "eval" else s for s in info.manifest.stages])
    pools = {"scorer": 4, "containers": 2, "gpu": 1}
    for name, apis in (("mini", METAL), ("box", CUDA)):
        report(db, fleet[name], apis, pools=pools)
    assert modcalls.stage_gpu_apis("relay", "sync")["linux-amd64"] == []
    sid = study(db, configs=2)
    j = pending(db, sid)[0]
    api_row = next(r for r in rows(db, j["job_id"], fleet["box"]) if r.code == "GPU_API_MISSING")
    assert api_row.required == ["vulkan in containers (runner)"]
    assert "relay" not in modsandbox.node_exclusions(db, fresh(db, fleet["box"]), {"relay"})
    assert not grants(db, fleet["box"])
    assert len(grants(db, fleet["mini"], free=1)) == 1
    assert ok(db)


def test_a_gpu_service_holds_the_stages_that_reserve_its_pool_to_its_apis(db, fleet, monkeypatch):
    """The scorer service names CUDA: eval (which reserves its pool) runs only where the host provides it, even on a node
    whose capacity still reports the pool."""
    info = modcalls.info("relay")
    relay_with(monkeypatch, services=[s.model_copy(update={"gpu": mf.ServiceGPU(use="shared", apis_any=["cuda"])})
                                      for s in info.manifest.services],
               stages=[s.model_copy(update={"requires": s.requires.model_copy(update={"pools": {"scorer": 1}, "needs_pools": []})})
                       if s.name == "eval" else s for s in info.manifest.stages])
    sid = study(db)
    j = pending(db, sid)[0]
    api_row = next(r for r in rows(db, j["job_id"], fleet["mini"]) if r.code == "GPU_API_MISSING")
    assert api_row.required == ["cuda on the host (service scorer)"]
    assert "relay" not in modsandbox.node_exclusions(db, fresh(db, fleet["mini"]), {"relay"})   # other stages still run
    assert not grants(db, fleet["mini"]) and grants(db, fleet["box"], free=1)
    assert ok(db)


def test_capacity_binds_a_unit_only_where_a_node_has_the_api_and_strands_when_it_goes(db, fleet, monkeypatch):
    """box has the most free CPU, but only arm reports CUDA: the campaign binds by capacity to linux-arm64, and once arm
    stops reporting it the unit's class has no node for its work."""
    runner_gpu(monkeypatch, use="shared", apis_any=["cuda"])
    report(db, fleet["box"], NONE, slots=16)
    report(db, fleet["arm"], CUDA)
    sid = study(db, SCENES[:1], placement={"mix": "same-platform"})
    b = placement.binding(db, f"c:{sid}")
    assert (b["class"], b["state"], b["source"]) == ("linux-arm64", "soft", "capacity")
    assert placement.class_has_node(db, b)
    assert not grants(db, fleet["box"]) and grants(db, fleet["arm"], free=1)
    report(db, fleet["arm"], NONE)
    assert not placement.class_has_node(db, placement.binding(db, f"c:{sid}"))
    assert ok(db)


def test_a_replica_needs_another_node_with_the_api(db, fleet, monkeypatch):
    """Adaptive replication queues a replica only when another node could run it: with CUDA on box alone nobody could;
    once arm reports it too, the replica is queued."""
    runner_gpu(monkeypatch, use="shared", apis_any=["cuda"])
    db.set_setting("replica_rate", 1.0)
    sid = study(db, SCENES[:2])
    first, second = grants(db, fleet["box"], free=2)
    assert core.complete(db, fresh(db, fleet["box"]), first["attempt_id"], relay_result(score="0.850000", image="A"))["canonical"]
    assert not db.q("SELECT 1 FROM jobs WHERE kind='replica'")
    report(db, fleet["arm"], CUDA)
    assert core.complete(db, fresh(db, fleet["box"]), second["attempt_id"], relay_result(score="0.850000", image="B"))["canonical"]
    assert db.one("SELECT json_extract(dispute_json,'$.replica_of') o FROM jobs WHERE kind='replica'")["o"] == second["job_id"]
    assert sid and ok(db)


def test_a_node_that_failed_a_job_retries_it_unless_another_node_has_the_api(db, fleet, monkeypatch):
    runner_gpu(monkeypatch, use="shared", apis_any=["cuda"])
    study(db, SCENES[:1])
    g = grants(db, fleet["box"], free=1)[0]
    core.fail(db, fresh(db, fleet["box"]), g["attempt_id"], {"reason": "relay/crash", "exit_code": 3, "fault": "job"})
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (g["job_id"],))
    assert not core._other_node_can_take(db, j, fleet["box"]["node_id"])    # nobody else provides CUDA
    report(db, fleet["arm"], CUDA)
    assert core._other_node_can_take(db, j, fleet["box"]["node_id"])
    assert ok(db)


def test_oarbank_fleet_shows_each_nodes_gpu_apis(monkeypatch, capsys):
    from oarbank.cli import main as cli
    node = {"hostname": "mini", "node_id": "n_1", "lifecycle": "ready", "desired_state": "active", "online": True, "live": 0,
            "cap": {}, "limits": {}, "mods": {}, "tel": {}, "doctor": {"gpu_apis": METAL}}
    bare = {**node, "hostname": "new", "doctor": None}
    monkeypatch.setattr(cli, "api", lambda *a, **k: {"nodes": [node, bare], "enrollments": [], "campaigns": [], "alerts": []})
    cli.cmd_fleet(None)
    out = capsys.readouterr().out.splitlines()
    assert "gpu metal,opencl containers vulkan" in out[0] and "gpu - containers -" in out[1]


def test_golden_lists_see_the_nodes_gpu_apis(db, fleet):
    assert modcalls.node_class(fresh(db, fleet["mini"]), "relay")["gpu_apis"] == METAL
    assert modcalls.node_class(None, "relay")["gpu_apis"] == NONE


def test_a_node_without_a_doctor_report_provides_no_api(db, monkeypatch):
    runner_gpu(monkeypatch, use="shared", apis_any=["cuda"])
    n = certify(db, enrolled_node(db, "new", facts=facts_for("linux-amd64", os_version="6.8"))[1])
    db.x("UPDATE nodes SET doctor_json=NULL WHERE node_id=?", (n["node_id"],))
    assert modsandbox.node_exclusions(db, fresh(db, n), {"relay"}) == {"relay": "GPU_API_MISSING"}
    assert json.loads(fresh(db, n)["facts_json"])["gpus"][0].keys() == {"vendor", "model", "unified"}
