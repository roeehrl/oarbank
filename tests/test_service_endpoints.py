"""Service endpoints on the coordinator (docs/design/service-endpoints.md): the release entry carries `endpoint` and `gpu`
only when set, a module with an endpoint service runs only where the agent hands out endpoints, a job reserving a pool of
a GPU service is a GPU job, and the kill switch reaches the agents' services."""
import copy
import dataclasses
import json
import tomllib
import uuid
from pathlib import Path

import pytest

from oarbank.coordinator import core, modcalls, modsandbox, modstore, ops, platforms, releases
from oarbank_sdk import manifest as mf

from helpers import FACTS, RELAY_DIR, SEATBELT, TOY_DIR, enrolled_node, fresh, make_db

MODELSERVER = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "modelserver"


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3", modules=(TOY_DIR, RELAY_DIR, MODELSERVER))


def gpu_manifest() -> mf.Manifest:
    d = tomllib.loads((MODELSERVER / "oarbank-module.toml").read_text(encoding="utf-8"))
    d = copy.deepcopy(d)
    d["services"][0]["gpu"] = {"use": "shared", "apis_any": ["metal"]}
    d["sandbox"] = {"devices": {"gpu": "compute"}}
    return mf.Manifest.model_validate(d)


def test_the_release_entry_carries_endpoint_and_gpu_only_when_set(db, tmp_path):
    r = modstore.record(db, "modelserver", "0.1.0")
    svc = releases.module_entry("modelserver", "0.1.0", r["content_digest"], r["path"])["services"][0]
    assert svc["endpoint"] is True and "gpu" not in svc
    assert svc["provides"] == {"capabilities": [], "pools": ["model"]}
    relay = modstore.record(db, "relay", modstore.channel(db, "relay")["current"])
    for s in releases.module_entry("relay", relay["version"], relay["content_digest"], relay["path"])["services"]:
        assert "endpoint" not in s and "gpu" not in s                 # other entries keep their bytes
    src = tmp_path / "gpu"
    src.mkdir()
    for f in MODELSERVER.rglob("*"):
        if f.is_file() and "__pycache__" not in f.parts:
            (src / f.relative_to(MODELSERVER)).parent.mkdir(parents=True, exist_ok=True)
            (src / f.relative_to(MODELSERVER)).write_bytes(f.read_bytes())
    toml = (src / "oarbank-module.toml").read_text(encoding="utf-8")
    toml = toml.replace("yieldable = true", 'yieldable = true\ngpu = { use = "shared", apis_any = ["metal"] }')
    (src / "oarbank-module.toml").write_text(toml + '\n[sandbox]\ndevices = { gpu = "compute" }\n', encoding="utf-8")
    svc = releases.module_entry("modelserver", "0.1.0", "d", src)["services"][0]
    assert svc["gpu"] == {"use": "shared", "apis_any": ["metal"]}


def test_a_module_with_an_endpoint_service_runs_only_where_the_agent_hands_out_endpoints(db, monkeypatch):
    monkeypatch.setattr(modsandbox, "REQUIRE_SANDBOXED_AGENTS", True)
    man = modcalls.info("modelserver").manifest
    assert platforms.sandbox_gaps(man, FACTS) == ["endpoints"]
    assert platforms.sandbox_gaps(modcalls.info("toy").manifest, FACTS) == []        # no endpoint service: no need
    with_endpoints = {**FACTS, "sandbox": {"backend": "seatbelt", "enforcement": {**SEATBELT, "endpoints": "enforced"}}}
    assert platforms.sandbox_gaps(man, with_endpoints) == []
    _, old = enrolled_node(db, "old", facts=FACTS)
    _, new = enrolled_node(db, "new", facts=with_endpoints)
    assert modsandbox.node_exclusions(db, fresh(db, old), {"modelserver", "toy"}) == {"modelserver": "CAPABILITY_NOT_ENFORCED"}
    assert modsandbox.node_exclusions(db, fresh(db, new), {"modelserver", "toy"}) == {}


def test_a_job_reserving_a_gpu_services_pool_is_a_gpu_job(db, monkeypatch):
    assert not modcalls.job_uses_gpu("modelserver", {"cpu": 1, "pools": {"model": 1}}, "darwin-arm64")
    info = modcalls.info("modelserver")
    monkeypatch.setitem(modcalls.CATALOG, "modelserver", dataclasses.replace(info, manifest=gpu_manifest()))
    assert modcalls.job_uses_gpu("modelserver", {"cpu": 1, "pools": {"model": 1}}, "darwin-arm64")
    assert not modcalls.job_uses_gpu("modelserver", {"cpu": 1}, "darwin-arm64")          # no reservation: not a GPU job


def test_the_kill_switch_reaches_the_agents_services(db):
    _, n = enrolled_node(db, "mini")
    assert core._node_directives(db, fresh(db, n))["modules_disabled"] == []
    ops.execute(db, ops.OpRequest(op="modules.disable", actor="test", target="modelserver", reason="bad model",
                                  idempotency_key=uuid.uuid4().hex))
    assert core._node_directives(db, fresh(db, n))["modules_disabled"] == ["modelserver"]


def test_oarbank_fleet_names_the_services_protection_stopped(monkeypatch, capsys):
    from oarbank.cli import main as cli
    node = {"hostname": "mini", "node_id": "n_1", "lifecycle": "ready", "desired_state": "active", "online": True, "live": 0,
            "cap": {}, "limits": {}, "mods": {}, "tel": {"guard": "hard", "services_held": {"modelserver/model": "preempt_memory"}}}
    monkeypatch.setattr(cli, "api", lambda *a, **k: {"nodes": [node], "enrollments": [], "campaigns": [], "alerts": []})
    cli.cmd_fleet(None)
    assert "STOPPED modelserver/model (preempt_memory)" in capsys.readouterr().out
