"""Protection on the coordinator: config validation, the decision journal from heartbeats (S16), the memory-floor
admission check (S17) and service-based pool gating."""
import json
import time
from pathlib import Path

import pytest

from oarbank.coordinator import config as C, core, invariants

from helpers import certify, enrolled_node, fresh, make_db


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def test_protection_policy_is_validated(db):
    n = enrolled_node(db)[1]
    with pytest.raises(core.ApiError) as e:
        core.set_policy(db, n["node_id"], {"protection": {"schema": 1, "rule": [{"id": "x", "match": {}}]}}, "t")
    assert e.value.code == "bad_protection"
    core.set_policy(db, n["node_id"], {"protection": {"schema": 1, "node": {"mode": "fleet_first"}, "rule": []}}, "t")
    assert json.loads(fresh(db, n)["policy_json"])["protection"]["node"]["mode"] == "fleet_first"


def test_journal_ingestion_ack_and_s16(db):
    node = certify(db, enrolled_node(db)[1])
    aid = db.one("SELECT attempt_id FROM attempts WHERE node_id=? LIMIT 1", (node["node_id"],))["attempt_id"]
    rec = lambda seq, **k: {"t": time.time(), "seq": seq, "kind": "actuation", "reason": "preempt_memory", "pid": 4242,
                            "start_us": "1", **k}
    out = core.heartbeat(db, fresh(db, node), {"journal": [rec(1, attempt=aid), rec(2, attempt=aid)]})
    assert out["journal_ack"] == 2
    core.heartbeat(db, fresh(db, node), {"journal": [rec(2, attempt=aid)]})          # redelivery is idempotent
    assert db.one("SELECT COUNT(*) n FROM protection_decisions")["n"] == 2
    assert not invariants.s16_actuation_only_on_spawned(db)
    core.heartbeat(db, fresh(db, node), {"journal": [rec(3, attempt=999999)]})        # not one of its attempts
    assert invariants.s16_actuation_only_on_spawned(db)


def test_s17_flags_admission_under_a_memory_floor(db):
    node = certify(db, enrolled_node(db)[1])
    core.heartbeat(db, fresh(db, node), {"telemetry": {"guard": "soft"}, "capacity": {"admit": True}})
    assert invariants.s17_no_admission_under_memory_floor(db)
    core.heartbeat(db, fresh(db, node), {"telemetry": {"guard": "soft"}, "capacity": {"admit": False}})
    assert not invariants.s17_no_admission_under_memory_floor(db)


def test_disabled_service_zeroes_its_pools(db):
    n = enrolled_node(db)[1]
    db.x("UPDATE nodes SET capacity_json=?, policy_json=? WHERE node_id=?",
         (json.dumps({"pools": {"scorer": 4}}), json.dumps({"disabled_services": ["relay/scorer"]}), n["node_id"]))
    assert core._node_pools(fresh(db, n)) == {"scorer": 0}
    db.x("UPDATE nodes SET policy_json=? WHERE node_id=?", (json.dumps({"disabled_services": []}), n["node_id"]))
    assert core._node_pools(fresh(db, n)) == {"scorer": 4}
    from oarbank.coordinator import modcalls
    assert modcalls.node_class(fresh(db, n), "relay")["pools"] == {"scorer": 1}


def test_golden_list_gets_the_nodes_platform_class(db, monkeypatch):
    """NodeClass [stable] fields: a module can return goldens for the node's platform, OS version, CPU and GPUs."""
    from oarbank.coordinator import modcalls
    from helpers import facts_for
    seen, real = [], modcalls.call
    monkeypatch.setattr(modcalls, "call", lambda db_, name, verb, params, *a, **k:
                        (seen.append(params["node_class"]) if verb == "golden.list" else None) or real(db_, name, verb, params, *a, **k))
    facts = {**facts_for("linux-amd64", os_version="6.8"), "cpu": {"model": "EPYC", "logical": 32},
             "gpus": [{"vendor": "nvidia", "model": "L4", "apis": ["cuda"], "vram_gb": 24}]}
    certify(db, enrolled_node(db, "box", facts=facts)[1])
    assert seen and all(c["platform"] == "linux-amd64" and c["os_version"] == "6.8" for c in seen), seen
    assert seen[0]["cpu"] == {"model": "EPYC", "logical": 32} and seen[0]["gpus"][0]["model"] == "L4"
    from oarbank_sdk.module_protocol import NodeClass
    NodeClass.model_validate(seen[0])
    assert modcalls.node_class(None, "relay")["platform"] is None


def test_goldens_per_platform_certify_each_platform_on_its_own_expectation(db):
    """A golden whose result legitimately differs on Windows (expected_by_platform) certifies Windows and Linux nodes
    alike; a golden limited to Linux (platforms) is never sent to the Windows node."""
    from helpers import GOLDEN, READY, DOCTOR_OK, POOLS, facts_for, relay_result
    from oarbank.coordinator import modcalls, releases
    win_exp = {"score": "0.900000", "tiles": 1536, "image_sha256": "W"}
    db.set_setting("module_settings:relay", {"goldens": [{**GOLDEN, "expected_by_platform": {"windows": win_exp}},
                                                         {**GOLDEN, "name": "G-linux", "platforms": ["linux"]}]})

    def run(name, platform, result):
        _, n = enrolled_node(db, name, facts=facts_for(platform, os_version="10.0.26100" if platform.startswith("windows") else "6.8"))
        core.hello(db, n, {"release_id": releases.assigned(db, fresh(db, n)), "facts": json.loads(fresh(db, n)["facts_json"]),
                           "live_attempts": [], "ready_datasets": READY})
        core.heartbeat(db, fresh(db, n), {"doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY, "capacity": {"pools": POOLS}})
        names = []
        for g in core.claim(db, fresh(db, n), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]:
            if g["module"] == "relay":
                names.append(db.one("SELECT name FROM jobs WHERE job_id=?", (g["job_id"],))["name"])
                core.complete(db, fresh(db, n), g["attempt_id"], result)
        return sorted(names), core.node_modules(fresh(db, n))["relay"]["state"]

    assert run("win", "windows-amd64", relay_result(score="0.900000", image="W")) == (["G1"], "certified")
    assert run("box", "linux-amd64", relay_result()) == (["G-linux", "G1"], "certified")
    assert run("win2", "windows-amd64", relay_result())[1] != "certified"          # the Linux result is wrong on Windows
    assert [g["expected"] for g in modcalls.goldens(db, "relay", {"platform": "windows-arm64"})] == [win_exp]
    assert [g["name"] for g in modcalls.goldens(db, "relay", None)] == ["G1"]       # unknown platform: unrestricted only


def test_release_stage_entries_carry_their_platforms(tmp_path):
    import shutil
    from oarbank.coordinator import releases
    shutil.copytree(Path(__file__).parent / "fixtures" / "modules" / "relay", tmp_path / "relay")
    toml = tmp_path / "relay" / "oarbank-module.toml"
    toml.write_text(toml.read_text().replace('requires = { pools = { scorer = 1 }, resources',
                                             'requires = { platforms = ["darwin-arm64"], pools = { scorer = 1 }, resources', 1))
    st = {s["name"]: s for s in releases.module_entry("relay", "1.0.0", "h1:x", tmp_path / "relay", "linux-amd64")["stages"]}
    assert st["score"]["platforms"] == ["darwin-arm64"] and st["render"]["platforms"] == []


def relay_per_platform(tmp_path) -> Path:
    """The relay fixture with per-platform files, wheels for several platforms and runner env (core >= 2.2)."""
    import shutil
    d = tmp_path / "relay"
    shutil.copytree(Path(__file__).parent / "fixtures" / "modules" / "relay", d, ignore=shutil.ignore_patterns("__pycache__"))
    toml = d / "oarbank-module.toml"
    toml.write_text(toml.read_text().replace('core = ">=2.0,<3"', 'core = ">=2.2,<3"').replace(
        'capabilities = ["cancellable", "deterministic_output", "freeze_ok"]\n',
        'capabilities = ["cancellable", "deterministic_output", "freeze_ok"]\nenv = { OMP_NUM_THREADS = "1", MKL_CBWR = "AUTO" }\n'
        '[runner.variants.windows]\nenv = { MKL_CBWR = "COMPATIBLE" }\n'
        '[runner.variants.windows-amd64]\nenv = { KMP_AFFINITY = "disabled" }\n', 1).replace(
        'executables = ["services/*.sh"]',
        'executables = ["services/*.sh"]\nplatform_files = { "native/windows-amd64/**" = ["windows-amd64"], "native/darwin/**" = ["darwin"] }'))
    for f in ("native/windows-amd64/scorer.dll", "native/darwin/scorer.dylib", "native/README.txt"):
        (d / f).parent.mkdir(parents=True, exist_ok=True)
        (d / f).write_text(f)
    (d / "wheels").mkdir()
    for w in ("dep-1.0-py3-none-any.whl", "fast-1.0-cp312-cp312-win_amd64.whl", "fast-1.0-cp312-cp312-macosx_11_0_arm64.whl",
              "fast-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"):
        (d / "wheels" / w).write_bytes(w.encode())
    return d


def test_release_runner_env_is_merged_for_the_platform_and_absent_when_undeclared(tmp_path):
    from oarbank.coordinator import releases
    d = relay_per_platform(tmp_path)
    env = lambda p: releases.module_entry("relay", "1.0.0", "h1:x", d, p)["runner"].get("env")
    assert env("darwin-arm64") == {"OMP_NUM_THREADS": "1", "MKL_CBWR": "AUTO"}
    assert env("windows-arm64") == {"OMP_NUM_THREADS": "1", "MKL_CBWR": "COMPATIBLE"}
    assert env("windows-amd64") == {"OMP_NUM_THREADS": "1", "MKL_CBWR": "COMPATIBLE", "KMP_AFFINITY": "disabled"}
    plain = Path(__file__).parent / "fixtures" / "modules" / "relay"
    assert "env" not in releases.module_entry("relay", "1.0.0", "h1:x", plain, "windows-amd64")["runner"]


def test_a_release_carries_only_the_files_and_wheels_of_its_platform(tmp_path):
    import tarfile
    from helpers import TOY_DIR
    from oarbank.coordinator import releases
    db = make_db(tmp_path / "oarbank.sqlite3", modules=(TOY_DIR, relay_per_platform(tmp_path)))

    def files(platform):
        with tarfile.open(releases.build(db, make_current=False, platform=platform)["path"]) as t:
            return {n.split("modules/relay/", 1)[1] for n in t.getnames() if n.startswith("modules/relay/")}
    win, mac, linux = files("windows-amd64"), files("darwin-arm64"), files("linux-amd64")
    common = {"oarbank-module.toml", "relay_runner.py", "native/README.txt", "wheels/dep-1.0-py3-none-any.whl"}
    assert common <= win & mac & linux
    assert {"native/windows-amd64/scorer.dll", "wheels/fast-1.0-cp312-cp312-win_amd64.whl"} <= win
    assert {"native/darwin/scorer.dylib", "wheels/fast-1.0-cp312-cp312-macosx_11_0_arm64.whl"} <= mac
    assert "wheels/fast-1.0-cp312-cp312-manylinux_2_17_x86_64.whl" in linux
    assert not {f for f in win if "darwin" in f or "macosx" in f or "manylinux" in f}
    assert not {f for f in mac if "windows" in f or "win_amd64" in f or "manylinux" in f}
    assert not {f for f in linux if f.startswith("native/") and f != "native/README.txt"}


def test_node_page_shows_protection_and_conditions(db, tmp_path):
    from oarbank.console import views
    from oarbank.console.state import ReadPool
    node = certify(db, enrolled_node(db)[1])
    pol = {**C.DEFAULT_POLICY, "protection": {"schema": 1, "node": {"mode": "fleet_first"}, "rule": [
        {"id": "gpu-trainer", "match": {"path_contains": "GPU Trainer/releases"}, "tree": "descendants",
         "reserve": {"mem_gb": "peak(300s).footprint + 2"}}]}}
    tel = {"guard": "clear", "protection": {"mode": "fleet_first", "active": ["gpu-trainer"],
                                            "rules": [{"id": "gpu-trainer", "active": True, "processes": 3, "cpu_cores": 0.5,
                                                       "footprint_gb": 4.1, "reason": "active"}],
                                            "constraint": {"reserved_mem_gb": 6.1, "reserved_cpu": 0, "binding": {"reserve_mem": "rule:gpu-trainer"}}}}
    db.x("UPDATE nodes SET policy_json=?, telemetry_json=? WHERE node_id=?", (json.dumps(pol), json.dumps(tel), node["node_id"]))
    d = views.node_page(db, node["node_id"], time.time())
    assert [c["code"] for c in d["conditions"]] == ["PROTECTION_RESERVED"]


def test_release_carries_each_bundle_with_services_and_stage_needs(db):
    import tarfile
    from oarbank.coordinator import releases
    rel = db.one("SELECT * FROM releases WHERE status='current' AND platform='darwin-arm64'")
    with tarfile.open(rel["path"]) as t:
        names = set(t.getnames())
        doc = json.loads(t.extractfile("modules.json").read())
        mods = {m["name"]: m for m in doc["modules"]}
    assert (doc["format"], doc["platform"]) == (2, "darwin-arm64")
    assert {"modules/relay/relay_runner.py", "modules/toy/toy_runner.py", "modules/relay/services/scorer.sh"} <= names
    e = mods["relay"]
    assert e["bundle"] == "modules/relay" and e["digest"].startswith("h2:") and e["version"] == "1.0.0"
    assert e["runner"]["exec"] == ["python", "-I", "{bundle}/relay_runner.py"] and e["runner"]["runtime"] == "python"
    assert [s["name"] for s in e["services"]] == ["scorer"] and e["services"][0]["exec"] == ["{bundle}/services/scorer.sh"]
    assert e["services"][0]["provides"]["pools"] == ["scorer"] and e["services"][0]["reserves_host_memory"]
    assert {s["name"]: s for s in e["stages"]}["score"] == {"name": "score", "capabilities": [], "pools": ["scorer"], "platforms": []}
    assert e["runner"]["capabilities"] == ["cancellable", "deterministic_output", "freeze_ok"]
    assert e["runner"]["gpu"]["use"] == "none" and e["runner"]["stop_grace_s"] == 20.0
    assert json.loads(rel["composition_json"])["relay"]["version"] == "1.0.0"
    assert releases.composition(db)["toy"]["digest"] == mods["toy"]["digest"]


def test_release_carries_a_declared_bandwidth_class_only(tmp_path):
    """The agent picks rungs by the module's measured bandwidth class; undeclared modules keep
    the exact runner entry they had, so existing releases compose to the same bytes."""
    import shutil
    from oarbank.coordinator import releases
    src = Path(__file__).parent / "fixtures" / "modules" / "relay"
    shutil.copytree(src, tmp_path / "relay")
    plain = releases.module_entry("relay", "1.0.0", "h1:x", tmp_path / "relay")
    assert "bandwidth_class" not in plain["runner"]
    toml = tmp_path / "relay" / "oarbank-module.toml"
    toml.write_text(toml.read_text().replace('capabilities = ["cancellable", "deterministic_output", "freeze_ok"]\n',
                                             'capabilities = ["cancellable", "deterministic_output", "freeze_ok"]\nbandwidth_class = "medium"\n', 1))
    assert releases.module_entry("relay", "1.0.0", "h1:x", tmp_path / "relay")["runner"]["bandwidth_class"] == "medium"
