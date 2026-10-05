"""Modules run out of process behind the module host.

Every module process runs confined, as in production (modsandbox.py). Host supervision (respawn, fault, timeouts, errors, callbacks, logs) against small SDK modules, then the
core's guarantees: a module fault on the completion path answers 503, keeps the lease and charges
nothing to the node or the job (S15); killing modules mid-run leaves zero invariant violations; oarbankd
imports no module code (D1)."""
import random
import subprocess
import sys
import textwrap
import time

import pytest

from helpers import create_study, PARAMS, READY, certified_fleet, enrolled_node, certify, fresh, make_db, relay_result
from oarbank.coordinator import core, invariants, modcalls, modsandbox
from oarbank.coordinator.modulehost import FAULT_AFTER, ModuleError, ModuleHost, ModuleSpec, ModuleUnavailable

MODULE = """
import os, sys, time
from oarbank_sdk.server import Module
m = Module("dev.test.m", "0.0.1", concurrency=2)
for verb in ("job.plan", "spec.build", "golden.list"):
    m.verb(verb)(lambda p, ctx, v=verb: {"job.plan": {"jobs": []}, "spec.build": {"specs": []}, "golden.list": {"goldens": []}}[v])
@m.verb("result.evaluate")
def ev(p, ctx):
    return {"verdict": "accept"}
@m.verb("params.check")
def check(p, ctx):
    if p.params.get("crash"):
        os._exit(7)
    if p.params.get("sleep"):
        time.sleep(p.params["sleep"])
    if p.params.get("setting"):
        return {"ok": True, "normalized_params": {"v": ctx.host.settings_get(p.params["setting"])}}
    if p.params.get("host"):
        info = ctx._module.host_info
        return {"ok": True, "normalized_params": {"version": info.version, "platform": ctx.host_platform,
                                                  "variants": ctx.host_has("coordinator.variants"),
                                                  "env": os.environ.get("OMP_NUM_THREADS")}}
    print("stderr noise", p.params)
    return {"ok": True, "normalized_params": p.params}
m.run()
"""


@pytest.fixture
def mod_file(tmp_path):
    f = tmp_path / "bundle" / "m.py"
    f.parent.mkdir()
    f.write_text(textwrap.dedent(MODULE))
    return f


def confined_spec(home, bundle, argv, **kw) -> ModuleSpec:
    """A spec for module `m` with its bundle at `bundle`, confined by the coordinator policy production gives it."""
    return ModuleSpec(name="m", argv=argv, cwd=str(bundle), env=modsandbox.coordinator_env(home, "m"),
                      sandbox=modsandbox.coordinator_policy(home, "m", "dev.test.m", bundle),
                      profile_dir=str(modsandbox.profile_dir(home)), **kw)


def make_host(tmp_path, mod_file, **kw):
    spec = confined_spec(tmp_path, mod_file.parent, ["python", "-I", str(mod_file)], timeouts_s={"default": 5.0}, **kw)
    return ModuleHost([spec], home=tmp_path, callbacks={"host.settings.get": lambda name, p: {"value": f"{name}:{p['key']}"}})


def test_calls_and_health(tmp_path, mod_file):
    h = make_host(tmp_path, mod_file)
    try:
        assert h.call("m", "params.check", {"params": {"a": 1}})["normalized_params"] == {"a": 1}
        hs = h.health("m")
        assert hs["state"] == "ready" and hs["calls"] == 1 and hs["module_version"] == "0.0.1"
        time.sleep(0.2)
        assert "stderr noise" in (tmp_path / "logs" / "modules" / "m.log").read_text(encoding="utf-8")
    finally:
        h.close()


def test_the_handshake_names_the_core_its_features_and_the_coordinators_platform(tmp_path, mod_file):
    from oarbank_sdk import portable
    from oarbank.coordinator.modstore import CORE_VERSION
    spec = confined_spec(tmp_path, mod_file.parent, ["python", "-I", str(mod_file)])
    spec.env["OMP_NUM_THREADS"] = "1"
    h = ModuleHost([spec], home=tmp_path)
    try:
        got = h.call("m", "params.check", {"params": {"host": True}})["normalized_params"]
        assert got == {"version": CORE_VERSION, "platform": portable.host_platform(), "variants": True, "env": "1"}
    finally:
        h.close()


def test_respawn_after_crash(tmp_path, mod_file):
    h = make_host(tmp_path, mod_file)
    try:
        h.call("m", "params.check", {"params": {}})
        pid = h.health("m")["pid"]
        with pytest.raises(ModuleUnavailable) as ei:
            h.call("m", "params.check", {"params": {"crash": True}})
        assert ei.value.kind == "crash"
        assert h.call("m", "params.check", {"params": {}})["ok"] is True      # respawned transparently
        assert h.health("m")["pid"] != pid and h.health("m")["restarts"] == 1
    finally:
        h.close()


def test_fault_fails_fast_and_restart_recovers(tmp_path, mod_file):
    h = ModuleHost([confined_spec(tmp_path, mod_file.parent, ["python", "-c", "import sys; sys.exit(1)"])], home=tmp_path)
    try:
        for _ in range(FAULT_AFTER):
            with pytest.raises(ModuleUnavailable) as ei:
                h.call("m", "params.check", {"params": {}})
            assert ei.value.kind == "handshake"
        assert h.health("m")["state"] == "fault"
        t = time.monotonic()
        with pytest.raises(ModuleUnavailable) as ei:
            h.call("m", "params.check", {"params": {}})
        assert ei.value.kind == "fault" and time.monotonic() - t < 0.05 and ei.value.retry_after > 0
        h.specs["m"].argv = ["python", "-I", str(mod_file)]                    # fixed (e.g. rolled back)
        h.restart("m")
        assert h.call("m", "params.check", {"params": {}})["ok"] is True
    finally:
        h.close()


def test_timeouts_restart_a_stuck_process(tmp_path, mod_file):
    h = make_host(tmp_path, mod_file)
    try:
        h.call("m", "params.check", {"params": {}})
        pid = h.health("m")["pid"]
        for _ in range(3):
            with pytest.raises(ModuleUnavailable) as ei:
                h.call("m", "params.check", {"params": {"sleep": 2}}, timeout=0.2)
            assert ei.value.kind in ("timeout", "fault")
        h.restart("m")
        assert h.call("m", "params.check", {"params": {}})["ok"] is True
        assert h.health("m")["pid"] != pid
    finally:
        h.close()


def test_module_errors_and_callback_permissions(tmp_path, mod_file):
    h = make_host(tmp_path, mod_file)
    try:
        with pytest.raises(ModuleError) as ei:
            h.call("m", "params.check", {"wrong": 1})
        assert ei.value.code == -32602
        with pytest.raises(ModuleError) as ei:                               # no settings:read:self permission
            h.call("m", "params.check", {"params": {"setting": "x"}})
        assert ei.value.code == -32002
        assert h.health("m")["state"] == "ready"                              # errors are not crashes
    finally:
        h.close()
    h = make_host(tmp_path, mod_file, permissions={"settings:read:self"})
    try:
        assert h.call("m", "params.check", {"params": {"setting": "x"}})["normalized_params"] == {"v": "m:x"}
    finally:
        h.close()


def test_fleetd_imports_no_module_code():
    code = ("import sys, oarbank.coordinator.app, oarbank.coordinator.core, oarbank.coordinator.campaigns, oarbank.coordinator.effects; "
            "print(sorted(m for m in sys.modules if m.startswith('oarbank.modules')))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "[]"


# ---------------------------------------------------------------- core: S15 and chaos

@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def break_module(db, name="relay"):
    h = modcalls.host(db)
    good = list(h.specs[name].argv)
    h.stop(name)
    h.specs[name].argv = ["python", "-c", "import sys; sys.exit(1)"]
    return lambda: (h.specs[name].__setattr__("argv", good), h.restart(name))


def test_completion_during_module_outage_is_never_charged(db):
    node = certify(db, enrolled_node(db)[1])
    create_study(db, "s", [], ["scene:s1"], {"label": "base", "params": PARAMS})
    g = core.claim(db, node, {"free_slots": 1, "ready_datasets": READY})["grants"][0]
    restore = break_module(db)
    for _ in range(FAULT_AFTER + 1):                                        # through handshake failures into fault
        with pytest.raises(core.ApiError) as ei:
            core.complete(db, node, g["attempt_id"], relay_result())
        assert ei.value.status == 503 and ei.value.code == "module_unavailable" and "Retry-After" in ei.value.headers
    a = db.one("SELECT * FROM attempts WHERE attempt_id=?", (g["attempt_id"],))
    assert a["state"] == "live" and a["phase"] == "awaiting_module" and a["expires_at"] > time.time() + 500
    db.x("UPDATE attempts SET hard_deadline=? WHERE attempt_id=?", (time.time() - 1, g["attempt_id"]))
    core.reap(db)                                                            # past the hard deadline: not killed
    assert db.one("SELECT state FROM attempts WHERE attempt_id=?", (g["attempt_id"],))["state"] == "live"
    j = db.one("SELECT * FROM jobs WHERE job_id=?", (g["job_id"],))
    assert (j["exec_failures"], j["expirations"]) == (0, 0)
    assert fresh(db, node)["breaker_failures"] == 0
    assert invariants.check_all(db) == []
    alert = db.one("SELECT * FROM alerts WHERE rule='module_host_down:relay' AND state='open'")
    assert alert is not None                                                 # in the inbox at once
    restore()
    r = core.complete(db, node, g["attempt_id"], relay_result())            # the agent's outbox redelivers
    assert r["accepted"] and r["canonical"]
    assert db.one("SELECT state FROM alerts WHERE rule='module_host_down:relay'")["state"] == "resolved"
    assert invariants.check_all(db) == []


def test_killing_modules_mid_run_leaves_zero_violations(db):
    rnd = random.Random(7)
    nodes = certified_fleet(db)
    create_study(db, "chaos", [{"label": "c1", "params": {**PARAMS, "samples": 12}}],
                         ["scene:s1", "scene:s2", "scene:s3", "scene:s4"], {"label": "base", "params": PARAMS})
    h = modcalls.host(db)
    kills = 0
    for _ in range(60):
        for n in nodes:
            n = fresh(db, n)
            for g in core.claim(db, n, {"free_slots": 2, "ready_datasets": READY})["grants"]:
                if rnd.random() < 0.4:
                    for name in list(h._procs):
                        h._procs[name].proc.kill()
                        kills += 1
                for _attempt in range(10):
                    try:
                        core.complete(db, n, g["attempt_id"], relay_result(score=f"0.8{g['job_id'] % 10}0000", image=f"v{g['job_id']}"))
                        break
                    except core.ApiError as e:
                        assert e.status == 503
                        h.restart("relay")
                assert invariants.check_all(db) == []
        if not db.one("SELECT 1 FROM jobs WHERE state IN ('pending','leased') AND kind!='golden'"):
            break
    assert kills > 0
    assert not db.one("SELECT 1 FROM jobs WHERE state IN ('pending','leased') AND kind!='golden'")
    assert invariants.check_all(db) == []


def test_close_host_stops_a_databases_module_processes_at_once(tmp_path):
    # the property test opens a database per example; its module processes waited for a garbage collection and ~150
    # of them at once (40 MB each) ran an 8 GB Linux VM out of memory
    db = make_db(tmp_path / "oarbank.sqlite3")
    assert modcalls.goldens(db, "toy")                         # spawns the toy module's coordinator process
    procs = [p.proc for p in modcalls.host(db)._procs.values()]
    assert procs and all(p.poll() is None for p in procs)
    modcalls.close_host(db)
    for p in procs:
        p.wait(timeout=10)
    assert db not in modcalls._hosts
