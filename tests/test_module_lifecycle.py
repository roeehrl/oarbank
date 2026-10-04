"""Modules as bundles in the coordinator's store, and their lifecycle through operations:
install (verified, nothing enabled), enable, canary on some nodes (their own release; re-certified on the
new digest; judged by that version's process), promote, rollback, the kill switch, pins, uninstall, and
the install refusals."""
import shutil
import tempfile
from pathlib import Path

import pytest

from oarbank.coordinator import core, modcalls, modstore, ops, releases
from oarbank_sdk import bundle as B

from helpers import (CAPACITY, sign_in, DOCTOR_OK, FACTS, PARAMS, READY, RELAY_DIR, SCENES, certify, create_study,
                     enrolled_node, fresh, golden_result, make_db, relay_result)


def relay_version(version: str, tweak: str = "", fields_type: str | None = None) -> Path:
    """A copy of the relay fixture at another version (a different digest)."""
    d = Path(tempfile.mkdtemp()) / "relay"
    shutil.copytree(RELAY_DIR, d, ignore=shutil.ignore_patterns("__pycache__", "dist"))
    m = (d / "oarbank-module.toml").read_text().replace('version = "1.0.0"', f'version = "{version}"')
    if fields_type:
        m = m.replace('{ name = "tiles", type = "integer"', f'{{ name = "tiles", type = "{fields_type}"')
    (d / "oarbank-module.toml").write_text(m)
    code = (d / "relay_module.py").read_text().replace('VERSION, COMPAT = "dev.codonic.oarbank.relay", "1.0.0"',
                                                       f'VERSION, COMPAT = "dev.codonic.oarbank.relay", "{version}"')
    (d / "relay_module.py").write_text(code + tweak)
    return d


def bundle_of(src: Path) -> Path:
    out, _ = B.build(src, Path(tempfile.mkdtemp()) / "m.mfb")
    return out


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def op(db, name, target=None, **kw):
    return ops.execute(db, ops.OpRequest(op=name, actor="test", target=target, **kw))


def planned(db, name, target, params=None, reason="test"):
    plan = op(db, name, target, params=params or {}, dry_run=True)["plan"]
    return plan, op(db, name, plan_id=plan["plan_id"], reason=reason, idempotency_key=plan["plan_id"])


def install_via_api(db, src: Path) -> dict:
    """What `oarbank module install` does: stage the bytes, then the reviewed T2 operation."""
    import hashlib
    from oarbank.coordinator import config as C
    data = bundle_of(src).read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    inc = C.HOME / "modules" / "incoming"
    inc.mkdir(parents=True, exist_ok=True)
    (inc / f"{sha}.mfb").write_bytes(data)
    plan, r = planned(db, "modules.install", None, {"sha256": sha})
    return {"plan": plan, "result": r["result"]}


def rehello(db, node):
    """The agent installs the release it is told to, says hello, and doctors."""
    rel = releases.assigned(db, fresh(db, node))
    core.hello(db, fresh(db, node), {"release_id": rel, "facts": FACTS, "live_attempts": [], "ready_datasets": READY})
    core.heartbeat(db, fresh(db, node), {"capacity": CAPACITY, "doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY})
    return rel


def run_goldens(db, node):
    for g in core.claim(db, fresh(db, node), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]:
        assert g["kind"] == "golden"
        core.complete(db, fresh(db, node), g["attempt_id"], golden_result(g, db))


def state(db, node, module="relay"):
    return core.node_modules(fresh(db, node)).get(module, {})


def test_install_is_verified_and_enables_nothing(db):
    r = install_via_api(db, relay_version("1.1.0"))
    assert r["plan"]["impact"]["installed_versions"] == ["1.0.0"] and r["plan"]["impact"]["version"] == "1.1.0"
    assert r["plan"]["impact"]["enables"].startswith("nothing")
    assert r["result"]["version"] == "1.1.0" and Path(r["result"]["path"]).is_dir()
    assert modstore.channel(db, "relay")["current"] == "1.0.0"
    assert [x["version"] for x in modstore.installed(db, "relay")] == ["1.0.0", "1.1.0"]
    assert all(v["ok"] for v in op(db, "modules.verify")["result"]["bundles"])
    again = install_via_api(db, relay_version("1.1.0"))                    # the same bytes: idempotent
    assert again["result"]["already_installed"]


def test_install_refusals(db, tmp_path):
    with pytest.raises(modstore.InstallError, match="immutable"):
        modstore.install(db, bundle_of(relay_version("1.0.0", tweak="\n# changed\n")), self_test=False)
    with pytest.raises(modstore.InstallError, match="type changed without a major"):
        modstore.install(db, bundle_of(relay_version("1.2.0", fields_type="number")), self_test=False)
    modstore.install(db, bundle_of(relay_version("2.0.0", fields_type="number")), self_test=False)   # a major may
    d = relay_version("1.3.0")
    m = (d / "oarbank-module.toml").read_text().replace('core = ">=2.3,<3"', 'core = ">=3.0"')
    (d / "oarbank-module.toml").write_text(m)
    with pytest.raises(modstore.InstallError, match="needs core >=3.0"):
        modstore.install(db, bundle_of(d), self_test=False)
    bad = relay_version("1.4.0", tweak="\nBROKEN = (\n")                    # cannot even start
    with pytest.raises(modstore.InstallError, match="self-test failed"):
        modstore.install(db, bundle_of(bad), self_test=True)
    assert not modstore.record(db, "relay", "1.4.0")
    tampered = bundle_of(relay_version("1.5.0"))
    data = bytearray(tampered.read_bytes())
    data[len(data) // 2] ^= 0xFF
    tampered.write_bytes(bytes(data))
    with pytest.raises(modstore.InstallError, match="bundle rejected"):
        modstore.install(db, tampered, self_test=False)


def relay_declaring(version: str, requires: str = "", tail: str = "") -> Path:
    """The relay fixture at `version` with per-platform declarations: lines added to [requires], and
    tables appended to the manifest."""
    d = relay_version(version)
    m = (d / "oarbank-module.toml").read_text().replace('core = ">=2.3,<3"', 'core = ">=2.3,<3"\n' + requires)
    (d / "oarbank-module.toml").write_text(m + tail)
    return d


@pytest.mark.parametrize("requires, edit, tail", [
    ("", None, '\n[placement]\nmix = "same-os"\nunit = "group"\nrebind = "if-stranded"\n'),
    ("", None, '\n[[stages]]\nname = "tally"\nafter = "render"\nplacement = { mix = "same-platform" }\n'),
    ('features = ["placement"]', None, ""),
    ("", ('kinds = ["scene", "demo"]', 'kinds = ["scene", "demo"]\nplatform_bound = ["scene"]'), ""),
    ("", ('determinism = "exact"', 'determinism = "exact"\ndeterminism_scope = "os"'), ""),
    ("", ('determinism = "exact"', 'determinism = "exact"\ndeterminism_scope = "arch"'), ""),
])
def test_install_accepts_placement_declarations(db, requires, edit, tail):
    """Core 2.2 enforces placement (D33), so a module may declare it."""
    d = relay_declaring("1.6.0", requires, tail)
    if edit:
        (d / "oarbank-module.toml").write_text((d / "oarbank-module.toml").read_text().replace(*edit))
    assert modstore.install(db, bundle_of(d), self_test=False)["version"] == "1.6.0"


def test_install_refuses_a_feature_this_core_does_not_implement(db, monkeypatch):
    """requires.features is must-understand: an SDK may know a feature before this core implements it."""
    monkeypatch.setattr(modstore, "FEATURES", ())
    with pytest.raises(modstore.InstallError, match=rf"requires features \['placement'\], which core {modstore.CORE_VERSION} does not implement"):
        modstore.install(db, bundle_of(relay_declaring("1.6.0", 'features = ["placement"]')), self_test=False)


def test_a_coordinator_side_that_does_not_run_on_this_coordinator_is_refused(db, monkeypatch):
    linux_only = relay_declaring("1.7.0", 'coordinator_platforms = ["linux-amd64", "linux-arm64"]\n'
                                          'unsupported.coordinator = { darwin = "the planner needs Linux cgroups" }')
    monkeypatch.setattr(modstore.portable, "host_platform", lambda: "darwin-arm64")
    with pytest.raises(modstore.InstallError, match="does not run on darwin-arm64: the planner needs Linux cgroups"):
        modstore.install(db, bundle_of(linux_only), self_test=False)
    monkeypatch.setattr(modstore.portable, "host_platform", lambda: "linux-amd64")
    modstore.install(db, bundle_of(linux_only), self_test=False)                # declared: installs
    monkeypatch.setattr(modstore.portable, "host_platform", lambda: "windows-amd64")
    for attempt in (lambda: modstore.canary(db, "relay", "1.7.0", ["n1"]), lambda: modstore.pin(db, "relay", "n1", "1.7.0")):
        with pytest.raises(modstore.LifecycleError, match="does not run on windows-amd64: requires.coordinator_platforms"):
            attempt()
    modstore.disable(db, "relay")
    db.x("UPDATE module_channels SET current='1.7.0' WHERE name='relay'")       # as a moved coordinator finds it
    with pytest.raises(modstore.LifecycleError, match="does not run on windows-amd64"):
        modstore.enable(db, "relay", None)


def test_canary_recertifies_only_its_nodes_then_promote_and_rollback(db):
    a, b = (certify(db, enrolled_node(db, n)[1]) for n in ("canary", "other"))
    d0 = state(db, a)["digest"]
    install_via_api(db, relay_version("1.1.0"))
    plan, _ = planned(db, "modules.enable_canary", "relay@1.1.0", {"nodes": ["canary"]})
    assert plan["tier"] == "T2"
    ra, rb = releases.assigned(db, fresh(db, a)), releases.assigned(db, fresh(db, b))
    assert ra != rb and fresh(db, b)["assigned_release"] is None
    assert releases.composition_of(db, ra)["relay"]["version"] == "1.1.0"
    assert core.heartbeat(db, fresh(db, a), {"capacity": CAPACITY})["release"]["release_id"] == ra
    # before the canary proves itself, promotion is refused, saying what each canary node still lacks
    with pytest.raises(core.ApiError, match=r"relay 1.1.0 is not certified on every canary node yet \(canary: not on 1.1.0 "
                                            r"yet \(installing its release; certified on the previous version\)\)"):
        planned(db, "modules.promote", "relay")
    rehello(db, a)
    assert state(db, a)["state"] == "certifying"                           # the digest changed: re-certify
    with pytest.raises(core.ApiError, match=r"\(canary: certifying: its goldens have not all passed\)"):
        planned(db, "modules.promote", "relay@1.1.0")
    run_goldens(db, a)
    assert state(db, a)["state"] == "certified" and state(db, a)["digest"] != d0
    assert state(db, b)["digest"] == d0 and state(db, b)["state"] == "certified"   # untouched
    # the canary node's jobs run version 1.1.0 and are judged by that version's own process
    create_study(db, "s", [], SCENES[:1], {"label": "base", "params": PARAMS})
    g = core.claim(db, fresh(db, a), {"free_cpu": 4, "free_mem_gb": 8, "ready_datasets": READY})["grants"][0]
    assert g["spec"]["module_version"] == "1.1.0"
    assert core.complete(db, fresh(db, a), g["attempt_id"], relay_result())["canonical"]
    assert db.one("SELECT module_version FROM results WHERE attempt_id=?", (g["attempt_id"],))["module_version"] == "1.1.0"
    assert "relay@1.1.0" in modcalls.host(db).specs
    plan, r = planned(db, "modules.promote", "relay@1.1.0")                # the canary's version names it as well
    assert plan["impact"]["ready"] and plan["impact"]["canary_nodes"] == {"canary": "certified"} and plan["target"] == "relay"
    ch = modstore.channel(db, "relay")
    assert (ch["current"], ch["previous"], ch["canary"]) == ("1.1.0", "1.0.0", None)
    assert fresh(db, a)["assigned_release"] is None and releases.assigned(db, fresh(db, b)) == ra
    rehello(db, b)
    assert state(db, b)["state"] == "certifying"                           # every node proves the new version
    op(db, "modules.rollback", "relay", reason="rehearsal")
    ch = modstore.channel(db, "relay")
    assert (ch["current"], ch["previous"]) == ("1.0.0", "1.1.0")
    assert releases.composition_of(db, releases.assigned(db, fresh(db, b)))["relay"]["version"] == "1.0.0"
    assert modcalls.info("relay").version == "1.0.0"


def test_module_operations_take_the_target_form_they_act_on(db):
    """name@version where a version is acted on, the name where the module is; promote takes both (the version names its
    canary). Another form is refused naming the form the operation takes, never read as a module name."""
    certify(db, enrolled_node(db, "canary")[1])
    modstore.install(db, bundle_of(relay_version("1.1.0")), self_test=False)
    with pytest.raises(core.ApiError, match=r"no_canary: relay has no canary to promote: oarbank module canary relay@<version>"):
        planned(db, "modules.promote", "relay@1.1.0")
    with pytest.raises(core.ApiError, match=r"bad_target: modules.enable_canary needs <name>@<version>, e\.g\. relay@1.1.0 "
                                            r"\(installed: 1.0.0, 1.1.0\)"):
        planned(db, "modules.enable_canary", "relay", {"nodes": ["canary"]})
    planned(db, "modules.enable_canary", "relay@1.1.0", {"nodes": ["canary"]})
    with pytest.raises(core.ApiError, match=r"not_canary: relay's canary is 1.1.0, not 1.0.0: promote relay or relay@1.1.0"):
        planned(db, "modules.promote", "relay@1.0.0")
    with pytest.raises(core.ApiError, match=r"not_found: no module 'bench' is installed"):
        planned(db, "modules.promote", "bench@2.4.1")
    for name in ("modules.rollback", "modules.disable"):
        with pytest.raises(core.ApiError, match=rf"bad_target: {name} takes a module name \(relay\), not relay@1.1.0"):
            op(db, name, "relay@1.1.0", reason="test")
    assert modstore.channel(db, "relay")["canary"] == "1.1.0" and not modstore.channel(db, "relay")["disabled"]
    op(db, "modules.pin", "relay", params={"node": "canary", "clear": True})        # unpinning names no version


def test_abandoning_a_canary_returns_its_nodes(db):
    a = certify(db, enrolled_node(db, "canary")[1])
    modstore.install(db, bundle_of(relay_version("1.1.0")), self_test=False)
    planned(db, "modules.enable_canary", "relay@1.1.0", {"nodes": [a["node_id"]]})
    assert fresh(db, a)["assigned_release"]
    op(db, "modules.rollback", "relay", reason="bad canary")
    assert fresh(db, a)["assigned_release"] is None and modstore.channel(db, "relay")["canary"] is None


def test_kill_switch_stops_dispatch_and_revokes_within_one_heartbeat(db):
    n = certify(db, enrolled_node(db)[1])
    create_study(db, "s", [], SCENES[:2], {"label": "base", "params": PARAMS})
    live = core.claim(db, fresh(db, n), {"free_cpu": 1, "free_mem_gb": 2, "ready_datasets": READY})["grants"]
    assert live
    op(db, "modules.disable", "relay", reason="bad results")
    assert core.claim(db, fresh(db, n), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"] == []
    hb = core.heartbeat(db, fresh(db, n), {"capacity": CAPACITY})
    assert hb["revoke"] == [live[0]["attempt_id"]]                         # the next heartbeat carries the revocation
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (live[0]["job_id"],))["state"] == "pending"
    op(db, "modules.enable", "relay", reason="fixed")
    assert core.claim(db, fresh(db, n), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]


def test_pin_and_uninstall(db):
    n = certify(db, enrolled_node(db)[1])
    modstore.install(db, bundle_of(relay_version("1.1.0")), self_test=False)
    op(db, "modules.pin", "relay@1.1.0", params={"node": n["node_id"]}, reason="try")
    assert releases.composition_of(db, releases.assigned(db, fresh(db, n)))["relay"]["version"] == "1.1.0"
    with pytest.raises(core.ApiError, match="in_use|current, previous"):
        planned(db, "modules.uninstall", "relay@1.1.0")
    op(db, "modules.pin", "relay@1.1.0", params={"node": n["node_id"], "clear": True}, reason="done")
    assert fresh(db, n)["assigned_release"] is None
    _, r = planned(db, "modules.uninstall", "relay@1.1.0")
    assert r["result"] == {"uninstalled": "relay@1.1.0"} and not modstore.record(db, "relay", "1.1.0")


def test_a_node_with_an_unrelated_digest_change_keeps_its_certification(db):
    """Certification is keyed by each module's digest: a new toy version re-certifies toy only."""
    n = certify(db, enrolled_node(db)[1])
    relay_before = state(db, n)
    toy = Path(tempfile.mkdtemp()) / "toy"
    from helpers import TOY_DIR
    shutil.copytree(TOY_DIR, toy, ignore=shutil.ignore_patterns("__pycache__", "dist"))
    (toy / "oarbank-module.toml").write_text((toy / "oarbank-module.toml").read_text().replace('version = "0.1.0"', 'version = "0.2.0"'))
    modstore.install(db, bundle_of(toy), self_test=False)
    planned(db, "modules.enable_canary", "toy@0.2.0", {"nodes": [n["node_id"]]})
    rehello(db, n)
    assert state(db, n, "toy")["state"] == "certifying"
    assert state(db, n)["state"] == "certified" and state(db, n)["generation"] == relay_before["generation"]


def test_cli_source_module_commands_against_a_real_fleetd(db, tmp_path):
    """`oarbank module install/enable/canary/list` over HTTP, as an operator runs them."""
    import os
    import subprocess
    import sys
    from oarbank.coordinator import app as coord_app
    from test_console import Server
    n = certify(db, enrolled_node(db, "mini")[1])
    b = bundle_of(relay_version("1.1.0"))
    with Server(coord_app.admin_app(db)) as oarbankd:
        from oarbank.coordinator import access
        env = {**os.environ, "OARBANKD_URL": f"http://127.0.0.1:{oarbankd.port}", "OARBANK_REASON": "cli test",
               "OARBANK_TOKEN": access.ensure_admin_token(db.root)}
        run = lambda *args: subprocess.run([sys.executable, "-m", "oarbank.cli.main", "module", *args, "--yes"],
                                           capture_output=True, text=True, env=env, timeout=300)
        r = run("install", str(b))
        assert r.returncode == 0, r.stderr
        assert '"version": "1.1.0"' in r.stdout
        r = run("canary", "relay@1.1.0", "--node", n["node_id"])
        assert r.returncode == 0, r.stderr
        r = subprocess.run([sys.executable, "-m", "oarbank.cli.main", "module", "list"], capture_output=True, text=True, env=env)
        assert "relay" in r.stdout and "canary 1.1.0" in r.stdout and "relay@1.1.0" in r.stdout
        r = subprocess.run([sys.executable, "-m", "oarbank.cli.main", "module", "show", "relay"], capture_output=True, text=True, env=env)
        assert r.returncode == 0, r.stderr
        assert any(line.replace(" *", "").split()[:4] == ["darwin-arm64", "yes", "yes", "1"] for line in r.stdout.splitlines()), r.stdout
    assert fresh(db, n)["assigned_release"]


def test_console_modules_page_installs_by_upload_and_shows_channels(db, tmp_path):
    from fastapi.testclient import TestClient
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from oarbank.coordinator import app as coord_app
    from test_console import SECRET, Server
    certify(db, enrolled_node(db, "mini")[1])
    b = bundle_of(relay_version("1.1.0"))
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(str(db.path), f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        with TestClient(console_app(state, tmp_path / "logs"), client=("127.0.0.1", 50003)) as c:
            sign_in(c, db)
            page = c.get("/modules").text
            assert "current 1.0.0" in page and 'enctype="multipart/form-data"' in page and "Verify every installed bundle" in page
            r = c.post("/do/modules.install", data={"return_to": "/modules", "idem": "i1", "target": ""},
                       files={"bundle": ("relay-1.1.0.mfb", b.read_bytes(), "application/octet-stream")}, follow_redirects=False)
            assert r.status_code == 200 and "Review" in r.text and "1.1.0" in r.text             # the T2 plan page
            plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
            r = c.post("/apply/modules.install", data={"plan_id": plan_id, "reason": "new relay", "return_to": "/modules", "idem": "i2"},
                       follow_redirects=False)
            assert r.status_code == 303 and "kind=ok" in r.headers["location"]
            page = c.get("/modules").text
            assert "relay@1.1.0" in page and "Canary…" in page
    assert modstore.record(db, "relay", "1.1.0")


def test_the_fixture_modules_pass_the_sdk_conformance_kit():
    from helpers import GOLDEN, TOY_DIR
    from oarbank_sdk.conformance import conform
    assert conform(TOY_DIR).ok
    rep = conform(RELAY_DIR, {"datasets": {"demo:atrium": {"kind": "demo", "attrs": {"scene": "atrium"}}},
                              "settings": {"goldens": [GOLDEN]},
                              "node_classes": [{"pools": {"scorer": 1}}, {"pools": {"scorer": 0}}],
                              "params": [PARAMS, {"samples": 0}]})
    assert rep.ok, rep.text()
    assert {c.status for c in rep.checks if c.suite == "runner" and "golden" in c.name} == {"skip"}   # no dataset files
