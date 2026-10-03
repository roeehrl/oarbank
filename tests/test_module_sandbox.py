"""The module sandbox on the coordinator side, and the approval of node-side grants (oarbank-sdk spec/sandbox.md)."""
import json
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from oarbank.coordinator import modcalls, modsandbox, modstore, ops, releases
from oarbank_sdk import manifest as mf
from oarbank_sdk import portable

from helpers import RELAY_DIR, TOY_DIR, make_db


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def op(db, name, target=None, **kw):
    return ops.execute(db, ops.OpRequest(op=name, actor="test", target=target, **kw))


def planned(db, name, target, reason="test", params=None):
    plan = op(db, name, target, dry_run=True, params=params or {})["plan"]
    return op(db, name, plan_id=plan["plan_id"], reason=reason, idempotency_key=plan["plan_id"])


def test_module_coordinator_and_cli_learn_the_coordinators_platform(db, tmp_path):
    from oarbank.cli.main import cli_env
    host = portable.host_platform()
    i = modcalls.info("toy")
    assert modcalls._spec(db, modcalls.host_key("toy", i.version), i).env["OARBANK_PLATFORM"] == host
    assert cli_env(tmp_path, 8080, "t", "toy")["OARBANK_PLATFORM"] == host


def test_the_coordinator_side_runs_its_variant_for_the_coordinators_platform(tmp_path, monkeypatch):
    doc = tomllib.loads((RELAY_DIR / "oarbank-module.toml").read_text())
    doc["requires"]["core"] = ">=2.2,<3"
    doc["coordinator"].update(timeouts_s={"default": 10.0, "job.plan": 30.0}, concurrency=1, env={"OMP_NUM_THREADS": "4", "A": "base"},
                              variants={"linux": {"exec": ["python", "-I", "{bundle}/relay_linux.py"], "concurrency": 2,
                                                  "timeouts_s": {"job.plan": 60.0}, "env": {"OMP_NUM_THREADS": "1"}},
                                        "linux-arm64": {"timeouts_s": {"default": 20.0}}})
    man = mf.Manifest.model_validate(doc)
    monkeypatch.setattr(portable, "host_platform", lambda: "linux-arm64")
    s = modsandbox.coordinator_spec(tmp_path, "relay", man, RELAY_DIR)
    assert s.argv == ["python", "-I", "{bundle}/relay_linux.py"] and s.concurrency == 2
    assert s.timeouts_s == {"default": 20.0, "job.plan": 60.0}
    assert (s.env["OMP_NUM_THREADS"], s.env["A"], s.env["OARBANK_PLATFORM"]) == ("1", "base", "linux-arm64")
    monkeypatch.setattr(portable, "host_platform", lambda: "darwin-arm64")
    s = modsandbox.coordinator_spec(tmp_path, "relay", man, RELAY_DIR, key="relay@1.0.0")
    assert s.name == "relay@1.0.0" and s.argv == ["python", "-I", "{bundle}/relay_module.py"] and s.concurrency == 1
    assert s.timeouts_s == {"default": 10.0, "job.plan": 30.0} and s.env["OMP_NUM_THREADS"] == "4"


def test_the_module_coordinator_runs_sandboxed(db):
    from oarbank.coordinator import sandboxexec
    modcalls.call(db, "toy", "params.check", {"params": {"n": 3}})
    pid = modcalls.host(db).health("toy")["pid"]
    assert pid and sandboxexec.is_confined(pid)
    assert (Path(db.path).parent / "run" / "sandbox" / "toy.sb").exists()


ESCAPE = r'''
import json, os, sys
H, home = os.environ["REAL_HOME"], os.environ["OARBANKD_HOME"]
r = {}
def t(n, f):
    try: f(); r[n] = True
    except Exception: r[n] = False
t("read_db", lambda: open(home + "/oarbank.sqlite3", "rb").read(16))
t("read_key", lambda: open(home + "/coordinator_key", "rb").read(1))
t("list_home", lambda: os.listdir(H))
t("write_bundle", lambda: open(os.path.dirname(__file__) + "/x", "w").write("x"))
t("write_data", lambda: open(os.environ["OARBANK_MODULE_DATA"] + "/x", "w").write("x"))
t("write_tmp", lambda: open(os.environ["TMPDIR"] + "x", "w").write("x"))
import socket
t("tcp", lambda: socket.create_connection(("1.1.1.1", 443), timeout=3).close())
print(json.dumps(r))
'''


def test_a_coordinator_process_cannot_reach_fleetd_state(tmp_path, db):
    from oarbank.coordinator import sandboxexec
    home = Path(db.path).parent
    (home / "coordinator_key").write_bytes(b"k")
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "escape.py").write_text(ESCAPE)
    pol = modsandbox.coordinator_policy(home, "escape", "dev.test.escape", bundle)
    env = {**modsandbox.coordinator_env(home, "escape"), "PATH": "/usr/bin:/bin", "REAL_HOME": os.path.expanduser("~"),
           "OARBANKD_HOME": str(home.resolve())}
    argv = sandboxexec.wrap(pol, modsandbox.profile_dir(home) / "escape.sb", [sys.executable, "-I", str(bundle / "escape.py")])
    p = subprocess.run(argv, cwd=bundle, env=env,
                       capture_output=True, text=True, timeout=60)
    r = json.loads(p.stdout)
    assert r["write_data"] and r["write_tmp"]
    assert not any(r[k] for k in ("read_db", "read_key", "list_home", "write_bundle", "tcp")), r


def _toy_with_sandbox(tmp_path, version="0.2.0") -> Path:
    src = tmp_path / "toy2"
    shutil.copytree(TOY_DIR, src)
    m = (src / "oarbank-module.toml").read_text().replace('version = "0.1.0"', f'version = "{version}"', 1)
    m += ('\n[sandbox]\nnet = { mode = "egress-allowlist", allow = ["api.example.org"] }\n'
          'tools = [{ id = "java17", trust = "code-exec" }]\n'
          'containers = [{ image = "docker.io/org/tool:1@sha256:' + "a" * 64 + '", platform = "linux/amd64" }]\n')
    (src / "oarbank-module.toml").write_text(m)
    return src


def test_grants_must_be_approved_before_a_version_runs_anywhere(tmp_path, db):
    from helpers import bundle
    r = modstore.install(db, bundle(_toy_with_sandbox(tmp_path)), actor="test", self_test=False)
    v = r["version"]
    with pytest.raises(modstore.LifecycleError, match="not approved"):
        modstore.canary(db, "toy", v, ["n1"])
    with pytest.raises(modstore.LifecycleError, match="not approved"):
        modstore.pin(db, "toy", "n1", v)
    plan = op(db, "modules.approve", f"toy@{v}", reason="t", dry_run=True)
    impact = json.dumps(plan, default=str)
    assert "api.example.org" in impact and "java17" in impact and "runs code" in impact and "linux/amd64" in impact
    planned(db, "modules.approve", f"toy@{v}", reason="reviewed")
    assert modsandbox.status(db, "toy", v)["approved"]
    modstore.canary(db, "toy", v, ["n1"])                 # now allowed
    entry = releases.module_entry("toy", v, r["content_digest"], r["path"], "darwin-arm64",
                                  {"java17": ["/opt/homebrew/opt/openjdk@17"]})
    assert entry["module_id"] == "dev.codonic.oarbank.toy"
    assert entry["sandbox"] == {"contract": 1, "net": {"mode": "egress-allowlist", "allow": ["api.example.org"]},
                                "tools": [{"id": "java17", "trust": "code-exec", "paths": ["/opt/homebrew/opt/openjdk@17"]}],
                                "devices": {"gpu": "none"}, "exec_writable": False,
                                "containers": [{"image": "docker.io/org/tool:1@sha256:" + "a" * 64, "platform": "linux/amd64"}]}


def test_tool_registry_maps_ids_per_os_and_reaches_the_release(tmp_path, db):
    from helpers import bundle, enrolled_node, fresh
    from oarbank.coordinator import platforms
    r = modstore.install(db, bundle(_toy_with_sandbox(tmp_path)), actor="test", self_test=False)
    planned(db, "modules.approve", f"toy@{r['version']}", reason="reviewed")
    with pytest.raises(Exception, match="not an absolute path"):
        planned(db, "settings.tools.update", "java17", params={"paths": {"darwin": ["opt/jdk"]}})
    with pytest.raises(Exception, match="not an absolute path"):
        planned(db, "settings.tools.update", "java17", params={"paths": {"windows": ["/opt/jdk"]}})
    with pytest.raises(Exception, match="no globs"):
        planned(db, "settings.tools.update", "java17", params={"paths": {"linux": ["/usr/lib/jvm/*"]}})
    planned(db, "settings.tools.update", "java17", reason="jdk", params={
        "trust": "code-exec", "paths": {"darwin": ["/opt/homebrew/opt/openjdk@17"], "windows": ["C:\\Program Files\\jdk-17"]}})
    assert platforms.tool_paths(db, ["java17"], "darwin") == (["/opt/homebrew/opt/openjdk@17"], [])
    assert platforms.tool_paths(db, ["java17"], "linux") == ([], ["java17"])
    from oarbank_sdk import manifest as mf
    man = mf.load(Path(r["path"]) / "oarbank-module.toml")
    _, mac = enrolled_node(db, "mac")
    _, box = enrolled_node(db, "box", facts={**json.loads(fresh(db, mac)["facts_json"]),
                                             "platform": {"os": "linux", "arch": "amd64", "os_version": "6.8"}})
    assert platforms.unsupported(db, man, fresh(db, mac)) is None
    assert platforms.unsupported(db, man, fresh(db, box)) == "TOOL_UNAVAILABLE"         # no Linux path registered


def test_a_version_that_requests_nothing_needs_no_approval(db):
    r = modstore.record(db, "toy", "0.1.0")
    assert modsandbox.status(db, "toy", "0.1.0")["approved"]
    e = releases.module_entry("toy", "0.1.0", r["content_digest"], r["path"])
    assert e["sandbox"] == {"contract": 1, "net": {"mode": "none", "allow": []}, "tools": [], "devices": {"gpu": "none"},
                            "exec_writable": False, "containers": []}
    with pytest.raises(Exception, match="requests no sandbox grants"):
        planned(db, "modules.approve", "toy@0.1.0")


def test_module_jobs_go_only_to_sandboxing_agents_that_are_new_enough(db, monkeypatch):
    from helpers import enrolled_node, fresh
    monkeypatch.setattr(modsandbox, "REQUIRE_SANDBOXED_AGENTS", True)
    from helpers import FACTS
    _, node = enrolled_node(db, "old")
    n = fresh(db, node)
    no_backend = {k: v for k, v in FACTS.items() if k != "sandbox"}
    db.x("UPDATE nodes SET facts_json=? WHERE node_id=?", (json.dumps(no_backend), n["node_id"]))
    assert modsandbox.node_exclusions(db, fresh(db, node), {"toy", "relay"}) == \
        {"toy": "SANDBOX_BACKEND_MISSING", "relay": "SANDBOX_BACKEND_MISSING"}
    db.x("UPDATE nodes SET facts_json=?, agent_version='0.6.0' WHERE node_id=?", (json.dumps(FACTS), n["node_id"]))
    assert modsandbox.node_excluded(db, fresh(db, node), {"toy", "relay"}) == set()
    # a backend that cannot enforce the always-on rules gets nothing
    weak = {**FACTS, "sandbox": {"backend": "landlock", "enforcement": {**FACTS["sandbox"]["enforcement"], "ipc": "cooperative"}}}
    db.x("UPDATE nodes SET facts_json=? WHERE node_id=?", (json.dumps(weak), n["node_id"]))
    assert modsandbox.node_exclusions(db, fresh(db, node), {"toy"}) == {"toy": "CAPABILITY_NOT_ENFORCED"}
    db.x("UPDATE nodes SET facts_json=? WHERE node_id=?", (json.dumps(FACTS), n["node_id"]))
    # a module version that needs a newer agent is withheld from this node only
    info = modcalls.info("toy")
    newer = info.manifest.model_copy(update={"requires": info.manifest.requires.model_copy(update={"agent": ">=0.7"})})
    import dataclasses
    monkeypatch.setitem(modcalls.CATALOG, "toy", dataclasses.replace(info, manifest=newer))
    assert modsandbox.node_exclusions(db, fresh(db, node), {"toy", "relay"}) == {"toy": "AGENT_TOO_OLD"}


def test_module_jobs_go_only_to_declared_platforms_and_os_versions(db, monkeypatch):
    from helpers import enrolled_node, facts_for, fresh
    import dataclasses
    _, box = enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8", kernel="6.8.0"))
    _, rv = enrolled_node(db, "rv", facts=facts_for("linux-riscv64"))
    assert modsandbox.node_exclusions(db, fresh(db, box), {"toy"}) == {}
    assert modsandbox.node_exclusions(db, fresh(db, rv), {"toy"}) == {"toy": "PLATFORM_UNSUPPORTED"}
    info = modcalls.info("toy")
    from oarbank_sdk import manifest as mf
    req = info.manifest.requires.model_copy(update={"os": mf.OSRequirements.model_validate({"linux": {"kernel": ">=6.10"}})})
    monkeypatch.setitem(modcalls.CATALOG, "toy", dataclasses.replace(info, manifest=info.manifest.model_copy(update={"requires": req})))
    assert modsandbox.node_exclusions(db, fresh(db, box), {"toy"}) == {"toy": "OS_VERSION_UNSUPPORTED"}
    # a node of a platform the fleet had no release for got one when it enrolled
    assert db.one("SELECT 1 FROM releases WHERE status='current' AND platform='linux-amd64'")


def test_explain_and_the_platform_matrix_give_the_modules_own_reason(db, monkeypatch):
    import dataclasses
    from helpers import READY, create_study, PARAMS, SCENES, certify, enrolled_node, facts_for, fresh
    from oarbank.coordinator import explain
    info = modcalls.info("relay")
    req = info.manifest.requires.model_copy(update={"unsupported": mf.Unsupported(runner={"linux-riscv64": "no riscv64 renderer"})})
    monkeypatch.setitem(modcalls.CATALOG, "relay", dataclasses.replace(info, manifest=info.manifest.model_copy(update={"requires": req})))
    rv = certify(db, enrolled_node(db, "rv", facts=facts_for("linux-riscv64"))[1])
    certify(db, enrolled_node(db, "mini")[1])
    create_study(db, "why", [], SCENES[:1], {"label": "base", "params": PARAMS})
    job = db.one("SELECT job_id FROM jobs WHERE module='relay' AND state='pending'")
    doc = explain.job_doc(db, job["job_id"], bodies={rv["node_id"]: {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY}})
    row = next(r for r in doc.matrix if r.node == "rv")
    bad = next(r for r in row.results if r.predicate == "module_runs_here(relay)")
    assert (bad.outcome, bad.code, bad.observed) == ("fail", "PLATFORM_UNSUPPORTED", "no riscv64 renderer")
    m = modcalls.platform_matrix(db, "relay")
    rows = {p["platform"]: p for p in m["platforms"]}
    assert rows["linux-riscv64"] == {"platform": "linux-riscv64", "here": False, "runner": False, "runner_reason": "no riscv64 renderer",
                                     "coordinator": True, "coordinator_reason": None, "nodes": 1, "certified": 0}
    assert (rows["darwin-arm64"]["runner"], rows["darwin-arm64"]["nodes"], rows["darwin-arm64"]["certified"]) == (True, 1, 1)
    assert set(portable.KNOWN_PLATFORMS) <= set(rows) and rows[portable.host_platform()]["here"]
    assert m["coordinator_unsupported"] is None


def test_a_coordinator_without_a_sandbox_backend_refuses_to_start_modules(tmp_path, monkeypatch):
    from oarbank.coordinator.modulehost import ModuleHost, ModuleSpec, ModuleUnavailable
    monkeypatch.setattr(modsandbox, "backend", lambda: None)
    pol = modsandbox.coordinator_policy(tmp_path, "toy", "dev.codonic.oarbank.toy", TOY_DIR)
    assert isinstance(pol, modsandbox.NoBackend)
    h = ModuleHost([ModuleSpec(name="toy", argv=["python", "-I", "{bundle}/toy_module.py"], cwd=str(TOY_DIR), sandbox=pol,
                               profile_dir=str(modsandbox.profile_dir(tmp_path)))], home=tmp_path)
    with pytest.raises(ModuleUnavailable, match="no module sandbox backend"):
        h._ensure("toy")
    h.close()
