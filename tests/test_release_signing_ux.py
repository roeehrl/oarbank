"""What the owner sees and does between enabling a module and its first job, with release signing on: releases are
built once per platform and composition (not on every hello), the ones waiting for the owner's signature are named
with the exact command (banner, alert, `oarbank release list`), nodes say why they run no release (NO_RELEASE,
RELEASE_UNSIGNED, RELEASE_PENDING), and a module's readiness checklist walks every step to its first operation."""
import json
import shutil
from pathlib import Path

import pytest

from oarbank import signing
from oarbank.contracts import reason_codes as RC
from oarbank.coordinator import clock, core, explain, modsandbox, modstore, ops, readiness, releases
from oarbank.coordinator import config as C

from helpers import FACTS, TOY_DIR, bundle, enrolled_node, facts_for, fresh, install, make_db

WIN = facts_for("windows-amd64", os_version="10.0.26100")


@pytest.fixture
def signing_on(monkeypatch):
    monkeypatch.setattr(C, "RELEASE_SIGNING", True)


@pytest.fixture
def db(tmp_path, signing_on):
    """A fleet with the owner key pinned and no module yet: a Mac and a Windows PC enrolled."""
    clock.set_fake(None)
    d = make_db(tmp_path / "oarbank.sqlite3", modules=())
    d.x("DELETE FROM releases")                                # make_db's empty release: a fresh install has none
    d.x("DELETE FROM events WHERE kind LIKE 'release_%'")
    d.set_state(releases.DEFAULTS, {})
    d.set_state("release_pubkey", signing.keygen(tmp_path / "keys" / "release.key"))
    d.key = tmp_path / "keys" / "release.key"
    yield d
    d.conn.close()


def hello(db, node, release_id=None, facts=FACTS):
    return core.hello(db, fresh(db, node), {"release_id": release_id, "facts": facts, "live_attempts": []})


def sign(db, rid, promote=True):
    rows = db.q("SELECT seq FROM releases WHERE signature IS NOT NULL")
    seq = max([r["seq"] or 0 for r in rows] + [0]) + 1
    sha = db.one("SELECT sha256 FROM releases WHERE release_id=?", (rid,))["sha256"]
    stmt = signing.statement(rid, sha, seq)
    releases.attach_signature(db, rid, stmt, signing.sign(stmt, db.key))
    if promote:
        releases.promote(db, rid, "owner")


def built(db):
    return [json.loads(e["payload_json"] or "{}") | {"reason": e["reason"]}
            for e in db.q("SELECT reason, payload_json FROM events WHERE kind='release_built' ORDER BY event_id")]


def op(db, op_id, target=None, params=None):
    return ops.execute(db, ops.OpRequest(op=op_id, actor="test", source="system", target=target, params=params or {},
                                         reason="test", idempotency_key=None))


# ------------------------------------------------------------------ 1. one build per platform and composition

def test_hellos_build_each_platform_once_while_its_release_waits_for_the_signature(db):
    _, mac = enrolled_node(db, "mac")
    _, pc = enrolled_node(db, "pc", facts=WIN)
    assert not built(db)                                       # no module: nothing to build, not even an empty release
    install(db, TOY_DIR)
    releases.sync(db)                                           # what enabling does (ops._after_lifecycle)
    assert sorted(e["reason"].split(" ")[1] for e in built(db)) == ["(darwin-arm64)", "(windows-amd64)"]
    for _ in range(5):
        hello(db, mac)
        hello(db, pc, facts=WIN)
    releases.ensure_fleet(db)
    assert len(built(db)) == 2                                  # N hellos: still one build per platform
    assert db.one("SELECT COUNT(*) n FROM releases")["n"] == 2
    assert not db.q("SELECT 1 FROM releases WHERE status='current'")
    assert all(e["next"].endswith("--promote") for e in built(db))


def test_a_changed_composition_builds_again_and_a_signed_release_is_not_rebuilt(db):
    _, mac = enrolled_node(db, "mac")
    install(db, TOY_DIR)
    releases.sync(db)
    rid = releases.awaiting(db)[0]["release_id"]
    sign(db, rid)
    hello(db, mac, rid)
    assert len(built(db)) == 1 and releases.awaiting(db) == []
    modstore.disable(db, "toy")                                 # the kill switch keeps the composition
    hello(db, mac, rid)
    assert len(built(db)) == 1


def test_build_operation_builds_every_platform_and_refuses_without_a_module(db):
    enrolled_node(db, "mac")
    enrolled_node(db, "pc", facts=WIN)
    with pytest.raises(core.ApiError) as e:
        op(db, "releases.build")
    assert e.value.status == 409 and "No module is enabled" in e.value.detail
    assert not db.q("SELECT 1 FROM releases")
    install(db, TOY_DIR)
    out = op(db, "releases.build")["result"]
    assert sorted(r["platform"] for r in out["releases"]) == ["darwin-arm64", "windows-amd64"]
    assert all(r["needs_signature"] and r["next"] == f"oarbank release sign {r['release_id']} --promote" for r in out["releases"])
    assert {a["release_id"] for a in out["awaiting"]} == {r["release_id"] for r in out["releases"]}


# ------------------------------------------------------------------ 2. waiting releases: named, alerted, cleared

def test_awaiting_releases_raise_one_alert_each_that_clears_when_signed_or_superseded(db):
    _, mac = enrolled_node(db, "mac")
    enrolled_node(db, "pc", facts=WIN)
    install(db, TOY_DIR)
    releases.sync(db)
    wait = {a["platform"]: a for a in releases.awaiting(db)}
    assert set(wait) == {"darwin-arm64", "windows-amd64"} and wait["darwin-arm64"]["nodes"] == ["mac"]
    assert db.get_state(releases.AWAITING) == releases.awaiting(db)        # what the console reads
    alerts = {a["rule"]: a for a in db.q("SELECT * FROM alerts WHERE state IN ('open','pending')")}
    mac_rule = f"release_awaiting_owner:{wait['darwin-arm64']['release_id']}"
    assert set(alerts) == {f"release_awaiting_owner:{a['release_id']}" for a in wait.values()}
    assert f"oarbank release sign {wait['darwin-arm64']['release_id']} --promote" in alerts[mac_rule]["detail"]
    assert "(toy@0.1.0)" in alerts[mac_rule]["detail"] and wait["windows-amd64"]["modules"] == ["toy@0.1.0"]
    assert alerts[mac_rule]["state"] == "pending"                          # the owner may sign within its 5 minutes
    from oarbank.contracts.alert_rules import policy
    assert policy(mac_rule)["severity"] == "P3" and "oarbank release sign" in policy(mac_rule)["runbook"]
    sign(db, wait["darwin-arm64"]["release_id"])
    assert [a["platform"] for a in releases.awaiting(db)] == ["windows-amd64"]
    assert not db.q("SELECT 1 FROM alerts WHERE rule=? AND state IN ('open','pending')", (mac_rule,))
    # a newer build replaces the windows candidate: its alert goes, the new one's opens
    old = wait["windows-amd64"]["release_id"]
    install(db, Path(__file__).parent / "fixtures" / "modules" / "relay")
    releases.sync(db)
    new = {a["platform"]: a["release_id"] for a in releases.awaiting(db)}
    assert new["windows-amd64"] != old
    assert not db.q("SELECT 1 FROM alerts WHERE rule=? AND state IN ('open','pending')", (f"release_awaiting_owner:{old}",))
    assert db.q("SELECT 1 FROM alerts WHERE rule=? AND state IN ('open','pending')", (f"release_awaiting_owner:{new['windows-amd64']}",))


def test_nothing_waits_in_developer_mode(db, monkeypatch):
    monkeypatch.setattr(C, "RELEASE_SIGNING", False)
    enrolled_node(db, "mac")
    install(db, TOY_DIR)
    releases.sync(db)
    assert releases.awaiting(db) == [] and db.q("SELECT 1 FROM releases WHERE status='current'")


def test_an_upgraded_fleet_learns_its_waiting_releases_without_a_rebuild(db):
    """Releases built by an older coordinator (no record of each platform's default): ensure() adopts the candidate."""
    enrolled_node(db, "mac")
    install(db, TOY_DIR)
    releases.sync(db)
    db.set_state(releases.DEFAULTS, {})
    db.set_state(releases.AWAITING, [])
    releases.ensure_fleet(db)
    assert len(built(db)) == 1 and [a["platform"] for a in releases.awaiting(db)] == ["darwin-arm64"]


# ------------------------------------------------------------------ 3. why a node runs no release

def test_node_reason_codes_name_the_release_state(db):
    _, mac = enrolled_node(db, "mac")
    nv = lambda: core.node_view_for_claim(db, fresh(db, mac), set(), set(), 8, 32, {})
    from oarbank.coordinator import predicates
    assert predicates.first_failure(predicates.admission(nv())).code == "NO_RELEASE"
    doc = explain.node_doc(db, mac["node_id"])
    assert doc.headline.code == "NO_RELEASE" and "install and enable a module" in doc.headline.text
    install(db, TOY_DIR)
    releases.sync(db)
    rid = releases.awaiting(db)[0]["release_id"]
    assert predicates.first_failure(predicates.admission(nv())).code == "RELEASE_UNSIGNED"
    doc = explain.node_doc(db, mac["node_id"])
    assert doc.headline.text == "Not admitting: " + RC.REGISTRY["RELEASE_UNSIGNED"].render(release=rid, platform="darwin-arm64")
    assert f"oarbank release sign {rid} --promote" in doc.headline.text
    assert [r.op for r in doc.remedies] == ["releases.attach_signature"]
    sign(db, rid)
    assert predicates.first_failure(predicates.admission(nv())).code == "RELEASE_PENDING"   # signed: it is installing


def test_hello_event_says_where_the_node_stands_with_its_release(db):
    _, mac = enrolled_node(db, "mac")
    last = lambda: json.loads(db.one("SELECT payload_json FROM events WHERE kind='hello' ORDER BY event_id DESC LIMIT 1")["payload_json"])
    hello(db, mac)
    assert last()["release"] == "none yet (no module enabled)" and "release_id" not in last()
    install(db, TOY_DIR)
    releases.sync(db)
    rid = releases.awaiting(db)[0]["release_id"]
    hello(db, mac)
    assert last()["release"] == f"waiting for signature: {rid}"
    sign(db, rid)
    hello(db, mac)
    assert last()["release"] == f"installing {rid}"
    hello(db, mac, rid)
    assert last()["release"] == rid and fresh(db, mac)["lifecycle"] == "ready"


# ------------------------------------------------------------------ 4. the readiness checklist

def javatoy(tmp_path) -> Path:
    """toy, asking for a host JDK 17 or newer (tool jdk), a java17 capability and a container per job, on macOS and Linux
    only."""
    src = tmp_path / "javatoy"
    shutil.copytree(TOY_DIR, src)
    t = (src / "oarbank-module.toml").read_text(encoding="utf-8")
    t = t.replace('id = "dev.codonic.oarbank.toy"', 'id = "dev.codonic.oarbank.javatoy"')
    t = t.replace('core = ">=2.1,<3"', 'core = ">=2.5,<3"')
    t = t.replace('platforms = ["darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64", "windows-arm64", "windows-amd64"]',
                  'platforms = ["darwin-arm64", "linux-amd64"]')
    t = t.replace("[coordinator]\n", '[requires.unsupported]\nrunner = { windows = "no JVM build for Windows" }\n\n[coordinator]\n', 1)
    t = t.replace('requires.resources = { cpu = 1, mem_gb = 0.1 }',
                  'requires = { capabilities = ["java17"], pools = { containers = 1 }, resources = { cpu = 1, mem_gb = 0.1 } }\n\n'
                  '[sandbox]\ncontract = 1\ntools = [{ id = "jdk", version = ">=17", trust = "code-exec" }]\n'
                  'containers = [{ image = "quay.io/biocontainers/bcftools:1.20--h8b25389_0@sha256:' + "b" * 64 + '", '
                  'platform = "linux/amd64" }]\n\n[[probes]]\nname = "java17"\nexec = ["python", "-I", "{bundle}/toy_runner.py"]\n')
    t = t.replace("runner_protocol = [1]\n", "runner_protocol = [1]\nservice_protocol = [1]\n", 1)
    (src / "oarbank-module.toml").write_text(t, encoding="utf-8")
    return src


def steps(r):
    return {s["id"]: s for s in r["steps"]}


def test_readiness_walks_every_blocker_to_the_first_operation(db, tmp_path):
    _, mac = enrolled_node(db, "mac")
    _, pc = enrolled_node(db, "pc", facts=WIN)
    src = javatoy(tmp_path)
    r = modstore.install(db, bundle(src), actor="test", self_test=False)
    name = r["name"]
    s = steps(readiness.module(db, name))
    assert s["installed"]["status"] == "done"
    assert s["grants"]["status"] == "blocked" and s["grants"]["actions"][0]["op"] == "modules.approve"
    assert s["enabled"]["status"] == "waiting"
    modsandbox.approve(db, name, r["version"], "test", None)
    s = steps(readiness.module(db, name))
    assert s["grants"]["status"] == "done" and s["enabled"]["status"] == "blocked"
    assert s["enabled"]["actions"][0] == {"label": "Enable", "op": "modules.enable", "target": f"{name}@{r['version']}",
                                          "command": f"oarbank module enable {name}@{r['version']}"}
    modstore.enable(db, name, r["version"])
    releases.sync(db)
    rd = readiness.module(db, name)
    s = steps(rd)
    # where it runs: the Windows PC is not counted as missing, it is not a platform the module supports
    texts = [i["text"] for i in s["platforms"]["items"]]
    assert any(t.startswith("windows-amd64: not a platform it supports (pc): no JVM build for Windows") for t in texts)
    assert s["built"]["status"] == "done"
    wait = {a["platform"]: a["release_id"] for a in releases.awaiting(db)}
    sign_items = [i for i in s["signed"]["items"] if i.get("sign")]
    assert s["signed"]["status"] == "blocked" and {i["command"] for i in sign_items} == {
        f"oarbank release sign {wait['darwin-arm64']} --promote", f"oarbank release sign {wait['windows-amd64']} --promote"}
    # host tools: per request, how many nodes resolve it and why the others do not (tools.resolution)
    assert s["tools"]["status"] == "blocked" and s["tools"]["actions"][0]["href"] == f"/modules/{name}/nodes"
    item = s["tools"]["items"][0]
    assert item["text"] == "jdk >=17: 0 of 1 node" and item["groups"][0]["nodes"] == ["mac"]
    assert "jdk not reported yet" in item["groups"][0]["reasons"][0]
    nodes = s["nodes"]
    assert nodes["status"] == "blocked"
    every = nodes["items"][0]
    assert every["groups"][0]["nodes"] == ["mac"] and every["groups"][0]["reasons"][0].startswith("jdk >=17: jdk not reported yet")
    run = next(i for i in nodes["items"] if i.get("stage") == "run")
    reasons = run["groups"][0]["reasons"]
    assert any(x.startswith("java17 not reported") for x in reasons)
    assert any("no container runtime reported: install Colima and Docker" in x for x in reasons)
    assert "pc" not in json.dumps(nodes["items"])                  # the unsupported PC is never a reason
    assert steps(rd)["certified"]["status"] == "waiting"
    nxt = s["next"]
    assert nxt["status"] == "next" and [o["verb"] for o in nxt["items"]][:2] == ["set_favorite", "queue_sums"]
    assert nxt["items"][0]["op"] == "mod.javatoy.set_favorite"
    assert rd["state"] == "blocked"
    assert rd["summary"] == "needs: sign 2 releases, jdk on a node, a node for run"

    # the Mac reports the JDK 11 it has: too old, with the command that installs one the module accepts
    core.heartbeat(db, fresh(db, mac), {"attempts": [], "tools": {"detected_at": 1.0, "native_arch": "arm64", "tools": {"jdk": [
        {"path": "/usr/local/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home", "version": "11.0.2", "arch": "x86_64",
         "source": "detected", "status": "ok"}]}}})
    item = steps(readiness.module(db, name))["tools"]["items"][0]
    assert item["groups"] == [{"reasons": ["found 11.0.2 (x86_64) at /usr/local/opt/openjdk@11/libexec/openjdk.jdk/Contents/Home; "
                                           "needs >=17 → brew install openjdk@17"], "nodes": ["mac"]}]
    assert item["counts"] == {"TOOL_VERSION_UNMET": 1}

    # the owner fixes it: signs, the Mac installs a JDK 17 and the release, and reports java17 and a container runtime
    for rid in wait.values():
        sign(db, rid)
    hello(db, mac, wait["darwin-arm64"])
    core.heartbeat(db, fresh(db, mac), {"doctor": {"capabilities": ["java17"], "modules": {name: {"health": "healthy", "checks": []}}},
                                        "attempts": [], "capacity": {"cpu_slots": 4, "pools": {"containers": 2}},
                                        "tools": {"detected_at": 2.0, "native_arch": "arm64", "tools": {"jdk": [
                                            {"path": "/opt/homebrew/Cellar/openjdk@17/17.0.12/libexec/openjdk.jdk/Contents/Home",
                                             "version": "17.0.12", "arch": "aarch64", "source": "detected", "status": "ok"}]}}})
    rd = readiness.module(db, name)
    s = steps(rd)
    assert [s[k]["status"] for k in ("signed", "tools", "nodes")] == ["done", "done", "done"]
    assert s["certified"]["status"] in ("waiting", "done")
    assert rd["state"] in ("waiting", "ready") and not rd["needs"]


def test_readiness_api_and_cli_print_every_step(db, tmp_path, capsys):
    from fastapi.testclient import TestClient
    from oarbank.cli import main as cli
    from oarbank.coordinator import app as coord_app
    from helpers import admin_headers
    enrolled_node(db, "mac")
    install(db, TOY_DIR)
    releases.sync(db)
    c = TestClient(coord_app.admin_app(db), client=("127.0.0.1", 50001))
    h = admin_headers(db)
    one = c.get("/api/v1/modules/toy/readiness", headers=h).json()
    assert one["name"] == "toy" and one["state"] == "blocked" and one["needs"] == ["sign 1 release"]
    assert [r["name"] for r in c.get("/api/v1/modules/readiness", headers=h).json()] == ["toy"]
    assert c.get("/api/v1/modules/nope/readiness", headers=h).status_code == 404
    rels = c.get("/api/v1/releases", headers=h).json()
    assert rels[0]["platform"] == "darwin-arm64" and rels[0]["awaiting"]["command"].endswith("--promote")
    assert rels[0]["modules"] == ["toy@0.1.0"] and rels[0]["awaiting"]["modules"] == ["toy@0.1.0"]
    cli.print_readiness(one)
    out = capsys.readouterr().out
    assert "[BLOCKED] Release signed and current per platform" in out and f"oarbank release sign {rels[0]['release_id']} --promote" in out
    assert "[next]" in out and "oarbank op mod.toy.set_favorite" in out


# ------------------------------------------------------------------ 5. the console says it

def test_console_names_waiting_releases_and_the_readiness_checklist(db, tmp_path):
    import httpx
    from fastapi.testclient import TestClient
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from oarbank.coordinator import app as coord_app
    from helpers import sign_in
    from test_console import SECRET, Server
    _, mac = enrolled_node(db, "mac")
    enrolled_node(db, "pc", facts=WIN)
    src = javatoy(tmp_path)
    r = modstore.install(db, bundle(src), actor="test", self_test=False)
    modsandbox.approve(db, r["name"], r["version"], "test", None)
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(db.path, f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        state.poll_fleetd(httpx.Client())
        with TestClient(console_app(state), client=("127.0.0.1", 50001)) as c:
            sign_in(c, db)
            state.rebuild()
            fleet = c.get("/").text
            assert "release-wait" not in fleet and "waiting for a release: install and enable a module" in fleet
            assert "Build releases" not in c.get("/settings").text          # nothing to build before a module is enabled
            modstore.enable(db, r["name"], r["version"])
            ops._after_lifecycle(db)                                      # what modules.enable does next
            wait = {a["platform"]: a["release_id"] for a in releases.awaiting(db)}
            state.rebuild()
            fleet = c.get("/").text
            assert "2 releases waiting for your signature." in fleet
            for rid in wait.values():
                assert f"oarbank release sign {rid} --promote" in fleet
            assert "release needs your signature" in fleet                   # the enrolled nodes' chip
            mods = c.get("/modules").text
            assert "2 releases waiting for your signature." in mods
            assert "needs: sign 2 releases, jdk on a node, a node for run" in mods and "Getting it running" in mods
            page = c.get(f"/modules/{r['name']}")
            assert page.status_code == 200 and "script-src 'self'" in page.headers["content-security-policy"]
            html = page.text
            assert "Getting this module running" in html and f"/modules/{r['name']}/nodes" in html
            assert "not a platform it supports (pc): no JVM build for Windows" in html
            assert "no container runtime reported: install Colima and Docker" in html
            assert 'action="/do/mod.javatoy.set_favorite"' in html and "oarbank op mod.javatoy.queue_sums" in html
            settings = c.get("/settings", params={"tool": "samtools"}).text
            assert 'value="samtools"' in settings and "Define it" in settings
            assert "needs your signature" in settings and "Build releases" in settings
            assert f"{r['name']}@{r['version']}" in settings and "(no module)" in settings      # each release's contents
            assert 'value="x&lt;y"' not in c.get("/settings", params={"tool": "x<y"}).text   # only a tool id is prefilled


def test_release_list_shows_platform_status_contents_and_the_command(db, monkeypatch, capsys):
    import argparse
    from fastapi.testclient import TestClient
    from oarbank.cli import main as cli
    from oarbank.coordinator import app as coord_app
    from helpers import admin_headers
    enrolled_node(db, "mac")
    enrolled_node(db, "pc", facts=WIN)
    install(db, TOY_DIR)
    releases.sync(db)
    c, h = TestClient(coord_app.admin_app(db), client=("127.0.0.1", 50001)), admin_headers(db)
    monkeypatch.setattr(cli, "api", lambda method, path, **kw: c.request(method, path, headers=h).json())
    cli.cmd_release(argparse.Namespace(action="list", target=None, key=None, promote=False, rotate=False, reason=None, yes=True))
    out = capsys.readouterr().out
    for a in releases.awaiting(db):
        row = next(line for line in out.splitlines() if line.startswith(a["release_id"]))
        assert a["platform"] in row and "candidate" in row and "UNSIGNED" in row and "toy@0.1.0" in row
        assert "waiting for your signature" in row and f"    oarbank release sign {a['release_id']} --promote" in out
    assert "2 releases waiting for your signature" in out
