"""Host tools (docs/design/host-tools.md): definitions at the fleet, detection on the node, overrides of two kinds,
module version constraints, per-node placement reasons with their fixes, the readiness step, the API and console, and
the one-shot migration of the old per-OS tool registry."""
import base64
import json
import shutil
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oarbank.coordinator import core, modsandbox, modstore, readiness, releases, statements, tools
from oarbank.coordinator.db import DB

import tool_vectors
from helpers import FACTS, TOY_DIR, bundle, enrolled_node, facts_for, fresh, make_db, run_op

REPO = Path(__file__).parents[1]


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def report(db, node, insts: dict, native="arm64"):
    """A heartbeat carrying the node's tool detection, as its agent sends it."""
    core.heartbeat(db, fresh(db, node), {"attempts": [], "tools": {"detected_at": 1.0, "native_arch": native, "tools": insts}})
    return fresh(db, node)


def jdk(path, version, arch="aarch64", status="ok", source="detected", **kw):
    return {"path": path, "version": version, "arch": arch, "vendor": "Test", "source": source, "status": status,
            "detected_at": 1.0, **kw}


def javatoy(tmp_path, tools_toml='{ id = "jdk", version = ">=17", trust = "code-exec" }', version="0.3.0") -> Path:
    src = tmp_path / f"javatoy-{version}"
    shutil.copytree(TOY_DIR, src)
    t = (src / "oarbank-module.toml").read_text(encoding="utf-8")
    t = t.replace('version = "0.1.0"', f'version = "{version}"', 1).replace('id = "dev.codonic.oarbank.toy"',
                                                                           'id = "dev.codonic.oarbank.javatoy"')
    (src / "oarbank-module.toml").write_text(t + f"\n[sandbox]\ntools = [{tools_toml}]\n", encoding="utf-8")
    return src


def installed(db, src):
    r = modstore.install(db, bundle(src), actor="test", self_test=False)
    modsandbox.approve(db, r["name"], r["version"], "test", None)
    if modstore.channel(db, r["name"])["current"] != r["version"]:
        modstore.enable(db, r["name"], r["version"])
    from oarbank.coordinator import modcalls
    modcalls.use(db)
    return r


# ------------------------------------------------------------------------------------------------ shared rules

def test_resolution_matches_the_vectors_the_agent_replays():
    path = REPO / "src" / "oarbank" / "contracts" / "vectors" / "tool-resolution.json"
    assert path.read_text(encoding="utf-8") == tool_vectors.document(), "regenerate: uv run python tests/tool_vectors.py"


def test_the_builtin_table_is_the_agents():
    got = json.loads((REPO / "rust" / "crates" / "oarbank-agent" / "src" / "builtin_tools.json").read_text(encoding="utf-8"))
    assert got == tools.BUILTIN


def test_search_patterns_and_definitions_are_checked():
    for ok in ["/opt/java/*/Contents/Home", "$JAVA_HOME", "$TOOLS/jdk-*", "C:\\Tools\\jdk-*", "/usr/lib/jvm/java-1?-*"]:
        assert tools.check_pattern(ok) == ok
    for bad, why in [("relative/*", "absolute"), ("/", "root"), ("/*/jdk", "literal"), ("/opt/[ab]", "only"),
                     ("/opt/**/jdk", "only"), ("/opt/../etc", "'..'"), ("", "non-empty"), ("C:\\*\\jdk", "literal")]:
        with pytest.raises(tools.ToolError, match=why):
            tools.check_pattern(bad)
    assert tools.check_definition("jdk", {"search": {"darwin": ["/opt/java/*"], "fleet": "$JDKS/*"}}) == {
        "kind": "jdk", "search": {"darwin": ["/opt/java/*"], "fleet": ["$JDKS/*"]}}
    with pytest.raises(tools.ToolError, match="built in"):
        tools.check_definition("jdk", {"kind": "executable", "search": {"linux": ["/x"]}})
    with pytest.raises(tools.ToolError, match="needs search paths"):
        tools.check_definition("samtools", {"version": {"args": ["--version"], "regex": "samtools (\\S+)"}})
    for rx, why in [("(?<=x)1", "look-around"), ("(a)(b)", "one capture group"), ("(", "version.regex")]:
        with pytest.raises(tools.ToolError, match=why):
            tools.check_definition("samtools", {"search": {"linux": ["/usr/bin/samtools"]}, "version": {"args": [], "regex": rx}})
    with pytest.raises(tools.ToolError, match="unknown scope"):
        tools.check_definition("jdk", {"search": {"freebsd": ["/x"]}})


def test_install_commands_name_a_version_the_request_accepts():
    req = lambda v: {"id": "jdk", "version": v, "arch": "any"}
    assert tools.install_command("jdk", req(">=17"), "darwin") == "brew install openjdk@17"
    assert tools.install_command("jdk", req(">=17, <22"), "linux") == "sudo apt install openjdk-17-jdk-headless"
    assert tools.install_command("jdk", req(">=18"), "windows") == "winget install EclipseAdoptium.Temurin.21.JDK"
    assert tools.install_command("jdk", req(None), "darwin") == "brew install openjdk@8"
    assert tools.install_command("python", {"id": "python", "version": "~> 3.11"}, "darwin") == "brew install python@3.13"
    assert tools.install_command("executable", req(None), "linux") is None


# ------------------------------------------------------------------------------------------------ definitions and releases

def test_definitions_reach_the_release_and_requests_never_carry_paths(db, tmp_path):
    r = installed(db, javatoy(tmp_path, '{ id = "jdk", version = ">=17,<22", arch = "native", trust = "code-exec" }'))
    run_op(db, "tools.define", "jdk", params={"search": {"darwin": ["/opt/java/*"], "fleet": ["$JDKS/*"]}})
    run_op(db, "tools.define", "samtools", params={"search": {"linux": ["/usr/bin/samtools"]},
                                                   "version": {"args": ["--version"], "regex": "samtools (\\d+(?:\\.\\d+)*)"}})
    rid = db.one("SELECT release_id, path FROM releases WHERE status='current' AND platform='darwin-arm64'")
    import tarfile
    with tarfile.open(db.abs(rid["path"])) as t:
        doc = json.loads(t.extractfile("modules.json").read())
    assert doc["tools"]["jdk"] == {"kind": "jdk", "search": ["$JDKS/*", "/opt/java/*"]}
    assert doc["tools"]["samtools"] == {"kind": "executable", "search": [],
                                        "version": {"args": ["--version"], "regex": "samtools (\\d+(?:\\.\\d+)*)"}}
    assert doc["tools"]["python"]["search"] == []
    entry = next(m for m in doc["modules"] if m["name"] == r["name"])
    assert entry["sandbox"]["tools"] == [{"id": "jdk", "trust": "code-exec", "version": ">=17, <22", "arch": "native"}]
    # the grant digest covers the constraint: another range is another approval
    req = modsandbox.status(db, r["name"], r["version"])["requests"]
    assert req["tools"] == [{"id": "jdk", "trust": "code-exec", "version": ">=17, <22", "arch": "native"}]
    assert "host tools jdk >=17, <22 (native) (runs code)" in modsandbox.describe(req)
    out = run_op(db, "tools.delete", "samtools")
    assert out["result"] == {"tool": "samtools", "builtin": False} and "samtools" not in tools.definitions(db)
    run_op(db, "tools.delete", "jdk")
    assert tools.definitions(db)["jdk"]["search"] == {} and tools.definitions(db)["jdk"]["builtin_search"]["darwin"]


# ------------------------------------------------------------------------------------------------ placement

def test_each_node_gets_a_reason_from_its_own_report(db, tmp_path):
    r = installed(db, javatoy(tmp_path))
    name = r["name"]
    _, mac = enrolled_node(db, "mac")
    _, old = enrolled_node(db, "old")
    _, bad = enrolled_node(db, "bad")
    _, quiet = enrolled_node(db, "quiet")
    _, box = enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))
    report(db, mac, {"jdk": [jdk("/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home", "17.0.12")]})
    report(db, old, {"jdk": [jdk("/usr/bin/java-home", "11.0.2")]})
    report(db, bad, {"jdk": [jdk("/Users/me/Documents", None, None, "refused: not a jdk installation", "override")]})
    report(db, box, {"jdk": []}, native="amd64")
    man = modsandbox._manifest(db, name, r["version"])[0]
    why = lambda n: (modsandbox.exclusion(db, man, fresh(db, n), name), (tools.unmet(db, man, fresh(db, n), name) or (None, None))[1])
    assert why(mac) == (None, None)
    assert why(old) == ("TOOL_VERSION_UNMET", "jdk >=17: found 11.0.2 at /usr/bin/java-home; needs >=17")
    assert why(bad) == ("TOOL_REFUSED", "jdk >=17: /Users/me/Documents: not a jdk installation")
    assert why(quiet)[0] == "TOOL_NOT_FOUND" and "not reported yet" in why(quiet)[1]
    assert why(box) == ("TOOL_NOT_FOUND", "jdk >=17: no jdk found on this node")
    # the readiness step counts the nodes per request, with the fix for each
    rows = tools.resolution(db, name, man, [fresh(db, n) for n in (mac, old, bad, quiet, box)])
    assert rows[0]["ok"] == ["mac"] and rows[0]["need"] == "jdk >=17"
    failed = {h: w for h, w, _ in rows[0]["failed"]}
    assert failed["old"] == "found 11.0.2 at /usr/bin/java-home; needs >=17 → brew install openjdk@17"
    assert failed["box"] == "not found → sudo apt install openjdk-17-jdk-headless"
    step = next(s for s in readiness.module(db, name)["steps"] if s["id"] == "tools")
    assert step["status"] == "done" and step["items"][0]["text"].startswith("jdk >=17: 1 of 5 nodes (mac)")
    # fixes per node, most direct first
    res = tools.resolve_for(db, fresh(db, old), name, {"id": "jdk", "version": ">=17", "arch": "any"})
    labels = [f["label"] for f in tools.fixes(db, fresh(db, old), name, {"id": "jdk", "version": ">=17", "arch": "any"}, res)]
    assert labels == ["Install on old", "Re-detect", "Set path on this node", "Add a search path for macOS"]


def test_a_module_asking_for_an_unknown_tool_id_needs_a_new_version(db, tmp_path):
    r = installed(db, javatoy(tmp_path, '{ id = "java17", trust = "code-exec" }'))
    _, mac = enrolled_node(db, "mac")
    report(db, mac, {"jdk": [jdk("/opt/jdk-17", "17.0.12")]})
    man = modsandbox._manifest(db, r["name"], r["version"])[0]
    assert tools.unmet(db, man, fresh(db, mac), r["name"])[0] == "TOOL_NOT_FOUND"
    rd = readiness.module(db, r["name"])
    step = next(s for s in rd["steps"] if s["id"] == "tools")
    assert step["status"] == "blocked" and "unknown tool id and needs a new module version" in step["items"][0]["text"]
    assert "'java17', which this fleet does not define" in step["reason"]
    assert "a new version (unknown tool java17)" in rd["summary"]


# ------------------------------------------------------------------------------------------------ overrides

def test_choosing_among_what_was_found_is_a_pin_and_adding_a_path_goes_into_the_signed_statement(db, tmp_path):
    r = installed(db, javatoy(tmp_path))
    name = r["name"]
    _, mac = enrolled_node(db, "mac")
    report(db, mac, {"jdk": [jdk("/opt/jdk-17", "17.0.12"), jdk("/opt/jdk-21", "21.0.4")]})
    req = {"id": "jdk", "version": ">=17", "arch": "any"}
    assert tools.resolve_for(db, fresh(db, mac), name, req)["installation"]["path"] == "/opt/jdk-21"
    nid = mac["node_id"]
    out = run_op(db, "tools.set_path", nid, params={"tool": "jdk", "path": "/opt/jdk-17", "module": name})
    assert out["result"]["value"]["kind"] == "choose" and not out["result"]["statement"]
    res = tools.resolve_for(db, fresh(db, mac), name, req)
    assert (res["installation"]["path"], res["source"], res["override"]["module"]) == ("/opt/jdk-17", "pinned", name)
    d = core.heartbeat(db, fresh(db, mac), {"attempts": []})
    assert d["tool_pins"] == {name: {"jdk": "/opt/jdk-17"}}
    assert d["statement"] is None                                      # a choice needs no signature
    # a path the node did not find: added, so it goes into the node's statement for the owner to sign
    out = run_op(db, "tools.set_path", nid, params={"tool": "jdk", "path": "/srv/jdks/zulu-17"})
    assert out["result"]["value"]["kind"] == "add" and out["result"]["statement"]
    st = json.loads(statements.statement(db, nid)["statement"])
    assert st["type"] == "oarbank.node/v1" and st["tools"] == [{"id": "jdk", "module": "", "path": "/srv/jdks/zulu-17"}]
    owner = Ed25519PrivateKey.generate()
    db.set_setting("release_pubkey", base64.b64encode(owner.public_key().public_bytes_raw()).decode())
    stmt = statements.statement(db, nid)["statement"]
    run_op(db, "nodes.sign_statement", nid, params={"statement": stmt, "signature": base64.b64encode(owner.sign(stmt.encode())).decode()})
    assert core.heartbeat(db, fresh(db, mac), {"attempts": []})["statement"]["signature"]
    # until the node verifies it, the module-qualified pin still wins for the module; other modules get the added path
    other = tools.resolve_for(db, fresh(db, mac), "", req)
    assert other["status"] == "refused" and "not an installation this node found" in other["detail"]
    report(db, mac, {"jdk": [jdk("/opt/jdk-17", "17.0.12"), jdk("/srv/jdks/zulu-17.0.9", "17.0.9", source="override",
                                                                   given="/srv/jdks/zulu-17")]})
    assert tools.resolve_for(db, fresh(db, mac), "", req)["installation"]["version"] == "17.0.9"
    # reset: inherited again (the added path leaves the statement)
    run_op(db, "tools.set_path", nid, params={"tool": "jdk", "path": None})
    assert json.loads(statements.statement(db, nid)["statement"])["tools"] == []
    for bad in ["relative/jdk", "/opt/jdk-*", "/opt/../etc"]:
        with pytest.raises(core.ApiError):
            run_op(db, "tools.set_path", nid, params={"tool": "jdk", "path": bad})


def test_group_and_fleet_values_are_inherited_after_the_nodes_own():
    class R:
        def __init__(self, rows):
            self.rows = rows

        def get_setting(self, k, default=None):
            return self.rows if k == tools.STORE else default
    rows = [{"scope": "fleet", "scope_id": "", "module": "", "tool": "jdk", "path": "/fleet", "kind": "choose"},
            {"scope": "group", "scope_id": "darwin", "module": "m", "tool": "jdk", "path": "/group-m", "kind": "choose"},
            {"scope": "node", "scope_id": "n1", "module": "", "tool": "jdk", "path": "/node", "kind": "add"}]
    node = {"node_id": "n1", "platform": "darwin-arm64"}
    pick = lambda rs, n, m: (tools.node_override(R(rs), n, "jdk", m) or {}).get("path")
    assert pick(rows, node, "m") == "/node"                          # the node's own before a group's module value
    assert pick(rows, {"node_id": "n2", "platform": "darwin-arm64"}, "m") == "/group-m"
    assert pick(rows, {"node_id": "n2", "platform": "darwin-arm64"}, "x") == "/fleet"
    assert pick(rows, {"node_id": "n2", "platform": "linux-amd64"}, "m") == "/fleet"
    assert pick(rows[2:], {"node_id": "n2"}, "") is None
    assert tools.statement_tools(R(rows), "n1") == [{"id": "jdk", "module": "", "path": "/node"}]


def test_a_detect_request_reaches_the_agent_once(db):
    _, mac = enrolled_node(db, "mac")
    run_op(db, "tools.detect", "mac")
    assert core.heartbeat(db, fresh(db, mac), {"attempts": []})["detect_tools"] is True
    assert core.heartbeat(db, fresh(db, mac), {"attempts": []})["detect_tools"] is False


# ------------------------------------------------------------------------------------------------ API, CLI and console

def test_the_api_cli_and_console_show_the_matrix(db, tmp_path, capsys):
    from fastapi.testclient import TestClient
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from oarbank.coordinator import app as coord_app
    from helpers import admin_headers, sign_in
    r = installed(db, javatoy(tmp_path))
    name = r["name"]
    _, mac = enrolled_node(db, "mac")
    _, old = enrolled_node(db, "old")
    report(db, mac, {"jdk": [jdk("/opt/jdk-17", "17.0.12")]})
    report(db, old, {"jdk": [jdk("/usr/lib/jvm/java-11", "11.0.2")]})
    api = TestClient(coord_app.admin_app(db), base_url="http://127.0.0.1:7401")
    doc = api.get(f"/api/v1/tools?module={name}", headers=admin_headers(db)).json()
    rows = {x["hostname"]: x for x in doc["module"]["rows"]}
    assert rows["mac"]["status"] == "ok" and rows["mac"]["installation"]["path"] == "/opt/jdk-17"
    assert rows["old"]["code"] == "TOOL_VERSION_UNMET" and rows["old"]["fixes"][0]["command"] == "brew install openjdk@17"
    node = api.get("/api/v1/tools?node=old", headers=admin_headers(db)).json()["nodes"][0]
    assert node["tools"]["jdk"][0]["version"] == "11.0.2" and node["modules"][name][0]["status"] == "version_unmet"
    c = TestClient(console_app(ConsoleState(db.path, "http://127.0.0.1:1", secret="s")), base_url="http://127.0.0.1:7400")
    sign_in(c, db)
    html = c.get(f"/nodes/{old['node_id']}").text
    assert 'id="tools"' in html and "/usr/lib/jvm/java-11" in html and "TOOL_VERSION_UNMET" in html
    assert "brew install openjdk@17" in html and 'action="/do/tools.detect"' in html and 'action="/do/tools.set_path"' in html
    settings = c.get("/settings").text
    assert 'action="/do/tools.define"' in settings and "/Library/Java/JavaVirtualMachines/*/Contents/Home" in settings
    from oarbank.cli import main as cli
    detail = api.get(f"/api/v1/nodes/{old['node_id']}", headers=admin_headers(db)).json()
    assert detail["tools"]["modules"][name][0]["code"] == "TOOL_VERSION_UNMET"
    import argparse
    cli.api = lambda method, path, body=None, timeout=600: api.request(method, path, headers=admin_headers(db), json=body).json()
    cli.cmd_tools(argparse.Namespace(action="list", node=None, module=name, json=False, what=None))
    out = capsys.readouterr().out
    assert "old" in out and "version_unmet" in out and "Install on old: brew install openjdk@17" in out


# ------------------------------------------------------------------------------------------------ migration

def test_the_old_tool_registry_becomes_definitions_with_fleet_search_paths(tmp_path):
    path = tmp_path / "old.sqlite3"
    DB(path)                                              # a coordinator home of an earlier version
    con = sqlite3.connect(path)
    con.execute("DELETE FROM tool_defs")
    con.execute("INSERT OR REPLACE INTO settings(key, value_json) VALUES('tool_registry', ?)", (json.dumps({
        "java17": {"trust": "code-exec", "paths": {"darwin": ["/opt/homebrew/opt/openjdk@17"], "linux": ["/usr/lib/jvm/java-17"]}},
        "renderer4": {"trust": "read", "paths": {"windows": ["C:\\Renderer\\4\\renderer.exe"]}}}),))
    con.execute("INSERT OR REPLACE INTO settings(key, value_json) VALUES('folder_statements', '{}')")
    con.commit()
    con.close()
    db = DB(path)
    defs = tools.definitions(db)
    assert defs["java17"]["kind"] == "jdk" and defs["java17"]["search"] == {"darwin": ["/opt/homebrew/opt/openjdk@17"],
                                                                             "linux": ["/usr/lib/jvm/java-17"]}
    assert defs["renderer4"]["kind"] == "executable" and defs["renderer4"]["version"]["args"] == ["--version"]
    assert db.get_setting("tool_registry") is None and db.get_setting("folder_statements") is None
    assert db.get_setting(statements.KEY) == {}
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(nodes)")}
    assert {"tools_json", "want_detect"} <= cols


def test_resolution_defaults_to_the_current_version_and_every_node(db, tmp_path):
    r = installed(db, javatoy(tmp_path))
    _, mac = enrolled_node(db, "mac")
    report(db, mac, {"jdk": [jdk("/opt/jdk-21", "21.0.4")]})
    (row,) = tools.resolution(db, r["name"])
    assert row["need"] == "jdk >=17" and row["ok"] == ["mac"] and not row["failed"]
