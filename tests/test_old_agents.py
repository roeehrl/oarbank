"""Nodes whose agent is an older release than the coordinator (an upgraded fleet before its nodes are updated): the
console says so wherever it matters, with what to do, instead of "up to date" or "not reported yet"."""
import pytest

from oarbank import __version__
from oarbank.coordinator import agentbuilds, tools

from helpers import certify, enrolled_node, make_db, sign_in


def test_older_compares_releases_and_never_guesses():
    assert agentbuilds.older("2.8.0", "2.9.0") and agentbuilds.older("2.8.9", "2.9.0")
    assert not agentbuilds.older("2.9.0", "2.9.0") and not agentbuilds.older("2.10.0", "2.9.0")
    assert agentbuilds.older("2.8.0-rc1", "2.9.0")
    assert not agentbuilds.older(None, "2.9.0") and not agentbuilds.older("dev", "2.9.0")     # unknown: not called older
    assert agentbuilds.behind({"agent_version": __version__}) is None
    b = agentbuilds.behind({"agent_version": "0.1.0"})
    assert b["version"] == "0.1.0" and b["coordinator"] == __version__ and "update the node" in b["text"]


def test_an_agent_older_than_host_tools_is_told_to_update_not_to_wait():
    req = {"id": "jdk", "version": ">=17"}
    defs = {"jdk": {"kind": "jdk"}}
    old = tools.resolve_for(None, {"node_id": "n1", "agent_version": "2.8.0", "tools_json": None}, "m", req, defs)
    assert old["status"] == "not_found" and old["unreported"]
    assert "agent 2.8.0 is older than 2.9.0 and does not report host tools" in old["detail"]
    assert "update the node" in old["detail"]
    new = tools.resolve_for(None, {"node_id": "n2", "agent_version": "2.9.0", "tools_json": None}, "m", req, defs)
    assert new["detail"] == "jdk not reported yet (the node's agent reports its tools after it connects)"


@pytest.fixture
def console(tmp_path):
    from fastapi.testclient import TestClient
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from oarbank.coordinator import app as coord_app
    from test_console import SECRET, Server
    db = make_db(tmp_path / "oarbank.sqlite3")
    old = enrolled_node(db, "oldmac")[1]
    new = enrolled_node(db, "newmac")[1]
    certify(db, old)
    certify(db, new)
    db.x("UPDATE nodes SET agent_version='2.8.0' WHERE node_id=?", (old["node_id"],))
    db.x("UPDATE nodes SET agent_version=? WHERE node_id=?", (__version__, new["node_id"]))
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(str(db.path), f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        with TestClient(console_app(state, tmp_path / "logs"), client=("127.0.0.1", 50013)) as c:
            sign_in(c, db)
            yield c, old, new


def _row(page: str, hostname: str) -> str:
    start = page.index(f"<td>{hostname}</td>") if f"<td>{hostname}</td>" in page else page.index(hostname)
    return page[start:page.index("</tr>", start)]


def test_the_console_names_old_agents_and_what_to_do(console):
    c, old, new = console
    agent = c.get("/agent").text
    assert f"older than the coordinator ({__version__})" in _row(agent, "oldmac")
    assert f"install the {__version__} node package" in _row(agent, "oldmac")
    assert "up to date" in _row(agent, "newmac") and "older than" not in _row(agent, "newmac")
    fleet = c.get("/").text
    assert "agent 2.8.0: update" in fleet and f"agent {__version__}: update" not in fleet
    page = c.get(f"/nodes/{old['node_id']}").text
    assert f"agent 2.8.0: update to {__version__}" in page
    assert "agent 2.8.0 is older than 2.9.0 and does not report host tools" in page
    assert "update to" not in c.get(f"/nodes/{new['node_id']}").text.split("<nav")[0]
    assert "the node&#39;s agent reports its tools after it connects" in c.get(f"/nodes/{new['node_id']}").text
