"""Workloads in the console and the CLI (docs/design/workloads.md, "Console and CLI"): the module's Workloads tab and the
node's Workloads card show each assignment with its seat, fence, state and reason, and offer Assign / Unassign /
Restart; `oarbank workload list|assign|unassign|restart|logs` do what the console does."""
import re
import sys

import pytest
from fastapi.testclient import TestClient

from oarbank.cli import main as cli
from oarbank.console.app import console_app
from oarbank.console.state import ConsoleState
from oarbank.coordinator import access, app as coord_app, core, modcalls, releases

from helpers import FACTS, enrolled_node, fresh, install, make_db, run_op, sign_in
from test_console import SECRET, Server
from test_workloads import identity_module, set_key


@pytest.fixture
def ui(tmp_path, monkeypatch):
    db = make_db(tmp_path / "oarbank.sqlite3", modules=())
    install(db, identity_module(tmp_path))
    modcalls.use(db)
    releases.sync(db)
    _, n = enrolled_node(db, "mini", FACTS)
    core.hello(db, n, {"release_id": releases.assigned(db, fresh(db, n)), "facts": FACTS, "live_attempts": [], "ready_datasets": []})
    set_key(db, n)
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        monkeypatch.setenv("OARBANK_TOKEN", access.ensure_admin_token(db.root))
        monkeypatch.setenv("OARBANK_REASON", "ui test")
        monkeypatch.setattr(cli, "URL", f"http://127.0.0.1:{oarbankd.port}")
        state = ConsoleState(db.path, f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        with TestClient(console_app(state), client=("127.0.0.1", 50011)) as c:
            sign_in(c, db)
            yield {"db": db, "nid": n["node_id"], "c": c}


def oarbank(capsys, *args) -> tuple[int, str]:
    capsys.readouterr()
    old = sys.argv
    sys.argv, code, msg = ["oarbank", *map(str, args)], 0, ""
    try:
        cli.main()
    except SystemExit as e:
        code, msg = (e.code, "") if isinstance(e.code, int) or e.code is None else (1, str(e.code))
    finally:
        sys.argv = old
    return code or 0, capsys.readouterr().out + msg


def text(page: str) -> str:
    import html
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def test_the_cli_assigns_lists_restarts_shows_logs_and_unassigns(ui, capsys):
    db, nid = ui["db"], ui["nid"]
    code, out = oarbank(capsys, "workload", "assign", "workload/worker", "--node", nid, "--yes")
    assert code == 0 and nid in out, out
    core.heartbeat(db, fresh(db, db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))), {
        "attempts": [], "ready_datasets": [], "workloads": [{"key": "workload/worker", "state": "running", "running": True,
                                                             "seat_id": "s_x", "fence": 1, "log_tail": "unit 7 done\n"}]})
    code, out = oarbank(capsys, "workload", "list")
    assert code == 0 and "workload/worker" in out and "running" in out, out
    code, out = oarbank(capsys, "workload", "logs", "workload/worker", "--node", nid)
    assert code == 0 and "unit 7 done" in out, out
    code, out = oarbank(capsys, "workload", "restart", "workload/worker", "--node", nid, "--yes")
    assert code == 0, out
    code, out = oarbank(capsys, "workload", "unassign", "workload/worker", "--node", nid, "--yes")
    assert code == 0, out
    code, out = oarbank(capsys, "workload", "list")
    assert "no workloads assigned" in out


def test_the_module_tab_and_node_card_show_assignments_and_offer_their_operations(ui):
    db, nid, c = ui["db"], ui["nid"], ui["c"]
    run_op(db, "workloads.assign", "workload/worker", {"node": nid})
    core.heartbeat(db, fresh(db, db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))), {
        "attempts": [], "ready_datasets": [], "workloads": [{"key": "workload/worker", "state": "held", "running": False,
                                                             "held": "preempt_protection", "held_code": "WORKLOAD_PAUSE_TOLERANCE",
                                                             "seat_id": "s_x", "fence": 2, "restarts": 3}]})
    page = c.get("/modules/workload/workloads").text
    t = text(page)
    assert "worker" in t and "per-node identity" in t and "held" in t and "WORKLOAD_PAUSE_TOLERANCE" in t and "fence 2" in t, t
    for op in ("workloads.restart", "workloads.unassign", "workloads.assign"):
        assert f'action="/do/{op}"' in page, op
    node = text(c.get(f"/nodes/{nid}").text)
    assert "Workloads" in node and "workload/worker" in node and "held (preempt_protection)" in node
    assert 'href="/modules/workload/workloads"' in c.get("/modules/workload/settings").text
