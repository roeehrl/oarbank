"""Module-defined GUI (PLAN D23/D24) end to end: the SDK toy module's pages, views, operations and
sandboxed frame, rendered by oarbank-console and executed by oarbankd."""
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import make_db, sign_in
from oarbank.console.app import console_app
from oarbank.console.frames import frames_app
from oarbank.console.state import ConsoleState
from oarbank.coordinator import app as coord_app
from oarbank.coordinator import modviews, ops
from oarbank_sdk import ui as U
from test_console import SECRET, Server

TOY = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "toy"


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "oarbank.sqlite3"
    db = make_db(path)
    # two toy results (rows its GUI reads)
    for jid, n in ((901, 4), (902, 5)):
        db.x("INSERT INTO jobs(job_id,job_key,kind,state,spec_json,module,created_at) VALUES(?,?,'eval','done',?,'toy',?)",
             (jid, f"k{jid}", json.dumps({"payload": {"n": n}}), time.time()))
        db.x("INSERT INTO results(job_key,job_id,attempt_id,node_id,accepted,canonical,value,fields_json,result_json,module,at) "
             "VALUES(?,?,?,?,1,1,?,?,'{}','toy',?)", (f"k{jid}", jid, jid, "n_x", n * (n - 1) // 2 + (jid == 902), '{"sum": 1}', time.time()))
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(path, f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        app = console_app(state, module_origin="http://127.0.0.1:7999")
        with TestClient(app, client=("127.0.0.1", 50002)) as c:
            sign_in(c, db)
            yield {"db": db, "c": c, "app": app, "state": state}


def test_modules_nav_and_toy_overview(env):
    c = env["c"]
    html = c.get("/modules").text
    assert "/modules/toy" in html and "/modules/relay" in html
    r = c.get("/modules/toy")
    assert r.status_code == 200 and "frame-src http://127.0.0.1:7999" in r.headers["content-security-policy"]
    page = r.text
    assert 'class="mod-region" hx-disable data-module="toy"' in page and "Checked sums" in page
    assert 'src="http://127.0.0.1:7999/f/toy/explorer/"' in page and 'sandbox="allow-scripts allow-forms"' in page
    assert ">Set the favorite n</button>" in page                         # label from the registry
    assert "/static-ui/ui.js" in page and "/modules/toy/health" in page


def test_views_are_computed_by_fleetd_and_read_by_the_console(env):
    db, c = env["db"], env["c"]
    assert "sums" not in [r["view_id"] for r in db.q("SELECT view_id FROM module_views")]
    assert "data unavailable" in c.get("/modules/toy").text                # the console never calls the module
    assert modviews.refresh(db, force=True) == 2                           # toy/sums and relay/scores
    doc = json.loads(db.one("SELECT doc_json FROM module_views WHERE module='toy' AND view_id='sums'")["doc_json"])
    assert doc["rows"] == [{"n": 5, "sum": 11, "ok": False}, {"n": 4, "sum": 6, "ok": True}]
    html = c.get("/modules/toy").text
    assert "computed " in html and ">11</span>" in html
    assert modviews.refresh(db) == 0                                       # same data version: nothing to do


def test_module_operation_end_to_end_and_audited(env):
    db, c = env["db"], env["c"]
    r = c.post("/do/mod.toy.set_favorite", data={"p.n": "9", "return_to": "/modules/toy"}, follow_redirects=False)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"], r.headers.get("location")
    assert db.get_setting("module_settings:toy") == {"favorite_n": 9}
    a = db.one("SELECT * FROM audit ORDER BY event_id DESC LIMIT 1")
    assert (a["operation"], a["outcome"], a["source"]) == ("mod.toy.set_favorite", "ok", "gui")
    r = c.post("/do/mod.toy.set_favorite", data={"p.n": "-1", "return_to": "/"}, follow_redirects=False)
    assert "kind=bad" in r.headers["location"] and db.get_setting("module_settings:toy") == {"favorite_n": 9}


def test_undeclared_effects_are_refused():
    decl = U.OperationDecl(verb="x", title="X", effects=["module_settings.update"])
    with pytest.raises(ops.OpError) as ei:
        ops.apply_effects(None, "toy", decl, [{"kind": "jobs.cancel", "args": {}}])
    assert ei.value.code == "undeclared_effect"


def test_bridge_reads_own_data_and_only_own_operations(env):
    db, c = env["db"], env["c"]
    modviews.refresh(db, force=True)
    assert c.get("/m/toy/_bridge/view/sums").json()["rows"][0]["n"] == 5
    assert c.get("/m/toy/_bridge/view/nope").status_code == 404
    assert c.get("/m/toy/_bridge/op/mod.toy.set_favorite").json()["title"] == "Set the favorite n"
    assert c.get("/m/toy/_bridge/op/nodes.retire").status_code == 403
    assert c.get("/m/toy/_bridge/op/mod.bench.anything").status_code == 403
    q = json.dumps({"query": "results", "fields": ["job_id", "value"]})
    rows = c.get("/m/toy/_bridge/query", params={"spec": q}).json()["rows"]
    assert {r["job_id"] for r in rows} == {901, 902}                        # only the module's own rows


def test_frames_origin_is_sandboxed_and_confined(env):
    app = env["app"]
    f = TestClient(frames_app(app.state.catalog, "http://127.0.0.1:7400", refresh=app.state.refresh_catalog_sync))
    r = f.get("/f/toy/explorer/")
    assert r.status_code == 200 and "Toy explorer" in r.text
    h = r.headers["content-security-policy"]
    assert h.startswith("sandbox allow-scripts allow-forms;") and "connect-src 'none'" in h
    assert "frame-ancestors http://127.0.0.1:7400" in h and r.headers["x-content-type-options"] == "nosniff"
    assert "set-cookie" not in r.headers
    assert f.get("/f/toy/explorer/explorer.js").status_code == 200
    assert f.get("/f/toy/explorer/..%2F..%2Foarbank-module.toml").status_code in (403, 404)
    assert f.get("/f/toy/explorer/../pages/overview.json").status_code in (403, 404)
    assert f.get("/f/toy/nope/").status_code == 404 and f.get("/f/bench/explorer/").status_code == 404


def test_job_page_shows_the_module_panel(env):
    html = env["c"].get("/jobs/901").text
    assert "Toy result" in html and 'data-module="toy"' in html
