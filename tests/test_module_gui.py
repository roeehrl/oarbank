"""Module-defined GUI (PLAN D23/D24/D41) end to end: the SDK reference modules' pages, views, operations and sandboxed
frames, rendered by oarbank-console and executed by oarbankd; UI contract 1.2's sources, links and bridge, with the
console's CSRF, capability, role and ownership checks."""
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import quote, unquote

import pytest
from fastapi.testclient import TestClient

from helpers import enrolled_node, fresh, install, make_db, sign_in
from oarbank.console import modpages
from oarbank.console.app import console_app
from oarbank.console.frames import frames_app
from oarbank.console.state import ConsoleState
from oarbank.coordinator import app as coord_app, core
from oarbank.coordinator import modcalls, modfiles, modsandbox, modstore, modviews, ops
from oarbank_sdk import manifest as mf, ui as U
from test_console import SECRET, Server
from oarbank.coordinator.settings import fleet_value

EX = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples"
TOY, REEL, MODELSERVER, GPUINFO, TASKBENCH = (EX / m for m in ("toy", "reel", "modelserver", "gpuinfo", "taskbench"))
DEPOT = Path(__file__).parent / "fixtures" / "modules" / "depot"


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "oarbank.sqlite3"
    db = make_db(path)
    for m in (REEL, MODELSERVER, GPUINFO, TASKBENCH, DEPOT):
        r = install(db, m, enable=False)
        if modsandbox.status(db, r["name"], r["version"])["requests"]:
            modsandbox.approve(db, r["name"], r["version"], "test", None)      # the grants an operator approves
        modstore.enable(db, r["name"], r["version"])
    modcalls.use(db)
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
            sess = sign_in(c, db)
            yield {"db": db, "c": c, "app": app, "state": state, "oarbankd": oarbankd, "session": sess}


def text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def rows(db, module, query, **params):
    return modpages.rows_for(db, module, modcalls.info(module).manifest, U.Source(query=query, params=params, limit=200))


def frame_caps(app, caps: list[str]):
    """The toy frame as if its manifest declared these bridge capabilities."""
    cat = app.state.catalog
    app.state.refresh_catalog_sync()
    man = cat.manifest("toy")
    fr = man.ui.iframes[0].model_copy(update={"bridge": caps})
    cat._man[f"toy@{cat.rows['toy']['version']}"] = man.model_copy(update={"ui": man.ui.model_copy(update={"iframes": [fr]})})


def bridge(c, frame="explorer", module="toy"):
    return f"/m/{module}/_bridge/{frame}"


# ------------------------------------------------------------------------------------------ pages, views, operations

def test_modules_nav_and_toy_overview(env):
    c = env["c"]
    html = c.get("/modules").text
    assert "/modules/toy" in html and "/modules/relay" in html
    r = c.get("/modules/toy")
    assert r.status_code == 200 and "frame-src http://127.0.0.1:7999" in r.headers["content-security-policy"]
    page = r.text
    assert 'class="mod-region" hx-disable data-module="toy"' in page and "Checked sums" in page
    assert 'src="http://127.0.0.1:7999/f/toy/explorer/"' in page and 'sandbox="allow-scripts allow-forms"' in page
    assert 'data-bridge-caps="read.view read.query request.operation resize navigate"' in page
    assert 'data-bridge-base="/m/toy/_bridge/explorer"' in page
    assert ">Set the favorite n</button>" in page                         # label from the registry
    assert "/static-ui/ui.js" in page and "/modules/toy/health" in page


def test_views_are_computed_by_fleetd_and_read_by_the_console(env):
    db, c = env["db"], env["c"]
    assert "sums" not in [r["view_id"] for r in db.q("SELECT view_id FROM module_views")]
    assert "data unavailable" in c.get("/modules/toy").text                # the console never calls the module
    assert modviews.refresh(db, force=True) >= 2                           # toy/sums, relay/scores and reel's
    doc = json.loads(db.one("SELECT doc_json FROM module_views WHERE module='toy' AND view_id='sums'")["doc_json"])
    assert doc["rows"] == [{"n": 5, "sum": 11, "ok": False}, {"n": 4, "sum": 6, "ok": True}]
    html = c.get("/modules/toy").text
    assert "computed " in html and ">11</span>" in html
    assert modviews.refresh(db) == 0                                       # same data version: nothing to do


def test_module_operation_end_to_end_and_audited(env):
    db, c = env["db"], env["c"]
    r = c.post("/do/mod.toy.set_favorite", data={"p.n": "9", "return_to": "/modules/toy"}, follow_redirects=False)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"], r.headers.get("location")
    assert fleet_value(db, "module.settings", "toy") == {"favorite_n": 9}
    a = db.one("SELECT * FROM audit ORDER BY event_id DESC LIMIT 1")
    assert (a["operation"], a["outcome"], a["source"]) == ("mod.toy.set_favorite", "ok", "gui")
    r = c.post("/do/mod.toy.set_favorite", data={"p.n": "-1", "return_to": "/"}, follow_redirects=False)
    assert "kind=bad" in r.headers["location"] and fleet_value(db, "module.settings", "toy") == {"favorite_n": 9}


def test_undeclared_effects_are_refused():
    decl = U.OperationDecl(verb="x", title="X", effects=["module_settings.update"])
    with pytest.raises(ops.OpError) as ei:
        ops.apply_effects(None, "toy", decl, [{"kind": "jobs.cancel", "args": {}}])
    assert ei.value.code == "undeclared_effect"


def test_frames_origin_is_sandboxed_and_confined(env):
    app = env["app"]
    f = TestClient(frames_app(app.state.catalog, "http://127.0.0.1:7400", refresh=app.state.refresh_catalog_sync))
    r = f.get("/f/toy/explorer/")
    assert r.status_code == 200 and "Toy explorer" in r.text
    h = r.headers["content-security-policy"]
    assert h.startswith("sandbox allow-scripts allow-forms;") and "connect-src 'none'" in h and "media-src 'self'" in h
    assert "frame-ancestors http://127.0.0.1:7400" in h and r.headers["x-content-type-options"] == "nosniff"
    assert "set-cookie" not in r.headers
    assert f.get("/f/toy/explorer/explorer.js").status_code == 200
    assert f.get("/f/toy/explorer/..%2F..%2Foarbank-module.toml").status_code in (403, 404)
    assert f.get("/f/toy/explorer/../pages/overview.json").status_code in (403, 404)
    assert f.get("/f/toy/nope/").status_code == 404 and f.get("/f/bench/explorer/").status_code == 404


def test_job_page_shows_the_module_panel(env):
    html = env["c"].get("/jobs/901").text
    assert "Toy result" in html and 'data-module="toy"' in html and ">6</dd>" in html     # $job is the job's id


# ------------------------------------------------------------------------------------------ 1a: CSRF on frame operations

def test_a_frame_operation_posts_with_the_session_csrf_through_the_real_console(env):
    """What ui.js posts for request.operation (SDK tests/js/bridge.cjs pins the fields), sent through the real console with
    no CSRF header: the meta tag's token in the form runs it; without it, 403."""
    db, c = env["db"], env["c"]
    page = c.get("/modules/toy").text
    token = re.search(r'<meta name="csrf-token" content="([^"]+)">', page).group(1)
    del c.headers["x-csrf-token"]                                           # a form navigation carries no header
    fields = {"target": "", "return_to": "/modules/toy", "idem": "frame-op-1", "params": json.dumps({"n": 12})}
    r = c.post("/do/mod.toy.set_favorite", data=fields, follow_redirects=False)
    assert r.status_code == 403 and r.json()["error"] == "csrf"
    assert fleet_value(db, "module.settings", "toy") == {}
    r = c.post("/do/mod.toy.set_favorite", data={**fields, "csrf": token}, follow_redirects=False)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"]
    assert fleet_value(db, "module.settings", "toy") == {"favorite_n": 12}      # a number: params arrive as JSON, intact
    a = db.one("SELECT * FROM audit ORDER BY event_id DESC LIMIT 1")
    assert (a["operation"], a["outcome"], a["source"]) == ("mod.toy.set_favorite", "ok", "gui")


# ------------------------------------------------------------------------------------------ 1b: capabilities

def test_bridge_routes_check_the_frames_declared_capabilities(env):
    db, c = env["db"], env["c"]
    modviews.refresh(db, force=True)
    assert c.get(bridge(c) + "/view/sums").json()["rows"][0]["n"] == 5
    assert c.get(bridge(c, "ghost") + "/view/sums").status_code == 404
    r = c.get(bridge(c) + "/media", params={"ref": "{}", "kind": "image"})       # toy's frame does not declare read.media
    assert r.status_code == 403 and r.json()["error"] == "capability"
    frame_caps(env["app"], ["resize"])
    for path, params in (("/view/sums", {}), ("/query", {"spec": json.dumps({"query": "results"})}),
                         ("/op/mod.toy.set_favorite", {}), ("/link", {"to": json.dumps({"job": 901})})):
        r = c.get(bridge(c) + path, params=params)
        assert r.status_code == 403 and r.json()["error"] == "capability", path


def test_bridge_reads_own_data_and_interpolates_the_frame_context(env):
    c = env["c"]
    q = json.dumps({"query": "results", "fields": ["job_id", "value"]})
    assert {r["job_id"] for r in c.get(bridge(c) + "/query", params={"spec": q}).json()["rows"]} == {901, 902}
    q = json.dumps({"query": "results", "params": {"job_id": "$job"}, "fields": ["job_id", "value"]})
    got = c.get(bridge(c) + "/query", params={"spec": q, "ctx": json.dumps({"job": 902})}).json()["rows"]
    assert got == [{"job_id": 902, "value": 11}]
    assert c.get(bridge(c) + "/query", params={"spec": json.dumps({"view": "sums"})}).status_code == 400


def test_bridge_operations_are_what_a_page_may_name_with_role_and_target_checks(env):
    db, c = env["db"], env["c"]
    assert c.get(bridge(c) + "/op/mod.toy.set_favorite").json()["title"] == "Set the favorite n"
    assert c.get(bridge(c) + "/op/mod.relay.anything").status_code in (403, 404)
    assert c.get(bridge(c) + "/op/nodes.retire").json()["tier"] == "T3"              # a core op: the admin may
    assert c.get(bridge(c) + "/op/jobs.cancel", params={"target": "901"}).status_code == 200
    db.x("INSERT INTO jobs(job_id,job_key,kind,state,spec_json,module,created_at) VALUES(950,'kr','eval','pending','{}','relay',0)")
    r = c.get(bridge(c) + "/op/jobs.cancel", params={"target": "950"})              # another module's job
    assert r.status_code == 403 and "not toy's" in r.json()["detail"]
    sign_in(c, db, "watcher", "viewer")
    r = c.get(bridge(c) + "/op/mod.toy.set_favorite")
    assert r.status_code == 403 and r.json()["error"] == "needs the operator role"


def test_navigate_maps_typed_references_like_rendered_links(env):
    c = env["c"]
    link = lambda to: c.get(bridge(c) + "/link", params={"to": json.dumps(to)},
                            headers={"referer": "http://testserver/modules/toy?var.x=1"})
    assert link({"job": 901}).json() == {"href": "/jobs/901"}
    assert link({"dataset": "asset:clip", "download": True}).json() == {"href": "/datasets/asset:clip/download.zip"}
    assert link({"campaign": "c_1"}).json() == {"href": "/campaigns/c_1"}
    assert link({"tab": "health"}).json() == {"href": "/modules/toy/health"}
    assert link({"tab": "secrets"}).status_code == 404                                 # toy declares no secrets
    assert link({"url": "https://example.org/x"}).status_code == 404                   # typed references only
    assert link({"page": "nope"}).status_code == 404


def test_read_media_gives_capability_urls_for_the_modules_own_artifacts(env):
    db, c = env["db"], env["c"]
    png = (EX / "reel" / "fixtures" / "ui" / "media" / "frames").glob("*.png").__next__().read_bytes()
    f = {"path": "f.png", "digest": modfiles.store_bytes(db, png), "size": len(png)}
    core._register_artifacts(db, {"artifacts": [{"name": "frames", "files": [f]}]}, "toy")
    db.x("INSERT INTO jobs(job_id,job_key,kind,state,spec_json,module,created_at,canonical_result_id) "
         "VALUES(960,'k960','eval','done','{}','toy',0,960)")
    db.x("INSERT INTO results(result_id,job_key,job_id,attempt_id,node_id,accepted,canonical,value,fields_json,result_json,module,at) "
         "VALUES(960,'k960',960,960,'n_x',1,1,1,'{}',?,'toy',0)", (json.dumps({"artifacts": [{"name": "frames", "files": [f]}]}),))
    frame_caps(env["app"], ["read.media"])
    r = c.get(bridge(c) + "/media", params={"ref": json.dumps({"job": 960, "artifact": "frames", "path": "f.png"}), "kind": "image"})
    assert r.status_code == 200 and r.json()["src"].startswith("http://127.0.0.1:7999/b/") and r.json()["job"] == 960
    r = c.get(bridge(c) + "/media", params={"ref": json.dumps({"job": 901, "artifact": "frames", "path": "f.png"}), "kind": "image"})
    assert r.status_code == 404                                                         # no such artifact of that job


# ------------------------------------------------------------------------------------------ 1c: ownership

def test_datasets_and_their_view_inputs_never_include_another_modules(env):
    db = env["db"]
    for did, kind, module in (("asset:mine", "asset", "reel"), ("asset:ops", "asset", None), ("asset:theirs", "asset", "relay"),
                              ("other:ops", "other", None)):
        db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?)",
             (did, kind, module, json.dumps({"size": "shadowed"}),
              json.dumps([{"path": "a", "digest": "d" * 64, "size": 10, "origins": ["https://cdn.example.org/a"]}]), time.time()))
    got = {d["dataset_id"]: d for d in rows(db, "reel", "datasets")}
    assert set(got) == {"asset:mine", "asset:ops"}                                     # not relay's, not another kind's
    assert got["asset:mine"]["owner"] == "module" and got["asset:ops"]["owner"] == "operator"
    assert got["asset:mine"]["size"] == 10 and got["asset:mine"]["origins"] == ["cdn.example.org"]   # meta cannot shadow
    inp = modviews._inputs(db, "reel", ["datasets:asset"])["datasets:asset"]
    assert {d["dataset_id"] for d in inp} == {"asset:mine", "asset:ops"}
    v0 = modviews._data_version(db, "reel", ["datasets:asset"])
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES('asset:t2','asset','relay','{}','[]',?)",
         (time.time() + 5,))
    assert modviews._data_version(db, "reel", ["datasets:asset"]) == v0               # another module's change: no recompute


def test_module_events_are_the_modules_own_exactly(env):
    db, c = env["db"], env["c"]
    db.event("module_fault", reason="toybox golden.list: boom (mentions toy)", module="toybox")
    db.event("module_fault", reason="toy golden.list: boom", module="toy")
    db.event("job_done", job_id=901, reason="ok")
    db.event("job_done", job_id=950, reason="toy toy toy")                             # another module's job, toy in its text
    got = rows(db, "toy", "module_events")
    assert {e["reason"] for e in got} >= {"toy golden.list: boom", "ok"}
    assert not any("toybox" in (e["reason"] or "") or e["reason"] == "toy toy toy" for e in got)
    health = text(c.get("/modules/toy/health").text)
    assert "toy golden.list: boom" in health and "toybox" not in health


def test_module_events_name_their_module():
    """Every event about one module carries it (events.module): the events tests above rely on the emitters."""
    src = "\n".join((Path(__file__).parents[1] / "src" / "oarbank" / "coordinator" / f).read_text(encoding="utf-8")
                    for f in ("ops.py", "modlife.py", "modstore.py", "modsandbox.py", "effects.py", "modimages.py", "campaigns.py"))
    untagged = [line.strip() for line in src.splitlines() if re.search(r'db\.event\("(module_|secret_|dataset_|container_image)', line)
                and "module=" not in line and "module=" not in src[src.index(line):src.index(line) + 400].split(")\n")[0]]
    assert not untagged, untagged


# ------------------------------------------------------------------------------------------ 2: links and roles

def test_dataset_and_campaign_links_and_downloads_resolve(env):
    db, c = env["db"], env["c"]
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES('asset:clip','asset','reel','{}','[]',?)",
         (time.time(),))
    db.x("INSERT INTO campaigns(campaign_id,module,name,state,created_at) VALUES('c_reel_1','reel','renders','running',?)", (time.time(),))
    html = c.get("/m/reel/data").text
    assert 'href="/datasets/asset:clip"' in html and 'href="/datasets/asset:clip/download.zip"' in html
    assert 'href="/campaigns/c_reel_1"' in html and 'href="/campaigns/c_reel_1/artifacts.zip"' in html
    assert 'href="#"' not in html
    up = re.search(r'href="(/datasets/upload\?[^"]+)"', html).group(1).replace("&amp;", "&")
    assert "module=reel" in up and "kind=upload" in up and "then=mod.reel.adopt_upload" in up and "return_to=%2Fm%2Freel%2Fdata" in up
    page = c.get(up).text
    assert '<option data-kinds="asset,upload" selected>reel</option>' in page and 'value="upload"' in page
    nxt = unquote(re.search(r'data-next="([^"]+)"', page).group(1).replace("&amp;", "&"))
    assert nxt == "/m/reel/_import?op=mod.reel.adopt_upload&return_to=/m/reel/data"


def test_the_upload_link_returns_to_the_importer_operation(env):
    db, c = env["db"], env["c"]
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES('upload:shots','upload','reel','{}','[]',?)",
         (time.time(),))
    r = c.get("/m/reel/_import", params={"op": "mod.reel.adopt_upload", "dataset": "upload:shots", "return_to": "/m/reel/data"})
    assert r.status_code == 200
    html = r.text
    assert 'action="/do/mod.reel.adopt_upload"' in html and 'name="target" value="upload:shots"' in html
    assert 'name="return_to" value="/m/reel/data"' in html and ">Use an uploaded dataset as assets</button>" in html
    assert c.get("/m/reel/_import", params={"op": "mod.reel.queue_render", "dataset": "upload:shots"}).status_code == 404
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES('x:theirs','x','relay','{}','[]',0)")
    assert c.get("/m/reel/_import", params={"op": "mod.reel.adopt_upload", "dataset": "x:theirs"}).status_code == 404


def test_pages_and_panels_see_the_viewers_role(env):
    db, c = env["db"], env["c"]
    assert '<form class="inline mod-op" method="post" action="/do/mod.toy.set_favorite"' in c.get("/modules/toy").text
    sign_in(c, db, "watcher", "viewer")
    html = c.get("/modules/toy").text
    assert 'disabled title="needs the operator role">Set the favorite n</button>' in html
    assert 'action="/do/mod.toy.set_favorite"' not in html


# ------------------------------------------------------------------------------------------ 3: UI contract 1.2 sources

def test_secrets_source_shows_state_never_a_value(env):
    db = env["db"]
    for module, name, node in (("taskbench", "provider_key", ""), ("taskbench", "provider_key", "n_1"), ("relay", "provider_key", "")):
        db.x("INSERT INTO secrets(module,name,node_id,ciphertext,fingerprint,set_at,set_by) VALUES(?,?,?,?,?,?,?)",
             (module, name, node, b"\x00secret-bytes", f"fp:{module}{node}", 1790000000.0, "owner"))
    got = rows(db, "taskbench", "secrets")
    assert got == [{"name": "provider_key", "description": "API key of the model provider the task harness calls", "set": True,
                    "fingerprint": "fp:taskbench", "changed_at": 1790000000.0, "changed_by": "owner", "node_values": 1,
                    "stages": ["attempt"], "coordinator": False, "unreadable": False}]
    db.x("DELETE FROM secrets WHERE module='taskbench' AND node_id=''")
    assert rows(db, "taskbench", "secrets")[0]["set"] is False
    code = Path(modpages.__file__).read_text(encoding="utf-8").split('"""', 2)[2]                      # past the module docstring
    assert "ciphertext" not in code and "secrets WHERE" in code                        # no query reads a value


def test_checkpoints_and_resumes(env):
    db = env["db"]
    for jid, module in ((970, "reel"), (971, "toy")):
        db.x("INSERT INTO jobs(job_id,job_key,kind,state,spec_json,module,created_at,generation) VALUES(?,?,'eval','leased','{}',?,0,1)",
             (jid, f"k{jid}", module))
        db.x("INSERT INTO checkpoints(job_id,generation,attempt_id,node_id,seq,digest,files_json,size,at) VALUES(?,1,?,?,3,?,?,?,?)",
             (jid, jid * 10, "n_a", "e" * 64, json.dumps([{"path": "a"}, {"path": "b"}]), 2048, 1790000000.0))
    db.x("INSERT INTO attempts(attempt_id,job_id,node_id,state,resume_json,module_version) VALUES(9701,970,'n_b','live',?,'0.1.0')",
         (json.dumps({"from_attempt": 9700, "node_id": "n_a", "digest": "e" * 64}),))
    assert [(r["job_id"], r["files"], r["seq"]) for r in rows(db, "reel", "checkpoints")] == [(970, 2, 3)]
    a = rows(db, "reel", "attempts", job_id=970)[0]
    assert (a["resumed_from_attempt"], a["resumed_from_node"], a["resume_digest"]) == (9700, "n_a", "e" * 64)


def test_nodes_and_services_sources(env):
    db = env["db"]
    _, n = enrolled_node(db, "studio")
    facts = {**json.loads(fresh(db, n)["facts_json"] or "{}"),
             "containers": {"runtime": "wslc", "state": "missing", "session": "oarbank-3f2a9c0b71de", "platforms": ["linux/amd64"],
                            "gpu": "undetected",
                            "missing": [{"what": "wsl_package", "detail": "WSL 2.9.3 or later is not installed",
                                         "fix": "oarbank-agent containers install"}]},
             "sandbox": {"enforcement": {"filesystem": "enforced", "ipc": "enforced", "net.none": "enforced",
                                         "endpoints": "unavailable"}}}
    doctor = {"gpu_apis": {"host": ["cuda", "vulkan"], "containers": []}, "modules": {}}
    db.x("UPDATE nodes SET facts_json=?, doctor_json=?, platform='windows-amd64', os='windows', arch='amd64' WHERE node_id=?",
         (json.dumps(facts), json.dumps(doctor), n["node_id"]))
    core.heartbeat(db, fresh(db, n), {"attempts": [], "services": [
        {"service": "modelserver/model", "health": "healthy", "running": False, "held": "preempt_memory", "endpoint": True},
        {"service": "relay/vm", "health": "healthy", "running": True, "ready": True}]})
    node = next(r for r in rows(db, "modelserver", "nodes") if r["node_id"] == n["node_id"])
    assert node["platform"] == "windows-amd64" and node["gpu_apis_host"] == ["cuda", "vulkan"]
    assert node["container_runtime"] == "wslc" and node["container_state"] == "missing"
    assert node["container_fixes"] == ["oarbank-agent containers install"] and node["container_missing"][0]["what"] == "wsl_package"
    assert node["container_platforms"] == ["linux/amd64"] and node["container_gpu"] is None
    assert [s["service"] for s in node["services"]] == ["model"] and node["service_health"] == "model: stopped (held: preempt_memory)"
    assert node["enforcement"]["endpoints"] == "unavailable" and "endpoints" in node["sandbox_gaps"]
    svc = rows(db, "modelserver", "services", node_id=n["node_id"])
    assert len(svc) == 1 and (svc[0]["state"], svc[0]["stopped_reason"], svc[0]["endpoint"]) == ("stopped", "held: preempt_memory", True)
    assert rows(db, "modelserver", "services", service="nope") == []


def test_pins_images_platforms_and_campaign_placement(env):
    db = env["db"]
    man = mf.load(DEPOT / "oarbank-module.toml")
    pin = man.datasets.pinned[0]
    assert rows(db, "depot", "pins")[0]["state"] == "missing"
    db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,NULL,'{}','[]',0)", (pin.dataset_id, pin.kind))
    core._alert(db, f"pinned_dataset_conflict:{pin.dataset_id}", "module:depot", "held by the operator")
    p = rows(db, "depot", "pins")[0]
    assert (p["state"], p["conflict"], p["alert"]) == ("conflict", f"the operator (kind {pin.kind})", True)
    db.x("UPDATE datasets SET module='depot', files_json=? WHERE dataset_id=?",
         (json.dumps([{**f, "origins": []} for f in pin.dataset_files()]), pin.dataset_id))
    assert rows(db, "depot", "pins")[0]["state"] == "registered"
    for module, digest in (("taskbench", "a" * 64), ("relay", "b" * 64)):
        db.x("INSERT INTO module_images(module,digest,image,set_name,key_sha256,first_run_at,node_id,attempt_id) VALUES(?,?,?,?,?,?,?,?)",
             (module, digest, f"ghcr.io/example/taskbench/t@sha256:{digest}", "tasks", "c" * 64, 1.0, "n_1", 1))
    img = rows(db, "taskbench", "images")
    assert [i["digest"] for i in img] == ["a" * 64] and img[0]["registry"] == "ghcr.io" and img[0]["platform"] == "linux/amd64"
    plats = {p["platform"]: p for p in rows(db, "taskbench", "platforms")}
    assert plats["linux-amd64"]["runner"] == "supported" and plats["darwin-arm64"]["coordinator"] == "any"
    db.x("INSERT INTO campaigns(campaign_id,module,name,state,created_at,placement_json) VALUES('c_pl','reel','x','running',0,?)",
         (json.dumps({"mix": "same-os", "unit": "campaign", "bind": "capacity", "rebind": "never", "pin": None}),))
    db.x("INSERT INTO placement_bindings(unit,module,campaign_id,mix,class,state,source) VALUES('c:c_pl','reel','c_pl','same-os','darwin',"
         "'hard','first_claim')")
    c = rows(db, "reel", "campaigns", campaign="c_pl")[0]
    assert (c["placement_mix"], c["bound_class"], c["binding_state"], c["binding_source"]) == ("same-os", "darwin", "hard", "first_claim")


def test_the_console_shapes_queries_with_the_published_shaper(env):
    db = env["db"]
    man = mf.load(TOY / "oarbank-module.toml")
    src = U.Source(query="results", agg={"value": "median"})
    assert modpages.resolve(db, "toy", man, src) == {"rows": [{"value": 8.5}]}
    src = U.Source(query="results", group_by="job_id", agg={"value": "sum"}, order_by="job_id", descending=False)
    assert modpages.resolve(db, "toy", man, src)["rows"] == [{"job_id": 901, "value": 6}, {"job_id": 902, "value": 11}]


# ------------------------------------------------------------------------------------------ 5, 7: services and the examples

def test_the_reference_modules_pages_render_in_the_console(env):
    db, c = env["db"], env["c"]
    _, n = enrolled_node(db, "studio")
    core.heartbeat(db, fresh(db, n), {"attempts": [], "services": [
        {"service": "modelserver/model", "health": "healthy", "running": True, "ready": True, "endpoint": True, "users": 1}]})
    db.x("INSERT INTO secrets(module,name,node_id,ciphertext,fingerprint,set_at,set_by) VALUES('taskbench','provider_key','',x'00',"
         "'fp:0123456789abcdef',1,'owner')")
    for path, want in (("/modules/modelserver", "studio model ready healthy"), ("/modules/gpuinfo", "GPU APIs per node"),
                       ("/modules/taskbench", "provider_key yes fp:0123456789abcdef"), ("/m/reel/data", "Checkpoints"),
                       ("/modules/reel", "Latest render")):
        r = c.get(path)
        assert r.status_code == 200, path
        assert "cannot be rendered" not in r.text and "needs UI contract" not in r.text, path
        assert want in text(r.text), (path, text(r.text)[:2000])
    assert 'href="/modules/taskbench/secrets"' in c.get("/modules/taskbench").text
    node = c.get(f"/nodes/{n['node_id']}").text
    assert "Model server" in node and "ready" in text(node)                            # modelserver's node panel ($node)
