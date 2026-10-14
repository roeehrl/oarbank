"""Module cleanup (docs/protocol.md, "Module cleanup"): what each module keeps on a node and when the node deletes what a
module that left it put there, as the agent reports it; each deletion recorded once and acknowledged; the owner's purge,
never where the module is enabled; the retention setting; explain's conditions; the cleanup stage in the release entry;
and a retired node's agent told so."""
import json
import shutil
import time

import pytest

from helpers import TOY_DIR, certify, enrolled_node, fresh, make_db, node_settings, run_op, set_node
from oarbank.coordinator import core, detail, explain, modcleanup, ops, placement, releases
from test_console_parity import console, fleet, oarbank, text  # noqa: F401 (the console and CLI fixtures)

DAY = 86400.0


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


@pytest.fixture
def node(db):
    return certify(db, enrolled_node(db)[1])


def storage(now: float) -> dict:
    """An agent's `module_storage`: toy enabled, relay turned off and deleted in a week, a cache over its cap."""
    return {"at": now, "retention_days": 7, "unremoved_images": 1,
            "modules": [{"module": "toy", "state": "enabled", "in_release": True, "data_bytes": 1024, "cache_bytes": 0,
                         "datasets": 0, "images": 0, "image_bytes": None, "delete_at": None},
                        {"module": "relay", "state": "disabled", "in_release": True, "data_bytes": 3 << 20,
                         "cache_bytes": 20 << 30, "datasets": 3, "images": 2, "image_bytes": 1 << 30,
                         "delete_at": now + 7 * DAY}],
            "cache": {"bytes": 21 << 30, "datasets": 3, "cap_bytes": 10 << 30, "over_cap": True}}


def deletion(rid: str, module: str, why: str, ok: bool | None = True) -> dict:
    return {"id": rid, "module": module, "reason": why, "at": time.time(), "freed_bytes": 5 << 20, "images_removed": 1,
            "cleanup": None if ok is None else {"stage": "release", "ok": ok, "detail": "" if ok else "the registry said no",
                                                 "seconds": 0.4},
            "error": None}


def events(db, kind: str) -> list[dict]:
    return db.q("SELECT * FROM events WHERE kind=? ORDER BY event_id", (kind,))


def test_what_modules_keep_is_reported_and_each_deletion_is_recorded_once(db, node):
    now = time.time()
    body = {"attempts": [], "module_storage": storage(now), "module_cleanup": [deletion("old@1", "old", "removed", ok=False)]}
    d = core.heartbeat(db, fresh(db, node), body)
    assert d["module_cleanup_ack"] == ["old@1"] and d["module_purge"] == []
    (deleted,) = events(db, "module_data_deleted")
    assert deleted["module"] == "old" and deleted["reason"] == ("old (no longer in the node's release): 5.0 MB deleted, 1 images "
                                                                "removed; cleanup stage release failed")
    (failed,) = events(db, "module_cleanup_failed")
    assert failed["reason"] == "old: cleanup stage release: the registry said no"
    d = core.heartbeat(db, fresh(db, node), body)             # the acknowledgement was lost: the agent sends it again
    assert d["module_cleanup_ack"] == ["old@1"] and len(events(db, "module_data_deleted")) == 1
    assert "module_cleanup_ack" not in core.heartbeat(db, fresh(db, node), {"attempts": []})

    doc = detail.node(db, node["node_id"], now, lambda m: None)["storage"]
    assert doc["reported"] and doc["retention_days"] == 7 and doc["unremoved_images"] == 1
    toy, relay = doc["modules"]
    assert (toy["module"], toy["leaving"], toy["total_text"]) == ("toy", False, "1 KB")
    assert (relay["leaving"], relay["why"], relay["total_text"], relay["images_text"]) == (True, "turned off here", "21.0 GB",
                                                                                         "2 (1.0 GB)")
    assert doc["cache"]["text"] == "21.0 GB of 10.0 GB" and doc["cache"]["over_cap"]

    rows = {r.code: r.detail for r in explain.node_doc(db, node["node_id"]).summary}
    assert rows["MODULE_DATA_SCHEDULED"]["module"] == "relay" and rows["MODULE_DATA_SCHEDULED"]["why"] == "turned off here"
    assert rows["MODULE_DATA_SCHEDULED"]["when"].startswith("in 7.0 days")
    assert rows["DISK_CACHE_OVER_CAP"] == {"used": "21.0 GB", "cap": "10.0 GB"}
    assert rows["MODULE_CLEANUP_FAILED"]["module"] == "old"
    remedies = {r.op for r in explain.node_doc(db, node["node_id"]).remedies}
    assert {"modules.purge", "settings.apply"} <= remedies


def test_a_purge_never_reaches_a_node_where_the_module_is_enabled(db, node):
    nid = node["node_id"]
    with pytest.raises(core.ApiError) as e:
        run_op(db, "modules.purge", "toy", {"node": nid})
    assert (e.value.status, e.value.code) == (409, "module_enabled") and "turn it off there first" in e.value.detail
    with pytest.raises(core.ApiError) as e:
        run_op(db, "modules.purge", "toy", {"all": True})
    assert "enabled on every node" in e.value.detail
    for params, code in (({}, "bad_params"), ({"node": nid, "all": True}, "bad_params")):
        with pytest.raises(core.ApiError) as e:
            run_op(db, "modules.purge", "toy", params)
        assert e.value.code == code
    with pytest.raises(core.ApiError) as e:
        run_op(db, "modules.purge", "nosuch", {"node": nid})
    assert e.value.status == 404

    set_node(db, node, "enabled", False, module="toy")
    second = certify(db, enrolled_node(db, "desk")[1])
    plan = ops.execute(db, ops.OpRequest(op="modules.purge", actor="test", target="toy", params={"all": True},
                                         dry_run=True))["plan"]
    assert plan["impact"]["deletes_on"] == ["mini: nothing reported"] and plan["impact"]["enabled_on"] == ["desk"]
    out = run_op(db, "modules.purge", "toy", {"node": "mini"})
    assert out["result"] == {"module": "toy", "nodes": ["mini"]}
    assert core.heartbeat(db, fresh(db, node), {"attempts": []})["module_purge"] == ["toy"]
    assert core.heartbeat(db, fresh(db, second), {"attempts": []})["module_purge"] == []
    (a,) = db.q("SELECT * FROM audit WHERE operation='modules.purge' AND outcome='ok' AND NOT dry_run")
    assert json.loads(a["after_json"]) == {"purging": ["mini"]} and a["target_id"] == "toy"
    # the node deleted it: the purge is done
    d = core.heartbeat(db, fresh(db, node), {"attempts": [], "module_cleanup": [deletion("toy@9", "toy", "purge", ok=None)]})
    assert d["module_purge"] == [] and modcleanup.purges(fresh(db, node)) == []
    # turned on again before the node deleted it: the purge is dropped, never sent
    run_op(db, "modules.purge", "toy", {"node": "mini"})
    set_node(db, node, "enabled", True, module="toy")
    assert core.heartbeat(db, fresh(db, node), {"attempts": []})["module_purge"] == []
    assert [e["module"] for e in events(db, "module_purge_dropped")] == ["toy"]


def test_the_retention_setting_reaches_the_agent(db, node):
    assert node_settings(db, node)["module_retention_days"] == 7
    set_node(db, node, "module_retention_days", 0)
    assert node_settings(db, node)["module_retention_days"] == 0
    with pytest.raises(Exception, match="below 0"):
        set_node(db, node, "module_retention_days", -1)


def test_the_cleanup_stage_is_in_the_release_entry_and_no_job_runs_it(db, tmp_path, monkeypatch):
    src = tmp_path / "toy"
    shutil.copytree(TOY_DIR, src, ignore=shutil.ignore_patterns("dist", "__pycache__"))
    m = src / "oarbank-module.toml"
    text = m.read_text(encoding="utf-8").replace('core = ">=2.9,<3"', 'core = ">=2.11,<3"')
    m.write_text(text + '\n[[stages]]\nname = "release"\ncleanup = true\ntimeout_s = 90\n'
                        'requires = { resources = { cpu = 0.5, mem_gb = 0.25 } }\n', encoding="utf-8")
    e = releases.module_entry("toy", "0.1.0", "d" * 64, src, "linux-amd64")
    assert e["stages"][-1] == {"name": "release", "capabilities": [], "pools": [], "platforms": [], "cleanup": True,
                               "timeout_s": 90.0, "cpu": 0.5, "mem_gb": 0.25}
    assert "cleanup" not in e["stages"][0] and e["requires"] == []

    from oarbank_sdk import manifest as mf

    class Info:
        manifest = mf.load(m)
    monkeypatch.setattr(placement.modcalls, "info", lambda name: Info)
    with pytest.raises(placement.PlacementError) as err:
        placement.check_stage("toy", {"stage": "release"})
    assert (err.value.status, err.value.code) == (422, "cleanup_stage") and "no job does" in err.value.detail
    assert placement.check_stage("toy", {"stage": "run"}) == "run"


def test_a_retired_nodes_certificate_says_so(db, node):
    from cryptography import x509
    der, n2 = enrolled_node(db, "spare")
    run_op(db, "nodes.retire", n2["node_id"], confirm="spare")
    with pytest.raises(core.ApiError) as e:
        core.auth_cert(db, der, "127.0.0.1")
    assert (e.value.status, e.value.code) == (403, "node_retired")
    x509.load_der_x509_certificate(der)                       # a real certificate, only its node is retired


def test_node_show_and_the_node_page_say_what_modules_keep_and_purge_from_both(console, capsys):
    """`oarbank node show` and the node page say the same of what each module keeps on the node; `oarbank module purge`
    and the page's Delete now reach the same operation, refused where the module is enabled."""
    db, nid, c = console["db"], console["nid"], console["c"]
    code, out = oarbank(capsys, "node", "show", nid)
    assert "module data: not reported yet" in out
    assert "Not reported yet" in text(c.get(f"/nodes/{nid}").text)
    core.heartbeat(db, fresh(db, {"node_id": nid}), {"attempts": [], "module_storage": storage(time.time())})
    code, out = oarbank(capsys, "node", "show", nid)
    lines = [x.strip() for x in out.splitlines()]
    assert code == 0 and "toy: 1 KB (data 1 KB, datasets 0 B in 0, images 0)" in lines
    relay = next(x for x in lines if x.startswith("relay: 21"))
    assert relay.startswith("relay: 21.0 GB (data 3.0 MB, datasets 20.0 GB in 3, images 2 (1.0 GB)), deleted ") \
        and relay.endswith("(turned off here)")
    assert "dataset cache: 21.0 GB of 10.0 GB, 3 datasets OVER THE CAP: what is left is in use" in lines
    assert "images of deleted modules waiting for the container runtime: 1" in lines
    doc = json.loads(oarbank(capsys, "node", "show", nid, "--json")[1])
    assert doc["storage"] == json.loads(json.dumps(detail.node(db, nid, time.time(), lambda m: None)["storage"]))
    page = text(c.get(f"/nodes/{nid}").text)
    assert "relay 21.0 GB 3.0 MB 20.0 GB (3) 2 (1.0 GB)" in page and "turned off here" in page
    assert "toy 1 KB 1 KB 0 B 0 kept: enabled here" in page
    assert "Dataset cache: 21.0 GB of 10.0 GB, 3 datasets over its cap" in page
    form = c.get(f"/nodes/{nid}").text
    assert 'action="/do/modules.purge"' in form and 'name="target" value="relay"' in form
    # relay is still enabled here: the purge is refused, from the CLI and the console alike
    code, out = oarbank(capsys, "module", "purge", "relay", "--node", nid, "--yes")
    assert code == 1 and "module_enabled" in out
    assert oarbank(capsys, "module", "purge", "relay")[0] == 1
    set_node(db, nid, "enabled", False, module="relay")
    code, out = oarbank(capsys, "module", "purge", "relay", "--node", "mini", "--yes")
    assert code == 0 and "modules.purge (T2) on relay:" in out and "deletes on: mini: 21.0 GB (2 images)" in out
    assert "relay: deleted at the next heartbeat of mini" in out
    assert "purges waiting for the node: relay" in oarbank(capsys, "node", "show", nid)[1]
