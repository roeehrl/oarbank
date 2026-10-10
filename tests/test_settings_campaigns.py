"""Campaign overrides (docs/design/settings.md, "Campaign overrides"): the keys a campaign may override (core keys in
the registry, a module's own keys declared `campaign` in its manifest), the write paths (settings.apply at scope
`campaign`, a module's campaigns.create / campaigns.update `settings`) through locks, the overridable check and the
tighten-only rule of safety keys, and where the campaign layer applies: replica sampling, claim (a node-applied key
holds the campaign's jobs), its jobs' runners, campaign.tick, explain and the console's campaign page."""
import pytest
from fastapi.testclient import TestClient

from helpers import (PARAMS, READY, SCENES, admin_headers, certify, create_study, enrolled_node, fresh, make_db, run_op,
                     settings_apply, sign_in)
from oarbank.coordinator import campaigns, core, explain, ops
from oarbank.coordinator.settings import apply as A, registry as R, resolve as V, store


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def camp(db, cid="c_one", module="relay", state="running"):
    db.x("INSERT INTO campaigns(campaign_id, module, name, state, created_at) VALUES(?,?,?,?,0)", (cid, module, cid, state))
    return cid


def put(db, cid, key, value, module=""):
    return settings_apply(db, {"scope": "campaign", "scope_id": cid, "module": module, "key": key, "value": value})


def refused(db, *changes) -> list:
    with pytest.raises(A.ApplyError) as e:
        A.plan(db, list(changes))
    return [(x["code"], x["message"]) for x in e.value.errors]


def test_the_registry_declares_campaign_keys_and_which_way_safety_keys_tighten():
    assert sorted(d.key for d in R.SETTINGS if d.campaign) == ["jobs", "replica_rate", "run_on_battery", "user_present_slots"]
    d = R.REGISTRY
    assert (d["run_on_battery"].tighten_dir, d["user_present_slots"].tighten_dir, d["replica_rate"].tighten_dir,
            d["jobs"].tighten_dir, d["enforce"].tighten_dir, d["job_mem_gb"].tighten_dir) == \
        ("lower", "lower", "higher", "lower", "higher", None)
    assert R.tighter(d["run_on_battery"], True, False) is False and R.tighter(d["jobs"], None, 3) == 3
    assert R.tighter(d["enforce"], "soft", "hard") == "hard" and R.tighter(d["replica_rate"], 0.03, 0.01) == 0.03
    assert R.loosens(d["user_present_slots"], 3, 2) and not R.loosens(d["user_present_slots"], 1, 2)
    assert not R.loosens(d["job_mem_gb"], 9, 1)                          # a preference: no direction


def test_writes_go_through_locks_the_overridable_check_and_tighten_only(db):
    enrolled_node(db, "mini")
    cid = camp(db)
    p = A.plan(db, [{"scope": "campaign", "scope_id": cid, "key": "replica_rate", "value": 0.2}])
    assert p["summary"].startswith("While c_one runs") and "Replica rate 0.03 → 0.2" in p["campaign"][0]
    assert p["_tier"] == "T1"                                        # a campaign change keeps the key's own tier
    put(db, cid, "replica_rate", 0.2)
    assert store.row(db, "campaign", cid, "", "replica_rate")["value"] == 0.2
    assert refused(db, {"scope": "campaign", "scope_id": cid, "key": "replica_rate", "value": 0.01})[0][0] == "loosens"
    assert refused(db, {"scope": "campaign", "scope_id": cid, "key": "run_on_battery", "value": True})[0] == (
        "loosens", "a campaign may only tighten Run jobs on battery (off is stricter): the fleet's value is off, and on "
                   "would loosen it")
    assert refused(db, {"scope": "campaign", "scope_id": cid, "key": "job_mem_gb", "value": 2})[0][0] == "not_campaign_overridable"
    assert refused(db, {"scope": "campaign", "scope_id": "c_nope", "key": "jobs", "value": 2})[0][0] == "unknown_campaign"
    # a module's own key: only one its schema declares `campaign`, and only for the campaign's module
    put(db, cid, "tile_size", 64)
    assert store.row(db, "campaign", cid, "relay", "module.relay.tile_size")["value"] == 64
    assert refused(db, {"scope": "campaign", "scope_id": cid, "key": "vm_mem_gb", "value": 4})[0][0] == "not_campaign_overridable"
    assert refused(db, {"scope": "campaign", "scope_id": cid, "key": "tile_size", "value": 7})[0][0] == "bad_value"
    assert refused(db, {"scope": "campaign", "scope_id": cid, "module": "toy", "key": "jobs", "value": 1})[0][0] == "not_settable_here"
    # a lock binds campaigns too
    settings_apply(db, {"scope": "fleet", "key": "jobs", "value": 4, "enforce": True})
    assert refused(db, {"scope": "campaign", "scope_id": cid, "key": "jobs", "value": 2})[0] == (
        "locked", "Concurrent jobs: locked by Fleet settings: change it there")
    # a reset is always allowed
    settings_apply(db, {"scope": "campaign", "scope_id": cid, "key": "replica_rate", "reset": True})
    assert store.row(db, "campaign", cid, "", "replica_rate") is None


def test_safety_keys_only_tighten_and_a_finished_campaigns_overrides_apply_nowhere(db):
    _, mini = enrolled_node(db, "mini")
    cid = camp(db)
    settings_apply(db, {"scope": "node", "scope_id": "mini", "key": "user_present_slots", "value": 1})
    put(db, cid, "user_present_slots", 2)                    # not looser than the fleet's 2: allowed
    res = V.resolve(V.snapshot(db), fresh(db, mini), "user_present_slots", campaign=cid)
    assert res["value"] == 1 and res["source"]["scope"] == "node" and res["chain"][-1]["role"] == "looser"
    put(db, cid, "user_present_slots", 0)
    res = V.resolve(V.snapshot(db), fresh(db, mini), "user_present_slots", campaign=cid)
    assert res["value"] == 0 and V.badge(res) == f"Campaign {cid}"
    assert V.resolve(V.snapshot(db), fresh(db, mini), "user_present_slots")["value"] == 1    # nothing else changes
    db.x("UPDATE campaigns SET state='done' WHERE campaign_id=?", (cid,))
    res = V.resolve(V.snapshot(db), fresh(db, mini), "user_present_slots", campaign=cid)
    assert res["value"] == 1 and res["chain"][-1]["inactive"] and "done" in res["chain"][-1]["reason"]


def test_a_modules_campaign_carries_overrides_that_reach_its_runners_ticks_and_replicas(db):
    node = certify(db, enrolled_node(db)[1])
    cid = create_study(db, "deep", [], SCENES[:3], {"label": "base", "params": PARAMS},
                       settings={"tile_size": 64, "replica_rate": 0.5})
    assert store.row(db, "campaign", cid, "relay", "module.relay.tile_size")["value"] == 64
    snap = V.snapshot(db)
    assert V.resolve(snap, None, "replica_rate", "relay", cid)["value"] == 0.5             # what _maybe_replicate reads
    assert V.resolve(snap, None, "replica_rate", "relay")["value"] == 0.03
    row = campaigns.campaign_row(db, db.one("SELECT * FROM campaigns WHERE campaign_id=?", (cid,)))
    assert row["settings"]["tile_size"] == 64 and row["overrides"] == {"module.relay.tile_size": 64, "replica_rate": 0.5}
    g = core.claim(db, fresh(db, node), {"free_slots": 2, "ready_datasets": READY})["grants"]
    assert g and all(x["settings"] == {"tile_size": 64} for x in g)
    # an invalid override refuses the module's whole operation
    with pytest.raises(ops.OpError) as e:
        create_study(db, "bad", [], SCENES[:1], {"label": "base", "params": PARAMS}, settings={"tile_size": 7})
    assert "bad_settings" in str(e.value.code) + str(e.value.detail)


def test_a_campaigns_node_keys_hold_its_jobs_at_claim_and_explain_says_why(db):
    node = certify(db, enrolled_node(db)[1])
    cid = create_study(db, "narrow", [], SCENES[:4], {"label": "base", "params": PARAMS}, settings={"jobs": 1})
    g = core.claim(db, fresh(db, node), {"free_slots": 4, "ready_datasets": READY})["grants"]
    assert len(g) == 1                                                       # one of its jobs at a time on this node
    jid = db.one("SELECT job_id FROM jobs WHERE campaign_id=? AND state='pending' LIMIT 1", (cid,))["job_id"]
    assert "CAMPAIGN_SETTING_HOLDS" in explain.job_doc(db, jid).model_dump_json()
    # run_on_battery off: none of its jobs while the node runs on battery
    settings_apply(db, {"scope": "campaign", "scope_id": cid, "key": "jobs", "reset": True})
    settings_apply(db, {"scope": "fleet", "key": "run_on_battery", "value": True})
    put(db, cid, "run_on_battery", False)
    db.x("UPDATE nodes SET telemetry_json='{\"on_battery\": true}' WHERE node_id=?", (node["node_id"],))
    assert core.claim(db, fresh(db, node), {"free_slots": 4, "ready_datasets": READY})["grants"] == []
    db.x("UPDATE nodes SET telemetry_json='{\"on_battery\": false}' WHERE node_id=?", (node["node_id"],))
    assert core.claim(db, fresh(db, node), {"free_slots": 4, "ready_datasets": READY})["grants"]


def test_the_api_and_console_show_the_campaign_layer(db):
    from oarbank.coordinator import app as coord_app
    _, n = enrolled_node(db, "mini")
    cid = camp(db)
    put(db, cid, "jobs", 2)
    c = TestClient(coord_app.admin_app(db, coord_app.EventBus()))
    h = admin_headers(db)
    doc = c.get(f"/api/v1/settings/effective?campaign={cid}&node=mini", headers=h).json()
    jobs = next(x for x in doc["settings"] if x["key"] == "jobs")
    assert jobs["value"] == 2 and jobs["set_by_campaign"] and jobs["badge"] == f"Campaign {cid}"
    ex = c.get(f"/api/v1/settings/explain?key=jobs&campaign={cid}&node=mini", headers=h).json()
    assert ex["chain"][-1]["scope"] == "campaign" and ex["chain"][-1]["role"] == "winner"
    assert c.get("/api/v1/settings/effective?campaign=c_nope", headers=h).status_code == 404


# ------------------------------------------------------------------ the console's campaign page

from test_console import env, save_section, settings_html  # noqa: E402,F401 (the console fixture)


def test_the_campaign_page_sets_and_resets_overrides_after_a_preview(env):
    db, c, sid = env["db"], env["c"], env["sid"]
    html, text = settings_html(env, path=f"/campaigns/{sid}")
    assert "While this campaign runs" in text and "Replica rate" in text and "Concurrent jobs" in text
    assert "Tile size" in text                                     # relay's own key it declares `campaign`
    assert "A campaign may only tighten it (off is stricter)" in text
    r = save_section(env, "campaign-settings", page=f"/campaigns/{sid}", **{"o.jobs": "1", "v.jobs": "2"})
    assert r.status_code == 200 and 'name="plan_id"' in r.text and "While study-a runs" in r.text
    plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
    r = c.post("/apply/settings.apply", data={"plan_id": plan_id, "reason": "narrow", "return_to": f"/campaigns/{sid}"},
               follow_redirects=False)
    assert r.status_code == 303
    assert store.row(db, "campaign", sid, "", "jobs")["value"] == 2
    _, text = settings_html(env, path=f"/campaigns/{sid}")
    assert "while this campaign runs" in text and f"Campaign study-a" in text
    # a looser safety value comes back refused, beside its field
    r = save_section(env, "campaign-settings", page=f"/campaigns/{sid}", **{"o.run_on_battery": "1", "v.run_on_battery": "1"})
    assert r.status_code == 400 and "There is a problem" in r.text and "may only tighten" in r.text
