"""Groups, labels, locks, bulk changes and canary-then-promote (docs/design/settings.md, "Groups and labels", "Locks",
"Bulk changes", "Canary to a group"): owner groups with a rank and a selector over facts and labels, the phase-4 exit
test (a Laptops group's locked run_on_battery = false holds against node and campaign overrides), one change set across
many nodes with its preview, and a group's value promoted to the fleet."""
import json

import pytest

from helpers import FACTS, admin_headers, certify, enrolled_node, facts_for, make_db, node_settings, set_node, settings_apply
from oarbank.coordinator import core, ops
from oarbank.coordinator.settings import apply as A, groups as G, registry as R, resolve as V, store

LAPTOP = {**FACTS, "power": {"battery": True}}


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def row(db, n):
    return db.one("SELECT * FROM nodes WHERE node_id=?", (n if isinstance(n, str) else n["node_id"],))


def groups_of(db, n) -> list[str]:
    return [g["name"] for g in V.node_groups(V.snapshot(db), row(db, n))]


def run_op(db, name, target=None, params=None, role=None, dry_run=False, reason="test"):
    """An operation as a client sends it: previewed, and the plan applied (confirmed at T3), whenever its tier for
    this request is T2 or T3."""
    req = dict(op=name, actor="test", source="system", target=target, params=params or {}, reason=reason, role=role)
    if dry_run:
        return ops.execute(db, ops.OpRequest(**req, dry_run=True))
    if ops.tier_of(ops.OpRequest(**req)) in ("T2", "T3"):
        plan = ops.execute(db, ops.OpRequest(**req, dry_run=True))["plan"]
        req.update(plan_id=plan["plan_id"], confirm=plan["confirm_name"])
    return ops.execute(db, ops.OpRequest(**req))


def create(db, name, **params):
    return run_op(db, "groups.create", name, params)["result"]


# ------------------------------------------------------------------ selectors and membership

def test_selectors_match_facts_labels_names_and_explicit_members(db):
    mbp = enrolled_node(db, "macbook", facts=LAPTOP)[1]
    mini = enrolled_node(db, "mini")[1]
    big = enrolled_node(db, "studio", facts={**FACTS, "memory_gb": 128.0})[1]
    box = enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1]
    create(db, "Laptops", selector={"battery": True})
    create(db, "Big Macs", selector={"os": "macOS", "ram_gb_min": 64})
    create(db, "Lab", selector={"hostname": ["mini*", "bo?"]})
    create(db, "Pinned", members=["studio"])
    assert groups_of(db, mbp) == ["macOS", "Laptops"]
    assert groups_of(db, mini) == ["macOS", "Lab"]
    assert groups_of(db, big) == ["macOS", "Big Macs", "Pinned"]
    assert groups_of(db, box) == ["Linux", "Lab"]
    # why: each term that holds, or "listed as a member"
    snap = V.snapshot(db)
    why = {g["name"]: g["why"] for g in V.memberships(snap, row(db, big)) if g["member"]}
    assert why["Big Macs"] == ["macOS", "64 GB of RAM or more"] and why["Pinned"] == ["listed as a member"]
    miss = next(g for g in V.memberships(snap, row(db, mini)) if g["name"] == "Big Macs")
    assert not miss["member"] and miss["missing"] == ["64 GB of RAM or more"]
    # a fact label: a node with a battery carries `laptop` without anyone setting it
    assert snap.node_labels(row(db, mbp)) == {"owner": [], "facts": ["laptop"], "all": ["laptop"]}


def test_labels_move_nodes_into_and_out_of_groups(db):
    a = enrolled_node(db, "a")[1]
    b = enrolled_node(db, "b")[1]
    create(db, "Render", selector={"labels": ["render"]})
    settings_apply(db, {"scope": "group", "scope_id": "Render", "key": "job_mem_gb", "value": 4})
    plan = run_op(db, "nodes.label", "a", {"add": ["render"], "nodes": ["b"]}, dry_run=True)["plan"]
    assert set(plan["impact"]["joins"]) == {"a joins Render", "b joins Render"}
    assert "a: Memory per job slot 1.5 GB → 4 GB" in plan["impact"]["nodes_changed"]
    rev = row(db, a)["settings_rev"]
    res = run_op(db, "nodes.label", "a", {"add": ["Render"], "nodes": ["b"]})["result"]
    assert res["labels"] == {a["node_id"]: ["render"], b["node_id"]: ["render"]}
    assert node_settings(db, a)["job_mem_gb"] == 4 and row(db, a)["settings_rev"] > rev
    run_op(db, "nodes.label", "b", {"remove": ["render"]})
    assert node_settings(db, b)["job_mem_gb"] == 1.5 and groups_of(db, b) == ["macOS"]       # no stale copy
    with pytest.raises(ops.OpError) as e:
        run_op(db, "nodes.label", "a", {"add": ["Not A Label!"]})
    assert e.value.code == "bad_label"


def test_ranks_decide_between_groups_and_explain_names_the_loser(db):
    n = enrolled_node(db, "macbook", facts=LAPTOP)[1]
    create(db, "Laptops", selector={"battery": True})
    create(db, "Travel", members=["macbook"])                         # created last: ranks highest
    settings_apply(db, {"scope": "group", "scope_id": "Laptops", "key": "user_present_slots", "value": 0},
                   {"scope": "group", "scope_id": "Travel", "key": "user_present_slots", "value": 1})
    res = V.resolve(V.snapshot(db), row(db, n), "user_present_slots")
    assert res["value"] == 1 and res["source"]["name"] == "Group: Travel"
    assert {x["name"]: x["role"] for x in res["chain"] if x["set"]} == {"Group: Laptops": "shadowed", "Group: Travel": "winner"}
    plan = run_op(db, "groups.rank", "Travel", {"move": "down"}, dry_run=True)["plan"]
    assert plan["impact"]["order"].startswith("Laptops > Travel")
    assert plan["impact"]["nodes_changed"] == ["macbook: Jobs while someone is using this computer 1 jobs → 0 jobs"]
    run_op(db, "groups.rank", "Travel", {"move": "down"})
    assert node_settings(db, n)["user_present_slots"] == 0
    ranks = {g["name"]: g["rank"] for g in store.groups(db)}
    assert ranks["Laptops"] > ranks["Travel"] >= store.OWNER_RANK_MIN > ranks["Coordinator host"]
    with pytest.raises(ops.OpError) as e:                             # built-in groups keep their system membership
        run_op(db, "groups.update", "macOS", {"selector": {"os": "linux"}})
    assert e.value.code == "builtin_group"


def test_a_group_change_previews_who_joins_and_what_changes(db):
    a = enrolled_node(db, "a")[1]
    enrolled_node(db, "b", facts={**FACTS, "memory_gb": 64.0})
    create(db, "Big", selector={"ram_gb_min": 64})
    settings_apply(db, {"scope": "group", "scope_id": "big", "key": "job_mem_gb", "value": 3})
    plan = run_op(db, "groups.update", "Big", {"selector": {"ram_gb_min": 16}}, dry_run=True)["plan"]
    assert plan["tier"] == "T2" and plan["impact"]["joins"] == ["a joins Big"]
    assert plan["impact"]["summary"] == "Changes the effective settings of 1 node (a)"
    ops.execute(db, ops.OpRequest(op="groups.update", actor="owner", plan_id=plan["plan_id"], reason="all Macs"))
    assert node_settings(db, a)["job_mem_gb"] == 3
    # deleting the group deletes its values: its members fall back to the fleet
    plan = run_op(db, "groups.delete", "Big", dry_run=True)["plan"]
    assert plan["impact"]["values_deleted"] == ["job_mem_gb"]
    run_op(db, "groups.delete", "Big")
    assert node_settings(db, a)["job_mem_gb"] == 1.5 and not store.rows(db, "job_mem_gb")
    assert db.one("SELECT reason FROM events WHERE kind='groups_changed' ORDER BY event_id DESC LIMIT 1")


def test_selectors_and_names_are_checked(db):
    for params, code in (({"selector": {"colour": "red"}}, "bad_selector"), ({"selector": {"os": "beos"}}, "bad_selector"),
                         ({"selector": {"battery": "yes"}}, "bad_selector"), ({"members": ["nope"]}, "unknown_node"),
                         ({"selector": {"ram_gb_min": 64, "ram_gb_max": 8}}, "bad_selector")):
        with pytest.raises(ops.OpError) as e:
            create(db, "X", **params)
        assert e.value.code == code, params
    create(db, "Laptops", selector={"battery": True})
    with pytest.raises(ops.OpError) as e:
        create(db, "laptops")
    assert e.value.code == "name_taken"


# ------------------------------------------------------------------ locks: the phase-4 exit test

def test_a_laptops_group_with_locked_run_on_battery_holds_against_node_and_campaign_overrides(db, monkeypatch):
    """Phase 4's exit test (docs/design/settings.md, "Locks"). A node that already ran on battery by its own choice is
    held off battery by the lock; setting its own value again is refused naming the group; the node's value is kept but
    ignored, and comes back if the lock goes; a campaign override is refused the same way, and a campaign value that
    exists anyway is ignored under the lock."""
    mbp = certify(db, enrolled_node(db, "macbook", facts=LAPTOP)[1])
    mini = certify(db, enrolled_node(db, "mini")[1])
    set_node(db, mbp, "run_on_battery", True)                          # a choice made before the lock
    set_node(db, mini, "run_on_battery", True)
    create(db, "Laptops", selector={"battery": True})
    change = {"changes": [{"scope": "group", "scope_id": "Laptops", "key": "run_on_battery", "value": False,
                           "enforce": True}]}
    plan = run_op(db, "settings.apply", "laptops", change, dry_run=True)["plan"]
    assert plan["tier"] == "T3" and plan["confirm_required"]
    assert plan["impact"]["nodes_changed"] == ["macbook: Run jobs on battery on → off"]
    assert any("macbook sets its own value (on): ignored while the lock holds" in x for x in plan["impact"]["lock_notes"])
    run_op(db, "settings.apply", "laptops", change)
    assert node_settings(db, mbp)["run_on_battery"] is False             # the lock holds
    assert node_settings(db, mini)["run_on_battery"] is True             # not a laptop: its own choice stays
    res = V.resolve(V.snapshot(db), row(db, mbp), "run_on_battery")
    assert res["locked_by"] == {"scope": "group", "id": "laptops", "name": "Group: Laptops"}
    assert res["chain"][-1] == {**res["chain"][-1], "scope": "node", "value": True, "role": "ignored"}
    # a node override is refused, naming the group
    with pytest.raises(ops.OpError) as e:
        run_op(db, "settings.apply", mbp["node_id"], {"changes": [{"scope": "node", "scope_id": "macbook",
                                                                   "key": "run_on_battery", "value": True}]})
    assert e.value.code == "invalid_settings"
    assert e.value.extra["errors"][0]["message"] == "locked by the group Laptops: change it there"
    assert node_settings(db, mbp)["run_on_battery"] is False
    # the agent gets the locked value, and the console row says who locked it
    assert core._node_directives(db, row(db, mbp))["policy"]["run_on_battery"] is False
    from oarbank.coordinator.settings import views
    r = views.row(V.snapshot(db), R.REGISTRY["run_on_battery"], "node", row(db, mbp))
    assert r["locked_by"]["name"] == "Group: Laptops" and r["lock_text"] == "Locked by the group Laptops"
    # campaigns: the hook a campaign override goes through refuses it with the same lock, even for a key a campaign
    # could otherwise override; and a campaign value written anyway is ignored under the lock
    monkeypatch.setitem(R.REGISTRY, "run_on_battery", __import__("dataclasses").replace(R.REGISTRY["run_on_battery"], campaign=True))
    refused = A.campaign_refusals(db, "c_1", "run_on_battery")
    assert [x["message"] for x in refused] == ["Run jobs on battery: locked by the group Laptops on macbook: change it there"]
    store.put(db, "campaign", "c_1", "", "run_on_battery", True, "test", 99)
    res = V.resolve(V.snapshot(db), row(db, mbp), "run_on_battery", campaign="c_1")
    assert res["value"] is False and res["chain"][-1]["scope"] == "campaign" and res["chain"][-1]["role"] == "ignored"
    assert V.resolve(V.snapshot(db), row(db, mini), "run_on_battery", campaign="c_1")["source"]["scope"] == "campaign"
    monkeypatch.undo()
    assert A.campaign_refusals(db, "c_1", "job_mem_gb")[0]["code"] == "not_campaign_overridable"
    # lifting the lock: the node's own choice comes back (it was never deleted)
    settings_apply(db, {"scope": "group", "scope_id": "Laptops", "key": "run_on_battery", "reset": True})
    assert node_settings(db, mbp)["run_on_battery"] is True


def test_an_operator_cannot_unlabel_a_node_out_of_a_locked_group(db):
    enrolled_node(db, "a")
    create(db, "Quiet", selector={"labels": ["quiet"]})
    run_op(db, "nodes.label", "a", {"add": ["quiet"]})
    settings_apply(db, {"scope": "group", "scope_id": "Quiet", "key": "user_present_slots", "value": 0, "enforce": True})
    with pytest.raises(ops.OpError) as e:
        run_op(db, "nodes.label", "a", {"remove": ["quiet"]}, role="operator")
    assert e.value.code == "forbidden_role" and "leave the group Quiet" in e.value.detail
    run_op(db, "nodes.label", "a", {"add": ["other"]}, role="operator")     # other labels are fine
    run_op(db, "nodes.label", "a", {"remove": ["quiet"]}, role="admin")


# ------------------------------------------------------------------ bulk

def test_a_bulk_set_and_reset_is_one_previewed_change_set(db):
    nodes = [certify(db, enrolled_node(db, h)[1]) for h in ("a", "b", "c")]
    set_node(db, nodes[2], "jobs", 1)
    changes = {"changes": [{"scope": "node", "scope_id": h, "key": "jobs", "value": 2} for h in ("a", "b", "c")]}
    plan = run_op(db, "settings.apply", "3 nodes", changes, dry_run=True)["plan"]
    assert {(x["hostname"], x["old"], x["new"]) for x in plan["impact"]["_diff"]} == {("a", None, 2), ("b", None, 2), ("c", 1, 2)}
    res = run_op(db, "settings.apply", "3 nodes", changes)["result"]
    assert all(node_settings(db, n)["jobs"] == 2 for n in nodes)
    assert len({row(db, n)["settings_rev"] for n in nodes}) == 1 == len({res["rev"]})      # one revision for all
    reset = {"changes": [{"scope": "node", "scope_id": h, "key": "jobs", "reset": True} for h in ("a", "b", "c")]}
    run_op(db, "settings.apply", "3 nodes", reset)
    assert all(node_settings(db, n)["jobs"] is None for n in nodes)
    # selecting by group or label, and a change set over more than ten nodes is one tier up
    from oarbank.coordinator.settings import bulk
    run_op(db, "nodes.label", "a", {"add": ["lab"], "nodes": ["b"]})
    assert [n["hostname"] for n in bulk.select_nodes(db, label="lab")] == ["a", "b"]
    assert [n["hostname"] for n in bulk.select_nodes(db, group="macOS")] == ["a", "b", "c"]
    many = [{"scope": "node", "scope_id": f"n{i}", "key": "jobs", "value": 1} for i in range(11)]
    assert bulk.tier(many) == "T1" and bulk.tier(many[:10]) == "T0"


# ------------------------------------------------------------------ canary, then promote

def test_a_change_goes_to_a_canary_group_first_then_is_promoted_to_the_fleet(db):
    a, b, c = (certify(db, enrolled_node(db, h)[1]) for h in ("a", "b", "c"))
    set_node(db, c, "job_mem_gb", 3)
    create(db, "Canary", members=["a"])
    settings_apply(db, {"scope": "group", "scope_id": "Canary", "key": "job_mem_gb", "value": 2})
    assert [node_settings(db, n)["job_mem_gb"] for n in (a, b, c)] == [2, 1.5, 3]
    plan = run_op(db, "settings.promote", "job_mem_gb", {"key": "job_mem_gb", "group": "Canary"}, dry_run=True)["plan"]
    assert plan["tier"] == "T2"
    assert plan["impact"]["changes"] == ["Memory per job slot at Fleet: not set → 2 GB",
                                         "Memory per job slot at group Canary: 2 GB → reset (inherits)"]
    assert plan["impact"]["summary"] == "Changes the effective value on 1 node (b); 2 nodes keep theirs (a, c)"
    run_op(db, "settings.promote", "job_mem_gb", {"key": "job_mem_gb", "group": "Canary"})
    assert [node_settings(db, n)["job_mem_gb"] for n in (a, b, c)] == [2, 2, 3]
    assert store.row(db, "group", "canary", "", "job_mem_gb") is None
    assert store.row(db, "fleet", "", "", "job_mem_gb")["value"] == 2
    with pytest.raises(ops.OpError) as e:
        run_op(db, "settings.promote", "job_mem_gb", {"key": "job_mem_gb", "group": "Canary"}, dry_run=True)
    assert e.value.code == "nothing_to_promote"


# ------------------------------------------------------------------ the API and CLI documents

def test_the_groups_api(db):
    from fastapi.testclient import TestClient
    from oarbank.coordinator import app as coord_app
    enrolled_node(db, "macbook", facts=LAPTOP)
    enrolled_node(db, "mini")
    create(db, "Laptops", selector={"battery": True}, description="the portable ones")
    run_op(db, "nodes.label", "mini", {"add": ["desk"]})
    c = TestClient(coord_app.admin_app(db, coord_app.EventBus()), headers=admin_headers(db))
    d = c.get("/api/v1/groups").json()
    assert [g["name"] for g in d["groups"]][:2] == ["Laptops", "Coordinator host"]
    lap = d["groups"][0]
    assert lap["rule"] == "has a battery" and [m["hostname"] for m in lap["members_list"]] == ["macbook"]
    assert d["labels"]["mini"] == {"owner": ["desk"], "facts": [], "all": ["desk"]}
    one = c.get("/api/v1/groups/laptops").json()["group"]
    assert one["members_list"][0]["why"] == ["has a battery"]
    prev = c.get("/api/v1/groups/preview", params={"selector": json.dumps({"labels": ["desk"]}), "members": "macbook"}).json()
    assert prev["members"] == 2 and prev["rule"] == "label desk · or listed: macbook"
    assert c.get("/api/v1/groups/preview", params={"selector": '{"x": 1}'}).status_code == 400
    eff = c.get("/api/v1/settings/effective", params={"node": "macbook"}).json()
    assert eff["labels"]["facts"] == ["laptop"] and eff["memberships"][0] == {
        "id": "laptops", "name": "Laptops", "rank": store.OWNER_RANK_MIN, "builtin": False, "why": ["has a battery"]}
    assert c.get("/api/v1/groups/nope").status_code == 404
