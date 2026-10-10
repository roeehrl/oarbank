"""The settings model (docs/design/settings.md): the registry and its generated Rust table, the sparse store and the
resolver (default, fleet, groups by rank, node; locks first; merge rules), change sets with their per-node preview and
tier, what the agent gets and reports back, the API, and the one-shot conversion of a home made by an earlier version."""
import json
import sqlite3
from pathlib import Path

import pytest

from helpers import (FACTS, admin_headers, certify, enrolled_node, facts_for, make_db, node_settings, run_op, set_fleet,
                     set_node, settings_apply)
from oarbank.coordinator import core, ops
from oarbank.coordinator.db import DB
from oarbank.coordinator.settings import apply as A, registry as R, resolve as V, rustgen, store


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def node_row(db, n):
    return db.one("SELECT * FROM nodes WHERE node_id=?", (n if isinstance(n, str) else n["node_id"],))


# ------------------------------------------------------------------ the registry

def test_the_agents_table_is_generated_from_the_registry():
    """Python and Rust can never drift: the agent's table is this file, generated (run the generator after a change)."""
    assert rustgen.OUT.read_text(encoding="utf-8") == rustgen.render(), \
        "run `uv run python -m oarbank.coordinator.settings.rustgen`"


def test_every_definition_is_complete():
    for d in R.SETTINGS:
        assert d.label and d.help and d.schema.get("type"), d.key
        assert d.danger in R.TIERS and d.merge in R.MERGES and set(d.scopes) <= set(R.SCOPES)
        if d.default is not None:
            assert R.same(R.check(d.key, d.default), d.default), d.key       # every default passes its own type
        if d.section:
            assert d.section in R.SECTIONS
    assert R.default(R.REGISTRY["os_reserve_gb"], FACTS) == (4, "24 GB RAM")


@pytest.mark.parametrize("key, value, why", [
    ("job_mem_gb", "abc", "expected number"), ("job_mem_gb", 0, "must be more than 0"), ("nice", 21, "above 20"),
    ("threads_per_job", 1.5, "not a whole number"), ("run_on_battery", "yes", "expected boolean"),
    ("disabled_services", ["Relay Scorer"], "expected form"), ("console_hosts", "a.example", "expected array"),
    ("schedule", {"start": "25:00", "end": "07:00"}, "a time as HH:MM"), ("enforce", "firm", "not one of soft, hard"),
    ("ntfy.url", "ftp://x", "not an http(s) URL"), ("replica_rate", 2, "above 1")])
def test_values_are_type_checked(key, value, why):
    with pytest.raises(R.SettingError) as e:
        R.check(key, value)
    assert why in e.value.detail


def test_values_are_normalized():
    assert R.check("user_present_slots", 3.0) == 3 and isinstance(R.check("user_present_slots", 3.0), int)
    assert R.check("console_hosts", ["Oarbank.Example.ts.net", "oarbank.example.ts.net"]) == ["oarbank.example.ts.net"]
    assert R.check("schedule", {"start": "7:30", "end": "24:00", "days": [6, 0, 0]}) == {"start": "07:30", "end": "24:00", "days": [0, 6]}
    assert R.check("max_slots", None) is None


def test_a_change_sets_tier_follows_its_keys_and_scopes():
    node, fleet = {"scope": "node"}, {"scope": "fleet"}
    assert R.change_tier([{**node, "key": "jobs"}]) == "T0"                      # a node's cap
    assert R.change_tier([{**node, "key": "job_mem_gb"}]) == "T1"                # a node's policy
    assert R.change_tier([{**fleet, "key": "jobs"}]) == "T1"
    assert R.change_tier([{**fleet, "key": "job_mem_gb"}, {**node, "key": "jobs"}]) == "T2"
    assert R.change_tier([{**fleet, "key": "run_on_battery", "enforce": True}]) == "T3"


# ------------------------------------------------------------------ the resolver

def test_the_chain_default_fleet_group_node(db):
    n = enrolled_node(db)[1]                                         # a 24 GB Mac: in the built-in macOS group
    res = V.resolve(V.snapshot(db), node_row(db, n), "job_mem_gb")
    assert res["value"] == 1.5 and res["source"]["scope"] == "default"
    assert [x["name"] for x in res["chain"]] == ["Default", "Fleet", "Group: macOS", "This node"]
    set_fleet(db, "job_mem_gb", 2)
    settings_apply(db, {"scope": "group", "scope_id": "macOS", "key": "job_mem_gb", "value": 3})
    assert node_settings(db, n)["job_mem_gb"] == 3
    set_node(db, n, "job_mem_gb", 4)
    res = V.resolve(V.snapshot(db), node_row(db, n), "job_mem_gb")
    assert res["value"] == 4 and [x["role"] for x in res["chain"]] == [None, "shadowed", "shadowed", "winner"]
    set_node(db, n, "job_mem_gb", reset=True)
    assert node_settings(db, n)["job_mem_gb"] == 3
    settings_apply(db, {"scope": "group", "scope_id": "os-darwin", "key": "job_mem_gb", "reset": True})
    assert node_settings(db, n)["job_mem_gb"] == 2
    linux = enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="6.8"))[1]
    assert [g["id"] for g in V.node_groups(V.snapshot(db), node_row(db, linux))] == ["os-linux"]


def test_caps_take_the_lowest_value_of_every_scope(db):
    n = enrolled_node(db)[1]
    set_fleet(db, "jobs", 4)
    set_node(db, n, "jobs", 6)                                       # a node cannot raise a fleet cap
    res = V.resolve(V.snapshot(db), node_row(db, n), "jobs")
    assert res["value"] == 4 and res["source"]["scope"] == "fleet" and res["chain"][-1]["role"] == "merged"
    set_node(db, n, "jobs", 2)
    assert node_settings(db, n)["jobs"] == 2
    set_fleet(db, "enforce", "hard")                                 # enforcement: hard beats soft from any scope
    set_node(db, n, "enforce", "soft")
    assert node_settings(db, n)["enforce"] == "hard"


def test_a_lock_holds_against_a_lower_value(db):
    n = enrolled_node(db)[1]
    set_node(db, n, "run_on_battery", True)
    settings_apply(db, {"scope": "fleet", "key": "run_on_battery", "value": False, "enforce": True})
    res = V.resolve(V.snapshot(db), node_row(db, n), "run_on_battery")
    assert res["value"] is False and res["locked_by"]["name"] == "Fleet" and res["chain"][-1]["role"] == "ignored"
    with pytest.raises(A.ApplyError) as e:
        set_node(db, n, "run_on_battery", True)
    assert e.value.errors[0]["code"] == "locked" and "locked by Fleet settings" in e.value.errors[0]["message"]


def test_the_coordinator_host_group_runs_every_service(db, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostname", lambda: "studio.local")
    set_fleet(db, "disabled_services", ["relay/scorer"])
    worker = enrolled_node(db, "mini")[1]
    studio = enrolled_node(db, "studio", facts={**FACTS, "hostname": "studio"})[1]
    assert node_settings(db, worker)["disabled_services"] == ["relay/scorer"]
    assert node_settings(db, studio)["disabled_services"] == []
    res = V.resolve(V.snapshot(db), node_row(db, studio), "disabled_services")
    assert V.badge(res) == "Group: Coordinator host · the coordinator's own machine runs every service"


def test_merged_values_are_checked_per_node(db):
    """Each value may be valid alone and their merge not: the reserves must leave memory for jobs on each node, and a
    node's own cap may not exceed its hardware (a fleet cap above a node's hardware simply does not bind there)."""
    small = enrolled_node(db, "small", facts={**FACTS, "memory_gb": 16.0})[1]
    enrolled_node(db, "big", facts={**FACTS, "memory_gb": 64.0})
    with pytest.raises(A.ApplyError) as e:
        set_fleet(db, "user_reserve_gb", 14)                        # 4 + 14 GB: fine on 64 GB, not on 16 GB
    assert [x["node"] for x in e.value.errors] == ["small"] and "leave no memory for jobs" in e.value.errors[0]["message"]
    set_fleet(db, "mem_gb", 48)                                     # above small's RAM: a fleet cap, so allowed
    with pytest.raises(A.ApplyError):
        set_node(db, small, "mem_gb", 20)
    assert node_settings(db, small)["mem_gb"] == 48


# ------------------------------------------------------------------ change sets and what nodes get

def test_a_mistyped_job_mem_gb_is_refused_at_the_coordinator(db):
    """Phase 0's exit test: the coordinator refuses it with the field named, so the agent never sees it."""
    n = enrolled_node(db)[1]
    with pytest.raises(ops.OpError) as e:
        run_op(db, "settings.apply", n["node_id"], {"changes": [{"scope": "node", "scope_id": n["node_id"],
                                                                 "key": "job_mem_gb", "value": "abc"}]})
    assert e.value.status == 400 and e.value.code == "invalid_settings"
    assert e.value.extra["errors"][0]["key"] == "job_mem_gb" and "expected number" in e.value.extra["errors"][0]["message"]
    assert node_settings(db, n)["job_mem_gb"] == 1.5 and not db.q("SELECT 1 FROM setting_values WHERE scope='node'")


def test_changing_a_fleet_default_reaches_every_non_overriding_node_and_the_preview_names_them(db):
    """Phase 1's exit test."""
    a, b, c = certify(db, enrolled_node(db, "a")[1]), certify(db, enrolled_node(db, "b")[1]), certify(db, enrolled_node(db, "c")[1])
    set_node(db, c, "job_mem_gb", 3)
    revs = {x["node_id"]: node_row(db, x)["settings_rev"] for x in (a, b, c)}
    change = {"changes": [{"scope": "fleet", "key": "job_mem_gb", "value": 2}]}
    plan = run_op(db, "settings.apply", None, change, dry_run=True)["plan"]
    assert plan["tier"] == "T2" and plan["impact"]["summary"] == ("Changes the effective value on 2 nodes (a, b); "
                                                                  "1 node keeps theirs (c)")
    assert {(x["hostname"], x["old"], x["new"]) for x in plan["impact"]["_diff"]} == {("a", 1.5, 2), ("b", 1.5, 2)}
    assert plan["impact"]["_unaffected"][0]["why"] == "overrides it" and plan["impact"]["_button_label"] == "Save for 2 nodes"
    with pytest.raises(ops.OpError) as e:                           # T2: a plan, then a reason
        run_op(db, "settings.apply", None, change)
    assert e.value.code == "plan_required"
    res = ops.execute(db, ops.OpRequest(op="settings.apply", actor="owner", plan_id=plan["plan_id"], reason="bigger jobs"))
    rev = res["result"]["rev"]
    for x in (a, b):
        d = core._node_directives(db, node_row(db, x))
        assert d["policy"]["job_mem_gb"] == 2 and d["settings_rev"] == rev > revs[x["node_id"]]
    d = core._node_directives(db, node_row(db, c))
    assert d["policy"]["job_mem_gb"] == 3 and d["settings_rev"] == revs[c["node_id"]]          # untouched
    a_row = db.one("SELECT * FROM audit WHERE operation='settings.apply' AND outcome='ok' AND dry_run=0")
    assert json.loads(a_row["after_json"]) == {"fleet:::job_mem_gb": {"value": 2, "enforced": False, "rev": rev}}


def test_the_agent_gets_a_complete_policy_with_a_revision_and_reports_what_it_applied(db):
    n = certify(db, enrolled_node(db)[1])
    d = core._node_directives(db, node_row(db, n))
    assert set(d["policy"]) == {*R.WIRE_POLICY, "module_settings", "protection"} and set(d["limits"]) == set(R.WIRE_LIMITS)
    assert d["limits"]["jobs"] is None and d["policy"]["protection"]["node"]["mode"] == "moderate"
    rev = d["settings_rev"]
    assert A.applied_state(node_row(db, n))["state"] == "unknown"           # an agent that does not report
    core.heartbeat(db, node_row(db, n), {"attempts": [], "settings": {"applied_rev": rev, "rejected": []}})
    assert A.applied_state(node_row(db, n))["text"] == f"Applied on the node · rev {rev}"
    set_node(db, n, "job_mem_gb", 2)
    assert A.applied_state(node_row(db, n))["state"] == "pending"
    new = node_row(db, n)["settings_rev"]
    core.heartbeat(db, node_row(db, n), {"attempts": [], "settings": {"applied_rev": new, "rejected": [
        {"key": "job_mem_gb", "reason": "expected a number"}]}})
    assert A.applied_state(node_row(db, n), "job_mem_gb")["text"] == "Refused by the node: expected a number"
    assert db.one("SELECT reason FROM events WHERE kind='settings_rejected'")["reason"] == "job_mem_gb: expected a number"


def test_facts_moving_a_node_into_another_default_give_it_a_new_revision(db):
    n = certify(db, enrolled_node(db)[1])
    rev = core._node_directives(db, node_row(db, n))["settings_rev"]
    db.x("UPDATE nodes SET facts_json=? WHERE node_id=?", (json.dumps({**FACTS, "memory_gb": 128.0}), n["node_id"]))
    d = core._node_directives(db, node_row(db, n))
    assert d["policy"]["os_reserve_gb"] == 8 and d["settings_rev"] > rev


def test_writer_owned_keys_go_through_their_own_operation(db):
    with pytest.raises(A.ApplyError) as e:
        settings_apply(db, {"scope": "fleet", "key": "folder_registry", "value": {}})
    assert e.value.errors[0]["code"] == "use_typed_operation" and "settings.folders.update" in e.value.errors[0]["message"]
    with pytest.raises(A.ApplyError) as e:
        settings_apply(db, {"scope": "node", "scope_id": "nope", "key": "replica_rate", "value": 0.1})
    assert e.value.errors[0]["code"] == "not_settable_here"


def test_the_ntfy_token_lives_in_the_secrets_store(db):
    from oarbank.coordinator import modsecrets
    run_op(db, "settings.secrets.set", "ntfy_token", {}, secret="s3cret-token")
    st = modsecrets.core_state(db, "ntfy_token")
    assert st["set"] and st["fingerprint"].startswith("fp:") and modsecrets.core_value(db, "ntfy_token") == "s3cret-token"
    assert "s3cret-token" not in json.dumps(db.q("SELECT * FROM audit"), default=str)
    assert db.q("SELECT 1 FROM setting_values WHERE key LIKE 'ntfy%'") == []
    with pytest.raises(ops.OpError):
        run_op(db, "settings.secrets.set", "other", {}, secret="x")


# ------------------------------------------------------------------ the API

def test_the_settings_api(db):
    from fastapi.testclient import TestClient
    from oarbank.coordinator import app as coord_app
    n = enrolled_node(db)[1]
    set_node(db, n, "job_mem_gb", 3)
    c = TestClient(coord_app.admin_app(db, coord_app.EventBus()), headers=admin_headers(db))
    schema = c.get("/api/v1/settings/schema").json()
    assert {s["key"] for s in schema["settings"]} == set(R.REGISTRY) | {"tool.<id>.path"}           # a key family once
    assert schema["groups"][0]["id"] == "os-darwin"
    eff = c.get("/api/v1/settings/effective", params={"node": "mini"}).json()
    row = next(x for x in eff["settings"] if x["key"] == "job_mem_gb")
    assert row["value"] == 3 and row["badge"] == "This node" and eff["groups"] == ["macOS"]
    fleet = c.get("/api/v1/settings/effective").json()
    assert next(x for x in fleet["settings"] if x["key"] == "replica_rate")["value"] == 0.03
    ex = c.get("/api/v1/settings/explain", params={"key": "os_reserve_gb", "node": "mini"}).json()
    assert ex["badge"] == "Default · 24 GB RAM" and ex["chain"][0]["value_text"] == "4 GB"
    over = c.get("/api/v1/settings/overrides", params={"key": "job_mem_gb"}).json()
    assert over["count"] == 1 and over["values"][0]["name"] == "mini" and over["nodes"][0]["source"] == "This node"
    assert c.get("/api/v1/settings/explain", params={"key": "nope"}).status_code == 404


# ------------------------------------------------------------------ the conversion of an earlier home

OLD_POLICY = {"os_reserve_gb": 4, "user_reserve_gb": 8, "max_slots": None, "threads_per_job": 1, "job_mem_gb": 1.5,
              "user_present_slots": 2, "user_idle_s": 300, "run_on_battery": False, "nice": 10, "hard_limits": False,
              "screen_sharing_present": True, "mem_in_use_bound": True, "disabled_services": ["relay/scorer"],
              "module_settings": {}, "protection": {"schema": 1, "node": {"mode": "moderate"}, "rule": []}}


def make_old_home(tmp_path) -> Path:
    """A home as Oarbank 2.9 left it: the settings table with owner and system keys, per-node policy copies and caps."""
    path = tmp_path / "old" / "oarbank.sqlite3"
    db = make_db(path)
    a = enrolled_node(db, "a")[1]
    b = enrolled_node(db, "b", facts={**FACTS, "memory_gb": 64.0})[1]
    c = sqlite3.connect(path)
    c.executescript("""
        ALTER TABLE nodes ADD COLUMN limits_json TEXT DEFAULT '{}';
        ALTER TABLE nodes ADD COLUMN policy_json TEXT DEFAULT '{}';
        CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT);
        INSERT INTO settings SELECT key, value_json FROM system_state WHERE key != 'settings_rev';
        DELETE FROM system_state; DELETE FROM setting_values;
        UPDATE nodes SET settings_json=NULL, settings_digest=NULL, settings_rev=NULL, protection_json=NULL;""")
    owner = {"ntfy": {"url": "https://ntfy.sh/topic", "token": None, "click_base": None}, "replica_rate": 0.05,
             "console_hosts": "oarbank.example.ts.net", "default_worker_disabled_services": ["relay/scorer"],
             "tool_registry": {"java17": {"trust": "code-exec", "paths": {"darwin": ["/opt/homebrew/opt/openjdk@17"]}}},
             "dataset_origins": {"hosts": ["example.org"]}, "pipeline:relay": "split",
             "module_settings:relay": {"goldens": []}, "dataset_groups": {"g": 1}, "release_pubkey": "abc"}
    c.executemany("INSERT OR REPLACE INTO settings VALUES(?,?)", [(k, json.dumps(v)) for k, v in owner.items()])
    c.execute("UPDATE nodes SET policy_json=?, limits_json='{}' WHERE node_id=?", (json.dumps(OLD_POLICY), a["node_id"]))
    pol_b = {**OLD_POLICY, "os_reserve_gb": 6, "job_mem_gb": 3, "nice": "high",
             "module_settings": {"relay": {"vm_mem_gb": 12}},
             "protection": {"schema": 1, "node": {"mode": "strict_yield"}, "rule": []}}
    c.execute("UPDATE nodes SET policy_json=?, limits_json=? WHERE node_id=?",
              (json.dumps(pol_b), json.dumps({"jobs": 2, "enforce": "hard"}), b["node_id"]))
    c.commit()
    c.close()
    db.conn.close()
    return path


def test_an_earlier_home_is_converted_once_keeping_only_choices(tmp_path):
    path = make_old_home(tmp_path)
    db = DB(path)                                                     # the coordinator opens it: converted
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(nodes)")}
    assert "policy_json" not in cols and "limits_json" not in cols
    assert not db.conn.execute("SELECT 1 FROM sqlite_master WHERE name='settings'").fetchone()
    rows = {(r["scope"], r["module"], r["key"]): r for r in store.rows(db)}
    nid = {r["hostname"]: r["node_id"] for r in db.q("SELECT node_id, hostname FROM nodes")}
    # a's policy was a copy of what it inherits: nothing of it remains; b keeps its two choices and its caps
    assert {(s, k) for (s, m, k), r in rows.items() if s == "node" and r["scope_id"] == nid["a"]} == set()
    assert {k: r["value"] for (s, m, k), r in rows.items() if s == "node" and r["scope_id"] == nid["b"]} == {
        "job_mem_gb": 3, "jobs": 2, "enforce": "hard", "module.node_settings": {"vm_mem_gb": 12}}
    assert {(m, k): r["value"] for (s, m, k), r in rows.items() if s == "fleet"} == {
        ("", "ntfy.url"): "https://ntfy.sh/topic", ("", "replica_rate"): 0.05, ("", "console_hosts"): ["oarbank.example.ts.net"],
        ("", "disabled_services"): ["relay/scorer"],
        ("", "dataset_origins"): ["example.org"], ("relay", "pipeline"): "split", ("relay", "module.settings"): {"goldens": []}}
    assert db.get_state("release_pubkey") == "abc" and db.get_state("fleet_id")
    from oarbank.coordinator import tools                             # the tool registry became a host tool definition
    assert tools.definitions(db)["java17"]["search"] == {"darwin": ["/opt/homebrew/opt/openjdk@17"]}
    assert json.loads(node_row(db, nid["b"])["protection_json"])["node"]["mode"] == "strict_yield"
    ev = db.one("SELECT payload_json FROM events WHERE kind='settings_migrated'")
    report = json.loads(ev["payload_json"])
    assert "b: nice: expected integer, got str 'high'" in report["dropped"] and any("dataset_groups" in x for x in report["dropped"])
    d = core._node_directives(db, node_row(db, nid["b"]))
    assert d["policy"]["job_mem_gb"] == 3 and d["policy"]["os_reserve_gb"] == 6 and d["limits"]["jobs"] == 2
    assert d["policy"]["module_settings"] == {"relay": {"vm_mem_gb": 12}} and d["settings_rev"] >= 1
    db.conn.close()
    again = DB(path)                                                  # converted once: opening it again changes nothing
    assert again.q("SELECT COUNT(*) n FROM events WHERE kind='settings_migrated'")[0]["n"] == 1


def test_an_operator_changes_nodes_and_only_an_admin_the_fleet(db):
    n = enrolled_node(db)[1]
    node = {"changes": [{"scope": "node", "scope_id": n["node_id"], "key": "jobs", "value": 2}]}
    assert run_op(db, "settings.apply", n["node_id"], node, role="operator")["ok"]
    with pytest.raises(ops.OpError) as e:
        run_op(db, "settings.apply", None, {"changes": [{"scope": "fleet", "key": "jobs", "value": 2}]}, role="operator",
               dry_run=True)
    assert e.value.code == "forbidden_role"
