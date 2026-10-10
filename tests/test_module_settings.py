"""Module settings (docs/design/settings.md, "Module settings"): each module's own keys from its manifest's settings
schema, registered per version and validated on every write; node-scoped keys reaching only that module's runners; the
core keys every module has (`enabled`, `services.disabled`, `pipeline`, `replica_rate`); required settings in readiness
and placement (SETTINGS_NOT_SET); the module Settings tab; and the one-shot conversion of the old stores."""
import json
import re
import shutil
import sqlite3
from pathlib import Path

import pytest

from helpers import (FACTS, PARAMS, READY, TOY_DIR, certify, create_study, enrolled_node, fresh, install, make_db,
                     node_settings, run_op, set_fleet, set_module, set_node, settings_apply)
from oarbank.coordinator import core, effects, explain, modcalls, modstore, ops, readiness, releases
from oarbank.coordinator.db import DB
from oarbank.coordinator.settings import apply as A, modkeys, resolve as V, store
from test_console import env, save_section, section_fields, settings_html  # noqa: F401 (the console fixture)


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def doc(db, n) -> dict:
    return A.node_values(fresh(db, n))


def module_rows(db, module: str) -> list[tuple]:
    return sorted((r["scope"], r["scope_id"], r["key"], json.dumps(r["value"])) for r in store.rows(db) if r["module"] == module)


def toy_copy(tmp_path, version: str, props: dict, required: list | None = None) -> Path:
    """The toy at another version with another settings schema."""
    d = tmp_path / f"toy-{version}"
    shutil.copytree(TOY_DIR, d, ignore=shutil.ignore_patterns("dist", "__pycache__"))
    m = d / "oarbank-module.toml"
    m.write_text(m.read_text(encoding="utf-8").replace('version = "0.1.0"', f'version = "{version}"'), encoding="utf-8")
    (d / "schemas" / "settings.schema.json").write_text(json.dumps(
        {"type": "object", "properties": props, **({"required": required} if required else {})}), encoding="utf-8")
    return d


# ------------------------------------------------------------------ the exit test of phase 3

def test_setting_one_modules_node_key_no_longer_touches_another_modules(db):
    """A node value of relay's own key is one row, for relay, for that key: toy's settings on the node (rows and what
    its runners get) and relay's other keys stay exactly as they were, and the preview names only that key."""
    _, n = enrolled_node(db)
    set_node(db, n, "module.toy.greeting", "hi", module="toy")
    set_node(db, n, "vm_mem_gb", 8, module="relay")                                     # the short name, for relay
    toy_before, toy_doc = module_rows(db, "toy"), doc(db, n)["policy"]["module_settings"]["toy"]
    p = A.plan(db, [{"scope": "node", "scope_id": n["node_id"], "module": "relay", "key": "tile_size", "value": 64}])
    assert [(x["key"], x["module"], x["new"]) for x in p["_diff"]] == [("module.relay.tile_size", "relay", 64)]
    set_node(db, n, "tile_size", 64, module="relay")
    assert module_rows(db, "toy") == toy_before and doc(db, n)["policy"]["module_settings"]["toy"] == toy_doc == {"greeting": "hi"}
    assert doc(db, n)["policy"]["module_settings"]["relay"] == {"vm_mem_gb": 8, "tile_size": 64}
    set_node(db, n, "tile_size", reset=True, module="relay")                            # reset deletes that one row
    assert doc(db, n)["policy"]["module_settings"]["relay"] == {"vm_mem_gb": 8, "tile_size": 32}
    assert [r[2] for r in module_rows(db, "relay") if r[0] == "node"] == ["module.relay.vm_mem_gb"]
    # the old stores are gone: one object per module and node, or per module at the fleet, is not a setting any more
    for key in ("module.node_settings", "module.settings"):
        with pytest.raises(A.ApplyError) as e:
            settings_apply(db, {"scope": "node", "scope_id": n["node_id"], "module": "relay", "key": key, "value": {}})
        assert e.value.errors[0]["code"] == "unknown_setting"


def test_a_fleet_value_of_a_node_key_reaches_every_node_that_sets_none(db):
    (_, a), (_, b) = enrolled_node(db, "a"), enrolled_node(db, "b")
    set_node(db, b, "tile_size", 16, module="relay")
    p = A.plan(db, [{"scope": "fleet", "module": "relay", "key": "tile_size", "value": 64}])
    assert p["summary"] == "Changes the effective value on 1 node (a); 1 node keeps theirs (b)"
    set_fleet(db, "module.relay.tile_size", 64, "relay")
    assert doc(db, a)["policy"]["module_settings"]["relay"]["tile_size"] == 64
    assert doc(db, b)["policy"]["module_settings"]["relay"]["tile_size"] == 16


# ------------------------------------------------------------------ declared keys, validated

@pytest.mark.parametrize("change, code, message", [
    ({"key": "tile_size", "value": 20}, "bad_value", "Tile size: 20 is not one of [16, 32, 64]"),
    ({"key": "vm_mem_gb", "value": "big"}, "bad_value", "'big' is not of type 'number'"),
    ({"key": "nope", "value": 1}, "unknown_setting", "the module relay declares no such key"),
    ({"key": "goldens", "value": [], "scope": "node"}, "not_settable_here", "can be set for: fleet"),
    ({"key": "module.toy.favorite_n", "value": 1}, "not_settable_here", "toy's own setting, not relay's"),
])
def test_a_modules_values_are_checked_against_its_schema(db, change, code, message):
    _, n = enrolled_node(db)
    c = {"scope": "fleet", "module": "relay", **change}
    if c["scope"] == "node":
        c["scope_id"] = n["node_id"]
    with pytest.raises(A.ApplyError) as e:
        settings_apply(db, c)
    assert e.value.errors[0]["code"] == code and message in e.value.errors[0]["message"], e.value.errors


def test_values_are_normalized_and_unset_keys_without_a_default_are_absent(db):
    set_module(db, "toy", {"favorite_n": 12.0})
    assert store.row(db, "fleet", "", "toy", "module.toy.favorite_n")["value"] == 12           # an integer key: an int
    assert effects.module_settings(db, "relay") == {"goldens": effects.module_settings(db, "relay")["goldens"], "tile_size": 32}
    assert effects.module_settings(db, "toy") == {"favorite_n": 12, "greeting": "hello"}     # what host.settings.get reads


def test_module_settings_update_is_validated_key_by_key_and_never_partly_applied(db):
    decl = next(o for o in modstore.installed(db, "toy")[0]["manifest"]["operations"] if o["verb"] == "set_favorite")
    from oarbank_sdk import ui as U
    d = U.OperationDecl(verb=decl["verb"], title=decl["title"], effects=decl["effects"])
    with db.tx():
        ops.apply_effects(db, "toy", d, [{"kind": "module_settings.update", "args": {"favorite_n": 3}}])
    assert effects.module_settings(db, "toy")["favorite_n"] == 3
    for bad in ({"favorite_n": 4, "nope": 1}, {"favorite_n": -1}):
        with pytest.raises(ops.OpError) as e, db.tx():
            ops.apply_effects(db, "toy", d, [{"kind": "module_settings.update", "args": bad}])
        assert e.value.code == "bad_settings"
        assert effects.module_settings(db, "toy")["favorite_n"] == 3                         # none of it was written
    with db.tx():
        ops.apply_effects(db, "toy", d, [{"kind": "module_settings.update", "args": {"favorite_n": None}}])
    assert "favorite_n" not in effects.module_settings(db, "toy")                            # null resets it


# ------------------------------------------------------------------ registration per version

def test_keys_follow_the_registered_version_keeping_dropped_keys_and_dropping_refused_values(db, tmp_path):
    _, n = enrolled_node(db)
    set_module(db, "toy", {"favorite_n": 50})
    set_node(db, n, "greeting", "hi", module="toy")
    v2 = toy_copy(tmp_path, "0.2.0", {"favorite_n": {"type": "integer", "maximum": 10, "title": "Favorite n"},
                                      "speed": {"type": "integer", "default": 2, "x-oarbank": {"scope": "node"}}})
    install(db, v2, enable=False)
    assert modkeys.registration(db, "toy")["version"] == "0.1.0"                 # installed, not current: nothing changes
    with db.tx():
        modstore.canary(db, "toy", "0.2.0", [n["node_id"]])
        modstore.promote(db, "toy")
    assert [k.name for k in modkeys.declared(db, "toy")] == ["favorite_n", "speed"]
    ev = json.loads(db.one("SELECT payload_json FROM events WHERE kind='module_settings_registered' ORDER BY event_id DESC")
                    ["payload_json"])
    assert ev["added"] == ["speed"] and ev["removed"] == ["greeting"] and ev["changed"] == ["favorite_n"]
    assert [(x["key"], x["value"]) for x in ev["dropped"]] == [("favorite_n", 50)]           # 50 > the new maximum
    assert store.row(db, "fleet", "", "toy", "module.toy.favorite_n") is None
    # greeting's value is kept, unused: not delivered, listed with a reset on the module page
    assert doc(db, n)["policy"]["module_settings"]["toy"] == {"speed": 2}
    assert [x["key"] for x in modkeys.orphans(db, "toy")] == ["module.toy.greeting"]
    with db.tx():
        modstore.rollback(db, "toy")                                             # back to 0.1.0: greeting applies again
    assert doc(db, n)["policy"]["module_settings"]["toy"] == {"greeting": "hi"} and modkeys.orphans(db, "toy") == []


def test_a_value_its_module_no_longer_declares_can_be_reset(db, tmp_path):
    set_module(db, "toy", {"favorite_n": 5})
    v2 = toy_copy(tmp_path, "0.2.0", {"other": {"type": "string"}})
    install(db, v2, enable=False)
    with db.tx():
        modstore.canary(db, "toy", "0.2.0", ["x"])
        modstore.promote(db, "toy")
    assert [x["key"] for x in modkeys.orphans(db, "toy")] == ["module.toy.favorite_n"]
    settings_apply(db, {"scope": "fleet", "module": "toy", "key": "module.toy.favorite_n", "reset": True})
    assert modkeys.orphans(db, "toy") == []
    with pytest.raises(A.ApplyError):                                            # and only reset
        settings_apply(db, {"scope": "fleet", "module": "toy", "key": "module.toy.favorite_n", "value": 1})


# ------------------------------------------------------------------ required settings: readiness and placement

def test_a_required_setting_holds_the_modules_work_until_it_has_a_value(tmp_path):
    db = make_db(tmp_path / "oarbank.sqlite3", modules=())
    install(db, toy_copy(tmp_path, "0.1.0", {"batch": {"type": "integer", "minimum": 1, "title": "Batch",
                                                       "x-oarbank": {"scope": "node", "required": True}}}))
    modcalls.use(db)
    releases.sync(db)
    (_, a), (_, b) = enrolled_node(db, "a"), enrolled_node(db, "b")
    step = next(s for s in readiness.module(db, "toy")["steps"] if s["id"] == "settings")
    assert step["status"] == "blocked" and "toy needs batch" in step["reason"] and "SETTINGS_NOT_SET" in step["reason"]
    assert step["actions"][0]["href"] == "/modules/toy/settings"
    assert step["actions"][0]["command"] == "oarbank settings set batch <value> --module toy"
    set_node(db, a, "batch", 4, module="toy")                                    # a has a value, b none
    a = certify(db, a)
    b = certify(db, b)
    assert core.certified_modules(a) == ["toy"] and core.certified_modules(b) == []      # b's goldens wait too
    assert doc(db, b)["settings_unset"] == {"toy": ["batch"]} and "settings_unset" not in doc(db, a) or \
        doc(db, a)["settings_unset"] == {}
    step = next(s for s in readiness.module(db, "toy")["steps"] if s["id"] == "settings")
    assert step["status"] == "done" and "except on 1 node" in step["reason"]
    golden = db.one("SELECT job_id FROM jobs WHERE kind='golden' AND target_node=? AND state='pending'", (b["node_id"],))
    d = explain.explain(db, "job", str(golden["job_id"]))
    assert "SETTINGS_NOT_SET" in [r.code for r in d.summary] and "settings.apply" in [r.op for r in d.remedies]   # on b
    set_fleet(db, "module.toy.batch", 2, "toy")                                  # a fleet value covers b
    assert doc(db, b).get("settings_unset") == {}
    assert core.certified_modules(certify(db, fresh(db, b))) == ["toy"]
    assert next(s for s in readiness.module(db, "toy")["steps"] if s["id"] == "settings")["status"] == "done"


def test_a_module_with_no_required_settings_passes_the_step(db):
    step = next(s for s in readiness.module(db, "toy")["steps"] if s["id"] == "settings")
    assert (step["status"], step["reason"]) == ("done", "it declares 2 settings, none required")


# ------------------------------------------------------------------ the core keys every module has

def test_a_module_can_be_off_on_one_node_and_the_kill_switch_is_its_fleet_value(db):
    mini, desk = certify(db, enrolled_node(db, "mini")[1]), certify(db, enrolled_node(db, "desk")[1])
    set_node(db, desk, "enabled", False, module="toy")
    assert core._node_directives(db, fresh(db, desk))["modules_disabled"] == ["toy"]
    assert core._node_directives(db, fresh(db, mini))["modules_disabled"] == []
    assert modstore.disabled_names(db, fresh(db, desk)) == {"toy"} and modstore.disabled_names(db) == set()
    run_op(db, "mod.toy.queue_sums", params={"ns": [3, 4]})
    claimed = lambda n: {g["module"] for g in core.claim(db, fresh(db, n), {"free_cpu": 8, "free_mem_gb": 32,
                                                                              "ready_datasets": READY})["grants"]}
    assert "toy" not in claimed(desk) and "toy" in claimed(mini)
    live = db.one("SELECT COUNT(*) n FROM attempts a JOIN jobs j ON j.job_id=a.job_id WHERE a.state='live' AND j.module='toy'")["n"]
    assert live
    run_op(db, "modules.disable", "toy")                                         # the kill switch: [toy] enabled off
    assert store.row(db, "fleet", "", "toy", "enabled")["value"] is False and modstore.channel(db, "toy")["disabled"]
    assert db.one("SELECT COUNT(*) n FROM attempts a JOIN jobs j ON j.job_id=a.job_id WHERE a.state='live' "
                  "AND j.module='toy'")["n"] == 0
    assert db.one("SELECT 1 FROM events WHERE kind='module_disabled' AND module='toy'")
    assert next(s for s in readiness.module(db, "toy")["steps"] if s["id"] == "enabled")["status"] == "blocked"
    run_op(db, "modules.enable", "toy")                                          # re-enable: the fleet's value is reset
    assert store.row(db, "fleet", "", "toy", "enabled") is None and not modstore.channel(db, "toy")["disabled"]
    assert modstore.disabled_names(db, fresh(db, desk)) == {"toy"}               # desk's own value stays


def test_a_module_rate_can_only_raise_the_fleets_replica_rate(db):
    set_fleet(db, "replica_rate", 0.1)
    set_fleet(db, "replica_rate", 0.5, "relay")
    set_fleet(db, "replica_rate", 0.05, "toy")
    snap = V.snapshot(db)
    assert V.resolve(snap, None, "replica_rate", "relay")["value"] == 0.5
    assert V.resolve(snap, None, "replica_rate", "toy")["value"] == 0.1          # merge max: the fleet's still applies
    assert V.resolve(snap, None, "replica_rate")["value"] == 0.1


def test_pipeline_is_a_setting_and_split_needs_a_stage_chain(db):
    create_study(db, "s", [{"label": "c1", "params": {**PARAMS, "samples": 25}}], ["scene:s1"], {"label": "base", "params": PARAMS})
    change = {"changes": [{"scope": "fleet", "module": "relay", "key": "pipeline", "value": "split"}]}
    plan = run_op(db, "settings.apply", None, change, dry_run=True)["plan"]          # a fleet change: previewed (T2)
    assert "Pipeline [relay] at Fleet: not set → split" in plan["impact"]["changes"]
    run_op(db, "settings.apply", None, change, plan_id=plan["plan_id"], confirm=plan["confirm_name"])
    assert db.one("SELECT COUNT(*) n FROM jobs WHERE kind='call'")["n"] == 2
    with pytest.raises(ops.OpError) as e:
        run_op(db, "settings.apply", None, {"changes": [{"scope": "fleet", "module": "toy", "key": "pipeline", "value": "split"}]},
               dry_run=True)
    assert "toy has no stage chain" in str(e.value)
    assert "modules.set_pipeline" not in ops.HANDLERS


# ------------------------------------------------------------------ groups and locks hold for module keys

def test_group_values_and_locks_hold_for_module_keys_against_node_overrides(db):
    """A group's value of `[relay] enabled` and of relay's own node key reaches its members; a group lock on either, or
    a fleet lock, refuses a member's override and wins over a value the member set before; leaving the group gives the
    node the module back."""
    from test_settings_groups import create, run_op as group_op
    (_, a), (_, b) = enrolled_node(db, "a"), enrolled_node(db, "b")
    set_node(db, a, "tile_size", 16, module="relay")                     # a's own choice, before any lock
    create(db, "Render farm", members=["a", "b"])
    settings_apply(db, {"scope": "group", "scope_id": "Render farm", "module": "relay", "key": "tile_size", "value": 64})
    assert doc(db, b)["policy"]["module_settings"]["relay"]["tile_size"] == 64       # a group value reaches members
    assert doc(db, a)["policy"]["module_settings"]["relay"]["tile_size"] == 16       # a's own value is more specific
    group_op(db, "settings.apply", "Render farm", {"changes": [
        {"scope": "group", "scope_id": "Render farm", "module": "relay", "key": "tile_size", "value": 64, "enforce": True},
        {"scope": "group", "scope_id": "Render farm", "module": "relay", "key": "enabled", "value": False, "enforce": True}]})
    snap = V.snapshot(db)
    res = V.resolve(snap, fresh(db, a), "module.relay.tile_size", "relay")
    assert res["value"] == 64 and res["locked_by"]["scope"] == "group"              # the lock wins over a's own value
    assert doc(db, a)["policy"]["module_settings"]["relay"]["tile_size"] == 64
    assert doc(db, a)["modules_disabled"] == doc(db, b)["modules_disabled"] == ["relay"]
    for key, value in (("tile_size", 32), ("enabled", True)):                         # a member's override is refused
        with pytest.raises(A.ApplyError) as e:
            set_node(db, b, key, value, module="relay")
        assert e.value.errors[0]["code"] == "locked" and "the group Render farm" in e.value.errors[0]["message"]
    set_node(db, a, "tile_size", reset=True, module="relay")                          # resetting one's own value is fine
    # a fleet lock holds over every node too, a module's fleet key included
    group_op(db, "settings.apply", None, {"changes": [{"scope": "fleet", "module": "relay", "key": "vm_mem_gb", "value": 4,
                                                       "enforce": True}]})
    with pytest.raises(A.ApplyError) as e:
        set_node(db, a, "vm_mem_gb", 8, module="relay")
    assert "locked by Fleet settings" in e.value.errors[0]["message"]
    with pytest.raises(A.ApplyError) as e:
        settings_apply(db, {"scope": "group", "scope_id": "Render farm", "module": "relay", "key": "vm_mem_gb", "value": 8})
    assert e.value.errors[0]["code"] == "locked"
    # leaving the group gives b relay back, through the group's own membership change
    group_op(db, "groups.update", "Render farm", {"members": ["a"]})
    assert doc(db, b)["modules_disabled"] == [] and doc(db, a)["modules_disabled"] == ["relay"]


def test_a_groups_page_has_its_module_sections(env):
    from test_settings_groups import create
    db = env["db"]
    create(db, "Render farm", members=[env["node"]["hostname"]])
    html, text = settings_html(env, path="/groups/" + db.one("SELECT id FROM node_groups WHERE name='Render farm'")["id"])
    assert "Modules on its members" in text and 'id="module-relay"' in html and 'id="s-relay-module-relay-tile_size"' in html
    f = section_fields(html, "module-relay")
    assert f["module"] == ["relay"] and f["scope"] == ["group"]


# ------------------------------------------------------------------ the conversion of the old stores

def _reopen(db) -> DB:
    path = db.path
    db.conn.close()
    return DB(path)


def test_a_29_home_with_module_objects_converts_them_key_by_key(tmp_path):
    """A home a 2.9 build made before module settings: one object per module (fleet) and per module and node, and
    disabled_services lists, become per-key values; the old rows go."""
    db = make_db(tmp_path / "oarbank.sqlite3")
    _, n = enrolled_node(db)
    with db.tx():
        rev = store.next_rev(db)
        store.put(db, "fleet", "", "relay", "module.settings", {"tool_datasets": {"lut": "lut:1"}, "nope": 2}, "old", rev)
        store.put(db, "node", n["node_id"], "relay", "module.node_settings", {"tile_size": 16, "vm_mem_gb": 0}, "old", rev)
        store.put(db, "fleet", "", "", "disabled_services", ["relay/scorer", "*/scorer", "ghost/x"], "old", rev)
        db.x("DELETE FROM module_setting_keys")
    db = _reopen(db)
    rows = {(r["scope"], r["module"], r["key"]): r["value"] for r in store.rows(db) if r["updated_by"] == "migration"}
    assert rows == {("fleet", "relay", "module.relay.tool_datasets"): {"lut": "lut:1"},
                    ("node", "relay", "module.relay.tile_size"): 16, ("fleet", "relay", "services.disabled"): ["scorer"]}
    assert not [r for r in store.rows(db) if r["key"] in ("module.settings", "module.node_settings", "disabled_services")]
    report = json.loads(db.one("SELECT payload_json FROM events WHERE kind='settings_migrated'")["payload_json"])
    assert "fleet: relay.nope (not a setting relay declares)" in report["dropped"]
    assert any(x.startswith(f"{n['hostname']}: relay.vm_mem_gb (Scorer VM memory: 0 is less than the minimum of 1")
               for x in report["dropped"]), report["dropped"]
    assert any("ghost/x" in x for x in report["dropped"])


def test_the_live_fleets_shape_converts_to_no_module_values(tmp_path):
    """The owner's fleet on 2.8: every node's policy a copy with module_settings {} and disabled_services [], no module
    settings in the settings table, one installed module never enabled: nothing to keep but the module's registration."""
    path = tmp_path / "old" / "oarbank.sqlite3"
    db = make_db(path, modules=())
    install(db, TOY_DIR, enable=False)
    nodes = [enrolled_node(db, f"n{i}", facts={**FACTS, "memory_gb": ram})[1] for i, ram in enumerate((16.0, 64.0, 128.0))]
    c = sqlite3.connect(path)
    c.executescript("""
        ALTER TABLE nodes ADD COLUMN limits_json TEXT DEFAULT '{}';
        ALTER TABLE nodes ADD COLUMN policy_json TEXT DEFAULT '{}';
        ALTER TABLE module_channels ADD COLUMN disabled INT DEFAULT 0;
        CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT);
        INSERT INTO settings SELECT key, value_json FROM system_state WHERE key != 'settings_rev';
        DELETE FROM system_state; DELETE FROM setting_values; DROP TABLE module_setting_keys;""")
    for n, osr in zip(nodes, (4, 6, 8)):
        pol = {"os_reserve_gb": osr, "user_reserve_gb": 8, "max_slots": None, "threads_per_job": 1, "job_mem_gb": 1.5,
               "user_present_slots": 2, "user_idle_s": 300, "run_on_battery": False, "nice": 10, "hard_limits": False,
               "disabled_services": [], "module_settings": {}, "protection": {"schema": 1, "node": {"mode": "moderate"}, "rule": []}}
        c.execute("UPDATE nodes SET policy_json=?, limits_json='{}' WHERE node_id=?", (json.dumps(pol), n["node_id"]))
    c.commit()
    c.close()
    db.conn.close()
    db = DB(path)
    assert store.rows(db) == []                                                  # copies, not choices: no value at all
    report = json.loads(db.one("SELECT payload_json FROM events WHERE kind='settings_migrated'")["payload_json"])
    assert report["modules"] == ["toy 0.1.0: 2 settings"] and report["node"] == [] and report["dropped"] == []
    assert modkeys.registration(db, "toy")["version"] == "0.1.0"


# ------------------------------------------------------------------ the console

def test_the_module_settings_tab_shows_its_keys_and_saves_them(env):
    db, n = env["db"], env["node"]
    set_node(db, n, "tile_size", 16, module="relay")
    html, text = settings_html(env, path="/modules/relay/settings")
    assert 'aria-current="page">Settings' in html and "Getting this module running" in text or "Required settings" in text
    for label in ("Run this module", "Services that do not run", "Pipeline", "Replica rate", "Tile size", "Scorer VM memory",
                  "Golden jobs"):
        assert label in text, label
    assert 'id="s-relay-module-relay-tile_size"' in html and "Overridden on 1 node" in text
    assert "Set for groups and nodes" in text and "mini" in text and "16" in text
    f = section_fields(html, "module_own")
    assert f["module"] == ["relay"] and f["scope"] == ["fleet"]
    r = save_section(env, "module_own", page="/modules/relay/settings", **{"o.module.relay.tile_size": "1",
                                                                         "v.module.relay.tile_size": "64"})
    assert r.status_code == 200 and "Save for 0 nodes" in r.text or "keeps theirs (mini)" in r.text   # the preview first
    r = save_section(env, "module_own", page="/modules/relay/settings", **{"o.module.relay.vm_mem_gb": "1",
                                                                         "v.module.relay.vm_mem_gb": "0"})
    assert r.status_code == 400 and "error-summary" in r.text and "Scorer VM memory" in r.text
    assert 'href="#v-relay-module-relay-vm_mem_gb"' in r.text


def test_the_node_settings_tab_has_a_section_per_module(env):
    db, n = env["db"], env["node"]
    html, text = settings_html(env)
    for m in ("relay", "toy"):
        assert f'id="module-{m}"' in html
    assert 'id="s-toy-module-toy-greeting"' in html and 'id="s-relay-enabled"' in html and 'id="s-toy-enabled"' in html
    r = save_section(env, "module-relay", **{"o.module.relay.tile_size": "1", "v.module.relay.tile_size": "64"})
    assert r.status_code == 303 and "kind=ok" in r.headers["location"], r.text[:300]
    assert node_settings(db, n)["module_settings"]["relay"]["tile_size"] == 64
    assert node_settings(db, n)["module_settings"]["toy"] == {"greeting": "hello"}
    r = save_section(env, "module-toy", **{"o.enabled": "1", "v.enabled": "0"})
    assert r.status_code == 303 and doc(db, n)["modules_disabled"] == ["toy"]
