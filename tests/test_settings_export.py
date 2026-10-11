"""Settings as code and the reports (docs/design/settings.md, "Settings as code", "Reports"): the YAML subset, export
per scope, import as one change (the phase-5 exit test: an exported fleet imported with --dry-run changes nothing),
round trips per scope, a changed file, shadowed values and applied drift."""
import json

import pytest

from helpers import FACTS, enrolled_node, fresh, make_db, run_op, settings_apply
from oarbank.coordinator import core, ops
from oarbank.coordinator.settings import apply as A, export as X, reports, store, yamlish as Y

LAPTOP = {**FACTS, "power": {"battery": True}}


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def op(db, name, target=None, params=None, dry_run=False):
    req = dict(op=name, actor="test", source="system", target=target, params=params or {}, reason="test")
    if dry_run:
        return ops.execute(db, ops.OpRequest(**req, dry_run=True))
    plan = ops.execute(db, ops.OpRequest(**req, dry_run=True))["plan"]
    return ops.execute(db, ops.OpRequest(**req, plan_id=plan["plan_id"], confirm=plan["confirm_name"]))


def furnished(db):
    """A fleet with something at every scope: fleet values and a lock, an owner group with a selector, members and
    values, a built-in group's value, node values and labels, a module's keys, protection rules, a tool definition."""
    _, mini = enrolled_node(db, "mini")
    _, mbp = enrolled_node(db, "macbook", facts=LAPTOP)
    op(db, "groups.create", "Laptops", {"selector": {"battery": True}, "description": "on battery sometimes"})
    op(db, "groups.create", "Lab", {"members": ["mini"]})
    run_op(db, "nodes.label", "mini", {"add": ["render", "lab"]})
    settings_apply(db, {"scope": "fleet", "key": "job_mem_gb", "value": 2},
                   {"scope": "fleet", "key": "user_idle_s", "value": 600, "enforce": True},
                   {"scope": "fleet", "key": "console_hosts", "value": ["oarbank.example.ts.net"]},
                   {"scope": "fleet", "module": "relay", "key": "goldens", "value": [{"name": "g", "params": {"a": 1}}]},
                   {"scope": "group", "scope_id": "Laptops", "key": "run_on_battery", "value": False, "enforce": True},
                   {"scope": "group", "scope_id": "macOS", "key": "user_reserve_gb", "value": 6},
                   {"scope": "group", "scope_id": "Lab", "module": "relay", "key": "tile_size", "value": 64},
                   {"scope": "node", "scope_id": "mini", "key": "schedule", "value": {"start": "22:00", "end": "07:00"}},
                   {"scope": "node", "scope_id": "mini", "key": "jobs", "value": 3},
                   {"scope": "node", "scope_id": "macbook", "module": "relay", "key": "enabled", "value": False})
    op(db, "tools.define", "samtools", {"kind": "executable", "search": {"darwin": ["/opt/homebrew/bin/samtools"]},
                                        "version": {"args": ["--version"], "regex": "samtools (\\d+\\.\\d+)"}})
    return mini, mbp


def test_the_yaml_subset_reads_back_what_it_writes():
    doc = {"oarbank": "settings/v1", "a": {"b": 1.5, "c": None, "d": True, "e": "plain.word", "f": "two words",
                                          "g": ["x", 2], "h": Y.Flow({"start": "22:00"}), "i": Y.Locked(False), "j": "yes",
                                          "k": "", "l": {}, "group:x": 1, "m": "a#b", "n": "-dash", "o": "1.5"}}
    text = Y.dump(doc, "header\nline")
    back = Y.load(text)
    assert back["a"]["h"] == {"start": "22:00"} and back["a"]["i"] == Y.Locked(False)
    assert {k: v for k, v in back["a"].items() if k not in ("h", "i")} == {k: v for k, v in doc["a"].items() if k not in ("h", "i")}
    hand = Y.load("x:\n  # a comment\n  y: [a, b]   # trailing\n  z: !reset\n  w: 'it''s'\nlist:\n- 1\n- k: v\n  q: 2\n")
    assert hand == {"x": {"y": ["a", "b"], "z": Y.RESET, "w": "it's"}, "list": [1, {"k": "v", "q": 2}]}
    for bad, why in (("a: yes", "ambiguous"), ("a: !nope 1", "unknown tag"), ("a:\n    b: 1\n  c: 2", "indentation"),
                     ("a: 1\na: 2", "twice"), ("a: &x 1", "anchors")):
        with pytest.raises(Y.YamlError, match=why):
            Y.load(bad)


def test_an_exported_fleet_imported_with_dry_run_is_a_no_op(db):
    """The phase-5 exit test."""
    furnished(db)
    text = X.export_yaml(db)
    assert "user_idle_s: !locked 600" in text
    assert "Laptops" in text and "samtools" in text and "render" in text
    plan = op(db, "settings.import", None, {"text": text}, dry_run=True)["plan"]
    assert plan["impact"]["empty"] and plan["impact"]["summary"] == "No changes: the file matches this fleet"
    rev = store.rev(db)
    res = op(db, "settings.import", None, {"text": text})["result"]
    assert res["changed"] == 0 and store.rev(db) == rev                     # nothing written, not even a revision


@pytest.mark.parametrize("scope", ["fleet", "group:laptops", "group:macOS", "node:mini", "node:macbook"])
def test_each_scope_round_trips_into_a_fresh_fleet(tmp_path, scope):
    """Export a scope, reset what it holds in another home with the same nodes, import: the values come back exactly."""
    a = make_db(tmp_path / "a.sqlite3")
    furnished(a)
    text = X.export_yaml(a, scope)
    b = make_db(tmp_path / "b.sqlite3")
    enrolled_node(b, "mini")
    enrolled_node(b, "macbook", facts=LAPTOP)
    if scope.startswith("node:") or scope == "group:laptops":
        op(b, "groups.create", "Laptops", {"selector": {"battery": True}, "description": "on battery sometimes"})
    if scope != "fleet":
        op(b, "groups.create", "Lab", {"members": ["mini"]})
    text_b = text
    for nid_a, nid_b in zip([n["node_id"] for n in a.q("SELECT node_id FROM nodes ORDER BY hostname")],
                            [n["node_id"] for n in b.q("SELECT node_id FROM nodes ORDER BY hostname")]):
        text_b = text_b.replace(nid_a, nid_b)                                # another fleet: other node ids
    op(b, "settings.import", None, {"text": text_b})
    again = X.export_yaml(b, scope)
    strip = lambda t: [x for x in t.splitlines() if not x.startswith("#") and "node_id" not in x]
    assert strip(again) == strip(text_b)
    assert op(b, "settings.import", None, {"text": again}, dry_run=True)["plan"]["impact"]["empty"]


def test_a_changed_file_imports_its_differences_and_only_those(db):
    mini, mbp = furnished(db)
    text = X.export_yaml(db)
    text = text.replace("job_mem_gb: 2", "job_mem_gb: 3").replace("jobs: 3", "jobs: !reset")
    text = text.replace("labels: [\"render\", \"lab\"]", "labels: [\"render\"]").replace("labels: [\"lab\", \"render\"]", "labels: [\"render\"]")
    text = text.replace("      run_on_battery: !locked false", "      run_on_battery: false")
    plan = op(db, "settings.import", None, {"text": text}, dry_run=True)["plan"]
    imp = plan["impact"]
    assert not imp["empty"]
    assert any("Memory per job slot at Fleet: 2 GB → 3 GB" in x for x in imp["changes"])
    assert any("Concurrent jobs at mini: 3 jobs → reset (inherits)" in x for x in imp["changes"])
    assert any("Run jobs on battery at group Laptops" in x for x in imp["changes"])
    assert imp["labels"] == ["mini: remove lab"]
    assert any(x.startswith("macbook: Memory per job slot") for x in imp["nodes_changed"])
    op(db, "settings.import", None, {"text": text})
    assert store.row(db, "fleet", "", "", "job_mem_gb")["value"] == 3
    assert store.row(db, "node", mini["node_id"], "", "jobs") is None
    assert not store.row(db, "group", "laptops", "", "run_on_battery")["enforced"]
    assert store.labels(db)[mini["node_id"]] == ["render"]
    assert store.row(db, "node", mini["node_id"], "", "schedule")["value"] == {"start": "22:00", "end": "07:00"}  # untouched
    # an unknown node or an invalid value refuses the whole import, naming each problem
    with pytest.raises(ops.OpError) as e:
        op(db, "settings.import", None, {"text": text.replace("job_mem_gb: 3", "job_mem_gb: -1")}, dry_run=True)
    assert e.value.code == "invalid_settings" and "Memory per job slot" in e.value.detail
    doc = "oarbank: settings/v1\nscope: fleet\nnodes:\n  nosuch:\n    settings:\n      jobs: 2\ngroups:\n  ghost:\n    settings: {}\n"
    with pytest.raises(ops.OpError) as e:
        op(db, "settings.import", None, {"text": doc}, dry_run=True)
    assert e.value.code == "invalid_import" and "no node 'nosuch' here" in e.value.detail and "ghost" in e.value.detail
    with pytest.raises(ops.OpError) as e:
        op(db, "settings.import", None, {"text": "just: text"}, dry_run=True)
    assert e.value.code == "bad_document"


def test_secrets_are_fingerprints_and_never_imported(db):
    furnished(db)
    run_op(db, "settings.secrets.set", "ntfy_token", secret="s3cret-value")
    text = X.export_yaml(db)
    assert "s3cret-value" not in text and "ntfy_token" in text
    store_fp = db.one("SELECT fingerprint FROM secrets WHERE name='ntfy_token'")["fingerprint"]
    assert store_fp in text
    other = text.replace(store_fp, "sha256:0000")
    imp = op(db, "settings.import", None, {"text": other}, dry_run=True)["plan"]["impact"]
    assert imp["empty"] and any("secret ntfy_token (fleet): set to another value here" in x for x in imp["notes"])


def test_module_scoped_export_keeps_one_modules_keys(db):
    furnished(db)
    text = X.export_yaml(db, "fleet", "relay")
    doc = Y.load(text)
    assert doc["module"] == "relay" and "settings" not in doc["fleet"]
    assert doc["groups"]["lab"]["modules"]["relay"]["tile_size"] == 64 and "name" not in doc["groups"]["lab"]
    assert op(db, "settings.import", None, {"text": text}, dry_run=True)["plan"]["impact"]["empty"]


# ------------------------------------------------------------------ reports

def test_shadowed_values_are_found_with_a_reset_for_each(db):
    mini, mbp = furnished(db)
    store.put(db, "node", mbp["node_id"], "", "user_idle_s", 900, "test", 1)         # set before the fleet locked it
    settings_apply(db, {"scope": "node", "scope_id": "mini", "key": "job_mem_gb", "value": 2},             # what it inherits
                   {"scope": "fleet", "key": "threads_per_job", "value": 1},                           # the default
                   {"scope": "fleet", "key": "cpu_cores", "value": 4},
                   {"scope": "node", "scope_id": "mini", "key": "cpu_cores", "value": 6})              # a min fold: no effect
    rep = reports.shadowed(db)
    got = {(x["scope"], x["name"], x["key"]): x["category"] for x in rep["rows"]}
    assert got[("node", "macbook", "user_idle_s")] == "locked"
    assert got[("node", "mini", "job_mem_gb")] == "same"
    assert got[("fleet", "Fleet", "threads_per_job")] == "same"
    assert got[("node", "mini", "cpu_cores")] == "no_effect"
    assert ("node", "mini", "jobs") not in got and ("group", "Laptops", "run_on_battery") not in got
    row = next(x for x in rep["rows"] if x["key"] == "user_idle_s")
    assert row["why"] == "ignored while locked by Fleet settings" and row["change"]["reset"]
    reset_all = rep["reset_all"]
    settings_apply(db, *reset_all)                                          # the one-click reset, all at once
    assert reports.shadowed(db)["total"] == 0
    assert store.row(db, "node", mini["node_id"], "", "jobs")["value"] == 3  # choices that change something stay


def test_applied_drift_names_lagging_refusing_and_managed_nodes(db):
    _, a = enrolled_node(db, "a")
    _, b = enrolled_node(db, "b")
    core.heartbeat(db, fresh(db, a), {"attempts": [], "settings": {"applied_rev": fresh(db, a)["settings_rev"], "rejected": []}})
    core.heartbeat(db, fresh(db, b), {"attempts": [], "settings": {
        "applied_rev": 0, "rejected": [{"key": "job_mem_gb", "reason": "expected a number"}],
        "managed": [{"key": "run_on_battery", "value": False, "binding": False}, {"key": "jobs", "value": 1, "binding": True},
                    {"key": "job_mem_gb", "value": 9}],
        "managed_refused": [{"key": "nice", "reason": "not a setting managed policy may set"}], "managed_by": "Example Org"}})
    d = reports.drift(db)
    by = {x["hostname"]: x for x in d["nodes"]}
    assert by["a"]["state"] == "applied" and by["b"]["state"] == "rejected" and d["drifting"] == ["b"]
    assert [(g["key"], g["binds"]) for g in by["b"]["managed"]] == [("jobs", True), ("run_on_battery", False)]
    assert by["b"]["managed_by"] == "Example Org" and by["b"]["managed_refused"][0]["key"] == "nice"
    # the managed layer: the coordinator shows it and folds it in where it is stricter
    from oarbank.coordinator.settings import resolve as V
    res = V.resolve(V.snapshot(db), fresh(db, b), "jobs")
    assert res["value"] == 1 and res["source"]["scope"] == "managed" and V.badge(res) == "On this machine (managed) · Example Org"
    settings_apply(db, {"scope": "fleet", "key": "run_on_battery", "value": True})
    assert A.node_values(fresh(db, b))["policy"]["run_on_battery"] is False     # managed off holds on b
    assert A.node_values(fresh(db, a))["policy"]["run_on_battery"] is True
    plan = A.plan(db, [{"scope": "fleet", "key": "jobs", "value": 4}])
    assert "a: Concurrent jobs none → 4 jobs" in plan["nodes_changed"] and any(x.startswith("b: keeps 1") for x in plan["nodes_unaffected"])
    # a machine that stops managing it: the layer goes, and the node's document follows
    core.heartbeat(db, fresh(db, b), {"attempts": [], "settings": {"applied_rev": 1, "rejected": []}})
    assert V.resolve(V.snapshot(db), fresh(db, b), "jobs")["source"]["scope"] == "default"
    assert A.node_values(fresh(db, b))["policy"]["run_on_battery"] is True


def test_the_install_then_redetect_flow(db):
    from oarbank.coordinator import tools as T
    assert T.install_command("jdk", {"id": "jdk", "version": ">=17"}, "linux", "fedora") == "sudo dnf install java-17-openjdk-headless"
    assert T.install_command("jdk", {"id": "jdk", "version": ">=17"}, "linux", "ubuntu") == "sudo apt install openjdk-17-jdk-headless"
    assert T.install_command("jdk", {"id": "jdk", "version": ">=21"}, "darwin") == "brew install openjdk@21"
    _, n = enrolled_node(db, "mini")
    assert T.redetect_state(fresh(db, n)) is None
    run_op(db, "tools.detect", "mini")
    st = T.redetect_state(fresh(db, n))
    assert st["state"] == "waiting" and "offline" in st["text"]
    import time
    core.heartbeat(db, fresh(db, n), {"attempts": [], "tools": {"detected_at": time.time() + 1, "native_arch": "aarch64", "tools": {}}})
    assert T.redetect_state(fresh(db, n))["state"] == "done"


# ------------------------------------------------------------------ the console

from test_console import env  # noqa: E402,F401 (the console fixture)


def test_console_export_import_and_reports(env):
    db, c = env["db"], env["c"]
    settings_apply(db, {"scope": "fleet", "key": "job_mem_gb", "value": 2},
                   {"scope": "node", "scope_id": env["node"]["node_id"], "key": "job_mem_gb", "value": 2})
    r = c.get("/settings/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/yaml")
    assert "attachment" in r.headers["content-disposition"] and "job_mem_gb: 2" in r.text
    page = c.get("/settings/import").text
    assert "Export and import" in page and 'name="file"' in page and 'value="node:mini"' in page
    r = c.post("/do/settings.import", data={"return_to": "/settings/import", "idem": "", "text": r.text}, follow_redirects=False)
    assert r.status_code == 200 and 'name="plan_id"' in r.text and "No changes: the file matches this fleet" in r.text
    changed = c.get("/settings/export").text.replace("job_mem_gb: 2\n  modules", "job_mem_gb: 3\n  modules").replace(
        "    job_mem_gb: 2\n", "    job_mem_gb: 3\n", 1)
    r = c.post("/do/settings.import", files={"file": ("fleet.yml", changed.encode(), "application/yaml")},
               data={"return_to": "/settings/import", "idem": "", "text": ""}, follow_redirects=False)
    assert r.status_code == 200 and "Memory per job slot at Fleet: 2 GB → 3 GB" in r.text
    plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
    r = c.post("/apply/settings.import", data={"plan_id": plan_id, "reason": "from file", "return_to": "/settings/import"},
               follow_redirects=False)
    assert r.status_code == 303 and store.row(db, "fleet", "", "", "job_mem_gb")["value"] == 3
    sh = c.get("/settings/shadowed").text
    assert "Shadowed values" in sh and "0 under a lock, 1 the same as inherited" in sh
    dr = c.get("/settings/drift").text
    assert "Applied drift" in dr and env["node"]["hostname"] in dr
