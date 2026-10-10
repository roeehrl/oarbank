"""The console's groups, locks, bulk changes and labels (docs/design/settings.md, "The console"): the Groups page with its
live member preview, a group's page with its settings at group scope (lock toggle, Promote to fleet), the node row that
names the lock, Bulk changes with their per-node review, and labels on the node page."""
import re
from urllib.parse import urlencode

from helpers import FACTS, certify, enrolled_node, node_settings, set_node
from oarbank.coordinator.settings import store
from test_console import env, form, save_section, settings_html  # noqa: F401 (the fixture)

LAPTOP = {**FACTS, "power": {"battery": True}}


def text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def plan_id(html: str) -> str:
    return re.search(r'name="plan_id" value="([^"]+)"', html).group(1)


def apply(env, op, html, reason="test", **extra):
    return env["c"].post(f"/apply/{op}", data={"plan_id": plan_id(html), "reason": reason, "return_to": "/", **extra},
                         follow_redirects=False)


def post(env, path, data):
    return env["c"].post(path, content=urlencode(data, doseq=True), follow_redirects=False,
                         headers={"content-type": "application/x-www-form-urlencoded"})


def test_the_pages_render_under_the_strict_csp(env):
    from helpers import run_op
    run_op(env["db"], "groups.create", "Laptops", {"selector": {"battery": True}})
    for path in ("/groups", "/groups/laptops", "/groups/os-darwin", "/nodes/bulk", "/nodes/bulk?label=x",
                 "/frag/groups/preview?sel.battery=yes"):
        r = env["c"].get(path)
        assert r.status_code == 200, (path, r.text[:300])
        assert "script-src 'self'" in r.headers["content-security-policy"]
    assert env["c"].get("/groups/nope").status_code == 404
    assert 'href="/groups">Groups</a>' in env["c"].get("/").text


def test_a_group_is_created_from_the_groups_page_after_its_member_preview(env):
    db = env["db"]
    mbp = enrolled_node(db, "macbook", facts=LAPTOP)[1]
    r = env["c"].get("/frag/groups/preview", params={"sel.battery": "yes"})
    t = text(r.text)
    assert "1 of 2 nodes" in t and "member macbook because has a battery" in t and "not a member mini not: has a battery" in t
    r = env["c"].get("/frag/groups/preview", params={"sel.ram_gb_min": "lots"})
    assert "ram gb min: a number" in r.text
    r = env["c"].get("/frag/groups/preview", params={"selector_json": '{"colour": 1}'})
    assert "unknown selector term" in r.text
    page = env["c"].get("/groups").text
    assert "New group" in page and 'hx-get="/frag/groups/preview"' in page and "Built-in groups" in page
    r = form(env["c"], "groups.create", target="", name="Laptops", **{"sel.battery": "yes", "description": "portable"})
    assert r.status_code == 200 and "macbook joins Laptops" in text(r.text)          # previewed first, nothing written
    assert not [g for g in store.groups(db) if not g["builtin"]]
    r = apply(env, "groups.create", r.text)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"], r.headers["location"]
    g = next(g for g in store.groups(db) if g["name"] == "Laptops")
    assert g["selector"] == {"battery": True} and g["description"] == "portable"
    page = text(env["c"].get("/groups/laptops").text)
    assert "macbook because has a battery" in page and "Settings for Laptops" in page
    assert mbp


def test_a_lock_set_on_a_group_page_holds_on_the_node_and_says_who_locked_it(env):
    db = env["db"]
    from helpers import run_op
    run_op(db, "groups.create", "Laptops", {"members": ["mini"]})
    set_node(db, env["node"], "run_on_battery", True)
    html = env["c"].get("/groups/laptops").text
    assert 'name="enf.run_on_battery"' in html and "lock" in text(html)
    r = save_section(env, "presence", page="/groups/laptops", o__run_on_battery="1", v__run_on_battery="0",
                     enf__run_on_battery="1")
    assert r.status_code == 200, r.text[:400]
    t = text(r.text)
    assert "Run jobs on battery at group Laptops: not set → off (locked)" in t and "Type run_on_battery to confirm" in t
    assert "mini sets its own value (on): ignored while the lock holds" in t
    r = apply(env, "settings.apply", r.text, confirm="run_on_battery")
    assert r.status_code == 303 and "kind=ok" in r.headers["location"], r.headers["location"]
    assert store.row(db, "group", "laptops", "", "run_on_battery")["enforced"] == 1
    assert node_settings(db, env["node"])["run_on_battery"] is False
    html, t = settings_html(env)
    i = html.index('id="s-run_on_battery"')
    row = text(html[i:html.index('<details class="small explain"', i)])
    assert "Locked by the group Laptops. Change it there: Group: Laptops" in row
    assert "own value (on) is kept and applies again when the lock goes" in row
    assert 'href="/groups/laptops?explain=run_on_battery#s-run_on_battery"' in html
    group_html = env["c"].get("/groups/laptops").text
    assert "locked here" in text(group_html) and 'name="had_enf.run_on_battery"' in group_html
    # the node's own value may still be reset under the lock; setting one again is refused, naming the lock
    r = save_section(env, "presence", reset="run_on_battery")
    assert r.status_code == 303 and store.row(db, "node", env["node"]["node_id"], "", "run_on_battery") is None
    r = save_section(env, "presence", o__run_on_battery="1", v__run_on_battery="1")
    assert r.status_code == 400 and "locked by the group Laptops: change it there" in text(r.text)


def test_a_group_value_is_promoted_to_the_fleet_from_its_page(env):
    db = env["db"]
    from helpers import run_op, settings_apply
    other = certify(db, enrolled_node(db, "desk")[1])
    run_op(db, "groups.create", "Canary", {"members": ["mini"]})
    settings_apply(db, {"scope": "group", "scope_id": "canary", "key": "job_mem_gb", "value": 2})
    html = env["c"].get("/groups/canary").text
    assert 'form="promote-canary-job_mem_gb"' in html and 'id="promote-canary-job_mem_gb"' in html
    r = post(env, "/do/settings.promote", {"target": "job_mem_gb", "return_to": "/groups/canary", "p.key": "job_mem_gb",
                                           "p.group": "canary", "idem": "", "csrf": ""})
    assert r.status_code == 200
    t = text(r.text)
    assert "Changes the effective value on 1 node (desk); 1 node keeps theirs (mini)" in t
    assert "Memory per job slot at group Canary: 2 GB → reset (inherits)" in t
    r = apply(env, "settings.promote", r.text)
    assert r.status_code == 303 and "Promoted" in r.headers["location"].replace("%20", " ")
    assert node_settings(db, other)["job_mem_gb"] == 2 and store.row(db, "fleet", "", "", "job_mem_gb")["value"] == 2


def test_bulk_changes_preview_every_node_then_save_one_change_set(env):
    db = env["db"]
    desk = certify(db, enrolled_node(db, "desk")[1])
    set_node(db, desk, "jobs", 1)
    page = env["c"].get("/nodes/bulk").text
    assert 'name="node" value="' in page and "Reset to inherited" in page and 'formaction="/do/nodes.label"' in page
    data = {"target": "nodes", "return_to": "/nodes/bulk", "idem": "", "bulk": "1", "page": "bulk",
            "node": [env["node"]["node_id"], desk["node_id"]], "bulk_key": "jobs", "bulk_action": "set", "bulk_value": "2"}
    r = post(env, "/do/settings.apply", data)
    assert r.status_code == 200, r.text[:300]
    t = text(r.text)
    assert "Changes the effective value on 2 nodes (desk, mini)" in t and "Save for 2 nodes" not in t   # node values
    r = apply(env, "settings.apply", r.text)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"]
    assert node_settings(db, env["node"])["jobs"] == 2 and node_settings(db, desk)["jobs"] == 2
    revs = {x["settings_rev"] for x in db.q("SELECT settings_rev FROM nodes")}
    assert len(revs) == 1                                             # one change set, one revision
    # nothing ticked: the page again, with the problem named
    r = post(env, "/do/settings.apply", {**data, "node": []})
    assert r.status_code == 400 and "tick at least one node" in r.text
    # labels on every ticked node, through the same form
    r = post(env, "/do/nodes.label", {**data, "labels": "lab, render", "label_action": "add"})
    assert r.status_code == 200 and "mini: lab, render" in text(r.text)
    r = apply(env, "nodes.label", r.text)
    assert r.status_code == 303
    assert store.labels(db) == {env["node"]["node_id"]: ["lab", "render"], desk["node_id"]: ["lab", "render"]}
    assert "desk" in text(env["c"].get("/nodes/bulk?label=lab").text)


def test_labels_are_set_and_removed_on_the_node_page(env):
    db, n = env["db"], env["node"]
    html, t = settings_html(env)
    assert 'id="labels"' in html and "no labels" in t and "macOS (built in) because macOS" in t
    r = form(env["c"], "nodes.label", target=n["node_id"], labels="render")
    assert r.status_code == 200
    assert apply(env, "nodes.label", r.text).status_code == 303
    html, t = settings_html(env)
    assert "render" in t and '"remove": ["render"]' in html.replace("&#34;", '"').replace("&quot;", '"')
    r = form(env["c"], "nodes.label", target=n["node_id"], params='{"remove": ["render"]}')
    assert apply(env, "nodes.label", r.text).status_code == 303 and store.labels(db) == {}
    overview = text(env["c"].get(f"/nodes/{n['node_id']}").text)
    assert "Groups and labels" in overview and "macOS because macOS" in overview
