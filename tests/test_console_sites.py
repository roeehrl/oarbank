"""The console's Sites pages (docs/design/sites.md, "Console"): the Sites page with its suggestions and new-site form, a
site's page with its state in words ("paused because <node>'s rule <rule> is in an upload phase"), members and budget,
and the node page's Site card. Forms go through the operation registry (create previewed first)."""
import re

from helpers import enrolled_node, fresh, run_op
from oarbank.coordinator import core, sites
from test_console import env, form  # noqa: F401 (the fixture)
from test_console_groups import apply, text as _text


def text(h: str) -> str:
    import html
    return html.unescape(_text(h))


def uplink(node, on):
    return {"telemetry": {"protection": {"phases": [{"key": "trainer#0", "rule": "trainer", "block": 0, "on": on,
                                                      "readable": True, "reader": "agent", "tags": ["uplink"]}]},
                          "uplink": {"active": [], "held": None}}}


def test_sites_pages_render_and_explain_the_hold(env):
    db, c, mini = env["db"], env["c"], env["node"]
    studio = enrolled_node(db, "studio")[1]
    gw = "ef" * 16
    for n in (mini, studio):
        sites.observe_network(db, fresh(db, n), {"gateway_fp": gw}, "10.0.0.2")
    page = c.get("/sites")
    assert page.status_code == 200 and "script-src 'self'" in page.headers["content-security-policy"]
    t = text(page.text)
    assert "2 nodes share a default gateway" in t and "New site" in t and gw not in page.text
    assert 'href="/sites">Sites</a>' in c.get("/").text
    # create from the form: previewed first, nothing written until the plan is applied
    r = form(c, "sites.create", target="", target_input="home", **{"pl.nodes": [mini["node_id"], studio["node_id"]],
                                                                   "p.max_transfers": "2", "p.max_heavy_jobs": "1",
                                                                   "p.uplink_mbps": ""})
    assert r.status_code == 200 and "mini: joins" in text(r.text), r.text[:500]
    assert sites.get(db, "home") is None
    r = apply(env, "sites.create", r.text)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"], r.headers["location"]
    s = sites.get(db, "home")
    assert s and s["max_transfers"] == 2 and s["uplink_mbps"] is None
    core.heartbeat(db, fresh(db, mini), uplink(mini, True))
    page = c.get(f"/sites/{s['site_id']}")
    assert page.status_code == 200
    t = text(page.text)
    assert "Network-heavy work at this site is paused because mini's rule trainer is in an upload phase" in t
    assert "trainer#0: on" in t
    node = text(c.get(f"/nodes/{studio['node_id']}").text)
    assert re.search(r"Site .*home .*paused because mini's rule trainer", node)
    core.heartbeat(db, fresh(db, mini), uplink(mini, False))
    assert "Free: 0 of 2 transfers" in text(c.get(f"/sites/{s['site_id']}").text)
    # the budget form (T1: previewed, then applied)
    r = form(c, "sites.update", target=s["site_id"], **{"p.max_transfers": "1", "p.max_heavy_jobs": "0", "p.uplink_mbps": "120",
                                                        "p.name": "home"})
    r = apply(env, "sites.update", r.text) if r.status_code == 200 else r
    assert sites.get(db, "home")["uplink_mbps"] == 120 and sites.get(db, "home")["max_heavy_jobs"] == 0
    assert c.get("/sites/nope").status_code == 404
    run_op(db, "sites.delete", s["site_id"])
    assert "No sites yet" in text(c.get("/sites").text)
