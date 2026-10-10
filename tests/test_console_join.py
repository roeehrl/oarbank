"""The console's machine enrollment (docs/design/node-enrollment.md, "Console"): Add machine makes a join code through
the operation's plan, the result shows it once with Copy, the deep link, per-OS steps and MDM files with the code filled
in, and follows the code's machines live; the Fleet page lists outstanding codes with Revoke and approves a machine by
the code it shows, beside the coordinator's fingerprint."""
import base64
import html as H
import plistlib
import re
from pathlib import Path

from helpers import FACTS, node_key_and_csr
from oarbank import __version__
from oarbank.coordinator import core, joincodes, tlsca

from test_console import env, form, last_audit  # noqa: F401  (the console fixture: oarbankd + console + a session)


def make_code(c, **fields):
    """Add machine through the console: the form, its plan, then apply. The result page."""
    r = form(c, "nodes.join_code", **{"count": "one", "ttl": "14400", **fields})
    assert r.status_code == 200 and 'name="plan_id"' in r.text, r.headers.get("location") or r.text[:300]
    plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
    r = c.post("/apply/nodes.join_code", data={"plan_id": plan_id, "reason": "new machine", "return_to": "/"},
               follow_redirects=False)
    assert r.status_code == 200, r.headers.get("location")
    return r


def code_of(page: str) -> str:
    return re.search(r'<code id="join-code">([^<]+)</code>', page).group(1)


def profile_of(page: str) -> dict:
    href = H.unescape(re.search(r'download="oarbank-node.mobileconfig" href="([^"]+)"', page).group(1))
    prefix = "data:application/x-apple-aspen-config;base64,"
    assert href.startswith(prefix)
    return plistlib.loads(base64.b64decode(href[len(prefix):]))


def test_the_fleet_page_offers_add_machine_and_the_form_has_its_fields(env):
    c = env["c"]
    fleet = c.get("/").text
    assert 'href="/add-machine"' in fleet and "Add machine" in fleet
    assert "oarbank-agent run --join" not in fleet                         # the old hint is gone
    r = c.get("/add-machine")
    assert r.status_code == 200 and 'action="/do/nodes.join_code"' in r.text
    page = r.text
    for field in ('name="label"', 'name="count" value="one" checked', 'name="count" value="many"',
                  'name="uses" min="2" max="10000"', 'name="approve"', 'name="system"', 'name="containers"'):
        assert field in page, field
    assert [v for v in re.findall(r'<option value="(\d+)"', page)] == ["3600", "14400", "86400", "604800", "2592000"]
    assert '<option value="14400" selected>' in page
    assert "Ignored for many machines" in page and "Windows installs the WSL components" in page
    env["c"].cookies.clear()
    assert c.get("/add-machine", follow_redirects=False).status_code == 303           # signed in only


def test_add_machine_shows_the_code_once_with_copy_deep_link_and_every_os(env):
    c, db = env["c"], env["db"]
    r = make_code(c, label="build-07", system="1")
    page = r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert not re.search(r"<script(?![^>]*\bsrc=)", page) and not re.search(r"\son[a-z]+\s*=", page)
    code = code_of(page)
    d = joincodes.decode(code)
    assert d["system"] and d["approve"] and not d["multi"]
    assert 'data-copy="join-code"' in page and f'href="oarbank://join?code={code}"' in page
    assert "Open in Oarbank Node" in page and "asks you to confirm" in page
    row = db.one("SELECT * FROM join_codes WHERE code_id=?", (d["id"],))
    assert row["label"] == "build-07" and row["max_uses"] == 1 and code not in str(dict(row))    # only a hash is kept
    a = last_audit(db)
    assert a["operation"] == "nodes.join_code" and code not in str(dict(a))
    # per-OS tabs, this version's assets
    v = __version__
    rel = f"https://github.com/roeehrl/oarbank/releases/download/v{v}/"
    for asset in (f"oarbank-agent-{v}-macos-arm64.pkg", f"oarbank-agent-{v}-macos-x86_64.pkg",
                  f"oarbank-agent_{v}_amd64.deb", f"oarbank-agent_{v}_arm64.deb",
                  f"oarbank-agent-{v}-1.x86_64.rpm", f"oarbank-agent-{v}-1.aarch64.rpm",
                  f"oarbank-agent-{v}-windows-x64.msi", f"oarbank-agent-{v}-windows-arm64.msi"):
        assert f'href="{rel}{asset}"' in page, asset
    for tab in ("macOS", "Linux", "Windows", "MDM &amp; automation"):
        assert f'">{tab}</label>' in page, tab
    text = H.unescape(page)
    for cmd in (f"sudo installer -pkg oarbank-agent-{v}-macos-arm64.pkg -target /",
                f"printf '%s' '{code}' | sudo oarbank-node join --code-stdin",
                "curl -fsSL https://github.com/roeehrl/oarbank/releases/latest/download/oarbank-install.sh | "
                f"sudo OARBANK_JOIN_CODE='{code}' sh",
                f"sudo OARBANK_JOIN_CODE='{code}' apt install ./oarbank-agent_{v}_amd64.deb",
                f"msiexec /i oarbank-agent-{v}-windows-x64.msi /qn JOINCODE={code}",
                f"msiexec /i oarbank-agent-{v}-windows-x64.msi /qn JOINCODEFILE=",
                r"%ProgramData%\Oarbank\status\joined", r"HKLM\SOFTWARE\Policies\Codonic\Oarbank\Agent",
                '{"JoinCode": "' + code + '"}',
                f'oarbank_join_code: "{code}"', "--code-stdin --no-input --wait 600", "no_log: true",
                "creates: /var/lib/oarbank/status/joined"):
        assert cmd in text, cmd
    # every snippet has its own Copy button naming it
    ids = re.findall(r'<pre id="([a-z0-9-]+)">', page)
    assert len(ids) >= 10 and all(f'data-copy="{i}"' in page for i in ids)
    # the configuration profile: managed preferences for the node's domain and the login items rule
    prof = profile_of(page)
    assert prof["PayloadType"] == "Configuration" and prof["PayloadScope"] == "System"
    prefs, items = prof["PayloadContent"]
    assert prefs["PayloadType"] == "com.apple.ManagedClient.preferences"
    forced = prefs["PayloadContent"]["dev.codonic.oarbank.agent"]["Forced"][0]["mcx_preference_settings"]
    assert forced == {"JoinCode": code, "Name": "build-07"}
    assert items["PayloadType"] == "com.apple.servicemanagement"
    assert items["Rules"] == [{"RuleType": "LabelPrefix", "RuleValue": "dev.codonic.oarbank",
                               "Comment": "The Oarbank Node agent and its helpers"}]
    uuids = {prof["PayloadUUID"], prefs["PayloadUUID"], items["PayloadUUID"]}
    assert len(uuids) == 3 and uuids.isdisjoint({profile_of(make_code(c).text)["PayloadUUID"]})
    # a single machine's code says nothing about waiting for approval
    assert "wait for your approval" not in page


def test_a_multi_use_code_says_machines_wait_unless_approved_automatically(env):
    c = env["c"]
    page = make_code(c, label="lab macs", count="many", uses="25", ttl="2592000", containers="1").text
    code = code_of(page)
    d = joincodes.decode(code)
    assert d["multi"] and not d["approve"] and d["containers"]
    assert "wait for your approval" in page and "up to 25 machines" in page
    forced = profile_of(page)["PayloadContent"][0]["PayloadContent"]["dev.codonic.oarbank.agent"]["Forced"][0]
    assert forced["mcx_preference_settings"] == {"JoinCode": code}          # no single name for many machines
    assert f"JOINCODE={code} CONTAINERS=1" in page and "OARBANK_CONTAINERS=1" in page
    page = make_code(c, count="many", uses="3", approve="1").text
    assert joincodes.decode(code_of(page))["approve"] and "approved automatically" in page


def test_the_form_refuses_what_a_code_cannot_be(env):
    c, db = env["c"], env["db"]
    before = db.one("SELECT COUNT(*) n FROM join_codes")["n"]
    for fields in ({"count": "many", "uses": "1"}, {"count": "many", "uses": ""}, {"count": "many", "uses": "10001"},
                   {"count": "one", "ttl": "2592000"}, {"count": "one", "ttl": "99"}):
        r = form(c, "nodes.join_code", **fields)
        assert r.status_code == 303 and "kind=bad" in r.headers["location"] and "invalid%20input" in r.headers["location"], fields
    assert db.one("SELECT COUNT(*) n FROM join_codes")["n"] == before


def test_the_result_follows_the_codes_machines_live(env):
    c, db = env["c"], env["db"]
    page = make_code(c, count="many", uses="5").text
    code = code_of(page)
    d = joincodes.decode(code)
    assert f'hx-get="/frag/joincode/{d["id"]}?tab=new"' in page and "sse:tick, sse:resync, every 3s" in page
    assert "Waiting for a machine to use this code" in page
    frag = c.get(f"/frag/joincode/{d['id']}")
    assert frag.status_code == 200 and "Waiting for a machine to use this code" in frag.text
    # a machine enrolls with the code: it waits for approval, with Approve and Decline
    e = core.enroll(db, "lab-1", {**FACTS, "hostname": "lab-1"}, "192.0.2.7", node_key_and_csr()[1], join=d["token"],
                    user_code="WDJBMJHT")
    assert e["status"] == "pending"
    html = c.get(f"/frag/joincode/{d['id']}").text
    assert "lab-1" in html and "192.0.2.7" in html and "WDJB-MJHT" in html and "waiting for approval" in html
    assert 'action="/do/nodes.admit"' in html and f'value="{e["enrollment_id"]}"' in html
    assert 'action="/do/nodes.reject_enrollment"' in html and 'target="_blank"' not in html
    assert "Waiting for more machines (4 uses left)" in html
    assert 'target="_blank"' in c.get(f"/frag/joincode/{d['id']}?tab=new").text   # the result page keeps its code
    # approving it from there goes through the plan and comes back to the code's page
    r = form(c, "nodes.admit", target=e["enrollment_id"], return_to=f"/join-codes/{d['id']}")
    plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
    r = c.post("/apply/nodes.admit", data={"plan_id": plan_id, "reason": "ours", "return_to": f"/join-codes/{d['id']}"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(f"/join-codes/{d['id']}")
    html = c.get(f"/frag/joincode/{d['id']}").text
    assert "approved" in html and 'action="/do/nodes.admit"' not in html
    db.x("UPDATE enrollments SET status='claimed' WHERE enrollment_id=?", (e["enrollment_id"],))
    html = c.get(f"/frag/joincode/{d['id']}").text
    assert "checking modules" in html and "Open node" in html
    # an attempt with a wrong secret for this code is refused and shown
    core.enroll(db, "stranger", {**FACTS, "hostname": "stranger"}, "198.51.100.9", node_key_and_csr()[1],
                join=f"{d['id']}.{'00' * 16}")
    html = c.get(f"/frag/joincode/{d['id']}").text
    assert "Refused attempts" in html and "stranger" in html and "unknown (from 198.51.100.9)" in html
    # the code's own page, after the one-time page is gone: status, never the code
    p = c.get(f"/join-codes/{d['id']}")
    assert p.status_code == 200 and "lab-1" in p.text and code not in p.text
    assert c.get("/join-codes/0000000000000000").status_code == 404
    assert "does not know this join code" in c.get("/frag/joincode/0000000000000000").text
    env["c"].cookies.clear()
    assert c.get(f"/frag/joincode/{d['id']}").status_code == 401                     # session-protected


def test_the_fleet_lists_outstanding_codes_with_revoke_and_approves_by_device_code(env):
    c, db, state = env["c"], env["db"], env["state"]
    code = code_of(make_code(c, label="spare mini", count="many", uses="3").text)
    cid = joincodes.decode(code)["id"]
    state.rebuild()
    fleet = c.get("/frag/fleet").text
    assert "Outstanding join codes" in fleet and f'href="/join-codes/{cid}"' in fleet and "spare mini" in fleet
    assert "0 / 3" in fleet and "you approve" in fleet
    assert 'action="/do/nodes.revoke_join_code"' in fleet and f'name="target" value="{cid}"' in fleet
    # approve by the code a machine shows, beside the fingerprint `oarbank-node join --coordinator` prints
    fp = tlsca.pins(Path(db.path).parent)["ca_spki_sha256"][:16]
    assert 'action="/do/nodes.admit_code"' in fleet and 'name="user_code"' in fleet and 'placeholder="WDJB-MJHT"' in fleet
    assert f"Your coordinator's fingerprint: <span class=\"mono\">sha256:{fp}…</span>" in fleet
    assert 'id="approve-by-code" hx-preserve' in fleet
    e = core.enroll(db, "by-address", {**FACTS, "hostname": "by-address"}, "192.0.2.8", node_key_and_csr()[1],
                    user_code="BCDF-GHJK")
    r = form(c, "nodes.admit_code", user_code="bcdf-ghjk")
    assert r.status_code == 200 and "by-address" in r.text                        # the plan names the machine
    plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
    r = c.post("/apply/nodes.admit_code", data={"plan_id": plan_id, "reason": "fingerprint matches", "return_to": "/"},
               follow_redirects=False)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"], r.headers["location"]
    assert db.one("SELECT status FROM enrollments WHERE enrollment_id=?", (e["enrollment_id"],))["status"] == "approved"
    # revoke (T1: straight through) takes it off the list
    r = form(c, "nodes.revoke_join_code", target=cid)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"]
    assert db.one("SELECT revoked_at FROM join_codes WHERE code_id=?", (cid,))["revoked_at"]
    state.rebuild()
    assert f'href="/join-codes/{cid}"' not in c.get("/frag/fleet").text
