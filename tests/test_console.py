"""oarbank-console (PLAN D10): a separate read-only process that forwards every change to oarbankd's
operation endpoint. Runs a real oarbankd admin API on a loopback port and drives the console over HTTP."""
import socket
import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient

from helpers import sign_in, create_study, release_id, PARAMS, certify, enrolled_node, fresh, make_db
from oarbank.console.app import console_app
from oarbank.console.state import ConsoleState, wait_for_schema
from oarbank.coordinator import app as coord_app

SECRET = "s3cret-for-tests"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, app):
        self.port = free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("server did not start")

    def __exit__(self, *a):
        self.server.should_exit = True
        self.thread.join(5)


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "oarbank.sqlite3"
    db = make_db(path)
    node = certify(db, enrolled_node(db)[1])
    sid = create_study(db, "study-a", [], ["scene:s1"], {"label": "base", "params": PARAMS})
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(path, f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        state.poll_fleetd(__import__("httpx").Client())
        with TestClient(console_app(state), client=("127.0.0.1", 50001)) as c:
            sess = sign_in(c, db)
            yield {"db": db, "node": node, "sid": sid, "state": state, "c": c, "oarbankd": oarbankd, "session": sess}


def form(c, op, **fields):
    return c.post(f"/do/{op}", data={"return_to": "/", "idem": fields.pop("idem", ""), **fields}, follow_redirects=False)


def last_audit(db):
    return db.one("SELECT * FROM audit ORDER BY event_id DESC LIMIT 1")


def test_pages_render_with_strict_csp(env):
    c, n, sid = env["c"], env["node"], env["sid"]
    for path in ("/", "/frag/fleet", f"/nodes/{n['node_id']}", "/campaigns", f"/campaigns/{sid}", f"/frag/campaign/{sid}", "/m/relay/scores",
                 "/jobs", "/events", "/audit", "/settings", "/healthz", "/verify", "/modules/relay", "/modules/relay/health",
                 f"/explain/job/{env['db'].one('SELECT job_id FROM jobs LIMIT 1')['job_id']}", f"/explain/node/{n['node_id']}"):
        r = c.get(path)
        assert r.status_code == 200, (path, r.text[:300])
        assert "script-src 'self'" in r.headers["content-security-policy"] and r.headers["x-frame-options"] == "DENY"
        if r.headers["content-type"].startswith("text/html") and "<html" in r.text:
            assert '"allowEval": false' in r.text and '"allowScriptTags": false' in r.text   # htmx 2 defaults are unsafe
    jid = env["db"].one("SELECT job_id FROM jobs LIMIT 1")["job_id"]
    assert c.get(f"/jobs/{jid}").status_code == 200


def test_t0_operation_is_forwarded_with_identity_and_audited(env):
    c, db, n = env["c"], env["db"], env["node"]
    r = form(c, "nodes.pause", target=n["node_id"])
    assert r.status_code == 303 and "kind=ok" in r.headers["location"]
    assert fresh(db, n)["desired_state"] == "paused"
    a = last_audit(db)
    assert (a["operation"], a["actor"], a["source"], a["outcome"]) == ("nodes.pause", "owner", "gui", "ok")
    sign_in(c, db, "alice", "operator")                                          # the session's account is the actor
    r = c.post("/do/nodes.resume", data={"target": n["node_id"], "return_to": "/"},
               headers={"tailscale-user-login": "mallory@example.com"}, follow_redirects=False)   # headers never count
    assert r.status_code == 303 and last_audit(db)["actor"] == "alice"
    sign_in(c, db, "vic", "viewer")
    r = c.post("/do/nodes.pause", data={"target": n["node_id"], "return_to": "/"}, follow_redirects=False)
    assert "forbidden_role" in r.headers["location"] and fresh(db, n)["desired_state"] == "active"


def test_t2_opens_a_plan_page_and_applies_the_plan(env):
    c, db = env["c"], env["db"]
    r = form(c, "releases.promote", target=release_id(env["db"]))
    assert r.status_code == 200 and 'name="plan_id"' in r.text and "Reason (required)" in r.text
    plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
    r = c.post("/apply/releases.promote", data={"plan_id": plan_id, "reason": "reviewed", "return_to": "/settings"},
               follow_redirects=False)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"]
    a = last_audit(db)
    assert (a["operation"], a["reason"], a["plan_id"], a["source"]) == ("releases.promote", "reviewed", plan_id, "gui")


def test_t3_needs_the_typed_name(env):
    c, db, n = env["c"], env["db"], env["node"]
    r = form(c, "nodes.retire", target=n["node_id"])
    plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
    assert "Type <b" in r.text
    r = c.post("/apply/nodes.retire", data={"plan_id": plan_id, "reason": "sold", "confirm": "nope", "confirm_name": "mini"})
    assert r.status_code == 400 and fresh(db, n)["lifecycle"] == "ready"
    r = c.post("/apply/nodes.retire", data={"plan_id": plan_id, "reason": "sold", "confirm": "mini"}, follow_redirects=False)
    assert r.status_code == 303 and fresh(db, n)["lifecycle"] == "retired"


def test_cross_site_posts_are_refused(env):
    r = env["c"].post("/do/fleet.pause", data={"target": "fleet"}, headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403
    r = env["c"].post("/do/fleet.pause", data={"target": "fleet"}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    assert env["db"].get_setting("fleet_state", "active") == "active"


def _signed_out(c):
    c.cookies.clear()
    c.headers.pop("x-csrf-token", None)


def test_pages_need_a_session_and_forms_need_its_csrf_token(env):
    db, n, c, sess = env["db"], env["node"], env["c"], env["session"]
    _signed_out(c)
    r = c.get(f"/nodes/{n['node_id']}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=")
    assert c.get("/frag/fleet").status_code == 401
    assert c.get("/", headers={"tailscale-user-login": "owner@example.com"}, follow_redirects=False).status_code == 303
    assert c.get("/login").status_code == 200 and "Sign in with a passkey" in c.get("/login").text
    c.cookies.set("oarbank_session", sess["sid"])                              # the cookie without its CSRF token
    r = c.post("/do/nodes.pause", data={"target": n["node_id"], "return_to": "/"})
    assert r.status_code == 403 and fresh(db, n)["desired_state"] == "active"
    r = c.post("/do/nodes.pause", data={"target": n["node_id"], "return_to": "/", "csrf": sess["csrf"]}, follow_redirects=False)
    assert r.status_code == 303 and fresh(db, n)["desired_state"] == "paused"
    assert c.get("/", headers={"host": "evil.example"}).status_code == 421           # DNS rebinding
    assert c.get("/", headers={"tailscale-funnel-request": "?1"}).status_code == 403


def test_sign_in_with_password_and_totp_or_a_one_time_link(env):
    from oarbank.coordinator import access
    db, c = env["db"], env["c"]
    seed = access.create_account(db, "ana", "operator", "correct horse battery", "test")["totp_secret"]
    _signed_out(c)
    code = access.totp_at(seed, int(time.time() // 30))
    r = c.post("/login", data={"name": "ana", "password": "wrong password!!", "code": code, "next": "/"}, follow_redirects=False)
    assert r.status_code == 401
    r = c.post("/login", data={"name": "ana", "password": "correct horse battery", "code": code, "next": "/jobs"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/jobs" and "httponly" in r.headers["set-cookie"].lower()
    assert "samesite=strict" in r.headers["set-cookie"].lower() and c.get("/jobs").status_code == 200
    _signed_out(c)
    r = c.post("/login", data={"name": "ana", "password": "correct horse battery", "code": code}, follow_redirects=False)
    assert r.status_code == 401                                                   # a TOTP code works once
    link = access.new_login_link(db, "owner")
    assert c.get(f"/login/link?t={link}", follow_redirects=False).status_code == 303
    assert c.get("/settings").status_code == 200
    _signed_out(c)
    assert c.get(f"/login/link?t={link}", follow_redirects=False).status_code == 401   # used up
    outcomes = [r["outcome"] for r in db.q("SELECT outcome FROM audit WHERE operation='access.sign_in'")]
    assert "denied" in outcomes and outcomes.count("ok") >= 2


def test_account_secrets_are_shown_once_on_a_page_never_in_a_url(env):
    c, db = env["c"], env["db"]
    r = form(c, "access.tokens.create", target="owner", **{"p.label": "ci", "p.role": "viewer", "p.days": "7"})
    plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
    r = c.post("/apply/access.tokens.create", data={"plan_id": plan_id, "reason": "ci", "return_to": "/account"})
    assert r.status_code == 200 and "Save this now" in r.text and "oak_" in r.text
    tok = r.text.split("oak_")[1].split("<")[0]
    assert db.one("SELECT COUNT(*) n FROM access_tokens WHERE token_hash LIKE ?", ("%" + tok[-6:] + "%",))["n"] == 0  # hashed
    assert c.get("/account").status_code == 200 and c.get("/access").status_code == 200


def test_fragments_render_once_per_snapshot_version(env):
    c, state = env["c"], env["state"]
    c.get("/frag/fleet")
    n = state.renders
    for _ in range(5):
        assert c.get("/frag/fleet").status_code == 200
    assert state.renders == n                     # five viewers, one render
    state.rebuild()
    c.get("/frag/fleet")
    assert state.renders == n + 1


def test_console_keeps_rendering_when_fleetd_is_down(env):
    c, state = env["c"], env["state"]
    env["oarbankd"].__exit__()
    time.sleep(0.3)
    assert state.poll_fleetd(__import__("httpx").Client()) is True           # changed: now unreachable
    r = c.get("/")
    assert r.status_code == 200 and "coordinator unreachable" in r.text
    assert c.get(f"/nodes/{env['node']['node_id']}").status_code == 200        # history still renders from SQLite
    for path in ("/settings", "/modules", f"/campaigns/{env['sid']}", "/audit", "/verify"):
        assert c.get(path).status_code in (200, 503), path                    # degrade, never a 500


def test_the_modules_page_shows_each_installed_bundles_files_and_the_files_a_module_stored(env):
    """Each installed version shows its bundle's file count and size (recorded at install); the card's other count is
    the files the module itself stored (files.write and files.put), which toy and relay have none of."""
    from pathlib import Path
    from oarbank.coordinator import modstore
    db = env["db"]
    for r in modstore.installed(db):
        meta = __import__("json").loads((Path(r["path"]) / "bundle.json").read_text())
        assert r["bundle_files"] == len(meta["files"]) > 0
        assert r["bundle_bytes"] == sum((Path(r["path"]) / f["path"]).stat().st_size for f in meta["files"]) > 0
    page = env["c"].get("/modules").text
    relay = modstore.record(db, "relay", "1.0.0")
    assert f"{relay['bundle_files']} files ({round(relay['bundle_bytes'] / 1e6, 1)} MB)" in page
    assert "files the module stored: 0 (0.0 MB)" in page and "files: 0 (0.0 MB)" not in page


def test_api_passthrough_for_cli_source(env):
    c, db = env["c"], env["db"]
    assert c.get("/api/v1/ops").status_code == 401                            # a session is not a CLI credential
    from oarbank.coordinator import access
    tok = access.new_token(db, "owner", "laptop", "admin", 1)["token"]
    h = {"authorization": f"Bearer {tok}"}
    rows = c.get("/api/v1/ops", headers=h).json()
    assert any(r["id"] == "nodes.pause" for r in rows)
    r = c.post("/api/v1/ops/nodes.pause", json={"target": env["node"]["node_id"]}, headers=h)
    assert r.status_code == 200 and last_audit(db)["source"] == "cli" and last_audit(db)["actor"] == "owner"


def test_waterfall_shows_each_phase(env):
    from helpers import READY, relay_result
    from oarbank.coordinator import core
    db, node = env["db"], env["node"]
    g = core.claim(db, fresh(db, node), {"free_slots": 1, "ready_datasets": READY})["grants"][0]
    core.heartbeat(db, fresh(db, node), {"attempts": [{"attempt_id": g["attempt_id"], "phase": "calling", "cpu_s": 5}],
                                         "ready_datasets": READY})
    core.complete(db, fresh(db, node), g["attempt_id"], relay_result())
    phases = [r["phase"] for r in db.q("SELECT phase FROM attempt_phases WHERE attempt_id=? ORDER BY at", (g["attempt_id"],))]
    assert phases[0] == "granted" and "calling" in phases and phases[-2:] == ["completion_received", "verdict"]
    html = env["c"].get(f"/jobs/{g['job_id']}").text
    for label in ("queued", "staging", "calling", "evaluating"):
        assert f">{label}</span>" in html, label


def test_invariant_conditions_render_and_latch(env):
    from oarbank.coordinator.app import _check_invariants
    db = env["db"]
    _check_invariants(db)
    conds = db.get_setting("invariant_conditions")
    assert [c["id"] for c in conds][:2] == ["S1", "S2"] and {c["status"] for c in conds} == {"True"}
    assert "S15" in [c["id"] for c in conds]
    assert "s15_module_faults_not_charged" in env["c"].get("/verify").text


def test_sse_resyncs_first_then_heartbeats_with_boot_id(env):
    """Over a real server (TestClient cannot disconnect an endless stream)."""
    import httpx
    state = env["state"]
    with Server(console_app(state)) as console:
        events, hb = [], None
        with httpx.stream("GET", f"http://127.0.0.1:{console.port}/sse", timeout=10,
                          cookies={"oarbank_session": env["session"]["sid"]}) as r:
            assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
            for line in r.iter_lines():
                if line.startswith("event:"):
                    events.append(line.split(":", 1)[1].strip())
                if line.startswith("data:") and events and events[-1] == "heartbeat":
                    hb = __import__("json").loads(line[5:])
                    break
    assert events[:2] == ["resync", "heartbeat"]                  # resync before anything else, on every connect
    assert hb["server_boot_id"] == state.boot_id and hb["snapshot_version"] == state.version and hb["coordinator_ok"]


def test_protection_editor_previews_live_and_applies_through_a_plan(env):
    import json as _json
    from oarbank.coordinator import core, protection
    from test_protection_dynamic import PROCS, RULE
    c, db, n = env["c"], env["db"], env["node"]
    core.heartbeat(db, fresh(db, n), {"processes": PROCS})
    r = c.get(f"/nodes/{n['node_id']}/protection")
    assert r.status_code == 200 and "Process picker" in r.text and "data-add-rule" in r.text and "Studio Tool" in r.text
    cfg = _json.dumps({"schema": 1, "rule": [RULE]})
    r = c.get(f"/frag/nodes/{n['node_id']}/protection/preview", params={"pj.config": cfg})
    assert r.status_code == 200 and "studio" in r.text and "100 Studio Tool" in r.text and "added" in r.text
    r = c.get(f"/frag/nodes/{n['node_id']}/protection/preview", params={"pj.config": '{"schema": 1, "rule": [{"id": "x", "match": {}}]}'})
    assert "match needs at least one key" in r.text
    assert protection.current(db, n["node_id"])[0] == 0                        # previews never write
    r = form(c, "protection.rules.update", target=n["node_id"], **{"pj.config": cfg})
    assert r.status_code == 200 and "Review" in r.text and "live matches" in r.text   # T2: the plan page
    plan_id = r.text.split('name="plan_id" value="')[1].split('"')[0]
    r = c.post("/apply/protection.rules.update", data={"plan_id": plan_id, "reason": "protect the studio tool",
                                                        "return_to": "/", "idem": "k1"}, follow_redirects=False)
    assert r.status_code == 303 and protection.current(db, n["node_id"]) == (1, {"schema": 1, "rule": [RULE]})
    r = form(c, "nodes.set_mode", target=n["node_id"], **{"p.mode": "strict_yield", "reason": "away"})
    assert r.status_code == 303 and protection.current(db, n["node_id"])[1]["node"]["mode"] == "strict_yield"
    r = c.get(f"/nodes/{n['node_id']}/protection")
    assert "Restore…" in r.text and "mode.set" in r.text


def test_a_session_in_use_stays_signed_in(env):
    """The idle timeout counts from the last use, not from sign-in: oarbankd touches a session the console sees used."""
    import time
    from oarbank.coordinator import access
    db, sid = env["db"], env["session"]["sid"]
    db.x("UPDATE sessions SET last_seen=?", (time.time() - access.SESSION_IDLE_S + 60,))     # a minute from timing out
    assert env["c"].get("/").status_code == 200
    for _ in range(100):
        if access.session_for(db, sid)["last_seen"] > time.time() - 60:
            break
        time.sleep(0.05)
    assert access.session_for(db, sid)["last_seen"] > time.time() - 60


ARTEFACTS = ("{}", "{'", "/ GB", "–%", "CPU –", "0 / 0", "None", "auto None", "GB GB", "· ·", "mem free", "swap  GB")


def node_html(env):
    """The fleet card (from a fresh snapshot) and the node page of the fixture node."""
    import re
    env["state"].rebuild()
    nid = env["node"]["node_id"]
    fleet = env["c"].get("/frag/fleet").text
    card = fleet[fleet.index(f'href="/nodes/{nid}"'):]
    card = card[:card.index("Details & caps")]
    page = env["c"].get(f"/nodes/{nid}").text
    page = page[page.index("<b>Hardware</b>"):page.index("<h2>Policy</h2>")]
    strip = lambda h: re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", h))
    return strip(card), strip(page)


def assert_clean(*texts):
    for t in texts:
        for a in ARTEFACTS:
            assert a not in t, (a, t)


def test_a_node_without_telemetry_shows_only_what_it_reported(env):
    """The fixture node has reported facts and pools, but no telemetry and no capacity model."""
    card, page = node_html(env)
    assert_clean(card, page)
    assert "capacity not reported yet" in card and "pools scorer 4" in card and "mem 24.0 GB" in card
    assert "CPU" not in card and "pressure" not in card and "thermal" not in card
    assert "Apple M5 Pro (5P + 10E)" in page and "24.0 GB" in page and "macOS 27.0" in page
    assert "15 cores · caps concurrent jobs" in page and "disk free" not in page and "user / power" not in page


def test_a_guarded_node_says_why_it_takes_no_jobs(env):
    """A Windows node without a CPU model or core classes, held back by the memory guard, with no pools."""
    import json as _json
    from helpers import facts_for
    db, n = env["db"], env["node"]
    facts = {**facts_for("windows-arm64", os_version="10.0"), "cpu": {"model": None, "perf_cores": None, "eff_cores": None,
             "logical": 4}, "memory_gb": 7.6, "gpus": []}
    tel = {"mem_used_gb": 6.9, "mem_free_pct": 9.2, "mem_pressure": 1, "swap_used_gb": None, "thermal": 0, "on_battery": False,
           "user_idle_s": 0.0, "presence": "unknown: no idle time for session 1 (ada)", "fleet_rss_gb": 0.0,
           "disk_free_gb": None, "guard": "soft", "services_running": [],
           "services_reserved_gb": 0.0, "protection": {"guard_reason": "free memory 9.2% under 10%"}}
    cap = {"cpu_slots": 0, "auto_cpu_slots": 0, "mem_gb_free": 0.0, "pools": {}, "slots": 0, "auto_slots": 0,
           "binding_limit": "guard:memory", "admit": False, "why": "guard:memory"}
    db.x("UPDATE nodes SET facts_json=?, telemetry_json=?, capacity_json=?, platform='windows-arm64', os='windows', arch='arm64', "
         "os_version='10.0' WHERE node_id=?", (_json.dumps(facts), _json.dumps(tel), _json.dumps(cap), n["node_id"]))
    card, page = node_html(env)
    assert_clean(card, page)
    assert "Windows arm64" in card and "no new jobs: memory guard" in card and "memory guard: soft" in card and "pools" not in card
    assert "mem 6.9 / 7.6 GB" in card and "pressure warning" in card and "thermal nominal" in card
    assert "4 cores" in page and "Windows 10.0 · arm64" in page and "no new jobs: memory guard" in page
    assert "6.9 GB used · 9% free · fleet jobs 0.0 GB" in page and "swap" not in page and "on AC power" in page
    assert "services running none" in page and "binding" not in page.split("Controls")[0]


def test_slots_show_the_automatic_count_and_what_binds(env):
    import json as _json
    db, n = env["db"], env["node"]
    cap = {"cpu_slots": 4, "auto_cpu_slots": 7, "mem_gb_free": 12.5, "pools": {"scorer": 2, "gpu": 1},
           "binding_limit": "cap.cpu_cores", "admit": True}
    db.x("UPDATE nodes SET capacity_json=?, limits_json=? WHERE node_id=?",
         (_json.dumps(cap), _json.dumps({"cpu_cores": 4}), n["node_id"]))
    card, page = node_html(env)
    assert_clean(card, page)
    assert "jobs 0 / 4 CPU slots (auto 7)" in card and "12.5 GB free for jobs" in card and "pools gpu 1, scorer 2" in card
    assert "cap on cpu cores" in page and "7 automatic CPU slots now" in page
    cap.update(cpu_slots=0, auto_cpu_slots=0, binding_limit="auto")
    db.x("UPDATE nodes SET capacity_json=?, telemetry_json=?, limits_json=NULL WHERE node_id=?",
         (_json.dumps(cap), _json.dumps({"thermal": 2}), n["node_id"]))
    card, page = node_html(env)
    assert_clean(card, page)
    assert "jobs 0 · no CPU slots: heat" in card and "no CPU slots: heat" in page


def test_a_pending_enrollment_shows_only_reported_facts(env):
    import json as _json
    from helpers import facts_for
    facts = {**facts_for("linux-amd64", os_version="24.04"), "cpu": {"model": None, "logical": 8}, "memory_gb": None}
    env["db"].x("INSERT INTO enrollments(enrollment_id, hostname, facts_json, peer_ip, status, created_at) VALUES(?,?,?,?,?,?)",
                ("enr_test", "build-box", _json.dumps(facts), "192.0.2.7", "pending", time.time()))
    env["state"].rebuild()
    html = env["c"].get("/frag/fleet").text
    line = html[html.index("build-box"):]
    line = line[line.index('<div class="small mut">'):]
    line = line[:line.index("</div>")]
    assert "Linux 24.04 · amd64 · requested" in line and "None" not in line and "GB" not in line


def test_the_console_waits_for_oarbankd_to_create_the_database(tmp_path):
    # a fresh install starts both services at once: the console must not read (or create) a database oarbankd has
    # not made yet ("no such table" killed it, and the service manager restarted it)
    path = tmp_path / "home with space" / "oarbank.sqlite3"
    path.parent.mkdir()
    said, done = [], threading.Event()
    t = threading.Thread(target=lambda: (wait_for_schema(path, poll_s=0.02, log=lambda m, **k: said.append(m)), done.set()))
    t.start()
    time.sleep(0.3)
    assert not done.is_set() and not path.exists(), "it waited without creating the file"
    assert said and "waiting for oarbankd" in said[0]
    make_db(path)
    t.join(5)
    assert done.is_set()
    ConsoleState(path, "http://127.0.0.1:1")          # the snapshot builds on the new schema


def test_campaign_results_follow_the_manifests_result_columns():
    # manifest contract: results.fields[].ui.column is the header ("absent = not shown"), ui.format the format and
    # ui.unit what follows the value; the table once showed every field under its raw name with its own formats
    from oarbank_sdk import manifest as mf
    from oarbank.console import views
    fields = [mf.ResultField(name="mhash_s", type="number", unit="Mhash/s", ui={"column": "Mhash/s", "format": ".2f"}),
              mf.ResultField(name="seconds", type="number", ui={"column": "Time", "format": ".1f", "unit": "s"}),
              mf.ResultField(name="iters", type="integer", ui={"column": "Iterations", "format": ",d"}),
              mf.ResultField(name="digest", type="string")]
    rows = [{"fields": {"mhash_s": 1.0595, "seconds": 2.8312, "iters": 3000000, "digest": "ab" * 32}}, {"fields": {}}]
    cols = views.result_columns(rows, fields)
    assert [c["header"] for c in cols] == ["Mhash/s", "Time", "Iterations"]
    assert rows[0]["cells"] == ["1.06", "2.8 s", "3,000,000"] and rows[1]["cells"] == ["", "", ""]
    rows = [{"fields": {"n": 7, "sum": 28, "digest": "ab" * 32}}]                # no manifest: short fields, raw names
    assert [c["header"] for c in views.result_columns(rows, None)] == ["n", "sum"] and rows[0]["cells"] == ["7", "28"]


CAMPAIGN_OFFERS = {
    "running": {"campaigns.pause", "campaigns.retry_failed", "campaigns.set_weight", "campaigns.set_priority", "campaigns.cancel",
                "campaigns.set_placement", "campaigns.rebind_platform"},
    "paused": {"campaigns.resume", "campaigns.retry_failed", "campaigns.set_weight", "campaigns.set_priority", "campaigns.cancel",
               "campaigns.set_placement", "campaigns.rebind_platform"},
    "done": {"campaigns.retry_failed", "campaigns.set_weight", "campaigns.set_priority", "campaigns.cancel"},
    "cancelled": set(),
}
REPEATS = {("campaigns.pause", "paused"), ("campaigns.resume", "running"), ("campaigns.cancel", "cancelled")}


@pytest.mark.parametrize("state", list(CAMPAIGN_OFFERS))
def test_a_campaign_offers_exactly_the_operations_its_state_takes(env, state):
    # a finished campaign offered Resume (primary-styled) though it reopens by itself; the console never offers an
    # operation oarbankd refuses, and oarbankd refuses every other one (a declarative repeat is a no-op, not offered).
    # Rebind is offered once the campaign keeps work on one platform class (Set placement, earlier in the loop, does that)
    from helpers import run_op
    from oarbank.contracts import operations as registry
    from oarbank.coordinator import core
    db, c, sid = env["db"], env["c"], env["sid"]
    job = db.one("SELECT job_id FROM jobs WHERE campaign_id=? LIMIT 1", (sid,))["job_id"]
    for op in (o for o in registry.REGISTRY if o.startswith("campaigns.")):
        db.x("UPDATE campaigns SET state=? WHERE campaign_id=?", (state, sid))
        db.x("UPDATE jobs SET state='failed' WHERE job_id=?", (job,))           # so Retry failed shows where it applies
        html = c.get(f"/campaigns/{sid}").text
        offered = f'action="/do/{op}"' in html
        assert offered == (op in CAMPAIGN_OFFERS[state]), (state, op)
        try:
            run_op(db, op, sid, params={"campaigns.set_weight": {"weight": 2}, "campaigns.set_priority": {"priority": 3},
                                        "campaigns.set_placement": {"mix": "same-os"},
                                        "campaigns.rebind_platform": {"platform": "darwin-arm64"}}.get(op))
            accepted = True
        except core.ApiError as e:
            assert (e.status, e.code) in ((409, f"campaign_{state}"), (409, "no_placement")), (state, op, e)
            accepted = False
        assert accepted == (offered or (op, state) in REPEATS), (state, op)
    if state in ("done", "cancelled"):
        db.x("UPDATE campaigns SET state=? WHERE campaign_id=?", (state, sid))
        assert ">Resume<" not in c.get(f"/campaigns/{sid}").text


def test_a_campaign_of_a_module_without_a_campaign_panel_shows_no_panel_placeholder(env):
    # the page printed "<module> declares no campaign panel."; the generic Results table covers such a module
    db, c, sid = env["db"], env["c"], env["sid"]
    assert ">Trials <" in c.get(f"/campaigns/{sid}").text                   # relay declares one
    db.x("UPDATE campaigns SET module='toy' WHERE campaign_id=?", (sid,))     # toy declares none
    html = c.get(f"/campaigns/{sid}").text
    assert "campaign panel" not in html and ">Trials <" not in html and "<h2>History</h2>" in html


def test_the_console_names_the_product_oarbank_with_a_capital(env):
    # the header wordmark and every page title said lowercase "oarbank"; lowercase stays only where it is an identifier
    # (the oarbank command, oarbankd, package and path names)
    import re
    c, n, sid = env["c"], env["node"], env["sid"]
    for path in ("/", f"/nodes/{n['node_id']}", "/campaigns", f"/campaigns/{sid}", "/jobs", "/events", "/audit", "/settings",
                 "/verify", "/modules", "/modules/relay", "/agent", "/coordinator", "/access", "/account", "/campaigns/nope"):
        html = c.get(path).text
        title = re.search(r"<title>(.*?)</title>", html, re.S).group(1)
        assert title.endswith("Oarbank") and "<b>Oarbank</b>" in html, (path, title)
    c.cookies.clear()
    html = c.get("/login").text
    assert "<title>Sign in · Oarbank</title>" in html and "<h1>Oarbank</h1>" in html


def test_campaigns_show_their_placement_and_offer_rebind(env):
    """D33: the campaign list's placement column, the campaign page's chip, a stranded unit's alert and the Rebind form."""
    from helpers import create_study
    db, c = env["db"], env["c"]
    sid = create_study(db, "pinned", [], ["scene:s2"], {"label": "base", "params": PARAMS},
                       placement={"mix": "same-platform", "pin": "darwin-arm64"})
    assert "darwin-arm64 · pinned" in c.get("/campaigns").text
    db.x("INSERT INTO alerts(rule,subject,state,detail,opened_at) VALUES(?,?,'open',?,0)",
         (f"placement_stranded:c:{sid}", f"campaign:{sid}", "no node of darwin-arm64 for 31 min"))
    db.x("UPDATE placement_bindings SET stranded_since=1 WHERE campaign_id=?", (sid,))
    page = c.get(f"/campaigns/{sid}").text
    assert "darwin-arm64 · pinned" in page and "no node of darwin-arm64 for 31 min" in page
    assert 'action="/do/campaigns.rebind_platform"' in page and 'name="p.platform"' in page
    assert 'action="/do/campaigns.set_placement"' not in page                 # pinned: move it with Rebind instead
    assert "stranded" in c.get("/campaigns").text


def _form_fields(html: str, op: str) -> dict:
    """The fields of the first form in `html` that posts to /do/<op>: hidden inputs and the inputs' and selects' values."""
    import html as H
    import re
    body = re.search(rf'<form[^>]*action="/do/{re.escape(op)}"[^>]*>(.*?)</form>', html, re.S)
    assert body, f"no {op} form"
    fields = {}
    for tag in re.findall(r"<input[^>]*>", body.group(1)):
        name, value = re.search(r'name="([^"]*)"', tag), re.search(r'value="([^"]*)"', tag)
        if name:
            fields[name.group(1)] = H.unescape(value.group(1)) if value else ""
    for name, opts in re.findall(r'<select name="([^"]*)"[^>]*>(.*?)</select>', body.group(1), re.S):
        fields[name] = re.findall(r"<option[^>]*>([^<]*)</option>", opts)[0]
    return fields


@pytest.mark.parametrize("frag, op", [("/frag/fleet", "nodes.pause"), ("/frag/campaign/{sid}", "campaigns.set_weight")])
def test_a_form_from_a_live_refreshed_fragment_posts(env, frag, op):
    """The fleet and campaign bodies refresh themselves (htmx); their forms once carried an empty csrf field, so every
    form failed with {"error": "csrf"} after the first refresh. The form posts as the page renders it (no header token)."""
    c = env["c"]
    html = c.get(frag.format(sid=env["sid"])).text
    fields = _form_fields(html, op)
    assert fields["csrf"] == env["session"]["csrf"]
    post = lambda data: c.post(f"/do/{op}", data=data, headers={"x-csrf-token": ""}, follow_redirects=False)
    assert post({k: v for k, v in fields.items() if k != "csrf"}).json()["error"] == "csrf"
    r = post(fields)
    assert r.status_code in (200, 303) and "csrf" not in r.text, r.text


def test_fragments_are_never_shared_between_sessions(env):
    from helpers import sign_in
    c = env["c"]
    first = _form_fields(c.get("/frag/fleet").text, "nodes.pause")["csrf"]
    other = sign_in(c, env["db"], "second")
    assert _form_fields(c.get("/frag/fleet").text, "nodes.pause")["csrf"] == other["csrf"] != first
