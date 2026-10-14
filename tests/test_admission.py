"""What a node starts as when it is approved (coordinator/admission.py; docs/design/node-enrollment.md, "Admission").

An approval may carry the node's state, module switches, settings, labels and groups, written in the same transaction as
the node and its certificate; a new node without them follows the fleet's onboarding policy; and a machine that looks
like a known node may be declared the same machine, which carries the old node's settings over and retires it."""
import json

import pytest

from helpers import (CAPACITY, DOCTOR_OK, FACTS, READY, fresh, make_db, node_key_and_csr, run_op, set_fleet, set_node)
from oarbank.contracts import impact as impact_text
from oarbank.coordinator import admission, clock, core, joincodes, ops, releases
from oarbank.coordinator.settings.apply import node_values

from test_console import env, form  # noqa: F401  (the console fixture: oarbankd + console + a session)
from test_reenroll import NEW_IP, OLD_IP, csr_for, join

OTHER_IP, FOURTH_IP = "100.64.0.21", "100.64.0.22"


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "home" / "oarbank.sqlite3")


@pytest.fixture
def tailnet(monkeypatch):
    devices = {OLD_IP: "ts-old", NEW_IP: "ts-new", OTHER_IP: "ts-other", FOURTH_IP: "ts-fourth"}
    monkeypatch.setattr(core, "tailscale_whois", lambda ip: {"ts_node_id": devices[ip], "ts_name": None, "login": None,
                                                             "tags": []} if ip in devices else None)
    return devices


def enroll(db, name="build-07", ip="127.0.0.1", key=None):
    return core.enroll(db, name, {**FACTS, "hostname": name}, ip, csr_for(key or node_key_and_csr()[0], name))["enrollment_id"]


def plan(db, eid, params, op="nodes.admit") -> dict:
    return ops.execute(db, ops.OpRequest(op=op, actor="test", source="system", target=eid, params=params, reason="test",
                                         dry_run=True))["plan"]


def node(db, nid):
    return db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))


def off_there(db, nid) -> list:
    return node_values(node(db, nid))["modules_disabled"]


def goldens(db, nid) -> set:
    return {x["module"] for x in db.q("SELECT module FROM jobs WHERE kind='golden' AND target_node=?", (nid,))}


def agent_session(db, nid) -> list:
    """The node's first session, as its agent runs it once it has its certificate: hello, a heartbeat with a healthy
    doctor report, a claim. Returns the grants."""
    n = fresh(db, node(db, nid))
    core.hello(db, n, {"release_id": releases.assigned(db, n), "facts": FACTS, "live_attempts": [], "ready_datasets": READY})
    core.heartbeat(db, fresh(db, n), {"doctor": DOCTOR_OK, "attempts": [], "ready_datasets": READY, "capacity": CAPACITY})
    return core.claim(db, fresh(db, n), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": READY})["grants"]


# ------------------------------------------------------------------ admission options

def test_a_node_approved_paused_with_a_module_off_never_gets_a_job_or_a_golden(db):
    eid = enroll(db)
    imp = plan(db, eid, {"state": "paused", "modules": {"toy": False}, "settings": [{"key": "max_slots", "value": 2}],
                         "labels": ["no-work"]})["impact"]
    assert imp["starts"].startswith("paused") and "no jobs (certification goldens included)" in imp["starts"]
    assert imp["modules_off_there"] == ["toy"] and imp["labels"] == ["no-work"]
    assert any("CPU slots" in x for x in imp["settings_set"])
    assert any(line.strip().startswith("starts: paused") for line in impact_text.lines(imp))
    assert db.one("SELECT COUNT(*) n FROM nodes")["n"] == 0                       # the preview made nothing
    res = run_op(db, "nodes.admit", eid, {"state": "paused", "modules": {"toy": False},
                                          "settings": [{"key": "max_slots", "value": 2}], "labels": ["no-work"]})["result"]
    nid = res["node_id"]
    n = node(db, nid)
    assert n["desired_state"] == "paused" and "toy" in off_there(db, nid)
    assert node_values(n)["limits"].get("max_slots") == 2 or node_values(n)["policy"].get("max_slots") == 2
    assert db.one("SELECT label FROM node_labels WHERE node_id=?", (nid,))["label"] == "no-work"
    assert res["admission"]["state"] == "paused"
    # the agent's first session: nothing is granted, and no golden is made for any module
    assert agent_session(db, nid) == []
    assert node(db, nid)["lifecycle"] == "ready" and goldens(db, nid) == set()
    # resumed: the modules it runs are certified; the one turned off at its approval never gets a golden
    run_op(db, "nodes.resume", nid)
    grants = agent_session(db, nid)
    assert grants and {g["module"] for g in grants} == {"relay"}
    assert goldens(db, nid) == {"relay"} and "toy" not in core.node_modules(node(db, nid))


def test_the_options_are_written_before_the_node_can_authenticate_and_a_refused_one_admits_nothing(db, monkeypatch):
    eid = enroll(db)
    seen = {}
    real = admission.apply

    def spy(db_, nid, adm, ident, actor, eid_):
        seen["enrollment"] = db_.one("SELECT status, cert_json FROM enrollments WHERE enrollment_id=?", (eid_,))
        seen["cert"] = db_.one("SELECT client_cert_fp FROM nodes WHERE node_id=?", (nid,))["client_cert_fp"]
        return real(db_, nid, adm, ident, actor, eid_)
    monkeypatch.setattr(admission, "apply", spy)
    nid = run_op(db, "nodes.admit", eid, {"state": "paused"})["result"]["node_id"]
    # when the options were written the enrollment was still pending, with no certificate to fetch: the agent cannot
    # have a session (let alone claim) before them, and it all committed as one transaction
    assert seen["enrollment"] == {"status": "pending", "cert_json": None} and seen["cert"] is None
    assert node(db, nid)["desired_state"] == "paused" and node(db, nid)["client_cert_fp"]
    approved = db.one("SELECT event_id FROM events WHERE kind='enroll_approved' AND node_id=?", (nid,))["event_id"]
    paused = db.one("SELECT event_id FROM events WHERE kind='node_state' AND node_id=?", (nid,))["event_id"]
    assert paused < approved

    # a refused option (in the preview, and when applied directly) leaves no node, no certificate and the request pending
    eid = enroll(db, "build-08")
    bad = {"state": "paused", "labels": ["ok"], "settings": [{"key": "max_slots", "value": -3}]}
    with pytest.raises(ops.OpError) as err:
        plan(db, eid, bad)
    assert err.value.status == 400 and err.value.extra["errors"]
    for params in (bad, {"state": "paused", "groups": ["no-such-group"]}, {"modules": {"no-such-module": False}}):
        with pytest.raises(core.ApiError):
            core.approve_enrollment(db, eid, "test", admission=admission.parse(params))
    assert db.one("SELECT status FROM enrollments WHERE enrollment_id=?", (eid,))["status"] == "pending"
    assert db.one("SELECT COUNT(*) n FROM nodes")["n"] == 1
    assert not db.one("SELECT 1 FROM node_labels WHERE label='ok'")
    with pytest.raises(ops.OpError) as err:
        plan(db, eid, {"state": "asleep"})
    assert err.value.code == "bad_state"


def test_approve_code_takes_the_same_options_and_groups_list_the_node(db):
    run_op(db, "groups.create", "quiet", {"name": "quiet"})
    e = core.enroll(db, "box", {**FACTS, "hostname": "box"}, "127.0.0.1", node_key_and_csr()[1], user_code="WDJBMJHT")
    params = {"user_code": "wdjb-mjht", "state": "draining", "groups": ["quiet"], "modules": {"relay": False}}
    assert plan(db, None, params, op="nodes.admit_code")["impact"]["groups"] == ["quiet"]
    nid = run_op(db, "nodes.admit_code", None, params)["result"]["node_id"]
    assert db.one("SELECT node_id FROM enrollments WHERE enrollment_id=?", (e["enrollment_id"],))["node_id"] == nid
    assert node(db, nid)["desired_state"] == "draining" and off_there(db, nid) == ["relay"]
    g = db.one("SELECT members_json FROM node_groups WHERE name='quiet'")
    assert json.loads(g["members_json"]) == [nid]


# ------------------------------------------------------------------ the fleet's onboarding policy

def test_the_fleet_policy_starts_new_nodes_paused_with_no_module_and_an_approval_may_choose_otherwise(db, tailnet):
    set_fleet(db, "new_node_state", "paused")
    set_fleet(db, "new_node_modules", "none")
    eid = enroll(db, "a")
    imp = plan(db, eid, {})["impact"]
    assert imp["starts"].startswith("paused") and "new_node_modules is none" in imp["policy"]
    nid = run_op(db, "nodes.admit", eid)["result"]["node_id"]
    assert node(db, nid)["desired_state"] == "paused" and off_there(db, nid) == ["relay", "toy"]
    assert agent_session(db, nid) == [] and goldens(db, nid) == set()
    # an approval's own choices win
    nid = run_op(db, "nodes.admit", enroll(db, "b"), {"state": "active", "modules": {"relay": True}})["result"]["node_id"]
    assert node(db, nid)["desired_state"] == "active" and off_there(db, nid) == ["toy"]
    # a multi-use code that approves automatically follows the policy too
    code = joincodes.create(db, urls=["https://127.0.0.1:7443"], pins=["ab" * 32], cik="AA" * 21 + "A=", actor="owner",
                            uses=5, approve=True)
    e = core.enroll(db, "c", {**FACTS, "hostname": "c"}, "127.0.0.1", node_key_and_csr()[1],
                    join=joincodes.decode(code["code"])["token"])
    nid = db.one("SELECT node_id FROM enrollments WHERE enrollment_id=?", (e["enrollment_id"],))["node_id"]
    assert node(db, nid)["desired_state"] == "paused" and off_there(db, nid) == ["relay", "toy"]
    # a re-enrolled node keeps its own state and switches: the policy is for new nodes
    key, _ = node_key_and_csr()
    set_fleet(db, "new_node_state", "active")
    set_fleet(db, "new_node_modules", "all")
    _, kept, _ = join(db, key, OLD_IP, name="kept")
    set_fleet(db, "new_node_state", "paused")
    set_fleet(db, "new_node_modules", "none")
    nid = run_op(db, "nodes.admit", enroll(db, "kept", NEW_IP, key))["result"]["node_id"]
    assert nid == kept and node(db, kept)["desired_state"] == "active" and "relay" not in off_there(db, kept)


# ------------------------------------------------------------------ the same machine

def test_the_same_machine_carries_its_settings_over_and_retires_the_old_record_in_one_audited_step(db, tailnet):
    run_op(db, "groups.create", "lab", {"name": "lab"})
    _, old, _ = join(db, node_key_and_csr()[0], OLD_IP)
    core.set_node_state(db, old, "paused", "owner")
    set_node(db, old, "enabled", False, module="toy")
    set_node(db, old, "max_slots", 3)
    run_op(db, "nodes.label", old, {"add": ["keep-out"]})
    run_op(db, "groups.update", "lab", {"name": "lab", "members": [old]})
    run_op(db, "updates.hold", old, {"reason": "certification lab machine"})
    run_op(db, "protection.rules.update", old, {"config": {"schema": 1, "node": {"mode": "strict_yield"}, "rule": []}})
    db.x("INSERT INTO module_pins(name,node_id,version) VALUES('relay',?,'1.0.0')", (old,))
    own = db.q("SELECT module, key, value_json FROM setting_values WHERE scope='node' AND scope_id=? ORDER BY module, key", (old,))
    assert {x["key"] for x in own} >= {"enabled", "max_slots", "update_hold", "protection.mode"}

    # reinstalled: a new key, a new Tailscale device, the same host name; nothing proves it is the old node
    eid = enroll(db, "host-a", NEW_IP)
    p = plan(db, eid, {"adopt_settings_from": old})
    assert p["tier"] == "T3" and p["confirm_required"] and p["confirm_name"] == "host-a"
    imp = p["impact"]
    assert "old_record" not in imp and "you confirm this machine is" in imp["warning"]
    assert any(f"retired host-a ({old})" in x for x in imp["same_machine"])
    assert imp["starts"].startswith("paused") and imp["modules_off_there"] == ["toy"]
    assert node(db, old)["lifecycle"] != "retired"                                 # the preview changed nothing
    res = run_op(db, "nodes.admit", eid, {"adopt_settings_from": old})
    new = res["result"]["node_id"]
    assert new != old
    assert [(x["module"], x["key"], x["value_json"]) for x in db.q(
        "SELECT module, key, value_json FROM setting_values WHERE scope='node' AND scope_id=? ORDER BY module, key", (new,))] \
        == [(x["module"], x["key"], x["value_json"]) for x in own]
    n = node(db, new)
    assert n["desired_state"] == "paused" and "toy" in off_there(db, new)
    from oarbank.coordinator.settings import resolve as V
    assert V.resolve(V.snapshot(db), n, "protection.mode")["value"] == "strict_yield"
    assert db.one("SELECT label FROM node_labels WHERE node_id=?", (new,))["label"] == "keep-out"
    assert json.loads(db.one("SELECT members_json FROM node_groups WHERE name='lab'")["members_json"]) == [new]
    assert db.one("SELECT version FROM module_pins WHERE node_id=? AND name='relay'", (new,))["version"] == "1.0.0"
    o = node(db, old)
    assert o["lifecycle"] == "retired" and o["client_cert_fp"] is None and o["client_key_sha256"] is None
    ev = db.one("SELECT reason, payload_json FROM events WHERE kind='node_adopted' AND node_id=?", (new,))
    assert old in ev["reason"] and json.loads(ev["payload_json"])["old_node_id"] == old
    assert "same machine" in db.one("SELECT reason FROM events WHERE kind='enroll_approved' AND node_id=?", (new,))["reason"]
    a = db.one("SELECT outcome, reason FROM audit WHERE operation='nodes.admit' AND dry_run=0 ORDER BY event_id DESC")
    assert a["outcome"] == "ok"
    # the new node never had the fleet's defaults: its first session is paused, so it gets nothing
    assert agent_session(db, new) == [] and goldens(db, new) == set()


def test_the_same_machine_is_never_automatic_and_is_refused_where_it_cannot_be_the_same(db, tailnet):
    key, _ = node_key_and_csr()
    _, old, _ = join(db, key, OLD_IP)
    _, other, _ = join(db, node_key_and_csr()[0], OTHER_IP, name="other")
    # a plain approval of a lookalike carries nothing over and retires nothing
    plain = run_op(db, "nodes.admit", enroll(db, "host-a", NEW_IP))["result"]["node_id"]
    assert node(db, old)["lifecycle"] != "retired" and not db.one("SELECT 1 FROM events WHERE kind='node_adopted'")
    run_op(db, "nodes.retire", plain)
    eid = enroll(db, "host-a", FOURTH_IP)
    # a node it does not look like (another host name)
    with pytest.raises(ops.OpError) as err:
        plan(db, eid, {"adopt_settings_from": other})
    assert err.value.code == "adopt_refused" and "not a node this machine looks like" in err.value.detail
    # the old node is still online: a machine that runs it cannot be the one asking
    db.x("UPDATE nodes SET last_heartbeat_at=? WHERE node_id=?", (clock.now(), old))
    with pytest.raises(ops.OpError) as err:
        plan(db, eid, {"adopt_settings_from": old})
    assert err.value.code == "adopt_refused" and "still online" in err.value.detail
    db.x("UPDATE nodes SET last_heartbeat_at=NULL WHERE node_id=?", (old,))
    # a request that proves the old node's key (the copied-key case looks the same): it keeps the node, never adopts
    proven = enroll(db, "host-a", OTHER_IP, key)
    with pytest.raises(ops.OpError) as err:
        plan(db, proven, {"adopt_settings_from": old})
    assert err.value.code == "adopt_refused" and "proves the key" in err.value.detail
    # without the typed name (T3) nothing happens
    p = plan(db, eid, {"adopt_settings_from": old})
    with pytest.raises(ops.OpError) as err:
        ops.execute(db, ops.OpRequest(op="nodes.admit", actor="test", source="system", plan_id=p["plan_id"], reason="x"))
    assert err.value.code == "confirmation_required"
    assert node(db, old)["lifecycle"] != "retired"
    assert db.one("SELECT status FROM enrollments WHERE enrollment_id=?", (eid,))["status"] == "pending"


def test_a_retired_node_is_never_carried_over(db, tailnet):
    _, old, _ = join(db, node_key_and_csr()[0], OLD_IP)
    set_node(db, old, "max_slots", 3)
    run_op(db, "nodes.retire", old)
    # the machine enrolls again, from the retired node's own Tailscale device (which the record still names) and from
    # another: the retired record is no lookalike, and naming it (by id or name) is refused, not quietly ignored
    for ip in (OLD_IP, NEW_IP):
        eid = enroll(db, "host-a", ip)
        assert "old_record" not in plan(db, eid, {})["impact"]
        for who in (old, "host-a"):
            with pytest.raises(ops.OpError) as err:
                plan(db, eid, {"adopt_settings_from": who})
            assert err.value.code == "adopt_refused" and f"host-a ({old}) is retired" in err.value.detail
            with pytest.raises(admission.AdmissionError) as err:                 # the approval itself, unpreviewed
                core.approve_enrollment(db, eid, "test", admission=admission.parse({"adopt_settings_from": who}))
            assert err.value.code == "adopt_refused"
        assert node(db, old)["lifecycle"] == "retired"
        assert db.one("SELECT status FROM enrollments WHERE enrollment_id=?", (eid,))["status"] == "pending"
        assert db.one("SELECT COUNT(*) n FROM nodes")["n"] == 1
        core.reject_enrollment(db, eid, "test")
    with pytest.raises(ops.OpError) as err:
        plan(db, enroll(db, "host-a", NEW_IP), {"adopt_settings_from": "no-such-node"})
    assert err.value.code == "unknown_node"
    # a request from a live node's own Tailscale device (a new key) keeps that node: nothing to carry over, and the
    # refusal says how it matched (it proves no key)
    _, live, _ = join(db, node_key_and_csr()[0], OTHER_IP, name="other")
    eid = enroll(db, "other", OTHER_IP)
    with pytest.raises(ops.OpError) as err:
        plan(db, eid, {"adopt_settings_from": live})
    assert err.value.code == "adopt_refused"
    assert f"comes from the Tailscale device of other ({live})" in err.value.detail
    # named by its host name, the old node is found, not the approval's own new node of that name
    imp = plan(db, enroll(db, "other", FOURTH_IP), {"adopt_settings_from": "other"})["impact"]
    assert any(f"retired other ({live})" in x for x in imp["same_machine"])


# ------------------------------------------------------------------ the console

def test_the_approve_dialog_offers_the_options_and_the_same_machine_and_reviews_them(env, monkeypatch):
    c, db, state = env["c"], env["db"], env["state"]
    devices = {OLD_IP: "ts-old", NEW_IP: "ts-new"}
    monkeypatch.setattr(core, "tailscale_whois", lambda ip: {"ts_node_id": devices[ip]} if ip in devices else None)
    _, old, _ = join(db, node_key_and_csr()[0], OLD_IP)
    eid = enroll(db, "host-a", NEW_IP)
    plain = enroll(db, "fresh-box")
    state.rebuild()
    fleet = c.get("/frag/fleet").text
    assert fleet.count("Approve with options…") == 2 and f'id="admit-{eid}"' in fleet
    assert 'name="state"' in fleet and "paused: no jobs, no certification goldens" in fleet
    assert 'name="mod.relay"' in fleet and 'name="mod.toy"' in fleet and 'name="settings"' in fleet
    assert "This is the same machine: carry over its settings and retire the old record" in fleet
    assert f'name="adopt" value="{old}"' in fleet
    # the dialog's fields become the approval's options, and Review shows what the node starts as
    r = form(c, "nodes.admit", target=plain, state="paused", **{"mod.toy": "off", "dflt.toy": "on", "mod.relay": "on",
                                                                  "dflt.relay": "on"}, settings="max_slots=2", labels="lab, quiet")
    assert r.status_code == 200 and "Apply nodes.admit" in r.text
    assert "starts" in r.text and "paused" in r.text and "modules off there" in r.text and "CPU slots" in r.text
    r = form(c, "nodes.admit", target=eid, adopt=old)
    assert r.status_code == 200 and "same machine" in r.text and "Type" in r.text and "host-a" in r.text
    # a malformed line is refused before anything is sent
    r = form(c, "nodes.admit", target=plain, settings="no equals sign")
    from urllib.parse import unquote
    assert r.status_code == 303 and "one setting per line: key=value" in unquote(r.headers["location"])


def test_the_dialog_form_reads_only_what_changed():
    from oarbank.console.forms import admission as read
    f = {"state": "", "mod.toy": "off", "dflt.toy": "on", "mod.relay": "on", "dflt.relay": "on",
         "settings": "max_slots=4\nrelay:services.disabled=[\"scorer\"]\n# a comment\nupdate_ring=canary", "labels": "a, b",
         "adopt": ""}
    assert read(f) == {"modules": {"toy": False}, "labels": ["a", "b"],
                       "settings": [{"key": "max_slots", "value": 4},
                                    {"key": "services.disabled", "value": ["scorer"], "module": "relay"},
                                    {"key": "update_ring", "value": "canary"}]}


def test_the_command_line_reads_the_approval_options():
    from oarbank.cli.main import admission_params, parser
    a = parser().parse_args(["node", "approve", "enr_1", "--state", "paused", "--module-off", "toy", "--module-on", "relay",
                             "--set", "max_slots=4", "--set", "relay:services.disabled=scorer", "--labels", "a,b",
                             "--groups", "lab", "--adopt-settings-from", "n_1"])
    assert admission_params(a) == {"state": "paused", "modules": {"toy": False, "relay": True}, "labels": ["a", "b"],
                                   "groups": ["lab"], "adopt_settings_from": "n_1",
                                   "settings": [{"key": "max_slots", "value": 4},
                                                {"key": "services.disabled", "value": ["scorer"], "module": "relay"}]}
    assert admission_params(parser().parse_args(["node", "approve-code", "WDJB-MJHT"])) == {}
    with pytest.raises(SystemExit):
        admission_params(parser().parse_args(["node", "approve", "e", "--set", "no-equals"]))
