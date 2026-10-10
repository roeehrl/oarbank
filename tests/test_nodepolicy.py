"""A node's settings with this node's defaults and why (coordinator/nodepolicy.py, config.policy_defaults), resetting
them through nodes.set_policy, and the one line that explains a node's slots and memory, on the five machines of the
owner's fleet as they reported on 2026-10-10 (capacity as the agent's CapacityModel computes it,
rust/crates/oarbank-protection/tests/capacity.rs, the_budget_never_exceeds_what_is_available)."""
import json

import pytest

from helpers import FACTS, enrolled_node, facts_for, fresh, make_db
from oarbank.console import forms, views
from oarbank.coordinator import config as C, core, nodepolicy
from oarbank.coordinator.core import ApiError


def facts(ram, os_="darwin", perf=5, eff=10, logical=15, hostname="mini-a"):
    return {**facts_for(f"{os_}-arm64"), "hostname": hostname, "memory_gb": ram,
            "cpu": {"model": "test", "perf_cores": perf, "eff_cores": eff, "logical": logical}}


def test_defaults_come_with_their_reason():
    for ram, want in ((15.8, 4), (24.0, 4), (64.0, 6), (128.0, 8)):
        d = C.policy_defaults(facts(ram), [])
        assert d["os_reserve_gb"] == (want, f"{ram:g} GB RAM")
        assert C.policy_for(facts(ram))["os_reserve_gb"] == want            # the values a node joins with
    assert C.policy_defaults({}, [])["os_reserve_gb"] == (6, "RAM not reported")
    assert C.policy_defaults(facts(24.0), ["relay/scorer"])["disabled_services"] == (["relay/scorer"], "the fleet's default for workers")
    assert C.policy_defaults(facts(24.0), [])["user_reserve_gb"] == (8, None)
    assert C.DEFAULT_POLICY["screen_sharing_present"] is True


def test_rows_label_every_setting_and_mark_what_changed():
    pol = {**C.policy_for(facts(64.0)), "os_reserve_gb": 12, "run_on_battery": True}
    rows = {r["key"]: r for r in nodepolicy.rows(pol, facts(64.0), [])}
    assert list(rows) == list(nodepolicy.KEYS)
    assert {k for k, r in rows.items() if r["changed"]} == {"os_reserve_gb", "run_on_battery"}
    r = rows["os_reserve_gb"]
    assert (r["label"], r["value"], r["default"], r["default_text"]) == ("Memory kept for the system", 12, 6, "default 6 GB (64 GB RAM)")
    assert rows["user_reserve_gb"]["label"] == "Memory kept for the person using it"
    assert rows["user_present_slots"]["label"] == "Jobs while someone is using this computer"
    assert rows["user_idle_s"]["label"] == "Idle time before the computer counts as free"
    assert rows["user_idle_s"]["default_text"] == "default 300 s"
    assert rows["run_on_battery"]["default_text"] == "default off" and rows["screen_sharing_present"]["default_text"] == "default on"
    assert rows["max_slots"]["default_text"] == "default none" and rows["disabled_services"]["default_text"] == "default none"
    assert all(r["help"] for r in rows.values())
    # a setting a node's stored policy predates (screen_sharing_present) shows its default, unchanged
    old = {k: v for k, v in pol.items() if k != "screen_sharing_present"}
    ss = {r["key"]: r for r in nodepolicy.rows(old, facts(64.0), [])}["screen_sharing_present"]
    assert ss["value"] is True and not ss["changed"]
    # 1.5 and 1.50 are the same; integral floats are the same as ints
    same = {r["key"]: r for r in nodepolicy.rows({"job_mem_gb": 1.50, "os_reserve_gb": 6.0}, facts(64.0), [])}
    assert not same["job_mem_gb"]["changed"] and not same["os_reserve_gb"]["changed"]
    assert rows["mem_in_use_bound"]["label"] == "Fit jobs into the memory free now" and rows["mem_in_use_bound"]["default_text"] == "default on"


def test_reset_puts_settings_back_to_this_nodes_defaults(tmp_path):
    db = make_db(tmp_path / "oarbank.sqlite3")
    n = enrolled_node(db)[1]
    nid = n["node_id"]
    core.set_policy(db, nid, {"os_reserve_gb": 10, "user_idle_s": 60, "screen_sharing_present": False}, "t")
    pol = core.set_policy(db, nid, {"user_idle_s": 90, "os_reserve_gb": 11}, "t", reset=["os_reserve_gb"])
    assert (pol["os_reserve_gb"], pol["user_idle_s"], pol["screen_sharing_present"]) == (4, 90, False)   # 24 GB: 4
    ev = db.one("SELECT payload_json FROM events WHERE kind='policy_changed' ORDER BY event_id DESC LIMIT 1")
    assert json.loads(ev["payload_json"])["reset"] == ["os_reserve_gb"]
    pol = core.set_policy(db, nid, {}, "t", reset="all")
    want = C.policy_for(json.loads(fresh(db, n)["facts_json"]), db.get_setting("default_worker_disabled_services"))
    assert {k: pol[k] for k in nodepolicy.KEYS} == {k: want[k] for k in nodepolicy.KEYS}
    assert "protection" in pol                                              # protection has its own page
    with pytest.raises(ApiError):
        core.set_policy(db, nid, {}, "t", reset=["protection"])
    with pytest.raises(ApiError):
        core.set_policy(db, nid, {}, "t", reset="some")


class Form(dict):
    """A posted form: repeated fields keep every value, the last one wins (Starlette's FormData)."""
    def __init__(self, pairs):
        super().__init__()
        self.pairs = pairs
        for k, v in pairs:
            self[k] = v

    def getlist(self, k):
        return [v for kk, v in self.pairs if kk == k]


def test_the_policy_form_maps_rows_checkboxes_and_resets():
    f = Form([("p_os_reserve_gb", "6"), ("p_job_mem_gb", "1.5"), ("p_max_slots", ""), ("p_run_on_battery", "0"),
              ("p_run_on_battery", "1"), ("p_hard_limits", "0"), ("p_disabled_services", "a/b, c/d")])
    assert forms.policy(f) == {"patch": {"os_reserve_gb": 6, "job_mem_gb": 1.5, "max_slots": None, "run_on_battery": True,
                                         "hard_limits": False, "disabled_services": ["a/b", "c/d"]}}
    assert forms.policy(Form([("p_user_idle_s", "300"), ("reset", "user_idle_s")]))["reset"] == ["user_idle_s"]
    assert forms.policy(Form([("reset", "all")])) == {"patch": {}, "reset": "all"}


# ---- the why line, from what the agent reported

def cap(cpu, idle, slots, free, binding="in_use", in_use=None, present=False, admit=True, why=None, limit="auto"):
    return {"cpu_slots": cpu, "auto_cpu_slots": cpu, "idle_cpu_slots": idle, "slots": slots, "mem_gb_free": free,
            "mem_binding": binding, "mem_in_use_gb": in_use, "user_present": present, "admit": admit, "why": why,
            "binding_limit": limit, "reserved_mem_gb": 0}


def test_why_on_the_owners_fleet():
    studio = nodepolicy.why(cap(2, 14, 2, 9.22, in_use=46.1, present=True), {"presence": "hid"},
                            facts(64.0, perf=12, eff=4, logical=16), C.policy_for(facts(64.0)), "darwin")
    assert studio["line"] == "2 slots while someone is using this Mac (14 when idle) · 9.2 GB free for jobs (apps and the system use 46 GB)"
    mbp = nodepolicy.why(cap(2, 12, 2, 63.74, in_use=47.9, present=True), {"presence": "screen sharing"},
                         facts(128.0, perf=6, eff=12, logical=18), C.policy_for(facts(128.0)), "darwin")
    assert mbp["slots"] == "2 slots while someone is screen sharing this Mac (12 when idle)"
    gurus = nodepolicy.why(cap(10, 10, 2, 4.12, in_use=16.0, limit="memory_in_use"), {}, facts(24.0), C.policy_for(facts(24.0)))
    assert gurus["line"] == ("10 slots (5 performance cores + 10 efficiency cores at half), memory for 2 jobs · "
                             "4.1 GB free for jobs (apps and the system use 16 GB)")
    pc_facts = facts(15.8, "windows", perf=8, eff=0, logical=8)
    pc = nodepolicy.why(cap(8, 8, 3, 5.6, in_use=7.3), {}, pc_facts, C.policy_for(pc_facts))
    assert pc["line"] == "8 slots (8 cores), memory for 3 jobs · 5.6 GB free for jobs (apps and the system use 7.3 GB)"
    present = nodepolicy.why(cap(2, 8, 2, 3.8, binding="reserve", present=True), {}, pc_facts, C.policy_for(pc_facts))
    assert present["line"] == ("2 slots while someone is using this PC (8 when idle) · 3.8 GB free for jobs "
                               "(4.0 GB for the system and 8.0 GB for the person using it kept)")


def test_why_says_what_holds_a_node_back_and_how_to_allow_it():
    p = C.policy_for(facts(24.0))
    battery = nodepolicy.why(cap(0, 10, 0, 0.0, admit=False, why="guard:battery", limit="guard:battery"), {}, facts(24.0), p)
    assert battery["line"] == "no new jobs: on battery (allow it in settings: Run jobs on battery) · 0.0 GB free for jobs"
    guard = nodepolicy.why(cap(0, 8, 0, 0.0, admit=False, why="guard:memory"),
                           {"protection": {"guard_reason": "free 9.2% < 12%"}}, facts(24.0), p)
    assert guard["held"] == "no new jobs: the memory guard (free 9.2% < 12%)"
    capped = nodepolicy.why(cap(4, 10, 4, 12.0, binding="reserve", limit="cap.cpu_cores"), {}, facts(24.0), p)
    assert capped["slots"] == "4 slots: the owner's cap on cpu cores"
    assert nodepolicy.why({}, {}, facts(24.0), p) is None                # nothing reported yet
    # an agent from before the budget explained itself: the slots and the bare figure
    old = nodepolicy.why({"cpu_slots": 10, "mem_gb_free": 20.0, "admit": True, "binding_limit": "auto"}, {}, facts(24.0), p)
    assert old["line"] == "10 slots (5 performance cores + 10 efficiency cores at half) · 20 GB free for jobs"


def test_hardware_counts_physical_cores():
    assert views.hardware(facts(64.0, perf=12, eff=4, logical=16))["cores"] == "12P + 4E"
    assert views.hardware(facts(15.8, "windows", perf=8, eff=0, logical=8))["cores"] == "8 cores"
    assert views.hardware(facts(16.0, "linux", perf=4, eff=0, logical=8))["cores"] == "4 cores (8 threads)"
    assert views.hardware(facts(32.0, "linux", perf=8, eff=4, logical=20))["cores"] == "8P + 4E (20 threads)"
    # facts from an agent that reported no core counts
    assert views.hardware({**FACTS, "cpu": {"perf_cores": None, "eff_cores": None, "logical": 8}})["cores"] == "8 cores"
