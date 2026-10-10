"""The computed defaults a node's settings start from (settings/registry.py) and the one line that explains a node's
slots and memory, citing the settings it rests on (coordinator/nodepolicy.py), on the five machines of the owner's
fleet as they reported on 2026-10-10 (capacity as the agent's CapacityModel computes it,
rust/crates/oarbank-protection/tests/capacity.rs, the_budget_never_exceeds_what_is_available)."""
from helpers import FACTS, facts_for
from oarbank.console import views
from oarbank.coordinator import nodepolicy
from oarbank.coordinator.settings import registry as R


def facts(ram, os_="darwin", perf=5, eff=10, logical=15, hostname="mini-a"):
    return {**facts_for(f"{os_}-arm64"), "hostname": hostname, "memory_gb": ram,
            "cpu": {"model": "test", "perf_cores": perf, "eff_cores": eff, "logical": logical}}


def defaults_for(f) -> dict:
    """A node's effective policy and caps with nothing set anywhere: the registry's defaults for its facts."""
    return {d.key: R.default(d, f)[0] for d in R.SETTINGS if d.wire}


def test_defaults_come_with_their_reason():
    for ram, want in ((15.8, 4), (24.0, 4), (64.0, 6), (128.0, 8)):
        assert R.default(R.REGISTRY["os_reserve_gb"], facts(ram)) == (want, f"{ram:g} GB RAM")
    assert R.default(R.REGISTRY["os_reserve_gb"], {}) == (6, "RAM not reported")
    assert R.default(R.REGISTRY["user_reserve_gb"], facts(24.0)) == (8, None)
    assert R.REGISTRY["screen_sharing_present"].default is True


# ---- the why line, from what the agent reported

def cap(cpu, idle, slots, free, binding="in_use", in_use=None, present=False, admit=True, why=None, limit="auto"):
    return {"cpu_slots": cpu, "auto_cpu_slots": cpu, "idle_cpu_slots": idle, "slots": slots, "mem_gb_free": free,
            "mem_binding": binding, "mem_in_use_gb": in_use, "user_present": present, "admit": admit, "why": why,
            "binding_limit": limit, "reserved_mem_gb": 0}


def test_why_on_the_owners_fleet():
    studio = nodepolicy.why(cap(2, 14, 2, 9.22, in_use=46.1, present=True), {"presence": "hid"},
                            facts(64.0, perf=12, eff=4, logical=16), defaults_for(facts(64.0)), "darwin")
    assert studio["line"] == "2 slots while someone is using this Mac (14 when idle) · 9.2 GB free for jobs (apps and the system use 46 GB)"
    mbp = nodepolicy.why(cap(2, 12, 2, 63.74, in_use=47.9, present=True), {"presence": "screen sharing"},
                         facts(128.0, perf=6, eff=12, logical=18), defaults_for(facts(128.0)), "darwin")
    assert mbp["slots"] == "2 slots while someone is screen sharing this Mac (12 when idle)"
    gurus = nodepolicy.why(cap(10, 10, 2, 4.12, in_use=16.0, limit="memory_in_use"), {}, facts(24.0), defaults_for(facts(24.0)))
    assert gurus["line"] == ("10 slots (5 performance cores + 10 efficiency cores at half), memory for 2 jobs · "
                             "4.1 GB free for jobs (apps and the system use 16 GB)")
    pc_facts = facts(15.8, "windows", perf=8, eff=0, logical=8)
    pc = nodepolicy.why(cap(8, 8, 3, 5.6, in_use=7.3), {}, pc_facts, defaults_for(pc_facts))
    assert pc["line"] == "8 slots (8 cores), memory for 3 jobs · 5.6 GB free for jobs (apps and the system use 7.3 GB)"
    present = nodepolicy.why(cap(2, 8, 2, 3.8, binding="reserve", present=True), {}, pc_facts, defaults_for(pc_facts))
    assert present["line"] == ("2 slots while someone is using this PC (8 when idle) · 3.8 GB free for jobs "
                               "(4.0 GB for the system and 8.0 GB for the person using it kept)")
    assert [c["key"] for c in present["cites"]] == ["user_present_slots", "user_idle_s", "os_reserve_gb", "user_reserve_gb"]


def test_why_says_what_holds_a_node_back_and_how_to_allow_it():
    p = defaults_for(facts(24.0))
    battery = nodepolicy.why(cap(0, 10, 0, 0.0, admit=False, why="guard:battery", limit="guard:battery"), {}, facts(24.0), p,
                             node_id="n_1", sources={"run_on_battery": "Fleet"})
    assert battery["line"] == "no new jobs: on battery (allow it in settings: Run jobs on battery) · 0.0 GB free for jobs"
    # the setting it rests on, with its value and where it comes from, linked to its Explain row
    assert battery["cites"] == [{"key": "run_on_battery", "label": "Run jobs on battery", "source": "Fleet",
                                 "text": "Run jobs on battery: off · Fleet",
                                 "href": "/nodes/n_1/settings?explain=run_on_battery#s-run_on_battery"}]
    guard = nodepolicy.why(cap(0, 8, 0, 0.0, admit=False, why="guard:memory"),
                           {"protection": {"guard_reason": "free 9.2% < 12%"}}, facts(24.0), p)
    assert guard["held"] == "no new jobs: the memory guard (free 9.2% < 12%)"
    capped = nodepolicy.why(cap(4, 10, 4, 12.0, binding="reserve", limit="cap.cpu_cores"), {}, facts(24.0), p)
    assert capped["slots"] == "4 slots: the owner's cap on cpu cores"
    assert [c["key"] for c in capped["cites"]] == ["cpu_cores", "os_reserve_gb"]
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
