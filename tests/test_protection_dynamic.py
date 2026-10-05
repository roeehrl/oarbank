"""Protection on the coordinator: the preview matcher's shared vectors (D20), protection operations (versioned
rules, restore, canary/promote, mode, probe), the process summary, GPU admission, paused-as-progress, S18
from the decision journal, and the flapping / probe-harm alerts."""
import json
import time
import uuid

import pytest

from oarbank.coordinator import core, explain, invariants, ops, protection
from oarbank.contracts import protection_match as PM

from helpers import READY, certify, enrolled_node, fresh, make_db

PROCS = [{"pid": 100, "ppid": 1, "start_us": 1, "path": "/Applications/Studio Tool.app/Contents/MacOS/Studio Tool",
          "bundle_id": "com.example.studio", "team_id": "ABCDE12345", "cpu_cores": 2.0, "footprint_gb": 3.1},
         {"pid": 101, "ppid": 100, "start_us": 2, "path": "/Applications/Studio Tool.app/Contents/Helpers/render",
          "team_id": "ABCDE12345", "cpu_cores": 1.0, "footprint_gb": 0.5},
         {"pid": 200, "ppid": 1, "start_us": 3, "path": "/usr/local/bin/trainer", "argv": ["trainer", "--epochs", "3"]}]
RULE = {"id": "studio", "match": {"bundle_id": ["com.example.studio"]}, "tree": "descendants",
        "reserve": {"mem_gb": "peak(60s).footprint + 1"}}


@pytest.fixture
def db(tmp_path):
    return make_db(tmp_path / "oarbank.sqlite3")


def op(db, name, target=None, **kw):
    return ops.execute(db, ops.OpRequest(op=name, actor="test", target=target, **kw))


def planned(db, name, target, params, reason="test"):
    """T2: preview, then apply the reviewed plan."""
    plan = op(db, name, target, params=params, dry_run=True)["plan"]
    return plan, op(db, name, plan_id=plan["plan_id"], reason=reason)


def test_shared_vectors_hold_for_the_python_matcher():
    v = json.loads(PM.VECTORS.read_text(encoding="utf-8"))
    assert len(v["cases"]) >= 10
    for c in v["cases"]:
        assert [p["pid"] for p in PM.group(v["processes"], c["match"], c["tree"])] == c["expected"], c["name"]


def test_unreadable_identity_counts_as_a_match_and_is_flagged():
    procs = [{"pid": 1, "ppid": 0, "start_us": 1, "path": None, "comm": "trainer", "argv": None},
             {"pid": 2, "ppid": 0, "start_us": 2, "path": r"C:\Tools\other.exe", "comm": "other.exe", "argv": ["other"]}]
    cfg = {"rule": [{"id": "t", "match": {"path_prefix": "/opt/trainer/"}}, {"id": "w", "match": {"name": "other.exe"}}]}
    assert PM.preview(cfg, procs) == [
        {"rule": "t", "processes": [{"pid": 1, "path": None, "name": "trainer", "bundle_id": None, "unreadable": True}]},
        {"rule": "w", "processes": [{"pid": 2, "path": r"C:\Tools\other.exe", "name": "other.exe", "bundle_id": None,
                                     "unreadable": False}]}]
    # the picker suggests the path, or the name when the path is unreadable
    assert PM.suggest(procs[0]) == {"name": "trainer"} and PM.suggest(procs[1]) == {"path_prefix": r"C:\Tools\other.exe"}
    assert PM.suggest_rule(procs[1])["id"] == "other-exe"


def test_suggested_rules_are_valid_and_match_their_process():
    from oarbank.contracts import protection as P
    for p in PROCS:
        r = PM.suggest_rule(p, {"studio"})
        P.ProtectionConfig.model_validate({"schema": 1, "rule": [r]})
        assert p["pid"] in [q["pid"] for q in PM.group(PROCS, r["match"], r["tree"])]


def test_process_summary_is_stored_and_requested_by_a_preview(db):
    node = certify(db, enrolled_node(db)[1])
    nid = node["node_id"]
    assert not core.heartbeat(db, fresh(db, node), {})["send_processes"]
    plan = op(db, "protection.rules.update", nid, params={"config": {"schema": 1, "rule": [RULE]}}, dry_run=True)["plan"]
    assert plan["impact"]["processes_age_s"] is None and plan["tier"] == "T2"
    assert core.heartbeat(db, fresh(db, node), {})["send_processes"]            # the preview asked for a summary
    core.heartbeat(db, fresh(db, node), {"processes": PROCS})
    assert not core.heartbeat(db, fresh(db, node), {})["send_processes"]
    p = protection.preview(db, nid, {"schema": 1, "rule": [RULE]})
    assert p["matches"] == [{"rule": "studio", "processes": [
        {"pid": 100, "path": PROCS[0]["path"], "name": "Studio Tool", "bundle_id": "com.example.studio", "unreadable": False},
        {"pid": 101, "path": PROCS[1]["path"], "name": "render", "bundle_id": None, "unreadable": False}]}]
    assert p["diff"]["rules_added"] == ["studio"]


def test_rules_update_is_versioned_previewed_and_restorable(db):
    node = certify(db, enrolled_node(db)[1])
    nid = node["node_id"]
    core.heartbeat(db, fresh(db, node), {"processes": PROCS})
    with pytest.raises(core.ApiError) as e:                                   # T2: no apply without a plan
        op(db, "protection.rules.update", nid, params={"config": {"schema": 1, "rule": [RULE]}}, reason="x", if_match=0)
    assert e.value.code == "plan_required"
    with pytest.raises(core.ApiError) as e:
        op(db, "protection.rules.update", nid, params={"config": {"schema": 1, "rule": [{"id": "x", "match": {}}]}}, dry_run=True)
    assert e.value.code == "bad_protection"
    plan, r = planned(db, "protection.rules.update", nid, {"config": {"schema": 1, "rule": [RULE]}})
    assert [m["rule"] for m in plan["impact"]["matches"]] == ["studio"] and r["result"]["version"] == 1
    assert json.loads(fresh(db, node)["policy_json"])["protection"]["rule"] == [RULE]
    two = {"schema": 1, "node": {"mode": "fleet_first"}, "rule": []}
    planned(db, "protection.rules.update", nid, {"config": two})
    stale = op(db, "protection.rules.update", nid, params={"config": {"schema": 1, "rule": [RULE]}}, dry_run=True)["plan"]
    op(db, "nodes.set_mode", nid, params={"mode": "strict_yield"}, reason="owner away")          # T1, versioned
    with pytest.raises(core.ApiError) as e:                                   # the rules moved since that preview
        op(db, "protection.rules.update", plan_id=stale["plan_id"], reason="late")
    assert e.value.code == "plan_drift"
    _, r = planned(db, "protection.rules.restore", nid, {"version": 1})
    assert r["result"] == {"version": 4, "restored": 1}
    hist = protection.history(db, nid)
    assert [h["version"] for h in hist] == [4, 3, 2, 1] and hist[0]["config"] == hist[-1]["config"]
    assert hist[1]["config"]["node"]["mode"] == "strict_yield" and hist[1]["source"] == "mode.set"
    assert json.loads(fresh(db, node)["policy_json"])["protection"]["rule"] == [RULE]
    with pytest.raises(core.ApiError):
        op(db, "nodes.set_mode", nid, params={"mode": "yolo"})


def test_policy_route_changes_are_versioned_too(db):
    nid = enrolled_node(db)[1]["node_id"]
    core.set_policy(db, nid, {"protection": {"schema": 1, "rule": [RULE]}}, "oarbank")
    assert protection.current(db, nid) == (1, {"schema": 1, "rule": [RULE]})


def test_probe_now_is_sent_once(db):
    node = certify(db, enrolled_node(db)[1])
    op(db, "protection.probe_now", node["node_id"])
    assert core.heartbeat(db, fresh(db, node), {})["run_probe"] is True
    assert core.heartbeat(db, fresh(db, node), {})["run_probe"] is False


def test_canary_then_promote_after_a_clean_soak(db):
    a, b, c = (certify(db, enrolled_node(db, n)[1]) for n in ("desk", "mini", "laptop"))
    cfg = {"schema": 1, "rule": [RULE]}
    plan, r = planned(db, "protection.rules.canary", a["node_id"], {"config": cfg})
    assert plan["impact"]["canary"] and r["result"]["node_id"] == a["node_id"]
    assert protection.current(db, b["node_id"])[0] == 0
    plan = op(db, "protection.rules.canary", a["node_id"], params={"promote": True}, dry_run=True)["plan"]
    assert not plan["impact"]["promotable"] and any("soaking" in w for w in plan["impact"]["why"])
    with pytest.raises(core.ApiError) as e:
        op(db, "protection.rules.canary", plan_id=plan["plan_id"], reason="too early")
    assert e.value.code == "canary_not_promotable"
    s = db.get_setting(protection.CANARY_KEY)
    db.set_setting(protection.CANARY_KEY, {**s, "started_at": time.time() - protection.CANARY_MIN_SOAK_S - 1})
    core.heartbeat(db, fresh(db, a), {})
    _, r = planned(db, "protection.rules.canary", a["node_id"], {"promote": True})
    assert sorted(r["result"]["promoted"]) == sorted([b["node_id"], c["node_id"]])
    for n in (b, c):
        assert protection.current(db, n["node_id"])[1] == cfg
        assert protection.history(db, n["node_id"])[0]["source"] == "rules.promote"
    assert db.get_setting(protection.CANARY_KEY) is None


def test_shared_support_vectors_hold_for_the_python_refusals():
    from oarbank.contracts import protection as P
    v = json.loads(P.SUPPORT_VECTORS.read_text(encoding="utf-8"))
    assert len(v["cases"]) >= 10
    for c in v["cases"]:
        P.ProtectionConfig.model_validate({"schema": 1, "rule": [c["rule"]]})
        got = P.refusals({"rule": [c["rule"]]}, c["os"])
        assert len(got) == len(c["refused"]) and all(w in g for w, g in zip(c["refused"], got)), (c["name"], got)


def test_a_rule_a_node_s_os_cannot_run_is_refused_there_and_skipped_by_promotion(db):
    from helpers import facts_for
    mac = certify(db, enrolled_node(db, "desk")[1])
    linux = certify(db, enrolled_node(db, "box", facts=facts_for("linux-amd64", os_version="7.0"))[1])
    win = certify(db, enrolled_node(db, "pc", facts=facts_for("windows-arm64", os_version="10.0"))[1])
    cfg = {"schema": 1, "rule": [RULE]}                              # matches on a macOS bundle id
    with pytest.raises(core.ApiError) as e:
        op(db, "protection.rules.update", linux["node_id"], params={"config": cfg}, dry_run=True)
    assert e.value.code == "bad_protection" and "on linux: rule studio: match.bundle_id" in str(e.value)
    with pytest.raises(core.ApiError) as e:                          # every route that writes the section
        core.set_policy(db, win["node_id"], {"protection": cfg}, "test")
    assert "on windows:" in str(e.value)
    portable = {"schema": 1, "rule": [{"id": "trainer", "match": {"path_contains": "trainer"}, "pause_fleet": {}}]}
    planned(db, "protection.rules.update", linux["node_id"], {"config": portable})
    assert protection.current(db, linux["node_id"])[1] == portable
    # a canary on the Mac promotes to every node that can run it, and says which it skipped and why
    protection.start_canary(db, mac["node_id"], cfg, "t", "try")
    s = db.get_setting(protection.CANARY_KEY)
    db.set_setting(protection.CANARY_KEY, {**s, "started_at": time.time() - protection.CANARY_MIN_SOAK_S - 1})
    core.heartbeat(db, fresh(db, mac), {})
    plan, r = planned(db, "protection.rules.canary", mac["node_id"], {"promote": True})
    assert plan["impact"]["targets"] == [] and sorted(plan["impact"]["skipped"]) == sorted([linux["node_id"], win["node_id"]])
    assert r["result"]["promoted"] == {} and "match.bundle_id" in r["result"]["skipped"][win["node_id"]]
    assert protection.current(db, linux["node_id"])[1] == portable


def test_what_protection_cannot_read_now_shows_as_node_conditions_and_in_explain(db):
    from oarbank.console.views import node_conditions
    node = certify(db, enrolled_node(db, "box")[1])
    tel = {"presence": "unknown: logind has no idle time for session 5 (sshd)",
           "protection": {"front": "unknown: session 7 is Wayland, whose compositor tells no other program which window is "
                                   "in front", "lowering": False, "source_error": None,
                          "rules": [{"id": "trainer", "active": True, "processes": 3, "unreadable": 2}],
                          "no_instruction_counters": ["build"]}}
    codes = [c["code"] for c in protection.runtime_conditions(tel)]
    assert codes == ["PROTECTION_FRONT_UNKNOWN", "PROTECTION_PRESENCE_UNKNOWN", "PROTECTION_UNREADABLE",
                     "PROTECTION_NO_IPC_COUNTERS", "PROTECTION_NO_LOWERING"]
    assert protection.runtime_conditions({"presence": "logind", "protection": {"front": "app 812 (x11 :0)", "lowering": True,
                                                                               "rules": [{"id": "t", "unreadable": 0}]}}) == []
    shown = node_conditions({"tel": tel, "cap": {}})
    assert "Wayland" in next(c["message"] for c in shown if c["code"] == "PROTECTION_FRONT_UNKNOWN")
    db.x("UPDATE nodes SET telemetry_json=? WHERE node_id=?", (json.dumps(tel), node["node_id"]))
    doc = explain.node_doc(db, node["node_id"])
    rows = {r.code: r.detail for r in doc.summary}
    assert rows["PROTECTION_UNREADABLE"] == {"rule": "trainer", "n": 2} and "PROTECTION_NO_LOWERING" in rows
    assert rows["PROTECTION_NO_IPC_COUNTERS"] == {"rule": "build"}


def test_a_refused_actuation_blocks_promotion(db):
    a = certify(db, enrolled_node(db, "desk")[1])
    protection.start_canary(db, a["node_id"], {"schema": 1, "rule": [RULE]}, "t", "try")
    s = db.get_setting(protection.CANARY_KEY)
    db.set_setting(protection.CANARY_KEY, {**s, "started_at": time.time() - 4000})
    core.heartbeat(db, fresh(db, a), {"journal": [{"t": time.time(), "seq": 1, "kind": "actuation_refused", "reason": "S16_GUARD"}]})
    h = protection.canary_health(db)
    assert not h["promotable"] and "refused actuation" in h["why"][0]


def test_paused_attempts_keep_their_lease(db):
    from helpers import create_study, PARAMS, SCENES
    node = certify(db, enrolled_node(db)[1])
    create_study(db, "s", [{"label": "a", "params": PARAMS}], SCENES[:1], {"label": "base", "params": PARAMS})
    g = core.claim(db, node, {"free_cpu": 4, "free_mem_gb": 8, "ready_datasets": READY})["grants"][0]
    a = lambda phase, cpu: {"attempts": [{"attempt_id": g["attempt_id"], "phase": phase, "cpu_s": cpu, "log_bytes": 0}]}
    core.heartbeat(db, fresh(db, node), a("running", 5.0))
    db.x("UPDATE attempts SET expires_at=? WHERE attempt_id=?", (time.time() + 5, g["attempt_id"]))
    core.heartbeat(db, fresh(db, node), a("paused", 5.0))                     # no CPU progress: SIGSTOPped
    assert db.one("SELECT expires_at FROM attempts WHERE attempt_id=?", (g["attempt_id"],))["expires_at"] > time.time() + 30
    assert db.one("SELECT 1 FROM attempt_phases WHERE attempt_id=? AND phase='paused'", (g["attempt_id"],))


def test_gpu_jobs_are_held_by_the_nodes_gpu_ceiling(db):
    n1 = certify(db, enrolled_node(db, "mini")[1])
    r = op(db, "mod.toy.queue_sums", idempotency_key=uuid.uuid4().hex, params={"ns": [10]})
    cid = r["result"]["result"]["campaign_id"]
    db.x("UPDATE jobs SET resources_json=? WHERE campaign_id=?", (json.dumps({"cpu": 1, "mem_gb": 1, "gpu": True}), cid))
    body = {"free_cpu": 4, "free_mem_gb": 8, "ready_datasets": READY, "gpu_jobs": 0}
    assert core.claim(db, fresh(db, n1), body)["grants"] == []
    j = db.one("SELECT * FROM jobs WHERE campaign_id=?", (cid,))
    codes = [x.code for x in explain._job_on_node(db, j, core.node_view_for_claim(db, fresh(db, n1), {"toy"}, set(READY), 4, 8, body),
                                                  time.time()) if x.outcome == "fail"]
    assert codes == ["GPU_BLOCKED"]
    assert len(core.claim(db, fresh(db, n1), {**body, "gpu_jobs": None})["grants"]) == 1


def test_only_gpu_jobs_count_against_the_gpu_ceiling(db, monkeypatch):
    """A runner that declares no GPU use is not held by gpu_jobs = 0; a per-platform variant's GPU use is (D33 2.3.6)."""
    import dataclasses
    from oarbank.coordinator import modcalls
    from oarbank_sdk import manifest as mf
    n1 = certify(db, enrolled_node(db, "mini")[1])
    op(db, "mod.toy.queue_sums", idempotency_key=uuid.uuid4().hex, params={"ns": [10]})
    body = {"free_cpu": 4, "free_mem_gb": 8, "ready_datasets": READY, "gpu_jobs": 0}
    j = db.one("SELECT * FROM jobs WHERE module='toy' AND kind!='golden' AND state='pending'")
    codes = lambda: [x.code for x in explain._job_on_node(db, j, core.node_view_for_claim(db, fresh(db, n1), {"toy"}, set(READY), 4, 8, body),
                                                          time.time()) if x.outcome == "fail"]
    assert codes() == [] and not modcalls.job_uses_gpu("toy", {}, "darwin-arm64")
    info = modcalls.info("toy")
    variant = lambda key: dataclasses.replace(info, manifest=info.manifest.model_copy(update={"runner": info.manifest.runner.model_copy(
        update={"variants": {key: mf.RunnerVariant(gpu=mf.GPUNeed(use="shared"))}})}))
    monkeypatch.setitem(modcalls.CATALOG, "toy", variant("linux"))
    assert codes() == [] and modcalls.job_uses_gpu("toy", {}, "linux-amd64")
    monkeypatch.setitem(modcalls.CATALOG, "toy", variant("darwin-arm64"))
    assert codes() == ["GPU_BLOCKED"]
    assert core.claim(db, fresh(db, n1), body)["grants"] == []
    assert len(core.claim(db, fresh(db, n1), {**body, "gpu_jobs": 1})["grants"]) == 1


def _journal(db, node, recs):
    core.heartbeat(db, fresh(db, node), {"journal": [{"seq": i + 1, **r} for i, r in enumerate(recs)]})


def test_s18_checks_rules_are_enforced_in_time(db):
    node = certify(db, enrolled_node(db)[1])
    nid = node["node_id"]
    core.set_policy(db, nid, {"protection": {"schema": 1, "rule": [{"id": "zoom", "match": {"bundle_id": "us.zoom.xos"},
                                                                    "cap_fleet": {"slots": 0}}]}}, "t")
    t = time.time()
    db.x("UPDATE protection_versions SET created_at=? WHERE node_id=?", (t - 7200, nid))
    _journal(db, node, [{"t": t - 3000, "kind": "rule_active", "reason": "PROTECTION_ACTIVE", "rule": "zoom"},
                        {"t": t - 2998, "kind": "constraint", "reason": "CONSTRAINT_CHANGED", "constraint": {"slots": 0}},
                        {"t": t - 1000, "kind": "rule_active", "reason": "PROTECTION_ACTIVE", "rule": "zoom"},
                        {"t": t - 999, "kind": "constraint", "reason": "CONSTRAINT_CHANGED", "constraint": {"slots": 3}},
                        {"t": t - 10, "kind": "rule_active", "reason": "PROTECTION_ACTIVE", "rule": "zoom"},     # not judged yet
                        {"t": t - 5, "kind": "constraint", "reason": "CONSTRAINT_CHANGED", "constraint": {"slots": 4}}])
    v = invariants.s18_rules_enforced(db)
    assert len(v) == 1 and "journal #3" in v[0] and "slots 3 > 0" in v[0]
    assert invariants.s18_rules_enforced(db, since=t - 500) == []


def test_flapping_and_probe_harm_alerts(db):
    node = certify(db, enrolled_node(db)[1])
    t = time.time()
    recs = []
    for i in range(14):
        recs += [{"t": t - 3000 + i * 100, "kind": "rung_change", "reason": "RUNG_3", "from": 0, "to": 3},
                 {"t": t - 2990 + i * 100, "kind": "rung_change", "reason": "RUNG_0", "from": 3, "to": 0}]
    recs.append({"t": t - 60, "kind": "probe_result", "reason": "PROBE_HARM", "rule": "rule:x", "signals": {"harm": 0.4}})
    _journal(db, node, recs)
    core.reap(db)
    open_ = {a["rule"] for a in db.q("SELECT rule FROM alerts WHERE state='open'")}
    assert {"protection_flapping", "protection_probe_harm"} <= open_


def test_timeline_reconstructs_every_transition_of_a_72h_journal(db):
    """The console's decision timeline over a 72 h journal (shipped through heartbeats in batches, as agents do):
    every rule activity period is a band, every rung change a step, every probe a point, every guard a mark."""
    import random
    from oarbank.console import views
    node = certify(db, enrolled_node(db)[1])
    rng, now = random.Random(72), time.time()
    t, recs, active, rung = now - 72 * 3600, [], {}, 0
    want = {"bands": {}, "rung": 0, "probes": 0, "guards": 0}
    while t < now - 60:
        t += rng.uniform(20, 400)
        k = rng.random()
        rid = rng.choice(["studio", "zoom", "xcode"])
        if k < 0.3:
            if rid in active:
                recs.append({"t": t, "kind": "rule_inactive", "reason": "PROTECTION_CLEARED", "rule": rid})
                active.pop(rid)
            else:
                recs.append({"t": t, "kind": "rule_active", "reason": "PROTECTION_ACTIVE", "rule": rid})
                active[rid] = t
                want["bands"][rid] = want["bands"].get(rid, 0) + 1
        elif k < 0.55:
            new = rng.randint(0, 6)
            recs.append({"t": t, "kind": "rung_change", "reason": f"RUNG_{new}", "from": rung, "to": new})
            rung, want["rung"] = new, want["rung"] + 1
        elif k < 0.7:
            recs.append({"t": t, "kind": "probe_result", "reason": "PROBE_HARM", "rule": "rule:studio", "signals": {"harm": 0.01}})
            want["probes"] += 1
        elif k < 0.75:
            recs.append({"t": t, "kind": "guard_fired", "reason": "MEMORY_SOFT"})
            want["guards"] += 1
        else:
            recs.append({"t": t, "kind": "budget_step", "reason": "L1_GROW", "rule": "l1", "signals": {"budget": rng.randint(0, 12)}})
    for i in range(0, len(recs), 200):                       # the agent ships at most 200 per heartbeat
        core.heartbeat(db, fresh(db, node), {"journal": [{"seq": j + 1, **r} for j, r in enumerate(recs) if i <= j < i + 200]})
    assert db.one("SELECT COUNT(*) n FROM protection_decisions")["n"] == len(recs)
    tl = views.timeline(db, node["node_id"], now, hours=72)
    assert {r["rule"]: len(r["spans"]) for r in tl["rows"]} == want["bands"]
    assert tl["rung"].count("L") == 2 * want["rung"] + 1                 # two segments per step, one tail
    assert len(tl["probes"]) == want["probes"] and len(tl["guards"]) == want["guards"]
