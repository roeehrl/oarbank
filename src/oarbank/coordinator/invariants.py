"""Protocol invariants as pure checks over the coordinator database (S8, S21 and S22 also read the modules' manifests).

One catalogue, reused by: the Hypothesis state machine (tests/test_stateful.py), the seeded
fault-injecting simulator (oarbank.sim), the swarm load test (bench/), and `oarbank verify`
against the live fleet. Each check returns a list of human-readable violations.

Safety (must hold after every committed transaction):
  S1  at most one canonical result per job
  S2  a done eval job points at a canonical, accepted result of that same job, or (result cache) of
      another job with the same job_key
  S3  a canonical result came from an attempt of the job's current generation
  S4  no lost job: every leased job has at least one live attempt
  S5  pending / done / cancelled / quarantined / failed jobs have no live attempts
  S6  accepted results are exactly the canonical ones, except results superseded by a later generation
  S7  live attempts only run on ready (not quarantined/retired) nodes
  S8  a live non-golden attempt runs a module certified on its node, under the current certification, or is an attempt
      of a stage that needs no certification (a bootstrap stage, or one that compares nothing and needs no capability or
      pool) on a node where the module is in a state its doctor decides (not revoked, not unknown). The certification an
      attempt was granted under stands while the node re-certifies (a new version, canary or periodic: `certifying`,
      same generation) for the attempts granted before that began; it ends with a new generation, a revocation or
      golden_failed. The version an attempt records is the one its node's release carried (the certified code)
  S9  attempt bookkeeping: ended_at is set iff the attempt is no longer live
  S10 a job's exec_failures never exceeds its failed/killed attempts
  S11 no node holds more live attempts than its `jobs` cap (when set and enforced hard)
  S12 staged jobs: no live attempt on a job whose dependency (its call) is not done
  S13 staged jobs: a done job's dependency is done and fed it the same input (digest)
  S14 every canonical result carries its job's module's verdict: produced for the job's module and
      evaluated by it (a bootstrap job's verdict is the host's pin check)
  S15 a module fault is never charged: an attempt whose completion waited on its module
      (phase awaiting_module) is never killed, and never ends failed unless the module, once back,
      judged its result (a recorded verdict); the wait itself never counts as an exec failure
  S16 every journaled actuation targets one of the node's own attempts, services or workloads (a workload's members
      included), or a process an owner rule delegated
  S17 no node admits work while its memory guard is active
  S18 an active protection rule is enforced within enter_for_s + 2 samples (from the decision journal)
  S20 every live, leased or done job of a bound unit of work ran on, or got its canonical result from, a node of the
      unit's class (and of its parent unit's), result-cache hits included (D33; S19 is the agent's protection invariant)
  S21 a job of a stage that does not compare (determinism none) never has a replica, a dispute or a golden, and never
      shares a canonical result through the cache (reads the catalogue's manifests)
  S22 a bootstrap job's canonical result is exactly pinned datasets of the module version that produced it: an empty
      payload, and artifacts that each hold one pin's files (reads the catalogue's manifests)
  S23 an attempt that resumed from a checkpoint resumed from one recorded by an earlier attempt of the same job under the
      same job generation
  S24 every listener and router mapping a node reports belongs to an approved grant (the module version the node runs
      requests that inbound listener, its grants approved by digest), an assignment (the node's statement lists it) and
      the statement the node applied (listeners.py)
  S25 for a rule marked immediate, a phase the agent's event path saw begin is followed by its pause request within
      100 ms (from the decision journal: the first pause of that phase is the event path's, requested within 100 ms of
      the source event)
  S26 at most one node runs a seat of a per-node workload identity at a time (workloads.py; TLA+ OarbankSeat)
  S27 a site's live (unexpired, unrevoked) transfer leases never number more than its max_transfers, their rates never sum
      past its uplink_mbps, and none is live while the site holds (a protected process there is in an uplink phase); a
      grant also leaves room for revoked leases not yet given back
  S28 the GPU duty budget a node journals never exceeds the certified ceiling it journals with it, and every fleet unit
      (a job or a workload) the duty governor holds or stops for exceeding (or for not being able to check) its gpu_duty
      is paused (a workload: paused or held by its ladder) within the S18 window, or has ended (from the decision journal; docs/design/gpu-cotenancy.md, "The duty governor")
  S29 no ring of a rollout has more nodes between draining and confirming (or staged with `go`) than its max_unavailable
      (rollouts.py; docs/design/fleet-updates.md)
  S30 no node is assigned, or was moved to, a fleet release newer than the coordinator's own version, and no node of a
      later ring was told `go` before every earlier ring of its rollout finished and baked
  S31 every `go` was granted while the node was eligible: online, inside its window, not held, not pinned to another
      version (from the rollout journal: each grant with the eligibility recorded beside it)
Liveness (checked by the simulator at the end of a run under bounded faults):
  L1  every job reaches done, cancelled, quarantined or failed
"""
import bisect
import json
import time

from oarbank_sdk import platform as pf

from .db import DB, jl



def _v(rows, fmt):
    return [fmt.format(**r) for r in rows]


def s1_single_canonical(db: DB):
    return _v(db.q("SELECT job_id, COUNT(*) n FROM results WHERE canonical=1 GROUP BY job_id HAVING n>1"),
              "S1 job {job_id} has {n} canonical results")


def s2_done_has_canonical(db: DB):
    rows = db.q("SELECT j.job_id, j.canonical_result_id cid, r.canonical, r.accepted, r.job_id rjob, "
                "r.job_key = j.job_key samekey "
                "FROM jobs j LEFT JOIN results r ON r.result_id=j.canonical_result_id "
                "WHERE j.state='done' AND j.kind!='golden'")
    out = []
    for r in rows:
        if r["cid"] is None or r["canonical"] != 1 or r["accepted"] != 1 or (r["rjob"] != r["job_id"] and not r["samekey"]):
            out.append(f"S2 done job {r['job_id']} canonical_result_id={r['cid']} canonical={r['canonical']} "
                       f"accepted={r['accepted']}")
    return out


def s3_canonical_current_generation(db: DB):
    return _v(db.q("SELECT j.job_id, j.generation g, a.generation ag FROM jobs j JOIN results r ON r.result_id=j.canonical_result_id "
                   "JOIN attempts a ON a.attempt_id=r.attempt_id WHERE j.state='done' AND r.canonical=1 AND r.job_id=j.job_id "
                   "AND a.generation!=j.generation"),
              "S3 job {job_id} canonical from generation {ag}, job is at {g}")


def s4_no_lost_job(db: DB):
    return _v(db.q("SELECT j.job_id FROM jobs j WHERE j.state='leased' AND NOT EXISTS "
                   "(SELECT 1 FROM attempts a WHERE a.job_id=j.job_id AND a.state='live')"),
              "S4 job {job_id} is leased with no live attempt (lost)")


def s5_no_live_on_settled(db: DB):
    return _v(db.q("SELECT j.job_id, j.state, a.attempt_id FROM jobs j JOIN attempts a ON a.job_id=j.job_id "
                   "WHERE a.state='live' AND j.state IN ('pending','done','cancelled','quarantined','failed')"),
              "S5 job {job_id} is {state} but attempt {attempt_id} is live")


def s6_accepted_iff_canonical(db: DB):
    """accepted == canonical, except results superseded by a later generation (user retry)."""
    return _v(db.q("SELECT r.result_id, r.job_id, r.accepted, r.canonical FROM results r JOIN attempts a ON a.attempt_id=r.attempt_id "
                   "JOIN jobs j ON j.job_id=r.job_id WHERE r.accepted!=r.canonical AND NOT (r.accepted=1 AND r.canonical=0 "
                   "AND a.generation < j.generation)"),
              "S6 result {result_id} (job {job_id}) accepted={accepted} canonical={canonical}")


def s7_live_on_ready_nodes(db: DB):
    return _v(db.q("SELECT a.attempt_id, n.node_id, n.lifecycle FROM attempts a JOIN nodes n ON n.node_id=a.node_id "
                   "WHERE a.state='live' AND n.lifecycle!='ready'"),
              "S7 attempt {attempt_id} live on node {node_id} in lifecycle {lifecycle}")


def _manifest(module: str, version: str | None):
    """The manifest of the module version that produced a row, else the current one (None: neither is catalogued)."""
    from . import modcalls
    try:
        return modcalls.info_for(module, version).manifest
    except KeyError:
        i = modcalls.CATALOG.get(module)
        return i.manifest if i else None


def _released_version(db: DB, release_id: str | None, module: str, cache: dict) -> dict:
    """{version, digest} of a module in a release's composition ({} when the release names none)."""
    if release_id not in cache:
        r = db.one("SELECT composition_json FROM releases WHERE release_id=?", (release_id,)) if release_id else None
        cache[release_id] = jl(r["composition_json"], {}) if r else {}
    return cache[release_id].get(module) or {}


def _s8_certified(r: dict, st: dict, ran: dict) -> str | None:
    """Why a live attempt of a stage that needs certification does not run under a certification that stands (None: it
    does). `ran`: the module's entry in the composition of the release the attempt was granted on."""
    gen, state = st.get("generation"), st.get("state")
    if gen != r["cert_generation"] or not isinstance(gen, int) or gen <= 0:
        return f"state={state} gen={gen} attempt_gen={r['cert_generation']}"
    if state == "certifying":
        # re-certifying (a new version, canary or periodic): the certification stands for the attempts granted under it,
        # but a node that is certifying is never granted work (claim: only `certified`)
        since = st.get("certifying_since")
        if since is not None and r["granted_at"] is not None and r["granted_at"] > since:
            return f"state=certifying gen={gen} attempt_gen={r['cert_generation']}: granted while certifying"
    elif state != "certified":
        return f"state={state} gen={gen} attempt_gen={r['cert_generation']}"
    if ran.get("version") and r["module_version"] and ran["version"] != r["module_version"]:
        return (f"state={state} gen={gen}: records {r['module']} {r['module_version']} but its release "
                f"{r['release_id']} carries {ran['version']}")
    if ran.get("digest") and st.get("digest") and ran["digest"] != st["digest"]:
        return f"state={state} gen={gen}: its release {r['release_id']} carries a digest of {r['module']} not certified here"
    return None


def s8_live_module_certified(db: DB):
    out, rels = [], {}
    for r in db.q("SELECT a.attempt_id, a.cert_generation, a.module_version, a.release_id, a.granted_at, j.module, j.kind, "
                  "j.stage, n.node_id, n.modules_json FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                  "JOIN nodes n ON n.node_id=a.node_id WHERE a.state='live'"):
        st = (jl(r["modules_json"], {}) or {}).get(r["module"], {})
        man = _manifest(r["module"], r["module_version"]) if r["kind"] != "golden" else None
        if man is not None and man.certification_exempt(r["stage"]):
            from .predicates import RUNNER_STATES
            if st.get("state") not in RUNNER_STATES:
                what = "bootstrap" if man.is_bootstrap(r["stage"]) else "certification-exempt"
                out.append(f"S8 {what} attempt {r['attempt_id']} live but {r['module']} is {st.get('state')} on {r['node_id']}")
        elif r["kind"] == "golden":
            if st.get("state") not in ("certifying", "certified"):
                out.append(f"S8 golden attempt {r['attempt_id']} live but {r['module']} is {st.get('state')} on {r['node_id']}")
        else:
            why = _s8_certified(r, st, _released_version(db, r["release_id"], r["module"], rels))
            if why:
                out.append(f"S8 attempt {r['attempt_id']} runs {r['module']} on {r['node_id']} {why}")
    return out


def s9_attempt_bookkeeping(db: DB):
    return _v(db.q("SELECT attempt_id, state FROM attempts WHERE (state='live' AND ended_at IS NOT NULL) "
                   "OR (state!='live' AND ended_at IS NULL)"),
              "S9 attempt {attempt_id} state={state} has inconsistent ended_at")


def s10_failure_accounting(db: DB):
    return _v(db.q("SELECT j.job_id, j.exec_failures f, (SELECT COUNT(*) FROM attempts a WHERE a.job_id=j.job_id "
                   "AND a.state IN ('failed','killed')) n FROM jobs j WHERE j.exec_failures > (SELECT COUNT(*) FROM attempts a "
                   "WHERE a.job_id=j.job_id AND a.state IN ('failed','killed'))"),
              "S10 job {job_id} exec_failures={f} > failed attempts {n}")


def s11_hard_job_caps(db: DB):
    out = []
    from .core import node_limits
    for n in db.q("SELECT node_id, settings_json FROM nodes"):
        lim = node_limits(n)
        if lim.get("jobs") is None or lim.get("enforce") != "hard":
            continue
        live = db.one("SELECT COUNT(*) c FROM attempts WHERE node_id=? AND state='live'", (n["node_id"],))["c"]
        if live > int(lim["jobs"]):
            out.append(f"S11 node {n['node_id']} has {live} live attempts > hard cap jobs={lim['jobs']}")
    return out


def s12_live_only_on_ready_inputs(db: DB):
    return _v(db.q("SELECT j.job_id, d.job_id dep, d.state FROM jobs j JOIN jobs d ON d.job_id=j.depends_on "
                   "JOIN attempts a ON a.job_id=j.job_id WHERE a.state='live' AND d.state!='done'"),
              "S12 job {job_id} has a live attempt but its dependency {dep} is {state}")


def s13_done_on_done_input(db: DB):
    out = _v(db.q("SELECT j.job_id, d.job_id dep, d.state FROM jobs j JOIN jobs d ON d.job_id=j.depends_on "
                  "WHERE j.state='done' AND d.state!='done'"),
             "S13 job {job_id} is done but its dependency {dep} is {state}")
    out += _v(db.q("SELECT j.job_id, r.digest a, dr.digest b FROM jobs j JOIN jobs d ON d.job_id=j.depends_on "
                   "JOIN results r ON r.result_id=j.canonical_result_id JOIN results dr ON dr.result_id=d.canonical_result_id "
                   "WHERE j.state='done' AND r.digest IS NOT NULL AND dr.digest IS NOT NULL AND r.digest!=dr.digest"),
              "S13 job {job_id} scored input {a} but its call produced {b}")
    return out


def s14_canonical_module_verdict(db: DB):
    return _v(db.q("SELECT j.job_id, j.module jm, r.module rm, r.fields_json IS NULL unevaluated FROM jobs j "
                   "JOIN results r ON r.result_id=j.canonical_result_id WHERE j.state='done' AND r.job_id=j.job_id "
                   "AND (r.module IS NOT j.module OR r.fields_json IS NULL)"),
              "S14 job {job_id} ({jm}) canonical result from module {rm} (unevaluated={unevaluated})")


def s15_module_faults_not_charged(db: DB):
    return _v(db.q("SELECT a.attempt_id, a.job_id, a.state, a.end_reason FROM attempts a WHERE a.phase='awaiting_module' "
                   "AND (a.state='killed' OR (a.state='failed' AND NOT EXISTS "
                   "(SELECT 1 FROM results r WHERE r.attempt_id=a.attempt_id)))"),
              "S15 attempt {attempt_id} (job {job_id}) waited on its module but ended {state} ({end_reason})")


def _delegated_rule(db: DB, node_id: str, rule: str) -> bool:
    """Whether the node's protection ever had an owner rule `rule` that delegates (protection_versions)."""
    for v in db.q("SELECT config_json FROM protection_versions WHERE node_id=?", (node_id,)):
        cfg = jl(v["config_json"], {}) or {}
        if any(r.get("id") == rule.removesuffix("@local") and r.get("delegate") for r in cfg.get("rule") or []):
            return True
    return False


def s16_actuation_only_on_spawned(db: DB):
    """Every signal or policy change an agent journaled targets one of its own attempts, services or workloads (a
    workload's members outside its process group included: the record names the workload), or a process an owner rule
    delegated: the agent-side spawn registry refuses anything else, and a refusal is journaled as actuation_refused."""
    out = []
    for r in db.q("SELECT d.node_id, d.seq, d.record_json FROM protection_decisions d WHERE d.kind='actuation'"):
        rec = json.loads(r["record_json"] or "{}")
        aid, svc = rec.get("attempt"), rec.get("service")
        if svc:
            continue
        if rec.get("workload"):
            m, _, w = str(rec["workload"]).partition("/")
            if not db.one("SELECT 1 FROM workload_assignments WHERE module=? AND workload=? AND node_id=?", (m, w, r["node_id"])):
                out.append(f"S16 node {r['node_id']} journal #{r['seq']}: actuation on pid {rec.get('pid')} for workload "
                           f"{rec['workload']}, which was never assigned to it")
            continue
        if rec.get("delegated"):
            if not _delegated_rule(db, r["node_id"], str(rec["delegated"])):
                out.append(f"S16 node {r['node_id']} journal #{r['seq']}: actuation on pid {rec.get('pid')} under "
                           f"delegation {rec['delegated']}, which no owner rule of the node declares")
            continue
        if aid is None or not db.one("SELECT 1 FROM attempts WHERE attempt_id=? AND node_id=?", (aid, r["node_id"])):
            out.append(f"S16 node {r['node_id']} journal #{r['seq']}: actuation on pid {rec.get('pid')} "
                       f"(attempt {aid}) that is not one of its attempts")
    return out


def s17_no_admission_under_memory_floor(db: DB):
    """A node whose memory guard is active does not report itself as admitting (and so claims nothing)."""
    out = []
    for n in db.q("SELECT node_id, telemetry_json, capacity_json FROM nodes WHERE lifecycle='ready'"):
        tel, cap = jl(n["telemetry_json"], {}) or {}, jl(n["capacity_json"], {}) or {}
        if tel.get("guard") in ("soft", "hard") and cap.get("admit"):
            out.append(f"S17 node {n['node_id']} admits while its memory guard is {tel.get('guard')}")
    return out


S18_WINDOW_S = 15.0      # "enter_for_s + 2 samples": rule_active is journaled after enter_for_s; 2 agent ticks + slack
CAP_DIMS = ("slots", "cpu_cores", "threads", "gpu_jobs", "staging_mbps")


def _rule_at(db: DB, node_id: str, rule_id: str, t: float) -> dict | None:
    """The rule as configured when it became active (the protection version in effect at t)."""
    r = db.one("SELECT config_json FROM protection_versions WHERE node_id=? AND created_at<=? ORDER BY version DESC LIMIT 1",
               (node_id, t))
    if r:
        cfg = json.loads(r["config_json"])
    else:
        n = db.one("SELECT settings_json FROM nodes WHERE node_id=?", (node_id,))       # what the agent was sent
        cfg = ((jl(n["settings_json"], {}) or {}).get("policy") or {}).get("protection") or {} if n else {}
    return next((x for x in cfg.get("rule") or [] if x.get("id") == rule_id), None)


def _live_at(db: DB, node_id: str, t: float) -> int:
    return db.one("SELECT COUNT(*) n FROM attempts WHERE node_id=? AND granted_at<=? AND (ended_at IS NULL OR ended_at>?)",
                  (node_id, t, t))["n"]


def s18_rules_enforced(db: DB, since: float = 0.0):
    """S18: after a rule becomes active, the fleet satisfies its constraint within enter_for_s + 2 samples: the
    node's combined constraint is at least as strict as the rule's cap, an evict scope is in force (or its
    attempts were released), and a pause/lower reached every fleet attempt (or none was live). Reserve and
    protect targets are budget-driven (one L1 interval) and checked by the agent's own tests, not here.
    Records newer than the node's journal horizon minus the window are not judged yet (Unknown)."""
    out = []
    for n in db.q("SELECT node_id, MAX(t) horizon FROM protection_decisions WHERE t>=? GROUP BY node_id", (since,)):
        nid, horizon = n["node_id"], n["horizon"] or 0
        recs = db.q("SELECT seq, t, kind, rule, record_json FROM protection_decisions WHERE node_id=? AND t>=? ORDER BY t, seq",
                    (nid, since - 3600))
        ts = [r["t"] or 0 for r in recs]
        cons_idx = [i for i, r in enumerate(recs) if r["kind"] == "constraint"]
        cons_t = [ts[i] for i in cons_idx]
        for a in recs:
            if a["kind"] != "rule_active" or (a["t"] or 0) < since or (a["t"] or 0) > horizon - S18_WINDOW_S:
                continue
            t0, t1, rid = a["t"], a["t"] + S18_WINDOW_S, a["rule"]
            rule = _rule_at(db, nid, rid, t0)
            if not rule:
                continue
            window = recs[bisect.bisect_left(ts, t0):bisect.bisect_right(ts, t1)]
            if any(r["kind"] == "rule_inactive" and r["rule"] == rid for r in window):
                continue
            kinds = {r["kind"] for r in window}
            k = bisect.bisect_right(cons_t, t1)
            c = (json.loads(recs[cons_idx[k - 1]]["record_json"] or "{}").get("constraint") or {}) if k else {}
            miss = []
            cap = rule.get("cap_fleet") or {}
            for dim in CAP_DIMS:
                if cap.get(dim) is None:
                    continue
                if dim == "slots" and cap[dim] == 0 and cap.get("pools") and c.get("pool_jobs_only") is not None:
                    continue
                got = c.get(dim)
                if dim == "slots" and cap[dim] == 0 and c.get("no_admit"):
                    continue
                if got is None or got > cap[dim] + 1e-9:
                    miss.append(f"{dim} {got} > {cap[dim]}")
            ev = rule.get("evict")
            if ev is not None and not ({(ev or {}).get("scope", "all"), "all"} & set(c.get("evict") or [])) \
                    and "attempt_evicted" not in kinds:
                miss.append("evict not in force")
            if rule.get("pause_fleet") is not None and not (kinds & {"attempt_paused", "attempt_evicted"}) \
                    and _live_at(db, nid, t1):
                miss.append("no fleet attempt paused")
            if rule.get("lower_fleet") is not None and not (kinds & {"attempt_lowered", "attempt_paused", "attempt_evicted"}) \
                    and _live_at(db, nid, t1):
                miss.append("no fleet attempt lowered")
            if miss:
                out.append(f"S18 node {nid} journal #{a['seq']}: rule {rid} active at {t0:.0f}, not enforced within "
                           f"{S18_WINDOW_S:.0f} s ({'; '.join(miss)})")
    return out


S25_LIMIT_S = 0.1        # docs/design/gpu-cotenancy.md: the pause request within 100 ms of the source event


def s25_immediate_phases_pause_at_once(db: DB, since: float = 0.0):
    """S25: an immediate rule's phase that the event path saw begin (`phase_change` PROTECTION_PHASE_ON via watch,
    helper or exec) and that paused fleet work (an `attempt_paused` naming the phase within the S18 window) was paused
    first by the event path (the record carries the source event's time), within 100 ms of the event. A phase first
    read by a tick (via poll: the rule was not armed, or the agent just started) is S18's to judge."""
    out = []
    for n in db.q("SELECT DISTINCT node_id FROM protection_decisions WHERE kind='phase_change' AND t>=?", (since,)):
        nid = n["node_id"]
        recs = db.q("SELECT seq, t, kind, reason, rule, record_json FROM protection_decisions WHERE node_id=? AND t>=? "
                    "AND kind IN ('phase_change','attempt_paused') ORDER BY t, seq", (nid, since))
        pauses = [(r, json.loads(r["record_json"] or "{}")) for r in recs if r["kind"] == "attempt_paused"]
        for r in recs:
            if r["reason"] != "PROTECTION_PHASE_ON":
                continue
            rec = json.loads(r["record_json"] or "{}")
            if rec.get("via") not in ("watch", "helper", "exec"):
                continue
            rule = _rule_at(db, nid, r["rule"], r["t"] or 0)
            if not rule or not rule.get("immediate"):
                continue
            block = rec.get("block")
            blocks = rule.get("during") or []
            if not isinstance(block, int) or block >= len(blocks) or blocks[block].get("pause_fleet") is None:
                continue
            key, t0 = f"{r['rule']}#{block}", r["t"] or 0
            mine = [(p, d) for p, d in pauses if key in (d.get("rules") or []) and t0 - 1 <= (p["t"] or 0) <= t0 + S18_WINDOW_S]
            if not mine:
                continue                                   # nothing pausable was in the phase's scope
            first, d = mine[0]
            ev = d.get("event_t")
            if ev is None:
                out.append(f"S25 node {nid} journal #{r['seq']}: phase {key} began at {t0:.3f}, but the first pause came "
                           f"from a tick at {first['t']:.3f}, not the event path")
            elif (first["t"] or 0) - float(ev) > S25_LIMIT_S:
                out.append(f"S25 node {nid} journal #{first['seq']}: phase {key} paused {((first['t'] or 0) - float(ev)) * 1000:.0f} "
                           f"ms after its source event (limit {S25_LIMIT_S * 1000:.0f} ms)")
    return out


S28_EVICT_S = 60.0      # a unit the governor stops has ended within a minute (its runner's stop grace and a heartbeat)


def s28_gpu_duty_within_ceiling_and_enforced(db: DB, since: float = 0.0, now: float | None = None):
    """S28: every `gpu_duty` record (the governor's budget steps) has a duty at most its ceiling; every
    GPU_DUTY_EXCEEDED or GPU_DUTY_UNVERIFIED record whose action is `paused` names an attempt that an `attempt_paused`
    record of the same node covers within the S18 window (or that ended by then), and one whose action is `evicted` an
    attempt that is no longer live a minute later."""
    t_now = time.time() if now is None else now
    out = []
    for r in db.q("SELECT node_id, seq, t, record_json FROM protection_decisions WHERE kind='gpu_duty' AND t>=?", (since,)):
        rec = json.loads(r["record_json"] or "{}")
        d, c = rec.get("duty"), rec.get("ceiling")
        if d is not None and c is not None and float(d) > float(c) + 1e-9:
            out.append(f"S28 node {r['node_id']} journal #{r['seq']}: GPU duty budget {d} above the certified ceiling {c}")
    for r in db.q("SELECT node_id, seq, t, reason, record_json FROM protection_decisions WHERE kind='gpu_compliance' "
                  "AND t>=?", (since,)):
        rec = json.loads(r["record_json"] or "{}")
        aid, action, t0 = rec.get("attempt"), rec.get("action"), r["t"] or 0
        if rec.get("workload"):
            # a workload: its ladder pauses it (workload_paused) or stops and holds it (workload_held), naming its key
            kinds = ("workload_paused", "workload_held") if action == "paused" else ("workload_held",)
            acts = db.q(f"SELECT record_json FROM protection_decisions WHERE node_id=? AND kind IN ({','.join('?' * len(kinds))}) "
                        "AND t>=? AND t<=?", (r["node_id"], *kinds, t0 - 1, t0 + S18_WINDOW_S))
            if not any(json.loads(x["record_json"] or "{}").get("workload") == rec["workload"] for x in acts) \
                    and t_now - t0 > S18_WINDOW_S:
                what = "paused" if action == "paused" else "stopped"
                out.append(f"S28 node {r['node_id']} journal #{r['seq']}: {r['reason']} {what} workload {rec['workload']}, "
                           f"but its ladder did not within {S18_WINDOW_S:.0f} s")
            continue
        if aid is None:
            continue
        att = db.one("SELECT state, ended_at FROM attempts WHERE attempt_id=?", (aid,))
        ended = att is not None and att["ended_at"] is not None
        if action == "paused":
            if ended and (att["ended_at"] or 0) <= t0 + S18_WINDOW_S:
                continue
            pauses = db.q("SELECT record_json FROM protection_decisions WHERE node_id=? AND kind='attempt_paused' "
                          "AND t>=? AND t<=?", (r["node_id"], t0 - 1, t0 + S18_WINDOW_S))
            if not any(aid in (json.loads(p["record_json"] or "{}").get("attempts") or []) for p in pauses) \
                    and t_now - t0 > S18_WINDOW_S:
                out.append(f"S28 node {r['node_id']} journal #{r['seq']}: {r['reason']} held attempt {aid}, but no pause "
                           f"of it followed within {S18_WINDOW_S:.0f} s")
        elif action == "evicted" and att is not None and att["state"] == "live" and t_now - t0 > S28_EVICT_S:
            out.append(f"S28 node {r['node_id']} journal #{r['seq']}: {r['reason']} stopped attempt {aid}, which is still "
                       f"live {t_now - t0:.0f} s later")
    return out


def s20_units_stay_in_their_class(db: DB):
    bound = {r["unit"]: r for r in db.q("SELECT unit, parent, mix, class FROM placement_bindings")}

    def misses(unit, platform):
        out, b = [], bound.get(unit)
        while b is not None:
            if b["class"] is not None and (not platform or pf.class_key(platform, b["mix"]) != b["class"]):
                out.append(f"{b['unit']} is bound to {b['class']}")
            b = bound.get(b["parent"])
        return out
    out = []
    for r in db.q("SELECT a.attempt_id, j.job_id, j.placement_unit u, n.platform FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                  "JOIN nodes n ON n.node_id=a.node_id WHERE a.state='live' AND j.placement_unit IS NOT NULL"):
        out += [f"S20 job {r['job_id']} runs on {r['platform']} (attempt {r['attempt_id']}) but {m}" for m in misses(r["u"], r["platform"])]
    for r in db.q("SELECT j.job_id, j.placement_unit u, rs.platform, rs.result_id FROM jobs j JOIN results rs "
                  "ON rs.result_id=j.canonical_result_id WHERE j.state='done' AND j.placement_unit IS NOT NULL"):
        out += [f"S20 job {r['job_id']} is done with result {r['result_id']} from {r['platform']} but {m}"
                for m in misses(r["u"], r["platform"])]
    return out


def s21_unreplicated_never_compared(db: DB):
    """S21: a job of a stage that does not compare (determinism none) never has a replica, a dispute or a golden, and
    never shares a canonical result with another job through the cache. Each row is judged by the module version that
    produced the result involved (the catalogue's manifests)."""
    from . import modcalls
    out = []
    no = lambda r, stage, ver: not modcalls.compares(r["module"], stage, ver)
    for r in db.q("SELECT j.job_id, j.module, j.stage, r.module_version FROM jobs j JOIN results r ON r.job_id=j.job_id "
                  "WHERE j.kind='golden'"):
        if no(r, r["stage"], r["module_version"]):
            out.append(f"S21 golden job {r['job_id']} ({r['module']}) ran stage {r['stage']}, which does not compare")
    for r in db.q("SELECT rj.job_id, rj.module, o.stage, cr.module_version FROM jobs rj "
                  "JOIN jobs o ON o.job_id=json_extract(rj.dispute_json, '$.replica_of') "
                  "JOIN results cr ON cr.result_id=o.canonical_result_id WHERE rj.kind='replica'"):
        if no(r, r["stage"], r["module_version"]):
            out.append(f"S21 replica job {r['job_id']} ({r['module']}) re-runs stage {r['stage']}, which does not compare")
    for r in db.q("SELECT j.job_id, j.module, j.stage, j.dispute_json FROM jobs j WHERE j.kind!='replica' "
                  "AND json_extract(j.dispute_json, '$.results') IS NOT NULL"):
        ids = (json.loads(r["dispute_json"]) or {}).get("results") or []
        vers = [x["module_version"] for x in db.q(f"SELECT module_version FROM results WHERE result_id IN "
                                                  f"({','.join('?' * len(ids))})", ids)] if ids else []
        if any(no(r, r["stage"], v) for v in vers):
            out.append(f"S21 job {r['job_id']} ({r['module']}) is disputed, but its stage {r['stage']} does not compare")
    for r in db.q("SELECT j.job_id, j.module, j.stage, cj.job_id cid, cj.stage cstage, rs.module_version FROM jobs j "
                  "JOIN results rs ON rs.result_id=j.canonical_result_id JOIN jobs cj ON cj.job_id=rs.job_id "
                  "WHERE j.state='done' AND cj.job_id!=j.job_id"):
        if no(r, r["stage"], r["module_version"]) or no(r, r["cstage"], r["module_version"]):
            out.append(f"S21 job {r['job_id']} shares job {r['cid']}'s canonical result through the cache, but a stage that "
                       "does not compare is involved")
    return out


def s22_bootstrap_results_are_pinned(db: DB):
    """S22: a bootstrap job's canonical result is exactly pinned datasets of the module version that produced it (an empty
    payload; artifacts that each hold one pin's files), judged by the catalogue's manifests."""
    out = []
    for r in db.q("SELECT j.job_id, j.module, j.stage, r.result_id, r.module_version, r.result_json FROM jobs j "
                  "JOIN results r ON r.result_id=j.canonical_result_id WHERE j.state='done' AND j.stage IS NOT NULL "
                  "AND r.job_id=j.job_id"):
        man = _manifest(r["module"], r["module_version"])
        if man is None or not man.is_bootstrap(r["stage"]):
            continue
        res = json.loads(r["result_json"] or "{}") or {}
        problem = man.bootstrap_problem(res.get("payload"), res.get("artifacts") or [])
        if problem:
            out.append(f"S22 bootstrap job {r['job_id']} ({r['module']}) has canonical result {r['result_id']}: {problem}")
    return out


def s23_resume_from_own_checkpoint(db: DB):
    """S23: an attempt that resumed from a checkpoint (resume_json) resumed from one an earlier attempt of the same job
    wrote, under the same job generation, on the node it names."""
    out = []
    for a in db.q("SELECT a.attempt_id, a.job_id, a.generation, a.resume_json, w.attempt_id w_id, w.job_id w_job, "
                  "w.generation w_gen, w.node_id w_node FROM attempts a LEFT JOIN attempts w ON "
                  "w.attempt_id=json_extract(a.resume_json, '$.from_attempt') WHERE a.resume_json IS NOT NULL"):
        r = json.loads(a["resume_json"])
        if a["w_id"] is None or a["w_job"] != a["job_id"] or a["w_gen"] != a["generation"] or a["w_id"] >= a["attempt_id"] \
                or a["w_node"] != r.get("node_id"):
            out.append(f"S23 attempt {a['attempt_id']} of job {a['job_id']} (generation {a['generation']}) resumed from attempt "
                       f"{r.get('from_attempt')}, which is not an earlier attempt of that job and generation on {r.get('node_id')}")
    return out


def s24_listeners_granted_and_assigned(db: DB):
    """S24 (docs/design/inbound-listeners.md): a listener or router mapping a node reports is granted, assigned by the
    node's statement and part of the statement it applied."""
    from . import listeners
    return listeners.s24_violations(db)


def s26_single_seat(db: DB):
    """S26: at most one node runs a seat of a per-node workload identity at a time (workloads.py)."""
    from .workloads import s26_single_seat as check
    return check(db)
def s27_site_uplink_budget(db: DB):
    """S27 (docs/design/sites.md): the live leases a site holds stay within its budget and none is live while it holds
    (grants also count revoked leases not yet given back, so a lowered budget is reached within one renewal). Leases past their expiry are dead (the agent stopped by its
    own clock before it) and do not count."""
    from . import clock
    t, out = clock.now(), []
    for s in db.q("SELECT * FROM sites"):
        # live leases: unexpired and unrevoked (a revoked one keeps its slot for new grants until given back, but a budget
        # lowered under it revokes it, so it is no longer the site's to count here)
        rows = db.q("SELECT mbps FROM uplink_leases WHERE site_id=? AND expires_at>=? AND revoked_at IS NULL", (s["site_id"], t))
        if len(rows) > s["max_transfers"]:
            out.append(f"S27 site {s['name']}: {len(rows)} live transfer leases, budget {s['max_transfers']}")
        total = sum(r["mbps"] or 0 for r in rows)
        if s["uplink_mbps"] and total > s["uplink_mbps"] + 1e-6:
            out.append(f"S27 site {s['name']}: leases pace at {total:g} Mbit/s together, budget {s['uplink_mbps']:g}")
        live = db.one("SELECT COUNT(*) n FROM uplink_leases WHERE site_id=? AND expires_at>=? AND revoked_at IS NULL",
                      (s["site_id"], t))["n"]
        if s["hold_on"] and live:
            out.append(f"S27 site {s['name']}: {live} live transfer lease(s) while it holds ({s['hold_why']})")
    return out


def s29_rollout_cap(db: DB):
    """S29 (docs/design/fleet-updates.md): a rollout ring's busy nodes never exceed its max_unavailable."""
    from .rollouts import s29_violations
    return s29_violations(db)


def s30_no_node_ahead_of_coordinator(db: DB):
    """S30: nothing newer than the coordinator is assigned or installed, and rings run in order."""
    from .rollouts import s30_violations
    return s30_violations(db)


def s31_go_only_when_eligible(db: DB):
    """S31: every update grant was made while the node was eligible (the rollout journal)."""
    from .rollouts import s31_violations
    return s31_violations(db)


SAFETY = [s1_single_canonical, s2_done_has_canonical, s3_canonical_current_generation, s4_no_lost_job,
          s5_no_live_on_settled, s6_accepted_iff_canonical, s7_live_on_ready_nodes, s8_live_module_certified,
          s9_attempt_bookkeeping, s10_failure_accounting, s11_hard_job_caps,
          s12_live_only_on_ready_inputs, s13_done_on_done_input, s14_canonical_module_verdict,
          s15_module_faults_not_charged, s16_actuation_only_on_spawned, s17_no_admission_under_memory_floor,
          s18_rules_enforced, s20_units_stay_in_their_class, s21_unreplicated_never_compared,
          s22_bootstrap_results_are_pinned, s23_resume_from_own_checkpoint, s24_listeners_granted_and_assigned,
          s25_immediate_phases_pause_at_once, s26_single_seat,
          s28_gpu_duty_within_ceiling_and_enforced, s27_site_uplink_budget, s29_rollout_cap,
          s30_no_node_ahead_of_coordinator, s31_go_only_when_eligible]


def check_all(db: DB) -> list[str]:
    out = []
    for fn in SAFETY:
        out.extend(fn(db))
    return out


def l1_all_settled(db: DB, campaign_id: str | None = None) -> list[str]:
    q = "SELECT job_id, state FROM jobs WHERE state NOT IN ('done','cancelled','quarantined','failed')"
    args = ()
    if campaign_id:
        q += " AND campaign_id=?"
        args = (campaign_id,)
    return _v(db.q(q, args), "L1 job {job_id} never settled (state {state})")


def health(db: DB, now: float) -> list[str]:
    """Operational warnings (not protocol violations): silent nodes, open alerts, stuck work."""
    out = []
    for n in db.q("SELECT hostname, lifecycle, last_heartbeat_at, modules_json, capacity_json FROM nodes "
                  "WHERE lifecycle NOT IN ('retired')"):
        age = now - (n["last_heartbeat_at"] or 0)
        cap = jl(n["capacity_json"], {}) or {}
        if not cap.get("admit", True):
            out.append(f"info: node {n['hostname']} not admitting work (binding limit: {cap.get('binding_limit')})")
            continue
        if n["lifecycle"] == "ready" and age > 120:
            out.append(f"node {n['hostname']} silent for {int(age)} s")
        if n["lifecycle"] == "quarantined":
            out.append(f"node {n['hostname']} is quarantined")
        for m, st in (jl(n["modules_json"], {}) or {}).items():
            if st.get("state") not in ("certified", None):
                out.append(f"node {n['hostname']}: {m} is {st.get('state')}" + (f" ({st['reason']})" if st.get("reason") else ""))
    for a in db.q("SELECT rule, subject, detail FROM alerts WHERE state='open'"):
        out.append(f"alert {a['rule']} [{a['subject']}]: {a['detail']}")
    stale = db.one("SELECT COUNT(*) n FROM attempts WHERE state='live' AND expires_at < ?", (now - 60,))["n"]
    if stale:
        out.append(f"{stale} live attempts past their lease by >60 s (reaper not running?)")
    alive = db.get_state("alive_at")
    if alive and now - float(alive) > 60:
        out.append(f"oarbankd background loop last ran {int(now - float(alive))} s ago")
    return out


def conditions(db: DB, now: float) -> list[dict]:
    """Every safety invariant as a condition record (True = good), for the console's Verify page."""
    out = []
    for fn in SAFETY:
        ident = fn.__name__.split("_", 1)[0].upper()
        try:
            v = fn(db)
            status, msg = ("True", "") if not v else ("False", f"{len(v)} violation(s): {v[0]}")
        except Exception as e:                   # a check that cannot run is Unknown, never assumed healthy
            status, msg = "Unknown", f"{type(e).__name__}: {e}"
        reason = {"True": "OK", "False": "INVARIANT_VIOLATED"}.get(status, "INVARIANT_UNKNOWN")
        out.append({"id": ident, "name": fn.__name__, "status": status, "reason": reason,
                    "message": msg[:300], "checked_at": now})
    return out


def report(db: DB, now: float | None = None) -> dict:
    import time
    v = check_all(db)
    return {"ok": not v, "violations": v, "checked": [f.__name__ for f in SAFETY],
            "warnings": health(db, now if now is not None else time.time()),
            "jobs": {r["state"]: r["n"] for r in db.q("SELECT state, COUNT(*) n FROM jobs GROUP BY state")}}


if __name__ == "__main__":
    import sys
    from . import config as C, modcalls
    db = DB(C.DB_PATH)
    modcalls.use(db)                             # S8, S21 and S22 read the modules' manifests
    print(json.dumps(report(db), indent=1))
    sys.exit(0)
