"""Hypothesis stateful test: random interleavings of every protocol action against the real
coordinator core, with the full invariant catalogue checked after every step.

This is the "model-based" layer of the verification plan (docs/verification.md): the agent-side
behaviours (outbox replays, late completions after sleep, restarts, hard-cap enforcement,
nondeterministic nodes) are generated as actions; the coordinator is the real code. The fleet is mixed (darwin-arm64,
linux-amd64, linux-arm64), and studies may keep their units of work on one platform class (placement, D33; S20).
"""
import json
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule

from oarbank.coordinator import clock, core, invariants, modcalls, placement
from oarbank.sim import _cfg

from helpers import (create_study, SCENES, MODE, PARAMS, READY, certify, enrolled_node, facts_for, fresh, golden_result,
                     make_db, relay_result)

FLEET = (("mini", None), ("box", "linux-amd64"), ("arm", "linux-arm64"))

NON_FAILURE = sorted(core.NON_FAILURE_RELEASES)


class CoordinatorMachine(RuleBasedStateMachine):
    @initialize()
    def setup(self):
        clock.set_fake(1_900_000_000.0)
        self.tmp = tempfile.TemporaryDirectory()
        self.db = make_db(Path(self.tmp.name) / "oarbank.sqlite3")
        self.nodes = [certify(self.db, enrolled_node(self.db, name, facts=facts_for(p, os_version="6.8") if p else None)[1])
                      for name, p in FLEET]
        self.sid = create_study(self.db, "prop", [{"label": "c1", "params": {**PARAMS, "samples": 25}}],
                                        SCENES[:3], {"label": "base", "params": PARAMS})
        self.attempts = []          # (attempt_id, node_index)
        self.completed_ok = set()   # attempts the coordinator acknowledged (for outbox replays)
        self.cpu = {}               # attempt -> reported cpu seconds

    def teardown(self):
        clock.set_fake(None)
        modcalls.close_host(self.db)        # each example's module processes go now, not at some later collection
        self.db.conn.close()
        self.tmp.cleanup()

    def node(self, i):
        return fresh(self.db, self.nodes[i % len(self.nodes)])

    # ------------------------------------------------------------------ agent actions
    @rule(i=st.integers(0, 2), free=st.integers(1, 6))
    def claim(self, i, free):
        n = self.node(i)
        if n["lifecycle"] != "ready":
            return
        for g in core.claim(self.db, n, {"free_cpu": free, "free_mem_gb": 64, "ready_datasets": READY})["grants"]:
            self.attempts.append((g["attempt_id"], i % len(self.nodes)))

    @precondition(lambda self: self.attempts)
    @rule(k=st.integers(0, 10 ** 6), variant=st.sampled_from(["good", "good", "good", "replay", "mode_bad", "nondet"]))
    def complete(self, k, variant):
        aid, i = self.attempts[k % len(self.attempts)]
        a = self.db.one("SELECT a.*, j.dataset_id, j.spec_json, j.kind, j.module, j.stage FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
                        "WHERE a.attempt_id=?", (aid,))
        if a["kind"] == "golden":      # re-certification after a revoke: answer with the golden result
            try:
                core.complete(self.db, self.node(i), aid, golden_result(
                    {"module": a["module"], "spec": {"payload": json.loads(a["spec_json"]), "stage": a["stage"]}}, self.db))
            except core.ApiError:
                pass
            return
        # deterministic per (config, dataset): a healthy node always reproduces the same result
        a["config_key"] = _cfg(a["spec_json"])
        score = f"0.{800000 + hash((a['config_key'], a['dataset_id'])) % 99999:06d}"
        image = f"frame-{a['config_key'][:8]}-{a['dataset_id']}"
        n = self.node(i)
        try:
            if variant == "mode_bad":
                core.complete(self.db, n, aid, relay_result(score=score, image=image,
                              mode={**MODE, "sampler": "random"}) | {"idempotency_key": f"k{aid}-bad"})
            elif variant == "nondet":
                core.complete(self.db, n, aid, relay_result(score="0.123456", image="different") | {"idempotency_key": f"k{aid}-nd"})
            else:
                r1 = core.complete(self.db, n, aid, relay_result(score=score, image=image))
                if variant == "replay":   # the outbox retries after a lost acknowledgement
                    assert core.complete(self.db, n, aid, relay_result(score=score, image=image)) == r1
        except core.ApiError:
            pass

    @precondition(lambda self: self.attempts)
    @rule(k=st.integers(0, 10 ** 6), reason=st.sampled_from(["exit_nonzero", "oom", "timeout", "no_metrics"]))
    def fail(self, k, reason):
        aid, i = self.attempts[k % len(self.attempts)]
        core.fail(self.db, self.node(i), aid, {"reason": reason})

    @precondition(lambda self: self.attempts)
    @rule(k=st.integers(0, 10 ** 6), reason=st.sampled_from(NON_FAILURE))
    def release(self, k, reason):
        aid, i = self.attempts[k % len(self.attempts)]
        core.release(self.db, self.node(i), aid, reason)

    @rule(i=st.integers(0, 2), progress=st.booleans())
    def heartbeat(self, i, progress):
        n = self.node(i)
        live = self.db.q("SELECT attempt_id FROM attempts WHERE node_id=? AND state='live'", (n["node_id"],))
        rep = []
        for a in live:
            self.cpu[a["attempt_id"]] = self.cpu.get(a["attempt_id"], 0.0) + (5.0 if progress else 0.0)
            rep.append({"attempt_id": a["attempt_id"], "phase": "render", "cpu_s": self.cpu[a["attempt_id"]], "log_bytes": 0})
        core.heartbeat(self.db, n, {"attempts": rep, "ready_datasets": READY})

    @rule(i=st.integers(0, 2))
    def agent_restart(self, i):
        n = self.node(i)
        core.hello(self.db, n, {"release_id": n["release_id"], "live_attempts": [], "ready_datasets": READY})

    @rule(i=st.integers(0, 2), cap=st.integers(1, 3))
    def hard_cap(self, i, cap):
        """User sets a hard jobs cap; the agent releases youngest attempts to fit (its contract)."""
        n = self.node(i)
        core.set_limits(self.db, n["node_id"], {"jobs": cap, "enforce": "hard"}, "prop")
        live = self.db.q("SELECT attempt_id FROM attempts WHERE node_id=? AND state='live' ORDER BY granted_at DESC",
                         (n["node_id"],))
        for a in live[:max(0, len(live) - cap)]:
            core.release(self.db, n, a["attempt_id"], "limit_cpu")

    @rule(i=st.integers(0, 2))
    def clear_caps(self, i):
        core.set_limits(self.db, self.node(i)["node_id"], {}, "prop", clear_all=True)

    # ------------------------------------------------------------------ time + coordinator
    @rule(dt=st.floats(1, 200))
    def advance_and_reap(self, dt):
        clock.advance(dt)
        core.reap(self.db)

    @rule(outage=st.floats(0, 600))
    def coordinator_restart(self, outage):
        clock.advance(outage)
        self.db.x("UPDATE attempts SET expires_at=expires_at+?, hard_deadline=hard_deadline+? WHERE state='live'",
                  (outage + 60.0, outage))

    # ------------------------------------------------------------------ user actions
    @rule(k=st.integers(0, 10 ** 6))
    def retry(self, k):
        jobs = self.db.q("SELECT job_id FROM jobs WHERE campaign_id=? AND state IN ('done','failed','quarantined','cancelled')",
                         (self.sid,))
        if jobs:
            core.retry_job(self.db, jobs[k % len(jobs)]["job_id"], "prop")

    @rule(k=st.integers(0, 10 ** 6))
    def cancel(self, k):
        jobs = self.db.q("SELECT job_id FROM jobs WHERE campaign_id=? AND state IN ('pending','leased')", (self.sid,))
        if jobs:
            core.cancel_job(self.db, jobs[k % len(jobs)]["job_id"], "prop")

    @rule(bq=st.sampled_from([10, 25]))
    def overlapping_study(self, bq):
        """A second study sharing configs and datasets: its jobs are result-cache hits (or pending
        twins), which every invariant must accept."""
        create_study(self.db, f"dup{bq}", [{"label": "c1", "params": {**PARAMS, "samples": bq}}],
                             SCENES[:3], {"label": "base", "params": PARAMS})

    @rule(mix=st.sampled_from(["same-os", "same-arch", "same-platform"]), unit=st.sampled_from(["campaign", "group"]),
          bind=st.sampled_from(["first-claim", "capacity", "explicit"]), pin=st.booleans())
    def placement_study(self, mix, unit, bind, pin):
        """A study whose units of work (the campaign, or each dataset's jobs) stay on one class: bound by first claim,
        by capacity, or waiting for a pin; or pinned now. Its keys overlap the other studies' (result-cache hits)."""
        pins = {"same-os": "linux", "same-arch": "arm64", "same-platform": "linux-amd64"}
        create_study(self.db, f"pl-{mix}-{unit}", [{"label": "c1", "params": {**PARAMS, "samples": 25}}], SCENES[:2],
                     {"label": "base", "params": PARAMS}, **({"group_by": "dataset"} if unit == "group" else {}),
                     placement={"mix": mix, "unit": unit, "bind": bind, **({"pin": pins[mix]} if pin else {})})

    @rule(k=st.integers(0, 10 ** 6), platform=st.sampled_from(["darwin-arm64", "linux-amd64", "linux-arm64"]))
    def rebind(self, k, platform):
        """campaigns.rebind_platform: a campaign's units move; their finished jobs run again in the new class."""
        cids = [r["campaign_id"] for r in self.db.q("SELECT DISTINCT campaign_id FROM placement_bindings ORDER BY campaign_id")]
        if cids:
            try:
                with self.db.tx():
                    placement.rebind_campaign(self.db, cids[k % len(cids)], platform)
            except placement.PlacementError:
                pass                                   # a class the campaign's work cannot run in

    @rule(mix=st.sampled_from(["same-os", "same-platform"]))
    def set_placement(self, mix):
        """campaigns.set_placement on the first study: refused once it has a result, else its units are derived again."""
        try:
            with self.db.tx():
                placement.set_mix(self.db, self.sid, mix)
        except placement.PlacementError:
            pass

    @rule(i=st.integers(0, 2))
    def quarantine(self, i):
        n = self.node(i)
        if n["lifecycle"] == "ready" and sum(1 for x in self.nodes if fresh(self.db, x)["lifecycle"] == "ready") > 1:
            core.quarantine(self.db, n["node_id"], "prop test", "prop")

    # ------------------------------------------------------------------ invariants
    @invariant()
    def safety(self):
        if hasattr(self, "db"):
            v = invariants.check_all(self.db)
            assert not v, "\n".join(v)


import os
CoordinatorMachine.TestCase.settings = settings(
    max_examples=1000 if os.environ.get("OARBANK_THOROUGH") else 150,
    stateful_step_count=100 if os.environ.get("OARBANK_THOROUGH") else 60, deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
TestCoordinatorProtocol = CoordinatorMachine.TestCase
