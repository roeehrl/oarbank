"""Hypothesis stateful test: random interleavings of every protocol action against the real
coordinator core, with the full invariant catalogue checked after every step.

This is the "model-based" layer of the verification plan (docs/verification.md): the agent-side
behaviours (outbox replays, late completions after sleep, restarts, hard-cap enforcement,
nondeterministic nodes) are generated as actions; the coordinator is the real code. The fleet is mixed (darwin-arm64,
linux-amd64, linux-arm64), studies may keep their units of work on one platform class (placement, D33; S20), and
ingestion jobs of a stage that does not compare run beside them (S21).
"""
import json
import sys
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule

from oarbank.common import sha256_hex
from oarbank.coordinator import clock, core, invariants, modcalls, placement
from oarbank.sim import _cfg

import helpers
from helpers import (create_study, SCENES, MODE, PARAMS, READY, certify, enrolled_node, facts_for, fresh, golden_result,
                     make_db, relay_result)
from helpers import settings_apply

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

    def campaigns(self, where: str) -> list[str]:
        """Campaign ids in creation order. The relay module names a study `s_<random hex>`, so an order by id would
        differ between two runs of the same steps: Hypothesis replays (and shrinks) a step sequence only if every rule
        draws the same way each time."""
        return [r["campaign_id"] for r in self.db.q(f"SELECT campaign_id FROM campaigns WHERE {where} ORDER BY rowid")]

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
        if a["stage"] == "sync":       # ingestion: what the feed held when this node ran it (honest runs differ)
            items = [f"r{x}" for x in range(k % 3 + i)]
            try:
                core.complete(self.db, self.node(i), aid, {"result": {
                    "envelope": 1, "schema": "relay/result@1", "module_version": "1.0.0", "protocol": 1,
                    "payload": {"items": items, "feed_sha": f"feed-{i}-{len(items)}"}}})
            except core.ApiError:
                pass
            return
        # deterministic per (config, dataset): a healthy node always reproduces the same result
        a["config_key"] = _cfg(a["spec_json"])
        score = f"0.{800000 + int(sha256_hex(a['config_key'] + a['dataset_id'])[:8], 16) % 99999:06d}"
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
        live = self.db.q("SELECT attempt_id FROM attempts WHERE node_id=? AND state='live' ORDER BY attempt_id",
                         (n["node_id"],))
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
        settings_apply(self.db, {"scope": "node", "scope_id": n["node_id"], "key": "jobs", "value": cap},
                       {"scope": "node", "scope_id": n["node_id"], "key": "enforce", "value": "hard"})
        live = self.db.q("SELECT attempt_id FROM attempts WHERE node_id=? AND state='live' ORDER BY granted_at DESC, attempt_id DESC",
                         (n["node_id"],))
        for a in live[:max(0, len(live) - cap)]:
            core.release(self.db, n, a["attempt_id"], "limit_cpu")

    @rule(i=st.integers(0, 2))
    def clear_caps(self, i):
        nid = self.node(i)["node_id"]
        if self.db.one("SELECT 1 FROM setting_values WHERE scope='node' AND scope_id=? AND key='jobs'", (nid,)):
            settings_apply(self.db, {"scope": "node", "scope_id": nid, "key": "jobs", "reset": True},
                           {"scope": "node", "scope_id": nid, "key": "enforce", "reset": True})

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
        jobs = self.db.q("SELECT job_id FROM jobs WHERE campaign_id=? AND state IN ('done','failed','quarantined','cancelled') "
                         "ORDER BY job_id", (self.sid,))
        if jobs:
            core.retry_job(self.db, jobs[k % len(jobs)]["job_id"], "prop")

    @rule(k=st.integers(0, 10 ** 6))
    def cancel(self, k):
        jobs = self.db.q("SELECT job_id FROM jobs WHERE campaign_id=? AND state IN ('pending','leased') ORDER BY job_id",
                         (self.sid,))
        if jobs:
            core.cancel_job(self.db, jobs[k % len(jobs)]["job_id"], "prop")

    @rule(bq=st.sampled_from([10, 25]))
    def overlapping_study(self, bq):
        """A second study sharing configs and datasets: its jobs are result-cache hits (or pending
        twins), which every invariant must accept."""
        create_study(self.db, f"dup{bq}", [{"label": "c1", "params": {**PARAMS, "samples": bq}}],
                             SCENES[:3], {"label": "base", "params": PARAMS})

    @rule(cursor=st.integers(0, 3), campaign=st.integers(0, 10 ** 6))
    def sync_job(self, cursor, campaign):
        """An ingestion job (relay's sync stage, determinism none) named by jobs.enqueue `stage`, into any campaign: its
        keys repeat across campaigns, so a result cache would be tempting, and its honest runs differ (S21)."""
        from oarbank_sdk import effects as fx
        from oarbank_sdk.keys import job_key
        from oarbank.coordinator import effects
        cids = self.campaigns("state!='cancelled'")
        payload = {"task": "sync", "cursor": cursor}
        key = job_key("dev.codonic.oarbank.relay", "relay1", payload, "sync")
        try:
            with self.db.tx():
                effects.apply(self.db, "relay", {"jobs.enqueue"}, [fx.jobs_enqueue(cids[campaign % len(cids)], [
                    fx.job(key, payload, stage="sync")]).model_dump()])
        except effects.EffectError:
            pass                                       # e.g. a pinned campaign's class where sync cannot run

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
        cids = self.campaigns("campaign_id IN (SELECT campaign_id FROM placement_bindings)")
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


# The machine once failed about 1 run in 16 with FlakyStrategyDefinition: it picked campaigns by id, and the relay module
# names a study `s_<random hex>`, so one step sequence acted on another campaign when replayed, a different claim
# followed, and a rule's precondition flipped. Found as these four steps (shrunk by replaying each candidate 10 times):
# whether the sync job joins the pinned linux-amd64 study or the first one decides what mini can claim.
COUNTEREXAMPLE = [("placement_study", {"mix": "same-platform", "unit": "group", "bind": "first-claim", "pin": True}),
                  ("sync_job", {"cursor": 0, "campaign": 810109}), ("heartbeat", {"i": 0, "progress": True}),
                  ("claim", {"i": 0, "free": 2})]


def _replay(monkeypatch, steps, ids):
    """Run `steps` on a fresh machine whose studies get the campaign ids `ids`, in creation order; the attempts after
    each step."""
    names = iter(ids)
    monkeypatch.setattr(sys.modules[__name__], "create_study",
                        lambda db, name, *a, **kw: helpers.create_study(db, name, *a, campaign_id=next(names), **kw))
    m = CoordinatorMachine()
    m.setup()
    try:
        out = []
        for rule_name, args in steps:
            getattr(m, rule_name)(**args)
            m.safety()
            out.append(list(m.attempts))
        return out
    finally:
        m.teardown()


def test_a_step_sequence_replays_the_same_whatever_the_campaign_ids(monkeypatch):
    """Hypothesis replays and shrinks a step sequence only if every rule draws and acts the same way each time: the
    counterexample's steps, with study ids ascending and then descending in creation order, end the same."""
    rising = _replay(monkeypatch, COUNTEREXAMPLE, ["s_00000001", "s_00000002"])
    assert _replay(monkeypatch, COUNTEREXAMPLE, ["s_ffffffff", "s_00000000"]) == rising


import os
CoordinatorMachine.TestCase.settings = settings(
    max_examples=1000 if os.environ.get("OARBANK_THOROUGH") else 150,
    stateful_step_count=100 if os.environ.get("OARBANK_THOROUGH") else 60, deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
TestCoordinatorProtocol = CoordinatorMachine.TestCase
