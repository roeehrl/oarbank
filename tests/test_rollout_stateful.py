"""Hypothesis stateful test of fleet rollouts (docs/design/fleet-updates.md; specs/OarbankRollout.tla): random fleets
(rings, update windows, holds, protected phases), offline periods, install outcomes (success, failure, a drain that
times out), the coordinator's own update (it succeeds or rolls back) and operator actions (start, pause, resume, halt,
roll back), against the real coordinator: the heartbeat path, the operations and the rollout tick.

After every step: S29 (no ring over its max_unavailable), S30 (no node assigned past the coordinator; rings in order),
S31 (every go granted while eligible, from the journal, and checked again here against the model's own view of
the node), and the TLA+ invariants HaltedStartsNothing (no new go while halted), BudgetHalts (after a tick, a running
rollout has no ring over its failure budget) and RolledBackIsOld (a rolled-back rollout left every node it moved on the
release it ran). At the end, a fair schedule (every node back, holds lifted, installs succeed, time passes) must bring
every rollout to done, halted or rolled_back.
"""
import hashlib
import json
import os
import sys
import tempfile
import types
from pathlib import Path

from hypothesis import HealthCheck, event, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule

from oarbank.coordinator import clock, core, fleetupdates as F, invariants, rollouts as RO

from helpers import enrolled_node, facts_for, fresh, make_db, run_op, set_node

OLD, NEW, NEXT = "2.9.0", "2.10.0", "2.11.0"
INSTALL = {"format": "tar", "scope": "system", "updater": True, "why": None}
WINDOWS = [None, {"start": "00:00", "end": "06:00"}, {"start": "22:00", "end": "02:00", "days": [5, 6]}]


def release_dir(d: Path, version: str) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    arts = []
    for p in sorted({"darwin-arm64", F.coordinator_platform()}):
        for role, name in (("node", f"oarbank-agent-{version}-{p}.tar.gz"), ("coordinator", f"oarbank-coordinator-{version}-{p}.tar.gz")):
            data = f"{name}\n".encode() * 20
            (d / name).write_bytes(data)
            arts.append({"name": name, "role": role, "platform": p, "format": "tar", "sha256": hashlib.sha256(data).hexdigest(),
                         "size": len(data)})
    a, b, c = (int(x) for x in version.split("."))
    doc = {"type": "oarbank-fleet-release", "format": 1, "version": version, "seq": a * 10000 + b * 100 + c, "expires": None,
           "agent_min": None, "stops": [], "artifacts": arts}
    (d / f"oarbank-fleet-{version}.json").write_text(json.dumps(doc, sort_keys=True, separators=(",", ":")))
    return d


class RolloutMachine(RuleBasedStateMachine):
    @initialize(rings=st.lists(st.sampled_from([None, "canary", "early", "broad"]), min_size=2, max_size=5),
                windows=st.lists(st.sampled_from(range(len(WINDOWS))), min_size=5, max_size=5),
                release=st.sampled_from([NEW, NEW, NEXT]), start_now=st.sampled_from([True, True, True, False]))
    def setup(self, rings, windows, release, start_now):
        clock.set_fake(1_800_000_000.0)
        self.tmp = tempfile.TemporaryDirectory()
        self.db = make_db(Path(self.tmp.name) / "oarbank.sqlite3", modules=())
        self.coord = NEW                                   # the coordinator's own version (it may update itself)
        self._saved = (F.coordinator_version, sys.modules.get("oarbank.coordinator.coordself"), RO._spawn)
        F.coordinator_version = lambda: self.coord
        RO._spawn = lambda fn: None                       # the periodic check never reaches the network here
        fake = types.ModuleType("oarbank.coordinator.coordself")
        from oarbank.coordinator.coordself import SCHEMA
        fake.SCHEMA = SCHEMA                    # a DB opened on another thread makes its table
        fake.current = None

        def request(db, version, actor):
            fake.current = {"state": "requested", "version": version}
            return fake.current
        fake.request, fake.state = request, lambda db: fake.current
        self.coordself = fake
        sys.modules["oarbank.coordinator.coordself"] = fake
        self.target = release
        self.nodes, self.window, self.held, self.online, self.phase, self.agents = [], [], [], [], [], []
        self.reported_phase = []
        for i, ring in enumerate(rings):
            _, n = enrolled_node(self.db, f"n{i}", {**facts_for("darwin-arm64"), "utc_offset_s": 0})
            self.nodes.append(n)
            self.window.append(WINDOWS[windows[i]])
            self.held.append(False)
            self.online.append(True)
            self.phase.append(False)
            self.reported_phase.append(False)
            self.agents.append({"state": "idle", "release": None})
            core.hello(self.db, fresh(self.db, n), {"agent_version": OLD, "facts": json.loads(fresh(self.db, n)["facts_json"]),
                                                    "live_attempts": [], "install": INSTALL})
            if ring:
                set_node(self.db, n["node_id"], "update_ring", ring)
            if self.window[i]:
                set_node(self.db, n["node_id"], "update_window", self.window[i])
        for v in (OLD, NEW, NEXT):
            F.import_dir(self.db, release_dir(Path(self.tmp.name) / v, v), "test")
        self.halted_grants: dict = {}
        self.grants_seen: set = set()
        if start_now:
            self.start(False, None, True, None)

    def teardown(self):
        if hasattr(self, "db"):
            try:
                self.settle()
            finally:
                F.coordinator_version, saved, RO._spawn = self._saved
                if saved is None:
                    sys.modules.pop("oarbank.coordinator.coordself", None)
                else:
                    sys.modules["oarbank.coordinator.coordself"] = saved
                clock.set_fake(None)
                self.db.conn.close()
                self.tmp.cleanup()

    # ------------------------------------------------------------------ the agents
    def node(self, i):
        return fresh(self.db, self.nodes[i % len(self.nodes)])

    def beat(self, i, report=None):
        tel = {"protection": {"phases": [{"key": "p", "on": True}]}} if self.phase[i] else {}
        body = {"attempts": [], "install": INSTALL, "telemetry": tel}
        ag = self.agents[i]
        if report is None and ag["release"]:             # an agent reports where it is on every heartbeat
            st = {"failed": "rolled_back"}.get(ag["state"], ag["state"])
            report = self.report(st, ag["release"])
        if report:
            body["node_update"] = report
        self.reported_phase[i] = self.phase[i]
        return core.heartbeat(self.db, self.node(i), body)

    def report(self, state, release, error=None):
        return {"state": state, "release": release, "seq": 1, "error": error, "at": clock.now()}

    def agent_step(self, i, outcome):
        """What the node's agent (and its runner) do next for its directive."""
        if not self.online[i]:
            return
        ag = self.agents[i]
        d = self.beat(i)["node_update"]
        if not d:
            self.agents[i] = {"state": "idle", "release": None}
            return
        if ag["release"] != d["release"]:
            self.agents[i] = ag = {"state": "staged", "release": d["release"]}
            self.beat(i, self.report("staged", d["release"]))
        elif ag["state"] == "staged" and d["go"]:
            ag["state"] = "draining"
            self.beat(i, self.report("draining", d["release"]))
        elif ag["state"] == "draining":
            ag["state"] = "staged" if outcome == "defer" else "installing"
            self.beat(i, self.report("deferred" if outcome == "defer" else "installing", d["release"]))
        elif ag["state"] == "installing":
            if outcome == "fail":
                ag["state"] = "failed"
                self.beat(i, self.report("rolled_back", d["release"], "the new agent never confirmed"))
            else:
                core.hello(self.db, self.node(i), {"agent_version": d["release"], "facts": json.loads(self.node(i)["facts_json"]),
                                                   "live_attempts": [], "install": INSTALL,
                                                   "node_update": self.report("confirming", d["release"])})
                self.beat(i, self.report("done", d["release"]))
                self.agents[i] = {"state": "idle", "release": None}

    @rule(i=st.integers(0, 4), outcome=st.sampled_from(["ok", "ok", "ok", "fail", "defer"]))
    def agent(self, i, outcome):
        self.agent_step(i % len(self.nodes), outcome)

    @rule(outcome=st.sampled_from(["ok", "ok", "fail", "defer"]))
    def every_agent(self, outcome):
        for i in range(len(self.nodes)):
            self.agent_step(i, outcome)

    @rule(i=st.integers(0, 4))
    def go_offline(self, i):
        self.online[i % len(self.nodes)] = False

    @rule(i=st.integers(0, 4))
    def come_back(self, i):
        self.online[i % len(self.nodes)] = True

    @rule(i=st.integers(0, 4))
    def toggle_phase(self, i):
        i %= len(self.nodes)
        self.phase[i] = not self.phase[i]

    @rule(i=st.integers(0, 4))
    def hold_or_unhold(self, i):
        i %= len(self.nodes)
        self.held[i] = not self.held[i]
        if self.held[i]:
            run_op(self.db, "updates.hold", self.nodes[i]["node_id"], {"reason": "model"})
        else:
            run_op(self.db, "updates.unhold", self.nodes[i]["node_id"])

    # ------------------------------------------------------------------ time and the tick
    @rule(dt=st.sampled_from([0, 10, 60, 600, 1800, 7200, 6 * 3600]))
    def tick(self, dt):
        clock.advance(dt)
        for i in range(len(self.nodes)):
            if self.online[i]:
                self.beat(i)
        RO.tick(self.db)
        self.check_new_grants()
        self.check_budgets()

    @rule(ok=st.booleans())
    def coordinator_update_finishes(self, ok):
        cur = self.coordself.current
        if not cur or cur["state"] != "requested":
            return
        if ok:
            self.coord = cur["version"]
            self.coordself.current = {**cur, "state": "done"}
        else:
            self.coordself.current = {**cur, "state": "rolled_back", "error": "probation failed"}

    # ------------------------------------------------------------------ the operator
    @precondition(lambda self: not self.db.q("SELECT 1 FROM rollouts"))
    @rule(fast=st.booleans(), cap=st.sampled_from([None, 1, 2]), auto_rollback=st.booleans(),
          rings=st.sampled_from([None, ["coordinator", "canary", "broad"], ["coordinator", "early", "broad"]]))
    def start(self, fast, cap, auto_rollback, rings):
        params = {"fast": fast, "auto_rollback": auto_rollback, **({"max_unavailable": cap} if cap else {}),
                  **({"rings": rings} if rings else {})}
        try:
            run_op(self.db, "updates.start", self.target, params)
        except core.ApiError:
            pass                                          # e.g. the fleet is unhealthy right now

    @rule(action=st.sampled_from(["updates.pause", "updates.resume", "updates.halt", "updates.rollback"]))
    def operator(self, action):
        try:
            run_op(self.db, action, None, reason="model")
        except core.ApiError:
            pass

    # ------------------------------------------------------------------ the checks
    def grants(self) -> list[tuple]:
        out = []
        for m in self.db.q("SELECT rollout_id, node_id, go_facts_json FROM rollout_nodes"):
            out += [(m["rollout_id"], m["node_id"], g["at"]) for g in json.loads(m["go_facts_json"] or "[]")]
        return out

    def check_new_grants(self):
        """S31 against the model: each new grant went to a node that heartbeated within 120 s, outside any hold, inside
        its window and with no protected phase on as it last reported."""
        ids = [n["node_id"] for n in self.nodes]
        for key in self.grants():
            if key in self.grants_seen:
                continue
            self.grants_seen.add(key)
            rid, nid, at = key
            assert at == clock.now(), key                 # grants are made by the tick that just ran
            i = ids.index(nid)
            hb = self.db.one("SELECT last_heartbeat_at FROM nodes WHERE node_id=?", (nid,))["last_heartbeat_at"]
            assert at - hb <= RO.ONLINE_S and not self.held[i] and not self.reported_phase[i], (nid, at - hb, self.held[i])
            assert RO.window_contains(self.window[i], at, 0), (nid, self.window[i], at)

    def check_budgets(self):
        """BudgetHalts: right after a tick, no running rollout has a started ring over its failure budget."""
        for r in self.db.q("SELECT rollout_id FROM rollouts WHERE state='running' AND kind='update'"):
            ro = RO.row(self.db, r["rollout_id"])
            for ring in RO.RINGS:
                if not RO._started(ro, ring):
                    continue
                ms = RO.members(self.db, ro["rollout_id"], ring)
                _, budget = RO._cap(ro, ring, ms)
                assert sum(m["failures"] or 0 for m in ms) <= budget, (ring, ms)

    @invariant()
    def safety(self):
        if not hasattr(self, "db"):
            return
        assert invariants.s29_rollout_cap(self.db) == []
        assert invariants.s30_no_node_ahead_of_coordinator(self.db) == []
        assert invariants.s31_go_only_when_eligible(self.db) == []
        for n in self.nodes:                              # nothing past the coordinator, assigned or running
            assert not F.newer(self.node(self.nodes.index(n))["agent_version"], self.coord)

    @invariant()
    def halted_starts_nothing(self):
        if not hasattr(self, "db"):
            return
        grants = self.grants()
        for r in self.db.q("SELECT rollout_id FROM rollouts WHERE state IN ('halted','rolling_back','rolled_back') AND kind='update'"):
            n = sum(1 for g in grants if g[0] == r["rollout_id"])
            seen = self.halted_grants.setdefault(r["rollout_id"], n)
            assert n == seen, f"rollout {r['rollout_id']} granted go after it halted"
        for rid in [k for k in self.halted_grants
                    if self.db.one("SELECT state FROM rollouts WHERE rollout_id=?", (k,))["state"] in ("running", "paused")]:
            del self.halted_grants[rid]                   # resumed: it may grant again

    @invariant()
    def rolled_back_is_old(self):
        if not hasattr(self, "db"):
            return
        for r in self.db.q("SELECT rollout_id FROM rollouts WHERE state='rolled_back'"):
            child = self.db.one("SELECT rollout_id FROM rollouts WHERE parent=?", (r["rollout_id"],))
            if not child:
                continue
            for m in self.db.q("SELECT node_id, target FROM rollout_nodes WHERE rollout_id=? AND state='done'", (child["rollout_id"],)):
                v = self.db.one("SELECT agent_version FROM nodes WHERE node_id=?", (m["node_id"],))["agent_version"]
                assert v == m["target"], (m, v)

    # ------------------------------------------------------------------ termination under a fair schedule
    def settle(self):
        """Liveness: everyone back, holds and phases lifted, the coordinator's update succeeding, installs succeeding,
        time passing; every rollout ends done, halted or rolled_back."""
        for i in range(len(self.nodes)):
            self.online[i], self.phase[i] = True, False
            if self.window[i]:
                self.window[i] = None
                set_node(self.db, self.nodes[i]["node_id"], "update_window", reset=True)
            if self.held[i]:
                self.held[i] = False
                run_op(self.db, "updates.unhold", self.nodes[i]["node_id"])
        for _ in range(200):
            if self.coordself.current and self.coordself.current["state"] == "requested":
                self.coord = self.coordself.current["version"]
                self.coordself.current = {**self.coordself.current, "state": "done"}
            for r in self.db.q("SELECT rollout_id FROM rollouts WHERE state='paused'"):
                run_op(self.db, "updates.resume", r["rollout_id"], reason="settle")
            for i in range(len(self.nodes)):
                self.agent_step(i, "ok")
            self.tick(1800)
            if not self.db.q("SELECT 1 FROM rollouts WHERE state IN ('running','paused','rolling_back')"):
                break
        event("rollouts ended: " + ", ".join(sorted(f"{r['kind']} {r['state']}" for r in self.db.q("SELECT kind, state FROM rollouts"))))
        event(f"nodes on {self.target}: {sum(1 for i in range(len(self.nodes)) if self.node(i)['agent_version'] == self.target)}")
        left = self.db.q("SELECT rollout_id, kind, state, ring FROM rollouts WHERE state IN ('running','paused','rolling_back')")
        assert not left, left


RolloutMachine.TestCase.settings = settings(
    max_examples=500 if os.environ.get("OARBANK_THOROUGH") else 40,
    stateful_step_count=100 if os.environ.get("OARBANK_THOROUGH") else 50, deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
TestRolloutProtocol = RolloutMachine.TestCase
