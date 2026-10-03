"""Seeded fault-injecting simulation of a whole fleet against the real coordinator core.

Each seed runs 4 agents (one of them silently nondeterministic) through lost requests and responses,
silent sleeps, agent crashes, coordinator outages, execution failures and wrong-mode runs. It asserts
every safety invariant along the way, liveness (every job settles) at the end, that no good node is
ever convicted, and that no canonical result from the convicted node survives.

The default run is a quick sample; OARBANK_THOROUGH=1 widens it (scripts/sim-sweep.sh runs thousands).
"""
import os

import pytest

from oarbank import sim

N = 60 if os.environ.get("OARBANK_THOROUGH") else 12


def _check(r):
    assert not r["violations"], r
    assert not r["liveness"], r
    assert not r["good_nodes_quarantined"], r
    assert not r["canonical_from_convicted_node"], r
    assert r["ok"], r


@pytest.mark.parametrize("seed", range(N))
def test_harsh_four_nodes(seed):
    r = sim.Simulation(seed, n_nodes=4, n_configs=5, n_datasets=12, faults=sim.PROFILES["harsh"]).run()
    _check(r)
    assert r["bad_node_quarantined"], "replication at 30% must expose the nondeterministic node"


@pytest.mark.parametrize("seed", range(N // 2))
def test_harsh_three_nodes(seed):
    _check(sim.Simulation(1000 + seed, n_nodes=3, faults=sim.PROFILES["harsh"]).run())


@pytest.mark.parametrize("seed", range(N // 2))
def test_harsh_two_nodes_settles_without_convicting_anyone(seed):
    """No quorum is possible with two nodes: disputes end quarantined. The only possible conviction is
    self-inconsistency (one node, two different answers for a job), so a good node is never convicted."""
    _check(sim.Simulation(2000 + seed, n_nodes=2, faults=sim.PROFILES["harsh"]).run())


@pytest.mark.parametrize("seed", range(N // 2))
@pytest.mark.parametrize("n_nodes", [2, 3])
def test_harsh_consistently_wrong_node(seed, n_nodes):
    """A node that is wrong the same way every time (e.g. a miscompiled library) can agree with itself;
    it must never outvote a correct node (TLA+ finding F2)."""
    import dataclasses
    f = dataclasses.replace(sim.PROFILES["harsh"], bad_mode="consistent")
    _check(sim.Simulation(4000 + seed, n_nodes=n_nodes, faults=f).run())


@pytest.mark.parametrize("seed", range(N // 2))
def test_mild_no_bad_node(seed):
    r = sim.Simulation(3000 + seed, n_nodes=4, faults=sim.Faults(nondeterministic_node=False)).run()
    _check(r)
    assert r["disputes"] == 0 and r["jobs"].get("quarantined", 0) == 0


@pytest.mark.parametrize("seed", range(N // 2))
@pytest.mark.parametrize("bad_mode", ["random", "consistent"])
def test_harsh_split_pipeline(seed, bad_mode):
    """Staged pipeline: node0 scores in the VM, the rest only render. Replicas/disputes at the render stage
    must convict the bad worker and every final score must be graded from a good frame."""
    import dataclasses
    f = dataclasses.replace(sim.PROFILES["harsh"], split=True, bad_mode=bad_mode)
    _check(sim.Simulation(5000 + seed, n_nodes=4, n_configs=4, n_datasets=8, faults=f).run())


GROUPS_BY_OS = {"mix": "same-os", "unit": "group", "bind": "first-claim"}


@pytest.mark.parametrize("seed", range(N // 2))
def test_harsh_mixed_fleet_keeps_each_group_on_one_os(seed):
    """Placement (D33) under every fault: each dataset's jobs stay on one OS (S20 along the way), groups spread over
    both OS classes of a darwin/linux-amd64/linux-arm64 fleet, and everything still settles."""
    import dataclasses
    f = dataclasses.replace(sim.PROFILES["harsh"], placement=GROUPS_BY_OS, group_by="dataset")
    r = sim.Simulation(6000 + seed, n_nodes=6, n_configs=3, n_datasets=8, faults=f).run()
    _check(r)
    assert sum(r["units"].values()) == 8 and set(r["classes"]) <= {"darwin", "linux"}


@pytest.mark.parametrize("seed", range(N // 4))
def test_mild_campaign_on_one_platform(seed):
    import dataclasses
    f = dataclasses.replace(sim.Faults(), placement={"mix": "same-platform"})
    r = sim.Simulation(7000 + seed, n_nodes=6, faults=f).run()
    _check(r)
    assert len(r["classes"]) == 1 and r["classes"][0] in sim.PLATFORMS


def test_a_thousand_jobs_on_a_mixed_fleet_verify_clean():
    """The acceptance run of D33 step 4: 1000 jobs on nine nodes of three platforms, grouped by dataset and kept on one
    OS per group, with a nondeterministic node; at the end the invariant report (`oarbank verify`) is clean."""
    import dataclasses
    from oarbank.coordinator import invariants
    f = dataclasses.replace(sim.Faults(), placement=GROUPS_BY_OS, group_by="dataset")
    s = sim.Simulation(7, n_nodes=9, n_configs=24, n_datasets=40, faults=f, max_hours=48)
    r = s.run(keep=True)
    try:
        _check(r)
        rep = invariants.report(s.db)
        assert rep["ok"], rep["violations"]
        assert r["jobs"] == {"done": 1000} and r["units"] == {"hard": 40} and set(r["classes"]) == {"darwin", "linux"}
    finally:
        s.db.conn.close()
        s.tmp.cleanup()


@pytest.mark.parametrize("seed", range(N // 4))
def test_harsh_split_pipelines_each_on_one_arch(seed):
    """Split pipelines (node0 alone scores) with each pipeline kept on one arch: a head binds only where its tail can run."""
    import dataclasses
    f = dataclasses.replace(sim.PROFILES["harsh"], split=True, placement={"mix": "same-arch", "unit": "pipeline"})
    _check(sim.Simulation(8000 + seed, n_nodes=6, n_configs=3, n_datasets=6, faults=f).run())
