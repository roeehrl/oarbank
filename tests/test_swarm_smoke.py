"""Tiny end-to-end swarm: ~10 simulated mTLS agents against a real oarbankd subprocess (scratch
OARBANKD_HOME in tmp_path, free localhost ports). Every job must end done exactly once canonically, the
agents' ack history must agree with the DB, and the invariant catalogue must report nothing."""
import importlib.util
import sys
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1] / "bench"


def _swarm():
    spec = importlib.util.spec_from_file_location("oarbank_bench_swarm", BENCH / "swarm.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod          # dataclasses need the module registered
    spec.loader.exec_module(mod)
    return mod


def test_swarm_smoke(tmp_path):
    sw = _swarm()
    cfg = sw.Cfg(agents=10, slots=2, total_jobs=50, heartbeat_s=0.5, job_min_s=0.2, job_max_s=0.8,
                 fail_rate=0.08, release_rate=0.08, dup_rate=0.2, procs=-1, max_drain_s=50,
                 agent_port=sw.free_port(), admin_port=sw.free_port(), home=str(tmp_path / "oarbankd"), keep_home=True)
    res = sw.run(cfg, log=lambda *a: None)
    assert res["invariant_violations"] == [], res["invariant_violations"]
    assert res["eval_jobs_done"] == 50 and res["jobs_seeded"] == 50
    assert res["db"]["jobs"].get("done") == sum(res["db"]["jobs"].values()), res["db"]["jobs"]
    assert res["expiries"]["false"] == 0
    eps = res["endpoints"]
    for ep in ("heartbeat", "claim", "complete"):
        assert eps[ep]["n"] > 0 and eps[ep]["http503"] == 0 and eps[ep]["conn_err"] == 0, (ep, eps[ep])
    assert res["counters"]["replays"] > 0, "lost-ack replays must be exercised"
    assert res["counters"]["fails"] > 0, "failure path must be exercised"
    assert "check_all" in res["db"]
