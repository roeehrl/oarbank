"""relay: the core test suite's fixture module (coordinator side). SDK only; every verb is a pure function
of its input plus host callbacks."""
import secrets
import time

from oarbank_sdk import module_protocol as mp
from oarbank_sdk.keys import job_key
from oarbank_sdk.rpc import RpcError
from oarbank_sdk.server import Module

MODULE_ID, VERSION, COMPAT = "dev.codonic.oarbank.relay", "1.0.0", "relay1"
DEFAULT_MODE = {"runtime": "native-arm64", "sampler": "sobol-owen", "filter": "blackman-harris"}
module = Module(MODULE_ID, VERSION, concurrency=4)


def invalid(msg: str):
    raise RpcError(mp.ERR_INVALID_PARAMS, msg)


def check(params: dict) -> tuple[bool, str]:
    lo, hi = params.get("min_tile_size"), params.get("max_tile_size")
    if lo is not None and hi is not None and lo > hi:
        return False, "min_tile_size must be <= max_tile_size"
    if params.get("samples") == 0:
        return False, "samples 0 is refused"
    return True, "ok"


def build_payload(host, params: dict, ds: str | None, mode: dict | None = None) -> dict:
    meta = {}
    if ds:
        found = host.datasets_query(ids=[ds]).datasets
        if not found:
            invalid(f"unknown dataset {ds}")
        meta = found[0].attrs
    tools = host.settings_get("tool_datasets") or {}
    datasets = [*tools.values(), *([ds] if ds else [])]
    return {"params": params, "dataset": ds, "frames": meta.get("frames"), "scene": meta.get("scene"),
            "mode": mode or DEFAULT_MODE, "datasets": datasets,
            "mounts": {**{v: f"tools/{k}" for k, v in tools.items()}, **({ds: "scene"} if ds else {})}}


def key_inputs(payload: dict) -> dict:
    return {"params": payload["params"], "dataset": payload["dataset"], "mode": payload["mode"]}


@module.verb("params.check")
def params_check(p: mp.ParamsCheckParams, ctx):
    ok, why = check(p.params)
    return mp.ParamsCheckResult(ok=ok, normalized_params=p.params if ok else None,
                                errors=[] if ok else [mp.Issue(message=why, code="relay/params")])


@module.verb("job.plan")
def job_plan(p: mp.JobPlanParams, ctx):
    return mp.JobPlanResult(jobs=[mp.PlanItem(key_inputs={"params": p.params, "dataset": d.id}, datasets=[d.id], label=d.id)
                                  for d in p.datasets])


@module.verb("spec.build")
def spec_build(p: mp.SpecBuildParams, ctx):
    out = []
    for j in p.jobs:
        ki = j.key_inputs
        payload = build_payload(ctx.host, ki.get("params") or {}, ki.get("dataset"), ki.get("mode"))
        stages = j.stages or ["eval"]
        out.append(mp.BuiltSpec(key_inputs=key_inputs(payload), spec_version=1,
                                stages=[mp.StageSpec(stage=s, payload={k: v for k, v in payload.items() if k not in ("datasets", "mounts")},
                                                     datasets=payload["datasets"], mounts=payload["mounts"]) for s in stages]))
    return mp.SpecBuildResult(specs=out)


def _payload(env: dict) -> dict:
    return env.get("payload") or {}


@module.verb("result.evaluate")
def result_evaluate(p: mp.ResultEvaluateParams, ctx):
    spec, res = p.spec, p.result
    want, got = _payload(spec).get("mode"), (res.get("effective") or {}).get("mode")
    pl = _payload(res)
    digest = pl.get("image_sha256")
    if want and got != want:
        return mp.ResultEvaluateResult(verdict="reject", reason="mode_mismatch", digest=digest, digest_version=1)
    if p.stage == "sync":                       # ingestion: what the feed held when it ran
        if "items" not in pl:
            return mp.ResultEvaluateResult(verdict="reject", reason="relay/no_items")
        return mp.ResultEvaluateResult(verdict="accept", digest=pl.get("feed_sha"), digest_version=1,
                                       summary={"tiles": len(pl["items"])})
    if p.stage == "render":
        if not digest or not res.get("artifacts"):
            return mp.ResultEvaluateResult(verdict="reject", reason="relay/no_artifact", digest=digest, digest_version=1)
        return mp.ResultEvaluateResult(verdict="accept", digest=digest, digest_version=1, summary={"tiles": pl.get("tiles")})
    if pl.get("score") is None:
        return mp.ResultEvaluateResult(verdict="reject", reason="relay/no_metrics", digest=digest, digest_version=1)
    return mp.ResultEvaluateResult(verdict="accept", value=float(pl["score"]), digest=digest, digest_version=1,
                                   summary={"score": pl["score"], "tiles": pl.get("tiles")},
                                   fields={"image_sha256": digest})


@module.verb("result.merge")
def result_merge(p: mp.ResultMergeParams, ctx):
    render, score = p.stages.get("render") or {}, p.stages.get("score") or {}
    merged = {**score, "payload": {**_payload(render), **_payload(score)}, "effective": render.get("effective") or score.get("effective") or {},
              "artifacts": render.get("artifacts") or []}
    merged.setdefault("envelope", 1)
    merged.setdefault("schema", "relay/result@1")
    merged.setdefault("module_version", VERSION)
    return mp.ResultMergeResult(result=merged)


@module.verb("golden.list")
def golden_list(p: mp.GoldenListParams, ctx):
    render_only = p.node_class.pools.get("scorer", 1) == 0
    out = []
    for g in ctx.host.settings_get("goldens") or []:
        exp, by = dict(g["expected"]), dict(g.get("expected_by_platform") or {})
        if render_only:
            if not exp.get("image_sha256"):
                continue
            exp = {"tiles": exp.get("tiles"), "image_sha256": exp["image_sha256"]}
            by = {k: {"tiles": e.get("tiles"), "image_sha256": e["image_sha256"]} for k, e in by.items()}
        out.append(mp.Golden(name=g["name"], key_inputs={"params": g["params"], "dataset": g["dataset"]},
                             datasets=[g["dataset"]], stages=["render"] if render_only else [], expected=exp,
                             platforms=g.get("platforms") or [], expected_by_platform=by))
    return mp.GoldenListResult(goldens=out)


@module.verb("golden.compare")
def golden_compare(p: mp.GoldenCompareParams, ctx):
    pl = _payload(p.result)
    bad = [k for k, v in p.expected.items() if k not in ("digest", "digest_version") and str(pl.get(k)) != str(v)]
    return mp.GoldenCompareResult(ok=not bad, reason="ok" if not bad else f"relay/golden_mismatch:{','.join(bad)}")


def _jobs(host, n: int, params: dict, datasets: list, priority: int, rung: int = 1) -> list:
    out = []
    for ds in datasets:
        pl = build_payload(host, params, ds)
        out.append({"job_key": job_key(MODULE_ID, COMPAT, key_inputs(pl)), "spec": pl, "labels": {"trial": n},
                    "dataset_id": ds, "priority": priority, "subpriority": rung})
    return out


@module.verb("op.plan")
def op_plan(p: mp.OpPlanParams, ctx):
    if p.verb == "rerun_baseline":
        trial = ctx.host.store_get("trial", f"{p.target}:0")
        if not trial:
            invalid(f"{p.target} is not a relay study")
        return mp.OpPlanResult(summary=f"queue the baseline of {p.target} again", targets=[p.target])
    return mp.OpPlanResult(summary=p.verb)


@module.verb("op.apply")
def op_apply(p: mp.OpApplyParams, ctx):
    if p.verb == "rerun_baseline":
        trial = ctx.host.store_get("trial", f"{p.target}:0")
        if not trial:
            return mp.OpApplyResult(response="errors", errors=[mp.Issue(message=f"{p.target} is not a relay study")])
        datasets = sorted({j["dataset_id"] for j in ctx.host.jobs_query(p.target) if j.get("dataset_id")})
        jobs = [{**j, "labels": {"trial": 0, "rerun": int(time.time())}} for j in _jobs(ctx.host, 0, trial["params"], datasets, 1)]
        return mp.OpApplyResult(effects=[mp.Effect(kind="jobs.enqueue", args={"campaign_id": p.target, "jobs": jobs})],
                                message=f"{len(jobs)} baseline jobs queued")
    if p.verb != "create_study":
        return mp.OpApplyResult(response="errors", errors=[mp.Issue(message=f"unknown verb {p.verb}", code="relay/unknown_verb")])
    q = p.params
    datasets = list(q.get("datasets") or [])
    if not datasets:
        return mp.OpApplyResult(response="errors", errors=[mp.Issue(path="/datasets", message="at least one dataset")])
    base = q.get("baseline") or {}
    cid = q.get("campaign_id") or "s_" + secrets.token_hex(4)
    try:
        jobs = _jobs(ctx.host, 0, base["params"], datasets, 1)
        effects = [mp.Effect(kind="campaigns.create", args={"campaign_id": cid, "name": q["name"], "priority": int(q.get("priority", 0)),
                                                           "weight": float(q.get("weight", 1.0)),
                                                           **({"placement": q["placement"]} if q.get("placement") else {})}),
                   mp.Effect(kind="store.write", args={"collection": "trial", "key": f"{cid}:0",
                                                       "doc": {"campaign_id": cid, "trial": 0, "label": base.get("label", "baseline"),
                                                               "params": base["params"], "created_at": time.time()}})]
        for i, c in enumerate(q.get("configs") or [], start=1):
            effects.append(mp.Effect(kind="store.write", args={"collection": "trial", "key": f"{cid}:{i}",
                                                               "doc": {"campaign_id": cid, "trial": i, "label": c.get("label") or f"c{i}",
                                                                       "params": c["params"], "created_at": time.time()}}))
            jobs += _jobs(ctx.host, i, c["params"], datasets, 0)
    except RpcError as e:
        return mp.OpApplyResult(response="errors", errors=[mp.Issue(message=e.message, code="relay/invalid")])
    for j in jobs:                    # placement (D33): each trial's or dataset's jobs as a group, and the jobs' platforms
        if q.get("group_by"):
            j["group"] = f"t{j['labels']['trial']}" if q["group_by"] == "trial" else j["dataset_id"]
        if q.get("platforms"):
            j["platforms"] = list(q["platforms"])
    effects.append(mp.Effect(kind="jobs.enqueue", args={"campaign_id": cid, "jobs": jobs}))
    return mp.OpApplyResult(effects=effects, response="redirect", message=f"study {cid}: {len(jobs)} jobs",
                            result={"campaign_id": cid, "jobs": len(jobs)})


@module.verb("ui.view.compute")
def view_compute(p: mp.ViewComputeParams, ctx):
    if p.view_id == "scores":
        rows = [{"trial": (r.get("labels") or {}).get("trial"), "dataset": r.get("dataset_id"), "score": r.get("value")}
                for r in p.inputs.get("results", [])]
        return mp.ViewComputeResult(rows=rows[:1000], data_version=p.data_version)
    if p.view_id == "trials":
        by = {}
        for j in p.inputs.get("jobs") or []:
            t = (j.get("labels") or {}).get("trial")
            if t is not None and j.get("state") == "done" and j.get("value") is not None:
                by.setdefault(t, []).append(j["value"])
        rows = [{"trial": d.get("trial"), "label": d.get("label"), "done": len(by.get(d.get("trial"), [])),
                 "mean": (sum(by[d["trial"]]) / len(by[d["trial"]])) if by.get(d.get("trial")) else None}
                for d in sorted(p.inputs.get("store:trial") or [], key=lambda d: d.get("trial") or 0)]
        return mp.ViewComputeResult(rows=rows, data_version=p.data_version)
    invalid(f"unknown view {p.view_id}")


if __name__ == "__main__":
    module.run()
