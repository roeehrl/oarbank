"""vault: the core test suite's fixture for secrets and container image sets (coordinator side). SDK only."""
import hashlib
import sys

from oarbank_sdk import module_protocol as mp
from oarbank_sdk.keys import job_key
from oarbank_sdk.server import Module

MODULE_ID, VERSION, COMPAT = "dev.codonic.oarbank.vault", "1.0.0", "vault1"
GOLDEN_DIGEST = "vault-golden-1"
module = Module(MODULE_ID, VERSION)


@module.verb("params.check")
def params_check(p: mp.ParamsCheckParams, ctx):
    return mp.ParamsCheckResult(ok=True, normalized_params=p.params)


@module.verb("job.plan")
def job_plan(p: mp.JobPlanParams, ctx):
    return mp.JobPlanResult(jobs=[mp.PlanItem(key_inputs={"n": p.params.get("n", 2)})])


@module.verb("spec.build")
def spec_build(p: mp.SpecBuildParams, ctx):
    return mp.SpecBuildResult(specs=[mp.BuiltSpec(key_inputs=j.key_inputs, spec_version=1, stages=[mp.StageSpec(
        stage="eval", payload={"n": j.key_inputs.get("n")})]) for j in p.jobs])


@module.verb("golden.list")
def golden_list(p: mp.GoldenListParams, ctx):
    return mp.GoldenListResult(goldens=[mp.Golden(name="G1", key_inputs={"n": 1}, expected={"digest": GOLDEN_DIGEST})])


@module.verb("result.evaluate")
def result_evaluate(p: mp.ResultEvaluateParams, ctx):
    digest = (p.result.get("payload") or {}).get("digest") or "none"
    return mp.ResultEvaluateResult(verdict="accept", digest=digest, digest_version=1, fields={"digest": digest})


@module.verb("result.merge")
def result_merge(p: mp.ResultMergeParams, ctx):
    return mp.ResultMergeResult(result=next(iter(p.stages.values())))


@module.verb("op.plan")
def op_plan(p: mp.OpPlanParams, ctx):
    return mp.OpPlanResult(summary=p.verb)


def _job(stage: str, spec: dict, **kw) -> dict:
    return {"job_key": job_key(MODULE_ID, COMPAT, spec, stage), "stage": stage, "spec": spec, **kw}


@module.verb("op.apply")
def op_apply(p: mp.OpApplyParams, ctx):
    """call: one job of the call stage and one of the probe stage (params.leak: the call runner logs the key);
    queue_tasks: a task job per image in params.images, each listing its image; key_check: reads the key through
    host.secrets.get and keeps only its hash (params.log: writes the key to stderr, which the host redacts)."""
    if p.verb == "key_check":
        key = ctx.host.secret("api_key")
        if p.params.get("log"):
            print(f"vault: using key {key}", file=sys.stderr, flush=True)
        digest = hashlib.sha256(key.encode()).hexdigest() if key else None
        return mp.OpApplyResult(effects=[mp.Effect(kind="store.write", args={"collection": "checks", "key": "last",
                                                                               "doc": {"key_sha256": digest}})],
                                result={"key_sha256": digest})
    cid = p.params.get("campaign_id", "c_" + p.verb)
    if p.verb == "call":
        jobs = [_job("call", {"call": 1, "leak": bool(p.params.get("leak"))}), _job("probe", {"probe": 1})]
    else:
        jobs = [_job("task", {"task": i}, images=[img]) for i, img in enumerate(p.params.get("images") or [])]
    return mp.OpApplyResult(effects=[mp.Effect(kind="campaigns.create", args={"campaign_id": cid, "name": p.verb}),
                                     mp.Effect(kind="jobs.enqueue", args={"campaign_id": cid, "jobs": jobs})],
                            result={"campaign_id": cid})


if __name__ == "__main__":
    module.run()
