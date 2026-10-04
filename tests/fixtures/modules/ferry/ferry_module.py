"""ferry: the core test suite's folder-grant fixture module (coordinator side). SDK only."""
from oarbank_sdk import module_protocol as mp
from oarbank_sdk.keys import job_key
from oarbank_sdk.server import Module

MODULE_ID, VERSION, COMPAT = "dev.codonic.oarbank.ferry", "1.0.0", "ferry1"
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
    return mp.GoldenListResult(goldens=[mp.Golden(name="G1", key_inputs={"n": 1}, expected={"digest": "ferry-golden-1"})])


@module.verb("result.evaluate")
def result_evaluate(p: mp.ResultEvaluateParams, ctx):
    digest = (p.result.get("payload") or {}).get("digest")
    if not digest:
        return mp.ResultEvaluateResult(verdict="reject", reason="ferry/no_digest")
    return mp.ResultEvaluateResult(verdict="accept", digest=digest, digest_version=1, fields={"digest": digest})


@module.verb("op.apply")
def op_apply(p: mp.OpApplyParams, ctx):
    n = int(p.params.get("n", 2))
    return mp.OpApplyResult(effects=[
        mp.Effect(kind="campaigns.create", args={"campaign_id": "c_ferry", "name": "ferry"}),
        mp.Effect(kind="jobs.enqueue", args={"campaign_id": "c_ferry", "jobs": [
            {"job_key": job_key(MODULE_ID, COMPAT, {"n": n}), "spec": {"n": n}}]})], result={"campaign_id": "c_ferry"})


if __name__ == "__main__":
    module.run()
