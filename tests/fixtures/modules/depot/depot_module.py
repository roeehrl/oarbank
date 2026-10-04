"""depot: the core test suite's bootstrap fixture module (coordinator side). SDK only."""
from oarbank_sdk import module_protocol as mp
from oarbank_sdk.keys import job_key
from oarbank_sdk.server import Module

MODULE_ID, VERSION, COMPAT = "dev.codonic.oarbank.depot", "1.0.0", "depot1"
TOOL = "tool:depot-1"
GOLDEN_DIGEST = "depot-golden-1"
module = Module(MODULE_ID, VERSION)


@module.verb("params.check")
def params_check(p: mp.ParamsCheckParams, ctx):
    return mp.ParamsCheckResult(ok=True, normalized_params=p.params)


@module.verb("job.plan")
def job_plan(p: mp.JobPlanParams, ctx):
    return mp.JobPlanResult(jobs=[mp.PlanItem(key_inputs={"n": p.params.get("n", 2)}, datasets=[TOOL])])


@module.verb("spec.build")
def spec_build(p: mp.SpecBuildParams, ctx):
    return mp.SpecBuildResult(specs=[mp.BuiltSpec(key_inputs=j.key_inputs, spec_version=1, stages=[mp.StageSpec(
        stage="eval", payload={"n": j.key_inputs.get("n")}, datasets=[TOOL], mounts={TOOL: "tool"})]) for j in p.jobs])


@module.verb("golden.list")
def golden_list(p: mp.GoldenListParams, ctx):
    return mp.GoldenListResult(goldens=[mp.Golden(name="G1", key_inputs={"n": 1}, datasets=[TOOL],
                                                  expected={"digest": GOLDEN_DIGEST})])


@module.verb("result.evaluate")
def result_evaluate(p: mp.ResultEvaluateParams, ctx):
    digest = (p.result.get("payload") or {}).get("digest")
    if not digest:
        return mp.ResultEvaluateResult(verdict="reject", reason="depot/no_digest")
    return mp.ResultEvaluateResult(verdict="accept", digest=digest, digest_version=1, fields={"digest": digest})


@module.verb("result.merge")
def result_merge(p: mp.ResultMergeParams, ctx):
    return mp.ResultMergeResult(result=next(iter(p.stages.values())))


@module.verb("op.plan")
def op_plan(p: mp.OpPlanParams, ctx):
    return mp.OpPlanResult(summary=f"fetch {TOOL}")


@module.verb("op.apply")
def op_apply(p: mp.OpApplyParams, ctx):
    """provision: a campaign with one bootstrap fetch job (it names its stage: a bootstrap stage is never the default),
    and `evals` eval jobs, which wait for certification."""
    fetch = {"job_key": job_key(MODULE_ID, COMPAT, {"fetch": TOOL}, "fetch"), "stage": "fetch", "spec": {"fetch": TOOL}}
    evals = [{"job_key": job_key(MODULE_ID, COMPAT, {"n": n}), "spec": {"n": n}, "datasets": [TOOL], "mounts": {TOOL: "tool"}}
             for n in range(2, 2 + int(p.params.get("evals", 0)))]
    return mp.OpApplyResult(effects=[
        mp.Effect(kind="campaigns.create", args={"campaign_id": "c_provision", "name": "depot tools"}),
        mp.Effect(kind="jobs.enqueue", args={"campaign_id": "c_provision", "jobs": [fetch, *evals]})],
        result={"campaign_id": "c_provision"})


if __name__ == "__main__":
    module.run()
