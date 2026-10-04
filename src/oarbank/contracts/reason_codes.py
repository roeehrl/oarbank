"""The reason-code registry (docs/design/admin-console.md "Reason codes form one registry").

Each code is declared once: category, message template, default severity, the operations it offers as remedies,
and the strings the agent and oarbankd write as an attempt's end reason or a result's reason for it (`wire`), so a
stored end reason renders as its code. Protection codes are the reasons the agent writes in its decision journal.
Every code has a producer and every code the console and explain name is here (tests/test_contracts.py). Modules add
codes only under their own namespace, `<module-short>/<code>`, rendered as escaped text.
"""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal["job_pending", "node_admission", "protection", "attempt_end", "verdict", "invariant"]
Severity = Literal["P1", "P2", "P3", "P4", "P5"]
CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
PLACEHOLDER_RE = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


class ReasonCode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    code: str = Field(pattern=CODE_RE.pattern)
    category: Category
    template: str = Field(min_length=3, description="Plain text with {name} placeholders; rendered escaped.")
    severity: Severity = "P1"
    remedies: tuple[str, ...] = Field(default=(), description="Operation ids (operations.REGISTRY).")
    wire: tuple[str, ...] = Field(default=(), description="Attempt end reasons (attempts.end_reason) this code explains.")
    counts_against_node: bool | None = Field(None, description="attempt_end/verdict: whether the node's breaker counts it.")
    counts_against_job: bool | None = Field(None, description="attempt_end/verdict: whether the job's retry budget counts it.")

    def render(self, **values) -> str:
        return PLACEHOLDER_RE.sub(lambda m: str(values.get(m.group(1), "?")), self.template)


def C(code, category, template, severity="P1", remedies=(), wire=(), node=None, job=None):
    return ReasonCode(code=code, category=category, template=template, severity=severity, remedies=tuple(remedies),
                      wire=tuple(wire), counts_against_node=node, counts_against_job=job)


CODES: list[ReasonCode] = [
    # ---------------------------------------------------------------- why a job is pending (explain headline/summary)
    C("NO_ELIGIBLE_NODE", "job_pending", "No node can run this job right now", remedies=["jobs.set_priority"]),
    C("QUEUED_BEHIND", "job_pending", "Eligible, but behind {ahead} higher-priority jobs", remedies=["jobs.set_priority"]),
    C("DEPENDENCY_UNMET", "job_pending", "Waiting for stage {stage} (job {job_id})"),
    C("CAMPAIGN_PAUSED", "job_pending", "Campaign {campaign} is not running", remedies=["campaigns.resume"]),
    C("OARBANK_PAUSED", "job_pending", "The fleet is paused", remedies=["fleet.resume"], wire=["fleet_halt"]),
    C("BACKOFF", "job_pending", "Retrying after {seconds} s (backoff)"),
    C("POOL_EXHAUSTED", "job_pending", "No free {pool} token ({free} free, {need} needed)"),
    C("POOL_ABSENT", "job_pending", "The node offers no {pool} pool"),
    C("INSUFFICIENT_CPU", "job_pending", "Needs {need} cores, {free} allocatable"),
    C("INSUFFICIENT_MEM", "job_pending", "Needs {need} GB, {free} GB allocatable"),
    C("USER_CAP_BINDING", "job_pending", "Owner cap {cap} is binding", remedies=["nodes.set_caps"]),
    C("MODULE_NOT_READY", "job_pending", "Module {module} is not ready on this node (doctor: {health})", remedies=["nodes.run_doctor"]),
    C("MODULE_NOT_CERTIFIED", "job_pending", "Module {module} is not certified on this node yet", remedies=["nodes.recertify"]),
    C("MODULE_DISABLED", "job_pending", "Module {module} is disabled", remedies=["modules.enable_canary"], wire=["module_disabled"]),
    C("PLATFORM_UNSUPPORTED", "job_pending", "Module {module} does not run on {platform} (requires.platforms)"),
    C("STAGE_PLATFORM_UNSUPPORTED", "job_pending", "The job runs only on {platforms} (its stage, its own platforms and its unit's "
      "feasible classes), not {platform}", remedies=["jobs.cancel"]),
    C("PLATFORM_BOUND_ELSEWHERE", "job_pending", "Its unit of work is bound to {class_}; this node is {platform}",
      remedies=["campaigns.rebind_platform"]),
    C("PLACEMENT_UNPINNED", "job_pending", "Its unit of work binds only to a pinned class (bind = explicit) and none is pinned yet",
      remedies=["campaigns.rebind_platform"]),
    C("STAGE_CAPABILITY_MISSING", "job_pending", "Its stage needs {capabilities}; this node's services, probes and module doctor "
      "do not provide {missing}", remedies=["nodes.run_doctor"]),
    C("GPU_API_MISSING", "job_pending", "Needs {need}; this node provides {have} (its doctor's GPU APIs)",
      remedies=["nodes.run_doctor"]),
    C("SECRETS_NOT_SET", "job_pending", "Its stage receives secrets {missing}, which have no value for this node",
      remedies=["secrets.set"]),
    C("DATASET_PLATFORM_MISMATCH", "job_pending", "Its dataset is bound to {platforms}; this node is {platform}", remedies=["jobs.cancel"]),
    C("OS_VERSION_UNSUPPORTED", "job_pending", "Module {module} needs another OS version than {os_version} (requires.os)"),
    C("TOOL_UNAVAILABLE", "job_pending", "Module {module} needs host tools the tool registry has no {os} paths for",
      remedies=["settings.tools.update"]),
    C("FOLDER_UNAVAILABLE", "job_pending", "Module {module} needs folders this node does not provide (unmapped, another "
      "access, refused by the node, or awaiting the owner's signature)", remedies=["settings.folders.update"]),
    C("SANDBOX_BACKEND_MISSING", "job_pending", "The agent on this node cannot sandbox module processes"),
    C("CAPABILITY_NOT_ENFORCED", "job_pending", "The node's sandbox cannot enforce {capability}, which module {module} needs"),
    C("AGENT_TOO_OLD", "job_pending", "Module {module} needs agent {need}; the node runs {have}", remedies=["agent.promote"]),
    C("PINNED_ELSEWHERE", "job_pending", "Pinned to node {node}"),
    C("POOL_JOBS_ONLY", "job_pending", "The node is yielding and takes only short pool jobs"),
    C("GPU_BLOCKED", "job_pending", "A GPU job: the node admits no more GPU jobs now (owner setting or a protected process is using the GPU)"),
    C("RETRIES_EXHAUSTED", "job_pending", "It failed {failures} times: its stage allows {max_attempts} attempts on {platform} "
      "(stages[].retry)", remedies=["jobs.cancel"]),
    C("FAILED_HERE", "job_pending", "It failed on this node before and another node can take it"),
    C("COMPARED_ON_PLATFORM", "job_pending", "A replica or tie-break that must run in class {class_}: the module compares results within "
      "one {scope} class (results.determinism_scope)"),
    C("DISPUTE_PARTY", "job_pending", "This node is a party to the job's dispute; a third node must break the tie", wire=["dispute_party"]),
    C("DATASETS_NOT_REGISTERED", "job_pending", "Waiting for {missing} to be registered (a bootstrap job brings a module's "
      "pinned datasets)"),
    C("DATASETS_NOT_STAGED", "job_pending", "The node has not staged {missing} yet"),

    # ---------------------------------------------------------------- why a node is not admitting work
    C("NODE_PAUSED_BY_ADMIN", "node_admission", "Paused by {actor}: {reason}", remedies=["nodes.resume"]),
    C("NODE_DRAINING", "node_admission", "Draining", remedies=["nodes.resume"]),
    C("NODE_QUARANTINED", "node_admission", "Quarantined: {reason}", "P3", remedies=["nodes.clear_quarantine"],
      wire=["node_quarantined"]),
    C("NODE_RETIRED", "node_admission", "Retired", wire=["node_retired"]),
    C("RELEASE_PENDING", "node_admission", "Installing release {release}"),
    C("NOT_ADMITTING", "node_admission", "The agent admits no new work: {why}"),
    C("CLOCK_SKEW", "node_admission", "The node's clock is {offset_s} s off the coordinator's: jobs and moves use the "
      "coordinator's time, but certificates and update metadata need a correct clock; set the node's time", "P3"),

    # ---------------------------------------------------------------- protection (the agent's decision journal and capacity)
    C("PROTECTION_CONFIG", "protection", "Protection config applied (mode {mode}, rules {rules})"),
    C("PROTECTION_CONFIG_ERROR", "protection", "A protection config part is broken and ignored: {error}", "P3"),
    C("PROTECTION_ACTIVE", "protection", "Rule {rule} is active"),
    C("PROTECTION_CLEARED", "protection", "Rule {rule} is no longer active"),
    C("PROTECTION_RESERVED", "protection", "{mem_gb} GB and {cpu} cores held for {rules}"),
    C("PROTECTION_BINDING", "protection", "Rule {rule} binds the node's capacity"),
    C("CONSTRAINT_CHANGED", "protection", "The fleet constraint changed: {constraint}"),
    C("PROTECTION_EVICT", "protection", "Evicted by rule {rule}; requeued", wire=["preempt_protection"], node=False, job=False),
    C("PROTECTION_PAUSE", "protection", "Fleet attempts paused by rule {rule}", node=False, job=False),
    C("PROTECTION_LOWER", "protection", "Fleet attempts lowered by rule {rule}", node=False, job=False),
    C("PROTECTION_RESUME", "protection", "Paused attempts resumed", node=False, job=False),
    C("PROTECTION_RESTORE", "protection", "Lowered attempts restored", node=False, job=False),
    C("MEMORY_CLEAR", "protection", "Memory guard clear (free {free_pct}%)"),
    C("MEMORY_SOFT", "protection", "Memory soft floor: free {free_pct}%; admitting no new work", "P2"),
    C("MEMORY_HARD", "protection", "Memory hard floor: free {free_pct}%; evicting fleet jobs", "P2"),
    C("MEMORY_HARD_FLOOR", "protection", "Attempt {attempt} evicted by the memory hard floor ({why})", "P2"),
    C("MEMORY_HARD_FLOOR_SERVICE", "protection", "Service {service} stopped by the memory hard floor ({why}); its jobs requeued",
      "P2", node=False, job=False),
    C("PROTECTION_SERVICE_STOP", "protection", "Service {service} stopped by host protection ({reason}); its jobs requeued",
      node=False, job=False),
    C("RUNG_0", "protection", "Dynamic rung 0: no constraint ({why})"),
    C("RUNG_1", "protection", "Dynamic rung 1: admitting no new work ({why})"),
    C("RUNG_2", "protection", "Dynamic rung 2: the fleet CPU budget is under the allocatable cores ({why})"),
    C("RUNG_3", "protection", "Dynamic rung 3: fleet jobs lowered to background scheduling ({why})"),
    C("RUNG_5", "protection", "Dynamic rung 5: fleet jobs paused ({why})"),
    C("RUNG_6", "protection", "Dynamic rung 6: fleet jobs evicted ({why})"),
    C("L2_EMERGENCY_LOWER", "protection", "Harm over twice its target ({pressure}) for two samples: fleet jobs lowered at once"),
    C("L2_RESTORED", "protection", "Harm back under its target for 30 s: lowered fleet jobs restored"),
    C("L1_TAKE_BACK", "protection", "Fleet CPU budget taken back to 0 (harm {pressure} or a memory guard); growth locked out"),
    C("L1_HALVE", "protection", "Fleet CPU budget halved to {budget} after a violation"),
    C("L1_GROW", "protection", "Fleet CPU budget grown to {budget}"),
    C("L1_HOLD_UNVALIDATED", "protection", "Fleet CPU budget held at {budget}: no validated signal for {rule}"),
    C("PROBE_HARM", "protection", "A pause probe measured harm {harm} to {rule}"),
    C("S16_GUARD", "protection", "Refused to act on process {pid}: it is not in the spawn registry ({why})", "P3"),
    C("PROTECTION_FRONT_UNKNOWN", "protection", "The front app cannot be read here ({why}); frontmost rules count it as "
      "in front", "P4"),
    C("PROTECTION_PRESENCE_UNKNOWN", "protection", "Whether someone is at the machine cannot be read ({why}); it counts "
      "as someone present", "P4"),
    C("PROTECTION_UNREADABLE", "protection", "Rule {rule} matched {n} processes whose path or arguments could not be read "
      "(counted as matches)", "P5"),
    C("PROTECTION_NO_LOWERING", "protection", "This node cannot lower fleet jobs (no delegated cgroup with the cpu "
      "controller): pausable jobs are paused instead", "P3"),
    C("PROTECTION_NO_IPC_COUNTERS", "protection", "Rule {rule} protects ipc_ratio, but this node's processes have no "
      "instruction or cycle counters (a virtual machine): the metric is unknown and the fleet's CPU budget does not grow",
      "P4"),
    C("PROTECTION_SOURCE_ERROR", "protection", "The process table cannot be read: {error}", "P3"),

    # ---------------------------------------------------------------- how an attempt ended
    C("OK", "attempt_end", "Completed", wire=["ok"], node=False, job=False),
    C("EXIT_NONZERO", "attempt_end", "The runner exited with code {code}", wire=["exit_nonzero"], node=True, job=True),
    C("INVALID_SPEC", "attempt_end", "The runner rejected the spec (exit 2)", wire=["bad_input"], node=False, job=True),
    C("MISSING_DEPENDENCY", "attempt_end", "A node dependency is missing (exit 3); re-doctoring", wire=["doctor"], node=True, job=False),
    C("RETRYABLE", "attempt_end", "Transient failure (exit 75); released and retried", wire=["transient"], node=False, job=False),
    C("TIMEOUT", "attempt_end", "Hit the {timeout_s} s limit", wire=["timeout"], node=True, job=True),
    C("LEASE_EXPIRED", "attempt_end", "Lease expired (no heartbeat for {seconds} s)", wire=["lease_expired"], node=True, job=False),
    C("AGENT_RESTARTED", "attempt_end", "The agent restarted without the attempt", wire=["agent_restart"], node=False, job=False),
    C("RELEASE_INVALID", "attempt_end", "Granted under a release the node no longer runs", wire=["release_invalid"], node=False, job=False),
    C("STALE_GENERATION", "attempt_end", "The job was requeued after this attempt was granted", wire=["stale_generation"],
      node=False, job=False),
    C("LOST_RACE", "attempt_end", "Another attempt finished first", wire=["lost_race"], node=False, job=False),
    C("MODULE_REVOKED", "attempt_end", "Module {module} was revoked on the node", wire=["module_revoked"], node=False, job=False),
    C("GOLDEN_FAILED", "attempt_end", "Golden jobs kept failing on the node; its certification stopped", wire=["golden_failed"],
      node=False, job=False),
    C("GOLDEN_SUPERSEDED", "attempt_end", "A new golden set replaced this golden job", wire=["superseded"], node=False, job=False),
    C("OOM", "attempt_end", "Killed for memory", wire=["oom"], node=False, job=True),
    C("SANDBOX_ESCAPE", "attempt_end", "A process of the attempt ran outside the module sandbox; the attempt was killed",
      wire=["sandbox_escape"], node=False, job=True),
    C("PREEMPT_MEMORY", "attempt_end", "Preempted by the memory guard", wire=["preempt_memory"], node=False, job=False),
    C("RELEASED_CAP_CPU", "attempt_end", "Released: the CPU cap was lowered", wire=["limit_cpu"], node=False, job=False),
    C("RELEASED_CAP_MEM", "attempt_end", "Released: over its declared memory under a memory floor, or the memory cap was lowered",
      wire=["limit_mem"], node=False, job=False),
    C("RELEASED_SCHEDULE", "attempt_end", "Released: outside the owner's schedule", wire=["limit_schedule"], node=False, job=False),
    C("USER_CANCEL", "attempt_end", "Cancelled by {actor}", wire=["user_cancel"], node=False, job=False),
    C("INPUT_INVALIDATED", "attempt_end", "The upstream stage result was demoted", wire=["input_invalidated"], node=False, job=False),
    C("PLACEMENT_REBOUND", "attempt_end", "Its unit of work moved to another platform class", wire=["placement_rebound"], node=False, job=False),
    C("JOB_CANCELLED", "attempt_end", "The job was cancelled", wire=["job_cancelled"], node=False, job=False),
    C("JOB_QUARANTINED", "attempt_end", "The job was quarantined", wire=["job_quarantined"], node=False, job=False),
    C("ATTEMPT_CLOSED", "attempt_end", "The attempt was already closed", wire=["attempt_closed"], node=False, job=False),
    C("JOB_DONE", "attempt_end", "The job was already done", wire=["job_done"], node=False, job=False),

    # ---------------------------------------------------------------- result verdicts (host side of result.evaluate)
    C("NO_METRICS", "verdict", "The result carries no metrics", wire=["no_metrics"], node=True, job=True),
    C("BAD_ARTIFACT", "verdict", "The result names an artifact without a name or files", wire=["bad_artifact"], node=False, job=True),
    C("ARTIFACT_MISSING", "verdict", "The result references artifacts the coordinator does not hold", wire=["artifact_missing"], node=True, job=False),
    C("INPUT_MISSING", "verdict", "A stage input (a dataset, a blob or the upstream result) was unavailable", wire=["input_missing"],
      node=True, job=False),
    C("BOOTSTRAP_PIN_MISMATCH", "verdict", "A bootstrap result is not exactly the module's pinned datasets: {detail}",
      wire=["pin_mismatch"], node=False, job=True),
    C("RESULT_INVALID", "verdict", "The result payload does not match the module's results.schema or exceeds results.max_inline_kb",
      wire=["result_invalid"], node=False, job=True),
    C("MODE_MISMATCH", "verdict", "The runner's effective mode is not the job's expected mode", wire=["mode_mismatch"], node=True, job=False),
    C("INPUT_MISMATCH", "verdict", "The score does not match its call's input digest", wire=["input_mismatch"], node=True, job=False),
    C("GOLDEN_MISMATCH", "verdict", "Golden job {golden} produced a different digest", "P5", remedies=["nodes.recertify"],
      wire=["golden_mismatch"], node=True, job=False),
    C("DISPUTED", "verdict", "Replicas disagree", "P3", wire=["disputed"], node=False, job=False),
    C("SELF_INCONSISTENT", "verdict", "The node disagrees with its own earlier result", "P5", wire=["self_inconsistent"], node=True, job=False),

    # ---------------------------------------------------------------- safety invariants (the Verify page)
    C("INVARIANT_VIOLATED", "invariant", "Invariant {invariant} is false: {detail}", "P5"),
    C("INVARIANT_UNKNOWN", "invariant", "Invariant {invariant} could not be checked: {detail}", "P4"),
]

REGISTRY: dict[str, ReasonCode] = {}
WIRE: dict[str, str] = {}               # an attempt's end reason -> its code
for _c in CODES:
    if _c.code in REGISTRY:
        raise ValueError(f"duplicate reason code {_c.code}")
    REGISTRY[_c.code] = _c
    for _w in _c.wire:
        if _w in WIRE:
            raise ValueError(f"end reason {_w!r} mapped twice ({WIRE[_w]}, {_c.code})")
        WIRE[_w] = _c.code
