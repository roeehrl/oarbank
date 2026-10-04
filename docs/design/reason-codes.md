# Reason codes (generated)

Generated from `oarbank.contracts.reason_codes`. Module codes use `<module-short>/<code>`. The last column lists the attempt end reasons the agent and oarbankd write for a code.

## job_pending

| Code | Message | Severity | Node / job fault | Remedies | End reasons |
|---|---|---|---|---|---|
| `NO_ELIGIBLE_NODE` | No node can run this job right now | P1 | – | `jobs.set_priority` | – |
| `QUEUED_BEHIND` | Eligible, but behind {ahead} higher-priority jobs | P1 | – | `jobs.set_priority` | – |
| `DEPENDENCY_UNMET` | Waiting for stage {stage} (job {job_id}) | P1 | – | – | – |
| `CAMPAIGN_PAUSED` | Campaign {campaign} is not running | P1 | – | `campaigns.resume` | – |
| `OARBANK_PAUSED` | The fleet is paused | P1 | – | `fleet.resume` | `fleet_halt` |
| `BACKOFF` | Retrying after {seconds} s (backoff) | P1 | – | – | – |
| `POOL_EXHAUSTED` | No free {pool} token ({free} free, {need} needed) | P1 | – | – | – |
| `POOL_ABSENT` | The node offers no {pool} pool | P1 | – | – | – |
| `INSUFFICIENT_CPU` | Needs {need} cores, {free} allocatable | P1 | – | – | – |
| `INSUFFICIENT_MEM` | Needs {need} GB, {free} GB allocatable | P1 | – | – | – |
| `USER_CAP_BINDING` | Owner cap {cap} is binding | P1 | – | `nodes.set_caps` | – |
| `MODULE_NOT_READY` | Module {module} is not ready on this node (doctor: {health}) | P1 | – | `nodes.run_doctor` | – |
| `MODULE_NOT_CERTIFIED` | Module {module} is not certified on this node yet | P1 | – | `nodes.recertify` | – |
| `MODULE_DISABLED` | Module {module} is disabled | P1 | – | `modules.enable_canary` | `module_disabled` |
| `PLATFORM_UNSUPPORTED` | Module {module} does not run on {platform} (requires.platforms) | P1 | – | – | – |
| `STAGE_PLATFORM_UNSUPPORTED` | The job runs only on {platforms} (its stage, its own platforms and its unit's feasible classes), not {platform} | P1 | – | `jobs.cancel` | – |
| `PLATFORM_BOUND_ELSEWHERE` | Its unit of work is bound to {class_}; this node is {platform} | P1 | – | `campaigns.rebind_platform` | – |
| `PLACEMENT_UNPINNED` | Its unit of work binds only to a pinned class (bind = explicit) and none is pinned yet | P1 | – | `campaigns.rebind_platform` | – |
| `STAGE_CAPABILITY_MISSING` | Its stage needs {capabilities}; this node's services, probes and module doctor do not provide {missing} | P1 | – | `nodes.run_doctor` | – |
| `GPU_API_MISSING` | Needs {need}; this node provides {have} (its doctor's GPU APIs) | P1 | – | `nodes.run_doctor` | – |
| `SECRETS_NOT_SET` | Its stage receives secrets {missing}, which have no value for this node | P1 | – | `secrets.set` | – |
| `DATASET_PLATFORM_MISMATCH` | Its dataset is bound to {platforms}; this node is {platform} | P1 | – | `jobs.cancel` | – |
| `OS_VERSION_UNSUPPORTED` | Module {module} needs another OS version than {os_version} (requires.os) | P1 | – | – | – |
| `TOOL_UNAVAILABLE` | Module {module} needs host tools the tool registry has no {os} paths for | P1 | – | `settings.tools.update` | – |
| `FOLDER_UNAVAILABLE` | Module {module} needs folders this node does not provide (unmapped, another access, refused by the node, or awaiting the owner's signature) | P1 | – | `settings.folders.update` | – |
| `SANDBOX_BACKEND_MISSING` | The agent on this node cannot sandbox module processes | P1 | – | – | – |
| `CAPABILITY_NOT_ENFORCED` | The node's sandbox cannot enforce {capability}, which module {module} needs | P1 | – | – | – |
| `AGENT_TOO_OLD` | Module {module} needs agent {need}; the node runs {have} | P1 | – | `agent.promote` | – |
| `PINNED_ELSEWHERE` | Pinned to node {node} | P1 | – | – | – |
| `POOL_JOBS_ONLY` | The node is yielding and takes only short pool jobs | P1 | – | – | – |
| `GPU_BLOCKED` | A GPU job: the node admits no more GPU jobs now (owner setting or a protected process is using the GPU) | P1 | – | – | – |
| `RETRIES_EXHAUSTED` | It failed {failures} times: its stage allows {max_attempts} attempts on {platform} (stages[].retry) | P1 | – | `jobs.cancel` | – |
| `FAILED_HERE` | It failed on this node before and another node can take it | P1 | – | – | – |
| `COMPARED_ON_PLATFORM` | A replica or tie-break that must run in class {class_}: the module compares results within one {scope} class (results.determinism_scope) | P1 | – | – | – |
| `DISPUTE_PARTY` | This node is a party to the job's dispute; a third node must break the tie | P1 | – | – | `dispute_party` |
| `DATASETS_NOT_REGISTERED` | Waiting for {missing} to be registered (a bootstrap job brings a module's pinned datasets) | P1 | – | – | – |
| `DATASETS_NOT_STAGED` | The node has not staged {missing} yet | P1 | – | – | – |

## node_admission

| Code | Message | Severity | Node / job fault | Remedies | End reasons |
|---|---|---|---|---|---|
| `NODE_PAUSED_BY_ADMIN` | Paused by {actor}: {reason} | P1 | – | `nodes.resume` | – |
| `NODE_DRAINING` | Draining | P1 | – | `nodes.resume` | – |
| `NODE_QUARANTINED` | Quarantined: {reason} | P3 | – | `nodes.clear_quarantine` | `node_quarantined` |
| `NODE_RETIRED` | Retired | P1 | – | – | `node_retired` |
| `RELEASE_PENDING` | Installing release {release} | P1 | – | – | – |
| `NOT_ADMITTING` | The agent admits no new work: {why} | P1 | – | – | – |
| `CLOCK_SKEW` | The node's clock is {offset_s} s off the coordinator's: jobs and moves use the coordinator's time, but certificates and update metadata need a correct clock; set the node's time | P3 | – | – | – |

## protection

| Code | Message | Severity | Node / job fault | Remedies | End reasons |
|---|---|---|---|---|---|
| `PROTECTION_CONFIG` | Protection config applied (mode {mode}, rules {rules}) | P1 | – | – | – |
| `PROTECTION_CONFIG_ERROR` | A protection config part is broken and ignored: {error} | P3 | – | – | – |
| `PROTECTION_ACTIVE` | Rule {rule} is active | P1 | – | – | – |
| `PROTECTION_CLEARED` | Rule {rule} is no longer active | P1 | – | – | – |
| `PROTECTION_RESERVED` | {mem_gb} GB and {cpu} cores held for {rules} | P1 | – | – | – |
| `PROTECTION_BINDING` | Rule {rule} binds the node's capacity | P1 | – | – | – |
| `CONSTRAINT_CHANGED` | The fleet constraint changed: {constraint} | P1 | – | – | – |
| `PROTECTION_EVICT` | Evicted by rule {rule}; requeued | P1 | no / no | – | `preempt_protection` |
| `PROTECTION_PAUSE` | Fleet attempts paused by rule {rule} | P1 | no / no | – | – |
| `PROTECTION_LOWER` | Fleet attempts lowered by rule {rule} | P1 | no / no | – | – |
| `PROTECTION_RESUME` | Paused attempts resumed | P1 | no / no | – | – |
| `PROTECTION_RESTORE` | Lowered attempts restored | P1 | no / no | – | – |
| `MEMORY_CLEAR` | Memory guard clear (free {free_pct}%) | P1 | – | – | – |
| `MEMORY_SOFT` | Memory soft floor: free {free_pct}%; admitting no new work | P2 | – | – | – |
| `MEMORY_HARD` | Memory hard floor: free {free_pct}%; evicting fleet jobs | P2 | – | – | – |
| `MEMORY_HARD_FLOOR` | Attempt {attempt} evicted by the memory hard floor ({why}) | P2 | – | – | – |
| `MEMORY_HARD_FLOOR_SERVICE` | Service {service} stopped by the memory hard floor ({why}); its jobs requeued | P2 | no / no | – | – |
| `PROTECTION_SERVICE_STOP` | Service {service} stopped by host protection ({reason}); its jobs requeued | P1 | no / no | – | – |
| `RUNG_0` | Dynamic rung 0: no constraint ({why}) | P1 | – | – | – |
| `RUNG_1` | Dynamic rung 1: admitting no new work ({why}) | P1 | – | – | – |
| `RUNG_2` | Dynamic rung 2: the fleet CPU budget is under the allocatable cores ({why}) | P1 | – | – | – |
| `RUNG_3` | Dynamic rung 3: fleet jobs lowered to background scheduling ({why}) | P1 | – | – | – |
| `RUNG_5` | Dynamic rung 5: fleet jobs paused ({why}) | P1 | – | – | – |
| `RUNG_6` | Dynamic rung 6: fleet jobs evicted ({why}) | P1 | – | – | – |
| `L2_EMERGENCY_LOWER` | Harm over twice its target ({pressure}) for two samples: fleet jobs lowered at once | P1 | – | – | – |
| `L2_RESTORED` | Harm back under its target for 30 s: lowered fleet jobs restored | P1 | – | – | – |
| `L1_TAKE_BACK` | Fleet CPU budget taken back to 0 (harm {pressure} or a memory guard); growth locked out | P1 | – | – | – |
| `L1_HALVE` | Fleet CPU budget halved to {budget} after a violation | P1 | – | – | – |
| `L1_GROW` | Fleet CPU budget grown to {budget} | P1 | – | – | – |
| `L1_HOLD_UNVALIDATED` | Fleet CPU budget held at {budget}: no validated signal for {rule} | P1 | – | – | – |
| `PROBE_HARM` | A pause probe measured harm {harm} to {rule} | P1 | – | – | – |
| `S16_GUARD` | Refused to act on process {pid}: it is not in the spawn registry ({why}) | P3 | – | – | – |
| `PROTECTION_FRONT_UNKNOWN` | The front app cannot be read here ({why}); frontmost rules count it as in front | P4 | – | – | – |
| `PROTECTION_PRESENCE_UNKNOWN` | Whether someone is at the machine cannot be read ({why}); it counts as someone present | P4 | – | – | – |
| `PROTECTION_UNREADABLE` | Rule {rule} matched {n} processes whose path or arguments could not be read (counted as matches) | P5 | – | – | – |
| `PROTECTION_NO_LOWERING` | This node cannot lower fleet jobs (no delegated cgroup with the cpu controller): pausable jobs are paused instead | P3 | – | – | – |
| `PROTECTION_NO_IPC_COUNTERS` | Rule {rule} protects ipc_ratio, but this node's processes have no instruction or cycle counters (a virtual machine): the metric is unknown and the fleet's CPU budget does not grow | P4 | – | – | – |
| `PROTECTION_SOURCE_ERROR` | The process table cannot be read: {error} | P3 | – | – | – |

## attempt_end

| Code | Message | Severity | Node / job fault | Remedies | End reasons |
|---|---|---|---|---|---|
| `OK` | Completed | P1 | no / no | – | `ok` |
| `EXIT_NONZERO` | The runner exited with code {code} | P1 | yes / yes | – | `exit_nonzero` |
| `INVALID_SPEC` | The runner rejected the spec (exit 2) | P1 | no / yes | – | `bad_input` |
| `MISSING_DEPENDENCY` | A node dependency is missing (exit 3); re-doctoring | P1 | yes / no | – | `doctor` |
| `RETRYABLE` | Transient failure (exit 75); released and retried | P1 | no / no | – | `transient` |
| `TIMEOUT` | Hit the {timeout_s} s limit | P1 | yes / yes | – | `timeout` |
| `LEASE_EXPIRED` | Lease expired (no heartbeat for {seconds} s) | P1 | yes / no | – | `lease_expired` |
| `AGENT_RESTARTED` | The agent restarted without the attempt | P1 | no / no | – | `agent_restart` |
| `RELEASE_INVALID` | Granted under a release the node no longer runs | P1 | no / no | – | `release_invalid` |
| `STALE_GENERATION` | The job was requeued after this attempt was granted | P1 | no / no | – | `stale_generation` |
| `LOST_RACE` | Another attempt finished first | P1 | no / no | – | `lost_race` |
| `MODULE_REVOKED` | Module {module} was revoked on the node | P1 | no / no | – | `module_revoked` |
| `GOLDEN_FAILED` | Golden jobs kept failing on the node; its certification stopped | P1 | no / no | – | `golden_failed` |
| `GOLDEN_SUPERSEDED` | A new golden set replaced this golden job | P1 | no / no | – | `superseded` |
| `OOM` | Killed for memory | P1 | no / yes | – | `oom` |
| `SANDBOX_ESCAPE` | A process of the attempt ran outside the module sandbox; the attempt was killed | P1 | no / yes | – | `sandbox_escape` |
| `PREEMPT_MEMORY` | Preempted by the memory guard | P1 | no / no | – | `preempt_memory` |
| `RELEASED_CAP_CPU` | Released: the CPU cap was lowered | P1 | no / no | – | `limit_cpu` |
| `RELEASED_CAP_MEM` | Released: over its declared memory under a memory floor, or the memory cap was lowered | P1 | no / no | – | `limit_mem` |
| `RELEASED_SCHEDULE` | Released: outside the owner's schedule | P1 | no / no | – | `limit_schedule` |
| `USER_CANCEL` | Cancelled by {actor} | P1 | no / no | – | `user_cancel` |
| `INPUT_INVALIDATED` | The upstream stage result was demoted | P1 | no / no | – | `input_invalidated` |
| `PLACEMENT_REBOUND` | Its unit of work moved to another platform class | P1 | no / no | – | `placement_rebound` |
| `JOB_CANCELLED` | The job was cancelled | P1 | no / no | – | `job_cancelled` |
| `JOB_QUARANTINED` | The job was quarantined | P1 | no / no | – | `job_quarantined` |
| `ATTEMPT_CLOSED` | The attempt was already closed | P1 | no / no | – | `attempt_closed` |
| `JOB_DONE` | The job was already done | P1 | no / no | – | `job_done` |

## verdict

| Code | Message | Severity | Node / job fault | Remedies | End reasons |
|---|---|---|---|---|---|
| `NO_METRICS` | The result carries no metrics | P1 | yes / yes | – | `no_metrics` |
| `BAD_ARTIFACT` | The result names an artifact without a name or files | P1 | no / yes | – | `bad_artifact` |
| `ARTIFACT_MISSING` | The result references artifacts the coordinator does not hold | P1 | yes / no | – | `artifact_missing` |
| `INPUT_MISSING` | A stage input (a dataset, a blob or the upstream result) was unavailable | P1 | yes / no | – | `input_missing` |
| `BOOTSTRAP_PIN_MISMATCH` | A bootstrap result is not exactly the module's pinned datasets: {detail} | P1 | no / yes | – | `pin_mismatch` |
| `RESULT_INVALID` | The result payload does not match the module's results.schema or exceeds results.max_inline_kb | P1 | no / yes | – | `result_invalid` |
| `MODE_MISMATCH` | The runner's effective mode is not the job's expected mode | P1 | yes / no | – | `mode_mismatch` |
| `INPUT_MISMATCH` | The score does not match its call's input digest | P1 | yes / no | – | `input_mismatch` |
| `GOLDEN_MISMATCH` | Golden job {golden} produced a different digest | P5 | yes / no | `nodes.recertify` | `golden_mismatch` |
| `DISPUTED` | Replicas disagree | P3 | no / no | – | `disputed` |
| `SELF_INCONSISTENT` | The node disagrees with its own earlier result | P5 | yes / no | – | `self_inconsistent` |

## invariant

| Code | Message | Severity | Node / job fault | Remedies | End reasons |
|---|---|---|---|---|---|
| `INVARIANT_VIOLATED` | Invariant {invariant} is false: {detail} | P5 | – | – | – |
| `INVARIANT_UNKNOWN` | Invariant {invariant} could not be checked: {detail} | P4 | – | – | – |

