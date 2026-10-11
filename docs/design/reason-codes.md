# Reason codes (generated)

Generated from `oarbank.contracts.reason_codes`. Module codes use `<module-short>/<code>`. The last column lists the attempt end reasons the agent and oarbankd write for a code.

## job_pending

| Code | Message | Severity | Node / job fault | Remedies | End reasons |
|---|---|---|---|---|---|
| `NO_ELIGIBLE_NODE` | No node can run this job right now | P1 | – | `jobs.set_priority` | – |
| `QUEUED_BEHIND` | Eligible, but behind {ahead} higher-priority jobs | P1 | – | `jobs.set_priority` | – |
| `DEPENDENCY_UNMET` | Waiting for stage {stage} (job {job_id}) | P1 | – | – | – |
| `CAMPAIGN_PAUSED` | Campaign {campaign} is not running | P1 | – | `campaigns.resume` | – |
| `CAMPAIGN_SETTING_HOLDS` | Its campaign's settings hold its jobs here: {setting} ({have}) | P1 | – | `settings.apply` | – |
| `OARBANK_PAUSED` | The fleet is paused | P1 | – | `fleet.resume` | `fleet_halt` |
| `BACKOFF` | Retrying after {seconds} s (backoff) | P1 | – | – | – |
| `POOL_EXHAUSTED` | No free {pool} token ({free} free, {need} needed) | P1 | – | – | – |
| `POOL_ABSENT` | The node offers no {pool} pool | P1 | – | – | – |
| `INSUFFICIENT_CPU` | Needs {need} cores, {free} allocatable | P1 | – | – | – |
| `INSUFFICIENT_MEM` | Needs {need} GB, {free} GB allocatable | P1 | – | – | – |
| `USER_CAP_BINDING` | Owner cap {cap} is binding | P1 | – | `settings.apply` | – |
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
| `SETTINGS_NOT_SET` | Module {module} needs settings {missing}, which have no value for this node | P1 | – | `settings.apply` | – |
| `DATASET_PLATFORM_MISMATCH` | Its dataset is bound to {platforms}; this node is {platform} | P1 | – | `jobs.cancel` | – |
| `OS_VERSION_UNSUPPORTED` | Module {module} needs another OS version than {os_version} (requires.os) | P1 | – | – | – |
| `TOOL_NOT_FOUND` | Module {module} needs a host tool this node does not have: {tools} | P1 | – | `tools.detect`, `tools.define` | – |
| `TOOL_VERSION_UNMET` | Module {module} needs another version of a host tool: {tools} | P1 | – | `tools.detect` | – |
| `TOOL_REFUSED` | Module {module} needs a host tool whose path this node refused: {tools} | P1 | – | `tools.detect` | – |
| `FOLDER_UNAVAILABLE` | Module {module} needs folders this node does not provide (unmapped, another access, refused by the node, or awaiting the owner's signature) | P1 | – | `settings.folders.update` | – |
| `SANDBOX_BACKEND_MISSING` | The agent on this node cannot sandbox module processes | P1 | – | – | – |
| `CAPABILITY_NOT_ENFORCED` | The node's sandbox cannot enforce {capability}, which module {module} needs | P1 | – | – | – |
| `AGENT_TOO_OLD` | Module {module} needs agent {need}; the node runs {have} | P1 | – | `updates.start`, `agent.promote` | – |
| `PINNED_ELSEWHERE` | Pinned to node {node} | P1 | – | – | – |
| `POOL_JOBS_ONLY` | The node is yielding and takes only short pool jobs | P1 | – | – | – |
| `GPU_BLOCKED` | A GPU job: the node admits no more GPU jobs now (owner setting or a protected process is using the GPU) | P1 | – | – | – |
| `RETRIES_EXHAUSTED` | It failed {failures} times: its stage allows {max_attempts} attempts on {platform} (stages[].retry) | P1 | – | `jobs.cancel` | – |
| `FAILED_HERE` | It failed on this node before and another node can take it | P1 | – | – | – |
| `COMPARED_ON_PLATFORM` | A replica or tie-break that must run in class {class_}: the module compares results within one {scope} class (results.determinism_scope) | P1 | – | – | – |
| `DISPUTE_PARTY` | This node is a party to the job's dispute; a third node must break the tie | P1 | – | – | `dispute_party` |
| `DATASETS_NOT_REGISTERED` | Waiting for {missing} to be registered (a bootstrap job brings a module's pinned datasets) | P1 | – | – | – |
| `DATASETS_NOT_STAGED` | The node has not staged {missing} yet | P1 | – | – | – |
| `SITE_UPLINK_BUSY` | Network-heavy: site {site} holds such work while {why} | P1 | – | – | – |
| `SITE_UPLINK_BUDGET` | Network-heavy: site {site} already runs {running} of its {max} network-heavy jobs | P1 | – | `sites.update` | – |

## node_admission

| Code | Message | Severity | Node / job fault | Remedies | End reasons |
|---|---|---|---|---|---|
| `NODE_PAUSED_BY_ADMIN` | Paused by {actor}: {reason} | P1 | – | `nodes.resume` | – |
| `NODE_DRAINING` | Draining | P1 | – | `nodes.resume` | – |
| `NODE_QUARANTINED` | Quarantined: {reason} | P3 | – | `nodes.clear_quarantine` | `node_quarantined` |
| `NODE_RETIRED` | Retired | P1 | – | – | `node_retired` |
| `RELEASE_PENDING` | Installing release {release} | P1 | – | – | – |
| `NO_RELEASE` | No release yet: install and enable a module | P1 | – | `modules.install`, `modules.enable` | – |
| `RELEASE_UNSIGNED` | Release {release} for {platform} is waiting for the owner's signature: oarbank release sign {release} --promote | P1 | – | `releases.attach_signature` | – |
| `NOT_ADMITTING` | The agent admits no new work: {why} | P1 | – | – | – |
| `CLOCK_SKEW` | The node's clock is {offset_s} s off the coordinator's: jobs and moves use the coordinator's time, but certificates and update metadata need a correct clock; set the node's time | P3 | – | – | – |
| `LISTENER_UNAVAILABLE` | Listener {listener} is not open on this node: {why} | P1 | – | `listeners.configure` | – |
| `PORT_TAKEN` | Listener {listener}: the router forwards its external port to another device: {text} | P3 | – | `listeners.configure` | – |
| `DOUBLE_NAT` | Listener {listener}: this machine is behind two routers: {text} | P3 | – | – | – |
| `CGNAT` | Listener {listener}: the provider shares one public address among many customers: {text} | P3 | – | – | – |
| `NO_MAPPING_PROTOCOL` | Listener {listener}: the router accepts no automatic port mapping: {text} | P3 | – | `listeners.configure` | – |
| `MAPPED_UNREACHABLE` | Listener {listener}: mapped, but connections from outside do not arrive: {text} | P3 | – | `listeners.probe` | – |
| `FIREWALL_BLOCKED` | Listener {listener}: this machine's firewall blocks incoming connections: {text} | P3 | – | – | – |

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
| `MEMORY_HARD_FLOOR_WORKLOAD` | Workload {workload} stopped by the memory hard floor ({why}) and held until the guard is clear | P2 | – | – | – |
| `WORKLOAD_PAUSE` | Workload {workload} paused (it tolerates {tolerance_s} s) | P1 | – | – | – |
| `WORKLOAD_RESUME` | Workload {workload} resumed | P1 | – | – | – |
| `WORKLOAD_LOWER` | Workload {workload} lowered to background scheduling | P1 | – | – | – |
| `WORKLOAD_RESTORE` | Workload {workload} restored from background scheduling | P1 | – | – | – |
| `WORKLOAD_THROTTLE` | Workload {workload} throttled: {threads} threads, a CPU cap of {cpu_cap} cores | P1 | – | – | – |
| `WORKLOAD_HOLD` | Workload {workload} stopped and held by host protection ({cause}) | P2 | – | – | – |
| `WORKLOAD_PAUSE_TOLERANCE` | Workload {workload} was paused for its tolerance ({tolerance_s} s): stopped and held while the pause would last | P2 | – | – | – |
| `WORKLOAD_RELEASE` | Workload {workload} released from its hold ({cause} cleared after {held_s} s) | P1 | – | – | – |
| `WORKLOAD_STOP` | Workload {workload} stopped by the agent | P1 | – | – | – |
| `DELEGATE_PAUSE` | Delegated processes of rule {rule} paused ({processes}) | P1 | – | – | – |
| `DELEGATE_RESUME` | Delegated processes of rule {rule} resumed ({processes}) | P1 | – | – | – |
| `DELEGATE_LOWER` | Delegated processes of rule {rule} lowered ({processes}) | P1 | – | – | – |
| `DELEGATE_RESTORE` | Delegated processes of rule {rule} restored ({processes}) | P1 | – | – | – |
| `DELEGATE_PAUSE_LIMIT` | Delegated processes of rule {rule} were paused for the pause ceiling: resumed and lowered instead (a delegation never stops them) | P2 | – | – | – |
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
| `PROTECTION_SOURCE_UNREADABLE` | Rule {rule}: source {source} cannot be read by the agent; protection holds fleet work back until it reads | P3 | – | – | – |
| `PROTECTION_SOURCE_NEEDS_HELPER` | Rule {rule}: source {source} is in a person's home and no session helper reports it (nobody logged in?); protection holds fleet work back | P3 | – | – | – |
| `PROTECTION_PHASE_ON` | A phase of rule {rule} began ({via}) | P1 | – | – | – |
| `PROTECTION_PHASE_OFF` | A phase of rule {rule} ended ({via}) | P1 | – | – | – |
| `GPU_NOT_CERTIFIED` | gpu_jobs = certified, but no valid co-tenancy certificate covers {rules}: fleet GPU work waits | P4 | – | `protection.ab.sweep` | – |
| `AB_STARTED` | Harness run {run_id} started on rule {rule} ({work}) | P1 | – | `protection.ab.abort` | – |
| `AB_ON` | Harness run {run_id}: the work under test runs (an ON window) | P1 | – | – | – |
| `AB_OFF` | Harness run {run_id}: the work under test is held (an OFF window) | P1 | no / no | – | – |
| `AB_IDLE` | Harness run {run_id} ended: its work runs as protection allows | P1 | – | – | – |
| `AB_FINISHED` | Harness run {run_id} ended: {decision} ({why}) | P1 | – | – | – |
| `AB_REFUSED` | Harness run {run_id} refused by the node: {why} | P4 | – | – | – |
| `GPU_DUTY_START` | GPU duty budget {duty} beside the protected GPU work (certified ceiling {ceiling}): {why} | P1 | – | – | – |
| `GPU_DUTY_BASELINE` | Fleet GPU work held for a minute to measure the protected program without it ({why}) | P1 | – | – | – |
| `GPU_DUTY_GROW` | GPU duty budget grown to {duty} after a clean minute (certified ceiling {ceiling}) | P1 | – | – | – |
| `GPU_DUTY_HALVE` | GPU duty budget halved to {duty}: the protected program slowed to its target | P1 | – | – | – |
| `GPU_DUTY_TAKE_BACK` | GPU duty budget taken back to 0: {why} | P3 | – | – | – |
| `GPU_DUTY_CLAMP` | GPU duty budget lowered to the certified ceiling {ceiling} | P1 | – | – | – |
| `GPU_DUTY_EXCEEDED` | {unit} kept the GPU {measured} busy against a gpu_duty of {duty} for three samples: {action} (the third time within an hour stops it, and it gets no duty for an hour) | P3 | – | – | – |
| `GPU_DUTY_UNVERIFIED` | The GPU time of {unit} cannot be read, so its gpu_duty cannot be checked: {action} | P4 | – | – | – |
| `TRANSFER_PAUSED` | A {transfer} transfer paused: {why} | P1 | no / no | – | – |
| `TRANSFER_RESUMED` | A {transfer} transfer resumed after {paused_s} s | P1 | – | – | – |
| `SITE_PAUSE` | Network-heavy attempts paused: their site is in an uplink phase | P1 | no / no | – | – |
| `SITE_RESUME` | Network-heavy attempts resumed: their site's uplink phase ended | P1 | no / no | – | – |

## workload

| Code | Message | Severity | Node / job fault | Remedies | End reasons |
|---|---|---|---|---|---|
| `WORKLOAD_UNASSIGNED` | {workload} is not assigned to this node | P1 | – | `workloads.assign` | – |
| `WORKLOAD_SEAT_ELSEWHERE` | {workload}'s seat (its identity) is held by another node until that node gives it up or its lease ends | P1 | – | `workloads.unassign` | – |
| `WORKLOAD_SEAT_LEASE_EXPIRED` | {workload}'s seat lease ran out on this node (no word from the coordinator in time): stopped | P2 | – | – | – |
| `WORKLOAD_HELD` | {workload} is held down by host protection ({reason}) | P1 | – | – | – |
| `WORKLOAD_WITHDRAWN` | {workload} failed {failures} times in a row and was withdrawn: {error} | P2 | – | `workloads.restart` | – |
| `WORKLOAD_RESTART` | {workload} restarted by the owner | P1 | – | – | – |
| `WORKLOAD_SECRETS_NOT_SET` | {workload} receives secrets that have no value for this node | P1 | – | `secrets.set` | – |
| `WORKLOAD_IDENTITY_SHARED` | {workload} has a per-node identity, and a secret it receives is set for a group or the whole module: set it for each node | P1 | – | `secrets.set` | – |
| `WORKLOAD_NO_CONTAINMENT` | This node cannot contain a workload ({detail}) | P1 | – | – | – |
| `WORKLOAD_POLICY_OFF` | This node's workloads setting is off | P1 | – | `settings.apply` | – |
| `WORKLOAD_NOT_OFFERED` | {workload} cannot run on this node ({detail}) | P1 | – | – | – |
| `WORKLOAD_NODE_NOT_ACTIVE` | The node is not active (paused or draining): its workloads are stopped | P1 | – | `nodes.resume` | – |

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
| `AGENT_STOPPED` | The agent on the node was stopped (its service stopped or restarted); released and requeued | P1 | no / no | – | `agent_stop` |
| `RELEASE_INVALID` | Granted under a release the node no longer runs | P1 | no / no | – | `release_invalid` |
| `STALE_GENERATION` | The job was requeued after this attempt was granted | P1 | no / no | – | `stale_generation` |
| `LOST_RACE` | Another attempt finished first | P1 | no / no | – | `lost_race` |
| `MODULE_REVOKED` | Module {module} was revoked on the node | P1 | no / no | – | `module_revoked` |
| `GOLDEN_FAILED` | Golden jobs kept failing on the node; its certification stopped | P1 | no / no | – | `golden_failed` |
| `GOLDEN_SUPERSEDED` | A new golden set replaced this golden job | P1 | no / no | – | `superseded` |
| `OOM` | Killed for memory | P1 | no / yes | – | `oom` |
| `SANDBOX_ESCAPE` | A process of the attempt ran outside the module sandbox; the attempt was killed | P1 | no / yes | – | `sandbox_escape` |
| `PREEMPT_MEMORY` | Preempted by the memory guard | P1 | no / no | – | `preempt_memory` |
| `PREEMPT_SITE` | Released: a network-heavy job that cannot pause, or paused too long, while its site was in an uplink phase; requeued | P1 | no / no | – | `preempt_site` |
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

