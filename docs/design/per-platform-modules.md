# Per-platform modules: audit and design (PLAN D33)

Status: approved direction (owner, 2026-10-03); defaults for the open questions below are chosen in D33.

**Implementation status.** Built: every step (core 2.2.0, SDK 1.2.2). Part A was Steps 0, 1, 2, 3 and 5; part B is
Step 4 (placement, with stage retry) and Step 6 (bench 2.4.0, these docs). The install refusal of part A is gone:
`requires.features = ["placement"]` is implemented (`modstore.FEATURES`), and `determinism_scope` takes `os` and `arch`
(an unknown scope is the strictest).

How the build differs from the plan below:
- The release's stage entries carry `platforms`, but not timeouts or resources: the agent takes both from each grant's
  envelope, which claim resolves for the node.
- `requires.coordinator_platforms` is enforced for every active version (current, canary, pinned), since each runs a
  coordinator process. A forced move disables an unsupported module on the target with the alert
  `coordinator_platform_unsupported:<module>`. That is an alert rule, not an explain reason code: no job waits on it.
- `oarbank module show <name>` prints the platform matrix.
- **Stage retry.** `stages[].retry.max_attempts` (its variant for the failing node's platform) replaces the old fixed
  rule (3 failures on 2 hosts). A failure spends an attempt only when its end reason's code counts against the job (a
  host fault re-places the job; transient is no failure); the job is quarantined once no ready node that could run it
  has attempts left on its platform. Claim skips a node whose attempts are spent (`RETRIES_EXHAUSTED`) and explain shows
  the retries left per node. Golden failures keep their own per-node count.
- **Units.** A pipeline sub-unit is keyed under its campaign (`c:<cid>/p:<tail job id>`, or `.../s` under a pipeline
  unit), so a campaign's units are found by prefix. Datasets carry a `platform` column. A soft capacity binding that no
  attempt ran under yet follows the classes the work it gets allows. An unbound unit binds only to a class where, for
  every stage still ahead of the job, a ready certified node runs that stage and holds its pools (the "eligible
  certified nodes" part of the feasible set, resolved in the job's facts at claim and explain). A pinned unit (by the module or the operator) is
  never moved automatically: when stranded it raises the alert, whatever `rebind` says.
- **Rebinding** re-queues the unit's finished jobs as `jobs.retry` does: their own results stop being canonical, and
  jobs in other campaigns that reused those results through the cache run again too. Keeping those results canonical
  would give the re-run job two canonical results (S1). Running attempts are revoked (`PLACEMENT_REBOUND`), replicas
  are dropped, and every job's generation moves, so no late result from the old class is accepted.
- **Comparisons.** A dispute or replica carries its comparison class as `{scope, class}`; `COMPARED_ON_PLATFORM`
  checks the node's class under that scope.
- **The invariant is S20**, not S19: S19 already names the protection controller's property (docs/verification.md).
- `campaigns.set_placement` refuses a pinned campaign (move it with `campaigns.rebind_platform`). CampaignTickParams'
  `placement` is `{mix, unit, bind, rebind, pin, class, state, units, stranded}`: `class` and `state` are the campaign
  unit's (null for group, dataset and pipeline units) and `units` counts the units by state.
- The toy example has no coordinator variant or `platform_files` example (Step 6.2 skipped): it has no platform-specific
  code or files, so either would be invented filler, and it would have to raise its `requires.core` floor to 2.2. The
  SDK's fixture `tests/fixtures/manifests/per-platform.toml` covers both in its tests.

## Summary

Modules can already declare which node platforms they run on, override the runner per platform, and keep replicas within one platform. The coordinator side has no platform model at all. Several per-platform fields exist in the manifest, but the coordinator never enforces them. Nothing lets a module keep one unit of work (campaign, job group, pipeline, dataset) on one platform.

The design below adds this without bumping the manifest major:
- a separate list of coordinator platforms;
- per-platform override tables;
- a `[placement]` policy that binds each unit of work to one platform class.

Old cores are kept away from new manifests by a `requires.core >= 2.2` floor that the SDK enforces.

I also found a bug that affects every module today: `modcalls.job_uses_gpu` returns true for all modules (details in 2.3).

---

## 1. What exists today

### 1.1 How modules declare and validate platforms (SDK, `vendor/oarbank-sdk`)

| Item | Where |
|---|---|
| Platform tokens `<os>-<arch>` form an open set. Known values are `darwin\|linux\|windows` × `arm64\|amd64`. There is also a host-platform detector. | `src/oarbank_sdk/portable.py:12-35`, `spec/platforms.md` ("Platform tokens") |
| `PlatformToken` type | `manifest.py:21` |
| `requires.platforms` is required and lists **node** platforms only | `manifest.py:108-110`. Per-OS version ranges `requires.os`: `manifest.py:92-101` |
| `[runner.variants."<token>\|<os>"]` overrides `exec`, `runtime`, `capabilities`, `stop_grace_s` and `gpu`. The most specific key wins. | `manifest.py:267-273` (`RunnerVariant`), `292-302` (`Runner.for_platform`) |
| `platforms` filters on stages, services and probes | `manifest.py:314`, `345`, `362` |
| Cross-field checks: each variant key must be a declared platform or OS, and each filter a subset of `requires.platforms` | `manifest.py:468-480` |
| `[coordinator]` has **no** platforms, variants or env | `manifest.py:246-256` |
| `results.determinism_scope` is an open set, `global` or `platform` | `manifest.py:408-410` |
| `[goldens]` is only a fixtures glob plus a compare mode. Its description says "expected digest per runner variant", but nothing implements that. | `manifest.py:428-430` |
| One bundle holds every platform's files, with one digest | `spec/manifest.md:37-45`, `spec/bundles.md` |
| Wheels are fetched and checked for every declared platform | `deps.py:140,173` |
| `OARBANK_PLATFORM` is a [stable] variable for runners and services | `spec/runner-protocol.md:34`, `spec/service-protocol.md:12`. The SDK constant is at `runner_protocol.py:24`. |
| `SpecEnvelope.platform` [beta] | `envelopes.py:41` |
| `NodeClass.platform/os_version/cpu/gpus` [stable], passed to `golden.list` | `module_protocol.py:89-96`, `spec/module-protocol.md:26` |
| `HostInfo` has no platform | `module_protocol.py:56-59` |
| `PlanItem` has no platform or group fields | `module_protocol.py:117-123` |
| `NodesQueryResult` returns `{node_id, hostname, online, module_state}`, with no platform | `module_protocol.py:487-488`, `server.py:84-86` |
| `CampaignTickParams` and `CampaignJob` carry no platform | `module_protocol.py:297-315` |
| Conformance portability lint: Windows `.exe` checks only. The runner is tested only on the host platform's variant. The default node class has no platform. | `conformance.py:161-185`, `354`, `383-386`, `227` |
| `spec/vectors/` has canonical-json, job-key, platform-token and portable-path vectors. There is **no variant-resolution vector**. | |

### 1.2 Where the coordinator checks platforms (`src/oarbank/coordinator`)

- **Node platform.** It comes from hello facts v2 (`platforms.py:19-25`) and is stored in `nodes.platform/os/arch/os_version` (`db.py:26`, `core.py:158,351-355`). A platform change emits `platform_changed`.
- **Whether a module runs on a node.** `platforms.unsupported()` checks `requires.platforms`, then `requires.os`, then the tool registry (`platforms.py:121-142`). `modsandbox.node_exclusions` adds sandbox gaps and `requires.agent` (`modsandbox.py:85-109`). The result is `NodeView.excluded`, and the predicate `module_runs_here` turns it into the reason code (`predicates.py:42,96-98`).
- **Release composition.** Each platform has its own release (`releases.py:28-44`). `module_entry` renders `runner.for_platform(platform)` and keeps only the services and probes for that platform (`releases.py:62-95`). Stage entries do **not** carry `platforms` (`:73-74`), and `build` copies **every** bundle file to every platform (`:107-114`). This contradicts "a node stages only its platform's files".
- **Module install.** `_check_requires` checks core, module protocol and runner protocol only (`modstore.py:156-163`). The self-test spawns the coordinator once (`:243-260`). There is no check of the coordinator host's platform. The coordinator process runs `coordinator.exec` unchanged, with no variant (`modcalls.py:196-205`). Its env has no `OARBANK_PLATFORM` (`modulehost.py:135-136`, `modsandbox.py:74-77`).
- **Coordinator move.** `coordmove.prepare` chooses a coordinator build for the target node's platform (`coordmove.py:145-147`, `coordbuilds.py:139-150`). It does **not** check whether enabled modules' coordinator sides can run there.
- **Doctor and certification.** The agent runs doctor with the platform's variant, and `OARBANK_PLATFORM` is in `base_env` (`rust/.../doctor.rs:38-42`). Certification records the platform and OS version (`core.py:642-649`) and re-certifies when either changes (`core.py:552-554`).
- **Goldens.** `golden.list` gets `modcalls.node_class(node)`, which returns **only `capabilities` and `pools`** (`modcalls.py:416-429`). The SDK's stable `platform/os_version/cpu/gpus` fields are never filled, so a module cannot return platform-specific goldens. Expected values come straight from the module (`modcalls.py:432-454`). The comparison is `golden.compare` or digest equality (`modcalls.py:462-466`).
- **Scheduling predicates.** `predicates.placement` (`predicates.py:84-142`) checks target node, dispute party, **comparison platform** (`dispute.platform`, `COMPARED_ON_PLATFORM`, `:92,127-128`), module certification, datasets, cpu, memory, pools and gpu. It has **no** check for stage platforms, unit-of-work platform, or dataset platform. Claim walks candidates in `core.py:942-990`.
- **Pipelines.** `expand_pipeline` splits a job into head `call` (key `<key>:<head>`) and tail (`depends_on`) (`core.py:747-767`). The two can land on any platforms.
- **Effect of `determinism_scope`.** `_scope_platform` reads the **current catalog manifest** and the **current** `nodes.platform` of the producer (`core.py:1162-1172`). `_maybe_replicate` pins replicas to that platform (`core.py:1194-1212`). Replicas and tie-breaks carry `dispute_json.platform` (`:1214-1232`, `:1406-1431`). Results from different platforms are logged as `replica_other_platform` and never disputed (`:1417-1418`). Stranded checks pass `d.get("platform")` (`:1513-1521`, `:1536-1540`). `_other_node_can_take` **ignores** the dispute platform (`core.py:832-847`).
- **Result cache.** `effects.enqueue` reuses any canonical result for the key and module, **regardless of platform** (`effects.py:57-59`). The pipeline head cache does the same (`core.py:757-758`). Even with `determinism_scope="platform"`, a job can be satisfied by a result from another OS.
- **Runner exec and runtime per node.** These are picked at release time (`releases.py:71`). The agent reads `modules.json` format 2 for its platform (`rust/.../release.rs:32-39`) and runs `entry.runner.exec` (`jobs.rs:218-219`) with `stop_grace_s` (`jobs.rs:313`). The agent also filters services and probes with `on_this_platform` (`services.rs:104-114,163`).
- **Schema.** `campaigns`, `jobs` and `results` have no platform or binding columns (`db.py:51-56,62-69,84-88`). Reason codes include `PLATFORM_UNSUPPORTED` and `COMPARED_ON_PLATFORM` (`contracts/reason_codes.py:61,72`). `SpecEnvelope.platform` is never filled by `core.envelope()` (`core.py:879-900`).

### 1.3 What is already per-platform

- Runner variants: exec, runtime, capabilities, `stop_grace_s`, gpu.
- `platforms` filters on services and probes. These are enforced by the release and the agent.
- Stage `platforms`: declared but **not enforced** (see 2.3).
- Per-platform releases, agent builds and coordinator builds.
- Per-OS tool registry paths.
- `requires.os`.
- Wheels per platform.
- `determinism_scope=platform` for replicas.
- Re-certification on a platform change.

### 1.4 Example modules

- **Bench** (`oarbank-module-bench/oarbank-module.toml`): all six platforms, `determinism_scope="global"`. `run_all` targets every certified node with `target_node` (`bench_module/module.py:102-121`). Its single golden has one expected digest (`goldens/bench-golden.json`).
- **Toy** (`vendor/oarbank-sdk/examples/toy/oarbank-module.toml`): all six platforms, no variants, default scope. The core test fixture `tests/fixtures/modules/relay/oarbank-module.toml:56` limits a service to four platforms.

---

## 2. Gaps against the requirement

### 2.1 Coordinator side
1. A module cannot declare coordinator-side platform support, nor give coordinator-side overrides (exec, runtime, timeouts, env).
2. Install, enable and moves do not check the coordinator host platform.
3. The module's coordinator process does not learn its platform: there is no `OARBANK_PLATFORM` and no `HostInfo.platform`.

### 2.2 Per-platform requirements and adjustments
1. No per-platform stage resources, timeouts or retry.
2. No env (for example `MKL_CBWR`, `OMP_NUM_THREADS`, which matter for determinism).
3. No subsets of bundle files per platform.
4. No per-platform golden expectations.
5. No way to say "unsupported, because …" (an allow-list by omission only).

### 2.3 Fields declared but not enforced
1. `stages[].requires.platforms` is not checked in `predicates.placement` and is not in `modules.json` stages.
2. `node_class` omits `platform`.
3. `SpecEnvelope.platform` is never filled.
4. The variant-resolution vector is missing.
5. The reserved capability prefixes `os.` and `arch.` are never emitted.
6. **Bug:** `modcalls.runner_gpu` returns the `GPUNeed` object, and `job_uses_gpu` compares it to `"none"`, so it is **always true** (`modcalls.py:474-481`). I confirmed this: it printed `GPUNeed(use='none', …) True`. Every job is treated as a GPU job by `GPU_BLOCKED`, and per-platform `variants.gpu` is ignored at placement.

### 2.4 No way to keep a unit of work on one platform
1. No campaign, group, pipeline or dataset affinity.
2. No binding, no rebinding, no explain reason.
3. The result cache crosses platforms (`effects.py:57-59`).
4. Comparisons use the producer's *current* platform and the *current* manifest version, not a snapshot taken when the result was produced.
5. Modules cannot see node platforms (`nodes_query`), the platforms of their jobs' results (`jobs_query`, `CampaignJob`), or pin jobs to a platform without pinning a node.

### 2.5 Protocol and safety
The manifest reader is lenient (`_base.py:26-28`, `extra="allow"`), so a 2.1 core would **silently ignore** new constraint keys and mix platforms. New constraints therefore need a gate that old cores already enforce.

---

## 3. Design

### 3.1 Concepts
- **Runner support:** `requires.platforms`, unchanged and documented as node-side.
- **Coordinator support:** new `requires.coordinator_platforms`. Absent means any.
- **Platform class:** `class_key(token, mix)`. `any` gives `*`, `same-os` gives `linux`, `same-arch` gives `amd64`, `same-platform` gives `linux-amd64`. Strictness order: `any < same-os, same-arch < same-platform`; combining `same-os` with `same-arch` gives `same-platform`. An unknown value is treated as `same-platform` (fail safe), and the SDK `check` warns.
- **Unit of work:** a campaign, a group within a campaign, a dataset within a campaign, or a pipeline (head → tail, plus replicas and tie-breaks). Each unit has one binding: a class, or none yet.
- **Feasible classes of a unit:** classes of `requires.platforms`, intersected with the stage `platforms` of every stage the unit runs, with job and dataset `platforms`, and with eligible certified nodes. A unit only binds to a feasible class, so a head stage can never bind to a class where its tail cannot run.

### 3.2 Manifest additions (`manifest = 1`, additive)

```toml
[requires]
core = ">=2.2,<3"            # SDK rule: any key below needs core >= 2.2 (old cores refuse at install)
platforms = ["darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64"]               # runner (nodes)
coordinator_platforms = ["darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64"]  # coordinator; absent = any
features = ["placement"]     # must-understand list: core >= 2.2 refuses features it does not know

[requires.unsupported]       # optional reasons shown by explain/console; keys = token or OS; must not contradict allow-lists
runner = { windows-arm64 = "no arm64 build of the scorer" }
coordinator = { windows = "the planner relies on fork()" }

[coordinator.variants.linux]          # same resolution as runner variants (token > os > base)
exec = ["python", "-I", "{bundle}/bin/coordinator.py"]
timeouts_s = { default = 10.0, "job.plan" = 60.0 }
concurrency = 2
env = { OMP_NUM_THREADS = "1" }

[runner]
exec = ["python", "-I", "{bundle}/node/main.py"]
runtime = { kind = "python" }
env = { MKL_CBWR = "COMPATIBLE", OMP_NUM_THREADS = "1" }   # names ^[A-Z][A-Z0-9_]*$, never OARBANK_*, PATH, HOME, SystemRoot, TEMP...

[runner.variants.windows-amd64]
exec = ["{bundle}/native/windows-amd64/scorer.exe"]
runtime = { kind = "native" }
env = { KMP_AFFINITY = "disabled" }

[[stages]]
name = "call"
timeout_s = 3600
requires.resources = { cpu = 4, mem_gb = 8 }
[stages.variants.windows]             # per-platform stage adjustments
timeout_s = 5400
requires.resources = { mem_gb = 10 }
retry = { max_attempts = 4 }

[[stages]]
name = "score"
after = "call"
requires.platforms = ["darwin-arm64", "linux-amd64"]
placement = { mix = "same-platform" } # constraint between this stage and its `after` stage

[placement]                            # [beta]; absent = mix "any" (today's behaviour)
mix = "same-os"                        # any | same-os | same-arch | same-platform (open set)
unit = "campaign"                      # campaign | group | dataset | pipeline
bind = "capacity"                      # capacity | first-claim | explicit
rebind = "never"                       # never | if-stranded
stranded_after_s = 1800

[results]
determinism = "exact"
determinism_scope = "platform"         # open set gains "os" and "arch"

[bundle.platform_files]                # glob -> platforms/OSes that receive it; unmatched files go everywhere
"native/windows-amd64/**" = ["windows-amd64"]
"native/linux-*/**" = ["linux"]

[datasets]
kinds = ["index"]
platform_bound = ["index"]             # datasets of these kinds must carry `platform` at creation
```

**New SDK cross-field rules** (in `manifest.py` `_consistency`):
- Keys of variants, `unsupported` and `platform_files` must be declared tokens or their OSes. For the coordinator, check against `coordinator_platforms` when it is set.
- `unsupported` keys must not be in the allow-list.
- Env names must not be reserved.
- Stage variant resources stay within bounds.
- Using `placement`, `coordinator_platforms`, `coordinator.variants`, `stages[].variants`, `stages[].placement`, `env`, `platform_files` or `datasets.platform_bound` requires the lower bound of `requires.core` to be at least 2.2.
- The argv[0] of each variant exec must be included in that platform's file subset.
- Lint (warning): `mix` coarser than `determinism_scope` while `results.value` is set means values are compared across classes within a campaign.

A module whose results agree across platforms keeps `mix = "any"` (implicit); one whose results differ per platform
would use `mix = "same-platform"` with `unit = "campaign"`.

### 3.3 How module code sees the current platform
- **Runner:** `OARBANK_PLATFORM` already exists (`doctor.rs:42`, used by `jobs.rs:229`). Also fill `SpecEnvelope.platform` in `core.envelope()`.
- **Coordinator:** add `HostInfo.platform` [beta] and set `OARBANK_PLATFORM` in `modsandbox.coordinator_env` and in the `cli.exec` env. Document that verbs must keep `job_key`s platform-independent.
- **New SDK module `oarbank_sdk.platform`:** `current()` (env, falling back to `host_platform()`), `os_()`, `arch()`, `resolve(mapping, token)` (most specific wins), `class_key(token, mix)`, `stricter(a, b)`, `feasible(manifest, stages)`. Pin it with a new vector `spec/vectors/placement-class.json`, plus the missing `variant-resolution.json`.

### 3.4 SDK API for coordinator-side verbs
- **`host.nodes.query`** returns `platform, os, arch, os_version` and accepts a `platforms` filter. Add `Host.fleet_platforms(certified=True) -> {platform: n}`.
- **`host.jobs.query`** and `CampaignJob` gain `platform` (the platform of the canonical result's node). `CampaignTickParams.campaign` gains `placement {mix, unit, class, state}`.
- **`PlanItem`** gains `group` and `platforms`. `jobs.enqueue` items gain `group` (≤64 chars) and `platforms` (tokens or OSes).
- **`campaigns.create`** gains `placement {mix?, unit?, bind?, pin?}`. It may be stricter than the manifest, never looser (422 `placement_looser_than_manifest`). `datasets.create` gains `platform`.
- **Builders** in `effects.py`: `fx.placement(mix, unit=None, pin=None, bind=None)`, `fx.campaign_create(cid, name, priority=0, weight=1, labels=None, placement=None)`, `fx.jobs_enqueue(cid, jobs)`, `fx.job(job_key, spec, *, group=None, platforms=None, target_node=None, ...)`.
- **Goldens:** `Golden` gains `platforms` and `expected_by_platform {key: expected}`. New helper `oarbank_sdk.goldens.load(root, glob, node_class)` filters and resolves them.
- **Host capabilities** in `HostInfo.capabilities`: `placement.v1`, `nodes.platform`, `goldens.by_platform`, `coordinator.variants`. Add `ctx.host_has(cap)`, so runtime-only use of the new effect arguments can check for support.
- **Example, bench `run_all` per platform:** group `nodes_query` by `platform`. For each platform, emit `campaign_create(f"c_bench_{p.replace('-','_')}_{stamp}", placement=fx.placement("same-platform", pin=p))` and enqueue that platform's jobs. Results are then compared only within each campaign.

### 3.5 How the coordinator enforces it

**Schema** (`db.py`):
- `jobs`: add `placement_unit TEXT`, `platforms_json TEXT`, `group_key TEXT`.
- `results`: add `platform TEXT`, a snapshot taken when the result is recorded.
- `campaigns`: add `placement_json TEXT`.
- New table: `placement_bindings(unit PK, module, mix, class, state unbound|soft|hard|pinned, source first_claim|capacity|cache_hit|pin|rebind|dataset, bound_at, bound_job, bound_node, generation)`.

**Unit derivation** happens in `effects.enqueue`, `expand_pipeline`, `_maybe_replicate` and `_check_replica`. The unit is `c:<cid>`, `c:<cid>/g:<group>`, `c:<cid>/d:<dataset>`, or `p:<tail job_id>`. A pipeline whose stage `placement` is stricter gets a pipeline sub-binding inside the campaign unit. Replicas and tie-breaks inherit the unit, plus `class_key(result.platform, determinism_scope)`.

**Predicates.** These go in `predicates.placement`, after "comparison platform". They stay pure: `_job_facts` (`core.py:869`) resolves `placement {mix, class, feasible}`, so claim and explain stay at parity.
- `STAGE_PLATFORM_UNSUPPORTED`: fixes the existing gap. Covers stage `platforms`, job `platforms`, and the feasible set.
- `PLATFORM_BOUND_ELSEWHERE`: binding set and `class_key(node, mix) != class`.
- `DATASET_PLATFORM_MISMATCH`.
- `PLACEMENT_UNPINNED`: `bind = "explicit"` and no pin yet.
- Generalise `COMPARED_ON_PLATFORM` to classes.

**Binding inside `claim()`** (one transaction, single writer, so first-claim is race-free):
- Pass an in-memory binding map through the candidate loop.
- When an eligible job's unit is unbound, set it to `soft` with `class_key(node.platform, mix)`.
- `bind = "capacity"` binds softly at campaign creation, or at first enqueue, to the feasible class with the most free certified CPU. If no node is certified yet, it falls back to first claim.
- The first accepted result in `complete()` makes the binding `hard`. A cache hit also makes it hard (source `cache_hit`).
- A soft binding with no live attempts and no accepted results is released by the reaper. A failed first attempt therefore never strands a unit.

**Result cache.** In `effects.py:57-59` and `core.py:757-758`, when `mix != any` or the scope is not global, a hit must match the unit's class on `results.platform`. If the unit is unbound and `bind = "first-claim"`, a hit binds the unit.

**Comparisons.** `_scope_platform` uses `results.platform` and the manifest of the version that produced the result. `_eligible_nodes`, `_other_node_can_take` and `_stranded_disputes` take a class filter, which also fixes `core.py:832-847`.

**Rebinding.** For each bound unit with pending work and no eligible node of its class for `stranded_after_s`:
- A soft binding is released.
- With `rebind = "never"`, raise the alert `placement_stranded:<unit>` with the remedy `campaigns.rebind_platform`.
- With `rebind = "if-stranded"`, rebind automatically to the best feasible class. Re-queue the unit's done jobs (generation+1, `canonical_result_id` NULL; the results stay canonical for other campaigns' jobs). Write an audit row and an info alert.

**New operations:**
- `campaigns.set_placement` (T2, stricter only before the first result).
- `campaigns.rebind_platform` (T2; the plan lists the done jobs to re-queue).

**Goldens:**
- `modcalls.node_class` adds `platform, os_version, cpu, gpus`.
- `modcalls.goldens` drops goldens whose `platforms` exclude the node, and resolves `expected_by_platform` (token, then OS, then default) before `_insert_goldens` stores `spec.expected`.
- Certification per platform already works (`core.py:552-554,646-649`).

**Coordinator side:**
- `modstore._check_requires` and `enable` refuse a module whose `coordinator_platforms` excludes `portable.host_platform()` (`COORDINATOR_PLATFORM_UNSUPPORTED`).
- `modcalls._spec` uses `coordinator.for_platform(host)`.
- `coordmove.prepare`/preflight compute the target platform (the node's platform, or a new `b_platform` in the pairing body for URL targets) and block on unsupported enabled modules. With `force`, those modules start disabled on the target, with an alert.

**Per-platform resources:**
- `enqueue` stores the manifest default plus `by_platform` overrides in `resources_json`, but only when the item sets no explicit resources.
- `claim()` and explain resolve them for the node. `envelope()` resolves `timeout_s`.
- The release's `module_entry` gains `runner.env`, `stages[].platforms`, `timeout_s` and resources per platform.
- `build()` filters files through `platform_files`, and `wheels/` by tag (`deps.wheel_fits`).

**Invariant S19** (`invariants.py`): every live, leased or done job of a bound unit ran on, or got its canonical result from, a node of the unit's class. This includes cache hits.

### 3.6 Versioning and backward compatibility
- The manifest stays at `1`: every change is additive (`spec/versioning.md:9,46-50`). Old cores are blocked by the SDK-enforced `requires.core >= 2.2` floor, which `_check_requires` in core 2.1 already refuses. Add `requires.features` as a must-understand list for later.
- Bump `CORE_VERSION` to 2.2.0 (`modstore.py:34`).
- Module protocol stays major 1, with optional fields plus host capability strings.
- SDK version 1.1.0. Regenerate `schemas/manifest-1*.schema.json` and `spec/manifest-reference.md`.
- Existing modules behave exactly as today (`mix = any`, coordinator any). Toy and bench need no change.

### 3.7 Console and CLI
- **Module page:** a platform matrix (six known tokens × runner and coordinator support, with `unsupported` reasons, nodes and certified counts), the placement policy, and a warning when the current coordinator platform is unsupported.
- **Campaign list and page:** a placement column, e.g. `linux-amd64 · hard` or `any`. Show `placement_stranded`, plus Rebind and Set placement actions.
- **Job and attempt views:** the result's `platform`.
- **Explain:** the new reason codes, added in `reason_codes.py` with remedies.
- **CLI:** `oarbank campaign show` prints placement; new `oarbank campaign rebind <id> --platform linux-amd64` and `oarbank campaign placement <id> --mix same-os`. `oarbank module show` prints the matrix. The move plan lists blocking modules.

### 3.8 Tests

**SDK:**
- `tests/test_platforms.py`: variant resolution for coordinator, stages and env; `class_key` vectors; the core floor rule; reserved env names; contradictions in `unsupported`; `platform_files` exec coverage.
- New fixture manifests in `tests/fixtures/manifests/`.
- Conformance:
  - manifest suite: per declared platform, a resolved view of exec, file subset and coordinator variant per coordinator platform; warn on an unknown `mix`;
  - protocol suite: by default one node class per declared platform (with `platform`), each with ≥1 golden; `expected_by_platform` keys must be declared; purity per class; check that `initialize` gets `host.platform`;
  - runner suite: expected values resolved for the host platform, variant env applied, `DoctorOutput.attrs.platform == OARBANK_PLATFORM`.
- CI on macOS, Linux and Windows (exists).

**Coordinator** (new `tests/test_placement.py`, plus extensions):
- binding by first claim, capacity and explicit pin;
- `same-os` mixes arm64 and amd64 Linux;
- groups spread across platforms but stay together;
- pipeline head and tail stay in one class, and the head never binds to an infeasible class;
- dataset `platform`;
- the cache is filtered by class;
- a soft binding is released after a failed first attempt;
- stranded units raise the alert, or rebind with re-queueing, and `invariants.check_all` stays ok;
- a looser campaign placement is refused;
- a regression test that toy and relay behave as before.

Other coordinator tests:
- `test_explain.py`: extend the claim/explain parity property to mixed fleets and the new predicates.
- `test_stateful.py` and `sim.py`: mixed platforms (`sim.py:150` hardcodes darwin-arm64); add S19.
- `test_module_sandbox.py`: stage platforms enforced.
- `test_robustness.py`: comparisons use `results.platform` after a node changes platform.
- Goldens: `node_class` includes platform, and `expected_by_platform` is resolved per node.
- Coordinator side: install and enable refused on an unsupported host (monkeypatch `host_platform`); variant exec used; `OARBANK_PLATFORM` and `host.platform` present; `test_coordinator_move.py` blocks a move to an unsupported target.
- Releases: file subsets and `modules.json` stage platforms.
- The GPU bug.

---

## 4. Implementation plan, in order

**Step 0: fix gaps that do not depend on the new design** (coordinator; small; each step has its own test).
1. `modcalls.node_class` includes `platform/os_version/cpu/gpus`. *Acceptance:* `golden.list` receives the node's platform; a test checks it.
2. Enforce `stages[].requires.platforms` in `predicates.placement` and add it to `modules.json` stages. *Acceptance:* a stage limited to darwin is never granted to a Linux node; explain shows `STAGE_PLATFORM_UNSUPPORTED`.
3. Fix `runner_gpu`/`job_uses_gpu` to use `runner.for_platform(node).gpu.use`. *Acceptance:* a non-GPU job is not blocked by `gpu_cap=0`.
4. Add the `results.platform` column. `_scope_platform` uses it and the version that produced the result. `_other_node_can_take` respects the dispute platform. *Acceptance:* the existing `test_robustness.py:189` passes, plus a test where a node changes platform.
5. Fill `SpecEnvelope.platform`; set `OARBANK_PLATFORM` in the coordinator env. *Acceptance:* the envelope and the env carry the token.
6. SDK: add `spec/vectors/variant-resolution.json` and a test that the coordinator reproduces it.

**Step 1: SDK 1.1.0.**
1. Add `oarbank_sdk.platform` and the placement-class vectors.
2. Manifest models and cross-field rules (3.2); regenerate the schemas and the reference.
3. Module protocol fields and host capability names (3.4).
4. Effect builders, the goldens helper, `Host.fleet_platforms`.
5. Bundle `platform_files` validation and lint.
6. Conformance updates (3.8).
7. Docs: `spec/platforms.md` gains "Per-platform declarations" and "Placement"; also update `manifest.md`, `module-protocol.md`, `conformance.md`, `versioning.md` and `docs/tutorial.md`.

*Acceptance:* CI is green on all three OSes, toy and bench validate unchanged, and the new fixtures cover every key.

**Step 2: coordinator side** (coordinator 2.2).
1. Install and enable checks; coordinator variants; `HostInfo.platform`.
2. Move preflight blockers.
3. Console and CLI matrix.

*Acceptance:* tests from 3.8; the move plan names the blocking modules.

**Step 3: per-platform runner adjustments.**
1. `module_entry` renders env, stage timeouts and resources per platform.
2. `build()` subsets files and wheels.
3. Resources resolved at claim and in explain.
4. Agent (Rust): apply `runner.env` in `jobs.rs` after `base_env`, refusing reserved names; same for doctor and services. No other agent change: subsets are covered by the MANIFEST.json check.

*Acceptance:* a Windows node's release has no darwin-only files; a stage's Windows timeout reaches the envelope and the hard deadline.

**Step 4: placement.**
1. Schema and unit derivation (enqueue, pipeline, replicas).
2. Predicates and binding in `claim()`, at explain parity.
3. Cache filter.
4. Soft and hard bindings, stranded detection, rebind policy, the two new ops.
5. Effect arguments `placement`, `group`, `platforms`; `datasets.create` platform.
6. Invariant S19, the stateful machine, the mixed-fleet simulator.
7. Console and CLI.

*Acceptance:* every placement test in 3.8 passes; `oarbank verify` is clean after a 1000-job mixed-fleet simulation; an old module's behaviour is byte-identical in the existing suites.

**Step 5: goldens per platform.** Host-side resolution of `platforms` and `expected_by_platform`; conformance.

*Acceptance:* a module with different digests on Windows and Linux certifies on both and is disputed on neither.

**Step 6: modules and design docs.**
1. Bench: `run_all` per platform (one pinned campaign per platform) and `requires.core >= 2.2`.
2. Toy: a coordinator variant and a `platform_files` example.
3. Notes for modules whose results differ per platform: `mix = "same-platform"`.
4. Add the decision to `docs/design/PLAN.md` (as D33).

**Open questions for the owner:**
- Default `bind`: I propose `capacity` for campaigns and `first-claim` for groups, datasets and pipelines.
- Default `rebind`: I propose `never`, which raises an alert.
- Whether an unknown `mix` should mean the strictest setting: I propose yes.
- Whether Windows counts as a coordinator platform now.

### Critical files for implementation
- vendor/oarbank-sdk/src/oarbank_sdk/manifest.py
- vendor/oarbank-sdk/src/oarbank_sdk/module_protocol.py
- src/oarbank/coordinator/predicates.py
- src/oarbank/coordinator/core.py
- src/oarbank/coordinator/modcalls.py

Also involved: `src/oarbank/coordinator/effects.py`, `releases.py`, `modstore.py`, `coordmove.py`, `db.py`, `invariants.py`, `vendor/oarbank-sdk/src/oarbank_sdk/conformance.py`, `rust/crates/oarbank-agent/src/jobs.rs`.