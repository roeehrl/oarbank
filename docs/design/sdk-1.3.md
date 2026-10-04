# SDK 1.3 and core 2.3: what a real module needed

Status: design for the six open issues on the public SDK repository (oarbank-sdk #2–#7). Each was written with the
SDK's invented `render` example; a real module, minos-gatk, works around every one of them today. One release
resolves them all: **oarbank-sdk 1.3.0** and **core 2.3.0**.

**Implementation status.** Built as designed (SDK 1.3.0, core 2.3.0). Where the build adds to the design:
- S21 judges each row by the module version that produced the result involved (golden results, a replica's original,
  the disputed results, the cached result), so a later version changing a stage's determinism raises no false alarm.
  The Hypothesis machine runs ingestion jobs on the relay fixture's `sync` stage beside its studies.
- `host.datasets.query` already scoped kinds by owning module; only the manifest text was wrong.
- The conformance kit also fails a golden run that the egress proxy refused a connection for.
- Released with the same version: the conformance stop check is timed to the runner's own acknowledgement
  (`failure.json` with `fault = "transient"`, `Control.acknowledge_stop`, sent once the runner wrote its first
  `phase`) within 2 s and to its exit within `stop_grace_s`, instead of process exit within 0.5 s (it flaked on loaded
  CI runners); the kit has one owner of a runner's wait; `Control` ignores nudges again at exit, so a nudge during
  interpreter teardown never kills a finished runner; `sandbox.interpreter_roots` never grants a shared prefix.
- Core, found on the way: capacity binding and the stranded check use the claim path's per-stage test (a unit no longer
  binds where a later stage's pool is missing, and is stranded when its class loses it), and `campaigns.set_placement`
  fences pending jobs' late results.
- `stages[].requires.capabilities` is enforced per stage: the agent's doctor report carries the capabilities its
  offered services and healthy probes provide (docs/protocol.md "Doctor"), and the claim path, explain
  (`STAGE_CAPABILITY_MISSING`), capacity binding, the stranded check, replica runners and failure anti-affinity check
  them against the job's stage, as they check its pools.

## Versioning, for all six

- **Manifest 1 and module protocol 1 stay.** Everything below is additive: new optional keys, new optional protocol
  fields, one new host capability.
- **New manifest keys need `requires.core >= 2.3`**, enforced by the SDK as the per-platform keys need 2.2 (manifest
  rule 12). A 2.2 core reads manifests leniently and would ignore them silently, which for these keys means wrong
  behaviour (replica disputes on ingestion jobs, a chain expanded when a stage was meant, effects that fail with 501).
  The keys: `stages[].determinism`, `stages[].default`, the coordinator capability `campaign.tick.results`, and the
  effect kinds `datasets.update` and `datasets.delete` in any effects list (`coordinator.campaign_effects`,
  `operations[].effects`, `coordinator.move.effects`). The SDK's floor check becomes one table of `(key, floor)`
  instead of one floor for every key.
- **Run-time features get a host capability.** `jobs.enqueue` `stage` is the only one that a manifest does not reveal:
  the host advertises `jobs.stage`, and a module that sends `stage` without raising its floor checks
  `ctx.host_has("jobs.stage")` (a 2.2 host ignores the field).
- `CORE_VERSION` becomes 2.3.0. The core's catalogue reads the new keys from the SDK models (no core-side copy).

## #2 Per-stage determinism: utility stages opt out of replica checks

**Shape.** `[[stages]].determinism`: `"exact" | "within_tolerance" | "none"`, optional [beta]. Absent, a stage
inherits `results.determinism`. A stage whose effective determinism is `none` does not **compare**: its results are a
function of when it ran (an ingestion `sync` job pulling a moving feed), not of its inputs.

The issue offered per stage or per `jobs.enqueue` item (`replicate = false`). Per stage wins: it is declared in the
manifest, so an operator reviews it at install, and with #5 a module can give utility work its own stage. A per-job
switch would let module code turn checks off at run time for any job, which weakens what certification promises.

**Validation (SDK).**
1. A stage in the chain (`after` another, or the one another is `after`) does not set `determinism`: head and tail are
   one evaluation and compare as `results.determinism` (the tail's digest is checked against its head's).
2. At least one stage compares (effective `exact` or `within_tolerance`): goldens need one, and every module is
   certified on golden evidence.
3. Needs `requires.core >= 2.3`.

**Coordinator.** `modcalls.compares(module, stage, version)` answers from the manifest of the module version that
produced the result (else the current one). A job of a stage that does not compare:
- is never sampled for a replica (`_maybe_replicate`);
- is never compared after it is done: a late second result is recorded `job_done` and nothing else, so neither
  `self_inconsistent` (two honest runs differ) nor a dispute can follow;
- neither takes nor serves a result-cache hit (`placement.cache_hit`): its result belongs to the run, not the key;
- never runs as a golden: a golden that names such a stage, or names none while the default stage does not compare, is a
  module error (`golden.list` faults, nothing is queued, the node is not charged, as for a golden `spec.build` cannot
  build);
- is otherwise an ordinary job: generation fencing, certified nodes only (S8), stage retry, placement (S20), and a
  node later convicted of nondeterminism has these results recomputed too.

**Invariant S21** (new): a job of a stage that does not compare never has a replica, a dispute or a golden, and never
shares a canonical result with another job through the cache. It joins the catalogue, so the Hypothesis machine, the
simulator, the Verify page and `oarbank verify` check it. It reads the catalogue's manifests (the live check loads
them).

**SDK conformance.** A golden for a stage that does not compare fails the protocol suite; the runner suite's
"deterministic across locales" check uses the golden's stage's determinism.

**Edge cases.** A version that changes a stage's determinism applies to results it produces; a replica queued under the
old version is not compared when either version says the stage does not compare. `within_tolerance` keeps today's
behaviour (digests decide, else values to 6 dp).

## #3 campaign.tick sees structured results

**Shape.** The coordinator capability `campaign.tick.results` (requires `campaign.tick`; `requires.core >= 2.3`).
For such a module each `CampaignJob` that is done carries `result`:
`{payload, artifacts: [{name, files: [{path, digest, size}]}]}`, the canonical result's payload and its uploaded
artifacts. The issue's other option, an `object` result field, would make the payload's structure a second schema
beside `results.schema`; the canonical payload already has a declared schema and an inline size limit.

**Validation (core, at acceptance).** For a module version that declares the capability, the payload of every result
of an evaluation (kind `eval`: a standalone or explicitly staged job, or a chain's merged result) must validate
against `results.schema` (JSON Schema, from the version's bundle) and fit `results.max_inline_kb` (compact UTF-8
JSON). Otherwise the verdict is `result_invalid` (reason code `RESULT_INVALID`): the attempt ends failed, it spends
the job's stage retry (the job is quarantined once no node has attempts left), and it never trips the node's breaker. So
nothing invalid is ever canonical, and the tick never re-validates. Head, replica and golden results are not
delivered and are not validated.

**Delivery.** `result` comes only from a canonical result that a capability-declaring version accepted (a cache hit
from an older version gives `result: null`). One tick carries at most 8 MiB of results (the RPC message limit is
16 MiB): done jobs newest first; a done job left out carries `result_omitted: true`. Ticks run per campaign, so an
ingestion campaign's few results are never crowded out by another campaign's evaluations.

## #4 Dataset effects, and the kind form

**Kinds are short everywhere.** A dataset row has a `kind` and an owning `module`; the module column scopes kinds,
so two modules' `archive` never collide. `datasets.create` takes the short kind, which must be one of
`[datasets].kinds` (422 `undeclared_kind`); `host.datasets.query {kind}` takes the short kind and returns the module's
own datasets plus the operator's unowned ones of that kind; `DatasetRef.kind` is the short kind. The manifest text
"stored namespaced" was never implemented (`datasets.register` refuses a `/` in a kind) and goes.

**`datasets.create` with an existing id.** The same module's dataset with the same kind, meta, files and platform:
skipped (a repeat is harmless, so a stateless tick can re-issue it). Anything else: 409 `dataset_exists`, and the
whole tick or operation fails, as for `campaigns.create`. Another owner's id: 409 `dataset_owned`.

**`datasets.update {dataset_id, meta}`** merges `meta` key by key at the top level; a key set to `null` is removed.
`kind`, `files` and `platform` never change (422 `dataset_immutable`): nodes stage a dataset's files by id, so new
files need a new id. Only the module's own datasets (403 `not_owner`); an unknown id is 404 `unknown_dataset`.

**`datasets.delete {dataset_id}`** removes the module's own dataset (403 `not_owner` otherwise); an unknown id is a
no-op, as `store.delete`. Refused with 409 `dataset_in_use` while a pending or leased job names it, and for the
host's artifact datasets (`art:…`, 422 `host_dataset`), which stage chains and the result cache read. Blobs stay.

SDK builders `fx.datasets_update` and `fx.datasets_delete`; `spec/module-protocol.md` documents all three effects
and the kind form.

## #5 jobs.enqueue selects a stage; the default stage is explicit

**Shape.** A `jobs.enqueue` item may carry `stage` (a stage name). Absent: the evaluation form, today's behaviour (the
default stage, or the chain head → tail when the module's pipeline is split). Present: the job runs exactly that
stage and is never expanded into the chain. `fx.job(..., stage=...)`; host capability `jobs.stage`.

`[[stages]].default = true` [beta] names the default stage (the single-stage form). Rules: at most one stage sets it,
and only a standalone stage (neither `after` another nor depended on); when more than one stage is standalone,
exactly one sets it (the old "first standalone stage" rule was ambiguous); needs `requires.core >= 2.3`.

**Coordinator.**
- `stage` must name a declared standalone stage (422 `bad_stage`): a chain stage alone has no input (tail) or would
  leave its tail behind (head).
- The job stores its stage; only stage-less jobs expand (`expand_pipeline`, `modules.set_pipeline`), so a utility job
  never spends a tail job.
- Resources default to that stage's; its timeout, retry and platforms are that stage's. Item `platforms` must leave a
  platform the stage runs on (422 `placement_infeasible`), and the job's placement unit is joined with that stage's
  feasible classes (an unbound unit binds only where the stage has a node), so placement and stage platforms hold as
  for any job. Claim and explain read the same facts (`_job_facts`), so they agree.
- The envelope and `result.evaluate` get the stage the job runs; the default stage stays absent, as today, so a
  runner sees one form whether the default stage was named or implied.
- `campaign.tick` and `host.jobs.query` show the job's `stage`.

**Edge cases.** The result cache is keyed by `job_key`; keys of different stages differ when modules use
`keys.job_key(..., stage)` (documented). A campaign unit (unit `campaign`) opens with the classes where the default
form runs, as today; a staged job narrows it further.

## #6 conform runs non-golden runner specs under the sandbox and the egress proxy

**Shape.** Fixtures (`conformance.json`, which ships in the bundle) may list `runner_specs`:
`{name, stage?, payload, datasets?, mounts?, expect: {exit (default 0), artifacts?, reason?}}`.

**Kit.** Each spec runs exactly as a golden does: its envelope (the stage's resources and timeout for this host's
platform), its fixture datasets mounted, a clean environment, this host's sandbox backend with the module's grants,
and for `egress-allowlist` the reference proxy enforcing `allow` (redirects to allowed hosts work: the client opens a
new proxied connection per host). The runner suite reports per spec: the exit code against `expect.exit`; for exit 0 a
valid `ResultEnvelope` (artifact names are `Name`s, which also catches names a real agent refuses) and the artifact
names against `expect.artifacts`; otherwise a valid `failure.json` and its `reason` against `expect.reason`. For every
run (goldens included), a connection the proxy refused fails the check "egress within the allowlist", naming the
hosts, even if the runner tolerated it. A spec for a chain tail is a fixture error (it would need inputs); a spec whose
datasets the fixtures lack, or whose stage reserves the `containers` pool, is skipped with the reason.

## #7 deps compile: one marker-free requirements file for every declared platform

**Shape.** `oarbank-sdk deps compile <module-dir> <requirements.in> [-o FILE] [-- uv args]` and
`oarbank_sdk.deps.compile(root, man, src, out=None, uv_args=())`.

**Which platforms a requirements file serves** (one function, used by `compile`, `check` and `download`): the
runner's file (beside the runner script) every node platform whose runner (its variant applied) runs that script;
the coordinator's file (bundle root) `requires.coordinator_platforms`, or `requires.platforms` when that is absent
(any platform: the node platforms stand in, as today); a file that is both serves both sets.

**Compile.**
1. Resolve the input once per platform with uv (`uv pip compile --python-platform <target> --python-version 3.12
   --only-binary :all: --generate-hashes`, extra uv args passed through), leaving out the host-provided closure with
   `--no-emit-package`.
2. Unify: a package resolved to different versions on different platforms fails, naming each version and its
   platforms, with every conflict in one report ("pin one version with wheels everywhere in requirements.in"). A
   package only some platforms need (a Windows-only `colorama`) is pinned for every platform, provided its version has
   a wheel on the others: uv checks that per platform (`--no-deps`); if not, the report names the package, the
   platforms that need it and those without a wheel. Hashes are the union over platforms.
3. Write one file, sorted, `name==version` with `--hash=sha256:` lines, no markers, with a header naming the
   platforms and the left-out packages. `deps.check` and `bundle wheels` accept it as is.

**The host-provided closure** is computed from the installed SDK's metadata: `oarbank-sdk` and, transitively, every
requirement that is not behind an `extra` marker (pydantic, jsonschema, jinja2 and their dependencies). It replaces the
hand-kept list in `parse_requirements`, so a module can no longer pin, say, `attrs` or `markupsafe` that the host's
SDK already provides (an overlay environment would shadow the host's copy).

`deps.download` fetches each file's wheels for the platforms that file serves; `deps.check` checks the same set.

## Tests

SDK: manifest rules and floors (every new key below 2.3 refused), builders, schema freshness, conformance (a golden
on a non-comparing stage; runner specs passing, failing on exit code, artifact names and a `failure.json` reason;
egress through the proxy with a redirect to an allowed host, and refused egress), deps (platform sets, closure,
compile with real uv against local wheels: conflicts, partial packages, hashes, the written file passing `check`).

Core: the relay fixture gains a standalone `sync` stage with `determinism = "none"` and an explicit default stage.
Per behaviour: no replica, no comparison of late results, no cache in either direction, goldens refused, S21 (and a
deliberately broken database it catches); stage selection (no expansion under split, resources, platforms and
placement, `bad_stage`, envelope stage, explain agrees with claim); tick results (delivered, budget and
`result_omitted`, old versions, `result_invalid` spends retries and never the breaker); dataset effects (create
repeat and conflict, update merge and immutables, delete ownership, in-use and artifact refusals, kind validation).
