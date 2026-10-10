# Bootstrap stages: a module provisions its own datasets on a fresh fleet

Status: built as designed (owner decision: bootstrap stages; PLAN D34) in **oarbank-sdk 1.4.0** and **core 2.4.0**.
Amended by [stage-gating.md](stage-gating.md) (PLAN D43): a bootstrap job now runs wherever the module's runner starts
(its doctor printed a DoctorOutput, healthy or not), not only where the doctor is healthy, and an unmapped host tool or
folder no longer keeps it off a node.
Found on the way: a bundle whose manifest does not validate made `oarbank_sdk.bundle.verify` raise pydantic's error
instead of a `BundleError`, so the core's install crashed on it instead of refusing it; it is a `BundleError` now.

## The problem

A module that provisions its own tools and reference data (minos-gatk: the GATK jar, fgkl, nine chromosome references)
does it with fetch jobs: a job downloads pinned files from public origins through its egress allowlist and uploads them
as artifacts, and the module's `campaign.tick` registers each one with `datasets.create`. On a fresh fleet that never
starts. Every non-golden job needs a node certified for the module (S8), certification needs the goldens to pass, and
the goldens mount the datasets the fetch jobs would bring. The minos-gatk 3.2.0 canary got past it only because the
operator registered the datasets by hand.

## The decision

A **bootstrap stage** is a standalone stage with `determinism = "none"` that declares `bootstrap = true`. Its jobs may
run on a node where the module's doctor is healthy but its goldens have not passed yet. What makes that safe is the
**pinned dataset table**, `[[datasets.pinned]]`: every dataset a bootstrap job may produce, file by file, with each
file's sha256 and size, declared in the manifest. The coordinator registers a bootstrap job's output only when it is
exactly one of those datasets, so a wrong or malicious node, or an origin that changed under the module, can never
register anything else.

A bootstrap job gets less than any other job of its module, not more: the module's egress allowlist and nothing else
(no host tools, containers, GPU, written-file execution, module data directory or module settings). Its result is never
compared, replicated, cached or golden-tested (already true for `determinism = "none"`), never counts toward
certification, and carries nothing but the pinned datasets.

## Manifest (SDK)

```toml
[[stages]]
name = "fetch"
bootstrap = true                  # runs where the module's runner starts, before the goldens pass
determinism = "none"              # required: a bootstrap stage never compares
timeout_s = 3600
requires = { resources = { cpu = 1, mem_gb = 1.0 } }

[[datasets.pinned]]
dataset_id = "tool:gatk-4.5.0.0"
kind = "tool"                     # one of [datasets].kinds
meta = { version = "4.5.0.0" }    # optional: the registered dataset's meta
# platform = "linux-amd64"        # optional; required for a [datasets].platform_bound kind
files = [{ path = "gatk-package-4.5.0.0-local.jar", sha256 = "<64 hex>", size = 1234567 }]
```

**Where the pins live.** Inline in the manifest, not in a separate bundle file. The manifest is part of the bundle, so
the pins are covered by the bundle digest the operator installs and approves by, and by the signed release that carries
the bundle to nodes; one document holds every fact an operator reviews; the core reads the pins from the SDK's own
`Manifest` model, as it reads every other manifest fact (no core-side copy, no second loader or schema); and the same
validation runs in `oarbank-sdk check`, at install and in the core's catalogue. A module's coordinator code reads its
pins from its own manifest (`oarbank_sdk.manifest.load`), so the module keeps one source of truth for what it fetches.

**Fields.** `Stage.bootstrap: bool = False` [beta]. `Datasets.pinned: list[PinnedDataset]` [beta], where
`PinnedDataset = {dataset_id, kind, meta = {}, platform = null, files: [{path, sha256, size}]}`; `path` is a
PortablePath, `sha256` 64 lowercase hex digits, `size` bytes (an integer, at least 0).

**Rules** (spec/manifest.md, new rule 15; the lint list becomes 16; all errors, in `oarbank-sdk check` and at install):
1. `bootstrap` is set only on a standalone stage (neither `after` another nor depended on) that is not the default
   stage: a job runs it only when it names the stage, so the evaluation form never runs as bootstrap.
2. A bootstrap stage's effective determinism is `none`.
3. A bootstrap stage reserves and needs no pools (`requires.pools`, `requires.needs_pools`): bootstrap jobs get no
   container broker, no GPU and no module services.
4. A module with a bootstrap stage has a non-empty `[[datasets.pinned]]`, and pins need a bootstrap stage (nothing
   else reads them).
5. Pins: unique `dataset_id`s (the core's dataset id form, `^[A-Za-z0-9][A-Za-z0-9_.:+-]{0,127}$`); `kind` is one of
   `[datasets].kinds`; `platform` is one of `requires.platforms` and is set exactly when the kind is platform-bound;
   at least one file, unique paths; no two pins hold the same set of files (an artifact names its pin by its files).
6. With a bootstrap stage, `sandbox.net.mode` is `none` or `egress-allowlist`: `egress-any` is a full-trust grant that
   bootstrap jobs never get.
7. `stages[].bootstrap` and `datasets.pinned` need `requires.core >= 2.4` (rule 12's floor table gains a 2.4 row; a
   2.3 core would ignore both silently and then never run the stage on an uncertified node, or register unchecked
   datasets through `datasets.create`).

## Runner side: the bootstrap grants

spec/sandbox.md gains "Bootstrap jobs". The agent runs a job of a stage the release marks `bootstrap` with:
- read-only: the bundle and its runtime, as any runner;
- read-write: the job's work directory only. No module data directory: `OARBANK_MODULE_DATA` is not set, so nothing
  a bootstrap job downloads persists on the node outside the coordinator's pin check;
- network: the module's `egress-allowlist` through the agent's proxy, or none when the module's mode is `none`;
- no host tools (`OARBANK_TOOLS_FILE` lists none), no GPU, no container broker, no execution of written files;
- module settings: an empty object (`OARBANK_SETTINGS_FILE`), since operators keep credentials there.

The SDK states this once as `SandboxSection.for_bootstrap()`, which the conformance kit uses; the agent applies the
same narrowing from the release's module entry (`stages[].bootstrap`, which the coordinator writes from the manifest),
never from anything in the grant, so it follows the signed release. An agent that implements it reports
`grants.bootstrap = "enforced"` in its facts' `sandbox.enforcement`; the coordinator grants bootstrap jobs only to such
nodes (`CAPABILITY_NOT_ENFORCED` otherwise), so an older agent never runs one with the module's full grants.

**The result.** A bootstrap runner writes a ResultEnvelope with an empty `payload` and one artifact per dataset it
fetched; each artifact's files are exactly one pin's files (its paths, and after the agent's upload their digests and
sizes). `effective` and `provenance` are not stored. The host does not call `result.evaluate` for a bootstrap job and
does not validate its payload against `results.schema`: the verdict is the pin check, so no module code ever reads a
bootstrap node's output.

## Coordinator

**Claim and explain** (one predicate set, D16). A bootstrap job's module check passes where the module is
`certifying` or `certified` on the node: its doctor is healthy and its release current (`doctor_failed`, `undetected`
and `golden_failed` are `MODULE_NOT_READY`; `revoked` stays `MODULE_NOT_CERTIFIED` until the node's next doctor report
starts its certification again). Everything else is checked as for any job: sandbox, platforms,
OS version, tools, agent range, stage platforms, capabilities, pools, placement, datasets, retries, failure
anti-affinity. A new predicate "bootstrap grants enforced" (`CAPABILITY_NOT_ENFORCED`) applies to bootstrap jobs.
Explain names the module check `module_ready_for_bootstrap(<module>)` for them and adds a system action saying the job
runs as a bootstrap job and what that means; a leased bootstrap job's headline says "running as a bootstrap job".

The node-wide questions that decide whether anyone can run a job (`_retry_possible`, `_other_node_can_take`,
`placement.classes_running`, `placement.capacity_class`) count a node that is certifying as able to run a bootstrap
stage; otherwise the first failed fetch on a fresh fleet would quarantine the job, and a unit holding only bootstrap
jobs would never find a class.

**Goldens that wait for pinned datasets.** A golden names datasets that may not be registered yet. A new predicate,
"datasets registered" (`DATASETS_NOT_REGISTERED`, before "datasets staged"), says so instead of "not staged yet", and
`prefetch` lists only registered datasets (an agent asked for an unknown one fails and retries every heartbeat). The
golden stays pending; once the bootstrap job's datasets are registered the node stages them, runs the goldens and is
certified. `certifying_stuck` still fires after 30 minutes, and its detail names the unregistered datasets and whether
a bootstrap stage of the module provides them.

**Acceptance.** For a bootstrap job, `complete()`:
1. fences as usual (closed attempt, settled job, quarantined or retired node, stale job generation) except the
   certification generation: a bootstrap result never depended on certification, so a node certified (or re-certified)
   while it fetched keeps its result. Revocation still ends a bootstrap attempt (it kills every live attempt).
2. checks the result against the pins of the module version the attempt ran (the current version when that one is no
   longer active): the payload is empty; there is at least one artifact; each artifact's files equal exactly one pin's
   files (path, sha256, size) with the blobs held by the coordinator, whose size the coordinator measured on upload.
3. on success records the canonical result (`{envelope, schema, module_version, payload: {}, artifacts}`, empty
   fields) and, in the same transaction, registers each pinned dataset with the pin's kind, meta, platform and files,
   owned by the module (event `dataset_imported`, actor `bootstrap`). An existing dataset with the same contents is
   left as it is; one with other contents (an operator's hand registration, say) is never overwritten: the result is
   still accepted and the P3 alert `pinned_dataset_conflict:<id>` names the difference. No `art:` datasets are made.
4. on failure records the verdict `pin_mismatch` (reason code `BOOTSTRAP_PIN_MISMATCH`) naming the artifact and the
   first file that differs; nothing is registered.

**The fault for a mismatch: the job's, never the node's breaker.** The attempt ends `failed`, spends one of the job's
attempts (`stages[].retry`), and `FAILED_HERE` moves the job to another node; the job is quarantined once no node that
could run it has attempts left, and the event and explain name the pinned file. The node is not charged
(`counts_against_node = false`), for three reasons. The likeliest cause is the origin, which every node would see the
same way (a re-published release asset, a moved mirror), and the remedy is a new module version with new pins, not a
re-doctored fleet. A bad node cannot hurt anything: nothing it sent is registered, and the job runs elsewhere. And the
breaker exists to stop a node's results from becoming canonical through certification, which a bootstrap node does not
have yet. A missing blob stays `artifact_missing` (the node's), as for any job.

**Effects.** `datasets.create` for a pinned id must equal its pin (kind, files, platform, and meta when the pin sets
it), else 422 `pin_mismatch`; so a module's own code can register a pinned dataset (an importer, an operation), but
only with its pinned contents. `datasets.update` (meta) and `datasets.delete` work on pinned datasets as on any of the
module's datasets; a deleted pinned dataset is provisioned again by the next bootstrap job.

**What else a bootstrap job may emit: nothing.** No store records, no settings, no files, no effects: effects come only
from module code (`campaign.tick`, operations), which sees a done bootstrap job (and with `campaign.tick.results` its
empty payload and pinned artifacts) and nothing a node chose.

**Already true, and kept:** never a replica, never compared, never cached, never a golden (`determinism = "none"`,
S21); certification only ever follows goldens, which a bootstrap result never is or feeds.

**Release entry.** `stages[]` entries carry `bootstrap: true` for a bootstrap stage (only then, so other entries keep
their bytes).

**No new approval.** A bootstrap stage asks for no grant: it narrows the module's approved grants. The pins are covered
by the bundle digest the operator installs, approves and signs releases over.

## Invariants

- **S8** (amended): a live non-golden attempt runs a module certified on its node under the current certification, or
  is a bootstrap attempt on a node where the module is certifying or certified.
- **S14** (amended): every canonical result carries its module's verdict; a bootstrap job's verdict is the host's pin
  check (empty fields).
- **S22** (new): a bootstrap job's canonical result is exactly pinned datasets of the module version that produced it:
  an empty payload, and artifacts that each hold one pin's files. (What a pinned id holds in the registry is not an
  invariant: an operator may register any dataset by hand, which `pinned_dataset_conflict` reports.)

The Hypothesis machine, the simulator, the Verify page and `oarbank verify` check S22 with the rest of the catalogue.

## Failure modes

| What happens | What the coordinator does |
|---|---|
| An origin serves other bytes than pinned | Every attempt fails `pin_mismatch` (the job's fault); the job is quarantined once retries are spent; the event names the file, the pinned and the received digest. Remedy: a module version with new pins. |
| A node returns a wrong or forged file | Its attempt fails `pin_mismatch`; nothing is registered; the job runs on another node. |
| A node never uploads a file | `artifact_missing`, the node's fault, as for any job. |
| The result carries a payload or an extra artifact | `pin_mismatch`; nothing is registered. |
| An operator registered the id by hand with other contents | The result is accepted, nothing is overwritten, alert `pinned_dataset_conflict:<id>`. |
| The node's agent predates bootstrap grants | The job waits there with `CAPABILITY_NOT_ENFORCED`. |
| No node's runner starts (its doctor does not run) | The job waits with `MODULE_NOT_READY`, explain saying the runner did not start (stage-gating.md). |
| The node is certified while it fetches | The result is accepted (no certification fence for bootstrap jobs). |
| The module is revoked or disabled on the node while it fetches | The attempt is ended as for any job; the job runs again. |
| A golden waits for a dataset nobody provisions | It waits with `DATASETS_NOT_REGISTERED`; `certifying_stuck` names the datasets after 30 minutes. |
| A module version changes the pins while a job runs | The verdict uses the pins of the version the attempt ran, else the current one. |

## Versioning

- `CORE_VERSION` 2.4.0; oarbank-sdk 1.4.0. Manifest 1 and module protocol 1 stay: additive keys gated by rule 12's
  floor table, which gains `(stages[].bootstrap, 2.4)` and `(datasets.pinned, 2.4)`.
- No host capability: everything is declared in the manifest, and the core floor keeps older cores out.
- The facts key `sandbox.enforcement["grants.bootstrap"]` is new (spec/platforms.md, spec/sandbox.md); an agent
  without it never gets a bootstrap job.

## Conformance

A `runner_specs` entry whose stage is a bootstrap stage runs under the bootstrap grants: the reference proxy with the
module's allowlist, no tools, empty settings, no module data directory, the narrowed sandbox profile. For exit 0 the kit
checks, besides the usual envelope: the payload is empty; there is at least one artifact; every artifact's files,
hashed from the work directory, equal exactly one pin's files ("artifacts match the pinned datasets", naming the
first file that differs). `expect.artifacts` still checks names. So `oarbank-sdk conform` proves a fetch against the
real origins, under the real allowlist, before a module is published.

## Tests

SDK: every rule above (determinism, default, chain, pools, pins required and pins without a bootstrap stage, pin
fields, duplicate file sets, egress-any, the 2.4 floor); `for_bootstrap()`; schemas regenerated; conformance with a
bootstrap runner spec passing, failing on a changed file, on an extra artifact and on a payload.

Core, with a fixture module (`depot`: an `eval` stage whose goldens mount a pinned tool, a bootstrap `fetch` stage and
a `provision` operation):
- a fresh fleet: the node is certifying and its golden waits (`DATASETS_NOT_REGISTERED`); the provision operation's
  fetch job is granted to the uncertified node, its pinned artifacts are accepted and the datasets registered; the
  node stages them, passes its golden and is certified; an eval job then runs;
- a dataset that does not match its pin is refused (`pin_mismatch`), the attempt failed as the job's fault (retry spent,
  breaker untouched), nothing registered; a payload or an unpinned extra artifact likewise;
- a node without `grants.bootstrap` and a node whose doctor failed never get a bootstrap job; explain says why, and
  shows the bootstrap module check and system action;
- a bootstrap stage without `determinism = "none"`, without pins, or with `requires.core` below 2.4 is refused at
  install (the SDK's model, which the core uses);
- `datasets.create` of a pinned id with other files is refused;
- the release entry marks the stage; S8, S14 and S22 hold, and S22 catches a deliberately broken database;
- `certifying_stuck` names the pinned datasets a node's goldens wait for.

Agent: the bootstrap grants as a pure function of the release entry and the job's stage (unit tests), applied in
`jobs::execute`; the facts key on every backend. End to end (tests/rust/test_agent_jobs.py): depot on a real agent and
a real oarbankd, from a fresh node to certified, the fetch job sandboxed with the bootstrap grants (depot's runner
fails if it sees a module data directory, a tool or the node's module settings).
