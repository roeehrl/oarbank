# Stage gating: doctor checks and certification gate only the stages that need them

Status: built (PLAN D43), unreleased: core after 2.8.0, oarbank-sdk after 1.5.0. Amends
[bootstrap-stages.md](bootstrap-stages.md) (which nodes run a bootstrap job) and the claim, doctor and certification
sections of [docs/protocol.md](../protocol.md).

## The problem

A fleet of five darwin-arm64 nodes and one windows-amd64 node running minos-gatk 4.0.0: its bootstrap campaign
(four `fetch` jobs and two `profile` jobs) and its live rounds (one `sync` job) all pending, unbound, nothing leased.
The darwin nodes' minos-gatk doctors all reported:

- `java17`: failed, "java17 is not granted on this node (no granted path has bin/java)", so the module said
  `undetected`;
- `pysam_import`: failed, a `dlopen` error cut at 300 characters;
- every other check passed.

Four things kept every job off every node, though `fetch` (pinned downloads) and `sync` (round ingestion) need neither
a JDK nor pysam:

1. **The tool registry had no darwin path for `java17`**, so every darwin node excluded the module outright
   (`TOOL_UNAVAILABLE`), for every stage, bootstrap ones included, though a bootstrap job never gets host tools at all.
2. **Any failed doctor check gated every stage.** The agent offered only `healthy` modules in claims, and the
   coordinator let a bootstrap job run only where the module was `certifying` or `certified`, which needs a healthy
   doctor. One unrelated dependency blocked a fresh fleet's bootstrap.
3. **Every non-bootstrap stage waited for certification**, which for minos-gatk needs JDK 17, pysam and containers.
   `sync` compares nothing and needs nothing a node must prove, yet waited; the live rounds it archives are gone after
   about five days.
4. **Explain said only "No node can run this job right now"**, with per-node codes in the summary, so it did not say
   which requirement no node met.

Two reporting faults made it harder to see: the `pysam_import` detail was cut to its first 300 characters, hiding the
cause at its end, and `oarbank node show` listed `vulkan` as a GPU API in containers on a Mac while showing no
container runtime.

## Decisions

### 1. A stage that needs no certification runs wherever the module's runner starts

`Manifest.certification_exempt(stage)` (oarbank-sdk) names two kinds of stage:

- a **bootstrap stage** (as before);
- a stage whose effective determinism is **`none`** and that requires **no capability and no pool**
  (`requires.capabilities`, `requires.pools`, `requires.needs_pools` all empty).

Their jobs run on a node where the module is in a state its doctor decides (`certified`, `certifying`,
`doctor_failed`, `undetected`, `golden_failed`; not `revoked`, and not before any doctor report) and **its runner
started**: its doctor printed a DoctorOutput for the node's current release, healthy or not. Health is the verdict on
the module as a whole, for certification; it no longer decides these stages. Everything else is checked as for any job
(platforms, sandbox enforcement, the bootstrap grants for a bootstrap job, secrets, placement, retries, failure
anti-affinity).

**Why an implicit rule and not a manifest flag** (`certification = "exempt"` per stage). The rule follows from facts
the manifest already states, so it needs no new key, no core floor, no approval and no new module version: minos-gatk
4.0.0's `sync` qualifies as it is. A flag would let an author exempt a stage whose results the host compares, which
would have to be refused anyway, so the flag could only ever restate the rule.

**Why this keeps the trust model sound.** Certification exists so that wrong results do not count: goldens show that a
node computes the module's comparable results exactly, and only then are its results replicated against, compared,
cached and served to other campaigns. For the exempt stages certification proves nothing:

- a `determinism = "none"` stage is never golden-tested (spec/manifest.md rule 14), replicated, compared or cached
  (S21); its results belong to the moment they were made, so the goldens of another stage say nothing about them, and
  no other node's result is ever checked against them;
- a bootstrap stage's output counts only when it is exactly the pinned datasets, checked file by file.

What does protect these results stays: the module's own verdict (`result.evaluate`) for an exempt stage, the pin check
for a bootstrap stage, job-generation fencing, the node's admission by the owner, and the breaker (a node whose jobs
keep failing revokes the module there, which stops these stages too until its doctor runs again). Their results never
count toward certification.

**Why `exact` stages still wait (minos-gatk `profile`).** A stage that compares has its result cached under its job key
and served to every campaign that asks for the same key, and replicas compare against it. An uncertified node's wrong
result would become canonical and spread through the cache before any replica could catch it; certification is the
admission control for exactly that. A stage that needs a capability or a pool waits too: a capability is node software
the stage depends on (a JDK) and a pool a runtime it uses (containers), which the goldens are what show to compute
correctly; a probe only shows they are present. (`profile` runs once a node is certified; a module that wants it to run
earlier could declare it `determinism = "none"`, giving up its caching.)

The certification fence (`release_invalid` when the attempt's certification generation is not the node's current
one) does not apply to these jobs: their results never depended on certification. Revocation still ends their live
attempts.

### 2. A failed doctor check gates only the stages that need what it proves

The mapping already existed in the manifest's capability namespace: a probe's name is the capability it provides
(spec/manifest.md rule 2), and minos-gatk names its doctor check `java17` after its `java17` probe. The rule:

> A doctor check named after a capability (a probe's name, or a capability one of the module's services provides)
> proves that capability for the module on that node. When it fails, the node lacks the capability for the module's
> stages, whatever the probe or service reports.

`predicates.node_capabilities(node, module)` subtracts the names of failed checks
(`oarbank_sdk.runner_protocol.disproved_capabilities`) from what services, probes and the module's doctor provide, so
the existing `stage capabilities` predicate (`STAGE_CAPABILITY_MISSING`) keeps a stage that requires the capability
off the node, and a stage that does not keeps running. A failed check named after no capability (`pysam_import`,
`disk_free_20gb`) gates no stage directly: it makes the doctor not `healthy`, so the module is not certified and the
stages that need certification wait; the exempt stages do not.

No manifest field maps checks to stages: names already do, and a second mapping would drift from the first. A module
that wants a check to gate a stage names the check after a capability the stage requires.

### 3. An unmapped host tool or folder keeps off only the jobs that would use it

Tools and folders are module-wide grants with no stage mapping, so a missing mapping excluded the whole module. Now
`predicates.SPARED` says which jobs an exclusion leaves alone:

- `TOOL_UNAVAILABLE` (the registry has no path for an approved tool on the node's OS) spares jobs of stages that need
  no certification. A tool serves a capability (`java17`), which such a stage never requires, and a bootstrap job gets
  no tools at all. The job runs with the tools that are mapped; a narrower grant is never less safe. The stages that
  need certification, and the goldens, still wait, and explain names the tools.
- `FOLDER_UNAVAILABLE` spares bootstrap jobs only (they get no folders). An exempt stage may read or write a folder,
  so it waits for its mapping.

The other exclusions (platform, OS version, sandbox enforcement, agent version, the runner's GPU APIs) keep every job
off: the runner cannot run there, or not confined.

### 4. The agent offers every module whose runner started

The agent's doctor report gains `ran` per module: true when the runner printed a DoctorOutput, false when the agent
wrote the report itself (the doctor did not start, crashed, hung or printed something else; its only check is
`doctor`). Claims offer the modules with `ran` true, whatever their health, and the coordinator decides per stage. A
report without `ran` (an agent before this change) counts as run unless it is the agent's own `doctor` failure, so the
coordinator reads older reports correctly; an older agent still offers only healthy modules in its claims, so its node
takes exempt jobs once the agent is updated.

### 5. Explain names the requirement no node meets

For a pending job that no node can take, the headline is the reason code's message followed by every distinct first
failure with its values filled in and the nodes it covers by platform, commonest first, for example:

- `No node can run this job right now: Its stage needs java17; this node's services, probes and module doctor do not
  provide java17 (5 nodes: 5 darwin-arm64)`
- `... Module minos-gatk is not ready on this node (doctor: undetected; failed checks java17, pysam_import) (5 nodes:
  5 darwin-arm64)`
- `... Module minos-gatk needs host tools the tool registry has no darwin paths for: java17 (5 nodes: 5 darwin-arm64);
  Module minos-gatk does not run on windows-amd64 (requires.platforms) (1 node: 1 windows-amd64)`

Each summary row carries the same sentence in `detail.text` and its platform counts in `detail.platforms`. The module
check of an exempt job is its own predicate, `module_runner_ready(<module>)` (bootstrap jobs keep
`module_ready_for_bootstrap(<module>)`), observed as `<state>, runner started` or `<state>, runner not started`, so
"its runner did not start" and "not certified" read differently; a system action says the job needs no certification
and why. `TOOL_UNAVAILABLE`'s message names the tools (`{tools}`).

### 6. Doctor details are kept whole

The coordinator, `oarbank node show` (and `--json`) and the console's node page never shortened a check's detail. The
300-character cut seen on that fleet is minos-gatk's own: its doctor's `add()` keeps `str(detail)[:300]`, the beginning
of the message, which drops the `dlopen` error's cause at its end. That is the module's to change (keep the whole
detail, or its end). What the core side did shorten is the agent's own report for a doctor that printed no
DoctorOutput: it kept the last 300 characters of stderr; it now keeps the last 4000 (stdout when stderr is empty). The
SDK's `DoctorCheck.detail` and spec/runner-protocol.md now say: give the whole reason; a runner that shortens one keeps
its end.

### 7. Container GPU APIs are listed only beside a container runtime

That Mac does have a runtime (Colima and docker installed, krunkit too: it offers the `containers` and `gpu` pools),
but macOS and Linux agents reported only `containers.gpu` in their facts, so `oarbank node show` printed a container GPU
API and no runtime. The agents now report `runtime` (`colima`, `podman`, `docker`), `state` (`installed`, or `absent`
with `runtime` null) and a `detail`; `gpu` is always `undetected` without a runtime. `oarbank node show` and the node
page print the runtime (or "containers: none"), and `detail.gpu` lists no container GPU APIs for a node whose runtime
is `absent`, whatever an older doctor report says.

## Invariants

- **S8** (amended): a live non-golden attempt runs a module certified on its node under the current certification, or
  is an attempt of a stage that needs no certification on a node where the module is in a state its doctor decides
  (not `revoked`, not unknown).

The Hypothesis machine, the simulator and `oarbank verify` check it with the rest of the catalogue.

## That fleet under the new rules

On a copy of its coordinator database (with a copy of its module store, under a scratch home): the five darwin nodes are
`undetected` with their runners started; the four `fetch` jobs and the `sync` job are eligible on all five
(`QUEUED_BEHIND`), and a claim from an updated agent is granted them. The two `profile` jobs wait, and explain says why:
`Module minos-gatk needs host tools the tool registry has no darwin paths for: java17 (5 nodes: 5 darwin-arm64)`.
Certifying the module there still needs the operator: map `java17` for darwin in the tool registry
(`settings.tools.update`) and fix the pysam build the darwin venvs load (the `dlopen` failure).

## Tests

SDK: `certification_exempt` for every stage kind (bootstrap, none with and without capabilities, pools or needs_pools,
exact, the default stage, an unknown one), `capability_names`, `disproved_capabilities`; schemas and the field reference
regenerated.

Core: a `determinism = "none"` stage runs on a `doctor_failed` node before certification and its result is accepted
with no certification fence, while the default stage waits and explain says which checks failed; an `exact` stage and a
revoked module run nothing there; S8 names an uncertified attempt of a stage that needs certification; bootstrap jobs
run where the runner starts (an `undetected` node with failed checks) and never where it did not (`ran` false, or an
older agent's `doctor` failure); a failed check named after a capability keeps off only a stage requiring it, with
explain's sentence; an unmapped tool spares exempt stages and names the tool; which exclusions spare which jobs;
container GPU APIs only beside a runtime, and doctor details printed whole.

Agent: modules offered when their runner starts, whatever their health; a failed doctor's output kept from its end; the
macOS and Linux container report with and without a runtime.
