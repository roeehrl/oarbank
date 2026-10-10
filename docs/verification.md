# Verification

How Oarbank shows that the coordinator keeps its promises under the failures a fleet of ordinary machines actually has:
nodes sleeping mid-job, network drops, agent crashes, the coordinator restarting, a module failing on one host, and a
node that returns plausible but wrong answers.

The layers share one **invariant catalogue**, `src/oarbank/coordinator/invariants.py`, so a property
proved in one layer means the same thing in every other.

## The promises

| id | property |
|----|----------|
| S1 | at most one canonical result per job |
| S2 | a done job points at a canonical, accepted result of that same job |
| S3 | a canonical result came from an attempt of the job's current generation |
| S4 | no lost job: every leased job has at least one live attempt |
| S5 | pending, done, cancelled and quarantined jobs have no live attempts |
| S6 | accepted results are exactly the canonical ones, except results superseded by a later generation |
| S7 | live attempts only run on ready nodes |
| S8 | a live attempt runs a module certified on its node, under the current certification; an attempt of a stage that needs no certification (a bootstrap stage, or one that compares nothing and needs no capability or pool), on a node where the module is in a state its doctor decides (not revoked) |
| S9 | attempt bookkeeping: `ended_at` is set if and only if the attempt is no longer live |
| S10 | a job's `exec_failures` never exceeds its failed or killed attempts |
| S11 | no node holds more live attempts than its hard `jobs` cap |
| S12 | staged jobs: no live attempt on a job whose dependency is not done |
| S13 | staged jobs: a done job's dependency is done and fed it the same input |
| S14 | every canonical result carries its job's module's verdict (a bootstrap job's: the host's pin check) |
| S15 | a module fault is never charged to a node or a job |
| S16 | every journaled actuation targets one of the node's own attempts or services (host protection never signals your processes) |
| S17 | no node admits work while its memory guard is active |
| S18 | an active protection rule is enforced within `enter_for_s` + 2 samples (from the decision journal) |
| S19 | the protection controller is monotone and fail-safe: worse, stale or missing signals never grow the fleet's allowance (agent tests) |
| S20 | every live, leased or done job of a bound unit of work ran on, or got its canonical result from, a node of the unit's platform class, result-cache hits included (placement, D33) |
| S21 | a job of a stage that does not compare (`determinism = "none"`) never has a replica, a dispute or a golden, and never shares a canonical result through the result cache (SDK 1.3) |
| S22 | a bootstrap job's canonical result is exactly pinned datasets of the module version that produced it: an empty payload, and artifacts that each hold one pin's files (SDK 1.4) |
| L1 | liveness: under bounded faults, every job reaches done, cancelled or quarantined |
| I1 | integrity: a node never convicted of nondeterminism is never quarantined by a dispute |
| I2 | integrity: once a node is convicted, no canonical result it produced survives |

## Layers

| layer | what it drives | where | default run | thorough run |
|-------|----------------|-------|-------------|--------------|
| unit tests | one behaviour per test, real core | `tests/test_core.py`, `tests/test_robustness.py`, and one file per area (console, HTTP, operations, campaigns, modules, protection, alerting, rescue, the Windows backends in `tests/test_windows_coordinator.py`) | every run, on macOS and Windows (x64 and arm64) in CI | same |
| HTTP | mTLS auth (a test client stands in for the TLS layer; `tests/test_mtls.py` runs the real listener), cross-node fencing, idempotent replay, 503 with Retry-After, admin identity, CSRF | `tests/test_http.py`, `tests/test_mtls.py` | every run | same |
| model-based (Hypothesis) | random interleavings of every agent, user and coordinator action on a mixed fleet (darwin-arm64, linux-amd64, linux-arm64), including placement studies, rebinds and placement changes; S1–S18 and S20–S22 after every step | `tests/test_stateful.py` | 150 × 60 steps | `OARBANK_THOROUGH=1`: 1000 × 100 |
| seeded fleet simulation | whole mixed-platform fleets over simulated hours with injected faults (including module process kills and outages), with and without placement; S1–S18 and S20–S22 during, L1/I1/I2 at the end, and a 1000-job mixed-fleet run whose `oarbank verify` report is clean. Runs the SDK's toy module and the core's relay fixture module | `src/oarbank/sim.py`, `tests/test_simulation.py` | 67 runs | `scripts/sim-sweep.sh` (seeds × 7 shapes) |
| model checking (TLA+) | exhaustive exploration of every interleaving in small scopes: 2–3 nodes, 1–2 jobs, ≤ 2 faults. Weakened variants must fail, and witness configs show the interesting paths are reachable | `specs/` (`run_tlc.sh`, README) | `QUICK=1 run_tlc.sh` | full `run_tlc.sh` |
| contracts and parity | every mutating route is an operation, every operation reachable from the API, CLI and console, every end reason has a code, generated docs and schemas fresh | `tests/test_contracts.py`, `oarbank.contracts.parity` | every run | — |
| agent (Rust) | protection (controller, evaluator, matcher on the shared vectors, spawn registry, memory guard, soaks), services, staging, jobs, sandbox backends, self-update, moves and rescue | `rust/` (`cargo test --workspace`) | every CI run, on macOS, Linux and Windows | — |
| core parity | `oarbank-core` (Rust) against the SDK's Python, the reference: the shared vectors and sandbox goldens, then seeded random inputs for canonical JSON, job keys, portable paths, platform tokens, bundle digests, sandbox profiles, the egress allow list, wheels and requirements | `rust/crates/oarbank-core-py/tests/test_parity.py` (through the `oarbank_core` extension) | every CI run on macOS, 4000 cases per test | `OCORE_PARITY_N`, `OCORE_PARITY_SEED` |
| end-to-end, real agent | the `oarbank-agent` binary against a real oarbankd: identity, enrollment by CSR and mTLS, releases and module environments, jobs and goldens, services, self-update through the launcher, TUF, coordinator moves (developer and signing mode), the install plan, discovery and the local admin channel | `tests/rust/` (`pytest tests/rust`) | every CI run on macOS and Windows (x64 and arm64) | — |
| load | a swarm of simulated mTLS agents against an instrumented oarbankd; exactly-once checks after every run | `bench/` (`tests/test_swarm_smoke.py` in the suite) | 10 agents | `bench/swarm.py sweep` |
| chaos | real oarbankd processes: `kill -9` mid-write, an external SQLite write lock, the module process killed during completions, ntfy down, an audit row edited by hand, the console killed | `tests/chaos/` (`pytest -m chaos`) | every CI run on macOS and Windows; nightly | — |
| module conformance | a module's manifest, bundle, protocol (purity, goldens through `spec.build`) and real runner (envelopes, golden match, determinism, stop) | `oarbank-sdk conform <dir>` | toy and the relay fixture in the suite; each module in its repository | — |
| accessibility | axe-core (WCAG 2.0/2.1 A and AA) on every console page; AA contrast of every colour pair in both schemes | `tests/test_accessibility.py` | contrast every run; axe with `OARBANK_A11Y_NODE_MODULES` | nightly |
| nightly | all of the above in one report | `scripts/nightly.sh` (a LaunchAgent example in `deploy/nightly/`) | — | when installed |
| live check | the same catalogue against a running coordinator's database; `oarbank verify` adds fleet health | `python -m oarbank.coordinator.invariants` | on demand | — |

### Simulator fault model (`harsh` profile)

Rates are per agent:

- 8 % of requests lost;
- 8 % of responses lost after the coordinator has already processed them;
- silent sleep at 0.2 per minute, lasting 30–400 s, with results delivered late;
- agent crash at 0.05 per minute (in-memory state lost, outbox kept);
- coordinator outage at 6 per hour, lasting 30–180 s, with lease extension on restart;
- 10 % execution failures;
- 2 % wrong-mode runs;
- one node that is silently nondeterministic.

Replication runs at 30 % in this profile; the default is 3 %. The bad node is either
`random` (a new wrong answer each run) or `consistent` (the same wrong answer every time, like a
miscompiled library; it can agree with itself, which is how TLC found F2).

## Findings

Every entry below was a real defect in the coordinator, found by these layers and fixed. Each one has a
regression test.

| found by | defect | fix |
|----------|--------|-----|
| Hypothesis | the same attempt completing under a second idempotency key crashed on the UNIQUE constraint (HTTP 500) | the second report returns the original verdict |
| Hypothesis | a wrong-mode run counted toward the failure breaker but was recorded as completed | recorded as a failed attempt |
| Hypothesis | a breaker trip left the node's live attempts running on a revoked module (S8) | the revoke also ends those attempts |
| Hypothesis | a released or revoked attempt could still deliver the canonical result | rejected as `attempt_closed` |
| design review of the simulator | a replica mismatch blamed whichever node reported later | quorum disputes: both results are distrusted, a third node breaks the tie, and only the outvoted node is quarantined |
| simulator | a silently wrong node was caught only by luck (a late replica) | adaptive replication: a deterministic sample of jobs is re-run on a different node |
| simulator | a convicted node's earlier canonical results stayed in the campaign | conviction invalidates and requeues them (I2) |
| simulator | a node that slept through its conviction delivered a canonical result afterwards | results from quarantined or retired nodes are rejected |
| simulator | jobs stuck pending forever once every node had failed them once, or failed them and sat in their dispute (L1) | failure anti-affinity is a preference, not an exclusion |
| simulator | a widening three-way dispute set the job to pending while another attempt was still live (S5) | the job stays leased until its last attempt ends |
| simulator | two late golden results, one from each expired attempt, both became canonical (S1) | a golden job that is already done accepts no second canonical result |
| simulator | on a two-node fleet a dispute could never be tie-broken, so the job waited forever (L1) | the reaper quarantines disputes that no uninvolved node can break, and raises an alert; nobody is convicted on a coin flip |
| review | a convicted node's requeued jobs in an already finished campaign were never served (claim only takes running campaigns) | invalidation reopens the campaign |
| HTTP review | `/metrics` was the only admin route without the identity check | it now requires the same identity as every other route |
| TLA+ (F1) | `claim()` decided from a node row read before its transaction, so a node quarantined or revoked in between still got grants (S7/S8) | the node row is re-read inside the transaction |
| TLA+ (F2) | a dispute party could break its own tie with an older duplicate attempt. A consistently wrong node then outvoted and convicted the correct node, on 2 or 3 nodes. This contradicted the 2-node claim above; the simulator never hit the interleaving | opening a dispute bumps the job generation (fencing every outstanding attempt), parties' completions are rejected, a node giving two answers for one job convicts itself, and late results never revive a quarantined or cancelled job |
| TLA+ (F3) | a replica with no other eligible node stayed pending forever (L1) | replicas need another eligible node; the reaper drops ones nobody can run |
| code reading, next to F3 | a golden job that failed once was never offered to its only possible node again, so certification hung | targeted jobs are always eligible for their target |
| simulator, split mode | after a tail job failed on the only node with its pool, failure anti-affinity counted nodes without the pool as able to take it, so it was never claimed again (L1) | eligibility (anti-affinity, replica runners, stranded disputes) checks that the node's pools fit the job |
| simulator, split mode | head-stage-only nodes could not re-certify: their golden needs the head stage's golden digest, which was never recorded | `oarbank pipeline split` records it from accepted golden results and refuses without them |
| TLA+ (F5), re-model of the fixed core | a node stuck in `certifying` counted as an eligible replica runner or tie-breaker but never got the work, so the job waited forever (L1) | `certifying` counts only within a 30 min grace period |
| code reading, replayed (F6) | a golden job that kept failing on its single host retried forever. Every breaker trip queued a new golden set and stale sets piled up | golden failures are counted per (node, module) across sets. After 3 the module goes to `golden_failed` with one alert, and is retried after 6 h or by manual recertify. Stale goldens are cancelled |
| live invariant check | S2 flagged cross-campaign result-cache hits: the invariant was too strict | S2 and S3 accept a cache hit (same `job_key`) |
| Hypothesis, 5 steps | retrying or disputing a job demoted its canonical result, while cache-hit jobs in other campaigns stayed done on it | demotion requeues every cache dependent and reopens its campaign |
| Hypothesis, 4 steps | the machine itself failed 1 run in 16 with `FlakyStrategyDefinition`: it picked campaigns by id, and the relay fixture names studies with random hex, so a replayed step sequence enqueued into another campaign and a precondition flipped | the machine picks campaigns in creation order; the four steps replay identically under rising and falling ids (`tests/test_stateful.py`) |
| chaos | another process's SQLite write lock surfaced as a 500 | 503 with Retry-After |
| chaos | a transaction whose BEGIN failed on that lock leaked the writer lock, so every later request answered 503 until a restart | the lock is released when the transaction cannot begin |
| chaos | the agent listener's coordinator fence read the database in a middleware, where a busy database escaped the handlers as a 500 | the fence answers 503 with Retry-After |

## Running it

```sh
uv sync --extra dev
uv run pytest -q --ignore=tests/rust          # the coordinator suite
(cd rust && cargo test --workspace --locked)  # the agent's tests
uv run pytest -q tests/rust                   # the agent end to end against a real oarbankd
uv run pytest -q -m chaos tests/chaos         # chaos
OARBANK_THOROUGH=1 uv run pytest -q tests/test_stateful.py
scripts/sim-sweep.sh 100
scripts/nightly.sh                            # everything, with a markdown report
```

The coordinator suite starts real module processes, and those always run confined; how depends on the OS:

- **macOS**: Seatbelt (`sandbox-exec`), nothing to build.
- **Linux and Windows**: the agent's launcher, `oarbank-agent sandbox-exec` (Landlock and seccomp; an AppContainer,
  in a Job Object the coordinator holds), which a coordinator build ships as `bin/oarbank-sandbox`. The suite builds it first with
  `cargo build -p oarbank-agent` in `rust/` (`tests/agentbin.py`, the same build the end-to-end tests use) and points
  `OARBANK_SANDBOX_EXEC` at `rust/target/debug/oarbank-agent`. On Windows the suite runs on x64 CPython (on arm64 too:
  `UV_PYTHON=cpython-3.12-windows-x86_64-none`), and module CLIs and egress allowlists need the elevated helper
  (`OarbankHelper`; CI installs it with `scripts/ci-windows-helper.ps1`). Set `OARBANK_SANDBOX_EXEC` yourself to use another
  copy. Without a Rust toolchain, or with a binary whose `sandbox-status` reports no backend (a Linux kernel without
  Landlock), the run stops with a usage error that says what to build: modules never run unconfined, and their tests
  are never skipped for it.

## Remaining gaps

- The agent is modelled by the simulator, not driven by it. Its own tests cover the outbox, the limits enforcer,
  services and host protection; the end-to-end tests drive the binary against a real oarbankd.
- Host protection's numbers come from a plant model, virtual-time soaks and measurements on Apple Silicon; other
  hardware has not been measured, and the dynamic controller has no Linux or Windows backend yet.
- The Linux and Windows agent backends are tested by CI on those systems, not on a running fleet.
- Byzantine agents that forge attempt ids or results for other nodes are out of scope: a node's credential is its
  certificate, and a node can only complete its own attempts.
- Certificate binding to a tailnet node fails open: if `tailscale whois` itself fails, a certificate presented from a
  new tailnet address is accepted and the address re-pinned. This favours availability; the event log records it.
- The alert-precision review needs a week of live alerts, and the console a manual screen-reader pass.
