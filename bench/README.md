# bench/: oarbankd load and scalability harness

A swarm of simulated agents (asyncio + httpx) runs the real enroll, hello, heartbeat, claim, complete, fail and release
loop against a private, instrumented oarbankd, over the same mTLS agent API real agents use, and checks exactly-once
invariants at the end of every run.

## Quick start

```sh
# one run: 200 agents, 60 s steady window, JSON summary on stdout (exit 1 on invariant violations)
.venv/bin/python bench/swarm.py run --agents 200 --duration 60

# a sweep: writes bench/results/sweep-n<N>.json and bench/results.md
.venv/bin/python bench/swarm.py sweep --ns 10,50,200,500,1000 --duration 60 --procs 8

# rebuild bench/results.md from bench/results/*.json (other runs saved with run --json-out bench/results/<name>.json
# appear as experiments)
.venv/bin/python bench/swarm.py report

# the pytest smoke test: 10 agents, 50 jobs, about 20 s
.venv/bin/python -m pytest tests/test_swarm_smoke.py -q
```

No results are checked in: they describe the machine they ran on. Run a sweep to produce them.

Useful knobs (`swarm.py run --help` lists them all):

| Knob | Controls |
|---|---|
| `--heartbeat-s` | heartbeat interval (default 1 s, 10x the production 10 s) |
| `--job-min-s` / `--job-max-s` | simulated job run time |
| `--slots` | concurrent jobs per agent |
| `--queue-depth` | pending jobs kept queued |
| `--total-jobs` | fixed workload: run until done instead of a timed window |
| `--fail-rate`, `--release-rate`, `--dup-rate`, `--abandon-rate` | fault mix |
| `--fleet-poll-s` | add a dashboard poller (`GET /api/v1/fleet`) |
| `--console-viewers` | run oarbank-console with this many viewers (SSE plus a page a second each) and a `/metrics` scraper |
| `--sqlite-sync NORMAL` | durability A/B knob, applied in the bench oarbankd only |
| `--procs` | client worker processes (default one per 60 agents, up to 8) |

## Safety

- The harness never talks to a running coordinator. `Coordinator` refuses ports 7400/7401/7443 and the real coordinator
  home; `coordinator_instrumented.py` refuses to start without a scratch `OARBANKD_HOME` and explicit non-production
  ports.
- Every run gets a fresh temp `OARBANKD_HOME`, binds 127.0.0.1 (defaults 17443 agent, 17400 admin) and sets
  `OARBANKD_TAILSCALE=/usr/bin/false`, so discovery never shells out to a real tailscaled.
- Runs are offline. The SDK's toy module is built into a bundle locally and installed through the admin API; the release
  is composed from it. Toy jobs have no datasets.
- oarbankd's source is not modified: `coordinator_instrumented.py` monkeypatches the measurement hooks at startup.

## What one run does

1. **Start oarbankd** through `coordinator_instrumented.py`, which wraps `oarbank.coordinator.__main__.main()`.
2. **Seed through the admin API only.**
   - The toy bundle is uploaded (`POST /api/v1/modules/bundles`), installed through the reviewed `modules.install`
     operation (T2: preview, then the plan) and enabled with `modules.enable`, which composes the release.
   - Each agent makes a P-256 key, enrolls with its CSR (`POST /v1/agent/enroll`), is admitted through `nodes.admit`
     (previewed, then applied) and fetches its client certificate. From then on it presents the certificate; the
     harness trusts the scratch coordinator's CA by reading it from the scratch home.
   - Certification happens through the protocol, as for a real node: hello with the current release, a heartbeat with
     a passing toy doctor report (goldens are queued), and the golden job claimed and completed.
   - The workload is the toy module's own operation, `mod.toy.queue_sums`, with a unique `n` per job, so each job has a
     unique `job_key`.
3. **Run N fake agents across worker processes.** Each agent runs the agent's loop:
   - **Heartbeat** every H s, reporting every running attempt with growing `cpu_s`/`log_bytes`, so oarbankd extends
     its lease; heartbeat and claim run one after the other in one loop.
   - **Claim** when slots are free: again 1 s after a grant, or after H s when nothing was granted.
   - **Directives:** `revoke`, `cancel`, `kill`, `run_doctor` (the doctor report is sent again and the node
     re-certifies) and `recertify` (hello again).
   - **Job run:** U(job_min, job_max) s, then a valid toy result envelope (the sum of `range(n)`), so replicas agree.
   - **Outbox:** completions carry the idempotency key `att-<id>-complete` and are retried with backoff on 5xx or
     transport errors; `--dup-rate` of them are sent twice (a lost ack), and the replay must return the same verdict.
   - **Faults:** `--fail-rate` of jobs fail once (`exit_nonzero`; never twice, so no job is quarantined),
     `--release-rate` of attempts are released mid-run with a non-failure reason the agent sends (`preempt_memory`,
     `preempt_protection`, `limit_cpu`, `transient`), `--abandon-rate` (default 0) silently drops attempts, which makes
     real lease expiries 60 s later.
4. **Keep the queue topped up during the steady window** (new campaigns while fewer than 60% of `queue_depth` jobs are
   pending), after `--warmup-s`.
5. **Drain:** refills stop and the run waits until nothing is pending or leased; the agents flush their outboxes and
   exit.
6. **Stop oarbankd and check invariants:** `oarbank.coordinator.invariants.check_all`, and the harness's own:
   - H1 every job is done; H2 exactly one canonical result per job; H3 the job points at it; H4 no two canonical results
     share a `job_key`; H5 no live attempts remain; H6 no node is quarantined; H7 the job count equals what was seeded;
   - H8–H10 the agents' ack history agrees with the database: no job acked canonical to two attempts, every client-side
     canonical ack is the database's canonical attempt, and every canonical result was acked to some agent.

## Metrics

| Metric | Meaning |
|---|---|
| per-endpoint `n`, `rps`, `p50/p95/p99/max` | client-side latency over the steady window (TLS, queueing inside oarbankd and client scheduling included) |
| `err` | transport errors and HTTP ≥ 400 except 404; `http503` = DB-lock timeouts (`DBBusy`); `conn_err` = timeouts and connection errors |
| `compl/s`, `jobs/h` | canonical completions acknowledged to agents during the window |
| expiries (false) | attempts whose lease expired; **false** = the agent was still running and reporting the attempt |
| hb gap max | longest interval between two successful heartbeats of one agent (the margin to the 60 s lease is `60 - gap`) |
| in-oarbankd | server-side time from request arrival to the last response byte (an ASGI middleware): threadpool queueing, GIL and the certificate check included |
| core op wall | server-side wall time of each `core.*` function, DB-lock waits included |
| lock wait / hold / util | wait for and hold of oarbankd's single DB lock (`db._TimedLock`) per outermost acquisition; util = total hold / window |
| SQL statements | per-statement time on oarbankd's connection; `commit` = `COMMIT` of `BEGIN IMMEDIATE`, `write_autocommit` = writes outside a transaction |
| loop lag | oarbankd's event-loop delay; the harness reports its own as `harness lag`, so client-limited runs show |

Server-side numbers come from log-bucketed histograms: bucket upper bounds at about 12% resolution.

## Findings the coordinator is built on

Comments in oarbankd cite these by number.

1. **fsync inside the global DB lock turns disk contention into a fleet-wide stall.** Every write runs under the one
   lock; with `synchronous=FULL` each COMMIT fsyncs while holding it, so a busy disk queued every request behind one
   commit for seconds, at any fleet size. oarbankd runs WAL with `synchronous=NORMAL`: durable across process crashes,
   and a power loss rolls back only the last commits, which the protocol absorbs (an unrecorded completion's attempt
   expires and re-runs). `OARBANKD_SYNC=FULL` restores the old mode.
2. **Claim cost grew with the pending queue.** A sort key no index could serve made every claim sort all pending jobs
   under the lock. The claim walks the `jobs_dispatch` index; a job's priority already includes its campaign's.
3. **The prefetch scan ran on every hello and heartbeat over every open job.** `prefetch_for` caches the fleet-wide scan
   of untargeted jobs for a few seconds, and the partial index `jobs_target` serves the per-node query.
4. **Campaign ticks delayed the reaper.** Module IPC and campaign summaries ran on the reaper's thread, so a slow module
   paused lease expiry and offline detection. Campaign ticks run on their own thread.

Two costs remain, neither significant below a few hundred nodes: an agent's heartbeat waits behind its own claim (one
loop), and an open dashboard's `fleet` polling takes the lock once per node.

## Files

| File | Purpose |
|---|---|
| `swarm.py` | the harness: oarbankd process control, admin seeding, simulated agents, metrics, invariants, `run`/`sweep`/`report` |
| `coordinator_instrumented.py` | oarbankd with monkeypatched measurement hooks and `GET /_bench/stats`; refuses production ports and home |
| `results/`, `results.md` | written by `sweep`, `run --json-out` and `report` |
| `../tests/test_swarm_smoke.py` | 10 agents and 50 jobs against a subprocess oarbankd: full completion, no violations, no false expiries, the replay and failure paths exercised |
