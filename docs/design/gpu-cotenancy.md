# Co-tenancy: measuring harm, event-driven sources and certificates

Fleet work runs beside the owner's own processes, and host protection ([protection.md](protection.md)) keeps it from
harming them. This document covers three pieces that make that measurable and fast (PLAN D50, D51, D52):

- **Event-driven owner sources** (D51): the owner's progress and phase sources are watched, not polled, so a phase
  such as an upload is seen within milliseconds; rules marked `immediate` pause fleet work between ticks; sources in
  a person's home are read by that person's session helper in a system install.
- **The paired on/off harness** (D52): a randomised, paired measurement of what given fleet work costs one protected
  process, with a decision at the owner's margin.
- **Co-tenancy certificates** (D52, gating D50): a run that shows no slowdown becomes a certificate for one node, rule
  and fleet configuration; `gpu_jobs = "certified"` lets cooperative GPU work run beside a protected GPU group only up
  to a certificate's duty level.

The GPU duty controller that grows and shrinks the duty under a certificate (AIMD on the protected progress rate, the
compliance check against measured GPU time) is the next step of D50; this release holds certified work at the
certificate's level. Nothing here names a particular program: protected programs are owner rules.

## Owner sources (D51)

A source belongs to a rule: `protect.source` (a progress rate for `protect.metric = "progress_rate"`) or a `during`
block's `source` (a phase). It is owner configuration, never a module's.

| Kind | Fields | Meaning |
|---|---|---|
| JSONL progress | `jsonl`, `event`, `event_key` | count lines whose `event_key` (a dotted path, default `event`) equals `event`; no `event` counts every line |
| Log progress | `log_regex`, `path` | count regex matches in new lines |
| Probe progress | `exec` | an owner-written program printing a rate (run by the agent, never by a helper) |
| Event phase | `jsonl`, `enter`, `exit`, `enter_soon`, `event_key` | on after an `enter` or `enter_soon` event, off after `exit` |
| Field phase | `jsonl`, `event`, `field`, `on`, `soon` | on while the dotted `field` of the `event` lines holds one of `on` or `soon` |
| Process trigger | `on_exec = { match, tree }` | on while a matching owner process runs |

```toml
[[rule]]
id        = "trainer"
match     = { path_prefix = "/Applications/Example Trainer.app/" }
tree      = "descendants"
immediate = true
protect   = { metric = "progress_rate", max_slowdown = 0.05,
              source = { jsonl = "~/Library/Application Support/Example/events-*.jsonl", event = "backward_complete" } }
[[rule.during]]
source      = { jsonl = "~/Library/Application Support/Example/events-*.jsonl", event = "heartbeat_response",
                field = "response.phase", on = ["weights_uploading", "merging_partitions"] }
pause_fleet = { scope = "gpu" }
cap_fleet   = { staging_mbps = 0 }
tags        = ["uplink"]
```

- **Newest file.** A path's last component may hold `*`. The reader follows the newest matching file (by
  modification time): a program that starts `events-<session>.jsonl` on every restart is picked up when the new file
  appears, and the rest of the old file is read first.
- **The tail** keeps the file's identity (device and inode; creation time on Windows) and offset. A rename or a new
  file finishes the old one through the open handle, a truncation starts again from 0, and only complete lines are
  parsed (a partial line waits for its newline; one over 1 MiB is dropped). A progress source starts at the end of the
  file; a phase source reads back up to 4 MiB to find the state already written, skipping the first fragment.
- **Watched.** macOS: kqueue `EVFILT_VNODE` on the newest file (`NOTE_WRITE`, `NOTE_EXTEND`, `NOTE_DELETE`,
  `NOTE_RENAME`, `NOTE_ATTRIB`) and on its directory, opened `O_EVTONLY`. Linux: inotify on the directory
  (`IN_MODIFY`, `IN_CLOSE_WRITE`, `IN_CREATE`, `IN_MOVED_*`, `IN_DELETE*`), `IN_Q_OVERFLOW` re-reading everything.
  Windows: a 250 ms poll of the newest file's size and write time (`ReadDirectoryChangesW` reports appends late, when
  the cache flushes, so the poll is what bounds the reaction there). Every backend re-resolves the newest file every
  250 ms, and the two-second tick reads every source anyway: a missed event costs at most a tick. A newly watched file
  is read once at once, so a change between configuration and watch is never lost.
- **Fail-safe.** An unreadable progress source counts as a violation (unchanged). An unreadable phase counts as **on**:
  never looser. Both are node conditions with their fix (`PROTECTION_SOURCE_UNREADABLE`,
  `PROTECTION_SOURCE_NEEDS_HELPER`; explain, the node page, `oarbank protection show`), never a silent hold.
- **Tags** are owner labels on a `during` block (`uplink`: the phase uses the site's internet line). The node acts on
  nothing but the block's actions; the tags travel with the phase in the heartbeat, for coordinator-side aggregation
  (below).

### Who reads a source: the session-helper relay

A system install's agent runs as a service account (`_oarbank` on macOS) that may not read a person's home, where
programs keep their logs and events. Before this release `~` expanded to the agent process's own `HOME`, the service
account's, so such a source could never be read and held fleet work back for good. Now:

| Path | Personal install (the agent runs as the person) | System install |
|---|---|---|
| `~/x`, `~name/x` | the agent reads it in its own (or `name`'s) home | the person's session helper reads it (`~`: any logged-in person whose file exists; `~name`: that person only) |
| `/Users/<name>/x`, `/home/<name>/x`, `C:\Users\<name>\x` | the agent | `name`'s session helper |
| anything else (`/Users/Shared`, `/var/log`, ...) | the agent | the agent |

The session helper (`oarbank-agent session-helper`, one per GUI login on macOS from
`/Library/LaunchAgents`, a systemd user unit on Linux, started per session by the elevated helper on Windows) already
reports to the service over a local endpoint whose peer credentials name the account. The relay adds one message the
other way: the service sends `{"v": 2, "watch": [{key, kind, account, rel, spec}]}` when the list changes and on every
connection (the spec without its path), and the helper reads those sources under its own home with the same tail
and watcher and reports, in every report and at once on a phase change, `sources: [{key, events, epoch, on, readable,
event_t}]`.

- **No new privilege, no file contents.** The helper reads only what its person can read, only paths under that
  person's home (a relative path that would leave it is refused), never runs a probe, and sends counts and phase
  states, never lines.
- **Checked.** The service accepts a source report only for a source it asked that principal for (a source for a
  named account goes only to that account's helper; on Windows, where the pipe proves the session rather than the
  account, the helper filters by its own account). A phase on at any helper wins; a count's epoch changes when the
  helper reconnects, and the next read sets a new baseline instead of a jump.
- **Nobody logged in.** No helper reports the source: it is unreadable. A progress source then counts as a violation
  and a phase as on, so fleet work under the rule is held back, and the node shows
  `PROTECTION_SOURCE_NEEDS_HELPER` ("source ... is in a person's home ...; nobody's helper reports it now"). This is
  the report's fail-safe philosophy: the agent cannot tell an idle program from one in an upload, so it assumes the
  worse. A rule whose protected process only runs while its person is logged in loses nothing: with nobody logged
  in its group is usually empty and the rule inactive. An owner who wants fleet work to run while logged out and the
  program keeps running puts its sources where the service account can read them (outside the home, readable by
  `_oarbank`).

### The event tick and `immediate` rules

A rule marked `immediate = true` has its `during` phases act between ticks:

1. The watcher thread wakes on a change (or a helper's report arrives) and re-reads only the phases the change can
   touch.
2. A phase that turned on is journaled (`phase_change`, `PROTECTION_PHASE_ON`, with `event_t`, when the change was
   seen, `via`: watch, helper, exec or poll, and the block's tags), and if its rule is **armed** (active, or its
   matched group is present: an immediate phase applies before the rule's `enter_for_s` has passed) and the block
   pauses (`pause_fleet`), the agent's fast path pauses the fleet work in scope at once: a freeze through the spawn
   registry, or `pause` in a cooperative runner's control document (S16 unchanged). The pause is journaled
   (`attempt_paused` with `event_t` and `latency_ms`).
3. The two-second tick does everything else: caps, lowering, services, the dynamic layer, and the release after the
   phase's own `exit` (hysteresis comes from the exit event, not from `exit_after_s`).

The event path only ever adds a pause. A tick that read its sources before a fast pause keeps that pause (it did not
see the phase), and the fast path records a freeze in the same set the tick resumes from, so a fast pause neither
flaps nor sticks. `specs/OarbankFastPause.tla` checks both (`FastPauseHolds`, `NoStuckPause`) and fails without
either rule.

**Process triggers** (`on_exec`) are evaluated on the tick from the process table, and for immediate rules by a
250 ms process listing on the same thread: kqueue `EVFILT_PROC` watches only known pids, the Linux proc connector
needs `CAP_NET_ADMIN`, and Windows' process events arrive on a one-second ETW flush.

**Latency.** Source write to pause request: the target is p99 under 50 ms; the agent reports its own histogram
(`event_latency`: count, p50, p99, max, buckets). On a heavily loaded development Mac the unit test measured
0.4–1.8 ms worst of five for a file the agent watches, and the relay test 44 ms through a session helper.

**S25** (new): for an immediate rule, the first pause of a phase the event path saw begin is the event path's, within
100 ms of the source event. The coordinator checks it from the decision journal (`invariants.s25_...`), beside S18.

### Per-site aggregation (the interface)

The heartbeat's `telemetry.protection.phases` lists every `during` block: `{key, rule, block, on, since, readable,
reader, tags, immediate}`. The coordinator reads it with `protection.node_phases(db, node_ids, tag)` and
`protection.any_phase_on(db, node_ids, tag)`, which is on, never looser, when any node's tagged phase is on or
unreadable or a node with such a phase has not reported for 60 s. A feature that groups nodes by shared internet line
(a site) asks `any_phase_on(site_nodes, "uplink")` and holds network-heavy fleet work at the site while it is on.

## The paired on/off harness (D52)

**What it measures.** For one rule with a `progress_rate` source on one node, `R = progress(fleet on) / progress(fleet
off)` for one fleet configuration: which work (`gpu`, `cpu`, `all`, `<module>`, or `<module>/<workload>`) and at which
`gpu_duty`.

**Design.**

- **Blocks.** A run is blocks of one ON and one OFF window in random order (a coin per block, splitmix64 from the
  run's seed). Default window 300 s, washout 60 s discarded after each switch.
- **OFF** pauses the work under test the way protection would (cooperative pause or freeze; work that can do neither
  is released), or with `off = "evicted"` releases it so its memory is free too. **ON** lets it run, exempt from the
  GPU gate (`gpu_jobs = when_no_gpu_protected` would otherwise pause GPU work beside a protected GPU group), with
  `gpu_duty` at the level under test in cooperative runners' control documents. Everything else protection does
  stays: owner rules' own pauses, the memory guard, the dynamic layer. The pause probe is suspended during a run (the
  harness replaces it).
- **Exclusions.** A block is dropped and repeated when an outside cause differed: a `during` phase of the rule was on,
  the protected process restarted (its group's pids and start times changed), the node slept (a gap of over 10 s
  between ticks), the power source changed, the memory guard acted, the rule went inactive, or the source could not
  be read. Thermal throttling is not a cause: if fleet work heats the machine, that slowdown counts. A block whose ON
  window made no progress at all while OFF did counts as harm, not an exclusion.
- **Statistic.** Per window, the mean progress rate after the washout; per block, `ln(on / off)`. The mean log ratio
  gets a 90 % interval by a bootstrap over blocks (2,000 resamples, type-7 quantiles) and by a t interval.
- **Decision (TOST).** Margin Δ (default 2 %; only slowdowns matter): **no slowdown shown** when the lower 90 % bound of
  `R` is above `1 − Δ`; **slowdown** when the whole interval is below 1 and the estimate below `1 − Δ`; otherwise
  **inconclusive**, with the further blocks the observed spread says are needed. The two intervals must agree; when
  they do not (few blocks, a skewed sample), the run is inconclusive (a refinement over the report, which made the t
  interval only a cross-check).
- **Power.** After a pilot of 3 blocks, the harness reports the slowdown the planned blocks detect with 80 % power and
  raises the block count to what the margin needs; a run that cannot reach it within its cap (default 8 hours) is
  **refused**.
- **Sequential stopping.** After each block (from 3), an always-valid mixture SPRT (normal approximation with the
  observed variance, mixing scale Δ, α = 5 % each way) may stop the run: a slowdown at once; "no slowdown shown" only
  when the fixed analysis agrees.
- **Guard.** In an ON window, harm over twice the rule's target (`max_slowdown`, else the margin) against the OFF
  baseline so far aborts the run as a slowdown.

The statistics live in the protection crate (`abstats.rs`) and, for the coordinator, in `oarbank.contracts.abstats`,
held equal by shared vectors (`src/oarbank/contracts/vectors/abstats-vectors.json`, generated by `gen_abstats.py`).
Property tests check the decision's error rates on a simulated plant: a zero effect yields "slowdown" in at most 5 %
of runs, a 5 % slowdown is detected in at least 80 %, and the sequential test stops a zero-effect run wrongly in at
most 5 %.

**Where it runs.** In the agent, as a mode of the controller (the windows are timed on the node). The coordinator
asks for a run (`ab_run` in the heartbeat reply), may abort it (`ab_abort`), stores the agent's reports (`ab_runs`),
and forgets the finished run on the node (`ab_ack`). A run lost to an agent restart is aborted at the next hello.

**Frontier search.** `protection.ab.sweep` runs the harness at rising `gpu_duty` levels (0.1, 0.2, 0.35, 0.5, 0.65,
0.8, 1.0, or the owner's list) and stops at the first that is not "no slowdown shown"; the highest passing level is
the node's certified duty for the rule.

## Certificates (D52) and `gpu_jobs = "certified"` (D50)

A run that ends "no slowdown shown" becomes a certificate: node, rule, fleet configuration (`work`, `duty`), `R` with
its interval, the margin, the run, and a validity of 14 days. It is bound to what the run was earned under: the node's
hardware (CPU model and cores), OS major version and agent version (`cert_context`), and the protected program's
identity (a fingerprint over the distinct path, Team ID and signing identifier of the rule's matched processes; a
restart keeps it, a new build at another path or signed differently changes it). The coordinator sends the
certificates in force with every heartbeat reply (`certificates`); the agent checks each itself, never looser, and a
certificate it cannot validate counts as none.

`gpu_jobs` gains `certified` (between `always` and `when_no_gpu_protected` in the strictest-wins union). Beside a
protected group that holds GPU work back through the GPU gate (a `protect.metric = gpu_share` group using the GPU),
cooperative GPU work (runners that declare `cooperative_throttle`) runs at `gpu_duty = D / n`, where `D` is the
smallest certified duty among the gating rules and `n` the cooperative GPU jobs; work that cannot throttle stays
paused, and no new GPU work is admitted beyond what runs. Without a valid certificate for every gating rule it behaves
as `when_no_gpu_protected` and journals `GPU_NOT_CERTIFIED` (a node condition, with the sweep as the remedy). An
owner's explicit pause of GPU work, a rule's or a phase's `pause_fleet` with scope `gpu`, `all` or `io`, always binds:
it pauses the work and admits no GPU job (capacity `paused`, `paused_by`), certificate or not; a certificate lifts only
the gate. Such a rule also counts as gating, so the GPU budget shows it as not certified unless a certificate covers
it.
`certified` is opt-in per node (owner decision 14).

**For the duty controller (the next step of D50).** `ProtectionController::certified_duty(rule, now)` is the ceiling;
the dynamic step receives each job's `gpu_duty` through `DynJob::gpu_duty`, and `ThrottleDoc::gpu_duty` carries it to
the control document, so an AIMD loop below the ceiling only replaces how `D` is chosen.

## Operations, console and CLI

| Operation | Tier | What |
|---|---|---|
| `protection.ab.start` | T2 | a run on a node; the preview names the rule and source, the work, the planned and capped hours |
| `protection.ab.abort` | T0 | abort a run |
| `protection.ab.sweep` | T2 | a duty sweep |

- **Protection page, Co-tenancy card:** every phase and progress source with its state and who reads it (the agent,
  the person's session helper, a process trigger), the event path's latency, the GPU budget, the certificates with
  `R`, interval, margin, expiry and state (valid, expired, stale with why), the latest run, and forms to start a run
  or a sweep.
- **Harness page** (`/protection/ab/<run>`): the blocks as a paired dot plot, `R` and its interval against the margin,
  the decision in words ("No slowdown shown: the protected process ran at 99.4 % of its speed without fleet work (90 %
  interval 98.6–100.3 %), within the 2 % margin"), excluded blocks and why.
- **CLI:** `oarbank protection ab start <node> --rule <id> [--work gpu|cpu|all|<module>|<module>/<workload>] [--duty
  0.3] [--blocks 12] [--window 300] [--washout 60] [--margin 0.02] [--off paused|evicted] [--max-hours 8]`,
  `oarbank protection ab status [<node>]`, `oarbank protection ab show|abort <run>`, `oarbank protection ab sweep <node>
  --rule <id> [--levels 0.1,0.2,0.35]`, `oarbank protection certificates [<node>]`.

## Running the first measurement against a real protected program

Only in a window the owner frees for it, started by hand:

1. Give the protected program a rule with a `progress_rate` source (its own event file, counted by event type). On a
   system install with the file in the person's home, stay logged in: the session helper reads it.
2. Check the source reads: the Co-tenancy card shows a rate, `read by` names the agent or the session helper.
3. CPU co-tenancy first (it already runs): `oarbank protection ab start <node> --rule <id> --work cpu`, about two hours
   at the defaults.
4. GPU co-tenancy, only with fleet GPU work whose runner declares `cooperative_throttle`: `oarbank protection ab sweep
   <node> --rule <id>`. Each level is a run; a slowdown stops the sweep at once and the guard aborts a collapse.
5. To use a certificate, set the node's `gpu_jobs = "certified"`.

## Failure modes

| Failure | Behaviour |
|---|---|
| Progress source unreadable or stale | a violation (fail-safe, unchanged); in a harness run the block is excluded |
| Phase source unreadable (a person's home with nobody logged in) | the phase counts as on; `PROTECTION_SOURCE_NEEDS_HELPER` |
| Watcher misses an event | the 250 ms re-scan and the tick catch it |
| The helper disconnects | its sources read as unreadable at once (the event path is told) |
| Harness confounded by an outside event | the block is excluded and repeated; too many exclusions abort the run |
| The agent restarts mid-run | the run is aborted at the next hello |
| Certificate stale (OS update, new hardware, agent or program build) | `certified` behaves as `when_no_gpu_protected` until a new run passes |
| Thermal throttling during ON windows | counted as harm, by design |

## Security

Runs and sweeps are owner operations (T2: they deliberately run fleet work beside a protected process); modules
cannot start runs, read certificates or name sources. Sources remain owner configuration read by the agent or the
person's own session helper, which gains no privilege and sends no file contents. A coordinator that could forge a
certificate can already set `gpu_jobs = "always"`; the node's local protection file still wins on every dimension.

## Verification

| Layer | Tests |
|---|---|
| Statistics | shared vectors (Rust and Python), error-rate and power properties, the sequential test's validity (`tests/abstats.rs`) |
| Harness | a simulated protected process: harmless and harmful co-tenants, the guard, every exclusion, sleep detection, power refusal (`tests/cotenancy.rs`) |
| Controller | harness arms and `gpu_duty`, certified work against valid and invalid certificates, immediate phases and process triggers (`tests/cotenancy.rs`) |
| Sources | newest-file following, field phases, rotation, truncation, partial lines, the lookback fragment, locations, the event path's latency (`tests/sources.rs`) |
| Relay | helper readings and filtering, the hub's checks and wake-ups (`tests/relay.rs`); a real helper over the session socket in one account with a scratch home (`tests/relay_live.rs`) |
| Agent | the fast pause freezing a real process between ticks and the tick keeping it (`prot.rs`, macOS) |
| Coordinator | runs, reports, certificates and their validity, sweeps, aborts, conditions, S25, per-site aggregation (`tests/test_cotenancy.py`) |
| End to end | a real agent and oarbankd with a synthetic protected process: phases with tags, a harness run to its decision (`tests/rust/test_agent_cotenancy.py`) |
| TLA+ | `OarbankFastPause.tla`: the agent's rules hold; each weakened variant fails |
