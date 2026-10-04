# Alert rules and runbook (generated)

Generated from `oarbank.contracts.alert_rules` by `python -m oarbank.contracts.docs`. A rule with a pending period notifies only if its condition outlives it; a flap rule turns N trips per window into one `<rule>:flapping` alert. P5 alerts re-notify every 30 min until acknowledged or snoozed. Acknowledge with a verdict (useful or noise): `oarbank alerts precision` is the monthly review (P4/P5 rules need at least 50 %).

| Rule | Severity | Pending | Flap | Runbook |
|---|---|---|---|---|
| `audit_chain_broken` | P5 | 0 min | – | The audit hash chain does not verify: compare with the off-host digest copy before trusting the log. |
| `audit_copy_failed` | P3 | 0 min | – | The off-host copy of the audit digests failed: check the `audit_digest_copy` command (ssh key, destination); the chain itself is fine. |
| `breaker` | P3 | 15 min | 3 in 60 min | Repeated job failures on one node: open the node's failures and attempt logs; the node re-doctors on its own. If it keeps tripping, quarantine it. |
| `certifying_stuck` | P3 | 0 min | – | Golden jobs have not finished: is the node asleep or yielding? Check its goldens on the node page; `nodes.recertify` retries. |
| `coordinator_platform_unsupported` | P4 | 0 min | – | The coordinator moved to a platform this module's coordinator side does not run on (requires.coordinator_platforms), so the module was disabled. Install a version that supports this platform and enable it, or move the coordinator back. |
| `dispute` | P4 | 0 min | – | Replicas disagree and no third node can break the tie: the job is quarantined. Retry it once another node is certified. |
| `doctor_failed` | P3 | 5 min | – | A module's doctor check fails on the node: see the failing checks on the node page, fix the dependency, then run the doctor. |
| `golden_failed` | P4 | 0 min | – | Golden jobs keep failing: compare the golden results with the expected values; a module or tool change may need a new version. |
| `invariant` | P5 | 0 min | – | A safety invariant failed: the condition is latched. Read the message on the Verify page; resolving needs a note. |
| `module_host_down` | P4 | 0 min | – | A module's coordinator process is down: completions wait (nothing is charged). See the module's health page and stderr; restart it. |
| `no_golden` | P4 | 0 min | – | The module returned no goldens for this node class: it cannot be certified. Fix the module's golden.list or its settings. |
| `node_offline` | P3 | 0 min | – | Check the machine is awake and reachable, then that its agent service (dev.codonic.oarbank.agent) runs: launchctl on macOS, systemctl on Linux, the service manager on Windows. Leases were already requeued. |
| `pinned_dataset_conflict` | P3 | 0 min | – | A bootstrap job brought a module's pinned dataset, but another dataset with other files is registered under its id (often a hand registration), so it was left as it is. Delete that dataset; the next bootstrap job registers the pinned one. |
| `placement_rebound` | P2 | 0 min | – | A unit of work with rebind = "if-stranded" moved to another platform class because its class had no eligible node; its finished jobs run again there. Nothing to do unless the move was unwanted. |
| `placement_stranded` | P3 | 0 min | – | A unit of work is bound to a platform class with no eligible node left: bring a node of that class back (online, certified), or move the campaign with campaigns.rebind_platform; its finished jobs run again in the new class. |
| `protection_flapping` | P3 | 0 min | – | A protection rule escalates and relaxes too often: widen its thresholds or timing in the node's protection editor. |
| `protection_probe_harm` | P3 | 0 min | – | Fleet work measurably slowed a protected process: consider strict_yield on that node or a tighter rule. |
| `quarantined` | P4 | 0 min | – | The node gave wrong answers (dispute lost or nondeterminism): its results were invalidated. Investigate before clearing the quarantine. |
| `revoked` | P4 | 0 min | – | A golden mismatch revoked the module on the node: its results are not trusted until it re-certifies. Check the node's tools. |
| `secret_unreadable` | P3 | 0 min | – | A module secret is stored but this coordinator cannot decrypt it (a backup restored or a home copied to another machine, whose secrets key stayed behind): set it again with `oarbank secret set`. Jobs needing it wait with SECRETS_NOT_SET. |
