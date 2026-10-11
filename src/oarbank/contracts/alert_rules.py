"""Alert rules as a contract: severity, pending period, flap detection and the runbook line per
rule prefix. oarbankd applies them (coordinator/alerting.py); the console shows the runbook beside each alert."""

# rule prefix (before ":") -> policy; P4/P5 rules need precision >= 50 % in the live review
POLICY: dict[str, dict] = {
    "node_offline": {"severity": "P3", "pending_s": 0,
                     "runbook": "Check the machine is awake and reachable, then that its agent service (dev.codonic.oarbank.agent) runs: launchctl on macOS, systemctl on Linux, the service manager on Windows. Leases were already requeued."},
    "breaker": {"severity": "P3", "pending_s": 900, "flap": (3, 3600),
                "runbook": "Repeated job failures on one node: open the node's failures and attempt logs; the node re-doctors on its own. If it keeps tripping, quarantine it."},
    "certifying_stuck": {"severity": "P3", "pending_s": 0,
                         "runbook": "Golden jobs have not finished: is the node asleep or yielding? Check its goldens on the node page; `nodes.recertify` retries."},
    "doctor_failed": {"severity": "P3", "pending_s": 300,
                      "runbook": "A module's doctor check fails on the node: see the failing checks on the node page, fix the dependency, then run the doctor."},
    "golden_failed": {"severity": "P4", "pending_s": 0,
                      "runbook": "Golden jobs keep failing: compare the golden results with the expected values; a module or tool change may need a new version."},
    "no_golden": {"severity": "P4", "pending_s": 0,
                  "runbook": "The module returned no goldens for this node class: it cannot be certified. Fix the module's golden.list or its settings."},
    "revoked": {"severity": "P4", "pending_s": 0,
                "runbook": "A golden mismatch revoked the module on the node: its results are not trusted until it re-certifies. Check the node's tools."},
    "quarantined": {"severity": "P4", "pending_s": 0,
                    "runbook": "The node gave wrong answers (dispute lost or nondeterminism): its results were invalidated. Investigate before clearing the quarantine."},
    "dispute": {"severity": "P4", "pending_s": 0,
                "runbook": "Replicas disagree and no third node can break the tie: the job is quarantined. Retry it once another node is certified."},
    "module_host_down": {"severity": "P4", "pending_s": 0,          # the inbox shows a module fault within 15 s (design)
                         "runbook": "A module's coordinator process is down: completions wait (nothing is charged). See the module's health page and stderr; restart it."},
    "coordinator_platform_unsupported": {"severity": "P4", "pending_s": 0,
                                         "runbook": "The coordinator moved to a platform this module's coordinator side does not run on (requires.coordinator_platforms), so the module was disabled. Install a version that supports this platform and enable it, or move the coordinator back."},
    "pinned_dataset_conflict": {"severity": "P3", "pending_s": 0,
                                "runbook": "A bootstrap job brought a module's pinned dataset, but another dataset with other files is registered under its id (often a hand registration), so it was left as it is. Delete that dataset; the next bootstrap job registers the pinned one."},
    "secret_unreadable": {"severity": "P3", "pending_s": 0,
                          "runbook": "A module secret is stored but this coordinator cannot decrypt it (a backup restored or a home copied to another machine, whose secrets key stayed behind): set it again with `oarbank secret set`. Jobs needing it wait with SECRETS_NOT_SET."},
    "placement_stranded": {"severity": "P3", "pending_s": 0,
                           "runbook": "A unit of work is bound to a platform class with no eligible node left: bring a node of that class back (online, certified), or move the campaign with campaigns.rebind_platform; its finished jobs run again in the new class."},
    "placement_rebound": {"severity": "P2", "pending_s": 0,
                          "runbook": "A unit of work with rebind = \"if-stranded\" moved to another platform class because its class had no eligible node; its finished jobs run again there. Nothing to do unless the move was unwanted."},
    "protection_flapping": {"severity": "P3", "pending_s": 0,
                            "runbook": "A protection rule escalates and relaxes too often: widen its thresholds or timing in the node's protection editor."},
    "protection_probe_harm": {"severity": "P3", "pending_s": 0,
                              "runbook": "Fleet work measurably slowed a protected process: consider strict_yield on that node or a tighter rule."},
    "release_awaiting_owner": {"severity": "P3", "pending_s": 300,
                               "runbook": "A release waits for the owner's signature, so its nodes get nothing new (an enrolled node gets no first release and runs no module). On the machine that holds the owner key run the command the alert names: `oarbank release sign <release> --promote` for a platform's release, `oarbank release sign <release>` for a canary or pinned node's own. `oarbank release list` shows every waiting release. The alert clears once the release is signed and current, or a newer build replaces it."},
    "listener_unreachable": {"severity": "P3", "pending_s": 600,
                             "runbook": "A module's inbound listener cannot be reached from the internet for 10 minutes (router port taken, two routers, carrier-grade NAT, no mapping protocol, a firewall). Read the listener's result and fix on the node page's Network card (oarbank listener show <node> <key>); Check now probes it again. It resolves when a probe reaches it."},
    "listener_saturated": {"severity": "P4", "pending_s": 0, "flap": (3, 3600),
                           "runbook": "A listener refuses connections at its caps (the listener's connection cap, or the per-address cap). If the clients are legitimate, drop a limit lowered on the node or raise the module's ceilings in a new version; if not, narrow the listener's allowed addresses (oarbank listener set <node> <key> --allow ...)."},
    "invariant": {"severity": "P5", "pending_s": 0,
                  "runbook": "A safety invariant failed: the condition is latched. Read the message on the Verify page; resolving needs a note."},
    "audit_copy_failed": {"severity": "P3", "pending_s": 0,
                          "runbook": "The off-host copy of the audit digests failed: check the `audit_digest_copy` command (ssh key, destination); the chain itself is fine."},
    "audit_chain_broken": {"severity": "P5", "pending_s": 0,
                           "runbook": "The audit hash chain does not verify: compare with the off-host digest copy before trusting the log."},
}
DEFAULT = {"severity": "P3", "pending_s": 0, "runbook": "See the event log around the time it opened."}




def policy(rule: str) -> dict:
    base = rule.split(":", 1)[0]
    return {**DEFAULT, **POLICY.get(base, {})}
