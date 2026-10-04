# Operation registry (generated)

Generated from `oarbank.contracts.operations` by `python -m oarbank.contracts.docs`. Tiers, reasons and previews follow PLAN D14–D15.

87 operations. Module operations (`mod.<module>.<verb>`) are registered per installed module and listed in the console.

## fleet

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `fleet.pause` — Stop granting new leases fleet-wide; running attempts continue | T0 | optional | – | operator | declarative | fleet.resume | `POST /api/v1/ops/{op}` (op=fleet.pause)<br>`POST /do/{op}` (op=fleet.pause) | oarbank op fleet.pause |
| `fleet.halt` — Pause pausable attempts and evict the rest gracefully | T1 | prompted | – | operator | declarative | fleet.resume | `POST /api/v1/ops/{op}` (op=fleet.halt)<br>`POST /do/{op}` (op=fleet.halt) | oarbank op fleet.halt |
| `fleet.resume` — Resume leasing (rollouts stay frozen until resumed separately) | T1 | required | – | operator | declarative | fleet.pause | `POST /api/v1/ops/{op}` (op=fleet.resume)<br>`POST /do/{op}` (op=fleet.resume) | oarbank op fleet.resume |

## nodes

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `nodes.admit` — Approve an enrollment request (the node gets its client certificate) | T2 | required | yes | admin | natural | nodes.retire | `POST /api/v1/ops/{op}` (op=nodes.admit)<br>`POST /do/{op}` (op=nodes.admit) | oarbank node approve <eid> |
| `nodes.join_code` — A one-time join code: a machine that enrolls with it is approved at once (expires, single use) | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=nodes.join_code)<br>`POST /do/{op}` (op=nodes.join_code) | oarbank join-code [--label NAME] |
| `nodes.reject_enrollment` — Reject an enrollment request | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=nodes.reject_enrollment)<br>`POST /do/{op}` (op=nodes.reject_enrollment) | oarbank node reject <eid> |
| `nodes.pause` — Stop leasing to a node; running attempts finish | T0 | optional | – | operator | declarative | nodes.resume | `POST /api/v1/ops/{op}` (op=nodes.pause)<br>`POST /do/{op}` (op=nodes.pause) | oarbank node state <nid> paused |
| `nodes.resume` — Resume leasing to a node | T0 | optional | – | operator | declarative | nodes.pause | `POST /api/v1/ops/{op}` (op=nodes.resume)<br>`POST /do/{op}` (op=nodes.resume) | oarbank node state <nid> active |
| `nodes.drain` — Finish running attempts, take no new ones (used by rolling upgrades) | T1 | prompted | – | operator | declarative | nodes.resume | `POST /api/v1/ops/{op}` (op=nodes.drain)<br>`POST /do/{op}` (op=nodes.drain) | oarbank node state <nid> draining |
| `nodes.set_caps` — Set or clear the owner's hard caps (cpu, memory, jobs, VM, disk, staging, schedule) | T0 (T1 when lowering a cap below current usage (attempts would be released)) | optional | – | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=nodes.set_caps)<br>`POST /do/{op}` (op=nodes.set_caps) | oarbank node limits <nid> ...<br>oarbank node limits <nid> --clear-all |
| `nodes.set_policy` — Edit node policy (reserves, VM scoring role, yield settings); re-doctors and re-certifies on role changes | T1 | prompted | – | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=nodes.set_policy)<br>`POST /do/{op}` (op=nodes.set_policy) | oarbank node policy <nid> ... |
| `nodes.quarantine` — Stop all work on a node and revoke its live attempts | T1 | prompted | – | operator | natural | nodes.clear_quarantine | `POST /api/v1/ops/{op}` (op=nodes.quarantine)<br>`POST /do/{op}` (op=nodes.quarantine) | – |
| `nodes.clear_quarantine` — Clear quarantine; the node re-doctors and re-certifies | T1 | prompted | – | operator | natural | nodes.quarantine | `POST /api/v1/ops/{op}` (op=nodes.clear_quarantine)<br>`POST /do/{op}` (op=nodes.clear_quarantine) | – |
| `nodes.run_doctor` — Ask the agent to re-run every module doctor | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=nodes.run_doctor)<br>`POST /do/{op}` (op=nodes.run_doctor) | – |
| `nodes.recertify` — Discard certification and re-run golden jobs | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=nodes.recertify)<br>`POST /do/{op}` (op=nodes.recertify) | – |
| `nodes.retire` — Retire a node and revoke its client certificate | T3 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=nodes.retire)<br>`POST /do/{op}` (op=nodes.retire) | – |
| `nodes.set_mode` — Set the protection mode (fleet_first | moderate | strict_yield) | T1 | prompted | – | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=nodes.set_mode)<br>`POST /do/{op}` (op=nodes.set_mode) | oarbank node mode <nid> <mode> |
| `nodes.confirm_identity` — Confirm that a node pinned this coordinator's identity key (compare the fingerprints once) | T1 | prompted | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=nodes.confirm_identity)<br>`POST /do/{op}` (op=nodes.confirm_identity) | oarbank node confirm-identity <node> |

## jobs

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `jobs.retry` — Requeue a failed or quarantined job | T0 · bulk | optional | – | operator | key | – | `POST /api/v1/ops/{op}` (op=jobs.retry)<br>`POST /do/{op}` (op=jobs.retry) | – |
| `jobs.cancel` — Cancel a job and revoke its live attempts (shows compute lost) | T1 · bulk | prompted | – | operator | natural | jobs.retry | `POST /api/v1/ops/{op}` (op=jobs.cancel)<br>`POST /do/{op}` (op=jobs.cancel) | – |
| `jobs.set_priority` — Change a job's priority | T0 · bulk | optional | – | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=jobs.set_priority)<br>`POST /do/{op}` (op=jobs.set_priority) | – |

## campaigns

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `campaigns.pause` — Stop dispatching a campaign's jobs | T0 | optional | – | operator | declarative | campaigns.resume | `POST /api/v1/ops/{op}` (op=campaigns.pause)<br>`POST /do/{op}` (op=campaigns.pause) | oarbank campaign pause <id> |
| `campaigns.resume` — Resume a paused campaign | T0 | optional | – | operator | declarative | campaigns.pause | `POST /api/v1/ops/{op}` (op=campaigns.resume)<br>`POST /do/{op}` (op=campaigns.resume) | oarbank campaign resume <id> |
| `campaigns.cancel` — Cancel a campaign and all its pending and running jobs | T3 | required | yes | operator | natural | – | `POST /api/v1/ops/{op}` (op=campaigns.cancel)<br>`POST /do/{op}` (op=campaigns.cancel) | oarbank campaign cancel <id> |
| `campaigns.retry_failed` — Retry every failed or quarantined job of a campaign (bulk jobs.retry) | T1 · bulk | prompted | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=campaigns.retry_failed)<br>`POST /do/{op}` (op=campaigns.retry_failed) | oarbank campaign retry-failed <id> |
| `campaigns.set_weight` — Change a campaign's fair-share weight | T0 | optional | – | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=campaigns.set_weight)<br>`POST /do/{op}` (op=campaigns.set_weight) | oarbank campaign weight <id> <w> |
| `campaigns.set_priority` — Change a campaign's priority (its open jobs move with it) | T0 | optional | – | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=campaigns.set_priority)<br>`POST /do/{op}` (op=campaigns.set_priority) | oarbank campaign priority <id> <p> |
| `campaigns.set_placement` — Keep a campaign's units of work on one platform class each (a stricter mix, before its first result) | T2 | required | yes | operator | declarative | – | `POST /api/v1/ops/{op}` (op=campaigns.set_placement)<br>`POST /do/{op}` (op=campaigns.set_placement) | oarbank campaign placement <id> --mix <mix> |
| `campaigns.rebind_platform` — Move a campaign's units of work to another platform class; their finished jobs run again there | T2 | required | yes | operator | natural | – | `POST /api/v1/ops/{op}` (op=campaigns.rebind_platform)<br>`POST /do/{op}` (op=campaigns.rebind_platform) | oarbank campaign rebind <id> --platform <token> |

## datasets

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `datasets.register` — Register a dataset from uploaded blobs, files on the coordinator or origin URLs | T1 | prompted | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=datasets.register)<br>`POST /api/v1/uploads/{digest}`<br>`PATCH /api/v1/uploads/{digest}`<br>`POST /do/{op}` (op=datasets.register)<br>`POST /datasets/uploads/{digest}`<br>`PATCH /datasets/uploads/{digest}` | oarbank dataset upload <dir> --kind <kind><br>oarbank dataset register <file.json> |
| `settings.origins.update` — Restrict the hosts dataset origins may name (empty: any public https host) | T2 | required | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=settings.origins.update)<br>`POST /do/{op}` (op=settings.origins.update) | oarbank op settings.origins.update -p hosts=... |

## modules

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `modules.set_pipeline` — Run a module single-stage or split | T2 | required | yes | admin | declarative | – | `POST /api/v1/ops/{op}` (op=modules.set_pipeline)<br>`POST /do/{op}` (op=modules.set_pipeline) | oarbank pipeline <module> single|split |
| `modules.install` — Install a module bundle: verify every file hash and the digest, check compatibility, self-test (enables nothing) | T2 | required | yes | admin | natural | modules.uninstall | `POST /api/v1/ops/{op}` (op=modules.install)<br>`POST /api/v1/modules/bundles`<br>`POST /do/{op}` (op=modules.install) | oarbank module install <bundle.mfb> |
| `modules.uninstall` — Remove an installed module version that no channel or pin uses | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=modules.uninstall)<br>`POST /do/{op}` (op=modules.uninstall) | oarbank module uninstall <name>@<version> |
| `modules.verify` — Re-verify installed bundles against their recorded digests | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=modules.verify)<br>`POST /do/{op}` (op=modules.verify) | oarbank module verify [name] |
| `modules.check` — Run module integrity checks (the module's integrity.check and the core's file checks) | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=modules.check)<br>`POST /do/{op}` (op=modules.check) | oarbank module check [name] [--deep] |
| `modules.enable` — Enable a module's first version, or re-enable it after the kill switch | T1 | prompted | – | admin | declarative | modules.disable | `POST /api/v1/ops/{op}` (op=modules.enable)<br>`POST /do/{op}` (op=modules.enable) | oarbank module enable <name>@<version> |
| `modules.approve` — Approve a module version's sandbox grants (network egress, host paths, GPU, containers) for its jobs | T2 | required | yes | admin | declarative | – | `POST /api/v1/ops/{op}` (op=modules.approve)<br>`POST /do/{op}` (op=modules.approve) | oarbank module approve <name>@<version> |
| `modules.enable_canary` — Stage a module version on canary nodes (they re-doctor and re-certify on it) | T2 | required | yes | admin | declarative | modules.rollback | `POST /api/v1/ops/{op}` (op=modules.enable_canary)<br>`POST /do/{op}` (op=modules.enable_canary) | oarbank module canary <name>@<version> --node <node> |
| `modules.promote` — Make the canary version the default on all nodes | T2 | required | yes | admin | declarative | modules.rollback | `POST /api/v1/ops/{op}` (op=modules.promote)<br>`POST /do/{op}` (op=modules.promote) | oarbank module promote <name>[@<canary version>] |
| `modules.rollback` — Abandon the canary, or flip the default back to the retained previous version | T1 | prompted | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=modules.rollback)<br>`POST /do/{op}` (op=modules.rollback) | oarbank module rollback <name> |
| `modules.disable` — Kill switch: stop dispatch fleet-wide within one heartbeat, requeue live attempts | T1 | prompted | – | operator | declarative | modules.enable | `POST /api/v1/ops/{op}` (op=modules.disable)<br>`POST /do/{op}` (op=modules.disable) | oarbank module disable <name> |
| `modules.pin` — Pin a node to a module version (or clear the pin) | T1 | prompted | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=modules.pin)<br>`POST /do/{op}` (op=modules.pin) | oarbank module pin|unpin <name>@<version> --node <node> |
| `modules.restart_host` — Restart a module's coordinator process | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=modules.restart_host)<br>`POST /do/{op}` (op=modules.restart_host) | – |
| `secrets.set` — Set a module secret for the module or one node (write-only: the value is never shown, only a fingerprint) | T1 | prompted | – | admin | declarative | secrets.clear | `POST /api/v1/ops/{op}` (op=secrets.set)<br>`POST /do/{op}` (op=secrets.set) | oarbank secret set <module> <name> [--node N] |
| `secrets.clear` — Remove a module secret's value for the module or one node (jobs needing it wait) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=secrets.clear)<br>`POST /do/{op}` (op=secrets.clear) | oarbank secret clear <module> <name> [--node N] |
| `modules.cli_token` — A one-hour token scoped to one module, for its CLI (oarbank cli <module>) | T1 | prompted | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=modules.cli_token)<br>`POST /do/{op}` (op=modules.cli_token) | oarbank cli <module> [args...] |

## releases

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `releases.build` — Build a release bundle from the installed modules (not deployed until promoted) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=releases.build)<br>`POST /do/{op}` (op=releases.build) | oarbank release build |
| `releases.attach_signature` — Attach an offline signature to a release (signing builds only) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=releases.attach_signature)<br>`POST /do/{op}` (op=releases.attach_signature) | oarbank release sign |
| `releases.promote` — Make a release current; agents install it on their next heartbeat | T2 | required | yes | admin | declarative | – | `POST /api/v1/ops/{op}` (op=releases.promote)<br>`POST /do/{op}` (op=releases.promote) | oarbank release promote <rid> |
| `releases.pin_key` — Pin or rotate the release public key (signing builds only) | T3 | required | yes | admin | declarative | – | `POST /api/v1/ops/{op}` (op=releases.pin_key)<br>`POST /do/{op}` (op=releases.pin_key) | oarbank release keygen |

## coordinator

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `coordinator.prepare` — Plan a coordinator move to another machine: a pairing code (and, for an enrolled node, its agent installs the standby) | T3 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=coordinator.prepare)<br>`POST /do/{op}` (op=coordinator.prepare) | oarbank coordinator prepare --to <node|http://host:port> |
| `coordinator.move` — Move the coordinator to the paired standby after the time lock (signed move statement; agents follow) | T3 | required | yes | admin | natural | coordinator.cancel | `POST /api/v1/ops/{op}` (op=coordinator.move)<br>`POST /do/{op}` (op=coordinator.move) | oarbank coordinator move [--timelock 24h] [--reason ...] |
| `coordinator.cancel` — Cancel a pending coordinator move (before the commit decision); this coordinator keeps serving | T1 | prompted | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=coordinator.cancel)<br>`POST /do/{op}` (op=coordinator.cancel) | oarbank coordinator cancel |
| `coordinator.finalize` — On the old machine after probation: stop serving redirects and never start again here | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=coordinator.finalize)<br>`POST /do/{op}` (op=coordinator.finalize) | oarbank coordinator finalize |
| `coordinator.sign_move` — Attach the owner's signature to a move waiting for it (signing mode); the move is then announced | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=coordinator.sign_move)<br>`POST /do/{op}` (op=coordinator.sign_move) | oarbank coordinator sign --owner-key <key> |
| `owner.set_anchors` — Set or rotate the owner key set (primary + offline backup, rescue locations); signed by the new keys and a current one | T3 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=owner.set_anchors)<br>`POST /do/{op}` (op=owner.set_anchors) | oarbank owner set --key <primary> --backup-key <backup> [--rescue URL] |
| `owner.disable_signing` — Turn owner signing off with an owner-signed statement (agents unpin the owner keys) | T3 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=owner.disable_signing)<br>`POST /do/{op}` (op=owner.disable_signing) | oarbank owner disable --key <owner key> |
| `coordinator.builds.upload` — Register a coordinator build for a platform (read from its manifest, never run) | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=coordinator.builds.upload)<br>`POST /api/v1/coordinator/builds`<br>`POST /do/{op}` (op=coordinator.builds.upload) | oarbank coordinator-build upload <archive> |
| `coordinator.builds.sign` — Attach an owner signature to a coordinator build (moves install only signed builds) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=coordinator.builds.sign)<br>`POST /do/{op}` (op=coordinator.builds.sign) | oarbank coordinator-build sign <build> |

## agent

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `agent.upload` — Register an oarbank-agent binary: its platform read from its headers and its version from its marker, never run (deploys nothing) | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=agent.upload)<br>`POST /api/v1/agent/builds`<br>`POST /do/{op}` (op=agent.upload) | oarbank agent upload <oarbank-agent> |
| `vendor.metadata.upload` — Mirror the vendor's TUF metadata for agents (they verify agent builds against the vendor root compiled into them) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=vendor.metadata.upload)<br>`POST /do/{op}` (op=vendor.metadata.upload) | oarbank vendor-metadata upload <dir> |
| `agent.canary` — Run an agent build on canary nodes (each drains, swaps and restarts on it) | T2 | required | yes | admin | declarative | agent.rollback | `POST /api/v1/ops/{op}` (op=agent.canary)<br>`POST /do/{op}` (op=agent.canary) | oarbank agent canary <build> --node <node> |
| `agent.promote` — Make the canary agent build current on every node of its platform (default: every platform with a canary) | T2 | required | yes | admin | declarative | agent.rollback | `POST /api/v1/ops/{op}` (op=agent.promote)<br>`POST /do/{op}` (op=agent.promote) | oarbank agent promote [--platform <os-arch>] |
| `agent.rollback` — Abandon the agent canary, or flip current back to the previous build | T1 | prompted | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=agent.rollback)<br>`POST /do/{op}` (op=agent.rollback) | oarbank agent rollback [--platform <os-arch>] |
| `agent.sign` — Attach an offline signature to an agent build (signing builds only) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=agent.sign)<br>`POST /do/{op}` (op=agent.sign) | oarbank agent sign <build> |

## protection

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `protection.rules.update` — Edit a node's protected-process rules (immutable versions) | T2 | required | yes | operator | declarative · versioned | protection.rules.restore | `POST /api/v1/ops/{op}` (op=protection.rules.update)<br>`POST /do/{op}` (op=protection.rules.update) | oarbank protection set <nid> <file> |
| `protection.rules.restore` — Restore a previous rule-set version (writes a new version) | T2 | required | yes | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=protection.rules.restore)<br>`POST /do/{op}` (op=protection.rules.restore) | oarbank protection restore <nid> <version> |
| `protection.rules.canary` — Apply a rule set to one node first, then promote it to the rest | T2 | required | yes | operator | declarative | – | `POST /api/v1/ops/{op}` (op=protection.rules.canary)<br>`POST /do/{op}` (op=protection.rules.canary) | oarbank protection canary <nid> <file><br>oarbank protection promote |
| `protection.probe_now` — Run a pause probe now | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=protection.probe_now)<br>`POST /do/{op}` (op=protection.probe_now) | oarbank protection probe <nid> |

## alerts

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `alerts.ack` — Acknowledge an alert (optionally: was it useful?) | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=alerts.ack)<br>`POST /do/{op}` (op=alerts.ack) | oarbank alerts ack <id> [--useful|--noise] |
| `alerts.snooze` — Snooze an alert until a time (no re-notification meanwhile) | T0 | optional | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=alerts.snooze)<br>`POST /do/{op}` (op=alerts.snooze) | oarbank alerts snooze <id> --minutes N |
| `alerts.resolve` — Resolve an alert (a latched invariant needs a note) | T0 (T1 with a note for a latched invariant) | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=alerts.resolve)<br>`POST /do/{op}` (op=alerts.resolve) | oarbank alerts resolve <id> [--useful|--noise] |

## settings

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `settings.notifications.update` — Edit ntfy and notification settings | T2 | required | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=settings.notifications.update)<br>`POST /do/{op}` (op=settings.notifications.update) | – |
| `settings.tools.update` — Map a host tool id to its paths per OS in the tool registry (modules request tools by id) | T2 | required | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=settings.tools.update)<br>`POST /do/{op}` (op=settings.tools.update) | – |
| `settings.folders.update` — Map a folder id to a path on each node in the folder registry (modules request folders by id) | T2 | required | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=settings.folders.update)<br>`POST /do/{op}` (op=settings.folders.update) | oarbank folders map <id> --access read|write --node <node>=<path> |
| `folders.sign` — Attach the owner's signature to a node's folder statement (signing mode) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=folders.sign)<br>`POST /do/{op}` (op=folders.sign) | oarbank folders sign <node> |
| `settings.update` — Write a raw setting (goldens, dataset groups) | T2 | required | yes | admin | declarative | – | `POST /api/v1/ops/{op}` (op=settings.update)<br>`POST /do/{op}` (op=settings.update) | oarbank op settings.update <key><br>module CLIs (golden:<module>, dataset_groups) |

## access

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `access.accounts.create` — Create a console account (a TOTP seed is shown once; a password is optional) | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=access.accounts.create)<br>`POST /do/{op}` (op=access.accounts.create) | oarbank account create <name> |
| `access.accounts.update` — Change an account's role, or disable or enable it (disabling ends its sessions and tokens) | T2 | required | yes | admin | declarative | – | `POST /api/v1/ops/{op}` (op=access.accounts.update)<br>`POST /do/{op}` (op=access.accounts.update) | – |
| `access.accounts.reset_totp` — Issue a new TOTP seed for an account (ends its sessions) | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=access.accounts.reset_totp)<br>`POST /do/{op}` (op=access.accounts.reset_totp) | – |
| `access.accounts.set_password` — Set an account's password (ends its sessions) | T1 | prompted | – | viewer | natural | – | `POST /api/v1/ops/{op}` (op=access.accounts.set_password)<br>`POST /do/{op}` (op=access.accounts.set_password) | – |
| `access.tokens.create` — Create a personal access token for scripts (shown once, expires) | T2 | required | yes | viewer | natural | – | `POST /api/v1/ops/{op}` (op=access.tokens.create)<br>`POST /do/{op}` (op=access.tokens.create) | oarbank token create |
| `access.tokens.revoke` — Revoke a personal access token | T1 | prompted | – | viewer | natural | – | `POST /api/v1/ops/{op}` (op=access.tokens.revoke)<br>`POST /do/{op}` (op=access.tokens.revoke) | – |
| `access.login_link` — Mint a one-time console sign-in link (valid 2 minutes) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=access.login_link)<br>`POST /do/{op}` (op=access.login_link) | oarbank console login [--account <name>] |
| `access.passkeys.remove` — Remove a passkey from an account | T1 | prompted | – | viewer | natural | – | `POST /api/v1/ops/{op}` (op=access.passkeys.remove)<br>`POST /do/{op}` (op=access.passkeys.remove) | – |

## audit

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `audit.verify` — Recompute the audit hash chain against the signed digests | T0 | optional | – | viewer | natural | – | `POST /api/v1/ops/{op}` (op=audit.verify)<br>`POST /do/{op}` (op=audit.verify) | oarbank audit verify |

## Agent protocol routes (not operations)

Machine-to-machine, authenticated by the node's client certificate and fenced by generation; audited as events under `node:<id>`.

- `POST /v1/agent/cert`
- `POST /v1/agent/claim`
- `POST /v1/agent/enroll`
- `POST /v1/agent/heartbeat`
- `POST /v1/agent/hello`
- `POST /v1/attempts/{aid}/checkpoint`
- `POST /v1/attempts/{aid}/complete`
- `POST /v1/attempts/{aid}/fail`
- `POST /v1/attempts/{aid}/log`
- `POST /v1/attempts/{aid}/release`
- `POST /v1/move/commit`
- `POST /v1/move/pair`
- `POST /v1/move/promote`
- `POST /v1/move/ready`
- `POST /v1/move/sign-statement`
- `POST /v1/move/snapshot`
- `PATCH /v1/uploads/{digest}`
- `POST /v1/uploads/{digest}`
