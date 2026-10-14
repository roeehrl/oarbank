# Operation registry (generated)

Generated from `oarbank.contracts.operations` by `python -m oarbank.contracts.docs`. Tiers, reasons and previews follow PLAN D14–D15.

125 operations. Module operations (`mod.<module>.<verb>`) are registered per installed module and listed in the console.

## fleet

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `fleet.pause` — Stop granting new leases fleet-wide; running attempts continue | T0 | optional | – | operator | declarative | fleet.resume | `POST /api/v1/ops/{op}` (op=fleet.pause)<br>`POST /do/{op}` (op=fleet.pause) | oarbank pause --all |
| `fleet.halt` — Pause pausable attempts and evict the rest gracefully | T1 | prompted | – | operator | declarative | fleet.resume | `POST /api/v1/ops/{op}` (op=fleet.halt)<br>`POST /do/{op}` (op=fleet.halt) | oarbank halt --all |
| `fleet.resume` — Resume leasing (rollouts stay frozen until resumed separately) | T1 | required | – | operator | declarative | fleet.pause | `POST /api/v1/ops/{op}` (op=fleet.resume)<br>`POST /do/{op}` (op=fleet.resume) | oarbank resume --all |

## nodes

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `nodes.admit` — Approve an enrollment request (the node gets its client certificate) | T2 | required | yes | admin | natural | nodes.retire | `POST /api/v1/ops/{op}` (op=nodes.admit)<br>`POST /do/{op}` (op=nodes.admit) | oarbank node approve <eid> |
| `nodes.join_code` — A join code for new machines: single use and approved at once by default; multi-use codes cap their uses and leave machines pending unless set to approve automatically (expires) | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=nodes.join_code)<br>`POST /do/{op}` (op=nodes.join_code) | oarbank join-code [--label NAME] [--uses N] [--ttl S] |
| `nodes.revoke_join_code` — Revoke a join code (machines that already joined with it stay) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=nodes.revoke_join_code)<br>`POST /do/{op}` (op=nodes.revoke_join_code) | oarbank join-code revoke <id> |
| `nodes.admit_code` — Approve the waiting machine that shows this code (a node joined by the coordinator's address) | T2 | required | yes | admin | natural | nodes.retire | `POST /api/v1/ops/{op}` (op=nodes.admit_code)<br>`POST /do/{op}` (op=nodes.admit_code) | oarbank node approve-code <CODE> |
| `nodes.reject_enrollment` — Reject an enrollment request | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=nodes.reject_enrollment)<br>`POST /do/{op}` (op=nodes.reject_enrollment) | oarbank node reject <eid> |
| `nodes.pause` — Stop leasing to a node; running attempts finish | T0 | optional | – | operator | declarative | nodes.resume | `POST /api/v1/ops/{op}` (op=nodes.pause)<br>`POST /do/{op}` (op=nodes.pause) | oarbank node state <nid> paused |
| `nodes.resume` — Resume leasing to a node | T0 | optional | – | operator | declarative | nodes.pause | `POST /api/v1/ops/{op}` (op=nodes.resume)<br>`POST /do/{op}` (op=nodes.resume) | oarbank node state <nid> active |
| `nodes.drain` — Finish running attempts, take no new ones (used by rolling upgrades) | T1 | prompted | – | operator | declarative | nodes.resume | `POST /api/v1/ops/{op}` (op=nodes.drain)<br>`POST /do/{op}` (op=nodes.drain) | oarbank node state <nid> draining |
| `nodes.quarantine` — Stop all work on a node and revoke its live attempts | T1 | prompted | – | operator | natural | nodes.clear_quarantine | `POST /api/v1/ops/{op}` (op=nodes.quarantine)<br>`POST /do/{op}` (op=nodes.quarantine) | – |
| `nodes.clear_quarantine` — Clear quarantine; the node re-doctors and re-certifies | T1 | prompted | – | operator | natural | nodes.quarantine | `POST /api/v1/ops/{op}` (op=nodes.clear_quarantine)<br>`POST /do/{op}` (op=nodes.clear_quarantine) | – |
| `nodes.run_doctor` — Ask the agent to re-run every module doctor | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=nodes.run_doctor)<br>`POST /do/{op}` (op=nodes.run_doctor) | – |
| `nodes.recertify` — Discard certification and re-run golden jobs | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=nodes.recertify)<br>`POST /do/{op}` (op=nodes.recertify) | – |
| `nodes.retire` — Retire a node and revoke its client certificate | T3 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=nodes.retire)<br>`POST /do/{op}` (op=nodes.retire) | – |
| `nodes.set_mode` — Set a node's own protection mode (fleet_first | moderate | strict_yield; a lock above refuses it) | T1 | prompted | – | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=nodes.set_mode)<br>`POST /do/{op}` (op=nodes.set_mode) | oarbank node mode <nid> <mode> |
| `nodes.confirm_identity` — Confirm that a node pinned this coordinator's identity key (compare the fingerprints once) | T1 | prompted | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=nodes.confirm_identity)<br>`POST /do/{op}` (op=nodes.confirm_identity) | oarbank node confirm-identity <node> |
| `sites.create` — Create a site (nodes that share one internet line) with its uplink budget; a node at another site moves; network-heavy work at the site pauses while a protected process there is in an uplink phase | T1 | prompted | yes | admin | natural · versioned | sites.delete | `POST /api/v1/ops/{op}` (op=sites.create)<br>`POST /do/{op}` (op=sites.create) | oarbank sites create <name> [--node N ...] [--mbps M] [--transfers N] [--heavy-jobs N]<br>oarbank sites accept <suggestion> [--name <name>] |
| `sites.update` — Change a site's name, description or uplink budget (transfers at once, network-heavy jobs at once, the rate the fleet's transfers may use); every lease is renewed at the new terms | T1 | prompted | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=sites.update)<br>`POST /do/{op}` (op=sites.update) | oarbank sites update <site> [--name N] [--mbps M] [--transfers N] [--heavy-jobs N] |
| `sites.assign` — Put nodes at a site (a node at another site moves there); the preview names each move | T1 | prompted | yes | admin | declarative · versioned | sites.unassign | `POST /api/v1/ops/{op}` (op=sites.assign)<br>`POST /do/{op}` (op=sites.assign) | oarbank sites add <site> <node> [<node> ...]<br>oarbank sites accept <suggestion> --site <site> |
| `sites.unassign` — Take nodes out of their site: their transfers and network-heavy jobs no longer follow any site | T1 | prompted | yes | admin | declarative · versioned | sites.assign | `POST /api/v1/ops/{op}` (op=sites.unassign)<br>`POST /do/{op}` (op=sites.unassign) | oarbank sites remove <node> [<node> ...] |
| `sites.delete` — Delete a site; its nodes are at no site (no hold, no budget) afterwards | T2 | required | yes | admin | natural · versioned | – | `POST /api/v1/ops/{op}` (op=sites.delete)<br>`POST /do/{op}` (op=sites.delete) | oarbank sites delete <site> |
| `sites.dismiss` — Dismiss a site suggestion (it is not offered again) | T0 | optional | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=sites.dismiss)<br>`POST /do/{op}` (op=sites.dismiss) | oarbank sites dismiss <suggestion> |
| `nodes.label` — Add or remove a node's labels (or several nodes'): a label can move nodes into or out of groups | T1 | prompted | yes | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=nodes.label)<br>`POST /do/{op}` (op=nodes.label) | oarbank node label <node> <labels> [--remove] |
| `tools.detect` — Ask a node's agent to detect its host tools again (Re-detect) | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=tools.detect)<br>`POST /do/{op}` (op=tools.detect) | oarbank tools detect <node> |
| `nodes.sign_statement` — Attach the owner's signature to a node's statement: its folders, added tool paths and listeners (signing mode) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=nodes.sign_statement)<br>`POST /do/{op}` (op=nodes.sign_statement) | oarbank node sign <node> |
| `listeners.configure` — Assign a module's inbound listener to a node, or change its entry: external port, fallback, mapping, IPv6, bind, internal port, lowered limits, allowed addresses (the node statement; signing mode: oarbank node sign) | T2 | required | yes | admin | declarative | listeners.remove | `POST /api/v1/ops/{op}` (op=listeners.configure)<br>`POST /do/{op}` (op=listeners.configure) | oarbank listener set <node> <key> |
| `listeners.remove` — Remove a listener's entry from a node: the agent closes it and removes its router mapping once it applies the new statement | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=listeners.remove)<br>`POST /do/{op}` (op=listeners.remove) | oarbank listener remove <node> <key> |
| `listeners.disable` — The listener kill switch for a node or the fleet: every listener closes and every router mapping is removed at the next heartbeat | T0 | optional | – | operator | declarative | listeners.resume | `POST /api/v1/ops/{op}` (op=listeners.disable)<br>`POST /do/{op}` (op=listeners.disable) | oarbank listener disable --node <node><br>oarbank listener disable --all |
| `listeners.resume` — Lift the listener kill switch for a node or the fleet | T1 | prompted | – | operator | declarative | listeners.disable | `POST /api/v1/ops/{op}` (op=listeners.resume)<br>`POST /do/{op}` (op=listeners.resume) | oarbank listener resume --node <node><br>oarbank listener resume --all |
| `listeners.probe` — Check a listener from outside now: a fleet node on another network dials its external address (at most once a minute) | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=listeners.probe)<br>`POST /do/{op}` (op=listeners.probe) | oarbank listener probe <node> <key> |

## jobs

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `jobs.retry` — Requeue a failed or quarantined job | T0 · bulk | optional | – | operator | key | – | `POST /api/v1/ops/{op}` (op=jobs.retry)<br>`POST /do/{op}` (op=jobs.retry) | oarbank job retry <jid> |
| `jobs.cancel` — Cancel a job and revoke its live attempts (shows compute lost) | T1 · bulk | prompted | – | operator | natural | jobs.retry | `POST /api/v1/ops/{op}` (op=jobs.cancel)<br>`POST /do/{op}` (op=jobs.cancel) | oarbank job cancel <jid> |
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
| `modules.install` — Install a module bundle: verify every file hash and the digest, check compatibility, self-test (enables nothing) | T2 | required | yes | admin | natural | modules.uninstall | `POST /api/v1/ops/{op}` (op=modules.install)<br>`POST /api/v1/modules/bundles`<br>`POST /do/{op}` (op=modules.install)<br>`POST /stage/{op}` (op=modules.install) | oarbank module install <bundle.mfb> |
| `modules.uninstall` — Remove an installed module version that no channel or pin uses | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=modules.uninstall)<br>`POST /do/{op}` (op=modules.uninstall) | oarbank module uninstall <name>@<version> |
| `modules.verify` — Re-verify installed bundles against their recorded digests | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=modules.verify)<br>`POST /do/{op}` (op=modules.verify) | oarbank module verify [name] |
| `modules.check` — Run module integrity checks (the module's integrity.check and the core's file checks) | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=modules.check)<br>`POST /do/{op}` (op=modules.check) | oarbank module check [name] [--deep] |
| `modules.enable` — Enable a module's first version, or re-enable it after the kill switch | T1 | prompted | – | admin | declarative | modules.disable | `POST /api/v1/ops/{op}` (op=modules.enable)<br>`POST /do/{op}` (op=modules.enable) | oarbank module enable <name>@<version> |
| `modules.approve` — Approve a module version's sandbox grants (network egress, host paths, GPU, containers) for its jobs | T2 | required | yes | admin | declarative | – | `POST /api/v1/ops/{op}` (op=modules.approve)<br>`POST /do/{op}` (op=modules.approve) | oarbank module approve <name>@<version> |
| `modules.enable_canary` — Stage a module version on canary nodes, or a group's members (they re-doctor and re-certify on it) | T2 | required | yes | admin | declarative | modules.rollback | `POST /api/v1/ops/{op}` (op=modules.enable_canary)<br>`POST /do/{op}` (op=modules.enable_canary) | oarbank module canary <name>@<version> --node <node><br>oarbank module canary <name>@<version> --group <group> |
| `modules.promote` — Make the canary version the default on all nodes | T2 | required | yes | admin | declarative | modules.rollback | `POST /api/v1/ops/{op}` (op=modules.promote)<br>`POST /do/{op}` (op=modules.promote) | oarbank module promote <name>[@<canary version>] |
| `modules.rollback` — Abandon the canary, or flip the default back to the retained previous version | T1 | prompted | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=modules.rollback)<br>`POST /do/{op}` (op=modules.rollback) | oarbank module rollback <name> |
| `modules.disable` — Kill switch: stop dispatch fleet-wide within one heartbeat, requeue live attempts | T1 | prompted | – | operator | declarative | modules.enable | `POST /api/v1/ops/{op}` (op=modules.disable)<br>`POST /do/{op}` (op=modules.disable) | oarbank module disable <name> |
| `modules.purge` — Delete what a module left on a node (or on every node where it is turned off) at once, after its cleanup stage; never where it is enabled | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=modules.purge)<br>`POST /do/{op}` (op=modules.purge) | oarbank module purge <name> --node <node><br>oarbank module purge <name> --all |
| `modules.pin` — Pin a node to a module version (or clear the pin) | T1 | prompted | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=modules.pin)<br>`POST /do/{op}` (op=modules.pin) | oarbank module pin|unpin <name>@<version> --node <node> |
| `modules.restart_host` — Restart a module's coordinator process | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=modules.restart_host)<br>`POST /do/{op}` (op=modules.restart_host) | – |
| `secrets.set` — Set a module secret for the module, a node group or one node (write-only: the value is never shown, only a fingerprint) | T1 | prompted | – | admin | declarative | secrets.clear | `POST /api/v1/ops/{op}` (op=secrets.set)<br>`POST /do/{op}` (op=secrets.set) | oarbank secret set <module> <name> [--node N]<br>oarbank secret set <module> <name> [--group G] |
| `secrets.clear` — Remove a module secret's value for the module, a node group or one node (nodes fall back along the chain; jobs needing it wait) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=secrets.clear)<br>`POST /do/{op}` (op=secrets.clear) | oarbank secret clear <module> <name> [--node N]<br>oarbank secret clear <module> <name> [--group G] |
| `modules.cli_token` — A one-hour token scoped to one module, for its CLI (oarbank cli <module>) | T1 | prompted | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=modules.cli_token)<br>`POST /do/{op}` (op=modules.cli_token) | oarbank cli <module> [args...] |

## releases

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `releases.build` — Build each fleet platform's release from the enabled modules (nodes get it once it is signed and promoted) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=releases.build)<br>`POST /do/{op}` (op=releases.build) | oarbank release build |
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
| `coordinator.builds.upload` — Register a coordinator build for a platform (read from its manifest, never run) | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=coordinator.builds.upload)<br>`POST /api/v1/coordinator/builds`<br>`POST /do/{op}` (op=coordinator.builds.upload)<br>`POST /stage/{op}` (op=coordinator.builds.upload) | oarbank coordinator-build upload <archive> |
| `coordinator.builds.sign` — Attach an owner signature to a coordinator build (moves install only signed builds) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=coordinator.builds.sign)<br>`POST /do/{op}` (op=coordinator.builds.sign) | oarbank coordinator-build sign <build> |

## agent

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `agent.upload` — Register an oarbank-agent binary: its platform read from its headers and its version from its marker, never run (deploys nothing) | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=agent.upload)<br>`POST /api/v1/agent/builds`<br>`POST /do/{op}` (op=agent.upload)<br>`POST /stage/{op}` (op=agent.upload) | oarbank agent upload <oarbank-agent> |
| `vendor.metadata.upload` — Mirror the vendor's TUF metadata for agents (they verify agent builds against the vendor root compiled into them) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=vendor.metadata.upload)<br>`POST /do/{op}` (op=vendor.metadata.upload) | oarbank vendor-metadata upload <dir> |
| `agent.canary` — Run an agent build on canary nodes (each drains, swaps and restarts on it) | T2 | required | yes | admin | declarative | agent.rollback | `POST /api/v1/ops/{op}` (op=agent.canary)<br>`POST /do/{op}` (op=agent.canary) | oarbank agent canary <build> --node <node> |
| `agent.promote` — Make the canary agent build current on every node of its platform (default: every platform with a canary) | T2 | required | yes | admin | declarative | agent.rollback | `POST /api/v1/ops/{op}` (op=agent.promote)<br>`POST /do/{op}` (op=agent.promote) | oarbank agent promote [--platform <os-arch>] |
| `agent.rollback` — Abandon the agent canary, or flip current back to the previous build | T1 | prompted | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=agent.rollback)<br>`POST /do/{op}` (op=agent.rollback) | oarbank agent rollback [--platform <os-arch>] |
| `agent.sign` — Attach an offline signature to an agent build (signing builds only) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=agent.sign)<br>`POST /do/{op}` (op=agent.sign) | oarbank agent sign <build> |

## updates

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `updates.import` — Import a fleet release: its manifest and the artifacts this fleet needs, each checked against its sha256 and size (installs nothing) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=updates.import)<br>`POST /api/v1/updates/uploads`<br>`POST /do/{op}` (op=updates.import) | oarbank update import <dir> |
| `updates.fetch` — Download a fleet release from the release source (update_source) and import it | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=updates.fetch)<br>`POST /do/{op}` (op=updates.fetch) | oarbank update fetch <version> |
| `updates.sign` — Attach the owner's signature to a fleet release (made offline with the owner key) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=updates.sign)<br>`POST /do/{op}` (op=updates.sign) | oarbank update sign <version> |
| `updates.start` — Update the fleet to a release: the coordinator first, then the canary, early and broad rings under their caps, bake gates and failure budgets | T2 | required | yes | admin | natural | updates.rollback | `POST /api/v1/ops/{op}` (op=updates.start)<br>`POST /do/{op}` (op=updates.start) | oarbank update start <version> [--fast]<br>oarbank update plan <version><br>oarbank update coordinator <version> |
| `updates.pause` — Pause a rollout: no new node is told to install; installs under way finish | T1 | prompted | – | operator | declarative | updates.resume | `POST /api/v1/ops/{op}` (op=updates.pause)<br>`POST /do/{op}` (op=updates.pause) | oarbank update pause |
| `updates.resume` — Resume a paused or halted rollout | T1 | prompted | – | admin | declarative | updates.pause | `POST /api/v1/ops/{op}` (op=updates.resume)<br>`POST /do/{op}` (op=updates.resume) | oarbank update resume |
| `updates.halt` — Halt a rollout: nothing new starts until it is resumed or rolled back | T1 | prompted | – | operator | declarative | updates.resume | `POST /api/v1/ops/{op}` (op=updates.halt)<br>`POST /do/{op}` (op=updates.halt) | oarbank update halt |
| `updates.rollback` — Roll a rollout back: every node it moved reinstalls the release it ran | T2 | required | yes | admin | natural | – | `POST /api/v1/ops/{op}` (op=updates.rollback)<br>`POST /do/{op}` (op=updates.rollback) | oarbank update rollback |
| `updates.skip` — Leave a node out of the current rollout (it frees its slot) | T1 | prompted | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=updates.skip)<br>`POST /do/{op}` (op=updates.skip) | oarbank update skip <node> |
| `updates.hold` — Hold a node's updates, with a reason and an optional expiry (update_hold) | T1 | prompted | – | operator | declarative | updates.unhold | `POST /api/v1/ops/{op}` (op=updates.hold)<br>`POST /do/{op}` (op=updates.hold) | oarbank update hold <node> --reason <why> [--until <time>] |
| `updates.unhold` — Lift a node's update hold; it rejoins the rollout | T1 | prompted | – | operator | declarative | updates.hold | `POST /api/v1/ops/{op}` (op=updates.unhold)<br>`POST /do/{op}` (op=updates.unhold) | oarbank update unhold <node> |
| `updates.pin` — Pin a node to a release, with a reason and an optional expiry (update_pin) | T1 | prompted | – | admin | declarative | updates.unpin | `POST /api/v1/ops/{op}` (op=updates.pin)<br>`POST /do/{op}` (op=updates.pin) | oarbank update pin <node> <version> --reason <why> [--until <time>] |
| `updates.unpin` — Lift a node's update pin; it follows rollouts again | T1 | prompted | – | operator | declarative | updates.pin | `POST /api/v1/ops/{op}` (op=updates.unpin)<br>`POST /do/{op}` (op=updates.unpin) | oarbank update unpin <node> |

## protection

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `protection.rules.update` — Set a scope's own protection section (a node, the fleet or a group): its rules, node section and mode; every scope's rules apply together on a node | T2 | required | yes | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=protection.rules.update)<br>`POST /do/{op}` (op=protection.rules.update) | oarbank protection set <node> <file><br>oarbank protection set fleet <file><br>oarbank protection set group:<group> <file><br>oarbank protection preview <node> <file> |
| `protection.probe_now` — Run a pause probe now | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=protection.probe_now)<br>`POST /do/{op}` (op=protection.probe_now) | oarbank protection probe <nid> |
| `protection.ab.start` — Start a paired on/off harness run on a node: fleet work under test runs beside a protected process in ON windows and is held in OFF windows until the margin is decided (D52) | T2 | required | yes | operator | natural | – | `POST /api/v1/ops/{op}` (op=protection.ab.start)<br>`POST /do/{op}` (op=protection.ab.start) | oarbank protection ab start <node> --rule <id> [--work <w>] [--duty <d>] [--blocks <n>] [--window <s>] [--washout <s>] [--margin <m>] [--off paused|evicted] [--max-hours <h>] |
| `protection.ab.abort` — Abort a harness run (its work under test runs as protection allows again) | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=protection.ab.abort)<br>`POST /do/{op}` (op=protection.ab.abort) | oarbank protection ab abort <run> |
| `protection.ab.sweep` — Search a node's certified GPU duty for a rule: harness runs at rising gpu_duty levels, stopping at the first that is not "no slowdown shown" | T2 | required | yes | operator | natural | – | `POST /api/v1/ops/{op}` (op=protection.ab.sweep)<br>`POST /do/{op}` (op=protection.ab.sweep) | oarbank protection ab sweep <node> --rule <id> [--work <w>] [--levels <list>] |

## alerts

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `alerts.ack` — Acknowledge an alert (optionally: was it useful?) | T0 | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=alerts.ack)<br>`POST /do/{op}` (op=alerts.ack) | oarbank alerts ack <id> [--useful|--noise] |
| `alerts.snooze` — Snooze an alert until a time (no re-notification meanwhile) | T0 | optional | – | operator | declarative | – | `POST /api/v1/ops/{op}` (op=alerts.snooze)<br>`POST /do/{op}` (op=alerts.snooze) | oarbank alerts snooze <id> --minutes N |
| `alerts.resolve` — Resolve an alert (a latched invariant needs a note) | T0 (T1 with a note for a latched invariant) | optional | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=alerts.resolve)<br>`POST /do/{op}` (op=alerts.resolve) | oarbank alerts resolve <id> [--useful|--noise] |

## settings

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `settings.apply` — Set or reset owner settings at the fleet, a group or a node, as one change set (policy, caps, notifications, access, verification); the preview names every node whose effective value changes | T0 (from each key's danger tier and scope: a node change keeps the key's tier (caps T0, policy T1), a fleet or group change is one tier up, a lock is T3) | optional | yes | operator | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=settings.apply)<br>`POST /do/{op}` (op=settings.apply) | oarbank settings set <key> <value> [--node <node>] [--group <group>]<br>oarbank settings reset <key> [--node <node>] [--group <group>] |
| `settings.import` — Import a settings export (YAML): groups, labels, tool definitions and values, only where they differ, as one change; absent keys inherit, !reset deletes | T2 (T3 when the file adds or changes a lock) | required | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=settings.import)<br>`POST /do/{op}` (op=settings.import) | oarbank settings import <file> [--dry-run] |
| `settings.secrets.set` — Set a core secret (the ntfy token): write-only, shown only as a fingerprint | T1 | prompted | – | admin | declarative | settings.secrets.clear | `POST /api/v1/ops/{op}` (op=settings.secrets.set)<br>`POST /do/{op}` (op=settings.secrets.set) | oarbank settings set-secret <name> |
| `settings.secrets.clear` — Remove a core secret's value (the ntfy token) | T1 | prompted | – | admin | natural | – | `POST /api/v1/ops/{op}` (op=settings.secrets.clear)<br>`POST /do/{op}` (op=settings.secrets.clear) | oarbank settings clear-secret <name> |
| `settings.promote` — Promote a group's value of a setting (a canary) to the fleet or a wider group: set there and deleted from the group, as one change set | T1 (from the key's danger tier at the target scope (a fleet change is one tier up); a lock is T3) | prompted | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=settings.promote)<br>`POST /do/{op}` (op=settings.promote) | oarbank settings promote <key> --group <group> [--to <group>] |
| `groups.create` — Create a node group: a selector over node facts and labels, explicit members; it ranks above every other owner group | T1 | prompted | yes | admin | natural · versioned | groups.delete | `POST /api/v1/ops/{op}` (op=groups.create)<br>`POST /do/{op}` (op=groups.create) | oarbank groups create <name> [--os <os>] [--label <label>] [--member <node>] |
| `groups.update` — Change a node group's name, selector, members or description; the preview names the nodes that join or leave and whose settings change | T2 | required | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=groups.update)<br>`POST /do/{op}` (op=groups.update) | oarbank groups update <group> |
| `groups.rank` — Move a node group up or down the ranking (where groups set the same key, the higher rank wins) | T2 | required | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=groups.rank)<br>`POST /do/{op}` (op=groups.rank) | oarbank groups rank <group> up|down|top|bottom |
| `groups.delete` — Delete a node group with its values and secret values; its members fall back to the next layer down | T2 | required | yes | admin | natural · versioned | – | `POST /api/v1/ops/{op}` (op=groups.delete)<br>`POST /do/{op}` (op=groups.delete) | oarbank groups delete <group> |
| `tools.define` — Define a host tool (a detector kind, extra search paths per OS, an executable's version command); jdk and python are built in | T2 | required | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=tools.define)<br>`POST /do/{op}` (op=tools.define) | oarbank tools define <id> --search <os>=<pattern> |
| `tools.delete` — Delete a host tool definition (a built-in tool loses only its extra search paths) | T2 | required | yes | admin | natural · versioned | – | `POST /api/v1/ops/{op}` (op=tools.delete)<br>`POST /do/{op}` (op=tools.delete) | oarbank tools delete <id> |
| `settings.folders.update` — Map a folder id to a path on each node in the folder registry (modules request folders by id) | T2 | required | yes | admin | declarative · versioned | – | `POST /api/v1/ops/{op}` (op=settings.folders.update)<br>`POST /do/{op}` (op=settings.folders.update) | oarbank folders map <id> --access read|write --node <node>=<path> |

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

## workloads

| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |
|---|---|---|---|---|---|---|---|---|
| `workloads.assign` — Assign a module's workload to a node (seat "node") or ask the coordinator to place a count of seats (seat "fleet"); the preview names each node, the secrets it receives, its seat, listeners and the protection rules there | T2 | required | yes | admin | natural | workloads.unassign | `POST /api/v1/ops/{op}` (op=workloads.assign)<br>`POST /do/{op}` (op=workloads.assign) | oarbank workload assign <module>/<workload> --node N<br>oarbank workload assign <module>/<workload> --count C |
| `workloads.unassign` — Stop running a workload on a node; its seat goes back once the node reports it stopped | T1 | prompted | – | operator | natural | workloads.assign | `POST /api/v1/ops/{op}` (op=workloads.unassign)<br>`POST /do/{op}` (op=workloads.unassign) | oarbank workload unassign <module>/<workload> --node N |
| `workloads.restart` — Restart a workload on a node (also lifts a withdrawal after repeated failures) | T1 | prompted | – | operator | natural | – | `POST /api/v1/ops/{op}` (op=workloads.restart)<br>`POST /do/{op}` (op=workloads.restart) | oarbank workload restart <module>/<workload> --node N |

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
- `POST /v1/agent/uplink/lease`
- `POST /v1/agent/uplink/network`
- `POST /v1/agent/uplink/release`
- `POST /v1/agent/uplink/renew`
- `POST /v1/agent/workloads/secrets`
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
