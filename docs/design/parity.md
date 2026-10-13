# Parity report (generated)

Generated from the registries and the sources by `python -m oarbank.contracts.docs`. Every operation must be reachable from the API (`POST /api/v1/ops/<id>` or its own route), the CLI (its own `oarbank` command, or `oarbank op <id>`) and the console (a form for it in a template); every explain kind from all three; every reason code's remedies must be operations.

**0 gaps.** 124 operations, 2 explain kinds, 190 reason codes. Module operations (`mod.<module>.<verb>`) are generic: the API endpoint, `oarbank mod <module> <verb>`, and the module's own pages and panels (rendered by the host from the module's declarations).

## Operations

| Operation | Tier | API | CLI | Console |
|---|---|---|---|---|
| `fleet.pause` | T0 | yes | `oarbank pause --all` | yes |
| `fleet.halt` | T1 | yes | `oarbank halt --all` | yes |
| `fleet.resume` | T1 | yes | `oarbank resume --all` | yes |
| `nodes.admit` | T2 | yes | `oarbank node approve <eid>` | yes |
| `nodes.join_code` | T2 | yes | `oarbank join-code [--label NAME] [--uses N] [--ttl S]` | yes |
| `nodes.revoke_join_code` | T1 | yes | `oarbank join-code revoke <id>` | yes |
| `nodes.admit_code` | T2 | yes | `oarbank node approve-code <CODE>` | yes |
| `nodes.reject_enrollment` | T1 | yes | `oarbank node reject <eid>` | yes |
| `nodes.pause` | T0 | yes | `oarbank node state <nid> paused` | yes |
| `nodes.resume` | T0 | yes | `oarbank node state <nid> active` | yes |
| `nodes.drain` | T1 | yes | `oarbank node state <nid> draining` | yes |
| `nodes.quarantine` | T1 | yes | `oarbank op nodes.quarantine` | yes |
| `nodes.clear_quarantine` | T1 | yes | `oarbank op nodes.clear_quarantine` | yes |
| `nodes.run_doctor` | T0 | yes | `oarbank op nodes.run_doctor` | yes |
| `nodes.recertify` | T0 | yes | `oarbank op nodes.recertify` | yes |
| `nodes.retire` | T3 | yes | `oarbank op nodes.retire` | yes |
| `nodes.set_mode` | T1 | yes | `oarbank node mode <nid> <mode>` | yes |
| `jobs.retry` | T0 | yes | `oarbank job retry <jid>` | yes |
| `jobs.cancel` | T1 | yes | `oarbank job cancel <jid>` | yes |
| `jobs.set_priority` | T0 | yes | `oarbank op jobs.set_priority` | yes |
| `campaigns.pause` | T0 | yes | `oarbank campaign pause <id>` | yes |
| `campaigns.resume` | T0 | yes | `oarbank campaign resume <id>` | yes |
| `campaigns.cancel` | T3 | yes | `oarbank campaign cancel <id>` | yes |
| `campaigns.retry_failed` | T1 | yes | `oarbank campaign retry-failed <id>` | yes |
| `campaigns.set_weight` | T0 | yes | `oarbank campaign weight <id> <w>` | yes |
| `campaigns.set_priority` | T0 | yes | `oarbank campaign priority <id> <p>` | yes |
| `campaigns.set_placement` | T2 | yes | `oarbank campaign placement <id> --mix <mix>` | yes |
| `campaigns.rebind_platform` | T2 | yes | `oarbank campaign rebind <id> --platform <token>` | yes |
| `datasets.register` | T1 | yes | `oarbank dataset upload <dir> --kind <kind>`<br>`oarbank dataset register <file.json>` | yes |
| `settings.origins.update` | T2 | yes | `oarbank op settings.origins.update -p hosts=...` | yes |
| `modules.install` | T2 | yes | `oarbank module install <bundle.mfb>` | yes |
| `modules.uninstall` | T2 | yes | `oarbank module uninstall <name>@<version>` | yes |
| `modules.verify` | T0 | yes | `oarbank module verify [name]` | yes |
| `modules.check` | T0 | yes | `oarbank module check [name] [--deep]` | yes |
| `modules.enable` | T1 | yes | `oarbank module enable <name>@<version>` | yes |
| `modules.approve` | T2 | yes | `oarbank module approve <name>@<version>` | yes |
| `modules.enable_canary` | T2 | yes | `oarbank module canary <name>@<version> --node <node>`<br>`oarbank module canary <name>@<version> --group <group>` | yes |
| `modules.promote` | T2 | yes | `oarbank module promote <name>[@<canary version>]` | yes |
| `modules.rollback` | T1 | yes | `oarbank module rollback <name>` | yes |
| `modules.disable` | T1 | yes | `oarbank module disable <name>` | yes |
| `modules.pin` | T1 | yes | `oarbank module pin|unpin <name>@<version> --node <node>` | yes |
| `modules.restart_host` | T0 | yes | `oarbank op modules.restart_host` | yes |
| `releases.build` | T1 | yes | `oarbank release build` | yes |
| `releases.attach_signature` | T1 | yes | `oarbank release sign` | yes |
| `coordinator.prepare` | T3 | yes | `oarbank coordinator prepare --to <node|http://host:port>` | yes |
| `coordinator.move` | T3 | yes | `oarbank coordinator move [--timelock 24h] [--reason ...]` | yes |
| `coordinator.cancel` | T1 | yes | `oarbank coordinator cancel` | yes |
| `coordinator.finalize` | T2 | yes | `oarbank coordinator finalize` | yes |
| `coordinator.sign_move` | T2 | yes | `oarbank coordinator sign --owner-key <key>` | yes |
| `owner.set_anchors` | T3 | yes | `oarbank owner set --key <primary> --backup-key <backup> [--rescue URL]` | yes |
| `owner.disable_signing` | T3 | yes | `oarbank owner disable --key <owner key>` | yes |
| `nodes.confirm_identity` | T1 | yes | `oarbank node confirm-identity <node>` | yes |
| `agent.upload` | T2 | yes | `oarbank agent upload <oarbank-agent>` | yes |
| `vendor.metadata.upload` | T1 | yes | `oarbank vendor-metadata upload <dir>` | yes |
| `agent.canary` | T2 | yes | `oarbank agent canary <build> --node <node>` | yes |
| `agent.promote` | T2 | yes | `oarbank agent promote [--platform <os-arch>]` | yes |
| `agent.rollback` | T1 | yes | `oarbank agent rollback [--platform <os-arch>]` | yes |
| `agent.sign` | T1 | yes | `oarbank agent sign <build>` | yes |
| `updates.import` | T1 | yes | `oarbank update import <dir>` | yes |
| `updates.fetch` | T1 | yes | `oarbank update fetch <version>` | yes |
| `updates.sign` | T1 | yes | `oarbank update sign <version>` | yes |
| `updates.start` | T2 | yes | `oarbank update start <version> [--fast]`<br>`oarbank update plan <version>`<br>`oarbank update coordinator <version>` | yes |
| `updates.pause` | T1 | yes | `oarbank update pause` | yes |
| `updates.resume` | T1 | yes | `oarbank update resume` | yes |
| `updates.halt` | T1 | yes | `oarbank update halt` | yes |
| `updates.rollback` | T2 | yes | `oarbank update rollback` | yes |
| `updates.skip` | T1 | yes | `oarbank update skip <node>` | yes |
| `updates.hold` | T1 | yes | `oarbank update hold <node> --reason <why> [--until <time>]` | yes |
| `updates.unhold` | T1 | yes | `oarbank update unhold <node>` | yes |
| `updates.pin` | T1 | yes | `oarbank update pin <node> <version> --reason <why> [--until <time>]` | yes |
| `updates.unpin` | T1 | yes | `oarbank update unpin <node>` | yes |
| `coordinator.builds.upload` | T2 | yes | `oarbank coordinator-build upload <archive>` | yes |
| `coordinator.builds.sign` | T1 | yes | `oarbank coordinator-build sign <build>` | yes |
| `releases.promote` | T2 | yes | `oarbank release promote <rid>` | yes |
| `releases.pin_key` | T3 | yes | `oarbank release keygen` | yes |
| `protection.rules.update` | T2 | yes | `oarbank protection set <node> <file>`<br>`oarbank protection set fleet <file>`<br>`oarbank protection set group:<group> <file>`<br>`oarbank protection preview <node> <file>` | yes |
| `protection.probe_now` | T0 | yes | `oarbank protection probe <nid>` | yes |
| `protection.ab.start` | T2 | yes | `oarbank protection ab start <node> --rule <id> [--work <w>] [--duty <d>] [--blocks <n>] [--window <s>] [--washout <s>] [--margin <m>] [--off paused|evicted] [--max-hours <h>]` | yes |
| `protection.ab.abort` | T0 | yes | `oarbank protection ab abort <run>` | yes |
| `protection.ab.sweep` | T2 | yes | `oarbank protection ab sweep <node> --rule <id> [--work <w>] [--levels <list>]` | yes |
| `alerts.ack` | T0 | yes | `oarbank alerts ack <id> [--useful|--noise]` | yes |
| `alerts.snooze` | T0 | yes | `oarbank alerts snooze <id> --minutes N` | yes |
| `alerts.resolve` | T0 | yes | `oarbank alerts resolve <id> [--useful|--noise]` | yes |
| `settings.apply` | T0 | yes | `oarbank settings set <key> <value> [--node <node>] [--group <group>]`<br>`oarbank settings reset <key> [--node <node>] [--group <group>]` | yes |
| `settings.import` | T2 | yes | `oarbank settings import <file> [--dry-run]` | yes |
| `settings.secrets.set` | T1 | yes | `oarbank settings set-secret <name>` | yes |
| `settings.secrets.clear` | T1 | yes | `oarbank settings clear-secret <name>` | yes |
| `settings.promote` | T1 | yes | `oarbank settings promote <key> --group <group> [--to <group>]` | yes |
| `groups.create` | T1 | yes | `oarbank groups create <name> [--os <os>] [--label <label>] [--member <node>]` | yes |
| `groups.update` | T2 | yes | `oarbank groups update <group>` | yes |
| `groups.rank` | T2 | yes | `oarbank groups rank <group> up|down|top|bottom` | yes |
| `groups.delete` | T2 | yes | `oarbank groups delete <group>` | yes |
| `sites.create` | T1 | yes | `oarbank sites create <name> [--node N ...] [--mbps M] [--transfers N] [--heavy-jobs N]`<br>`oarbank sites accept <suggestion> [--name <name>]` | yes |
| `sites.update` | T1 | yes | `oarbank sites update <site> [--name N] [--mbps M] [--transfers N] [--heavy-jobs N]` | yes |
| `sites.assign` | T1 | yes | `oarbank sites add <site> <node> [<node> ...]`<br>`oarbank sites accept <suggestion> --site <site>` | yes |
| `sites.unassign` | T1 | yes | `oarbank sites remove <node> [<node> ...]` | yes |
| `sites.delete` | T2 | yes | `oarbank sites delete <site>` | yes |
| `sites.dismiss` | T0 | yes | `oarbank sites dismiss <suggestion>` | yes |
| `nodes.label` | T1 | yes | `oarbank node label <node> <labels> [--remove]` | yes |
| `tools.define` | T2 | yes | `oarbank tools define <id> --search <os>=<pattern>` | yes |
| `tools.delete` | T2 | yes | `oarbank tools delete <id>` | yes |
| `tools.detect` | T0 | yes | `oarbank tools detect <node>` | yes |
| `settings.folders.update` | T2 | yes | `oarbank folders map <id> --access read|write --node <node>=<path>` | yes |
| `nodes.sign_statement` | T1 | yes | `oarbank node sign <node>` | yes |
| `listeners.configure` | T2 | yes | `oarbank listener set <node> <key>` | yes |
| `listeners.remove` | T1 | yes | `oarbank listener remove <node> <key>` | yes |
| `listeners.disable` | T0 | yes | `oarbank listener disable --node <node>`<br>`oarbank listener disable --all` | yes |
| `listeners.resume` | T1 | yes | `oarbank listener resume --node <node>`<br>`oarbank listener resume --all` | yes |
| `listeners.probe` | T0 | yes | `oarbank listener probe <node> <key>` | yes |
| `access.accounts.create` | T2 | yes | `oarbank account create <name>` | yes |
| `access.accounts.update` | T2 | yes | `oarbank op access.accounts.update` | yes |
| `access.accounts.reset_totp` | T2 | yes | `oarbank op access.accounts.reset_totp` | yes |
| `access.accounts.set_password` | T1 | yes | `oarbank op access.accounts.set_password` | yes |
| `access.tokens.create` | T2 | yes | `oarbank token create` | yes |
| `access.tokens.revoke` | T1 | yes | `oarbank op access.tokens.revoke` | yes |
| `access.login_link` | T1 | yes | `oarbank console login [--account <name>]` | yes |
| `workloads.assign` | T2 | yes | `oarbank workload assign <module>/<workload> --node N`<br>`oarbank workload assign <module>/<workload> --count C` | yes |
| `workloads.unassign` | T1 | yes | `oarbank workload unassign <module>/<workload> --node N` | yes |
| `workloads.restart` | T1 | yes | `oarbank workload restart <module>/<workload> --node N` | yes |
| `secrets.set` | T1 | yes | `oarbank secret set <module> <name> [--node N]`<br>`oarbank secret set <module> <name> [--group G]` | yes |
| `secrets.clear` | T1 | yes | `oarbank secret clear <module> <name> [--node N]`<br>`oarbank secret clear <module> <name> [--group G]` | yes |
| `modules.cli_token` | T1 | yes | `oarbank cli <module> [args...]` | yes |
| `access.passkeys.remove` | T1 | yes | `oarbank op access.passkeys.remove` | yes |
| `audit.verify` | T0 | yes | `oarbank audit verify` | yes |

## Explain

| Kind | API | CLI | Console |
|---|---|---|---|
| `job` | yes | yes | yes |
| `node` | yes | yes | yes |

## Reason codes with remedies

| Code | Remedies |
|---|---|
| `NO_ELIGIBLE_NODE` | `jobs.set_priority` |
| `QUEUED_BEHIND` | `jobs.set_priority` |
| `CAMPAIGN_PAUSED` | `campaigns.resume` |
| `CAMPAIGN_SETTING_HOLDS` | `settings.apply` |
| `OARBANK_PAUSED` | `fleet.resume` |
| `USER_CAP_BINDING` | `settings.apply` |
| `MODULE_NOT_READY` | `nodes.run_doctor` |
| `MODULE_NOT_CERTIFIED` | `nodes.recertify` |
| `MODULE_DISABLED` | `modules.enable_canary` |
| `STAGE_PLATFORM_UNSUPPORTED` | `jobs.cancel` |
| `PLATFORM_BOUND_ELSEWHERE` | `campaigns.rebind_platform` |
| `PLACEMENT_UNPINNED` | `campaigns.rebind_platform` |
| `STAGE_CAPABILITY_MISSING` | `nodes.run_doctor` |
| `GPU_API_MISSING` | `nodes.run_doctor` |
| `SECRETS_NOT_SET` | `secrets.set` |
| `SETTINGS_NOT_SET` | `settings.apply` |
| `DATASET_PLATFORM_MISMATCH` | `jobs.cancel` |
| `TOOL_NOT_FOUND` | `tools.detect`, `tools.define` |
| `TOOL_VERSION_UNMET` | `tools.detect` |
| `TOOL_REFUSED` | `tools.detect` |
| `FOLDER_UNAVAILABLE` | `settings.folders.update` |
| `AGENT_TOO_OLD` | `updates.start`, `agent.promote` |
| `RETRIES_EXHAUSTED` | `jobs.cancel` |
| `SITE_UPLINK_BUDGET` | `sites.update` |
| `NODE_PAUSED_BY_ADMIN` | `nodes.resume` |
| `NODE_DRAINING` | `nodes.resume` |
| `NODE_QUARANTINED` | `nodes.clear_quarantine` |
| `NO_RELEASE` | `modules.install`, `modules.enable` |
| `RELEASE_UNSIGNED` | `releases.attach_signature` |
| `LISTENER_UNAVAILABLE` | `listeners.configure` |
| `PORT_TAKEN` | `listeners.configure` |
| `NO_MAPPING_PROTOCOL` | `listeners.configure` |
| `MAPPED_UNREACHABLE` | `listeners.probe` |
| `WORKLOAD_UNASSIGNED` | `workloads.assign` |
| `WORKLOAD_SEAT_ELSEWHERE` | `workloads.unassign` |
| `WORKLOAD_WITHDRAWN` | `workloads.restart` |
| `WORKLOAD_SECRETS_NOT_SET` | `secrets.set` |
| `WORKLOAD_IDENTITY_SHARED` | `secrets.set` |
| `WORKLOAD_POLICY_OFF` | `settings.apply` |
| `WORKLOAD_NODE_NOT_ACTIVE` | `nodes.resume` |
| `GPU_NOT_CERTIFIED` | `protection.ab.sweep` |
| `AB_STARTED` | `protection.ab.abort` |
| `GOLDEN_MISMATCH` | `nodes.recertify` |
