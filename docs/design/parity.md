# Parity report (generated)

Generated from the registries and the sources by `python -m oarbank.contracts.docs`. Every operation must be reachable from the API (`POST /api/v1/ops/<id>` or its own route), the CLI (its own `oarbank` command, or `oarbank op <id>`) and the console (a form for it in a template); every explain kind from all three; every reason code's remedies must be operations.

**0 gaps.** 87 operations, 2 explain kinds, 122 reason codes. Module operations (`mod.<module>.<verb>`) are generic: the API endpoint, `oarbank mod <module> <verb>`, and the module's own pages and panels (rendered by the host from the module's declarations).

## Operations

| Operation | Tier | API | CLI | Console |
|---|---|---|---|---|
| `fleet.pause` | T0 | yes | `oarbank op fleet.pause` | yes |
| `fleet.halt` | T1 | yes | `oarbank op fleet.halt` | yes |
| `fleet.resume` | T1 | yes | `oarbank op fleet.resume` | yes |
| `nodes.admit` | T2 | yes | `oarbank node approve <eid>` | yes |
| `nodes.join_code` | T2 | yes | `oarbank join-code [--label NAME]` | yes |
| `nodes.reject_enrollment` | T1 | yes | `oarbank node reject <eid>` | yes |
| `nodes.pause` | T0 | yes | `oarbank node state <nid> paused` | yes |
| `nodes.resume` | T0 | yes | `oarbank node state <nid> active` | yes |
| `nodes.drain` | T1 | yes | `oarbank node state <nid> draining` | yes |
| `nodes.set_caps` | T0 | yes | `oarbank node limits <nid> ...`<br>`oarbank node limits <nid> --clear-all` | yes |
| `nodes.set_policy` | T1 | yes | `oarbank node policy <nid> ...` | yes |
| `nodes.quarantine` | T1 | yes | `oarbank op nodes.quarantine` | yes |
| `nodes.clear_quarantine` | T1 | yes | `oarbank op nodes.clear_quarantine` | yes |
| `nodes.run_doctor` | T0 | yes | `oarbank op nodes.run_doctor` | yes |
| `nodes.recertify` | T0 | yes | `oarbank op nodes.recertify` | yes |
| `nodes.retire` | T3 | yes | `oarbank op nodes.retire` | yes |
| `nodes.set_mode` | T1 | yes | `oarbank node mode <nid> <mode>` | yes |
| `jobs.retry` | T0 | yes | `oarbank op jobs.retry` | yes |
| `jobs.cancel` | T1 | yes | `oarbank op jobs.cancel` | yes |
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
| `modules.set_pipeline` | T2 | yes | `oarbank pipeline <module> single|split` | yes |
| `modules.install` | T2 | yes | `oarbank module install <bundle.mfb>` | yes |
| `modules.uninstall` | T2 | yes | `oarbank module uninstall <name>@<version>` | yes |
| `modules.verify` | T0 | yes | `oarbank module verify [name]` | yes |
| `modules.check` | T0 | yes | `oarbank module check [name] [--deep]` | yes |
| `modules.enable` | T1 | yes | `oarbank module enable <name>@<version>` | yes |
| `modules.approve` | T2 | yes | `oarbank module approve <name>@<version>` | yes |
| `modules.enable_canary` | T2 | yes | `oarbank module canary <name>@<version> --node <node>` | yes |
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
| `coordinator.builds.upload` | T2 | yes | `oarbank coordinator-build upload <archive>` | yes |
| `coordinator.builds.sign` | T1 | yes | `oarbank coordinator-build sign <build>` | yes |
| `releases.promote` | T2 | yes | `oarbank release promote <rid>` | yes |
| `releases.pin_key` | T3 | yes | `oarbank release keygen` | yes |
| `protection.rules.update` | T2 | yes | `oarbank protection set <nid> <file>` | yes |
| `protection.rules.restore` | T2 | yes | `oarbank protection restore <nid> <version>` | yes |
| `protection.rules.canary` | T2 | yes | `oarbank protection canary <nid> <file>`<br>`oarbank protection promote` | yes |
| `protection.probe_now` | T0 | yes | `oarbank protection probe <nid>` | yes |
| `alerts.ack` | T0 | yes | `oarbank alerts ack <id> [--useful|--noise]` | yes |
| `alerts.snooze` | T0 | yes | `oarbank alerts snooze <id> --minutes N` | yes |
| `alerts.resolve` | T0 | yes | `oarbank alerts resolve <id> [--useful|--noise]` | yes |
| `settings.notifications.update` | T2 | yes | `oarbank op settings.notifications.update` | yes |
| `settings.tools.update` | T2 | yes | `oarbank op settings.tools.update` | yes |
| `settings.folders.update` | T2 | yes | `oarbank folders map <id> --access read|write --node <node>=<path>` | yes |
| `folders.sign` | T1 | yes | `oarbank folders sign <node>` | yes |
| `access.accounts.create` | T2 | yes | `oarbank account create <name>` | yes |
| `access.accounts.update` | T2 | yes | `oarbank op access.accounts.update` | yes |
| `access.accounts.reset_totp` | T2 | yes | `oarbank op access.accounts.reset_totp` | yes |
| `access.accounts.set_password` | T1 | yes | `oarbank op access.accounts.set_password` | yes |
| `access.tokens.create` | T2 | yes | `oarbank token create` | yes |
| `access.tokens.revoke` | T1 | yes | `oarbank op access.tokens.revoke` | yes |
| `access.login_link` | T1 | yes | `oarbank console login [--account <name>]` | yes |
| `secrets.set` | T1 | yes | `oarbank secret set <module> <name> [--node N]` | yes |
| `secrets.clear` | T1 | yes | `oarbank secret clear <module> <name> [--node N]` | yes |
| `modules.cli_token` | T1 | yes | `oarbank cli <module> [args...]` | yes |
| `access.passkeys.remove` | T1 | yes | `oarbank op access.passkeys.remove` | yes |
| `settings.update` | T2 | yes | `oarbank op settings.update <key>`<br>`module CLIs (golden:<module>, dataset_groups)` | yes |
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
| `OARBANK_PAUSED` | `fleet.resume` |
| `USER_CAP_BINDING` | `nodes.set_caps` |
| `MODULE_NOT_READY` | `nodes.run_doctor` |
| `MODULE_NOT_CERTIFIED` | `nodes.recertify` |
| `MODULE_DISABLED` | `modules.enable_canary` |
| `STAGE_PLATFORM_UNSUPPORTED` | `jobs.cancel` |
| `PLATFORM_BOUND_ELSEWHERE` | `campaigns.rebind_platform` |
| `PLACEMENT_UNPINNED` | `campaigns.rebind_platform` |
| `STAGE_CAPABILITY_MISSING` | `nodes.run_doctor` |
| `GPU_API_MISSING` | `nodes.run_doctor` |
| `SECRETS_NOT_SET` | `secrets.set` |
| `DATASET_PLATFORM_MISMATCH` | `jobs.cancel` |
| `TOOL_UNAVAILABLE` | `settings.tools.update` |
| `FOLDER_UNAVAILABLE` | `settings.folders.update` |
| `AGENT_TOO_OLD` | `agent.promote` |
| `RETRIES_EXHAUSTED` | `jobs.cancel` |
| `NODE_PAUSED_BY_ADMIN` | `nodes.resume` |
| `NODE_DRAINING` | `nodes.resume` |
| `NODE_QUARANTINED` | `nodes.clear_quarantine` |
| `GOLDEN_MISMATCH` | `nodes.recertify` |
