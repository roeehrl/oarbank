# Settings

Oarbank's owner settings are one model: a **registry** declared in code, one **sparse store** of the values an owner
set, and one **resolver** that says, for every node and key, what is in effect and where it comes from. This note is
the model's reference; the code is `src/oarbank/coordinator/settings/` (registry.py, store.py, resolve.py, apply.py,
views.py, migrate.py, rustgen.py) and the agent's side `rust/crates/oarbank-protection/src/settings.rs` over the
generated `settings_table.rs`.

It replaces the stores whose scope was fixed by where a value happened to be written: per-node copies of a default
policy (`nodes.policy_json`), per-node caps (`nodes.limits_json`) and owner keys in a key/value table they shared with
machine state (`settings`). Oarbank is not in production, so the change has no shims: a home made by an earlier version
is converted once when the coordinator opens it ([Migration](#migration)), and the old stores and operations are gone.

## The registry

Each key is one `Setting` (registry.py):

| Field | Meaning |
|---|---|
| `label`, `help`, `unit` | What a person reads; the raw key is shown beside the label, never as it |
| `schema` | The value's type, a JSON Schema subset (number, integer, boolean, string with enum, format or pattern, list, object, the cap `schedule`); a type may include `null` |
| `default` / `computed` | A static default, or one computed from the node's facts with its reason (`os_reserve_gb`: 4 GB up to 32 GB of RAM, 8 GB from 96 GB, 6 GB between, "24 GB RAM") |
| `scopes` | Where it may be set: `fleet`, `group`, `node` |
| `merge` | How values from several scopes combine: `replace` (the most specific wins), `min` and `max` (every scope applies; caps take the lowest, enforcement the strictest), `union` (lists that only restrict) |
| `lockable` | Whether a fleet or group value may lock it |
| `advanced` | Shown under the section's Advanced disclosure |
| `danger` | The key's tier (T0 caps, T1 policy and fleet-wide keys, T2 for keys whose own operation writes them) |
| `applies` | `coordinator`, `agent` or `both` |
| `wire` | The agent directive section it travels in: `policy` or `limits` |
| `section` | The console section that shows it |
| `qualifier` | `required` for a module's own key, set per module (`pipeline`, `module.settings`, `module.node_settings`) |
| `writer` | The operation that owns writes to it (`settings.tools.update`, `settings.folders.update`, `settings.origins.update`, `modules.set_pipeline`): `settings.apply` refuses the key and names that operation, which checks it and applies its effects |
| `effects` | Hooks run on the nodes whose effective value changed (`redoctor`: `disabled_services` changes a node's role, so its modules are re-doctored and re-certified) |
| `hardware` | `cores` or `ram`: a node's own value may not exceed its hardware |

The keys, by section:

- **Memory**: `os_reserve_gb`, `user_reserve_gb`, `job_mem_gb`, `mem_in_use_bound`.
- **When someone is using it**: `user_present_slots`, `user_idle_s`, `screen_sharing_present`, `run_on_battery`.
- **Jobs**: `threads_per_job`, `max_slots`; advanced `nice` (not applied by agents yet), `hard_limits`,
  `disabled_services`.
- **Caps** (merge `min`; enforcement `max`, hard over soft): `cpu_cores`, `mem_gb`, `jobs`, `schedule`, `enforce`;
  advanced `vm_mem_gb`, `vm_cpus`, `disk_gb`, `staging_mbps`.
- **Notifications** (fleet only): `ntfy.url`, `ntfy.click_base`. The ntfy token is not a setting: it is a core secret
  in the encrypted secrets store (write-only, shown as a fingerprint; `settings.secrets.set` / `clear`).
- **Access** (fleet only): `console_hosts`, a typed list of host names (an optional `:port`).
- **Data and verification** (fleet only): `replica_rate`, 0 to 1.
- **Written by their own operations** (fleet only): `tool_registry` (paths per OS, never a trust: trust is the module
  request's, approved with it), `folder_registry`, `dataset_origins`, `pipeline` per module, `module.settings` (a
  module's own fleet settings, which its operations write through the `module_settings.update` effect).
- **Per module on a node**: `module.node_settings`, handed to the module's runners and services there
  (`OARBANK_SETTINGS_FILE`).

`GET /api/v1/settings/schema` returns the registry as data; `oarbank settings schema` prints it.

### The agent's table is generated

`uv run python -m oarbank.coordinator.settings.rustgen` writes `rust/crates/oarbank-protection/src/settings_table.rs`
from the registry: every `wire` key with its section, type, bounds and default, and the typed constants the capacity
engine's `Policy::default()` reads. `tests/test_settings.py` fails when the file is stale, so the coordinator and the
agent can never disagree on a key, a type or a default. There are no hand-written default values anywhere else: the
Python `DEFAULT_POLICY`, the Rust `Policy::default()` literals and the console's `or 300` fallbacks are gone.

## The store

```sql
setting_values (scope fleet|group|node|campaign, scope_id, module, key, value_json, enforced, rev, comment,
                updated_by, updated_at; PRIMARY KEY (scope, scope_id, module, key))
node_groups (id, name, rank UNIQUE, selector_json, builtin)
system_state (key, value_json)          -- machine state: fleet id, coordinator key, move phase, alive_at, ...
nodes: protection_json, settings_json, settings_digest, settings_rev, settings_applied_rev, settings_rejected_json
```

- **Absence means inherit.** A row exists only where an owner set a value. Reset deletes the row and never writes the
  default back, so a later fleet change still reaches the node and "overridden here" stays truthful. A value equal to
  today's default is still a choice, and stays.
- **Every save is one change set** with one revision (`system_state.settings_rev`), shared by its rows and written to
  the audit log (who, when, each row before and after, the reason).
- **Groups** are named selectors over node facts with a unique rank. The built-in groups have the lowest ranks and
  system-defined membership: `os-darwin` (macOS), `os-linux`, `os-windows` and `coordinator-host` (the coordinator's own
  machine, rank 4, above the OS groups). The coordinator-host group sets `disabled_services = []` by itself ("the
  coordinator's own machine runs every service"), replacing the old special case that gave that machine every
  service at enrolment. Membership is evaluated when values are resolved, so a node whose facts change moves at once.
  Owner groups (rank 100 and up), labels and their console come later; values can already be set on a built-in group
  (`oarbank settings set … --group macOS`).
- **System state** is not settings: it is written only by the code that owns it, never by an operation that takes a raw
  key. The raw `settings.update` operation is gone.

## Resolution

For one node, key and optional module (resolve.py):

1. The **default**: static, or computed from the node's facts with its reason.
2. The **fleet**'s value.
3. Each **group** the node belongs to, lowest rank first (a built-in group's own value counts as set there).
4. The **node**'s own value.

A **lock** (an enforced fleet or group value) is found first: the fleet's before any group's, a higher rank before a
lower. It wins outright and the values below it are ignored. Otherwise the merge rule decides: `replace` takes the most
specific value set; `min` and `max` fold every value set (caps: a lower scope can only tighten; the default does not
take part, so the fleet may set `replica_rate` below its default); `union` joins lists. With nothing set, the default applies.
The result names the source (scope, group or node, revision, who and when, the comment), every layer with its role
(in effect, overridden below, ignored under a lock, also applies under a fold), the lock and the default with its
reason. `badge()` says the source as the console shows it: `Default · 24 GB RAM`, `Fleet`, `Group: macOS`,
`Group: Coordinator host · the coordinator's own machine runs every service`, `This node`.

**Merged values are checked per node** (`cross_checks`): the system reserve must leave memory for jobs, the two reserves
together too, a job slot must fit in RAM, and a node's own cap may not exceed its hardware (a fleet or group cap above a
node's hardware simply does not bind there). A change set is refused only for errors it introduces, so an existing
invalid state never blocks an unrelated save.

## Saving: `settings.apply`

```json
{"changes": [{"scope": "fleet|group|node", "scope_id": "<group or node: id or name>", "module": "", "key": "job_mem_gb",
              "value": 2}, {"scope": "node", "scope_id": "mini", "key": "jobs", "reset": true}],
 "comment": "…"}
```

- Each change is checked against the registry: the key exists, may be set at that scope, is not owned by another
  operation, its value has the right type and range (normalized: an integral float of an integer key becomes an int,
  host names lower-case), no lock holds above it. Then the merged values of every node it reaches are checked. Every
  problem comes back at once: `400 invalid_settings` with `errors: [{key, scope, scope_id, code, message}]`.
- **The dry run is the same call** and returns the impact per node: which nodes' effective value changes (old and new,
  and the source after the change), which keep theirs and why (they override it, a lock holds), and a summary:
  "Changes the effective value on 2 nodes (a, b); 1 node keeps theirs (c)".
- **The tier follows the keys and scopes it changes**: a node change keeps the key's tier (a cap T0, policy T1), a fleet
  or group change is one tier up, a lock is T3 (typed confirmation). The registry declares `settings.apply` as T0 with
  that escalation; `ops.tier_of` computes a request's own tier and the plan carries it, so preview, reason and
  confirmation follow it.
- Committing writes the rows under one revision, runs the effect hooks on the nodes whose effective value changed,
  refreshes those nodes' effective settings, and returns "Saved · rev 42 · 3 of 4 nodes get it at their next heartbeat,
  1 pending (offline)".

`settings.apply` replaced `nodes.set_policy`, `nodes.set_caps`, `settings.notifications.update` (its URL fields; the
token became `settings.secrets.set`) and the raw `settings.update`. The tool, folder and origin operations
(`settings.tools.update`, `settings.folders.update`, `settings.origins.update`) and `modules.set_pipeline` keep their
own operations until the host-tools and module-settings phases, because each validates against more than a type (paths
per OS, per node, a module's stage chain) and has its own side effects (release rebuilds, signed folder statements,
splitting queued jobs); they now store their values as fleet rows through `store.write_fleet`.

## What the agent gets

The coordinator resolves everything and keeps each node's complete effective settings in `nodes.settings_json`:
`{"policy": {every policy key, "module_settings": {module: …}, "protection": {…}}, "limits": {every cap, null when
unset}}`, with the revision at which the document last changed (`settings_rev`; a change set's revision, or a new one
when the node's facts or group membership moved it). Every hello and heartbeat reply carries `policy`, `limits` and
`settings_rev`. Hot paths (claim, placement, golden node classes) read this document instead of resolving.

The agent checks each key against its generated table (`settings::validate`): a value of the right type and range is
applied; a wrong type, a value out of range, a missing key or a key this agent does not know is refused, keeps the value
it had (before the first heartbeat: the table's default) and is reported. Nothing falls back silently. The heartbeat
carries `"settings": {"applied_rev": N, "rejected": [{"key", "reason"}]}`; the coordinator stores it
(`settings_applied_rev`, `settings_rejected_json`) and records a `settings_rejected` event when the refusals change.
Each row then shows its applied state: "Applied on the node · rev 41", "Pending: the node applies rev 42 at its next
heartbeat", "Pending: node offline", "Refused by the node: …", or, for an agent from before this protocol,
"Pending: this agent does not report what it applied (update it)". Services still get only the caps that are set in
`OARBANK_LIMITS_FILE`, as before.

## The console

- **The node's Settings tab** (`/nodes/<node>/settings`): one explicit-save section per area (Memory, When someone is
  using it, Jobs, Caps), each a `fieldset` with a `legend`. Every row renders through one macro,
  `setting_row(row)` in `templates/_settings.html`: the label and unit, one line of help, the raw key in small monospace
  with a Copy button, the source badge, **Override** (a box that reveals the field, prefilled with the inherited value;
  CSS only) or, for a value set here, the field with **Reset to inherited**, a left bar plus the "changed here" text (never
  colour alone), the node's merged-value errors, the applied state, "Configure fleet default", and an **Explain**
  disclosure with the whole chain (each scope, its value or "not set", its role, revision, who, when, comment).
  `?explain=<key>` opens that row's Explain; the why line's citations link there. Help, source and error text are tied
  to the field with `aria-describedby`.
- **Fleet Settings** (`/settings`): **Node defaults** (the same sections at fleet scope, each row with "Overridden on N
  nodes" linking to the reverse view `/settings/overrides?key=…`), Notifications (the two URLs and the write-only token),
  Access (`console_hosts`), Data and verification (`replica_rate`), then the tool registry (each tool's form prefilled
  with its current paths on every OS, so changing one OS never drops another), folders, dataset origins, releases.
- **Apply-then-Save**: a fleet or group change always opens the preview first (`plan.html`): the summary, the per-node
  old/new table, the nodes that keep their value and why, and a button that says what it does ("Save for 4 nodes"). A
  node change saves at once (T1 keys confirm in the browser).
- **A refused save** comes back to its page with a GOV.UK-style error summary at the top of the section (it takes focus
  and links to each field), each message beside its field (`aria-invalid`), and what was typed kept. Forms are
  `novalidate`, so the Save button stays usable and the server's messages are the ones shown.
- **The why line** on the node page cites the settings it rests on with their value and source ("Run jobs on battery:
  off · Default"), each linked to its Explain row.

## The CLI

```text
oarbank settings get [<key>] [--node N] [--module M] [--json]     effective values with their source, or one key's chain
oarbank settings explain <key> [--node N]                         the whole chain
oarbank settings set <key> <value> [--node N | --group G] [--module M] [--enforce] [--dry-run]
oarbank settings reset <key> [--node N | --group G] [--module M]
oarbank settings overrides <key>                                  who overrides the fleet value, with what
oarbank settings schema                                           the registry
oarbank settings set-secret ntfy_token / clear-secret ntfy_token  the write-only ntfy token
```

`set` and `reset` always preview (the per-node impact), then apply; without a scope they act on the fleet.
`oarbank node policy` and `oarbank node limits` are removed; `oarbank node show` lists what the node sets itself, with
the command that resets each.

## Migration

`migrate.run`, when the coordinator opens a home made before the settings model, in one transaction:

- The `settings` table splits: owner keys become fleet rows (`ntfy` → `ntfy.url`, `ntfy.click_base`, its token into
  the secrets store; `console_hosts` (a string becomes a one-entry list), `replica_rate`, `default_worker_disabled_services`
  → the fleet's `disabled_services`, `tool_registry` without its `trust`, `folder_registry`, `dataset_origins` (its
  host list), `pipeline:<m>`, `module_settings:<m>` → that module's `module.settings`); `dataset_groups` is dropped (no
  owner control, no reader); every other key is machine state and moves to `system_state`. The table is dropped.
- For each node, a policy value becomes a node row only where it differs from what the node now inherits (its computed
  default, the fleet's and its groups' values), so copies disappear and choices stay; caps become node rows (`enforce`
  only when hard, beside a cap); each module's node settings become `module.node_settings` rows; the protection section
  moves to `nodes.protection_json` (its history stays in `protection_versions`). Then `policy_json` and `limits_json`
  are dropped.
- Values the registry refuses are dropped and named, with the counts, in the `settings_migrated` event.

On the owner's fleet (six nodes whose policies differed only in the RAM-computed `os_reserve_gb`, no caps, no owner keys)
this yields no node rows at all: the old model stored copies, not choices.

## Later phases

- **Host tools**: tool definitions, node-side detection reported in `tools_json`, per-node overrides in a signed node
  statement, module version constraints, per-node tool reason codes.
- **Module settings**: manifest key annotations validated on write, a module Settings tab, module-qualified core keys
  (`enabled`, `services.disabled`, `replica_rate`, `pipeline`); both old module-settings stores (`module.settings`,
  `module.node_settings`) replaced by per-key values.
- **Groups and locks in the console**: owner groups with rank and selectors, labels, bulk set and reset, canary to a
  group, secrets on the same chain, protection on the chain (mode replace and lockable, rules union).
- **Campaigns, settings as code, drift**: campaign-overridable keys (tighten-only for safety keys), per-scope YAML
  export and import, shadowed-override and applied-drift reports.
