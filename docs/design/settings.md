# Settings

Oarbank's owner settings are one model: a **registry** declared in code, one **sparse store** of the values an owner
set, and one **resolver** that says, for every node and key, what is in effect and where it comes from. This note is
the model's reference; the code is `src/oarbank/coordinator/settings/` (registry.py, store.py, resolve.py, apply.py,
views.py, migrate.py, rustgen.py, and for modules modkeys.py and modcore.py) and the agent's side `rust/crates/oarbank-protection/src/settings.rs` over the
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
| `qualifier` | `required`: set per module only (the core keys every module has, `enabled`, `services.disabled`, `pipeline`, and each module's own keys); `optional`: a core key a module may qualify (`replica_rate`, `tool.<id>.path`) |
| `writer` | The operation that owns writes to it (`settings.folders.update`, `settings.origins.update`): `settings.apply` refuses the key and names that operation, which checks it and applies its effects |
| `required` | A module's own key the owner must set before its work runs ([Module settings](#module-settings)) |
| `validator` | A module's own key: its property's whole JSON Schema checks the value (the core keys use the `schema` subset) |
| `effects` | Hooks run on the nodes whose effective value changed (`redoctor`: a module's `services.disabled` changes its role on a node, so that module is re-doctored and re-certified there; `module_enabled`: a module turned off releases its live attempts there; `pipeline`: split splits its queued jobs) |
| `hardware` | `cores` or `ram`: a node's own value may not exceed its hardware |

The keys, by section:

- **Memory**: `os_reserve_gb`, `user_reserve_gb`, `job_mem_gb`, `mem_in_use_bound`.
- **When someone is using it**: `user_present_slots`, `user_idle_s`, `screen_sharing_present`, `run_on_battery`.
- **Jobs**: `threads_per_job`, `max_slots`; advanced `nice` (not applied by agents yet), `hard_limits`.
- **Caps** (merge `min`; enforcement `max`, hard over soft): `cpu_cores`, `mem_gb`, `jobs`, `schedule`, `enforce`;
  advanced `vm_mem_gb`, `vm_cpus`, `disk_gb`, `staging_mbps`.
- **Notifications** (fleet only): `ntfy.url`, `ntfy.click_base`. The ntfy token is not a setting: it is a core secret
  in the encrypted secrets store (write-only, shown as a fingerprint; `settings.secrets.set` / `clear`).
- **Access** (fleet only): `console_hosts`, a typed list of host names (an optional `:port`).
- **Data and verification** (fleet only): `replica_rate`, 0 to 1, which a module may raise for its own work.
- **Written by their own operations** (fleet only): `folder_registry`, `dataset_origins`.
- **Every module's core keys** (`[module] <key>`): `enabled`, `services.disabled`, `pipeline`, and `replica_rate`
  qualified ([Module settings](#module-settings)).
- **Each module's own keys** (`module.<module>.<key>`), from its manifest's settings schema.
- **Host tools** (a key family): `tool.<id>.path` at fleet, group or node scope, optionally qualified by a module, the
  installation of a host tool a node grants ([host-tools.md](host-tools.md)). Its value is an absolute path (no globs,
  roots or `..`); its effect hook rebuilds the node statements, which carry the node values naming a path the node did
  not find itself. A key that names a module resolves the module's chain above the plain one: a value set for the
  module beats a plain value at any scope (the registry's `qualifier = "optional"`).
- **Protection** ([Protection on the chain](#protection-on-the-chain)): `protection.mode` (lockable), `protection.rules`
  (merge `union`), `protection.node` (advanced).

`GET /api/v1/settings/schema` returns the registry as data, every installed module's own keys included;
`oarbank settings schema` prints it.

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
node_groups (id, name, rank UNIQUE, selector_json, builtin, members_json, description, updated_by, updated_at)
node_labels (node_id, label, set_by, set_at)
system_state (key, value_json)          -- machine state: fleet id, coordinator key, move phase, alive_at, ...
nodes: settings_json, settings_digest, settings_rev, settings_applied_rev, settings_rejected_json
```

- **Absence means inherit.** A row exists only where an owner set a value. Reset deletes the row and never writes the
  default back, so a later fleet change still reaches the node and "overridden here" stays truthful. A value equal to
  today's default is still a choice, and stays.
- **Every save is one change set** with one revision (`system_state.settings_rev`), shared by its rows and written to
  the audit log (who, when, each row before and after, the reason).
- **Groups** are named selectors over node facts with a unique rank. The built-in groups have the lowest ranks and
  system-defined membership: `os-darwin` (macOS), `os-linux`, `os-windows` and `coordinator-host` (the coordinator's own
  machine, rank 4, above the OS groups). The coordinator-host group sets `services.disabled = []` by itself, for every
  module ("the coordinator's own machine runs every service"), replacing the old special case that gave that machine
  every service at enrolment. Membership is evaluated when values are resolved, so a node whose facts change moves at once.
  Owner groups rank 100 and up ([Groups and labels](#groups-and-labels)).
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
token became `settings.secrets.set`), the raw `settings.update` and `modules.set_pipeline` (`[module] pipeline`, whose
check needs a stage chain and whose effect splits queued jobs); host tools replaced `settings.tools.update` with tool
definitions (`tools.define`, `tools.delete`) and the `tool.<id>.path` keys. The folder and origin operations
(`settings.folders.update`, `settings.origins.update`) keep their own operations, because each validates against more
than a type (paths per OS, per node) and has its own side effects (release rebuilds, signed folder statements); they
store their values as fleet rows through `store.write_fleet`.

## What the agent gets

The coordinator resolves everything and keeps each node's complete effective settings in `nodes.settings_json`:
`{"policy": {every policy key, "disabled_services": ["<module>/<service>", …], "module_settings": {module: {key: value}},
"protection": {…}}, "limits": {every cap, null when unset}, "modules_disabled": […], "settings_unset": {module: […]}}`,
with the revision at which the document last changed (`settings_rev`; a change set's revision, or a new one
when the node's facts or group membership moved it). Every hello and heartbeat reply carries `policy`, `limits`,
`settings_rev` and `modules_disabled` (the modules whose `enabled` is off for that node: their services stop there). Hot paths (claim, placement, golden node classes) read this document instead of resolving.

The agent checks each key against its generated table (`settings::validate`): a value of the right type and range is
applied; a wrong type, a value out of range, a missing key or a key this agent does not know is refused, keeps the value
it had (before the first heartbeat: the table's default) and is reported. Nothing falls back silently. The heartbeat
carries `"settings": {"applied_rev": N, "rejected": [{"key", "reason"}]}`; the coordinator stores it
(`settings_applied_rev`, `settings_rejected_json`) and records a `settings_rejected` event when the refusals change.
Each row then shows its applied state: "Applied on the node · rev 41", "Pending: the node applies rev 42 at its next
heartbeat", "Pending: node offline", "Refused by the node: …", or, for an agent from before this protocol,
"Pending: this agent does not report what it applied (update it)". Services still get only the caps that are set in
`OARBANK_LIMITS_FILE`, as before.

## Module settings

A module's settings are settings like any other: values in `setting_values`, one row per key and scope with `module`
naming the module, resolved by the same chain, written by `settings.apply` with its dry run and per-node preview. Two
kinds of keys exist per module.

**Its own keys** come from its manifest. The `[settings].schema` file is a JSON Schema whose properties are the
module's settings (oarbank-sdk `spec/manifest.md`, "Settings"):

```json
{"type": "object", "properties": {
  "vm_mem_gb": {"type": "number", "minimum": 2, "maximum": 64, "default": 8, "title": "VM memory",
                "description": "Memory the module's VM gets on a node.", "x-oarbank": {"scope": "node", "unit": "GB"}},
  "pool_tao": {"type": "number", "minimum": 0, "title": "Miner pool per round",
               "x-oarbank": {"scope": "fleet", "unit": "TAO", "required": true}}}}
```

- **Registration** (modkeys.py). When a version is installed, enabled, promoted, rolled back or uninstalled, the
  coordinator reads the schema of the module's registered version (its current version, else its newest installed one)
  and keeps its keys in `module_setting_keys`. Each becomes a registry definition `module.<module>.<key>`: label from
  `title`, help from `description`, the unit, `advanced`, `required`, scopes (`fleet` only, or fleet, group and node for
  `scope = node`), merge `replace`, lockable, tier T1, and a validator that checks a value against the property's whole
  JSON Schema. `oarbank-sdk check`, `bundle build` and `bundle verify` refuse a schema the core would not read, so an
  installed bundle always registers.
- **A new version's keys.** A key the new version no longer declares keeps its values, inert (nothing resolves or
  delivers them), listed on the module's Settings tab with a Delete, until a later version (or a rollback) declares it
  again. A value the new version's schema refuses (its type or range changed, or the key became fleet-only and the value
  was set below the fleet) is deleted. The `module_settings_registered` event names what was added, removed, changed
  and dropped, with the dropped values.
- **Writes.** `settings.apply` takes the full key (`module.relay.vm_mem_gb`) or the short one with the module
  (`{"key": "vm_mem_gb", "module": "relay"}`; a name that is also a core key a module qualifies, such as `enabled`, is
  the core key). The value must validate, the key must be declared by that module, and a fleet key may be set only for
  the fleet. A module's own operations change its settings with the `module_settings.update` effect: one change set at
  fleet scope through the same checks (`null` resets a key); one undeclared key or invalid value refuses the whole
  effect (`bad_settings`).
- **What each process gets.** A node's runners, doctor and services of a module get `policy.module_settings[<module>]`
  in `OARBANK_SETTINGS_FILE`: that module's `node` keys resolved for the node (the value set for the fleet, a group or
  the node, else the key's default; a key with neither is absent), and no other module's. The agent writes each module's
  file only when its content changes, so a change to one module's settings never touches another module's file. The
  module's coordinator side (`host.settings.get`, the `module_settings` UI query, op and campaign contexts) gets every key
  at fleet scope the same way (effects.module_settings).
- **Required keys.** A key marked `required` has no default. Until it has a value for a node (a fleet value covers
  every node), the module's work there waits with `SETTINGS_NOT_SET` (claim and explain share the predicate; bootstrap
  jobs, which get no settings, are exempt), and the readiness checklist's step **Required settings** is blocked while
  a fleet key, or a node key on every node, has none; nodes still missing one are listed by what they miss.

**The core keys every module has** (`[module] <key>`, registry `qualifier = "required"` unless noted; modcore.py):

| Key | Scopes | What it does |
|---|---|---|
| `enabled` | fleet (lockable), group, node; default on | Off for the fleet is the kill switch (`modules.disable` writes it, `modules.enable` resets it): no dispatch, live attempts released (`module_disabled`), services stopped on every node. Off for a group or node does the same on those nodes only; each node's heartbeat lists the modules it must not run (`modules_disabled`) |
| `services.disabled` | fleet, group, node; default `[]` | The module's services a node does not run (service names). The coordinator turns each node's per-module values into the agent's `disabled_services` list (`<module>/<service>`). A change re-doctors and re-certifies that module, and only that module, on the nodes whose value changed. The built-in coordinator-host group sets `[]` for every module |
| `pipeline` | fleet | `single` or `split`; split needs a module whose stages form a chain, and switching to it splits the module's queued jobs (`pipeline_changed`). Replaces `modules.set_pipeline` |
| `replica_rate` | fleet (`qualifier = "optional"`) | A module's own rate; merge `max`, so it can only raise the fleet's for that module's work |

**The console.** The module page's **Settings** tab (`/modules/<module>/settings`) shows the readiness checklist on
top, then two explicit-save sections at fleet scope, Running it (the core keys; `pipeline` only for a module with a
stage chain) and Its settings (its own keys, Advanced ones under the disclosure), through the same `setting_row` macro:
source badge, Override and Reset to inherited, "Overridden on N nodes" linking to `/settings/overrides?key=…&module=…`,
Explain, a "required: not set" chip with the row's error text. A change opens the per-node preview first. Below them,
**Set for groups and nodes** lists every value of the module's keys set below the fleet with a Reset each, and **Values
<module> no longer declares** lists the inert ones. The node's Settings tab ends with **Modules on this node**: one
section per installed module at node scope (`enabled`, `services.disabled`, its node keys), each a form of its own,
whose "Configure the fleet value" links to the module's tab; a group's page has the same sections at group scope
(**Modules on its members**), each with its lock toggle.

**Groups and locks hold for module keys as for any other.** A group value of `[m] enabled`, `[m] services.disabled` or
a module's node key `module.<m>.<key>` reaches the group's members; a fleet or group lock on one of them holds against
a node's (or a lower-ranked group's) value, which is refused while it holds ("locked by the group Laptops"), and a
membership change re-runs the module's effects (its attempts released where it turned off, that module re-certified
where its services changed).

**The API and CLI.** `GET /api/v1/settings/schema` lists the modules and their keys; `effective?module=M` (with or
without `node`) returns that module's keys with their provenance; `explain?key=vm_mem_gb&module=relay&node=N` and
`overrides?key=…&module=…` take the short or the full key. `oarbank settings get --module relay [--node N]`,
`oarbank settings set vm_mem_gb 12 --module relay --node mini` (the value typed from the module's schema),
`oarbank settings set enabled false --module relay --group macOS`, `oarbank settings set pipeline split --module relay`.

## Groups and labels

An owner group (`settings/groups.py`) is a name, a **selector** over node facts and labels, optional **explicit
members** and a unique **rank**. A node is a member when it is listed, or when the selector is not empty and every term
holds:

| Term | Holds when |
|---|---|
| `os` | the node's OS is this one (or one of these): `darwin` (macOS), `linux`, `windows` |
| `arch` | its architecture: `arm64`, `amd64` |
| `labels` | it carries every one of these labels |
| `hostname` | its name matches this glob (or one of these), ignoring case: `mac-*` |
| `battery` | it has a system battery (`true`: a laptop) or not, from the agent's facts (`power.battery`) |
| `ram_gb_min`, `ram_gb_max`, `cores_min` | its RAM is at least / at most, its cores at least |

Membership is evaluated whenever values are resolved; a node that stops matching falls back to the next layer down,
with no stale copy. Every resolution can say why: the explain view, `oarbank node show`, the node page and the group
page name each group a node is in and the terms that put it there ("Laptops because has a battery"), and the member
preview names the terms a node misses. Where several groups set the same key, the **highest rank wins** (a new group
goes on top; `groups.rank` moves one up, down, to the top or the bottom) and the explain chain shows the groups that
lost. Built-in groups keep their system membership and the lowest ranks; values can be set on them.

**Labels** are short owner words on a node (`node_labels`: 1 to 63 of `a-z 0-9 _ . : -`), set with `nodes.label` from a
node's page, Bulk changes or `oarbank node label`. The coordinator adds labels from facts (`laptop` for a node with a
battery), shown "from facts": they can be matched, not removed. Facts come from the node itself, so a group that locks
a safety value should select on owner labels, listed members or the OS. Removing a label that takes a node out of a
group holding a lock needs the admin role, so a label is never a way around a lock.

Operations: `groups.create` (T1, previewed in the console: who joins), `groups.update`, `groups.rank`,
`groups.delete` (T2: the preview names who joins or leaves and every node whose effective settings change, key by key;
deleting a group deletes its values and its secrets' values) and `nodes.label` (T1). Each writes one settings revision
for the nodes it moved, runs the effect hooks (a services change re-doctors) and rebuilds node statements. Reads:
`GET /api/v1/groups`, `GET /api/v1/groups/{id}`, `GET /api/v1/groups/preview?selector=&members=` (the live preview).

## Locks

A lock is an enforced value at the fleet or a group (`enforce` on a change; a T3 change, typed confirmation). The
resolver finds it first: the fleet's before any group's, the highest-ranked group's first. It wins outright; values
below it are kept but ignored (and apply again when the lock goes), and the preview of a new lock lists them ("mini
sets its own value (on): ignored while the lock holds"). A node value, or a group value under a fleet lock, is refused
while it holds: "locked by the group Laptops: change it there". A node may still reset its own value. In the console a
fleet or group row has a **lock** toggle beside its value, and a locked row on a node shows the value read-only with a
"Locked" disclosure naming who locked it and linking there.

**Campaigns** come under locks too. A campaign override (phase 5) goes through `apply.campaign_refusals(db, campaign,
key)`, which refuses a value where the fleet or a group any of the campaign's nodes belongs to locks it, naming the
lock, and then a key not declared campaign-overridable (`Setting.campaign`). The resolver already takes a campaign
layer on top of the node (`resolve(..., campaign=)`), for campaign-overridable keys only, and a lock ignores it.

The phase-4 exit test (`tests/test_settings_groups.py`): a Laptops group (selector `battery: true`) with a locked
`run_on_battery = false` holds on a laptop that had chosen `true`, refuses the node's override with the group named,
refuses a campaign override the same way, ignores a campaign value written anyway, and gives the node back its own
choice when the lock goes.

## Bulk changes

One key set or reset on many nodes is one `settings.apply` change set with one change per node: one revision, and one
preview that lists every node's old and new value and the nodes that keep theirs (a lock above, or the same value).
Over ten nodes' own values it is one tier up (operations.BULK_ESCALATE_ITEMS). The console's **Bulk changes** page
(`/nodes/bulk`, filtered by group or label) ticks nodes, then sets an override or (the safer default) resets to
inherited, or adds or removes labels; a change across several nodes always opens its review first. The CLI: `oarbank
settings set <key> <value> --nodes a,b` or `--label <label>`, and the same for `reset`.

## Canary to a group

A change goes to a small group first (an ordinary group value, or a group's protection rules), and **`settings.promote
{key, group, to}`** moves it up in one change set: set at the fleet (or a wider group), deleted from the group, so the
canary nodes see no change and the rest get it. A `union` list (protection rules) joins the target's entries instead of
replacing them, an entry with the same id being the group's version; a lock moves with its value. The group page has
"Promote to fleet…" on each value set there; the CLI is `oarbank settings promote <key> --group <group> [--to <group>]`.
A module version's canary may target a group too (`modules.enable_canary {group}`, `oarbank module canary <m>@<v> --group
<g>`): the group's members when the canary starts.

## Secrets on the chain

Module secrets resolve like a setting: a node's own value, else the value of the highest-ranked group it belongs to that
sets one, else the module's (fleet-wide). The encrypted table keeps its shape: the `node_id` column is the scope, `''`
for the module, a node id, or `group:<group id>`; the associated data binds each value to it, and a coordinator move
seals group values like the others. `secrets.set` and `secrets.clear` take `group` beside `node`; values stay
write-only, shown as fingerprints per scope (the module's Secrets page lists module, group and node values). Deleting a
group deletes its values. The ntfy token stays a fleet-only core secret.

## Protection on the chain

Protection is three settings at fleet, group or node scope, assembled into the agent's `policy.protection`:

- `protection.mode` (`fleet_first`, `moderate`, `strict_yield`; default `moderate`): replace, lockable;
- `protection.rules`: merge `union`, so the fleet's, each group's and the node's rules all apply (a rule only ever
  protects more); rule ids are unique on a node, and a change that would meet the same id from two scopes is refused;
- `protection.node`: the node section's other fields (memory guard, timing, GPU jobs, longest pause), replace.

A rule the node's OS cannot run (a code-signing matcher on Linux) is refused when set on that node, and skipped (named,
in the preview and on the protection page) when it comes from the fleet or a group. `protection.rules.update` writes
one scope's own section (a node, `fleet` or `group:<group>`) as one change set; `nodes.set_mode` writes a node's own
mode. Each change of a node's effective section appends a history row (`protection_versions`). The node's protection
page shows its effective rules with their source, the rules skipped there, and edits its own section; the per-node
canary, promote and restore are gone, replaced by a canary group and `settings.promote`. A home whose nodes held their
own sections is hoisted once: the mode, rules and node section every node had in common became the fleet's, the rest
stayed per node.

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
  Access (`console_hosts`), Data and verification (`replica_rate`), then host tool definitions and search paths
  ([host-tools.md](host-tools.md)), folders, dataset origins, releases.
- **Groups** (`/groups`): your groups in rank order (Up and Down move one), the built-in groups, every node's labels,
  and the new-group form: name, selector terms, listed members, the selector as JSON, and a live member preview that
  says for each node why it is in or not. A group's page (`/groups/<id>`) has its members and why, the rule's edit form
  with the same preview, its settings at group scope (lock toggles, "Promote to fleet…" on a value set there), its own
  protection rules and the secrets set for it.
- **Bulk changes** (`/nodes/bulk`) and **labels** on a node's Settings tab (add, remove) and overview.
- **Apply-then-Save**: a fleet or group change, a change across several nodes, a promotion, a label or a new group
  always opens the preview first (`plan.html`): the summary, the per-node old/new table, the nodes that keep their
  value and why, the values a new lock overrides, and a button that says what it does ("Save for 4 nodes"). A single
  node change saves at once (T1 keys confirm in the browser).
- **A refused save** comes back to its page with a GOV.UK-style error summary at the top of the section (it takes focus
  and links to each field), each message beside its field (`aria-invalid`), and what was typed kept. Forms are
  `novalidate`, so the Save button stays usable and the server's messages are the ones shown.
- **The why line** on the node page cites the settings it rests on with their value and source ("Run jobs on battery:
  off · Default"), each linked to its Explain row.
- **A module's Settings tab** and the node tab's per-module sections: [Module settings](#module-settings).

## The CLI

```text
oarbank settings get [<key>] [--node N] [--module M] [--json]     effective values with their source, or one key's chain
                                                                  (--module M alone: that module's keys)
oarbank settings explain <key> [--node N]                         the whole chain
oarbank settings set <key> <value> [--node N | --group G | --nodes A,B | --label L] [--module M] [--enforce] [--dry-run]
oarbank settings reset <key> [--node N | --group G | --nodes A,B | --label L] [--module M]
oarbank settings promote <key> --group G [--to <group>]           a group's value (a canary) to the fleet
oarbank settings overrides <key>                                  who overrides the fleet value, with what
oarbank groups list|show [G] | create <name> [--os --arch --label --hostname --battery --ram-min --member ...]
oarbank groups update <G> ... | rank <G> up|down|top|bottom | delete <G>
oarbank node label <node> <a,b> [--remove]
oarbank settings schema                                           the registry
oarbank settings set-secret ntfy_token / clear-secret ntfy_token  the write-only ntfy token
```

`set` and `reset` always preview (the per-node impact), then apply; without a scope they act on the fleet.
`oarbank node policy` and `oarbank node limits` are removed; `oarbank node show` lists what the node sets itself, with
the command that resets each.

## Migration

`migrate.run`, when the coordinator opens a home made before the settings model, in one transaction:

- Every installed module's keys are registered first, so module values convert key by key against the schema it
  declares.
- The `settings` table splits: owner keys become fleet rows (`ntfy` → `ntfy.url`, `ntfy.click_base`, its token into
  the secrets store; `console_hosts` (a string becomes a one-entry list), `replica_rate`, `default_worker_disabled_services`
  → each module's fleet `services.disabled` (`relay/scorer` → `[relay] services.disabled = [scorer]`; `*/x` → every
  installed module with a service x), `tool_registry` → host tool definitions, `folder_registry`, `dataset_origins` (its
  host list), `pipeline:<m>` → `[m] pipeline`, `module_settings:<m>` → one fleet row per key `m` declares);
  `dataset_groups` is dropped (no owner control, no reader); every other key is machine state and moves to
  `system_state`. The table is dropped.
- For each node, a policy value becomes a node row only where it differs from what the node now inherits (its computed
  default, the fleet's and its groups' values), so copies disappear and choices stay; caps become node rows (`enforce`
  only when hard, beside a cap); each module's node settings become one node row per key, and its disabled services
  `[m] services.disabled`, by the same rule; the protection sections are hoisted onto the chain ([Protection on the
  chain](#protection-on-the-chain); their history stays in `protection_versions`). Then `policy_json` and `limits_json`
  are dropped. A home whose nodes held `nodes.protection_json` is hoisted the same way once, and the column dropped.
- `module_channels.disabled` (the kill switch) becomes `[m] enabled = false` for the fleet, and the column is dropped.
- A home made by a 2.9 build before module settings converts its `module.settings`, `module.node_settings` and
  `disabled_services` rows the same way, and deletes them.
- Values the registry refuses (an undeclared module key, a value its schema refuses, a fleet-only module key set on a
  node) are dropped and named, with the counts and each module's registration, in the `settings_migrated` event.

On the owner's fleet (six nodes whose policies differed only in the RAM-computed `os_reserve_gb`, `module_settings`
`{}` and `disabled_services` `[]` everywhere, no caps, no owner keys, minos-gatk 4.0.0 installed and current) this
yields no rows at all, only minos-gatk's registration: the old model stored copies, not choices.

## Later phases

- **Host tools**: tool definitions, node-side detection reported in `tools_json`, per-node overrides in a signed node
  statement, module version constraints, per-node tool reason codes.
- **Campaigns, settings as code, drift**: campaign-overridable keys (tighten-only for safety keys), per-scope YAML
  export and import, shadowed-override and applied-drift reports.
