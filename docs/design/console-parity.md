# Console and CLI parity for operators

Status: built (PLAN D42) in **core 2.5.0**, with no SDK change; see Implementation status.

## The problem

The parity report ([parity.md](parity.md)) said 0 gaps while the CLI lacked commands the registry promised:
`oarbank protection …` and `oarbank node mode` did not exist, and the report only checked that an operation *named* a
command. Operators also could not see from the terminal what the console shows: a node's doctor, GPU API evidence,
container runtime, folders and sandbox enforcement (`oarbank node show`, D41, printed its state and services); one job's
attempts, checkpoint and explanation; a node's protection. The console itself left facts
unshown or unreadable: bootstrap pins, container image first runs (recorded and audited, never displayed), per-capability
enforcement (only explain's `CAPABILITY_NOT_ENFORCED`), GPU API evidence (a tooltip), remedies as inert chips, and a
plan's impact as raw JSON.

## Decisions

1. **The parity report checks the commands themselves.** Every `oarbank …` string in the operation registry is parsed
   against the CLI's own argparse parser (`cli.main.parser()`): its subcommand must exist, each literal word must be one
   the positional takes (`pin|unpin`: every alternative), and each flag must be one the subcommand defines. Placeholders,
   values and `...` are not checked; prose in the CLI column is not a command. Explain kinds are checked against
   `oarbank explain`'s choices. A promised command that does not exist is a gap, so the generated report is exactly true.
2. **One detail document per node and per job, read by both.** `coordinator/detail.py` builds them as pure functions
   over a reader. oarbankd serves them on `GET /api/v1/nodes/{node}` and `GET /api/v1/jobs/{job}` (the job's with its
   explain document, under explain's own limiter); the console's node and job pages call the same functions on their
   query-only connection, so the console still never calls oarbankd for a page (D10) and the two cannot disagree. The
   node document's services are the agent's per-service report as `nodeservices.rows` reads it (D41), the rows of the
   node page's one Services table. A node's protection has `GET /api/v1/nodes/{node}/protection` (`protection.status`).
   The CLI never reads the database.
3. **The CLI covers what operators do from the console:** `oarbank node show` (D41's, now from the node document: its
   modules, the doctor's failed checks, GPU APIs with evidence, the container runtime and what it misses, services,
   folder grants and per-capability enforcement), `oarbank node mode`, `oarbank job show|retry|cancel`,
   `oarbank protection show|set|preview|probe` (a node's, `fleet`'s or `group:<g>`'s own section in JSON, as the console
   edits it, or TOML, the local protection file's format; `preview` is the T2 dry run, exit 2; rolling rules out is a
   group's rules promoted with `oarbank settings promote protection.rules --group <g>`), `oarbank groups`,
   `oarbank node label`. `oarbank fleet` shows a node's container runtime state and
   what is missing. Every `--json` prints the document as served.
4. **Remedies carry their target.** An explain remedy has `target` when the subject names it: a node operation on the
   node, a job operation on the job, a campaign operation on the job's campaign, a fleet operation on the fleet; job
   remedies also carry the module. The console renders a remedy as a button when the operation needs nothing but its
   target (T2/T3 still open their plan review), as a link to the page whose form collects the rest
   (`views.REMEDY_FORMS`: caps, rebind, secrets, tools, folders, listeners, canary, agent promotion), and otherwise as its name with
   the command; `oarbank explain` prints the command (`operations.command`). A test keeps every remedy in one of the
   three.
5. **A plan's impact reads as rows**, in the console's review page and in the CLI's preview, from one function
   (`contracts/impact.py`): keys as labels, `_s` keys as durations, lists one item per line, the JSON kept in a
   collapsed element on the page.
6. **The node page shows GPU API evidence, per-capability enforcement and folder grants** as tables (`detail.node`);
   the module health page shows each pinned dataset as registered, waiting or in conflict (with the
   `pinned_dataset_conflict` detail; `datasets.pin_states`, sharing the comparison bootstrap acceptance uses) and the
   first run of each container set image (`modimages.first_runs`).

## Per OS

Nothing here is OS-specific: the documents report what each agent sends. The enforcement table lists what the node's
sandbox backend reports (`seatbelt` on macOS, `landlock` on Linux, `appcontainer` on Windows) and which modules each
`cooperative` or `unavailable` capability keeps out. The container runtime state and its `missing` list come from
Windows agents (docs/design/windows-containers.md), which `oarbank node show` and `oarbank fleet` show; macOS and Linux
agents report only how containers get the GPU.

## Versioning

Released in core 2.5.0. The explain document (schema `explain-1`) gains `remedies[].target`; the
admin API gains three read routes; the registry's CLI strings now name existing commands (`oarbank pause|halt|resume
--all`, `oarbank pipeline single|split --module`, `oarbank job retry|cancel`, `oarbank protection preview`).

## Acceptance tests

- The parity report has no gaps, and a registry command that does not exist, a word a positional does not take, an
  unknown flag or an explain kind the CLI lacks is one (`tests/test_console_parity.py`).
- `oarbank node show` prints the node's modules, the doctor's failed checks, GPU APIs with evidence, the container
  runtime with what is missing and its fix, the reported services once each, folder grants with their statement, and
  per-capability enforcement naming the modules a gap keeps out; `--json` equals what the console renders; by id or
  hostname. `oarbank fleet` shows a node's container runtime state and what is missing.
- `oarbank node mode` sets the mode and refuses an unknown one; `oarbank protection` previews (exit 2, live matches),
  sets from JSON and TOML, restores, starts a canary, refuses to promote a soaking canary and promotes with `--force`
  (audited against the canary's node), and requests a probe.
- `oarbank job show` prints attempts, the checkpoint the next attempt resumes from and the explanation; `retry` and
  `cancel` run the operations.
- Explain remedies carry their target; the CLI prints a runnable command; the console's remedy button runs the
  operation; operations needing more input link to their form.
- The console's node page shows the GPU API evidence, enforcement (naming the modules a gap keeps out) and folder
  tables; the module health page shows pins in each state and image first runs; the plan page shows a move's impact as
  rows; the CLI's preview has no raw JSON.
- axe finds no violations on the pages with these sections and on a move's plan page (`tests/test_accessibility.py`).

## Implementation status

Built as designed; every acceptance test above is automated (`tests/test_console_parity.py`, `tests/test_bootstrap.py`,
`tests/test_console.py`, `tests/test_accessibility.py` with axe-core).

- Reconciled with the module GUI work (D41) after it merged: one Services table on the node page and one `oarbank
  node show`, both D41's; `node show` now reads `GET /api/v1/nodes/{id}` and prints this note's sections beside D41's
  services lines, and the module health page's events use D41's `events.module` column.
- The node page's container runtime row and its `missing` list are the Windows containers work's
  (docs/design/windows-containers.md); this note adds them to `oarbank node show` and `oarbank fleet`.
- Found on the way: the axe test inserted agent builds without a platform (it ran only with Node modules, so it had
  stopped running); fixed.
