# The console, operations and explanations

The console is how the owner sees and changes the fleet. Three choices shape it (PLAN D9–D21): it runs as its own
read-only process, every change goes through one operation registry in oarbankd, and every "why" is answered by the
same predicate code the scheduler runs. Module pages are drawn by the console from declarations (D22–D24; the SDK's
`spec/ui-contract.md`).

## Read-path isolation

- **oarbank-console** is a separate process with no write path (D10). It reads the database through its own
  query-only connection: every 250 ms it checks `PRAGMA data_version` and, when something changed, rebuilds the hot
  snapshot (at most once a second) in one short read transaction. Each snapshot version renders each fragment once,
  shared by every viewer.
- **Drill-down pages** use a two-connection read pool behind a limiter, with a per-query time budget (0.25 s), so no
  query holds a snapshot long enough to starve WAL checkpoints.
- **In-memory facts** (writer lock statistics, module health, fleet state) come from oarbankd's `/internal/state`
  once a second; a failed poll marks the console "coordinator unreachable" while history keeps rendering.
- **oarbankd's own reads** (identity checks, `/internal/state`, `/metrics`) use a read-only connection with short
  caches, never the writer's lock.
- **SSE: one stream per page, resync-first.** The first message on every (re)connect is `resync`; a `heartbeat` every
  5 s drives the page's staleness watchdog and `: ping` comments every 15 s keep proxies open. Each client has a
  bounded queue (32); a slow client is dropped and resyncs when it reconnects. At most 16 streams; more get 429.
- **The console load gate** (D9): with five hostile viewers (an SSE stream plus a page a second each) and a `/metrics`
  scraper, agent throughput stays at or above 95% of the no-viewer baseline (`bench/swarm.py --console-viewers 5`).

## One operation registry sets parity, friction and audit

Every mutation is declared once in `oarbank.contracts.operations` (D14): id, friction tier, preview, reason policy,
minimum role, audit category, the operation that reverses it, idempotency style, and the routes, CLI commands and
console forms that reach it. The API, `oarbank` and the console all go through `POST /api/v1/ops/<op>`, so the console
can do nothing the API cannot; the generated [operations.md](operations.md) lists them.

- **Tiers.** T0 applies at once; T1 confirms; T2 previews and needs a reason; T3 also needs the resource's name typed.
  The emergency pause is T0 to engage and T1 (with a reason) to resume.
- **Preview, then apply.** A T2/T3 operation is previewed (`dry_run`), which returns a plan with its impact and a plan
  id; applying names the plan id. If anything the plan read changed since, the apply is refused with a fresh plan
  (409, D15).
- **Versions and idempotency.** Editable resources carry a version (`If-Match`: 412 on a mismatch, 428 when missing at
  T2+). Creations take an `Idempotency-Key`; a replay returns the stored answer, and a reused key with another
  payload is refused (422).
- **Bulk operations** move up one tier above ten items or a quarter of the fleet.
- **Roles** (viewer, operator, admin) are checked on every operation (D21); a module-scoped token runs only that
  module's own operations.
- **Module operations** (`mod.<module>.<verb>`) are registered from the module's manifest at install, with tiers raised
  by the effects they declare; the host draws their preview, confirmation and audit (D23).
- **Parity** is a test: every operation is reachable from the API, the CLI and a console form, every explain kind from
  all three, and every reason code's remedies are operations ([parity.md](parity.md), generated).

## The audit log is hash-chained

Every operation, accepted or refused, writes one audit row in the same transaction as its change (or right after it,
for operations that call module code) (D13). Rows are never pruned and form a SHA-256 hash chain; an hourly digest of
the chain head is signed with an Ed25519 key from the secret store and copied off the host by an owner-set command.
Verification runs hourly and on demand (`oarbank audit verify [--against <copy>]`); a failure is a latched P5 alert.
The signing key may change only where a digest signed by the old key names the new one (a coordinator move) or where
an owner-signed rescue move names it.

## One explain document answers every "why"

`oarbank explain job|node <id>` and the console's explain panels read one document (D16,
`oarbank.contracts.explain`): a verdict, a headline, a per-node matrix of predicate results with what was observed
and required, a summary by reason code, evidence and remedies (operations). Explain has its own limiter (two at a
time) so it never competes with the agent path.

### The claim path and the explainer share one pure predicate function

`coordinator/predicates.py` decides whether a node may take a job, and both `claim()` and the explainer call it, so an
explanation can never disagree with the decision it explains. A property test checks that they agree.

### Reason codes form one registry

Every reason the scheduler, the agent or a module gives has a code in `oarbank.contracts.reason_codes`: its category,
message template, severity, remedies, and for attempt endings the end reasons it explains and whether it counts
against the node or the job ([reason-codes.md](reason-codes.md), generated). Modules add codes only in their own
namespace, `<module-short>/<code>`, rendered as escaped text.

### Node states carry their cause

A node's page shows why its capacity is what it is: the protection rules reserving or capping, the binding limit, the
memory guard, a protection config error. Its decision timeline is the agent's protection journal, shipped in heartbeat
batches (`protection_decisions`).

## Alerts are precise or they are noise

Alerting runs inside oarbankd (D18; `coordinator/alerting.py`, rules in `oarbank.contracts.alert_rules`):

- each rule has a severity (P1–P5), a pending period (a condition that clears within it never notifies) and flap
  detection (repeated trips of one rule on one subject become one alert), and a runbook line the console shows;
- invariant conditions are three-valued and latched: a failed check stays open until an operator resolves it;
- alerts are acknowledged, snoozed or resolved with a useful/noise verdict, and the precision review
  (`oarbank alerts precision`) holds P4/P5 rules to at least 50% useful;
- notifications go to ntfy; a P5 alert is re-published every 30 minutes until acknowledged or snoozed.

## Security

Nothing is admin for being local, and identity headers are never trusted (architecture.md, "Network and access"):
console accounts with a password and TOTP, passkeys or one-time links; HttpOnly, SameSite=Strict sessions with a CSRF
token on every form and htmx request; a strict CSP with no inline script; Fetch Metadata and Origin checks; a Host
allowlist on both listeners; Funnel traffic refused. Module pages and panels render through host components only; the
sandboxed iframe placement is served from a separate origin and can only request operations, which the host confirms.

## Chaos

`tests/chaos` runs real oarbankd processes on scratch homes and checks each fault's outcome: `kill -9` mid-write leaves
a consistent database and every invariant holding; an external process holding SQLite's write lock gets agents a 503
with Retry-After, and they recover once it is released; killing a module's process during completions charges nobody
(S15); ntfy being down breaks nothing; a hand-edited audit row fails verification with a P5 alert; killing the console
leaves the agent path untouched.
