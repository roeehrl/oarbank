# Module GUIs: UI contract 1.2 and a safe bridge (SDK 1.5, core 2.5)

Status: built as designed (PLAN D41; see Implementation status), in the unreleased oarbank-sdk 1.5.0 and core 2.5.0.
Versions stay 1.5.0 and 2.5.0; the UI contract's minor goes from 1.1 to 1.2.

A module's GUI is the SDK's UI contract (spec/ui-contract.md): pages and panels made of host components bound to host
queries and module views, and sandboxed iframes talking to the host through a MessageChannel bridge (PLAN D23, D24). An
audit of the contract against core 2.2 to 2.5 found three kinds of gap:

1. **Security bugs on main.** A frame's `request.operation` posts its form without the session's CSRF token, so the real
   console answers 403 (the preview has no CSRF check, which hid it). The bridge capabilities a frame declares are not
   enforced anywhere. The `datasets` host query and the `datasets:<kind>` view input filter by kind only, so another
   module's dataset of the same kind leaks; `module_events` matches the module's name as a substring of an event's text.
2. **Correctness.** Dataset and campaign links (and `dataset_ref`, `campaign_ref` cells) render `href="#"`; module pages
   always see `user.role = "admin"` and panels no role at all; `request.operation` turns every parameter into a string.
3. **Coverage.** Most of what cores 2.2 to 2.5 added cannot be shown on a module page: secrets, checkpoints and
   resumes, a node's platform, GPU APIs, container runtime, services, folders and sandbox enforcement, campaign
   placement, dataset owners, sizes, origins and pins, container image first runs, the module's platform matrix. Frames
   lack what built-in components have: navigation, the subject they are shown for, media, core operations, uploads. The
   agent computes a per-service report but sends it only in a test build. Preview shapes queries differently from the
   console, cannot fill a panel's context, and does not run the axe checks D24 promises; conformance never computes a
   view or renders a page.

This note fixes all three, security first.

## Versioning

- **UI contract 1.2.** The host announces `ui_contract:1.2` in `initialize`. Everything is additive within major 1.
- **A page names what is new in 1.2 with `requires = "1.2"` and a `fallback`**, exactly as media components name 1.1.
  The SDK's page check (`ui.check_page`) refuses a component without it when it uses any of: a 1.2 host query, a 1.2
  field of an older host query (by name: in the source's `fields`, a table column, a `kv` item, or the `field` of `stat`,
  `status`, `progress`, `media`), or a 1.2 link (`tab`, `download`, `upload`). The renderer draws the fallback on a 1.1
  host. The page check knows the 1.2 fields per source from one table (`ui.SOURCE_FIELDS_1_2`), so a page that reads only
  1.1 fields keeps working on a 1.1 host without `requires`.
- **Bridge methods** are not versioned per component: a frame calls them, and a host that does not know one answers
  `method not allowed`. `read.media` is a new capability name a frame declares in `[[ui.iframes]].bridge`.
- No new manifest key needs a core floor: `[[ui.iframes]].bridge` values and page files are read by the SDK's models,
  which the core uses (no core-side copy).

## 1. Security fixes

### a. CSRF on operations a frame requests

The console checks a session CSRF token on every state-changing request (`/do/<op>` reads the form's `csrf` field or
the `X-CSRF-Token` header). The console's own forms get the field from `app.js` on `submit`; `ui.js` submits its form
with `form.submit()`, which fires no `submit` event, so the field was never added.

- **`ui.js` sends the token.** It reads the console page's `<meta name="csrf-token">` and puts it in the form it posts.
  A form field, not a header: the request must navigate (a T2 or T3 operation continues on the host's plan page, which
  is the response to that POST), and a navigation cannot carry a header. The field is the same one every console form
  sends. The frame never sees the token: `ui.js` runs in the console origin and the frame only receives replies on its
  port.
- **The preview enforces CSRF like the console.** Its shell carries a per-process token in the same meta tag, its form
  script adds the field on submit, and `POST /op/<op>` answers 403 `csrf` without a matching token, or when
  `Sec-Fetch-Site` is not `same-origin`/`none`, or when `Origin` is another host. So a page that works in preview works
  in the console.
- **Test through the real console.** A test renders a toy page with its frame in the real console app, takes the meta
  token, and posts exactly the fields `ui.js` builds (checked against `ui.js` by running it in jsdom where Node is
  available): with the token the operation runs and is audited; without it, 403.

### b. Bridge capabilities are enforced, twice

`[[ui.iframes]].bridge` lists what a frame may call: `read.query`, `read.view`, `read.media`, `request.operation`,
`resize`, `navigate` (default `read.view`, `resize`).

- **The renderer passes the declared list** to the frame element (`data-bridge-caps`), with a per-frame bridge base
  `/m/<module>/_bridge/<frame id>` (`data-bridge-base`). `Host.frame(view_id)` returns `{src, bridge}` for a declared
  frame, or None (the component then shows a placeholder instead of an iframe nobody declared).
- **`ui.js` refuses an undeclared method** on the port (`method not allowed`) before it does anything.
- **The console refuses it again**: every bridge route carries the frame id and checks the frame's declared capability
  (403 `capability`): `view/<id>` needs `read.view`, `query` needs `read.query`, `media` needs `read.media`, `op/<op>`
  needs `request.operation`, `link` needs `navigate`. An unknown frame is 404. So a bug in `ui.js`, or a request made by
  hand, gets no more than the manifest the operator installed allows.

### c. Ownership: owner-scoped exactly

- **Datasets.** The `datasets` host query and the `datasets:<kind>` view input (and its data version) return the
  module's own datasets plus the operator's (unowned) datasets of the module's kinds: the same rule as
  `host.datasets.query`, which every module already relies on. Another module's dataset is never returned, whatever its
  kind. Each row says `owner` (`module` or `operator`).
- **Events.** `events` gains a `module` column, set by every event that is about one module (install, enable, disable,
  promote, rollback, canary, pin, restart, uninstall, faults, runtime rebuilds, grants approved, revocations, secrets set
  and cleared, image first runs, dataset changes by the module, bootstrap registrations). `module_events` returns events
  `WHERE module = ?`, or of one of the module's jobs (`job_id`) or campaigns (`campaign_id`). The console's Health tab
  uses the same filter instead of `reason LIKE '%<name>%'` (module `toy` no longer sees `toybox`). D4: one baseline
  schema, so the column is simply in it.
- Tests create a second module with a dataset of the same kind, events whose text contains the first module's name, and
  jobs and campaigns of both, and assert that neither the query, the view input, the bridge nor the Health tab shows the
  other module's rows.

## 2. Correctness

- **Typed links resolve.** `Host.link_url` maps every link and every `*_ref` cell: `job` → `/jobs/<id>`, `node` →
  `/nodes/<id>`, `dataset` → `/datasets/<id>`, `campaign` → `/campaigns/<id>`, `page` → `/m/<module>/<page>`. With
  `download = true` (1.2), a dataset link goes to `/datasets/<id>/download.zip` and a campaign link to
  `/campaigns/<id>/artifacts.zip`, the console's existing downloads. Ids are URL-quoted. The preview maps the same links
  to its own stand-in pages, which show the fixture row the link names. An `https` URL needs the manifest allowlist, as
  before; anything else renders as text, never `href="#"`.
- **The viewer's role.** Pages and panels get `user.role` from the session (`viewer`, `operator` or `admin`), so `when`
  conditions on the role work, and the console draws a button whose operation needs a higher role as disabled, with the
  role it needs (oarbankd refuses it anyway).
- **Parameters stay JSON.** `request.operation` sends `params` as one JSON field (`params`, which the console's generic
  form mapping already reads), so numbers, booleans, `"007"`, lists and objects arrive as the frame sent them.

## 3. UI contract 1.2: what a page can show

Every host query is filtered to the module's own rows and never returns a secret value; each runs under the 250 ms
budget and returns at most 200 rows after shaping (`limit`). The console's queries are SQL over its read connection; the
console never calls the module.

### New host queries

| Query | One row per | Fields | Params |
|---|---|---|---|
| `secrets` | declared secret | `name`, `description`, `set` (module scope), `fingerprint`, `changed_at`, `changed_by`, `node_values` (nodes with their own value), `stages` (the stages that receive it), `coordinator` (the coordinator side may read it), `unreadable` (an open `secret_unreadable` alert) | `name` |
| `checkpoints` | job of this module with a checkpoint | `job_id`, `attempt_id`, `node_id`, `generation`, `seq`, `files`, `size`, `at`, `digest` | `job_id`, `node_id` |
| `services` | node and service of this module | `node_id`, `hostname`, `service`, `health`, `state` (`running`, `ready`, `starting`, `stopped`), `stopped_reason` (`held: <reason>`, `disabled`, `withdrawn`, `gpu api missing`, `idle`), `error`, `gpu_api_missing`, `lifecycle`, `users`, `endpoint`, `reported_at` | `node_id`, `service` |
| `pins` | pinned dataset (`[[datasets.pinned]]`) | `dataset_id`, `kind`, `platform`, `files`, `size`, `state` (`registered`, `missing`, `conflict`), `conflict` (who holds the id, with what kind), `alert` (an open `pinned_dataset_conflict` alert) | `dataset_id` |
| `images` | container set image first run | `digest`, `image`, `set_name`, `key_sha256`, `first_run_at`, `node_id`, `attempt_id`, plus the set's `registry`, `repository`, `platform` | `set_name` |
| `platforms` | platform the module declares, refuses or the fleet has | `platform`, `runner` (`supported`, `unsupported`, `undeclared`), `reason` (`requires.unsupported`), `coordinator` (`supported`, `unsupported`, `any`), `nodes`, `online`, `certified`, `doctor_failed` | `platform` |

### Richer existing queries (fields new in 1.2)

| Query | New fields |
|---|---|
| `attempts` | `resumed_from_attempt`, `resumed_from_node`, `resume_digest`, `module_version`, `rss_gb` |
| `nodes` | `platform`, `os`, `arch`, `os_version`, `gpu_apis_host`, `gpu_apis_containers`, `container_gpu`, `container_runtime`, `container_state`, `container_platforms`, `container_detail`, `container_missing` (`[{what, detail, fix}]`), `container_fixes` (the fixes as text), `services` (this module's, as in `services`), `service_health` (one line), `folders` (`{id: {access, status}}`, this module's folders only), `folders_ok`, `enforcement` (`{capability: state}` for the capabilities this module's sandbox needs), `sandbox_gaps` |
| `campaigns` | `placement_mix`, `placement_unit`, `placement_pin`, `bound_class`, `binding_state`, `binding_source`, `stranded_since` |
| `datasets` | `owner` (`module`, `operator`), `module`, `platform`, `files`, `size`, `origins` (the distinct origin hosts), `pinned` (one of the module's `[[datasets.pinned]]`) |

Notes:
- Container runtime state (`container_runtime`, `container_state`, `container_platforms`, `container_detail`,
  `container_missing`) is the node's facts' `containers` report (D39, [windows-containers.md](windows-containers.md),
  "The node's report"): a Windows node's WSL containers session (`wslc`: `ready`, `starting`, `missing`, `failed`,
  `absent`, with what is missing and its fix). Nodes whose agent reports no runtime state there (macOS and Linux report
  only `gpu`) have these null and `container_missing` empty.
- `enforcement` lists the capabilities `platforms.sandbox_needs(manifest)` names for this module (the same list
  placement checks), each with the node's reported state (`enforced`, `unavailable`, or `unreported`).
- A row's dataset `meta` keys are merged under the core fields: a module cannot shadow `owner` or `size` with meta.
- A list value in a `text` cell renders joined with commas, not as a Python list.

### Links

`link` targets and `row_link` gain (all 1.2):
- `tab`: `secrets` or `health`, the module's own core tabs (`/modules/<module>/secrets`, `/modules/<module>/health`).
- `download: true` beside `dataset` or `campaign` (above).
- `upload: {kind, then?}`: the console's folder upload with the module and `kind` filled in (`kind` one of the
  module's `[datasets].kinds`; the page check refuses another). With `then = "self.<verb>"`, an operation of the module
  whose `target = "dataset"` (checked), the upload page sends the browser, once the dataset is registered, to a host page
  that offers that operation on the new dataset, drawn by the host with the registry title and tier, and returns to the
  module page afterwards. The module never sees the upload until the operator runs its importer.

## 4. The bridge in 1.2

Frames reach what built-in components reach, with the host's checks:

| Method | Capability | What the host does |
|---|---|---|
| `read.query {query, params, fields, group_by, agg, order_by, limit}` | `read.query` | The same catalogue, owner scoping and shaping as pages; `$job`, `$node`, `$campaign`, `$self` are interpolated by the console from the frame's context. |
| `read.view {view}` | `read.view` | The stored view; a campaign-scoped view reads the frame's campaign. |
| `read.media {ref, kind}` | `read.media` | The same ownership check as `media`; answers `{src, thumb, job}`: capability URLs on the module origin. |
| `request.operation {op, target, params}` | `request.operation` | What a page action may name: `self.<verb>` or a core operation; the viewer's role must meet its `min_role`; a target of a core job, campaign or dataset operation must be this module's; the host confirms outside the frame with the registry title, tier and target, then posts (T2 and T3 continue on the plan page). |
| `resize {height}` | `resize` | Bounded by twice the declared height. |
| `navigate {to}` | `navigate` | `to` is a typed reference (`job`, `node`, `dataset`, `campaign`, `page`, `tab`, with `download`); the console maps it with the same `link_url` the renderer uses and the top page goes there. URLs are refused. |

- **Frame context.** The host's first message is `{type: "oarbank.bridge", module, view, context}` where `context` is
  the subject the frame is shown for: `{job}` on a job panel, `{node}` on a node panel, `{campaign}` on a campaign
  panel, and the page's route variables. `ui.js` takes it from the frame element (`data-context`, rendered by the
  console; a frame cannot change the console's DOM) and sends it with every read; the console interpolates server side.
  It is a convenience, not an authority: every read stays owner-scoped.
- **Media in frames.** The frame CSP gains `media-src 'self'` (images were already `img-src 'self' data:`): `'self'` is
  the module origin, where `/b/<token>` lives. `connect-src` stays `'none'`, so a frame shows media only through
  elements, never by fetching bytes.
- One link mapping (`modpages.link_url`) serves rendered links and `navigate`; one operation check
  (`modpages.op_allowed`) serves rendered buttons and `request.operation`.

## 5. The agent's service report

The agent keeps a per-service state (health, running, ready, error, held, disabled, withdrawn, `gpu_api_missing`,
lifecycle, users) for host protection and its tests. It now sends it:

- **Heartbeat.** `services`: `[{service: "<module>/<name>", health, running, ready, error, held, disabled, withdrawn,
  gpu_api_missing, lifecycle, users, endpoint, accepting}]` and `probes`: `[{probe, health}]`, on every heartbeat (the
  same cadence as `folders`; a few hundred bytes per service). The agent's former test-only report is this report.
- **oarbankd** stores it in `nodes.services_json` (with `services_at`); a node that sends none keeps none.
- **Console node page**: a Services table (module, service, health, state, why stopped, error), beside the existing
  "services running/held" lines, which it replaces. **`oarbank node show <node>`** prints the node's summary with the
  same table. The `services` and `nodes` host queries read it, filtered to the module.
- Per OS: the services manager is the same code on macOS, Linux and Windows (its spawning, endpoints and stopping are
  per-OS, the report is not), so every agent reports the same shape. The agent's report tests run on all three.

## 6. Preview and conformance

- **One query shaper.** `oarbank_sdk.render.shape(rows, source)` (group_by with `count`, `mean`, `median`, `min`,
  `max`, `p95`, `sum`; `order_by`, `descending`; `fields`; `limit`) and `oarbank_sdk.render.FILTERABLE` (the params a
  host query filters on) are used by the console and the preview, so a fixture page aggregates exactly as the console
  does.
- **Panel context fixtures.** `fixtures/ui/context.json`: `{"job": {...}, "node": {...}, "campaign": "...", "user":
  {"role": "..."}}`. The preview renders panels with it, so `$job`, `$node`, `$campaign` params and `when` conditions
  behave as on a job, node or campaign page; `?role=` switches the viewer's role.
- **Axe in preview, as D24 promises.** `oarbank-sdk preview <manifest> --check` renders every page and panel with the
  fixtures (no server) and runs axe-core (WCAG 2.0/2.1 A and AA, best practice) in Node with jsdom, the same harness the
  console's accessibility test uses; serious or critical violations fail it. Node, `axe-core` and `jsdom` come from
  `OARBANK_SDK_NODE_MODULES` (or `--node-modules`); without them the check says it was skipped and why, never passes
  silently. Colour contrast needs layout, which jsdom lacks; the published stylesheet's tokens are checked for WCAG AA
  contrast in Python instead (both schemes).
- **Conformance `ui` suite.** For every declared view, `ui.view.compute` runs on `fixtures/ui/inputs.json` and the
  answer is validated against the declaration by the same function oarbankd uses (`ui.validate_view`: shape, row limit,
  declared columns, and every `artifact_ref` cell a valid reference). Every page and panel is rendered with the fixtures
  and the panel context; a component that renders a placeholder for missing data is a warning, a render error fails.
  The axe check runs when Node modules are available (skip with the reason otherwise).

## Threat model

The adversary is a module (its pages, views, frame code and data) and anyone who can get data into its rows. The
operator and the console's signed-in users are trusted with what their role allows.

- **A frame acting with the viewer's session.** It cannot: it has an opaque origin, no cookies and `connect-src 'none'`;
  the console's `ui.js` makes every request, after checking the declared capability, and the console checks it again.
  Operations need the viewer's confirmation outside the frame, the session's CSRF token (which the frame never sees),
  the viewer's role, and, for a core operation on a job, campaign or dataset, a target the module owns.
- **A frame reading another module's data.** Every query, view input, media reference and event list is owner-scoped in
  SQL; context interpolation cannot widen it.
- **A frame steering navigation.** `navigate` takes typed references only, mapped by the console to console paths;
  `href`s are checked to start with one `/`.
- **Phishing inside the frame.** The confirmation is the browser's own dialog with registry text; the plan page is the
  host's. A frame can draw anything inside its own box, which is visibly the module's.
- **Secrets.** No query selects a value or a ciphertext; fingerprints are keyed (HMAC under a coordinator key) and
  already shown on the Secrets tab.
- **Upload links.** They only pre-fill the console's own upload page; the importer runs as a normal, confirmed operation.

## Per-OS behaviour

The GUI is the console's and the browser's; it is the same for every OS a fleet runs. What differs is what nodes report:
container runtime state comes from nodes whose agent reports it (Windows' WSL containers session today); GPU APIs come
from every agent's doctor (Metal on macOS; CUDA, ROCm, Vulkan, OpenCL on Linux; DirectML besides them on Windows); the
service report and folder outcomes come from every agent. A field a node does not report is null and renders as "—".

## Docs and examples

- SDK docs: a how-to **Build your module's GUI** (pages, panels, views, iframes and a bridge client), a "Show it on your
  module's pages" section in each feature how-to (secrets and images, service endpoints, GPU placement, files, media
  and checkpoints, bootstrap pins), and `spec/ui-contract.md` for 1.2 (sources, links, frame context, `navigate`,
  `read.media`, enforcement).
- Reference modules: **reel** shows its checkpoints and its datasets (owner, size, origins) with working download links
  and an upload link to its importer; **modelserver** shows its service per node with health and why it stopped;
  **gpuinfo** shows each node's GPU APIs and its platform matrix; **taskbench** shows its secret set or unset with a link
  to the Secrets tab, and its container image first runs; **toy**'s frame uses frame context, `read.query`, `navigate`
  and an operation with JSON parameters.

## Acceptance tests

| Criterion | Test |
|---|---|
| 1a frame operation posts with CSRF; the console runs it; without the token 403; preview enforces CSRF | core tests/test_module_gui.py (real console app); SDK tests/test_preview.py; tests/js bridge test (ui.js in jsdom) |
| 1b undeclared bridge methods refused in ui.js and by the console | tests/test_module_gui.py (every route, 403 per capability); tests/js bridge test |
| 1c no other module's datasets, events (query, view input, bridge, Health tab) | tests/test_module_gui.py (two modules, same kind, names as substrings) |
| 2 dataset and campaign links and refs, downloads; viewer role on pages and panels; JSON params intact | tests/test_module_gui.py; SDK tests/test_render.py |
| 3 every new source and field, owner-scoped, never a secret value | tests/test_module_gui.py (one test per source, a second module's rows present); a test greps every query's SQL for `ciphertext` |
| 3 `requires = "1.2"` enforced by the page check, fallback on a 1.1 host | SDK tests/test_ui.py, tests/test_render.py |
| 4 navigate, frame context, read.media, core operations with role and target checks, upload link | tests/test_module_gui.py; tests/js bridge test |
| 5 the agent sends the service report; stored; node page; `oarbank node show`; `nodes`/`services` sources | agent unit test (heartbeat body), tests/rust e2e (a real agent's report reaches the node page); tests/test_module_gui.py; tests/test_console.py |
| 6 preview shapes like the console; context fixtures; axe check; conformance ui suite | SDK tests/test_preview.py, tests/test_conformance.py; core tests/test_module_gui.py (console and preview give the same rows for the same source) |
| 7 examples render with the new sources | SDK conformance of reel, modelserver, gpuinfo, taskbench (ui suite); core tests render each example's pages in the console |

## Open questions

Decisions taken on the conservative side:

- **Operator datasets stay visible to modules** in the `datasets` query and inputs (with `owner = "operator"`), as
  `host.datasets.query` and media visibility already have them. Only other modules' datasets are excluded. A stricter
  "module's own only" would hide the uploads an importer exists to adopt.
- **Core operations from frames** are any a page action may name, with role and target-ownership checks. A narrower
  allowlist would also narrow pages; nothing in the contract asks for that today.
- **Axe needs Node.** The SDK does not bundle axe-core or jsdom (a Python package that vendors a browser engine would be
  heavier than the rest of the SDK); the check skips with its reason when they are missing.

## Implementation status

Built as designed in oarbank-sdk 1.5.0 and core 2.5.0 (UI contract 1.2), with these changes found while building:

- **One copy of each policy.** The console page's, a frame's and media's CSPs moved into the SDK's renderer
  (`console_csp`, `frame_csp`, `media_csp`); the console, its frames listener and the preview all use them, so the
  preview's frame CSP gained the console's `font-src` and both gained `media-src 'self'`. The axe harness moved there
  too (`render/axe_run.cjs`), and the console's accessibility test runs it.
- **`$job`, `$node` and `$campaign` were broken in the console**: a panel's context holds its subject as an object
  (what `when` reads), so `{"job_id": "$job"}` bound the object and the query failed. They now interpolate to the
  subject's id, in pages, panels and frames alike; the campaign panel's context became an object like the others.
- **A `results` query filtered on `dataset_id` compared it with `job_id`**, and a `jobs` query with `node_id` failed.
  Each host query now filters on its own declared params only (`ui.QUERY_PARAMS`), in the console and the preview.
- **The preview showed undeclared view columns** the console never sees; it now stores what `ui.validate_view` keeps,
  the function oarbankd uses (moved from the core to the SDK).
- **Column `download`** (1.2): a `dataset_ref` or `campaign_ref` column with `"download": true` links each cell to its
  download, which is what a table of datasets needs (a link component names one fixed target).
- **The node page's services**: the "services running" and "services stopped by protection" lines became one Services
  table from the report; `oarbank node show <node>` is new (the CLI had no per-node view); it reads the node's detail
  document, `GET /api/v1/nodes/{id}` (D42, console-parity.md), and `/api/v1/fleet`'s node rows carry `services` too. `coordinator/nodeservices.py` is the one reading of the report.
- **The service report** is the agent's former test-only `ServiceManager::report` (now with `endpoint`, without the
  capabilities the doctor report already carries), merged into every heartbeat as `services` and `probes`.
- **`check_page` takes the manifest** (it needs the dataset kinds and operation targets for upload links).
- reel gained the dataset kind `upload` (what its upload link registers, before `adopt_upload` makes it an asset), a Data
  page and a job panel; modelserver, gpuinfo and taskbench gained pages and fixtures; toy's frame uses the frame context,
  `read.query`, `navigate` and an operation with JSON parameters.

Tests (automated; every acceptance criterion above has one):

| Criterion | Test |
|---|---|
| 1a CSRF on frame operations, through the real console; preview enforces it | tests/test_module_gui.py `test_a_frame_operation_posts_with_the_session_csrf_through_the_real_console`; SDK tests/test_ui_1_2.py `test_preview_enforces_csrf_like_the_console`; SDK tests/js/bridge.cjs (ui.js in jsdom: the form's fields) |
| 1b capabilities enforced by ui.js and by every console route | SDK `test_ui_js_bridge_enforces_capabilities_and_posts_with_csrf_and_json_params`; core `test_bridge_routes_check_the_frames_declared_capabilities`; preview `test_preview_bridge_checks_capabilities_and_interpolates_context` |
| 1c owner-scoped datasets, view inputs and events | core `test_datasets_and_their_view_inputs_never_include_another_modules`, `test_module_events_are_the_modules_own_exactly`, `test_module_events_name_their_module` |
| 2 links, downloads, role, JSON params | core `test_dataset_and_campaign_links_and_downloads_resolve`, `test_pages_and_panels_see_the_viewers_role`, the CSRF test (a number arrives as a number); SDK `test_links_resolve_or_render_as_text_never_hash`, `test_the_viewer_role_gates_buttons_and_when` |
| 3 sources and fields, owner-scoped, no secret value | core `test_secrets_source_shows_state_never_a_value`, `test_checkpoints_and_resumes`, `test_nodes_and_services_sources`, `test_pins_images_platforms_and_campaign_placement`; SDK `test_1_2_sources_fields_and_links_need_requires`, `test_upload_links_name_a_kind_and_an_importer` |
| 4 navigate, context, read.media, operations, upload | core `test_navigate_maps_typed_references_like_rendered_links`, `test_bridge_reads_own_data_and_interpolates_the_frame_context`, `test_read_media_gives_capability_urls_for_the_modules_own_artifacts`, `test_bridge_operations_are_what_a_page_may_name_with_role_and_target_checks`, `test_the_upload_link_returns_to_the_importer_operation`; SDK `test_frames_carry_their_capabilities_base_and_context` |
| 5 service report: heartbeat, stored, node page, `oarbank node show`, sources | tests/rust/test_agent_endpoints.py (a real agent's report reaches the node and says `disabled` after the kill switch); core tests/test_console.py `test_services_are_shown_with_their_state_and_why_they_stopped`, `test_oarbank_node_show_prints_the_services_report`; the agent's services unit tests assert on the same report |
| 6 one shaper, panel context, axe, conformance ui suite | SDK `test_one_shaper`, `test_preview_panels_get_their_context_and_views_are_validated`, `test_preview_check_runs_axe_and_catches_a_violation`, `test_the_ui_suite_passes_for_the_examples`, `test_the_ui_suite_fails_a_view_that_breaks_its_declaration`; core `test_the_console_shapes_queries_with_the_published_shaper` |
| 7 examples render with the new sources | core `test_the_reference_modules_pages_render_in_the_console`; SDK `test_the_ui_suite_passes_for_the_examples` |
