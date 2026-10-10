# Datasets in and out, media and portable checkpoints (SDK 1.5, core 2.5)

Status: built as designed (PLAN D37; see Implementation status), for three issues on the public SDK repository, in one
release with the other 1.5 work: **oarbank-sdk 1.5.0** and **core 2.5.0**.

- #10 Datasets: get user files and downloads in, and results out (origins, upload, download, folder grants).
- #11 UI contract: media components (`media`, `gallery`, `compare`) with bytes served safely.
- #15 Portable checkpoints: a paused or evicted job resumes on any node from its last checkpoint.

All three move files that the coordinator keeps by content digest, so they share one **blob transport**: one way to
upload a blob (resumable, digest-checked), one way to serve one (ranges, by digest), one way to fetch one from a public
origin, and one rule for when a blob may be deleted. That part is designed once, first.

## Versioning, for all three

- **Manifest 1, module protocol 1, runner protocol 1 and envelope 1 stay.** Everything is additive.
- **New manifest keys need `requires.core >= 2.5`**, a new row of the SDK's floor table (spec/manifest.md rule 12):
  `sandbox.folders`, `stages[].checkpoint`, `runner.checkpoint_grace_s`, the runner capability `checkpoint` and the
  view cell type `artifact_ref`. A 2.4
  core reads manifests leniently and would drop them silently: folders would never be granted (jobs fail on missing
  inputs), checkpoints would never be kept (a long job restarts from zero without a word).
- **Run-time features get a host capability.** `datasets.create` with `origins` is a run-time choice of module code:
  the host advertises `datasets.origins`; a 2.4 host refuses an unheld blob (422 `unknown_blob`), so nothing is
  silent either way.
- **UI contract 1.1.** The three components are new in minor 1; the host announces `ui_contract:1.1`. A page uses them
  with `requires = "1.1"` and a `fallback` (the SDK's page check requires it), so a 1.0 host draws the fallback.
- `CORE_VERSION` 2.5.0, oarbank-sdk 1.5.0. The core reads every new key from the SDK's models (no core-side copy).

## The blob transport (shared)

A **blob** is a file the coordinator keeps under `<home>/blobs/<d[0:2]>/<d>`, named by its sha256 `d` in the `blobs`
table with the size it measured. Artifacts, checkpoint files, uploads and origin fetches all end up there.
`coordinator/blobstore.py` owns all of it; the agent API, the admin API and the console are thin routes over it.

### Upload: resumable, digest-checked (after tus 1.0)

The protocol is the core of [tus 1.0](https://tus.io/protocols/resumable-upload) with the digest as the upload's id,
so a client never needs a creation round trip it could lose, and a blob already held costs one request.

| Request | Meaning |
|---|---|
| `POST <base>/uploads/{digest}` `{"size": N}` | Create or resume. Answers `{"offset": k, "complete": bool}`. `complete` is true when the coordinator already holds the blob (nothing to send). |
| `PATCH <base>/uploads/{digest}` with `Upload-Offset: k` | Append the body at `k`. Answers 204 with the new `Upload-Offset`. An offset that is not the partial's size is 409 `offset_mismatch` with the current offset in `Upload-Offset` (the client resumes from it). When the partial reaches `size`, the coordinator checks its sha256: a match registers the blob (204, `Upload-Complete: 1`); a mismatch deletes the partial (422 `digest_mismatch`). |

- `<base>` is `/v1` on the agent API (mTLS, a node) and `/api/v1` on the admin API (an operator or admin). The agent
  API's single-shot `PUT /v1/artifacts/{digest}` and `HEAD /v1/artifacts/{digest}` are removed: the agent uploads
  artifacts and checkpoint files through `/v1/uploads` (resumable after an agent restart or a network cut).
- **Partials are per uploader**: `<home>/uploads/<digest>.<uploader>.partial`, the uploader being the node id or the
  account. Two parties uploading the same digest never write into each other's partial, so one cannot spoil another's
  upload by appending other bytes.
- The coordinator hashes as it writes. A resumed PATCH from another process (after a coordinator restart) hashes the
  bytes already on disk first, as the agent does for resumed downloads.
- **Limits.** One blob is at most `C.BLOB_MAX_BYTES` (the old `ARTIFACT_MAX_BYTES`, renamed; `size` above it is 413
  at POST). Partials together are at most `C.UPLOAD_PARTIAL_MAX_BYTES` (a POST that would exceed it is 507
  `upload_space`). A partial untouched for 7 days is removed by the coordinator's daily prune (the existing loop).
- Events: `blob_uploaded` (actor, digest, size). Uploads are not operations: bytes change no state anybody sees until
  an operation or a completion names them, and those are audited.

### Serve

- **Agents:** `GET /v1/blobs/{digest}` (as today, `Range` capable). New: when the coordinator does not hold the blob
  but a registered dataset lists origins for it, it fetches it (below) while it serves it.
- **People:** `GET /api/v1/blobs/{digest}` (viewer), for downloads. Only blobs named by a dataset's files or a
  canonical result's artifacts (module files and checkpoints are internal). Always `application/octet-stream`,
  `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox;
  default-src 'none'`, `Range` capable.
- **Pages:** media bytes for module pages come only from the module origin (#11), never from the admin API or the
  console origin.

### Fetch from an origin

One rule, implemented on both sides (agent `staging.rs`, coordinator `blobstore`): `https` only; the host a DNS name
(never an IP literal); every address it resolves to public (not loopback, link-local, private, shared, multicast or
reserved); the connection made to an address that was checked (no second lookup between check and connect); the size
and the sha256 checked; resumable with `Range`. The coordinator connects to the vetted address with the host name for
SNI and certificate checks, so a DNS answer that changes between check and connect (rebinding) cannot point it at the
LAN. **Redirects** are followed, at most 5, and only to a URL that passes the same rule (and the operator's origin host
policy) at every hop: the public places models and tools live (Hugging Face, GitHub release assets) answer with a
redirect to their CDN, and the digest still decides what is accepted. The agent used to refuse every redirect; it now
follows them under this rule.

### Deletion

Blobs are deleted only when something that owned them goes away and nothing else names them:
`blobstore.release(db, digests)` deletes each digest's file and row unless a module file, a dataset's files, a result's
artifacts or a checkpoint still names it. Only checkpoints call it (a replaced or dropped checkpoint, #15): the rest
of the system keeps its rule "blobs stay".

## #10 Datasets in and out

### Origins on `datasets.create`

`files[]` entries are `{path, digest, size, origins?}`:

- `digest` (64 lowercase hex) and `size` (bytes) are **mandatory** for every file, so a dataset's contents never depend
  on an origin.
- A file **without** `origins` must name a blob the coordinator holds and the module can see, at exactly `size`
  (new: the size is checked).
- A file **with** `origins` (1 to 8 URLs, each at most 2048 characters) may name a blob the coordinator does not
  hold. If it holds it, the size must match. Each URL must pass the origin URL rule (https, a DNS name with a dot, no
  user info, no IP literal, not `localhost`) and the operator's **origin host policy**; otherwise 422 `origin_refused`
  naming the URL and why.
- The same rules apply to the operator's `datasets.register` (an importer or `oarbank dataset upload`).
- **The origin host policy** is the setting `dataset_origins` `{"hosts": [...]}` (operation `settings.origins.update`,
  T2): host patterns as in `[sandbox].net.allow` (`example.org`, `*.example.org`, an optional `:port`). Empty, the
  default: any host the URL rule admits. The policy is applied when a dataset is registered and again whenever the
  coordinator serves a dataset manifest to an agent or fetches an origin itself: an origin the policy no longer admits
  is left out, so tightening it takes effect at once without touching datasets.
- `effects.datasets_create(...)` takes origins in `files`; host capability `datasets.origins`.

**No byte passes through the coordinator unless the origin fails.** Agents stage origin first (as today): an https
download straight into the node's blob cache, resumed with `Range`, the sha256 checked; each node caches the blob
once and every job that mounts it places it from the cache. Only when every origin fails for a node does it ask
`GET /v1/blobs/{digest}`. The coordinator then fetches the blob from the dataset's origins itself, single-flight per
digest (one fetch, however many nodes ask): the first request streams the bytes to the node as they arrive (a tee into
the coordinator's partial, skipping the bytes the node's `Range` says it has), and later requests wait for the fetch
and are served from the file. The blob is registered only after its sha256 matched; a node that received bad bytes
from a failing fetch rejects them by its own digest check. Events `origin_fetched` and `origin_fetch_failed`.

`host.blobs.stat` still answers `held: false` for a blob only an origin has. `host.datasets.query {with_files: true}`
already returns each dataset's `files`, now with their `origins`, so an importer operation can derive datasets from
uploaded or origin ones.

### Upload

`oarbank dataset upload <dir> --kind <kind> [--id <dataset_id>] [--module <name>] [--meta key=value ...]`:

1. Walks `<dir>`: regular files only (a symlink, a socket or a device is refused, naming it); every relative path must
   be a PortablePath (spec/platforms.md), else the command lists the offenders and stops.
2. Hashes each file, then uploads it through `POST/PATCH /api/v1/uploads/{digest}` in 8 MiB chunks, retrying a failed
   chunk with backoff from the coordinator's offset. A file the coordinator holds is skipped.
3. Registers the dataset with `datasets.register` (`{dataset_id, kind, module, meta, files: [{path, digest, size}]}`).
   With `--module` the dataset belongs to that module (its kind must be one of the module's `[datasets].kinds`), so
   only that module sees it; without, it is the operator's, which every module sees. The default id is
   `<kind>:<directory name>-<the first 8 hex digits of the file list's digest>`.

**Resume after an interruption:** run the same command again. Held files are skipped and partials continue from the
coordinator's offset; nothing already sent is sent again.

**A module's importer** is an ordinary operation with `target = "dataset"` (reel's `adopt_upload`:
`oarbank mod reel adopt_upload <dataset id>`): it reads the uploaded dataset through `host.datasets.query {ids,
with_files: true}` and returns `datasets.create` effects that name the same blobs (visible to it: the dataset is its own
or the operator's).

**Console upload** (`/datasets/upload`): the operator picks a folder (`<input type=file webkitdirectory>`); the page
hashes each file in the browser (an incremental SHA-256 in the console's own script, since WebCrypto cannot hash a
stream) and sends it to the console's upload routes, which forward each chunk to oarbankd with the account's identity
(the console holds no blobs). A failed chunk resumes from the coordinator's offset; a reload resumes the same way (the
file's digest names its partial). The form then applies `datasets.register` like any T1 operation.

### Download

- `oarbank dataset download <dataset_id> [<dir>]` and `oarbank campaign download <campaign_id> [<dir>]`. A campaign's
  artifacts are its done jobs' canonical results' artifacts, written as `<dir>/<job id>[-<job name>]/<artifact>/<path>`.
  Each file is fetched from `GET /api/v1/blobs/{digest}` into `<path>.partial`, resumed with `Range`, checked against
  its sha256, then renamed; a file already present with the right digest is skipped.
- Admin API: `GET /api/v1/datasets/{id}` (with files), `GET /api/v1/campaigns/{cid}/artifacts`.
- Console: a Datasets page (`/datasets`, `/datasets/{id}` with its files) and, on the dataset and campaign pages,
  "Download" for a file and "Download all (zip)". The console streams the files from the coordinator's blob directory
  (it runs beside oarbankd and reads its home) as attachments: `application/octet-stream` or a stored (uncompressed)
  ZIP64 archive, `Content-Disposition: attachment`, `nosniff`, `Content-Security-Policy: sandbox`, so nothing
  downloaded is ever rendered in the console origin.

### Folder grants: read-only input folders, write-only outbox folders

```toml
[sandbox]
folders = [{ id = "inputs", access = "read" }, { id = "outbox", access = "write" }]
```

A module asks for folders by **id**, as it asks for tools. `access = "read"`: the runner may read the folder (files and
listings), never write it. `access = "write"`: an outbox: the runner may create files and directories in it and write
them, never read, list, rename or delete anything there (so it cannot learn what else the folder holds, or remove it).
Only runners get folders: never doctor, services, probes, the coordinator side, or bootstrap jobs.

**Approval.** Folders are part of `[sandbox]`, so they are in the requests the operator approves per version by
digest. The approval page and `oarbank module approve` say "reads folder `inputs`" and "writes into folder `outbox`
(files it creates may replace files there)"; a version that adds a folder or changes its access needs a new approval.

**Resolution, per node.** The operator maps each folder id to a path **per node** in the folder registry, setting
`folder_registry` `{id: {"access": "read"|"write", "nodes": {node_id: path}}}`, operation `settings.folders.update`
(T2; the impact names the approved module versions that use the id and the nodes it changes). The registry's access must
equal the module's: a module that asks to read an outbox, or to write an input folder, is not granted it.

A path is an absolute path for the node's OS, not a root, no globs, no `..` (the coordinator's syntactic check, as for
tools). What the node accepts is decided **on the node** (below).

**Delivery, signed.** Releases are per platform and folder paths are per node, so paths cannot travel in a release.
Each node gets a **statement** (since core 2.9 the node statement, which also carries the host tool paths added for the
node: [host-tools.md](host-tools.md)): canonical JSON `{"type": "oarbank.node/v1", "fleet_id", "node_id", "seq",
"folders": {id: {"access", "path"}}, "tools": [...], "signed_at"}`, built by the coordinator whenever its content
changes, and sent in directives as `statement: {statement, signature}`. In signing mode (docs/release-signing.md) a node
accepts it only with a valid signature by the pinned release key and a seq above the last one it accepted, as for
releases: `oarbank node sign <node>` signs it on the owner's machine and uploads only the signature (operation
`nodes.sign_statement`). Until the owner signs, a node keeps applying the last statement it accepted. So a compromised
coordinator or admin account cannot point an approved module's folder at `~/.ssh`: it would need the owner's key. In
developer mode statements are unsigned. Which modules may use which folder ids still comes from the signed release's
module entries (`sandbox.folders: [{id, access}]`, the approved requests); the statement only says where they are.

**On the node** the agent checks every folder of an accepted statement when it accepts it, and reports the outcome per
id in each heartbeat (`folders: {id: {"access": "read" | "write", "status": "ok" | "<why not>"}}`):

- the path exists and is a directory; the agent keeps its **canonical** path (`realpath`; on Windows the final path of
  an opened handle), and grants exactly that;
- the canonical path is not a filesystem root, not the account's home directory itself, neither inside nor around
  Oarbank's data (the agent's home, and the `Oarbank` directory it sits in by default, beside a coordinator's), not a
  system directory (`/System`, `/usr`, `/bin`, `/sbin`, `/etc`, `/Library`, `/private/etc`, `/opt`, `/proc`, `/sys`,
  `/dev`, `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramData%`), and neither inside nor around any path the sandbox already grants (the base
  system roots, the bundles, the runtime), because a grant there would widen or contradict it (an outbox under `/opt`
  would be readable through the base system rule);
- it does not overlap another folder of the statement (an input folder inside an outbox would make the outbox
  readable, and the reverse would make inputs writable);
- on Windows the agent can edit the folder's ACL (below).

**Placement.** A job of a module that requests folders runs only on a node whose latest heartbeat reports every one
of them `ok` with the requested access, and whose sandbox enforces `folders.read` / `folders.write` (facts
`sandbox.enforcement`); otherwise it waits with `FOLDER_UNAVAILABLE` (new reason code, "Module {module} needs folders
{folders} that this node does not provide: {why}"; remedy `settings.folders.update`). Claim and explain use the same
predicate (D16).

**The runner** finds its folders in `OARBANK_FOLDERS_FILE`, `{"inputs": {"path": "<canonical path>", "access": "read"}}`
(like `OARBANK_TOOLS_FILE`; `oarbank_sdk.folders.path(id)` reads it). Only granted, `ok` folders are listed.

**Per-OS enforcement**

| | Read folder | Write folder (outbox) | Links |
|---|---|---|---|
| macOS (Seatbelt, profile 4) | `file-read*` on the subpath, no `file-map-executable` or `process-exec` | `file-write-create` for regular files and directories only, `file-write-data`, `file-read-metadata`; no `file-read-data` (no reading or listing), no unlink, rename, mode, owner or xattr changes | creating a symlink or a hard link in an outbox is denied (not a regular file or directory create); a symlink already inside a read folder that points out of it is denied at its target, which the profile does not grant |
| Linux (Landlock ABI 3+) | `ReadFile`, `ReadDir` beneath the folder | `MakeReg`, `MakeDir`, `WriteFile`, `Truncate`; no `ReadFile`, `ReadDir`, `RemoveFile`, `RemoveDir`, `MakeSym`, `Refer` or `Execute` | `MakeSym` and `Refer` are not granted, so no symlink is created and no file linked or renamed into or out of the folder; a symlink inside a read folder that leads out is denied at its target |
| Windows (AppContainer) | an inheritable allow entry `FILE_GENERIC_READ` | an inheritable allow entry for `FILE_ADD_FILE`, `FILE_ADD_SUBDIRECTORY`, `FILE_WRITE_EA`, `FILE_WRITE_ATTRIBUTES` and `SYNCHRONIZE` on the folder, which created files inherit as write-data rights; no `FILE_LIST_DIRECTORY`/`FILE_READ_DATA`, `DELETE`, `FILE_DELETE_CHILD`, `READ_CONTROL` or `WRITE_DAC` | an AppContainer cannot create symbolic links (the privilege is never in its token); a junction or symlink inside a read folder is checked at its target, which carries no entry for the job |

On Windows the entries are granted to a **capability SID derived for the module's runners**
(`DeriveCapabilitySidsFromName("oarbank.runner.<module>")`), which only a runner's AppContainer token carries (the
module's doctor, services and probes run without it), so a folder entry never reaches them. The agent adds an entry
when it first launches a runner that needs it and removes entries that no accepted statement or current release still
grants, whenever either changes and when it starts (it keeps what it granted in `state/folder-acl.json`). Adding an
inheritable entry walks the folder's tree once (Windows propagates it); removing one walks it again.

Execution: macOS and Linux refuse to execute anything from a folder. Windows cannot refuse executing a readable file
without application control (as for `exec_writable`), so a read folder's files are executable there; the approval page
says so for Windows nodes.

Nodes report `folders.read` and `folders.write` in `sandbox.enforcement`: `enforced` on macOS, on Linux with Landlock
ABI 3 or later (the agent's sandbox floor), and on Windows; `unavailable` otherwise.

**Threat model (folders)**

| Threat | Defence |
|---|---|
| A module reads the user's files through a folder it was never meant to have | Folders are per-version approved requests; the paths are the operator's per node, delivered in owner-signed statements in signing mode; the agent refuses homes, data roots, system directories and roots. |
| A compromised coordinator or admin account remaps an approved folder id to a secret directory | Signing mode: a statement needs the owner's release key and a rising seq. Developer mode trusts the coordinator for this as for everything else. |
| A symlink inside a read folder points at a secret elsewhere | Every backend checks the target, which the policy does not grant. The agent grants the canonical path, so a folder that is itself a symlink grants its target only. |
| The module plants a symlink or a hard link in an outbox for the user to follow later | Link creation is denied in outboxes on every backend (above). |
| The module learns what else an outbox holds, or deletes it | No read, list, unlink or rename rights in an outbox. It can replace a file whose name it guesses: put an empty, dedicated directory there (the approval page says so). |
| An outbox overlaps a read grant (or another folder) and becomes readable | The agent refuses overlaps with any sandbox grant and between folders. |
| A Windows grant outlives its approval or its mapping | Entries belong to a runner-only capability SID and are removed when no statement or release grants them, and at agent start. |
| A folder fills the disk | Out of scope: an outbox is the operator's directory on the operator's disk; the job's own limits apply to its process, not to the folder. |

Residual risks: Landlock cannot hide `stat` (an outbox file's existence and size can be probed by name); Seatbelt and
Landlock reveal whether a guessed path exists (ENOENT against EPERM); on Windows a read folder's binaries are
executable.

## #11 Media components (UI contract 1.1)

### Components

```json
{"type": "media", "requires": "1.1", "kind": "image", "source": {"view": "best"}, "field": "frame", "caption_field": "label"}
{"type": "gallery", "requires": "1.1", "kind": "image", "source": {"query": "results", "limit": 48}, "field": "preview",
 "caption_field": "seed", "columns": 4}
{"type": "compare", "requires": "1.1", "source": {"view": "pair"}, "left": "a", "right": "b", "mode": "slider",
 "labels": ["seed 1", "seed 2"]}
```

- `media`: one artifact of `kind` `image`, `video`, `audio` or `text`, from the first row of its source.
- `gallery`: a grid (2 to 8 `columns`) of `image` or `video` artifacts, one per row, with an optional caption field,
  each linked to its job when the reference names one. The grid shows each item's thumbnail when it has one.
- `compare`: two images side by side (`side_by_side`) or overlaid with a slider (`slider`, the console's own script).
- **Artifact references.** The field holds an artifact reference: `{"job": <job id>, "artifact": <name>, "path":
  <path>}` (a file of one of the job's canonical result's artifacts) or `{"digest": <sha256>}` (a blob the module can
  see: its files, its datasets, its jobs' artifacts, the operator's datasets). A digest reference may name a
  `thumbnail` digest; a job reference's thumbnail is the result file's own.
- **Views declare reference columns.** Only a view's declared columns reach the console, so a view that carries
  references declares them with the new cell type `artifact_ref` (core 2.5; a table shows the artifact and path, and a
  table column of that type needs `requires = "1.1"` like the components).
- **Ownership is the host's check, every render.** The console resolves each reference against the database: a job of
  this module with that artifact file, or a digest the module can see. Anything else renders as the placeholder "not
  this module's artifact" and no URL is made.
- **Fallback.** Each component sets `requires = "1.1"` and `fallback` (`placeholder` or `drop`). The renderer draws the
  fallback when its host renders an older minor; the SDK's page check refuses a 1.1 component without `requires`.

### Bytes only from the module origin

The console never serves media bytes. For each reference it passes the check for, it mints a **capability URL** on the
module origin (the listener that already serves sandboxed frames): `<module origin>/b/<token>`, where the token is the
module, digest, kind and an expiry (1 hour) signed with a key the console process holds in memory and shares only with
its frames listener (HMAC-SHA256). The frames listener has no sessions; the token is the authorization.

The frames listener, for `/b/<token>`:

1. verifies the HMAC and the expiry (403 otherwise) and finds the blob's file by digest (404);
2. **sniffs the first bytes** (`oarbank_sdk.media.sniff`) and serves only an allowlisted type for the token's kind,
   whatever the module claims or the file is named:

   | Kind | Allowed (by magic number) | Cap |
   |---|---|---|
   | `image`, thumbnails | PNG, JPEG, WebP, AVIF | 64 MiB (thumbnails 1 MiB) |
   | `video` | MP4 (ISO BMFF `ftyp` with a video brand), WebM (EBML with doctype `webm`) | 16 GiB |
   | `audio` | MP3 (ID3 or a frame sync), M4A (`ftyp` `M4A `), Ogg (`OggS`), WAV (`RIFF`/`WAVE`) | 1 GiB |
   | `text` | valid UTF-8 without NUL in the first 64 KiB; plain text, VTT, SRT and Markdown all served as `text/plain; charset=utf-8` | 4 MiB |

   Anything else, SVG and HTML included, is refused (415 `media_type_refused`); a file over its cap is 413;
3. answers with the sniffed `Content-Type`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox;
   default-src 'none'; frame-ancestors <console origin>`, `Cross-Origin-Resource-Policy: cross-origin`,
   `Referrer-Policy: no-referrer`, `Accept-Ranges: bytes`, `Cache-Control: private, max-age=<until expiry>`, and
   serves a single `Range` (206; 416 when unsatisfiable), so video seeks.

The console page shows images with `<img>`, video and audio with `<video>`/`<audio controls>` and text in an
`<iframe sandbox>` (an empty sandbox: no scripts, an opaque origin). Its CSP gains `img-src <module origin>` and
`media-src <module origin>`. So an SVG with a script is refused; an HTML file named `.png` is refused by the sniffer,
and would be inert anyway (served as an image type, `nosniff`, sandboxed); text is never HTML.

### Thumbnails from the module

The host never transcodes untrusted media. A runner may give any result file a thumbnail it made itself:
`artifacts[].files[]` entries take `thumbnail: {local}` (a small PNG, JPEG, WebP or AVIF in the workdir), which the
agent uploads like the file and replaces with `{digest, size}`. The gallery and video posters use it; a thumbnail that
is not an allowed image or is over 1 MiB is refused when served (the placeholder shows).

### Preview

`oarbank-sdk preview` resolves media references from fixtures (`fixtures/ui/media/<path>` or by digest) and serves them
with the same sniffer, so a module author sees what the console will refuse.

## #15 Portable checkpoints

### Manifest

```toml
[runner]
capabilities = ["cooperative_pause", "checkpoint"]
checkpoint_grace_s = 120           # from a checkpoint-then-stop request to the kill (default 120, 1..1800)

[[stages]]
name = "train"
checkpoint = { max_mb = 4096, min_interval_s = 600 }
```

- Runner capability `checkpoint`: the runner writes portable checkpoints, honours a checkpoint-then-stop request and
  resumes from `<W>/checkpoint/`.
- `stages[].checkpoint`: this stage keeps portable checkpoints. `max_mb` (1 to 65536, required): the largest checkpoint
  the agent uploads. `min_interval_s` (30 to 86400, default 600): the agent uploads at most one checkpoint per interval
  (the upload-rate cap); a checkpoint answering a checkpoint-then-stop request is always uploaded.
- Rules (spec/manifest.md rule 17, errors): a stage with `checkpoint` needs the runner capability `checkpoint`, and the
  capability needs at least one such stage; a bootstrap stage never checkpoints (it keeps nothing); `checkpoint`,
  `checkpoint_grace_s` and the capability need `requires.core >= 2.5`.

### Runner protocol

- **The checkpoint event.** A runner with `checkpoint` gets `--events` (as `progress_events` runners do) and writes
  `{"t", "kind": "checkpoint", "files": [{"path": "<workdir path>", "name": "<checkpoint path>"}], "data": {...}}`.
  `path` names a regular file in the workdir; `name` is where it appears in the checkpoint (default: `path`); both are
  PortablePaths; `data` is at most 4 KiB of JSON the runner gets back on resume. **Once written, the files belong to the
  agent**: it moves them out of the workdir, so a runner writes each checkpoint to new paths and never touches named
  files again. Only the latest checkpoint is kept.
- **Checkpoint, then stop.** The control document gains `checkpoint: true`, sent only with `stop: true`: "write a
  checkpoint at your next safe point, then acknowledge the stop". The agent nudges as for any change (SIGUSR1 or the
  control event) and sends no SIGTERM; the runner has `checkpoint_grace_s` to checkpoint and exit before the agent kills
  its container. A runner without the capability gets a plain stop.
- **Resume.** The next attempt, on any node, gets the job's latest checkpoint as read-only regular files under
  `<W>/checkpoint/<name>`, and its spec envelope says so: `resume: {from_attempt, digest, data}` (beta). `digest` is
  the sha256 of the canonical JSON list of `{name, digest, size}` sorted by name. A runner seeing no `resume` starts
  from the beginning.
- `oarbank_sdk.control` (stdlib only) adds `Control.checkpoint_requested`, `Checkpoints` (write a checkpoint into a
  fresh directory and emit its event; find the resume directory and `data`).
- **Determinism.** A resumed attempt must give the same result as an uninterrupted one (`results.determinism` and the
  stage's still apply): the result is judged and compared like any other.

### Agent

- **Reading events.** The job monitor reads the events file's new complete lines in the pass that already samples the
  runner's usage, log and phase (runner protocol 1 has no runner-to-agent signal; the events file is runner output like
  `phase`). The request to the runner is event-driven (control document and nudge), and so is the end of a
  checkpoint-then-stop (the runner's exit).
- **Taking a checkpoint.** For the latest checkpoint event of a stage with `checkpoint`: every `path` must be a regular
  file inside the workdir (`symlink_metadata`, PortablePath, no `..`), the names unique, the total at most `max_mb`, and
  the interval since the last upload at least `min_interval_s` unless it answers a request; otherwise the event is
  skipped with a line in the attempt log. The agent moves the files into `<agent home>/checkpoints/<attempt>/`, hashes
  them, links each into its blob cache (so the same node resumes without a download), uploads them through
  `/v1/uploads`, and records them: `POST /v1/attempts/{id}/checkpoint {seq, files: [{name, digest, size}], data}`.
  Uploads run one at a time per attempt; a newer event replaces one still waiting.
- **When protection releases a job** (a pause past its limit, an eviction, a hard cap, a drain) or its deadline comes,
  and the runner declares `checkpoint` on a stage with `checkpoint`, the agent writes `{stop: true, checkpoint: true}`
  instead of a plain stop, waits for the exit (at most `checkpoint_grace_s`, then kills), takes the last checkpoint the
  runner wrote, and finishes its upload (phase `checkpointing`, which keeps the lease) **before** it releases the
  attempt, so the next attempt finds it. A user cancel and a revoke stop as before.
- **Resuming.** A grant may carry `checkpoint: {files: [{name, digest, size}]}`. The agent stages each file from its
  cache or `GET /v1/blobs/{digest}` (no origins) and places it read-only under `<W>/checkpoint/<name>`.

### Host protection: checkpoint, then release

Protection's ladder does not change: throttle, pause, then evict. What eviction means for a checkpointing runner
does: "checkpoint, then release" instead of "stop" (above), so a pause past its limit costs the work since the last
checkpoint, not the whole job. The longest pause becomes an owner setting, `[node] max_pause_s` (10 to 600; default
600, so "at most 10 minutes" still holds) in protection schema 1, for owners who want a paused job off the machine
sooner (the end-to-end test sets 10 s).

### Coordinator

- **Table `checkpoints`**: one row per job (`job_id`, `generation`, `attempt_id`, `node_id`, `seq`, `digest`,
  `files_json`, `data_json`, `size`, `at`). `POST /v1/attempts/{id}/checkpoint` accepts a checkpoint from a live attempt
  of the node under the job's current generation, for a stage of the attempt's module version that declares
  `checkpoint`, at most `max_mb`, every blob held at its size. It replaces the job's row (a later attempt, or a higher
  seq of the same attempt), and the replaced files' blobs are released (deleted when nothing else names them). Event
  `checkpoint_recorded`.
- **Claim** passes the job's checkpoint when its generation is the job's: the envelope's `resume`, the grant's
  `checkpoint`, and the attempt row's `resume_json` (`{from_attempt, node_id, digest}`).
- **A checkpoint is valid for one generation of one open job.** Rows of jobs that are done, cancelled or quarantined,
  or of an older generation (a dispute, a conviction, a demoted head), are dropped by the reaper and their blobs
  released. A node convicted of nondeterminism has its checkpoints dropped with its results, and every done job whose
  canonical result resumed from one of its checkpoints is recomputed (`invalidate_node_results`).
- **Integrity.** A resumed result depends on the node that wrote the checkpoint as much as on the node that finished.
  So a result that resumed from **another** node's checkpoint is always replicated when its stage compares (a fresh
  run on a third node, compared as any replica), and convictions reach through checkpoints (above). A stage that does
  not compare gets no replica, as before.
- **Leases.** Phase `checkpointing` extends the lease like `staging`.
- **Explain** shows a pending job's checkpoint ("resumes from attempt N's checkpoint, 1.2 GB, 14 min old") and a
  running attempt's `resume`. The console's job page shows the checkpoint.
- **Invariant S23** (new): an attempt that resumes from a checkpoint names one recorded by an earlier attempt of the
  same job under the same job generation. It joins the catalogue (the Hypothesis machine, the simulator, the Verify page,
  `oarbank verify`).

### Conformance

For a stage with `checkpoint`, the runner suite replays an interrupted run: on its golden (else a runner spec of that
stage) it runs once uninterrupted; runs again and, once the runner has written its first `phase`, sends `{stop: true,
checkpoint: true}` (expecting the acknowledgement, exit 75 and a checkpoint event within `checkpoint_grace_s`); then runs
a third time in a fresh workdir with that checkpoint under `<W>/checkpoint/` and `resume` in its envelope. The resumed
result's digest (from `result.evaluate`) must equal the uninterrupted one ("resumes from a checkpoint with the same
digest"). Checkpoint events are checked too (regular files, unique names, within `max_mb`).

## Reference module: `examples/reel`

A second SDK example beside `toy` (which stays the smallest module and keeps its 2.1 floor): it renders deterministic
frames (PNG, written by the standard library), with thumbnails, and a short clip, for the three features:

- `render` stage (`checkpoint = {max_mb = 64, min_interval_s = 30}`, runner `checkpoint` and `cooperative_pause`): one
  frame per step, a checkpoint every few frames and on request, resuming from `<W>/checkpoint/`;
- an `import_asset` operation that registers an origin dataset (`datasets.create` with `origins`), and an importer,
  `adopt_upload`, that turns an uploaded dataset into one of reel's own; both run in the conformance fixtures and the
  core's tests;
- an overview page with a `gallery` of frames, a `media` video player and a `compare` slider, and no iframe;
- conformance fixtures with the checkpoint replay.

## Tests

SDK: manifest rules and the 2.5 floor; event, control, envelope and effect models; the media sniffer (every allowed
type, SVG, HTML disguised as PNG, truncated files); the page check's `requires`; `Checkpoints`; the sandbox profile 4
(golden text, read-only and write-only folders enforced on macOS by a real `sandbox-exec`: read, list, write, link and
delete each tried); conformance (the replay passing, and failing for a runner that resumes wrongly); `reel` conforms.

Core: the blob transport (resume, per-uploader partials, digest mismatch, limits, release); origins (create without the
blob, URL rule, policy at create and at manifest time, coordinator fallback fetch single-flight with a tee and digest
check, SSRF refused for loopback and private answers); `oarbank dataset upload` interrupted and resumed; downloads
(datasets and campaigns, resumed, digests); the console's upload and download routes; folder registry, statements (signed
and unsigned), placement (`FOLDER_UNAVAILABLE`), approval text; media (ownership refused for another module's job and
an unseen digest, token forgery and expiry, SVG and HTML-as-PNG refused, ranges, caps, the console's CSP);
checkpoints (record, replace and release, claim's resume, generation fencing, drop on done, forced replica, conviction
reach, S23 with a broken database, explain, the lease in `checkpointing`).

Agent: event parsing and taking files (symlink, outside, oversized, rate cap), the checkpoint-then-stop control
document, resume staging, folder checks (roots, homes, data roots, overlaps, symlinked folders), the Windows capability
SID grant and removal, the resumable upload. End to end (tests/rust): a module registers an origin dataset and a real
agent fetches it from an https origin while the coordinator never holds it; **a reel job paused past its node's limit is
checkpointed and released, moves to a second agent, and finishes from its checkpoint with the same result digest as an
uninterrupted run**; folders on a real agent (a read folder's file in the result, a file written into the outbox, a
read of the outbox refused). On Linux and Windows the agent tests and the folder enforcement run in the VMs.

## Open questions

Owner decisions this design took the conservative side of; each can be relaxed later without breaking anything.

- A module importer reads what it imports only through file names, sizes and digests (`host.datasets.query` with
  `with_files`); reading content would need a job. Kept: modules never read host disks.
- A folder's disk use is not limited. Kept out: it is the operator's directory.
- **Goldens and bootstrap jobs keep no checkpoints.** Certification runs a golden whole; a resumed golden would
  certify a node on another run's first half. The agent ignores their checkpoint events and the coordinator refuses to
  record one (422 `no_checkpoints`).
- **A disputed resumed result.** A result resumed from another node's checkpoint is always replicated on a third node.
  If the replica disagrees, the dispute runs between the finishing node and the replica's, as for any replica; the node
  that wrote the checkpoint is not charged unless it is convicted on its own record (a conviction then reaches every
  result resumed from its checkpoints). Charging the writer on every such dispute would need a three-party dispute.
- **The origin host policy is fleet-wide**, not per module: an operator who wants a module to reach only some hosts
  keeps the list short. A per-module list would be a new approved request in `[sandbox]`.
- **Windows read folders are executable** (no application control): the approval page says so for Windows nodes.

## Implementation status

Built as designed in oarbank-sdk 1.5.0 and core 2.5.0, with these changes found while building:

- **Views declare reference columns** with the new cell type `artifact_ref` (core 2.5, UI 1.1 in a table): a view's
  undeclared columns never reach the console, so a gallery's references were dropped on the way.
- **reel has an importer** (`adopt_upload`, `target = "dataset"`) beside `import_asset`, and an optional `asset` a
  render mounts and lists, so the end-to-end test can show a job reading an origin-only dataset.
- **The agent pins an origin's checked addresses** for the connection (`resolve_to_addrs`), as the coordinator does, so
  DNS rebinding cannot point either at the LAN.
- **The folder data-root rule** is the agent's home and the `Oarbank` directory it sits in by default, not whatever
  directory holds a custom `--home`.
- **The conformance kit also checks a resumed result's files exist** (a checkpoint that left out thumbnails passed the
  digest check but failed the agent's upload); fixture datasets' `dir` is relative to the module and their `files` feed
  `host.datasets.query {with_files}`.

Tests (automated; every acceptance criterion of the three issues has one):

| Criterion | Test |
|---|---|
| #10 origins: created without a coordinator round trip, fetched by nodes, the coordinator fetching only on failure | tests/test_origins.py; tests/rust/test_agent_files.py (a real agent through a redirect, the coordinator never holding the blob) |
| #10 streamed, resumable, digest-checked upload; CLI and console | tests/test_blobs.py, tests/test_transfer.py (an interrupted `oarbank dataset upload` resumes without resending), the console's staging routes and the browser hash (tests/js) |
| #10 usable by a module importer | tests/test_transfer.py (`adopt_upload`), SDK conformance fixture |
| #10 dataset and campaign downloads (CLI and console) | tests/test_transfer.py (resumed with `Range`, digest-checked, zips) |
| #10 folder grants: approval, registry, signed statements, placement | tests/test_folders.py |
| #10 per-OS enforcement | SDK tests/test_sandbox.py (Seatbelt profile 4 with a real `sandbox-exec`); tests/rust/test_agent_files.py on macOS and Linux (Landlock) with a real agent; rust tests/sandbox_windows.rs on Windows (capability SID entries) |
| #11 media, gallery, compare; ownership; sandboxed origin; allowlist; ranges; caps; nosniff; CSP | tests/test_media.py, SDK tests/test_files_media.py |
| #11 malicious artifact refused or inert | tests/test_media.py (an SVG with a script and HTML named `.png` refused, text never HTML) |
| #15 checkpoint events, upload, resume, control `checkpoint`, limits | agent unit tests (checkpoints.rs), tests/test_checkpoints.py, SDK conformance replay (and its failing variants) |
| #15 a job paused past the limit moves and finishes from its checkpoint with the same digest | tests/rust/test_agent_files.py, on macOS and Linux |

