# Oarbank agent protocol

The wire contract between **oarbankd** (the coordinator) and **oarbank-agent** (every node). Job types are modules:
bundles built on the open SDK. How the agent runs a module's job is **runner protocol 1** and how oarbankd talks to a
module's coordinator side is **module protocol 1**. Both are specified in the SDK (`vendor/oarbank-sdk/spec/`),
together with envelopes, bundles and services. The architecture is in docs/design/architecture.md and the decisions
in docs/design/PLAN.md.

All bodies are JSON (UTF-8). Times are Unix seconds as floats. Unknown fields must be ignored (forward
compatibility).

## Addressing and auth

- **Base URL.** The agent API's base URL comes from the agent config (`coordinator`): `https://<host>:7443`.
- **Identity first.** Before any credential is sent, the agent checks the coordinator's identity (see
  "Coordinator identity and moves"). An agent never follows an HTTP redirect.
- **TLS pin.** The agent listener's certificate is issued by the coordinator's internal CA (P-256). The CIK-signed
  identity payload names the CA's SPKI SHA-256 (`tls.ca_spki_sha256`, and `tls.ca_next_spki_sha256` during a CA
  rotation); the agent fetches the proof over TLS without verification, checks the signature against the key it
  pinned, and from then on verifies the listener against that CA only.
- **Credentials: mTLS (D29).** The node's identity is a client certificate for a P-256 key generated on the node,
  which never leaves it.
  - `POST /v1/agent/enroll` carries `csr` (PEM); after the owner approves, `GET /v1/agent/enroll/{id}` returns
    `cert_pem`, `ca_pem` and `cert_not_after` once.
  - Certificates last 30 days. The `renew_cert` directive (within 10 days of expiry) asks for
    `POST /v1/agent/cert {"csr"}`; the old certificate keeps working until the new one is first used.
  - The coordinator stores only certificate fingerprints. Retiring a node revokes its certificate.
  - When the peer address is a Tailscale IP, oarbankd also checks `tailscale whois` and rejects a certificate
    presented from another tailnet node.
- **Errors.** HTTP 4xx/5xx with `{"error": "<code>", "detail": "..."}`. The agent must handle:
  - `client_certificate_required`: the request reached the listener without the node's certificate;
  - `unauthorized` (an unknown or replaced client certificate): re-enroll;
  - `coordinator_moved` (410): follow the signed move statement in the body;
  - `stale_coordinator` (raised by the agent itself): the coordinator answered at a lower epoch; refuse it;
  - `node_retired`: stop;
  - `stale_generation` and `lease_lost`: drop the attempt and kill its process group;
  - `503 busy` with `Retry-After`: back off and retry. oarbankd is shedding load, for example while another
    process holds the database's write lock; nothing is lost.

## Agent config: `<agent home>/agent.json` (owner-only)

The agent home is `<data root>/agent` (docs/design/architecture.md, "Data roots"); its client key and certificate and
the pinned CA sit beside the config.
```json
{"coordinator": "https://100.64.0.10:7443", "enrollment_id": null, "node_id": "n_…", "heartbeat_s": 10,
 "manage_services": true, "release_seq": 0, "agent_seq": 0, "release_pubkey": null,
 "coordinator_trust": {"cik": "<base64>", "fleet_id": "fleet_…", "max_epoch": 1, "ca_spki_sha256": "…",
                       "ca_next_spki_sha256": null, "retired": [], "fallback": null, "pending_move": null,
                       "owner_keys": [], "owner_version": 0, "owner_rescue": []}}
```
- `manage_services: false` stops the agent from ever starting or stopping module services.
- `release_pubkey` and `owner_keys` are pinned on first sight in signing mode (docs/release-signing.md);
  `release_seq` and `agent_seq` are the highest signed seq installed (anti-rollback).
- `protection.json` beside the agent home is the owner's local protection file. The agent unions it with the central
  policy section, and the stricter setting wins.

## Enrollment

`POST /v1/agent/enroll` (no client certificate)
```json
{"hostname": "mini-a", "facts": { ...Facts... }, "csr": "-----BEGIN CERTIFICATE REQUEST-----…", "join": null}
```
→ `{"enrollment_id": "enr_…", "status": "pending"}`. A request without a CSR is refused (`csr_required`). With a
valid join code (`join`), the node is approved at once (`"status": "approved"`); a refused code leaves it pending
(`"join": "refused"`).

`GET /v1/agent/enroll/{enrollment_id}` → `{"status": "pending"}`, or exactly once after approval
`{"status": "approved", "node_id": "n_…", "cert_pem": "…", "ca_pem": "…", "cert_not_after": 1792592000.0}`; later
polls return `{"status": "claimed"}`. A rejected request returns `{"status": "rejected"}`.

**Facts** (version 2, sent on enroll and every hello; the platform token is `<os>-<arch>`, oarbank-sdk
spec/platforms.md):
```json
{"facts": 2, "hostname": "mini-a",
 "platform": {"os": "darwin", "arch": "arm64", "os_version": "27.0", "os_build": "26A123",
              "kernel": "25.0.0", "distro": null, "libc": null, "libc_version": null},
 "cpu": {"model": "Apple M5 Pro", "perf_cores": 5, "eff_cores": 10, "logical": 15}, "memory_gb": 24.0,
 "gpus": [{"vendor": "apple", "model": "Apple M5 Pro", "vram_gb": null, "unified": true}],
 "sandbox": {"backend": "seatbelt", "enforcement": {"filesystem": "enforced", "ipc": "enforced", "net.none": "enforced",
             "net.egress-allowlist": "enforced", "net.egress-any": "enforced", "no_loopback": "enforced",
             "gpu.compute": "enforced", "exec_writable_deny": "enforced", "no_link_local": "unavailable",
             "grants.bootstrap": "enforced"}},
 "disk_free_gb": 398.0, "addresses": ["100.64.0.11", "192.168.1.20"]}
```
- **Platform.** The coordinator stores the node's platform, OS, architecture and OS version in columns and
  re-certifies every module when the platform or OS version changes. A node of a platform the fleet has no
  release for gets one built when it enrolls.
- **Sandbox.** `enforcement` reports, per capability of the module sandbox contract (spec/sandbox.md), whether
  the node's backend enforces it: `enforced`, `cooperative` or `unavailable`. A module runs only where its
  always-on rules and its grants are `enforced`. A node without a `backend` gets no module work
  (`SANDBOX_BACKEND_MISSING`); a gap is `CAPABILITY_NOT_ENFORCED`. `grants.bootstrap` says the agent runs a bootstrap
  stage's jobs with the bootstrap grants (spec/sandbox.md, "Bootstrap jobs"); only such a node gets them.
- **Placement.** A module version runs only on the platforms in its `requires.platforms`, on OS versions in
  `requires.os`, and where the tool registry maps every approved `[sandbox].tools` id for the node's OS
  (`PLATFORM_UNSUPPORTED`, `OS_VERSION_UNSUPPORTED`, `TOOL_UNAVAILABLE`, `AGENT_TOO_OLD`).

`hostname` is the name the node reports: the machine's host name, or `OARBANK_NODE_NAME` in the agent's
environment when the owner names it. The coordinator names the node after it, unless the node enrolled with a
labelled join code (`oarbank join-code --label`): the label is then the node's name, and a reported `hostname` never
changes it.

## Session

`POST /v1/agent/hello` is sent on start, on wake, after a clock jump over 30 s, and on `recertify`.
```json
{"agent_version": "…", "boot_id": "…", "facts": {…}, "live_attempts": [123, 124], "release_id": "r_…",
 "ready_datasets": ["scene:atrium", …], "clock": 1790000000.2}
```
→ directives (below), plus `"kill": [124]`: live attempts oarbankd no longer considers live. The agent kills
their process groups, deletes their workspaces, and does not report them.

`POST /v1/agent/heartbeat` is sent every `heartbeat_s`.
```json
{"seq": 17, "clock": 1790000010.2,
 "telemetry": {"mem_used_gb": 14.1, "mem_free_pct": 31.0, "mem_pressure": 0, "swap_used_gb": 0.4,
               "thermal": 0, "on_battery": false, "user_idle_s": 912.0, "presence": "hid", "fleet_rss_gb": 6.4,
               "disk_free_gb": 350.2, "services_running": ["example/vm"], "services_reserved_gb": 8.0,
               "services_held": {"example/model": "preempt_memory"},
               "guard": "clear", "protection": {"mode": "moderate", "active": ["…"], "rules": [{"id": "…", "active": true,
               "processes": 3, "unreadable": 0, "cpu_cores": 0.5, "footprint_gb": 4.1}], "constraint": {…}, "rung": 0,
               "budget_cores": 6, "front": "app 812 (lsappinfo)", "source_error": null, "lowering": true}},
 "capacity": { …Capacity… },
 "attempts": [{"attempt_id": 123, "phase": "staging|running|<runner phase>|paused|checkpointing", "cpu_s": 55.2,
               "log_bytes": 10231, "rss_gb": 0.9}],
 "ready_datasets": ["scene:atrium", …], "doctor": null,
 "folders": {"inputs": {"access": "read", "status": "ok"}, "outbox": {"access": "write", "status": "not a directory"}},
 "journal": [{"t": 1790000000.1, "seq": 41, "kind": "rule_active", "reason": "PROTECTION_ACTIVE", "rule": "zoom"}],
 "processes": [{"pid": 812, "ppid": 1, "start_us": 1790000000000000, "path": "/Applications/…", "comm": "…",
                "argv": ["…"], "team_id": "ABCDE12345", "signing_id": "…", "bundle_id": "…", "cpu_cores": 1.2,
                "footprint_gb": 2.3}]}
```
- **`services_held`** names the services host protection stopped and holds down, with the release reason their jobs
  got (see Capacity and host protection).
- **`clock`** (hello and heartbeat) is the agent's wall clock when it sent the request. oarbankd records the node's clock
  offset from it (see Clocks).
- **`doctor`**, when present, is the latest doctor report (see Doctor).
- **`folders`** is the outcome, per folder id, of the folder statement the agent applied (see Folders).
- **`journal`** carries unacknowledged host-protection decisions, at most 200; oarbankd answers with
  `journal_ack`, the highest seq it stored.
- **`processes`** is the summary the console's process picker uses: the owner's processes by resource use,
  at most 80, the agent's own jobs excluded. The agent sends it every 5 minutes, or on the next heartbeat
  after `send_processes`. `comm` is the kernel's short name (the Windows image name); a null `path` or `argv` could
  not be read (another account's process), and a rule key that needs it counts as holding (a rule's `unreadable`
  counts the processes it matched that way).
- **Leases.** oarbankd extends `expires_at = now + 60 s` for each listed attempt that is live server-side and
  shows progress: `cpu_s` or `log_bytes` advanced, the attempt is `staging`, it is `paused` by host protection, or it
  is `checkpointing` (uploading a checkpoint before it releases). The agent bounds a pause at 10 minutes (less with the
  node's protection `[node] max_pause_s`, 10 to 600 s), then releases the attempt: after a checkpoint when the stage
  keeps them (see Checkpoints).

**Directives** (the answer to hello and to every heartbeat):
```json
{"node_id": "n_…", "now": 1790000010.4, "desired_state": "active|paused|draining", "lifecycle": "enrolled|ready|quarantined|retired",
 "limits": {…Limits…}, "policy": {…Policy…}, "heartbeat_s": 10,
 "release": {"release_id": "r_…", "url": "/v1/releases/r_….tar.gz", "sha256": "…", "statement": "…", "signature": "…"},
 "release_pubkey": null, "prefetch": ["tool:example-1.0", "scene:atrium"], "run_doctor": false, "recertify": false,
 "cancel": [125], "revoke": [126], "run_probe": false, "send_processes": false, "journal_ack": 41,
 "modules_disabled": ["example"],
 "folders": {"statement": "{…oarbank.folders/v1…}", "signature": null}}
```
| Directive | Meaning |
|---|---|
| `now` | oarbankd's clock when it answered (see Clocks). |
| `release` | The release this node must run: its own composition, or the current one (see Releases). `null` when the node already runs it. `statement` and `signature` are present only with release signing. |
| `cancel` | Stop the attempt and `release(reason=user_cancel)`. |
| `revoke` | Another attempt won, or the module was disabled: kill silently, no report. |
| `run_doctor`, `recertify` | Run every module's doctor again; send hello again (certification restarts). |
| `run_probe` | Run a host-protection pause probe at the next tick (from `protection.probe_now`). |
| `send_processes` | Send a process summary (the rule editor's preview is open). |
| `modules_disabled` | Modules the owner disabled (the kill switch, `modules.disable`): every service of theirs is disabled on the node (stopped, never offered) until they are enabled again. |
| `folders` | This node's latest folder statement and the owner's signature (`null` in developer mode, or until the owner signs); `null` when no folder is mapped here (see Folders). |

## Work

`POST /v1/agent/claim`
```json
{"free_cpu": 3, "free_mem_gb": 6.0, "modules": ["example", "toy"], "release_id": "r_…",
 "ready_datasets": ["tool:example-1.0", "scene:atrium", …], "pool_jobs_only": false, "gpu_jobs": null}
```
oarbankd grants jobs:

- whose resources fit `free_cpu` and `free_mem_gb`;
- whose module is offered in `modules` (its doctor reported healthy) and certified on this node, or, for a job of a
  bootstrap stage (docs/design/bootstrap-stages.md), certifying there, on a node whose facts report `grants.bootstrap`;
- whose datasets are all registered (else `DATASETS_NOT_REGISTERED`) and in `ready_datasets`;
- whose pool needs fit the node's pools;
- whose stage's `requires.capabilities` the node has for the module, by its latest doctor report (see Doctor);
  otherwise the job waits with `STAGE_CAPABILITY_MISSING`;
- whose stage's secrets (`stages[].secrets`) each have a value the coordinator can read for this node (its own, else
  the module's); otherwise the job waits with `SECRETS_NOT_SET` (docs/design/secrets-and-signed-images.md).

With `pool_jobs_only`, only jobs reserving pools are granted. `gpu_jobs` is how many more GPU jobs the node
may run, with `null` meaning no limit. A GPU job is one whose module's `runner.gpu` is not `none`, or that reserves a pool
of a service whose `gpu.use` is not `none`; it waits with `GPU_BLOCKED` while the node's live GPU jobs reach that number.

→ `{"grants": [Grant, …]}`, possibly empty. A **Grant** carries a SpecEnvelope:
```json
{"attempt_id": 812, "job_id": 90, "job_key": "…", "generation": 1, "kind": "eval|call|golden|replica",
 "module": "example", "issued_at": 1790000000.0, "expires_at": 1790000060.0, "hard_deadline": 1790001900.0,
 "spec": {"envelope": 1, "schema": "example/spec@1", "module_id": "org.example.module", "module_version": "2.1.0",
          "job_key": "…", "stage": null, "protocol": 1, "platform": "darwin-arm64",
          "datasets": ["tool:example-1.0", "scene:atrium", "data:textures-1"],
          "mounts": {"scene:atrium": "scene", "data:textures-1": "textures"}, "inputs": {}, "resources": {"cpu": 1, "mem_gb": 2.0},
          "timeout_s": 1800, "payload": {…the module's own spec…}},
 "checkpoint": {"files": [{"name": "state.json", "digest": "sha256…", "size": 812}, …]}}
```
- **`module_version`** is the version this node runs: its pin, its canary, or the current version.
- **`resources`** is what the stage reserves on this node's platform (the stage's variant for it applied); the agent
  accounts running jobs by it.
- **`timeout_s`** is the stage's timeout on this node's platform (or the job's own); `hard_deadline` follows it.
- **`checkpoint`** and the spec's **`resume`** (`{"from_attempt", "digest", "data"}`) are present when the job resumes
  from a checkpoint an earlier attempt recorded (see Checkpoints).
- **`issued_at`**, `expires_at` and `hard_deadline` are oarbankd's clock. The agent stops the attempt
  `hard_deadline - issued_at` seconds after the grant arrived, on its monotonic clock (see Clocks).
- **`secrets`** (only for a job whose stage lists secrets): `{name: value}`, resolved for this node. The agent writes
  them to `<ws>/.grants/secrets.json` (mode 0600; on Windows the work directory's protected DACL) and sets
  `OARBANK_SECRETS_FILE`; they are never part of `spec`, never stored by oarbankd and never written to the agent's log.
  The agent replaces exact copies of a value (6 bytes or more) with `[secret:<name>]` in the log chunks it streams and in
  `stderr_tail`, holding back the last bytes of the log until it knows a value is not split across two chunks.
- **`images`** (only for a job that listed them in jobs.enqueue): the container set images its runner may run. The
  broker refuses any other set image.

**Clocks.** oarbankd's clock is the fleet's: every absolute time it sends (a grant's deadlines, a move statement's
`not_before` and `expires`) is in it, and a node's wall clock may be hours off. The agent never compares such a time
with its own wall clock. A grant's deadline becomes a local monotonic deadline when the grant arrives; a move's times
are compared with oarbankd's clock as the agent last saw it (`now` in every directive and in a 410's body; before the
first answer, its own clock). Certificates and update metadata are checked against the node's own wall clock, and a
failure says what that clock reads, so a skewed clock shows as one. oarbankd records each node's clock offset
(`clock` minus its own time at hello and heartbeat); an offset over 60 s shows as the node condition `CLOCK_SKEW` in the
console and in the node's explain.

**Running a job** (runner protocol 1, in the SDK's spec/runner-protocol.md):

1. The agent builds the attempt's work directory by placing every dataset file at `<mount>/<path>` as a read-only
   regular file (a clone or hardlink where the filesystem allows, else a copy), never a symlink: a container mounting
   the work directory would see dangling links.
2. It writes `spec.json` and `control.json` (`{"seq": 0}`).
3. It spawns the runner from the release's `runner.exec` (the `python` token and `{bundle}` resolved), with an argv
   array, no shell, in its own process container (process group, cgroup or Job Object), under the module sandbox, with
   exactly the environment of runner protocol 1 (spec/runner-protocol.md, "Environment"): `OARBANK_WORKDIR`,
   `OARBANK_TMP`, `OARBANK_MODULE_DATA`, `OARBANK_PLATFORM`, `OARBANK_MODULE`, `OARBANK_ATTEMPT_ID`,
   `OARBANK_PROTOCOL`, `OARBANK_SETTINGS_FILE`, `OARBANK_TOOLS_FILE`, `OARBANK_FOLDERS_FILE`,
   `OARBANK_POOL_<NAME>_TOKENS`, `OARBANK_DISABLED_SERVICES`, `OARBANK_BROKER` (container modules),
   `OARBANK_SERVICE_<NAME>` (a connector to each endpoint service of the module providing a pool the stage reserves),
   the proxy variables (egress-allowlist) and the
   OS's conventional variables, then the module entry's `runner.env`. Nothing is inherited. An entry whose env names
   a reserved variable (`OARBANK_*` or the SDK's `RESERVED_ENV`, compared case-insensitively) is refused: the job
   fails and the doctor reports unhealthy.
4. The runner writes a `ResultEnvelope` (`payload`, `effective`, `provenance`, `artifacts`) and exits 0; or it
   writes `failure.json` (`{reason, detail, fault?, retryable?}`) and exits non-zero (2 = the spec can never
   succeed, 3 = a missing node dependency, 75 = transient; these count only with `failure.json`).

The runner's own phases, written to `<ws>/phase`, show in the console. Host protection may stop, pause, freeze or
throttle a running job, but only as the runner declares it tolerates: `cancellable`, `cooperative_pause`,
`freeze_ok` and `cooperative_throttle` (the control document; the agent nudges the runner after every change: SIGUSR1 on POSIX, the inherited `OARBANK_CONTROL_EVENT` on Windows).

**Results and endings**

- `POST /v1/attempts/{id}/log`: a `text/plain` body appended to the attempt log.
- `POST /v1/attempts/{id}/complete` with `{"idempotency_key": "att-123-complete", "result": <ResultEnvelope>, "images"?: [{"set", "image"}]}`
  → `{"accepted": true, "canonical": true, "reason": "ok"}`. Replays return the stored response. The module's
  `result.evaluate` judges the envelope; while the module cannot answer, oarbankd returns 503 with
  `Retry-After` and charges nothing (S15). The `accepted: false` reasons are:
  - the module's verdict (`mode_mismatch`, or a module code `<module>/<code>`);
  - `golden_mismatch`, `stale_generation` and `job_done` (compared as a replica);
  - `release_invalid`, `attempt_closed` and `dispute_party`;
  - `node_quarantined` and `node_retired`;
  - `artifact_missing`, `input_missing` and `input_mismatch`;
  - `pin_mismatch`: a bootstrap job's result is not exactly the module's pinned datasets. For a bootstrap job the host
    checks the pins instead of calling `result.evaluate`, and registers the datasets when the result is accepted.
- `POST /v1/attempts/{id}/release` with `{"reason": "preempt_memory|preempt_protection|limit_mem|limit_cpu|limit_schedule|user_cancel"}`;
  a release without a reason is refused (400 `reason_required`). These are not failures.
- `POST /v1/attempts/{id}/fail` with `{"reason": "exit_nonzero|oom|timeout|no_metrics|mode_mismatch|bad_input|doctor|input_missing", "exit_code": 1, "stderr_tail": "…", "fault": "job|host|transient", "images"?: [{"set", "image"}]}`.
  `fault` comes from the runner's `failure.json`: `transient` is no failure at all (the attempt is released and
  the job retried), `host` implicates this node, `job` never trips its breaker. `doctor`, `mode_mismatch`, `oom` and
  `no_metrics` implicate the host first.
- **Retries.** A failure spends one of the job's attempts when its end reason's code counts against the job
  (docs/design/reason-codes.md; a runner's own reason counts): a host fault does not, and sends the job to another node.
  The job stays pending with backoff while some ready node certified for its module may still try it, its stage's
  `retry.max_attempts` (the stage variant for that node's platform) above the job's failures; otherwise it is
  quarantined. A node whose platform's attempts are spent is skipped (`RETRIES_EXHAUSTED`), and explain shows the
  retries left on each node. Golden jobs count failures per node and module instead (a node stops certifying after 3).
- Every end reason has a reason code; docs/design/reason-codes.md lists them per code.
- **`images`** on complete and fail: the container set images the attempt's broker verified and ran. oarbankd records
  each digest's first run per module (`module_images`, the event `container_image_first_run` and an audit row
  `containers.first_run` by `node:<id>`).

**Artifacts.** A runner lists output files as `artifacts: [{name, files: [{path, local, thumbnail?: {local}}]}]`.
Before completing, the agent uploads each file (and its thumbnail) as a blob (see Uploads) and reports `{path, digest,
size}` (`thumbnail: {digest, size}`). On the canonical completion, oarbankd registers each artifact as the
content-addressed dataset `art:<…>`, served through `/v1/blobs/<digest>`.

**Uploads** (artifacts and checkpoint files; the core of tus 1.0, the digest naming the upload):

- `POST /v1/uploads/{digest}` with `{"size": N}` → `{"offset": k, "complete": bool}`: where this node's upload stands;
  `complete` when oarbankd already holds the blob, so nothing is sent.
- `PATCH /v1/uploads/{digest}` with `Upload-Offset: k` and the bytes → 204 with the new `Upload-Offset`; at `size`,
  oarbankd checks the sha256 and registers the blob (`Upload-Complete: 1`) or drops the partial (422
  `digest_mismatch`). A wrong offset is 409 `offset_mismatch` with the current one in `Upload-Offset`.

The agent sends 8 MiB chunks and, after a failure or a restart, asks again and goes on from the offset. Partials are
per uploader, so two nodes uploading the same digest never mix their bytes. A blob is at most `BLOB_MAX_BYTES`.

**Checkpoints.** A runner that declares the `checkpoint` capability, on a stage the release marks with `checkpoint =
{max_mb, min_interval_s}`, announces checkpoints in its events file: `{"kind": "checkpoint", "files": [{"path",
"name"}], "data"}` (spec/runner-protocol.md, "Checkpoints"). The agent moves the files out of the workdir at once,
uploads them (at most `max_mb` in all; a periodic one sooner than `min_interval_s` after the last is skipped) and
records the checkpoint with `POST /v1/attempts/{id}/checkpoint` `{"seq", "files": [{"name", "digest", "size"}], "data"}`
→ `{"recorded": bool, "digest"}`. oarbankd keeps each open job's latest checkpoint for its current generation and drops
it when the job is done. Bootstrap jobs and goldens keep none.

When host protection releases an attempt whose runner keeps checkpoints (a pause past the limit, a memory or schedule
limit), the agent writes `{"stop": true, "checkpoint": true}` to the control document instead of signalling: the runner
writes a checkpoint at its next safe point and exits 75 within `runner.checkpoint_grace_s`. The attempt shows the phase
`checkpointing` while the files upload, then is released. The job's next attempt, on any node, gets the files read-only
under `<workdir>/checkpoint/` (the grant's `checkpoint`, staged like dataset files) and `resume` in its envelope. A
result resumed from another node's checkpoint is always checked by a replica on a third node, and a node convicted of
nondeterminism takes the results resumed from its checkpoints with it.

## Datasets and staging

`GET /v1/datasets/{dataset_id}` → its manifest:
```json
{"dataset_id": "scene:atrium", "files": [{"path": "atrium.scene", "digest": "sha256…", "size": 65000000,
  "origins": ["https://data.example.org/scenes/atrium.scene"]}, …]}
```
- **Origin first.** Agents download from the origin first, hashing while streaming into
  `<agent home>/cache/tmp/<digest>.partial`, then rename it into `<agent home>/cache/blobs/<digest[0:2]>/<digest>`.
  An origin is `https` to a host name (never an IP literal) whose every address is public; the agent connects to the
  addresses it checked, and follows at most 5 redirects, each to a URL under the same rule. The manifest lists only
  the origins the operator's origin host policy (setting `dataset_origins`) admits. On an origin failure or a digest
  mismatch the agent falls back to `GET /v1/blobs/{digest}` (oarbankd, range-capable).
- **Origin-only blobs.** A dataset may name a blob oarbankd does not hold (registered by URL and digest). When a node
  asks for one, oarbankd fetches it from the origins under the same rule, once however many nodes ask (later requests
  follow the same fetch), streams it to them as it arrives, and keeps it only if its size and sha256 match. No origin
  answering is 502 `origin_failed`.
- **Resumable.** Partials survive failures and agent restarts and are dropped after 7 days. A download
  resumes with `Range: bytes=<size>-`, pre-hashing the bytes already on disk:
  - 206 appends the rest;
  - 200 means the range was ignored, so the file restarts;
  - 416 discards the partial.

  The final SHA-256 check guards every blob.
- **Ready.** A dataset is ready when every file is present and verified. `prefetch` names registered datasets to
  stage ahead of need.

## Folders

An operator maps the folder ids modules ask for (`[sandbox].folders`, approved per version) to a path per node in the
folder registry (`settings.folders.update`). Each node gets a **folder statement** in its directives: canonical JSON
`{"type": "oarbank.folders/v1", "fleet_id", "node_id", "seq", "folders": {id: {"access": "read"|"write", "path"}},
"signed_at"}` and a signature. With release signing the agent applies a statement only with a valid signature by the
pinned release key (`oarbank folders sign <node>`) and a seq above the last one it applied; in developer mode statements
are unsigned. The agent checks each folder (an absolute, existing directory, granted by its canonical path; not a root,
a home directory, Oarbank's data, a system directory or a path the sandbox already grants; no two folders overlapping),
keeps the outcome in `state/folders.json` and reports it in every heartbeat. A job of a module that asks for folders is
placed only where every one of them reports `ok` with the access asked for (else `FOLDER_UNAVAILABLE`). The runner gets
the granted folders in `OARBANK_FOLDERS_FILE`, read folders read-only and write folders as outboxes it can create and
write files in but never read, list or delete (the SDK's spec/sandbox.md, "Folders").

## Releases

A release is **per platform** and composed from the coordinator's module store (`oarbank module install`, then
enable, canary, promote; see the SDK's spec/bundles.md). For each module with a current version that supports the
platform, it holds the bundle of the version the node runs:
```
<release>/MANIFEST.json            every file: path, sha256, mode
<release>/modules.json             {"format": 2, "platform": "darwin-arm64", "modules": [Module, ...]}
<release>/modules/<name>/...       the module's bundle files a node of the platform receives
```
A bundle's `[bundle.platform_files]` decides which files each platform's release carries (unmatched files go
everywhere), and of `wheels/` only the wheels that install on the platform go; the coordinator keeps the whole bundle.
**Module** entry, rendered for the release's platform (the runner variant for it applied; services and probes
limited to it). Execs stay unresolved argv: the agent replaces the `python` token with the module environment's
interpreter and `{bundle}` with the module's bundle directory (`modules/<name>` under the release).
```json
{"name": "example", "module_id": "org.example.module", "version": "2.3.0", "digest": "h2:…",
 "bundle": "modules/example", "requirements": "requirements.txt", "requires": ["java17"],
 "stages": [{"name": "call", "capabilities": ["java17"], "pools": [], "platforms": []}, …],
 "runner": {"exec": ["python", "-I", "{bundle}/node/main.py"], "runtime": "python",
            "capabilities": ["cancellable", "freeze_ok", "cooperative_throttle"], "stop_grace_s": 20.0,
            "gpu": {"use": "none", "apis_any": [], "min_vram_gb": null, "in_container": false}, "bandwidth_class": "medium",
            "env": {"OMP_NUM_THREADS": "1"}},
 "services": [{"name": "…", "exec": ["{bundle}/node/svc"], "lifecycle": "on_demand", "provides": {"pools": ["…"]},
               "freeze_ok": false, "endpoint": true, "gpu": {"use": "shared", "apis_any": ["metal"]}, …}],
 "probes": [{"name": "java17", "exec": ["{bundle}/node/probes/java17"], "period_s": 3600}],
 "sandbox": {"contract": 1, "net": {"mode": "egress-allowlist", "allow": ["api.example.org"]},
             "tools": [{"id": "java17", "trust": "code-exec", "paths": ["/opt/homebrew/opt/openjdk@17"]}],
             "devices": {"gpu": "none"}, "exec_writable": false, "containers": []}}
```
A stage's `platforms` limits where its jobs are granted (empty: every platform of the module). A service's `endpoint`
and `gpu` are present only when the manifest sets them (docs/design/service-endpoints.md). `runner.env` is
`[runner].env` with the platform's variant merged, present only when the manifest declares one.
`runner.bandwidth_class` (`low`, `medium` or `high`) is present only when the manifest declares it. Host
protection uses it to pick rungs when the harm is to a GPU-bound protected group (docs/design/protection.md).
`sandbox.tools`
carries the host paths the operator's tool registry (`settings.tools.update`) maps each approved tool id to on the
release's OS. `sandbox.container_sets` (present only when the manifest declares sets) carries each approved set with its
public key: `[{"name", "registry", "repository", "platform", "key": "<PEM>", "index"?}]`; the agent verifies a set
image's cosign signature (or its index membership) with it before the runtime pulls the image.
- **Fetch.** `GET /v1/releases/{release_id}.tar.gz` serves the tarball; its sha256 comes with the
  `release` directive.
- **Install.** The agent verifies the tarball and every MANIFEST entry's digest and mode. It creates one
  environment per module that needs one and installs the module's `requirements` into it offline, from the wheels
  pinned by hash in the bundle and inside the sandbox, then switches its current release atomically and runs the
  doctors.
- **Equal compositions are one release.** Each platform's default composition is its current release. A canary
  or pinned node gets its own release in its directive.
- **Signing** is on by default (D31; `OARBANK_RELEASE_SIGNING=0` is developer mode): a release is the signed lock of
  module digests, and agents pin the key and refuse unsigned and rolled-back releases (docs/release-signing.md). The
  platform is bound into the signed sha256 through `modules.json`.

## Agent self-update

The coordinator keeps oarbank-agent builds by sha256 and one channel per platform: current, previous, and a
canary on chosen nodes (`agent.upload`, `agent.canary`, `agent.promote`, `agent.rollback`, `agent.sign`;
`oarbank agent …` or the console's Agent page). No step uses ssh.

- **Upload.** The coordinator never runs an uploaded binary. It reads the platform from the executable's headers
  (64-bit Mach-O, including universal binaries; ELF; PE) and the version from the marker every build embeds,
  `oarbank-agent-version:<semver>` followed by a NUL byte. A build can serve only nodes of its platforms.

- **Report.** hello and heartbeat carry `agent_build` (the sha256 of the running binary) and `agent_update`
  `{state, target, version, error, at}`. States: `idle`, `staging`, `draining`, `restarting`, `confirming`,
  `confirmed`, `failed`, `rolled_back`, `blocked`.
- **Directive.** While a node's assigned build (the canary on canary nodes, else current; none before the
  first promotion) differs from `agent_build`, every hello and heartbeat reply carries
  `agent_update: {sha256, version, size, url, statement?, signature?}` (`statement`/`signature` in signing
  mode). Agents built with the vendor's TUF root also verify the build against the vendor metadata the coordinator
  mirrors (`GET /v1/tuf/{name}`). `GET /v1/agent/builds/{sha256}` serves it to nodes it is assigned to; it is `null` otherwise, and an
  update not yet swapped in is abandoned when it disappears.
- **Agent.** It downloads into `versions/.incoming/` and checks the sha256 and size, that the file is an
  executable for its own platform (headers) and that its embedded version marker is the directive's version; in
  signing mode with a pinned key it also checks the statement (`{"agent_sha256", "version", "platforms", "seq",
  "signed_at"}`: its platform listed, seq above the installed one). It never runs the download. It installs it
  beside the running version as `versions/<version>-<sha12>/oarbank-agent`, then drains: no new claims, running
  attempts finish (they do not survive a restart). Drained, it records `state/upgrade.json {state: "staged",
  target}` and exits 75. The new agent claims nothing until its first successful hello and heartbeat, which
  confirm it.
- **Rollback, on the node.** The service manager runs `oarbank-launcher`, never the agent; updates never replace
  the launcher. The launcher owns `current` (a symlink to the running version): on a staged update it moves it to
  the target and starts it on trial. A version that has not confirmed itself within three starts goes back to the
  previous one, and the new agent gives up by itself (exit 75) if not confirmed within 600 s. Either way the next
  agent reports `rolled_back` with the reason, and does not retry that build: never after a failed start or a
  verification failure, and not for 6 hours after a missed confirmation (the coordinator may have been down). An
  agent not started by the launcher reports `blocked` and does not update itself.
- **Promotion** is refused until every canary node reports running the canary build and has heartbeated in
  the last 120 s. In signing mode canary and promotion need a signed build.

## Coordinator identity and moves

Agents trust a key, not a URL (design: docs/design/coordinator-move.md).

**Identity.**
- oarbankd has a coordinator identity key (CIK, Ed25519, in `<home>/coordinator_key`; it never leaves the
  machine), a `fleet_id`, an epoch, and a role: `active`, `standby` or `handed_off`.
- `GET /v1/identity?nonce=<n>` returns `{payload, sig}`. The payload is canonical JSON naming the fleet,
  epoch, role, key and nonce, and is signed with the CIK.
- At each hello (and before enrolling), the agent checks the signature over the exact payload bytes, the nonce,
  and the key and fleet it pinned. It pins them on first use; the owner then confirms each node's pinned
  fingerprint once (`nodes.confirm_identity`).
- Every agent-API answer carries `X-Oarbank-Epoch` and `X-Oarbank-Role`.
- The agent keeps the highest epoch it has seen and refuses any coordinator answering below it. A restored or
  stale old coordinator is therefore harmless.

**Moves.**
- Hello and heartbeat replies carry `coordinator_move: {statement, signatures: {from, to, owner?}}`. The
  statement is canonical JSON: `type`, `fleet_id`, `move_id`, `epoch` (exactly the agent's epoch + 1),
  `from: {url, cik}`, `to: {url, cik, ts_stable_node_id}`, `not_before` (the time lock), `expires`, `prev`.
- The agent records it as pending (an fsync, reported as `coordinator_move_state`) only if all of these hold:
  - `from` verifies against the key it trusts, and `to` against the named key;
  - with owner keys pinned, `owner` verifies against one of them;
  - the epoch is exactly +1;
  - the target key is not retired.
- `coordinator_move_cancel: {payload, sig}`, signed by the current key, drops it.
- **Following**, after `not_before`, in this order:
  1. the target's address is a tailnet address whose `tailscale whois` StableID matches the statement (when
     named);
  2. the target's identity proof verifies with `to.cik`, shows role `active` at the statement's epoch, and
     names the same fleet;
  3. a hello to the target with the node's client certificate succeeds (the target holds the fleet's data and CA).
- Only then does the agent commit: new URL and key, epoch raised, old key retired, old URL kept as a fallback
  for fetching the chain.
- A target that is not ready yet is retried; an identity failure is reported and backed off, never answered by
  going back to the old coordinator.
- A handed-off coordinator answers every agent call `410 coordinator_moved` with the statement.
  `GET /v1/coordinator/moves?since_epoch=<n>` returns the committed chain, which an agent offline across
  several moves walks one epoch at a time: an agent whose coordinator's identity proof shows `handed_off` while it
  holds no statement (it was away through the time lock, or the freeze came before a heartbeat carried the
  statement) reads the chain there, records the next move and follows it.
- **Signing mode.** Agents built with release signing also pin the owner key set (`owner_anchors`), and
  accept a new set only at version + 1 when signed by a key of the old set and every new key. A move then needs
  the `owner` signature. `owner_security` turns signing off only when an owner key signs it.
- **Rescue moves.** An owner-signed move with `"rescue": true` needs no signature from the lost or compromised
  coordinator. Agents read `{"coordinator_move": {statement, signatures: {owner, to}}}` from the owner key set's rescue
  locations once their coordinator has been unreachable for 30 minutes (then every 10 minutes while that lasts), and
  every 6 hours in any case; a statement found there is verified and followed like any other. The target takes the
  fleet over from a copy of the old home and trusts the old CA for the nodes' certificates until they renew
  (docs/design/coordinator-move.md, "If something goes wrong").

**The move channel between coordinators.** These routes are not for agents:
- the standby pairs with a single-use code, then authenticates with a move token and its tailnet identity:
  `/v1/move/pair`, `manifest`, `file`, `snapshot`, `snapshot-file`, `status`, `ready`, `commit`. Pairing names the
  standby's platform (`b_platform`); enabled modules whose coordinator side does not run there block the move unless
  it is forced, and a forced move's target disables them with an alert;
- the old coordinator signs its calls to the standby with its CIK: `sign-statement`, `promote`;
- an enrolled target's agent downloads the coordinator bundle from `/v1/move/bundle/{sha256}`, as ordered by
  `install_coordinator`.

## Services and probes

A module's services, such as a VM, follow service protocol 1 (the SDK's spec/service-protocol.md).

- **Starting.** A service starts on demand when an admitted job needs its pools, gated on its readiness
  check.
- **Stopping.** It stops after its idle timeout, under a memory floor if it is yieldable, or after a drain.
- **Failures** back off, then withdraw the service.
- **Restarts and cleanup.** A running service is adopted after an agent restart (an endpoint service is stopped and
  started again instead: its channel ended with the old agent). Objects a service created for attempts that no longer
  exist are reaped through its label-scoped `list_owned` and `destroy`.
- **Endpoints** (docs/design/service-endpoints.md). An endpoint service gets its endpoint channel at `start` and is
  ready once it has said hello on it; each attempt reserving one of its pools gets a connector, and every connection it
  opens is a fresh connected pair whose ends the agent hands to the job and to the service (SCM_RIGHTS on macOS and
  Linux, handles duplicated into a member of the right Job Object on Windows). When the attempt ends, its container is
  killed, its connectors close and the service gets `ended`. The facts report `endpoints` enforced in the sandbox
  enforcement map; a module with an endpoint service is placed only there.
- **Kill switch.** The services of a module in `modules_disabled` are disabled: stopped once no attempt uses them.
- **Probes** provide capabilities, such as `java17`, on a period.

## Doctor

For each module the agent runs the runner's exec with `doctor --json`, sandboxed, with the job environment. The runner
prints a `DoctorOutput`, whose `health` decides: `healthy`, `unhealthy` (it should work here but something is
broken) or `undetected` (this node cannot run it). The agent folds in its own capability checks (the module's
`requires`, from probes and services, and the GPU APIs its runner names) and reports:
```json
"doctor": {"at": 1790000000.0, "release_id": "r_…", "capabilities": ["java17"],
           "gpu_apis": {"host": ["metal", "opencl"], "containers": ["vulkan"],
                        "evidence": {"metal": "Apple M5 Pro", "cuda": "CUDA does not run on macOS", "…": "…",
                                     "containers": "virtio-gpu:venus (krunkit)"}},
           "modules": {"example": {"health": "healthy", "checks": [...], "capabilities": ["gatk4"]},
                       "toy": {"health": "undetected", "checks": [...]}}}
```
`capabilities` are what the node's offered services and healthy probes provide when the doctors ran (the agent runs
them again when that set changes); a module's `capabilities` are its own doctor's. Together they are the node's
capabilities for that module: a job is granted only where they hold every capability its stage requires
(`stages[].requires.capabilities`), and a unit of work binds only to a class with such a node.
`gpu_apis` are the GPU APIs the node provides on the host and inside its containers, each detected by asking the API's
runtime for a GPU device (`oarbank-agent gpu-apis` prints the same object; docs/design/gpu-placement.md), with what was
found or why not per API. The agent probes at start and whenever its doctors run, never on a timer. A job is granted
only where every GPU API group its stage needs is met (`GPU_API_MISSING`; the runner's `gpu.apis_any` for the node's
platform, on the host or with `in_container` in containers, and those of GPU services it reserves a pool of); a module
whose runner needs an API the host lacks is not offered there (the agent reports it `undetected`, with a `gpu_apis`
check) and is excluded by oarbankd. A node that has not reported provides none.
Only `healthy` modules are offered in claims. oarbankd records `unhealthy` as `doctor_failed` and alerts;
`undetected` is recorded as such and never alerts. Release-install refusals appear as `release_install`.

## Certification and goldens

- **Per node and module.** A node is certified per (node, module), keyed by the module's content digest in
  the node's release. A new version re-certifies that module on that node and nothing else.
  Re-certification also happens after a platform or OS version change, and periodically.
- **Goldens come from the module.** For the node's class (platform, OS version, CPU, GPUs and GPU APIs, pools and
  capabilities, never its identity), the module returns its goldens (`golden.list`), builds each one's spec (`spec.build`), and
  judges the result (`golden.compare`, or the evaluated digest against `expected.digest`). A golden limited to other
  platforms is not run on the node, and its expected value is the one for the node's platform
  (`Golden.expected_by_platform`).
- **Mismatches.** A golden mismatch revokes that module on that node and alerts. Repeated golden failures
  stop retrying and alert. Nondeterminism against another node's canonical result quarantines the node.
- **Stages that do not compare.** A stage whose effective determinism is `none` (`stages[].determinism`, else
  `results.determinism`) is never golden-tested, replicated or compared, and neither takes nor serves a result-cache hit:
  its results depend on when it ran. Its jobs are otherwise ordinary (fenced, certified nodes only, stage retry,
  placement). S21 checks it.
- **Offers.** A node is granted only jobs of modules it is certified for.

## Staged jobs (stage chains)

A module whose manifest has a stage `B` with `after = "A"` can run a job as the chain A → B. Its
single-stage form is the default stage: the one marked `default = true`, or the only stage that neither runs `after`
another nor is depended on. The chain is enabled when the module's pipeline is split (`oarbank pipeline split --module
<name>`, setting `pipeline:<module>`), for jobs that name no stage. A `jobs.enqueue` item that names a standalone stage
(`stage`, host capability `jobs.stage`) runs exactly that stage in any pipeline mode, with that stage's resources,
timeout, retry and platforms; its envelope names the stage, except the default stage, which stays absent.

| | head job | tail job |
|---|---|---|
| kind / stage | `call` / A | `eval` / B, with `depends_on` pointing at the head job |
| key | the job key + `:A` (cached like any result) | unchanged from single-stage, so caches and campaigns are unaffected |
| runs on | any node certified for the module whose resources fit | nodes whose pools fit the tail stage |
| result | the head's envelope with its `artifacts` | `result.merge` of both stages: one canonical result |

- **Claiming.** A tail job is claimable only once its head is done. Its envelope's `inputs.<name>` names the
  head's artifact datasets, which are mounted like any dataset.
- **Checks.** The tail's digest must match its head's (`input_mismatch` otherwise).
- **Integrity.** Replicas, disputes and convictions apply to head jobs. Demoting a head result (dispute,
  conviction, retry) requeues its tail and revokes a live tail attempt. When a head job ends cancelled or
  quarantined, the reaper settles its tail the same way (S12, S13).
- **Pools.** `resources.pools` reserves node tokens for the whole job; `resources.needs_pools` only requires
  that the pool exist. Pools provided only by services a node disabled count as 0 there.

## Limits and node policy

**Limits** (user caps): every key is optional, and a missing key or `null` means uncapped (the default):
```json
{"cpu_cores": null, "mem_gb": null, "jobs": null, "vm_mem_gb": null, "vm_cpus": null, "disk_gb": null,
 "staging_mbps": null, "schedule": null, "enforce": "soft"}
```
- **`schedule`** is `{"days": [0..6], "start": "22:00", "end": "07:30"}` in local time, or null.
- **Effective capacity** is always `min(automatic, cap)`.
- **`enforce`.** `"hard"` makes the agent release the youngest attempts (`limit_*`) until the node is
  within the cap, and the agent applies `schedule` the same way (`limit_schedule`); `"soft"` only stops admitting.

**Policy** (the owner's per-node settings):
```json
{"run_on_battery": false, "user_idle_s": 300, "nice": 10, "threads_per_job": 1, "job_mem_gb": 1.5,
 "disabled_services": ["example/vm"], "module_settings": {"example": {…}},
 "protection": {"schema": 1, "node": {"mode": "moderate"}, "rule": [ … ]}}
```
- **`disabled_services`** sets a node's role. Changing it re-doctors and re-certifies the node.
- **`module_settings.<module>`** holds what a module's services read.
- **`protection`** is owner-set host protection (schema 1). The console edits it with versions, restore and
  canary; see docs/design/protection.md.
- **`hard_limits`** (default `false`) turns each job's reservation (`resources.cpu`, `resources.mem_gb`) into hard
  limits where the OS has them: a cgroup v2 leaf on Linux (when systemd delegated the agent's cgroup), the Job
  Object on Windows; macOS has none. A job over its memory limit fails with `oom`, the job's fault.

## Capacity and host protection

The agent computes `capacity` every tick and sends it in the heartbeat:
```json
{"cpu_slots": 10, "mem_gb_free": 14.5, "pools": {"containers": 3}, "auto_cpu_slots": 12,
 "binding_limit": "auto|cap.jobs|cap.cpu_cores|cap.mem_gb|rule:<id>|guard:memory|thermal|battery|user",
 "admit": true, "why": null, "pool_jobs_only": false, "gpu_jobs": null, "reserved_mem_gb": 6.1}
```
`cpu_slots` and `mem_gb_free` are what fleet jobs may still use; `pools` are what the node's services provide, plus the
agent's own `containers` pool (its container runtime) and `gpu` pool (one token where containers can get the node's
GPUs through CDI; never on macOS) (a node that reports none is offered no pool work). The facts' `containers.gpu` says
which: `cdi:<kind>` or `undetected`. They are computed after:

- user caps, thermal state, battery and user presence;
- running jobs and the memory services hold;
- host protection's combined constraint.

Host protection's combined constraint includes:

- owner rules matched by code-signing identity, bundle id, path or argv, with their process trees, that
  reserve, cap, lower, pause or evict fleet work;
- the memory guard: soft floor at 12 % free, hard floor at 8 %;
- in `moderate` and `strict_yield`, the dynamic controller.

Running services are fleet work: their processes are never matched as the owner's, and host protection may stop a
`yieldable` one, releasing the attempts that use it with the same reason: the memory guard's victim at the hard floor
(`MEMORY_HARD_FLOOR_SERVICE`, `preempt_memory`), every one on a rule's `evict` and, for a GPU service, while GPU work may
not run (`PROTECTION_SERVICE_STOP`, `preempt_protection`). The agent holds a stopped service down while the stop holds
and reports it in `services_held`.

Every actuation goes through the agent's spawn registry, so only the agent's own jobs and services can be
signalled (S16). The decisions are journaled and shipped in heartbeats.
