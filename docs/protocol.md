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
{"coordinator": "https://100.64.0.10:7443", "enrollment_id": null, "node_id": "n_…", "heartbeat_s": 10, "name": null,
 "manage_services": true, "release_seq": 0, "agent_seq": 0, "release_pubkey": null,
 "coordinator_trust": {"cik": "<base64>", "fleet_id": "fleet_…", "max_epoch": 1, "ca_spki_sha256": "…",
                       "ca_next_spki_sha256": null, "retired": [], "fallback": null, "pending_move": null,
                       "owner_keys": [], "owner_version": 0, "owner_rescue": []}}
```
- `manage_services: false` stops the agent from ever starting or stopping module services.
- While joining, `join_secret` holds a join code's secret until the coordinator answers the enrollment request, and
  `user_code` the device code of a node joined by address; both go once used. The node's status for people and
  installers is the separate, readable status document (design/node-enrollment.md).
- `release_pubkey` and `owner_keys` are pinned on first sight in signing mode (docs/release-signing.md);
  `release_seq` and `agent_seq` are the highest signed seq installed (anti-rollback).
- `protection.json` beside the agent home is the owner's local protection file. The agent unions it with the central
  policy section, and the stricter setting wins.

## Enrollment

`POST /v1/agent/enroll` (no client certificate)
```json
{"hostname": "mini-a", "facts": { ...Facts... }, "csr": "-----BEGIN CERTIFICATE REQUEST-----…",
 "join": "<code id hex>.<secret hex>", "name": "build-07", "user_code": null}
```
→ `{"enrollment_id": "enr_…", "status": "pending"}`. A request without a CSR is refused (`csr_required`). `join` is a
join code's id and secret (design/node-enrollment.md; the agent sends it only over a connection verified against the
code's CA pin, after the identity proof matched the code's key). A single-use code, or one set to approve
automatically, approves the node at once (`"status": "approved", "join": "approved"`); a multi-use code leaves it
pending (`"join": "pending_approval"`); a code the coordinator refuses ends the request (`"status": "rejected",
"join": "refused", "join_error": "unknown|expired|used|revoked"`). `name` is the name the node asks for (a single-use
code's label wins). Without a code, `user_code` is the 8-letter device code the node shows (RFC 8628 alphabet,
`XXXX-XXXX`); the owner approves by it (`nodes.admit_code`).

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
 "containers": {"runtime": "colima", "state": "installed", "detail": "the agent's Colima VMs start when a job needs one",
                "gpu": "virtio-gpu:venus"},
 "disk_free_gb": 398.0, "power": {"battery": true}, "addresses": ["100.64.0.11", "192.168.1.20"]}
```
- **CPU.** `perf_cores` and `eff_cores` are physical cores (a core running two hardware threads counts once), the
  same on every OS; a CPU without core classes reports all its cores as `perf_cores` and `eff_cores` 0; `logical` is
  the logical processors the agent may use. docs/design/protection.md, "Capacity", says how each OS is read.
- **Power.** `battery` says the machine has a system battery (a laptop; a UPS or a device's battery does not count).
  Node groups may select on it, and it gives the node the `laptop` label "from facts" (docs/design/settings.md,
  "Groups and labels").
- **Platform.** The coordinator stores the node's platform, OS, architecture and OS version in columns and
  re-certifies every module when the platform or OS version changes. A node of a platform the fleet has no
  release for gets one built when it enrolls.
- **Sandbox.** `enforcement` reports, per capability of the module sandbox contract (spec/sandbox.md), whether
  the node's backend enforces it: `enforced`, `cooperative` or `unavailable`. A module runs only where its
  always-on rules and its grants are `enforced`. A node without a `backend` gets no module work
  (`SANDBOX_BACKEND_MISSING`); a gap is `CAPABILITY_NOT_ENFORCED`. `grants.bootstrap` says the agent runs a bootstrap
  stage's jobs with the bootstrap grants (spec/sandbox.md, "Bootstrap jobs"); only such a node gets them.
- **Placement.** A module version runs only on the platforms in its `requires.platforms`, on OS versions in
  `requires.os`, and where every `[sandbox].tools` request resolves to an installation the node reported (`tools`,
  below; docs/design/host-tools.md): `PLATFORM_UNSUPPORTED`, `OS_VERSION_UNSUPPORTED`, `TOOL_NOT_FOUND`,
  `TOOL_VERSION_UNMET` ("found 11.0.2 at …; needs >=17"), `TOOL_REFUSED` (a path set for the node that it refused),
  `AGENT_TOO_OLD`. A tool that does not resolve keeps off only the jobs of stages that need certification (and the
  goldens): a stage that needs none runs without it (docs/design/stage-gating.md), and explain names the tool, what
  the node found and what the module needs.
- **Containers.** `runtime` and `state` say whether the node has a container runtime: on macOS `colima` (the agent's
  Colima profiles; `installed`: their VMs start when a job needs one), on Linux `podman` or `docker` (`installed`),
  else `runtime` null and `state` `absent`. `gpu` is how containers get the node's GPUs (`cdi:<kind>`,
  `virtio-gpu:venus`), else `undetected`, always `undetected` without a runtime; the APIs such a container can use are
  the doctor report's `gpu_apis.containers` (below), which `oarbank node show` and the node page list only beside a
  runtime. A Windows node reports its WSL containers session's state instead ([design/windows-containers.md](design/windows-containers.md), "The
  node's report"): `runtime` (`wslc`), `state` (`absent`, `starting`, `ready`, `missing`, `failed`), `session`,
  `platforms`, and `missing` (`[{what, detail, fix}]`); it sends a new hello whenever that state changes. A macOS node
  reports its Colima runtime the same way ([design/macos-containers.md](design/macos-containers.md)): `runtime`
  (`colima`), the same `state` values, `profile`, `colima_home`, `platforms`, `missing`, `detail` when failed, and
  `gpu_profile` (`{profile, state, missing}`: `unavailable`, `on_demand`, `starting`, `ready`, `failed`); its `gpu` is
  `virtio-gpu:venus` only while the runtime is ready and krunkit is installed.

`hostname` is the name the node reports: the machine's host name, or `OARBANK_NODE_NAME` in the agent's
environment when the owner names it. The coordinator names the node after it, unless the node enrolled with a
labelled join code (`oarbank join-code --label`): the label is then the node's name, and a reported `hostname` never
changes it.

## Session

`POST /v1/agent/hello` is sent on start, on wake, after a clock jump over 30 s, and on `recertify`.
```json
{"agent_version": "…", "boot_id": "…", "facts": {…}, "live_attempts": [123, 124], "release_id": "r_…",
 "ready_datasets": ["scene:atrium", …], "clock": 1790000000.2, "tools": {…Tools…}}
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
 "attempts": [{"attempt_id": 123, "phase": "staging|running|<runner phase>|paused|checkpointing|uploading", "cpu_s": 55.2,
               "log_bytes": 10231, "rss_gb": 0.9}],
 "ready_datasets": ["scene:atrium", …], "doctor": null,
 "folders": {"inputs": {"access": "read", "status": "ok"}, "outbox": {"access": "write", "status": "not a directory"}},
 "tools": {"detected_at": 1790000005.0, "native_arch": "arm64", "tools": {
   "jdk": [{"path": "/opt/homebrew/Cellar/openjdk@17/17.0.12/libexec/openjdk.jdk/Contents/Home", "version": "17.0.12",
            "arch": "aarch64", "vendor": "Homebrew", "source": "detected", "status": "ok", "detected_at": 1790000005.0},
           {"path": "/srv/jdk", "given": "/srv/jdk", "version": null, "arch": null, "vendor": null, "source": "override",
            "status": "refused: /srv/jdk does not exist here", "detected_at": 1790000005.0}],
   "python": []}},
 "services": [{"service": "example/model", "health": "healthy", "running": false, "ready": false, "held": "preempt_memory",
               "disabled": false, "withdrawn": false, "failures": 0, "error": null, "gpu_api_missing": null, "users": 0,
               "pools": {"model": 1}, "reserve_mem_gb": 0.0, "busy": false, "endpoint": true, "accepting": false,
               "lifecycle": "on_demand"}],
 "probes": [{"probe": "example/java17", "health": "healthy", "attrs": {"version": "17"}}],
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
- **`folders`** is the outcome, per folder id, of the node statement the agent applied (see Node statement).
- **`tools`** (hello and every heartbeat) is the agent's latest host tool detection (see Host tools); oarbankd keeps
  it as `nodes.tools_json` and places jobs by it.
- **`services`** and **`probes`** are the agent's service report, sent on every heartbeat: each module service
  (`<module>/<name>`) with its health, whether it runs and has answered `ready`, why it is down (`held` by host protection
  with the release reason, `disabled` by the kill switch, `withdrawn` after failures, `gpu_api_missing`), its last
  `error`, the jobs using it (`users`) and its lifecycle; each probe with its health and attributes. oarbankd keeps the
  latest in `nodes.services_json`; the node page, `oarbank node show` and module pages (the `services` and `nodes` host
  queries) show it.
- **`journal`** carries unacknowledged host-protection decisions, at most 200; oarbankd answers with
  `journal_ack`, the highest seq it stored. The GPU duty governor journals its budget steps as `kind: "gpu_duty"`
  (`GPU_DUTY_START`, `_BASELINE`, `_GROW`, `_HALVE`, `_TAKE_BACK`, `_CLAMP`, each with `duty`, `ceiling`, `why`, and
  `pressure` per rule at an interval's end) and its compliance actions as `kind: "gpu_compliance"` (`GPU_DUTY_EXCEEDED`,
  `GPU_DUTY_UNVERIFIED`, with `attempt` (a job's) or `workload` (a workload's key), `unit`, `measured`, `duty`,
  `action: "paused|evicted"`); S28 reads both.
- **`telemetry.protection`** also carries, for co-tenancy (docs/design/gpu-cotenancy.md): `phases` (every `during`
  block: `{"key": "trainer#0", "rule": "trainer", "block": 0, "on": false, "since": 1790000000.0, "readable": true,
  "reader": "agent|helper|exec", "tags": ["uplink"], "immediate": true}`), `progress` (each `progress_rate` source:
  `{"rule", "readable", "reader", "rate"}`), `event_latency` (source event to pause request: `n`, `p50_ms`, `p99_ms`,
  `max_ms`, `edges_ms`, `buckets`), `gpu_budget` (under `gpu_jobs = certified` while a gating group is active: the
  duty governor's `{"duty", "ceiling", "rules", "jobs", "per_job", "state": "measuring|running|held|locked|harness",
  "lockout_s", "baseline": {"<rule>": {"rate", "age_s", "pressure"}}, "units": [{"id": <attempt or workload fleet id>,
  "unit": "<module>[/<workload>]", "workload": bool, "duty", "measured",
  "state": "ok|waiting|held|distrusted|cannot_throttle|evicted", "why"?: "exceeded|unverified", "for_s"?}],
  "distrusted": [{"unit": "<module>[/<name>]", "for_s"}]}`, or `{"duty": 0, "rules", "not_certified": [...], "state":
  "not_certified"}`) and `identities` (per rule, the protected program's identity a certificate
  is bound to); `telemetry.cert_context` is what the node's certificates must match (`hardware`, `os_major`,
  `agent_version`). The coordinator aggregates `phases` across nodes by tag (`protection.node_phases`,
  `protection.any_phase_on`).
- **`telemetry.uplink`** is the agent's site uplink gate (docs/design/sites.md): `{"site": "home", "site_id": "site_…",
  "held": "site home: mini's rule trainer is in an upload phase (trainer#0)", "local_phases": ["trainer#0"],
  "cap_mbps": 50.0, "leases": 1, "heavy_jobs": [123], "active": [{"kind": "staging|upload", "dir": "down|up", "done":
  1048576, "total": 1073741824, "paused": true, "why": "…"}]}`; the site's page shows it per member.
- **`ab_runs`** is the current or last paired on/off harness run (at most one): `{"run_id", "rule", "work", "duty",
  "state": "pilot|running|done|aborted", "started_at", "target_blocks", "blocks": [{"on_first", "on_rate",
  "off_rate", "start", "end"}], "excluded": [{"start", "end", "reason"}], "current": {"arm": "on|off",
  "window_elapsed_s", "on_first", "excluded_reason"}, "outcome": {"decision":
  "no_slowdown|slowdown|inconclusive|refused|aborted", "reason", "analysis", "min_detectable", "ended_at"}, "identity",
  "margin", "window_s", "washout_s", "off"}`. A run that ends `no_slowdown` earns a certificate.
- **`processes`** is the summary the console's process picker uses: the owner's processes by resource use,
  at most 80, the agent's own jobs excluded. The agent sends it every 5 minutes, or on the next heartbeat
  after `send_processes`. `comm` is the kernel's short name (the Windows image name); a null `path` or `argv` could
  not be read (another account's process), and a rule key that needs it counts as holding (a rule's `unreadable`
  counts the processes it matched that way).
- **Leases.** oarbankd extends `expires_at = now + 60 s` for each listed attempt that is live server-side and
  shows progress: `cpu_s` or `log_bytes` advanced, the attempt is `staging`, it is `paused` by host protection or its
  site, it is `checkpointing` (uploading a checkpoint before it releases), or it is `uploading` its results (an upload
  its site holds may wait out an uplink phase). The agent bounds a pause at 10 minutes (less with the
  node's protection `[node] max_pause_s`, 10 to 600 s), then releases the attempt: after a checkpoint when the stage
  keeps them (see Checkpoints).

**Directives** (the answer to hello and to every heartbeat):
```json
{"node_id": "n_…", "now": 1790000010.4, "desired_state": "active|paused|draining", "lifecycle": "enrolled|ready|quarantined|retired",
 "limits": {…Limits…}, "policy": {…Policy…}, "settings_rev": 42, "heartbeat_s": 10,
 "release": {"release_id": "r_…", "url": "/v1/releases/r_….tar.gz", "sha256": "…", "statement": "…", "signature": "…"},
 "release_pubkey": null, "prefetch": ["tool:example-1.0", "scene:atrium"], "run_doctor": false, "recertify": false,
 "cancel": [125], "revoke": [126], "run_probe": false, "send_processes": false, "journal_ack": 41,
 "modules_disabled": ["example"],
 "statement": {"statement": "{…oarbank.node/v1…}", "signature": null},
 "tool_pins": {"": {"jdk": "/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home"}, "example": {"jdk": "/opt/jdk-21"}},
 "detect_tools": false,
 "uplink": {"site": {"id": "site_…", "name": "home", "hold": false, "code": null, "why": null, "since": null,
                     "lease_ttl_s": 20, "poll_s": 2, "lease_mbps": 50.0, "max_transfers": 2}, "salt": "…"}}
```
| Directive | Meaning |
|---|---|
| `now` | oarbankd's clock when it answered (see Clocks). |
| `release` | The release this node must run: its own composition, or the current one (see Releases). `null` when the node already runs it. `statement` and `signature` are present only with release signing. |
| `cancel` | Stop the attempt and `release(reason=user_cancel)`. |
| `revoke` | Another attempt won, or the module was disabled: kill silently, no report. |
| `run_doctor`, `recertify` | Run every module's doctor again; send hello again (certification restarts). |
| `run_probe` | Run a host-protection pause probe at the next tick (from `protection.probe_now`). |
| `ab_run` | A harness run to start (`{"run_id", "rule", "work", "duty", "blocks", "window_s", "washout_s", "margin", "off", "pilot_blocks", "max_hours", "seed"}`, from `protection.ab.start` or `.sweep`); `null` when none. The agent starts each run id once, refuses one while another runs or for a rule without a `progress_rate` source (journaled `AB_REFUSED`). |
| `ab_abort` | Run ids to abort (`protection.ab.abort`). |
| `ab_ack` | The last run oarbankd stored as ended: the agent stops reporting it. |
| `certificates` | The node's co-tenancy certificates in force: `[{"id", "rule", "work", "duty", "r", "r_lo", "r_hi", "margin", "run_id", "issued_at", "valid_until", "identity", "context"}]`. The agent checks each (expiry, `context` against its own, `identity` against the rule's live group) before `gpu_jobs = certified` uses it. |
| `send_processes` | Send a process summary (the rule editor's preview is open). |
| `modules_disabled` | Modules that must not run on this node: their effective `[module] enabled` is off here (for the fleet: the kill switch, `modules.disable`; or for a group the node is in, or the node itself). Every service of theirs is disabled on the node (stopped, never offered) until they are enabled again; the coordinator grants none of their work there. |
| `statement` | This node's latest statement (its folders and the tool paths added for it) and the owner's signature (`null` in developer mode, or until the owner signs); `null` when nothing is set for this node (see Node statement). |
| `tool_pins` | Tool paths chosen among what this node found, per module (`""`: every module without values of its own). The agent grants a pinned path only when it names an installation it detected (see Host tools). |
| `detect_tools` | Detect the host tools again now (`tools.detect`, the console's Re-detect); sent once. |
| `listeners_disabled` | The inbound-listener kill switch for this node or the fleet: close every listener and remove every router mapping (see Inbound listeners). |
| `listener_probes`, `dial_probes`, `listener_reachability`, `observed_addr`, `send_listener_talkers` | Dial-back probes to expect and to make, their outcomes, the node's public source address, and a request for the listeners' top client addresses (see Inbound listeners). |
| `uplink` | The node's site (docs/design/sites.md): `site` is `null` at no site, else its id and name, whether it holds network-heavy work now (`hold`, `code` `SITE_UPLINK_BUSY`, `why` in words, `since`) and the lease terms (`lease_ttl_s`, `poll_s`, `lease_mbps`: the pace of each lease, `null` unpaced). `salt` keys the agent's gateway fingerprint (see Site uplink). |

## Work

`POST /v1/agent/claim`
```json
{"free_cpu": 3, "free_mem_gb": 6.0, "modules": ["example", "toy"], "release_id": "r_…",
 "ready_datasets": ["tool:example-1.0", "scene:atrium", …], "pool_jobs_only": false, "gpu_jobs": null,
 "paused": [], "paused_by": null}
```
oarbankd grants jobs:

- whose resources fit `free_cpu` and `free_mem_gb`;
- whose module is offered in `modules` (its runner started: its doctor printed a DoctorOutput, healthy or not) and
  certified on this node; or, for a job of a stage that needs no certification (docs/design/stage-gating.md: a
  bootstrap stage, or one that compares nothing and needs no capability or pool), in any state its doctor decides there
  (certified, certifying, `doctor_failed`, `undetected`, `golden_failed`; not `revoked`), a bootstrap stage only on a
  node whose facts report `grants.bootstrap` (docs/design/bootstrap-stages.md);
- whose datasets are all registered (else `DATASETS_NOT_REGISTERED`) and in `ready_datasets`;
- whose pool needs fit the node's pools;
- whose stage's `requires.capabilities` the node has for the module, by its latest doctor report (see Doctor: a failed
  check named after a capability takes it away); otherwise the job waits with `STAGE_CAPABILITY_MISSING`;
- whose stage's secrets (`stages[].secrets`) each have a value the coordinator can read for this node (its own, else
  the module's); otherwise the job waits with `SECRETS_NOT_SET` (docs/design/secrets-and-signed-images.md).

With `pool_jobs_only`, only jobs reserving pools are granted. `gpu_jobs` is how many more GPU jobs the node
may run, with `null` meaning no limit. A GPU job is one whose module's `runner.gpu` is not `none`, or that reserves a pool
of a service whose `gpu.use` is not `none`; it waits with `GPU_BLOCKED` while the node's live GPU jobs reach that number.
`paused` is the work active host protection rules pause on the node (`pause_fleet` scopes: `all`, `cpu`, `gpu`, `io`) and
`paused_by` the first such rule (`rule:<id>`): none of that work is granted there while they last (`PROTECTION_ACTIVE`;
`all` and `io` every job, `gpu` GPU jobs, `cpu` the others), since a job granted now would be paused at once, released
after the node's longest pause (`preempt_protection`, no charge) and granted to the same node again.

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
- **`settings`** (only for a job of a running campaign that overrides some of its module's own keys declared
  `"x-oarbank": {"campaign": true}`): `{short name: value}`. The agent lays them over the module's node settings, key
  by key, in that job's `OARBANK_SETTINGS_FILE` (never a bootstrap job's). A campaign's overrides of the keys a node
  applies (`jobs`, `run_on_battery`, `user_present_slots`) are not sent: the coordinator holds the campaign's jobs to them
  at claim (docs/design/settings.md, "Campaign overrides").
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
- `POST /v1/attempts/{id}/release` with `{"reason": "preempt_memory|preempt_protection|limit_mem|limit_cpu|limit_schedule|user_cancel|agent_stop"}`;
  a release without a reason is refused (400 `reason_required`). These are not failures. `agent_stop`: the agent was
  asked to stop (its service stopped or restarted) and stopped the runner first (docs/design/architecture.md,
  "Stopping the agent").
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

## Site uplink

Nodes that share one internet line are one **site** (docs/design/sites.md, PLAN D55). The agent's bulk transfers, each
of at least 8 MiB or of unknown size (dataset staging from origins and `GET /v1/blobs`, result and checkpoint uploads),
wait while any of these holds, and resume where they stopped:

- one of this node's protection phases tagged `uplink` is on or cannot be read (seen at once by the agent's watcher);
- a protection rule caps staging at 0 (`cap_fleet.staging_mbps = 0`);
- the coordinator says the node's site holds (`uplink.site.hold` in a directive or a renewal).

At a site every bulk transfer also needs a lease:

```text
POST /v1/agent/uplink/lease    {"kind": "staging|upload", "dir": "down|up", "bytes": 1073741824}
  → {"granted": true, "lease_id": "ul_…", "mbps": 50.0, "ttl_s": 20, "site": {…}}
  → {"granted": false, "code": "SITE_UPLINK_BUSY|SITE_UPLINK_BUDGET", "why": "…", "retry_s": 2, "site": {…}}
  → {"granted": true, "lease_id": null, "site": null}                       (the node is at no site)
POST /v1/agent/uplink/renew    {"leases": ["ul_…"]}  → {"leases": {"ul_…": "ok|revoked"}, "site": {…}}
POST /v1/agent/uplink/release  {"lease_id": "ul_…", "kind", "dir", "bytes": 1073741824, "seconds": 41.2, "paced": false}
POST /v1/agent/uplink/network  {"gateway_fp": "<32 hex>"}
```

- **The budget.** oarbankd grants at most the site's `max_transfers` live leases, each paced at `uplink_mbps /
  max_transfers` when the site sets a rate, and none while the site holds. A hold or a budget change revokes every
  lease (`revoked` at the next renewal). S27 checks it.
- **Renewal.** While it holds a lease or runs a network-heavy job, the agent renews every `poll_s` (and learns the
  site's state from each answer). A lease not renewed for `lease_ttl_s` is gone on the coordinator; the agent treats one
  it could not renew for `lease_ttl_s - 5` seconds, counted from when it sent the last successful renewal, as gone
  already, so it has stopped before the slot is given to another node.
- **Pace.** The smallest of the lease's `mbps`, the node's `staging_mbps` cap and a rule's staging cap. While a node
  is at a site or capped, uploads go in 1 MiB chunks (8 MiB otherwise), so a hold stops one within a fraction of a
  second.
- **At once.** When one of its `uplink` phases changes, the agent sends a heartbeat at once instead of waiting for
  `heartbeat_s`, and oarbankd recomputes the node's site in that heartbeat: the other nodes' transfers stop at their
  next renewal, within `SITE_HOLD_BOUND_S` (5 s) of the phase source changing.
- **Network-heavy jobs** (`resources.network = "heavy"` in the spec envelope) are paused while the node's site holds
  (`pause` in a cooperative runner's control document, or a freeze), and released as `preempt_site` (requeued, never
  charged) when they can do neither or wait past the node's longest pause. oarbankd admits none at a site while it
  holds, and at most the site's `max_heavy_jobs` at once.
- **Network fingerprint.** Every 10 minutes the agent reports `gateway_fp`, an HMAC-SHA256 (keyed with
  `uplink.salt`) of its default gateway's hardware address read from the OS's route and neighbour tables, truncated to
  16 bytes; oarbankd also keeps a keyed fingerprint of a public address the node connects from. Neither address is
  stored or shown; equal fingerprints suggest a site.
- Releases and agent updates are not held: they are fetched on the agent's control path, and holding them would hold
  its heartbeats.
- Journal records: `transfer_paused` (`TRANSFER_PAUSED`, with `transfer`, `dir`, `why`, `done`, `paused_at`) and
  `transfer_resumed` (`TRANSFER_RESUMED`, with `paused_s`); a frozen network-heavy job's actuation is journaled with
  `SITE_PAUSE` and `SITE_RESUME`.

## Node statement

Every node-scope value that grants access on one node travels in that node's **statement**: canonical JSON
`{"type": "oarbank.node/v1", "fleet_id", "node_id", "seq", "folders": {id: {"access": "read"|"write", "path"}}, "tools":
[{"id", "module", "path"}], "listeners": {"<module>/<listener>": {…}}, "signed_at"}` and a signature, rebuilt with a rising seq whenever its content changes. With
release signing the agent applies a statement only with a valid signature by the pinned release key (`oarbank node sign
<node>`, operation `nodes.sign_statement`) and a seq above the last one it applied; in developer mode statements are
unsigned. The agent keeps the applied statement in `state/folders.json`. `listeners` are the owner's inbound listeners on the node (see
Inbound listeners); a statement without the key has none.

## Folders

An operator maps the folder ids modules ask for (`[sandbox].folders`, approved per version) to a path per node in the
folder registry (`settings.folders.update`); the mapping reaches each node in its statement (`folders`). The agent
checks each folder (an absolute, existing directory, granted by its canonical path; not a root, a home directory,
Oarbank's data, a system directory or a path the sandbox already grants; no two folders overlapping) and reports the
outcome in every heartbeat. A job of a module that asks for folders is placed only where every one of them reports `ok`
with the access asked for (else `FOLDER_UNAVAILABLE`). The runner gets the granted folders in `OARBANK_FOLDERS_FILE`,
read folders read-only and write folders as outboxes it can create and write files in but never read, list or delete
(the SDK's spec/sandbox.md, "Folders").

## Host tools

The node is the source of truth for what is installed (docs/design/host-tools.md). The agent detects every tool the
fleet defines (the built-in `jdk` and `python`, plus the release's `tools` table) at startup, after a release install,
on `detect_tools`, when its statement's tool paths change and hourly, and reports **Tools** in hello and every
heartbeat:

- `detected_at`, `native_arch` (`arm64`, `amd64`);
- `tools`: per tool id, every installation it found: `path` (canonical: a JDK's home, an executable's file), `given`
  (the path as set or hinted, when it differs), `version` (a JDK 8's `1.8.0_392` is `8.0.392`), `arch` (as the
  installation names it: `aarch64`, `x86_64`), `vendor` (a JDK's `IMPLEMENTOR`), `source` (`detected`: a built-in
  search pattern; `search`: the fleet's; `override`: a path the node's statement adds; `local-hint`: the hints file
  `<agent home>/tool-hints.json`), `status` (`ok` or `refused: <reason>`) and `detected_at`.

A JDK is read without running anything: its home's `release` file (`JAVA_VERSION`, `OS_ARCH`, `IMPLEMENTOR`) beside
`bin/java`. Any other tool runs its version command inside the sandbox (read and execute on that installation only,
no network, 10 s at most) and the definition's regex reads the version from its output. A path the statement adds first
passes the folder rules (no roots, homes, data roots or system directories themselves) and then the detector.
`OARBANK_TOOLS_BUILTIN_SEARCH=0` in the agent's environment skips the built-in patterns.

For each module the agent resolves each approved request (`sandbox.tools` of the module entry: `{id, version, arch,
trust}`) to one installation, as the coordinator does (`oarbank_core::tools::resolve`, `tools.resolve`; vectors in
`src/oarbank/contracts/vectors/tool-resolution.json`): the module's pin in `tool_pins` when it names an installation
found here, else the node's native arch first, then the highest version that satisfies the request. Its runners,
doctor, services and probes get exactly that installation in **`OARBANK_TOOLS_FILE`**, a UTF-8 JSON file
`{"<tool id>": [{"path": "<canonical path>", "version": "17.0.12", "arch": "aarch64"}]}`, and read and execute on its
path (an interpreter's prefix for `python`); a request that does not resolve is left out. A bootstrap job's file lists
no tools.

## Releases

A release is **per platform** and composed from the coordinator's module store (`oarbank module install`, then
enable, canary, promote; see the SDK's spec/bundles.md). For each module with a current version that supports the
platform, it holds the bundle of the version the node runs:
```
<release>/MANIFEST.json            every file: path, sha256, mode
<release>/modules.json             {"format": 2, "platform": "darwin-arm64", "modules": [Module, ...], "tools": {…}}
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
             "tools": [{"id": "jdk", "trust": "code-exec", "version": ">=17, <22", "arch": "native"}],
             "devices": {"gpu": "none"}, "exec_writable": false, "containers": []}}
```
A stage's `platforms` limits where its jobs are granted (empty: every platform of the module). A service's `endpoint`
and `gpu` are present only when the manifest sets them (docs/design/service-endpoints.md). `runner.env` is
`[runner].env` with the platform's variant merged, present only when the manifest declares one.
`runner.bandwidth_class` (`low`, `medium` or `high`) is present only when the manifest declares it. Host
protection uses it to pick rungs when the harm is to a GPU-bound protected group (docs/design/protection.md).
`sandbox.tools`
carries each approved tool request, never a path; the release's top-level `tools` table carries the fleet's tool
definitions for the release's OS: `{"<id>": {"kind": "jdk"|"python"|"executable", "search": [extra patterns],
"version": {"args", "regex"}}}` (`version` for executables only; see Host tools). `sandbox.container_sets` (present only when the manifest declares sets) carries each approved set with its
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

## Fleet updates

A fleet release moves a node's whole package (launcher, helpers, apps, runtime and agent) through the node's root
update runner, and the coordinator before any node ([design/fleet-updates.md](design/fleet-updates.md); D56–D62,
S29–S31). While a node has a `node_update` directive, the agent-only `agent_update` above is `null` for it; a node
without an update runner keeps agent-only self-update.

- **Release.** `oarbank-fleet-<version>.json` names every artifact of a version (`role` node, agent or coordinator;
  `platform`; `format` pkg, msi, deb, rpm, tar or binary; `sha256`; `size`) with `seq`, `agent_min`, `stops` and
  `expires`. Its text travels verbatim: everyone hashes those bytes. In signing mode the owner's statement
  `{"type":"oarbank.fleet-release/v1","version","seq","manifest_sha256","signed_at"}` (sorted keys, `(",", ":")`
  separators, Ed25519, base64) is checked against the owner key set. The coordinator imports a release from a
  directory, from files staged through `POST /api/v1/updates/uploads`, or from `update_source`
  (`<source>/download/v<version>/<asset>`). It checks each artifact's sha256 and size and keeps only the platforms its
  nodes and itself run.
- **Report.** hello and heartbeat carry `install: {format, scope, updater, why}` (how the agent was installed and
  whether the runner's trigger and trust are in place) and `node_update: {state, release, seq, error, at}`. States:
  `idle`, `unsupported`, `staging`, `staged`, `draining`, `deferred`, `installing`, `confirming`, `done`, `failed`,
  `rolled_back`, `refused`.
- **Directive.** While a node's target differs from the version it runs, every reply carries
  `node_update: {release, seq, go, rollback, drain_timeout_s, artifact: {name, format, sha256, size, url}, manifest,
  signature | null, owner_anchors | null}`; `null` otherwise. The target is the node's pin (`update_pin`), else none
  while it is held (`update_hold`), else the governing rollout's release once the node's ring started (or, after the
  rollout is done, to catch up), else what it runs. It is never newer than the coordinator's own version, and a
  `stops` version the node has not reached comes first. `owner_anchors` relays the owner key set for the runner's
  rotation rule.
- **Artifact.** `GET /v1/updates/artifacts/{sha256}` (agent listener, mTLS) serves only the artifact of the node's
  current directive (404 otherwise).
- **Agent.** It stages (downloads under a site transfer lease, checks size, sha256, the manifest's entry for its
  platform and format, and the signature) and reports `staged`. On `go` it drains: no new claims; running attempts
  finish. Past `drain_timeout_s` it reports `deferred` and claims again. Drained, it writes its spool request for the
  runner and reports `installing`; the new agent confirms after its first hello and heartbeat (`confirming`), then
  `done`. If the runner rolled back, the old agent reports `rolled_back`. A `failed` seq is not retried until the
  coordinator issues another.
- **Rollout.** The coordinator first (ring 0: a snapshot, a self-test, the root coordinator runner, probation), then the
  rings `canary`, `early` and `broad` (`update_ring`). Within a ring at most `max_unavailable` nodes are staged with `go`
  or between draining and confirming (S29). `go` goes only to a node that is online (heartbeat within 120 s), inside its
  `update_window`, not held, not pinned elsewhere, with no protected phase on and no workload seat due for renewal (S31;
  each grant is journaled with these facts). A ring's next starts when it finished and baked: its bake time passed and
  every node it updated heartbeated 10 times on the new release, healthy (S30). Failures above a ring's budget (0 for
  canary, 1 after) halt the rollout and, with `auto_rollback`, send the nodes it moved back through the same directive
  (`rollback: true`). A rollout does not start, nor start a ring, while more than a third of the fleet is unhealthy. A
  node older than the coordinator's `agent_min` is refused work (`AGENT_TOO_OLD`) until it updates.

## Coordinator self-update

The coordinator updates itself from a stored fleet release ([fleet-updates.md](design/fleet-updates.md), D58). Two
parties take part: oarbankd, unprivileged, prepares it, and a root runner (`python -m oarbank.coordupdate run`; a
build's `bin/oarbank-coordupdate`) swaps it.

- **`GET /v1/health`** on the agent listener answers without a client certificate, in every role:
  `{"version", "started_at", "migrated": true, "ticking": <a background tick within 30 s>, "role"}`. The runner's
  probation reads it: the new version, migrated and ticking, within 300 s, holding for 60 s.
- **Request.** oarbankd checks the release's coordinator build for its platform: the sha256, the size, and in
  signing mode the owner's `oarbank.fleet-release/v1` signature over the manifest. It refuses when:
  - a move is on, or this coordinator is handed off;
  - an enrolled, non-retired node that is not held (`update_hold`) runs an agent older than the release's `agent_min`.

  It snapshots the database (`VACUUM INTO updates/snapshots/<from>-<ts>.sqlite3`, plus an integrity check) and runs the
  new build's `oarbankd --self-test --home <scratch>` on a copy. Only then does it write `coordinator_updates {state:
  requested}` and the spool request, atomically.
- **Spool** (`<coordinator home>/updates/`):
  - `coordinator-request.json`: `{"id", "version", "sha256", "size", "archive": "updates/artifacts/<sha256>",
    "manifest", "signature", "snapshot", "from_version", "requested_at"}`. Its appearance starts the runner, through
    the launchd job `dev.codonic.oarbank.oarbankd.update` (`WatchPaths`), the systemd unit
    `dev.codonic.oarbank.oarbankd.update.path` (`PathExists`), or the SYSTEM task `\Oarbank\CoordinatorUpdate` (every
    minute). The runner removes the file once it has journaled the request; oarbankd then records `running` and grants
    no new leases until the outcome.
  - `coordinator-result.json`: `{"id", "version", "state": "refused|done|rolled_back", "error", "at"}`. The runner
    writes it, owned by the coordinator's account. oarbankd reads it at start and on every background tick, records
    `coordinator_update_{done,rolled_back,refused}` (alerting on the last two), and moves the file to `updates/results/`.
- **Runner.** It reads the request as data. It copies the build from `updates/artifacts/<sha256>` into its own
  root-only `<system data>/coordinator-update/` and verifies the copy against `trust.json` there. Then it stops both
  services, takes its own copy of the database (`db-<id>.sqlite3`), unpacks into `PROGRAMS/<v>-<sha12>`, flips
  `current`, refreshes the services (`install-oarbankd --refresh --installed <build>`) and starts them. It commits, or
  restores the copy, flips back and starts the old version. Every step is journaled in `journal.json`; a runner that
  finds an active journal rolls back unless it was committing.

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

## Workloads

A module's workloads (docs/design/workloads.md; the SDK's spec/workload-protocol.md) are long-running processes the
owner assigns to nodes (`workloads.assign`, T2).

- **Directive** (every hello and heartbeat reply): `workloads: [{key, module, workload, desired, seat_id, fence,
  lease_s, restart_seq, reason}]`, one entry per assignment of the node. `desired` is `running` only for a workload the
  node may run now: for a per-node identity, with the seat's lease (`seat_id`, `fence`, and `lease_s`, the lease's end
  minus the coordinator's now when it wrote the reply); otherwise `stopped` with a reason code (`WORKLOAD_SEAT_ELSEWHERE`,
  `WORKLOAD_SECRETS_NOT_SET`, `WORKLOAD_IDENTITY_SHARED`, `WORKLOAD_NOT_OFFERED`, `WORKLOAD_NODE_NOT_ACTIVE`). The agent
  runs exactly what is listed `running` and stops what is not; a workload missing from the list is unassigned. The
  agent's lease ends at the time it **sent** the request plus `lease_s`, on its boot clock (it counts sleep), and the
  workload stops then unless a later reply renewed it. A raised `restart_seq` restarts the workload (and lifts a
  withdrawal).
- **Report** (hello and heartbeat): `workloads: [{key, state, running, seat_id, fence, release, pid, run, adopted,
  members, restarts, failures, withdrawn, error, blocked, held, held_code, paused, lowered, threads, cpu_cap, health,
  lease_left_s, progress, log_tail, ...}]`. `running` is true while anything of the workload may run (starting, running,
  stopping). `release: true` with `running: false` gives the seat up; the coordinator frees a seat only on such a report
  from its holder carrying the current fence (an older fence is ignored), else when the lease and a grace of 60 s have
  passed. `log_tail` is the last 2 KiB of the workload's log, with its secrets' values redacted.
- **Report events** (heartbeat): `workload_reports: [{key, seat_id, fence, events: [{seq, t, data}]}]`, a workload's
  `report` events (at most 4 KiB each, 60 a minute); the reply's `workload_reports_ack: {key: seq}` names the highest
  sequence stored, which the agent then drops. The coordinator delivers them to the module's `workload.report` verb and
  applies the effects it answers (`coordinator.workload_effects`), with an audit row.
- **Secrets**: `POST /v1/agent/workloads/secrets {key, seat_id, fence}` answers `{secrets: {name: value}}` only while the
  node holds the seat with that fence and its lease runs (409 `seat_not_held`, `secrets_not_set`, `identity_shared`,
  `not_assigned`). The agent asks at each start and keeps the values only in the run's owner-only secrets file.
- **Adoption**: workloads outlive their agent; the next agent adopts a recorded run (`<home>/state/workloads/`) while its
  lease runs and its leader is the recorded process, and reports it at hello, which renews the lease.

## Inbound listeners

docs/design/inbound-listeners.md is the full contract; in short:

- **Facts** (hello): `"listeners": {"version": 1, "probe": true}`: the agent runs listeners and can dial back for
  others.
- **What the agent runs.** For each statement entry `<module>/<listener>`, a listener when the module version in its
  release requests that `inbound` listener, an enabled endpoint service or a workload of the module lists it, `listeners_disabled`
  is off, the policy's `inbound_listeners` is not false and the protection mode is not `strict_yield`; else a refusal
  (`LISTENER_NOT_GRANTED`, `LISTENER_NO_TARGET`, `MODULE_DISABLED`, `LISTENERS_DISABLED`, `LISTENERS_FORBIDDEN`,
  `LISTENER_STRICT_YIELD`, `LISTENER_HANDOVER_UNSUPPORTED`, `LISTENER_BIND_FAILED`).
- **Heartbeat** (when the node has or had listeners): `listeners` (per key: state, bind and external addresses, the
  announcement, the reachability result with the owner's text and fix, connection counters and refusals by reason,
  `probe_wanted`, `statement_seq`), `portmaps` (every router mapping it holds: protocol, gateway, external and internal
  address, lease, expiry, last verification, state, error), `network` (gateway, local addresses, the gateway's
  external address, the observed address, which mapping protocols answer, the router's other mappings for this node,
  the firewall), `probe_results` (dial-backs this node made), and `listener_talkers` once after
  `send_listener_talkers`.
- **Probes.** The coordinator schedules a dial-back when a report asks (`probe_wanted`) or on `listeners.probe`, at most
  once a minute per listener: the target gets `listener_probes: [{probe_id, key, nonce, expires_at}]`, the prober
  `dial_probes: [{probe_id, host, port, nonce}]`; the prober writes `OARBANK-PROBE/1 <probe_id>` and expects
  `OARBANK-PROBE/1 OK <nonce>` (`SAME`: from the target's own network) and reports `probe_results: [{probe_id, ok,
  detail, rtt_ms}]`; the target then gets `listener_reachability: {key: {state, at, via, detail}}`.
- **Mappings** are journaled in `state/portmaps.json` before each request; `oarbank-agent portmap status|release-all`
  read and empty it; the agent releases its mappings when it stops (its graceful stop), when the coordinator answers
  `node_retired`, and the launcher's uninstall runs `portmap release-all`.

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
them again when that set changes); a module's `capabilities` are its own doctor's. Together, less every capability a
failed check of the module's doctor is named after, they are the node's capabilities for that module: a job is granted
only where they hold every capability its stage requires (`stages[].requires.capabilities`), and a unit of work binds
only to a class with such a node. A failed check proves nothing else: one named after no capability (`pysam_import`,
`disk_free_20gb`) keeps the module from being certified (the doctor is not `healthy`) and so off the stages that need
certification, never off a stage that needs none.
`gpu_apis` are the GPU APIs the node provides on the host and inside its containers, each detected by asking the API's
runtime for a GPU device (`oarbank-agent gpu-apis` prints the same object; docs/design/gpu-placement.md), with what was
found or why not per API. The agent probes at start and whenever its doctors run, never on a timer. A job is granted
only where every GPU API group its stage needs is met (`GPU_API_MISSING`; the runner's `gpu.apis_any` for the node's
platform, on the host or with `in_container` in containers, and those of GPU services it reserves a pool of); a module
whose runner needs an API the host lacks is not offered there (the agent reports it `undetected`, with a `gpu_apis`
check) and is excluded by oarbankd. A node that has not reported provides none.
Each module's report carries `ran`: true when its runner printed a DoctorOutput, false when the agent wrote the report
itself because the doctor did not start, crashed, hung or printed something else (then its only check is `doctor`, whose
detail ends with the last 4000 characters of what the doctor printed). Modules with `ran` true are offered in claims,
whatever their health; a report without `ran` (an older agent) counts as run unless it is that `doctor` failure. Check
details are kept and shown whole (`oarbank node show`, the node page). oarbankd records `unhealthy` as `doctor_failed`
and alerts; `undetected` is recorded as such and never alerts. Neither is certified, so only stages that need no
certification run there (docs/design/stage-gating.md). Release-install refusals appear as `release_install`.

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
  its results depend on when it ran. Its jobs are otherwise ordinary (fenced, stage retry, placement). S21 checks it.
- **Stages that need no certification** (docs/design/stage-gating.md): a bootstrap stage, and a stage that compares
  nothing and requires no capability and no pool (oarbank-sdk `Manifest.certification_exempt`). Their jobs run on any
  node where the module's runner started, before its goldens pass, and their results carry no certification fence;
  they never count toward certification. S8 holds them to a state the doctor decides.
- **Offers.** A node is granted only jobs of modules it is certified for, except jobs of stages that need no
  certification.

## Staged jobs (stage chains)

A module whose manifest has a stage `B` with `after = "A"` can run a job as the chain A → B. Its
single-stage form is the default stage: the one marked `default = true`, or the only stage that neither runs `after`
another nor is depended on. The chain is enabled when the module's pipeline is split (the setting `[module] pipeline`:
`oarbank settings set pipeline split --module <name>`), for jobs that name no stage. A `jobs.enqueue` item that names a standalone stage
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

Both are the node's complete effective settings (docs/design/settings.md): the coordinator resolves every key (its
default, the fleet's value, the node's groups', the node's own) and sends every key in every hello and heartbeat reply,
with `settings_rev`, the revision at which they last changed. The agent checks each key against its table (generated
from the coordinator's registry): a value of the wrong type or out of range, a missing key or one this agent does not
know is refused, keeps its previous value (before the first heartbeat: the table's default) and is reported in the next
heartbeat:
```json
"settings": {"applied_rev": 42, "rejected": [{"key": "job_mem_gb", "reason": "expected a number, got \"abc\""}]}
```
Owners change them with `settings.apply` at the fleet, a group or a node; there is no per-node copy to edit.

**Managed on this machine.** The machine's managed policy may set keys of either section under `Settings` (macOS
domain `dev.codonic.oarbank.agent`, the `Settings` subkey of `HKLM\SOFTWARE\Policies\Codonic\Oarbank\Agent`,
`/etc/oarbank/policy.json`; docs/install.md, "MDM"). The agent applies each only where it is stricter than what the
coordinator sends (and over its defaults before the first heartbeat), so it can only tighten: the keys the table marks
`managed`, in each key's `tighten` direction. When the policy sets any, the report adds them:
```json
"settings": {"applied_rev": 42, "rejected": [],
             "managed": [{"key": "run_on_battery", "value": false, "binding": true}, {"key": "jobs", "value": 4, "binding": false}],
             "managed_refused": [{"key": "job_mem_gb", "reason": "not a setting managed policy may set"}],
             "managed_by": "Example Org"}
```
`binding` says the managed value is what applies (stricter than the coordinator's). The coordinator keeps the report,
shows it ("Managed on this machine") and folds it into the node's resolution where it is stricter.

**Limits** (user caps): every key is present; `null` means uncapped (the default). Every scope's cap applies and the
lowest wins:
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
{"os_reserve_gb": 6, "user_reserve_gb": 8, "user_present_slots": 2, "user_idle_s": 300, "screen_sharing_present": true,
 "run_on_battery": false, "mem_in_use_bound": true, "job_mem_gb": 1.5, "threads_per_job": 1, "max_slots": null,
 "nice": 10, "hard_limits": false, "disabled_services": ["example/vm"], "module_settings": {"example": {…}},
 "protection": {"schema": 1, "node": {"mode": "moderate"}, "rule": [ … ]}}
```
- **Defaults** come from the settings registry; `os_reserve_gb`'s is computed from the node's RAM (4 GB up to 32 GB,
  8 GB from 96 GB, else 6), so it follows the hardware the node reports. Nothing is copied at enrolment.
- **`screen_sharing_present`** (default `true`): a macOS Screen Sharing session counts as someone using the machine
  even without input.
- **`mem_in_use_bound`** (default `true`): the memory for jobs never exceeds what the machine has available now (see
  Capacity and host protection); `false` leaves the reserves alone.
- **`disabled_services`** sets a node's role: `<module>/<service>` for each service a module does not run here, which
  the coordinator computes from each module's effective `[module] services.disabled` for the node (set for the fleet, a
  group or the node). Changing a module's re-doctors and re-certifies that module on the node.
- **`module_settings.<module>`** is exactly what that module's runners, doctor and services read on this node in
  `OARBANK_SETTINGS_FILE`: each key its settings schema declares with `"x-oarbank": {"scope": "node"}`, resolved for
  the node (the fleet's, a group's or the node's value, else the key's default; a key with neither is absent). A module
  appears only when it has such a value, and never sees another module's keys. The agent rewrites a module's file only
  when its content changes, through a temporary file and a rename; a bootstrap job gets `{}`.
- **Session helpers** (a system install; docs/design/protection.md, "Whose processes") report one JSON line every two
  seconds to the agent's local endpoint. The agent sends lines back: `{"v": 2, "watch": [{"key", "kind":
  "progress|phase", "account", "rel", "spec"}]}`, the owner sources under the person's home the helper should read
  (when the list changes and on each connection; `spec` is the source without its path). The helper's report then
  carries `"sources": [{"key", "events", "epoch", "on", "readable", "event_t"}]` (counts and phase states, never file
  contents), and it reports at once when a phase changes (docs/design/gpu-cotenancy.md).
- **`protection`** is owner-set host protection (schema 1): the node's effective section, which the coordinator
  assembles from the settings chain (`protection.mode`, `protection.rules` from every scope together, `protection.node`;
  a rule the node's OS cannot run is left out). See docs/design/protection.md and docs/design/settings.md,
  "Protection on the chain".
- **`hard_limits`** (default `false`) turns each job's reservation (`resources.cpu`, `resources.mem_gb`) into hard
  limits where the OS has them: a cgroup v2 leaf on Linux (when systemd delegated the agent's cgroup), the Job
  Object on Windows; macOS has none. A job over its memory limit fails with `oom`, the job's fault.

## Capacity and host protection

The agent computes `capacity` every tick and sends it in the heartbeat:
```json
{"cpu_slots": 10, "mem_gb_free": 14.5, "pools": {"containers": 3}, "auto_cpu_slots": 12, "idle_cpu_slots": 12,
 "slots": 9, "auto_slots": 9, "user_present": false,
 "binding_limit": "auto|cap.jobs|cap.cpu_cores|cap.mem_gb|rule:<id>|guard:memory|thermal|battery|memory_in_use|user",
 "admit": true, "why": null, "pool_jobs_only": false, "gpu_jobs": null, "reserved_cpu": 0, "reserved_mem_gb": 6.1,
 "host_budget_gb": 14.5, "mem_binding": "reserve|in_use|cap", "mem_budget_reserve_gb": 44.0,
 "mem_budget_in_use_gb": 14.5, "mem_in_use_gb": 40.9, "mem_margin_gb": 8.68, "paused": [], "paused_by": null}
```
`paused` and `paused_by` are what the claim sends (see Work): a rule pausing `all` or `io` also stops admission
(`admit` false, `why` and `binding_limit` the rule), one pausing `gpu` sets `gpu_jobs` to 0.
`host_budget_gb` is the smaller of the reserve bound (RAM minus the OS and user reserves, the services' and protection's
reservations) and the in-use bound (memory available now plus the fleet jobs' resident share of their reservations,
minus the memory guard's soft floor and 1 GB), and of the owner's `mem_gb` cap; `mem_binding` names which.
`mem_in_use_gb` is what everything but the fleet's jobs uses; `idle_cpu_slots` is the CPU slots with nobody present.
Cores are physical (`perf + eff/2`); the formulas and the per-OS readings are in docs/design/protection.md, "Capacity".
`cpu_slots` and `mem_gb_free` are what fleet jobs may still use; `pools` are what the node's services provide, plus the
agent's own `containers` pool (its container runtime, while it can run containers: a Windows node whose session is not
ready offers none) and `gpu` pool (one token where containers can get the node's GPUs through CDI; never on macOS) (a
node that reports none is offered no pool work). The facts' `containers.gpu` says which: `cdi:<kind>` or
`undetected`. They are computed after:

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
