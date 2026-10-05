# Service endpoints: jobs reach a warm per-node service

Status: built (oarbank-sdk issue #12; PLAN D36) in **oarbank-sdk 1.5.0** and **core 2.5.0**; see Implementation status.

## The problem

LLM batch work, embeddings, image generation and speech-to-text load a model that costs seconds to minutes and many GB
of memory. The efficient shape is one warm model server per node, with every job on the node sending it work. Service
protocol 1 already runs long-lived node helpers (`[[services]]`), but a job cannot reach one: the sandbox's network rules
hold in every mode (never loopback, never listening, no unix socket or pipe but the job's broker endpoint). So modules
load the model in every job and make jobs large to amortise it, which costs scheduling granularity, replica checks per
item, and twice the memory when two jobs on one node load the same model. Services also cannot declare GPU use, so host
protection cannot account for a GPU-resident server.

## The decision

A service declares `endpoint = true`. The agent, never module code, owns every end of every channel:

- The service gets one **endpoint channel** when the agent starts it: an inherited, already-connected stream
  (`OARBANK_ENDPOINT_CHANNEL`). Every connection a job opens arrives on it as a handle, the way socket activation hands a
  daemon its sockets. The service never creates, binds or listens on anything.
- Each attempt whose stage reserves one of the service's pools (`requires.pools`) gets a **connector**: another inherited,
  already-connected stream, in `OARBANK_SERVICE_<NAME>`. To open a connection the job asks the agent on its connector;
  the agent makes a fresh connected pair, gives one end to the job and the other to the service, and keeps neither once
  each has said it has its end.
- The connection is a plain byte stream between the job and the service. The SDK speaks HTTP/1.1 over it.
- When the attempt ends the agent kills its process container (which closes every connection end the job held), closes
  the connector and tells the service the attempt ended, so it drops whatever it still holds for it.

Nothing is reachable by name: there is no socket path, pipe name or port that another job, another module or a
process of the owner could find. The sandbox rules stay exactly as they are, so a job's and a service's confinement need
no new grant and no operator approval (both ends are the same module, under the same approved grants).

### Why handles, not a per-attempt socket path or pipe name

The issue sketched a per-attempt endpoint that only the job's sandbox can reach, with the Seatbelt, Landlock and
AppContainer rules allowing exactly that path or pipe. Each backend was checked:

| | A per-attempt path or pipe name | An inherited, already-connected handle |
|---|---|---|
| macOS (Seatbelt) | works: `(remote unix-socket (path-literal …))`, as the broker does | works: nothing to allow (tested: a deny-default profile receives a connected socket over an inherited one with `SCM_RIGHTS` and uses it) |
| Linux (Landlock, seccomp) | does not hold: seccomp must allow `socket(AF_UNIX)`, and Landlock only restricts `connect` to pathname sockets from ABI 9 (`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`, not in Linux 7.0, ABI 8). The job could reach every pathname socket its account may write: the session bus (`systemd-run --user`), an ssh agent, a Docker socket | works on every Landlock ABI: `recvmsg` on an inherited socket needs no `socket()` call, so seccomp keeps refusing `AF_UNIX` |
| Windows (AppContainer) | partly: a pipe whose DACL grants the module's AppContainer SID is open to every process of that module, other attempts included; telling attempts apart needs a check per client on top | works: the agent duplicates the handle into a process it has verified is in the attempt's Job Object |

The handle design holds on every backend and every kernel the sandbox supports, gives one protocol shape on all three
operating systems, and keeps "no other socket or pipe" literally true.

## Manifest (SDK)

```toml
[[services]]
name = "model"
exec = ["python", "-I", "{bundle}/model_service.py"]
lifecycle = "on_demand"              # or "always"; never "manual" for an endpoint
endpoint = true                      # jobs reach it through OARBANK_SERVICE_MODEL
provides = { pools = ["model"] }
reserves_host_memory = true          # fingerprint reserve.mem_gb is charged while it runs
yieldable = true                     # host protection may stop it (and release the jobs using it)
gpu = { use = "shared", apis_any = ["metal", "cuda"] }

[[stages]]
name = "summarise"
requires.pools = { model = 1 }       # each job holds a model token and gets the endpoint
```

**Fields.** `Service.endpoint: bool = False` [beta]. `Service.gpu: ServiceGPU` [beta], `{use = "none" | "shared" |
"exclusive", apis_any = []}`, as `runner.gpu` without the runner-only keys.

**Rules** (spec/manifest.md, new rule 16; the lint list becomes 17; errors in `oarbank-sdk check`, at install and in
the core's catalogue):
1. An endpoint service provides at least one pool: a job reaches it through a pool its stage reserves.
2. An endpoint service's lifecycle is `on_demand` or `always`: the agent never starts a `manual` service, so it could
   never hand it a channel.
3. A service whose `gpu.use` is not `none` needs `[sandbox].devices.gpu = "compute"` (the approved grant that lets it
   reach the GPU at all).
4. `services[].endpoint` and `services[].gpu` need `requires.core >= 2.5` (rule 12): a 2.4 core would ignore them
   silently, and the module's jobs would find no endpoint.

`OARBANK_SERVICE_<NAME>` uses the service name upper-cased; names are `^[a-z][a-z0-9_]*$`, so two services never map to
one variable. A job gets the variable for every endpoint service providing a pool its stage reserves
(`requires.pools`); `needs_pools` (a pool that must merely exist) gives no endpoint, so every connection is backed by a
counted reservation.

## The endpoint protocol (service protocol 1, additive)

Every message is one JSON object on one line (UTF-8, at most 4096 bytes). Handle values travel in two forms, hidden by
the SDK: `fd:<n>` and an `SCM_RIGHTS` file descriptor on macOS and Linux, `handle:<n>` and a handle value on Windows.

**Connector** (job ↔ agent; one per attempt and endpoint service; requests are answered in order):

| Job sends | Agent answers |
|---|---|
| `{"op": "connect", "pid": <the requesting process>}` | `{"ok": true, "conn": <n>}` with the connection's job end: one file descriptor attached to the answer (POSIX), or `"handle": <n>`, a handle already in process `pid` (Windows) |
| | `{"ok": false, "error": <code>, "detail": <text>}` |
| `{"op": "received", "conn": <n>}`, once it has the end | |

Refusals: `service_unavailable` (the service is not running and ready, or did not come back within its
`start_timeout_s`), `bad_pid` (Windows: `pid` is not in this attempt's process container), `rate_limited`, `ended` (the
attempt is ending), `bad_request`. A connect waits while the service is restarting (event-driven, until it is ready or
the start timeout passes); it never polls.

**Endpoint channel** (service ↔ agent; one per service run, given to `start` and inherited by what it leaves running):

| Direction | Message |
|---|---|
| service → agent | `{"op": "hello", "pid": <the accepting process>}`, once, before `ready` answers true: the service is accepting, and on Windows the process the agent places handles in |
| agent → service | `{"op": "connection", "conn": <n>, "attempt": <attempt id>}` with the connection's service end (`SCM_RIGHTS`, or `"handle": <n>` already in the hello's process) |
| service → agent | `{"op": "accepted", "conn": <n>}`, once it has the end |
| agent → service | `{"op": "ended", "attempt": <attempt id>}`: the attempt is over and its processes are gone; close anything left of it |

**Receipts.** The agent keeps its copy of each end it sent until the receiver's `received` or `accepted`, then closes
it. macOS disposes of a socket in flight whose last outside reference closes while the receiver is still installing it:
measured, a pair whose two ends a sender closed right after `sendmsg` broke within a hundred hand-overs on macOS, never
in thousands on Linux; with the receipts, none broke in thousands on either. On Windows nothing is in flight (the handle
is duplicated straight into the receiver), so the agent closes its copies at once and ignores the receipts; the SDK
sends them everywhere, so a module has one protocol.

End of file on the channel means the agent is gone or is stopping the service: the service exits. The agent closes its
end when the service stops, and treats end of file from the service as the service's failure (its process group is
ended and the restart policy applies). The channel is given only to `start`, never to `fingerprint`, `stop` or the
other ops.

**Readiness.** The readiness gate opens for an endpoint service only once `ready` answered true and the hello arrived,
so a runner never starts before its service accepts.

**Adoption.** An endpoint service lives no longer than the agent that started it: its channel ends with that agent.
After an agent restart, an endpoint service found running (`fingerprint.running`) has no channel, so the agent stops it,
and starts it again when a job needs it. (A service that does not exit on the end of its channel is still stopped
then.)

## Per OS

| | macOS | Linux | Windows |
|---|---|---|---|
| Connector and channel | a `socketpair(AF_UNIX, SOCK_STREAM)`; the module's end is inherited through the launcher's exec (close-on-exec cleared only in that child, between fork and exec) | the same | a duplex named pipe with a random name, created by the agent, its client end opened at once and made inheritable; the launcher shim adds it to the module's handle list (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) beside the standard handles and the control event |
| A connection | a fresh `socketpair`, one end to each side with `SCM_RIGHTS` | the same | a fresh named-pipe pair (first instance, remote clients refused, the agent's default DACL), both ends synchronous; each end duplicated (`DuplicateHandle`) into the verified job process and the service's hello process |
| What the module's sandbox allows | unchanged | unchanged (seccomp still refuses `socket(AF_UNIX)`) | unchanged |
| Process checks | none needed: a descriptor goes only to whoever reads the connector | the same | `pid` must be a member of the attempt's Job Object (connector) or of the service's Job Object (hello), checked on the process's own handle (`IsProcessInJob`), else `bad_pid` |
| Concurrency on one connection | full duplex | full duplex | synchronous pipes serialise I/O on a handle: one thread at a time reads or writes (an HTTP request, then its response); the agent's own ends are overlapped |

All three are built. An agent with a sandbox backend reports `endpoints` as `enforced` in the facts' sandbox
enforcement, and the coordinator places a module with an endpoint service only on a node that reports it
(`CAPABILITY_NOT_ENFORCED` otherwise, as for every grant), so an older agent never gets a job it could not connect.

## The agent

- **Channel at start.** A `start` of an endpoint service gets a new channel. The agent reads hello on a thread of its own
  (blocking reads: no polling); a hello from a process outside the service's container is ignored (Windows).
- **Per attempt.** After the readiness gate, the agent opens one connector per endpoint service the attempt reserves a
  pool of, before it spawns the runner, and starts a thread per connector. On Windows it learns the attempt's Job
  Object when the runner is spawned; a request that comes first waits for it.
- **A connect** is answered from the service's state: if it is running, ready and greeted, the agent makes the pair,
  sends the service end on the channel (one `sendmsg` per message, so descriptors and lines stay in order) and answers
  the job. Once each side has said it has its end the agent keeps no copy, so either side closing is seen by the other
  at once.
- **Attempt end.** After the attempt's container is killed, the agent shuts its connector down, joins the thread and
  sends `ended` to every service the attempt had a connector to.
- **Limits.** A token bucket per connector (64 at once, 32 a second after that) answers `rate_limited` beyond it, so a
  job cannot flood the agent or the service with connections. The SDK's service side keeps at most 64 open connections
  per attempt and closes the oldest beyond that (configurable).
- **Readiness without polling.** The service manager signals every state change (ready, hello, stopped); a job waiting
  at the readiness gate and a connect waiting for a restart wait on that signal, not on a timer.

## Host protection

- **Services are fleet work.** The processes of every running service join `fleet_pids`, so their memory, CPU and GPU
  are never taken for the owner's, and no owner rule matches them. (Before this, a module service's GPU use could make a
  `gpu_active` rule fire against the fleet's own work.)
- **Accounting.** `reserves_host_memory` keeps charging `fingerprint.reserve.mem_gb` to capacity. A running service with
  `gpu.use` other than `none` is GPU-resident fleet work.
- **GPU jobs.** A job reserving a pool of a GPU service is a GPU job, in the agent (protection's job view) and in the
  coordinator (`GPU_BLOCKED` while the node may admit no more GPU jobs).
- **Stopping a service** (`yieldable = true` only; a service with `yieldable = false` is never stopped by protection):
  the controller's tick result gains `service_stops` (service key and release reason), a level that holds for as long as
  its cause does:
  - the memory guard's hard floor picks its victim among jobs and yieldable services alike (largest footprint); a service
    picked is stopped (`preempt_memory`, journaled `MEMORY_HARD_FLOOR_SERVICE`). Like every hard-floor victim this is
    one stop, then a wait for the reclaim; the soft floor that follows keeps an idle yieldable service from starting
    again;
  - a rule's `evict` stops every yieldable service with the jobs (`preempt_protection`);
  - while GPU work may not run (`gpu_jobs` is 0: the owner's `gpu_jobs = "never"`, a protected process using the GPU, a
    rule's GPU cap or pause), every yieldable GPU service stops (`preempt_protection`).
  The agent stops each such service (`stop`, its channel closed, then its process group), keeps it down while the stop
  holds, and releases every attempt using it with the same reason, so those jobs are re-queued without a charge. Idle yieldable services
  still stop under the soft floor, as before. Each stop is journaled (`service_stopped`), and the node page shows the
  services held down and why.

## The coordinator

- **Release entry.** The module entry's service carries `endpoint: true` and `gpu: {use, apis_any}` only when set, so
  other entries keep their bytes.
- **GPU jobs.** `modcalls.job_uses_gpu` also holds for a job whose resources reserve a pool a GPU service of its module
  provides; claim and explain read it from the same function.
- **Placement.** A module with an endpoint service needs `endpoints` enforced on the node (`platforms.sandbox_gaps`, as
  `gpu.compute` for the GPU grant).
- **The kill switch.** `modules.disable` revokes a module's attempts but keeps it in the release (re-enabling is
  instant), so the agents' services never heard of it. The directives now carry `modules_disabled`; the agent disables
  every service of those modules, which stops them once no attempt uses them. This is "stopping the module" in the
  issue's acceptance.
- `apis_any` places the service and the jobs reserving its pools by the node's GPU APIs, as `runner.gpu.apis_any`
  places the runner's ([gpu-placement.md](gpu-placement.md), D38).

## SDK

- `oarbank_sdk.service_endpoint`, standard library only:
  - **Client:** `connect(name)` opens a connection (a socket on POSIX, a socket-like object over the pipe on Windows);
    `request(name, method, path, body=None, headers=None, timeout=...)` sends one HTTP/1.1 request and returns
    `Response(status, headers, body)` (`json()` decodes); `HTTPConnection(name)` is an `http.client.HTTPConnection` for
    keep-alive. The connector is shared by threads (one request at a time on it).
  - **Service:** `Acceptor()` reads `OARBANK_ENDPOINT_CHANNEL`, says hello, and yields `(connection, attempt_id)`; it
    closes an attempt's connections on `ended` and raises `ChannelClosed` at end of file. `serve_http(handler)` runs an
    `http.server.BaseHTTPRequestHandler` class on every connection, a thread each, and returns when the channel closes.
  - Children of a runner do not inherit the connector unless passed on (`pass_fds`, or `handle_list` on Windows).
- **Conformance.** The kit's new **service** suite runs each endpoint service as the agent does (its `start` with a
  channel the kit owns, sandboxed where the kit sandboxes), checks the hello, the readiness gate, an optional HTTP probe
  per `service_specs` fixture through a connection the kit hands it, `ended`, and `stop`; and it fails **"the service never
  listens itself"** when any process of the service holds a listening socket after `ready` and after the probe (Linux:
  `/proc/<pid>/fd` against `/proc/net/{tcp,tcp6,udp,udp6,unix}`; macOS: `lsof`; Windows: the TCP and UDP tables by
  process), or when the service fails to come up because the sandbox refused it a listening socket.

## The reference module: `modelserver`

`examples/modelserver` in the SDK: an `on_demand`, `endpoint` service that "loads" a fake model once per run (it sleeps
briefly and appends to `<data>/model.loads`) and answers `POST /v1/generate` with a deterministic completion and the
model's load count; jobs of its `generate` stage send prompts through `service_endpoint.request`. It is what the tests
below run on all three operating systems.

## Threat model

| Threat | Defence |
|---|---|
| A job reaches another job's connections or connector | Nothing has a name. A connector exists only as a handle inherited by one attempt's runner; a connection only as handles the agent placed in that attempt (POSIX: sent over its own connector; Windows: duplicated into a process verified to be in its Job Object). |
| A job reaches another module's service | A job gets connectors only for services of its own module that provide a pool its stage reserves, from the signed release. |
| A job reaches anything else local (the session bus, an ssh agent, Docker) | The sandbox is unchanged: on Linux seccomp still refuses `socket(AF_UNIX)`, on macOS no unix-socket rule is added, on Windows no pipe is opened by name. |
| A service listens anyway | It cannot: seccomp refuses `listen`, Seatbelt has no inbound or bind rule, an AppContainer has no server capability. The conformance kit fails a service that listens, before it ships. |
| A job passes something nasty to the service over a connection (a descriptor, a handle) | Both ends are the module's own code under the same grants; what a job can send is what it could already reach. The agent reads the connector and the channel with plain reads, so a descriptor sent to the agent is discarded by the kernel. |
| Handle leaks: a connection outlives its attempt | The agent keeps no copy of a connection's ends past their receipts (and drops any left when the connector or channel closes). The job's ends die with its container, which is always killed when the attempt ends; the service gets `ended` and drops the rest. On Windows the inheritable connector is also inherited by other launcher shims the agent starts meanwhile (unconfined agent code, as for the control event), never by modules: each shim passes on only its own handle list. |
| A connection outlives its service | Stopping or evicting the service ends its process group, so every service end closes and the jobs see end of file. |
| DoS of the service by a job | Connects are rate-limited per connector; concurrent users are bounded by the service's pool tokens (each job holds one); the SDK's acceptor caps open connections per attempt; the service bounds its own work per request. A slow or stuck service fails only its own module's jobs. |
| DoS of the agent by a job or a service | Message lines are capped at 4096 bytes, one thread per connector and per channel, nothing buffered beyond a line. |
| A hello or connect names a process outside the sandbox (Windows) | The agent duplicates handles only into members of the right Job Object, which every module process is born into. |
| An adopted service keeps a channel to a dead agent | An endpoint service is never adopted: the agent restarts it. |

Residual: on Windows, jobs and services of one module share one AppContainer identity, so they can open each other's
processes; that predates endpoints and gives nothing beyond the module's own code.

## Versioning

- Manifest 1, service protocol 1 and runner protocol 1 stay; everything is additive. The new keys need
  `requires.core >= 2.5` (rule 12's table gains a 2.5 row).
- `OARBANK_SERVICE_<NAME>` and `OARBANK_ENDPOINT_CHANNEL` are new reserved names (every `OARBANK_*` name already is).
- `CORE_VERSION` becomes 2.5.0 and the SDK 1.5.0 (with the other 2.5 features).

## Acceptance tests

| Criterion | Test |
|---|---|
| Endpoint and GPU keys validated, floors enforced | SDK `tests/test_manifest.py`: the rules above, each key refused below 2.5 |
| Client and service helpers, one shape across OSes | SDK `tests/test_service_endpoint.py` (macOS, Linux, Windows): HTTP over connections the SDK's stand-in for the agent hands out, concurrent and keep-alive; `ended` cuts what is left of an attempt; the acceptor's cap; refusals; the reference service started as an agent starts it, two job processes loading the model once |
| The kit fails a service that listens | SDK `tests/test_conformance.py`: modelserver passes, its golden run through its endpoint; a variant that opens a port fails "the service never listens itself" (the sandbox refuses the port on macOS, the socket scan finds it on Linux and Windows) |
| Two concurrent jobs share one warm service, which loads once | agent `endpoints.rs`, real processes under the module sandbox on macOS, Linux and Windows: `two_concurrent_jobs_share_one_warm_sandboxed_service_that_loads_once` (the job still reaches no unix socket of its own) |
| The endpoint is reachable only from its own attempt | `a_connect_from_outside_the_attempt_is_refused_on_windows` (`bad_pid`); on POSIX nothing names it |
| Stopping the module tears the service down | `a_release_without_the_module_stops_its_service`; core e2e `tests/rust/test_agent_endpoints.py`: `modules.disable` on a real agent stops the server |
| Host-protection eviction tears it down cleanly | protection `tests/controller.rs` (memory victim, rule evict, GPU stop, yieldable only, journaled once); agent `a_hold_by_host_protection_stops_the_service_and_keeps_it_down` |
| A service's GPU and memory are accounted | protection tests (services are fleet work; GPU services stop under GPU protection); core `tests/test_service_endpoints.py` (a job reserving a GPU service's pool is a GPU job) |
| The release entry, placement, kill switch, console and CLI | core `tests/test_service_endpoints.py`, `tests/test_console.py` |
| End to end with the coordinator | `tests/rust/test_agent_endpoints.py`: modelserver installed, certified through its endpoint, two concurrent jobs on one agent share one load, results accepted |

## Open questions

- **Endpoint services surviving an agent restart.** A restart costs a reload. Keeping a channel across restarts needs a
  hand-over the launcher would broker; not worth it until reloads hurt.

## Implementation status

Built as designed, in oarbank-sdk 1.5.0 and core 2.5.0. Where the build adds to the design:

- **Receipts** (`received`, `accepted`) were added when the macOS in-flight disposal showed up under load (above).
- **`OARBANK_ENDPOINT_CHANNEL`** is the service's variable, not `OARBANK_SERVICE_CHANNEL`, which a service named
  `channel` would collide with in its own jobs.
- **The kill switch** reaches the agents' services through the `modules_disabled` directive (above); before, a disabled
  module's on-demand services stopped only after their idle timeout.
- **Readiness without polling.** The service manager wakes waiters on every change of state; the jobs' readiness gate
  (which slept a second at a time) and a connect waiting for a restart now wait on it.
- **Services are fleet work in protection** (their pids join `fleet_pids`), which also stops a service's own CPU and GPU
  use from counting as the owner's.
- **The conformance kit** runs a golden whose stage reserves an endpoint service's pool with that service up, and has a
  `service` suite. `_endpoint_host` is the SDK's stand-in for the agent's side (overlapped on Windows, as the agent's
  ends are), used by the kit and the SDK's tests.
- **Windows synchronous pipes** need refcounted closing in the SDK's pipe wrapper (`close` waits for the files
  `makefile` returned, as a socket's does), else an HTTP response is lost after `Connection: close`.
- **Found on CI (windows-2025):** Windows Server 2025 refuses an AppContainer the null device, so the reference service's
  `subprocess.DEVNULL` failed there; it now passes on the stdin the agent gave `start` (the Windows backend page says
  so). That start failed after marking itself up, so the service was fingerprinted running without a channel, stopped,
  and started again for ever: a successful `stop` reset the failure count and the error. It no longer does: only a
  service that becomes ready again is past its failures, so such a service backs off and is withdrawn, with its error
  in the report. The Windows sandbox also stopped rewriting a granted interpreter's ACL at every launch (a file's
  entries carry no inheritance flags, so an existing grant was never seen).
- **Found on CI (windows-2025, windows-11-arm), now and then:** a job, a service op or a fingerprint failed to start with
  ERROR_FILE_NOT_FOUND naming the interpreter. Every shim called CreateAppContainerProfile, which races itself: a call
  on an existing profile beside another can delete the profile until a later call creates it again, and CreateProcess
  for a container with no profile fails with ERROR_FILE_NOT_FOUND. A shim now creates the profile only when Windows
  does not know it, one shim at a time.
