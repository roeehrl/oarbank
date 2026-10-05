# The module sandbox (design, built)

**Status (2026-10-02):** built. The contract lives in the SDK ([spec/sandbox.md](https://github.com/roeehrl/oarbank-sdk/blob/main/spec/sandbox.md)).
This page records the decisions, the threat model and how the core and the agent implement it.

**Update (2026-10-03, protocol 1.0):** the grants became platform-neutral: `net` (`none`, `egress-allowlist` through the
agent's local proxy, `egress-any`), `tools` (registry ids the operator maps to host paths per OS, replacing
`host_paths`), `devices.gpu` and `exec_writable`. Every node reports per-capability enforcement, and the coordinator
places modules only where every rule they need is enforced. A coordinator on an OS with no backend yet refuses to
start module processes instead of running them unconfined.

## The requirement

Modules are third-party code. A module must not be able to read or write anything on a host outside its own
bundle, its persistence folder inside the oarbank namespace and, for a job, its work directory. That holds on the
coordinator and on every node, for every module process: the coordinator side, runners, `doctor`, services and probes.

## Decisions (the owner's, 2026-10-02)

1. **Seatbelt profiles generated per process.** The same approach Chromium, Codex CLI and Claude Code's
   sandbox-runtime use. App Sandbox does not fit: the inherit entitlement needs a sandboxed, signed parent and a
   re-signed interpreter per module. A separate macOS user per module needs root and still sees group-readable files.
2. **Network is off unless declared and approved.** Grants (`net`, `tools`, `devices.gpu`, `exec_writable`,
   `containers`; originally `network`, `host_paths`, `gpu`) are declared in `[sandbox]` and approved by an operator per module version, by the digest of the
   requests (`modules.approve`, T2 with preview). An unapproved version cannot be enabled, canaried, pinned or promoted.
3. **Docker and VMs go through an agent broker.** Colima's default VM mounts `$HOME` writable, so access to its
   Docker socket is access to the whole home. A module never reaches Docker. The agent owns a Colima profile,
   `oarbank`, that mounts only `~/Library/Application Support/Oarbank/agent/work` and `~/Library/Application Support/Oarbank/agent/modules-data`, and runs validated `docker run --rm` requests
   for approved, digest-pinned images. The broker listens on a per-job socket, the only socket the job's profile allows.
4. **Enforced immediately**, with no report-only period. Modules adapt: egress for what they sync, tools from the
   operator's registry, containers through the broker instead of their own VM service.

## Threat model

| Threat | Defence |
|---|---|
| A module reads `~/.ssh`, the keychain, the user's files, oarbankd's database or keys | `(deny default)`; only the module's own directories, the interpreter and the system are readable. The keychain's mach service is not allowed. |
| A module writes outside its directories, or plants code elsewhere (launchd jobs, shell profiles) | Writes are allowed only in its data, work and tmp directories; `launchctl submit` and AppleScript are denied. |
| A module escapes through a child process | The sandbox is inherited across fork and exec, and a sandboxed process cannot re-sandbox itself. |
| A module reaches local daemons (ssh-agent, Docker, other unix sockets) | No `network*` rule covers unix sockets, except the job's broker socket, by literal path. |
| A module talks to the internet without the owner knowing | No sockets at all without an approved `egress` grant; the requested hosts are shown at approval. |
| A container mounts the user's home | The broker validates every mount (resolved inside the job's work dir or the module's data dir). The runtime VM mounts nothing else. Images are approved by digest. |
| A path trick (symlink, hard link, `..`) | Rules match resolved paths; parameters are realpath'd; hard links and renames out of denied directories fail. |
| The launcher fails and the module runs unconfined | The launcher only execs after `sandbox_init` succeeds (else exit 70). The parent checks `sandbox_check(pid)` and kills a process that is not sandboxed. |
| A new module version quietly widens its grants | Approvals are per version and per digest of the requests. |

Residual risks: SBPL is undocumented, so the escape tests run on every macOS version. `sysctl-read` exposes
hardware details. ENOENT and EPERM differ, which reveals whether a path exists. Egress is per IP, not per host.

## How it is built

- **One generator.** `oarbank_sdk.sandbox` renders the profile. The text depends only on the counts of paths and the
  grants; paths enter as parameters. The agent's `oarbank-core` renders byte-identical text, checked by both test
  suites against `spec/sandbox/golden`.
- **Coordinator** (`coordinator/modsandbox.py`, `modulehost.py`). Each module process starts through the SDK's launcher.
  - Read: its bundle (with its `.venv`), the interpreter and oarbankd's import roots.
  - Read-write: `<home>/modules/data/<name>` and `<home>/tmp/modules/<name>`.
  - After the `initialize` handshake the host checks `sandbox_check`.
  - Install self-tests and a coordinator move's target-side integrity checks run sandboxed too.
  - There is no switch to turn it off. Without a backend on the OS, module processes are refused (fail closed),
    never started unconfined.
- **Agent.**
  - `oarbank-agent sandbox-exec PROFILE K=V -- argv` is the launcher.
  - Runners, `doctor`, services and probes all start through it, with the module's approved grants from the
    release's `modules.json`.
  - The runner environment is the job's: its home and temporary directory inside the work dir, plus
    `OARBANK_MODULE_DATA` ([A runner's home](#a-runners-home-decision-2026-10-05)).
  - The launcher tells the agent when its sandbox holds, just before the module runs: one byte on a pipe it inherits
    (an event on Windows), named in `OARBANK_CONFINED` and closed before the module starts. The agent waits for that
    or the launcher's exit, never a fixed window, then checks the confinement (`sandbox_check` here) and kills a
    process that is not confined. A 60 s guard catches only a hung launcher (`sandbox_hung`).
  - Every container's leader is in its container before it runs a line, so all it starts is born there: on Windows
    it starts suspended and runs only once in its Job Object; on Linux it enters its cgroup between fork and exec.
  - On Windows the agent watches each sandboxed job and service for as long as it runs: any member of the job
    besides the shim outside the AppContainer kills it (`sandbox_escape`). None is allowed: children inherit the
    AppContainer, breakaway is refused, and the console host Windows starts for a console client runs in the
    client's AppContainer. The runner gets a console without a window, which its console children share.
  - The broker and the agent's container runtime (the `oarbank` Colima profile, the host's Podman or Docker, the
    agent's WSL containers session on Windows) provide the `containers` pool.
- **Conformance.** `oarbank-sdk conform` runs the runner and `doctor` under the module's sandbox, so violations show
  up before install.

## A runner's home (decision, 2026-10-05)

**Decision.** A job's home is its work directory and its temporary directory `<W>/tmp`, on every OS, and every per-user
location a runner's environment names points into it, set explicitly (`sys.rs` `os_env` in the agent,
`oarbank_sdk.portable.os_env` on the coordinator; the SDK's spec/platforms.md, "What the home is"):

| | macOS, Linux | Windows |
|---|---|---|
| home | `HOME=<W>` | `USERPROFILE=<W>` |
| configuration, data, state | `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME` under `<W>` | `APPDATA=<W>\AppData\Roaming` |
| caches | `XDG_CACHE_HOME=<W>/.cache` | `LOCALAPPDATA=<W>\AppData\Local` |
| temporary files | `TMPDIR=<W>/tmp` | `TEMP`, `TMP`; inside the AppContainer `<W>\AppData\Local\Packages\<container>\AC\Temp` |

All of it is deleted with the work directory after the attempt. A module's env may not set any of these names. A
doctor, a service, a probe and the coordinator side's processes have the module's data directory as their home: they
are the module's long-lived parts on a node, not attempts.

**Why per attempt.** The sandbox's intent is that an attempt starts from the same state wherever and whenever it runs:
certification by goldens and exact result digests rely on it, and a replayed job must not depend on what an earlier one
left. Anything one attempt leaves for the next is also a channel between attempts, and across releases between
versions of a module (a cache poisoned by one version read by the next). What a module means to keep on a node has a
place of its own, `OARBANK_MODULE_DATA`: explicit, per module, removed with the module. A runner that wants a warm cache
points the tool there itself (`UV_CACHE_DIR`, `HF_HOME`).

**Evidence.** Tools that keep caches or configuration in per-user locations (pip, uv, npm, Hugging Face, matplotlib,
anything following XDG) create them when they are missing, so an empty home costs a cold cache, not a failure. The one breakage found was Windows'
own: starting a process in an AppContainer rewrites `LOCALAPPDATA`, `TEMP` and `TMP` to
`<LOCALAPPDATA>\Packages\<container lower-cased>\AC` (and its `Temp`) under whatever `LOCALAPPDATA` the parent passed,
and Windows creates that folder only under a profile's own. Under a work directory it did not exist, so `GetTempPath`
named a missing directory: on the Windows VM `uv venv` failed with os error 3, and Python's `tempfile` quietly fell back
to the working directory. That is a missing folder, not a reason to keep state: the module launcher (`sandbox-exec`)
creates it before the start. The coordinator had worked around the same rewrite by passing the host account's
`LOCALAPPDATA`, which shared the container's real profile folder between every run and install of a module; it now
follows the same rule. The rejected alternative, a module-scoped cache the agent manages, would carry state between
attempts that no grant shows and no approval covers.

**Tests.** The agent's `doctor::tests::every_per_user_location_lies_in_the_home` and the SDK's
`test_every_per_user_location_lies_in_the_home` pin the variables per OS; `tests/rust/test_agent_jobs.py
::test_a_runner_s_home_and_temporary_files_are_its_work_directory_s_and_go_with_it` runs a real job on macOS, Linux
and Windows (in its AppContainer there): every location lies in the work directory, the OS's temporary directory exists
and takes a file, and the work directory is gone after the attempt.

## Rollout

1. Publish the SDK spec; module authors adapt (done for the spec: oarbank-sdk 7d09987).
2. Deploy oarbankd (coordinator processes sandboxed at its restart; both shipped modules' coordinators pass under it).
3. Agent 0.6.0 through self-update: canary on one node, then promote. From then on, jobs of a module that needs grants
   run only once a compliant, approved version is current.
4. Approve each module version's grants on the Modules page or with `oarbank module approve <name>@<version>`.
