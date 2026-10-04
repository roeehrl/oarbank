# Containers on Windows (core 2.5)

Status: built (Implementation status at the end). PLAN D39. Windows nodes get the container runtime macOS and Linux
nodes already have: a module's `container.run` (a digest-pinned image, or a signed image of one of its sets) runs on a
Windows node with the same broker semantics as on Linux: the same refusals, egress, CPU and memory limits, mounts
confined to the job's directories, cleanup by attempt label, and `gpus = "all"` through CDI where the node has a GPU.

Module images are Linux images (`platform = "linux/amd64|arm64"`), so the runtime runs Linux containers in a
virtual machine. The runtime is **WSL containers** (WSLc: `wslc.exe` and the `Microsoft.WSL.Containers` SDK, generally
available since WSL 3.0.1, 2026-09-29), in a **session the agent creates and owns**: its own name, its own storage
under the agent's home, its own VM size, its own settings.

## Versioning

- **No new manifest key, no new broker field, no new floor.** A module that runs containers on Linux runs them on
  Windows unchanged; `requires.platforms` decides whether it may. The broker's request surface is spec/sandbox.md's.
- **The broker endpoint on Windows is a named pipe**, `OARBANK_BROKER=npipe://./pipe/<name>`, which spec/sandbox.md
  already allowed and the SDK's `broker` client already speaks (it now waits for a free pipe instance instead of
  failing on `ERROR_PIPE_BUSY`).
- **Facts gain `containers.gpu_apis`** on every platform, and on Windows `containers.runtime`, `containers.state`,
  `containers.platforms` and `containers.missing` (below). Facts are format 2 and open: a coordinator that does not know
  a key ignores it. `CORE_VERSION` stays 2.5.0, the SDK stays 1.5.0 (both unreleased).

## Decision: an agent-owned WSL containers session

### What was compared

| Option | Isolation from the user | Who maintains the Linux side | Limits, GPU | Unattended install | Verdict |
|---|---|---|---|---|---|
| **WSL containers (WSLc), an agent-owned session** | a VM per session, created by the WSL service for the session's account; nothing shared with the user's WSL distributions (which share one utility VM among themselves) | Microsoft: the session's guest, kernel and engine ship with WSL | `--cpus`, `--memory` per container (cgroups in the session VM); GPU-PV through a CDI spec the guest writes (`microsoft.com/wslc=gpu`) | `WslcInstallWithDependencies` installs the Virtual Machine Platform and the WSL package | **chosen** |
| An agent-owned WSL2 distribution running Podman | a distribution in the account's shared WSL2 VM: root in the VM reaches the account's other distributions and their interop | the agent: a pinned rootfs, its package updates, rootless setup, cgroup delegation (WSL's hybrid cgroups need `kernelCommandLine` in the account-wide `.wslconfig`) | rootless Podman with delegated cgroups; GPU through `nvidia-ctk cdi generate --mode=wsl` (NVIDIA only) | `wsl --import` of a pinned rootfs, then package installs over the network | rejected: weaker isolation, a Linux distribution to keep patched |
| Podman machine (WSL provider) | the same shared VM as above, plus a `podman-machine-default` distribution the user may also use | Podman's machine image | as above | Podman's own installer | rejected: shares a well-known machine with the user |
| Docker Desktop, Rancher Desktop | the vendor's distributions, usually shared with the user's tools | the vendor | as their engine | a desktop app; Docker Desktop needs a paid subscription in larger companies | rejected: a third party's product and licence on every node |
| containerd/nerdctl in a WSL distribution | as the Podman distribution | the agent | as Podman | as the Podman distribution | rejected for the same reasons |
| Windows containers (process or Hyper-V isolation) | strong | Microsoft | Job Object limits | built in on Server | rejected: they run Windows images only; Linux containers on Windows (LCOW) are not a supported runtime |

### Why WSLc

- **The agent owns everything.** The session is created through the SDK with a name only this agent uses
  (`oarbank-<12 hex of sha256(agent home)>`: session names are machine-wide keys, so two agents on one machine, a
  personal and a system one, never collide), storage at `<agent home>\containers\wslc` (the session's VHD: images,
  containers, volumes), the VM's CPUs and memory from the same budget the macOS VM gets (`sizing`: 8, 12 or 32 GB by
  host RAM), and a VHD size cap (100 GB, as the Colima profile's disk). Nothing is read from or written to the user's
  WSL distributions or the user's own containers session.
- **Isolation.** WSL distributions of one account share one utility VM and kernel; a WSLc session gets a VM of its own.
  A container escape lands in a VM that holds only the agent's images and the two directories it mounts.
- **No Linux distribution to maintain.** The guest, its kernel and its Docker engine are part of the WSL package and
  are updated with it (Windows Update or the WSL MSI).
- **The same argument shape as Linux.** `wslc container run` takes `--rm`, `--network none|bridge`, `--cpus`,
  `--memory`, `--label`, `-v`, `--workdir`, `--entrypoint`, `-e` and `--gpus all`; `container list --filter label=`,
  `container rm -f`, `image pull`, `image list --digests --format json`. Windows paths are mounted as they are
  (virtiofs), so a job's directories need no translation.
- **GPU passthrough is CDI.** The session VM gets the host's GPUs by GPU-PV (`/dev/dxg`, mirror mode), and the guest
  writes `/etc/cdi/microsoft.com-wslc.json`: the device `gpu` maps `/dev/dxg`, mounts the host driver libraries
  (`/usr/lib/wsl/lib`, `/usr/lib/wsl/drivers`) read-only and runs the image's `ldconfig` through a hook. It is the
  vendor-neutral equivalent of `nvidia-ctk cdi generate --mode=wsl`, so no NVIDIA toolkit is installed.

### Costs, accepted

- WSLc is new (GA 2026-09-29). The agent needs WSL 2.9.3 or later (3.0.1 is the first GA; the WSL package needs
  Windows 10 2004, build 19041, or later, and WSLc's VM code handles Windows 10's older HCS schema) and loads the SDK
  library shipped beside it, which reports when the installed WSL needs updating (`SDK_NEEDS_UPDATE`). Windows Server
  2025 runs WSL; WSLc says nothing about Server either way.
- **No platform selection.** wslc has no `--platform`: a session runs its host's architecture. An x64 node runs
  `linux/amd64` images, an arm64 node `linux/arm64` (amd64 under emulation is not offered there). `containers.platforms`
  says which, and the broker refuses the other with `platform_unavailable`, as on a Linux host without binfmt.
- **GPU in musl images** fails in WSL 3.0.1: the guest's hook treats a musl `ldconfig`'s exit status as fatal
  (microsoft/WSL#41791). glibc images work.
- **Service accounts are untested upstream.** WSLc creates the session VM in the WSL service and runs the session in a
  per-account COM server; classic WSL refuses only LocalSystem, WSLc checks no account kind. The system scope's virtual
  account (`NT SERVICE\Oarbank`) is expected to work; where it does not, doctor says so and the service can run as a
  dedicated local account (`service install --system --user ACCOUNT`).

## How the agent drives it

- **The session host** (`wslc.rs`, Windows): one thread, in the COM multithreaded apartment, loads `wslcsdk.dll` from
  the agent's own directory (never from the search path), checks `WslcGetVersion` and `WslcGetMissingComponents`,
  creates the session (`WslcInitSessionSettings`, CPU count, memory, VHD size, the GPU feature when the host has a
  hardware GPU) and holds it for the agent's life. It waits on the session's termination event: when the session ends
  (its VM crashed, WSL was updated or stopped), the host records it and creates the session again. A runtime that is
  missing something checks again when the agent's doctors run again (a new release, a restart), when a broker request
  finds it not ready, or when a `wslc` call finds the session gone; nothing polls.
- **Containers through the CLI.** Every container operation is `wslc.exe --session <name> ...` with a fixed shape, as
  the macOS and Linux runtimes run `docker`/`podman`. The SDK's C API has no per-container CPU or memory limit, no
  labels and no listing; the CLI has all three, and a session created through the SDK is reachable by name from the
  CLI of the same account (upstream confirms this is the design).
- **Readiness.** The session is ready once the session exists and `image list` answers (the first container operation
  starts the VM; a host without the Virtual Machine Platform fails there with `HCS_E_SERVICE_NOT_AVAILABLE`). Only a
  ready runtime offers the `containers` pool, and the `gpu` pool only when the session has the GPU feature. Each change
  of state is written to `<home>/state/containers.json` and the agent re-sends its facts (a new hello).
- **Settings the agent requires.** WSLc reads one account-wide setting into every session: `session.hostLoopback`
  (`%LOCALAPPDATA%\wslc\settings.yaml`), the DNS name `host.wslc.internal` that leads to the host's loopback. A Linux
  container on a bridge network cannot reach the host's 127.0.0.1, so the agent's session must not either: the system
  scope's agent owns its account's settings file and sets `hostLoopback: none`; a personal-scope agent never edits the
  user's file and reports `host_loopback` as missing until the user sets it. The settings shape a session when it is
  created, so a session that already runs (the agent's earlier process; the service's, for an administrator's doctor)
  is used as it is.
- **Runs.** `container run --rm --network none|bridge --cpus C --memory <MB>m --label oarbank.attempt_id=<id> --label
  oarbank.module=<name> [--gpus all] [-v <host>:<dst>[:ro]]... [--workdir W] [--entrypoint E] [-e K=V]... <image>
  <args>...`, the image spelled with its registry (`qualified`, as for Podman). Output goes straight to the broker's
  files. On timeout or cancellation the agent kills the `wslc` process and removes the attempt's containers by label.
- **Cleanup.** Attempt containers carry the same labels as on Linux: the broker removes an attempt's containers when it
  ends, and the agent removes every labelled container at start (`reap`). The session's VM idles out after WSLc's idle
  timeout and starts again on the next run.
- **Images.** `image pull <qualified ref>` after the broker's signature check (`imageset.rs`, unchanged) for set images,
  `image list --digests --format json` for `status`. The session's VHD caps the image store at 100 GB.

## Per OS

| | macOS | Linux | Windows |
|---|---|---|---|
| Runtime | the agent's Colima profile `oarbank` | rootless Podman, else Docker Engine | the agent's WSLc session |
| Broker endpoint | unix socket | unix socket | named pipe, DACL: the agent's account and the module's AppContainer |
| Platforms | arm64, amd64 (Rosetta) | the host's, plus binfmt handlers | the host's |
| Limits | `--cpus`/`--memory` in the VM | cgroups | `--cpus`/`--memory` in the session VM (cgroups) |
| Egress | `none` or bridge | `none` or bridge | `none` or bridge; the host's loopback is unreachable (`hostLoopback: none`) |
| GPU | none (`undetected`) | CDI spec on the host (`cdi:<kind>`) | GPU-PV through the guest's CDI spec (`cdi:microsoft.com/wslc`) |
| `containers.gpu_apis` | `[]` | from the CDI kind: `nvidia.com/gpu` → `cuda`, `amd.com/gpu` → `rocm`, `intel.com/gpu` → `levelzero` | `directml` with any hardware GPU (D3D12 and DXCore come with WSL), plus `cuda` where the host's NVIDIA driver installed its WSL library (`libcuda.so.1` in `System32\lxss\lib`) |

ROCm on WSL (Radeon RX 7000 and later) and Intel's Level Zero on WSL work through `/dev/dxg` too, but their user-space
runtimes come in the image, not from the host, so the node cannot attest them: they are not listed. Vulkan through
Mesa's `dzn` and OpenCL through `clon12` are the same (image side).

## The node's report (doctor)

Facts `containers` (every hello; `oarbank-agent facts`; the console's node page):

```json
"containers": {"runtime": "wslc", "state": "ready", "session": "oarbank-3f2a9c0b71de",
               "platforms": ["linux/amd64"], "gpu": "cdi:microsoft.com/wslc", "gpu_apis": ["cuda", "directml"],
               "missing": []}
```

- `state`: `ready` (offers the `containers` pool), `starting`, `missing` (something below is missing), `failed` (the
  last attempt failed; `detail` says how). `absent` when no release wants containers yet.
- `missing`: what stops the runtime, each `{"what": <code>, "detail", "fix"}`: `virtual_machine_platform` (the Windows
  feature; needs a reboot), `wsl_package` (WSL 2.9.3+), `sdk_update` (the WSL installed is older than the agent's SDK),
  `sdk_library` (`wslcsdk.dll` missing beside the agent), `wslc_cli`, `host_loopback`, `virtualization` (the VM cannot
  start: firmware virtualization off, or a VM without nested virtualization), `account` (the session cannot be created
  for this account).
- `gpu`: `cdi:microsoft.com/wslc` only when the runtime is ready and the session has the GPU; otherwise `undetected`.
- **`gpu_apis`** is the field the GPU-API placement work (D38) reads for containers: the GPU APIs a container started
  with `gpus = "all"` can use on this node, tokens from the manifest's open set (`^[a-z][a-z0-9]*$`: `cuda`, `rocm`,
  `directml`, `levelzero`, `vulkan`). Empty whenever `gpu` is `undetected`.

`oarbank-agent containers doctor` prints the same report from a fresh check of the prerequisites and the running
agent's last state (exit 0 when ready, 3 when something is missing); `--probe` also runs a container (and with
`--gpu` a GPU container) through the real runtime. `oarbank-agent containers install` installs what is missing
(administrator; exit 3010 when a reboot is needed), `oarbank-agent containers remove` deletes the agent's session
storage.

## Packaging

- `scripts/package-windows.ps1` fetches `Microsoft.WSL.Containers` 3.0.1 from nuget.org, checks its SHA-256 against
  the script's pin, and puts the architecture's `wslcsdk.dll` (MIT) beside the agent; `check-pe-imports.py` keeps the
  agent free of a link-time dependency on it (it is loaded at run time).
- The MSI installs the DLL. `CONTAINERS=1` runs `oarbank-agent containers install` (the Virtual Machine Platform and
  WSL, unattended; a reboot may follow). Without it nothing is installed and doctor names what is missing.
- Uninstalling (`oarbank-launcher remove`, which the MSI runs) ends the agent's session and deletes its storage through
  `oarbank-agent containers remove` once the service is gone: the images are a cache, never the node's identity. The
  WSL package stays (other software may use it).

## Threat model

| Threat | What stops it |
|---|---|
| A module reaches the container engine directly | It cannot open anything but its broker pipe: AppContainer isolation, and the pipe's DACL names only the agent's account and the module's AppContainer (low integrity label for the latter); remote clients are refused |
| Another local process squats the broker's pipe name | The name has 96 random bits and the agent creates the first instance exclusively (`FILE_FLAG_FIRST_PIPE_INSTANCE`): a taken name fails the attempt |
| A container mounts more than the job's directories | The broker resolves every mount inside the work or data directory (symlinks and junctions followed, `\\?\` paths compared); the runtime gets only those paths |
| A runner swaps the broker's output directory for a junction | The agent holds `broker\` open without `FILE_SHARE_DELETE` for the broker's life (it cannot be renamed or replaced) and creates output files new, never through a reparse point |
| A container reaches the host's loopback services (the agent's proxy, a coordinator) | The session has no host-loopback device (`hostLoopback: none`); `--network none` unless the module is approved for egress |
| A container escapes its namespaces | It lands in the session VM: the agent's images, the job's two directories and nothing of the user's WSL; reaching Windows needs a Hyper-V escape |
| A container escapes into the WSL interop or automount features | Not present in a WSLc session VM (no distribution, no `/mnt/c`, no Windows interop); the only Windows paths are the `-v` mounts |
| A tampered SDK library | Loaded only from the agent's own install directory (Program Files, administrators only), never through the DLL search path |
| An image the module was not approved for | Unchanged: the broker's static list, set signatures checked before the pull, `image_not_approved` |
| Leftover containers of a crashed agent | `reap` by label at start; a session whose agent died ends with it (WSLc releases a session without references) |

## Testing

- **Below the WSL boundary, everywhere.** The run arguments, path spelling, the settings file merge, the image list
  parser, error mapping from recorded `wslc` output (a host without the Virtual Machine Platform, a missing session),
  GPU API detection from a driver library listing, the doctor report, pools from state: unit tests on every OS. The
  broker over its named pipe (round trip, refusals, cancellation, the pipe's exclusivity) on Windows.
- **Real WSL.** The Windows 11 arm64 test VM (QEMU 11.1 with HVF on an M4 Max) cannot run WSL2: with EL2 exposed
  (`virtualization=on`) Windows hangs after the firmware hands over (QEMU's HVF nesting is nVHE only, and Hyper-V since
  24H2 needs VHE), and without it there is no hypervisor. A clone of it with WSL 3.0.1 ran everything up to the VM
  start for real: the SDK library loaded by the agent (version, missing components), the agent's session created
  through the SDK and found by name by `wslc`, the MSI with `CONTAINERS=1` installing the Virtual Machine Platform
  unattended (as LocalSystem, through the SDK; it answers "restart required"), and the doctor reporting first
  `virtual_machine_platform`, then after the restart `virtualization` (the VM cannot start without nesting). The CLI's
  outputs are the unit tests' recorded fixtures. GitHub's `windows-2025` runners have
  nested virtualization and WSL 2 (`windows-11-arm` has neither): CI installs WSL 3.0.1 there and runs
  `scripts/verify-windows-containers.ps1`, the same command a contributor runs.
- **GPU.** No GPU runner: everything below the hardware is tested (detection from the session VM's listing, the
  `--gpus all` argument, pools, the broker's refusals); the live GPU test runs wherever `-Gpu` (`OARBANK_LIVE_WSLC_GPU=1`)
  is given on a machine with a GPU.

### Verifying on hardware we do not have

Each is one command; the output to attach when it fails is named.

| Hardware | Command | Success | Attach on failure |
|---|---|---|---|
| Windows 11 or Server 2025, x64 or arm64, virtualization on, from a checkout (Rust, uv) | `scripts\verify-windows-containers.ps1 -InstallWsl` (administrator for `-InstallWsl`; without it WSL 2.9.3+ must be installed) | ends with `OK: the Windows container runtime works here`; the probe's checks all `"ok": true` | `dist\verify-windows-containers.log` |
| The same with an NVIDIA, AMD or Intel GPU (a WDDM driver with WSL support) | `scripts\verify-windows-containers.ps1 -Gpu` | `OK: ... GPU included`; the report's `gpu` is `cdi:microsoft.com/wslc`, `gpu_apis` has `cuda` on NVIDIA, `directml` on any | the same log |
| An installed Windows agent (MSI with `CONTAINERS=1`), its service running | `"C:\Program Files\Oarbank\oarbank-agent.exe" --home C:\ProgramData\Oarbank\agent containers doctor --probe --gpu` (administrator: it runs in the service's session, which an administrator may open) | exit 0, every check `"ok": true` | its output, and `C:\ProgramData\Oarbank\agent\state\containers.json` |
| Linux with an NVIDIA, AMD or Intel GPU and a CDI spec (`nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml`), Podman or Docker | `oarbank-agent containers doctor --probe --gpu` | exit 0; `gpu` is `cdi:<kind>`, `gpu_apis` names the vendor's API | its output and `ls /etc/cdi /var/run/cdi` |

## Acceptance tests

1. The broker serves `container.run`, `container.pull` and `status` over a named pipe with the Linux refusals
   (`image_not_approved`, `bad_mount`, `network_not_granted`, `gpu_not_granted`, `gpu_unavailable`), output files, a
   timed-out and a cancelled run removing their containers (Windows unit tests).
2. The pipe refuses a second creator of its name; mounts through a junction out of the work directory are `bad_mount`.
3. `wslc` runs get exactly the documented arguments; mounts are Windows paths without `\\?\`; `--platform` never appears.
4. The doctor report names each missing prerequisite from the SDK's flags and from recorded `wslc` errors; the
   `containers` pool appears only in `state = ready`, the `gpu` pool only with the GPU feature.
5. `gpu_apis`: `cuda` exactly when the driver library listing has `libcuda.so.1`; `directml` with any hardware GPU;
   Linux CDI kinds map as documented; macOS reports `[]`.
6. The settings merge sets `hostLoopback: none` and keeps the rest of the file; a personal-scope agent never writes it.
7. Live (gated): the agent provisions its session unattended, a signed digest-pinned image runs with the broker's
   semantics (egress none and bridge, limits visible in the container's cgroup, the two mounts, cleanup by label,
   `image_not_approved`), and `gpus = "all"` reaches the GPU on a node with one.

## Implementation status

Built as designed in **core 2.5.0** and **oarbank-sdk 1.5.0** (both unreleased). Where the build adds to or narrows the
design:

- **Agent.** `wslc.rs` (the session host over the SDK's C API, loaded with `LoadLibraryExW` from the agent's directory
  only; the CLI driver; the report, the settings merge and the parsers, tested on every OS), the broker on a named pipe
  (`broker.rs`: exclusive first instance, the DACL from `oarbank-core`'s `broker_pipe_sddl`, the output directory held
  open on Windows), `container_runtime::probe` and `oarbank-agent containers doctor|install|remove`, pools only from a
  ready runtime (`container_pools`), the facts' `containers` with `gpu_apis` on every OS and the Windows report, a new
  hello when the runtime's report changes. The Windows stub broker is gone: `container_runtime`, `imageset` and the
  broker compile on every OS.
- **Launcher.** `remove` ends the session and deletes its storage on Windows.
- **Packaging.** `scripts/package-windows.ps1` pins and installs `wslcsdk.dll`; the MSI's `CONTAINERS=1`;
  `scripts/verify-windows-containers.ps1` for CI and contributors; the CI job `windows-containers` (windows-2025).
- **SDK.** spec/sandbox.md (the Windows runtime, platforms, the GPU row, `containers.gpu_apis`), the Windows backend
  page (the broker pipe, containers enforcement), the `broker` client waits for a busy pipe instance, the portability
  lint flags a Windows platform without container images of its architecture, the docs site's requirements page and the
  GPU how-to.
- **Core.** The console's node page shows the Windows runtime's state, what is missing with its fix, and the GPU APIs;
  docs/protocol.md documents the facts.
- **Verified** on Windows 11 arm64 (QEMU): the broker over the named pipe including an AppContainer client of the right
  module and the refusal of another, junction escapes, the real SDK and CLI up to the VM start, and the MSI built by
  `scripts/package-windows.ps1` (with the pinned `wslcsdk.dll`) installing with `CONTAINERS=1`. Linux (rootless Podman
  in the Lima VM): the broker refactor with the real engine, and the live test's registry push helper against a real
  `registry:3`. **Not verified here:** a running session VM (no WSL 2 in a nested arm64 guest; GitHub's windows-2025
  runner runs it in CI), the system scope's virtual account driving WSLc (upstream untested; doctor reports `account`
  and the remedy if it fails), and GPU passthrough (no GPU: the gated GPU test runs on contributors' hardware).

## Open questions

- **The service's virtual account and WSLc.** Not blocked in WSL's code, not documented either way. If a real node shows
  WSLc refusing `NT SERVICE\Oarbank`, the conservative fallback is already supported (a dedicated local account for the
  service); making the MSI create one would be the owner's decision.
- **GPU counts.** WSLc passes every GPU or none (`--gpus all` only), as the broker's `gpus` does today.
- **amd64 on arm64 Windows.** Waits for WSLc to select platforms (its source marks it as planned).
