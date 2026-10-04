# GPU placement by API, and GPU in containers on macOS

Status: built (PLAN D38) in **oarbank-sdk 1.5.0** and **core 2.5.0** (both still unreleased, so nothing here bumps a
version); see Implementation status.

## The problem

`runner.gpu.apis_any` and `services[].gpu.apis_any` are declared, validated and carried in the release entry, but they
select nothing ([service-endpoints.md](service-endpoints.md), "Open questions"). A module that needs CUDA is granted to
a Mac, its runner fails, and the job is charged a failure on every node that cannot run it before it is quarantined.
The node also has no truthful way to say what it offers: the facts' `gpus[].apis` is `["metal"]` on Apple Silicon and
nothing anywhere else, written from the platform rather than detected.

And on macOS no container gets a GPU: `containers.gpu = "undetected"`, no `gpu` pool, because the agent's Colima VM
(Apple's Virtualization.framework) has no GPU device for a Linux guest.

## Decisions

1. **The agent's doctor report names the GPU APIs the node provides**, on the host and in its containers, detected by
   asking each API's own runtime for a GPU device, never inferred from the platform. The coordinator places by that
   report, as it places stage capabilities by the doctor's `capabilities` (core 2.3). The facts keep the GPU inventory
   (vendor, model, memory) and lose `apis`, so there is one source.
2. **A job's stage needs, per platform, a list of "any of" groups**, each checked against the host's or the containers'
   APIs: the runner's `gpu.apis_any` (its platform variant applied), and the `gpu.apis_any` of every GPU service
   providing a pool the stage reserves. One pure test is used by the claim path, explain (`GPU_API_MISSING`), capacity
   binding, the stranded check, replica runners and failure anti-affinity: the same places stage capabilities are
   checked.
3. **A module whose runner needs an API the node lacks on the host is excluded on that node** (`GPU_API_MISSING`, like
   `PLATFORM_UNSUPPORTED`), and the agent reports that module `undetected` there, so it is never certified, offered or
   golden-tested where it cannot run.
4. **A service with `gpu.apis_any` is offered and started only on nodes providing one of them.** Elsewhere it is not
   offered, so its pools and capabilities do not exist there, and its report says why.
5. **macOS containers get the GPU through a second, agent-owned Colima profile, `oarbank-gpu`, on krunkit** (libkrun's
   VMM): its virtio-gpu device carries Vulkan to the host (Mesa's Venus driver in the container, virglrenderer and
   MoltenVK on the host). Only jobs that reserved the agent's `gpu` pool run there; every other container keeps the
   Virtualization.framework profile `oarbank` with Rosetta. The node reports `containers.gpu = "virtio-gpu:venus"`,
   `vulkan` in its containers' APIs, and the `gpu` pool.

## The GPU API set

The set stays open (`^[a-z][a-z0-9]*$`): a name nobody detects is valid and matches no node, as an unknown platform
token means "no node of this platform here". The agent and the SDK detect six, each by its runtime enumerating at least
one device that is a GPU (software rasterisers, CPU devices and Windows' Basic Render Driver do not count):

| API | macOS | Linux | Windows |
|---|---|---|---|
| `metal` | `MTLCopyAllDevices` (Metal.framework) returns a device; works headless, so a LaunchDaemon sees it | – | – |
| `cuda` | – | `libcuda.so.1`: `cuInit(0)`, `cuDeviceGetCount` > 0 | `nvcuda.dll`, the same calls |
| `rocm` | – | the HIP runtime (`libamdhip64.so`, `/opt/rocm/lib`): `hipGetDeviceCount` > 0 | the HIP SDK's `amdhip64_7.dll` or `amdhip64_6.dll`, the same call |
| `vulkan` | the loader (`libvulkan.1.dylib`, MoltenVK's portability enumeration): a physical device whose type is not CPU | `libvulkan.so.1`: the same (lavapipe and SwiftShader are CPU devices) | `vulkan-1.dll`: the same |
| `opencl` | OpenCL.framework: `clGetPlatformIDs`, then a device of type GPU or accelerator | `libOpenCL.so.1`: the same (pocl's CPU device does not count) | `OpenCL.dll`: the same |
| `directml` | – | – | `DirectML.dll` loads and a DXGI adapter that is not a software adapter creates a Direct3D 12 device at feature level 11_0 (`D3D12CreateDevice` with no output pointer, which tests without creating) |

Detection runs as the agent's own account, which is what jobs run as: a Linux system install whose `oarbank` account
is not in the `render` or `video` group cannot open `/dev/dri` or `/dev/kfd`, and the report then honestly lacks those
APIs (docs/install.md says which groups to add). It runs in a child process (`oarbank-agent gpu-apis`) with a 60 s
limit (the child ends itself, so the agent only waits for it), so a driver that crashes or hangs while loading never
takes the agent with it; a probe that fails names the API as absent with the error as its evidence.

**In containers** the APIs come from how the runtime passes the GPU through, never from running an image (the agent
runs only images a module was approved for):

| Mechanism | `containers.gpu` | Container APIs |
|---|---|---|
| Linux CDI, an NVIDIA spec (`nvidia.com/gpu`) | `cdi:nvidia.com/gpu` | `cuda` when the spec mounts `libcuda.so`, `vulkan` when it mounts the NVIDIA Vulkan ICD (`nvidia_icd.json`), `opencl` when it mounts `libnvidia-opencl` |
| Linux CDI, any other kind (AMD, Intel) | `cdi:<kind>` | `rocm` when it passes `/dev/kfd`, `vulkan` when it passes a DRM render node (the image brings Mesa) |
| Linux CDI over WSL2 GPU-PV (`/dev/dxg`, an `nvidia-ctk cdi generate --mode=wsl` spec) | `cdi:<kind>` | `cuda` when the spec mounts `libcuda.so` |
| Windows, the agent's WSL containers session ([windows-containers.md](windows-containers.md)) | `cdi:microsoft.com/wslc` | from the session VM's host driver libraries: `directml` with WSL's D3D12 and DXCore and a hardware GPU (the image brings `libdirectml.so`), `cuda` when the NVIDIA driver provides `libcuda.so.1` |
| macOS, krunkit (below) | `virtio-gpu:venus` | `vulkan` (the image brings the libkrun build of Mesa's Venus driver) |
| none | `undetected` | none |

The image's user space is the module's part: a CDI spec gives the device and the driver's libraries, Venus and Mesa's
AMD and Intel drivers live in the image. The conformance kit cannot check that (it has no broker), so the reference
GPU test image below documents what an image needs.

## The doctor report

```json
"doctor": {"at": 1790000000.0, "release_id": "r_…", "capabilities": ["java17"],
           "gpu_apis": {"host": ["metal", "opencl"], "containers": ["vulkan"],
                        "evidence": {"metal": "Apple M4 Max", "opencl": "Apple M4 Max (GPU)",
                                     "vulkan": "no Vulkan loader (libvulkan.1.dylib)", "containers": "virtio-gpu:venus (krunkit)"}},
           "modules": {…}}
```

- `host` and `containers` are sorted API names; `evidence` says, per API and for the container mechanism, what was
  found or why not (a device name, a missing library, an error code). The console shows it; `GPU_API_MISSING` shows
  the node's list.
- The agent probes when it starts, when the doctors run (a release, a change of the services' capabilities,
  `nodes.run_doctor`) and never on a timer: installing a driver is followed by `nodes.run_doctor`, the remedy the
  reason code names.
- **One command prints it**, on any node with the agent installed and for a crowd-sourced detection matrix:
  `oarbank-agent gpu-apis`. It prints exactly the `gpu_apis` object above, plus the platform and agent version.
- The facts' `gpus` keep `{vendor, model, vram_gb, unified}`. Golden lists learn the APIs from `NodeClass.gpu_apis`
  (`{host, containers}`), so a module can give a CUDA node and a Metal node different goldens.

## Placement

**What a stage needs** on a node of platform `p` (`modcalls.stage_gpu_apis`, resolved by `predicates.gpu_need`):

- the runner's `gpu` for `p` (`[runner.variants.<key>].gpu` replaces it whole, the most specific key winning): when its
  `use` is not `none` and `apis_any` is not empty, one group. With `in_container = false` the group is checked against
  the host's APIs and applies to every stage; with `in_container = true` it is checked against the containers' APIs
  and applies only to stages that reserve the agent's `gpu` pool (no other stage can give a container the GPU);
- each service on `p` (`services[].platforms`) whose `gpu.use` is not `none`, whose `apis_any` is not empty and which
  provides a pool the stage reserves (`requires.pools`; `needs_pools` reaches no service): one group against the host.

A node fits when every group shares an API with the node's list for that place. A node that has not reported yet has
empty lists, so GPU-API work waits for its first doctor report.

**Where it is checked** (the same places as `requires.capabilities`, one pure function `predicates.gpu_apis_fit`):

| Where | What |
|---|---|
| `predicates.placement` (claim and explain) | `GPU_API_MISSING`: "Needs one of {apis} {where}; this node provides {have}", remedy `nodes.run_doctor` |
| `modsandbox.node_exclusions` | a runner group against the host (every stage needs it): the module is excluded on the node with `GPU_API_MISSING`, and explain's module check names it with the module's need |
| `placement.classes_running` | capacity binding, a head's feasible classes and the stranded check never pick a class without a node meeting every stage's groups |
| `core._eligible_nodes` | replicas and tie-breaks need another node that meets them |
| `core._other_node_can_take` | failure anti-affinity: a node that failed the job retries it only when no node meeting them could take it |

**Per-platform variants.** A runner with `apis_any = ["cuda"]` and `[runner.variants.darwin] gpu = {use = "shared",
apis_any = ["metal"]}` needs CUDA on Linux and Windows and Metal on macOS; a variant with `use = "none"` needs nothing
there. Job facts carry the base groups and one list per variant key that sets `gpu`, resolved per node by
`pf.resolve` (token, then OS), as a stage's retry limits are.

**The agent.** Its doctor fold marks a module `undetected` (check `gpu_apis`, "needs one of cuda on the host; this node
provides metal, opencl") when the release entry's runner (already rendered for this platform) needs an API the host
lacks. A service whose `gpu.apis_any` the host does not meet is kept but never offered or started, and the service
report shows `gpu_api_missing`.

## GPU in containers on macOS

### What exists in 2026

| Option | GPU in a Linux container | Fit |
|---|---|---|
| Colima / Lima on Virtualization.framework (today's profile) | none: a Linux guest gets a 2D virtio display only; paravirtualised Metal is for macOS guests | keeps Rosetta for amd64 images |
| Apple `container` / Containerization | none: one Virtualization.framework VM per container, no GPU device | – |
| **krunkit** (libkrun on Hypervisor.framework) | **Vulkan**: a virtio-gpu device with Venus; the guest's Mesa serialises Vulkan, the VMM's virglrenderer replays it on MoltenVK | used by Podman machine's libkrun provider and RamaLama; Colima 0.10 (`--vm-type krunkit`) and Lima 2 (`vmType: krunkit`) drive it; no Rosetta |
| Podman machine, libkrun provider | the same krunkit device | a second container tool beside Colima, with its own machine image |
| A native macOS "container" for Metal | not a container: a process | not an isolation boundary the broker could promise |

**Chosen: Colima with krunkit, as a second agent-owned profile.** It is the same tool the agent already drives (one
code path, one docker CLI, one way of confining mounts), krunkit is the VMM Podman and RamaLama use for the same
purpose, and keeping it a separate VM means CPU containers keep Rosetta (krunkit has none, and bioinformatics images
are often amd64-only) and never share a kernel with a VM that has a GPU device.

### How it works

- `ColimaRuntime` gains a `Profile`: `oarbank` (`--vm-type vz --vz-rosetta`, as today) and `oarbank-gpu`
  (`--vm-type krunkit`, `--arch aarch64`, the same CPU, memory and disk sizing, the same two mounts of the agent's
  work and modules-data directories, over `sshfs`: Lima's krunkit driver accepts only virtiofs or reverse-sshfs, and
  Colima 0.10.3 turns every type but reverse-sshfs into 9p off `vz`, abiosoft/colima#1607). The agent never starts, stops or queries any other profile (the
  user's `default`, or anyone's).
- `container_runtime::for_node` returns `Containers { cpu, gpu }`: on macOS `gpu` is the `oarbank-gpu` runtime when
  Colima, docker and `krunkit` are installed (Colima looks krunkit up on `PATH`; the agent's helper `PATH` holds
  Homebrew's directories) on Apple Silicon; on Linux it is the same runtime as `cpu` when a CDI spec exists.
- A job that reserved the `gpu` pool gets a broker on `gpu`; every request it makes (status, pull, run) goes to that
  VM, and `gpus = "all"` adds `--device /dev/dri` (macOS) or `--device <kind>=all` (CDI). Its containers count against
  its `containers` token as before, and the `gpu` pool (one token) serialises GPU jobs on the node, which is also the
  GPU VM's only workload.
- The GPU VM starts on its first GPU job (as the CPU VM starts on its first container job) and is never stopped by
  the agent. After a start the runtime checks that the guest has a DRM render node (`/dev/dri/renderD128`); without
  one the start fails, the broker refuses the run with `runtime_unavailable`, and the reason names the start's log.
  It runs arm64 images only (krunkit has no Rosetta); an amd64 image is refused with `platform_unavailable`.
- `remove_attempt` and the start-of-day `reap` cover both profiles (only containers carrying the attempt label).
- The node reports `containers.gpu = "virtio-gpu:venus"`, `gpu_apis.containers = ["vulkan"]` and the `gpu` pool. The
  broker's `status` answers `gpus: "all"` to a job that reserved the pool on a node that passes GPUs through, else
  `"none"`.

### What an image needs

Mesa's Venus Vulkan driver in its libkrun build and the Vulkan loader. Stock Mesa (Fedora 44's 26.2) fails
`vkCreateInstance` with `ERROR_OUT_OF_HOST_MEMORY` under krunkit; the build in the `slp/mesa-libkrun-vulkan` COPR
(25.3.6-102.fc44, pinned with `dnf versionlock`, as RamaLama's images do) works.
The agent's live test builds one from Fedora with `vulkan-tools`, `glslc` and a small compute program, and checks the
device is `Virtio-GPU Venus (Apple …)` and that a compute shader's output is right.

### Threat model (macOS GPU VM)

| Threat | Defence |
|---|---|
| A GPU container escapes into the host through the GPU path (virglrenderer and MoltenVK run in the krunkit process, which parses the guest's command stream) | Only jobs of module versions the operator approved for "GPU passthrough to containers" (the `gpu` pool request) ever run there; the VM is separate from the CPU containers' VM; krunkit runs as the agent's account (the dedicated `_oarbank` account in a system install), which owns nothing but the agent's data; the VM mounts only the agent's work and modules-data directories. Residual: a virglrenderer bug is a host-account compromise, which is why the grant is flagged at approval. |
| A non-GPU job reaches the GPU VM | Its broker is bound to the CPU runtime; `gpus = "all"` is refused with `gpu_not_granted` before any runtime is chosen. |
| One GPU job reads another's data in the VM | GPU jobs are serialised by the `gpu` pool's one token, every container runs `--rm` with only its own mounts, and the attempt's containers are removed by label when it ends. |
| Docker on the GPU VM is reached by something else | Its socket is under the profile's directory, owned by the agent's account, and the docker CLI is pointed at it with the agent's own `DOCKER_CONFIG`, as for the CPU profile. |

## Per OS

| | macOS | Linux | Windows |
|---|---|---|---|
| Host APIs | `metal`, `opencl` (Apple Silicon and Intel Macs), `vulkan` with a Vulkan loader and MoltenVK installed | `cuda`, `rocm`, `vulkan`, `opencl` as installed and readable by the agent's account | `cuda`, `rocm` (HIP SDK), `vulkan`, `opencl`, `directml` |
| Container APIs | `vulkan` with krunkit installed (Apple Silicon, macOS 14+) | from the CDI spec | `directml`, and `cuda` on NVIDIA, from the agent's WSL containers session (D39) |
| Cannot | Metal in a Linux container (no such device exists) | – | – |

## SDK

- **Manifest.** Rule 21: `gpu.apis_any` (runner, its variants, services) needs `gpu.use` `shared` or `exclusive`
  (with `none` it would select nodes for work that uses no GPU). `runner.gpu.apis_any`, in the runner or a variant,
  needs `requires.core >= 2.5` (rule 12; a 2.4 core ignores it and places the module anywhere); `services[].gpu`
  already does. Lint (rule 22): an `apis_any` entry outside the detected set ("no core detects it yet: such work is
  placed nowhere").
- **`oarbank_sdk.gpu`**, standard library only (ctypes): `KNOWN_APIS`, `detect()` (the same probes as the agent, so
  the kit and `oarbank-sdk gpu-apis` see what a node on this host would report), and `fits(any_of, have)`.
- **`NodeClass.gpu_apis`** `{host, containers}`.
- **Conformance.** The kit resolves the runner's GPU need for this host's platform and detects this host's APIs: when
  the host provides one of the runner's APIs it says so (`gpu: this host provides …`); when it does not, the golden
  runs are skipped with that reason (a node like this host gets none of the module's jobs), never failed; a service
  whose `apis_any` the host lacks is skipped the same way. The kit's node class for this host carries the host's
  `gpu_apis`, so golden lists filtered by API are exercised.
- **Spec.** runner-protocol.md "GPU use", service-protocol.md, sandbox.md's GPU passthrough table (macOS row),
  module-protocol.md's `NodeClass`, manifest.md rules 21 and 22, versioning.md's 2.5 list.
- **Example.** `examples/modelserver` declares `gpu = {use = "shared", apis_any = ["metal", "cuda", "vulkan"]}` on its
  service, so the reference endpoint service is placed by API (its fake model still runs on any CPU).

## Versioning

No version changes: the keys and fields sit under the existing 2.5 floor (`SDK15_KEYS_CORE`). Facts stay format 2
with `gpus[].apis` removed (nothing is released). `GPU_API_MISSING` is a new reason code.

## Acceptance tests

| Criterion | Test |
|---|---|
| A stage needing `cuda` never lands on a Mac, and explain says why | core `tests/test_gpu_placement.py`: a Mac and a Linux CUDA node; the job is granted only on Linux; explain on the Mac names `GPU_API_MISSING` with `cuda` and the Mac's list; the module is excluded on the Mac |
| One needing `["metal", "vulkan"]` lands on a Mac | the same file: granted on the Mac; not on a Linux node with only `cuda` |
| Per-platform variants | the same file: base `cuda`, darwin variant `metal`: each node checked against its own platform's need; a variant with `use = "none"` needs nothing |
| A container-GPU stage checks the containers' APIs | the same file: `in_container` with `vulkan` lands on a Mac reporting `containers: ["vulkan"]`, not on a CDI node with only `cuda` in containers; stages without the `gpu` pool are not held to it |
| A service with `apis_any` only starts where its API exists | agent `services.rs`: a service needing `cuda` on a node with `metal` is neither offered nor started and its report says why; it starts once the APIs include it; core: a stage reserving its pool explains `GPU_API_MISSING` |
| Capacity binding, stranded check, replicas, anti-affinity | `tests/test_gpu_placement.py`: a campaign binds to the only class with the API; a class losing it strands; a replica needs another node with it; a node that failed retries only when no other node has it |
| Detection per OS | agent `gpuapi.rs`: the CDI rules on recorded specs (NVIDIA, AMD, WSL), the evidence format, the probe's child process and its time limit; live on each OS: the report matches `oarbank_sdk.gpu.detect()` on the same host (core `tests/rust/test_gpu_apis.py`), and on macOS includes `metal` |
| The SDK | `tests/test_gpu.py`: rule 21, the floor, the lint, `fits`, `NodeClass.gpu_apis`, the kit's skip and pass on a fake host |
| GPU in a macOS container | agent `container_runtime.rs`: the GPU profile's start arguments, the broker choosing it for a gpu-pool job, `--device /dev/dri`; live (gated on krunkit and `OARBANK_LIVE_COLIMA=1`): a container job with `gpus = "all"` reports a Venus device on the Apple GPU and a compute shader's output is right |
| Console and CLI | `tests/test_console.py` (the node page: the APIs with their evidence, how containers get the GPU), `tests/test_gpu_placement.py` (`oarbank fleet`) |

## Open questions

- **Stopping an idle GPU VM.** The GPU VM, like the CPU VM, stays up once started. Stopping it after an idle period
  would give its memory back; not done until a node shows it matters.
- **Device counts and memory.** `min_vram_gb` is carried and still selects nothing; the `gpu` pool is one token for
  all devices. Both wait for a per-device inventory on Linux and Windows.
- **Level Zero, SYCL, WebGPU** are not detected; a module may name them, and is placed nowhere until a core detects them.

## Implementation status

Built as designed, in oarbank-sdk 1.5.0 and core 2.5.0. Where the build adds to the design:

- **One list of APIs, pinned.** The agent's probes and the SDK's `gpu.KNOWN_APIS` are held to one list by an agent test
  that reads the SDK's source, and to one answer on each host by `tests/rust/test_gpu_apis.py`.
- **The probe's limit is its own.** `oarbank-agent gpu-apis` arms a watchdog that `_exit`s (Windows: terminates) after
  60 s, so the agent only waits for the child; a crash, a hang or garbage leaves every API absent with the reason.
- **Windows' Basic Render Driver** showed up on the Windows test VM as an adapter without DXGI's software flag, so it
  is excluded by its ids (vendor 0x1414, device 0x8C) and its name too, for DirectML, Vulkan (Dozen) and OpenCL
  (OpenCLOn12) alike.
- **The broker's `status`** answers `gpus: "all"` only to a job that reserved the `gpu` pool (it reported the node's
  passthrough to every job before), since on macOS a job's containers reach the GPU only on the GPU VM.
- **The facts' `gpus`** keep vendor, model, memory and `unified`; `apis` moved to the doctor report.

**Verified on each OS.**

- macOS (Apple M4 Max, macOS 27): the core suite, the SDK suite, the Rust workspace with clippy; detection reports
  `metal` and `opencl`, identically from the agent and the SDK, and the gpuinfo example runs its golden sandboxed with
  Metal reachable (the kit, and a real agent certifying it against a real oarbankd).
- Linux (the Lima VM, aarch64, kernel 7.0): clippy and the Rust workspace; the core GPU tests and the end-to-end test,
  where the agent reports no API (lavapipe is a CPU device), gpuinfo is `undetected` and explain says
  `GPU_API_MISSING`; the Vulkan compute probe image built and run with rootless Podman (Fedora 44, Mesa 26.2 with the
  Venus driver), its compute check passing on lavapipe.
- Windows 11 arm64 (the QEMU VM): clippy and the Rust workspace; detection reports no API (no GPU adapter but the Basic
  Render Driver), identically from the agent and the SDK; the SDK's GPU, manifest and conformance tests.

**Not verified, for want of hardware.** No machine here has an NVIDIA, AMD or Intel GPU, so the CUDA, ROCm, DirectML
and hardware Vulkan and OpenCL probes, and the CDI container APIs on a real spec, are covered by the probes running
(and reporting absence) on all three OSes and by recorded specs, not by a device. The macOS GPU VM is built and its
arguments, socket, device and selection are tested, and its live test
(`live_colima_gpu_runs_vulkan_compute_on_the_apple_gpu`, krunkit 1.3.2, Colima 0.10.3, Lima 2.2.0, M4 Max) passes: the
container sees `Virtio-GPU Venus (Apple M4 Max)` and the compute shader's output is right. The live run found two
things the unit tests could not: the GPU VM's mounts must be `sshfs` (above), and the image needs the libkrun build of
Mesa (What an image needs).
