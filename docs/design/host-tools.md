# Host tools

Status: built (settings scope redesign, phase 2), unreleased: core after 2.8.0, oarbank-sdk after 1.5.0. Replaces the
per-OS tool registry (`tool_registry`, `settings.tools.update`) and its `TOOL_UNAVAILABLE` outright; no compatibility
shim.

A module that needs a program installed on the node (a JDK, an interpreter, a tool such as samtools) used to name an
operator-defined registry id (`java17`) that the coordinator mapped to absolute paths **per OS** and baked into the
release; the agent silently dropped the paths that did not exist, so a Mac without a JDK 17 showed up only as a
module capability failure, after an hourly probe. Tool installs are neither fleet-wide nor per OS: they are per
machine, and only the machine can see them. So the job is split four ways:

| Layer | Who writes | Where it lives | What it can say |
|---|---|---|---|
| Built-in detector | Oarbank | agent code (`builtin_tools.json`) and the coordinator's mirror (`tools.BUILTIN`) | How to find and version-check `jdk` and `python` on each OS |
| Fleet / group search paths | Admin | `tool_defs` → the release (per OS) | "Also look in `/opt/java/*` on Macs" |
| Node detection | Agent | `tools` in hello and heartbeats → `nodes.tools_json` | What is installed here, verified, with versions |
| Node override (choose) | Operator | node-scope value `tool.<id>.path` (interim store, below) → `tool_pins` directive | "Use the JDK 17 it found, not the 21" |
| Node override (add) | Operator, owner-signed | the node statement `oarbank.node/v1` | "Use this path here" (verified before it is granted) |
| Local hint | Node owner | `<agent home>/tool-hints.json` | Extra candidates only |
| Module request | Module author; owner approves | manifest `[sandbox].tools`, `module_grants` | Id, version range, arch, trust |
| Module-on-node pin | Operator | node-scope value `tool.<id>.path` qualified by the module | "minos-gatk uses JDK 17 here even though 21 exists" |

Code: `src/oarbank/coordinator/tools.py` (definitions, overrides, resolution, views, migration), `statements.py` (the
node statement), `rust/crates/oarbank-agent/src/tools.rs` (detection and grants), `rust/crates/oarbank-core/src/tools.rs`
(the shared version, constraint and resolution rules), `vendor/oarbank-sdk/src/oarbank_sdk/toolversion.py` (the
reference version rules) and `tools.py` (what a runner reads).

## Definitions

A tool definition is a fleet object: an id, a **detector kind** and search patterns.

- `jdk` and `python` are **built in**, each a tool of the kind of the same name, with built-in patterns per OS that
  ship with Oarbank. An admin adds extra patterns to them; deleting one removes only its extras.
- An admin defines more tools of kind **`executable`**: search patterns (where the file is on each OS) and a version
  command (`args`, default `--version`) with a `regex` whose first group is the version (no look-around or
  back-references: the agent's regex engine has none). A tool of kind `jdk` or `python` that an admin defines searches
  that kind's built-in patterns too.
- Extra patterns are per scope: `fleet` (every OS) or one platform group (`darwin`, `linux`, `windows`). Group-ranked
  owner groups arrive in phase 4; the platform groups are their built-in members.

| Kind | macOS built-in patterns | Linux | Windows |
|---|---|---|---|
| `jdk` | `/opt/homebrew/opt/openjdk@*`, `/opt/homebrew/opt/openjdk`, `/usr/local/opt/openjdk@*`, `/usr/local/opt/openjdk`, `/Library/Java/JavaVirtualMachines/*/Contents/Home`, `$JAVA_HOME` | `/usr/lib/jvm/*`, `/usr/lib64/jvm/*`, `/usr/java/*`, `/opt/java/*`, `/opt/jdk*`, `/home/linuxbrew/.linuxbrew/opt/openjdk@*`, `$JAVA_HOME` | `C:\Program Files\Eclipse Adoptium\jdk-*`, `…\Microsoft\jdk-*`, `…\Zulu\zulu-*`, `…\Java\jdk*`, `…\Amazon Corretto\jdk*`, `…\BellSoft\LibericaJDK-*`, `$JAVA_HOME` |
| `python` | `/opt/homebrew/bin/python3.?`, `…/python3.??`, `/usr/local/bin/python3.?`, `…/python3.??`, `/Library/Frameworks/Python.framework/Versions/3.*/bin/python3` | `/usr/bin/python3.?`, `…/python3.??`, `/usr/local/bin/python3.?`, `…/python3.??` | `C:\Program Files\Python3*\python.exe`, `$LOCALAPPDATA\Programs\Python\Python3*\python.exe` |

macOS's `/usr/bin/python3` is deliberately absent: it is the Command Line Tools shim, and running it on a machine
without them opens an installer dialog.

**Patterns** are an absolute path whose components may hold `*` and `?` (matching within one component, never a
leading dot), or `$VAR` with an optional sub-path, expanded from the agent's environment. No `[ ]`, no `**`, no `..`,
no root, and the first directory is literal (a pattern never scans a whole disk). **Globs live only in patterns**: a
grant is always one canonical path, so the old rule against globs, roots and `..` in grants holds.

The release carries the definitions for its OS (`modules.json` → `tools`: `{id: {kind, search, version?}}`), never a
path. A definition change rebuilds every platform's release (in signing mode each waits for the owner's signature);
nodes detect again once they install it.

## Detection on the node

The agent detects every defined tool at startup (before its first hello), after installing a release, when the
coordinator asks (`detect_tools`, from `tools.detect`: the console's **Re-detect**), when its statement's tool paths
change, and hourly. A change of what it found re-runs the doctors (their tools files change) and reconfigures the
services.

- **A JDK is read, never run.** A candidate directory, or a home inside it (Homebrew's
  `libexec/openjdk.jdk/Contents/Home`, a bundle's `Contents/Home`, Linuxbrew's `libexec`), counts when it has
  `bin/java` and a `release` file: `JAVA_VERSION` (a JDK 8's `1.8.0_392` is reported as `8.0.392`), `OS_ARCH` and
  `IMPLEMENTOR`. `bin/java` without a `release` file is reported refused ("not a JDK home"); a directory without
  `bin/java` is not a JDK and is skipped.
- **Any other tool runs its version command inside the sandbox**: read and execute on that installation only (an
  interpreter's prefix for `python`), a private temporary directory, no network, 10 s at most, stdout and stderr
  together; the regex reads the version. A node that cannot sandbox reports it refused instead of running it. The
  architecture comes from the file's header (ELF, Mach-O, a universal binary's native slice, PE).
- **Candidates**, in order: the paths the node's statement adds (source `override`), the hints file (`local-hint`),
  the built-in patterns (`detected`) and the fleet's (`search`). Installations are deduplicated by canonical path (the
  first source wins), and nothing inside or around Oarbank's data directory is ever an installation.
  `OARBANK_TOOLS_BUILTIN_SEARCH=0` in the agent's environment skips the built-in patterns (a machine whose owner wants
  explicit paths only; the end-to-end tests).
- **The hints file** `<agent home>/tool-hints.json` (`{"jdk": ["/Users/me/jdks/zulu-17"]}`) is the node owner's,
  like Kubernetes NFD's `features.d` or HTCondor's `JAVA`: hints add candidates and never bypass verification.

The report (`tools` in hello and every heartbeat; `nodes.tools_json`): `{detected_at, native_arch, tools: {id:
[{path, given?, version, arch, vendor, source, status, detected_at}]}}`, `status` being `ok` or `refused: <reason>`.
`oarbank-agent tools detect` prints the same, run as the agent's account.

## Module requests

```toml
[sandbox]
tools = [
  { id = "jdk", version = ">=17, <22", arch = "native", trust = "code-exec" },
  { id = "python", version = "~> 3.12" },
  { id = "samtools", version = ">=1.19" },
]
```

- `id`: a fleet tool definition (`jdk`, `python`, or one an admin defines), at most once per manifest.
- `version` (optional): comma-separated clauses, all of which must hold, with Nomad's operators `=` (`==`), `!=`, `>`,
  `>=`, `<`, `<=` and `~>` (the last given segment may grow: `~> 17.0.2` is `>=17.0.2, <17.1`, `~> 17` is `>=17,
  <18`). Versions are dot-separated numbers (`_` separates too), an optional pre-release (`22-ea`, below `22`) and build
  (`+7`, ignored); missing segments are zero. The SDK stores the constraint in its canonical spelling. Vectors:
  oarbank-sdk `spec/vectors/tool-versions.json`, replayed by the SDK, the coordinator and the agent.
- `arch`: `any` (default; the node's own preferred), `native` (only the node's own: no x86_64 JDK under Rosetta on
  Apple silicon), `arm64` or `amd64`.
- `trust`: `read` or `code-exec` (flagged at approval). The registry's own `trust` is gone: the module request is
  what is enforced.

The owner approves the whole request set by digest, as before (`modsandbox.requests` includes `version` and `arch`
when set, so a new range is a new approval). Bootstrap jobs still get no tools.

## Resolution

For each node and module, one installation per request:

1. a path set for **this module on this node** (`tool.<id>.path`, module-qualified, node scope),
2. a path set for **this node**,
3. a path set for the node's **platform group**, module-qualified first,
4. a path set for the **fleet**, module-qualified first,
5. else the **best detected match**: the node's native arch first, then the highest version that satisfies the
   request, then the path (ascending).

A pinned path counts only when it names an installation the node reported (by its canonical path, or the path as set)
with status `ok` and a version and arch the request accepts; otherwise the request does not resolve (no silent fall
back). `tools.resolve` (coordinator) and `oarbank_core::tools::resolve` (agent) implement the same rule and replay
`src/oarbank/contracts/vectors/tool-resolution.json` (`tests/tool_vectors.py` regenerates it).

The coordinator resolves for placement, the console and readiness; the agent resolves for the grant and writes only
that module's resolution to `OARBANK_TOOLS_FILE`: `{"jdk": [{"path": "…", "version": "17.0.12", "arch": "aarch64"}]}`.
The sandbox grants read and execute on that path (a JDK's home, an executable's file, an interpreter's prefix). A
request that does not resolve is left out of the file.

### Two kinds of override

- **Choosing among what the node found** needs no signature: the agent grants only installations its own detector
  verified. The coordinator sends the effective pins per module in the `tool_pins` directive (`{"": {...}, "<module>":
  {...}}`).
- **Adding a path the node did not find** is a grant decision: it goes into the node's signed statement (below). The
  agent applies its folder refusals to it (no roots, homes, the Oarbank data root, or a system directory itself or one
  containing one; `/usr/lib/jvm/...` is fine, `/usr` is not), then the detector, and only then is it an installation
  (source `override`). Without the signature a compromised coordinator could point an override at a user's documents.

`tools.set_path` decides the kind at write time: a path among the node's `ok` installations is a choice, any other is
added.

**Interim store.** Until the phase-1 settings registry merges, the values live in the `tool_path_values` setting
(rows `{scope: fleet|group|node, scope_id, module, tool, path, kind}`), read only through `tools.node_override(db, node,
tool, module)` and written only through `tools.set_override` (operation `tools.set_path`). At the merge they become
`setting_values` rows of key `tool.<id>.path` (module-qualified where set), `node_override` reads them through the
resolver and `tools.set_path` becomes `settings.apply`; nothing else changes.

## The node statement

The folder statement is generalized: every node-scope value that grants access on one node travels in
`{"type": "oarbank.node/v1", "fleet_id", "node_id", "seq", "folders": {...}, "tools": [{id, module, path}],
"signed_at"}` (statements.py; settings key `node_statements`, directive `statement`). It is rebuilt with a rising seq
whenever its content changes; in signing mode the owner signs it (`oarbank node sign <node>`, operation
`nodes.sign_statement`) and the agent applies only a signed statement with a higher seq. An agent refuses the old
`oarbank.folders/v1` type; at upgrade the coordinator moves `folder_statements` to `node_statements` and reissues each
statement as `oarbank.node/v1` with the next seq at startup.

## Placement

`TOOL_UNAVAILABLE` splits into three codes, all computed from the node's report within one heartbeat of detection:

| Code | When | Example |
|---|---|---|
| `TOOL_NOT_FOUND` | no installation of the tool, the node has not reported yet, or the fleet defines no such tool | `jdk >=17: no jdk found on this node` |
| `TOOL_VERSION_UNMET` | installations, none the request accepts (or the pinned one does not) | `jdk >=17: found 11.0.2 at /usr/lib/jvm/java-11; needs >=17` |
| `TOOL_REFUSED` | the path set for the node is refused or not an installation it found | `jdk >=17: the path set for jdk here, /srv/jdk, was refused: /srv/jdk does not exist here` |

They are stage-scoped as stage gating requires (docs/design/stage-gating.md): a stage that needs no certification
gets no tools and is spared (`predicates.SPARED`); the goldens and every other stage wait. Explain renders `Module
{module} needs another version of a host tool: {tools}`. Module probes remain for functional health but no longer
gate tool presence.

**Remediation** sits next to each failure (`tools.fixes`): a copyable install command for a version the request
accepts (the lowest JDK LTS: `brew install openjdk@17`, `sudo apt install openjdk-17-jdk-headless`, `winget install
EclipseAdoptium.Temurin.17.JDK`; the newest Python: `brew install python@3.13`, …), **Re-detect**, **Set path on this
node** and **Add a search path for <OS>**.

## Operations, API, CLI

| Endpoint / op | Purpose |
|---|---|
| op `tools.define {target: id, params: {kind?, search: {fleet\|darwin\|linux\|windows: [patterns]}, version?: {args, regex}}}` (T2) | Define a tool or replace a built-in's extra patterns; rebuilds releases |
| op `tools.delete {target: id}` (T2) | Delete a definition (a built-in loses only its extras) |
| op `tools.detect {target: node}` (T0) | Ask the node to detect again |
| op `tools.set_path {target: node, params: {tool, module?, path\|null}}` (T1) | Set or reset a tool's path on a node (interim; `settings.apply` after phase 1) |
| op `nodes.sign_statement {target: node, params: {statement, signature}}` (T1) | Attach the owner's signature to the node statement |
| `GET /api/v1/tools?node=&module=` | Definitions, overrides, and the detection and resolution matrix (per node, or a module's Nodes matrix) |
| `GET /api/v1/statements` | Each node's statement and whether it is signed |

CLI: `oarbank tools [--node N] [--module M] [--json]`, `oarbank tools detect <node>`, `oarbank tools define <id>
--search <scope>=<pattern> [--kind executable --version-args ... --version-regex ...]`, `oarbank tools delete <id>`,
`oarbank tools set-path <node> <tool> <path>|--reset [--module M]`, `oarbank node sign <node>`; `oarbank node show`
lists the node's tools and each module's resolution.

## Console

- **Node page → Host tools** (`/nodes/<id>#tools`): the installations it found (path, version, arch, vendor, how it
  was found, status), what each module gets (request, effective installation, source, status, fixes), the paths set on
  the node with Reset to inherited, and Set path on this node (a datalist of what it found). Re-detect in the section
  header.
- **Module page → Nodes** (`/modules/<name>/nodes`, shown when the module asks for tools): a row per node and request
  with Detected (version, arch, path, Re-detect), Override (an empty input whose placeholder is the detected match, so
  empty means "use detected"), Effective with its source, and Status with its fix. One row is edited at a time: each
  row's editor is a `<details name="tool-row-edit">`, an exclusive group.
- **Settings → Tools**: the definitions with their built-in patterns (collapsed), extra search paths per scope, who
  asks for each, and the form that adds search paths or defines a tool; a warning names tools approved module versions
  ask for that the fleet does not define.

They follow console-layout.md (a wide card per wide table, `td.actions`, monospace paths that may break) and
console-loading-states.md (every change is an `op_form` with its busy state; the pages are plain GETs).

## Readiness

Step 7 of the module checklist, "Host tools on the nodes", reads `tools.resolution(db, module, manifest, nodes)`:
per request, how many nodes of a supported platform resolve it and why the others do not, grouped by reason with the
install command (`jdk >=17: 1 of 5 nodes (mac)` · `old: found 11.0.2 at /usr/bin/java-home; needs >=17 → brew install
openjdk@17` · `box: not found → sudo apt install openjdk-17-jdk-headless`), with per-code counts. A request for a tool
id the fleet does not define blocks the step: the module asks for an unknown tool id and needs a new module version.

## Migration

One shot, at upgrade (`DB.__init__`):

- `tool_registry` → `tool_defs`: each id becomes a definition with its per-OS paths as that OS's extra patterns (an id
  named like a JDK, `java*`/`jdk*`/`openjdk*`, becomes kind `jdk`; any other an `executable` read with `--version`);
  the setting and its `trust` are deleted. The live fleet had no registry row.
- A module version asking for `java17` against no definition cannot be converted: its jobs wait with `TOOL_NOT_FOUND`
  and its checklist says it needs a new version (minos-gatk: `{ id = "jdk", version = ">=17", trust = "code-exec" }`,
  one re-approval for the new digest).
- `folder_statements` → `node_statements`, reissued as `oarbank.node/v1`.
- `nodes` gains `tools_json` and `want_detect`.

## Not built here

- The settings store itself (phase 1): the interim `tool_path_values` store above is replaced at the merge.
- Owner groups with ranks and their group-scope pinned paths and search paths beyond the platform groups (phase 4).
- A managed install (a T2 operation with the node owner's consent that downloads a pinned, digest-checked JDK into an
  Oarbank-managed tools directory, Jenkins' auto-installer pattern) (phase 5).
- An SDK core-version gate for `version` and `arch` (`requires.core >= 2.9`): the SDK's rule for keys older cores
  ignore, deferred until the integration branch reports core 2.9.0 (today it still reports 2.8.0, so every module using
  them would be refused at install).
