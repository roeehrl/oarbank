# Secrets and signed container image sets (SDK 1.5, core 2.5)

Status: built (Implementation status at the end). Two issues on the public SDK repository, part of **oarbank-sdk 1.5.0** and **core 2.5.0**:
- **#13** containers: approve image sets by signature, and specify GPU passthrough;
- **#14** settings: secrets that are write-only and delivered only to declaring stages.

Both are about trust that a manifest of digests or a settings document cannot express: which images a module may run
when there are hundreds of them, and which part of a module may see a credential.

## Versioning, for both

- **Manifest 1 and module protocol 1 stay.** Everything is additive: new optional keys, one new host callback, one new
  permission, new optional broker fields, one new runner environment variable.
- **The new keys need `requires.core >= 2.5`** (manifest rule 12 gains a 2.5 row): `[[secrets]]`, `stages[].secrets`,
  the permission `secrets:read:self`, `[[sandbox.container_sets]]`, and a stage reserving the agent's `gpu` pool. A 2.4
  core reads manifests leniently: it would deliver no secrets and the runner would fail, or it would refuse every set
  image at the broker. The floor makes that a clear install refusal instead.
- `x-secret` in form schemas (ui-contract.md) is **removed**: a module form never asks for a credential, because a
  credential handed to module code through an operation's parameters is exactly the plain setting #14 replaces. There
  is one way to give a module a secret: `[[secrets]]`, set by the owner through the core.
- `CORE_VERSION` becomes 2.5.0; the core reads every new key from the SDK's models (no core-side copy).

---

## #14 Secrets

### The decision: a `[[secrets]]` section, not `x-secret` settings

Settings are a JSON document the core stores and never interprets, delivered whole: to every runner in
`OARBANK_SETTINGS_FILE` (the node's module settings) and to coordinator verbs through `host.settings.get`. Marking a
schema field `x-secret` would leave a secret inside that document, so every path that carries settings (effects,
views, `module_settings.update`, the node policy) would need an exception, and the schema is a bundle file the manifest
models cannot cross-check. A secret is a fact the scheduler and the console need before running module code (which
stage gets it, whether it is set for a node), so by the manifest's rule of thumb it is declared in the manifest:

```toml
requires = { core = ">=2.5,<3", ... }

[[secrets]]
name = "llm_api_key"                      # a Name; unique
description = "API key for the model provider the agent harness calls"

[[stages]]
name = "attempt"
secrets = ["llm_api_key"]                 # only this stage's runner receives it

[coordinator]
permissions = ["secrets:read:self"]       # only if a verb needs it (rare: most modules never do)
```

`Secret = {name, description}` [beta]; `Stage.secrets: list[Name]` [beta]. Rules (manifest rule 16; errors in
`oarbank-sdk check` and at install):
1. Secret names are unique; every name a stage lists is declared, once per stage.
2. A bootstrap stage lists no secrets (bootstrap jobs get nothing beyond the egress allowlist).
3. A declared secret is used: some stage lists it, or the coordinator has `secrets:read:self`.
4. `[[secrets]]`, `stages[].secrets` and `secrets:read:self` need `requires.core >= 2.5`.

There is no `required` flag and no manifest scope: a stage that lists a secret needs it, and where the value is set
(the module or one node) is the owner's choice.

### Values, scope and storage (coordinator)

- **Values** are UTF-8 strings of 1 byte to 64 KiB, set by the owner (admin role) with `secrets.set` and removed with
  `secrets.clear`, for the module (every node) or for one node. A node's own value wins over the module's. The
  coordinator side reads only the module's value.
- **At rest** each value is encrypted with AES-256-GCM under the coordinator's **secrets key** (32 random bytes, a fresh
  12-byte nonce per value), with the associated data `oarbank-secret/v1 \0 module \0 name \0 node` so a ciphertext
  cannot be moved to another name, module or node. Table `secrets(module, name, node_id, ciphertext, fingerprint,
  set_at, set_by, sealed)`; `node_id` is `''` for the module scope.
- **The secrets key** lives in the secret store ([architecture.md](architecture.md), "The coordinator"), never in the
  database, never in a backup:

  | Coordinator OS | Where the key is |
  |---|---|
  | macOS | the login Keychain, a generic password `module-secrets` (the store's default there) |
  | Linux | `<home>/keys/module-secrets.key`, mode 0600 in a 0700 directory owned by the coordinator's account |
  | Windows | `<home>\keys\module-secrets.key`, the key wrapped with DPAPI (`CryptProtectData`, current user) in a file whose directory is private to the account |

  Windows is not a coordinator platform yet; the store's DPAPI backend is built and tested on its own so the
  coordinator inherits it. Hardware keys (Secure Enclave, TPM through systemd-creds) are an open question below.
- **Fingerprint.** `fp:` and the first 16 hex digits of HMAC-SHA256(fingerprint key, value). The fingerprint key is a
  random fleet-wide key stored like a secret (encrypted, carried by moves), so a fingerprint is stable across moves and
  cannot be brute-forced from the console. The owner compares it with what `oarbank secret set` printed.
- **Unreadable values.** A backup restored on another machine, or a home copied without its key, holds ciphertexts the
  new secrets key cannot open. Such a value shows as "set, unreadable here (set it again)", counts as not set for
  placement, and raises the P3 alert `secret_unreadable:<module>/<name>`.

### Write-only and never echoed

- **Reads.** `GET /v1/modules/<name>/secrets` (and the console, the CLI's `oarbank secret list`) return, per declared
  secret: its name, description, the stages that receive it, whether the coordinator side may read it, and per scope
  (module, each node with its own value) `{set, fingerprint, set_at, set_by, readable}`. No read returns a value, and
  nothing decrypts a value except delivery (below).
- **The operation.** `secrets.set` takes the value outside `params`: the request carries `secret` beside `params`, which
  `OpRequest.secret` holds and nothing serializes. It never reaches the payload hash, plans, idempotency rows, the audit
  row (before/after are `{set, fingerprint, set_at}`), events or error messages (errors name the module, the secret and
  the scope). `secret` on any other operation is refused (400 `secret_not_accepted`). `secrets.set` is T1, so there is
  never a plan holding it. `secrets.clear` (T1) removes a value.
- **Console.** The module's pages gain a Secrets tab (`/modules/<name>/secrets`): each secret's state, a password field (never filled
  in) with Set, a node selector for a node's own value, and Clear. The node page lists which module secrets have a
  node value (names and fingerprints).
- **CLI.** `oarbank secret set <module> <name> [--node N]` reads the value from stdin (or a no-echo prompt), never from
  argv; `oarbank secret clear`, `oarbank secret list`.
- **Plans, audit, exports, errors.** None ever holds a value: the plan and audit tables have no path to it; the core has
  no export besides audit digests and database backups, which hold ciphertexts only.

### Delivery

- **To runners.** Only a job whose stage lists secrets gets them. The claim path resolves each listed name for the node
  (the node's value, else the module's) and puts `secrets: {name: value}` in the grant (the mTLS claim response; grants
  are not stored). The agent writes them to `<W>/.grants/secrets.json` (`{"<name>": "<value>"}`), mode 0600 from the
  first byte on POSIX; on Windows the file inherits the work directory's DACL, which the agent home's protected DACL
  (the service account, Administrators and SYSTEM; a personal install's per-user data root) and the job's AppContainer
  grant make, and nobody else's. It sets `OARBANK_SECRETS_FILE` to it. Nothing else of the grant carries them: not `spec.json`,
  not the environment, not the agent's logs. The work directory (and the file with it) is deleted when the result is
  recorded, and at agent start every leftover work directory is removed. `oarbank_sdk.secrets.get(name)` reads it.
- **Bootstrap jobs, doctor, services and probes** never get secrets (a bootstrap stage cannot list them).
- **Placement.** A job whose stage lists a secret that has no readable value for the node waits there with
  `SECRETS_NOT_SET` (claim and explain share the predicate; explain names the secrets and the remedy `oarbank secret
  set`). Goldens of such a stage wait too, and `certifying_stuck` names the missing secrets.
- **To coordinator verbs.** `host.secrets.get {name}` returns `{set, value?}` for the module's value, only with the
  `secrets:read:self` permission (`-32002` otherwise) and only for a declared name. Values are never part of
  `initialize`, settings or any other callback.
- **Redaction (a safety net, not a guarantee).** The agent replaces every exact occurrence of a delivered value of at
  least 6 bytes with `[secret:<name>]` in what it sends from an attempt: the runner log stream, `stderr_tail`, the
  `failure.json` detail and `events.ndjson` log events. The coordinator does the same to its module process's stderr
  log for module-scope values when the module may read them. Results and artifacts are module data and are not
  rewritten: the conformance kit checks that a module never puts a value there. A value transformed (encoded, split,
  hashed) passes through; the docs say so plainly.
- **Guidance.** Pair a secret with `net.mode = "egress-allowlist"` naming only the service the key is for, so a leaked
  key can reach only that host. `oarbank-sdk check` warns when a stage lists secrets and the module's network mode is
  `egress-any`.

### Coordinator moves

The secrets key cannot leave its machine (the Keychain cannot export it, and it should not travel), so secrets move
**re-encrypted under the target's key**:
1. At pairing the standby sends `b_secrets_pub`, an X25519 public key it keeps the private half of in its secret store
   (`move-transport`).
2. Every snapshot of the database (seed and final) is rewritten after `VACUUM INTO`: each row is decrypted with the
   source's key and sealed to the target (ephemeral X25519, HKDF-SHA256 with info `oarbank-move-secret/v1` and both
   public keys, AES-256-GCM with the same associated data), with `sealed = 1`. The invariants (counts, hash) are taken
   after the rewrite. The source's own database is never touched, so a thawed source loses nothing.
3. The target opens sealed rows with its transport key the first time it starts active and re-encrypts them under its
   own secrets key; a row it cannot open is unreadable (above). Fingerprints travel unchanged.
4. **The move preview** (`coordinator.prepare` and `coordinator.move` impact, and the console's Move page) lists every
   secret by `module/name` and scope (module or node), never values.

### Threat model

| Who | Can they read a secret? | Why not, or what limits it |
|---|---|---|
| A console viewer or operator | No | No read returns a value; set and clear need the admin role; the fingerprint is keyed |
| An admin | Can replace or clear, not read | Write-only API and console; a determined admin owns the coordinator host (below) |
| The module's coordinator side | Only with `secrets:read:self`, module scope | The permission is in the manifest, so in the digest the owner installs and the approval diff |
| A runner of another stage of the module | No | Its grant carries no secrets; the file is in the declaring job's own work directory, which no other job's sandbox may read |
| Another module, a service, a probe, doctor | No | Never delivered; work directories are per attempt and outside every other sandbox |
| A database or backup thief | No | Ciphertexts only; the key is in the Keychain or an owner-only file on the coordinator host |
| Someone with the coordinator account | Yes | They hold the key and the database; out of scope, as for every coordinator credential |
| The node's owner or root | Yes, while the job runs | The file is on their disk for the attempt; a node the owner does not trust should get node-scoped secrets of its own, or none |
| A declaring runner itself | Yes, by design | Redaction catches careless logging; the egress allowlist limits where it can send the key |
| A network observer | No | Grants travel over mTLS; moves seal values to the target's key |

### Acceptance tests (#14)

- SDK: the rules above; `secrets.get`; schema regeneration; the floor.
- Conformance: the kit gives each declared secret a random canary. A runner spec of a declaring stage gets
  `OARBANK_SECRETS_FILE` (0600, inside the work directory) with exactly its stage's names; every other runner spec and
  golden runs without it. The fake host refuses `host.secrets.get` without the permission (`-32002`). After every run
  and every verb, the kit fails if a canary appears in a result, an artifact, `failure.json`, events, the runner's
  output, a built spec (`spec.build`, `golden.list`) or any verb response: so "other stages and the coordinator side
  cannot read it" holds for the module's own code paths, which a host could not otherwise check.
- Core: set through the API, the console and the CLI; no console page, API read, plan, audit row, event, error or
  attempt log shows the value (a test greps every table and every rendered page for it); `secret` refused on other
  operations; only the declaring stage's grant carries it, resolved per node; `SECRETS_NOT_SET` in claim and explain;
  `host.secrets.get` with and without the permission; redaction of module logs; a move seals, carries and re-encrypts
  them (fingerprints equal, the preview lists names); an unreadable value alerts.
- Agent: the secrets file (mode, content, deletion with the work directory, absent for other stages), redaction of the
  log stream and failure detail; end to end on a real agent and oarbankd (tests/rust), on macOS, Linux and Windows.

---

## #13 Signed container image sets

### The decision: cosign keyed signatures, verified by the agent in Rust

The options for "approve a key, not a digest list":

| | cosign keyed (Sigstore) | cosign keyless (Fulcio identity) | Notary v2 (notation) |
|---|---|---|---|
| Trust root | the pinned public key | the Sigstore trust root (TUF), Fulcio CA, CT log, Rekor | an X.509 CA chain in a trust store, plus a trust policy |
| Offline verification | yes, with the key alone | needs the trust root and the bundle's inclusion proofs | yes, with the trust store |
| What a verifier implements | ECDSA P-256 over the payload; parse two small JSON formats | the keyed path plus X.509 chains, SCTs, Rekor SETs and inclusion proofs, OIDC claims | X.509 chain building and revocation, JWS or COSE envelopes |
| Publisher tooling | `cosign generate-key-pair`, `cosign sign --key` | `cosign sign` with an OIDC login | `notation cert`, `notation sign` |

**Decision: cosign keyed signatures with a pinned ECDSA P-256 key**, verified by a small Rust implementation in
`oarbank-core` (`images.rs`: about 400 lines, `ring` for ECDSA, already in the agent's dependency tree through
rustls), never by shelling out to `cosign`, which nodes do not have. It is offline-verifiable with the key alone, its
whole trust decision is "this key signed this digest", and it is what the issue asks for (a pinned key). Keyless
identities and Notary v2 are open questions: both are much larger and depend on trust roots the fleet would have to
keep current.

**Signature formats the agent reads** (both are cosign's; a publisher needs nothing else):
1. **Sigstore bundle** (cosign 3's default; cosign 2.4+ with `--new-bundle-format`): an OCI 1.1 referrer of the image
   (`GET /v2/<repo>/referrers/<digest>`, falling back to the referrers tag `sha256-<hex>`), artifact type
   `application/vnd.dev.sigstore.bundle.v0.3+json`, whose layer is the bundle. The agent verifies its `dsseEnvelope`:
   payload type `application/vnd.in-toto+json`, an ECDSA P-256 signature by the pinned key over the DSSE
   pre-authentication encoding, and an in-toto statement whose predicate type is `https://sigstore.dev/cosign/sign/v1`
   and whose subject names the image digest. Transparency-log entries in the bundle are ignored: trust is the pinned
   key, not the log.
2. **Simple signing** (cosign 2's default): the manifest at tag `sha256-<hex>.sig` in the image's repository, each layer
   of type `application/vnd.dev.cosign.simplesigning.v1+json` with the signature in the annotation
   `dev.cosignproject.cosign/signature`; the payload's `critical.image.docker-manifest-digest` is the image digest,
   `critical.type` is `cosign container image signature`, and `critical.identity.docker-reference` lies inside the set.

Every blob is checked against its descriptor digest before it is parsed; manifests are capped at 4 MiB and blobs at
4 MiB.

### Manifest

```toml
[[sandbox.container_sets]]
name = "tasks"                              # a Name; unique; shown at approval and in the audit
registry = "ghcr.io"                        # host[:port]; Docker Hub is docker.io
repository = "example/swe-tasks/"           # ends with "/": every repository below; else exactly that repository
platform = "linux/amd64"
key = "keys/tasks.pub"                      # bundle path of the cosign public key (ECDSA P-256, PEM SPKI)
index = "ghcr.io/example/swe-tasks-index:current"   # optional: a signed image index (below)
```

`ContainerSet` [beta]. Rules (manifest rule 17): names unique; `registry` is a lowercase `host[:port]`; `repository` is
lowercase path segments (`[a-z0-9._-]`, `/`-separated), optionally ending with `/`; the key file exists in the bundle
and holds one ECDSA P-256 public key (checked by `oarbank-sdk check`, bundle verification and install); `index`, when
set, is a tagged reference.

**Membership.** A reference `<registry>/<repository>[:tag]@sha256:<64 hex>` (normalized as Docker does: `docker.io`,
`library/`) is in a set when its registry equals the set's, its repository equals the set's repository or starts with
it when that ends with `/`, and its platform equals the set's. Then:
- **without `index`:** its digest carries a signature by the set's key (either format above);
- **with `index`:** its digest is listed in the set's current index. The **index** is an OCI artifact at the `index`
  reference: artifact type `application/vnd.oarbank.image-set.v1+json`, one layer of that type holding
  `{"type": "oarbank.image-set/v1", "registry", "repository", "seq", "images": ["sha256:…", …]}`, whose manifest
  digest carries a signature by the set's key. Its `registry` and `repository` equal the set's. The agent refuses an
  index whose `seq` is below the highest it accepted for that set (kept in its home), so an old signed index cannot
  bring back a withdrawn image. `oarbank_sdk.images.index_document()` writes the layer; `oras push` and `cosign sign`
  publish it.

**Digest pinning stays mandatory.** `container.run`, `container.pull` and `jobs.enqueue` name images by digest only.

### jobs.enqueue `images`

A job item may list `images` [beta]: the digest-pinned references its runner will run (at most 16). Each must be one of
the module's `containers` entries or inside one of its sets (422 `image_not_approved` names the image; the coordinator
checks membership by prefix and platform, the agent checks the signature), and the job's stage must reserve the
`containers` pool (422 `bad_images`). The grant carries them. **A job may run set images only if it lists them**: the
broker refuses any other set image (`image_not_approved`), so the coordinator knows, per job, which digests may run.
Static `containers` images stay allowed for every job of the module.

### The broker and the agent

- `container.run` and `container.pull` check, in order: the reference is digest-pinned and its platform approved; it
  is a static image, or a set image the job listed; for a set image, the agent's **verification** (below) passes. Any
  failure is `image_not_approved` with the reason in `detail` (outside every set; not listed by the job; no signature by
  the set's key; not in the set's index; index older than one already accepted). A registry the agent cannot reach is
  `registry_unavailable` (retryable). Only then does the runtime pull, by digest, so the engine checks the content
  against the signed digest.
- **Verification** fetches the signature artifacts itself through a small OCI distribution client (`registry.rs`:
  anonymous bearer tokens, `https` only except for `localhost` and loopback registries, no redirects to other hosts,
  size caps) and caches each verified `(set, digest)` for the agent's lifetime. An index is fetched again on a miss.
  The agent never sends registry credentials: sets name public or anonymously readable registries (private registries
  are an open question).
- **Audit.** The attempt's report lists each set image the broker verified and ran (`images: [{set, image}]`). The
  coordinator records the first run of each `(module, digest)`: a row in `module_images`, the event
  `container_image_first_run` and an audit row (`containers.first_run`, actor `node:<id>`), naming the set, the key
  fingerprint, the node and the attempt.

### Approval

`modsandbox.requests` lists each set as `{name, registry, repository, platform, key_sha256, index}`, where `key_sha256`
is the SHA-256 of the key's DER (SPKI). The approval page, the CLI and the audit show "container images under
`ghcr.io/example/swe-tasks/` (linux/amd64) signed by key SHA256:ab12…" (plus "listed in index …"). The approval
digest covers the key and the prefix, never a list of digests, so **adding images to a set needs no new module version
and no new approval**; changing the key, the prefix or the index is a new version.

### GPU passthrough

- **Broker.** `container.run` gains `gpus`: `"none"` (default) or `"all"`. A later minor adds an integer count; an
  integer today is `bad_request` (`gpus` is a string or, later, a count, so readers never confuse the two).
- **Scheduling: the agent's `gpu` pool.** An agent whose runtime can pass GPUs through offers the core pool `gpu` with
  one token (all of the node's GPUs, one job at a time; a count makes it one token per device later). A stage that runs
  GPU containers reserves it: `pools = {containers = 1, gpu = 1}`. The pool predicate then keeps those jobs on nodes
  that can, `explain` says `POOL_MISSING gpu` elsewhere, and **the `containers` pool accounting covers GPU jobs**: the
  job holds a container token and the GPU token for its lifetime. Manifest rule 17 adds: a stage reserving `gpu` also
  reserves `containers`, and the runner declares `gpu.in_container = true` with `gpu.use` `shared` or `exclusive`, so
  the core's GPU admission (`GPU_BLOCKED` when the owner's protected processes use the GPU, `gpu_jobs = "never"`)
  applies to it like any GPU job. Approval shows "GPU passthrough to containers".
- **The broker refuses** `gpus = "all"` with `gpu_not_granted` unless the job reserved the `gpu` pool, and with
  `gpu_unavailable` when the runtime cannot pass a GPU through.

| Platform | Mechanism | What the node reports |
|---|---|---|
| Linux | CDI: the agent finds a CDI spec (`/etc/cdi`, `/var/run/cdi`, JSON or YAML) declaring a device kind with an `all` device (`nvidia.com/gpu=all` from `nvidia-ctk cdi generate`, AMD's likewise) and runs `--device <kind>=all` (Podman 4.1+, Docker 25+ with CDI, the default from Docker 28.2) | facts `containers.gpu = "cdi:<kind>"`, the `gpu` pool |
| Windows | GPU-PV in the agent's WSL containers session: its guest writes the CDI spec `microsoft.com/wslc=gpu` (`/dev/dxg`, the host driver's libraries under `/usr/lib/wsl`) and runs get `--gpus all` ([windows-containers.md](windows-containers.md)) | `containers.gpu = "cdi:microsoft.com/wslc"` and the `gpu` pool when the session's VM has a GPU |
| macOS | none: Colima and Apple's `container` VMs have no Metal passthrough | `containers.gpu = "undetected"`, no `gpu` pool |

The node's report is the agent's facts (`containers.gpu`), which placement reads through the `gpu` pool and the
console's node page shows ("GPU in containers: undetected", with the reason). The broker's `status` answer gains
`gpus: "all" | "none"`, so a runner can choose its GPU or CPU path.

### Threat model

| Threat | What stops it |
|---|---|
| A runner asks for an image outside every set | `image_not_approved`: prefix and platform are checked before anything is fetched |
| A registry (or someone who can push to it) serves an unsigned image inside the prefix | No signature by the pinned key: `image_not_approved` |
| A forged or altered signature, a signature for another digest | ECDSA verification against the pinned key; the signed payload must name the requested digest |
| Swapping image content after signing | The runtime pulls by digest; the digest is what was signed |
| A stale signed index that still lists a withdrawn image | `seq` must not go backwards on a node; withdrawing an image needs a new index with a higher `seq` (a node that never saw the newer index still accepts the old one: rotate the key to revoke everywhere) |
| A compromised signing key | Anything it signs runs. Remedy: a new module version with a new key (a new approval); the audit lists every digest that ran and where |
| A job running images the coordinator did not plan | Set images run only if the job lists them; each first run is audited |
| A malicious registry answer (huge blobs, redirects, wrong content) | Size caps, digests checked before parsing, no cross-host redirects, `https` except loopback |
| A GPU container escaping more than a CPU container | Only with the `gpu` pool reserved, approved per version; the same `--rm`, no privileged mode, no host network |

### Acceptance tests (#13)

- SDK: the set rules and floor; `images.verify` (pure Python, including ECDSA P-256) against vectors shared with
  `oarbank-core` (`spec/vectors/image-signatures.json`: both formats, wrong key, wrong digest, tampered payload, index
  membership and `seq`), and `broker.run(gpus=...)`.
- Conformance: for each set, the kit verifies the fixture's member images (from a registry or an OCI image layout
  directory, `conformance.json` `images`), and checks **both refusal cases** with the reference policy: an image outside
  the set's prefix and an unsigned image inside it are refused with `image_not_approved`.
- Agent: `images.rs` and the broker against a local registry: **500 distinct signed images under one approval** run
  through the broker (a fake runtime), every first run reported once; an unsigned one, one outside the prefix, one not
  listed by its job, an index with a lower `seq` are refused; CDI detection and the `--device` argument; `gpus` refusals.
- Core: `jobs.enqueue` with images (accepted in a set, 422 outside); the release entry carries the sets and the key;
  approval shows prefix and key; 500 jobs with distinct images run under one approval and each digest's first run is
  audited once; `gpu` pool placement and GPU admission for GPU container jobs.
- End to end on Linux (the Lima VM's rootless Podman and a local registry): signed images run, an unsigned one is
  refused.

## Open questions

- **Keyless identities** (a Fulcio certificate's OIDC issuer and subject instead of a key) and **Notary v2**: deferred;
  both need trust roots kept current on every node. Sets take a key today.
- **Private registries**: the agent sends no registry credentials. A secret-backed pull credential per set would join
  #14's machinery; not built.
- **Hardware-held secrets keys** (Secure Enclave, TPM via systemd-creds, TPM-backed DPAPI): the store's file and
  Keychain backends are the conservative default; a hardware backend would make the key non-exportable by design.
- **Revoking one image everywhere** without a new key: a node that never fetched the newer index keeps accepting an old
  one until it does; an expiry on the index document would bound that.
</content>
</invoke>

## Implementation status

Built as designed in **oarbank-sdk 1.5.0** and **core 2.5.0**. Where the build adds to or narrows the design:

- **SDK.** `Manifest.secrets`, `Stage.secrets`, `ContainerSet`, the gpu-pool rule and the 2.5 floor (rules 16 and 17);
  `oarbank_sdk.secrets`, `Host.secret`, `oarbank_sdk.images` (the reference policy, ECDSA P-256 in pure Python),
  `oarbank_sdk.imagetest` (signed test images in OCI image layouts), `fx.job(images=...)`, `broker.run(gpus=...)`;
  `spec/vectors/image-signatures.json`; the kit's secrets and images checks; the `taskbench` example (a secret for one
  stage, signed task images, conformance with a committed OCI layout) and the docs site's how-to page. `x-secret` is
  refused by `oarbank-sdk check` and no longer rendered.
- **Core.** `modsecrets.py` (storage, delivery, redaction, sealing and adoption for moves), `modimages.py` (enqueue
  checks, approval requests, release entries, first-run audit), `secrets.set` and `secrets.clear`, the
  `SECRETS_NOT_SET` predicate in claim and explain, `host.secrets.get` (the module host redacts the values a process
  received from its log), the console's Secrets tab and node-page list, `oarbank secret set|clear|list`, the
  `secret_unreadable` alert, the DPAPI backend of the secret store, and `CORE_VERSION` 2.5.0. A retired node's own
  values are deleted with it.
- **Agent.** `oarbank-core` `images.rs` (the decisions, `ring` for ECDSA) and the agent's `imageset.rs` (the registry
  client and the verifier with its seq file), the broker's set, listed-image and `gpus` checks and `ran_images`
  report, CDI detection (`cdi_kind`) behind `gpu_device()` and the `gpu` pool, the facts' `containers.gpu`, the
  secrets file and redaction in `jobs.rs` (the streamed log holds back as many bytes as the longest value, so a value is
  never split across two chunks).
- **Not built, as the design says:** keyless identities, Notary v2, private registries, hardware-held keys (open
  questions), and the Windows container runtime the WSL2 GPU-PV path needs (`containers.gpu` is `undetected` there).
- **Tests.** SDK: `tests/test_trust.py` (rules, vectors, layouts in both cosign formats, an index and its seq, the kit's
  secret delivery and leak checks, its set checks and both refusals, the example). Core: `tests/test_secrets.py`
  (write-only storage, the value beside params only, per-node delivery to the declaring stage, `SECRETS_NOT_SET`,
  `host.secrets.get` with and without the permission and its log redaction, no API read or console page showing it,
  the CLI, an unreadable value, sealing and adoption), `tests/test_image_sets.py` (approval, the release entry,
  enqueue checks, 500 distinct images under one approval with each first run audited, the gpu pool and GPU
  admission), a secret carried by the whole-move test, and on a real agent `tests/rust/test_agent_jobs.py` (the
  declaring stage's file and its mode, none for the probe stage, redaction of the streamed log and the failure). Agent:
  `imageset.rs` (both formats, the referrers tag fallback, an index's seq kept across agents, an unreachable registry),
  `broker.rs` (500 distinct signed images through one broker, the refusals, `gpus`), CDI detection, redaction. Rust
  parity (`oarbank-core-py`): the image vectors and random tampering.

- **Verified on each OS.** macOS: the whole core suite (real agent included), chaos, the SDK suite, the Rust
  workspace and clippy. Linux (aarch64 VM): the same, plus a broker test in which the real rootless Podman pulls, by
  digest, an image the agent verified from a local registry, and refuses an unsigned one before any pull; the real-agent
  test finds the secrets file at mode 0600 under Landlock. Windows (arm64 VM): clippy for the workspace, the
  `oarbank-core`, agent and protection tests (secrets file, redaction, work-directory cleanup; the broker and the
  verifier are POSIX-only, as the container runtime is), the SDK suite, and the DPAPI backend of the secret store
  (a key wrapped and unwrapped for the current user). Not verified on Windows: a sandboxed runner reading the secrets
  file end to end (the core's real-agent tests need a coordinator, which does not run on Windows yet).
