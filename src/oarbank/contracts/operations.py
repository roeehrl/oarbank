"""The operation registry (PLAN D14, D15, D21; docs/design/admin-console.md "One operation registry").

Every mutation is declared once, here: id, friction tier, preview, reason policy, minimum role, audit
category, reversing operation, idempotency style, and the routes/CLI commands/GUI forms that reach it.
The API, oarbank and the console all read these facts; a test fails if any mutating route in oarbankd
is not reachable from a registered operation (tests/test_contracts.py).

"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Tier = Literal["T0", "T1", "T2", "T3"]
TIERS = ("T0", "T1", "T2", "T3")
Role = Literal["viewer", "operator", "admin"]
ReasonPolicy = Literal["optional", "prompted", "required"]
DEFAULT_REASON = {"T0": "optional", "T1": "prompted", "T2": "required", "T3": "required"}
# bulk operations move up one tier above these sizes (admin-console.md, "Bulk")
BULK_ESCALATE_ITEMS, BULK_ESCALATE_FLEET_FRACTION = 10, 0.25


class Route(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    method: Literal["POST", "PUT", "PATCH", "DELETE"]
    path: str
    when: dict[str, str] = Field(default_factory=dict, description="Discriminator: path/body field values selecting this operation on a shared route.")


class Operation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    id: str = Field(pattern=r"^[a-z]+(\.[a-z_]+)+$")
    area: Literal["fleet", "nodes", "jobs", "campaigns", "datasets", "modules", "releases", "agent", "coordinator",
                  "protection", "alerts", "settings", "audit", "access"]
    summary: str
    tier: Tier
    escalates: str | None = Field(None, description="When the tier rises one level (besides bulk).")
    preview: bool = Field(False, description="Accepts dry_run and returns a plan (mandatory at T2+).")
    reason: ReasonPolicy | None = Field(None, description="Defaults from the tier.")
    min_role: Role = "operator"
    category: Literal["create", "modify", "remove", "access"]
    reverses: str | None = Field(None, description="The operation that undoes this one, if any.")
    idempotency: Literal["declarative", "key", "natural"] = Field(
        description="declarative: PUT of a desired state; key: needs Idempotency-Key; natural: repeating is harmless.")
    versioned: bool = Field(False, description="Edits a resource with a version (If-Match; 428 when missing at T2+).")
    bulk: bool = False
    routes: list[Route] = Field(default_factory=list)
    cli: list[str] = Field(default_factory=list, description="oarbank invocations reaching it.")
    gui: list[Route] = Field(default_factory=list, description="Console form posts reaching it.")

    @property
    def reason_policy(self) -> ReasonPolicy:
        return self.reason or DEFAULT_REASON[self.tier]

    @model_validator(mode="after")
    def _rules(self):
        if self.tier in ("T2", "T3") and not self.preview:
            raise ValueError(f"{self.id}: T2/T3 operations must support preview")
        if self.reason and TIERS.index(self.tier) >= 2 and self.reason != "required":
            raise ValueError(f"{self.id}: reasons are required at T2 and above")
        if not (self.routes or self.gui):
            raise ValueError(f"{self.id}: an operation needs a route")
        return self


def R(method, path, **when):
    return Route(method=method, path=path, when=when)


# The generic operation endpoint (oarbankd admin API): POST /api/v1/ops/<operation id> reaches every
# implemented operation; the console and oarbank both use it.
OPS_ROUTE_PATH = "/api/v1/ops/{op}"


def OPR(op_id):
    return [R("POST", OPS_ROUTE_PATH, op=op_id)]


# oarbank-console's blob staging for a browser upload: bytes only, forwarded to oarbankd's upload routes with the account's
# identity; nothing changes until datasets.register names them
CONSOLE_UPLOADS = [R("POST", "/datasets/uploads/{digest}"), R("PATCH", "/datasets/uploads/{digest}")]


# oarbank-console's operation form endpoint (T2/T3 continue on POST /apply/{op} with the reviewed plan)
CONSOLE_ROUTE_PATH = "/do/{op}"


def CON(op_id):
    return [R("POST", CONSOLE_ROUTE_PATH, op=op_id)]


# oarbank-console's staging of an operation's upload (module bundle, agent binary, coordinator build): the browser sends
# the file first so the page can show progress, the console forwards the bytes to the operation's staging route on
# oarbankd with the account's identity, and the form then posts the operation with the SHA-256; nothing changes until then
CONSOLE_STAGE_PATH = "/stage/{op}"


def STAGED(op_id):
    return [R("POST", CONSOLE_STAGE_PATH, op=op_id)]


OPS: list[Operation] = [
    # ------------------------------------------------------------------ fleet
    Operation(id="fleet.pause", area="fleet", summary="Stop granting new leases fleet-wide; running attempts continue",
              tier="T0", category="modify", reverses="fleet.resume", idempotency="declarative", 
              routes=OPR("fleet.pause"), cli=["oarbank pause --all"], gui=CON("fleet.pause")),
    Operation(id="fleet.halt", area="fleet", summary="Pause pausable attempts and evict the rest gracefully",
              tier="T1", category="modify", reverses="fleet.resume", idempotency="declarative", 
              routes=OPR("fleet.halt"), cli=["oarbank halt --all"], gui=CON("fleet.halt")),
    Operation(id="fleet.resume", area="fleet", summary="Resume leasing (rollouts stay frozen until resumed separately)",
              tier="T1", reason="required", category="modify", reverses="fleet.pause", idempotency="declarative",
              routes=OPR("fleet.resume"), cli=["oarbank resume --all"], gui=CON("fleet.resume")),

    # ------------------------------------------------------------------ nodes
    Operation(id="nodes.admit", area="nodes", summary="Approve an enrollment request (the node gets its client certificate)",
              tier="T2", preview=True, min_role="admin", category="create", reverses="nodes.retire", idempotency="natural",
              routes=OPR("nodes.admit"), cli=["oarbank node approve <eid>"], gui=CON("nodes.admit")),
    Operation(id="nodes.join_code", area="nodes", summary="A join code for new machines: single use and approved at once by default; multi-use codes cap their uses and leave machines pending unless set to approve automatically (expires)",
              tier="T2", preview=True, min_role="admin", category="create", idempotency="natural",
              routes=OPR("nodes.join_code"), cli=["oarbank join-code [--label NAME] [--uses N] [--ttl S]"], gui=CON("nodes.join_code")),
    Operation(id="nodes.revoke_join_code", area="nodes", summary="Revoke a join code (machines that already joined with it stay)",
              tier="T1", min_role="admin", category="remove", idempotency="natural",
              routes=OPR("nodes.revoke_join_code"), cli=["oarbank join-code revoke <id>"], gui=CON("nodes.revoke_join_code")),
    Operation(id="nodes.admit_code", area="nodes", summary="Approve the waiting machine that shows this code (a node joined by the coordinator's address)",
              tier="T2", preview=True, min_role="admin", category="create", reverses="nodes.retire", idempotency="natural",
              routes=OPR("nodes.admit_code"), cli=["oarbank node approve-code <CODE>"], gui=CON("nodes.admit_code")),
    Operation(id="nodes.reject_enrollment", area="nodes", summary="Reject an enrollment request",
              tier="T1", min_role="admin", category="remove", idempotency="natural",
              routes=OPR("nodes.reject_enrollment"), cli=["oarbank node reject <eid>"], gui=CON("nodes.reject_enrollment")),
    Operation(id="nodes.pause", area="nodes", summary="Stop leasing to a node; running attempts finish",
              tier="T0", category="modify", reverses="nodes.resume", idempotency="declarative",
              routes=OPR("nodes.pause"), cli=["oarbank node state <nid> paused"], gui=CON("nodes.pause")),
    Operation(id="nodes.resume", area="nodes", summary="Resume leasing to a node",
              tier="T0", category="modify", reverses="nodes.pause", idempotency="declarative",
              routes=OPR("nodes.resume"), cli=["oarbank node state <nid> active"], gui=CON("nodes.resume")),
    Operation(id="nodes.drain", area="nodes", summary="Finish running attempts, take no new ones (used by rolling upgrades)",
              tier="T1", category="modify", reverses="nodes.resume", idempotency="declarative",
              routes=OPR("nodes.drain"),
              cli=["oarbank node state <nid> draining"], gui=CON("nodes.drain")),
    Operation(id="nodes.set_caps", area="nodes", summary="Set or clear the owner's hard caps (cpu, memory, jobs, VM, disk, staging, schedule)",
              tier="T0", escalates="T1 when lowering a cap below current usage (attempts would be released)",
              category="modify", idempotency="declarative", versioned=True,
              routes=OPR("nodes.set_caps"), cli=["oarbank node limits <nid> ...", "oarbank node limits <nid> --clear-all"], gui=CON("nodes.set_caps")),
    Operation(id="nodes.set_policy", area="nodes", summary="Edit node policy (reserves, VM scoring role, yield settings); re-doctors and re-certifies on role changes",
              tier="T1", category="modify", idempotency="declarative", versioned=True,
              routes=OPR("nodes.set_policy"),
              cli=["oarbank node policy <nid> ..."], gui=CON("nodes.set_policy")),
    Operation(id="nodes.quarantine", area="nodes", summary="Stop all work on a node and revoke its live attempts",
              tier="T1", category="modify", reverses="nodes.clear_quarantine", idempotency="natural", gui=CON("nodes.quarantine"), routes=OPR("nodes.quarantine")),
    Operation(id="nodes.clear_quarantine", area="nodes", summary="Clear quarantine; the node re-doctors and re-certifies",
              tier="T1", category="modify", reverses="nodes.quarantine", idempotency="natural", gui=CON("nodes.clear_quarantine"), routes=OPR("nodes.clear_quarantine")),
    Operation(id="nodes.run_doctor", area="nodes", summary="Ask the agent to re-run every module doctor",
              tier="T0", category="modify", idempotency="natural", gui=CON("nodes.run_doctor"), routes=OPR("nodes.run_doctor")),
    Operation(id="nodes.recertify", area="nodes", summary="Discard certification and re-run golden jobs",
              tier="T0", category="modify", idempotency="natural", gui=CON("nodes.recertify"), routes=OPR("nodes.recertify")),
    Operation(id="nodes.retire", area="nodes", summary="Retire a node and revoke its client certificate",
              tier="T3", preview=True, min_role="admin", category="remove", idempotency="natural", gui=CON("nodes.retire"), routes=OPR("nodes.retire")),
    Operation(id="nodes.set_mode", area="nodes", summary="Set the protection mode (fleet_first | moderate | strict_yield)",
              tier="T1", category="modify", idempotency="declarative", versioned=True,
              routes=OPR("nodes.set_mode"), cli=["oarbank node mode <nid> <mode>"], gui=CON("nodes.set_mode")),

    # ------------------------------------------------------------------ jobs
    Operation(id="jobs.retry", area="jobs", summary="Requeue a failed or quarantined job",
              tier="T0", category="create", idempotency="key", bulk=True, gui=CON("jobs.retry"), routes=OPR("jobs.retry"),
              cli=["oarbank job retry <jid>"]),
    Operation(id="jobs.cancel", area="jobs", summary="Cancel a job and revoke its live attempts (shows compute lost)",
              tier="T1", category="remove", reverses="jobs.retry", idempotency="natural", bulk=True, gui=CON("jobs.cancel"), routes=OPR("jobs.cancel"),
              cli=["oarbank job cancel <jid>"]),
    Operation(id="jobs.set_priority", area="jobs", summary="Change a job's priority",
              tier="T0", category="modify", idempotency="declarative", versioned=True, bulk=True, routes=OPR("jobs.set_priority"), gui=CON("jobs.set_priority")),

    # ------------------------------------------------------------------ campaigns (D22)
    # A campaign is the core's only grouping of work; what it means (a parameter search, a benchmark sweep)
    # is its module's, and modules create campaigns through their own operations (mod.<module>.<verb>).
    Operation(id="campaigns.pause", area="campaigns", summary="Stop dispatching a campaign's jobs",
              tier="T0", category="modify", reverses="campaigns.resume", idempotency="declarative",
              routes=OPR("campaigns.pause"), cli=["oarbank campaign pause <id>"], gui=CON("campaigns.pause")),
    Operation(id="campaigns.resume", area="campaigns", summary="Resume a paused campaign",
              tier="T0", category="modify", reverses="campaigns.pause", idempotency="declarative",
              routes=OPR("campaigns.resume"), cli=["oarbank campaign resume <id>"], gui=CON("campaigns.resume")),
    Operation(id="campaigns.cancel", area="campaigns", summary="Cancel a campaign and all its pending and running jobs",
              tier="T3", preview=True, category="remove", idempotency="natural",
              routes=OPR("campaigns.cancel"), cli=["oarbank campaign cancel <id>"], gui=CON("campaigns.cancel")),
    Operation(id="campaigns.retry_failed", area="campaigns", summary="Retry every failed or quarantined job of a campaign (bulk jobs.retry)",
              tier="T1", category="create", idempotency="natural", bulk=True,
              routes=OPR("campaigns.retry_failed"), cli=["oarbank campaign retry-failed <id>"], gui=CON("campaigns.retry_failed")),
    Operation(id="campaigns.set_weight", area="campaigns", summary="Change a campaign's fair-share weight",
              tier="T0", category="modify", idempotency="declarative", versioned=True,
              routes=OPR("campaigns.set_weight"), cli=["oarbank campaign weight <id> <w>"], gui=CON("campaigns.set_weight")),
    Operation(id="campaigns.set_priority", area="campaigns", summary="Change a campaign's priority (its open jobs move with it)",
              tier="T0", category="modify", idempotency="declarative", versioned=True,
              routes=OPR("campaigns.set_priority"), cli=["oarbank campaign priority <id> <p>"], gui=CON("campaigns.set_priority")),
    # D33: placement keeps a campaign's units of work on one platform class each
    Operation(id="campaigns.set_placement", area="campaigns",
              summary="Keep a campaign's units of work on one platform class each (a stricter mix, before its first result)",
              tier="T2", preview=True, category="modify", idempotency="declarative",
              routes=OPR("campaigns.set_placement"), cli=["oarbank campaign placement <id> --mix <mix>"],
              gui=CON("campaigns.set_placement")),
    Operation(id="campaigns.rebind_platform", area="campaigns",
              summary="Move a campaign's units of work to another platform class; their finished jobs run again there",
              tier="T2", preview=True, category="modify", idempotency="natural",
              routes=OPR("campaigns.rebind_platform"), cli=["oarbank campaign rebind <id> --platform <token>"],
              gui=CON("campaigns.rebind_platform")),

    # ------------------------------------------------------------------ datasets
    Operation(id="datasets.register", area="datasets", summary="Register a dataset from uploaded blobs, files on the coordinator or origin URLs",
              tier="T1", category="create", idempotency="natural",
              # the resumable blob upload stages bytes for it (they change nothing until this operation names them)
              routes=[*OPR("datasets.register"), R("POST", "/api/v1/uploads/{digest}"), R("PATCH", "/api/v1/uploads/{digest}")],
              cli=["oarbank dataset upload <dir> --kind <kind>", "oarbank dataset register <file.json>"],
              gui=[*CON("datasets.register"), *CONSOLE_UPLOADS]),
    Operation(id="settings.origins.update", area="datasets", summary="Restrict the hosts dataset origins may name (empty: any public https host)",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="declarative", versioned=True,
              routes=OPR("settings.origins.update"), cli=["oarbank op settings.origins.update -p hosts=..."],
              gui=CON("settings.origins.update")),

    # ------------------------------------------------------------------ modules
    Operation(id="modules.set_pipeline", area="modules", summary="Run a module single-stage or split",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="declarative",
              routes=OPR("modules.set_pipeline"), cli=["oarbank pipeline single|split --module <module>"], gui=CON("modules.set_pipeline")),
    Operation(id="modules.install", area="modules", summary="Install a module bundle: verify every file hash and the digest, check compatibility, self-test (enables nothing)",
              tier="T2", preview=True, min_role="admin", category="create", reverses="modules.uninstall", idempotency="natural",
              routes=[*OPR("modules.install"), R("POST", "/api/v1/modules/bundles")], cli=["oarbank module install <bundle.mfb>"],
              gui=[*CON("modules.install"), *STAGED("modules.install")]),
    Operation(id="modules.uninstall", area="modules", summary="Remove an installed module version that no channel or pin uses",
              tier="T2", preview=True, min_role="admin", category="remove", idempotency="natural",
              routes=OPR("modules.uninstall"), cli=["oarbank module uninstall <name>@<version>"], gui=CON("modules.uninstall")),
    Operation(id="modules.verify", area="modules", summary="Re-verify installed bundles against their recorded digests",
              tier="T0", category="access", idempotency="natural", routes=OPR("modules.verify"), cli=["oarbank module verify [name]"],
              gui=CON("modules.verify")),
    Operation(id="modules.check", area="modules", summary="Run module integrity checks (the module's integrity.check and the core's file checks)",
              tier="T0", category="access", idempotency="natural", routes=OPR("modules.check"), cli=["oarbank module check [name] [--deep]"],
              gui=CON("modules.check")),
    Operation(id="modules.enable", area="modules", summary="Enable a module's first version, or re-enable it after the kill switch",
              tier="T1", min_role="admin", category="modify", reverses="modules.disable", idempotency="declarative",
              routes=OPR("modules.enable"), cli=["oarbank module enable <name>@<version>"], gui=CON("modules.enable")),
    Operation(id="modules.approve", area="modules", summary="Approve a module version's sandbox grants (network egress, host paths, GPU, containers) for its jobs",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="declarative",
              routes=OPR("modules.approve"), cli=["oarbank module approve <name>@<version>"], gui=CON("modules.approve")),
    Operation(id="modules.enable_canary", area="modules", summary="Stage a module version on canary nodes (they re-doctor and re-certify on it)",
              tier="T2", preview=True, min_role="admin", category="modify", reverses="modules.rollback", idempotency="declarative",
              routes=OPR("modules.enable_canary"), cli=["oarbank module canary <name>@<version> --node <node>"],
              gui=CON("modules.enable_canary")),
    Operation(id="modules.promote", area="modules", summary="Make the canary version the default on all nodes",
              tier="T2", preview=True, min_role="admin", category="modify", reverses="modules.rollback", idempotency="declarative",
              routes=OPR("modules.promote"), cli=["oarbank module promote <name>[@<canary version>]"], gui=CON("modules.promote")),
    Operation(id="modules.rollback", area="modules", summary="Abandon the canary, or flip the default back to the retained previous version",
              tier="T1", category="modify", idempotency="declarative", routes=OPR("modules.rollback"),
              cli=["oarbank module rollback <name>"], gui=CON("modules.rollback")),
    Operation(id="modules.disable", area="modules", summary="Kill switch: stop dispatch fleet-wide within one heartbeat, requeue live attempts",
              tier="T1", category="modify", reverses="modules.enable", idempotency="declarative",
              routes=OPR("modules.disable"), cli=["oarbank module disable <name>"], gui=CON("modules.disable")),
    Operation(id="modules.pin", area="modules", summary="Pin a node to a module version (or clear the pin)",
              tier="T1", category="modify", idempotency="declarative", routes=OPR("modules.pin"),
              cli=["oarbank module pin|unpin <name>@<version> --node <node>"], gui=CON("modules.pin")),
    Operation(id="modules.restart_host", area="modules", summary="Restart a module's coordinator process",
              tier="T0", category="modify", idempotency="natural", routes=OPR("modules.restart_host"), gui=CON("modules.restart_host")),

    # ------------------------------------------------------------------ releases
    Operation(id="releases.build", area="releases", summary="Build each fleet platform's release from the enabled modules (nodes get it once it is signed and promoted)",
              tier="T1", min_role="admin", category="create", idempotency="natural",
              routes=OPR("releases.build"), cli=["oarbank release build"], gui=CON("releases.build")),
    Operation(id="releases.attach_signature", area="releases", summary="Attach an offline signature to a release (signing builds only)",
              tier="T1", min_role="admin", category="modify", idempotency="natural",
              routes=OPR("releases.attach_signature"), cli=["oarbank release sign"], gui=CON("releases.attach_signature")),

    # ------------------------------------------------------------------ coordinator move (coordinator-move.md)
    Operation(id="coordinator.prepare", area="coordinator", summary="Plan a coordinator move to another machine: a pairing code (and, for an enrolled node, its agent installs the standby)",
              tier="T3", preview=True, min_role="admin", category="create", idempotency="natural",
              routes=OPR("coordinator.prepare"), cli=["oarbank coordinator prepare --to <node|http://host:port>"], gui=CON("coordinator.prepare")),
    Operation(id="coordinator.move", area="coordinator", summary="Move the coordinator to the paired standby after the time lock (signed move statement; agents follow)",
              tier="T3", preview=True, min_role="admin", category="modify", reverses="coordinator.cancel", idempotency="natural",
              routes=OPR("coordinator.move"), cli=["oarbank coordinator move [--timelock 24h] [--reason ...]"], gui=CON("coordinator.move")),
    Operation(id="coordinator.cancel", area="coordinator", summary="Cancel a pending coordinator move (before the commit decision); this coordinator keeps serving",
              tier="T1", category="modify", idempotency="natural", routes=OPR("coordinator.cancel"),
              cli=["oarbank coordinator cancel"], gui=CON("coordinator.cancel")),
    Operation(id="coordinator.finalize", area="coordinator", summary="On the old machine after probation: stop serving redirects and never start again here",
              tier="T2", preview=True, min_role="admin", category="remove", idempotency="natural",
              routes=OPR("coordinator.finalize"), cli=["oarbank coordinator finalize"], gui=CON("coordinator.finalize")),
    Operation(id="coordinator.sign_move", area="coordinator", summary="Attach the owner's signature to a move waiting for it (signing mode); the move is then announced",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="natural",
              routes=OPR("coordinator.sign_move"), cli=["oarbank coordinator sign --owner-key <key>"], gui=CON("coordinator.sign_move")),
    Operation(id="owner.set_anchors", area="coordinator", summary="Set or rotate the owner key set (primary + offline backup, rescue locations); signed by the new keys and a current one",
              tier="T3", preview=True, min_role="admin", category="modify", idempotency="natural",
              routes=OPR("owner.set_anchors"), cli=["oarbank owner set --key <primary> --backup-key <backup> [--rescue URL]"], gui=CON("owner.set_anchors")),
    Operation(id="owner.disable_signing", area="coordinator", summary="Turn owner signing off with an owner-signed statement (agents unpin the owner keys)",
              tier="T3", preview=True, min_role="admin", category="remove", idempotency="natural",
              routes=OPR("owner.disable_signing"), cli=["oarbank owner disable --key <owner key>"], gui=CON("owner.disable_signing")),
    Operation(id="nodes.confirm_identity", area="nodes", summary="Confirm that a node pinned this coordinator's identity key (compare the fingerprints once)",
              tier="T1", category="modify", idempotency="declarative", routes=OPR("nodes.confirm_identity"),
              cli=["oarbank node confirm-identity <node>"], gui=CON("nodes.confirm_identity")),

    # ------------------------------------------------------------------ agent self-update (no ssh)
    Operation(id="agent.upload", area="agent", summary="Register an oarbank-agent binary: its platform read from its headers and its version from its marker, never run (deploys nothing)",
              tier="T2", preview=True, min_role="admin", category="create", idempotency="natural",
              routes=[*OPR("agent.upload"), R("POST", "/api/v1/agent/builds")], cli=["oarbank agent upload <oarbank-agent>"],
              gui=[*CON("agent.upload"), *STAGED("agent.upload")]),
    Operation(id="vendor.metadata.upload", area="agent", summary="Mirror the vendor's TUF metadata for agents (they verify agent builds against the vendor root compiled into them)",
              tier="T1", min_role="admin", category="modify", idempotency="natural",
              routes=OPR("vendor.metadata.upload"), cli=["oarbank vendor-metadata upload <dir>"], gui=CON("vendor.metadata.upload")),
    Operation(id="agent.canary", area="agent", summary="Run an agent build on canary nodes (each drains, swaps and restarts on it)",
              tier="T2", preview=True, min_role="admin", category="modify", reverses="agent.rollback", idempotency="declarative",
              routes=OPR("agent.canary"), cli=["oarbank agent canary <build> --node <node>"], gui=CON("agent.canary")),
    Operation(id="agent.promote", area="agent", summary="Make the canary agent build current on every node of its platform (default: every platform with a canary)",
              tier="T2", preview=True, min_role="admin", category="modify", reverses="agent.rollback", idempotency="declarative",
              routes=OPR("agent.promote"), cli=["oarbank agent promote [--platform <os-arch>]"], gui=CON("agent.promote")),
    Operation(id="agent.rollback", area="agent", summary="Abandon the agent canary, or flip current back to the previous build",
              tier="T1", category="modify", idempotency="declarative", routes=OPR("agent.rollback"),
              cli=["oarbank agent rollback [--platform <os-arch>]"], gui=CON("agent.rollback")),
    Operation(id="agent.sign", area="agent", summary="Attach an offline signature to an agent build (signing builds only)",
              tier="T1", min_role="admin", category="modify", idempotency="natural",
              routes=OPR("agent.sign"), cli=["oarbank agent sign <build>"], gui=CON("agent.sign")),
    Operation(id="coordinator.builds.upload", area="coordinator", summary="Register a coordinator build for a platform (read from its manifest, never run)",
              tier="T2", preview=True, min_role="admin", category="create", idempotency="natural",
              routes=[*OPR("coordinator.builds.upload"), R("POST", "/api/v1/coordinator/builds")],
              cli=["oarbank coordinator-build upload <archive>"], gui=[*CON("coordinator.builds.upload"), *STAGED("coordinator.builds.upload")]),
    Operation(id="coordinator.builds.sign", area="coordinator", summary="Attach an owner signature to a coordinator build (moves install only signed builds)",
              tier="T1", min_role="admin", category="modify", idempotency="natural",
              routes=OPR("coordinator.builds.sign"), cli=["oarbank coordinator-build sign <build>"], gui=CON("coordinator.builds.sign")),
    Operation(id="releases.promote", area="releases", summary="Make a release current; agents install it on their next heartbeat",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="declarative",
              routes=OPR("releases.promote"),
              cli=["oarbank release promote <rid>"], gui=CON("releases.promote")),
    Operation(id="releases.pin_key", area="releases", summary="Pin or rotate the release public key (signing builds only)",
              tier="T3", preview=True, min_role="admin", category="modify", idempotency="declarative",
              routes=OPR("releases.pin_key"), cli=["oarbank release keygen"], gui=CON("releases.pin_key")),

    # ------------------------------------------------------------------ protection
    Operation(id="protection.rules.update", area="protection", summary="Edit a node's protected-process rules (immutable versions)",
              tier="T2", preview=True, category="modify", reverses="protection.rules.restore", idempotency="declarative",
              versioned=True, routes=OPR("protection.rules.update"), cli=["oarbank protection set <nid> <file>", "oarbank protection preview <nid> <file>"],
              gui=CON("protection.rules.update")),
    Operation(id="protection.rules.restore", area="protection", summary="Restore a previous rule-set version (writes a new version)",
              tier="T2", preview=True, category="modify", idempotency="declarative", versioned=True,
              routes=OPR("protection.rules.restore"), cli=["oarbank protection restore <nid> <version>"],
              gui=CON("protection.rules.restore")),
    Operation(id="protection.rules.canary", area="protection", summary="Apply a rule set to one node first, then promote it to the rest",
              tier="T2", preview=True, category="modify", idempotency="declarative",
              routes=OPR("protection.rules.canary"), cli=["oarbank protection canary <nid> <file>", "oarbank protection promote"],
              gui=CON("protection.rules.canary")),
    Operation(id="protection.probe_now", area="protection", summary="Run a pause probe now",
              tier="T0", category="modify", idempotency="natural", routes=OPR("protection.probe_now"),
              cli=["oarbank protection probe <nid>"], gui=CON("protection.probe_now")),

    # ------------------------------------------------------------------ alerts
    Operation(id="alerts.ack", area="alerts", summary="Acknowledge an alert (optionally: was it useful?)", tier="T0", category="modify",
              idempotency="natural", routes=OPR("alerts.ack"), cli=["oarbank alerts ack <id> [--useful|--noise]"], gui=CON("alerts.ack")),
    Operation(id="alerts.snooze", area="alerts", summary="Snooze an alert until a time (no re-notification meanwhile)", tier="T0",
              category="modify", idempotency="declarative", routes=OPR("alerts.snooze"), cli=["oarbank alerts snooze <id> --minutes N"],
              gui=CON("alerts.snooze")),
    Operation(id="alerts.resolve", area="alerts", summary="Resolve an alert (a latched invariant needs a note)",
              tier="T0", escalates="T1 with a note for a latched invariant", category="modify",
              idempotency="natural", routes=OPR("alerts.resolve"), cli=["oarbank alerts resolve <id> [--useful|--noise]"],
              gui=CON("alerts.resolve")),

    # ------------------------------------------------------------------ settings
    Operation(id="settings.notifications.update", area="settings", summary="Edit ntfy and notification settings",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="declarative", versioned=True, gui=CON("settings.notifications.update"), routes=OPR("settings.notifications.update")),
    Operation(id="settings.tools.update", area="settings", summary="Map a host tool id to its paths per OS in the tool registry (modules request tools by id)",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="declarative", versioned=True,
              gui=CON("settings.tools.update"), routes=OPR("settings.tools.update")),
    Operation(id="settings.folders.update", area="settings", summary="Map a folder id to a path on each node in the folder registry (modules request folders by id)",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="declarative", versioned=True,
              gui=CON("settings.folders.update"), routes=OPR("settings.folders.update"),
              cli=["oarbank folders map <id> --access read|write --node <node>=<path>"]),
    Operation(id="folders.sign", area="settings", summary="Attach the owner's signature to a node's folder statement (signing mode)",
              tier="T1", min_role="admin", category="modify", idempotency="natural",
              routes=OPR("folders.sign"), cli=["oarbank folders sign <node>"], gui=CON("folders.sign")),
    Operation(id="access.accounts.create", area="access", summary="Create a console account (a TOTP seed is shown once; a password is optional)",
              tier="T2", preview=True, min_role="admin", category="create", idempotency="natural",
              gui=CON("access.accounts.create"), routes=OPR("access.accounts.create"), cli=["oarbank account create <name>"]),
    Operation(id="access.accounts.update", area="access", summary="Change an account's role, or disable or enable it (disabling ends its sessions and tokens)",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="declarative",
              gui=CON("access.accounts.update"), routes=OPR("access.accounts.update")),
    Operation(id="access.accounts.reset_totp", area="access", summary="Issue a new TOTP seed for an account (ends its sessions)",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="natural",
              gui=CON("access.accounts.reset_totp"), routes=OPR("access.accounts.reset_totp")),
    Operation(id="access.accounts.set_password", area="access", summary="Set an account's password (ends its sessions)",
              tier="T1", min_role="viewer", category="modify", idempotency="natural",
              gui=CON("access.accounts.set_password"), routes=OPR("access.accounts.set_password")),
    Operation(id="access.tokens.create", area="access", summary="Create a personal access token for scripts (shown once, expires)",
              tier="T2", preview=True, min_role="viewer", category="create", idempotency="natural",
              gui=CON("access.tokens.create"), routes=OPR("access.tokens.create"), cli=["oarbank token create"]),
    Operation(id="access.tokens.revoke", area="access", summary="Revoke a personal access token",
              tier="T1", min_role="viewer", category="remove", idempotency="natural",
              gui=CON("access.tokens.revoke"), routes=OPR("access.tokens.revoke")),
    Operation(id="access.login_link", area="access", summary="Mint a one-time console sign-in link (valid 2 minutes)",
              tier="T1", min_role="admin", category="access", idempotency="natural",
              routes=OPR("access.login_link"), cli=["oarbank console login [--account <name>]"], gui=CON("access.login_link")),
    Operation(id="secrets.set", area="modules", summary="Set a module secret for the module or one node (write-only: the value is never shown, only a fingerprint)",
              tier="T1", min_role="admin", category="modify", reverses="secrets.clear", idempotency="declarative",
              routes=OPR("secrets.set"), cli=["oarbank secret set <module> <name> [--node N]"], gui=CON("secrets.set")),
    Operation(id="secrets.clear", area="modules", summary="Remove a module secret's value for the module or one node (jobs needing it wait)",
              tier="T1", min_role="admin", category="remove", idempotency="natural",
              routes=OPR("secrets.clear"), cli=["oarbank secret clear <module> <name> [--node N]"], gui=CON("secrets.clear")),
    Operation(id="modules.cli_token", area="modules", summary="A one-hour token scoped to one module, for its CLI (oarbank cli <module>)",
              tier="T1", min_role="operator", category="access", idempotency="natural",
              routes=OPR("modules.cli_token"), cli=["oarbank cli <module> [args...]"],
              gui=CON("modules.cli_token")),
    Operation(id="access.passkeys.remove", area="access", summary="Remove a passkey from an account",
              tier="T1", min_role="viewer", category="remove", idempotency="natural",
              gui=CON("access.passkeys.remove"), routes=OPR("access.passkeys.remove")),
    Operation(id="settings.update", area="settings", summary="Write a raw setting (goldens, dataset groups)",
              tier="T2", preview=True, min_role="admin", category="modify", idempotency="declarative",
              routes=OPR("settings.update"), cli=["oarbank op settings.update <key>", "module CLIs (golden:<module>, dataset_groups)"], gui=CON("settings.update")),

    # ------------------------------------------------------------------ audit
    Operation(id="audit.verify", area="audit", summary="Recompute the audit hash chain against the signed digests",
              tier="T0", min_role="viewer", category="access", idempotency="natural", routes=OPR("audit.verify"),
              cli=["oarbank audit verify"], gui=CON("audit.verify")),
]

# The campaign operations each campaign state takes: the console offers exactly these, and oarbankd refuses the rest
# (409 campaign_<state>), except a repeat of the state an operation sets (pause on paused: declarative). A done
# campaign reopens by itself when its jobs are retried or requeued, so it is never resumed; cancelled is final.
_CAMPAIGN_EDITS = ("campaigns.retry_failed", "campaigns.set_weight", "campaigns.set_priority", "campaigns.rebind_platform",
                   "campaigns.cancel")
CAMPAIGN_OPS: dict[str, tuple[str, ...]] = {
    "running": ("campaigns.pause", "campaigns.set_placement", *_CAMPAIGN_EDITS),
    "paused": ("campaigns.resume", "campaigns.set_placement", *_CAMPAIGN_EDITS),
    "done": _CAMPAIGN_EDITS,
    "cancelled": (),
}
_CAMPAIGN_SETS = {"campaigns.pause": "paused", "campaigns.resume": "running", "campaigns.cancel": "cancelled"}


def campaign_op_applies(state: str, op_id: str) -> bool:
    return op_id in CAMPAIGN_OPS.get(state, ()) or _CAMPAIGN_SETS.get(op_id) == state


REGISTRY: dict[str, Operation] = {}
for _op in OPS:
    if _op.id in REGISTRY:
        raise ValueError(f"duplicate operation {_op.id}")
    REGISTRY[_op.id] = _op

# Agent protocol routes: machine-to-machine, authenticated by node token and fenced by generation,
# not admin operations. They are audited as events under actor node:<id>, not through the registry.
AGENT_ROUTES = {
    ("POST", "/v1/agent/enroll"), ("POST", "/v1/agent/hello"), ("POST", "/v1/agent/heartbeat"),
    ("POST", "/v1/agent/claim"), ("POST", "/v1/agent/cert"), ("POST", "/v1/attempts/{aid}/complete"), ("POST", "/v1/attempts/{aid}/release"),
    ("POST", "/v1/attempts/{aid}/fail"), ("POST", "/v1/attempts/{aid}/log"), ("POST", "/v1/attempts/{aid}/checkpoint"),
    ("POST", "/v1/uploads/{digest}"), ("PATCH", "/v1/uploads/{digest}"),
    # the coordinator-move channel between the old coordinator and its standby target (coordinator-move.md):
    # authenticated by the pairing code, then a move token plus the target's tailnet identity, or by a
    # signature from the paired coordinator's key; the operations that start and stop a move are audited
    ("POST", "/v1/move/pair"), ("POST", "/v1/move/snapshot"), ("POST", "/v1/move/ready"), ("POST", "/v1/move/commit"),
    ("POST", "/v1/move/sign-statement"), ("POST", "/v1/move/promote"),
}


# Sign-in ceremonies, not operations: oarbankd answers them only for the console (its per-boot secret), they create or
# end a session and change no fleet state; each is audited as an `access` record.
SESSION_ROUTES = {
    ("POST", "/api/v1/access/login"), ("POST", "/api/v1/access/link"), ("POST", "/api/v1/access/logout"),
    ("POST", "/api/v1/access/touch"),
    ("POST", "/api/v1/access/passkey/options"), ("POST", "/api/v1/access/passkey/login"),
    ("POST", "/api/v1/access/passkey/register"),
}
CONSOLE_SESSION_ROUTES = {
    ("POST", "/login"), ("POST", "/logout"), ("POST", "/login/passkey/options"), ("POST", "/login/passkey"),
    ("POST", "/account/passkey/options"), ("POST", "/account/passkey"),
}


def operations_for(method: str, path: str) -> list[Operation]:
    if (method, path) == ("POST", OPS_ROUTE_PATH):
        return list(OPS)                                  # the generic endpoint dispatches by operation id
    return [op for op in OPS for r in (*op.routes, *op.gui) if r.method == method and r.path == path]


def effective_tier(op: Operation, items: int = 1, fleet_fraction: float = 0.0) -> Tier:
    """Bulk operations move up one tier above BULK_ESCALATE_ITEMS items or a quarter of the fleet."""
    t = TIERS.index(op.tier)
    if op.bulk and (items > BULK_ESCALATE_ITEMS or fleet_fraction > BULK_ESCALATE_FLEET_FRACTION):
        t = min(t + 1, 3)
    return TIERS[t]


# ------------------------------------------------------------------ module operations (D23)

def module_op_id(module_name: str, verb: str) -> str:
    return f"mod.{module_name.replace('-', '_')}.{verb}"


def register_module_operations(module_name: str, decls) -> list[Operation]:
    """Registry entries for a module's [[operations]] (oarbank_sdk.ui.OperationDecl), registered when the
    module is catalogued (at install, with the owner approving tier or effect changes). The tier
    is the effective tier (declared tier raised by effect floors); reasons and previews follow it."""
    out = []
    for d in decls:
        tier = d.effective_tier()
        effects = set(d.effects)
        category = "remove" if effects & {"jobs.cancel", "campaigns.cancel", "datasets.delete", "store.delete"} else \
            "create" if effects & {"jobs.enqueue", "campaigns.create", "datasets.create"} else "modify"
        op = Operation(id=module_op_id(module_name, d.verb), area="modules", summary=d.title, tier=tier,
                       preview=tier in ("T2", "T3") or bool(d.preview), min_role=d.min_role, category=category,
                       idempotency="key" if category == "create" else "natural",
                       routes=OPR(module_op_id(module_name, d.verb)), gui=CON(module_op_id(module_name, d.verb)))
        REGISTRY[op.id] = op
        if op not in OPS:
            OPS[:] = [o for o in OPS if o.id != op.id] + [op]
        MODULE_OPS[op.id] = (module_name, d)
        out.append(op)
    return out


MODULE_OPS: dict[str, tuple] = {}         # op id -> (module name, OperationDecl)


def command(op_id: str, target: str | None = None) -> str:
    """The `oarbank` command that runs an operation (on `target`): its own command with the first placeholder filled in,
    else `oarbank op <op> [target]`. Explain's remedies name it."""
    import re
    cli = next((c for c in REGISTRY[op_id].cli if c.startswith("oarbank ")), None) if op_id in REGISTRY else None
    if cli and not cli.startswith("oarbank op "):
        return re.sub(r"<[^>]+>", target, cli, count=1) if target else cli
    return f"oarbank op {op_id}" + (f" {target}" if target else "")
