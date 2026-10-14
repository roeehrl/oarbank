"""The settings registry (docs/design/settings.md): every owner setting declared once, in code.

Each definition carries what a person reads (label, one line of help, unit), its type as a JSON Schema subset, its
default (static, or computed from the node's facts with the reason), the scopes it may be set at, how values from
several scopes combine (merge rule), whether a fleet or group value may lock it, its danger tier, where it applies
(the coordinator, the agent or both), the agent directive section it travels in, and its effect hooks. The agent's
pre-first-heartbeat defaults are generated from these definitions into Rust (`rustgen.py`, freshness-tested), so the
coordinator and the agent can never disagree on a default.

Absence of a value means inherit; nothing here stores a default as a value (store.py, resolve.py)."""
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable

SCOPES = ("fleet", "group", "node")
SCOPE_NAMES = {"fleet": "Fleet", "group": "Group", "node": "This node"}
MERGES = ("replace", "min", "max", "union")
TIERS = ("T0", "T1", "T2", "T3")


@dataclass(frozen=True)
class Setting:
    key: str
    label: str
    help: str
    schema: dict
    default: Any = None
    # computed default: facts -> (value, reason); `default` is then the value the agent starts with before it hears
    # from the coordinator, and what a node with no facts gets
    computed: Callable[[dict], tuple] | None = None
    computed_how: str | None = None
    unit: str | None = None
    scopes: tuple = SCOPES
    merge: str = "replace"
    order: tuple = ()                 # min/max over named values (enforce: soft < hard)
    lockable: bool = True
    advanced: bool = False
    danger: str = "T1"
    applies: str = "agent"            # coordinator | agent | both
    wire: str | None = None           # the agent directive section: policy | limits
    section: str | None = None        # where the console shows it (SECTIONS)
    qualifier: str | None = None      # None: a core key; "required": set per module only (a core key every module has,
                                      # or a module's own key); "optional": a core key a module may qualify (its
                                      # module-qualified chain wins over the plain one)
    writer: str | None = None         # the operation that owns its writes (settings.apply refuses it)
    effects: tuple = ()               # hooks run on nodes whose effective value changed (apply.py)
    hardware: str | None = None       # cores | ram: a node's own value may not exceed its hardware
    campaign: bool = False            # a campaign may override it while it runs (bounded by locks; apply.campaign_refusals)
    tighten: str | None = None        # a safety key: which way is stricter, "lower" or "higher" (a boolean: off < on; a
                                      # choice: `order`); a campaign and a machine's managed policy may only move it that
                                      # way. A min/max merge implies it (tighten_dir)
    managed: bool = False             # a machine's managed policy (MDM, Group Policy, /etc/oarbank/policy.json) may set it,
                                      # tighten-only, on that machine (docs/design/settings.md, "Managed on this machine")
    note: str | None = None           # beside the row (for example: not applied by agents yet)
    examples: tuple = field(default=())
    required: bool = False            # a module's own key the owner must set (readiness, SETTINGS_NOT_SET)
    validator: Callable[[Any], Any] | None = None   # the value normalized, or SettingError (a module's own key: its
                                                    # property's whole JSON Schema); None: the `schema` subset below

    @property
    def nullable(self) -> bool:
        t = self.schema.get("type")
        return isinstance(t, list) and "null" in t

    @property
    def tighten_dir(self) -> str | None:
        """"lower" or "higher": the stricter direction of a safety key (a cap's min merge is "lower", a max merge
        "higher"), else None (a preference: any value)."""
        return self.tighten or {"min": "lower", "max": "higher"}.get(self.merge)


def _os_reserve(facts: dict) -> tuple:
    ram = float((facts or {}).get("memory_gb") or 0)
    if not ram:
        return 6, "RAM not reported"
    return (4 if ram <= 32 else (8 if ram >= 96 else 6)), f"{ram:g} GB RAM"


def _port_range(v):
    """listener_port_range: "<a>-<b>" with 1024 <= a <= b <= 65535."""
    v = _check(REGISTRY["listener_port_range"].schema, v, "listener_port_range")
    a, b = (int(x) for x in v.split("-"))
    if not 1024 <= a <= b <= 65535:
        raise SettingError("bad_value", f"listener_port_range: {v!r} must be <a>-<b> with 1024 <= a <= b <= 65535")
    return f"{a}-{b}"


def _until(v, where: str):
    """An expiry: Unix seconds, an ISO 8601 time (UTC when it names no zone), or none."""
    if v is None or (isinstance(v, str) and not v.strip()):
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v > 0:
        return float(v)
    if isinstance(v, str) and v.strip():
        import datetime as dt
        try:
            t = dt.datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
        except ValueError:
            raise SettingError("bad_value", f"{where}.until: {v!r} is not a time (ISO 8601 or Unix seconds)")
        return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).timestamp()
    raise SettingError("bad_value", f"{where}.until: a time (ISO 8601 or Unix seconds), or none")


def _reason(v: dict, where: str) -> str:
    r = v.get("reason")
    if not isinstance(r, str) or not r.strip() or len(r) > 300:
        raise SettingError("bad_value", f"{where}.reason: say why (at most 300 characters)")
    return r.strip()


def _hold(v):
    """update_hold: {reason, until} (until: an expiry, or none), or none."""
    if v is None:
        return None
    if not isinstance(v, dict) or set(v) - {"reason", "until"}:
        raise SettingError("bad_value", "update_hold: {reason, until}, or none")
    return {"reason": _reason(v, "update_hold"), "until": _until(v.get("until"), "update_hold")}


VERSION = r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]{1,40})?$"


def _pin(v):
    """update_pin: {version, reason, until}, or none."""
    if v is None:
        return None
    if not isinstance(v, dict) or set(v) - {"version", "reason", "until"}:
        raise SettingError("bad_value", "update_pin: {version, reason, until}, or none")
    if not isinstance(v.get("version"), str) or not re.fullmatch(VERSION, v["version"].strip()):
        raise SettingError("bad_value", "update_pin.version: a release version such as 2.10.0")
    return {"version": v["version"].strip(), "reason": _reason(v, "update_pin"), "until": _until(v.get("until"), "update_pin")}


def _source(v):
    """update_source: an http(s) or file URL."""
    v = _check(REGISTRY["update_source"].schema, v, "update_source")
    if not re.fullmatch(r"(https?://[^\s/$.?#][^\s]*|file:///?[^\s]+)", v):
        raise SettingError("bad_value", f"update_source: {v!r} is not an http(s) or file URL")
    return v.rstrip("/")


def _listen(v):
    """console_listen: localhost, tailscale, all or IP addresses (consolelisten.normalize: localhost always first)."""
    from ..consolelisten import ListenError, normalize
    if not isinstance(v, list):
        raise SettingError("bad_type", f"console_listen: expected array, got {type(v).__name__} {v!r}"[:300])
    try:
        return normalize(v)
    except ListenError as e:
        raise SettingError("bad_value", f"console_listen: {e}")


def _https_or_none(v):
    """listener_probe_endpoint: an https:// URL, or none."""
    v = _check(REGISTRY["listener_probe_endpoint"].schema, v, "listener_probe_endpoint")
    if v is not None and not v.lower().startswith("https://"):
        raise SettingError("bad_value", f"listener_probe_endpoint: {v!r} is not an https:// URL")
    return v


SERVICE_NAME = r"^[a-z0-9][a-z0-9_.-]{0,63}$"
HOST = r"^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*(:[0-9]{1,5})?$"
NUM_GE0 = {"type": "number", "minimum": 0}
POS_NUM = {"type": "number", "exclusiveMinimum": 0}
POS_INT = {"type": "integer", "minimum": 1}

SECTIONS = {
    "memory": ("Memory", "What a job may use, and what stays free for the system and the person at the computer."),
    "presence": ("When someone is using it", "How the computer yields while a person is at it, or it runs on battery."),
    "jobs": ("Jobs", "How many jobs at once and how they run."),
    "caps": ("Caps", "Hard upper bounds the owner sets. A cap can only lower capacity: every scope's cap applies and the "
                     "lowest wins; a node's hardware bounds it anyway."),
    "notifications": ("Notifications", "Push notifications for alerts, through ntfy (self-hosted or ntfy.sh)."),
    "access": ("Access", "Where the console listens, and the host names the console and the admin API answer to besides "
                         "localhost (the remote mode)."),
    "verification": ("Data and verification", "How often finished work is re-run on another node to catch a wrong one."),
    "tools": ("Host tools", "Which installation of a host tool a node grants (docs/design/host-tools.md)."),
    "module": ("Running it", "Where the module runs, which of its services run, and how its work is split and checked."),
    "module_own": ("Its settings", "The settings the module declares in its manifest."),
    "protection": ("Protection", "How fleet work yields to the owner's own programs. Protected-process rules from every "
                                 "scope apply together; they are edited on the protection pages."),
    "storage": ("Module data", "What a module leaves on the node, and how long the node keeps it once the module is turned "
                              "off there (docs/protocol.md, \"Module cleanup\")."),
    "network": ("Network", "Inbound listeners and how they are checked from outside (docs/design/inbound-listeners.md)."),
    "updates": ("Updates", "How new Oarbank releases reach the coordinator and the nodes (docs/design/fleet-updates.md)."),
    "onboarding": ("New machines", "What a machine you approve starts as, until you change it (an approval's own choices "
                                   "win: docs/design/node-enrollment.md, \"Admission\")."),
}
NODE_SECTIONS = ("memory", "presence", "jobs", "caps", "storage", "protection", "network", "updates")
FLEET_SECTIONS = ("notifications", "access", "verification", "onboarding")
# the core keys every module has, set as `[module] <key>` (docs/design/settings.md, "Module settings")
MODULE_CORE_KEYS = ("enabled", "services.disabled", "pipeline", "replica_rate")

SETTINGS = (
    # ---------------------------------------------------------------- memory
    Setting("os_reserve_gb", "Memory kept for the system", "Never offered to jobs, whoever is using the computer.",
            NUM_GE0, default=4, computed=_os_reserve,
            computed_how="4 GB up to 32 GB of RAM, 8 GB from 96 GB, 6 GB between (6 GB when RAM is not reported)",
            unit="GB", wire="policy", section="memory", applies="both", tighten="higher", managed=True),
    Setting("user_reserve_gb", "Memory kept for the person using it", "Also kept free while someone is using the computer.",
            NUM_GE0, default=8, unit="GB", wire="policy", section="memory", applies="both", tighten="higher", managed=True),
    Setting("job_mem_gb", "Memory per job slot",
            "The memory one job slot stands for: the jobs it can take are its free memory divided by this.",
            POS_NUM, default=1.5, unit="GB", wire="policy", section="memory"),
    Setting("mem_in_use_bound", "Fit jobs into the memory free now",
            "On: jobs get at most what the computer has available now, less the memory guard's floor and 1 GB; off: only "
            "the two reserves above decide (the memory guard still stops new jobs at its floor).",
            {"type": "boolean"}, default=True, wire="policy", section="memory", tighten="higher", managed=True),
    # ---------------------------------------------------------------- presence
    Setting("user_present_slots", "Jobs while someone is using this computer",
            "The most jobs at once while someone is at it; 0 holds every new job back.",
            {"type": "integer", "minimum": 0}, default=2, unit="jobs", wire="policy", section="presence", tighten="lower",
            managed=True, campaign=True),
    Setting("user_idle_s", "Idle time before the computer counts as free",
            "Seconds without keyboard or mouse input before it runs at full capacity.",
            NUM_GE0, default=300, unit="s", wire="policy", section="presence", applies="both", tighten="higher", managed=True),
    Setting("screen_sharing_present", "Screen sharing counts as someone using it",
            "A connected Screen Sharing viewer holds jobs back like a person at the keyboard, even without input (macOS).",
            {"type": "boolean"}, default=True, wire="policy", section="presence", tighten="higher", managed=True),
    Setting("run_on_battery", "Run jobs on battery", "Off: a laptop on battery power takes no new jobs.",
            {"type": "boolean"}, default=False, wire="policy", section="presence", applies="both", tighten="lower",
            managed=True, campaign=True),
    # ---------------------------------------------------------------- jobs
    Setting("threads_per_job", "Threads per job",
            "Threads one job counts as against a CPU cores cap (the cap divided by this is the jobs it allows).",
            POS_INT, default=1, unit="threads", wire="policy", section="jobs"),
    Setting("max_slots", "CPU slots for jobs (cores)",
            "The node's CPU budget for jobs, in cores, whatever the hardware allows: each running job takes its stage's "
            "resources.cpu from it, so a stage needing more cpu than this never runs here; none: no bound. It is not a job "
            "count: to run one job at a time, set Concurrent jobs (jobs) to 1.",
            {"type": ["integer", "null"], "minimum": 0}, default=None, unit="slots", wire="policy", section="jobs",
            applies="both", tighten="lower", managed=True),
    Setting("nice", "Job priority (nice)", "0 normal to 20 lowest.",
            {"type": "integer", "minimum": 0, "maximum": 20}, default=10, wire="policy", section="jobs", advanced=True,
            note="Not applied by agents yet: protection lowers jobs when the owner's work needs it."),
    Setting("hard_limits", "Hard limits",
            "Jobs over their memory or CPU reservation are stopped where the OS enforces it (Linux cgroups, Windows Job "
            "Objects; macOS has none).", {"type": "boolean"}, default=False, wire="policy", section="jobs", advanced=True,
            tighten="higher", managed=True),
    Setting("workloads", "Run workloads",
            "Off: the node runs no module workloads (long-running daemons the owner assigned), and running ones stop.",
            {"type": "boolean"}, default=True, wire="policy", section="jobs", tighten="lower", managed=True),
    Setting("delegated_processes", "Delegated processes",
            "On: owner rules with `delegate` let host protection pause and lower the owner's named processes (by code "
            "signature or a trusted exact path) for a protected process. Never stopped.",
            {"type": "boolean"}, default=False, wire="policy", section="protection", danger="T2", tighten="lower",
            managed=True),
    Setting("services.disabled", "Services that do not run",
            "The module's services by name; a change re-checks and re-certifies the module on the nodes it reaches.",
            {"type": "array", "items": {"type": "string", "pattern": SERVICE_NAME}, "maxItems": 64}, default=[],
            section="module", advanced=True, applies="both", qualifier="required", effects=("redoctor",),
            examples=("scorer",)),
    # ---------------------------------------------------------------- caps (min: every scope's cap applies)
    Setting("cpu_cores", "CPU cores", "Caps concurrent jobs times their threads.", {"type": "number", "exclusiveMinimum": 0},
            unit="cores", wire="limits", section="caps", merge="min", danger="T0", hardware="cores", managed=True),
    Setting("mem_gb", "Memory", "For jobs and module services.", {"type": "number", "exclusiveMinimum": 0},
            unit="GB", wire="limits", section="caps", merge="min", danger="T0", hardware="ram", managed=True),
    Setting("jobs", "Concurrent jobs", "The most jobs running at once, whatever cpu each takes (1: one job at a time).", POS_INT, unit="jobs", wire="limits",
            section="caps", merge="min", danger="T0", applies="both", managed=True, campaign=True),
    Setting("schedule", "Schedule", "Work only inside this window (local time on the node); none: any time.",
            {"type": "object", "x-kind": "schedule"}, unit=None, wire="limits", section="caps", danger="T0"),
    Setting("enforce", "Cap enforcement",
            "soft: stop admitting and let running jobs finish; hard: also hand back the youngest jobs to fit.",
            {"type": "string", "enum": ["soft", "hard"]}, default="soft", wire="limits", section="caps", merge="max",
            order=("soft", "hard"), danger="T0", applies="both", managed=True),
    Setting("vm_mem_gb", "VM memory (services)", "A module VM service applies it at its next start.",
            {"type": "number", "exclusiveMinimum": 0}, unit="GB", wire="limits", section="caps", merge="min",
            danger="T0", advanced=True, hardware="ram", managed=True),
    Setting("vm_cpus", "VM CPUs (services)", "A module VM service applies it at its next start.", POS_INT,
            unit="cpus", wire="limits", section="caps", merge="min", danger="T0", advanced=True, hardware="cores", managed=True),
    Setting("disk_gb", "Disk cache", "The datasets cached on the node: above it, the least recently used ones no job here "
            "holds or waits for are deleted.", {"type": "number", "exclusiveMinimum": 0},
            unit="GB", wire="limits", section="caps", merge="min", danger="T0", advanced=True, managed=True),
    Setting("staging_mbps", "Download bandwidth", "Dataset staging.", {"type": "number", "exclusiveMinimum": 0},
            unit="Mbps", wire="limits", section="caps", merge="min", danger="T0", advanced=True, managed=True),
    # ---------------------------------------------------------------- module data on the node (the agent's cleanup)
    Setting("module_retention_days", "Keep a turned-off module's data",
            "Days the node keeps what a module left there (its data directory, cached datasets, container images) after "
            "the module is turned off on it; turning it back on in that time keeps everything. 0 deletes at once. A module "
            "no longer in the node's release goes after at most a day.",
            NUM_GE0, default=7, unit="days", wire="policy", section="storage"),
    # ---------------------------------------------------------------- protection (assembled into the agent's policy)
    Setting("protection.mode", "Protection mode",
            "fleet_first: static rules and guards only; moderate: an adaptive budget that protects the front app and "
            "the owner's busy programs; strict_yield: fleet work pauses at once on any protected activity.",
            {"type": "string", "enum": ["fleet_first", "moderate", "strict_yield"]}, default="moderate",
            section="protection", effects=("protection",)),
    Setting("protection.rules", "Protected-process rules",
            "Programs fleet work yields to, and how (reserve, cap, lower, pause, evict fleet work). Every scope's rules "
            "apply together: a rule only ever protects more.", {"type": "array", "x-kind": "protection_rules",
                                                                "maxItems": 64}, default=[], merge="union",
            lockable=False, effects=("protection",)),
    Setting("protection.node", "Protection tuning",
            "The memory guard, timing, GPU jobs and longest pause beside the mode (the node section of a protection "
            "config).", {"type": "object", "x-kind": "protection_node"}, default={}, advanced=True,
            effects=("protection",)),
    # ---------------------------------------------------------------- network (inbound listeners; the agent)
    Setting("inbound_listeners", "Inbound listeners",
            "Off: no module listener opens on this computer and every router mapping is removed (a machine's managed policy "
            "can forbid listeners).", {"type": "boolean"}, default=True, wire="policy", section="network", tighten="lower",
            managed=True),
    Setting("listener_port_range", "Internal listener ports",
            "The local ports listeners bind when their entry names no internal port (each listener gets the same port on "
            "every start while it is free).", {"type": "string", "pattern": r"^\d{4,5}-\d{4,5}$", "maxLength": 11},
            default="41000-41999", wire="policy", section="network", advanced=True,
            validator=lambda v: _port_range(v), examples=("41000-41999",)),
    Setting("listener_probe_endpoint", "Probe endpoint",
            "An https:// URL of an `oarbank-agent probe-endpoint` the owner runs on another network: it checks a listener "
            "from outside when no fleet node on another network can; none: no endpoint.",
            {"type": ["string", "null"], "format": "uri", "maxLength": 2048}, default=None, scopes=("fleet",),
            wire="policy", section="network", lockable=False, validator=lambda v: _https_or_none(v),
            examples=("https://probe.example.net:7480/",)),
    Setting("listener_stun_server", "STUN server",
            "host:port of a STUN server the agents ask for their public address every 30 minutes; none: no third party is "
            "ever contacted.", {"type": ["string", "null"], "pattern": r"^[A-Za-z0-9.-]+:[0-9]{1,5}$", "maxLength": 260},
            default=None, scopes=("fleet",), wire="policy", section="network", lockable=False,
            examples=("stun.example.net:3478",)),
    # ---------------------------------------------------------------- fleet-wide (the coordinator)
    Setting("ntfy.url", "Topic URL", "The ntfy topic alerts are pushed to; none: notifications off.",
            {"type": ["string", "null"], "format": "uri", "maxLength": 2048}, scopes=("fleet",), applies="coordinator",
            section="notifications", lockable=False, examples=("https://ntfy.sh/your-secret-topic",)),
    Setting("ntfy.click_base", "Click link", "Where a tapped notification opens (the console's address).",
            {"type": ["string", "null"], "format": "uri", "maxLength": 2048}, scopes=("fleet",), applies="coordinator",
            section="notifications", lockable=False, examples=("https://oarbank.example.ts.net",)),
    Setting("console_hosts", "Console host names",
            "Host names (an optional :port) the console and the admin API answer to besides localhost.",
            {"type": "array", "items": {"type": "string", "pattern": HOST, "maxLength": 260}, "maxItems": 32},
            default=[], scopes=("fleet",), applies="coordinator", section="access", lockable=False,
            examples=("oarbank.example.ts.net",)),
    Setting("console_listen", "Console listen addresses",
            "Where the console and its module frames listen: localhost (always), tailscale (this machine's Tailscale "
            "addresses, followed when they change), IP addresses of this machine, or all (every interface: anyone who can "
            "reach the machine reaches the sign-in page). The console rebinds within seconds; sign-in still applies.",
            {"type": "array", "items": {"type": "string", "maxLength": 64}, "maxItems": 16}, default=["localhost"],
            scopes=("fleet",), applies="coordinator", section="access", lockable=False, validator=lambda v: _listen(v),
            examples=("localhost", "tailscale", "100.64.0.1")),
    Setting("console_https", "Console over https (Tailscale)",
            "tailscale: this machine's tailscaled serves the console at https://<its MagicDNS name>/ and the module frames "
            "at port 8443 (tailscale serve, tailnet only, never Funnel), so passkeys work from other devices; off: no "
            "https name is set up by Oarbank. Needs MagicDNS and HTTPS certificates on in the tailnet.",
            {"type": "string", "enum": ["off", "tailscale"]}, default="off", scopes=("fleet",), applies="coordinator",
            section="access", lockable=False),
    Setting("replica_rate", "Replica rate",
            "The share of finished jobs re-run on another node and compared (0 to 1); a module's own rate can only raise "
            "the fleet's (the higher applies).",
            {"type": "number", "minimum": 0, "maximum": 1}, default=0.03, scopes=("fleet",), merge="max",
            applies="coordinator", section="verification", lockable=False, qualifier="optional", campaign=True),
    # ---------------------------------------------------------------- new machines (docs/design/node-enrollment.md, "Admission")
    Setting("new_node_state", "A new node starts",
            "active: a machine you approve takes work once its modules are certified; paused: it joins paused, takes no "
            "jobs (certification goldens included) and runs no workloads until you resume it. Applied when it is "
            "approved, in the same step; an approval may choose otherwise, and a re-enrolled node keeps its own state.",
            {"type": "string", "enum": ["active", "paused"]}, default="active", scopes=("fleet",), applies="coordinator",
            section="onboarding", lockable=False),
    Setting("new_node_modules", "Modules on a new node",
            "all: every module runs on a machine you approve (as the fleet and its groups say); none: the approval turns "
            "every installed module off on that node (its own value), so it is certified for nothing until you turn "
            "modules on. A module installed later is not turned off by this.",
            {"type": "string", "enum": ["all", "none"]}, default="all", scopes=("fleet",), applies="coordinator",
            section="onboarding", lockable=False),
    # ---------------------------------------------------------------- fleet updates (docs/design/fleet-updates.md, D60)
    Setting("update_auto", "Update automatically",
            "on: a newly imported signed release starts a rollout by itself (inside each node's window); notify: the "
            "coordinator says it is ready and the owner starts it; off: neither (it can still be started by hand).",
            {"type": "string", "enum": ["off", "notify", "on"]}, default="notify", applies="coordinator", section="updates",
            order=("on", "notify", "off"), tighten="higher", managed=True),
    Setting("update_ring", "Update ring",
            "Which ring of a rollout updates this node: canary first, then early, then broad.",
            {"type": "string", "enum": ["canary", "early", "broad"]}, default="broad", scopes=("group", "node"),
            applies="coordinator", section="updates"),
    Setting("update_window", "Update window",
            "Updates install only inside this window (local time on the node); none: any time.",
            {"type": ["object", "null"], "x-kind": "schedule"}, default=None, applies="coordinator", section="updates"),
    Setting("update_hold", "Update hold",
            "Held: the node takes no update until the hold is lifted or expires ({reason, until}).",
            {"type": ["object", "null"]}, default=None, scopes=("group", "node"), applies="coordinator",
            section="updates", tighten="higher", managed=True, lockable=False, writer="updates.hold",
            validator=lambda v: _hold(v)),
    Setting("update_pin", "Update pin",
            "The node stays on (or moves to) this release whatever rollouts do, until the pin is lifted or expires "
            "({version, reason, until}).", {"type": ["object", "null"]}, default=None, scopes=("node",),
            applies="coordinator", section="updates", lockable=False, writer="updates.pin", validator=lambda v: _pin(v)),
    Setting("update_source", "Release source",
            "Where `oarbank update fetch` and the periodic check download fleet releases from: a GitHub releases page, "
            "or any http(s) or file URL laid out the same way (<source>/download/v<version>/<asset>).",
            {"type": "string", "maxLength": 2048}, default="https://github.com/roeehrl/oarbank/releases", scopes=("fleet",),
            applies="coordinator", section="updates", lockable=False, validator=lambda v: _source(v),
            examples=("https://github.com/roeehrl/oarbank/releases",)),
    Setting("update_check_h", "Check for releases every",
            "Hours between checks of the release source for a newer release (0: never).",
            {"type": "number", "minimum": 0}, default=6, unit="h", scopes=("fleet",), applies="coordinator",
            section="updates", lockable=False),
    # ---------------------------------------------------------------- written by their own operations
    Setting("folder_registry", "Folders", "A folder id mapped to its access and a path on each node.", {"type": "object"},
            default={}, scopes=("fleet",), applies="coordinator", lockable=False, writer="settings.folders.update",
            danger="T2"),
    Setting("dataset_origins", "Dataset origins", "Host patterns dataset origins must match; none: any public https host.",
            {"type": "array", "items": {"type": "string", "pattern": HOST}}, default=[], scopes=("fleet",),
            applies="coordinator", lockable=False, writer="settings.origins.update", danger="T2"),
    # ---------------------------------------------------------------- every module's own core keys ([module] <key>)
    Setting("enabled", "Run this module",
            "Off: none of its work runs and its services stop, on the whole fleet or on the nodes this value reaches.",
            {"type": "boolean"}, default=True, applies="both", qualifier="required", section="module",
            effects=("module_enabled",)),
    Setting("pipeline", "Pipeline",
            "single: one job runs every stage; split: the module's stage chain (switching to split splits its queued jobs).",
            {"type": "string", "enum": ["single", "split"]}, default="single", scopes=("fleet",), applies="coordinator",
            qualifier="required", section="module", effects=("pipeline",), danger="T1"),
)

# Key families: one definition stands for every key its pattern matches (`tool.<id>.path`, one per host tool).
TOOL_PATH = re.compile(r"^tool\.([a-z][a-z0-9_.-]{0,63})\.path$")
# an absolute path (POSIX, or a Windows drive path), not a root, no globs, no `..` component
TOOL_PATH_VALUE = (r"^(?!.*(^|[/\\])\.\.([/\\]|$))(/[^*?\[\x00\n]*[^/*?\[\x00\n]|[A-Za-z]:\\[^*?\[\x00\n<>|\"]*"
                   r"[^\\*?\[\x00\n<>|\"])$")
FAMILIES = (
    (TOOL_PATH, Setting(
        "tool.<id>.path", "Host tool path",
        "Which installation of this host tool the node grants: an installation it found is chosen as it is; any other "
        "path goes into the node's signed statement and is verified on the node before it is granted.",
        {"type": "string", "pattern": TOOL_PATH_VALUE, "maxLength": 1024}, default=None, scopes=SCOPES,
        applies="both", lockable=False, qualifier="optional", effects=("statement",), section="tools", danger="T1",
        examples=("/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home",))),
)


class _Registry(dict):
    """The declared keys, and every key a family's pattern matches (made on demand)."""

    def get(self, key, default=None):
        if key in self:
            return dict.__getitem__(self, key)
        for pat, d in FAMILIES:
            m = pat.fullmatch(key or "")
            if m:
                import dataclasses
                return dataclasses.replace(d, key=key, label=f"Path of {m.group(1)}")
        return default

    def __missing__(self, key):
        d = self.get(key)
        if d is None:
            raise KeyError(key)
        return d


REGISTRY: dict[str, Setting] = _Registry({s.key: s for s in SETTINGS})


def lookup(key: str, extra: dict | None = None) -> Setting | None:
    """A core key or key family, else one of `extra` (a module's own keys, `module.<module>.<key>`: modkeys.py)."""
    d = REGISTRY.get(key)
    return d if d is not None or not extra else extra.get(key)


WIRE_POLICY = tuple(s.key for s in SETTINGS if s.wire == "policy")
WIRE_LIMITS = tuple(s.key for s in SETTINGS if s.wire == "limits")
NODE_KEYS = tuple(s.key for s in SETTINGS if s.section in NODE_SECTIONS)
assert all(s.merge in MERGES and s.danger in TIERS and set(s.scopes) <= set(SCOPES) for s in SETTINGS)


class SettingError(ValueError):
    def __init__(self, code: str, detail: str, key: str | None = None):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.key = code, detail, key


def get(key: str, extra: dict | None = None) -> Setting:
    d = lookup(key, extra)
    if d is None:
        raise SettingError("unknown_setting", f"no setting {key!r} (oarbank settings get lists them)", key)
    return d


# ------------------------------------------------------------------ values

_HHMM = re.compile(r"^([01]?[0-9]|2[0-4]):([0-5][0-9])(:[0-5][0-9])?$")


def _types(schema: dict) -> list:
    t = schema.get("type")
    return t if isinstance(t, list) else [t]


def _check(schema: dict, v, where: str):
    """The value normalized (an integral float of an integer setting becomes an int), or SettingError."""
    types = _types(schema)
    if v is None:
        if "null" in types:
            return None
        raise SettingError("bad_value", f"{where}: a value is required (reset it to inherit)")
    if schema.get("x-kind") == "schedule":
        return _schedule(v, where)
    if schema.get("x-kind") in ("protection_rules", "protection_node"):
        from ..protection import check_kind
        return check_kind(schema["x-kind"], v, where)
    if "boolean" in types and isinstance(v, bool):
        return v
    if ("integer" in types or "number" in types) and isinstance(v, (int, float)) and not isinstance(v, bool):
        if isinstance(v, float) and not math.isfinite(v):
            raise SettingError("bad_value", f"{where}: {v} is not a number")
        if "integer" in types and "number" not in types:
            if float(v) != int(v):
                raise SettingError("bad_value", f"{where}: {v} is not a whole number")
            v = int(v)
        elif isinstance(v, float) and v.is_integer() and "integer" not in types:
            v = int(v) if abs(v) < 2 ** 53 else v
        if "minimum" in schema and v < schema["minimum"]:
            raise SettingError("bad_value", f"{where}: {v} is below {schema['minimum']}")
        if "exclusiveMinimum" in schema and v <= schema["exclusiveMinimum"]:
            raise SettingError("bad_value", f"{where}: {v} must be more than {schema['exclusiveMinimum']}")
        if "maximum" in schema and v > schema["maximum"]:
            raise SettingError("bad_value", f"{where}: {v} is above {schema['maximum']}")
        return v
    if "string" in types and isinstance(v, str):
        v = v.strip()
        if "enum" in schema and v not in schema["enum"]:
            raise SettingError("bad_value", f"{where}: {v!r} is not one of {', '.join(schema['enum'])}")
        if len(v) > schema.get("maxLength", 10_000):
            raise SettingError("bad_value", f"{where}: longer than {schema['maxLength']} characters")
        if schema.get("format") == "uri":
            if not v:
                if "null" in types:
                    return None
                raise SettingError("bad_value", f"{where}: a URL is required")
            if not re.fullmatch(r"https?://[^\s/$.?#][^\s]*", v):
                raise SettingError("bad_value", f"{where}: {v!r} is not an http(s) URL")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], v):
            raise SettingError("bad_value", f"{where}: {v!r} does not have the expected form")
        return v
    if "array" in types and isinstance(v, list):
        if len(v) > schema.get("maxItems", 10_000):
            raise SettingError("bad_value", f"{where}: more than {schema['maxItems']} entries")
        items = schema.get("items") or {}
        out = []
        for i, x in enumerate(v):
            if isinstance(x, str) and items.get("pattern") == HOST:
                x = x.strip().lower()                          # host names are case-insensitive
            x = _check(items, x, f"{where}[{i}]") if items else x
            if x not in out:
                out.append(x)
        return out
    if "object" in types and isinstance(v, dict):
        return v
    want = " or ".join(t for t in types if t != "null")
    raise SettingError("bad_type", f"{where}: expected {want}, got {type(v).__name__} {v!r}"[:300])


def _schedule(v, where: str) -> dict:
    if not isinstance(v, dict):
        raise SettingError("bad_type", f"{where}: expected {{start, end, days}}")
    extra = set(v) - {"start", "end", "days"}
    if extra:
        raise SettingError("bad_value", f"{where}: unknown fields {sorted(extra)}")
    out = {}
    for k in ("start", "end"):
        s = v.get(k)
        m = _HHMM.fullmatch(s.strip()) if isinstance(s, str) else None
        if not m or (m.group(1) == "24" and m.group(2) != "00"):
            raise SettingError("bad_value", f"{where}.{k}: a time as HH:MM")
        out[k] = f"{int(m.group(1)):02d}:{m.group(2)}"
    days = v.get("days")
    if days is not None:
        if not isinstance(days, list) or not all(isinstance(d, int) and not isinstance(d, bool) and 0 <= d <= 6 for d in days):
            raise SettingError("bad_value", f"{where}.days: weekdays 0 (Monday) to 6 (Sunday)")
        out["days"] = sorted(set(days))
    return out


def check(key: str, v, d: Setting | None = None):
    """A value for `key` (its definition `d` when it is a module's own key), normalized, or SettingError naming what is
    wrong."""
    d = d or get(key)
    return d.validator(v) if d.validator else _check(d.schema, v, key)


def default(d: Setting, facts: dict | None) -> tuple:
    """(value, reason): the computed default with why, else the static one (reason None)."""
    import copy
    if d.computed is not None:
        return d.computed(facts or {})
    return copy.deepcopy(d.default), None


def same(a, b) -> bool:
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) and not isinstance(b, bool):
        return float(a) == float(b)
    return a == b


def _strictness(d: Setting, v):
    """A value's place on the key's scale, loosest lowest (a "lower" key: smaller is stricter; none, an unset cap or no
    bound, is the loosest of all)."""
    if v is None:
        return float("-inf")
    if isinstance(v, dict):
        x = 1                                    # a key whose value is an object or none (a hold): set is stricter
    elif d.order:
        x = d.order.index(v) if v in d.order else -1
    elif isinstance(v, bool):
        x = int(v)
    elif isinstance(v, (int, float)):
        x = float(v)
    else:
        return None
    return -x if d.tighten_dir == "lower" else x


def tighter(d: Setting, a, b):
    """The stricter of two values of a safety key (`a` when they are as strict, or the key has no direction)."""
    if d.tighten_dir is None:
        return a
    sa, sb = _strictness(d, a), _strictness(d, b)
    if sa is None or sb is None:
        return a
    return b if sb > sa else a


def loosens(d: Setting, new, base) -> bool:
    """Whether `new` is looser than `base` for a safety key (always False for a preference)."""
    if d.tighten_dir is None:
        return False
    sn, sb = _strictness(d, new), _strictness(d, base)
    return sn is not None and sb is not None and sn < sb


def tighten_text(d: Setting) -> str:
    """The stricter direction in words: "lower", "higher", "off", "on", or a choice ("hard")."""
    if d.order:
        return d.order[-1] if d.tighten_dir == "higher" else d.order[0]
    if "boolean" in _types(d.schema):
        return "on" if d.tighten_dir == "higher" else "off"
    return d.tighten_dir or ""


# ------------------------------------------------------------------ how values read

def _num(v) -> str:
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return f"{v:g}" if isinstance(v, float) else str(v)


DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def show(key: str, v, d: Setting | None = None) -> str:
    """A value as a person reads it (`d`: the definition of a module's own key)."""
    d = d or REGISTRY.get(key)
    t = _types(d.schema) if d else []
    if "boolean" in t:
        return "on" if v else "off"
    if v is None or v == [] or v == {}:
        return "none"
    if d and d.schema.get("x-kind") == "protection_rules" and isinstance(v, list):
        return ", ".join(str(r.get("id")) for r in v if isinstance(r, dict))
    if d and d.schema.get("x-kind") == "schedule" and isinstance(v, dict):
        days = v.get("days")
        when = "every day" if not days or len(days) == 7 else ", ".join(DAYS[i] for i in days)
        return f"{v.get('start')}–{v.get('end')} {when}"
    if isinstance(v, list):
        return ", ".join(map(str, v))
    if isinstance(v, dict):
        import json
        return json.dumps(v, sort_keys=True)
    return f"{_num(v)} {d.unit}" if d and d.unit and isinstance(v, (int, float)) else _num(v)


# ------------------------------------------------------------------ friction

def _up(t: str) -> str:
    return TIERS[min(TIERS.index(t) + 1, 3)]


def _listens_everywhere(v) -> bool:
    from ..consolelisten import ALL
    return isinstance(v, list) and any(isinstance(x, str) and x.strip().lower() == ALL for x in v)


def change_tier(changes) -> str:
    """A change set's tier from each key's danger tier and its scope (admin-console.md, tiers): a node change keeps the
    key's tier, a fleet or group change is one tier up, a lock is T3. Unknown keys count as T1 (apply refuses them)."""
    tier = "T0"
    for c in changes or []:
        d = REGISTRY.get((c or {}).get("key") or "")
        t = d.danger if d else "T1"
        if (c or {}).get("scope", "node") in ("fleet", "group"):
            t = _up(t)
        if (c or {}).get("enforce"):
            t = "T3"
        if (c or {}).get("key") == "console_listen" and _listens_everywhere((c or {}).get("value")):
            t = "T3"                              # every interface: confirmed by typing the key's name
        tier = max(tier, t, key=TIERS.index)
    return tier


def schema_doc(module_keys: dict | None = None) -> list[dict]:
    """GET /api/v1/settings/schema: every definition as data (a key family once, by its pattern's name; each module's
    own keys from `module_keys`)."""
    out = []
    for d in (*SETTINGS, *(f for _, f in FAMILIES), *(module_keys or {}).values()):
        dv, why = default(d, None)
        out.append({"key": d.key, "label": d.label, "help": d.help, "unit": d.unit, "schema": d.schema,
                    "default": dv if d.computed is None else None, "computed_default": d.computed_how,
                    "agent_default": d.default if d.wire else None,
                    "scopes": list(d.scopes), "merge": d.merge, "lockable": d.lockable, "advanced": d.advanced,
                    "danger": d.danger, "applies": d.applies, "wire": d.wire, "section": d.section,
                    "qualifier": d.qualifier, "writer": d.writer, "effects": list(d.effects), "note": d.note,
                    "hardware": d.hardware, "examples": list(d.examples), "required": d.required,
                    "campaign": d.campaign, "tighten": d.tighten_dir if (d.campaign or d.managed or d.tighten) else None,
                    "managed": d.managed})
    return out
