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
    note: str | None = None           # beside the row (for example: not applied by agents yet)
    examples: tuple = field(default=())
    required: bool = False            # a module's own key the owner must set (readiness, SETTINGS_NOT_SET)
    validator: Callable[[Any], Any] | None = None   # the value normalized, or SettingError (a module's own key: its
                                                    # property's whole JSON Schema); None: the `schema` subset below

    @property
    def nullable(self) -> bool:
        t = self.schema.get("type")
        return isinstance(t, list) and "null" in t


def _os_reserve(facts: dict) -> tuple:
    ram = float((facts or {}).get("memory_gb") or 0)
    if not ram:
        return 6, "RAM not reported"
    return (4 if ram <= 32 else (8 if ram >= 96 else 6)), f"{ram:g} GB RAM"


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
    "access": ("Access", "Host names the console and the admin API answer to besides localhost (the remote mode)."),
    "verification": ("Data and verification", "How often finished work is re-run on another node to catch a wrong one."),
    "tools": ("Host tools", "Which installation of a host tool a node grants (docs/design/host-tools.md)."),
    "module": ("Running it", "Where the module runs, which of its services run, and how its work is split and checked."),
    "module_own": ("Its settings", "The settings the module declares in its manifest."),
    "protection": ("Protection", "How fleet work yields to the owner's own programs. Protected-process rules from every "
                                 "scope apply together; they are edited on the protection pages."),
}
NODE_SECTIONS = ("memory", "presence", "jobs", "caps", "protection")
FLEET_SECTIONS = ("notifications", "access", "verification")
# the core keys every module has, set as `[module] <key>` (docs/design/settings.md, "Module settings")
MODULE_CORE_KEYS = ("enabled", "services.disabled", "pipeline", "replica_rate")

SETTINGS = (
    # ---------------------------------------------------------------- memory
    Setting("os_reserve_gb", "Memory kept for the system", "Never offered to jobs, whoever is using the computer.",
            NUM_GE0, default=4, computed=_os_reserve,
            computed_how="4 GB up to 32 GB of RAM, 8 GB from 96 GB, 6 GB between (6 GB when RAM is not reported)",
            unit="GB", wire="policy", section="memory", applies="both"),
    Setting("user_reserve_gb", "Memory kept for the person using it", "Also kept free while someone is using the computer.",
            NUM_GE0, default=8, unit="GB", wire="policy", section="memory", applies="both"),
    Setting("job_mem_gb", "Memory per job slot",
            "The memory one job slot stands for: the jobs it can take are its free memory divided by this.",
            POS_NUM, default=1.5, unit="GB", wire="policy", section="memory"),
    Setting("mem_in_use_bound", "Fit jobs into the memory free now",
            "On: jobs get at most what the computer has available now, less the memory guard's floor and 1 GB; off: only "
            "the two reserves above decide (the memory guard still stops new jobs at its floor).",
            {"type": "boolean"}, default=True, wire="policy", section="memory"),
    # ---------------------------------------------------------------- presence
    Setting("user_present_slots", "Jobs while someone is using this computer",
            "The most jobs at once while someone is at it; 0 holds every new job back.",
            {"type": "integer", "minimum": 0}, default=2, unit="jobs", wire="policy", section="presence"),
    Setting("user_idle_s", "Idle time before the computer counts as free",
            "Seconds without keyboard or mouse input before it runs at full capacity.",
            NUM_GE0, default=300, unit="s", wire="policy", section="presence", applies="both"),
    Setting("screen_sharing_present", "Screen sharing counts as someone using it",
            "A remote Screen Sharing session holds jobs back like a person at the keyboard, even without input (macOS).",
            {"type": "boolean"}, default=True, wire="policy", section="presence"),
    Setting("run_on_battery", "Run jobs on battery", "Off: a laptop on battery power takes no new jobs.",
            {"type": "boolean"}, default=False, wire="policy", section="presence", applies="both"),
    # ---------------------------------------------------------------- jobs
    Setting("threads_per_job", "Threads per job",
            "Threads one job counts as against a CPU cores cap (the cap divided by this is the jobs it allows).",
            POS_INT, default=1, unit="threads", wire="policy", section="jobs"),
    Setting("max_slots", "Most jobs at once", "An upper bound on job slots whatever the hardware allows; none: no bound.",
            {"type": ["integer", "null"], "minimum": 0}, default=None, unit="slots", wire="policy", section="jobs",
            applies="both"),
    Setting("nice", "Job priority (nice)", "0 normal to 20 lowest.",
            {"type": "integer", "minimum": 0, "maximum": 20}, default=10, wire="policy", section="jobs", advanced=True,
            note="Not applied by agents yet: protection lowers jobs when the owner's work needs it."),
    Setting("hard_limits", "Hard limits",
            "Jobs over their memory or CPU reservation are stopped where the OS enforces it (Linux cgroups, Windows Job "
            "Objects; macOS has none).", {"type": "boolean"}, default=False, wire="policy", section="jobs", advanced=True),
    Setting("services.disabled", "Services that do not run",
            "The module's services by name; a change re-checks and re-certifies the module on the nodes it reaches.",
            {"type": "array", "items": {"type": "string", "pattern": SERVICE_NAME}, "maxItems": 64}, default=[],
            section="module", advanced=True, applies="both", qualifier="required", effects=("redoctor",),
            examples=("scorer",)),
    # ---------------------------------------------------------------- caps (min: every scope's cap applies)
    Setting("cpu_cores", "CPU cores", "Caps concurrent jobs times their threads.", {"type": "number", "exclusiveMinimum": 0},
            unit="cores", wire="limits", section="caps", merge="min", danger="T0", hardware="cores"),
    Setting("mem_gb", "Memory", "For jobs and module services.", {"type": "number", "exclusiveMinimum": 0},
            unit="GB", wire="limits", section="caps", merge="min", danger="T0", hardware="ram"),
    Setting("jobs", "Concurrent jobs", "The most jobs running at once.", POS_INT, unit="jobs", wire="limits",
            section="caps", merge="min", danger="T0", applies="both"),
    Setting("schedule", "Schedule", "Work only inside this window (local time on the node); none: any time.",
            {"type": "object", "x-kind": "schedule"}, unit=None, wire="limits", section="caps", danger="T0"),
    Setting("enforce", "Cap enforcement",
            "soft: stop admitting and let running jobs finish; hard: also hand back the youngest jobs to fit.",
            {"type": "string", "enum": ["soft", "hard"]}, default="soft", wire="limits", section="caps", merge="max",
            order=("soft", "hard"), danger="T0", applies="both"),
    Setting("vm_mem_gb", "VM memory (services)", "A module VM service applies it at its next start.",
            {"type": "number", "exclusiveMinimum": 0}, unit="GB", wire="limits", section="caps", merge="min",
            danger="T0", advanced=True, hardware="ram"),
    Setting("vm_cpus", "VM CPUs (services)", "A module VM service applies it at its next start.", POS_INT,
            unit="cpus", wire="limits", section="caps", merge="min", danger="T0", advanced=True, hardware="cores"),
    Setting("disk_gb", "Disk cache", "Dataset and image cache on the node.", {"type": "number", "exclusiveMinimum": 0},
            unit="GB", wire="limits", section="caps", merge="min", danger="T0", advanced=True),
    Setting("staging_mbps", "Download bandwidth", "Dataset staging.", {"type": "number", "exclusiveMinimum": 0},
            unit="Mbps", wire="limits", section="caps", merge="min", danger="T0", advanced=True),
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
    Setting("replica_rate", "Replica rate",
            "The share of finished jobs re-run on another node and compared (0 to 1); a module's own rate can only raise "
            "the fleet's (the higher applies).",
            {"type": "number", "minimum": 0, "maximum": 1}, default=0.03, scopes=("fleet",), merge="max",
            applies="coordinator", section="verification", lockable=False, qualifier="optional"),
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
                    "hardware": d.hardware, "examples": list(d.examples), "required": d.required})
    return out
