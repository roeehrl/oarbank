"""Node protection config schema 1 (PLAN D3, D3a-d, D20; docs/design/protection.md).

Owner-set only: a module can never declare or loosen protection. The central copy is the node policy's
"protection" section (edited in the console); the local copy is protection.json beside the agent's home on the
node. The agent unions both and the most restrictive setting wins on every dimension, so the two never conflict.

The action vocabulary contains only fleet-side verbs. There is no field that could name a protected
process as a target (S16 made structural).
"""
import re
import tomllib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA = 1
Mode = Literal["fleet_first", "moderate", "strict_yield"]
DEFAULT_MODE: Mode = "moderate"                 # D3a: a new node's mode until the owner sets one
Metric = Literal["cpu_stall", "ipc_ratio", "gpu_share", "pageins_rate", "progress_rate"]
Scope = Literal["all", "cpu", "gpu", "io"]
# reservation expressions: a number, or peak(<N>s).<metric> [* k] [+ c]
EXPR_RE = re.compile(r"^\s*(\d+(\.\d+)?|peak\(\d+s\)\.(cpu|footprint)(\s*\*\s*\d+(\.\d+)?)?(\s*\+\s*\d+(\.\d+)?)?)\s*$")
Pos = Annotated[float, Field(gt=0)]
NonNeg = Annotated[float, Field(ge=0)]


class _M(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)


# ------------------------------------------------------------------------------------------ node section

class MemoryGuard(_M):
    # Calibrated on 6,946 recorded node samples: 20/10 % stopped admission on a node in 34 % of samples without any
    # memory pressure.
    soft_free_pct: Annotated[float, Field(gt=0, lt=100)] = 12
    hard_free_pct: Annotated[float, Field(gt=0, lt=100)] = 8
    swap_growth_soft_mb_min: NonNeg = 256
    swap_growth_hard_mb_min: NonNeg = 1024
    min_reclaim_gb: NonNeg = 2

    @model_validator(mode="after")
    def _order(self):
        if self.hard_free_pct >= self.soft_free_pct:
            raise ValueError("memory.hard_free_pct must be below soft_free_pct")
        return self


class OwnerStall(_M):
    max: Annotated[float, Field(gt=0, lt=1)] = 0.15


class Implicit(_M):
    frontmost_app: bool = True
    owner_stall: OwnerStall | None = Field(default_factory=OwnerStall)


class Cooldown(_M):
    base_s: Pos = 120
    backoff: Annotated[float, Field(ge=1)] = 2.0
    max_s: Pos = 3840
    window_s: Pos = 3600


class Timing(_M):
    enter_for_s: NonNeg = 4
    exit_after_s: NonNeg = 60
    cooldown: Cooldown = Field(default_factory=Cooldown)


class NodeSection(_M):
    mode: Mode = DEFAULT_MODE
    pause: bool = Field(False, description="Local brake: no fleet work at all (local file only needs no coordinator).")
    gpu_jobs: Literal["never", "when_no_gpu_protected", "always"] = "when_no_gpu_protected"
    duty_cycle: bool = Field(False, description="D3d: SIGSTOP/SIGCONT time-slicing rung, off by default.")
    memory: MemoryGuard = Field(default_factory=MemoryGuard)
    implicit: Implicit = Field(default_factory=Implicit, description="moderate/strict_yield only.")
    defaults: Timing = Field(default_factory=Timing)
    private_signals: bool = Field(True, description="D3c: feature-detected private sources; they can only restrict.")


# ------------------------------------------------------------------------------------------ rules

class Match(_M):
    """Strongest first: a code-signing requirement or team id survives updates and relocation."""
    requirement: str | None = Field(None, description="Code-signing requirement string (SecCodeCheckValidity).")
    team_id: str | None = Field(None, pattern=r"^[A-Z0-9]{10}$")
    identifier: str | None = None
    bundle_id: str | list[str] | None = None
    path_prefix: str | None = None
    path_contains: str | None = None
    argv_regex: str | None = None
    name: str | None = Field(None, max_length=16, description="p_comm (weakest; truncated at 16 characters).")

    @model_validator(mode="after")
    def _some(self):
        if not any(v for v in self.model_dump().values()):
            raise ValueError("match needs at least one key")
        if self.argv_regex:
            re.compile(self.argv_regex)
        return self


class GpuActive(_M):
    min_busy: Annotated[float, Field(gt=0, le=1)] = Field(
        0.05, description="GPU busy seconds per second of the group's processes, summed over the GPU's engines, over "
                          "the last sample interval. Usage that cannot be read counts as busy.")


class ActiveWhen(_M):
    """Any one trigger that holds activates the rule, after for_s."""
    frontmost: bool | None = None
    cpu_cores_gt: NonNeg | None = None
    footprint_gb_gt: NonNeg | None = None
    gpu_active: GpuActive | None = None
    for_s: NonNeg | None = None


class Reserve(_M):
    cpu: float | str | None = None
    mem_gb: float | str | None = None

    @field_validator("cpu", "mem_gb")
    @classmethod
    def _expr(cls, v):
        if isinstance(v, str) and not EXPR_RE.match(v):
            raise ValueError(f"reservation {v!r}: use a number or peak(<N>s).cpu|footprint [* k] [+ c]")
        return v


class CapFleet(_M):
    slots: Annotated[int, Field(ge=0)] | None = None
    cpu_cores: NonNeg | None = None
    threads: Annotated[int, Field(ge=1)] | None = None
    staging_mbps: NonNeg | None = None
    gpu_jobs: Annotated[int, Field(ge=0)] | None = None
    pools: dict[str, Annotated[int, Field(ge=0)]] = Field(
        default_factory=dict, description="With slots = 0: only jobs reserving these pools may start, up to the tokens.")


class LowerFleet(_M):
    to: Literal["e_cores"] = "e_cores"


class PauseFleet(_M):
    scope: Scope = "all"


class Evict(_M):
    scope: Scope = "all"


class Source(_M):
    jsonl: str | None = None
    event: str | None = None
    enter: str | None = None
    exit: str | None = None
    log_regex: str | None = None
    exec: list[str] | None = Field(None, min_length=1, description="Owner-written probe printing a number (never from a module).")


class Protect(_M):
    metric: Metric
    max: NonNeg | None = None
    max_slowdown: Annotated[float, Field(gt=0, lt=1)] | None = None
    window_s: Pos = 20
    source: Source | None = None

    @model_validator(mode="after")
    def _target(self):
        if (self.max is None) == (self.max_slowdown is None):
            raise ValueError("protect needs exactly one of max / max_slowdown")
        if self.metric == "progress_rate" and not self.source:
            raise ValueError("protect.metric = progress_rate needs a source")
        return self


class Actions(_M):
    reserve: Reserve | None = None
    cap_fleet: CapFleet | None = None
    lower_fleet: LowerFleet | None = None
    pause_fleet: PauseFleet | None = None
    protect: Protect | None = None
    evict: Evict | None = None

    def any(self) -> bool:
        return any(getattr(self, k) is not None for k in ACTION_KEYS)


ACTION_KEYS = ("reserve", "cap_fleet", "lower_fleet", "pause_fleet", "protect", "evict")


class During(Actions):
    """Phase-scoped extra actions while an owner-supplied source says a phase is on."""
    source: Source


class Rule(Actions):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$", max_length=64)
    match: Match
    tree: Literal["self", "descendants", "same_team"] = "self"
    active_when: Literal["present"] | ActiveWhen = "present"
    ignore: bool = Field(False, description="Only removes the processes from heuristic triggers; memory still counts.")
    enter_for_s: NonNeg | None = None
    exit_after_s: NonNeg | None = None
    during: list[During] = Field(default_factory=list)

    @model_validator(mode="after")
    def _actions(self):
        if self.ignore and (self.any() or self.during):
            raise ValueError(f"rule {self.id}: ignore cannot be combined with actions")
        if not self.ignore and not (self.any() or self.during):
            raise ValueError(f"rule {self.id}: needs at least one action (or ignore = true)")
        if self.tree == "same_team" and not (self.match.team_id or self.match.requirement):
            raise ValueError(f"rule {self.id}: tree = same_team needs a team_id or requirement matcher")
        return self


class ProtectionConfig(_M):
    schema_: Literal[1] = Field(1, alias="schema")
    node: NodeSection = Field(default_factory=NodeSection)
    rules: list[Rule] = Field(default_factory=list, alias="rule")

    @model_validator(mode="after")
    def _unique(self):
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return self


def load(path: str | Path) -> ProtectionConfig:
    return ProtectionConfig.model_validate(tomllib.loads(Path(path).read_text()))
