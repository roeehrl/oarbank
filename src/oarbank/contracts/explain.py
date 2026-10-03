"""The explain document (PLAN D16; admin-console.md "One explain document answers every why").

GET /api/v1/explain/{kind}/{id} returns one of these; the GUI renders it as HTML and
`oarbank explain` as text or --json. Claim and explain share one pure predicate function,
`evaluate(job, node_view) -> list[PredicateResult]`; a property test asserts they agree.
"""
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Kind = Literal["job", "attempt", "node", "campaign", "module", "release", "alert", "protection"]
Outcome = Literal["pass", "fail", "unknown"]


class _M(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class PredicateResult(_M):
    """One predicate evaluated for one (job, node): the unit claim() and explain() share."""
    predicate: str = Field(description="Stable predicate name with its argument, e.g. pool(docker_amd64) >= 1.")
    code: str = Field(description="Reason code reported when the predicate fails.")
    outcome: Outcome
    observed: Any = None
    required: Any = None
    layer: Literal["admission", "placement", "ordering"]


class Subject(_M):
    kind: Kind
    id: str | int


class AsOf(_M):
    snapshot_version: int
    evaluated_at: float
    stale: bool = False


class Headline(_M):
    code: str
    text: str


class SummaryRow(_M):
    code: str
    nodes: list[str] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)
    evidence: list[int] = Field(default_factory=list, description="Event ids.")


class Clause(_M):
    predicate: str
    matched: int
    of: int


class MatrixRow(_M):
    node: str
    results: list[PredicateResult]


class Remedy(_M):
    op: str = Field(description="Operation id from the registry.")
    params: dict[str, Any] = Field(default_factory=dict)
    label: str


class Evidence(_M):
    event_id: int
    kind: str


class ExplainDocument(_M):
    explain: Literal[1] = 1
    subject: Subject
    as_of: AsOf
    verdict: str = Field(description="Kind-specific state word, e.g. pending, running, admitting, blocked.")
    headline: Headline
    summary: list[SummaryRow] = Field(default_factory=list, description="Aggregated first: each distinct reason with the nodes it covers.")
    clauses: list[Clause] = Field(default_factory=list)
    matrix: list[MatrixRow] = Field(default_factory=list, description="Every node x every predicate (complete, not first-fail).")
    next_trigger: str | None = None
    system_actions: list[str] = Field(default_factory=list)
    remedies: list[Remedy] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    journal: list[dict[str, Any]] = Field(default_factory=list, description="protection/attempt kinds: the decision records involved.")
