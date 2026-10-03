"""Audit records and the hash chain (PLAN D13; admin-console.md "The audit log is hash-chained").

Each row: hash = sha256(prev_hash || canonical_json(row without hash)). Rows are written in the same
transaction as the mutation, by the single writer, and never pruned. Hourly digests
{last_event_id, hash, ts, prev_digest_sig} are signed with an Ed25519 key kept in the secret store and
copied off the host; `oarbank audit verify` recomputes the chain against them (coordinator/audit.py).
"""
import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

GENESIS = "0" * 64


class AuditRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    event_id: int
    ts: float
    actor: str = Field(pattern=r"^([A-Za-z0-9._%+@-]+|node:[A-Za-z0-9_-]+|module:[a-z0-9.-]+|system:[a-z_]+)$",
                       description="A Tailscale login, node:<id>, module:<id> or system:<component>.")
    source: Literal["gui", "cli", "api", "system", "scheduler"]
    user_agent: str | None = None
    request_id: str = Field(description="ULID, returned as X-Request-Id and shown in GUI toasts.")
    idempotency_key: str | None = None
    operation: str = Field(description="Operation id from the registry.")
    category: Literal["create", "modify", "remove", "access"]
    target_type: str
    target_id: str
    dry_run: bool = False
    plan_id: str | None = None
    before: Any = None
    after: Any = None
    patch: list[dict[str, Any]] | None = Field(None, description="RFC 6902 patch, instead of before/after for large documents.")
    reason: str | None = None
    outcome: Literal["ok", "rejected", "conflict", "denied", "error"]
    error: str | None = None
    parent_event_id: int | None = Field(None, description="Bulk operations: the parent record.")
    prev_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    hash: str = Field(pattern=r"^[0-9a-f]{64}$")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def row_hash(prev_hash: str, fields: dict) -> str:
    body = {k: v for k, v in fields.items() if k != "hash"}
    return hashlib.sha256(prev_hash.encode() + canonical(body)).hexdigest()
