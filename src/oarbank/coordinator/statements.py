"""The per-node signed statement (`oarbank.node/v1`; docs/design/host-tools.md, "Node statements"): every node-scope
value that grants access on one node, which the owner signs in signing mode before the node applies it.

Releases are per platform; paths are per node. So each node gets its own statement: canonical JSON
`{"type": "oarbank.node/v1", "fleet_id", "node_id", "seq", "folders": {id: {access, path}}, "tools": [{id, module,
path}], "signed_at"}`, rebuilt with a rising seq whenever its content changes, and sent in directives with its signature.

- `folders`: the folder registry's mapping on this node (folders.py).
- `tools`: the tool paths added for this node that its detector did not find itself (tools.py, kind `add`); the agent
  applies its refusals (no roots, homes, data roots, system directories) and verifies each with the tool's detector
  before granting it. Choosing among installations the node found needs no signature and is not here.

In signing mode (docs/release-signing.md) the agent applies a statement only with a valid signature by the release key
and a seq above the last it accepted (`oarbank node sign <node>`, operation `nodes.sign_statement`); until then it keeps
the last one it applied.
"""
import json
import time

from . import identity
from .db import DB

TYPE = "oarbank.node/v1"
KEY = "node_statements"                    # {node_id: {"seq", "statement", "signature"}}
SIGNED_FIELDS = {"type", "node_id", "seq", "folders", "tools"}


class StatementError(ValueError):
    pass


def content(db: DB, node_id: str) -> dict:
    from . import folders, tools
    return {"folders": folders.mapping_for(db, node_id), "tools": tools.statement_tools(db, node_id)}


def statements(db) -> dict:
    return db.get_setting(KEY, {}) or {}


def statement(db, node_id: str) -> dict | None:
    return statements(db).get(node_id)


def refresh(db: DB, node_ids=None) -> list[str]:
    """Rebuild the statement of every node whose content changed (a rising seq, no signature yet); returns their ids."""
    sts = statements(db)
    changed = []
    nodes = node_ids if node_ids is not None else [r["node_id"] for r in db.q("SELECT node_id FROM nodes WHERE lifecycle!='retired'")]
    for nid in nodes:
        want = content(db, nid)
        cur = sts.get(nid)
        if cur:
            have = json.loads(cur["statement"])
            if have.get("type") == TYPE and {k: have.get(k) for k in want} == want:
                continue
        elif not want["folders"] and not want["tools"]:
            continue
        seq = (cur or {}).get("seq", 0) + 1
        stmt = json.dumps({"type": TYPE, "fleet_id": identity.fleet_id(db), "node_id": nid, "seq": seq, **want,
                           "signed_at": int(time.time())}, sort_keys=True, separators=(",", ":"))
        sts[nid] = {"seq": seq, "statement": stmt, "signature": None}
        changed.append(nid)
    if changed:
        db.set_setting(KEY, sts)
    return changed


def sign(db: DB, node_id: str, stmt: str, signature: str) -> dict:
    """Attach the owner's signature to a node's current statement (verified against the release key)."""
    from .. import signing
    cur = statement(db, node_id)
    if not cur or cur["statement"] != stmt:
        raise StatementError(f"that is not {node_id}'s current statement (it changed: sign it again)")
    key = db.get_setting("release_pubkey")
    if not key:
        raise StatementError("no release key is pinned (oarbank owner set): nothing can verify the signature")
    try:
        signing._verify_fields(stmt, signature, key, "node", SIGNED_FIELDS)
    except ValueError as e:
        raise StatementError(str(e)) from None
    sts = statements(db)
    sts[node_id] = {**cur, "signature": signature}
    db.set_setting(KEY, sts)
    return {"node_id": node_id, "seq": cur["seq"]}


def directive(db, node_id: str) -> dict | None:
    """The `statement` directive: the node's statement and its signature (None: no statement)."""
    cur = statement(db, node_id)
    return {"statement": cur["statement"], "signature": cur["signature"]} if cur else None


def migrate(conn) -> None:
    """One-shot at upgrade: the folder statements become node statements (rebuilt as `oarbank.node/v1` with the next
    seq at startup, `refresh`)."""
    row = conn.execute("SELECT value_json FROM settings WHERE key='folder_statements'").fetchone()
    if row is None:
        return
    if not conn.execute("SELECT 1 FROM settings WHERE key=?", (KEY,)).fetchone():
        conn.execute("INSERT INTO settings(key, value_json) VALUES(?, ?)", (KEY, row[0]))
    conn.execute("DELETE FROM settings WHERE key='folder_statements'")
