"""Folder grants (oarbank-sdk spec/sandbox.md, "Folders"; docs/design/datasets-media-checkpoints.md): read-only input
folders and write-only outboxes on nodes, which a module version asks for by id and an operator maps per node.

- **The registry** (setting `folder_registry`): `{id: {"access": "read"|"write", "nodes": {node_id: path}}}`, edited by
  `settings.folders.update`. A module's request and the registry's access must be equal for the folder to be granted.
- **Statements.** Releases are per platform and paths per node, so each node gets its own folder statement: canonical
  JSON `{"type": "oarbank.folders/v1", "fleet_id", "node_id", "seq", "folders": {id: {access, path}}, "signed_at"}`,
  rebuilt with a rising seq whenever the node's mapping changes, and sent in directives with its signature. In signing
  mode (docs/release-signing.md) the agent applies a statement only with a valid signature by the release key and a seq
  above the last it accepted (`oarbank folders sign <node>`, operation `folders.sign`); until then it keeps the last one.
- **The node decides what it accepts** (canonical paths, no roots, homes, data roots, system directories or overlaps)
  and reports each folder of the statement it applied, with its access, `ok` or why not, in its heartbeats; a job of a
  module that needs a folder the node does not provide with that access waits with FOLDER_UNAVAILABLE.
"""
import json
import re
import time

from oarbank_sdk import portable

from . import identity
from .db import DB, jl

REGISTRY = "folder_registry"
STATEMENTS = "folder_statements"          # {node_id: {"seq", "statement", "signature"}}
FOLDER_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
STATEMENT_TYPE = "oarbank.folders/v1"
_WIN_ABS = re.compile(r"^[A-Za-z]:\\[^*?\"<>|]*$")


class FolderError(ValueError):
    pass


def registry(db: DB) -> dict:
    from .settings import fleet_value
    return fleet_value(db, REGISTRY) or {}


def check_path(path: str, os_: str | None) -> str:
    """A node path as the registry keeps it: absolute for the node's OS, not a root, no globs or `..`. What the node
    accepts is decided on the node (canonical path, homes, data roots, system directories)."""
    p = (path or "").strip()
    win = os_ == "windows" or (os_ is None and _WIN_ABS.fullmatch(p) is not None)
    ok = _WIN_ABS.fullmatch(p) if win else p.startswith("/") and "\x00" not in p and "\n" not in p
    if not ok or any(c in p for c in "*?[") or p.rstrip("/\\") in ("", "/") or re.fullmatch(r"[A-Za-z]:\\?", p):
        raise FolderError(f"{p!r} is not an absolute path to a directory for {os_ or 'the node'} (no globs, not a root)")
    if "/../" in p.replace("\\", "/") + "/" or p.replace("\\", "/").endswith("/.."):
        raise FolderError(f"{p!r} contains '..'")
    return p.rstrip("/\\") if len(p) > 3 else p


def check_entry(db: DB, folder_id: str, entry: dict) -> dict:
    """A registry entry, normalized: {"access", "nodes": {node_id: path}}; a node set to null or "" is removed."""
    if not FOLDER_ID.fullmatch(folder_id or ""):
        raise FolderError(f"folder id {folder_id!r}: lower-case letters, digits, '_', '.', '-'")
    access = entry.get("access")
    if access not in ("read", "write"):
        raise FolderError("access: read (an input folder) or write (an outbox)")
    cur = (registry(db).get(folder_id) or {}).get("nodes") or {}
    nodes = dict(cur)
    for nid, path in (entry.get("nodes") or {}).items():
        node = db.one("SELECT node_id, platform FROM nodes WHERE node_id=?", (nid,))
        if not node:
            raise FolderError(f"unknown node {nid!r}")
        if not path:
            nodes.pop(nid, None)
            continue
        os_ = portable.split_platform(node["platform"])[0] if node["platform"] else None
        nodes[nid] = check_path(path, os_)
    return {"access": access, "nodes": dict(sorted(nodes.items()))}


def mapping_for(db: DB, node_id: str) -> dict:
    """{id: {access, path}}: what the registry maps on one node."""
    return {fid: {"access": e["access"], "path": e["nodes"][node_id]}
            for fid, e in sorted(registry(db).items()) if node_id in (e.get("nodes") or {})}


def statements(db: DB) -> dict:
    return db.get_state(STATEMENTS, {}) or {}


def statement(db: DB, node_id: str) -> dict | None:
    return statements(db).get(node_id)


def refresh(db: DB, node_ids=None) -> list[str]:
    """Rebuild the statement of every node whose mapping changed (a rising seq, no signature yet); returns their ids."""
    sts = statements(db)
    changed = []
    nodes = node_ids if node_ids is not None else [r["node_id"] for r in db.q("SELECT node_id FROM nodes WHERE lifecycle!='retired'")]
    for nid in nodes:
        want = mapping_for(db, nid)
        cur = sts.get(nid)
        if cur and json.loads(cur["statement"])["folders"] == want:
            continue
        if not cur and not want:
            continue
        seq = (cur or {}).get("seq", 0) + 1
        stmt = json.dumps({"type": STATEMENT_TYPE, "fleet_id": identity.fleet_id(db), "node_id": nid, "seq": seq,
                           "folders": want, "signed_at": int(time.time())}, sort_keys=True, separators=(",", ":"))
        sts[nid] = {"seq": seq, "statement": stmt, "signature": None}
        changed.append(nid)
    if changed:
        db.set_state(STATEMENTS, sts)
    return changed


def sign(db: DB, node_id: str, stmt: str, signature: str) -> dict:
    """Attach the owner's signature to a node's current statement (verified against the release key)."""
    from .. import signing
    cur = statement(db, node_id)
    if not cur or cur["statement"] != stmt:
        raise FolderError(f"that is not {node_id}'s current folder statement (it changed: sign it again)")
    key = db.get_state("release_pubkey")
    if not key:
        raise FolderError("no release key is pinned (oarbank owner set): nothing can verify the signature")
    try:
        signing._verify_fields(stmt, signature, key, "folder", {"type", "node_id", "seq", "folders"})
    except ValueError as e:
        raise FolderError(str(e)) from None
    sts = statements(db)
    sts[node_id] = {**cur, "signature": signature}
    db.set_state(STATEMENTS, sts)
    return {"node_id": node_id, "seq": cur["seq"]}


def directive(db: DB, node_id: str) -> dict | None:
    """The `folders` directive: the node's statement and its signature (None: no statement)."""
    cur = statement(db, node_id)
    return {"statement": cur["statement"], "signature": cur["signature"]} if cur else None


def report(node: dict) -> dict:
    """{id: {"access", "status": "ok" | why not}}: the folders of the statement the node applied, as its latest heartbeat
    reported them (what it enforces, signed or not, may lag the registry until the owner signs a new statement)."""
    return jl(node.get("folders_json"), {}) or {}


def missing(manifest, node: dict) -> list[str]:
    """The folders a module version asks for that the node does not provide with that access: not in the statement it
    applied, another access there, or not `ok` on the node."""
    rep = report(node)
    return [f.id for f in manifest.sandbox.folders
            if (rep.get(f.id) or {}).get("access") != f.access or (rep.get(f.id) or {}).get("status") != "ok"]
