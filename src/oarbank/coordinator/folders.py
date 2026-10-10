"""Folder grants (oarbank-sdk spec/sandbox.md, "Folders"; docs/design/datasets-media-checkpoints.md): read-only input
folders and write-only outboxes on nodes, which a module version asks for by id and an operator maps per node.

- **The registry** (setting `folder_registry`): `{id: {"access": "read"|"write", "nodes": {node_id: path}}}`, edited by
  `settings.folders.update`. A module's request and the registry's access must be equal for the folder to be granted.
- **Statements.** Releases are per platform and paths per node, so each node's mapping travels in its signed node
  statement (`oarbank.node/v1`, statements.py), with the tool paths added for it; in signing mode the owner signs it
  (`oarbank node sign <node>`) before the node applies it.
- **The node decides what it accepts** (canonical paths, no roots, homes, data roots, system directories or overlaps)
  and reports each folder of the statement it applied, with its access, `ok` or why not, in its heartbeats; a job of a
  module that needs a folder the node does not provide with that access waits with FOLDER_UNAVAILABLE.
"""
import re

from oarbank_sdk import portable

from .db import DB, jl

REGISTRY = "folder_registry"
FOLDER_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_WIN_ABS = re.compile(r"^[A-Za-z]:\\[^*?\"<>|]*$")


class FolderError(ValueError):
    pass


def registry(db: DB) -> dict:
    return db.get_setting(REGISTRY, {}) or {}


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
