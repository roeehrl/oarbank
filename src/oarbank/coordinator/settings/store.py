"""The settings store (docs/design/settings.md): one sparse table of values, node groups, and the change revision.

- `setting_values` holds only what an owner set, at one scope (fleet, a group, a node), optionally for one module. A
  missing row means inherit; Reset deletes the row and never writes a default as a value, so a later upstream change
  still flows down and "overridden here" stays truthful. `enforced` is a lock (fleet and group only): lower scopes may
  not set the key while it holds.
- `node_groups` are named selectors over node facts and labels, with explicit members and a unique rank: a node in
  several groups resolves by rank, highest wins. Built-in groups (one per OS and the coordinator's own machine) have
  system-defined membership and the lowest ranks; owner groups rank above them (groups.py). `node_labels` holds the
  owner's labels on each node.
- Every save is one change set with one revision (`system_state.settings_rev`), shared by its rows; a node's effective
  settings carry the revision at which they last changed (apply.sync_nodes)."""
import json
import time

from . import registry as R

SCHEMA = """
CREATE TABLE IF NOT EXISTS system_state (key TEXT PRIMARY KEY, value_json TEXT);
CREATE TABLE IF NOT EXISTS setting_values (
  scope      TEXT NOT NULL CHECK (scope IN ('fleet','group','node','campaign')),
  scope_id   TEXT NOT NULL DEFAULT '',     -- group id, node id, campaign id; '' for fleet
  module     TEXT NOT NULL DEFAULT '',     -- '' = a core key; else the module of a module's own key
  key        TEXT NOT NULL,
  value_json TEXT NOT NULL,                -- absence of a row = inherit; never NULL-as-value
  enforced   INTEGER NOT NULL DEFAULT 0,   -- lock: lower scopes may not set it (fleet and group only)
  rev        INTEGER NOT NULL,             -- the change set's revision, shared by one save
  comment TEXT, updated_by TEXT NOT NULL, updated_at REAL NOT NULL,
  PRIMARY KEY (scope, scope_id, module, key));
CREATE INDEX IF NOT EXISTS setting_values_key ON setting_values(key, module);
CREATE TABLE IF NOT EXISTS node_groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, rank INTEGER UNIQUE NOT NULL,
  selector_json TEXT NOT NULL, builtin INTEGER NOT NULL DEFAULT 0,
  members_json TEXT NOT NULL DEFAULT '[]',  -- explicit members (node ids), beside the selector (groups.py)
  description TEXT, updated_by TEXT, updated_at REAL);
CREATE TABLE IF NOT EXISTS node_labels (node_id TEXT NOT NULL, label TEXT NOT NULL, set_by TEXT, set_at REAL,
  PRIMARY KEY (node_id, label));
"""
# columns added to node_groups after it first shipped (db.ADDED_COLUMNS)
GROUP_COLUMNS = {"members_json": "TEXT NOT NULL DEFAULT '[]'", "description": "TEXT", "updated_by": "TEXT",
                 "updated_at": "REAL"}

# id, name, rank, selector: the built-in groups (the coordinator's own machine above the OS groups)
BUILTIN_GROUPS = (("os-darwin", "macOS", 1, {"os": "darwin"}),
                  ("os-linux", "Linux", 2, {"os": "linux"}),
                  ("os-windows", "Windows", 3, {"os": "windows"}),
                  ("coordinator-host", "Coordinator host", 4, {"coordinator_host": True}))
# values a built-in group sets by itself (shown with their reason; a node may still override them)
BUILTIN_VALUES = {"coordinator-host": {"services.disabled": ([], "the coordinator's own machine runs every service")}}
OWNER_RANK_MIN = 100            # owner groups rank above every built-in group


def ensure(conn) -> None:
    """Create the built-in groups (inside the schema transaction)."""
    for gid, name, rank, sel in BUILTIN_GROUPS:
        conn.execute("INSERT OR IGNORE INTO node_groups(id,name,rank,selector_json,builtin) VALUES(?,?,?,?,1)",
                     (gid, name, rank, json.dumps(sel)))


def groups(r) -> list[dict]:
    """Every group, lowest rank first: {id, name, rank, selector, members, description, builtin, updated_by, updated_at}."""
    out = r.q("SELECT id, name, rank, selector_json, builtin, members_json, description, updated_by, updated_at "
              "FROM node_groups ORDER BY rank")
    for g in out:
        g["selector"] = json.loads(g.pop("selector_json") or "{}")
        g["members"] = json.loads(g.pop("members_json") or "[]")
    return out


def labels(r) -> dict:
    """{node_id: [owner labels]}."""
    out: dict = {}
    for x in r.q("SELECT node_id, label FROM node_labels ORDER BY label"):
        out.setdefault(x["node_id"], []).append(x["label"])
    return out


def rows(r, key: str | None = None) -> list[dict]:
    sql = "SELECT * FROM setting_values" + (" WHERE key=?" if key else "")
    out = r.q(sql, (key,) if key else ())
    for x in out:
        x["value"] = json.loads(x.pop("value_json"))
    return out


def row(r, scope: str, scope_id: str, module: str, key: str) -> dict | None:
    out = r.q("SELECT * FROM setting_values WHERE scope=? AND scope_id=? AND module=? AND key=?", (scope, scope_id, module, key))
    if not out:
        return None
    x = out[0]
    x["value"] = json.loads(x.pop("value_json"))
    return x


def rev(r) -> int:
    out = r.q("SELECT value_json FROM system_state WHERE key='settings_rev'")
    return int(json.loads(out[0]["value_json"])) if out else 0


def next_rev(db) -> int:
    """A new change-set revision (inside the caller's transaction)."""
    n = rev(db) + 1
    db.set_state("settings_rev", n)
    return n


def put(db, scope: str, scope_id: str, module: str, key: str, value, actor: str, rev_: int, comment: str | None = None,
        enforced: bool = False) -> None:
    db.x("INSERT INTO setting_values(scope,scope_id,module,key,value_json,enforced,rev,comment,updated_by,updated_at) "
         "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(scope,scope_id,module,key) DO UPDATE SET value_json=excluded.value_json, "
         "enforced=excluded.enforced, rev=excluded.rev, comment=excluded.comment, updated_by=excluded.updated_by, "
         "updated_at=excluded.updated_at",
         (scope, scope_id, module, key, json.dumps(value), int(bool(enforced)), rev_, comment, actor, time.time()))


def delete(db, scope: str, scope_id: str, module: str, key: str) -> bool:
    before = row(db, scope, scope_id, module, key)
    if before:
        db.x("DELETE FROM setting_values WHERE scope=? AND scope_id=? AND module=? AND key=?", (scope, scope_id, module, key))
    return before is not None


# ------------------------------------------------------------------ fleet values (the coordinator's own reads)

def fleet_value(r, key: str, module: str = ""):
    """A fleet-scope key's value: the fleet's row, else the registry default. For keys the coordinator itself applies
    (notifications, console hosts, replica rate, registries, a module's pipeline and settings)."""
    d = R.get(key)
    x = r.q("SELECT value_json FROM setting_values WHERE scope='fleet' AND scope_id='' AND module=? AND key=?", (module, key))
    if x:
        return json.loads(x[0]["value_json"])
    return R.default(d, None)[0]


def write_fleet(db, key: str, value, actor: str, module: str = "", comment: str | None = None) -> int:
    """A fleet value written by the operation that owns the key (R.Setting.writer: the tool and folder registries, dataset
    origins, a module's pipeline; a module's own settings through its effects). The value is checked against the
    registry; the registry default (an empty registry, single) deletes the row. Returns the change set's revision."""
    d = R.get(key)
    value = R.check(key, value)
    n = next_rev(db)
    if R.same(value, R.default(d, None)[0]):
        delete(db, "fleet", "", module, key)
    else:
        put(db, "fleet", "", module, key, value, actor, n, comment)
    return n
