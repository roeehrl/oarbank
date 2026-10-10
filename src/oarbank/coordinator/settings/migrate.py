"""The one-shot conversion to the settings model (docs/design/settings.md, "Migration"), run when the coordinator opens
a home made by an earlier version. Oarbank is not in production, so there are no shims: the old stores are converted
once and deleted.

- The `settings` table splits: owner keys become fleet values (`setting_values`), every other key is machine state and
  moves to `system_state`. The ntfy token moves into the secrets store (write-only). `default_worker_disabled_services`
  becomes the fleet's `disabled_services` (the built-in coordinator-host group still runs every service), the tool
  registry becomes host tool definitions (tools.convert_registry), `pipeline:<m>`
  and `module_settings:<m>` become that module's fleet values; `dataset_groups` (no owner control, nothing reads it but
  a retired endpoint) is dropped.
- `nodes.policy_json` and `nodes.limits_json` go: for each node, a value becomes a node value only where it differs from
  what the node now inherits (the computed default, the fleet, its groups), so copies of defaults disappear; caps become
  node values; the protection sections are hoisted onto the chain (protection.hoist: what every node has in common
  goes to the fleet, the rest stays per node; their versions stay in `protection_versions`).
- Values the registry refuses are dropped and named in the `settings_migrated` event."""
import json

from . import registry as R
from . import resolve as V
from . import store

ACTOR = "migration"
COMMENT = "migrated from the per-node policy and the settings table"


def _has_table(conn, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _cols(conn, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def needed(conn) -> bool:
    return _has_table(conn, "settings") or "policy_json" in _cols(conn, "nodes")


def _eq(a, b) -> bool:
    if isinstance(a, list) and isinstance(b, list):
        return sorted(map(json.dumps, a)) == sorted(map(json.dumps, b))
    return R.same(a, b)


def _owner(db, key: str, v, rev: int, report: dict) -> bool:
    """Convert one owner key of the old settings table; False: not an owner key (machine state)."""
    def fleet(k, val, module=""):
        try:
            val = R.check(k, val)
        except R.SettingError as e:
            report["dropped"].append(f"{key}: {e.detail}")
            return
        if _eq(val, R.default(R.get(k), None)[0]):
            return
        store.put(db, "fleet", "", module, k, val, ACTOR, rev, COMMENT)
        report["fleet"].append(f"{k}" + (f" [{module}]" if module else ""))

    if key == "ntfy":
        v = v or {}
        if v.get("url"):
            fleet("ntfy.url", v["url"])
        if v.get("click_base"):
            fleet("ntfy.click_base", v["click_base"])
        if v.get("token"):
            from .. import modsecrets
            try:
                modsecrets.core_set(db, "ntfy_token", str(v["token"]), ACTOR)
                report["secrets"].append("ntfy_token")
            except Exception as e:                       # noqa: BLE001 (no secret store here: say so, keep going)
                report["dropped"].append(f"ntfy token: the secret store refused it ({type(e).__name__})")
        return True
    if key == "console_hosts":
        fleet("console_hosts", [v] if isinstance(v, str) else v)
        return True
    if key == "replica_rate":
        fleet("replica_rate", v)
        return True
    if key == "default_worker_disabled_services":
        if v:
            fleet("disabled_services", v)
        return True
    if key == "tool_registry":                       # host tools: definitions with fleet search paths per OS
        from ..tools import convert_registry
        report["fleet"] += [f"tool {t}" for t in convert_registry(db, v or {})]
        return True
    if key == "folder_registry":
        fleet("folder_registry", v or {})
        return True
    if key == "dataset_origins":
        fleet("dataset_origins", list((v or {}).get("hosts") or []) if isinstance(v, dict) else v)
        return True
    if key.startswith("pipeline:"):
        fleet("pipeline", v, key.split(":", 1)[1])
        return True
    if key.startswith("module_settings:"):
        if v:
            fleet("module.settings", v, key.split(":", 1)[1])
        return True
    if key == "dataset_groups":
        if v:
            report["dropped"].append("dataset_groups: no owner control and no reader")
        return True
    return False


def run(db) -> dict | None:
    """Convert a home made by an earlier version (inside one transaction); None when there is nothing to convert."""
    conn = db.conn
    if not needed(conn):
        return None
    report = {"fleet": [], "node": [], "system": 0, "dropped": [], "secrets": [], "protection": 0}
    with db.tx():
        rev = store.next_rev(db)
        if _has_table(conn, "settings"):
            for r in conn.execute("SELECT key, value_json FROM settings").fetchall():
                key, raw = r[0], r[1]
                try:
                    v = json.loads(raw) if raw is not None else None
                except ValueError:
                    report["dropped"].append(f"{key}: not JSON")
                    continue
                if not _owner(db, key, v, rev, report):
                    conn.execute("INSERT OR REPLACE INTO system_state(key, value_json) VALUES(?,?)", (key, raw))
                    report["system"] += 1
            conn.execute("DROP TABLE settings")
        cols = _cols(conn, "nodes")
        if "policy_json" in cols:
            snap = V.snapshot(db)
            prot = {}
            for n in db.q("SELECT * FROM nodes"):
                if n["lifecycle"] == "retired":
                    continue
                pol = json.loads(n.get("policy_json") or "{}") or {}
                lim = json.loads(n.get("limits_json") or "{}") or {}
                if isinstance(pol.get("protection"), dict):
                    prot[n["node_id"]] = pol["protection"]
                    report["protection"] += 1
                for m, ms in (pol.get("module_settings") or {}).items():
                    if ms:
                        store.put(db, "node", n["node_id"], m, "module.node_settings", ms, ACTOR, rev, COMMENT)
                        report["node"].append(f"{n['hostname']}: module.node_settings [{m}]")
                for k, v in pol.items():
                    if k in ("protection", "module_settings"):
                        continue
                    d = R.REGISTRY.get(k)
                    if d is None or "node" not in d.scopes:
                        report["dropped"].append(f"{n['hostname']}: {k} (no such setting)")
                        continue
                    if _eq(v, V.resolve(snap, n, k)["value"]):
                        continue                         # a copy of what it inherits: not a choice
                    try:
                        v = R.check(k, v)
                    except R.SettingError as e:
                        report["dropped"].append(f"{n['hostname']}: {e.detail}")
                        continue
                    store.put(db, "node", n["node_id"], "", k, v, ACTOR, rev, COMMENT)
                    report["node"].append(f"{n['hostname']}: {k}")
                caps = [k for k in R.WIRE_LIMITS if k != "enforce" and lim.get(k) not in (None, "")]
                for k in caps + (["enforce"] if caps and lim.get("enforce") == "hard" else []):
                    try:
                        v = R.check(k, lim[k])
                    except R.SettingError as e:
                        report["dropped"].append(f"{n['hostname']}: {e.detail}")
                        continue
                    store.put(db, "node", n["node_id"], "", k, v, ACTOR, rev, COMMENT)
                    report["node"].append(f"{n['hostname']}: {k}")
            from .. import protection                    # common to every node: the fleet's; the rest per node
            hoisted = protection.hoist(db, prot, rev, ACTOR)
            report["fleet"] += hoisted["fleet"]
            report["node"] += hoisted["node"]
            report["dropped"] += hoisted["dropped"]
            conn.execute("ALTER TABLE nodes DROP COLUMN policy_json")
            conn.execute("ALTER TABLE nodes DROP COLUMN limits_json")
        from .apply import sync_nodes
        sync_nodes(db, rev_=rev)
        db.event("settings_migrated", reason=f"{len(report['fleet'])} fleet values, {len(report['node'])} node values, "
                                             f"{report['system']} system keys, {len(report['dropped'])} dropped",
                 **report)
    return report
