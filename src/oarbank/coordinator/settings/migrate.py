"""The one-shot conversion to the settings model (docs/design/settings.md, "Migration"), run when the coordinator opens
a home made by an earlier version. Oarbank is not in production, so there are no shims: the old stores are converted
once and deleted.

- Every installed module's own keys are registered first (modkeys.register_all), so module values convert key by key
  against the schema the module declares.
- The `settings` table splits: owner keys become fleet values (`setting_values`), every other key is machine state and
  moves to `system_state`. The ntfy token moves into the secrets store (write-only). `default_worker_disabled_services`
  becomes each module's fleet `services.disabled` (`relay/scorer` is `[relay] services.disabled = [scorer]`, `*/x` the
  modules that have a service x; the built-in coordinator-host group still runs every service), the tool registry
  becomes host tool definitions (tools.convert_registry), `pipeline:<m>` becomes `[m] pipeline`, and
  `module_settings:<m>` becomes one fleet value per key of `m`'s settings schema; `dataset_groups` (no owner control,
  nothing reads it but a retired endpoint) is dropped.
- `nodes.policy_json` and `nodes.limits_json` go: for each node, a value becomes a node value only where it differs from
  what the node now inherits (the computed default, the fleet, its groups), so copies of defaults disappear; caps become
  node values; each module's node settings become one node value per key, and its disabled services `[m]
  services.disabled`, by the same rule; the protection sections are hoisted onto the chain (protection.hoist: what
  every node has in common goes to the fleet, the rest stays per node; their versions stay in `protection_versions`).
- `module_channels.disabled` (the kill switch) becomes `[m] enabled = false` for the fleet, and the column goes.
- A home made by a 2.9 build before module settings (one `module.settings` object per module, one `module.node_settings`
  per module and node, `disabled_services` lists) converts the same way, and those rows go.
- Values the registry refuses (an undeclared key, a value its schema does not accept, a fleet-only key set on a node)
  are dropped and named in the `settings_migrated` event."""
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


LEGACY_KEYS = ("module.settings", "module.node_settings", "disabled_services")


def needed(conn) -> bool:
    return (_has_table(conn, "settings") or "policy_json" in _cols(conn, "nodes") or "disabled" in _cols(conn, "module_channels")
            or conn.execute(f"SELECT 1 FROM setting_values WHERE key IN ({','.join('?' * len(LEGACY_KEYS))}) LIMIT 1",
                            LEGACY_KEYS).fetchone() is not None
            or conn.execute("SELECT 1 FROM modules WHERE name NOT IN (SELECT module FROM module_setting_keys) LIMIT 1")
            .fetchone() is not None)


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
        for m, names in _services_by_module(db, v or [], report, "default_worker_disabled_services").items():
            fleet("services.disabled", names, m)
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
        _module_values(db, key.split(":", 1)[1], v, "fleet", "", rev, report)
        return True
    if key == "dataset_groups":
        if v:
            report["dropped"].append("dataset_groups: no owner control and no reader")
        return True
    return False


def _services(db, module: str) -> set:
    """The services a module's newest installed version declares."""
    from .. import modstore
    rows = modstore.installed(db, module)
    return {x.get("name") for x in ((rows[-1]["manifest"] or {}).get("services") or [])} if rows else set()


def _services_by_module(db, entries, report: dict, where: str) -> dict:
    """An old `disabled_services` list (module/service, */service) as {module: [service, ...]} over the installed modules;
    a `*/x` entry names every module that has a service x, an entry no installed module has is dropped."""
    from . import modkeys
    out: dict = {}
    names = modkeys.module_names(db)
    for e in entries if isinstance(entries, list) else []:
        m, _, svc = str(e).partition("/")
        targets = [x for x in names if svc in _services(db, x)] if m == "*" else ([m] if m in names else [])
        if not svc or not targets:
            report["dropped"].append(f"{where}: {e} (no installed module has that service)")
            continue
        for t in targets:
            if svc not in out.setdefault(t, []):
                out[t].append(svc)
    return out


def _module_values(db, module: str, values, scope: str, scope_id: str, rev: int, report: dict, node: dict | None = None,
                   snap=None, where: str = "") -> None:
    """A module's old settings object as one value per key of its settings schema: undeclared keys, values its schema
    refuses and fleet-only keys set on a node are dropped and named; a value equal to what the scope inherits (the
    default; on a node, its fleet's and groups' value) is a copy, not a choice, and is not kept."""
    from . import modkeys
    if not values:
        return
    where = where or ("fleet" if scope == "fleet" else (node or {}).get("hostname") or scope_id)
    if not isinstance(values, dict):
        report["dropped"].append(f"{where}: {module}'s settings: not an object")
        return
    keys = {k.name: k for k in modkeys.declared(db, module)}
    for name, v in values.items():
        k = keys.get(name)
        if k is None:
            report["dropped"].append(f"{where}: {module}.{name} (not a setting {module} declares)")
            continue
        if scope != "fleet" and k.scope == "fleet":
            report["dropped"].append(f"{where}: {module}.{name} (set for the whole fleet only)")
            continue
        d = modkeys.definition(module, k)
        try:
            v = d.validator(v)
        except R.SettingError as e:
            report["dropped"].append(f"{where}: {module}.{name} ({e.detail})")
            continue
        key = modkeys.key_of(module, name)
        inherited = V.resolve(snap, node, key, module)["value"] if node is not None else (k.default if k.has_default else None)
        if (node is not None or k.has_default) and _eq(v, inherited):
            continue                                     # a copy of what it inherits: not a choice
        store.put(db, scope, scope_id, module, key, v, ACTOR, rev, COMMENT)
        report.setdefault(scope, []).append(f"{where if scope == 'node' else ''}{': ' if scope == 'node' else ''}{key}")


def _node_services(db, n: dict, entries, snap, rev: int, report: dict) -> None:
    """A node's old disabled_services list as `[m] services.disabled` node values where they differ from what the node
    inherits for that module (the fleet's value, the coordinator-host group's)."""
    from . import modkeys
    mine = _services_by_module(db, entries, report, n["hostname"])
    for m in modkeys.module_names(db):
        want = mine.get(m, [])
        if _eq(want, V.resolve(snap, n, "services.disabled", m)["value"]):
            continue
        store.put(db, "node", n["node_id"], m, "services.disabled", want, ACTOR, rev, COMMENT)
        report["node"].append(f"{n['hostname']}: services.disabled [{m}]")


def _legacy_rows(db, rev: int, report: dict) -> None:
    """Rows a 2.9 build made before module settings: one object per module (`module.settings`, `module.node_settings`)
    and `disabled_services` lists, converted key by key, then deleted."""
    legacy = [x for x in store.rows(db) if x["key"] in LEGACY_KEYS]
    for x in legacy:
        store.delete(db, x["scope"], x["scope_id"], x["module"], x["key"])
    snap = V.snapshot(db)
    nodes = {n["node_id"]: n for n in db.q("SELECT * FROM nodes WHERE lifecycle!='retired'")}
    for x in sorted(legacy, key=lambda x: (x["scope"] != "fleet", x["scope"], x["scope_id"])):
        node = nodes.get(x["scope_id"]) if x["scope"] == "node" else None
        if x["scope"] == "node" and node is None:
            continue
        if x["key"] == "disabled_services":
            for m, names in _services_by_module(db, x["value"], report, x["scope_id"] or x["scope"]).items():
                if x["scope"] == "node" or names:
                    store.put(db, x["scope"], x["scope_id"], m, "services.disabled", names, ACTOR, rev, COMMENT)
                    report.setdefault(x["scope"], []).append(f"services.disabled [{m}]")
        elif x["module"]:
            _module_values(db, x["module"], x["value"], x["scope"], x["scope_id"], rev, report, node=node, snap=snap)


def run(db) -> dict | None:
    """Convert a home made by an earlier version (inside one transaction); None when there is nothing to convert."""
    conn = db.conn
    if not needed(conn):
        return None
    from . import modkeys
    report = {"fleet": [], "node": [], "system": 0, "dropped": [], "secrets": [], "protection": 0, "modules": []}
    with db.tx():
        rev = store.next_rev(db)
        # each installed module's own keys first: its old values convert against the schema it declares
        report["modules"] = [f"{x['module']} {x['version']}: {len(x['keys'])} settings" for x in
                             modkeys.register_all(db, ACTOR, sync=False)]
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
        if "disabled" in _cols(conn, "module_channels"):    # the kill switch becomes the fleet's [module] enabled
            for r in conn.execute("SELECT name FROM module_channels WHERE disabled=1").fetchall():
                store.put(db, "fleet", "", r[0], "enabled", False, ACTOR, rev, COMMENT)
                report["fleet"].append(f"enabled [{r[0]}]")
            conn.execute("ALTER TABLE module_channels DROP COLUMN disabled")
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
                    _module_values(db, m, ms, "node", n["node_id"], rev, report, node=n, snap=snap)
                if "disabled_services" in pol:
                    _node_services(db, n, pol["disabled_services"], snap, rev, report)
                for k, v in pol.items():
                    if k in ("protection", "module_settings", "disabled_services"):
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
        _legacy_rows(db, rev, report)
        from .apply import sync_nodes
        sync_nodes(db, rev_=rev)
        db.event("settings_migrated", reason=f"{len(report['fleet'])} fleet values, {len(report['node'])} node values, "
                                             f"{report['system']} system keys, {len(report['dropped'])} dropped",
                 **report)
    return report
