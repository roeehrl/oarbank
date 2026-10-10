"""Each module's own settings in the registry (docs/design/settings.md, "Module settings").

A module declares its settings in the JSON Schema file `[settings].schema` names (oarbank-sdk spec/manifest.md,
"Settings"): one property per key, with its type and constraints, default, title, description and an `x-oarbank`
annotation (scope `fleet` or `node`, `required`, `unit`, `advanced`, `campaign`). When a version is installed, enabled,
promoted or rolled back, the coordinator registers the keys of the module's registered version (its current one, else
its newest installed one) as `module.<module>.<key>` definitions, kept in `module_setting_keys`. Values live in
`setting_values` like every other setting, one row per key and scope with `module` naming the module, and change
through `settings.apply` (or the module's own `module_settings.update` effect), checked against the property's whole
JSON Schema. A key declared `campaign` may also be overridden by a campaign of the module while it runs.

- A `fleet` key may be set for the fleet only; the module's coordinator side reads it. A `node` key may be set for the
  fleet, a node group or a node; each node's runners and services of that module get it in `OARBANK_SETTINGS_FILE`.
- A key a new version drops keeps its values, inert (nothing resolves or delivers them), until the owner resets them or
  a later version declares it again; a value a new version no longer accepts (its type or range changed, or the key
  became fleet-only and the value was set below the fleet) is deleted, and the `module_settings_registered` event names
  it with its old value."""
import json
import time
from pathlib import Path

from . import registry as R
from . import store

SCHEMA = """
CREATE TABLE IF NOT EXISTS module_setting_keys (
  module TEXT PRIMARY KEY, version TEXT NOT NULL,
  keys_json TEXT NOT NULL,                 -- the declared keys (oarbank_sdk.settings.SettingKey.as_dict), in order
  registered_at REAL NOT NULL);
"""
PREFIX = "module."


def key_of(module: str, name: str) -> str:
    return f"{PREFIX}{module}.{name}"


def split(key: str) -> tuple[str, str] | tuple[None, None]:
    """(module, name) of a module's own key, else (None, None)."""
    parts = (key or "").split(".")
    if len(parts) == 3 and parts[0] == "module" and parts[1] and parts[2]:
        return parts[1], parts[2]
    return None, None


def has_default(d: R.Setting) -> bool:
    return "default" in d.schema


def _validator(label: str, k):
    from oarbank_sdk import settings as S

    def check(v):
        if v is None and not k.nullable:
            raise R.SettingError("bad_value", f"{label}: a value is required (reset it to inherit)")
        if k.type == "integer" and isinstance(v, float) and v.is_integer():
            v = int(v)
        if isinstance(v, str):
            v = v.strip()
        why = S.check_value(k, v)
        if why:
            raise R.SettingError("bad_value", f"{label}: {why}"[:300])
        return v
    return check


def definition(module: str, k) -> R.Setting:
    """The registry definition of one declared key (oarbank_sdk.settings.SettingKey)."""
    node = k.scope == "node"
    return R.Setting(key_of(module, k.name), k.label, k.help, k.schema, default=k.default if k.has_default else None,
                     unit=k.unit, scopes=R.SCOPES if node else ("fleet",), lockable=True, advanced=k.advanced,
                     danger="T1", applies="agent" if node else "coordinator", section="module_own",
                     qualifier="required", required=k.required, validator=_validator(k.label, k),
                     campaign=bool(getattr(k, "campaign", False)))


def _keys(raw: str) -> list:
    from oarbank_sdk import settings as S
    return [S.SettingKey.from_dict(x) for x in json.loads(raw or "[]")]


def load(r) -> dict[str, R.Setting]:
    """Every registered key of every module: {module.<module>.<key>: definition}."""
    out = {}
    for row in r.q("SELECT module, keys_json FROM module_setting_keys ORDER BY module"):
        for k in _keys(row["keys_json"]):
            out[key_of(row["module"], k.name)] = definition(row["module"], k)
    return out


def declared(r, module: str) -> list:
    """The keys a module's registered version declares (SettingKey), in schema order."""
    row = r.q("SELECT keys_json FROM module_setting_keys WHERE module=?", (module,))
    return _keys(row[0]["keys_json"]) if row else []


def registration(r, module: str) -> dict | None:
    row = r.q("SELECT module, version, registered_at FROM module_setting_keys WHERE module=?", (module,))
    return row[0] if row else None


def module_names(r) -> list[str]:
    """The installed modules (every one has the core's per-module keys)."""
    return [x["name"] for x in r.q("SELECT DISTINCT name FROM modules ORDER BY name")]


def resolve_key(snap, key: str, module: str = "") -> tuple[str, str]:
    """(key, module) for a change or a read: `vm_mem_gb` with module `m` is `module.m.vm_mem_gb` when `m` declares it,
    and `module.m.vm_mem_gb` names its module itself."""
    m, name = split(key)
    if m:
        return key, module or m
    core = R.REGISTRY.get(key)
    # the module's own key, unless the name is a core key a module qualifies (enabled, pipeline, ...: those are the
    # core's; a module's own key of that name is reached as module.<module>.<name>)
    if module and (core is None or not core.qualifier) and key_of(module, key) in snap.defs:
        return key_of(module, key), module
    return key, module


def orphans(r, module: str) -> list[dict]:
    """Values of keys the registered version does not declare: kept, never resolved or delivered (reset deletes them)."""
    names = {k.name for k in declared(r, module)}
    out = []
    for x in store.rows(r):
        m, name = split(x["key"])
        if m == module and name not in names:
            out.append(x)
    return out


def unset(snap, node: dict | None, module: str) -> list[str]:
    """The module's required keys with no value set for this node (None: at the fleet)."""
    from . import resolve as V
    out = []
    for key, d in snap.defs.items():
        m, name = split(key)
        if m != module or not d.required:
            continue
        if V.resolve(snap, node, key, module)["source"]["scope"] == "default":
            out.append(name)
    return out


def _version(db, module: str) -> str | None:
    from .. import modstore
    ch = modstore.channel(db, module)
    rows = modstore.installed(db, module)
    if ch["current"] and any(r["version"] == ch["current"] for r in rows):
        return ch["current"]
    return rows[-1]["version"] if rows else None


def schema_keys(db, module: str, version: str) -> list:
    """The keys an installed version's settings schema declares (SettingKey)."""
    from oarbank_sdk import manifest as mf
    from oarbank_sdk import settings as S

    from .. import modstore
    rec = modstore.record(db, module, version)
    if not rec:
        return []
    root = Path(rec["path"])
    return S.load(root, mf.load(root / "oarbank-module.toml")).keys


def register(db, module: str, actor: str = "oarbank", sync: bool = True) -> dict:
    """Register the keys of a module's registered version (inside the caller's transaction): what it now declares,
    what it no longer declares, and the values its schema no longer accepts (deleted). Nodes' effective settings follow
    (`sync`)."""
    from oarbank_sdk import settings as S
    version = _version(db, module)
    before = {k.name: k for k in declared(db, module)}
    if version is None:                              # no version installed any more
        db.x("DELETE FROM module_setting_keys WHERE module=?", (module,))
        keys = []
    else:
        try:
            keys = schema_keys(db, module, version)
        except S.SettingsSchemaError as e:          # verified at install: a store modified since
            db.event("module_settings_unreadable", module=module, reason=f"{module} {version}: " + "; ".join(e.errors)[:300])
            keys = []
        db.x("INSERT INTO module_setting_keys(module, version, keys_json, registered_at) VALUES(?,?,?,?) "
             "ON CONFLICT(module) DO UPDATE SET version=excluded.version, keys_json=excluded.keys_json, "
             "registered_at=excluded.registered_at", (module, version, json.dumps([k.as_dict() for k in keys]), time.time()))
    now = {k.name: k for k in keys}
    dropped = []
    for x in store.rows(db):
        m, name = split(x["key"])
        if m != module or name not in now:
            continue
        k = now[name]
        why = None
        if k.scope == "fleet" and x["scope"] != "fleet":
            why = "now set for the whole fleet only"
        else:
            try:
                definition(module, k).validator(x["value"])
            except R.SettingError as e:
                why = e.detail
        if why:
            store.delete(db, x["scope"], x["scope_id"], module, x["key"])
            dropped.append({"key": name, "scope": x["scope"], "scope_id": x["scope_id"], "value": x["value"], "why": why})
    added = sorted(set(now) - set(before))
    removed = sorted(set(before) - set(now))
    changed = sorted(n for n in set(now) & set(before) if now[n] != before[n])
    if added or removed or changed or dropped:
        db.event("module_settings_registered", actor=actor, module=module,
                 reason=f"{module} {version or '(uninstalled)'}: " + "; ".join(
                     ([f"declares {', '.join(added)}"] if added else []) + ([f"no longer {', '.join(removed)} (values kept)"]
                     if removed else []) + ([f"changed {', '.join(changed)}"] if changed else [])
                     + ([f"dropped {len(dropped)} value(s) its schema no longer accepts"] if dropped else []))[:400],
                 added=added, removed=removed, changed=changed, dropped=dropped, version=version)
        if sync:
            from .apply import sync_nodes
            sync_nodes(db)
    return {"module": module, "version": version, "keys": [k.name for k in keys], "added": added, "removed": removed,
            "changed": changed, "dropped": dropped}


def register_all(db, actor: str = "oarbank", sync: bool = True) -> list[dict]:
    names = set(module_names(db)) | {r["module"] for r in db.q("SELECT module FROM module_setting_keys")}
    return [register(db, m, actor, sync=sync) for m in sorted(names)]


def write(db, module: str, values: dict, actor: str, comment: str | None = None) -> dict:
    """Set a module's own keys at fleet scope (inside the caller's transaction): one change set through settings.apply,
    so every key must be declared and every value valid, or nothing is written (ApplyError); `None` resets a key. What
    the module's `module_settings.update` effect and the core's own callers use."""
    from .apply import ApplyError, commit
    if not isinstance(values, dict) or not values:
        raise ApplyError(400, "bad_params", "module settings: a non-empty object of {key: value}")
    changes = [{"scope": "fleet", "module": module, "key": key_of(module, k),
                **({"reset": True} if v is None else {"value": v})} for k, v in values.items()]
    return commit(db, changes, actor, comment)
