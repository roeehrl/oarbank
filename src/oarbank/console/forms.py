"""Form fields -> operation params, per operation (the console's only knowledge of form layouts)."""
import json


class FieldErrors(ValueError):
    """A settings form whose fields could not be read: [{key, message}], shown like the coordinator's own refusals."""

    def __init__(self, errors: list[dict]):
        super().__init__("; ".join(f"{e['key']}: {e['message']}" for e in errors))
        self.errors = errors


def _setting_value(form, key: str, kind: str):
    """A field's text as the setting's value, by the input kind the page rendered (settings/views.input_of)."""
    from ..coordinator.settings import REGISTRY
    getlist = getattr(form, "getlist", None)
    last = lambda k: ((getlist(k) or [""])[-1] if getlist else form.get(k, "")) or ""
    raw = last(f"v.{key}").strip()
    if kind == "checkbox":
        return raw in ("1", "true", "on")
    if kind == "schedule":
        days = [int(d) for d in (getlist(f"v.{key}.days") if getlist else []) if str(d).isdigit()]
        return {"start": last(f"v.{key}.start").strip(), "end": last(f"v.{key}.end").strip(), "days": days or list(range(7))}
    if kind == "list":
        return [x.strip() for x in raw.replace(",", "\n").splitlines() if x.strip()]
    if kind == "json":
        try:
            return json.loads(raw or "{}")
        except ValueError:
            raise FieldErrors([{"key": key, "message": "not valid JSON"}])
    if kind in ("number", "selectnum"):
        if raw == "":
            d = REGISTRY.get(key)
            if (d is not None and d.nullable) or form.get(f"null.{key}") == "1":
                return None
            raise FieldErrors([{"key": key, "message": "enter a number"}])
        try:
            return float(raw) if any(c in raw for c in ".eE") else int(raw)
        except ValueError:
            raise FieldErrors([{"key": key, "message": f"{raw!r} is not a number"}])
    return raw or None


def settings_changes(form) -> dict:
    """A Settings section (templates/_settings.html): `scope`, `scope_id`, one `keys` entry per row with its input kind
    (`t.<key>`), whether this scope set it when the page was drawn (`had.<key>`) and its value then (`cur.<key>`). A ticked
    "Override" (`o.<key>`) sets the field's value here when it is new or changed; an override unticked resets it; a row's
    "Reset to inherited" button (`reset=<key>`) resets that row alone. A `params` field (the reverse view's Reset) is the
    change set itself."""
    if form.get("params"):
        return json.loads(form["params"])
    if form.get("tool"):                     # a host tool's path on a node (`tool`, `module`, `path`; empty: reset)
        c = {"scope": form.get("scope") or "node", "scope_id": form.get("scope_id") or "",
             "module": (form.get("module") or "").strip(), "key": f"tool.{form.get('tool').strip()}.path"}
        path = (form.get("path") or "").strip()
        return {"changes": [{**c, "value": path} if path else {**c, "reset": True}]}
    if form.get("bulk"):
        return bulk_changes(form)
    scope, sid = form.get("scope") or "node", form.get("scope_id") or ""
    base = {"scope": scope, "scope_id": sid, **({"module": form.get("module").strip()} if form.get("module") else {})}
    getlist = getattr(form, "getlist", None)
    keys = getlist("keys") if getlist else [form.get("keys")] if form.get("keys") else []
    reset = (form.get("reset") or "").strip()
    if reset:
        return {"changes": [{**base, "key": reset, "reset": True}]}
    changes, errors = [], []
    for key in keys:
        had = form.get(f"had.{key}") == "1"
        if form.get(f"o.{key}"):
            try:
                v = _setting_value(form, key, form.get(f"t.{key}") or "text")
            except FieldErrors as e:
                errors += e.errors
                continue
            # a lock (fleet and group rows): ticked, the value set here holds below (`enf.<key>`; `had_enf`: it did)
            enforce = scope in ("fleet", "group") and bool(form.get(f"enf.{key}"))
            was_enforced = form.get(f"had_enf.{key}") == "1"
            cur = form.get(f"cur.{key}")
            if had and cur is not None and json.dumps(v, sort_keys=True) == cur and enforce == was_enforced:
                continue
            changes.append({**base, "key": key, "value": v, **({"enforce": True} if enforce else {})})
        elif had:
            changes.append({**base, "key": key, "reset": True})
    if errors:
        raise FieldErrors(errors)
    if not changes:
        raise FieldErrors([{"key": keys[0] if keys else "", "message": "nothing changed: tick Override to set a value here, "
                                                                     "or untick it to go back to the inherited one"}])
    return {"changes": changes}


def bulk_changes(form) -> dict:
    """The Bulk changes page: one setting (`bulk_key`, its input kind `t.<key>`, the value `v.<key>`) set or reset
    (`bulk_action`) on every ticked node (`node`), as one change set."""
    getlist = getattr(form, "getlist", None)
    nodes = [x for x in (getlist("node") if getlist else [form.get("node")]) if x]
    key = (form.get("bulk_key") or "").strip()
    if not key:
        raise FieldErrors([{"key": "", "message": "choose a setting"}])
    if not nodes:
        raise FieldErrors([{"key": key, "message": "tick at least one node"}])
    if form.get("bulk_action") == "reset":
        return {"changes": [{"scope": "node", "scope_id": n, "key": key, "reset": True} for n in nodes]}
    from ..coordinator.settings import REGISTRY
    from ..coordinator.settings.views import input_of
    d = REGISTRY.get(key)
    kind = input_of(d)["kind"] if d else "text"
    raw = form.get("bulk_value") or ""
    if kind == "checkbox":
        v = raw.strip().lower() in ("1", "true", "on", "yes")
    else:
        v = _setting_value({f"v.{key}": raw}, key, kind if kind in ("number", "list", "json") else "text")
    return {"changes": [{"scope": "node", "scope_id": n, "key": key, "value": v} for n in nodes]}


def group_params(form) -> dict:
    """The group form (the Groups page and a group's page): name, description, the selector's terms (any left empty
    is not a term), explicit members, or the selector as JSON (`selector_json`, which wins when given)."""
    getlist = getattr(form, "getlist", None)
    split = lambda k: [x.strip() for x in (form.get(k) or "").replace("\n", ",").split(",") if x.strip()]
    if (form.get("selector_json") or "").strip():
        try:
            sel = json.loads(form["selector_json"])
        except ValueError:
            raise ValueError("selector: not valid JSON")
    else:
        sel = {}
        for k in ("os", "arch"):
            if (form.get(f"sel.{k}") or "").strip():
                sel[k] = form.get(f"sel.{k}").strip()
        if split("sel.labels"):
            sel["labels"] = split("sel.labels")
        if split("sel.hostname"):
            sel["hostname"] = split("sel.hostname")
        if form.get("sel.battery") in ("yes", "no"):
            sel["battery"] = form.get("sel.battery") == "yes"
        for k in ("ram_gb_min", "ram_gb_max", "cores_min"):
            raw = (form.get(f"sel.{k}") or "").strip()
            if raw:
                try:
                    sel[k] = float(raw)
                except ValueError:
                    raise ValueError(f"{k.replace('_', ' ')}: a number")
    out = {"selector": sel, "members": [x for x in (getlist("member") if getlist else []) if x],
           "description": (form.get("description") or "").strip()}
    if (form.get("name") or "").strip():
        out["name"] = form.get("name").strip()
    return out


def node_labels(form) -> dict:
    """Labels added to or removed from a node (`labels`, comma-separated; `label_action` add | remove), or from every
    ticked node (`node`, the Bulk changes page). A `params` field (a label's Remove button) is the request itself."""
    if form.get("params"):
        return json.loads(form["params"])
    getlist = getattr(form, "getlist", None)
    labels = [x.strip() for x in (form.get("labels") or "").split(",") if x.strip()]
    out = {"remove" if form.get("label_action") == "remove" else "add": labels}
    nodes = [x for x in (getlist("node") if getlist else []) if x]
    if nodes:
        out["nodes"] = nodes
    return out


def _coerce(v: str):
    if v in ("true", "false"):
        return v == "true"
    try:
        return int(v)
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return v


def generic(form) -> dict:
    """Operation params from a JSON `params` field and/or `p.<name>` fields (module forms and buttons)."""
    raw = form.get("params")
    out = json.loads(raw) if raw else {}
    getlist = getattr(form, "getlist", None)
    for k in form.keys():
        if k.startswith("pl.") and getlist:                    # multi-select: a list parameter
            out[k[3:]] = [v for v in getlist(k) if v]
            continue
        if k.startswith("p."):
            out[k[2:]] = _coerce(form.get(k))
        elif k.startswith("pj.") and (form.get(k) or "").strip():
            out[k[3:]] = json.loads(form.get(k))             # object/array fields are edited as JSON text
    return out


def tool_definition(form) -> dict:
    """Settings → Tools: a definition's extra search patterns, one per line, for every OS (`search_fleet`) or one
    platform group (`search_darwin`, ...), and an executable's version command (`version_args`, `version_regex`)."""
    out = {"search": {scope: [x.strip() for x in (form.get(f"search_{scope}") or "").splitlines() if x.strip()]
                      for scope in ("fleet", "darwin", "linux", "windows")}}
    if form.get("kind"):
        out["kind"] = form.get("kind")
    if (form.get("version_regex") or "").strip():
        out["version"] = {"args": (form.get("version_args") or "--version").split(), "regex": form.get("version_regex").strip()}
    return out


JOIN_TTLS = {3600, 4 * 3600, 86400, 7 * 86400, 30 * 86400}     # the Add machine form's lifetimes, in seconds
MANY_MIN, MANY_MAX, ONE_MAX_TTL = 2, 10000, 7 * 86400


def join_code(form) -> dict:
    """The Add machine form (node-enrollment.md, "Code types"): one machine is a single-use code approved at once; many
    machines need a use count (2-10000), may last up to 30 days, and wait for approval unless "approve automatically" is
    ticked. The coordinator checks the same bounds; checking here names the form's own fields."""
    many = form.get("count") == "many"
    try:
        ttl = int(form.get("ttl") or 4 * 3600)
    except ValueError:
        raise ValueError("choose how long the code stays valid")
    if ttl not in JOIN_TTLS:
        raise ValueError("choose how long the code stays valid")
    if many:
        try:
            uses = int((form.get("uses") or "").strip())
        except ValueError:
            raise ValueError(f"how many machines: a number from {MANY_MIN} to {MANY_MAX}")
        if not MANY_MIN <= uses <= MANY_MAX:
            raise ValueError(f"how many machines: a number from {MANY_MIN} to {MANY_MAX}")
    else:
        uses = 1
        if ttl > ONE_MAX_TTL:
            raise ValueError("a code for one machine lasts at most 7 days (30 days is for many machines)")
    return {"label": (form.get("label") or "").strip(), "ttl_s": ttl, "uses": uses,
            "approve": bool(form.get("approve")) if many else True,
            "system": bool(form.get("system")), "containers": bool(form.get("containers"))}


MAPPERS = {
    "nodes.join_code": lambda f, ctx: join_code(f),
    # a device code stays a string (WDJB-MJHT); the coordinator folds case and dashes
    "nodes.admit_code": lambda f, ctx: {"user_code": (f.get("user_code") or "").strip()},
    "settings.apply": lambda f, ctx: settings_changes(f),
    "groups.create": lambda f, ctx: group_params(f),
    "groups.update": lambda f, ctx: group_params(f),
    "nodes.label": lambda f, ctx: node_labels(f),
    # a core secret's value is the form's `secret` field, sent beside params
    "settings.secrets.set": lambda f, ctx: {},
    "settings.secrets.clear": lambda f, ctx: {},
    "tools.define": lambda f, ctx: tool_definition(f),
    # a settings export: the file's text (an upload, read by the console, or the text box), as it is
    "settings.import": lambda f, ctx: {"text": f.get("text") or "", **({"comment": f.get("comment")} if f.get("comment") else {})},
    # a folder's path per node, one "<node>=<path>" per line; a node with an empty path is removed
    "settings.folders.update": lambda f, ctx: {"access": f.get("access") or "read", "nodes": {
        k.strip(): v.strip() or None for k, _, v in (x.partition("=") for x in (f.get("nodes") or "").splitlines()) if k.strip()}},
    "settings.origins.update": lambda f, ctx: {"hosts": [x.strip() for x in (f.get("hosts") or "").splitlines() if x.strip()]},
    # secrets and labels stay strings (generic coercion would turn a numeric password into a number)
    "access.accounts.create": lambda f, ctx: {"role": f.get("p.role") or "viewer",
                                              **({"password": f.get("p.password")} if f.get("p.password") else {})},
    "access.accounts.set_password": lambda f, ctx: {"password": f.get("p.password") or ""},
    "access.tokens.create": lambda f, ctx: {"label": f.get("p.label") or "", "role": f.get("p.role") or "viewer",
                                            "days": float(f.get("p.days") or 90)},
    # a secret's value is the form's `secret` field, sent beside params; never a parameter
    "secrets.set": lambda f, ctx: {"name": f.get("p.name") or "", **({"node": f.get("p.node")} if f.get("p.node") else {}),
                                   **({"group": f.get("p.group")} if f.get("p.group") else {})},
    "secrets.clear": lambda f, ctx: {"name": f.get("p.name") or "", **({"node": f.get("p.node")} if f.get("p.node") else {}),
                                     **({"group": f.get("p.group")} if f.get("p.group") else {})},
    "jobs.set_priority": lambda f, ctx: {"priority": int(f.get("priority") or 0)},
}


def params_for(op: str, form, ctx) -> dict:
    return MAPPERS.get(op, lambda f, c: generic(f))(form, ctx)
