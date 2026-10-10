"""Form fields -> operation params, per operation (the console's only knowledge of form layouts)."""
import json

POLICY_BOOL = {"run_on_battery", "hard_limits", "screen_sharing_present", "mem_in_use_bound"}
POLICY_LIST = {"disabled_services"}


def limits(form) -> dict:
    if form.get("clear_all"):
        return {"clear_all": True}
    patch = {}
    for k in ("cpu_cores", "mem_gb", "jobs", "vm_mem_gb", "vm_cpus", "disk_gb", "staging_mbps"):
        patch[k] = form.get(k) if form.get(f"on_{k}") else None
    if form.get("on_schedule") and form.get("sched_start") and form.get("sched_end"):
        patch["schedule"] = {"start": form["sched_start"], "end": form["sched_end"],
                             "days": [int(d) for d in form.getlist("sched_days")] or list(range(7))}
    else:
        patch["schedule"] = None
    patch["enforce"] = form.get("enforce") or "soft"
    return {"patch": patch}


def policy(form) -> dict:
    """The Policy table: one `p_<key>` field per setting (a checkbox's hidden `p_<key>=0` comes first, so a ticked box
    sends 0 then 1 and the last value wins). A row's Reset button submits `reset=<key>` with the table, Reset all
    `reset=all` alone: the other rows' values are saved as shown, the reset ones go back to the node's defaults."""
    patch = {}
    getlist = getattr(form, "getlist", None)
    for k in form.keys():
        if not k.startswith("p_"):
            continue
        name = k[2:]
        v = (getlist(k) or [""])[-1] if getlist else form[k]
        if name in POLICY_BOOL:
            patch[name] = v in ("1", "true", "on", "True")
        elif name in POLICY_LIST:
            patch[name] = [x.strip() for x in v.split(",") if x.strip()]
        elif v == "":
            patch[name] = None
        else:
            try:
                patch[name] = float(v) if "." in v else int(v)
            except ValueError:
                patch[name] = v
    reset = (form.get("reset") or "").strip()
    return {"patch": patch, **({"reset": "all" if reset == "all" else [reset]} if reset else {})}


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
    "nodes.set_caps": lambda f, ctx: limits(f),
    "nodes.set_policy": lambda f, ctx: policy(f),
    "settings.notifications.update": lambda f, ctx: {"url": f.get("ntfy_url"), "token": f.get("ntfy_token"),
                                                      "click_base": f.get("click_base")},
    "settings.tools.update": lambda f, ctx: {"trust": f.get("trust") or "read",
                                              "paths": {os_: [x.strip() for x in (f.get(f"paths_{os_}") or "").splitlines() if x.strip()]
                                                        for os_ in ("darwin", "linux", "windows")}},
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
    "secrets.set": lambda f, ctx: {"name": f.get("p.name") or "", **({"node": f.get("p.node")} if f.get("p.node") else {})},
    "secrets.clear": lambda f, ctx: {"name": f.get("p.name") or "", **({"node": f.get("p.node")} if f.get("p.node") else {})},
    "jobs.set_priority": lambda f, ctx: {"priority": int(f.get("priority") or 0)},
    "modules.set_pipeline": lambda f, ctx: {"mode": f.get("mode")},
}


def params_for(op: str, form, ctx) -> dict:
    return MAPPERS.get(op, lambda f, c: generic(f))(form, ctx)
