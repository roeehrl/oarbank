"""Form fields -> operation params, per operation (the console's only knowledge of form layouts)."""
import json

POLICY_BOOL = {"run_on_battery", "hard_limits"}
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
    patch = {}
    for k in form.keys():
        if not k.startswith("p_"):
            continue
        name, v = k[2:], form[k]
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
    return {"patch": patch}


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


MAPPERS = {
    "nodes.set_caps": lambda f, ctx: limits(f),
    "nodes.set_policy": lambda f, ctx: policy(f),
    "settings.notifications.update": lambda f, ctx: {"url": f.get("ntfy_url"), "token": f.get("ntfy_token"),
                                                      "click_base": f.get("click_base")},
    "settings.tools.update": lambda f, ctx: {"trust": f.get("trust") or "read",
                                              "paths": {os_: [x.strip() for x in (f.get(f"paths_{os_}") or "").splitlines() if x.strip()]
                                                        for os_ in ("darwin", "linux", "windows")}},
    # secrets and labels stay strings (generic coercion would turn a numeric password into a number)
    "access.accounts.create": lambda f, ctx: {"role": f.get("p.role") or "viewer",
                                              **({"password": f.get("p.password")} if f.get("p.password") else {})},
    "access.accounts.set_password": lambda f, ctx: {"password": f.get("p.password") or ""},
    "access.tokens.create": lambda f, ctx: {"label": f.get("p.label") or "", "role": f.get("p.role") or "viewer",
                                            "days": float(f.get("p.days") or 90)},
    "jobs.set_priority": lambda f, ctx: {"priority": int(f.get("priority") or 0)},
    "modules.set_pipeline": lambda f, ctx: {"mode": f.get("mode")},
}


def params_for(op: str, form, ctx) -> dict:
    return MAPPERS.get(op, lambda f, c: generic(f))(form, ctx)
