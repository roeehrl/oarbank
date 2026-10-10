"""A node's policy settings as people read them, and why a node takes the work it takes.

`rows` is the node page's Policy table and `oarbank node show`'s policy lines: each setting with a human label, a
one-line help, this node's value and its default (from `config.policy_defaults`, the same function that set the node's
policy when it joined) with the reason, and whether the value differs from the default. `why` is the one line under
each node card and on the node page that explains the node's slots and its memory for jobs from the capacity the agent
reported (docs/protocol.md, "Capacity and host protection"). Pure functions over plain dicts."""
from . import config as C

# key, label, help, unit; the order is the page's
SETTINGS = (
    ("os_reserve_gb", "Memory kept for the system",
     "Never offered to jobs, whoever is using the computer.", "GB"),
    ("user_reserve_gb", "Memory kept for the person using it",
     "Also kept free while someone is using the computer.", "GB"),
    ("user_present_slots", "Jobs while someone is using this computer",
     "The most jobs at once while someone is at it; 0 holds every new job back.", "jobs"),
    ("user_idle_s", "Idle time before the computer counts as free",
     "Seconds without keyboard or mouse input before it runs at full capacity.", "s"),
    ("screen_sharing_present", "Screen sharing counts as someone using it",
     "A remote Screen Sharing session holds jobs back like a person at the keyboard, even without input (macOS).", None),
    ("run_on_battery", "Run jobs on battery",
     "Off: a laptop on battery power takes no new jobs.", None),
    ("mem_in_use_bound", "Fit jobs into the memory free now",
     "On: jobs get at most what the computer has available now, less the memory guard's floor and 1 GB; off: only the "
     "two reserves above decide (the memory guard still stops new jobs at its floor).", None),
    ("job_mem_gb", "Memory per job slot",
     "The memory one job slot stands for: the jobs it can take are its free memory divided by this.", "GB"),
    ("threads_per_job", "Threads per job",
     "Threads one job counts as against a CPU cores cap (the cap divided by this is the jobs it allows).", "threads"),
    ("max_slots", "Most jobs at once",
     "An upper bound on job slots whatever the hardware allows; empty: no bound.", "jobs"),
    ("nice", "Job priority (nice)",
     "0 normal to 20 lowest. Not applied by agents yet: protection lowers jobs when the owner's work needs it.", None),
    ("hard_limits", "Hard limits",
     "Jobs over their memory or CPU reservation are stopped where the OS enforces it (Linux cgroups, Windows Job "
     "Objects; macOS has none).", None),
    ("disabled_services", "Services this computer does not run",
     "Module services as module/service, separated by commas; a change re-checks and re-certifies the node.", None),
)
KEYS = tuple(k for k, *_ in SETTINGS)
BOOL = {"screen_sharing_present", "run_on_battery", "hard_limits", "mem_in_use_bound"}


def _num(v) -> str:
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return f"{v:g}" if isinstance(v, float) else str(v)


def show(key: str, v) -> str:
    """A setting's value as a person reads it."""
    unit = next((u for k, _, _, u in SETTINGS if k == key), None)
    if key in BOOL:
        return "on" if v else "off"
    if v is None or v == []:
        return "none"
    if isinstance(v, list):
        return ", ".join(map(str, v))
    return f"{_num(v)} {unit}" if unit else _num(v)


def _same(a, b) -> bool:
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) and not isinstance(b, bool):
        return float(a) == float(b)
    if isinstance(a, list) and isinstance(b, list):
        return sorted(map(str, a)) == sorted(map(str, b))
    return a == b


def defaults(facts: dict, default_worker_disabled: list | None) -> dict:
    """{key: (default, reason)} for this node's settings."""
    d = C.policy_defaults(facts or {}, default_worker_disabled)
    return {k: d[k] for k in KEYS}


def rows(policy: dict, facts: dict, default_worker_disabled: list | None) -> list[dict]:
    """The Policy table: label, help, value (the node's, else the default), default, `default_text` with its reason,
    and `changed` when the value differs from the default."""
    policy = policy or {}
    out = []
    for (key, label, help_, unit), (dv, why) in zip(SETTINGS, defaults(facts, default_worker_disabled).values()):
        v = policy.get(key, dv)
        out.append({"key": key, "label": label, "help": help_, "unit": unit, "bool": key in BOOL, "value": v,
                    "default": dv, "default_text": f"default {show(key, dv)}" + (f" ({why})" if why else ""),
                    "changed": not _same(v, dv)})
    return out


def _gb(x) -> str:
    return f"{x:.0f} GB" if x >= 10 else f"{x:.1f} GB"


def _noun(os_: str | None) -> str:
    return {"darwin": "this Mac", "windows": "this PC"}.get(os_ or "", "this computer")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


HELD = {"guard:battery": "on battery (allow it in settings: Run jobs on battery)",
        "guard:thermal": "too hot", "thermal": "too hot",
        "local_pause": "paused on the machine itself", "local:pause": "paused on the machine itself",
        "outside_schedule": "outside its schedule (Limits)", "cap.mem_gb exceeded": "its jobs reached the memory cap (Limits)",
        "desired_state=paused": "paused (resume it in Controls)", "desired_state=draining": "draining: finishing its jobs"}


def _held(key: str, tel: dict) -> str:
    if key in HELD:
        return HELD[key]
    if key == "guard:memory":
        r = (tel.get("protection") or {}).get("guard_reason")
        return "the memory guard" + (f" ({r})" if r else "")
    if key.startswith("rule:"):
        return "protecting " + key[5:]
    if key.startswith("desired_state="):
        return key.split("=", 1)[1]
    return key.replace("_", " ")


def why(cap: dict, tel: dict, facts: dict, policy: dict, os_: str | None = None) -> dict | None:
    """Why the node has the slots and memory it has: {"slots", "memory", "held", "line"} (None before it reports)."""
    cap, tel, facts, policy = cap or {}, tel or {}, facts or {}, policy or {}
    if cap.get("cpu_slots") is None:
        return None
    os_ = os_ or (facts.get("platform") or {}).get("os")
    noun, binding = _noun(os_), cap.get("binding_limit") or "auto"
    out = {"slots": None, "memory": None, "held": None}
    if cap.get("admit") is False:
        out["held"] = "no new jobs: " + _held(cap.get("why") or binding, tel)
    cpu, idle = cap["cpu_slots"], cap.get("idle_cpu_slots")
    present = cap.get("user_present")
    if present is None and tel.get("user_idle_s") is not None:
        present = tel["user_idle_s"] < (policy.get("user_idle_s") or 300)
    jobs = cap.get("slots")
    if out["held"] is None:
        cores = facts.get("cpu") or {}
        perf, eff = cores.get("perf_cores"), cores.get("eff_cores")
        if binding.startswith("cap."):
            s = f"{_plural(cpu, 'slot')}: the owner's cap on {binding[4:].replace('_', ' ')}"
        elif binding.startswith("rule:"):
            s = f"{_plural(cpu, 'slot')}: protecting {binding[5:]}"
        elif binding == "thermal":
            s = f"{_plural(cpu, 'slot')}: fewer while it runs hot"
        elif present and idle is not None and idle > cpu:
            who = "someone is screen sharing" if tel.get("presence") == "screen sharing" else "someone is using"
            s = f"{_plural(cpu, 'slot')} while {who} {noun} ({idle} when idle)"
        elif perf and eff:
            s = f"{_plural(cpu, 'slot')} ({perf} performance cores + {eff} efficiency cores at half)"
        elif perf:
            s = f"{_plural(cpu, 'slot')} ({perf} cores)"
        else:
            s = _plural(cpu, "slot")
        if policy.get("max_slots") is not None and cpu == policy["max_slots"] and not binding.startswith(("cap.", "rule:")):
            s = f"{_plural(cpu, 'slot')} (at most {policy['max_slots']} in settings)"
        if jobs is not None and jobs < cpu:
            s += f", memory for {_plural(jobs, 'job')}"
        out["slots"] = s
    free, mb = cap.get("mem_gb_free"), cap.get("mem_binding")
    if free is not None:
        m = f"{_gb(free)} free for jobs"
        if mb == "in_use" and cap.get("mem_in_use_gb") is not None:
            m += f" (apps and the system use {_gb(cap['mem_in_use_gb'])})"
        elif mb == "reserve":
            kept = [f"{_gb(policy.get('os_reserve_gb') or 0)} for the system"]
            if present and policy.get("user_reserve_gb"):
                kept.append(f"{_gb(policy['user_reserve_gb'])} for the person using it")
            if tel.get("services_reserved_gb"):
                kept.append(f"{_gb(tel['services_reserved_gb'])} for services")
            if cap.get("reserved_mem_gb"):
                kept.append(f"{_gb(cap['reserved_mem_gb'])} protection reserves")
            m += " (" + ", ".join(kept[:-1]) + (" and " if len(kept) > 1 else "") + kept[-1] + " kept)"
        elif mb == "cap":
            m += " (the owner's memory cap)"
        out["memory"] = m
    out["line"] = " · ".join(x for x in (out["held"] or out["slots"], out["memory"]) if x)
    return out
