"""Why a node takes the work it takes: the one line under each node card and on the node page that explains the node's
slots and its memory for jobs from the capacity the agent reported (docs/protocol.md, "Capacity and host protection"),
citing the settings that decide it, each with its value and where that value comes from (settings/resolve.py), linked to
its Explain row on the node's Settings tab. Pure functions over plain dicts."""
from .settings import registry as R


def _gb(x) -> str:
    return f"{x:.0f} GB" if x >= 10 else f"{x:.1f} GB"


def _noun(os_: str | None) -> str:
    return {"darwin": "this Mac", "windows": "this PC"}.get(os_ or "", "this computer")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


HELD = {"guard:battery": "on battery (allow it in settings: Run jobs on battery)",
        "guard:thermal": "too hot", "thermal": "too hot",
        "local_pause": "paused on the machine itself", "local:pause": "paused on the machine itself",
        "outside_schedule": "outside its schedule (Settings: Caps)", "cap.mem_gb exceeded": "its jobs reached the memory cap (Settings: Caps)",
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


CAP_KEYS = {"cap.cpu_cores": "cpu_cores", "cap.mem_gb": "mem_gb", "cap.jobs": "jobs", "cap.staging_mbps": "staging_mbps",
            "cap.mem_gb exceeded": "mem_gb", "outside_schedule": "schedule"}


def why(cap: dict, tel: dict, facts: dict, policy: dict, os_: str | None = None, node_id: str | None = None,
        sources: dict | None = None) -> dict | None:
    """Why the node has the slots and memory it has: {"slots", "memory", "held", "line", "cites"} (None before it
    reports). `policy` is the node's effective policy and caps (settings/apply.node_values, both sections merged);
    `sources` names where each value comes from (`resolve.badge`), and `cites` lists the settings the line rests on:
    {key, label, text ("Run jobs on battery: off · Fleet"), href (its Explain row)}."""
    cap, tel, facts, policy = cap or {}, tel or {}, facts or {}, policy or {}
    if cap.get("cpu_slots") is None:
        return None
    os_ = os_ or (facts.get("platform") or {}).get("os")
    noun, binding = _noun(os_), cap.get("binding_limit") or "auto"
    out = {"slots": None, "memory": None, "held": None, "cites": []}
    cited = []

    def cite(key):
        if key in R.REGISTRY and key not in cited:
            cited.append(key)
    if cap.get("admit") is False:
        reason = cap.get("why") or binding
        out["held"] = "no new jobs: " + _held(reason, tel)
        cite({"guard:battery": "run_on_battery"}.get(reason) or CAP_KEYS.get(reason, ""))
    cpu, idle = cap["cpu_slots"], cap.get("idle_cpu_slots")
    present = cap.get("user_present")
    if present is None and tel.get("user_idle_s") is not None and policy.get("user_idle_s") is not None:
        present = tel["user_idle_s"] < policy["user_idle_s"]
    jobs = cap.get("slots")
    if out["held"] is None:
        cores = facts.get("cpu") or {}
        perf, eff = cores.get("perf_cores"), cores.get("eff_cores")
        if binding.startswith("cap."):
            s = f"{_plural(cpu, 'slot')}: the owner's cap on {binding[4:].replace('_', ' ')}"
            cite(CAP_KEYS.get(binding, binding[4:]))
        elif binding.startswith("rule:"):
            s = f"{_plural(cpu, 'slot')}: protecting {binding[5:]}"
        elif binding == "thermal":
            s = f"{_plural(cpu, 'slot')}: fewer while it runs hot"
        elif present and idle is not None and idle > cpu:
            who = "someone is screen sharing" if tel.get("presence") == "screen sharing" else "someone is using"
            s = f"{_plural(cpu, 'slot')} while {who} {noun} ({idle} when idle)"
            cite("user_present_slots")
            cite("user_idle_s")
        elif perf and eff:
            s = f"{_plural(cpu, 'slot')} ({perf} performance cores + {eff} efficiency cores at half)"
        elif perf:
            s = f"{_plural(cpu, 'slot')} ({perf} cores)"
        else:
            s = _plural(cpu, "slot")
        if policy.get("max_slots") is not None and cpu == policy["max_slots"] and not binding.startswith(("cap.", "rule:")):
            s = f"{_plural(cpu, 'slot')} (at most {policy['max_slots']} in settings)"
            cite("max_slots")
        if jobs is not None and jobs < cpu:
            s += f", memory for {_plural(jobs, 'job')}"
        out["slots"] = s
    free, mb = cap.get("mem_gb_free"), cap.get("mem_binding")
    if free is not None:
        m = f"{_gb(free)} free for jobs"
        if mb == "in_use" and cap.get("mem_in_use_gb") is not None:
            m += f" (apps and the system use {_gb(cap['mem_in_use_gb'])})"
            cite("mem_in_use_bound")
        elif mb == "reserve":
            kept = [f"{_gb(policy.get('os_reserve_gb') or 0)} for the system"]
            cite("os_reserve_gb")
            if present and policy.get("user_reserve_gb"):
                kept.append(f"{_gb(policy['user_reserve_gb'])} for the person using it")
                cite("user_reserve_gb")
            if tel.get("services_reserved_gb"):
                kept.append(f"{_gb(tel['services_reserved_gb'])} for services")
            if cap.get("reserved_mem_gb"):
                kept.append(f"{_gb(cap['reserved_mem_gb'])} protection reserves")
            m += " (" + ", ".join(kept[:-1]) + (" and " if len(kept) > 1 else "") + kept[-1] + " kept)"
        elif mb == "cap":
            m += " (the owner's memory cap)"
            cite("mem_gb")
        out["memory"] = m
    out["line"] = " · ".join(x for x in (out["held"] or out["slots"], out["memory"]) if x)
    for k in cited:
        d, src = R.REGISTRY[k], (sources or {}).get(k)
        out["cites"].append({"key": k, "label": d.label, "source": src,
                             "text": f"{d.label}: {R.show(k, policy.get(k))}" + (f" · {src}" if src else ""),
                             "href": f"/nodes/{node_id}/settings?explain={k}#s-{k}" if node_id else None})
    return out
