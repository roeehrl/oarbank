"""View models for the console pages: pure functions over a read-only reader (q/one/get_setting).

Hot pages (the fleet home) render from the snapshot built by state.ConsoleState; drill-down pages call
these with a pooled read connection. Nothing here writes; module views are materialized by oarbankd, so the
console never runs module code.
"""
import json
from pathlib import Path
import time

from ..coordinator import detail

OFFLINE_AFTER = 30.0          # oarbankd config.OFFLINE_AFTER
CLOCK_SKEW_S = 60.0           # oarbankd core.CLOCK_SKEW_S
LIMIT_KEYS = ("cpu_cores", "mem_gb", "jobs", "vm_mem_gb", "vm_cpus", "disk_gb", "staging_mbps", "schedule")


def jl(s, default=None):
    return default if s in (None, "") else json.loads(s)


def node_stats(r, now: float) -> dict:
    """Per-node counters for every node in three grouped queries (the snapshot rebuilds every second
    under load; per-node queries made it cost O(nodes) round trips)."""
    live = {x["node_id"]: x["n"] for x in r.q("SELECT node_id, COUNT(*) n FROM attempts WHERE state='live' GROUP BY node_id")}
    done = {x["node_id"]: x["n"] for x in r.q("SELECT node_id, COUNT(*) n FROM attempts WHERE state='completed' AND ended_at>? "
                                               "GROUP BY node_id", (now - 3600,))}
    return {"live": live, "done": done}


OS_NAMES = {"darwin": "macOS", "linux": "Linux", "windows": "Windows"}
PRESSURE = {0: "normal", 1: "warning", 3: "critical"}                 # the heartbeat's mem_pressure scale
THERMAL = {0: "nominal", 1: "fair", 2: "serious", 3: "critical"}
HELD = {"guard:memory": "memory guard", "guard:thermal": "heat", "guard:battery": "on battery",
        "local:pause": "paused on the machine", "local_pause": "paused on the machine", "thermal": "heat",
        "outside_schedule": "outside its schedule", "cap.mem_gb exceeded": "memory cap reached",
        "protection": "host protection", "user": "the owner"}


def hardware(facts: dict) -> dict:
    """What the node's facts (format 2) say about its hardware, with None for anything it did not report."""
    facts = facts or {}
    cpu, plat = facts.get("cpu") or {}, facts.get("platform") or {}
    perf, eff, logical = cpu.get("perf_cores"), cpu.get("eff_cores"), cpu.get("logical")
    total = logical or ((perf or 0) + (eff or 0)) or None
    os_name = OS_NAMES.get(plat.get("os"), plat.get("os"))
    return {"cpu": cpu.get("model") or None, "cores_total": total,
            "cores": f"{perf}P + {eff}E" if perf and eff else (f"{total} cores" if total else None),
            "memory_gb": facts.get("memory_gb"), "os": " ".join(x for x in (os_name, plat.get("os_version")) if x) or None,
            "arch": plat.get("arch") or None,
            "gpus": [g.get("model") or g.get("vendor") for g in facts.get("gpus") or [] if g.get("model") or g.get("vendor")]}


def limit_label(b: str | None) -> str | None:
    """A capacity binding or not-admitting cause as a reader says it; None when nothing but the hardware binds."""
    if not b or b == "auto":
        return None
    if b in HELD:
        return HELD[b]
    if b.startswith("desired_state="):
        return b.split("=", 1)[1]
    if b.startswith("cap."):
        return f"the owner's cap on {b[4:].replace('_', ' ')}"
    if b.startswith("rule:"):
        rule, _, during = b[5:].partition("/")
        return f"protecting {rule}" + (f" ({during})" if during else "")
    return b.replace("_", " ")


def capacity_summary(n: dict) -> dict:
    """The node card's jobs line: running jobs against CPU slots, or why the node takes no new jobs.

    `held` is set while the node does not admit (memory guard, pause, schedule, a protection rule); `zero_why` says
    why an admitting node has no CPU slots. Nothing here is invented: a node that has not reported capacity says so."""
    cap, tel = n.get("cap") or {}, n.get("tel") or {}
    if cap.get("cpu_slots") is None:
        return {"reported": False}
    slots, auto = cap["cpu_slots"], cap.get("auto_cpu_slots")
    out = {"reported": True, "slots": slots, "auto": auto if auto is not None and auto != slots else None,
           "held": None, "zero_why": None, "binding": limit_label(cap.get("binding_limit"))}
    if cap.get("admit") is False:
        out["held"] = limit_label(cap.get("why") or cap.get("binding_limit")) or "not admitting"
    elif slots == 0:
        policy = n.get("policy") or {}
        idle = tel.get("user_idle_s")
        out["zero_why"] = out["binding"] or (
            "heat" if (tel.get("thermal") or 0) >= 2 else
            "user present" if idle is not None and idle < (policy.get("user_idle_s") or 300) else
            "automatic capacity is 0")
    return out


def node_view(r, n: dict, now: float, stats: dict | None = None) -> dict:
    stats = stats or node_stats(r, now)
    hb = n["last_heartbeat_at"] or 0
    tel, cap = jl(n["telemetry_json"], {}), jl(n["capacity_json"], {})
    live = stats["live"].get(n["node_id"], 0)
    done1h = stats["done"].get(n["node_id"], 0)
    online = bool(hb and now - hb < OFFLINE_AFTER)
    facts = jl(n["facts_json"], {}) or {}
    v = {**n, "mods": jl(n.get("modules_json"), {}) or {},
         "facts": facts, "hw": hardware(facts), "tel": tel, "cap": cap, "limits": jl(n["limits_json"], {}),
         "policy": jl(n["policy_json"], {}) or {}, "doctor": jl(n["doctor_json"]), "online": online,
         "hb_age": now - hb if hb else None, "live": live, "done1h": done1h,
         "pressure": PRESSURE.get(tel.get("mem_pressure")), "heat": THERMAL.get(tel.get("thermal"))}
    v["slots"] = capacity_summary(v)
    v["gpu"] = detail.gpu(facts, v["doctor"])
    return v


def eta(r, campaign_id: str, now: float):
    rem = r.one("SELECT COUNT(*) n FROM jobs WHERE campaign_id=? AND kind!='call' AND state IN ('pending','leased')",
                (campaign_id,))["n"]
    if not rem:
        return 0
    rate = r.one("SELECT COUNT(*) n FROM jobs WHERE campaign_id=? AND kind!='call' AND state='done' AND done_at>?",
                 (campaign_id, now - 900))["n"] / 900.0
    return rem / rate if rate > 0 else None


def fleet_data(r, now: float | None = None) -> dict:
    now = now or time.time()
    stats = node_stats(r, now)
    nodes = [node_view(r, n, now, stats) for n in r.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")]
    enr = [{**e, "hw": hardware(jl(e["facts_json"], {}))}
           for e in r.q("SELECT * FROM enrollments WHERE status='pending' ORDER BY created_at")]
    camps = r.q("SELECT * FROM campaigns WHERE state IN ('running','paused') ORDER BY created_at DESC")
    counts = {x["campaign_id"]: x for x in r.q(
        "SELECT campaign_id, COUNT(*) n, SUM(state='done') d, SUM(state='leased') l, SUM(state IN ('failed','quarantined')) f, "
        "SUM(state IN ('pending','leased')) rem, SUM(state='done' AND done_at>?) recent FROM jobs WHERE kind!='call' AND "
        "campaign_id IN (SELECT campaign_id FROM campaigns WHERE state IN ('running','paused')) GROUP BY campaign_id",
        (now - 900,))}
    for s in camps:
        c = counts.get(s["campaign_id"], {"n": 0, "d": 0, "l": 0, "f": 0, "rem": 0, "recent": 0})
        s["jobs"] = {k: c[k] for k in ("n", "d", "l", "f")}
        rate = (c["recent"] or 0) / 900.0
        s["eta_s"] = 0 if not c["rem"] else (c["rem"] / rate if rate > 0 else None)
    from ..contracts.alert_rules import policy
    alerts = [{**a, "severity": policy(a["rule"])["severity"], "runbook": policy(a["rule"])["runbook"],
               "snoozed": bool(a.get("snoozed_until") and a["snoozed_until"] > now)}
              for a in r.q("SELECT * FROM alerts WHERE state='open' ORDER BY opened_at DESC")]
    pending = r.one("SELECT COUNT(*) n FROM alerts WHERE state='pending'")["n"]
    known = {n["ts_node_id"] for n in nodes if n["ts_node_id"]}
    discovered = [d for d in (r.get_setting("discovered", []) or []) if d["ts_node_id"] not in known]
    events = r.q("SELECT * FROM events ORDER BY event_id DESC LIMIT 25")
    return {"nodes": nodes, "enrollments": enr, "campaigns": camps, "alerts": alerts, "alerts_pending": pending, "discovered": discovered,
            "events": events, "now": now, "fleet_state": r.get_setting("fleet_state", "active"),
            "modules_disabled": r.get_setting("modules_disabled", []) or []}


def node_page(r, nid: str, now: float, manifest_for) -> dict | None:
    """The node page: its card (node_view), its GPU APIs with their evidence, per-capability enforcement and folders
    (detail.node), history, protection and secrets."""
    n = r.one("SELECT * FROM nodes WHERE node_id=?", (nid,))
    if not n:
        return None
    samples = r.q("SELECT ts, telemetry_json, capacity_json, busy FROM node_samples WHERE node_id=? AND ts>? ORDER BY ts",
                  (nid, now - 6 * 3600))
    atts = r.q("SELECT a.*, j.campaign_id, j.dataset_id, j.kind FROM attempts a JOIN jobs j ON j.job_id=a.job_id "
               "WHERE a.node_id=? ORDER BY a.attempt_id DESC LIMIT 40", (nid,))
    fails = r.q("SELECT end_reason, COUNT(*) n FROM attempts WHERE node_id=? AND state IN ('failed','killed') "
                "AND ended_at>? GROUP BY end_reason", (nid, now - 86400))
    events = r.q("SELECT * FROM events WHERE node_id=? ORDER BY event_id DESC LIMIT 40", (nid,))
    history = r.q("SELECT * FROM audit WHERE target_type='node' AND (target_id=? OR target_id=?) ORDER BY event_id DESC LIMIT 30",
                  (nid, n["hostname"]))
    tel = lambda s: jl(s["telemetry_json"], {})
    capj = lambda s: jl(s["capacity_json"], {})
    series = {"t": [s["ts"] for s in samples], "mem": [tel(s).get("mem_used_gb") for s in samples], "busy": [s["busy"] for s in samples],
              "slots": [capj(s).get("cpu_slots") for s in samples],
              "reserved": [((tel(s).get("protection") or {}).get("constraint") or {}).get("reserved_mem_gb") for s in samples]}
    nv = node_view(r, n, now)
    decisions = [{**d, "detail": {k: v for k, v in (jl(d.pop("record_json"), {}) or {}).items()
                                  if k not in ("t", "seq", "kind", "reason", "rule")}}
                 for d in r.q("SELECT t, kind, reason, rule, record_json FROM protection_decisions WHERE node_id=? "
                              "ORDER BY t DESC LIMIT 80", (nid,))]
    # module secrets with a value of this node's own (names, fingerprints: never a value)
    secrets = r.q("SELECT module, name, fingerprint, set_at FROM secrets WHERE node_id=? AND module!='' ORDER BY module, name",
                  (nid,))
    return {"n": nv, "d": detail.node(r, nid, manifest_for), "attempts": atts, "fails": fails, "events": events,
            "history": history, "series": json.dumps(series), "limit_keys": LIMIT_KEYS, "decisions": decisions,
            "conditions": node_conditions(nv), "node_secrets": secrets}


def node_conditions(n: dict) -> list[dict]:
    """Node conditions with causes (admin-console.md): why capacity is what it is."""
    out = []
    cap, tel = n.get("cap") or {}, n.get("tel") or {}
    prot = tel.get("protection") or {}
    cons = prot.get("constraint") or {}
    if (cons.get("reserved_mem_gb") or 0) > 0 or (cons.get("reserved_cpu") or 0) > 0:
        out.append({"code": "PROTECTION_RESERVED", "tone": "acc",
                    "message": f"{cons.get('reserved_mem_gb', 0)} GB / {cons.get('reserved_cpu', 0)} cores held for "
                               f"{', '.join(prot.get('active') or []) or 'protected processes'}"})
    b = cap.get("binding_limit") or ""
    if b.startswith("cap."):
        out.append({"code": "USER_CAP_BINDING", "tone": "acc", "message": f"the owner's cap {b[4:]} binds"})
    if b.startswith("rule:"):
        out.append({"code": "PROTECTION_BINDING", "tone": "acc", "message": f"{b} binds capacity"})
    if tel.get("guard") in ("soft", "hard"):
        out.append({"code": {"soft": "MEMORY_SOFT", "hard": "MEMORY_HARD"}[tel["guard"]], "tone": "warn",
                    "message": prot.get("guard_reason") or ""})
    if cap.get("admit") is False:
        out.append({"code": "NOT_ADMITTING", "tone": "warn", "message": cap.get("why") or b})
    if prot.get("config_error"):
        out.append({"code": "PROTECTION_CONFIG_ERROR", "tone": "bad", "message": prot["config_error"]})
    from ..coordinator import protection
    out += [{k: c[k] for k in ("code", "tone", "message")} for c in protection.runtime_conditions(tel)]
    off = n.get("clock_offset_s") or 0
    if abs(off) > CLOCK_SKEW_S:
        out.append({"code": "CLOCK_SKEW", "tone": "warn",
                    "message": f"its clock is {abs(off):.0f} s {'ahead of' if off > 0 else 'behind'} the coordinator's: set the "
                               "node's time (certificates and update metadata need it)"})
    return out


# explain remedies whose operation needs more than its target: the page whose form collects the rest, formatted with
# the explain document's subject ids, and where to go when the subject does not name them; `jobs.set_priority` takes its
# one value inline
REMEDY_FORMS = {"nodes.set_caps": ("/nodes/{node}#limits", "/"), "campaigns.rebind_platform": ("/campaigns/{campaign_id}", "/campaigns"),
                "modules.enable_canary": ("/modules", "/modules"), "secrets.set": ("/modules/{module}/secrets", "/modules"),
                "settings.tools.update": ("/settings", "/settings"), "settings.folders.update": ("/settings", "/settings"),
                "agent.promote": ("/agent", "/agent")}
REMEDY_INPUTS = {"jobs.set_priority": "priority"}


def remedy_actions(doc: dict) -> list[dict]:
    """Explain's remedies as the console offers them: a button for an operation that needs only its target (T2/T3 still
    open their plan review), the operation's form page when it needs more, else its name with the CLI command."""
    from ..contracts import operations as registry
    out = []
    for r in doc.get("remedies") or []:
        href = None
        if r["op"] in REMEDY_FORMS:
            page, fallback = REMEDY_FORMS[r["op"]]
            try:
                href = page.format(**r.get("params") or {})
            except KeyError:
                href = fallback
        out.append({**r, "href": href, "input": REMEDY_INPUTS.get(r["op"]),
                    "button": href is None and r.get("target") is not None, "command": registry.command(r["op"], r.get("target"))})
    return out


PLATFORM_TOKENS = ("darwin-arm64", "darwin-amd64", "linux-arm64", "linux-amd64", "windows-arm64", "windows-amd64")   # oarbank_sdk.portable


def placement_of(r, c: dict) -> dict:
    """A campaign's placement for the console (D33): its mix and unit, the campaign unit's class and state, its units by
    state, and the units no node of their class can serve (stranded). `label` is the list column: `linux-amd64 · hard`,
    `same-os · 3 units` or `any`."""
    pol = jl(c.get("placement_json")) or {}
    units = r.q("SELECT unit, class, state, stranded_since FROM placement_bindings WHERE campaign_id=? ORDER BY unit",
                (c["campaign_id"],))
    top = next((u for u in units if u["unit"] == f"c:{c['campaign_id']}"), None)
    states: dict = {}
    for u in units:
        states[u["state"]] = states.get(u["state"], 0) + 1
    if top:
        label = f"{top['class']} · {top['state']}" if top["class"] else f"{pol.get('mix')} · {top['state']}"
    elif units:
        label = f"{pol.get('mix') or 'same-platform'} · {len(units)} units"
    else:
        label = pol.get("mix") or "any"
    return {**{k: pol.get(k) for k in ("mix", "unit", "bind", "rebind", "pin")}, "label": label, "units": units,
            "states": states, "stranded": [u["unit"] for u in units if u["stranded_since"] is not None]}


def campaigns_page(r, module: str = "", state: str = "") -> dict:
    rows = r.q("SELECT * FROM campaigns WHERE (?='' OR module=?) AND (?='' OR state=?) ORDER BY created_at DESC LIMIT 300",
               (module, module, state, state))
    counts = {x["campaign_id"]: x for x in r.q(
        "SELECT campaign_id, COUNT(*) n, SUM(state='done') d, SUM(state='leased') l, SUM(state IN ('failed','quarantined')) f "
        "FROM jobs WHERE kind!='call' AND campaign_id IS NOT NULL GROUP BY campaign_id")}
    for c in rows:
        c["jobs"] = {k: (counts.get(c["campaign_id"]) or {}).get(k) or 0 for k in ("n", "d", "l", "f")}
        c["placement"] = placement_of(r, c)
    return {"campaigns": rows, "module": module, "state": state,
            "modules": [x["module"] for x in r.q("SELECT DISTINCT module FROM campaigns ORDER BY module")]}


def campaign_page(r, cid: str, now: float) -> dict | None:
    c = r.one("SELECT * FROM campaigns WHERE campaign_id=?", (cid,))
    if not c:
        return None
    c["labels"] = jl(c["labels_json"], {}) or {}
    jobs = r.one("SELECT COUNT(*) n, COALESCE(SUM(state='done'),0) d, COALESCE(SUM(state='pending'),0) p, "
                 "COALESCE(SUM(state='leased'),0) l, COALESCE(SUM(state IN ('failed','quarantined')),0) f, "
                 "COALESCE(SUM(state='cancelled'),0) x FROM jobs WHERE campaign_id=? AND kind!='call'", (cid,))
    history = r.q("SELECT * FROM audit WHERE target_type='campaign' AND target_id=? ORDER BY event_id DESC LIMIT 30", (cid,))
    events = r.q("SELECT * FROM events WHERE campaign_id=? ORDER BY event_id DESC LIMIT 30", (cid,))
    # each job's canonical result, where it ran: a module without a campaign panel still shows what it produced
    results = r.q("SELECT j.job_id, j.name, rs.value, rs.at, rs.fields_json, n.hostname, rs.platform FROM jobs j "
                  "JOIN results rs ON rs.result_id=j.canonical_result_id LEFT JOIN nodes n ON n.node_id=rs.node_id "
                  "WHERE j.campaign_id=? AND j.kind!='call' ORDER BY rs.at DESC LIMIT 100", (cid,))
    for x in results:
        x["fields"] = {k: v for k, v in (jl(x.pop("fields_json"), {}) or {}).items() if isinstance(v, (int, float, str))}
    stranded = r.q("SELECT rule, detail FROM alerts WHERE subject=? AND state='open' AND rule LIKE 'placement_%'", (f"campaign:{cid}",))
    platforms = sorted(set(PLATFORM_TOKENS) | {x["platform"] for x in r.q("SELECT DISTINCT platform FROM nodes WHERE platform IS NOT NULL")})
    return {"c": c, "jobs": jobs, "eta_s": eta(r, cid, now), "history": history, "events": events, "results": results,
            "placement": placement_of(r, c), "placement_alerts": stranded, "platforms": platforms}


def result_cell(v, fmt: str | None, unit: str | None) -> str:
    """One result value as the manifest asks (ui.format: .Nf, .Ne, .N%, d, ,d or s; ui.unit after it)."""
    if v is None:
        return ""
    try:
        s = format(v, fmt) if fmt else f"{v:.2f}" if isinstance(v, float) else f"{v:,}" if type(v) is int else str(v)
    except (TypeError, ValueError):
        s = str(v)
    return f"{s} {unit}" if unit else s


def result_columns(results: list[dict], fields) -> list[dict]:
    """The Results table's columns, and each row's cells: the module's result fields that declare a ui.column, in
    manifest order (the manifest contract: absent = not shown). Without the manifest (the module is gone), every
    short field under its own name."""
    if fields is None:
        keys: list[str] = []
        for x in results:
            keys += [k for k, v in x["fields"].items() if k not in keys and not (isinstance(v, str) and len(v) > 24)]
        cols = [{"key": k, "header": k, "format": None, "unit": None} for k in keys[:6]]
    else:
        cols = [{"key": f.name, "header": f.ui.column, "format": f.ui.format, "unit": f.ui.unit} for f in fields if f.ui.column]
    for x in results:
        x["cells"] = [result_cell(x["fields"].get(c["key"]), c["format"], c["unit"]) for c in cols]
    return cols


def jobs_page(r, state: str, campaign: str, node: str, now: float) -> dict:
    where, args = ["1=1"], []
    if state:
        where.append("j.state=?"); args.append(state)
    if campaign:
        where.append("j.campaign_id=?"); args.append(campaign)
    if node:
        where.append("EXISTS (SELECT 1 FROM attempts a WHERE a.job_id=j.job_id AND a.node_id=?)"); args.append(node)
    rows = r.q("SELECT j.*, r.value AS score FROM jobs j LEFT JOIN results r ON r.result_id=j.canonical_result_id WHERE "
               + " AND ".join(where) + " ORDER BY j.job_id DESC LIMIT 300", tuple(args))
    live = r.q("SELECT a.*, n.hostname, j.dataset_id, j.campaign_id FROM attempts a JOIN nodes n ON n.node_id=a.node_id "
               "JOIN jobs j ON j.job_id=a.job_id WHERE a.state='live' ORDER BY a.granted_at")
    return {"jobs": rows, "live": live, "state": state, "campaign": campaign, "node": node, "now": now}


def job_page(r, jid: int, attempt_log_dir) -> dict | None:
    """The job page: the detail document `oarbank job show` prints (attempts, the checkpoint the next attempt resumes
    from), with results, logs, events, history and the waterfall."""
    d = detail.job(r, jid)
    if d is None:
        return None
    j = r.one("SELECT * FROM jobs WHERE job_id=?", (jid,))
    atts = d["attempts"]
    res = r.q("SELECT * FROM results WHERE job_id=? ORDER BY result_id", (jid,))
    for x in res:
        full = jl(x["result_json"], {}) or {}
        x["fields"], x["prov"], x["mode"] = jl(x["fields_json"], {}) or {}, full.get("provenance") or {}, full.get("effective_mode") or {}
    j["labels"] = jl(j["labels_json"], {}) or {}
    logs = {}
    for a in atts[-3:]:
        p = attempt_log_dir / f"{a['attempt_id']}.log"
        if p.exists():
            logs[a["attempt_id"]] = p.read_bytes()[-20000:].decode(errors="replace")
    events = r.q("SELECT * FROM events WHERE job_id=? ORDER BY event_id", (jid,))
    history = r.q("SELECT * FROM audit WHERE target_type='job' AND target_id=? ORDER BY event_id DESC LIMIT 30", (str(jid),))
    return {"j": j, "spec": jl(j["spec_json"], {}), "attempts": atts, "results": res, "logs": logs, "events": events,
            "history": history, "waterfall": waterfall(r, j, atts), "checkpoint": d["checkpoint"]}


SEGMENT_CLASS = {"queued": "seg-q", "staging": "seg-s", "finalizing": "seg-f", "evaluating": "seg-e"}


def waterfall(r, j: dict, atts: list, now: float | None = None) -> dict:
    """Buildkite-style bars: per attempt, queued (created or previous end -> granted), each reported phase,
    finalizing (last phase -> completion received) and evaluating (received -> verdict committed)."""
    now = now or time.time()
    start = j["created_at"] or now
    end = max([start] + [a["ended_at"] or now for a in atts])
    span = max(end - start, 1e-6)
    rows, prev_end = [], start
    for a in atts:
        ph = r.q("SELECT phase, at FROM attempt_phases WHERE attempt_id=? ORDER BY at, phase", (a["attempt_id"],))
        marks = [(p["phase"], p["at"]) for p in ph]
        if not marks:
            marks = [("granted", a["granted_at"] or prev_end)]
        segs = [("queued", prev_end, marks[0][1])]
        names = {"granted": "staging", "completion_received": "evaluating"}
        for (name, t0), nxt in zip(marks, marks[1:] + [(None, a["ended_at"] or now)]):
            if name == "verdict":
                continue
            label = names.get(name, name)
            if nxt[0] == "completion_received" and name not in ("granted", "completion_received"):
                label = name                                     # the last runner phase runs until the report arrives
            segs.append((label, t0, nxt[1]))
        rows.append({"attempt_id": a["attempt_id"], "node": a.get("hostname"), "state": a["state"], "end_reason": a["end_reason"],
                     "segments": [{"label": l, "cls": SEGMENT_CLASS.get(l, "seg-r"), "secs": max(0.0, t1 - t0),
                                   "left": round(100 * (t0 - start) / span, 2), "width": round(max(0.3, 100 * (t1 - t0) / span), 2)}
                                  for l, t0, t1 in segs if t1 is not None and t0 is not None and t1 >= t0]})
        prev_end = a["ended_at"] or now
    return {"rows": rows, "span_s": span, "start": start}


def events_page(r, kind: str, before: int | None) -> dict:
    where, args = [], []
    if kind:
        where.append("kind=?"); args.append(kind)
    if before:
        where.append("event_id<?"); args.append(before)
    rows = r.q("SELECT * FROM events" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY event_id DESC LIMIT 200",
               tuple(args))
    return {"events": rows, "kind": kind, "next_before": rows[-1]["event_id"] if len(rows) == 200 else None}


def audit_page(r, op: str, target: str, before: int | None) -> dict:
    where, args = [], []
    if op:
        where.append("operation LIKE ?"); args.append(op.replace("*", "%"))
    if target:
        where.append("target_id=?"); args.append(target)
    if before:
        where.append("event_id<?"); args.append(before)
    rows = r.q("SELECT * FROM audit" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY event_id DESC LIMIT 200",
               tuple(args))
    head = r.one("SELECT MAX(event_id) m FROM audit")["m"]
    dig = r.one("SELECT last_event_id, ts FROM audit_digests ORDER BY last_event_id DESC LIMIT 1")
    return {"rows": rows, "op": op, "target": target, "head": head, "digest": dig,
            "next_before": rows[-1]["event_id"] if len(rows) == 200 else None}


def settings_page(r) -> dict:
    s = {k: r.get_setting(k) for k in ("ntfy", "console_hosts", "dataset_groups", "tool_registry", "folder_registry",
                                       "folder_statements", "dataset_origins")}
    s["nodes"] = {n["node_id"]: n for n in r.q("SELECT node_id, hostname, platform, folders_json FROM nodes WHERE lifecycle!='retired' "
                                                "ORDER BY hostname")}
    for n in s["nodes"].values():
        n["folders"] = jl(n.pop("folders_json"), {}) or {}
    return {"s": s, "releases": r.q("SELECT release_id, platform, created_at, status, sha256 FROM releases ORDER BY created_at DESC LIMIT 10"),
            "dscount": r.q("SELECT kind, COUNT(*) n FROM datasets GROUP BY kind")}


# ------------------------------------------------------------------ protection editor

def protection_page(r, nid: str, now: float) -> dict | None:
    """The rule editor's view: the current version and its history, the node's reported processes (the
    picker), the agent's live per-rule state, the running canary and the decision timeline."""
    from ..contracts import protection_match as PM
    from ..coordinator import protection
    n = r.one("SELECT * FROM nodes WHERE node_id=? OR hostname=?", (nid, nid))
    if not n:
        return None
    nid = n["node_id"]
    hist = r.q("SELECT version, config_json, config_hash, actor, reason, source, created_at FROM protection_versions "
               "WHERE node_id=? ORDER BY version DESC LIMIT 50", (nid,))
    for h in hist:
        h["config"] = jl(h.pop("config_json"), {})
    cfg = hist[0]["config"] if hist else ((jl(n["policy_json"], {}) or {}).get("protection") or {"schema": 1, "rule": []})
    procs = jl(n.get("processes_json"), []) or []
    ids = {x.get("id") for x in cfg.get("rule") or []}
    matched = {p["pid"]: [m["rule"] for m in PM.preview(cfg, procs) if any(q["pid"] == p["pid"] for q in m["processes"])]
               for p in procs}
    picker = [{**p, "name": PM.display_name(p), "rules": matched.get(p["pid"], []), "suggest": json.dumps(PM.suggest_rule(p, ids))}
              for p in procs]
    tel = jl(n["telemetry_json"], {}) or {}
    canary = r.get_setting("protection_canary")
    if canary:
        refused = r.one("SELECT COUNT(*) n FROM protection_decisions WHERE node_id=? AND t>=? AND kind='actuation_refused'",
                        (canary["node_id"], canary["started_at"]))["n"]
        canary = {**{k: v for k, v in canary.items() if k != "config"}, "soak_s": int(now - canary["started_at"]),
                  "refused": refused}
    return {"n": {**n, "online": (n["last_heartbeat_at"] or 0) > now - OFFLINE_AFTER}, "config": cfg,
            "config_text": json.dumps(cfg, indent=2), "version": hist[0]["version"] if hist else 0, "history": hist,
            "picker": picker, "processes_at": n.get("processes_at"), "prot": tel.get("protection") or {},
            "canary": canary, "timeline": timeline(r, nid, now), "mode": (cfg.get("node") or {}).get("mode", "moderate"),
            "os_note": os_note(n.get("os")), "runtime": protection.runtime_conditions(tel)}


def os_note(os: str | None) -> str | None:
    """What rules can match on this node's OS (the rest is refused there)."""
    from ..contracts import protection as P
    if os not in P.NAME_LIMIT:
        return None
    limit = P.NAME_LIMIT[os]
    if os == "darwin":
        return f"macOS: every match key works; names keep {limit} characters."
    return (f"{os}: match on path_prefix, path_contains, name (up to {limit} characters) or argv_regex. "
            f"Code-signing identity, bundle ids and protect.metric = ipc_ratio are macOS-only and refused here.")


def timeline(r, nid: str, now: float, hours: float = 6.0, width: int = 1000) -> dict:
    """The decision timeline as drawable geometry (server-side SVG, no script): a band per rule while it
    was active, the rung and budget step lines, probe points and guard firings."""
    t0 = now - hours * 3600
    x = lambda t: round((max(t0, min(now, t)) - t0) / (now - t0) * width, 1)
    recs = r.q("SELECT t, kind, reason, rule, record_json FROM protection_decisions WHERE node_id=? AND t>=? ORDER BY t, seq",
               (nid, t0 - 3600))
    bands, open_, rung, budget, probes, guards = {}, {}, [], [], [], []
    for d in recs:
        rec, t = jl(d["record_json"], {}) or {}, d["t"] or 0
        if d["kind"] == "rule_active":
            open_[d["rule"]] = t
        elif d["kind"] == "rule_inactive" and d["rule"] in open_:
            bands.setdefault(d["rule"], []).append((open_.pop(d["rule"]), t))
        elif d["kind"] == "rung_change" and t >= t0:
            rung.append((x(t), rec.get("to") or 0))
        elif d["kind"] == "budget_step" and t >= t0:
            budget.append((x(t), (rec.get("signals") or {}).get("budget") or 0))
        elif d["kind"] == "probe_result":
            if t >= t0:
                probes.append({"x": x(t), "harm": (rec.get("signals") or {}).get("harm")})
        elif d["kind"] == "guard_fired" and t >= t0:
            guards.append({"x": x(t), "reason": d["reason"]})
    for rid, s in open_.items():
        bands.setdefault(rid, []).append((s, now))
    rows = [{"rule": rid, "spans": [{"x": x(a), "w": max(1.0, x(b) - x(a))} for a, b in spans if b >= t0]}
            for rid, spans in sorted(bands.items())]
    def steps(pts, top):
        if not pts:
            return ""
        scale = 40.0 / max(top, 1)
        path, last = [f"M0,{40}"], 0
        for px, v in pts:
            path.append(f"L{px},{40 - last * scale}L{px},{40 - v * scale}")
            last = v
        path.append(f"L{width},{40 - last * scale}")
        return "".join(path)
    return {"rows": [r_ for r_ in rows if r_["spans"]], "rung": steps(rung, 6), "budget": steps(budget, max([b for _, b in budget] or [1])),
            "probes": probes, "guards": guards, "width": width, "hours": hours, "events": len(recs)}


def protection_preview(r, nid: str, config) -> dict:
    """The editor's live preview (no writes: a stale process summary is refreshed by oarbankd when the change
    is reviewed as a plan)."""
    from ..contracts import protection as P, protection_match as PM
    P.ProtectionConfig.model_validate(config)
    n = r.one("SELECT node_id, os, policy_json, processes_json, processes_at FROM nodes WHERE node_id=? OR hostname=?", (nid, nid))
    if not n:
        raise ValueError(f"node {nid} not found")
    refused = P.refusals(config, n["os"]) if n["os"] else []
    if refused:
        raise ValueError(f"on {n['os']}: " + "; ".join(refused))
    top = r.one("SELECT version, config_json FROM protection_versions WHERE node_id=? ORDER BY version DESC LIMIT 1", (n["node_id"],))
    cur = jl(top["config_json"], {}) if top else ((jl(n["policy_json"], {}) or {}).get("protection") or {})
    procs = jl(n["processes_json"], []) or []
    return {"base_version": top["version"] if top else 0, "diff": PM.diff(cur, config), "matches": PM.preview(config, procs),
            "processes_reported": len(procs),
            "processes_age_s": None if n["processes_at"] is None else time.time() - n["processes_at"],
            "note": "Computed from the node's last process summary with the same matcher the agent uses (shared test "
                    "vectors); after apply the agent's own match counts show on the node page."}


# ------------------------------------------------------------------ module lifecycle

def module_store(r) -> dict:
    """Installed bundles, which version runs where (channels, canary nodes, pins), and each canary node's
    certification of the module, for the Modules page's lifecycle panel."""
    inst = r.q("SELECT name, version, module_id, content_digest, installed_at, installed_by, manifest_json, bundle_files, bundle_bytes, "
               "path FROM modules ORDER BY name, installed_at")
    from oarbank.coordinator import modsandbox
    from oarbank_sdk import manifest as mf
    grants = {(g["name"], g["version"]): g["digest"] for g in r.q("SELECT name, version, digest FROM module_grants")}
    for row in inst:
        try:
            req = modsandbox.requests(mf.Manifest.model_validate(json.loads(row.pop("manifest_json") or "{}")),
                                      r.home / row.pop("path"))
        except Exception:
            req = {}
        row["sandbox"] = {"requests": modsandbox.describe(req) if req else "",
                          "approved": not req or grants.get((row["name"], row["version"])) == modsandbox.digest(req)}
    digest_of = {(i["name"], i["version"]): i["content_digest"] for i in inst}
    chans = {c["name"]: {**c, "canary_nodes": jl(c["canary_nodes_json"], []) or []} for c in r.q("SELECT * FROM module_channels")}
    pins = r.q("SELECT p.name, p.node_id, p.version, n.hostname FROM module_pins p LEFT JOIN nodes n ON n.node_id=p.node_id")
    nodes = r.q("SELECT node_id, hostname, modules_json FROM nodes WHERE lifecycle NOT IN ('retired') ORDER BY hostname")
    out = {}
    for row in inst:
        m = out.setdefault(row["name"], {"name": row["name"], "versions": [], "channel": chans.get(row["name"]) or {}, "pins": []})
        m["versions"].append(row)
    for p in pins:
        if p["name"] in out:
            out[p["name"]]["pins"].append(p)
    for m in out.values():
        ch = m["channel"]
        want = digest_of.get((m["name"], ch.get("canary")))

        def canary_state(n):
            st = jl(n["modules_json"], {}).get(m["name"]) or {}
            return st.get("state") if want and st.get("digest") == want else "installing"   # certified on the canary itself
        m["canary_state"] = [{"hostname": n["hostname"], "state": canary_state(n)}
                             for n in nodes if n["node_id"] in (ch.get("canary_nodes") or [])]
        last = r.one("SELECT scope, at, ok, fingerprint, checks_json FROM module_checks WHERE module=? ORDER BY check_id DESC LIMIT 1",
                     (m["name"],))
        m["integrity"] = {**last, "failed": [c for c in jl(last["checks_json"], []) if not c.get("ok")]} if last else None
        m["files"] = r.one("SELECT COUNT(*) n, COALESCE(SUM(size),0) bytes FROM module_files WHERE module=?", (m["name"],))
    return {"store": list(out.values()), "nodes": [{"node_id": n["node_id"], "hostname": n["hostname"]} for n in nodes]}


def agent_builds(r) -> dict:
    """Agent self-update: the uploaded oarbank-agent builds, the channel (current, previous, canary), and per node
    what it runs, what it is assigned, and its update state, for the Agent page."""
    builds = [{**b, "platforms": b["platform"].split(",")} for b in r.q(
        "SELECT sha256, version, size, uploaded_at, uploaded_by, seq, signature IS NOT NULL AS signed, platform "
        "FROM agent_builds ORDER BY uploaded_at DESC")]
    ver = {b["sha256"]: b["version"] for b in builds}
    chans = {c["platform"]: {"current": c.get("current"), "previous": c.get("previous"), "canary": c.get("canary"),
                             "canary_nodes": jl(c.get("canary_nodes_json"), []) or []}
             for c in r.q("SELECT * FROM agent_channel ORDER BY platform")}
    nodes = []
    for n in r.q("SELECT node_id, hostname, platform, agent_version, agent_build, agent_update_json, last_heartbeat_at FROM nodes "
                 "WHERE lifecycle NOT IN ('retired') ORDER BY hostname"):
        ch = chans.get(n["platform"]) or {"current": None, "canary": None, "canary_nodes": []}
        assigned = ch["canary"] if ch["canary"] and n["node_id"] in ch["canary_nodes"] else ch["current"]
        nodes.append({**n, "update": jl(n["agent_update_json"], {}) or {}, "assigned": assigned,
                      "assigned_version": ver.get(assigned), "canary": n["node_id"] in ch["canary_nodes"],
                      "up_to_date": assigned is None or n["agent_build"] == assigned})
    for plat, ch in chans.items():
        ch["ready"] = bool(ch["canary"]) and all(n["agent_build"] == ch["canary"] for n in nodes if n["canary"] and n["platform"] == plat)
    return {"builds": builds, "channels": chans, "versions": ver, "nodes": nodes}


def coordinator(r) -> dict:
    """The Coordinator page: identity, epoch, role and move phase, the plan and the move, and per node which
    coordinator key it pinned (from the published public key; the console never reads the private key)."""
    import base64
    import hashlib
    st = {row["key"]: jl(row["value_json"]) for row in r.q(
        "SELECT key, value_json FROM settings WHERE key IN ('coordinator_cik','coordinator_epoch','coordinator_role',"
        "'move_phase','fleet_id')")}
    cik = st.get("coordinator_cik") or ""
    fp = hashlib.sha256(base64.b64decode(cik)).hexdigest() if cik else ""
    plan = (r.q("SELECT plan_id, target_url, target_stable_id, state, created_at FROM coordinator_plans "
                "ORDER BY created_at DESC LIMIT 1") or [None])[0]
    mv = (r.q("SELECT move_id, epoch, statement, state, not_before, actor, reason FROM coordinator_moves "
              "ORDER BY created_at DESC LIMIT 1") or [None])[0]
    if mv:
        mv = {**mv, "statement_doc": jl(mv["statement"], {})}
    nodes = [{**n, "move": jl(n["coordinator_move_json"])} for n in r.q(
        "SELECT node_id, hostname, cik_pinned, cik_confirmed, coordinator_move_json FROM nodes "
        "WHERE lifecycle NOT IN ('retired') ORDER BY hostname")]
    role = st.get("coordinator_role") or "active"
    from ..coordinator import config as CC
    cbuilds = r.q("SELECT sha256, version, platform, seq, signature FROM coordinator_builds ORDER BY uploaded_at DESC LIMIT 20")
    return {"cbuilds": cbuilds, "signing": CC.RELEASE_SIGNING,
            "s": {"role": role, "epoch": st.get("coordinator_epoch") or 1, "phase": st.get("move_phase") or "idle",
                  "cik_fingerprint": fp, "fleet_id": st.get("fleet_id") or "", "plan": plan, "move": mv},
            "nodes": nodes, "fp": fp}


def coordinator_banner(r) -> dict | None:
    """The fleet-wide banner: a coordinator move waiting, pending or cutting over, or this console reading a
    coordinator that handed off (or is a standby)."""
    st = {row["key"]: jl(row["value_json"]) for row in r.q(
        "SELECT key, value_json FROM settings WHERE key IN ('coordinator_role','move_phase')")}
    mv = (r.q("SELECT move_id, statement, state, not_before FROM coordinator_moves WHERE state IN ('awaiting_owner','pending','cutover') "
              "ORDER BY created_at DESC LIMIT 1") or [None])[0]
    role = st.get("coordinator_role") or "active"
    if not mv and role == "active":
        return None
    to = (jl(mv["statement"], {}) or {}).get("to", {}).get("url") if mv else None
    return {"state": mv["state"] if mv else role, "to": to, "not_before": mv["not_before"] if mv else None, "role": role,
            "phase": st.get("move_phase") or "idle"}



# ------------------------------------------------------------------ datasets (docs/design/datasets-media-checkpoints.md)

def datasets_page(r, kind: str = "", module: str = "") -> dict:
    rows = r.q("SELECT dataset_id, kind, module, files_json, created_at, platform FROM datasets WHERE kind!='artifact' "
               "AND (?='' OR kind=?) AND (?='' OR COALESCE(module,'')=?) ORDER BY created_at DESC LIMIT 500",
               (kind, kind, module, module))
    for d in rows:
        files = jl(d.pop("files_json"), []) or []
        d["n_files"], d["size"] = len(files), sum(int(f.get("size") or 0) for f in files)
        d["origins"] = sum(1 for f in files if f.get("origins"))
    return {"datasets": rows, "kinds": [x["kind"] for x in r.q("SELECT DISTINCT kind FROM datasets WHERE kind!='artifact' ORDER BY kind")],
            "kind": kind, "module": module}


def dataset_page(r, did: str) -> dict | None:
    d = r.one("SELECT * FROM datasets WHERE dataset_id=?", (did,))
    if not d:
        return None
    files = jl(d["files_json"], []) or []
    held = {x["digest"] for x in r.q("SELECT digest FROM blobs WHERE digest IN (%s)" % ",".join("?" * len(files)),
                                       tuple(f["digest"] for f in files))} if files else set()
    for f in files:
        f["held"] = f["digest"] in held
    return {"d": {**d, "meta": jl(d["meta_json"], {}) or {}}, "files": files, "size": sum(int(f.get("size") or 0) for f in files),
            "jobs": r.q("SELECT job_id, state, module FROM jobs WHERE dataset_id=? OR EXISTS (SELECT 1 FROM json_each(jobs.datasets_json) "
                        "WHERE value=?) ORDER BY job_id DESC LIMIT 20", (did, did))}


def blob_file(r, home: Path, digest: str) -> Path | None:
    """A held blob's file (paths in `blobs` are relative to the coordinator's home)."""
    row = r.one("SELECT path FROM blobs WHERE digest=?", (digest,))
    if not row or not row["path"]:
        return None
    p = Path(row["path"])
    p = p if p.is_absolute() else home / p
    return p if p.is_file() else None


def dataset_files(r, home: Path, did: str) -> list[tuple[str, Path]] | None:
    """(path in the dataset, blob file) for each held file of a dataset, or None when it does not exist."""
    d = r.one("SELECT files_json FROM datasets WHERE dataset_id=?", (did,))
    if not d:
        return None
    return [(f["path"], p) for f in jl(d["files_json"], []) or [] if (p := blob_file(r, home, f.get("digest") or ""))]


def campaign_files(r, home: Path, cid: str) -> list[tuple[str, Path]]:
    """(`<job id>[-<name>]/<artifact>/<path>`, blob file) for every artifact file of a campaign's done jobs' canonical
    results: the layout `oarbank campaign download` writes."""
    out = []
    for row in r.q("SELECT j.job_id, j.name, rs.result_json FROM jobs j JOIN results rs ON rs.result_id=j.canonical_result_id "
                   "WHERE j.campaign_id=? AND j.state='done' AND j.kind!='call' ORDER BY j.job_id", (cid,)):
        from ..coordinator.campaigns import artifact_dir
        top = artifact_dir(row["job_id"], row["name"])
        for a in (jl(row["result_json"], {}) or {}).get("artifacts") or []:
            for f in a.get("files") or []:
                p = blob_file(r, home, f.get("digest") or "")
                if p:
                    out.append((f"{top}/{a.get('name')}/{f.get('path')}", p))
    return out

