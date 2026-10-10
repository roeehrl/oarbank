"""Settings reports (docs/design/settings.md, "Reports"): values that change nothing, and nodes that do not run what the
coordinator sent them. Pure functions over a reader (anything with `q`).

- **Shadowed overrides**: values set below the fleet (or at it) that change no node's effective value: set under a
  lock above them (ignored while it holds), identical to what the scope would inherit without them, or with no effect
  for another reason (a cap above a stricter one, a group whose members all set their own value). Each comes with the
  change set that resets it; a value equal to the inherited one is still a choice, so nothing is reset by itself.
- **Applied drift**: nodes whose agent has not applied their latest settings revision (pending while online, offline,
  an agent that does not report), that refused keys, or whose machine's managed policy tightens what the coordinator
  sends ("Managed on this machine")."""
import copy
import json
import time

from . import modkeys
from . import registry as R
from . import resolve as V
from .apply import applied_state


def _without(snap: V.Snap, ident: tuple) -> V.Snap:
    out = copy.copy(snap)
    out.rows = {k: x for k, x in snap.rows.items() if k != ident}
    return out


def _reset(scope: str, sid: str, module: str, key: str) -> dict:
    return {"scope": scope, "scope_id": sid, "module": module, "key": key, "reset": True}


def shadowed(r) -> dict:
    """GET /api/v1/settings/shadowed: [{scope, scope_id, name, module, key, label, value_text, category, why,
    inherited_text, change}] and the change set that resets them all."""
    snap = V.snapshot(r)
    nodes = r.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    names = {n["node_id"]: n["hostname"] for n in nodes}
    gnames = {g["id"]: g["name"] for g in snap.groups}
    members = {g["id"]: [n for n in nodes if any(x["id"] == g["id"] for x in V.node_groups(snap, n))] for g in snap.groups}
    out = []
    for ident, x in sorted(snap.rows.items()):
        scope, sid, m, key = ident
        if scope not in ("fleet", "group", "node"):
            continue
        try:
            d = snap.defn(key)
        except R.SettingError:
            continue                                  # a value its module no longer declares: the module page lists it
        if d.writer:
            continue
        mod = m if d.qualifier else ""
        show = lambda v: R.show(key, v, d)
        item = {"scope": scope, "scope_id": sid, "module": m, "key": key, "label": d.label, "value": x["value"],
                "value_text": show(x["value"]), "enforced": bool(x["enforced"]), "rev": x["rev"], "by": x["updated_by"],
                "at": x["updated_at"], "change": _reset(scope, sid, m, key),
                "name": "Fleet" if scope == "fleet" else gnames.get(sid, sid) if scope == "group" else names.get(sid, sid)}
        if scope == "fleet":
            if x["enforced"] or d.computed is not None:
                continue
            dv = R.default(d, None)[0]
            if R.same(x["value"], dv) and (d.qualifier != "required" or modkeys.has_default(d) or not modkeys.split(key)[0]):
                out.append({**item, "category": "same", "why": "the same as the default", "inherited_text": show(dv)})
            continue
        if scope == "group":
            fl = snap.get("fleet", "", m, key)
            if fl and fl.get("enforced") and d.lockable:
                out.append({**item, "category": "locked", "why": "ignored while locked by Fleet settings",
                            "inherited_text": show(fl["value"])})
                continue
            if x["enforced"]:
                continue                              # a lock equal to what members inherit still binds their own values
            mem = members.get(sid) or []
            if not mem:
                continue                              # set for members to come: not shadowed
            without = _without(snap, ident)
            before = [V.resolve(snap, n, key, mod)["value"] for n in mem]
            after = [V.resolve(without, n, key, mod)["value"] for n in mem]
            if all(R.same(a, b) for a, b in zip(before, after)):
                same = all(R.same(x["value"], a) for a in after)
                out.append({**item, "category": "same" if same else "no_effect",
                            "why": (f"the same as what its {len(mem)} member{'s' if len(mem) != 1 else ''} inherit" if same else
                                    f"changes no member's value (each of its {len(mem)} member{'s' if len(mem) != 1 else ''} "
                                    "gets its value from elsewhere)"),
                            "inherited_text": show(after[0]) if len({json.dumps(a, sort_keys=True) for a in after}) == 1 else "varies"})
            continue
        node = next((n for n in nodes if n["node_id"] == sid), None)
        if node is None:
            continue
        res = V.resolve(snap, node, key, mod)
        inh = V.resolve(_without(snap, ident), node, key, mod)
        if res["locked_by"]:
            lk = res["locked_by"]
            out.append({**item, "category": "locked", "why": "ignored while locked by " + (
                "Fleet settings" if lk["scope"] == "fleet" else f"the group {lk['name'].removeprefix('Group: ')}"),
                        "inherited_text": show(res["value"])})
        elif R.same(res["value"], inh["value"]):
            same = R.same(x["value"], inh["value"])
            out.append({**item, "category": "same" if same else "no_effect",
                        "why": f"the same as it inherits ({V.badge(inh)})" if same else
                               f"has no effect: {show(res['value'])} comes from {V.badge(res)}",
                        "inherited_text": show(inh["value"])})
    counts = {k: sum(1 for x in out if x["category"] == k) for k in ("locked", "same", "no_effect")}
    return {"rows": out, "counts": counts, "total": len(out), "reset_all": [x["change"] for x in out]}


def drift(r, now: float | None = None) -> dict:
    """GET /api/v1/settings/drift: per node, the settings revision the coordinator sent and the one its agent applied,
    since when it lags, the keys it refused and what its machine's managed policy tightens; `drifting` lists the nodes
    that do not run their latest settings (pending, offline, refused, an agent that does not report)."""
    now = now or time.time()
    rows = []
    for n in r.q("SELECT * FROM nodes WHERE lifecycle!='retired' ORDER BY hostname"):
        st = applied_state(n, None, now)
        rej = json.loads(n.get("settings_rejected_json") or "[]")
        mg = V.managed_of(n)
        binding = [x for x in json.loads(n.get("settings_managed_json") or "{}").get("managed") or [] if x.get("binding")]
        rev, done = n.get("settings_rev") or 0, n.get("settings_applied_rev")
        lag_s = (now - n["settings_changed_at"]) if n.get("settings_changed_at") and (done is None or done < rev) else None
        state = "rejected" if rej else st["state"]
        rows.append({"node_id": n["node_id"], "hostname": n["hostname"], "settings_rev": rev, "applied_rev": done,
                     "state": state, "text": st["text"] if not rej else f"Refused {len(rej)} key{'s' if len(rej) != 1 else ''}: "
                     + "; ".join(f"{x['key']} ({x['reason']})" for x in rej),
                     "tone": "bad" if rej else st["tone"], "lag_s": lag_s, "rejected": rej,
                     "online": bool(n.get("last_heartbeat_at") and now - n["last_heartbeat_at"] < 30.0),
                     "managed": [{"key": k, "value": v, "value_text": R.show(k, v), "label": R.REGISTRY[k].label,
                                  "binds": any(b["key"] == k for b in binding)} for k, v in sorted(mg["values"].items())
                                 if k in R.REGISTRY],
                     "managed_by": mg["by"], "managed_refused": mg["refused"]})
    drifting = [x for x in rows if x["state"] != "applied"]
    managed = [x for x in rows if x["managed"]]
    summary = (f"{len(drifting)} of {len(rows)} node{'s' if len(rows) != 1 else ''} do not run their latest settings"
               if drifting else f"Every node runs its latest settings ({len(rows)})")
    if managed:
        summary += f"; managed policy tightens settings on {len(managed)}"
    return {"nodes": rows, "drifting": [x["hostname"] for x in drifting], "managed": [x["hostname"] for x in managed],
            "summary": summary}
