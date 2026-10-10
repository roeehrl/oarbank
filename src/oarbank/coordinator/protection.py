"""Owner-set protection on the coordinator (PLAN D3, D20; docs/design/protection.md): protection on the settings chain,
the live match preview against the processes the node reported, the history of each node's effective protection, and
probe requests.

Protection is three settings (docs/design/settings.md, "Protection on the chain"), set at the fleet, a group or a node:

- `protection.mode`: fleet_first, moderate or strict_yield; the most specific value wins, and a fleet or group value
  may lock it;
- `protection.rules`: protected-process rules; every scope's rules apply together (union: a rule only ever protects
  more), so a rule moves to the fleet instead of being copied to every node; rule ids are unique on a node;
- `protection.node`: the rest of the node section (memory guard, timing, GPU jobs, pause limit); the most specific
  value wins.

The coordinator assembles each node's effective section from them (`assemble`) and sends it in the agent's policy,
under the node's settings revision; a rule the node's OS cannot run (a macOS code-signing matcher on Linux) is skipped
there and named. The agent still unions it with its local protection file, strictest wins. Each change of a node's
effective section appends a row to `protection_versions`, its history. To roll rules out, add them to a group first
(a canary group) and promote them to the fleet (`settings.promote`); a scope's own rules are edited as one protection
section (`protection.rules.update`: a node, `fleet` or `group:<group>`).

The preview's matcher (oarbank.contracts.protection_match) is held equal to the agent's by shared test vectors; after
apply, the agent's own match sets are the authority.
"""
import hashlib
import json
import time

from ..common import canonical_json
from ..contracts import protection as P
from ..contracts import protection_match as PM
from .db import DB, jl

PROCESSES_FRESH_S = 60        # older than this, a preview asks the agent for a fresh process summary
KEYS = ("protection.mode", "protection.rules", "protection.node")
DEFAULT = {"schema": 1, "node": {"mode": P.DEFAULT_MODE}, "rule": []}


class ProtectionError(ValueError):
    pass


def resource_key(nid: str) -> str:
    return f"node:{nid}:protection"


def config_hash(config: dict) -> str:
    return hashlib.sha256(canonical_json(config).encode()).hexdigest()[:16]


def validate(config: dict, os: str | None = None) -> dict:
    """Check against schema 1, and against what a node of `os` can do when given (contracts.protection.refusals),
    and return the config as written."""
    if not isinstance(config, dict):
        raise ProtectionError("the protection config must be an object")
    try:
        P.ProtectionConfig.model_validate(config)
    except ValueError as e:
        raise ProtectionError(str(e)[:800])
    refused = P.refusals(config, os) if os else []
    if refused:
        raise ProtectionError(f"on {os}: " + "; ".join(refused)[:800])
    return config


def check_kind(kind: str, v, where: str):
    """The registry's check of a protection setting's value (registry.py, x-kind): `protection_rules` a list of rules
    with unique ids, `protection_node` the node section without its mode (that is protection.mode)."""
    from .settings.registry import SettingError
    if kind == "protection_rules":
        if not isinstance(v, list):
            raise SettingError("bad_type", f"{where}: expected a list of rules")
        try:
            P.ProtectionConfig.model_validate({"schema": 1, "rule": v})
        except ValueError as e:
            raise SettingError("bad_value", f"{where}: {str(e)[:600]}")
        return v
    if not isinstance(v, dict):
        raise SettingError("bad_type", f"{where}: expected an object (the node section)")
    if "mode" in v:
        raise SettingError("bad_value", f"{where}: the mode is its own setting (protection.mode)")
    try:
        P.NodeSection.model_validate(v)
    except ValueError as e:
        raise SettingError("bad_value", f"{where}: {str(e)[:600]}")
    return v


def node_os(db: DB, nid: str) -> str | None:
    n = db.one("SELECT os FROM nodes WHERE node_id=?", (nid,))
    return n["os"] if n else None


# ------------------------------------------------------------------ the chain

def assemble(snap, node: dict) -> dict:
    """A node's effective protection: {"config", "sources" (rule id -> the scope that set it), "mode_source",
    "skipped" (rules its OS cannot run: [{rule, source, why}]), "conflicts" (a rule id set at two scopes)}."""
    from .settings import registry as R, resolve as V
    mode = V.resolve(snap, node, "protection.mode")
    sec = V.resolve(snap, node, "protection.node")["value"] or {}
    os = node.get("os") or ((V.facts_of(node).get("platform") or {}).get("os"))
    rules, sources, skipped, conflicts = [], {}, [], []
    for lay in V.chain(snap, node, R.get("protection.rules")):
        if not lay["set"]:
            continue
        for r in lay["value"] or []:
            rid = r.get("id")
            if rid in sources:
                conflicts.append(f"rule {rid} is set at both {sources[rid]} and {lay['name']}: rule ids must be unique "
                                 "on a node (the first applies)")
                continue
            why = P.refusals({"rule": [r]}, os) if os else []
            if why:
                skipped.append({"rule": rid, "source": lay["name"], "why": "; ".join(why)})
                continue
            sources[rid] = lay["name"]
            rules.append(r)
    config = {"schema": 1, "node": {**sec, "mode": mode["value"]}, "rule": rules}
    return {"config": config, "sources": sources, "mode_source": V.badge(mode), "mode_locked_by": mode["locked_by"],
            "skipped": skipped, "conflicts": conflicts}


def effective(snap, node: dict) -> dict:
    return assemble(snap, node)["config"]


def own(snap, scope: str, sid: str) -> dict:
    """What one scope sets itself, as one protection section (the editor's text): its rules, its node section and
    its mode when it sets one."""
    get = lambda k: (snap.get(scope, sid, "", k) or {}).get("value")
    sec = dict(get("protection.node") or {})
    if get("protection.mode") is not None:
        sec["mode"] = get("protection.mode")
    return {"schema": 1, **({"node": sec} if sec else {}), "rule": list(get("protection.rules") or [])}


def changes_for(snap, scope: str, sid: str, config: dict) -> list[dict]:
    """A scope's own protection section as a change set: its mode, rules and node section each set, or reset when
    the section leaves them out (only where the scope set them)."""
    sec = dict(config.get("node") or {})
    mode = sec.pop("mode", None)
    rules = config.get("rule") if "rule" in config else config.get("rules") or []
    out = []
    for key, value in (("protection.mode", mode), ("protection.rules", rules or None), ("protection.node", sec or None)):
        base = {"scope": scope, "scope_id": sid, "key": key}
        if value is not None:
            out.append({**base, "value": value})
        elif snap.get(scope, sid, "", key) is not None:
            out.append({**base, "reset": True})
    return out


def chain_errors(snap, node: dict) -> list[str]:
    """Errors of a node's merged protection (apply.plan refuses a change that introduces one): a rule id set at two
    scopes."""
    return assemble(snap, node)["conflicts"]


def scope_of(db: DB, target: str | None) -> tuple[str, str]:
    """(scope, scope id) of a protection target: `fleet`, `group:<group>` (id or name), else a node (id or name)."""
    t = (target or "").strip()
    if t == "fleet":
        return "fleet", ""
    if t.startswith("group:"):
        from .settings.groups import find
        g = find(db, t[6:])
        if g is None:
            raise ProtectionError(f"no group {t[6:]!r}")
        return "group", g["id"]
    n = db.one("SELECT node_id FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (t, t))
    if not n:
        raise ProtectionError(f"no node {t!r}")
    return "node", n["node_id"]


def current(db: DB, nid: str) -> tuple[int, dict]:
    """(the latest history version, the node's effective protection now)."""
    from .settings import resolve as V
    r = db.one("SELECT MAX(version) v FROM protection_versions WHERE node_id=?", (nid,))
    n = db.one("SELECT * FROM nodes WHERE node_id=?", (nid,))
    return (r["v"] or 0) if r else 0, effective(V.snapshot(db), n) if n else json.loads(json.dumps(DEFAULT))


def history(db: DB, nid: str, limit: int = 50) -> list[dict]:
    rows = db.q("SELECT version, config_json, config_hash, actor, reason, source, created_at FROM protection_versions "
                "WHERE node_id=? ORDER BY version DESC LIMIT ?", (nid, limit))
    for r in rows:
        r["config"] = json.loads(r.pop("config_json"))
    return rows


def record_version(db: DB, nid: str, config: dict, actor: str, reason: str | None, source: str) -> int:
    """Append a history row (inside the caller's transaction)."""
    top = db.one("SELECT MAX(version) v FROM protection_versions WHERE node_id=?", (nid,))["v"] or 0
    db.x("INSERT INTO protection_versions(node_id,version,config_json,config_hash,actor,reason,source,created_at) "
         "VALUES(?,?,?,?,?,?,?,?)", (nid, top + 1, json.dumps(config), config_hash(config), actor, reason, source, time.time()))
    return top + 1


def record_if_changed(db: DB, nid: str, config: dict, rev: int | None, actor: str | None = None) -> int | None:
    """Append a history row when a node's effective protection changed (apply.sync_nodes): the first row only once it
    differs from the default."""
    top = db.one("SELECT config_json FROM protection_versions WHERE node_id=? ORDER BY version DESC LIMIT 1", (nid,))
    was = json.loads(top["config_json"]) if top else DEFAULT
    if canonical_json(was) == canonical_json(config):
        return None
    v = record_version(db, nid, config, actor or "settings", None, f"settings rev {rev}" if rev else "settings")
    db.event("protection_changed", actor=actor or "settings", node_id=nid, reason=f"version {v}")
    return v


def write(db: DB, target: str, config: dict, actor: str, reason: str | None) -> dict:
    """Set a scope's own protection section (inside the caller's transaction): one settings change set."""
    from .settings import apply as A, resolve as V
    scope, sid = scope_of(db, target)
    validate(config, node_os(db, sid) if scope == "node" else None)
    changes = changes_for(V.snapshot(db), scope, sid, config)
    if not changes:
        return {"rev": None, "message": "nothing changed"}
    return A.commit(db, changes, actor, reason)


def set_mode(db: DB, nid: str, mode: str, actor: str, reason: str | None) -> dict:
    from .settings import apply as A
    return A.commit(db, [{"scope": "node", "scope_id": nid, "key": "protection.mode", "value": mode}], actor, reason)


# ------------------------------------------------------------------ what the node cannot read now

def runtime_conditions(tel: dict) -> list[dict]:
    """What protection cannot read or do on a node right now, from its telemetry (the agent reports it; the config
    already refused what its OS can never do): each with its code, tone, the reason code's values and a message.
    The fail-safe defaults apply meanwhile, and these say which."""
    out = []
    prot = tel.get("protection") or {}
    front = prot.get("front") or ""
    if front.startswith("unknown"):
        why = front.removeprefix("unknown: ")
        out.append({"code": "PROTECTION_FRONT_UNKNOWN", "tone": "warn", "values": {"why": why},
                    "message": f"the front app cannot be read here ({why}); frontmost rules count it as in front"})
    presence = tel.get("presence") or ""
    if presence.startswith("unknown"):
        why = presence.removeprefix("unknown: ")
        out.append({"code": "PROTECTION_PRESENCE_UNKNOWN", "tone": "warn", "values": {"why": why},
                    "message": f"whether someone is at the machine cannot be read ({why}); it counts as someone present"})
    for r in prot.get("rules") or []:
        if r.get("unreadable"):
            out.append({"code": "PROTECTION_UNREADABLE", "tone": "acc", "values": {"rule": r["id"], "n": r["unreadable"]},
                        "message": f"rule {r['id']} matched {r['unreadable']} processes whose path or arguments could not be "
                                   "read (counted as matches)"})
    for rule in prot.get("no_instruction_counters") or []:
        out.append({"code": "PROTECTION_NO_IPC_COUNTERS", "tone": "warn", "values": {"rule": rule},
                    "message": f"rule {rule} protects ipc_ratio, but this node's processes have no instruction or cycle "
                               "counters (a virtual machine): the metric is unknown and the fleet's CPU budget does not grow"})
    if prot.get("lowering") is False:
        out.append({"code": "PROTECTION_NO_LOWERING", "tone": "warn", "values": {},
                    "message": "this node cannot lower fleet jobs (no delegated cgroup with the cpu controller): pausable "
                               "jobs are paused instead"})
    if prot.get("source_error"):
        out.append({"code": "PROTECTION_SOURCE_ERROR", "tone": "bad", "values": {"error": prot["source_error"]},
                    "message": f"the process table cannot be read: {prot['source_error']}"})
    return out


# ------------------------------------------------------------------ preview

diff = PM.diff


def processes(db: DB, nid: str) -> tuple[list[dict], float | None]:
    n = db.one("SELECT processes_json, processes_at FROM nodes WHERE node_id=?", (nid,))
    if not n:
        return [], None
    return jl(n["processes_json"], []) or [], n["processes_at"]


def request_processes(db: DB, nid: str):
    db.x("UPDATE nodes SET want_processes=1 WHERE node_id=?", (nid,))


def preview_doc(r, nid: str, config: dict) -> dict:
    """What this node's own protection section would do now (a pure read): the diff of its effective protection (the
    inherited rules stay), each effective rule's live matches among the reported processes, and their age."""
    from .settings import apply as A, resolve as V
    node = r.one("SELECT * FROM nodes WHERE node_id=? OR hostname=?", (nid, nid))
    if not node:
        raise ProtectionError(f"node {nid} not found")
    cfg = validate(config, node.get("os"))
    snap = V.snapshot(r)
    before = effective(snap, node)
    changes = changes_for(snap, "node", node["node_id"], cfg)
    try:
        after_snap = A._after(snap, A.normalize(r, changes)) if changes else snap
    except A.ApplyError as e:
        raise ProtectionError("; ".join(x.get("message") or "" for x in e.errors) or e.detail)
    after = assemble(after_snap, node)
    if after["conflicts"]:
        raise ProtectionError("; ".join(after["conflicts"]))
    ver = (r.one("SELECT MAX(version) v FROM protection_versions WHERE node_id=?", (node["node_id"],)) or {}).get("v") or 0
    procs = jl(node.get("processes_json"), []) or []
    at = node.get("processes_at")
    return {"node_id": node["node_id"], "base_version": ver, "diff": diff(before, after["config"]),
            "matches": PM.preview(after["config"], procs),
            "inherited": [f"{rid} ({src})" for rid, src in after["sources"].items() if src != "This node"],
            "skipped": [f"{x['rule']} ({x['source']}): {x['why']}" for x in after["skipped"]],
            "processes_reported": len(procs), "processes_age_s": None if at is None else round(time.time() - at, 1),
            "note": "Matches are computed on the coordinator from the node's last process summary, with the same matcher "
                    "the agent uses (shared test vectors); after apply the agent's own match sets are authoritative."}


def preview(db: DB, nid: str, config: dict) -> dict:
    """preview_doc, and a stale process summary asks the agent for a fresh one."""
    out = preview_doc(db, nid, config)
    if out["processes_age_s"] is None or out["processes_age_s"] > PROCESSES_FRESH_S:
        request_processes(db, out["node_id"])
    return out


# ------------------------------------------------------------------ hoisting per-node sections onto the chain

def hoist(db: DB, configs: dict, rev: int, actor: str = "migration") -> dict:
    """Per-node protection sections (the old store: one copy per node) as settings values: what every node has in
    common goes to the fleet (its mode, each rule every node has, its node section), the rest stays on each node.
    Sections the schema refuses are dropped and named. Returns a report."""
    from .settings import store
    comment = "hoisted from the per-node protection sections"
    report = {"fleet": [], "node": [], "dropped": []}
    ok = {}
    for nid, cfg in configs.items():
        try:
            ok[nid] = validate(cfg or {})
        except ProtectionError as e:
            report["dropped"].append(f"{nid}: {e}")
    if not ok:
        return report
    secs = {nid: dict(c.get("node") or {}) for nid, c in ok.items()}
    modes = {nid: s.pop("mode", P.DEFAULT_MODE) for nid, s in secs.items()}
    rules = {nid: list(c.get("rule") or c.get("rules") or []) for nid, c in ok.items()}
    canon = lambda x: canonical_json(x)
    if len(set(modes.values())) == 1:
        m = next(iter(modes.values()))
        if m != P.DEFAULT_MODE:
            store.put(db, "fleet", "", "", "protection.mode", m, actor, rev, comment)
            report["fleet"].append(f"protection.mode {m}")
    else:
        for nid, m in modes.items():
            if m != P.DEFAULT_MODE:
                store.put(db, "node", nid, "", "protection.mode", m, actor, rev, comment)
                report["node"].append(f"{nid}: protection.mode {m}")
    common = [r for r in next(iter(rules.values())) if all(canon(r) in {canon(x) for x in rs} for rs in rules.values())]
    if common:
        store.put(db, "fleet", "", "", "protection.rules", common, actor, rev, comment)
        report["fleet"].append("protection.rules " + ", ".join(r["id"] for r in common))
    keep = {canon(r) for r in common}
    for nid, rs in rules.items():
        mine = [r for r in rs if canon(r) not in keep]
        if mine:
            store.put(db, "node", nid, "", "protection.rules", mine, actor, rev, comment)
            report["node"].append(f"{nid}: protection.rules " + ", ".join(r["id"] for r in mine))
    if len({canon(s) for s in secs.values()}) == 1:
        sec = next(iter(secs.values()))
        if sec:
            store.put(db, "fleet", "", "", "protection.node", sec, actor, rev, comment)
            report["fleet"].append("protection.node")
    else:
        for nid, sec in secs.items():
            if sec:
                store.put(db, "node", nid, "", "protection.node", sec, actor, rev, comment)
                report["node"].append(f"{nid}: protection.node")
    return report


def migrate(db: DB) -> dict | None:
    """A home whose nodes still hold their own protection section (`nodes.protection_json`): hoisted onto the chain
    once, then the column is dropped (its history stays in protection_versions)."""
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(nodes)")}
    if "protection_json" not in cols:
        return None
    from .settings import store
    with db.tx():
        rev = store.next_rev(db)
        configs = {n["node_id"]: jl(n["protection_json"], None) for n in db.q(
            "SELECT node_id, protection_json FROM nodes WHERE lifecycle!='retired' AND protection_json IS NOT NULL")}
        report = hoist(db, {k: v for k, v in configs.items() if v}, rev)
        db.conn.execute("ALTER TABLE nodes DROP COLUMN protection_json")
        from .settings.apply import sync_nodes
        sync_nodes(db, rev_=rev)
        db.event("protection_hoisted", reason=f"{len(report['fleet'])} fleet values, {len(report['node'])} node values, "
                                              f"{len(report['dropped'])} dropped", **report)
    return report


# ------------------------------------------------------------------ probe

def request_probe(db: DB, nid: str, actor: str):
    db.x("UPDATE nodes SET want_probe=1 WHERE node_id=?", (nid,))
    db.event("protection_probe_requested", actor=actor, node_id=nid)


# ------------------------------------------------------------------ status (`oarbank protection show`)

def status(db: DB, ident: str, history_limit: int = 20) -> dict | None:
    """A node's protection as the console's protection page shows it: its effective section with where each rule and
    the mode come from, the rules skipped on its OS, its own section (what the editor edits), the history, what the
    agent reports live (active rules, controller, guard) and what protection cannot read or do there now. By node id
    or hostname."""
    from .settings import resolve as V
    n = db.one("SELECT * FROM nodes WHERE node_id=? OR hostname=?", (ident, ident))
    if not n:
        return None
    snap = V.snapshot(db)
    a = assemble(snap, n)
    ver = (db.one("SELECT MAX(version) v FROM protection_versions WHERE node_id=?", (n["node_id"],)) or {}).get("v") or 0
    tel = jl(n["telemetry_json"], {}) or {}
    hist = [{"version": h["version"], "created_at": h["created_at"], "actor": h["actor"], "source": h["source"],
             "reason": h["reason"], "rules": [x.get("id") for x in h["config"].get("rule") or []],
             "mode": (h["config"].get("node") or {}).get("mode", "moderate")} for h in history(db, n["node_id"], history_limit)]
    return {"node_id": n["node_id"], "hostname": n["hostname"], "version": ver, "config": a["config"],
            "mode": a["config"]["node"]["mode"], "mode_source": a["mode_source"],
            "mode_locked_by": (a["mode_locked_by"] or {}).get("name"), "sources": a["sources"], "skipped": a["skipped"],
            "conflicts": a["conflicts"], "own": own(snap, "node", n["node_id"]), "history": hist,
            "live": tel.get("protection") or {}, "guard": tel.get("guard"), "conditions": runtime_conditions(tel)}


# ------------------------------------------------------------------ alerts (from the journals)

FLAP_MAX_PER_HOUR = 12        # lower/pause escalations per node-hour (judgement; docs/design/protection.md)
PROBE_HARM_MAX = 0.25         # a pause probe that shows the protected process losing over 25 % throughput


def check_alerts(db: DB, now: float):
    from . import core
    for n in db.q("SELECT node_id, hostname FROM nodes WHERE lifecycle NOT IN ('retired')"):
        nid = n["node_id"]
        ups = 0
        for r in db.q("SELECT record_json FROM protection_decisions WHERE node_id=? AND kind='rung_change' AND t>=?",
                      (nid, now - 3600)):
            rec = json.loads(r["record_json"] or "{}")
            if (rec.get("to") or 0) > (rec.get("from") or 0):
                ups += 1
        if ups > FLAP_MAX_PER_HOUR:
            core._alert(db, "protection_flapping", nid, f"{n['hostname']}: {ups} lower/pause escalations in the last hour "
                        f"(limit {FLAP_MAX_PER_HOUR}); a rule's thresholds or timing oscillate")
        elif ups <= FLAP_MAX_PER_HOUR // 2:
            core._resolve_alert(db, "protection_flapping", nid)
        harm = [json.loads(r["record_json"] or "{}").get("signals", {}).get("harm") or 0
                for r in db.q("SELECT record_json FROM protection_decisions WHERE node_id=? AND kind='probe_result' AND t>=?",
                              (nid, now - 3600))]
        if harm and max(harm) > PROBE_HARM_MAX:
            core._alert(db, "protection_probe_harm", nid, f"{n['hostname']}: a pause probe measured {max(harm):.0%} harm to a "
                        "protected process; the fleet is holding it back (consider strict_yield or a tighter rule)")
        elif not harm or max(harm) <= PROBE_HARM_MAX / 2:
            core._resolve_alert(db, "protection_probe_harm", nid)
