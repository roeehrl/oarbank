"""Owner-set protection on the coordinator (PLAN D3, D20; docs/design/protection.md): immutable rule-set versions per node,
the live match preview against the processes the node reported, canary-then-promote, and probe requests.

The node policy's "protection" section stays the copy the agent reads; every change to it goes through
`write_version`, which appends a version row first, so the history is complete and a restore is just a new
version with old content. The preview's matcher (oarbank.contracts.protection_match) is held equal
to the agent's by shared test vectors; after apply, the agent's own match sets are the authority.
"""
import hashlib
import json
import time

from ..common import canonical_json
from ..contracts import protection as P
from ..contracts import protection_match as PM
from .db import DB, jl

PROCESSES_FRESH_S = 60        # older than this, a preview asks the agent for a fresh process summary
CANARY_MIN_SOAK_S = 600       # a canary must run this long, cleanly, before promotion


class ProtectionError(ValueError):
    pass


def resource_key(nid: str) -> str:
    return f"node:{nid}:protection"


def config_hash(config: dict) -> str:
    return hashlib.sha256(canonical_json(config).encode()).hexdigest()[:16]


def validate(config: dict, os: str | None = None) -> dict:
    """Check against schema 1, and against what a node of `os` can do when given (contracts.protection.refusals),
    and return the config as written (stored verbatim, so diffs stay minimal)."""
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


def node_os(db: DB, nid: str) -> str | None:
    n = db.one("SELECT os FROM nodes WHERE node_id=?", (nid,))
    return n["os"] if n else None


def current(db: DB, nid: str) -> tuple[int, dict]:
    """(version number, config). Version 0 is the policy's section before any versioned edit."""
    r = db.one("SELECT version, config_json FROM protection_versions WHERE node_id=? ORDER BY version DESC LIMIT 1", (nid,))
    if r:
        return r["version"], json.loads(r["config_json"])
    n = db.one("SELECT policy_json FROM nodes WHERE node_id=?", (nid,))
    return 0, (jl(n["policy_json"], {}) or {}).get("protection") or {} if n else {}


def history(db: DB, nid: str, limit: int = 50) -> list[dict]:
    rows = db.q("SELECT version, config_json, config_hash, actor, reason, source, created_at FROM protection_versions "
                "WHERE node_id=? ORDER BY version DESC LIMIT ?", (nid, limit))
    for r in rows:
        r["config"] = json.loads(r.pop("config_json"))
    return rows


def record_version(db: DB, nid: str, config: dict, actor: str, reason: str | None, source: str) -> int:
    """Append a version row (inside the caller's transaction). Called by core.set_policy for every change
    to the protection section, whatever route made it."""
    top = db.one("SELECT MAX(version) v FROM protection_versions WHERE node_id=?", (nid,))["v"] or 0
    db.x("INSERT INTO protection_versions(node_id,version,config_json,config_hash,actor,reason,source,created_at) "
         "VALUES(?,?,?,?,?,?,?,?)", (nid, top + 1, json.dumps(config), config_hash(config), actor, reason, source, time.time()))
    return top + 1


def write_version(db: DB, nid: str, config: dict, actor: str, reason: str | None, source: str = "rules.update") -> int:
    from . import core
    config = validate(config, node_os(db, nid))
    core.set_policy(db, nid, {"protection": config}, actor, reason=reason, source=source)
    return current(db, nid)[0]


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


def preview(db: DB, nid: str, config: dict) -> dict:
    """What a rule set would do on this node now: the diff against the current version, each rule's live
    matches among the reported processes, and the reported processes' age (a stale summary asks for a new one)."""
    cfg = validate(config, node_os(db, nid))
    ver, cur = current(db, nid)
    procs, at = processes(db, nid)
    age = None if at is None else round(time.time() - at, 1)
    if age is None or age > PROCESSES_FRESH_S:
        request_processes(db, nid)
    return {"node_id": nid, "base_version": ver, "diff": diff(cur, cfg), "matches": PM.preview(cfg, procs),
            "processes_reported": len(procs), "processes_age_s": age,
            "note": "Matches are computed on the coordinator from the node's last process summary; after apply the "
                    "agent's own match sets are authoritative (shown on the node page)."}


# ------------------------------------------------------------------ canary

CANARY_KEY = "protection_canary"


def start_canary(db: DB, nid: str, config: dict, actor: str, reason: str | None) -> dict:
    cfg = validate(config, node_os(db, nid))
    v = write_version(db, nid, cfg, actor, reason, source="rules.canary")
    c = {"node_id": nid, "config_hash": config_hash(cfg), "config": cfg, "version": v, "started_at": time.time(),
         "actor": actor}
    db.set_setting(CANARY_KEY, c)
    db.event("protection_canary", actor=actor, node_id=nid, version=v, config_hash=c["config_hash"])
    return c


def canary_health(db: DB) -> dict:
    """Is the running canary fit to promote? Soaked long enough, node heartbeating, no S16/S18 findings or
    refused actuations on it since it started."""
    from . import invariants
    c = db.get_setting(CANARY_KEY)
    if not c:
        return {"canary": None, "promotable": False, "why": ["no canary running"]}
    why, t0 = [], c["started_at"]
    soak = time.time() - t0
    if soak < CANARY_MIN_SOAK_S:
        why.append(f"soaking: {int(soak)} of {CANARY_MIN_SOAK_S} s")
    n = db.one("SELECT last_heartbeat_at, lifecycle FROM nodes WHERE node_id=?", (c["node_id"],))
    if not n or (n["last_heartbeat_at"] or 0) < time.time() - 120:
        why.append("the canary node is not heartbeating")
    if current(db, c["node_id"])[1] and config_hash(current(db, c["node_id"])[1]) != c["config_hash"]:
        why.append("the canary node's rules changed since the canary started")
    refused = db.one("SELECT COUNT(*) n FROM protection_decisions WHERE node_id=? AND t>=? AND kind='actuation_refused'",
                     (c["node_id"], t0))["n"]
    if refused:
        why.append(f"{refused} refused actuation(s) on the canary node")
    bad = [v for v in invariants.s16_actuation_only_on_spawned(db) + invariants.s18_rules_enforced(db, since=t0)
           if f"node {c['node_id']} " in v]
    why += bad[:5]
    return {"canary": {k: v for k, v in c.items() if k != "config"}, "promotable": not why, "why": why, "soak_s": int(soak)}


def promote_targets(db: DB, c: dict) -> tuple[list[str], dict[str, str]]:
    """The nodes a canary's rules go to, and those skipped because their OS cannot run them (node -> why)."""
    targets, skipped = [], {}
    for r in db.q("SELECT node_id, os FROM nodes WHERE lifecycle!='retired' AND node_id!=? ORDER BY node_id", (c["node_id"],)):
        refused = P.refusals(c["config"], r["os"]) if r["os"] else []
        if refused:
            skipped[r["node_id"]] = f"on {r['os']}: " + "; ".join(refused)
        else:
            targets.append(r["node_id"])
    return targets, skipped


def promote(db: DB, actor: str, reason: str | None, force: bool = False) -> dict:
    h = canary_health(db)
    if not h["promotable"] and not force:
        raise ProtectionError("canary not promotable: " + "; ".join(h["why"]))
    c = db.get_setting(CANARY_KEY)
    targets, skipped = promote_targets(db, c)
    done = {nid: write_version(db, nid, c["config"], actor, reason, source="rules.promote") for nid in targets}
    db.set_setting(CANARY_KEY, None)
    db.event("protection_promoted", actor=actor, node_id=c["node_id"], config_hash=c["config_hash"], nodes=sorted(done),
             skipped=sorted(skipped))
    return {"promoted": done, "skipped": skipped, "config_hash": c["config_hash"]}


# ------------------------------------------------------------------ mode and probe

def set_mode(db: DB, nid: str, mode: str, actor: str, reason: str | None) -> int:
    _, cur = current(db, nid)
    cfg = json.loads(json.dumps(cur or {"schema": 1}))
    cfg.setdefault("node", {})["mode"] = mode
    return write_version(db, nid, cfg, actor, reason, source="mode.set")


def request_probe(db: DB, nid: str, actor: str):
    db.x("UPDATE nodes SET want_probe=1 WHERE node_id=?", (nid,))
    db.event("protection_probe_requested", actor=actor, node_id=nid)


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
