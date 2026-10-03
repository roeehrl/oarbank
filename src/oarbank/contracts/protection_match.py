"""The rule-preview matcher (PLAN D20): the Python equivalent of the agent's matcher (rust/crates/oarbank-protection),
used by the console's live preview against the processes a node reported. The two are kept equivalent by shared test
vectors (fixtures/protection-match-vectors.json, loaded by both test suites); the agent's own match sets remain the
authority."""
import json
import re
from pathlib import Path

VECTORS = Path(__file__).parent / "fixtures" / "protection-match-vectors.json"


def matches(p: dict, m: dict) -> bool:
    if m.get("requirement") and m["requirement"] not in (p.get("requirements_met") or []):
        return False
    if m.get("team_id") and p.get("team_id") != m["team_id"]:
        return False
    if m.get("identifier") and p.get("signing_id") != m["identifier"]:
        return False
    bundles = m.get("bundle_id")
    if bundles:
        bundles = [bundles] if isinstance(bundles, str) else bundles
        if p.get("bundle_id") not in bundles:
            return False
    if m.get("path_prefix") and not (p.get("path") or "").startswith(m["path_prefix"]):
        return False
    if m.get("path_contains"):
        line = " ".join([p.get("path") or ""] + list((p.get("argv") or [])[1:]))
        if m["path_contains"] not in line:
            return False
    if m.get("name"):
        comm = p.get("comm") or (p.get("path") or "").rsplit("/", 1)[-1]
        if comm != m["name"]:
            return False
    if m.get("argv_regex"):
        if p.get("argv") is None or not re.search(m["argv_regex"], " ".join(p["argv"])):
            return False
    return True


def group(procs: list[dict], match: dict, tree: str = "self") -> list[dict]:
    direct = [p for p in procs if matches(p, match)]
    if not direct:
        return []
    key = lambda p: (p["pid"], p.get("start_us", 0))
    if tree == "self":
        return sorted(direct, key=lambda p: p["pid"])
    if tree == "same_team":
        teams = {p.get("team_id") for p in direct if p.get("team_id")}
        keys = {key(p) for p in direct}
        return sorted([p for p in procs if key(p) in keys or (p.get("team_id") in teams)], key=lambda p: p["pid"])
    children: dict = {}
    for p in procs:
        children.setdefault(p.get("ppid"), []).append(p)
    out, stack = {}, list(direct)
    while stack:
        p = stack.pop()
        if key(p) in out:
            continue
        out[key(p)] = p
        stack += [c for c in children.get(p["pid"], []) if c.get("start_us", 0) >= p.get("start_us", 0) and c["pid"] != p["pid"]]
    return sorted(out.values(), key=lambda p: p["pid"])


def _canon(x) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"))


def diff(old: dict, new: dict) -> dict:
    """Rule-level change summary between two protection sections."""
    o = {r["id"]: r for r in (old.get("rule") or [])}
    n = {r["id"]: r for r in (new.get("rule") or [])}
    return {"rules_added": sorted(set(n) - set(o)), "rules_removed": sorted(set(o) - set(n)),
            "rules_changed": sorted(k for k in set(o) & set(n) if _canon(o[k]) != _canon(n[k])),
            "node_changed": _canon(old.get("node") or {}) != _canon(new.get("node") or {}),
            "mode": {"from": (old.get("node") or {}).get("mode"), "to": (new.get("node") or {}).get("mode")}}


def preview(config: dict, procs: list[dict]) -> list[dict]:
    """Per rule: which reported processes it would protect right now."""
    return [{"rule": r["id"], "processes": [{"pid": p["pid"], "path": p.get("path"), "bundle_id": p.get("bundle_id")}
                                            for p in group(procs, r.get("match") or {}, r.get("tree", "self"))]}
            for r in (config.get("rule") or config.get("rules") or [])]


def suggest(p: dict) -> dict:
    """The strongest match for one reported process (the picker's "protect this"): the code-signing team and
    bundle survive updates and relocation; a path prefix is the fallback for unsigned tools."""
    m: dict = {}
    if p.get("team_id"):
        m["team_id"] = p["team_id"]
    if p.get("bundle_id"):
        m["bundle_id"] = [p["bundle_id"]]
    elif p.get("signing_id") and p.get("team_id"):
        m["identifier"] = p["signing_id"]
    if not m:
        path = p.get("path") or ""
        app = path.find(".app/")
        m["path_prefix"] = path[:app + 5] if app > 0 else path
    return m


def suggest_rule(p: dict, existing_ids: set | None = None) -> dict:
    base = re.sub(r"[^a-z0-9]+", "-", ((p.get("bundle_id") or (p.get("path") or "proc").rsplit("/", 1)[-1]).lower()))
    base = base.strip("-")[:48] or "proc"
    rid, k = base, 2
    while existing_ids and rid in existing_ids:
        rid, k = f"{base}-{k}", k + 1
    return {"id": rid, "match": suggest(p), "tree": "same_team" if p.get("team_id") else "descendants",
            "reserve": {"cpu": "peak(60s).cpu", "mem_gb": "peak(300s).footprint * 1.2"}}
