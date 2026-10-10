"""Node groups and labels (docs/design/settings.md, "Groups and labels").

A group is a named selector over node facts and labels, plus an optional list of explicit members, with a unique rank:
a node in several groups resolves a key by rank (the highest-ranked group that sets it wins), and the explain view names
the groups that lost. Built-in groups (one per OS and the coordinator's own machine) have system-defined membership and
the lowest ranks; owner groups rank from store.OWNER_RANK_MIN up, and a new one goes on top.

Membership is evaluated on the coordinator whenever values are resolved, from the node's facts and labels, so a node
whose facts or labels change moves at once, and a node that leaves a group falls back to the next layer down (no stale
copies). A node is a member when it is listed explicitly, or when the group's selector is not empty and every one of
its terms holds:

| term | holds when |
|---|---|
| `os` | the node's OS is this one (or one of these): darwin (macOS), linux, windows |
| `arch` | its architecture is this one (or one of these): arm64, amd64 |
| `labels` | it carries every one of these labels |
| `hostname` | its name matches this glob (or one of these), ignoring case: `mac-*`, `*.lab` |
| `battery` | it has a battery (true) or not (false), as its agent reports (facts `power.battery`) |
| `ram_gb_min`, `ram_gb_max` | its RAM is at least / at most this |
| `cores_min` | it has at least this many CPU cores |

Labels are short owner-set words on a node (`node_labels`), set with `nodes.label` from the console or the CLI. The
coordinator adds labels derived from the node's facts (`laptop` for a node with a battery); those are shown "from
facts" and cannot be removed, only matched. Facts and fact labels come from the node itself: a group that locks a
safety value should select on owner labels, explicit members or the OS, which a node cannot claim for itself (the
coordinator sets the OS from the release it serves the node)."""
import fnmatch
import json
import re
import time

from . import store

LABEL = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,62}$")
GROUP_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
OS_NAMES = {"darwin": "macOS", "linux": "Linux", "windows": "Windows"}
OS_ALIASES = {"macos": "darwin", "mac": "darwin", "osx": "darwin", "darwin": "darwin", "linux": "linux",
              "windows": "windows", "win": "windows"}
ARCHES = {"arm64": "arm64", "aarch64": "arm64", "amd64": "amd64", "x86_64": "amd64", "x64": "amd64"}
SELECTOR_KEYS = ("os", "arch", "labels", "hostname", "battery", "ram_gb_min", "ram_gb_max", "cores_min")
BUILTIN_KEYS = ("coordinator_host", "nodes")      # system-defined membership (built-in groups only)
MAX_MEMBERS, MAX_LABELS = 512, 32


class GroupError(ValueError):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail = status, code, detail


def _facts(node: dict) -> dict:
    if isinstance(node.get("facts"), dict):
        return node["facts"]
    try:
        return json.loads(node.get("facts_json") or "{}") or {}
    except ValueError:
        return {}


# ------------------------------------------------------------------ labels

def fact_labels(facts: dict) -> list[str]:
    """Labels the coordinator derives from a node's facts (shown "from facts", never stored)."""
    out = []
    if ((facts or {}).get("power") or {}).get("battery") is True:
        out.append("laptop")
    return out


def check_label(label) -> str:
    s = str(label or "").strip().lower()
    if not LABEL.fullmatch(s):
        raise GroupError(400, "bad_label", f"{label!r}: a label is 1 to 63 of a-z, 0-9, _ . : - (starting with a letter "
                                           "or digit)")
    return s


def labels_of(owner: dict, node: dict) -> dict:
    """{"owner": [...], "facts": [...], "all": [...]} for a node (`owner`: {node_id: [labels]} from store.labels)."""
    mine = sorted(owner.get(node.get("node_id"), ()))
    derived = [x for x in fact_labels(_facts(node)) if x not in mine]
    return {"owner": mine, "facts": derived, "all": sorted({*mine, *derived})}


def set_labels(db, node_id: str, add=(), remove=(), actor: str = "") -> dict:
    """Add and remove a node's owner labels (inside the caller's transaction); {"added", "removed", "labels"}."""
    add = [check_label(x) for x in add or []]
    remove = [check_label(x) for x in remove or []]
    have = set(store.labels(db).get(node_id, ()))
    added = [x for x in dict.fromkeys(add) if x not in have and x not in remove]
    removed = [x for x in dict.fromkeys(remove) if x in have]
    if len(have) + len(added) - len(removed) > MAX_LABELS:
        raise GroupError(400, "too_many_labels", f"a node carries at most {MAX_LABELS} labels")
    now = time.time()
    for x in added:
        db.x("INSERT OR IGNORE INTO node_labels(node_id,label,set_by,set_at) VALUES(?,?,?,?)", (node_id, x, actor, now))
    for x in removed:
        db.x("DELETE FROM node_labels WHERE node_id=? AND label=?", (node_id, x))
    return {"added": added, "removed": removed, "labels": sorted((have | set(added)) - set(removed))}


# ------------------------------------------------------------------ selectors

def _list(v) -> list:
    return v if isinstance(v, list) else [v]


def check_selector(sel) -> dict:
    """An owner group's selector, normalized (GroupError naming the term that is wrong)."""
    if sel in (None, ""):
        return {}
    if not isinstance(sel, dict):
        raise GroupError(400, "bad_selector", "a selector is an object of terms: os, arch, labels, hostname, battery, "
                                              "ram_gb_min, ram_gb_max, cores_min")
    out = {}
    for k, v in sel.items():
        if k not in SELECTOR_KEYS:
            raise GroupError(400, "bad_selector", f"unknown selector term {k!r} (terms: {', '.join(SELECTOR_KEYS)})")
        if v in (None, "", []):
            continue
        if k == "os":
            vals = [OS_ALIASES.get(str(x).strip().lower()) for x in _list(v)]
            if None in vals:
                raise GroupError(400, "bad_selector", f"os: darwin (macOS), linux or windows, not {v!r}")
            out[k] = vals[0] if len(set(vals)) == 1 else sorted(set(vals))
        elif k == "arch":
            vals = [ARCHES.get(str(x).strip().lower()) for x in _list(v)]
            if None in vals:
                raise GroupError(400, "bad_selector", f"arch: arm64 or amd64, not {v!r}")
            out[k] = vals[0] if len(set(vals)) == 1 else sorted(set(vals))
        elif k == "labels":
            out[k] = sorted({check_label(x) for x in _list(v)})
        elif k == "hostname":
            pats = [str(x).strip().lower() for x in _list(v) if str(x).strip()]
            if not pats or any(len(p) > 253 or not re.fullmatch(r"[a-z0-9*?\[\]._-]+", p) for p in pats):
                raise GroupError(400, "bad_selector", "hostname: a name or a glob of a-z, 0-9, . _ - and * ? [ ]")
            out[k] = pats[0] if len(pats) == 1 else pats
        elif k == "battery":
            if not isinstance(v, bool):
                raise GroupError(400, "bad_selector", "battery: true or false")
            out[k] = v
        else:
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise GroupError(400, "bad_selector", f"{k}: a number, 0 or more")
            out[k] = v
    if "ram_gb_min" in out and "ram_gb_max" in out and out["ram_gb_min"] > out["ram_gb_max"]:
        raise GroupError(400, "bad_selector", "ram_gb_min is above ram_gb_max: no node could match")
    return out


def _term(k: str, want, node: dict, facts: dict, labels: list) -> tuple[bool, str]:
    """(holds, what it says) for one selector term on a node."""
    from ..config import is_coordinator_host
    from ..platforms import cores, memory_gb
    plat = facts.get("platform") or {}
    if k == "os":
        have = node.get("os") or plat.get("os")
        names = " or ".join(OS_NAMES.get(x, x) for x in _list(want))
        return have in _list(want), names
    if k == "arch":
        have = ARCHES.get(str(node.get("arch") or plat.get("arch") or "").lower())
        return have in _list(want), " or ".join(_list(want))
    if k == "labels":
        miss = [x for x in want if x not in labels]
        return not miss, "label " + ", ".join(want) if len(want) == 1 else "labels " + ", ".join(want)
    if k == "hostname":
        name = str(node.get("hostname") or facts.get("hostname") or "").lower()
        short = name.split(".")[0]
        ok = any(fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(short, p) for p in _list(want))
        return ok, "name " + " or ".join(_list(want))
    if k == "battery":
        have = ((facts.get("power") or {}).get("battery") is True)
        return have == want, "has a battery" if want else "no battery"
    if k == "ram_gb_min":
        return memory_gb(facts) >= float(want), f"{want:g} GB of RAM or more"
    if k == "ram_gb_max":
        ram = memory_gb(facts)
        return 0 < ram <= float(want), f"{want:g} GB of RAM or less"
    if k == "cores_min":
        return cores(facts) >= float(want), f"{want:g} cores or more"
    if k == "coordinator_host":
        return bool(is_coordinator_host(facts)) == bool(want), "the coordinator's own machine"
    if k == "nodes":
        return node.get("node_id") in (want or []), "listed"
    return False, f"unknown term {k}"          # a selector this coordinator cannot evaluate matches nothing


def membership(g: dict, node: dict, labels: list | None = None) -> dict:
    """Whether a node belongs to a group and why: {"member", "why": [what holds], "missing": [what does not]}."""
    facts = _facts(node)
    labels = labels if labels is not None else fact_labels(facts)
    if node.get("node_id") in (g.get("members") or []):
        return {"member": True, "why": ["listed as a member"], "missing": []}
    sel = g.get("selector") or {}
    if not sel:
        return {"member": False, "why": [], "missing": ["not listed (the group has no selector)"]}
    why, missing = [], []
    for k, want in sel.items():
        ok, text = _term(k, want, node, facts, labels)
        (why if ok else missing).append(text)
    return {"member": not missing, "why": why, "missing": missing}


def describe(g: dict, names: dict | None = None) -> str:
    """A group's membership rule as a person reads it: "macOS · label laptop · or listed: mini, studio"."""
    parts = []
    for k, want in (g.get("selector") or {}).items():
        if k == "os":
            parts.append(" or ".join(OS_NAMES.get(x, x) for x in _list(want)))
        elif k == "arch":
            parts.append(" or ".join(_list(want)))
        elif k == "labels":
            parts.append(("label " if len(want) == 1 else "labels ") + ", ".join(want))
        elif k == "hostname":
            parts.append("name " + " or ".join(_list(want)))
        elif k == "battery":
            parts.append("has a battery" if want else "no battery")
        elif k == "ram_gb_min":
            parts.append(f"≥ {want:g} GB RAM")
        elif k == "ram_gb_max":
            parts.append(f"≤ {want:g} GB RAM")
        elif k == "cores_min":
            parts.append(f"≥ {want:g} cores")
        elif k == "coordinator_host":
            parts.append("the coordinator's own machine")
        elif k == "nodes":
            parts.append("listed nodes")
    rule = " · ".join(parts)
    members = [(names or {}).get(m, m) for m in g.get("members") or []]
    if members:
        rule = (rule + " · or listed: " if rule else "listed: ") + ", ".join(members)
    return rule or "no members (no selector, nobody listed)"


def groups_of(r, node_id: str) -> list[dict]:
    """The groups one node belongs to, lowest rank first, without reading every setting (secrets resolve with it)."""
    rows = r.q("SELECT node_id, hostname, os, arch, facts_json FROM nodes WHERE node_id=?", (node_id,))
    if not rows:
        return []
    labs = labels_of(store.labels(r), rows[0])["all"]
    return [g for g in store.groups(r) if membership(g, rows[0], labs)["member"]]


# ------------------------------------------------------------------ owner groups

def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")[:48].strip("-")
    return s or "group"


def find(r, ident: str) -> dict | None:
    """A group by id or name (case-insensitive)."""
    for g in store.groups(r):
        if ident and ident.lower() in (g["id"].lower(), g["name"].lower()):
            return g
    return None


def get_owner(r, ident: str) -> dict:
    g = find(r, ident)
    if g is None:
        raise GroupError(404, "unknown_group", f"no group {ident!r} (oarbank groups list)")
    if g["builtin"]:
        raise GroupError(409, "builtin_group", f"{g['name']} is a built-in group: its membership is the system's own "
                                               "(values can still be set on it)")
    return g


def check_members(r, members) -> list[str]:
    """Node ids from ids or names (GroupError for one that is not a node)."""
    if members in (None, ""):
        return []
    if not isinstance(members, list) or len(members) > MAX_MEMBERS:
        raise GroupError(400, "bad_members", f"members: a list of at most {MAX_MEMBERS} nodes (ids or names)")
    out = []
    for m in members:
        x = r.q("SELECT node_id FROM nodes WHERE (node_id=? OR hostname=?) AND lifecycle!='retired'", (str(m), str(m)))
        if not x:
            raise GroupError(404, "unknown_node", f"members: no node {m!r}")
        if x[0]["node_id"] not in out:
            out.append(x[0]["node_id"])
    return sorted(out)


def check_name(r, name, gid: str | None = None) -> str:
    name = str(name or "").strip()
    if not name or len(name) > 64 or any(c in name for c in "\n\r\t<>"):
        raise GroupError(400, "bad_name", "a group's name is 1 to 64 characters")
    for g in store.groups(r):
        if g["id"] != gid and g["name"].lower() == name.lower():
            raise GroupError(409, "name_taken", f"a group named {g['name']!r} exists")
    return name


def spec(r, params: dict, current: dict | None = None) -> dict:
    """A create or update request checked: {id, name, selector, members, description} (an update keeps what it does
    not name)."""
    cur = current or {}
    extra = set(params) - {"id", "name", "selector", "members", "description"}
    if extra:
        raise GroupError(400, "bad_params", f"unknown fields {sorted(extra)} (name, selector, members, description)")
    name = check_name(r, params["name"] if "name" in params else cur.get("name"), cur.get("id"))
    gid = cur.get("id") or str(params.get("id") or slug(name)).strip().lower()
    if not current:
        if not GROUP_ID.fullmatch(gid):
            raise GroupError(400, "bad_id", "a group id is 1 to 48 of a-z, 0-9 and -")
        if any(g["id"] == gid for g in store.groups(r)):
            raise GroupError(409, "id_taken", f"a group with the id {gid!r} exists")
    sel = check_selector(params["selector"]) if "selector" in params else cur.get("selector") or {}
    members = check_members(r, params["members"]) if "members" in params else cur.get("members") or []
    desc = str(params["description"] if "description" in params else cur.get("description") or "").strip()[:280]
    return {"id": gid, "name": name, "selector": sel, "members": members, "description": desc}


def top_rank(r) -> int:
    ranks = [g["rank"] for g in store.groups(r) if not g["builtin"]]
    return max(ranks) + 10 if ranks else store.OWNER_RANK_MIN


def create(db, s: dict, actor: str) -> dict:
    rank = top_rank(db)
    db.x("INSERT INTO node_groups(id,name,rank,selector_json,builtin,members_json,description,updated_by,updated_at) "
         "VALUES(?,?,?,?,0,?,?,?,?)", (s["id"], s["name"], rank, json.dumps(s["selector"]), json.dumps(s["members"]),
                                       s["description"], actor, time.time()))
    return {**s, "rank": rank, "builtin": 0}


def update(db, gid: str, s: dict, actor: str) -> None:
    db.x("UPDATE node_groups SET name=?, selector_json=?, members_json=?, description=?, updated_by=?, updated_at=? "
         "WHERE id=? AND builtin=0", (s["name"], json.dumps(s["selector"]), json.dumps(s["members"]), s["description"],
                                       actor, time.time(), gid))


def reorder(r, gid: str, move: str | None = None, order: list | None = None) -> list[str]:
    """The owner groups' ids, highest rank first, after moving one (`up`, `down`, `top`, `bottom`) or as `order` gives
    them (every owner group, highest first)."""
    owner = [g["id"] for g in sorted((g for g in store.groups(r) if not g["builtin"]), key=lambda g: -g["rank"])]
    if order is not None:
        ids = [x["id"] if isinstance(x, dict) else str(x) for x in order]
        resolved = [(find(r, x) or {}).get("id", x) for x in ids]
        if sorted(resolved) != sorted(owner) or len(set(resolved)) != len(resolved):
            raise GroupError(400, "bad_order", "order: every owner group once, highest rank first ("
                                               + ", ".join(owner) + ")")
        return resolved
    if gid not in owner:
        raise GroupError(404, "unknown_group", f"no owner group {gid!r}")
    i = owner.index(gid)
    j = {"up": i - 1, "down": i + 1, "top": 0, "bottom": len(owner) - 1}.get(move or "")
    if j is None:
        raise GroupError(400, "bad_move", "move: up, down, top or bottom")
    j = max(0, min(len(owner) - 1, j))
    owner.insert(j, owner.pop(i))
    return owner


def write_order(db, ids: list[str]) -> None:
    """Rank owner groups as `ids` gives them (highest first): ranks step by 10 from OWNER_RANK_MIN."""
    n = len(ids)
    for k, gid in enumerate(ids):                       # through negative ranks: the column is UNIQUE
        db.x("UPDATE node_groups SET rank=? WHERE id=? AND builtin=0", (-1 - k, gid))
    for k, gid in enumerate(ids):
        db.x("UPDATE node_groups SET rank=? WHERE id=? AND builtin=0", (store.OWNER_RANK_MIN + 10 * (n - 1 - k), gid))


def delete(db, gid: str) -> dict:
    """Delete an owner group with its values and its secrets' values (inside the caller's transaction)."""
    vals = db.q("SELECT key, module FROM setting_values WHERE scope='group' AND scope_id=?", (gid,))
    db.x("DELETE FROM setting_values WHERE scope='group' AND scope_id=?", (gid,))
    from .. import modsecrets
    secrets = modsecrets.drop_group(db, gid)
    db.x("DELETE FROM node_groups WHERE id=? AND builtin=0", (gid,))
    return {"values": [v["key"] + (f" [{v['module']}]" if v["module"] else "") for v in vals], "secrets": secrets}


# ------------------------------------------------------------------ what a change of membership does

def impact(db, before, after, extra: dict | None = None) -> dict:
    """Two snapshots (resolve.Snap) of groups and labels: which nodes join or leave which group, and which nodes'
    effective settings change, key by key (old → new)."""
    from . import apply as A, registry as R, resolve as V
    nodes = A._nodes(db)
    joins, leaves, changed, diff = [], [], [], []
    for n in nodes:
        gb = {g["id"]: g["name"] for g in V.node_groups(before, n)}
        ga = {g["id"]: g["name"] for g in V.node_groups(after, n)}
        joins += [f"{n['hostname']} joins {ga[x]}" for x in ga if x not in gb]
        leaves += [f"{n['hostname']} leaves {gb[x]}" for x in gb if x not in ga]
        db_ = A.node_document(before, n)
        da = A.node_document(after, n)
        flat_b = {**db_["policy"], **db_["limits"]}
        flat_a = {**da["policy"], **da["limits"]}
        moved = [k for k in sorted(set(flat_b) | set(flat_a)) if not R.same(flat_b.get(k), flat_a.get(k))]
        for k in moved:
            label = R.REGISTRY[k].label if k in R.REGISTRY else {"protection": "Protection", "module_settings":
                                                                 "Module settings"}.get(k, k)
            old = R.show(k, flat_b.get(k)) if k in R.REGISTRY else _short(flat_b.get(k))
            new = R.show(k, flat_a.get(k)) if k in R.REGISTRY else _short(flat_a.get(k))
            diff.append({"node_id": n["node_id"], "hostname": n["hostname"], "key": k, "label": label,
                         "old": flat_b.get(k), "new": flat_a.get(k), "old_text": old, "new_text": new})
            changed.append(f"{n['hostname']}: {label} {old} → {new}")
    hosts = sorted({x["hostname"] for x in diff})
    summary = (f"Changes the effective settings of {len(hosts)} node{'s' if len(hosts) != 1 else ''}"
               + (f" ({', '.join(hosts[:6])}{', …' if len(hosts) > 6 else ''})" if hosts else ""))
    return {"summary": summary, "joins": joins, "leaves": leaves, "nodes_changed": changed, **(extra or {}),
            "_diff": diff, "_nodes": len(hosts)}


def _short(v) -> str:
    if isinstance(v, dict) and "rule" in v:
        rules = [r.get("id") for r in v.get("rule") or []]
        return f"mode {(v.get('node') or {}).get('mode', 'moderate')}, rules {', '.join(rules) or 'none'}"
    s = json.dumps(v, sort_keys=True)
    return s if len(s) <= 80 else s[:77] + "…"


def view(r, ident: str | None = None) -> dict:
    """GET /api/v1/groups (and one group): every group in rank order (highest first) with its rule in words, its
    members and why each is one, the values it sets, and every node's labels."""
    from . import registry as R, resolve as V
    snap = V.snapshot(r)
    nodes = r.q("SELECT node_id, hostname, os, arch, facts_json FROM nodes WHERE lifecycle!='retired' ORDER BY hostname")
    names = {n["node_id"]: n["hostname"] for n in nodes}
    out = []
    for g in sorted(snap.groups, key=lambda g: -g["rank"]):
        if ident and ident.lower() not in (g["id"].lower(), g["name"].lower()):
            continue
        members = []
        for n in nodes:
            m = membership(g, n, snap.node_labels(n)["all"])
            if m["member"]:
                members.append({"node_id": n["node_id"], "hostname": n["hostname"], "why": m["why"]})
        vals = [{"key": k, "module": mm, "label": (R.REGISTRY.get(k).label if R.REGISTRY.get(k) else k),
                 "value": x["value"], "value_text": R.show(k, x["value"]), "enforced": bool(x["enforced"]),
                 "rev": x["rev"], "by": x["updated_by"], "at": x["updated_at"]}
                for (scope, sid, mm, k), x in sorted(snap.rows.items()) if scope == "group" and sid == g["id"]]
        out.append({**g, "rule": describe(g, names), "members_list": members, "values": vals,
                    "builtin_values": [{"key": k, "value_text": R.show(k, v), "reason": why}
                                       for k, (v, why) in store.BUILTIN_VALUES.get(g["id"], {}).items()]})
    labels = {n["hostname"]: snap.node_labels(n) for n in nodes}
    return {"groups": out, "labels": labels}
