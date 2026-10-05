"""A plan's impact as a person reads it: labelled rows of plain text, the same in the console's review page
(templates/plan.html) and in `oarbank`'s preview (cli/main.py run_op). The impact itself stays the operation's own JSON
(the plan stores it, the API returns it); this only says it.

Keys become labels (`live_attempts_carried` -> "live attempts carried"), a key ending in `_s` is a duration, booleans
are yes or no, lists are one item per line, objects are `key: value` lines, and an empty or missing value is left out.
"""
from typing import Any

MATCHES = "matches"        # a protection preview's live matches: a table in the console, a summary line per rule here


def duration(s: float) -> str:
    s = float(s)
    if s >= 86400 and s % 3600 == 0:
        d, h = divmod(int(s) // 3600, 24)
        return f"{d} d" + (f" {h} h" if h else "")
    if s >= 3600:
        return f"{s / 3600:g} h"
    if s >= 60:
        return f"{s / 60:g} min"
    return f"{s:g} s"


def _text(v: Any) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, dict):
        return ", ".join(f"{label(k)} {_text(x)}" for k, x in v.items() if x not in (None, "", [], {}))
    if isinstance(v, list):
        return ", ".join(_text(x) for x in v)
    return str(v)


def label(key: str) -> str:
    return (key[:-2] if key.endswith("_s") else key).replace("_", " ")


def rows(impact: dict | None, skip=(MATCHES,)) -> list[dict]:
    """[{"label", "items": [str, ...]}] for every key of the impact with a value, except those in `skip`."""
    out = []
    for k, v in (impact or {}).items():
        if k in skip or v in (None, "", [], {}):
            continue
        if k.endswith("_s") and isinstance(v, (int, float)) and not isinstance(v, bool):
            items = [duration(v)]
        elif isinstance(v, list):
            items = [_text(x) for x in v]
        elif isinstance(v, dict):
            items = [f"{kk}: {_text(x)}" for kk, x in v.items() if x not in (None, "", [], {})]
        else:
            items = [_text(v)]
        out.append({"label": label(k), "items": items})
    return out


def lines(impact: dict | None, indent: str = "  ") -> list[str]:
    """The rows as terminal lines: one line per single-item row, a bulleted block otherwise; a protection preview's
    matches as one line per rule."""
    out = []
    for m in (impact or {}).get(MATCHES) or []:
        procs = m.get("processes") or []
        names = ", ".join(f"{q.get('pid')} {str(q.get('path') or q.get('comm') or '').rsplit('/', 1)[-1]}" for q in procs[:8])
        out.append(f"{indent}rule {m.get('rule')} matches {len(procs)} process(es)" + (f": {names}" if names else ""))
    for r in rows(impact):
        if len(r["items"]) == 1:
            out.append(f"{indent}{r['label']}: {r['items'][0]}")
        else:
            out.append(f"{indent}{r['label']}:")
            out += [f"{indent}  - {x}" for x in r["items"]]
    return out
