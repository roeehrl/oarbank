"""The parity audit (admin-console.md "One operation registry sets parity"): every
operation is reachable from the API, the CLI and the console; every explain kind from all three; every
reason code's remedies are operations that exist. `gaps()` is the zero-gap gate; `report_md()` renders
docs/design/parity.md (freshness-tested with the other generated docs)."""
from pathlib import Path

from . import operations as ops, reason_codes as rc

SRC = Path(__file__).resolve().parents[1]                     # src/oarbank
EXPLAIN_KINDS = ("job", "node")                               # oarbankd.explain.explain


def _templates() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in (SRC / "console" / "templates").glob("*.html"))


def _subcommands() -> dict:
    """{name: its argparse parser} for every `oarbank` command, from the CLI's own parser."""
    import argparse
    from ..cli.main import parser
    return next(a for a in parser()._actions if isinstance(a, argparse._SubParsersAction)).choices


def cli_exists(cmd: str, subs: dict | None = None) -> bool:
    """Whether an `oarbank ...` command the registry names exists: its subcommand, the literal words it gives each
    positional that takes choices (`pin|unpin`: each alternative), and every flag it names. Placeholders (`<node>`,
    `[name]`), values and `...` are not checked. Prose that is not an `oarbank` command is not a command to check."""
    import argparse
    import re
    if not cmd.startswith("oarbank "):
        return True
    subs = subs if subs is not None else _subcommands()
    words = re.sub(r"<[^>]*>", "<p>", cmd).split()[1:]
    sp = subs.get(words[0])
    if sp is None:
        return False
    flags = {o: a for a in sp._actions for o in a.option_strings}
    slots = [a for a in sp._actions if not a.option_strings]
    skip_value, i = False, 0
    for w in (x.strip("[]") for x in words[1:]):
        if skip_value:
            skip_value = False
            continue
        if not w or w.startswith("...") or w.endswith("..."):
            continue
        if w.startswith("-"):
            alts = [x.split("=", 1)[0] for x in w.split("|")]
            if any(x not in flags for x in alts):
                return False
            skip_value = flags[alts[0]].nargs != 0 and "=" not in w
            continue
        if i >= len(slots):
            return False
        slot = slots[i]
        if "<" not in w and slot.choices is not None and any(x not in slot.choices for x in w.split("|")):
            return False
        if slot.nargs not in ("*", argparse.REMAINDER):
            i += 1
    return True


def op_rows() -> list[dict]:
    t, subs = _templates(), _subcommands()
    out = []
    for o in ops.OPS:
        if o.id.startswith("mod."):
            continue
        api = [f"{r.method} {r.path}" for r in o.routes] or []
        generic_api = any(r.path == ops.OPS_ROUTE_PATH for r in o.routes)
        gui_form = f'op_form("{o.id}"' in t
        missing = [c for c in o.cli if not cli_exists(c, subs)]
        out.append({"id": o.id, "tier": o.tier, "api": api, "api_ok": bool(api) or generic_api,
                    "cli": list(o.cli), "cli_missing": missing,
                    "cli_ok": not missing and (bool(o.cli) or "op" in subs),      # `oarbank op <id>` reaches all
                    "gui": [f"{r.method} {r.path}" for r in o.gui], "gui_ok": bool(o.gui) and gui_form})
    return out


def explain_rows() -> list[dict]:
    t, subs = _templates(), _subcommands()
    console = (SRC / "console" / "app.py").read_text(encoding="utf-8")
    app = (SRC / "coordinator" / "app.py").read_text(encoding="utf-8")
    kinds = next((a.choices for a in subs["explain"]._actions if a.dest == "kind"), ()) if "explain" in subs else ()
    return [{"kind": k, "api_ok": "/api/v1/explain/{kind}/{ident}" in app, "cli_ok": k in kinds,
             "gui_ok": "/explain/{kind}/{ident}" in console and f"/explain/{k}/" in t} for k in EXPLAIN_KINDS]


def code_rows() -> list[dict]:
    out = []
    for c in rc.CODES:
        bad = [r for r in c.remedies if r not in ops.REGISTRY]
        out.append({"code": c.code, "category": c.category, "remedies": list(c.remedies), "unknown": bad})
    return out


def gaps() -> list[str]:
    g = []
    for r in op_rows():
        for side in ("api", "cli", "gui"):
            if not r[f"{side}_ok"] and not (side == "cli" and r["cli_missing"]):
                g.append(f"operation {r['id']}: no {side.upper()} path")
        g += [f"operation {r['id']}: the registry's CLI command `{c}` does not exist" for c in r["cli_missing"]]
    for r in explain_rows():
        for side in ("api", "cli", "gui"):
            if not r[f"{side}_ok"]:
                g.append(f"explain {r['kind']}: no {side.upper()} path")
    for r in code_rows():
        if r["unknown"]:
            g.append(f"reason code {r['code']}: remedies name unknown operations {r['unknown']}")
    return g


def report_md() -> str:
    rows, ex, codes = op_rows(), explain_rows(), code_rows()
    mark = lambda ok: "yes" if ok else "**GAP**"
    g = gaps()
    lines = ["# Parity report (generated)", "",
             "Generated from the registries and the sources by `python -m oarbank.contracts.docs`. "
             "Every operation must be reachable from the API (`POST /api/v1/ops/<id>` or its own route), the CLI "
             "(its own `oarbank` command, or `oarbank op <id>`) and the console (a form for it in a template); every explain "
             "kind from all three; every reason code's remedies must be operations.", "",
             f"**{len(g)} gaps.** {len(rows)} operations, {len(ex)} explain kinds, {len(codes)} reason codes. "
             f"Module operations (`mod.<module>.<verb>`) are generic: the API endpoint, `oarbank mod <module> <verb>`, and the "
             "module's own pages and panels (rendered by the host from the module's declarations).", ""]
    if g:
        lines += ["## Gaps", ""] + [f"- {x}" for x in g] + [""]
    lines += ["## Operations", "", "| Operation | Tier | API | CLI | Console |", "|---|---|---|---|---|"]
    for r in rows:
        cli = "<br>".join(f"`{c}`" for c in r["cli"]) or "`oarbank op " + r["id"] + "`"
        lines.append(f"| `{r['id']}` | {r['tier']} | {mark(r['api_ok'])} | {cli if r['cli_ok'] else '**GAP**'} | {mark(r['gui_ok'])} |")
    lines += ["", "## Explain", "", "| Kind | API | CLI | Console |", "|---|---|---|---|"]
    lines += [f"| `{r['kind']}` | {mark(r['api_ok'])} | {mark(r['cli_ok'])} | {mark(r['gui_ok'])} |" for r in ex]
    lines += ["", "## Reason codes with remedies", "", "| Code | Remedies |", "|---|---|"]
    lines += [f"| `{r['code']}` | {', '.join(f'`{x}`' for x in r['remedies'])} |" for r in codes if r["remedies"]]
    return "\n".join(lines) + "\n"
