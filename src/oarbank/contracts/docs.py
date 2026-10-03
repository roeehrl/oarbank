"""Render the operation and reason-code registries as markdown (docs/design/operations.md,
docs/design/reason-codes.md). Freshness-tested, so the docs never drift from the registries."""
from pathlib import Path

from . import operations as ops, reason_codes as rc

DOCS = Path(__file__).resolve().parents[3] / "docs" / "design"


def _routes(op):
    rs = [f"`{r.method} {r.path}`" + (f" ({', '.join(f'{k}={v}' for k, v in r.when.items())})" if r.when else "")
          for r in (*op.routes, *op.gui)]
    return "<br>".join(rs) or "–"


def _core_ops():
    return [o for o in ops.OPS if not o.id.startswith("mod.")]     # module operations are per install


def operations_md() -> str:
    lines = ["# Operation registry (generated)", "",
             "Generated from `oarbank.contracts.operations` by `python -m oarbank.contracts.docs`. "
             "Tiers, reasons and previews follow PLAN D14–D15.", "",
             f"{len(_core_ops())} operations. Module operations (`mod.<module>.<verb>`) are registered per installed module and listed in the console.", ""]
    for area in dict.fromkeys(o.area for o in _core_ops()):
        lines += [f"## {area}", "", "| Operation | Tier | Reason | Preview | Role | Idempotency | Reverses | Routes | CLI |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for o in (o for o in _core_ops() if o.area == area):
            tier = o.tier + (f" ({o.escalates})" if o.escalates else "") + (" · bulk" if o.bulk else "")
            lines.append(f"| `{o.id}` — {o.summary} | {tier} | {o.reason_policy} | {'yes' if o.preview else '–'} | {o.min_role} | "
                         f"{o.idempotency}{' · versioned' if o.versioned else ''} | {o.reverses or '–'} | {_routes(o)} | "
                         f"{'<br>'.join(o.cli) or '–'} |")
        lines.append("")
    lines += ["## Agent protocol routes (not operations)", "",
              "Machine-to-machine, authenticated by the node's client certificate and fenced by generation; audited as events "
              "under `node:<id>`.", ""]
    lines += [f"- `{m} {p}`" for m, p in sorted(ops.AGENT_ROUTES, key=lambda x: x[1])]
    return "\n".join(lines) + "\n"


def reason_codes_md() -> str:
    lines = ["# Reason codes (generated)", "",
             "Generated from `oarbank.contracts.reason_codes`. Module codes use `<module-short>/<code>`. "
             "The last column lists the attempt end reasons the agent and oarbankd write for a code.", ""]
    for cat in dict.fromkeys(c.category for c in rc.CODES):
        lines += [f"## {cat}", "", "| Code | Message | Severity | Node / job fault | Remedies | End reasons |", "|---|---|---|---|---|---|"]
        for c in (c for c in rc.CODES if c.category == cat):
            fault = "–" if c.counts_against_node is None else f"{'yes' if c.counts_against_node else 'no'} / {'yes' if c.counts_against_job else 'no'}"
            lines.append(f"| `{c.code}` | {c.template} | {c.severity} | {fault} | {', '.join(f'`{r}`' for r in c.remedies) or '–'} | "
                         f"{', '.join(f'`{w}`' for w in c.wire) or '–'} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def parity_md() -> str:
    from . import parity
    return parity.report_md()


def alert_runbook_md() -> str:
    from .alert_rules import DEFAULT, POLICY
    lines = ["# Alert rules and runbook (generated)", "",
             "Generated from `oarbank.contracts.alert_rules` by `python -m oarbank.contracts.docs`. A rule with a pending "
             "period notifies only if its condition outlives it; a flap rule turns N trips per window into one `<rule>:flapping` "
             "alert. P5 alerts re-notify every 30 min until acknowledged or snoozed. Acknowledge with a verdict (useful or "
             "noise): `oarbank alerts precision` is the monthly review (P4/P5 rules need at least 50 %).", "",
             "| Rule | Severity | Pending | Flap | Runbook |", "|---|---|---|---|---|"]
    for rule, p in sorted(POLICY.items()):
        p = {**DEFAULT, **p}
        flap = f"{p['flap'][0]} in {p['flap'][1] // 60:g} min" if p.get("flap") else "–"
        lines.append(f"| `{rule}` | {p['severity']} | {p['pending_s'] // 60:g} min | {flap} | {p['runbook']} |")
    return "\n".join(lines) + "\n"


RENDERED = {"operations.md": operations_md, "reason-codes.md": reason_codes_md, "parity.md": parity_md,
            "alert-runbook.md": alert_runbook_md}


def write() -> list[str]:
    changed = []
    for name, fn in RENDERED.items():
        p, text = DOCS / name, fn()
        if not p.exists() or p.read_text() != text:
            p.write_text(text)
            changed.append(name)
    return changed


if __name__ == "__main__":
    print(write())
