"""Generate the agent's settings table (rust/crates/oarbank-protection/src/settings_table.rs) from the registry.

The agent gets its complete effective policy and caps from the coordinator in every heartbeat reply; it checks each
key against this table, refuses (and reports) a value of the wrong type or out of range, and before its first
heartbeat starts from the defaults here. Generating the table keeps the coordinator and the agent from ever
disagreeing on a key, a type or a default: tests/test_settings.py fails when the file is stale.

    uv run python -m oarbank.coordinator.settings.rustgen        # rewrite the file
"""
import json
import sys
from pathlib import Path

from . import registry as R

OUT = Path(__file__).resolve().parents[4] / "rust" / "crates" / "oarbank-protection" / "src" / "settings_table.rs"

# the policy section also carries what is not one registry key: per module, the services a node does not run (each
# module's `services.disabled`, as module/service) and its node-scoped settings, and the protection section
EXTRA_POLICY = (("disabled_services", "Strings", False, []), ("module_settings", "Object", False, {}),
                ("protection", "Object", True, None))


def _kind(d: R.Setting) -> str:
    if d.schema.get("x-kind") == "schedule":
        return "Schedule"
    if "enum" in d.schema:
        return "Choice"
    t = next(x for x in (d.schema["type"] if isinstance(d.schema["type"], list) else [d.schema["type"]]) if x != "null")
    return {"number": "Number", "integer": "Integer", "boolean": "Bool", "array": "Strings", "object": "Object",
            "string": "Text"}[t]


def _f(v) -> str:
    return "None" if v is None else f"Some({float(v)!r})"


def _rs_str(s: str) -> str:
    return json.dumps(s)


def render() -> str:
    lines = [
        "//! The agent's settings table: every key of the policy and caps the coordinator sends, its type, bounds and",
        "//! default. GENERATED from the settings registry (src/oarbank/coordinator/settings/registry.py) by",
        "//! `uv run python -m oarbank.coordinator.settings.rustgen`; do not edit (tests/test_settings.py checks it).",
        "",
        "use crate::settings::{Def, Kind, Section};",
        "",
        "/// Every key, in the registry's order (the policy's extra keys last).",
        "pub const DEFS: &[Def] = &[",
    ]
    for d in R.SETTINGS:
        if not d.wire:
            continue
        sch = d.schema
        lo = sch.get("minimum", sch.get("exclusiveMinimum"))
        choices = ", ".join(_rs_str(c) for c in sch.get("enum", []))
        lines.append(f"    Def {{ key: {_rs_str(d.key)}, section: Section::{d.wire.capitalize()}, kind: Kind::{_kind(d)}, "
                     f"nullable: {'true' if d.nullable or d.wire == 'limits' and d.default is None else 'false'}, "
                     f"min: {_f(lo)}, exclusive_min: {'true' if 'exclusiveMinimum' in sch else 'false'}, max: {_f(sch.get('maximum'))}, "
                     f"choices: &[{choices}], default: {_rs_str(json.dumps(d.default))} }},")
    for key, kind, nullable, dflt in EXTRA_POLICY:
        lines.append(f"    Def {{ key: {_rs_str(key)}, section: Section::Policy, kind: Kind::{kind}, nullable: "
                     f"{'true' if nullable else 'false'}, min: None, exclusive_min: false, max: None, choices: &[], "
                     f"default: {_rs_str(json.dumps(dflt))} }},")
    lines += ["];", "", "// The defaults the capacity engine's Policy starts from (pre-first-heartbeat only)."]
    for d in R.SETTINGS:
        if d.wire != "policy":
            continue
        k, v = _kind(d), d.default
        name = d.key.upper()
        if k == "Bool":
            lines.append(f"pub const {name}: bool = {'true' if v else 'false'};")
        elif k == "Number":
            lines.append(f"pub const {name}: f64 = {float(v)!r};")
        elif k == "Integer" and d.nullable:
            lines.append(f"pub const {name}: Option<i64> = {'None' if v is None else f'Some({int(v)})'};")
        elif k == "Integer":
            lines.append(f"pub const {name}: i64 = {int(v)};")
    return "\n".join(lines) + "\n"


def write() -> bool:
    text = render()
    if OUT.exists() and OUT.read_text(encoding="utf-8") == text:
        return False
    OUT.write_text(text, encoding="utf-8")
    return True


if __name__ == "__main__":
    print(f"{'wrote' if write() else 'unchanged'} {OUT}")
    sys.exit(0)
