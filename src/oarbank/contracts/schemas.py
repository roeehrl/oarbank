"""Generate JSON Schemas for the agent-facing and API-facing core contracts into schemas/, for clients outside this
repository (tests keep the files fresh)."""
import json
from pathlib import Path

from . import audit, explain, protection

ROOT = Path(__file__).parent / "schemas"
CONTRACTS = {
    "protection-config-1": protection.ProtectionConfig,
    "explain-1": explain.ExplainDocument,
    "audit-record-1": audit.AuditRecord,
}


def render_all() -> dict[str, str]:
    out = {}
    for name, model in sorted(CONTRACTS.items()):
        s = {"$schema": "https://json-schema.org/draft/2020-12/schema", **model.model_json_schema(by_alias=True)}
        out[f"{name}.schema.json"] = json.dumps(s, indent=2, sort_keys=True) + "\n"
    return out


def export() -> list[str]:
    ROOT.mkdir(exist_ok=True)
    changed = []
    for name, text in render_all().items():
        p = ROOT / name
        if not p.exists() or p.read_text() != text:
            p.write_text(text)
            changed.append(name)
    return changed


if __name__ == "__main__":
    print(export())
