"""The host tool resolution vectors (src/oarbank/contracts/vectors/tool-resolution.json): cases the coordinator's
tools.resolve and the agent's oarbank_core::tools::resolve must answer identically.

    uv run python tests/tool_vectors.py      # rewrite the file after a deliberate change of the rule
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src" / "oarbank" / "contracts" / "vectors" / "tool-resolution.json"


def inst(path, version, arch="aarch64", status="ok", source="detected", **kw):
    return {"path": path, "version": version, "arch": arch, "status": status, "source": source, **kw}


JDK17 = inst("/opt/homebrew/Cellar/openjdk@17/17.0.12/libexec/openjdk.jdk/Contents/Home", "17.0.12")
JDK21 = inst("/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home", "21.0.4")
JDK21X = inst("/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home", "21.0.4", "x86_64")
JDK11 = inst("/usr/lib/jvm/java-11-openjdk-arm64", "11.0.2")
JDK22EA = inst("/opt/jdk-22-ea", "22-ea")
ODD = inst("/opt/jdk-odd", "", None)
REFUSED = inst("/", None, None, "refused: a filesystem root", "override", given="/")
ADDED = inst("/opt/tools/jdk-17.0.9", "17.0.9", source="override", given="/opt/tools/current-jdk")
REQ = {"id": "jdk", "version": ">=17", "arch": "any"}

CASES = [
    ("the highest version that satisfies", [JDK11, JDK17, JDK21], REQ, "arm64", None),
    ("the native arch before a newer foreign one", [JDK17, JDK21X], REQ, "arm64", None),
    ("only an x86_64 JDK on an Intel Mac is native there", [JDK17, JDK21X], REQ, "amd64", None),
    ("found only an older one", [JDK11], {"id": "jdk", "version": ">=17, <22", "arch": "any"}, "arm64", None),
    ("nothing found", [], REQ, "arm64", None),
    ("only a refused path", [REFUSED], REQ, "arm64", None),
    ("a pin among what was found", [JDK17, JDK21], REQ, "arm64", JDK17["path"]),
    ("a pin that names nothing found", [JDK17], REQ, "arm64", "/opt/elsewhere"),
    ("a pin on a refused path", [REFUSED, JDK17], REQ, "arm64", "/"),
    ("a pin too old for the request", [JDK11, JDK17], REQ, "arm64", JDK11["path"]),
    ("a pin by the path the operator gave", [ADDED, JDK21], REQ, "arm64", "/opt/tools/current-jdk"),
    ("native only, none native", [JDK21X], {"id": "jdk", "version": ">=17", "arch": "native"}, "arm64", None),
    ("an exact arch", [JDK17, JDK21X], {"id": "jdk", "version": None, "arch": "amd64"}, "arm64", None),
    ("an unknown version satisfies no constraint", [ODD], REQ, "arm64", None),
    ("with no constraint an unknown version is fine", [ODD], {"id": "jdk", "version": None, "arch": "any"}, "arm64", None),
    ("a pre-release sorts below its release", [JDK21, JDK22EA], {"id": "jdk", "version": "<22", "arch": "any"}, "arm64", None),
    ("equal versions: the first path", [inst("/b/jdk", "17.0.12"), inst("/a/jdk", "17.0.12")], REQ, "arm64", None),
    ("many found, none accepted", [inst(f"/j/{v}", v) for v in ("8.0.392", "11.0.2", "11.0.21", "15.0.1", "16.0.2")],
     REQ, "arm64", None),
]


def cases() -> list[dict]:
    from oarbank.coordinator import tools
    return [{"name": n, "installations": insts, "request": req, "native": native, "pin": pin,
             "resolved": tools.resolve(insts, req, native, pin)} for n, insts, req, native, pin in CASES]


def document() -> str:
    return json.dumps({"comment": "Host tool resolution vectors shared by oarbank.coordinator.tools.resolve and "
                                  "oarbank_core::tools::resolve (docs/design/host-tools.md)", "cases": cases()},
                      indent=1, sort_keys=True) + "\n"


if __name__ == "__main__":
    OUT.write_text(document(), encoding="utf-8", newline="\n")
    print("written", OUT)
