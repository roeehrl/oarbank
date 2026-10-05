"""depot runner (runner protocol 1): `fetch` writes the pinned tool as one artifact with an empty payload (a real module
downloads it through its egress allowlist), and fails unless it runs with the bootstrap grants (no module data directory,
no tools, empty settings); `eval` hashes the mounted tool with its input. Stdlib only."""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

TOOL = {"bin/tool.txt": b"depot tool v1\n", "README": b"depot: the core test suite's bootstrap fixture\n"}


def write(path: Path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj))
    os.replace(tmp, path)


def run(spec_path: Path, ws: Path, out: Path) -> int:
    env = json.loads(spec_path.read_text(encoding="utf-8"))
    res = {"envelope": 1, "schema": "depot/result@1", "module_version": env.get("module_version", "1.0.0"), "protocol": 1}
    if env.get("stage") == "fetch":
        granted = {"data": os.environ.get("OARBANK_MODULE_DATA"), "tools": Path(os.environ["OARBANK_TOOLS_FILE"]).read_text(encoding="utf-8"),
                   "settings": Path(os.environ["OARBANK_SETTINGS_FILE"]).read_text(encoding="utf-8")}
        if granted != {"data": None, "tools": "{}", "settings": "{}"}:      # the bootstrap grants, and nothing more
            write(ws / "failure.json", {"reason": "depot/not_bootstrap_grants", "detail": json.dumps(granted), "fault": "job"})
            return 1
        for path, body in TOOL.items():
            (ws / "out" / path).parent.mkdir(parents=True, exist_ok=True)
            (ws / "out" / path).write_bytes(body)
        write(out, {**res, "payload": {}, "artifacts": [{"name": "tool", "files": [
            {"path": p, "local": f"out/{p}"} for p in TOOL]}]})
        return 0
    tool = (ws / env["mounts"]["tool:depot-1"] / "bin" / "tool.txt").read_bytes()
    n = env["payload"]["n"]
    digest = "depot-golden-1" if n == 1 else hashlib.sha256(tool + str(n).encode()).hexdigest()
    write(out, {**res, "payload": {"digest": digest}})
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    for a in ("--spec", "--workdir", "--out"):
        r.add_argument(a, required=True)
    r.add_argument("--events")
    sub.add_parser("doctor").add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "doctor":
        print(json.dumps({"runner_protocol": {"supported": [1]}, "health": "healthy", "checks": []}))
        return 0
    return run(Path(a.spec), Path(a.workdir), Path(a.out))


if __name__ == "__main__":
    sys.exit(main())
