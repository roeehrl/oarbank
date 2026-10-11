"""javelin runner (runner protocol 1): reads the host JDK the agent granted (OARBANK_TOOLS_FILE) and that JDK's `release`
file inside the sandbox, and reports the tool file's entry and the release file's JAVA_VERSION line. The golden (n = 1)
reports a fixed digest. Stdlib only."""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path


def write(path: Path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj))
    os.replace(tmp, path)


def run(spec_path: Path, ws: Path, out: Path) -> int:
    env = json.loads(spec_path.read_text(encoding="utf-8"))
    res = {"envelope": 1, "schema": "javelin/result@1", "module_version": env.get("module_version", "1.0.0"), "protocol": 1}
    n = env["payload"]["n"]
    if n == 1:
        write(out, {**res, "payload": {"digest": "javelin-golden-1"}})
        return 0
    tools = json.loads(Path(os.environ["OARBANK_TOOLS_FILE"]).read_text(encoding="utf-8"))
    jdk = tools["jdk"][0]
    line = next(x for x in (Path(jdk["path"]) / "release").read_text(encoding="utf-8").splitlines() if x.startswith("JAVA_VERSION="))
    digest = hashlib.sha256(f"{jdk['version']} {line}".encode()).hexdigest()
    write(out, {**res, "payload": {"digest": digest, "tools": tools, "release": line}})
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
