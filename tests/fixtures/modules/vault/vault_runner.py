"""vault runner (runner protocol 1). `call` reads its secret from OARBANK_SECRETS_FILE and reports only facts about
it (the file's mode, whether it lies in the work directory, the value's sha256), never the value, unless the spec asks it
to log the key (the agent redacts that); `probe` reports whether it got any secrets file; `eval` is the golden stage.
Stdlib only."""
import argparse
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path


def write(path: Path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj))
    os.replace(tmp, path)


def secrets_seen(ws: Path) -> dict:
    p = os.environ.get("OARBANK_SECRETS_FILE")
    if not p:
        return {"file": False}
    f = Path(p)
    doc = json.loads(f.read_text(encoding="utf-8"))
    return {"file": True, "names": sorted(doc), "inside_workdir": f.resolve().is_relative_to(ws.resolve()),
            "mode": oct(stat.S_IMODE(f.stat().st_mode)) if os.name == "posix" else None,
            "key_sha256": hashlib.sha256(doc.get("api_key", "").encode()).hexdigest()}


def run(spec_path: Path, ws: Path, out: Path) -> int:
    env = json.loads(spec_path.read_text(encoding="utf-8"))
    res = {"envelope": 1, "schema": "vault/result@1", "module_version": env.get("module_version", "1.0.0"), "protocol": 1}
    stage, payload = env.get("stage"), env.get("payload") or {}
    if stage in ("call", "probe"):
        seen = secrets_seen(ws)
        if stage == "call" and payload.get("leak") and seen["file"]:
            key = json.loads(Path(os.environ["OARBANK_SECRETS_FILE"]).read_text(encoding="utf-8"))["api_key"]
            sys.stderr.write("x" * 6000 + "\n")              # enough output for the agent to stream a log chunk
            print(f"calling the provider with {key}", file=sys.stderr, flush=True)
            sys.stderr.write("y" * 6000 + "\n")
            sys.stderr.flush()
            time.sleep(2)                                   # still running when the agent streams the log
            write(ws / "failure.json", {"reason": "vault/leaked", "detail": f"the key was {key}", "fault": "job"})
            return 1
        write(out, {**res, "payload": {"digest": stage, "secrets": seen}})
        return 0
    n = payload.get("n")
    write(out, {**res, "payload": {"digest": "vault-golden-1" if n == 1 else f"n{n}"}})
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
