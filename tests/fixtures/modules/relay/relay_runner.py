"""relay runner (runner protocol 1): echoes a deterministic result for its spec envelope. Stdlib only."""
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
    env = json.loads(spec_path.read_text())
    pl = env["payload"]
    h = hashlib.sha256(json.dumps([pl.get("params"), pl.get("dataset")], sort_keys=True).encode()).hexdigest()
    res = {"envelope": 1, "schema": "relay/result@1", "module_version": env.get("module_version", "1.0.0"), "protocol": 1,
           "effective": {"mode": pl.get("mode")}, "payload": {"image_sha256": h, "tiles": int(h[:4], 16)}}
    if env.get("stage") == "render":
        (ws / "frame.exr").write_text(h)
        res["artifacts"] = [{"name": "frame", "files": [{"path": "frame.exr", "local": "frame.exr"}]}]
    else:
        res["payload"]["score"] = round(int(h[4:10], 16) / 0xFFFFFF, 6)
    write(out, res)
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
