"""ferry runner (runner protocol 1): reads inbox/input.txt from the read-only folder, writes ferried-<n>.txt into the
write-only outbox, and reports in its payload whether the sandbox let it read the outbox back, write into the inbox,
or list the outbox (each must be refused). The golden (n = 1) touches no folder. Stdlib only."""
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


def tried(fn) -> str:
    try:
        fn()
        return "allowed"
    except OSError:
        return "refused"


def run(spec_path: Path, ws: Path, out: Path) -> int:
    env = json.loads(spec_path.read_text(encoding="utf-8"))
    res = {"envelope": 1, "schema": "ferry/result@1", "module_version": env.get("module_version", "1.0.0"), "protocol": 1}
    n = env["payload"]["n"]
    if n == 1:
        write(out, {**res, "payload": {"digest": "ferry-golden-1"}})
        return 0
    granted = json.loads(Path(os.environ["OARBANK_FOLDERS_FILE"]).read_text(encoding="utf-8"))
    inbox, outbox = Path(granted["inbox"]["path"]), Path(granted["outbox"]["path"])
    data = (inbox / "input.txt").read_bytes()
    digest = hashlib.sha256(data + str(n).encode()).hexdigest()
    sent = outbox / f"ferried-{n}.txt"
    with open(sent, "w", encoding="utf-8") as f:
        f.write(digest + "\n")
    probes = {"read_outbox": tried(lambda: sent.read_bytes()),
              "list_outbox": tried(lambda: os.listdir(outbox)),
              "write_inbox": tried(lambda: (inbox / "planted.txt").write_text("x")),
              "list_inbox": tried(lambda: os.listdir(inbox))}
    write(out, {**res, "payload": {"digest": digest, "probes": probes}})
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
