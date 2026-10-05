"""vault runner (runner protocol 1). `call` reads its secret from OARBANK_SECRETS_FILE and reports only facts about
it (the file's mode, whether it lies in the work directory, the value's sha256), never the value, unless the spec asks it
to log the key (the agent redacts that); `probe` reports whether it got any secrets file and where its home, its
application data and its temporary files are; `eval` is the golden stage. Stdlib only."""
import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
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


def home_seen(ws: Path) -> dict:
    """Where the runner's per-user locations point (spec/platforms.md, "Environment per OS") and whether each lies in the
    work directory; the temporary directory the OS gives programs (Windows: GetTempPath, which an AppContainer start
    points into the container's folder) and whether a file can be made there."""
    names = (("USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP") if os.name == "nt" else
             ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"))
    root = ws.resolve()
    outside = [n for n in names if not (os.environ.get(n) and Path(os.environ[n]).resolve().is_relative_to(root))]
    if os.name == "nt":
        import ctypes
        buf = ctypes.create_unicode_buffer(1024)
        ctypes.windll.kernel32.GetTempPathW(1024, buf)
        tmp = buf.value
    else:
        tmp = os.environ.get("TMPDIR", "")
    try:
        fd, made = tempfile.mkstemp(dir=tmp)
        os.close(fd)
        os.unlink(made)
        writable = True
    except OSError:
        writable = False
    return {"workdir": str(root), "outside": outside, "temp_dir_inside": bool(tmp) and Path(tmp).resolve().is_relative_to(root),
            "temp_dir_writable": writable, "user_home_inside": Path.home().resolve().is_relative_to(root)}


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
        payload = {"digest": stage, "secrets": seen}
        if stage == "probe":
            payload["home"] = home_seen(ws)
        write(out, {**res, "payload": payload})
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
