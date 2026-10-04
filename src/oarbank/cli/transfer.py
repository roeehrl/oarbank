"""Files in and out of the fleet (docs/design/datasets-media-checkpoints.md, #10): `oarbank dataset upload`, `oarbank
dataset download` and `oarbank campaign download`.

- **Upload**: every regular file of a folder is hashed, then uploaded through the admin API's resumable upload (after
  tus 1.0: `POST /api/v1/uploads/{digest}` says where it stands, `PATCH` appends at `Upload-Offset`) in 8 MiB chunks,
  retrying from the coordinator's offset; then `datasets.register` names the files. Running the same command again
  after an interruption sends only what the coordinator does not hold yet.
- **Download**: each file is fetched into `<path>.partial`, resumed with `Range`, checked against its sha256 and then
  renamed; a file already there with the right digest is skipped. A dataset file the coordinator does not hold comes
  from its origins (https, redirects only to https URLs under the same rule).
"""
import contextlib
import hashlib
import json
import sys
import time
from pathlib import Path
from urllib.parse import urljoin

import httpx

from oarbank_sdk import origins as O
from oarbank_sdk import portable

CHUNK = 8 * 1024 * 1024
RETRIES = 8


def _client() -> httpx.Client:
    """A client for the admin API: the local admin socket on the coordinator's own account, else OARBANKD_URL."""
    from . import main
    sock = main._local_socket()
    if sock:
        return httpx.Client(transport=httpx.HTTPTransport(uds=str(sock)), base_url="http://oarbank", timeout=600)
    return httpx.Client(base_url=main.URL, timeout=600)


def _auth() -> dict:
    from . import main
    return main.auth_headers()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while b := f.read(CHUNK):
            h.update(b)
    return h.hexdigest()


def folder_files(root: Path) -> list[tuple[str, Path]]:
    """(PortablePath, file) for every file under `root`; a symlink, a special file or a path that is not portable stops
    the upload, naming every offender."""
    out, bad = [], []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            bad.append(f"{rel}: a symlink (upload what it points to instead)")
        elif p.is_dir():
            continue
        elif not p.is_file():
            bad.append(f"{rel}: not a regular file")
        else:
            try:
                portable.check_portable_path(rel, allow_dotfiles=True)
            except (ValueError, TypeError) as e:
                bad.append(str(e))
                continue
            out.append((rel, p))
    if bad:
        sys.exit("cannot upload:\n  " + "\n  ".join(bad))
    if not out:
        sys.exit(f"{root}: no files to upload")
    return out


def upload_file(c: httpx.Client, path: Path, digest: str, size: int, label: str, out=print):
    """Upload one blob, resuming from the coordinator's offset after any failure."""
    for attempt in range(RETRIES):
        try:
            r = c.post(f"/api/v1/uploads/{digest}", json={"size": size}, headers=_auth())
            if r.status_code >= 400:
                if r.status_code in (502, 503, 504):
                    raise httpx.TransportError(f"{r.status_code}")
                sys.exit(f"{label}: {r.status_code} {r.text}")
            st = r.json()
            off, complete = st["offset"], st["complete"]
            if complete:
                out(f"{label}: already on the coordinator")
                return
            with open(path, "rb") as f:
                while not complete:
                    f.seek(off)
                    chunk = f.read(CHUNK)
                    p = c.patch(f"/api/v1/uploads/{digest}", content=chunk,
                                headers={**_auth(), "upload-offset": str(off), "content-type": "application/offset+octet-stream"})
                    if p.status_code == 409 and p.headers.get("upload-offset"):
                        off = int(p.headers["upload-offset"])
                        continue
                    if p.status_code >= 400:
                        if p.status_code in (502, 503, 504):
                            raise httpx.TransportError(f"{p.status_code}")
                        sys.exit(f"{label}: {p.status_code} {p.text}")
                    off = int(p.headers["upload-offset"])
                    complete = p.headers.get("upload-complete") == "1"
                    out(f"{label}: {100 * off // max(size, 1)}%")
            return
        except httpx.TransportError as e:
            wait = min(60, 2 ** attempt)
            out(f"{label}: {type(e).__name__} {e}; resuming in {wait} s")
            time.sleep(wait)
    sys.exit(f"{label}: the upload kept failing; run the same command again to resume it")


def default_id(kind: str, root: Path, files: list[dict]) -> str:
    """`<kind>:<folder name>-<the first 8 hex digits of the file list's digest>`."""
    import re
    from oarbank_sdk.keys import canonical_json
    name = re.sub(r"[^A-Za-z0-9_.+-]+", "-", root.resolve().name).strip("-.") or "upload"
    return f"{kind}:{name[:80]}-{hashlib.sha256(canonical_json(files).encode()).hexdigest()[:8]}"


def upload(root: Path, kind: str, dataset_id: str | None, module: str | None, meta: dict, out=print) -> dict:
    """`oarbank dataset upload`: hash and upload every file of `root`, then register the dataset."""
    from . import main
    files = []
    pairs = folder_files(root)
    with _client() as c:
        for i, (rel, p) in enumerate(pairs, 1):
            label = f"[{i}/{len(pairs)}] {rel}"
            size = p.stat().st_size
            digest = sha256_file(p)
            upload_file(c, p, digest, size, label, out)
            files.append({"path": rel, "digest": digest, "size": size})
    params = {"dataset_id": dataset_id or default_id(kind, root, files), "kind": kind, "meta": meta, "files": files}
    if module:
        params["module"] = module
    return main.run_op("datasets.register", params["dataset_id"], params, yes=True)


def _safe_target(dest: Path, rel: str) -> Path:
    portable.check_portable_path(rel, allow_dotfiles=True)
    t = (dest / rel).resolve()
    if dest.resolve() not in t.parents:
        sys.exit(f"{rel}: outside {dest}")
    return t


def _fetch(get, target: Path, digest: str, size: int | None, label: str, out=print) -> bool:
    """Fetch one file with `get(range_start) -> streaming response`, resumable, digest-checked. False when no source
    answered."""
    if target.is_file() and (size is None or target.stat().st_size == size) and sha256_file(target) == digest:
        out(f"{label}: already here")
        return True
    target.parent.mkdir(parents=True, exist_ok=True)
    part = target.with_name(target.name + ".partial")
    for attempt in range(RETRIES):
        have = part.stat().st_size if part.exists() else 0
        h = hashlib.sha256()
        if have:
            with open(part, "rb") as f:
                while b := f.read(CHUNK):
                    h.update(b)
        try:
            with get(have) as r:
                if r.status_code == 416:
                    part.unlink(missing_ok=True)
                    continue
                if r.status_code == 200 and have:
                    have, h = 0, hashlib.sha256()                     # the source ignored the range: start over
                elif r.status_code not in (200, 206):
                    out(f"{label}: {r.status_code}")
                    return False
                with open(part, "ab" if have else "wb") as f:
                    for b in r.iter_bytes(1 << 20):
                        h.update(b)
                        f.write(b)
            if h.hexdigest() != digest:
                part.unlink(missing_ok=True)
                sys.exit(f"{label}: the bytes hash to {h.hexdigest()}, not {digest}")
            part.replace(target)
            out(f"{label}: done")
            return True
        except httpx.TransportError as e:
            wait = min(60, 2 ** attempt)
            out(f"{label}: {type(e).__name__}; resuming in {wait} s")
            time.sleep(wait)
    return False


def _from_coordinator(c: httpx.Client, digest: str):
    def get(start: int):
        return c.stream("GET", f"/api/v1/blobs/{digest}", headers={**_auth(), **({"range": f"bytes={start}-"} if start else {})})
    return get


def _from_origin(url: str):
    """An origin download: https, and a redirect only to an https URL under the same rule (the digest decides)."""
    @contextlib.contextmanager
    def get(start: int):
        with httpx.Client(timeout=600, follow_redirects=False) as cl:
            u = url
            for _ in range(6):
                why = O.url_problem(u)
                if why:
                    raise httpx.TransportError(f"{u}: {why}")
                with cl.stream("GET", u, headers={"range": f"bytes={start}-"} if start else {}) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                        u = urljoin(u, resp.headers["location"])
                        continue
                    yield resp
                    return
            raise httpx.TransportError(f"{url}: too many redirects")
    return get


def download_dataset(dataset_id: str, dest: Path, out=print) -> int:
    """`oarbank dataset download`: every file of a dataset under `dest`; returns how many could not be fetched."""
    from . import main
    d = main.api("GET", f"/api/v1/datasets/{dataset_id}")
    failed = 0
    with _client() as c:
        for i, f in enumerate(d["files"], 1):
            label = f"[{i}/{len(d['files'])}] {f['path']}"
            target = _safe_target(dest, f["path"])
            sources = ([_from_coordinator(c, f["digest"])] if f.get("held") else []) + [_from_origin(o) for o in f.get("origins") or []]
            if not any(_fetch(get, target, f["digest"], f.get("size"), label, out) for get in sources):
                out(f"{label}: no source answered")
                failed += 1
    return failed


def download_campaign(campaign_id: str, dest: Path, out=print) -> int:
    """`oarbank campaign download`: every artifact file of the campaign's done jobs as
    `<dest>/<job id>[-<job name>]/<artifact>/<path>`; returns how many could not be fetched."""
    from . import main
    jobs = main.api("GET", f"/api/v1/campaigns/{campaign_id}/artifacts")
    failed = 0
    with _client() as c:
        for j in jobs:
            for a in j["artifacts"]:
                for f in a["files"]:
                    rel = f"{j['dir']}/{a['name']}/{f['path']}"
                    if not _fetch(_from_coordinator(c, f["digest"]), _safe_target(dest, rel), f["digest"], f.get("size"), rel, out):
                        failed += 1
    out(json.dumps({"jobs": len(jobs), "failed": failed}))
    return failed
