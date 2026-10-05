"""Blobs: the files the coordinator keeps by content digest (docs/design/datasets-media-checkpoints.md, "The blob
transport"). Job artifacts, checkpoint files, uploads and origin fetches all land in `<home>/blobs/<d[0:2]>/<d>`, named
in the `blobs` table with the size measured here.

- **Upload** (agent API `/v1/uploads/{digest}`, admin API `/api/v1/uploads/{digest}`), after tus 1.0 with the digest as
  the upload's id: `begin()` creates or resumes a partial and says where it stands; `append()` streams bytes onto it at
  the stated offset; the partial that reaches its size is checked against its sha256 and becomes a blob. Partials are
  per uploader, so one party never writes into another's.
- **Serve**: `path()` finds a held blob's file; `origin_stream()` fetches one that only a dataset's origins have (the
  fallback for a node whose every origin failed), single-flight per digest, streaming it to the first node while it
  writes it.
- **Fetch from an origin**: https only, a host name whose every address is public, the connection made to an address
  that was checked, redirects only to URLs under the same rule, the size and sha256 checked.
- **Deletion**: `release()` deletes blobs nothing names any more (only checkpoints are ever released).
"""
import asyncio
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from oarbank_sdk import origins as O

from ..platform import files
from . import clock
from .db import DB, jl

DIGEST = re.compile(r"^[0-9a-f]{64}$")
BLOB_MAX_BYTES = int(os.environ.get("OARBANKD_BLOB_MAX_BYTES", str(256 * 1024 ** 3)))
UPLOAD_PARTIAL_MAX_BYTES = int(os.environ.get("OARBANKD_UPLOAD_PARTIAL_MAX_BYTES", str(1024 ** 4)))
DISK_RESERVE_BYTES = 2 * 1024 ** 3          # an upload never takes the coordinator's disk below this
PARTIAL_MAX_AGE_S = 7 * 86400
ORIGIN_SETTING = "dataset_origins"          # {"hosts": [host patterns]}: the operator's origin host policy


class BlobError(Exception):
    def __init__(self, status: int, code: str, detail: str, offset: int | None = None):
        super().__init__(f"{code}: {detail}")
        self.status, self.code, self.detail, self.offset = status, code, detail, offset


def blob_dir(db: DB) -> Path:
    return db.root / "blobs"


def upload_dir(db: DB) -> Path:
    return db.root / "uploads"


def path(db: DB, digest: str) -> Path | None:
    """A held blob's file, or None."""
    row = db.one("SELECT path FROM blobs WHERE digest=?", (digest,)) if DIGEST.match(digest or "") else None
    p = db.abs(row["path"]) if row and row["path"] else None
    return p if p is not None and p.is_file() else None


def held(db: DB, digest: str) -> dict | None:
    return db.one("SELECT digest, size FROM blobs WHERE digest=?", (digest,)) if path(db, digest) else None


def register(db: DB, digest: str, file: Path, size: int):
    db.x("INSERT INTO blobs(digest,path,size) VALUES(?,?,?) ON CONFLICT(digest) DO UPDATE SET path=excluded.path, "
         "size=excluded.size", (digest, db.rel(file), size))


def adopt(db: DB, src: Path, digest: str, size: int) -> Path:
    """Move a verified file into the blob directory (read-only) and register it."""
    final = blob_dir(db) / digest[:2] / digest
    final.parent.mkdir(parents=True, exist_ok=True)
    files.seal(src)
    os.replace(src, final)
    register(db, digest, final, size)
    return final


# ---------------------------------------------------------------------------- resumable upload

def _who(uploader: str) -> str:
    return hashlib.sha256(uploader.encode()).hexdigest()[:16]


def _partial(db: DB, uploader: str, digest: str) -> Path:
    return upload_dir(db) / f"{digest}.{_who(uploader)}.partial"


_hashers: dict = {}          # (uploader, digest) -> (offset, sha256 so far): resumes without rereading what is on disk
_locks: dict = {}


def _lock(key) -> asyncio.Lock:
    lk = _locks.get(key)
    if lk is None:
        lk = _locks[key] = asyncio.Lock()
    return lk


def begin(db: DB, uploader: str, digest: str, size) -> dict:
    """Create or resume an upload: {offset, complete}. `complete` when the coordinator holds the blob already."""
    if not DIGEST.match(digest or ""):
        raise BlobError(400, "bad_digest", f"{digest!r}: 64 lowercase hex digits")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise BlobError(400, "bad_size", "size: the blob's length in bytes")
    h = held(db, digest)
    if h:
        if h["size"] != size:
            raise BlobError(409, "size_mismatch", f"the coordinator holds {digest[:12]} at {h['size']} bytes, not {size}")
        return {"offset": size, "complete": True}
    if size > BLOB_MAX_BYTES:
        raise BlobError(413, "too_large", f"{size} bytes > {BLOB_MAX_BYTES}")
    part = _partial(db, uploader, digest)
    have = part.stat().st_size if part.exists() else 0
    if have > size:
        part.unlink()
        have = 0
    upload_dir(db).mkdir(parents=True, exist_ok=True)
    held_partials = sum(p.stat().st_size for p in upload_dir(db).glob("*.partial"))
    if held_partials - have + size > UPLOAD_PARTIAL_MAX_BYTES or \
            shutil.disk_usage(upload_dir(db)).free < size - have + DISK_RESERVE_BYTES:
        raise BlobError(507, "upload_space", "not enough room for this upload on the coordinator")
    part.touch()
    (part.with_suffix(".json")).write_text(json.dumps({"size": size, "uploader": uploader, "at": clock.now()}),
                                           encoding="utf-8", newline="\n")
    return {"offset": have, "complete": False}


async def append(db: DB, uploader: str, digest: str, offset: int, chunks) -> dict:
    """Append the async iterable `chunks` at `offset`; when the partial reaches its size, check its digest and adopt it.
    Returns {offset, complete}. A wrong offset is 409 with the current one; a digest mismatch drops the partial."""
    if not DIGEST.match(digest or ""):
        raise BlobError(400, "bad_digest", repr(digest))
    key = (uploader, digest)
    async with _lock(key):
        if held(db, digest):
            return {"offset": held(db, digest)["size"], "complete": True}
        part = _partial(db, uploader, digest)
        meta = part.with_suffix(".json")
        if not part.exists() or not meta.exists():
            raise BlobError(404, "no_upload", "start the upload first (POST)")
        size = int(json.loads(meta.read_text(encoding="utf-8"))["size"])
        have = part.stat().st_size
        if offset != have:
            raise BlobError(409, "offset_mismatch", f"the upload stands at {have}", offset=have)
        cached = _hashers.pop(key, None)
        if cached and cached[0] == have:
            h = cached[1]
        else:
            h = hashlib.sha256()
            with open(part, "rb") as f:
                while b := f.read(1 << 20):
                    h.update(b)
        n = have
        try:
            with open(part, "ab") as f:
                async for chunk in chunks:
                    n += len(chunk)
                    if n > size:
                        raise BlobError(400, "too_long", f"more than the {size} bytes announced")
                    h.update(chunk)
                    f.write(chunk)
        except BlobError:
            part.unlink(missing_ok=True)
            meta.unlink(missing_ok=True)
            raise
        finally:
            if part.exists():
                _hashers[key] = (part.stat().st_size, h)
        if n < size:
            return {"offset": n, "complete": False}
        _hashers.pop(key, None)
        got = h.hexdigest()
        if got != digest:
            part.unlink(missing_ok=True)
            meta.unlink(missing_ok=True)
            raise BlobError(422, "digest_mismatch", f"the bytes hash to {got}")
        adopt(db, part, digest, size)
        meta.unlink(missing_ok=True)
        db.event("blob_uploaded", actor=uploader, reason=digest[:12], size=size)
        return {"offset": size, "complete": True}


def sweep_partials(db: DB, now: float | None = None) -> int:
    """Remove partials untouched for PARTIAL_MAX_AGE_S (the daily prune)."""
    t, n = now or time.time(), 0
    for p in upload_dir(db).glob("*.partial") if upload_dir(db).is_dir() else []:
        if t - p.stat().st_mtime > PARTIAL_MAX_AGE_S:
            p.unlink(missing_ok=True)
            p.with_suffix(".json").unlink(missing_ok=True)
            n += 1
    return n


# ---------------------------------------------------------------------------- deletion

def named_elsewhere(db: DB, digest: str) -> bool:
    """Whether a module file, a dataset, a result or a checkpoint names the blob."""
    return bool(db.one("SELECT 1 FROM module_files WHERE digest=? LIMIT 1", (digest,))
                or db.one("SELECT 1 FROM datasets WHERE instr(files_json, ?) > 0 LIMIT 1", (digest,))
                or db.one("SELECT 1 FROM results WHERE instr(result_json, ?) > 0 LIMIT 1", (digest,))
                or db.one("SELECT 1 FROM checkpoints WHERE instr(files_json, ?) > 0 LIMIT 1", (digest,)))


def release(db: DB, digests) -> int:
    """Delete the blobs among `digests` that nothing names any more; returns how many."""
    n = 0
    for d in sorted(set(digests)):
        if named_elsewhere(db, d):
            continue
        p = path(db, d)
        db.x("DELETE FROM blobs WHERE digest=?", (d,))
        if p is not None:
            p.unlink(missing_ok=True)
        n += 1
    return n


# ---------------------------------------------------------------------------- origins

def origin_policy(db: DB) -> list[str]:
    return list((db.get_setting(ORIGIN_SETTING) or {}).get("hosts") or [])


def check_origins(db: DB, files: list) -> str | None:
    """Why a dataset's files cannot be registered as they name origins (None: they can): the URL rule and the operator's
    origin host policy."""
    pol = origin_policy(db)
    for f in files:
        for o in f.get("origins") or []:
            why = O.url_problem(o)
            if why:
                return f"{f.get('path')}: origin {o!r}: {why}"
            if not O.allowed(o, pol):
                return f"{f.get('path')}: origin {o!r}: its host is not in the operator's origin host policy ({', '.join(pol)})"
    return None


def served_files(db: DB, files: list) -> list:
    """A dataset's files as an agent gets them: each file's origins that the URL rule and the current policy admit."""
    pol = origin_policy(db)
    return [{**f, "origins": [o for o in f.get("origins") or [] if not O.url_problem(o) and O.allowed(o, pol)]} for f in files]


def origins_of(db: DB, digest: str) -> tuple[int | None, list[str]]:
    """(size, admitted origins) a registered dataset gives for a blob."""
    urls, size = [], None
    for r in db.q("SELECT files_json FROM datasets WHERE instr(files_json, ?) > 0", (digest,)):
        for f in served_files(db, [f for f in jl(r["files_json"], []) if f.get("digest") == digest]):
            size = f.get("size") if size is None else size
            urls += [o for o in f["origins"] if o not in urls]
    return size, urls


def public(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global and not a.is_multicast


def ssl_context() -> ssl.SSLContext:
    import certifi
    return ssl.create_default_context(cafile=certifi.where())


class OriginError(Exception):
    pass


async def _resolve(host: str, port: int) -> str:
    """The address to connect to: every address the name resolves to must be public (no rebinding window: the caller
    connects to this address, with the name only for SNI and the certificate)."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = sorted({i[4][0] for i in infos})
    if not addrs:
        raise OriginError(f"{host}: no address")
    bad = [a for a in addrs if not public(a)]
    if bad:
        raise OriginError(f"{host} resolves to {bad[0]}, which is not a public address")
    return addrs[0]


MAX_REDIRECTS = 5


async def _get(url: str, start: int, policy: list[str] | None = None):
    """Open `url` (from byte `start`): (reader, status, headers, writer). https to a public address; a redirect is
    followed (at most MAX_REDIRECTS) only to a URL that passes the same rule and the origin host policy."""
    for _ in range(MAX_REDIRECTS + 1):
        reader, status, headers, writer = await _get_once(url, start, policy)
        if status not in (301, 302, 303, 307, 308) or not headers.get("location"):
            return reader, status, headers, writer
        writer.close()
        url = urljoin(url, headers["location"])
    raise OriginError(f"more than {MAX_REDIRECTS} redirects")


async def _get_once(url: str, start: int, policy: list[str] | None):
    why = O.url_problem(url)
    if why:
        raise OriginError(f"{url}: {why}")
    if policy and not O.allowed(url, policy):
        raise OriginError(f"{url}: its host is not in the operator's origin host policy")
    u = urlsplit(url)
    host, port = u.hostname, u.port or 443
    ip = await _resolve(host, port)
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ssl_context(), server_hostname=host), 30)
    target = (u.path or "/") + (f"?{u.query}" if u.query else "")
    req = f"GET {target} HTTP/1.1\r\nHost: {u.netloc}\r\nUser-Agent: oarbankd\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
    if start:
        req += f"Range: bytes={start}-\r\n"
    writer.write((req + "\r\n").encode())
    await writer.drain()
    status_line = (await asyncio.wait_for(reader.readline(), 60)).decode("latin-1").strip()
    parts = status_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        writer.close()
        raise OriginError(f"{url}: not an HTTP answer")
    headers = {}
    while True:
        line = (await asyncio.wait_for(reader.readline(), 60)).decode("latin-1")
        if line in ("\r\n", "\n", ""):
            break
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return reader, int(parts[1]), headers, writer


async def _body(reader, headers):
    """The response body's chunks (Content-Length, chunked, or until the connection closes)."""
    if headers.get("transfer-encoding", "").lower() == "chunked":
        while True:
            n = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
            if n == 0:
                return
            left = n
            while left:
                b = await reader.read(min(left, 1 << 20))
                if not b:
                    raise OriginError("the origin closed the connection mid-chunk")
                left -= len(b)
                yield b
            await reader.readline()
    left = int(headers["content-length"]) if "content-length" in headers else None
    while left is None or left > 0:
        b = await reader.read(1 << 20 if left is None else min(left, 1 << 20))
        if not b:
            if left:
                raise OriginError("the origin closed the connection early")
            return
        if left is not None:
            left -= len(b)
        yield b


class _Fetch:
    """One origin fetch of a blob, shared by every node that asked for it: a background task writes the partial, and
    readers follow it as it grows (woken per chunk, never polling)."""

    def __init__(self, part: Path, size: int):
        self.part, self.size = part, size
        self.written = 0
        self.grew = asyncio.Condition()
        self.done = False
        self.ok = False
        self.error = ""

    async def wrote(self, n: int):
        async with self.grew:
            self.written = n
            self.grew.notify_all()

    async def finish(self, ok: bool, error: str = ""):
        async with self.grew:
            self.done, self.ok, self.error = True, ok, error
            self.grew.notify_all()

    async def follow(self, start: int):
        """The blob's bytes from `start`, as the fetch writes them."""
        with open(self.part, "rb") as f:
            f.seek(start)
            pos = start
            while True:
                async with self.grew:
                    await self.grew.wait_for(lambda: self.written > pos or self.done)
                    if self.done and not self.ok:
                        raise OriginError(self.error or "the origin fetch failed")
                    upto = self.written
                while pos < upto:
                    b = f.read(min(1 << 20, upto - pos))
                    if not b:
                        break
                    pos += len(b)
                    yield b
                if self.done and pos >= self.size:
                    return


_fetches: dict[str, _Fetch] = {}


async def origin_stream(db: DB, digest: str, start: int = 0):
    """Fetch a blob only a dataset's origins have, for a node whose every origin failed: an async iterator of its bytes
    from `start` (it raises OriginError when no origin answers), or None when no registered dataset gives an admitted
    origin for it. One fetch per digest, in the background: every node that asks follows the partial as it grows, and the
    blob is adopted only once its size and sha256 match."""
    if path(db, digest):
        return _file_chunks(path(db, digest), start)
    size, urls = origins_of(db, digest)
    if not urls or size is None:
        return None
    fetch = _fetches.get(digest)
    if fetch is None:                                 # registered before anything awaits: one fetch, however many ask
        upload_dir(db).mkdir(parents=True, exist_ok=True)
        fetch = _fetches[digest] = _Fetch(upload_dir(db) / f"{digest}.origin.partial", size)
        fetch.part.write_bytes(b"")
        asyncio.get_running_loop().create_task(_run_fetch(db, digest, urls, fetch))
    return fetch.follow(start)


async def _first_answer(urls: list[str], start: int, policy: list[str] | None = None):
    last = None
    for url in urls:
        try:
            reader, status, headers, writer = await _get(url, start, policy)
        except (OSError, OriginError, asyncio.TimeoutError, ssl.SSLError) as e:
            last = f"{url}: {e}"
            continue
        if status == (206 if start else 200):
            return url, reader, headers, writer
        writer.close()
        last = f"{url}: answered {status}"
    raise OriginError(last or "no origin")


async def _run_fetch(db: DB, digest: str, urls: list[str], fetch: _Fetch):
    h, n, size = hashlib.sha256(), 0, fetch.size
    try:
        current = await _first_answer(urls, 0, origin_policy(db))
        with open(fetch.part, "ab") as f:
            while True:
                url, reader, headers, writer = current
                try:
                    async for chunk in _body(reader, headers):
                        n += len(chunk)
                        if n > size:
                            raise OriginError(f"{url}: more than the {size} bytes the dataset names")
                        h.update(chunk)
                        f.write(chunk)
                        f.flush()
                        await fetch.wrote(n)
                    break
                except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
                    if n >= size:
                        break
                    db.event("origin_fetch_retry", reason=digest[:12], detail=f"{url}: {e}"[:300])
                    current = await _first_answer([u for u in urls if u != url] + [url], n, origin_policy(db))   # resume
                finally:
                    writer.close()
        if n != size or h.hexdigest() != digest:
            raise OriginError(f"the origins gave {n} bytes hashing to {h.hexdigest()}, not {size} bytes of {digest}")
        final = blob_dir(db) / digest[:2] / digest
        final.parent.mkdir(parents=True, exist_ok=True)
        os.link(fetch.part, final)                    # followers keep reading the partial they opened
        files.seal(final)
        register(db, digest, final, size)
        db.event("origin_fetched", reason=digest[:12], size=size)
        await fetch.finish(True)
    except Exception as e:                            # noqa: BLE001 - every follower hears why
        db.event("origin_fetch_failed", reason=digest[:12], detail=str(e)[:300])
        await fetch.finish(False, str(e))
    finally:
        _fetches.pop(digest, None)
        fetch.part.unlink(missing_ok=True)


async def _file_chunks(p: Path | None, start: int):
    if p is None:
        raise OriginError("the fetched blob is gone")
    with open(p, "rb") as f:
        f.seek(start)
        while b := f.read(1 << 20):
            yield b
