"""Files in and out (docs/design/datasets-media-checkpoints.md, #10): `oarbank dataset upload` resumes an interrupted
upload from the coordinator's offset and registers the dataset; `oarbank dataset download` and `oarbank campaign
download` resume with Range and check every digest; the console stages browser uploads through the same admin API and
serves dataset files and zips of datasets and campaign artifacts."""
import hashlib
import io
import json
import os
import shutil
import subprocess
import time
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from helpers import admin_headers, make_db, sign_in
from oarbank.cli import main as cli
from oarbank.cli import transfer as T
from oarbank.console.app import console_app
from oarbank.console.state import ConsoleState
from oarbank.coordinator import app as coord_app
from oarbank.coordinator import blobstore, clock, datasets
from test_console import SECRET, Server

BIG = os.urandom(5 * 4096 + 123)
SMALL = b"label,score\na,1\n"


@pytest.fixture
def env(tmp_path, monkeypatch):
    clock.set_fake(None)
    path = tmp_path / "oarbank.sqlite3"
    db = make_db(path)
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        url = f"http://127.0.0.1:{oarbankd.port}"
        monkeypatch.setattr(cli, "URL", url)
        monkeypatch.setenv("OARBANKD_URL", url)
        monkeypatch.setenv("OARBANK_TOKEN", admin_headers(db)["authorization"].split(" ", 1)[1])
        monkeypatch.setattr(T, "CHUNK", 4096)
        monkeypatch.setattr(T.time, "sleep", lambda s: None)
        yield {"db": db, "url": url, "path": path, "tmp": tmp_path}


class Cut:
    """An httpx client whose `n`-th matching request fails before it is sent, once, as a dropped connection does; it
    counts the bytes of every PATCH and records every Range asked for."""

    def __init__(self, method: str, n: int):
        self.method, self.n, self.seen, self.sent, self.ranges = method, n, 0, 0, []

    def hook(self, request: httpx.Request):
        if request.headers.get("range"):
            self.ranges.append(request.headers["range"])
        if request.method == self.method:
            self.seen += 1
            if self.seen == self.n:
                raise httpx.ConnectError("connection dropped")
        if request.method == "PATCH":
            self.sent += len(request.content)

    def client(self, url: str):
        return lambda: httpx.Client(base_url=url, timeout=60, event_hooks={"request": [self.hook]})


def folder(tmp):
    root = tmp / "inputs"
    (root / "sub").mkdir(parents=True)
    (root / "big.bin").write_bytes(BIG)
    (root / "sub" / "labels.csv").write_bytes(SMALL)
    return root


def test_an_interrupted_upload_resumes_from_the_coordinators_offset_and_registers_the_dataset(env, monkeypatch):
    db, root = env["db"], folder(env["tmp"])
    cut = Cut("PATCH", 3)
    monkeypatch.setattr(T, "_client", cut.client(env["url"]))
    lines = []
    T.upload(root, "inputs", "inputs:set-1", None, {"note": "x"}, out=lines.append)
    assert any("ConnectError" in s and "resuming" in s for s in lines)
    assert cut.sent == len(BIG) + len(SMALL)                     # the cut chunk never left: nothing was sent twice
    d = datasets.detail(db, "inputs:set-1")
    assert {f["path"]: f["digest"] for f in d["files"]} == {"big.bin": hashlib.sha256(BIG).hexdigest(),
                                                          "sub/labels.csv": hashlib.sha256(SMALL).hexdigest()}
    assert blobstore.path(db, hashlib.sha256(BIG).hexdigest()).read_bytes() == BIG
    # the same command again sends nothing
    again = Cut("none", 0)
    monkeypatch.setattr(T, "_client", again.client(env["url"]))
    lines = []
    T.upload(root, "inputs", "inputs:set-1", None, {"note": "x"}, out=lines.append)
    assert again.sent == 0 and sum("already on the coordinator" in s for s in lines) == 2


def test_an_upload_refuses_symlinks_and_paths_that_are_not_portable(env):
    root = folder(env["tmp"])
    (root / "link").symlink_to(root / "big.bin")
    (root / "a:b.txt").write_text("x")
    with pytest.raises(SystemExit) as e:
        T.folder_files(root)
    assert "link: a symlink" in str(e.value) and "a:b.txt" in str(e.value)


def test_the_default_id_names_the_kind_folder_and_content(env):
    files = [{"path": "a", "digest": "ab" * 32, "size": 1}]
    a = T.default_id("inputs", env["tmp"] / "My Set", files)
    assert a.startswith("inputs:My-Set-") and a != T.default_id("inputs", env["tmp"] / "My Set", files + files)


def registered(env):
    db, root = env["db"], folder(env["tmp"])
    T.upload(root, "inputs", "inputs:set-1", None, {}, out=lambda s: None)
    return db


def test_a_dataset_download_resumes_with_range_and_checks_each_digest(env, monkeypatch):
    registered(env)
    dest = env["tmp"] / "out"
    (dest).mkdir()
    (dest / "big.bin.partial").write_bytes(BIG[:5000])          # what an interrupted download left
    cut = Cut("GET", 1)                                         # and the first fetch is cut too
    monkeypatch.setattr(T, "_client", cut.client(env["url"]))
    assert T.download_dataset("inputs:set-1", dest, out=lambda s: None) == 0
    assert (dest / "big.bin").read_bytes() == BIG and (dest / "sub" / "labels.csv").read_bytes() == SMALL
    assert "bytes=5000-" in cut.ranges and not list(dest.rglob("*.partial"))
    lines = []
    assert T.download_dataset("inputs:set-1", dest, out=lines.append) == 0
    assert sum("already here" in s for s in lines) == 2
    # a partial whose bytes are not the file's: the digest check refuses the result and drops the partial
    (dest / "big.bin").unlink()
    (dest / "big.bin.partial").write_bytes(b"\0" * 5000)
    with pytest.raises(SystemExit, match="the bytes hash to"):
        T.download_dataset("inputs:set-1", dest, out=lambda s: None)
    assert not (dest / "big.bin").exists() and not (dest / "big.bin.partial").exists()


def test_a_download_never_writes_outside_its_folder(env):
    with pytest.raises((SystemExit, ValueError)):
        T._safe_target(env["tmp"] / "out", "../escape")


def done_campaign_job(db, jid, name, files):
    db.x("INSERT OR IGNORE INTO campaigns(campaign_id,module,name,state,created_at) VALUES('c1','toy','c1','done',?)", (time.time(),))
    db.x("INSERT INTO jobs(job_id,job_key,kind,state,spec_json,module,name,campaign_id,created_at,canonical_result_id) "
         "VALUES(?,?,'eval','done','{}','toy',?,'c1',?,?)", (jid, f"k{jid}", name, time.time(), jid))
    db.x("INSERT INTO results(result_id,job_key,job_id,attempt_id,node_id,accepted,canonical,value,fields_json,result_json,module,at) "
         "VALUES(?,?,?,?,'n_x',1,1,1,'{}',?,'toy',?)", (jid, f"k{jid}", jid, jid, json.dumps({"artifacts": [{"name": "out", "files": files}]}), time.time()))


def stored(db, path, data):
    from oarbank.coordinator import modfiles
    return {"path": path, "digest": modfiles.store_bytes(db, data), "size": len(data)}


def test_a_campaign_download_writes_each_jobs_artifacts_under_its_own_folder(env, monkeypatch):
    db = env["db"]
    done_campaign_job(db, 41, "seed 1", [stored(db, "a.bin", BIG)])
    done_campaign_job(db, 42, None, [stored(db, "nested/b.txt", SMALL)])
    monkeypatch.setattr(T, "_client", Cut("none", 0).client(env["url"]))
    dest = env["tmp"] / "camp"
    assert T.download_campaign("c1", dest, out=lambda s: None) == 0
    assert (dest / "41-seed-1" / "out" / "a.bin").read_bytes() == BIG
    assert (dest / "42" / "out" / "nested" / "b.txt").read_bytes() == SMALL


def test_the_admin_api_serves_only_dataset_and_canonical_result_blobs(env):
    db = env["db"]
    from oarbank.coordinator import modfiles
    loose = modfiles.store_bytes(db, b"a module's private file")
    h = admin_headers(db)
    with httpx.Client(base_url=env["url"], headers=h) as c:
        assert c.get(f"/api/v1/blobs/{loose}").status_code == 404
        done_campaign_job(db, 43, "x", [stored(db, "r.bin", SMALL)])
        r = c.get(f"/api/v1/blobs/{hashlib.sha256(SMALL).hexdigest()}", headers={"range": "bytes=6-"})
        assert r.status_code == 206 and r.content == SMALL[6:] and r.headers["content-disposition"].startswith("attachment")
        assert r.headers["x-content-type-options"] == "nosniff"


# ---------------------------------------------------------------------------- the console

@pytest.fixture
def console(env):
    state = ConsoleState(env["path"], env["url"], secret=SECRET)
    with TestClient(console_app(state), client=("127.0.0.1", 50002)) as c:
        sign_in(c, env["db"])
        yield c


def test_the_console_stages_a_browser_upload_through_the_admin_api(env, console):
    digest = hashlib.sha256(BIG).hexdigest()
    r = console.post(f"/datasets/uploads/{digest}", json={"size": len(BIG)})
    assert r.status_code == 200 and r.json() == {"offset": 0, "complete": False}
    r = console.patch(f"/datasets/uploads/{digest}", content=BIG[:4096], headers={"upload-offset": "0"})
    assert r.status_code == 204 and r.headers["upload-offset"] == "4096"
    assert console.patch(f"/datasets/uploads/{digest}", content=BIG[:10], headers={"upload-offset": "0"}).status_code == 409
    r = console.patch(f"/datasets/uploads/{digest}", content=BIG[4096:], headers={"upload-offset": "4096"})
    assert r.headers["upload-complete"] == "1"
    assert blobstore.path(env["db"], digest).read_bytes() == BIG
    bad = hashlib.sha256(b"other").hexdigest()
    console.post(f"/datasets/uploads/{bad}", json={"size": 5})
    assert console.patch(f"/datasets/uploads/{bad}", content=b"wrong", headers={"upload-offset": "0"}).status_code == 422
    # without the session's CSRF token the console forwards nothing
    del console.headers["x-csrf-token"]
    assert console.post(f"/datasets/uploads/{digest}", json={"size": len(BIG)}).status_code == 403
    assert "Upload" in console.get("/datasets/upload").text


def test_the_console_lists_datasets_and_serves_their_files_and_zips(env, console):
    registered(env)
    page = console.get("/datasets").text
    assert "inputs:set-1" in page
    detail = console.get("/datasets/inputs:set-1").text
    assert "big.bin" in detail and "download.zip" in detail
    f = console.get("/datasets/inputs:set-1/files/sub/labels.csv")
    assert f.status_code == 200 and f.content == SMALL and f.headers["content-type"] == "application/octet-stream"
    assert f.headers["x-content-type-options"] == "nosniff" and "attachment" in f.headers["content-disposition"]
    assert console.get("/datasets/inputs:set-1/files/../oarbank.sqlite3").status_code == 404
    z = zipfile.ZipFile(io.BytesIO(console.get("/datasets/inputs:set-1/download.zip").content))
    assert sorted(z.namelist()) == ["big.bin", "sub/labels.csv"] and z.read("big.bin") == BIG


def test_the_console_zips_a_campaigns_artifacts(env, console):
    db = env["db"]
    done_campaign_job(db, 41, "seed 1", [stored(db, "a.bin", BIG)])
    z = zipfile.ZipFile(io.BytesIO(console.get("/campaigns/c1/artifacts.zip").content))
    assert z.namelist() == ["41-seed-1/out/a.bin"] and z.read("41-seed-1/out/a.bin") == BIG


@pytest.mark.skipif(not shutil.which("node"), reason="needs node")
def test_the_browser_upload_hashes_like_sha256():
    root = Path(__file__).parents[1]
    out = subprocess.run(["node", str(root / "tests" / "js" / "sha256_check.cjs"),
                          str(root / "src" / "oarbank" / "console" / "static" / "upload.js")], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0 and out.stdout.strip() == "ok", out.stderr


def test_a_module_importer_turns_an_uploaded_dataset_into_its_own(env):
    from helpers import install, run_op
    from oarbank.coordinator import modcalls
    db = registered(env)
    install(db, Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "reel")
    modcalls.use(db)
    r = run_op(db, "mod.reel.adopt_upload", "inputs:set-1", params={})
    assert r["ok"] and r["result"]["result"] == {"dataset_id": "asset:set-1"}
    d = datasets.detail(db, "asset:set-1")
    src = datasets.detail(db, "inputs:set-1")
    assert d["module"] == "reel" and {f["digest"] for f in d["files"]} == {f["digest"] for f in src["files"]}
