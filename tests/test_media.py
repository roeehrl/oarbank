"""Media components (docs/design/datasets-media-checkpoints.md, #11): the reference module shows a gallery, a video
player, a text artifact and a compare slider from job artifacts with no iframe; every artifact reference is checked
against the module's own rows; bytes come only from the module origin, at capability URLs, sniffed against the
allowlist (an SVG with a script and HTML named .png are refused, text is never HTML), with ranges, caps, nosniff and a
sandboxing CSP."""
import json
import re
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from helpers import install, make_db, sign_in
from oarbank.console import media
from oarbank.console.app import console_app
from oarbank.console.frames import frames_app
from oarbank.console.state import ConsoleState, Reader
from oarbank.coordinator import app as coord_app
from oarbank.coordinator import modcalls, modfiles, modviews
from test_console import SECRET, Server

REEL_DIR = Path(__file__).parents[1] / "vendor" / "oarbank-sdk" / "examples" / "reel"
sys.path.insert(0, str(REEL_DIR))
import reel_frames as F  # noqa: E402

ORIGIN = "http://127.0.0.1:7999"
CLIP = (REEL_DIR / "assets" / "clip.webm").read_bytes()
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>'
HTML = b"<!doctype html><script>fetch('/api/v1/fleet')</script>"


def done_job(db, jid, module, artifacts):
    from oarbank.coordinator import core
    core._register_artifacts(db, {"artifacts": artifacts}, module)          # as a completion does: art: datasets
    db.x("INSERT INTO jobs(job_id,job_key,kind,state,spec_json,module,created_at,canonical_result_id) "
         "VALUES(?,?,'eval','done',?,?,?,?)", (jid, f"k{jid}", "{}", module, time.time(), jid))
    db.x("INSERT INTO results(result_id,job_key,job_id,attempt_id,node_id,accepted,canonical,value,fields_json,result_json,module,at) "
         "VALUES(?,?,?,?,?,1,1,?,?,?,?,?)", (jid, f"k{jid}", jid, jid, "n_x", 3, json.dumps({"frames": 3}),
                                            json.dumps({"artifacts": artifacts}), module, time.time()))


def file(db, path, data, thumb=None):
    f = {"path": path, "digest": modfiles.store_bytes(db, data), "size": len(data)}
    if thumb is not None:
        f["thumbnail"] = {"digest": modfiles.store_bytes(db, thumb), "size": len(thumb)}
    return f


@pytest.fixture
def env(tmp_path):
    path = tmp_path / "oarbank.sqlite3"
    db = make_db(path)
    install(db, REEL_DIR)
    modcalls.use(db)
    frames = [file(db, F.frame_name(i), F.png(F.pixels(7, i)), F.png(F.thumbnail(F.pixels(7, i)), 16, 12)) for i in range(3)]
    done_job(db, 700, "reel", [{"name": "frames", "files": frames},
                               {"name": "clip", "files": [file(db, "clip.webm", CLIP)]},
                               {"name": "log", "files": [file(db, "render.txt", b"<b>reel</b> 3 frames\n")]}])
    done_job(db, 701, "reel", [{"name": "frames", "files": [file(db, "frame-0000.png", SVG), file(db, "frame-0001.png", HTML)]}])
    done_job(db, 800, "toy", [{"name": "out", "files": [file(db, "secret.png", F.png(F.pixels(1, 1)))]}])
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(path, f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        app = console_app(state, module_origin=ORIGIN)
        frames_c = TestClient(frames_app(app.state.catalog, "http://127.0.0.1:7400", tokens=app.state.media_tokens,
                                         reader=Reader(path), home=tmp_path))
        with TestClient(app, client=("127.0.0.1", 50002)) as c:
            sign_in(c, db)
            yield {"db": db, "c": c, "f": frames_c, "tokens": app.state.media_tokens, "reader": Reader(path)}


def token_of(url):
    return url.rsplit("/b/", 1)[1]


def test_the_reference_module_shows_a_gallery_a_video_text_and_a_compare_slider_with_no_iframe(env):
    db, c, f = env["db"], env["c"], env["f"]
    db.x("DELETE FROM jobs WHERE job_id=701")                        # its frames are the malicious ones
    modviews.refresh(db, force=True)
    r = c.get("/modules/reel")
    html, csp = r.text, r.headers["content-security-policy"]
    assert f"img-src 'self' data: {ORIGIN}" in csp and f"media-src {ORIGIN}" in csp
    assert "<iframe class=\"mod-frame\"" not in html                # no module frame: the console draws the media
    gallery = re.findall(rf'<a href="({ORIGIN}/b/[^"]+)" [^>]+><img class="mod-media-img" src="({ORIGIN}/b/[^"]+)"', html)
    assert len(gallery) == 3 and all(full != thumb for full, thumb in gallery)       # each frame by its thumbnail
    compare = re.findall(rf'<img class="mod-media-img[^"]*" src="({ORIGIN}/b/[^"]+)" alt="(first|last) frame"', html)
    assert len(compare) == 2
    imgs = [thumb for _, thumb in gallery]
    video = re.search(rf'<video class="mod-media-av" src="({ORIGIN}/b/[^"]+)"', html)
    text = re.search(rf'<iframe class="mod-media-text" src="({ORIGIN}/b/[^"]+)" sandbox=""', html)
    assert video and text and "data-compare" in html and 'href="/jobs/700"' in html
    thumb = f.get(f"/b/{token_of(imgs[0])}")
    assert thumb.status_code == 200 and thumb.headers["content-type"] == "image/png" and thumb.content.startswith(b"\x89PNG")
    assert thumb.headers["x-content-type-options"] == "nosniff" and thumb.headers["content-security-policy"].startswith("sandbox")
    assert "set-cookie" not in thumb.headers
    v = f.get(f"/b/{token_of(video.group(1))}", headers={"range": "bytes=0-99"})
    assert v.status_code == 206 and v.content == CLIP[:100] and v.headers["content-range"] == f"bytes 0-99/{len(CLIP)}"
    assert v.headers["content-type"] == "video/webm" and v.headers["accept-ranges"] == "bytes"
    assert f.get(f"/b/{token_of(video.group(1))}", headers={"range": f"bytes={len(CLIP)}-"}).status_code == 416
    t = f.get(f"/b/{token_of(text.group(1))}")
    assert t.headers["content-type"] == "text/plain; charset=utf-8" and t.content == b"<b>reel</b> 3 frames\n"   # text, never HTML


def test_an_svg_with_a_script_and_html_named_png_are_refused(env):
    f, tokens = env["f"], env["tokens"]
    for i in (0, 1):
        hit = media.resolve(env["reader"], "reel", {"job": 701, "artifact": "frames", "path": F.frame_name(i)})
        assert hit is not None                                       # the module's own: the reference passes ...
        r = f.get(f"/b/{tokens.mint('reel', hit['digest'], 'image')}")
        assert r.status_code == 415 and "refused" in r.text and r.headers["content-type"].startswith("text/plain")
        assert r.headers["x-content-type-options"] == "nosniff"     # ... and its bytes are refused, inert either way


def test_references_are_checked_against_the_modules_own_rows(env):
    rd = env["reader"]
    toy_png = rd.one("SELECT result_json FROM results WHERE job_id=800")["result_json"]
    toy_digest = json.loads(toy_png)["artifacts"][0]["files"][0]["digest"]
    assert media.resolve(rd, "reel", {"job": 800, "artifact": "out", "path": "secret.png"}) is None     # another module's job
    assert media.resolve(rd, "reel", {"digest": toy_digest}) is None                                  # a blob reel cannot see
    assert media.resolve(rd, "reel", {"job": 700, "artifact": "frames", "path": "missing.png"}) is None
    assert media.resolve(rd, "reel", {"job": 700, "artifact": "frames", "path": "../frame-0000.png"}) is None
    assert media.resolve(rd, "reel", "<img src=x>") is None
    hit = media.resolve(rd, "reel", {"job": 700, "artifact": "frames", "path": F.frame_name(0)})
    assert hit["thumbnail"] and hit["job"] == 700
    assert media.resolve(rd, "reel", {"digest": hit["digest"]})["digest"] == hit["digest"]          # its jobs' artifacts
    assert media.urls(rd, env["tokens"], "reel", ORIGIN, {"job": 800, "artifact": "out", "path": "secret.png"}, "image") is None


def test_capability_urls_cannot_be_forged_widened_or_kept(env):
    f, tokens = env["f"], env["tokens"]
    hit = media.resolve(env["reader"], "reel", {"job": 700, "artifact": "clip", "path": "clip.webm"})
    good = tokens.mint("reel", hit["digest"], "video")
    assert f.get(f"/b/{good}").status_code == 200
    body, sig = good.split(".")
    assert f.get(f"/b/{body}.{'A' * len(sig)}").status_code == 403                     # forged signature
    other = media.Tokens()
    assert f.get(f"/b/{other.mint('reel', hit['digest'], 'video')}").status_code == 403     # another process's key
    old = tokens.mint("reel", hit["digest"], "video", now=time.time() - 2 * media.TOKEN_TTL_S)
    assert f.get(f"/b/{old}").status_code == 403                                          # expired
    assert f.get(f"/b/{tokens.mint('reel', hit['digest'], 'image')}").status_code == 415   # a video is not an image


def test_size_caps(env, monkeypatch):
    from oarbank_sdk import media as M
    hit = media.resolve(env["reader"], "reel", {"job": 700, "artifact": "frames", "path": F.frame_name(0)})
    monkeypatch.setitem(M.CAPS, "image", 10)
    assert env["f"].get(f"/b/{env['tokens'].mint('reel', hit['digest'], 'image')}").status_code == 413
