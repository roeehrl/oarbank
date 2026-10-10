"""Loading, busy and connection states in the console (docs/design/console-loading-states.md): the shipped app.js
against a DOM fake (tests/console_ui.mjs), the markup it binds to, and the upload staging route that gives uploads real
progress."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from helpers import certify, enrolled_node, make_db, sign_in

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src" / "oarbank" / "console" / "templates"


def test_app_js_busy_states_errors_and_live_indicator():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is needed to exercise the console JavaScript")
    r = subprocess.run([node, str(Path(__file__).with_name("console_ui.mjs"))], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr


def test_markup_the_loading_states_bind_to():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert '"timeout": 30000' in base                                      # no htmx request waits forever
    assert 'id="live"' in base and 'data-state="connecting"' in base       # the stream indicator
    assert 'id="announcer"' in base and 'role="status"' in base            # one polite live region
    banner = re.search(r'<div id="stale-banner"[^>]*>', base).group(0)
    assert "role=" not in banner, "the banner's age ticks every 2 s: it is not a live region"
    assert "data-reload data-always" in base
    macro = (TEMPLATES / "_macros.html").read_text(encoding="utf-8")
    assert 'data-busy-label="Preparing review…"' in macro and 'data-stage="/stage/{{ op }}"' in macro
    assert '<script src="{{ asset(\'/static/app.js\') }}" defer></script>' in (TEMPLATES / "login.html").read_text(encoding="utf-8")
    prot = (TEMPLATES / "protection.html").read_text(encoding="utf-8")
    assert 'hx-sync="this:replace"' in prot and 'class="placeholder"' in prot


@pytest.fixture
def console(tmp_path):
    from fastapi.testclient import TestClient
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from oarbank.coordinator import app as coord_app
    from test_console import SECRET, Server
    db = make_db(tmp_path / "oarbank.sqlite3")
    certify(db, enrolled_node(db, "mini")[1])
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(str(db.path), f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        with TestClient(console_app(state, tmp_path / "logs"), client=("127.0.0.1", 50011)) as c:
            sign_in(c, db)
            yield c, db


def test_rendered_pages_carry_busy_and_stage_attributes(console):
    c, _ = console
    page = c.get("/modules").text
    form = re.search(r'<form[^>]*action="/do/modules.install"[^>]*>', page).group(0)
    assert 'data-stage="/stage/modules.install"' in form and 'data-stage-field="bundle"' in form
    assert 'data-busy-label="Preparing review…"' in page                   # modules.install is T2: it opens a review
    agent = c.get("/agent").text
    meta = re.search(r'<form[^>]*action="/do/vendor.metadata.upload"[^>]*>', agent).group(0)
    assert "data-stage" not in meta, "metadata files are read by the console, not staged"
    assert 'data-stage="/stage/agent.upload"' in agent
    assert 'data-stage="/stage/coordinator.builds.upload"' in c.get("/coordinator").text
    home = c.get("/").text
    assert 'class="live"' in home and 'id="as-of"' in home


def test_stage_then_operation_posts_only_the_digest(console):
    """app.js uploads the bundle to /stage/<op> (progress events), then posts the form with p.sha256 and no file: the same
    T2 plan page as a form that carries the file."""
    from test_module_lifecycle import bundle_of, relay_version
    c, _ = console
    data = bundle_of(relay_version("1.2.0")).read_bytes()
    r = c.post("/stage/modules.install", content=data, headers={"content-type": "application/octet-stream"})
    assert r.status_code == 200, r.text
    sha = r.json()["sha256"]
    assert len(sha) == 64
    r = c.post("/do/modules.install", data={"return_to": "/modules", "idem": "s1", "target": "", "p.sha256": sha},
               follow_redirects=False)
    assert r.status_code == 200 and "Review" in r.text and "1.2.0" in r.text
    # oarbankd's refusal (an empty archive) comes back as JSON the page shows inline
    r = c.post("/stage/coordinator.builds.upload", content=b"", headers={"content-type": "application/octet-stream"})
    assert r.status_code == 400 and r.json()["error"] == "bad_coordinator_build"
    assert c.post("/stage/fleet.pause", content=b"x").status_code == 404


def test_stage_needs_the_session_and_its_csrf_header(console):
    c, _ = console
    token = c.headers.pop("x-csrf-token")
    try:
        assert c.post("/stage/modules.install", content=b"x").status_code == 403
    finally:
        c.headers["x-csrf-token"] = token
    c.cookies.clear()
    assert c.post("/stage/modules.install", content=b"x", headers={"x-csrf-token": token}).status_code == 403


def test_scripts_and_stylesheets_carry_a_content_version():
    """After an upgrade a browser must fetch the new app.js and app.css, not run the old ones from its cache: every
    asset URL carries a version of the file's content."""
    from oarbank.console import app as console
    url = console.asset("/static/app.js")
    assert url.startswith("/static/app.js?v=") and len(url.split("=", 1)[1]) == 12
    assert console.asset("/static/no-such-file.js") == "/static/no-such-file.js"
    for t in TEMPLATES.glob("*.html"):
        text = t.read_text(encoding="utf-8")
        assert 'src="/static' not in text and 'href="/static' not in text, f"{t.name} links an unversioned asset"
