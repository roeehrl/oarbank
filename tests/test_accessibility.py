"""Accessibility: axe-core (WCAG 2.0/2.1 A and AA, best practices) over every console page as
rendered, and WCAG contrast for every text/background pair the stylesheet uses, in both colour schemes.

axe runs in Node with jsdom; point OARBANK_A11Y_NODE_MODULES at a node_modules holding axe-core and jsdom
(the nightly job installs them). Without it the axe test is skipped; the contrast test always runs."""
import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "src" / "oarbank" / "console" / "static" / "app.css"
NODE_MODULES = os.environ.get("OARBANK_A11Y_NODE_MODULES")


# ------------------------------------------------------------------ contrast (always)

def _tokens(block: str) -> dict:
    out = {}
    for k, v in re.findall(r"--([a-z]+):\s*#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\b", block):
        out[k] = "#" + (v if len(v) == 6 else "".join(c * 2 for c in v))
    return out


def schemes() -> dict:
    css = CSS.read_text(encoding="utf-8")
    light = _tokens(css.split("@media")[0])
    dark_block = re.search(r"@media \(prefers-color-scheme: dark\) \{(.*?)\}\s*\}", css, re.S).group(1)
    return {"light": light, "dark": {**light, **_tokens(dark_block)}}


def _lum(hex_: str) -> float:
    c = [int(hex_[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def ratio(a: str, b: str) -> float:
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# (foreground, background) pairs as the stylesheet uses them; "#fff" is literal white text on a filled chip/button
PAIRS = [("fg", "bg"), ("fg", "card"), ("fg", "chip"), ("mut", "bg"), ("mut", "card"), ("mut", "chip"), ("acc", "bg"),
         ("acc", "card"), ("#fff", "okf"), ("#fff", "warnf"), ("#fff", "badf"), ("#fff", "accf"), ("ok", "card"), ("bad", "card"),
         ("warn", "card"), ("ok", "bg"), ("bad", "bg")]


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_text_contrast_meets_wcag_aa(scheme):
    t = schemes()[scheme]
    bad = []
    for fg, bg in PAIRS:
        f = fg if fg.startswith("#") else t[fg]
        f = "#ffffff" if f == "#fff" else f
        r = ratio(f, t[bg])
        if r < 4.5:                                   # AA for normal text (most console text is 12-14 px)
            bad.append(f"{fg} on {bg}: {r:.2f}")
    assert not bad, f"{scheme}: " + "; ".join(bad)


# ------------------------------------------------------------------ axe (with Node modules)

@pytest.mark.skipif(not NODE_MODULES, reason="set OARBANK_A11Y_NODE_MODULES to a node_modules with axe-core and jsdom")
def test_every_console_page_has_no_serious_axe_violations(tmp_path):
    from fastapi.testclient import TestClient
    from helpers import SCENES, PARAMS, certify, create_study, enrolled_node, fresh, make_db, sign_in
    from oarbank.console.app import console_app
    from oarbank.console.state import ConsoleState
    from oarbank.coordinator import app as coord_app, core, modviews
    from test_console import SECRET, Server
    db = make_db(tmp_path / "oarbank.sqlite3")
    node = certify(db, enrolled_node(db)[1])
    cid = create_study(db, "a11y", [{"label": "c1", "params": {**PARAMS, "samples": 25}}], SCENES[:1],
                       {"label": "base", "params": PARAMS})
    modviews.refresh(db, force=True)
    job = db.one("SELECT job_id FROM jobs WHERE campaign_id=? LIMIT 1", (cid,))["job_id"]
    nid = node["node_id"]
    # the Agent page with two builds, a canary on the node, and a failed update (every control renders)
    for sha, v in (("a" * 64, "0.4.0"), ("b" * 64, "0.4.1")):
        db.x("INSERT INTO agent_builds(sha256, version, path, size, uploaded_at, uploaded_by) VALUES(?,?,?,?,?,?)",
             (sha, v, "/dev/null", 2_900_000, 0, "test"))
    db.x("INSERT INTO agent_channel(id, current, canary, canary_nodes_json) VALUES(1, ?, ?, ?)", ("a" * 64, "b" * 64, json.dumps([nid])))
    db.x("UPDATE nodes SET agent_build=?, agent_update_json=? WHERE node_id=?",
         ("a" * 64, json.dumps({"state": "failed", "error": "sha256 mismatch"}), nid))
    db.x("INSERT INTO coordinator_plans(plan_id,target_url,state,created_at) VALUES('mvp_1','http://100.64.0.2:7443','paired',0)")
    db.x("INSERT INTO coordinator_moves(move_id,plan_id,epoch,statement,state,created_at,not_before,actor,reason) VALUES(?,?,?,?,?,?,?,?,?)",
         ("mv_1", "mvp_1", 2, json.dumps({"to": {"url": "http://100.64.0.2:7443"}}), "pending", 0, 2e9, "test", "a11y"))
    db.x("UPDATE nodes SET cik_pinned='ab'||substr(hex(randomblob(31)),1,62) WHERE node_id=?", (nid,))
    pages = ["/", "/agent", "/coordinator", f"/nodes/{nid}", f"/nodes/{nid}/protection", "/campaigns", f"/campaigns/{cid}", "/jobs", f"/jobs/{job}",
             "/events", "/audit", "/settings", "/verify", "/modules", "/modules/relay", "/modules/toy", "/m/relay/scores",
             f"/explain/job/{job}", f"/explain/node/{nid}", "/modules/relay/health", "/datasets", "/datasets/upload"]
    files = []
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(str(db.path), f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        with TestClient(console_app(state, tmp_path / "logs"), client=("127.0.0.1", 50009)) as c:
            sign_in(c, db)
            for p in pages:
                r = c.get(p)
                assert r.status_code == 200, p
                f = tmp_path / (re.sub(r"[^a-z0-9]+", "_", p.lower()).strip("_") or "home")
                f = f.with_suffix(".html")
                f.write_text(r.text)
                files.append(f)
            r = c.post("/do/releases.promote", data={"target": "x", "return_to": "/", "idem": "a"})     # a plan page
            (tmp_path / "plan.html").write_text(r.text)
            files.append(tmp_path / "plan.html")
    out = subprocess.run(["node", str(ROOT / "tests" / "a11y" / "run_axe.cjs"), *map(str, files)], capture_output=True, text=True,
                         env={**os.environ, "NODE_PATH": NODE_MODULES}, timeout=600)
    assert out.returncode == 0, out.stderr[-2000:]
    report = json.loads(out.stdout)
    (tmp_path / "axe-report.json").write_text(out.stdout)
    if os.environ.get("OARBANK_A11Y_REPORT"):
        Path(os.environ["OARBANK_A11Y_REPORT"]).write_text(out.stdout)
    serious = [f"{Path(r['file']).stem}: {v['id']} ({v['impact']}) {v['help']} at {v['nodes'][:2]}"
               for r in report for v in r["violations"] if v["impact"] in ("serious", "critical")]
    assert not serious, "\n".join(serious)
