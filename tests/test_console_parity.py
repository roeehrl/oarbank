"""The operator's side in parity (docs/design/console-parity.md, PLAN D42): what operators read and do on the console's node,
job and protection pages has `oarbank` commands reading the same documents through the admin API, every command the registry
names exists, explain's remedies are runnable from both, and the console shows what it left unshown (GPU API evidence,
per-capability enforcement, folders, pinned datasets, container image first runs, a plan's impact)."""
import json
import re
import sys
import time

import pytest
from fastapi.testclient import TestClient

from oarbank.cli import main as cli
from oarbank.console.app import console_app
from oarbank.console.state import ConsoleState
from oarbank.contracts import impact, operations, parity
from oarbank.coordinator import access, app as coord_app, core, detail, modcalls, protection

from helpers import FACTS, PARAMS, SEATBELT, certify, create_study, enrolled_node, fresh, make_db, run_op, sign_in
from test_console import SECRET, Server

GPU = {"host": ["metal", "opencl"], "containers": ["vulkan"],
       "evidence": {"metal": "Apple M5 Pro", "cuda": "CUDA does not run on macOS", "containers": "virtio-gpu:venus (krunkit)"}}
DOCTOR = {"at": 1790000000.0, "release_id": "r_1", "capabilities": ["java17"], "gpu_apis": GPU,
          "modules": {"relay": {"health": "healthy", "checks": [{"name": "runner", "ok": True}]},
                      "toy": {"health": "undetected", "checks": [{"name": "gpu_apis", "ok": False, "detail": "needs cuda"}]}}}
CONTAINERS = {"runtime": "wslc", "state": "missing", "platforms": [], "gpu": "undetected",
              "missing": [{"what": "virtual_machine_platform", "detail": "the Virtual Machine Platform feature is off",
                           "fix": "oarbank-agent containers install"}]}
PROCS = [{"pid": 812, "ppid": 1, "path": "/Applications/zoom.us.app/Contents/MacOS/zoom.us", "comm": "zoom.us",
          "argv": ["zoom.us"], "cpu_cores": 0.4, "footprint_gb": 1.1}]
RULES = {"schema": 1, "rule": [{"id": "zoom", "match": {"path_contains": "zoom.us"}, "reserve": {"mem_gb": 2}}]}


@pytest.fixture
def fleet(tmp_path, monkeypatch):
    """A real oarbankd admin API on a loopback port, and `oarbank` pointed at it with the owner's token."""
    db = make_db(tmp_path / "oarbank.sqlite3")
    node = certify(db, enrolled_node(db)[1])
    sid = create_study(db, "parity", [], ["scene:s1"], {"label": "base", "params": PARAMS})
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        monkeypatch.setenv("OARBANK_TOKEN", access.ensure_admin_token(db.root))
        monkeypatch.setenv("OARBANK_REASON", "parity test")
        monkeypatch.setattr(cli, "URL", f"http://127.0.0.1:{oarbankd.port}")
        yield {"db": db, "node": node, "nid": node["node_id"], "sid": sid, "oarbankd": oarbankd, "tmp": tmp_path}


def oarbank(capsys, *args) -> tuple[int, str]:
    """`oarbank <args>` in this process: (exit code, stdout and any exit message)."""
    capsys.readouterr()
    old = sys.argv
    sys.argv, code, msg = ["oarbank", *map(str, args)], 0, ""
    try:
        cli.main()
    except SystemExit as e:
        code, msg = (e.code, "") if isinstance(e.code, int) or e.code is None else (1, str(e.code))
    finally:
        sys.argv = old
    return code or 0, capsys.readouterr().out + msg


def dress(db, nid):
    """Give the node everything the node page and `oarbank node show` report."""
    facts = {**FACTS, "containers": CONTAINERS,
             "sandbox": {"backend": "seatbelt", "enforcement": {**SEATBELT, "ipc": "cooperative"}}}
    tel = {"services_running": [], "services_held": {"relay/scorer": "preempt_memory"}, "services_reserved_gb": 0.0,
           "guard": "clear"}
    run_op(db, "settings.folders.update", "inputs", {"access": "read", "nodes": {nid: "/Users/shared/in"}})
    db.x("UPDATE nodes SET facts_json=?, doctor_json=?, telemetry_json=?, folders_json=?, processes_json=?, processes_at=? "
         "WHERE node_id=?", (json.dumps(facts), json.dumps(DOCTOR), json.dumps(tel),
                             json.dumps({"inputs": {"access": "read", "status": "ok"}}), json.dumps(PROCS), time.time(), nid))


# ------------------------------------------------------------------ the parity report checks the commands themselves

def test_every_command_the_registry_names_exists():
    assert parity.gaps() == []
    assert parity.cli_exists("oarbank protection preview <nid> <file>") and parity.cli_exists("oarbank node mode <nid> <mode>")
    assert parity.cli_exists("oarbank module pin|unpin <name>@<version> --node <node>")
    assert parity.cli_exists("oarbank folders map <id> --access read|write --node <node>=<path>")
    assert not parity.cli_exists("oarbank protection frob <nid>")                 # a word the positional does not take
    assert not parity.cli_exists("oarbank nodes show <nid>")                      # no such subcommand
    assert not parity.cli_exists("oarbank job show <jid> --verbose")              # no such flag
    assert parity.cli_exists("module CLIs (golden:<module>, dataset_groups)")     # prose, not a command


def test_a_registry_command_that_does_not_exist_is_a_gap(monkeypatch):
    bad = operations.REGISTRY["nodes.set_mode"].model_copy(update={"cli": ["oarbank node frob <nid> <mode>"]})
    monkeypatch.setattr(operations, "OPS", [bad if o.id == bad.id else o for o in operations.OPS])
    assert parity.gaps() == ["operation nodes.set_mode: the registry's CLI command `oarbank node frob <nid> <mode>` does not exist"]


def test_explain_kinds_are_checked_against_the_cli_parser(monkeypatch):
    monkeypatch.setattr(parity, "EXPLAIN_KINDS", ("job", "node", "campaign"))
    assert "explain campaign: no CLI path" in parity.gaps()


# ------------------------------------------------------------------ oarbank node show | mode

def test_node_show_prints_what_the_node_page_shows(fleet, capsys):
    db, nid = fleet["db"], fleet["nid"]
    dress(db, nid)
    db.x("UPDATE nodes SET services_json=?, services_at=? WHERE node_id=?", (json.dumps({"services": [
        {"service": "relay/scorer", "health": "healthy", "running": False, "held": "preempt_memory"}]}), time.time(), nid))
    code, out = oarbank(capsys, "node", "show", nid)
    assert code == 0, out
    lines = [x.strip() for x in out.splitlines()]
    assert lines[0].startswith(f"mini {nid} darwin-arm64 ready active online") and "module relay: certified" in lines
    assert "toy: undetected, 1 checks" in lines and "failed gpu_apis: needs cuda" in lines
    assert "gpu apis: host metal, opencl; containers vulkan" in lines         # the facts' containers.gpu says undetected
    assert "cuda: CUDA does not run on macOS" in lines and "metal: Apple M5 Pro" in lines
    assert "containers: wslc missing" in lines
    assert "missing virtual_machine_platform: the Virtual Machine Platform feature is off; fix: oarbank-agent containers install" in lines
    assert "service relay/scorer: stopped, healthy, stopped: held: preempt_memory" in lines     # the agent's report, once
    assert out.count("relay/scorer") == 1
    assert "folder inputs: read /Users/shared/in, ok (statement 1, unsigned)" in lines
    assert "sandbox: seatbelt" in lines and "ipc: cooperative, keeps out relay, toy" in lines
    assert "filesystem: enforced, needed by relay, toy" in lines and "no_link_local: unavailable" in lines
    assert oarbank(capsys, "node", "show", "mini")[1] == out                         # by hostname too
    doc = json.loads(oarbank(capsys, "node", "show", nid, "--json")[1])
    same = detail.node(db, nid, time.time(), lambda m: modcalls.info(m).manifest)       # what the console renders
    for k in ("doctor", "gpu", "containers", "services", "folders", "sandbox"):
        assert doc[k] == json.loads(json.dumps(same[k])), k
    assert oarbank(capsys, "node", "show", "nope")[0] == 1


def test_node_mode_sets_the_protection_mode(fleet, capsys):
    db, nid = fleet["db"], fleet["nid"]
    code, out = oarbank(capsys, "node", "mode", nid, "strict_yield", "--yes")
    assert code == 0, out
    assert "nodes.set_mode (T1)" not in out and protection.current(db, nid)[1]["node"]["mode"] == "strict_yield"
    code, out = oarbank(capsys, "node", "mode", nid, "turbo")
    assert code == 1 and "fleet_first|moderate|strict_yield" in out


def test_settings_commands_do_what_the_settings_pages_do(fleet, capsys):
    """`oarbank settings` reads and writes what the node's Settings tab and Fleet Settings do: the effective values with
    their source, set and reset at a node or the fleet (previewed: the nodes it reaches), the whole chain, the reverse
    view; `oarbank node show` names what the node sets itself, and `node policy` / `node limits` are gone."""
    db, nid = fleet["db"], fleet["nid"]
    vals = lambda: json.loads(db.one("SELECT settings_json FROM nodes WHERE node_id=?", (nid,))["settings_json"])
    code, out = oarbank(capsys, "settings", "set", "os_reserve_gb", "10", "--node", nid, "--yes")
    assert code == 0, out
    assert "settings.apply (T1)" in out and "Changes the effective value on 1 node (mini)" in out and "Saved · rev" in out
    assert vals()["policy"]["os_reserve_gb"] == 10
    code, out = oarbank(capsys, "settings", "set", "job_mem_gb", "abc", "--node", nid, "--yes")
    assert code == 1 and "job_mem_gb: Memory per job slot: expected number" in out           # refused at the coordinator
    code, out = oarbank(capsys, "settings", "get", "--node", "mini")
    lines = [x.strip() for x in out.splitlines()]
    assert any(x.startswith("os_reserve_gb") and "10 GB" in x and x.endswith("This node") for x in lines), out
    assert any(x.startswith("user_reserve_gb") and x.endswith("Default") for x in lines)
    code, out = oarbank(capsys, "settings", "explain", "os_reserve_gb", "--node", nid)
    assert "Memory kept for the system (os_reserve_gb) on mini: 10 GB · This node" in out
    assert "Default" in out and "(24 GB RAM)" in out and "<- in effect" in out
    code, out = oarbank(capsys, "node", "show", nid)
    assert "os_reserve_gb (Memory kept for the system): 10 GB · This node  reset: oarbank settings reset os_reserve_gb --node mini" in out
    code, out = oarbank(capsys, "settings", "set", "user_idle_s", "60", "--yes")                  # the fleet: T2, previewed
    assert code == 0 and "settings.apply (T2)" in out and "Changes the effective value on 1 node (mini)" in out
    assert vals()["policy"]["user_idle_s"] == 60
    code, out = oarbank(capsys, "settings", "overrides", "os_reserve_gb")
    assert "node   mini" in out and "10 GB" in out
    assert oarbank(capsys, "settings", "reset", "os_reserve_gb", "--node", nid, "--yes")[0] == 0
    assert vals()["policy"]["os_reserve_gb"] == 4 and not db.q("SELECT 1 FROM setting_values WHERE scope='node'")
    code, out = oarbank(capsys, "settings", "set", "disabled_services", "relay/scorer,relay/vm", "--node", nid, "--dry-run")
    assert code == 2 and "plan pl_" in out and vals()["policy"]["disabled_services"] == []
    assert oarbank(capsys, "node", "policy", nid)[0] != 0 and oarbank(capsys, "node", "limits", nid)[0] != 0
    db.x("UPDATE nodes SET capacity_json=? WHERE node_id=?", (json.dumps(
        {"cpu_slots": 10, "idle_cpu_slots": 10, "slots": 10, "mem_gb_free": 14.0, "mem_binding": "in_use", "mem_in_use_gb": 6.0,
         "user_present": False, "admit": True, "binding_limit": "auto"}), nid))
    lines = [x.strip() for x in oarbank(capsys, "node", "show", nid)[1].splitlines()]
    assert ("why: 10 slots (5 performance cores + 10 efficiency cores at half) · 14 GB free for jobs "
            "(apps and the system use 6.0 GB)") in lines
    assert "(5 performance cores + 10 efficiency cores at half)" in oarbank(capsys, "fleet")[1]


def test_the_ntfy_token_is_write_only(fleet, capsys, monkeypatch):
    import io
    db = fleet["db"]
    monkeypatch.setattr(sys, "stdin", io.StringIO("tok-123456\n"))
    code, out = oarbank(capsys, "settings", "set-secret", "ntfy_token")
    assert code == 0 and "ntfy_token set: fingerprint fp:" in out and "tok-123456" not in out
    from oarbank.coordinator import modsecrets
    assert modsecrets.core_value(db, "ntfy_token") == "tok-123456"
    assert "tok-123456" not in json.dumps(db.q("SELECT * FROM audit"), default=str)
    assert oarbank(capsys, "settings", "clear-secret", "ntfy_token", "--yes")[0] == 0
    assert modsecrets.core_state(db, "ntfy_token") == {"set": False}


# ------------------------------------------------------------------ oarbank protection

def test_protection_commands_do_what_the_protection_page_does(fleet, capsys):
    db, nid, tmp = fleet["db"], fleet["nid"], fleet["tmp"]
    dress(db, nid)
    rules = tmp / "rules.json"
    rules.write_text(json.dumps(RULES))
    code, out = oarbank(capsys, "protection", "preview", nid, rules)
    assert code == 2, out                                            # previewed, nothing applied (Terraform's convention)
    assert f"protection.rules.update (T2) on {nid}:" in out and "rule zoom matches 1 process(es): 812 zoom.us" in out
    assert protection.current(db, nid)[0] == 0
    assert oarbank(capsys, "protection", "set", nid, rules, "--yes")[0] == 0
    effective = {"schema": 1, "node": {"mode": "moderate"}, "rule": RULES["rule"]}
    assert protection.current(db, nid) == (1, effective)
    toml = tmp / "rules.toml"
    toml.write_text('schema = 1\n[node]\nmode = "fleet_first"\n[[rule]]\nid = "zoom"\nmatch = { path_contains = "zoom.us" }\n'
                    'reserve = { mem_gb = 3 }\n')
    assert oarbank(capsys, "protection", "set", nid, toml, "--yes")[0] == 0
    assert protection.current(db, nid)[1]["node"]["mode"] == "fleet_first"
    # the fleet's rules and a group's join the node's own: `show` names where each comes from
    fleet_rules = tmp / "fleet.json"
    fleet_rules.write_text(json.dumps({"schema": 1, "rule": [{"id": "slack", "match": {"path_contains": "Slack"},
                                                              "reserve": {"mem_gb": 1}}]}))
    assert oarbank(capsys, "protection", "set", "fleet", fleet_rules, "--yes")[0] == 0
    code, out = oarbank(capsys, "protection", "show", "mini")
    assert code == 0 and f"protection on mini ({nid}): mode fleet_first · This node; history version 3" in out
    assert re.search(r"zoom\s+not reported\s+- processes\s+from This node", out) and re.search(r"slack .* from Fleet", out)
    assert "this node's own section: 1 rules, mode fleet_first" in out
    assert db.one("SELECT target_id FROM audit WHERE operation='protection.rules.update' ORDER BY event_id DESC LIMIT 1")["target_id"] == "fleet"
    assert oarbank(capsys, "protection", "probe", nid)[0] == 0 and fresh(db, fleet["node"])["want_probe"] == 1
    assert oarbank(capsys, "protection", "set", nid)[1].endswith("oarbank protection set <node|fleet|group:G> <file>")


# ------------------------------------------------------------------ oarbank job show | retry | cancel

def test_job_show_retry_and_cancel(fleet, capsys):
    db, nid = fleet["db"], fleet["nid"]
    j = db.one("SELECT * FROM jobs WHERE campaign_id=? AND kind='eval' ORDER BY job_id LIMIT 1", (fleet["sid"],))
    code, out = oarbank(capsys, "job", "show", j["job_id"])
    assert code == 0, out
    assert out.startswith(f"job {j['job_id']} (eval) pending  relay") and "attempts: none yet" in out
    assert f"job {j['job_id']}: pending - " in out and "remedy: " in out
    g = core.claim(db, fresh(db, fleet["node"]), {"free_cpu": 8, "free_mem_gb": 32, "ready_datasets": ["scene:s1"]})["grants"]
    a = next(x for x in g if x["job_id"] == j["job_id"])
    db.x("INSERT INTO checkpoints(job_id,generation,attempt_id,node_id,seq,digest,files_json,size,at) VALUES(?,?,?,?,?,?,?,?,?)",
         (j["job_id"], j["generation"], a["attempt_id"], nid, 1, "ab" * 32, json.dumps([{"path": "state.bin"}]), 2 * 1048576, time.time()))
    code, out = oarbank(capsys, "job", "show", j["job_id"])
    assert re.search(rf"#{a['attempt_id']}\s+mini\s+live", out), out
    assert f"checkpoint: attempt {a['attempt_id']} on {nid}, 1 files, 2.0 MB, digest abababababab" in out
    assert f"Running on mini (attempt {a['attempt_id']}" in out
    doc = json.loads(oarbank(capsys, "job", "show", j["job_id"], "--json")[1])
    assert doc["explain"]["subject"] == {"kind": "job", "id": j["job_id"]} and doc["checkpoint"]["files"] == 1
    assert oarbank(capsys, "job", "cancel", j["job_id"], "--yes")[0] == 0
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (j["job_id"],))["state"] == "cancelled"
    assert oarbank(capsys, "job", "retry", j["job_id"])[0] == 0
    assert db.one("SELECT state FROM jobs WHERE job_id=?", (j["job_id"],))["state"] == "pending"
    assert oarbank(capsys, "job", "show", 999999)[0] == 1


# ------------------------------------------------------------------ explain's remedies carry their target

def test_explain_remedies_name_the_command_that_applies_them(fleet, capsys):
    db, nid = fleet["db"], fleet["nid"]
    run_op(db, "nodes.pause", nid)
    code, out = oarbank(capsys, "explain", "node", nid)
    assert code == 0 and f"remedy: Resume: oarbank node state {nid} active" in out
    r = next(x for x in json.loads(oarbank(capsys, "explain", "node", nid, "--json")[1])["remedies"] if x["op"] == "nodes.resume")
    assert r["target"] == nid and r["params"] == {"node": nid}
    assert operations.command("fleet.resume", "fleet") == "oarbank resume --all"
    assert operations.command("jobs.set_priority", "12") == "oarbank op jobs.set_priority 12"
    assert operations.command("nodes.run_doctor", nid) == f"oarbank op nodes.run_doctor {nid}"


def test_job_remedies_target_the_job_its_campaign_or_the_fleet(fleet):
    from oarbank.coordinator import explain
    db = fleet["db"]
    j = db.one("SELECT * FROM jobs WHERE campaign_id=? LIMIT 1", (fleet["sid"],))
    rem = explain._remedies(["QUEUED_BEHIND", "CAMPAIGN_PAUSED", "OARBANK_PAUSED", "SECRETS_NOT_SET"], explain._job_ids(j))
    assert {r.op: r.target for r in rem} == {"jobs.set_priority": str(j["job_id"]), "campaigns.resume": fleet["sid"],
                                             "fleet.resume": "fleet", "secrets.set": None}
    assert rem[0].params == {"job_id": j["job_id"], "module": "relay", "campaign_id": fleet["sid"]}


# ------------------------------------------------------------------ the fleet line and a plan's impact

def test_oarbank_fleet_shows_the_container_runtime_state(monkeypatch, capsys):
    node = {"hostname": "win", "node_id": "n_1", "lifecycle": "ready", "desired_state": "active", "online": True, "live": 0,
            "cap": {}, "limits": {}, "mods": {}, "tel": {}, "doctor": None, "facts": {"containers": CONTAINERS}}
    mac = {**node, "hostname": "mini", "facts": {"containers": {"gpu": "virtio-gpu:venus"}}}
    monkeypatch.setattr(cli, "api", lambda *a, **k: {"nodes": [node, mac], "enrollments": [], "campaigns": [], "alerts": []})
    cli.cmd_fleet(None)
    out = capsys.readouterr().out.splitlines()
    assert "runtime wslc missing MISSING virtual_machine_platform caps" in out[0] and "runtime" not in out[1]


def test_a_plans_impact_reads_as_rows():
    rows = impact.rows({"to": "http://100.64.0.2:7443", "paired": True, "timelock_s": 86400, "frozen_window": "about a minute",
                        "module_rules": ["relay: rebuild scores (all) cache"], "secrets_carried": "none", "force": None,
                        "matches": [{"rule": "zoom", "processes": []}], "versions": {"setting:x": 2, "y": None}})
    assert rows == [{"label": "to", "items": ["http://100.64.0.2:7443"]}, {"label": "paired", "items": ["yes"]},
                    {"label": "timelock", "items": ["1 d"]}, {"label": "frozen window", "items": ["about a minute"]},
                    {"label": "module rules", "items": ["relay: rebuild scores (all) cache"]},
                    {"label": "secrets carried", "items": ["none"]}, {"label": "versions", "items": ["setting:x: 2"]}]
    assert [impact.duration(s) for s in (45, 900, 5400, 90000, 172800)] == ["45 s", "15 min", "1.5 h", "1 d 1 h", "2 d"]
    assert impact.lines({"matches": [{"rule": "zoom", "processes": PROCS}], "why": ["soaking: 3 of 600 s"]}) == [
        "  rule zoom matches 1 process(es): 812 zoom.us", "  why: soaking: 3 of 600 s"]


def test_the_cli_prints_a_previewed_plan_readably(fleet, capsys):
    code, out = oarbank(capsys, "coordinator", "move", "--dry-run")
    assert code == 2, out
    assert "coordinator.move (T3):" in out and "  timelock: 1 d" in out and "  live attempts carried: 0" in out
    assert "{" not in out.split("plan pl_")[0]                         # no raw JSON


# ------------------------------------------------------------------ the console says the same

@pytest.fixture
def console(fleet):
    state = ConsoleState(fleet["db"].path, f"http://127.0.0.1:{fleet['oarbankd'].port}", secret=SECRET)
    with TestClient(console_app(state), client=("127.0.0.1", 50011)) as c:
        sign_in(c, fleet["db"])
        yield {**fleet, "c": c}


def text(page: str) -> str:
    import html
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


def test_the_node_page_shows_gpu_evidence_enforcement_and_folders(console):
    db, nid, c = console["db"], console["nid"], console["c"]
    dress(db, nid)
    page = text(c.get(f"/nodes/{nid}").text)
    assert "cuda no no CUDA does not run on macOS" in page and "metal yes no Apple M5 Pro" in page
    assert "Containers: virtio-gpu:venus (krunkit)" in page
    assert "ipc cooperative relay, toy relay, toy CAPABILITY_NOT_ENFORCED" in page
    assert "filesystem enforced relay, toy" in page
    assert "inputs read /Users/shared/in ok seq 1 · unsigned" in page


def test_explain_remedies_are_buttons_that_run_their_operation(console):
    db, nid, c = console["db"], console["nid"], console["c"]
    run_op(db, "nodes.pause", nid)
    html = c.get(f"/explain/node/{nid}").text
    form = re.search(r'<form class="inline" method="post" action="/do/nodes.resume".*?</form>', html, re.S).group(0)
    assert f'name="target" value="{nid}"' in form and f'name="return_to" value="/explain/node/{nid}"' in form
    fields = dict(re.findall(r'name="([^"]+)" value="([^"]*)"', form))
    r = c.post("/do/nodes.resume", data=fields, follow_redirects=False)
    assert r.status_code == 303 and fresh(db, console["node"])["desired_state"] == "active"
    j = db.one("SELECT job_id FROM jobs WHERE campaign_id=? AND kind='eval' LIMIT 1", (console["sid"],))["job_id"]
    html = c.get(f"/explain/job/{j}").text
    form = re.search(r'action="/do/jobs.set_priority".*?</form>', html, re.S).group(0)
    assert f'value="{j}"' in form and '<input name="priority" type="number"' in form


def test_remedies_that_need_more_than_a_target_link_to_their_form():
    from oarbank.console import views
    doc = {"remedies": [{"op": "settings.apply", "target": "n_1", "params": {"node": "n_1"}, "label": "Set caps"},
                        {"op": "secrets.set", "target": None, "params": {"job_id": 3, "module": "vault"}, "label": "Set"},
                        {"op": "secrets.set", "target": None, "params": {"node": "n_1"}, "label": "Set"},
                        {"op": "nodes.run_doctor", "target": None, "params": {"job_id": 3}, "label": "Run doctor"}]}
    acts = views.remedy_actions(doc)
    assert [(a["href"], a["button"]) for a in acts] == [("/nodes/n_1/settings#caps", False), ("/modules/vault/secrets", False),
                                                        ("/modules", False), (None, False)]
    assert acts[3]["command"] == "oarbank op nodes.run_doctor"
    from oarbank.contracts import reason_codes
    for op in {op for c in reason_codes.CODES for op in c.remedies}:     # every remedy is a button, a form page or a command
        area = op.split(".", 1)[0]
        assert op in views.REMEDY_FORMS or area in ("nodes", "jobs", "campaigns", "fleet"), op


def test_the_plan_page_shows_a_moves_impact_as_rows(console):
    c = console["c"]
    html = c.post("/do/coordinator.move", data={"return_to": "/coordinator", "idem": "x"}).text
    body = text(html.split("<details>")[0])
    assert "timelock 1 d" in body and "live attempts carried 0" in body and "frozen window about a minute" in body
    assert "{" not in body.split("Review:")[1]                          # the JSON stays in its details element
    assert "the plan's impact, as stored" in html


def test_module_health_shows_pinned_datasets_and_container_image_first_runs(console):
    db, c = console["db"], console["c"]
    db.x("INSERT INTO module_images(module,digest,image,set_name,key_sha256,first_run_at,node_id,attempt_id) VALUES(?,?,?,?,?,?,?,?)",
         ("relay", "cd" * 32, "ghcr.io/example/relay/scorer@sha256:" + "cd" * 32, "scorers", "ef" * 32, time.time(), console["nid"], 7))
    page = text(c.get("/modules/relay/health").text)
    assert f"ghcr.io/example/relay/scorer@sha256:{'cd' * 32} scorers {'ef' * 8}" in page and f"{console['nid']} 7" in page
    assert "Pinned datasets" not in page                                 # relay pins none
    assert "no image of a container set has run yet" in text(c.get("/modules/toy/health").text)


def test_module_health_shows_each_pinned_dataset_registered_waiting_or_in_conflict(tmp_path):
    from oarbank.coordinator import modsandbox, modstore, releases
    from helpers import FIXTURES, install
    db = make_db(tmp_path / "oarbank.sqlite3", modules=())
    r = install(db, FIXTURES / "depot", enable=False)
    modsandbox.approve(db, "depot", r["version"], "test", None)
    modstore.enable(db, "depot", r["version"])
    modcalls.use(db)
    releases.sync(db)
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(db.path, f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        with TestClient(console_app(state), client=("127.0.0.1", 50012)) as c:
            sign_in(c, db)
            page = text(c.get("/modules/depot/health").text)
            assert "tool:depot-1 tool any 2 0.0 waiting a bootstrap job of the module registers it" in page
            db.x("INSERT INTO datasets(dataset_id,kind,module,meta_json,files_json,created_at) VALUES(?,?,?,?,?,?)",
                 ("tool:depot-1", "tool", None, "{}", json.dumps([{"path": "gatk.jar", "digest": "aa" * 32, "size": 1}]), 0))
            core._alert(db, "pinned_dataset_conflict:tool:depot-1", "module:depot", "depot: bootstrap job 4 brought pinned "
                        "dataset tool:depot-1, but a dataset of the operator (kind tool) with other files is registered")
            page = text(c.get("/modules/depot/health").text)
            assert ("conflict the operator's dataset of kind tool with 1 file(s) holds the id: pinned_dataset_conflict depot: "
                    "bootstrap job 4 brought pinned dataset tool:depot-1") in page
            man = modcalls.info("depot").manifest
            db.x("UPDATE datasets SET module='depot', files_json=? WHERE dataset_id='tool:depot-1'",
                 (json.dumps(man.datasets.pinned[0].dataset_files()),))
            assert "registered since" in text(c.get("/modules/depot/health").text)

