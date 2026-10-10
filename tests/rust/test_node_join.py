"""Joining as docs/design/node-enrollment.md describes it, against a real oarbankd: a service installed with nothing to
join with waits and joins as soon as a code is staged; `oarbank-node join` checks first, stages the code (owner-only,
never on a command line) and reports; `oarbank-node check` names each check and refuses forged, expired and
unreachable codes with their codes; a multi-use code from managed policy waits for approval; a node joined by address
shows a device code the owner approves by."""
import base64
import json
import os
import socket
import stat
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
import agentbin  # noqa: E402
from conftest import agent_env  # noqa: E402
from helpers import stop_tree  # noqa: E402
from oarbank.coordinator import joincodes as J  # noqa: E402
from oarbank.platform import files  # noqa: E402
from test_agent_session import wait  # noqa: E402

LAUNCHER = agentbin.LAUNCHER_BIN


def mint(coordinator, **params):
    plan = coordinator.api("POST", "/api/v1/ops/nodes.join_code", json={"params": params, "dry_run": True})["plan"]
    return coordinator.api("POST", "/api/v1/ops/nodes.join_code", json={"plan_id": plan["plan_id"], "reason": "e2e"})["result"]


def forged(code: str, **change) -> str:
    """The code re-encoded with some fields changed (a wrong pin, another key, an address nothing answers on)."""
    d = J.decode(code)
    f = {"urls": d["urls"], "pins": d["pins"], "cik": d["cik"], "expires_at": d["expires_at"], "flags": d["flags"], **change}
    return J.encode(urls=f["urls"], pins=f["pins"], cik=f["cik"], code_id=bytes.fromhex(d["id"]),
                    secret=bytes.fromhex(d["secret"]), expires_at=f["expires_at"], flags=f["flags"])


def closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def setup_home(agent_bin, home):
    """The install plan with nothing to join with (what every package now does), without loading a service; returns the
    agent arguments it would give the service."""
    r = subprocess.run([str(LAUNCHER), "--home", str(home), "setup", "--agent", str(agent_bin), "--no-service"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    line = next(l for l in r.stdout.splitlines() if l.startswith("agent arguments: run "))
    return line.removeprefix("agent arguments: run ").split()


def start(home, args, env=None):
    return subprocess.Popen([str(LAUNCHER), "--home", str(home), "run", *args], env={**agent_env(), **(env or {})},
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def status(home):
    p = home.parent / "status" / "node.json"
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


def stop(p):
    stop_tree(p.pid)
    print(p.communicate(timeout=30)[0][-3000:])


def node_cmd(home, *args, stdin=None, env=None):
    return subprocess.run([str(LAUNCHER), "--home", str(home), *args], input=stdin, capture_output=True, text=True,
                          env={**agent_env(), "OARBANK_SETUP_NO_SERVICE": "1", **(env or {})}, timeout=120)


def test_a_waiting_service_joins_when_a_code_is_staged(agent_bin, coordinator, tmp_path):
    home = tmp_path / "agent"
    args = setup_home(agent_bin, home)
    assert args[:2] == ["--join-file", str(home / "state" / "join-code")] and "--policy" in args
    p = start(home, args)
    try:
        wait(lambda: status(home).get("state") == "unjoined", 30)
        staged = home / "state" / "join-code"
        staged.write_text(mint(coordinator, label="staged")["code"])
        st = wait(lambda: status(home).get("state") == "connected" and status(home), 90)
        assert st["node_id"] and st["coordinator"] == coordinator.url and "error" not in st
        assert not staged.exists() and (home.parent / "status" / "joined").exists()
        assert "join_secret" not in json.loads((home / "agent.json").read_text())
    finally:
        stop(p)


def test_oarbank_node_join_checks_stages_and_reports(agent_bin, coordinator, tmp_path):
    home = tmp_path / "agent"
    setup_home(agent_bin, home)
    code = mint(coordinator, label="cli")["code"]
    r = node_cmd(home, "join", "--scope", "personal", "--code-stdin", "--no-wait", "--json", stdin=code)
    assert r.returncode == 0, r.stdout + r.stderr
    lines = [json.loads(l) for l in r.stdout.splitlines() if l.startswith("{")]
    assert [x["row"] for x in lines if x["type"] == "row"] == ["code", "dns", "tcp", "identity", "tls", "clock"]
    assert lines[-1]["type"] == "result" and lines[-1]["ok"] and lines[-1]["detail"]["staged"]
    staged = home / "state" / "join-code"
    assert staged.read_text() == code and files.owner_only(staged)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(staged).st_mode) == 0o600
    assert code not in r.stdout + r.stderr, "the code is never echoed"
    p = start(home, setup_home(agent_bin, home))
    try:
        wait(lambda: status(home).get("state") == "connected", 90)
        s = node_cmd(home, "status", "--json")
        assert s.returncode == 0 and json.loads(s.stdout)["status"]["state"] == "connected"
        again = node_cmd(home, "join", "--scope", "personal", "--code-stdin", stdin=mint(coordinator)["code"])
        assert again.returncode == 0 and "already joined" in again.stdout
    finally:
        stop(p)


def test_check_names_each_check_and_refuses_bad_codes(agent_bin, coordinator, tmp_path):
    code = mint(coordinator)["code"]
    d = J.decode(code)

    def check(c):
        r = node_cmd(tmp_path / "x", "check", "--code-stdin", "--json", stdin=c)
        res = json.loads(r.stdout.splitlines()[-1])
        return r.returncode, res.get("code")

    assert check(code) == (0, None)
    assert check(forged(code, pins=["00" * 32])) == (5, "E_TLS_PIN_MISMATCH")
    assert check(forged(code, cik=base64.b64encode(bytes(32)).decode())) == (5, "E_IDENTITY")
    assert check(forged(code, urls=[f"https://127.0.0.1:{closed_port()}"])) == (6, "E_TCP")
    assert check(forged(code, urls=["https://no-such-host.invalid:7443"])) == (6, "E_DNS")
    assert check(forged(code, expires_at=1700000000)) == (4, "E_CODE_EXPIRED")
    assert check(code[:-3]) == (2, "E_CODE_FORMAT")
    # by address: nothing pinned, the fingerprint to compare is printed
    r = node_cmd(tmp_path / "x", "check", "--coordinator", coordinator.url, "--json")
    assert r.returncode == 0 and d["pins"][0].startswith(json.loads(r.stdout.splitlines()[-1])["detail"]["check"]["fingerprint"])


def test_a_policy_code_for_many_machines_waits_for_approval(agent_bin, coordinator, tmp_path):
    home = tmp_path / "agent"
    args = setup_home(agent_bin, home)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"JoinCode": mint(coordinator, uses=5, ttl_s=3600)["code"], "Name": "lab-7",
                                  "ManagedByOrganizationName": "Example Lab"}))
    code = json.loads(policy.read_text())["JoinCode"]
    shown = lambda *extra: json.loads(subprocess.run([str(agent_bin), "policy", *extra], capture_output=True, text=True, check=True,
                                                     env={**os.environ, "OARBANK_POLICY_FILE": str(policy)}).stdout)["JoinCode"]
    assert shown() == "(set)" and shown("--with-join-code") == code       # a person's terminal never sees the code
    p = start(home, args, env={"OARBANK_POLICY_FILE": str(policy)})
    try:
        st = wait(lambda: status(home).get("state") == "pending" and status(home), 60)
        assert st["key_fingerprint"].startswith("sha256:") and st["managed_by"] == "Example Lab"
        eid = wait(lambda: [e for e in coordinator.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"], 30)[0]["enrollment_id"]
        coordinator.admit(eid)
        wait(lambda: status(home).get("state") == "connected", 90)
        node = next(n for n in coordinator.api("GET", "/api/v1/fleet")["nodes"] if n["node_id"] == status(home)["node_id"])
        assert node["hostname"] == "lab-7"
    finally:
        stop(p)


def test_a_node_joined_by_address_is_approved_by_its_device_code(agent_bin, coordinator, tmp_path):
    home = tmp_path / "agent"
    args = setup_home(agent_bin, home)
    p = start(home, [*args, "--coordinator", coordinator.url])
    try:
        st = wait(lambda: status(home).get("user_code") and status(home), 60)
        assert st["state"] == "pending" and len(st["user_code"]) == 9
        plan = coordinator.api("POST", "/api/v1/ops/nodes.admit_code", json={"params": {"user_code": st["user_code"].lower()}, "dry_run": True})["plan"]
        coordinator.api("POST", "/api/v1/ops/nodes.admit_code", json={"plan_id": plan["plan_id"], "reason": "e2e"})
        st = wait(lambda: status(home).get("state") == "connected" and status(home), 90)
        assert "user_code" not in st
    finally:
        stop(p)


def test_an_unreachable_code_is_retried_until_another_is_staged_and_a_forged_one_ends(agent_bin, coordinator, tmp_path):
    home = tmp_path / "agent"
    args = setup_home(agent_bin, home)
    code = mint(coordinator)["code"]
    p = start(home, args)
    try:
        wait(lambda: status(home).get("state") == "unjoined", 30)
        staged = home / "state" / "join-code"
        staged.write_text(forged(code, urls=[f"https://127.0.0.1:{closed_port()}"]))
        st = wait(lambda: status(home).get("retrying") and status(home), 60)
        assert st["error"]["code"] == "E_TCP" and st["state"] == "error"
        staged.write_text(forged(code, pins=["11" * 32]))          # replaces the code being retried
        st = wait(lambda: (status(home).get("error") or {}).get("code") == "E_TLS_PIN_MISMATCH" and status(home), 60)
        assert not st.get("retrying")
        wait(lambda: not staged.exists(), 30)
        staged.write_text(code)                                   # and a good code still joins afterwards
        wait(lambda: status(home).get("state") == "connected", 90)
    finally:
        stop(p)
