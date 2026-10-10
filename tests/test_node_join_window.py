"""The node's join window (deploy/node/join-window.py) over real loopback HTTP, with a fake `oarbank-node`.

The fake launcher is a small Python script: it records the argv and the code file it was given, prints canned check rows,
appends progress lines and writes the status document named by OARBANK_NODE_STATUS. Nothing here elevates, opens a
browser, or touches the machine's own Oarbank installation; elevation is tested as the command it would run.
"""
import base64
import contextlib
import http.client
import importlib.util
import json
import os
import socket
import stat
import sys
import textwrap
import threading
import time
from pathlib import Path

import httpx
import pytest

from oarbank.coordinator import joincodes

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("join_window", ROOT / "deploy" / "node" / "join-window.py")
jw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jw)
VECTORS = json.loads((ROOT / "src/oarbank/contracts/vectors/joincode.json").read_text())


def make_code(ttl=3600, approve=True, system=True, containers=False, urls=("https://coord.example.net:7443",)):
    flags = (joincodes.F_APPROVE if approve else 0) | (joincodes.F_SYSTEM if system else 0) | \
            (joincodes.F_CONTAINERS if containers else 0)
    return joincodes.encode(urls=list(urls), pins=["ab" * 32], cik=base64.b64encode(bytes(range(32))).decode(),
                            code_id=bytes(range(1, 9)), secret=bytes(range(16, 32)), expires_at=time.time() + ttl,
                            flags=flags)


CODE = make_code()

FAKE = textwrap.dedent(r'''
    import json, os, stat, sys, time
    log = os.environ["FAKE_LOG"]
    args = sys.argv[1:]
    record = {"argv": args}
    def opt(name):
        return args[args.index(name) + 1] if name in args else None
    def status(doc):
        path = os.environ["OARBANK_NODE_STATUS_PERSONAL" if opt("--scope") == "personal" else "OARBANK_NODE_STATUS"]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        doc = dict(doc, format=1, updated_at=time.time())
        with open(path + ".tmp", "w") as f:
            json.dump(doc, f)
        os.replace(path + ".tmp", path)
    mode = os.environ.get("FAKE_MODE", "ok")
    if args[0] == "check":
        code = sys.stdin.read()
        record["stdin"] = code
        rows = [{"type": "row", "row": "code", "ok": True, "detail": "coordinator coord.example.net:7443"},
                {"type": "row", "row": "dns", "ok": True, "detail": "coord.example.net -> 192.0.2.7"}]
        if mode == "fail":
            rows.append({"type": "row", "row": "tcp", "ok": False, "detail": "no answer on port 7443"})
            result = {"type": "result", "ok": False, "exit": 6, "code": "E_TCP", "message": "No answer on port 7443."}
        elif mode == "leak":
            result = {"type": "result", "ok": False, "exit": 2, "code": "E_CODE_FORMAT", "message": "bad code " + code.strip()}
        else:
            rows.append({"type": "row", "row": "tcp", "ok": True, "detail": "port 7443 answered in 3 ms"})
            result = {"type": "result", "ok": True, "exit": 0, "detail": {"message": "All checks passed.",
                      "check": {"url": "https://coord.example.net:7443", "fingerprint": "abababababababab"}}}
        for r in rows + [result]:
            print(json.dumps(r))
        print("diagnostic noise on stderr", file=sys.stderr)
    elif args[0] == "join":
        f = opt("--code-file")
        st, dst = os.stat(f), os.stat(os.path.dirname(f))
        record.update(code=open(f).read(), file_mode=stat.S_IMODE(st.st_mode), dir_mode=stat.S_IMODE(dst.st_mode),
                      code_file=f)
        with open(opt("--progress-file"), "a") as p:
            p.write(json.dumps({"type": "row", "row": "tls", "ok": True, "detail": "matches the code"}) + "\n")
            p.write(json.dumps({"type": "state", "status": {"state": "joining", "coordinator": "https://coord.example.net:7443"}}) + "\n")
            p.flush()
            time.sleep(float(os.environ.get("FAKE_SLEEP", "0")))
            if mode == "denied":
                p.write(json.dumps({"type": "result", "ok": False, "exit": 4, "code": "E_CODE_USED", "message": "Already used."}) + "\n")
            else:
                status({"state": "pending", "coordinator": "https://coord.example.net:7443", "key_fingerprint": "sha256:1234"})
                p.write(json.dumps({"type": "result", "ok": True, "exit": 0, "detail": {"message": "staged", "staged": True}}) + "\n")
                p.write('{"type": "row", "partial')  # an unfinished line is not relayed
    elif args[0] == "leave":
        with open(opt("--progress-file"), "a") as p:
            p.write(json.dumps({"type": "result", "ok": True, "exit": 0, "detail": {"message": "left"}}) + "\n")
        status({"state": "unjoined"})
    with open(log, "a") as f:
        f.write(json.dumps(record) + "\n")
''')


@pytest.fixture
def env(tmp_path, monkeypatch):
    fake = tmp_path / "fake oarbank-node.py"
    fake.write_text(FAKE)
    log = tmp_path / "launcher.log"
    status = tmp_path / "status" / "node.json"
    personal = tmp_path / "personal" / "node.json"
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("OARBANK_NODE_STATUS", str(status))
    monkeypatch.setenv("OARBANK_NODE_STATUS_PERSONAL", str(personal))
    monkeypatch.setenv("OARBANK_POLICY_FILE", str(tmp_path / "policy.json"))
    monkeypatch.setattr(jw.webbrowser, "open", lambda *a, **kw: pytest.fail("Unstubbed browser launch"))

    class Env:
        def window(self, platform="macos", prefill=None, root=True):
            return jw.Window([sys.executable, str(fake)], platform=platform, prefill=prefill, workdir=str(work),
                             elevate_root=root)

        def calls(self):
            return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

        def policy(self, value):
            (tmp_path / "policy.json").write_text(json.dumps(value))

    e = Env()
    e.status, e.personal, e.work, e.tmp = status, personal, work, tmp_path
    return e


@contextlib.contextmanager
def serving(window):
    with jw.WindowServer(window) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=2)
            window.close()


def post(server, path, body=None, headers=None):
    base = {"Origin": server.origin, jw.HEADER: server.window.capability}
    base.update(headers or {})
    return httpx.post(server.origin + path, json={} if body is None else body, headers=base, trust_env=False, timeout=30)


def wait_done(server, offset=0, timeout=10):
    deadline = time.monotonic() + timeout
    lines = []
    while time.monotonic() < deadline:
        p = post(server, "/progress", {"offset": offset}).json()
        lines += p["lines"]
        offset = p["offset"]
        if p["done"]:
            return p, lines
        time.sleep(.05)
    pytest.fail("the launcher did not finish")


JOIN = {"code": CODE, "scope": "personal", "containers": False, "name": ""}


# ---------------------------------------------------------------- the HTTP guard
def test_page_headers_and_no_capability_in_page(env):
    window = env.window()
    with serving(window) as server:
        assert server.server_address[0] == "127.0.0.1"
        r = httpx.get(server.origin, trust_env=False)
        assert r.status_code == 200 and "Join code" in r.text
        assert window.capability not in r.text and "__NONCE__" not in r.text
        csp = r.headers["Content-Security-Policy"]
        assert csp.startswith("default-src 'none';") and "'nonce-" in csp and "img-src data:;" in csp
        assert "frame-ancestors 'none'" in csp and "connect-src 'self'" in csp
        nonce = csp.split("'nonce-", 1)[1].split("'", 1)[0]
        assert f'<script nonce="{nonce}">' in r.text and f'<style nonce="{nonce}">' in r.text
        assert r.headers["Cache-Control"].startswith("no-store")
        assert r.headers["X-Frame-Options"] == "DENY" and r.headers["Referrer-Policy"] == "no-referrer"
        assert httpx.get(server.origin + "/favicon.ico", trust_env=False).status_code == 404
    # the page loads nothing from elsewhere
    page = (ROOT / "deploy/node/join-window.html").read_text()
    assert "http://" not in page and "https://" not in page and " style=" not in page


@pytest.mark.parametrize("headers,status", [
    ({"Host": "evil.example"}, 421),
    ({"Host": "localhost:7400"}, 421),
    ({"Origin": "https://evil.example"}, 403),
    ({"Origin": "null"}, 403),
    ({"Origin": ""}, 403),
    ({"Sec-Fetch-Site": "cross-site"}, 403),
    ({"Sec-Fetch-Site": "same-site"}, 403),
    ({jw.HEADER: "forged"}, 403),
    ({jw.HEADER: ""}, 403),
])
@pytest.mark.parametrize("path,body", [("/check", {"code": CODE}), ("/join", JOIN), ("/leave", {}), ("/state", {})])
def test_forged_posts_have_no_effect(env, headers, status, path, body):
    with serving(env.window()) as server:
        r = post(server, path, body, headers)
        assert r.status_code == status
        assert CODE not in r.text
    assert env.calls() == []
    assert not any(env.work.iterdir())


def test_missing_origin_duplicates_and_close(env):
    window = env.window()
    with serving(window) as server:
        assert httpx.post(server.origin + "/state", json={}, headers={jw.HEADER: window.capability},
                          trust_env=False).status_code == 403
        data = json.dumps({"code": CODE}).encode()
        for duplicate in ("Host", "Origin", jw.HEADER, "Content-Length"):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
            connection.putrequest("POST", "/check", skip_host=True)
            values = {"Host": server.host, "Origin": server.origin, jw.HEADER: window.capability,
                      "Content-Type": "application/json", "Content-Length": str(len(data))}
            for key, value in values.items():
                connection.putheader(key, value)
                if key == duplicate:
                    connection.putheader(key, value)
            connection.endheaders(data)
            assert connection.getresponse().status in (400, 403, 421)
            connection.close()
        assert post(server, "/close", {}, {jw.HEADER: "forged"}).status_code == 403 and not server.finished
        assert post(server, "/ping").json() == {"ok": True}
        assert post(server, "/close").status_code == 200 and server.finished
    assert env.calls() == []


def test_payload_limits_and_routes(env):
    with serving(env.window()) as server:
        assert post(server, "/state", []).status_code == 400
        assert post(server, "/state", {"x": 1}).status_code == 400
        try:
            assert post(server, "/check", {"code": "A" * 17000}).status_code == 400
        except httpx.ReadError:
            pass  # oversized framing is not drained (setup.py); the next requests prove the server is alive
        assert post(server, "/check", headers={"Content-Type": "text/plain"}).status_code == 415
        assert post(server, "/run").status_code == 404
        assert post(server, "/check?code=x").status_code == 404
        assert httpx.get(server.origin + "/state", trust_env=False).status_code == 404
        assert httpx.options(server.origin + "/state", trust_env=False).status_code == 501
        with socket.create_connection(server.server_address, timeout=2) as connection:
            connection.sendall((f"POST /check HTTP/1.1\r\nHost: {server.host}\r\nOrigin: {server.origin}\r\n"
                                f"{jw.HEADER}: {server.window.capability}\r\nTransfer-Encoding: chunked\r\n\r\n").encode())
            response = http.client.HTTPResponse(connection)
            response.begin()
            assert response.status == 400
        assert post(server, "/progress", {"offset": 0}).status_code == 409  # nothing ran
        assert post(server, "/check", {"code": "OB2-\x00"}).status_code == 400
        assert post(server, "/check", {"code": 5}).status_code == 400
        assert post(server, "/check", {"code": CODE, "extra": 1}).status_code == 400
    assert env.calls() == []


# ---------------------------------------------------------------- state, policy, prefill
def test_state_reads_both_scopes_and_only_two_policy_values(env):
    env.status.parent.mkdir()
    env.status.write_text(json.dumps({"format": 1, "state": "connected", "coordinator": "https://c:7443", "node_id": "n_1"}))
    env.policy({"JoinCode": CODE, "Coordinator": "https://secret.example:7443", "AllowUserJoin": "false",
                "ManagedByOrganizationName": "Example Corp"})
    with serving(env.window()) as server:
        r = post(server, "/state")
        s = r.json()
        assert s["platform"] == "macos" and s["scopes"] == ["system", "personal"]
        assert s["status"] == {"system": json.loads(env.status.read_text()), "personal": None}
        assert s["policy"] == {"allow_user_join": False, "managed_by": "Example Corp"}
        assert CODE not in r.text and "secret.example" not in r.text
        assert s["prefill"] is None and s["job"] is None
    with serving(env.window(platform="linux")) as server:
        s = post(server, "/state").json()
        assert s["scopes"] == ["system"] and list(s["status"]) == ["system"]


@pytest.mark.parametrize("link", [f"oarbank://join?code={CODE}", f"oarbank:join?code={CODE}", f"OARBANK://JOIN?code={CODE}",
                                  f"oarbank://join/?code={CODE.replace('-', '%2D')}"])
def test_links_give_the_code(link):
    assert jw.code_from_link(link) == CODE


@pytest.mark.parametrize("link", ["https://join?code=OB2-X", "oarbank://evil?code=OB2-X", "oarbank://join",
                                  "oarbank://join?code=a&code=b", "oarbank://join/extra?code=OB2-X", "oarbank://join?code=",
                                  "oarbank://join?code=%00OB2"])
def test_other_links_are_refused(link):
    with pytest.raises(jw.WindowError):
        jw.code_from_link(link)


def test_link_and_file_prefill_set_the_source(env, tmp_path):
    f = tmp_path / "code.txt"
    f.write_text("\n  " + CODE + "\n")
    assert jw.code_from_file(f) == CODE
    with serving(env.window(prefill={"code": jw.code_from_link(f"oarbank://join?code={CODE}"), "source": "link"})) as server:
        assert post(server, "/state").json()["prefill"] == {"code": CODE, "source": "link"}
        # a second launch with another file hands it over (capability holders only)
        assert post(server, "/prefill", {"code": CODE, "source": "file"}, {jw.HEADER: "x"}).status_code == 403
        assert post(server, "/prefill", {"code": CODE, "source": "typed"}).status_code == 400
        assert post(server, "/prefill", {"code": CODE, "source": "file"}).json() == {"ok": True}
        assert post(server, "/state").json()["prefill"]["source"] == "file"
    with pytest.raises(jw.WindowError):
        jw.code_from_file(tmp_path / "missing")
    (tmp_path / "binary").write_bytes(b"\xff\xfe")
    with pytest.raises(jw.WindowError):
        jw.code_from_file(tmp_path / "binary")


# ---------------------------------------------------------------- check
def test_check_relays_rows_on_stdin_and_never_echoes_the_code(env):
    with serving(env.window()) as server:
        r = post(server, "/check", {"code": "  " + CODE + "\n"})
        assert r.status_code == 200
        data = r.json()
        assert [row["row"] for row in data["rows"]] == ["code", "dns", "tcp"] and all(row["ok"] for row in data["rows"])
        assert data["result"]["ok"] and data["result"]["detail"]["check"]["fingerprint"] == "abababababababab"
        assert CODE not in r.text
    (call,) = env.calls()
    assert call["argv"] == ["check", "--code-stdin", "--json"] and call["stdin"] == CODE


def test_check_failure_and_a_launcher_that_quotes_the_code(env, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "fail")
    with serving(env.window()) as server:
        data = post(server, "/check", {"code": CODE}).json()
        assert data["result"] == {"type": "result", "ok": False, "exit": 6, "code": "E_TCP", "message": "No answer on port 7443."}
        assert data["rows"][-1] == {"row": "tcp", "ok": False, "detail": "no answer on port 7443"}
        monkeypatch.setenv("FAKE_MODE", "leak")
        r = post(server, "/check", {"code": CODE.lower()})
        assert CODE not in r.text and CODE.lower() not in r.text and "[redacted]" in r.text


# ---------------------------------------------------------------- join
def test_join_uses_a_private_code_file_deleted_after_the_launcher_exits(env, monkeypatch):
    monkeypatch.setenv("FAKE_SLEEP", ".6")
    window = env.window(root=False)  # macOS "only while I'm logged in": runs without elevation
    with serving(window) as server:
        r = post(server, "/join", {**JOIN, "name": "build-07"})
        assert r.status_code == 200 and r.json()["elevated"] is False and r.json()["scope"] == "personal"
        assert CODE not in r.text
        job = window.job
        assert job.code_file.read_text() == CODE  # present while the launcher runs
        assert post(server, "/join", JOIN).status_code == 409  # one run at a time
        assert post(server, "/leave").status_code == 409
        p, lines = wait_done(server)
        assert not job.code_file.exists()
        assert [line["type"] for line in lines] == ["row", "state", "result"]
        assert p["result"]["ok"] and p["result"]["detail"]["staged"] and p["exit"] == 0 and not p["cancelled"]
        assert p["status"]["state"] == "pending" and p["fresh"]
        # following the status document after the run: no more lines, the same status
        again = post(server, "/progress", {"offset": p["offset"]}).json()
        assert again["lines"] == [] and again["done"] and again["status"]["key_fingerprint"] == "sha256:1234"
        assert post(server, "/state").json()["job"] == {"kind": "join", "scope": "personal", "running": False}
    (call,) = env.calls()
    argv = call["argv"]
    assert CODE not in json.dumps(argv) and call["code"] == CODE
    assert argv[:2] == ["join", "--code-file"] and Path(argv[2]) == job.code_file
    assert argv[3:6] == ["--no-input", "--no-wait", "--progress-file"]
    assert argv[7:] == ["--scope", "personal", "--name", "build-07"]
    if os.name == "posix":
        assert call["file_mode"] == 0o600 and call["dir_mode"] == 0o700
    assert not job.dir.exists()  # the window's close removed its private directory


def test_join_reports_a_refusal_and_linux_has_no_scope_flag(env, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "denied")
    window = env.window(platform="windows")
    with serving(window) as server:
        assert post(server, "/join", {**JOIN, "scope": "personal"}).status_code == 400  # Windows has one scope
        assert post(server, "/join", {**JOIN, "scope": "system", "containers": True}).status_code == 200
        p, lines = wait_done(server)
        assert p["result"]["code"] == "E_CODE_USED" and not p["fresh"]
    (call,) = env.calls()
    assert "--scope" not in call["argv"] and call["argv"][-1] == "--containers"
    assert not window.job.code_file.exists()


@pytest.mark.parametrize("change", [{"scope": "root"}, {"containers": "yes"}, {"name": "-x"}, {"name": "a" * 64},
                                    {"name": "a b"}, {"code": "OB2-0000"}, {"code": make_code(ttl=-60)},
                                    {"code": CODE[:-1] + ("0" if CODE[-1] != "0" else "1")}, {"extra": True}])
def test_bad_join_requests_run_nothing(env, change):
    with serving(env.window()) as server:
        r = post(server, "/join", {**JOIN, **change})
        assert r.status_code == 400 and CODE not in r.text
    assert env.calls() == [] and not any(env.work.iterdir())


def test_policy_forbids_join_and_leave(env):
    env.policy({"AllowUserJoin": False})
    with serving(env.window()) as server:
        r = post(server, "/join", JOIN)
        assert r.status_code == 403 and r.json()["code"] == "E_MANAGED"
        assert post(server, "/leave").status_code == 403
    env.policy({"AllowUserJoin": 0})
    with serving(env.window()) as server:
        assert post(server, "/leave").status_code == 403
    assert env.calls() == []


def test_leave_runs_the_launcher_for_the_joined_scope(env):
    env.personal.parent.mkdir()
    env.personal.write_text(json.dumps({"state": "connected", "coordinator": "https://c:7443"}))
    env.policy({"AllowUserJoin": True})
    window = env.window(root=False)
    with serving(window) as server:
        r = post(server, "/leave").json()
        assert r["scope"] == "personal" and r["elevated"] is False
        p, lines = wait_done(server)
        assert p["result"]["ok"] and lines[-1]["detail"]["message"] == "left"
    (call,) = env.calls()
    assert call["argv"][0] == "leave" and call["argv"][1] == "--progress-file"


def test_a_dismissed_prompt_is_cancelled_not_failed(env, monkeypatch):
    window = env.window(platform="linux")
    monkeypatch.setattr(window, "command", lambda args, scope: [sys.executable, "-c", "import sys; sys.exit(126)"])
    with serving(window) as server:
        assert post(server, "/join", {**JOIN, "scope": "system"}).status_code == 200
        p, lines = wait_done(server)
        assert p["cancelled"] and p["result"] is None and lines == [] and p["exit"] == 126
    assert not window.job.code_file.exists()


# ---------------------------------------------------------------- elevation commands
def test_macos_administrator_prompt_quotes_paths():
    argv = ["/Library/Oar bank/bin/oarbank-launcher", "join", "--code-file", "/tmp/it's \"here\"/code", "--name", "a\\b"]
    cmd = jw.elevated_command(argv, "macos", True)
    assert cmd[:2] == ["/usr/bin/osascript", "-e"] and len(cmd) == 3
    script = cmd[2]
    assert script.startswith('do shell script "') and script.endswith("with administrator privileges")
    # AppleScript unescapes the literal back to exactly the shell-quoted command
    literal = script[len("do shell script "):script.index(" with prompt")]
    inner = literal[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    import shlex
    assert shlex.split(inner) == argv
    assert "'/Library/Oar bank/bin/oarbank-launcher'" in inner
    assert jw.elevated_command(argv, "macos", False) == argv


def test_linux_pkexec_and_missing_pkexec():
    argv = ["/usr/lib/oarbank/oarbank-launcher", "join", "--code-file", "/tmp/x y/code"]
    assert jw.elevated_command(argv, "linux", True, pkexec="/usr/bin/pkexec") == ["/usr/bin/pkexec", *argv]
    with pytest.raises(jw.WindowError, match="sudo oarbank-node join") as e:
        jw.elevated_command(argv, "linux", True, pkexec=None)
    assert e.value.code == "E_PRIVILEGE"


def test_windows_uac_quotes_arguments():
    argv = [r"C:\Program Files\Oarbank\oarbank-node.exe", "join", "--code-file",
            r"C:\Users\O'Brien\AppData\Local\Temp\oarbank-join-1\code", "--name", "lab pc", "--progress-file", "C:\\p\u2019s\\x"]
    cmd = jw.elevated_command(argv, "windows", True)
    assert cmd[:4] == ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command"]
    script = cmd[4]
    assert r"-FilePath 'C:\Program Files\Oarbank\oarbank-node.exe'" in script
    assert "-Verb RunAs -Wait -PassThru -WindowStyle Hidden" in script and "exit $p.ExitCode" in script
    assert "catch { exit 1223 }" in script
    arglist = script.split("-ArgumentList ", 1)[1].split(" -Verb", 1)[0]
    assert arglist.startswith("'") and arglist.endswith("'")
    assert "O''Brien" in arglist and "p\u2019\u2019s" in arglist and '"lab pc"' in arglist
    assert jw.cancelled("windows", 1223, b"") and not jw.cancelled("windows", 1, b"")
    assert jw.cancelled("macos", 1, b"execution error: User canceled. (-128)") and not jw.cancelled("macos", 1, b"other")
    assert jw.cancelled("linux", 126, b"") and not jw.cancelled("linux", 127, b"")


def test_root_needs_no_elevation(env):
    window = env.window(platform="linux", root=True)
    assert window.command(["leave"], "system")[-1] == "leave" and window.command(["leave"], "system")[0] == sys.executable
    window = env.window(platform="macos", root=False)
    assert window.command(["leave"], "personal")[0] == sys.executable
    assert window.command(["leave"], "system")[0] == "/usr/bin/osascript"


# ---------------------------------------------------------------- where things are
def test_launcher_search_order(tmp_path, monkeypatch):
    mac = tmp_path / "Library/Oarbank"
    (mac / "share/join").mkdir(parents=True)
    (mac / "bin").mkdir()
    script = mac / "share/join/join-window.py"
    script.write_text("")
    launcher = mac / "bin/oarbank-launcher"
    launcher.write_text("")
    launcher.chmod(0o755)
    assert jw.find_launcher(script, "macos", {"PATH": ""}) == str(launcher)
    other = tmp_path / "custom-node"
    other.write_text("")
    other.chmod(0o755)
    assert jw.find_launcher(script, "macos", {"PATH": "", "OARBANK_NODE_LAUNCHER": str(other)}) == str(other)
    lin = tmp_path / "usr/lib/oarbank"
    (lin / "join").mkdir(parents=True)
    (lin / "oarbank-launcher").write_text("")
    (lin / "oarbank-launcher").chmod(0o755)
    assert jw.find_launcher(lin / "join/join-window.py", "linux", {"PATH": ""}) == str(lin / "oarbank-launcher")
    win = tmp_path / "Program Files/Oarbank"
    (win / "join").mkdir(parents=True)
    (win / "oarbank-node.exe").write_text("")
    assert jw.find_launcher(win / "join/join-window.py", "windows", {"PATH": ""}) == str(win / "oarbank-node.exe")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "oarbank-node").write_text("")
    (bindir / "oarbank-node").chmod(0o755)
    empty = tmp_path / "empty/join/join-window.py"
    candidates = jw.launcher_candidates(empty, "linux", {})
    assert candidates[0] == empty.parent.parent / "oarbank-launcher"
    if os.name == "posix" and not Path("/usr/lib/oarbank/oarbank-launcher").exists():
        assert jw.find_launcher(empty, "linux", {"PATH": str(bindir)}) == str(bindir / "oarbank-node")
        with pytest.raises(jw.WindowError, match="--launcher"):
            jw.find_launcher(empty, "linux", {"PATH": str(tmp_path / "none")})


def test_status_paths_per_os(tmp_path):
    assert jw.status_paths("macos", {}, home=tmp_path) == {
        "system": Path("/Library/Application Support/Oarbank/status/node.json"),
        "personal": tmp_path / "Library/Application Support/Oarbank/status/node.json"}
    assert jw.status_paths("linux", {}) == {"system": Path("/var/lib/oarbank/status/node.json")}
    assert jw.status_paths("windows", {"ProgramData": r"D:\Data"})["system"] == Path(r"D:\Data") / "Oarbank" / "status" / "node.json"
    assert jw.status_paths("linux", {"OARBANK_NODE_STATUS": "/x/node.json", "OARBANK_NODE_STATUS_PERSONAL": "/y"}) == {
        "system": Path("/x/node.json")}


def test_policy_from_the_agent_beside_the_launcher(tmp_path, monkeypatch):
    monkeypatch.delenv("OARBANK_POLICY_FILE", raising=False)
    launcher = tmp_path / "oarbank-launcher"
    launcher.write_text("")
    agent = tmp_path / ("oarbank-agent.exe" if os.name == "nt" else "oarbank-agent")
    agent.write_text("")
    window = jw.Window(str(launcher), platform="windows" if os.name == "nt" else "linux", workdir=str(tmp_path))
    assert window.agent() == str(agent.resolve())
    seen = []

    class Done:
        returncode = 0
        stdout = json.dumps({"JoinCode": CODE, "AllowUserJoin": False, "ManagedByOrganizationName": " Example "}).encode()

    monkeypatch.setattr(jw.subprocess, "run", lambda argv, **kw: seen.append(argv) or Done())
    assert window.policy() == {"allow_user_join": False, "managed_by": "Example"}
    assert seen == [[str(agent.resolve()), "policy"]]


# ---------------------------------------------------------------- the code, offline
def test_decoder_matches_the_shared_vectors():
    for case in VECTORS["codes"]:
        c = jw.decode_code(case["text"])
        assert (c["flags"], c["expires_at"], c["cik"], c["pins"], c["urls"], c["id"]) == \
               (case["flags"], case["expires_at"], case["cik"], case["pins"], case["urls"], case["id"])
        assert c["fingerprint"] == case["pins"][0][:16] and "secret" not in c
    for case in VECTORS["equivalent"]:
        assert jw.decode_code(case["text"]) == jw.decode_code(VECTORS["codes"][case["same_as"]]["text"])
    for case in VECTORS["invalid"]:
        with pytest.raises(jw.WindowError) as e:
            jw.decode_code(case["text"])
        assert e.value.code == "E_CODE_FORMAT"
    with pytest.raises(jw.WindowError) as e:
        jw.offline_check(VECTORS["codes"][0]["text"], now=VECTORS["codes"][0]["expires_at"] + 1)
    assert e.value.code == "E_CODE_EXPIRED"
    fresh = jw.offline_check(CODE)
    assert fresh["host"] == "coord.example.net:7443" and fresh["approve"] and fresh["system"]


# ---------------------------------------------------------------- one window per user
def test_reopen_hands_over_a_new_code_and_the_lock_is_exclusive(env, tmp_path):
    (tmp_path / "temp").mkdir()
    directory = jw.private_dir(tmp_path / "temp")
    if os.name == "posix":
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    window = env.window()
    with serving(window) as server:
        active = directory / "join.active.json"
        jw.write_private(active, json.dumps({"origin": server.origin, "capability": window.capability}))
        url = jw.running_window(directory, {"code": CODE, "source": "link"})
        assert url == f"{server.origin}/#{window.capability}"
        assert window.prefill == {"code": CODE, "source": "link"}
        jw.write_private(active, json.dumps({"origin": server.origin, "capability": "x" * 43}))
        assert jw.running_window(directory) is None
        jw.write_private(active, json.dumps({"origin": "http://example.com:80", "capability": window.capability}))
        assert jw.running_window(directory) is None
    with jw.window_lock(directory):
        if os.name == "posix":
            with pytest.raises(jw.WindowError, match="already"):
                with jw.window_lock(directory):
                    pytest.fail("a second window took the lock")


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and modes")
def test_a_shared_or_foreign_private_dir_is_refused(tmp_path):
    base = tmp_path / "temp"
    base.mkdir()
    d = base / f"oarbank-join-{os.getuid()}"
    d.mkdir(mode=0o755)
    d.chmod(0o755)
    with pytest.raises(jw.WindowError):
        jw.private_dir(base)
    d.rmdir()
    d.symlink_to(tmp_path)
    with pytest.raises(jw.WindowError):
        jw.private_dir(base)


def test_main_prints_the_link_and_exits_when_idle(env, monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(jw.tempfile, "tempdir", str(tmp_path / "temp"))
    (tmp_path / "temp").mkdir()
    real = jw.WindowServer
    monkeypatch.setattr(jw, "WindowServer", lambda w, port: real(w, port, idle_timeout=.2))
    window = env.window()
    monkeypatch.setattr(jw, "Window", lambda launcher, prefill=None, workdir=None: setattr(window, "prefill", prefill) or window)
    # what the native front ends pass: macOS `--launcher /Library/Oarbank/bin/oarbank-launcher [--link URL]`, Windows
    # `--launcher <INSTALLFOLDER>oarbank-node.exe`, Linux `--link %u` (a bare --link when opened from the menu)
    launcher = tmp_path / "Program Files" / "Oarbank" / "oarbank-node.exe"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("")
    start = time.monotonic()
    assert jw.main(["--launcher", str(launcher), "--no-browser", "--link", f"oarbank://join?code={CODE}"]) == 0
    assert time.monotonic() - start < 5
    out = capsys.readouterr().out
    assert out.startswith("Open this private link on this computer: http://127.0.0.1:") and "/#" in out
    assert CODE not in out
    assert window.prefill == {"code": CODE, "source": "link"}
    assert not (jw.private_dir() / "join.active.json").exists()
    assert jw.main(["--no-browser", "--link", "https://example.com"]) == 1
    assert jw.main(["--launcher", str(tmp_path / "missing"), "--no-browser"]) == 1
    for bare in (["--link"], ["--link", ""], ["--link", "  "], []):
        window.prefill = "unchanged"
        assert jw.main(["--launcher", str(launcher), "--no-browser", *bare]) == 0
        assert window.prefill is None, bare
    assert jw.main(["--no-browser", "--link", "--launcher", str(launcher)]) == 0 and window.prefill is None
    with pytest.raises(SystemExit):
        jw.main(["--no-browser", "--link", f"oarbank://join?code={CODE}", "--code-file", str(launcher)])
    assert env.calls() == []
