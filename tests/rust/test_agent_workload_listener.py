"""A public listener reaches a workload (docs/design/workloads.md, inbound-listeners.md): a real coordinator, a real
agent and the fake NAT gateway on loopback. A copy of the SDK's `publicecho` whose `echo` listener is served by a
workload instead of an endpoint service: the owner assigns the workload to the node and the listener to the same node,
the agent maps the port on the gateway and relays a client's connection, accepted at the mapped address, into the
workload's endpoint channel; the workload answers with the external address the agent announced to it. Unassigned,
the workload ends while the listener stays bound (new connections are closed at once). Every process the agent acted
on is one this test started."""
import json
import os
import shutil
import signal
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from conftest import REPO, agent_env, free_port, install_module  # noqa: E402
from procguard import SpawnTree  # noqa: E402
from test_agent_listeners import Gateway, ask, listener  # noqa: E402
from test_agent_session import wait  # noqa: E402

PUBLICECHO = REPO / "vendor" / "oarbank-sdk" / "examples" / "publicecho"

WORKLOAD = r'''
"""publicecho's `echo` listener served by a workload: each connection the agent hands it on its endpoint channel is
answered line by line with `echo <line> <external>`."""
import json, os, socket, sys, threading, time
from oarbank_sdk import service_endpoint as ep

op = sys.argv[1] if len(sys.argv) > 1 else ""
if op == "status":
    print(json.dumps({"healthy": True, "detail": "ok"}))
    sys.exit(0)
if op != "run":
    sys.exit(64)


def watch_stop():
    ctl = os.environ["OARBANK_CONTROL_FILE"]
    while True:
        try:
            if json.load(open(ctl)).get("stop"):
                os._exit(0)
        except (OSError, ValueError):
            pass
        time.sleep(0.3)


def serve_one(acc, conn, origin):
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                text = line.rstrip(b"\r").decode("utf-8", "replace")
                conn.sendall(f"echo {text} {acc.external('echo') or '-'}\n".encode())
    except OSError:
        pass
    finally:
        conn.close()


threading.Thread(target=watch_stop, daemon=True).start()
acc = ep.Acceptor()
for conn, origin in acc:
    threading.Thread(target=serve_one, args=(acc, conn, origin), daemon=True).start()
'''


def workload_echo(tmp) -> "Path":
    src = tmp / "publicecho"
    shutil.copytree(PUBLICECHO, src)
    m = (src / "oarbank-module.toml").read_text(encoding="utf-8")
    head, _, rest = m.partition("[[services]]")
    rest = rest[rest.index("[results]"):]                  # the echo service goes; a workload serves the listener
    m = head + rest
    m = m.replace("service_protocol = [1]\n", "workload_protocol = [1]\n")
    m += '''
[[workloads]]
name = "worker"
exec = ["python", "-I", "{bundle}/echo_workload.py"]
listeners = ["echo"]
control = ["freeze_ok"]
stop_timeout_s = 5
restart = { backoff_initial_s = 1, backoff_max_s = 5, max_failures = 5 }
'''
    (src / "oarbank-module.toml").write_text(m, encoding="utf-8")
    (src / "echo_workload.py").write_text(WORKLOAD, encoding="utf-8")
    (src / "echo_service.py").unlink()
    return src


def planned(c, name, target, params):
    plan = c.api("POST", f"/api/v1/ops/{name}", json={"target": target, "params": params, "dry_run": True})["plan"]
    return c.api("POST", f"/api/v1/ops/{name}", json={"plan_id": plan["plan_id"], "reason": "e2e"})


def row(c):
    rows = c.api("GET", "/api/v1/workloads")["workloads"]
    return rows[0] if rows else {}


@pytest.mark.skipif(os.name == "nt", reason="the guard reads the POSIX process table; Windows relays the same way")
def test_a_public_listener_reaches_a_workload_through_the_relay(agent_bin, coordinator, tmp_path):
    c = coordinator
    ext = free_port()
    gw = Gateway({"forward": True, "external": "127.0.0.1", "natpmp": True, "pcp": True, "upnp": True})
    install_module(c, workload_echo(tmp_path), tmp_path, approve=True)
    home = tmp_path / "agent"
    tree = SpawnTree().__enter__()
    env = {**agent_env(), "OARBANK_PORTMAP_GATEWAY": gw.addr["pmp"], "OARBANK_PORTMAP_SSDP": gw.addr["ssdp"],
           "OARBANK_PORTMAP_TIMING": "fast", "OARBANK_TEST_IGNORE_OS_MEMORY_PRESSURE": "1"}
    log = open(f"{home}.log", "ab")
    p = subprocess.Popen([str(agent_bin), "--home", str(home), "run", "--coordinator", c.url], env=env,
                         stdout=log, stderr=subprocess.STDOUT)
    try:
        floors = {"soft_free_pct": 1, "hard_free_pct": 0.5, "swap_growth_soft_mb_min": 1e9, "swap_growth_hard_mb_min": 1e9}
        planned(c, "protection.rules.update", "fleet", {"config": {"schema": 1, "node": {"mode": "fleet_first", "memory": floors}}})
        pending = wait(lambda: [e for e in c.api("GET", "/api/v1/fleet")["enrollments"] if e["status"] == "pending"] or None)
        nid = c.admit(pending[0]["enrollment_id"])["result"]["node_id"]
        # the owner assigns the workload, and the listener, to the node
        planned(c, "workloads.assign", "publicecho/worker", {"node": nid})
        r = wait(lambda: (lambda x: x if x.get("state") == "running" else None)(row(c)), timeout=240)
        tree.add(r["report"]["pid"])
        params = {"key": "publicecho/echo", "external_port": ext, "fallback": "refuse", "mapping": "auto"}
        planned(c, "listeners.configure", nid, params)
        x = wait(lambda: (lambda x: x if x.get("state") == "listening" and x.get("external") else None)(listener(c, nid)),
                 timeout=240)
        assert x["external"] == f"127.0.0.1:{ext}", x
        assert [m["external_port"] for m in gw.ours()] == [ext]
        # a client at the mapped address is answered by the workload, through the relay, with its announced address
        answer = wait(lambda: (lambda a: a if a.endswith(f"127.0.0.1:{ext}") else None)(ask(f"127.0.0.1:{ext}", "hello")),
                      timeout=90)
        assert answer == f"echo hello 127.0.0.1:{ext}"
        wait(lambda: (listener(c, nid).get("conns") or {}).get("accepted", 0) >= 1, timeout=60)
        # the workload saw the announcement in its listeners file too
        data = home / "modules-data" / "publicecho" / "listeners-worker.json"
        assert json.loads(data.read_text())["echo"]["external"] == f"127.0.0.1:{ext}"
        # unassigned: the workload ends; the listener stays bound and closes new connections at once
        leader = row(c)["report"]["pid"]
        c.api("POST", "/api/v1/ops/workloads.unassign", json={"target": "publicecho/worker", "params": {"node": nid},
                                                             "reason": "e2e"})
        wait(lambda: not tree.alive(leader), timeout=60)

        def refused():
            try:
                return ask(f"127.0.0.1:{ext}", "anyone") == ""
            except OSError:
                return True
        wait(lambda: refused() or None, timeout=60)
        # the guard: the agent acted on nothing but this test's own processes
        tree.check_journal(home)
    finally:
        if p.poll() is None:
            tree.signal(p.pid, signal.SIGTERM)
            try:
                p.wait(60)
            except subprocess.TimeoutExpired:
                tree.signal(p.pid, signal.SIGKILL)
                p.wait()
        subprocess.run([str(agent_bin), "--home", str(home), "stop-workloads"], capture_output=True)
        tree.__exit__(None, None, None)
        gw.close()
        text = open(f"{home}.log", encoding="utf-8", errors="replace").read() if os.path.exists(f"{home}.log") else ""
        print(text[-6000:])
