"""Where the console listens (setting `console_listen`; coordinator/consolelisten.py, console/serve.py): the setting's
validation, tier, plan warning, explain and Settings form; the addresses it resolves to (Tailscale addresses injected);
the Host allowlist and the module-frame origins as the browser sees them; the console's supervisor binding and rebinding
real listeners when the setting or the Tailscale addresses change; and `oarbank console login`'s link per address."""
import asyncio
import re
import socket
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from helpers import admin_headers, make_db, run_op, set_fleet, sign_in
from oarbank.coordinator import access as A, consolelisten as L
from oarbank.coordinator.settings import registry as R
from oarbank.coordinator.settings.registry import SettingError
from test_console import SECRET, Server, env, save_section, settings_html  # noqa: F401 (the fixture)

TS4, TS6 = "100.64.0.1", "fd7a:115c:a1e0::1"
NAME = "box.example.ts.net"


def text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


# ------------------------------------------------------------------ the setting

def test_the_value_is_checked_and_normalized_with_localhost_always_first():
    assert R.get("console_listen").section == "access" and R.get("console_listen").scopes == ("fleet",)
    assert R.default(R.get("console_listen"), None)[0] == ["localhost"]
    assert R.check("console_listen", ["tailscale"]) == ["localhost", "tailscale"]
    assert R.check("console_listen", []) == ["localhost"]
    assert R.check("console_listen", [" Tailscale ", "100.64.0.1", "tailscale", "FD7A:115C:A1E0:0::1"]) == \
        ["localhost", "tailscale", "100.64.0.1", TS6]
    assert R.check("console_listen", ["tailscale", "ALL", "100.64.0.1"]) == ["localhost", "all"]   # all covers the rest
    for bad, why in ((["0.0.0.0"], "write all"), (["::"], "write all"), (["bogus"], "not localhost, tailscale"),
                     (["fe80::1"], "link-local"), (["224.0.0.1"], "multicast"), ([""], "an entry is"),
                     (["100.64.0.1"] * 2 + [f"100.64.0.{i}" for i in range(2, 20)], "at most")):
        with pytest.raises(SettingError, match=why):
            R.check("console_listen", bad)
    with pytest.raises(SettingError, match="expected array"):
        R.check("console_listen", "tailscale")


def test_the_cli_takes_a_comma_list():
    from oarbank.cli.main import _setting_value
    assert _setting_value("console_listen", "localhost,tailscale") == ["localhost", "tailscale"]
    assert _setting_value("console_listen", "tailscale") == ["tailscale"]
    assert _setting_value("console_listen", '["100.64.0.1"]') == ["100.64.0.1"]


def test_every_interface_is_confirmed_by_name_and_the_plan_warns(tmp_path):
    fleet = lambda v: [{"scope": "fleet", "scope_id": "", "key": "console_listen", "value": v}]
    assert R.change_tier(fleet(["tailscale"])) == "T2" and R.change_tier(fleet(["localhost", "all"])) == "T3"
    assert R.change_tier([{"scope": "fleet", "key": "console_listen", "reset": True}]) == "T2"
    db = make_db(tmp_path / "oarbank.sqlite3")
    from oarbank.coordinator.settings import apply
    p = apply.plan(db, fleet(["all"]))
    assert "the console rebinds its listeners within seconds" in p["summary"]
    assert len(p["warnings"]) == 1 and "every interface" in p["warnings"][0]
    assert "reachable from other machines" in apply.plan(db, fleet(["tailscale"]))["warnings"][0]
    assert apply.plan(db, fleet(["localhost"]))["warnings"] == []
    from oarbank.contracts import impact
    assert any(line.startswith("  warnings:") for line in impact.lines(p))            # the CLI's preview shows it


def test_explain_shows_the_default_and_the_fleet_value(tmp_path):
    from oarbank.coordinator import app as coord_app
    db = make_db(tmp_path / "oarbank.sqlite3")
    c = TestClient(coord_app.admin_app(db, coord_app.EventBus()), headers=admin_headers(db))
    ex = c.get("/api/v1/settings/explain", params={"key": "console_listen"}).json()
    assert ex["value"] == ["localhost"] and ex["label"] == "Console listen addresses" and "Tailscale" in ex["help"]
    set_fleet(db, "console_listen", ["tailscale"])
    ex = c.get("/api/v1/settings/explain", params={"key": "console_listen"}).json()
    assert ex["value"] == ["localhost", "tailscale"] and ex["badge"].startswith("Fleet")


def test_the_settings_page_sets_it_through_a_reviewed_plan(env):
    c, db = env["c"], env["db"]
    html, t = settings_html(env, path="/settings")
    assert "Console listen addresses" in t and 'name="v.console_listen"' in html
    assert "cannot see the console's listeners" in t                  # a test client is not oarbank-console
    r = save_section(env, "access", page="/settings", o__console_listen="1", v__console_listen="localhost\ntailscale")
    assert r.status_code == 200, r.text[:400]
    t = text(r.text)
    assert "Exposure" in t and "reachable from other machines" in t and "(T2)" in t
    pid = re.search(r'name="plan_id" value="([^"]+)"', r.text).group(1)
    r = c.post("/apply/settings.apply", data={"plan_id": pid, "reason": "reach it over the tailnet", "return_to": "/settings"},
               follow_redirects=False)
    assert r.status_code == 303 and "kind=ok" in r.headers["location"], r.headers["location"]
    from oarbank.coordinator.settings.store import fleet_value
    assert fleet_value(db, "console_listen") == ["localhost", "tailscale"]
    # every interface: the warning and the typed confirmation
    r = save_section(env, "access", page="/settings", o__console_listen="1", v__console_listen="all")
    t = text(r.text)
    assert "every interface" in t and "Type console_listen to confirm" in t and "(T3)" in t
    pid = re.search(r'name="plan_id" value="([^"]+)"', r.text).group(1)
    r = c.post("/apply/settings.apply", data={"plan_id": pid, "reason": "lan", "confirm": "nope"})
    assert r.status_code == 400 and fleet_value(db, "console_listen") == ["localhost", "tailscale"]


# ------------------------------------------------------------------ resolving the addresses

def test_targets_resolve_to_addresses_with_tailscale_injected():
    assert L.resolve(["localhost"], None) == (["127.0.0.1"], [])
    assert L.resolve(["tailscale"], [TS4, TS6]) == (["127.0.0.1", TS4, TS6], [])
    addrs, notes = L.resolve(["tailscale", "100.64.0.7"], [])
    assert addrs == ["127.0.0.1", "100.64.0.7"] and "no Tailscale address now" in notes[0]
    assert L.resolve(["tailscale", "all"], [TS4]) == (["0.0.0.0", "::"], [])            # wildcards alone
    assert L.resolve(["127.0.0.1", "tailscale"], [TS4]) == (["127.0.0.1", TS4], [])
    addrs, notes = L.resolve(["0.0.0.0"], [TS4])                                         # a bad stored value
    assert addrs == ["127.0.0.1"] and "not valid" in notes[0]
    assert L.link_hosts(["tailscale"], [TS4, TS6]) == ["127.0.0.1", TS4, f"[{TS6}]"]
    assert L.link_hosts(["all"], [TS4]) == ["127.0.0.1", TS4]
    assert L.parse_ips(f"{TS6}\n{TS4}\n") == [TS4, TS6] and L.parse_ips(f'["{TS4}"]') == [TS4]
    assert L.parse_ips("no addresses\n127.0.0.1\n") == []
    assert L.tailscale_ips(cli="/nonexistent/tailscale") == []
    assert L.exposes(["localhost"]) is None


def test_the_other_listeners_origin_follows_the_host_the_browser_used():
    for host, want in ((f"{TS4}:7400", f"http://{TS4}:7402"), ("localhost:7400", "http://localhost:7402"),
                       (f"[{TS6}]:7400", f"http://[{TS6}]:7402"), ("Box.Example.ts.net:7400", "http://box.example.ts.net:7402"),
                       ("oarbank.example.ts.net", "http://127.0.0.1:7402"),          # proxied (tailscale serve): the default
                       (f"{TS4}:443", "http://127.0.0.1:7402"), (None, "http://127.0.0.1:7402")):
        assert L.other_origin(host, 7400, 7402, "http://127.0.0.1:7402") == want, host
    assert L.split_host(f"[{TS6}]:7402") == (f"[{TS6}]", 7402) and L.split_host("a.example") == ("a.example", None)
    from oarbank.console.__main__ import origins
    a = SimpleNamespace(port=7400, frames_port=7402, module_origin=None, console_origin=None)
    mo, co = origins(a)
    req = lambda host: SimpleNamespace(headers={"host": host})
    assert mo(req(f"{TS4}:7400")) == f"http://{TS4}:7402" and co(req(f"{TS4}:7402")) == f"http://{TS4}:7400"
    mo, co = origins(SimpleNamespace(port=7400, frames_port=7402, module_origin="https://frames.example",
                                     console_origin="https://console.example"))
    assert mo(req(f"{TS4}:7400")) == "https://frames.example" and co(req("x")) == "https://console.example"


def test_listen_addresses_join_the_host_allowlist():
    allowed = A.allowed_hosts(7400, ["box.example.ts.net"], [TS4, TS6, "0.0.0.0"])
    assert {f"{TS4}:7400", f"[{TS6}]:7400", "box.example.ts.net:7400", "localhost:7400"} <= allowed
    assert "0.0.0.0:7400" not in allowed and TS4 not in allowed                       # its port only
    assert A.host_ok(f"{TS4}:7400", allowed) and not A.host_ok("100.64.0.9:7400", allowed)
    assert A.host_ok("192.0.2.4:7400", allowed, any_ip_port=7400)                      # under all: any IP literal
    assert not A.host_ok("192.0.2.4:7401", allowed, any_ip_port=7400)
    assert not A.host_ok("rebind.example:7400", allowed, any_ip_port=7400)            # never a name


class FakeListening:
    def __init__(self, addrs, value=("localhost", "tailscale")):
        self.addrs, self.value = list(addrs), list(value)

    def hosts(self, name=None):
        return [a for a in self.addrs if a not in L.WILDCARDS]

    def everywhere(self):
        return any(a in L.WILDCARDS for a in self.addrs)

    https = None                                   # the https name while tailscale serve proxies to this console

    def https_name(self):
        return self.https

    def names(self, name=None):
        return [] if not self.https else [self.https, f"{self.https}:443"] if name in (None, "console") \
            else [f"{self.https}:8443"]

    def status(self):
        return {"value": self.value, "notes": [], "errors": ["frames 100.64.0.5:7402: [Errno 49] cannot assign"],
                "https": {"mode": "tailscale", "name": NAME, "url": f"https://{NAME}/" if self.https else None,
                          "frames": f"https://{NAME}:8443" if self.https else None, "error": None, "commands": []},
                "listeners": {"console": [f"http://{L.url_host(a)}:7400" for a in self.addrs],
                              "frames": [f"http://{L.url_host(a)}:7402" for a in self.addrs]}}


@pytest.fixture
def remote(tmp_path):
    """The console app as oarbank-console builds it (origins from the request), listening on loopback and a Tailscale
    address, reached at http://100.64.0.1:7400."""
    from oarbank.console.__main__ import origins
    from oarbank.console.app import console_app
    from oarbank.console.frames import frames_app
    from oarbank.console.state import ConsoleState, Reader
    from oarbank.coordinator import app as coord_app
    path = tmp_path / "oarbank.sqlite3"
    db = make_db(path)
    lis = FakeListening(["127.0.0.1", TS4])
    mo, co = origins(SimpleNamespace(port=7400, frames_port=7402, module_origin=None, console_origin=None),
                     https_name=lambda: lis.https)
    with Server(coord_app.admin_app(db, console_secret=SECRET)) as oarbankd:
        state = ConsoleState(path, f"http://127.0.0.1:{oarbankd.port}", secret=SECRET)
        app = console_app(state, module_origin=mo, listening=lambda: lis)
        frames = frames_app(app.state.catalog, co, reader=Reader(path), listening=lambda: lis)
        A.TEST_HOSTS.discard("testserver")
        try:
            with TestClient(app, base_url=f"http://{TS4}:7400") as c:
                sign_in(c, db)
                yield SimpleNamespace(db=db, c=c, app=app, frames=frames, lis=lis)
        finally:
            A.TEST_HOSTS.add("testserver")


def test_the_console_answers_at_its_listen_addresses_with_frames_at_the_same_host(remote):
    r = remote.c.get("/settings")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert f"frame-src http://{TS4}:7402" in csp and "127.0.0.1:7402" not in csp
    t = text(r.text)
    assert f"http://{TS4}:7400" in t and "http://127.0.0.1:7400" in t and "Listening now" in t
    assert "cannot assign" in t and "Every interface" not in t
    assert remote.c.get("/healthz").json()["listening"]["console"] == ["http://127.0.0.1:7400", f"http://{TS4}:7400"]
    csp = remote.c.get("/healthz", headers={"host": "localhost:7400"}).headers["content-security-policy"]
    assert "frame-src http://localhost:7402" in csp
    assert remote.c.get("/healthz", headers={"host": "100.64.0.9:7400"}).status_code == 421     # not a listen address
    remote.lis.addrs = ["0.0.0.0", "::"]                                                         # all
    remote.lis.value = ["localhost", "all"]
    assert remote.c.get("/healthz", headers={"host": "192.0.2.4:7400"}).status_code == 200
    assert remote.c.get("/healthz", headers={"host": "rebind.example:7400"}).status_code == 421
    assert "Every interface" in text(remote.c.get("/settings", headers={"host": "192.0.2.4:7400"}).text)


def test_the_module_origin_checks_hosts_and_frames_only_into_the_console_at_the_same_host(remote):
    with TestClient(remote.frames, base_url=f"http://{TS4}:7402") as f:
        assert f.get("/healthz").status_code == 200
        r = f.get("/f/nope/main/")
        assert r.status_code == 404 and r.headers["content-security-policy"].endswith(f"frame-ancestors http://{TS4}:7400")
        r = f.get("/f/nope/main/", headers={"host": "localhost:7402"})
        assert r.headers["content-security-policy"].endswith("frame-ancestors http://localhost:7400")
        assert f.get("/healthz", headers={"host": "100.64.0.9:7402"}).status_code == 421
        assert f.get("/healthz", headers={"host": "evil.example:7402"}).status_code == 421
        set_fleet(remote.db, "console_hosts", ["box.example.ts.net"])                              # a MagicDNS name
        assert f.get("/healthz", headers={"host": "box.example.ts.net:7402"}).status_code == 200


# ------------------------------------------------------------------ the supervisor: binding and rebinding

def _app(name):
    app = FastAPI()
    app.get("/who")(lambda: {"listener": name})
    return app


def test_the_supervisor_binds_every_address_and_rebinds_when_the_setting_or_tailscale_changes():
    from oarbank.console import serve
    value, ips, ports, refuse = {"v": ["localhost"]}, {"v": [TS4]}, {}, set()

    def bind(addr, port):                      # each address lands on its own loopback port (the test cannot own 100.64/10)
        if addr in refuse:
            raise OSError(49, "Can't assign requested address")
        s = serve.bind_socket("127.0.0.1", 0)
        ports[(addr, port)] = s.getsockname()[1]
        return s

    async def get(addr, port):
        async with httpx.AsyncClient() as c:
            return (await c.get(f"http://127.0.0.1:{ports[(addr, port)]}/who", timeout=5)).json()["listener"]

    async def closed(addr, port):
        with pytest.raises(httpx.HTTPError):
            await get(addr, port)

    async def scenario():
        lis = serve.Listeners({"console": (_app("console"), 7400), "frames": (_app("frames"), 7402)},
                              targets=lambda: value["v"], tailscale=lambda: list(ips["v"]), bind=bind, tailscale_s=0)
        await lis.reconcile()
        assert lis.addresses() == ["127.0.0.1"] and lis.addresses("frames") == ["127.0.0.1"]
        assert await get("127.0.0.1", 7400) == "console" and await get("127.0.0.1", 7402) == "frames"
        value["v"] = ["localhost", "tailscale"]
        await lis.reconcile()
        assert lis.addresses() == ["127.0.0.1", TS4] and lis.hosts("frames") == ["127.0.0.1", TS4]
        assert await get(TS4, 7400) == "console" and await get(TS4, 7402) == "frames"
        assert lis.status()["listeners"]["console"] == ["http://127.0.0.1:7400", f"http://{TS4}:7400"]
        loopback = lis.servers[("console", "127.0.0.1")]
        ips["v"] = ["100.64.0.2"]                                                        # Tailscale's address changed
        await lis.reconcile()
        assert lis.addresses() == ["127.0.0.1", "100.64.0.2"] and lis.servers[("console", "127.0.0.1")] is loopback
        await closed(TS4, 7400)
        ips["v"] = []                                                                    # Tailscale down: noted
        await lis.reconcile()
        assert lis.addresses() == ["127.0.0.1"] and "no Tailscale address" in lis.status()["notes"][0]
        value["v"] = ["localhost", "100.64.0.5"]
        refuse.add("100.64.0.5")
        await lis.reconcile()                                                            # not bindable now: retried
        assert lis.addresses() == ["127.0.0.1"] and "Can't assign" in " ".join(lis.status()["errors"])
        refuse.clear()
        await lis.reconcile()
        assert lis.addresses() == ["127.0.0.1", "100.64.0.5"] and lis.status()["errors"] == []
        value["v"] = ["all"]                                                             # specific ones go first
        await lis.reconcile()
        assert lis.addresses() == ["0.0.0.0", "::"] and lis.everywhere() and lis.hosts() == []
        await closed("127.0.0.1", 7400)
        value["v"] = ["localhost"]
        await lis.reconcile()
        assert lis.addresses() == ["127.0.0.1"] and set(lis.servers) == {("console", "127.0.0.1"), ("frames", "127.0.0.1")}
        await lis.close()
        assert lis.servers == {}
    asyncio.run(scenario())


def test_the_supervisor_reads_the_setting_until_stopped_and_exits_when_localhost_is_taken():
    from oarbank.console import serve
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen()
    taken = holder.getsockname()[1]

    async def first_pass_fails():
        lis = serve.Listeners({"console": (_app("console"), taken)}, targets=lambda: ["localhost"],
                              bind=lambda a, p: serve.bind_socket("127.0.0.1", p))
        with pytest.raises(SystemExit):
            await lis.run()

    async def runs_until_stopped():
        reads = {"n": 0}

        def targets():
            reads["n"] += 1
            if reads["n"] == 3:
                raise RuntimeError("database is locked")                      # kept: the last value stands
            return ["localhost"]
        lis = serve.Listeners({"console": (_app("console"), 0)}, targets=targets, poll_s=0.01,
                              bind=lambda a, p: serve.bind_socket("127.0.0.1", 0))
        task = asyncio.get_running_loop().create_task(lis.run())
        while lis.passes < 4:
            await asyncio.sleep(0.01)
        assert lis.addresses() == ["127.0.0.1"] and lis.value == ["localhost"]
        lis.stop()
        await asyncio.wait_for(task, 10)
        assert lis.servers == {}
    try:
        asyncio.run(first_pass_fails())
        asyncio.run(runs_until_stopped())
    finally:
        holder.close()


def test_a_real_socket_binds_exactly_its_address():
    from oarbank.console import serve
    s = serve.bind_socket("127.0.0.1", 0)
    try:
        assert s.getsockname()[0] == "127.0.0.1"
    finally:
        s.close()
    if socket.has_ipv6:
        try:
            s = serve.bind_socket("::1", 0)
        except OSError:
            return                                                             # no IPv6 loopback on this runner
        try:
            assert s.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
        finally:
            s.close()


# ------------------------------------------------------------------ sign-in links

def test_console_login_prints_a_link_for_each_listen_address(tmp_path, monkeypatch):
    db = make_db(tmp_path / "oarbank.sqlite3")
    from oarbank.coordinator import access
    access.create_account(db, "owner", "admin", None, "test")
    r = run_op(db, "access.login_link", "owner")["result"]
    assert r["urls"] == [r["url"]] and r["url"].startswith("http://127.0.0.1:7400/login/link?t=")
    monkeypatch.setattr(L, "tailscale_ips", lambda *a, **k: [TS4, TS6])
    set_fleet(db, "console_listen", ["tailscale"])
    r = run_op(db, "access.login_link", "owner")["result"]
    t = r["url"].split("?t=")[1]
    assert r["urls"] == [f"http://127.0.0.1:7400/login/link?t={t}", f"http://{TS4}:7400/login/link?t={t}",
                         f"http://[{TS6}]:7400/login/link?t={t}"]
    r = run_op(db, "access.login_link", "owner", {"console": "https://box.example.ts.net/"})["result"]
    assert r["urls"] == [r["url"]] and r["url"].startswith("https://box.example.ts.net/login/link?t=")


# ------------------------------------------------------------------ https on the Tailscale name (passkeys)

def test_console_https_is_a_choice_and_the_plan_says_who_reaches_it(tmp_path):
    assert R.check("console_https", "tailscale") == "tailscale" and R.default(R.get("console_https"), None)[0] == "off"
    with pytest.raises(SettingError):
        R.check("console_https", "funnel")
    db = make_db(tmp_path / "oarbank.sqlite3")
    from oarbank.coordinator.settings import apply
    p = apply.plan(db, [{"scope": "fleet", "scope_id": "", "key": "console_https", "value": "tailscale"}])
    assert "never Funnel" in p["warnings"][0] and "tailscale serve entries" in p["summary"]


class FakeTailscale:
    """`tailscale status --json`, `serve status --json` and `serve --bg --https=<port> <target>` / `--https=<port> off`."""

    def __init__(self, name=NAME, refuse=False):
        self.name, self.refuse, self.web, self.calls = name, refuse, {}, []

    def __call__(self, args):
        import json
        self.calls.append(list(args))
        if args == ["status", "--json"]:
            return (0, json.dumps({"Self": {"DNSName": f"{self.name}."}})) if self.name else (1, "not running")
        if args == ["serve", "status", "--json"]:
            return 0, json.dumps({"Web": {k: {"Handlers": {"/": {"Proxy": v}}} for k, v in self.web.items()}})
        if args[0] == "serve":
            if self.refuse:
                return 1, "Access denied: serve config denied"
            port = int(args[-2 if args[-1] == "off" else 2].split("=")[1])
            if args[-1] == "off":
                self.web.pop(f"{self.name}:{port}", None)
            else:
                self.web[f"{self.name}:{port}"] = args[-1]
            return 0, ""
        return 1, "unknown"


def test_https_mode_sets_up_tailscale_serve_and_removes_only_its_own_entries():
    from oarbank.console.serve import HttpsServe
    mode, ts = {"v": "off"}, FakeTailscale()
    h = HttpsServe(lambda: mode["v"], 7400, 7402, cli=ts)
    h.check()
    assert h.https_name() is None and not [c for c in ts.calls if c[:2] == ["serve", "--bg"]]
    mode["v"] = "tailscale"
    h.check()
    assert ts.web == {f"{NAME}:443": "http://127.0.0.1:7400", f"{NAME}:8443": "http://127.0.0.1:7402"}
    assert h.https_name() == NAME and h.status()["url"] == f"https://{NAME}/" and h.status()["frames"] == f"https://{NAME}:8443"
    n = len(ts.calls)
    h.check()                                                                            # already right: nothing run
    assert not [c for c in ts.calls[n:] if c[:2] == ["serve", "--bg"]]
    mode["v"] = "off"
    h.check()
    assert ts.web == {} and h.https_name() is None
    # an entry set outside Oarbank is never replaced, nor removed when the setting is off at start
    ts.web = {f"{NAME}:443": "http://127.0.0.1:9000"}
    mode["v"] = "tailscale"
    h.check()
    assert "already serves http://127.0.0.1:9000" in h.error and ts.web == {f"{NAME}:443": "http://127.0.0.1:9000"}
    ts.web = {f"{NAME}:443": "http://localhost:7400"}                                    # the owner's own, to this console
    fresh = HttpsServe(lambda: "off", 7400, 7402, cli=ts)
    fresh.check()
    assert fresh.https_name() == NAME and ts.web == {f"{NAME}:443": "http://localhost:7400"}


def test_https_mode_names_the_commands_when_it_may_not_change_tailscale_serve():
    from oarbank.console.serve import HttpsServe
    h = HttpsServe(lambda: "tailscale", 7400, 7402, cli=FakeTailscale(refuse=True))
    h.check()
    assert "Access denied" in h.error and h.https_name() is None
    assert h.commands[0].endswith("serve --bg --https=443 http://127.0.0.1:7400") and h.commands[1].endswith("--https=8443 http://127.0.0.1:7402")
    h = HttpsServe(lambda: "tailscale", 7400, 7402, cli=FakeTailscale(name=None))
    h.check()
    assert "no host name" in h.error and h.commands == []


def test_the_supervisor_runs_the_https_check_on_change_and_every_30s():
    from oarbank.console import serve
    clock, mode, ts = {"t": 0.0}, {"v": "off"}, FakeTailscale()
    h = serve.HttpsServe(lambda: mode["v"], 7400, 7402, cli=ts, clock=lambda: clock["t"])

    async def go():
        await h.reconcile()
        n = len(ts.calls)
        await h.reconcile()
        assert len(ts.calls) == n                                                        # not yet
        mode["v"] = "tailscale"
        await h.reconcile()                                                              # a change: at once
        assert h.https_name() == NAME
        n = len(ts.calls)
        clock["t"] = 31
        await h.reconcile()
        assert len(ts.calls) > n
    asyncio.run(go())
    lis = serve.Listeners({"console": (None, 7400), "frames": (None, 7402)}, targets=lambda: ["localhost"], https=h)
    assert lis.names() == [NAME, f"{NAME}:443"] and lis.names("frames") == [f"{NAME}:8443"]
    assert lis.status()["https"]["url"] == f"https://{NAME}/"


def test_through_the_https_name_the_frames_are_on_8443_and_passkeys_have_a_host_name(remote):
    remote.lis.https = NAME
    with TestClient(remote.app, base_url=f"https://{NAME}") as c:
        sign_in(c, remote.db)
        r = c.get("/settings")
        assert r.status_code == 200 and f"frame-src https://{NAME}:8443" in r.headers["content-security-policy"]
        assert f"https://{NAME}/" in text(r.text)
    assert A.rp_for(NAME, "https") == (NAME, f"https://{NAME}")
    with TestClient(remote.frames, base_url=f"https://{NAME}:8443") as f:
        r = f.get("/f/nope/main/")
        assert r.status_code == 404 and r.headers["content-security-policy"].endswith(f"frame-ancestors https://{NAME}")
    remote.lis.https = None                                                              # serve gone: the name is refused
    with TestClient(remote.app, base_url=f"https://{NAME}") as c:
        assert c.get("/healthz").status_code == 421


def test_the_sign_in_links_include_the_https_name(tmp_path, monkeypatch):
    import json
    db = make_db(tmp_path / "oarbank.sqlite3")
    from oarbank.coordinator import access
    access.create_account(db, "owner", "admin", None, "test")
    monkeypatch.setattr(L, "tailscale_status", lambda *a, **k: json.loads(json.dumps({"Self": {"DNSName": f"{NAME}."}})))
    set_fleet(db, "console_https", "tailscale")
    r = run_op(db, "access.login_link", "owner")["result"]
    t = r["url"].split("?t=")[1]
    assert r["urls"] == [f"http://127.0.0.1:7400/login/link?t={t}", f"https://{NAME}/login/link?t={t}"]
