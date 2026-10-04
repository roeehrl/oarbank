"""oarbank: command line for oarbankd's admin API (the same API the console uses). Module-specific commands (a
module's importers, its campaign kinds) live in the module's own CLI, which calls the same API.

Talks to oarbankd's admin API at http://127.0.0.1:7401 by default (on the coordinator; works while oarbank-console
is down, e.g. for `oarbank pause --all`), or OARBANKD_URL, e.g. https://oarbank.<tailnet>.ts.net from any
tailnet device (oarbank-console forwards /api/* with your Tailscale identity).
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import httpx

URL = os.environ.get("OARBANKD_URL", "http://127.0.0.1:7401")


def _local_socket():
    """The coordinator's local admin socket (its directory is owner-only: reaching it is the credential)."""
    if os.environ.get("OARBANKD_URL") or os.environ.get("OARBANK_TOKEN"):
        return None
    from ..coordinator import config as C
    from ..paths import runtime_socket
    try:
        p = runtime_socket(C.HOME, "admin.sock")
    except OSError:
        return None
    return p if p.exists() and os.access(p, os.R_OK | os.W_OK) else None


def http_request(method, url, **kw):
    """httpx.request, through the local admin socket when this is the coordinator's own account."""
    sock = _local_socket()
    if sock and url.startswith(URL):
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(sock)), base_url="http://oarbank") as c:
            return c.request(method, url[len(URL):], **kw)
    return httpx.request(method, url, **kw)


def auth_headers() -> dict:
    """The caller's credential: OARBANK_TOKEN (a personal access token, or the admin token), else the local owner's
    admin token from the coordinator's home (readable only by the account that runs oarbankd)."""
    tok = os.environ.get("OARBANK_TOKEN")
    if not tok and _local_socket():
        return {}
    if not tok:
        from ..coordinator import config as C
        p = C.HOME / "admin.token"
        try:
            tok = p.read_text().strip()
        except OSError:
            sys.exit(f"no credential: set OARBANK_TOKEN, or run this as the account that runs oarbankd ({p})")
    return {"authorization": f"Bearer {tok}"}


def api(method, path, body=None, timeout=600):
    r = http_request(method, URL + path, json=body, timeout=timeout, headers=auth_headers())
    if r.status_code >= 400:
        sys.exit(f"{method} {path}: {r.status_code} {r.text}")
    return r.json() if r.text else None


def _kv(items):
    out = {}
    for it in items or []:
        k, _, v = it.partition("=")
        try:
            out[k] = json.loads(v)
        except json.JSONDecodeError:
            out[k] = v
    return out


def ask(prompt: str, flag: str) -> str:
    """A question for the person at the terminal; with nobody to answer (stdin closed: a script, ssh, CI), name the flag
    that answers it instead of failing with a traceback."""
    try:
        return input(prompt)
    except EOFError:
        sys.exit(f"\n{prompt.strip()} has no answer on stdin: pass {flag}")


def run_op(op, target=None, params=None, reason=None, yes=False, confirm=None, if_match=None, dry_run=False, out=print,
           secret=None):
    """One operation through POST /api/v1/ops/<op>: T2/T3 preview first, print the impact, ask (unless
    --yes), then apply the plan; creations get an Idempotency-Key. Exit codes: 0 applied / no-op,
    2 changes previewed but not applied, 1 error (Terraform's -detailed-exitcode convention)."""
    import uuid
    info = {o["id"]: o for o in api("GET", "/api/v1/ops")}.get(op)
    if info is None:
        sys.exit(f"unknown operation {op}")
    reason = reason or os.environ.get("OARBANK_REASON")
    headers = {"x-oarbank-source": "cli"}
    if info["idempotency"] == "key":
        headers["idempotency-key"] = str(uuid.uuid4())
    if if_match is not None:
        headers["if-match"] = str(if_match)
    body = {"target": target, "params": params or {}, "reason": reason}
    if secret is not None:
        body["secret"] = secret                  # secrets.set's value, beside params (never echoed back)

    def post(b):
        r = http_request("POST", f"{URL}/api/v1/ops/{op}", json=b, headers={**headers, **auth_headers()}, timeout=3600)
        return r.status_code, (r.json() if r.text else {})

    if info["tier"] in ("T2", "T3") or dry_run:
        code, res = post({**body, "dry_run": True})
        if code >= 400:
            sys.exit(f"{op}: {code} {res}")
        plan = res["plan"]
        from ..contracts import impact
        on = plan.get("target") or target
        out(f"{op} ({info['tier']})" + (f" on {on}" if on else "") + ":")
        for line in impact.lines(plan["impact"]):
            out(line)
        if dry_run:
            out(f"plan {plan['plan_id']} (expires in 30 min)")
            sys.exit(2)
        if not yes and ask("apply? [y/N] ", "--yes").strip().lower() != "y":
            sys.exit(2)
        if info["tier"] == "T3" and not confirm:
            confirm = ask(f"type {plan['confirm_name']!r} to confirm: ", f"--confirm {plan['confirm_name']!r}").strip()
        if info["reason_policy"] == "required" and not reason:
            reason = ask("reason: ", "--reason").strip()
        body = {"plan_id": plan["plan_id"], "reason": reason, "confirm": confirm}
    elif info["tier"] == "T1" and not yes and sys.stdin.isatty():
        if input(f"{op} on {target}? [y/N] ").strip().lower() != "y":
            sys.exit(2)
    code, res = post(body)
    if code >= 400:
        sys.exit(f"{op}: {code} {json.dumps(res)}")
    return res


def cmd_op(a):
    res = run_op(a.op, a.target, {**_kv(a.param), **(json.loads(a.json) if a.json else {})}, a.reason, a.yes,
                 a.confirm, a.if_match, a.dry_run)
    print(json.dumps(res, indent=1, default=str))


def cmd_secret(a):
    """Module secrets, write-only: set reads the value from stdin (or a prompt that does not echo), never from argv."""
    if a.action == "list":
        d = api("GET", f"/api/v1/modules/{a.module}/secrets")
        for s in d["secrets"]:
            scopes = ([f"module {s['module']['fingerprint']}{'' if s['module']['readable'] else ' (unreadable here)'}"]
                      if s["module"] else []) + [f"{n['hostname'] or n['node_id']} {n['fingerprint']}" for n in s["nodes"]]
            print(f"{s['name']:<24} {'set' if s['set'] else 'NOT SET':<8} stages={','.join(s['stages']) or '-'}"
                  f"{' +coordinator' if s['coordinator'] else ''}  {'; '.join(scopes)}")
        return
    if not a.name:
        sys.exit(f"oarbank secret {a.action} <module> <name>")
    params = {"name": a.name, **({"node": a.node} if a.node else {})}
    if a.action == "clear":
        print(json.dumps(run_op("secrets.clear", a.module, params, a.reason, a.yes)["result"], default=str))
        return
    if sys.stdin.isatty():
        import getpass
        value = getpass.getpass(f"{a.module}/{a.name}: ")
        if getpass.getpass("again: ") != value:
            sys.exit("the two entries differ; nothing was set")
    else:
        value = sys.stdin.read()
        value = value[:-1] if value.endswith("\n") else value
    res = run_op("secrets.set", a.module, params, a.reason, True, secret=value)["result"]
    print(f"{a.module}/{a.name} set for {res['node'] or 'the module'}: fingerprint {res['fingerprint']}")


def cmd_module(a):
    """oarbank module <list|show|install|verify|enable|canary|promote|rollback|disable|pin|unpin|uninstall>."""
    ask = dict(reason=a.reason, yes=a.yes, dry_run=a.dry_run)
    if a.action == "list":
        s = api("GET", "/api/v1/modules/store")
        for name, ch in sorted(s["channels"].items()):
            flags = " DISABLED" if ch["disabled"] else ""
            canary = f"  canary {ch['canary']} on {', '.join(ch['canary_nodes'])}" if ch["canary"] else ""
            print(f"{name:<14} current {ch['current'] or '-':<8} previous {ch['previous'] or '-':<8}{canary}{flags}")
        for r in s["installed"]:
            print(f"  {r['name']}@{r['version']:<8} {r['content_digest'][:19]}…  installed by {r['installed_by']}")
        for p in s["pins"]:
            print(f"  pin {p['name']}@{p['version']} on {p['node_id']}")
        return
    if a.action == "show":
        m = next((m for m in api("GET", "/api/v1/modules") if m["name"] == a.what), None)
        if m is None:
            sys.exit(f"no enabled or current module {a.what!r} (oarbank module list)")
        print(f"{m['name']}  {m['id']} {m['version']}  {'enabled' if m['enabled'] else 'disabled'}  stages {', '.join(m['stages'])}")
        if m["coordinator_unsupported"]:
            print(f"  this coordinator cannot run it: {m['coordinator_unsupported']}")
        print(f"  {'platform':<16} {'runner':<6} {'coordinator':<11} nodes certified")
        for p in m["platforms"]:
            why = "; ".join(x for x in (p["runner_reason"], p["coordinator_reason"]) if x)
            print(f"  {p['platform'] + (' *' if p['here'] else ''):<16} {'yes' if p['runner'] else 'no':<6} "
                  f"{'yes' if p['coordinator'] else 'no':<11} {p['nodes']:>5} {p['certified']:>9}" + (f"  {why}" if why else ""))
        print("  * this coordinator's platform")
        return
    if a.action == "install":
        data = Path(a.what).read_bytes()
        r = http_request("POST", f"{URL}/api/v1/modules/bundles", content=data, headers={"x-oarbank-source": "cli", **auth_headers()}, timeout=600)
        if r.status_code >= 400:
            sys.exit(f"upload: {r.status_code} {r.text}")
        res = run_op("modules.install", None, {"sha256": r.json()["sha256"]}, **ask)
    elif a.action == "verify":
        res = run_op("modules.verify", a.what, **ask)
    elif a.action == "check":
        res = run_op("modules.check", a.what, {"deep": True} if a.deep else {}, **ask)
        for name, c in ((res.get("result") or {}).get("modules") or {}).items():
            print(f"{name:<14} {'ok' if c['ok'] else 'FAILED'}  fingerprint {(c.get('fingerprint') or '-')[:16]}")
            for x in c["checks"]:
                print(f"  {'✓' if x['ok'] else '✗'} {x['name']}" + (f": {x['detail']}" if x.get("detail") else ""))
        sys.exit(0 if (res.get("result") or {}).get("ok") else 1)
    elif a.action == "canary":
        if not a.node:
            sys.exit("oarbank module canary <name>@<version> --node N [--node M]")
        res = run_op("modules.enable_canary", a.what, {"nodes": a.node}, **ask)
    elif a.action in ("pin", "unpin"):
        if not a.node or len(a.node) != 1:
            sys.exit(f"oarbank module {a.action} <name>@<version> --node N")
        res = run_op("modules.pin", a.what, {"node": a.node[0], **({"clear": True} if a.action == "unpin" else {})}, **ask)
    else:
        res = run_op(f"modules.{a.action}", a.what, **ask)
    print(json.dumps(res, indent=1, default=str))


def _duration(s: str) -> int:
    s = s.strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return int(float(s[:-1]) * mult[s[-1]]) if s and s[-1] in mult else int(s)


def cmd_coordinator(a):
    """oarbank coordinator <status|prepare|move|cancel|finalize>: move the coordinator to another machine (no ssh)."""
    ask = dict(reason=a.reason, yes=a.yes, dry_run=a.dry_run, confirm=a.confirm)
    if a.action == "status":
        s = api("GET", "/api/v1/coordinator")
        print(f"role {s['role']}  epoch {s['epoch']}  phase {s['phase']}  fleet {s['fleet_id']}  key {s['cik_fingerprint'][:16]}")
        if s.get("plan"):
            p = s["plan"]
            print(f"plan {p['plan_id']} -> {p.get('target_url')} ({p['state']})")
        if s.get("move"):
            m = s["move"]
            nb = time.strftime("%Y-%m-%d %H:%M", time.localtime(m["not_before"])) if m.get("not_before") else "-"
            print(f"move {m['move_id']} epoch {m['epoch']} {m['state']}  not before {nb}")
        for n in s["agents"]:
            mv = n.get("move") or {}
            print(f"  {n['hostname']:<22} {mv.get('state') or '-':<12} {(mv.get('error') or '')[:80]}")
        return
    if a.action == "prepare":
        if not a.to:
            sys.exit("oarbank coordinator prepare --to <enrolled node | http://host:port>")
        res = run_op("coordinator.prepare", a.to, {}, **{**ask, "confirm": a.confirm or a.to})
    elif a.action == "move":
        params = {"timelock_s": _duration(a.timelock)} if a.timelock else {}
        if a.force:
            params["force"] = True
        res = run_op("coordinator.move", None, params, **{**ask, "confirm": a.confirm or "move"})
        st = (res.get("result") or {}).get("state")
        if st == "awaiting_owner" and a.owner_key:
            res = _sign_move(a, ask)
        elif st == "awaiting_owner":
            print("this fleet requires the owner's signature: oarbank coordinator sign --owner-key <key>")
    elif a.action == "sign":
        res = _sign_move(a, ask)
    else:
        res = run_op(f"coordinator.{a.action}", None, {}, **ask)
    print(json.dumps(res, indent=1, default=str))


def _sign_move(a, ask):
    from .. import signing
    s = api("GET", "/api/v1/coordinator")
    if not s.get("move") or s["move"]["state"] != "awaiting_owner":
        sys.exit("no move is waiting for the owner's signature")
    stmt = api("GET", "/api/v1/coordinator/statement")["statement"]
    print(json.dumps(json.loads(stmt), indent=1))
    sig = signing.sign(stmt, Path(a.owner_key) if a.owner_key else signing.DEFAULT_KEY)
    return run_op("coordinator.sign_move", None, {"owner_sig": sig}, **ask)


def cmd_owner(a):
    """oarbank owner <show|set|disable|rescue-move>: the owner key set in signing mode (coordinator-move.md)."""
    from .. import signing
    ask = dict(reason=a.reason, yes=a.yes, dry_run=a.dry_run)
    if a.action == "rescue-move":
        # where the owner keys are, offline: the new coordinator's request names everything the move needs
        if not a.request or not a.out:
            sys.exit("oarbank owner rescue-move --request rescue-request.json --out move.json [--key KEY] [--to-stable-id ID]")
        stmt = signing.rescue_move_statement(json.loads(Path(a.request).read_text()), a.to_stable_id)
        f = Path(a.key) if a.key else signing.DEFAULT_KEY
        Path(a.out).write_text(json.dumps({"coordinator_move": {"statement": stmt, "signatures": {"owner": signing.sign(stmt, f)}}},
                                          indent=1) + "\n")
        print(f"wrote {a.out}: on the new coordinator, python -m oarbank.coordinator.rescue sign {a.out}; then publish it at"
              f" a rescue location of the owner key set")
        return
    s = api("GET", "/api/v1/coordinator")
    if a.action == "show":
        print(json.dumps(api("GET", "/api/v1/owner"), indent=1))
        return
    cur = api("GET", "/api/v1/owner")
    version = (cur.get("version") or 0) + 1
    if a.action == "set":
        if not a.key or not a.backup_key:
            sys.exit("oarbank owner set --key <primary key file> --backup-key <backup key file> [--old-key <current key file>] [--rescue URL ...]")
        files = [Path(a.key), Path(a.backup_key)]
        for f in files:
            if not f.exists():
                print(f"creating {f}"); signing.keygen(f)
        pubs = [signing.public_key_of(f) for f in files]
        stmt = signing.owner_anchors_statement(s["fleet_id"], version, pubs, a.rescue or [])
        sigs = [{"key": signing.public_key_of(f), "sig": signing.sign(stmt, f)} for f in files]
        if a.old_key and signing.public_key_of(Path(a.old_key)) not in pubs:
            sigs.append({"key": signing.public_key_of(Path(a.old_key)), "sig": signing.sign(stmt, Path(a.old_key))})
        res = run_op("owner.set_anchors", None, {"statement": stmt, "signatures": sigs}, **ask, confirm="owner-keys")
        print("keep the backup key offline (another device, or printed); it recovers a lost primary with no node touched")
    else:
        stmt = signing.owner_disable_statement(s["fleet_id"], version)
        f = Path(a.key) if a.key else signing.DEFAULT_KEY
        res = run_op("owner.disable_signing", None, {"statement": stmt, "signatures": [{"key": signing.public_key_of(f),
                                                                                       "sig": signing.sign(stmt, f)}]},
                     **ask, confirm="disable-signing")
    print(json.dumps(res, indent=1, default=str))


def cmd_agent(a):
    """oarbank agent <list|upload|canary|promote|rollback|sign>: agent self-update through oarbankd (no ssh)."""
    ask = dict(reason=a.reason, yes=a.yes, dry_run=a.dry_run)
    if a.action == "list":
        v = api("GET", "/api/v1/agent/builds")
        ver = {b["sha256"]: b["version"] for b in v["builds"]}
        name = lambda s: f"{ver.get(s, '?')} ({s[:12]})" if s else "-"
        for plat, ch in sorted(v["channels"].items()):
            print(f"{plat:<14} current {name(ch['current'])}  previous {name(ch['previous'])}"
                  + (f"  canary {name(ch['canary'])} on {', '.join(ch['canary_nodes'])}" if ch["canary"] else ""))
        for b in v["builds"]:
            signed = f"  signed seq {b['seq']}" if b.get("signature") else ""
            print(f"  {b['version']:<10} {b['sha256'][:12]}  {', '.join(b['platforms']):<28} {b['size'] // 1024} KB  by {b['uploaded_by']}{signed}")
        for n in v["nodes"]:
            u = n["update"]
            state = "up to date" if n["up_to_date"] else f"-> {name(n['assigned'])}: {u.get('state') or 'pending'}"
            err = f" ({u['error'][:80]})" if u.get("error") and not n["up_to_date"] else ""
            print(f"  {n['hostname']:<22} runs {n['agent_version'] or '?':<8} {(n['agent_build'] or '')[:12]:<12}  {state}{err}")
        for plat, rd in sorted((v.get("readiness") or {}).items()):
            print(f"promote {plat} ready: {rd['ready']}  {rd['canary_nodes']}")
        return
    if a.action == "upload":
        if not a.what:
            sys.exit("oarbank agent upload <path to an oarbank-agent binary>")
        r = http_request("POST", f"{URL}/api/v1/agent/builds", content=Path(a.what).read_bytes(), headers={"x-oarbank-source": "cli", **auth_headers()}, timeout=600)
        if r.status_code >= 400:
            sys.exit(f"upload: {r.status_code} {r.text}")
        res = run_op("agent.upload", None, {"sha256": r.json()["sha256"]}, **ask)
    elif a.action == "canary":
        if not a.what or not a.node:
            sys.exit("oarbank agent canary <build: sha256, prefix or version> --node N [--node M]")
        res = run_op("agent.canary", a.what, {"nodes": a.node}, **ask)
    elif a.action == "sign":
        if not a.what:
            sys.exit("oarbank agent sign <build> [--key PATH] [--seq N]")
        if not api("GET", "/api/v1/features")["release_signing"]:
            sys.exit("release signing is off in this oarbankd (OARBANK_RELEASE_SIGNING=0, developer mode)")
        from .. import signing
        v = api("GET", "/api/v1/agent/builds")
        hit = [b for b in v["builds"] if b["sha256"].startswith(a.what) or b["version"] == a.what]
        if len(hit) != 1:
            sys.exit(f"{a.what!r} names {len(hit)} agent builds")
        b = hit[0]
        seq = a.seq or 1 + max([x.get("seq") or 0 for x in v["builds"]] + [0])
        stmt = signing.agent_statement(b["sha256"], b["version"], seq, b["platforms"])
        sig = signing.sign(stmt, Path(a.key) if a.key else signing.DEFAULT_KEY)
        res = run_op("agent.sign", b["sha256"], {"statement": stmt, "signature": sig}, **ask)
    else:
        res = run_op(f"agent.{a.action}", a.what, {"platform": a.platform} if a.platform else None, **ask)
    print(json.dumps(res, indent=1, default=str))


def cmd_account(a):
    """oarbank account <list|create|disable|enable|role|reset-totp|password>: console accounts (access.py)."""
    ask = dict(reason=a.reason, yes=a.yes, dry_run=a.dry_run)
    if a.action == "list":
        v = api("GET", "/api/v1/access")
        for x in v["accounts"]:
            print(f"{x['name']:<20} {x['role']:<9} {'disabled' if x['disabled'] else 'enabled'}")
        for t in v["tokens"]:
            print(f"  token {t['token_id']} {t['account']:<16} {t['role']:<9} {t['label'] or ''}{'  revoked' if t['revoked'] else ''}")
        for k in v["passkeys"]:
            print(f"  passkey {k['credential_id'][:16]} {k['account']:<16} {k['label']} ({k['rp_id']})")
        return
    if not a.name:
        sys.exit(f"oarbank account {a.action} <name>")
    import getpass
    if a.action == "create":
        pw = getpass.getpass("password (empty: sign in only with a link or a passkey): ") if a.password else None
        res = run_op("access.accounts.create", a.name, {"role": a.role or "admin", **({"password": pw} if pw else {})}, **ask)
        r = (res or {}).get("result") or {}
        if r.get("totp_secret"):
            print(f"account {r['account']} ({r['role']}). Add this to an authenticator app now; it is not shown again:\n"
                  f"  secret {r['totp_secret']}\n  {r['otpauth']}\nSign in: oarbank console login --account {r['account']}")
        return
    if a.action in ("disable", "enable"):
        res = run_op("access.accounts.update", a.name, {"disabled": a.action == "disable"}, **ask)
    elif a.action == "role":
        res = run_op("access.accounts.update", a.name, {"role": a.role}, **ask)
    elif a.action == "reset-totp":
        res = run_op("access.accounts.reset_totp", a.name, **ask)
    else:
        pw = getpass.getpass("new password: ")
        res = run_op("access.accounts.set_password", a.name, {"password": pw}, **ask)
    print(json.dumps((res or {}).get("result") or res, indent=1, default=str))


def cmd_token(a):
    """oarbank token <create|revoke>: personal access tokens for scripts (OARBANK_TOKEN)."""
    ask = dict(reason=a.reason, yes=a.yes, dry_run=a.dry_run)
    if a.action == "create":
        res = run_op("access.tokens.create", a.account, {"label": a.label or "", "role": a.role or "viewer",
                                                         "days": a.days}, **ask)
        r = (res or {}).get("result") or {}
        if r.get("token"):
            print(f"{r['token']}\n(shown once; {r['role']}, expires in {a.days:g} days; use it as OARBANK_TOKEN)")
        return
    if not a.id:
        sys.exit("oarbank token revoke <token id>")
    print(json.dumps(run_op("access.tokens.revoke", a.id, **ask), indent=1, default=str))


def cmd_console(a):
    """oarbank console login: a one-time sign-in link to the console (valid 2 minutes)."""
    res = run_op("access.login_link", a.account, {"console": a.console} if a.console else None, yes=True)
    r = (res or {}).get("result") or {}
    print(r.get("url") or json.dumps(res, indent=1))
    if a.open and r.get("url"):
        import webbrowser
        webbrowser.open(r["url"])


def cmd_coordinator_build(a):
    """oarbank coordinator-build <list|upload|sign>: coordinator builds a move installs (signed, per platform)."""
    ask = dict(reason=a.reason, yes=a.yes, dry_run=a.dry_run)
    if a.action == "list":
        v = api("GET", "/api/v1/coordinator/builds")
        for b in v["builds"]:
            print(f"{b['version']:<10} {b['platform']:<14} {b['sha256'][:12]}  {'signed seq ' + str(b['seq']) if b.get('signature') else 'unsigned'}")
        print(f"signing: {'on' if v['signing'] else 'off (developer mode: a move bundles the running checkout)'}")
        return
    if not a.what:
        sys.exit(f"oarbank coordinator-build {a.action} <{'archive' if a.action == 'upload' else 'build sha256 prefix'}>")
    if a.action == "upload":
        r = http_request("POST", f"{URL}/api/v1/coordinator/builds", content=Path(a.what).read_bytes(),
                       headers={"x-oarbank-source": "cli", **auth_headers()}, timeout=600)
        if r.status_code >= 400:
            sys.exit(f"upload: {r.status_code} {r.text}")
        res = run_op("coordinator.builds.upload", None, {"sha256": r.json()["sha256"]}, **ask)
    else:
        from .. import signing
        v = api("GET", "/api/v1/coordinator/builds")
        hit = [b for b in v["builds"] if b["sha256"].startswith(a.what)]
        if len(hit) != 1:
            sys.exit(f"{a.what!r} names {len(hit)} coordinator builds")
        b = hit[0]
        seq = a.seq or 1 + max([x.get("seq") or 0 for x in v["builds"]] + [0])
        stmt = signing.coordinator_statement(b["sha256"], b["version"], b["platform"], seq)
        sig = signing.sign(stmt, Path(a.key) if a.key else signing.DEFAULT_KEY)
        res = run_op("coordinator.builds.sign", b["sha256"], {"statement": stmt, "signature": sig}, **ask)
    print(json.dumps(res, indent=1, default=str))


def cmd_vendor_metadata(a):
    """oarbank vendor-metadata upload <dir>: mirror the vendor's TUF metadata (root, N.root, timestamp, snapshot,
    targets) for agents, which verify agent builds against the vendor root compiled into them."""
    d = Path(a.dir)
    files = {p.name: p.read_text() for p in sorted(d.glob("*.json"))}
    if not files:
        sys.exit(f"no .json metadata in {d}")
    res = run_op("vendor.metadata.upload", None, {"files": files}, a.reason, a.yes)
    print(json.dumps(res, indent=1, default=str))


def cmd_join_code(a):
    """oarbank join-code: a one-time code that enrolls (and approves) a new machine: oarbank-agent run --join <code>."""
    res = run_op("nodes.join_code", None, {"label": a.label or "", "ttl_s": a.ttl}, a.reason, a.yes)
    r = (res or {}).get("result") or {}
    if r.get("code"):
        print(f"{r['command']}\n(single use; expires in {a.ttl / 60:.0f} min)")


def cmd_alerts(a):
    """oarbank alerts <list|ack|snooze|resolve|precision>."""
    if a.action == "list":
        for x in api("GET", f"/api/v1/alerts?state={a.state}"):
            print(f"#{x['alert_id']:<5} {x['severity']} {x['state']:<9} {x['rule']:<28} {x['detail'][:90]}")
        return
    if a.action == "precision":
        r = api("GET", f"/api/v1/alerts/precision?days={a.days}")
        print(f"precision over {r['days']:g} days (P4/P5 rules need >= 50 %):")
        for s in r["rules"]:
            p = "-" if s["precision"] is None else f"{s['precision']:.0%}"
            print(f"  {s['rule']:<28} {s['severity']} fired {s['fired']:>3}  useful {s['useful']:>3}  noise {s['not_useful']:>3}  "
                  f"unrated {s['unrated']:>3}  precision {p:>5}{'' if s['meets_bar'] else '  BELOW THE BAR'}")
        return
    params = {}
    if a.useful or a.noise:
        params["useful"] = bool(a.useful)
    if a.action == "snooze":
        params["minutes"] = a.minutes
    print(json.dumps(run_op(f"alerts.{a.action}", a.id, params, a.reason, yes=True), indent=1, default=str))


def print_explain(d: dict, kind: str, ident) -> None:
    from ..contracts import operations as registry
    print(f"{kind} {ident}: {d['verdict']} - {d['headline']['text']} [{d['headline']['code']}]")
    for x in d.get("system_actions") or []:
        print(f"  {x}")
    for s in d.get("summary") or []:
        print(f"  {s['code']:<24} {', '.join(s.get('nodes') or [])} {json.dumps(s.get('detail') or {}) if s.get('detail') else ''}")
    for row in d.get("matrix") or []:
        bad = [r for r in row["results"] if r["outcome"] != "pass"]
        print(f"  {row['node']:<16} " + ("eligible" if not bad else
              "; ".join(f"{r['predicate']} ({r['observed']} vs {r['required']}) {r['code']}" for r in bad[:3])))
    for r in d.get("remedies") or []:
        print(f"  remedy: {r['label']}: {registry.command(r['op'], r.get('target'))}")


def cmd_explain(a):
    d = api("GET", f"/api/v1/explain/{a.kind}/{a.id}")
    if a.json:
        print(json.dumps(d, indent=1))
        return
    print_explain(d, a.kind, a.id)


def cmd_audit(a):
    if a.action == "verify":
        params = {}
        if a.against:          # an off-host copy of the digests (audit/digests.jsonl from another machine)
            params["digests"] = [json.loads(l) for l in Path(a.against).read_text().splitlines() if l.strip()]
        r = run_op("audit.verify", "audit", params, yes=True)["result"]
        print(json.dumps(r, indent=1))
        sys.exit(0 if r["ok"] else 1)
    q = f"/api/v1/audit?limit={a.limit}" + (f"&op={a.op}" if a.op else "") + (f"&target={a.target}" if a.target else "")
    for r in reversed(api("GET", q)):
        print(f"{time.strftime('%m-%d %H:%M:%S', time.localtime(r['ts']))} #{r['event_id']:<6} {r['actor']:<22} "
              f"{r['source']:<4} {r['operation']:<30} {r['target_type']}:{r['target_id']:<14} {r['outcome']:<9} "
              f"{r['reason'] or ''}")


def cmd_fleet(a):
    d = api("GET", "/api/v1/fleet")
    for n in d["nodes"]:
        cap, tel, lim = n["cap"], n["tel"], n["limits"]
        caps = ",".join(f"{k}={v}" for k, v in lim.items() if k != "enforce") or "none"
        mods = ",".join(f"{m}:{st.get('state')}" for m, st in (n.get("mods") or {}).items()) or "-"
        g = (n.get("doctor") or {}).get("gpu_apis") or {}
        gpu = f"gpu {','.join(g.get('host') or []) or '-'} containers {','.join(g.get('containers') or []) or '-'}"
        ct = (n.get("facts") or {}).get("containers") or {}
        runtime = f" runtime {ct['runtime']} {ct.get('state') or '?'}" if ct.get("runtime") else ""
        runtime += "".join(f" MISSING {m.get('what')}" for m in ct.get("missing") or [])
        print(f"{n['hostname']:<20} {n['node_id']:<11} {n['lifecycle']:<11} {n['desired_state']:<9} "
              f"{'online ' if n['online'] else 'OFFLINE'} jobs {n['live']}/{cap.get('cpu_slots', 0)} "
              f"(auto {cap.get('auto_cpu_slots')}, bind {cap.get('binding_limit')}) guard {tel.get('guard')} "
              f"protecting {','.join((tel.get('protection') or {}).get('active') or []) or '-'} "
              f"modules {mods} {gpu}{runtime} caps {caps}"
              + "".join(f" STOPPED {k} ({why})" for k, why in sorted((tel.get("services_held") or {}).items())))
    for e in d["enrollments"]:
        print(f"PENDING enrollment {e['enrollment_id']} from {e['hostname']} ({e['peer_ip']})  -> oarbank node approve {e['enrollment_id']}")
    for c in d["campaigns"]:
        j = c["jobs"]
        print(f"campaign {c['campaign_id']} {c['module']:<11} {c['name']:<30} {c['state']:<8} {j['d'] or 0}/{j['n']} done, "
              f"{j['l'] or 0} running")
    for al in d["alerts"]:
        print(f"ALERT {al['rule']}: {al['detail']}")


NODE_STATE_OPS = {"paused": "nodes.pause", "active": "nodes.resume", "draining": "nodes.drain"}
PROTECTION_MODES = ("fleet_first", "moderate", "strict_yield")


def _when(t) -> str:
    return time.strftime("%m-%d %H:%M", time.localtime(t)) if t else "-"


def cmd_node(a):
    if a.action == "confirm-identity":
        res = run_op("nodes.confirm_identity", a.target, {}, yes=True)
    elif a.action == "approve":
        res = run_op("nodes.admit", a.target, reason=a.reason, yes=a.yes)
    elif a.action == "reject":
        res = run_op("nodes.reject_enrollment", a.target, reason=a.reason, yes=a.yes)
    elif a.action == "mode":
        if a.value not in PROTECTION_MODES:
            sys.exit(f"oarbank node mode <node> {'|'.join(PROTECTION_MODES)}")
        res = run_op("nodes.set_mode", a.target, {"mode": a.value}, a.reason, a.yes)
    elif a.action == "state":
        if a.value not in NODE_STATE_OPS:
            sys.exit(f"oarbank node state <node> {'|'.join(NODE_STATE_OPS)}")
        res = run_op(NODE_STATE_OPS[a.value], a.target, reason=a.reason, yes=a.yes)
    elif a.action == "limits":
        if a.clear_all:
            res = run_op("nodes.set_caps", a.target, {"clear_all": True}, a.reason, a.yes)
        else:
            patch = {}
            for k in ("cpu_cores", "mem_gb", "jobs", "vm_mem_gb", "vm_cpus", "disk_gb", "staging_mbps"):
                v = getattr(a, k)
                if v is not None:
                    patch[k] = None if v in ("off", "none") else float(v)
            if a.enforce:
                patch["enforce"] = a.enforce
            res = run_op("nodes.set_caps", a.target, {"patch": patch}, a.reason, a.yes)
    else:
        patch = {}
        for kv in a.kv:
            k, _, v = kv.partition("=")
            try:
                patch[k] = json.loads(v)
            except json.JSONDecodeError:
                patch[k] = v
        res = run_op("nodes.set_policy", a.target, {"patch": patch}, a.reason, a.yes)
    print(json.dumps((res or {}).get("result"), indent=1, default=str))


def print_job(d: dict) -> None:
    """`oarbank job show`: the job page's facts (detail.job and its explain document, GET /api/v1/jobs/<id>)."""
    j = d["job"]
    print(f"job {j['job_id']} ({j['kind']}) {j['state']}  {j['module']}" + (f"/{j['stage']}" if j["stage"] else "")
          + (f"  campaign {j['campaign_id']}" if j["campaign_id"] else "")
          + (f"  dataset {j['dataset_id']}" if j["dataset_id"] else "")
          + f"  priority {j['priority'] or 0}  generation {j['generation']}  failures {j['exec_failures']}  "
            f"expirations {j['expirations']}" + (f"  target {j['target_node']}" if j["target_node"] else ""))
    print("attempts:" + ("" if d["attempts"] else " none yet"))
    for x in d["attempts"]:
        r = x["resume"]
        print(f"  #{x['attempt_id']:<6} {x['hostname'] or x['node_id']:<20} {x['state']:<9} {x['end_reason'] or x['phase'] or '':<16} "
              f"cpu {x['cpu_s'] or 0:.0f} s  granted {_when(x['granted_at'])}  ended {_when(x['ended_at'])}"
              + (f"  resumed from #{r['from_attempt']}'s checkpoint (written on {r['node_id']})" if r else ""))
    c = d["checkpoint"]
    if c:
        print(f"checkpoint: attempt {c['attempt_id']} on {c['node_id']}, {c['files']} files, {c['size'] / 1048576:.1f} MB, "
              f"digest {c['digest'][:12]}, {_when(c['at'])}: the next attempt resumes from it on any node")
    for x in d["results"]:
        print(f"result {x['result_id']}: attempt {x['attempt_id']} value {x['value']} "
              + ("canonical" if x["canonical"] else "accepted" if x["accepted"] else f"rejected ({x['reason']})"))
    print_explain(d["explain"], "job", j["job_id"])


def cmd_job(a):
    """oarbank job <show|retry|cancel> <id>."""
    if a.action == "show":
        d = api("GET", f"/api/v1/jobs/{a.id}")
        if a.json:
            print(json.dumps(d, indent=1, default=str))
        else:
            print_job(d)
        return
    res = run_op(f"jobs.{a.action}", a.id, None, a.reason, a.yes)
    print(json.dumps((res or {}).get("result"), indent=1, default=str))


def _protection_file(path: str) -> dict:
    """A protection section from a file: TOML (`.toml`, the local protection file's format) or JSON (the console's)."""
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith(".toml"):
        import tomllib
        return tomllib.loads(text)
    return json.loads(text)


def print_protection(d: dict) -> None:
    live, c = d["live"], d["canary"]
    print(f"protection on {d['hostname']} ({d['node_id']}): version {d['version']}, mode {d['mode']}")
    print(f"live: active {', '.join(live.get('active') or []) or 'none'}; rung {live.get('rung') or 0}"
          + (f"; budget {live['budget_cores']} cores" if live.get("budget_cores") is not None else "")
          + f"; guard {d['guard'] or 'not reported'}" + (f"; CONFIG ERROR {live['config_error']}" if live.get("config_error") else ""))
    state = {r.get("id"): r for r in live.get("rules") or []}
    print("rules:" + ("" if d["config"].get("rule") else " none (only the memory, thermal and battery guards apply)"))
    for r in d["config"].get("rule") or []:
        st = state.get(r.get("id")) or {}
        print(f"  {r.get('id'):<20} {'active' if st.get('active') else st.get('reason') or 'not reported':<14} "
              f"{st.get('processes', '-')} processes  match {json.dumps(r.get('match'))}")
    for x in d["conditions"]:
        print(f"  {x['code']}: {x['message']}")
    if c["canary"]:
        print(f"canary: {c['canary']['node_id']} version {c['canary']['version']}, soaked {c['soak_s']} s, "
              + ("promotable: oarbank protection promote" if c["promotable"] else f"not promotable: {'; '.join(c['why'])}"))
    print("versions:")
    for h in d["history"]:
        print(f"  {h['version']:<4} {_when(h['created_at'])}  {h['actor']:<14} {h['source']:<16} {','.join(h['rules']) or '-'}  "
              f"{h['mode']}  {h['reason'] or ''}")


def cmd_protection(a):
    """oarbank protection <show|set|preview|restore|canary|promote|probe>: a node's protected-process rules, as the
    console's protection page edits them (the mode: oarbank node mode)."""
    ask = dict(reason=a.reason, yes=a.yes)
    need = {"show": "<node>", "probe": "<node>", "set": "<node> <file>", "preview": "<node> <file>", "canary": "<node> <file>",
            "restore": "<node> <version>"}
    if a.action in need and (not a.node or need[a.action].count("<") == 2 and not a.value):
        sys.exit(f"oarbank protection {a.action} {need[a.action]}")
    if a.action == "show":
        d = api("GET", f"/api/v1/nodes/{a.node}/protection")
        if a.json:
            print(json.dumps(d, indent=1, default=str))
        else:
            print_protection(d)
        return
    if a.action in ("set", "preview"):
        res = run_op("protection.rules.update", a.node, {"config": _protection_file(a.value)}, dry_run=a.action == "preview", **ask)
    elif a.action == "canary":
        res = run_op("protection.rules.canary", a.node, {"config": _protection_file(a.value)}, **ask)
    elif a.action == "promote":
        res = run_op("protection.rules.canary", None, {"promote": True, **({"force": True} if a.force else {})}, **ask)
    elif a.action == "restore":
        res = run_op("protection.rules.restore", a.node, {"version": int(a.value)}, **ask)
    else:
        res = run_op("protection.probe_now", a.node, None, **ask)
    print(json.dumps((res or {}).get("result"), indent=1, default=str))


def cmd_verify(a):
    """Protocol invariants (S1-S11) + operational health of the live fleet; exit 1 on a violation
    (and on warnings with --strict), so it can gate deploys or run from cron/launchd."""
    r = api("GET", "/api/v1/verify")
    print(("OK" if r["ok"] else "VIOLATIONS") + f"  jobs {r['jobs']}  ({len(r['checked'])} invariants checked)")
    for v in r["violations"]:
        print("  VIOLATION", v)
    for w in r["warnings"]:
        print("  warning  ", w)
    real = [w for w in r["warnings"] if not w.startswith("info:")]
    sys.exit(0 if r["ok"] and not (a.strict and real) else 1)


def cmd_release(a):
    if a.action in ("keygen", "sign") and not api("GET", "/api/v1/features")["release_signing"]:
        sys.exit("release signing is off in this oarbankd (OARBANK_RELEASE_SIGNING=0, developer mode)")
    ask = dict(reason=a.reason, yes=a.yes)
    if a.action in ("keygen", "sign") or a.key:
        from .. import signing
        key = Path(a.key) if a.key else signing.DEFAULT_KEY
    else:
        key = None
    if a.action == "build":
        out = run_op("releases.build", None, **ask)["result"]
        print(json.dumps(out, indent=1))
        if out.get("needs_signature"):
            from .. import signing
            key = key or signing.DEFAULT_KEY
        if out.get("needs_signature") and key.exists():
            a.target, a.promote = out["release_id"], True
            a.action = "sign"
        else:
            return
    if a.action == "keygen":
        pub = signing.keygen(key, overwrite=a.rotate)
        run_op("releases.pin_key", "release-key", {"pubkey": pub, "rotate": a.rotate}, confirm="release-key", **ask)
        print(f"signing key: {key} (0600; keep a backup offline)\npublic key pinned in oarbankd: {pub}")
        print("agents pin it on their next heartbeat; from then on they refuse unsigned or rolled-back releases")
    elif a.action == "sign":
        rels = {r["release_id"]: r for r in api("GET", "/api/v1/releases")}
        r = rels.get(a.target) or sys.exit(f"unknown release {a.target}")
        seq = max([x["seq"] or 0 for x in rels.values() if x["signed"]] + [0]) + 1
        if r["signed"] and r["seq"]:
            seq = max(seq, r["seq"] + 1)
        stmt = signing.statement(r["release_id"], r["sha256"], seq)
        print(json.dumps(run_op("releases.attach_signature", r["release_id"],
                                {"statement": stmt, "signature": signing.sign(stmt, key)}, **ask), indent=1, default=str))
        if a.promote:
            print(json.dumps(run_op("releases.promote", r["release_id"], **ask), indent=1, default=str))
    elif a.action == "promote":
        print(json.dumps(run_op("releases.promote", a.target, **ask), indent=1, default=str))
    elif a.action == "list":
        for r in api("GET", "/api/v1/releases"):
            print(f"{r['release_id']:<16} {r['status']:<9} seq={r['seq'] or '-':<4} {'signed' if r['signed'] else 'UNSIGNED'} "
                  f"{time.strftime('%m-%d %H:%M', time.localtime(r['created_at']))}")


def cmd_campaign(a):
    if a.action == "list":
        for c in api("GET", "/api/v1/campaigns" + (f"?module={a.module}" if a.module else "")):
            j = c["jobs"]
            print(f"{c['campaign_id']:<14} {c['module']:<12} {c['state']:<9} p{c['priority']:<3} w{c['weight']:<4} "
                  f"{j['d']}/{j['n']} done {j['l']} running {j['f']} failed  {c['name']}")
        return
    if a.action == "show":
        c = api("GET", f"/api/v1/campaigns/{a.id}")
        p = c.get("placement")
        print("placement: " + (f"{p['mix']} per {p['unit']}, bind {p['bind']}, rebind {p['rebind']}"
                               + (f"; bound to {p['class']} ({p['state']})" if p.get("class") else
                                  f"; units {', '.join(f'{n} {s}' for s, n in sorted(p['units'].items())) or 'none yet'}")
                               + (f"; stranded: {', '.join(p['stranded'])}" if p.get("stranded") else "")
                               if p else "any (no unit of work is kept on one platform)"))
        print(json.dumps(c, indent=1, default=str))
        return
    if a.action == "download":
        from . import transfer
        sys.exit(1 if transfer.download_campaign(a.id, Path(a.value or f"{a.id}-artifacts")) else 0)
    if a.action == "rebind" and not a.platform or a.action == "placement" and not a.mix:
        sys.exit(f"oarbank campaign {a.action} <id> " + ("--platform <token>" if a.action == "rebind" else "--mix <mix>"))
    op = {"pause": "campaigns.pause", "resume": "campaigns.resume", "cancel": "campaigns.cancel",
          "retry-failed": "campaigns.retry_failed", "weight": "campaigns.set_weight", "priority": "campaigns.set_priority",
          "rebind": "campaigns.rebind_platform", "placement": "campaigns.set_placement"}[a.action]
    params = {"weight": float(a.value)} if a.action == "weight" else {"priority": int(a.value)} if a.action == "priority" else \
        {"platform": a.platform} if a.action == "rebind" else {"mix": a.mix} if a.action == "placement" else {}
    print(json.dumps(run_op(op, a.id, params, a.reason, a.yes, a.confirm), indent=1, default=str))


def cmd_dataset(a):
    """oarbank dataset <upload|download|list|show|register>: files in and out (cli/transfer.py)."""
    from . import transfer
    if a.action == "upload":
        if not a.what or not a.kind:
            sys.exit("oarbank dataset upload <dir> --kind <kind> [--id ID] [--module NAME] [--meta k=v]")
        if not Path(a.what).is_dir():
            sys.exit(f"{a.what} is not a directory")
        print(json.dumps(transfer.upload(Path(a.what), a.kind, a.id, a.module, _kv(a.meta)), indent=1, default=str))
    elif a.action == "download":
        if not a.what:
            sys.exit("oarbank dataset download <dataset id> [dir]")
        sys.exit(1 if transfer.download_dataset(a.what, Path(a.dest or a.what.replace(":", "_"))) else 0)
    elif a.action == "show":
        print(json.dumps(api("GET", f"/api/v1/datasets/{a.what}"), indent=1, default=str))
    elif a.action == "register":
        print(json.dumps(run_op("datasets.register", None, json.loads(Path(a.what).read_text()), yes=True), indent=1, default=str))
    else:
        print(json.dumps(api("GET", "/api/v1/datasets" + (f"?kind={a.kind}" if a.kind else "")), indent=1, default=str))


def cmd_folders(a):
    """oarbank folders <list|map|sign>: the folder registry (modules ask for folders by id; the operator maps each to a
    path per node) and, in signing mode, the owner's signature on each node's folder statement."""
    if a.action == "list":
        v = api("GET", "/api/v1/folders")
        for fid, e in sorted(v["registry"].items()):
            for nid, path in e["nodes"].items():
                n = v["nodes"].get(nid, {})
                st = (n.get("folders") or {}).get(fid) or {}
                stmt = v["statements"].get(nid) or {}
                print(f"{fid:<16} {e['access']:<6} {n.get('hostname', nid):<20} {path}  "
                      f"{st.get('status', 'not applied yet')}{'  (statement unsigned)' if v['signing'] and not stmt.get('signature') else ''}")
        return
    if a.action == "map":
        if not a.what or a.access not in ("read", "write"):
            sys.exit("oarbank folders map <id> --access read|write --node <node>=<path> [--node ...]")
        nodes = {k: v or None for k, _, v in (x.partition("=") for x in a.node or [])}
        res = run_op("settings.folders.update", a.what, {"access": a.access, "nodes": nodes}, a.reason, a.yes)
    else:
        if not a.what:
            sys.exit("oarbank folders sign <node> [--key PATH]")
        from .. import signing
        stmt = (api("GET", "/api/v1/folders")["statements"].get(a.what) or {}).get("statement")
        if not stmt:
            sys.exit(f"{a.what} has no folder statement")
        sig = signing.sign(stmt, Path(a.key) if a.key else signing.DEFAULT_KEY)
        res = run_op("folders.sign", a.what, {"statement": stmt, "signature": sig}, a.reason, True)
    print(json.dumps(res, indent=1, default=str))


def cmd_mod(a):
    """A module's own operation: mod.<module>.<verb> (see `oarbank ops`)."""
    raw = (Path(a.json).read_text() if Path(a.json).exists() else a.json) if a.json else "{}"
    params = {**_kv(a.param), **json.loads(raw)}
    print(json.dumps(run_op(f"mod.{a.module.replace('-', '_')}.{a.verb}", a.target, params, a.reason, a.yes, a.confirm, dry_run=a.dry_run),
                     indent=1, default=str))


def cli_env(tmp: Path, port: int, token: str, module: str) -> dict:
    """The whole environment of a module CLI: nothing inherited but the locale and terminal."""
    from oarbank_sdk import portable
    return {"PATH": "/usr/bin:/bin", "HOME": str(tmp), "TMPDIR": str(tmp) + "/", "LANG": os.environ.get("LANG", "C.UTF-8"),
            "OARBANKD_URL": f"http://127.0.0.1:{port}", "OARBANK_TOKEN": token, "OARBANK_MODULE": module,
            "OARBANK_PLATFORM": portable.host_platform(), "PYTHONUTF8": "1", "TERM": os.environ.get("TERM", "dumb")}


def cmd_cli(a):
    """oarbank cli <module> [args...]: run a module's own CLI ([cli] in its manifest) on the coordinator, sandboxed: its
    bundle read-only, a scratch directory writable, and only the admin API reachable, with a one-hour token scoped to
    that module's operations."""
    import shutil
    import subprocess
    import tempfile
    from oarbank_sdk import manifest as mf, sandbox as S
    from ..coordinator import modsandbox
    from ..coordinator.modulehost import module_python
    info = api("GET", f"/api/v1/modules/{a.module}/cli")
    bundle = Path(info["bundle"])
    if not bundle.is_dir():
        sys.exit(f"{a.module}'s bundle is not on this machine: run `oarbank cli` on the coordinator")
    res = run_op("modules.cli_token", a.module, yes=True, out=lambda *x, **k: None)
    tok = ((res or {}).get("result") or {}).get("token")
    if not tok:
        sys.exit(f"no token: {res}")
    from urllib.parse import urlsplit
    u = urlsplit(URL)
    if u.hostname not in ("127.0.0.1", "localhost", "::1"):
        sys.exit("run `oarbank cli` on the coordinator itself (OARBANKD_URL must be its loopback admin API)")
    port = u.port or 80
    py = module_python(bundle)
    argv = mf.resolve_exec(info["exec"], bundle, py) + list(a.args)
    tmp = Path(tempfile.mkdtemp(prefix=f"oarbank-cli-{a.module}-"))
    env = cli_env(tmp, port, tok, a.module)
    try:
        if modsandbox.backend() is None:
            sys.exit("no module sandbox backend on this OS: a module CLI does not run unconfined")
        pol = S.Policy(module=info["module_id"], ro=[str(bundle), *S.interpreter_roots(), py], rw=[str(tmp)],
                       net="egress-allowlist", proxy_port=port, kind="cli", exe=py)
        from ..coordinator import sandboxexec
        argv = sandboxexec.wrap(pol, tmp / "cli.sb", argv)
        sys.exit(subprocess.run(argv, cwd=str(bundle), env=env).returncode)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    """Every `oarbank` command (the parity report checks the registry's CLI commands against it)."""
    from ..paths import release_key
    key = release_key()
    ap = argparse.ArgumentParser(prog="oarbank")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fleet").set_defaults(fn=cmd_fleet)
    n = sub.add_parser("node", help="a node: approve, reject, state, mode, limits, policy, confirm-identity")
    n.add_argument("action", choices=["approve", "reject", "state", "mode", "limits", "policy", "confirm-identity"])
    n.add_argument("target")
    n.add_argument("value", nargs="?", help="state: active|paused|draining; mode: " + "|".join(PROTECTION_MODES))
    n.add_argument("kv", nargs="*")
    for k in ("cpu_cores", "mem_gb", "jobs", "vm_mem_gb", "vm_cpus", "disk_gb", "staging_mbps"):
        n.add_argument("--" + k.replace("_", "-"), dest=k, help="number, or 'off' to remove this cap")
    n.add_argument("--enforce", choices=["soft", "hard"])
    n.add_argument("--clear-all", action="store_true", help="remove every cap")
    n.add_argument("--reason")
    n.add_argument("--yes", action="store_true")
    n.set_defaults(fn=cmd_node)
    jb = sub.add_parser("job", help="a job: show (attempts, checkpoint, results, why), retry, cancel")
    jb.add_argument("action", choices=["show", "retry", "cancel"])
    jb.add_argument("id")
    jb.add_argument("--json", action="store_true", help="show: the detail document as JSON")
    jb.add_argument("--reason")
    jb.add_argument("--yes", "-y", action="store_true")
    jb.set_defaults(fn=cmd_job)
    pr = sub.add_parser("protection", help="a node's protected-process rules: show, set, preview, restore, canary, promote, "
                                           "probe (the mode: oarbank node mode)")
    pr.add_argument("action", choices=["show", "set", "preview", "restore", "canary", "promote", "probe"])
    pr.add_argument("node", nargs="?", help="a node id or hostname (every action but promote)")
    pr.add_argument("value", nargs="?", help="set, preview, canary: a rules file (JSON, or TOML ending .toml); restore: a version")
    pr.add_argument("--force", action="store_true", help="promote: even when the canary is not promotable")
    pr.add_argument("--json", action="store_true", help="show: as JSON")
    pr.add_argument("--reason")
    pr.add_argument("--yes", "-y", action="store_true")
    pr.set_defaults(fn=cmd_protection)
    r = sub.add_parser("release", help="build / keygen / sign / promote / list release bundles")
    r.add_argument("action", nargs="?", default="build", choices=["build", "keygen", "sign", "promote", "list"])
    r.add_argument("target", nargs="?", help="release id (sign, promote)")
    r.add_argument("--key", help=f"signing key path (default {key})")
    r.add_argument("--promote", action="store_true", help="sign: also make it current")
    r.add_argument("--rotate", action="store_true", help="keygen: replace an existing key (agents must be re-keyed)")
    r.add_argument("--reason")
    r.add_argument("--yes", action="store_true")
    r.set_defaults(fn=cmd_release)
    cp = sub.add_parser("campaign", help="campaigns: every module's grouped work (list, show, pause, resume, cancel, download, ...)")
    cp.add_argument("action", choices=["list", "show", "pause", "resume", "cancel", "retry-failed", "weight", "priority",
                                       "rebind", "placement", "download"])
    cp.add_argument("id", nargs="?")
    cp.add_argument("value", nargs="?", help="weight/priority: the value; download: the directory (default <id>-artifacts)")
    cp.add_argument("--module")
    cp.add_argument("--platform", help="rebind: the platform token whose class the campaign's work moves to")
    cp.add_argument("--mix", help="placement: same-os, same-arch or same-platform (stricter only, before the first result)")
    cp.add_argument("--reason")
    cp.add_argument("--yes", "-y", action="store_true")
    cp.add_argument("--confirm")
    cp.set_defaults(fn=cmd_campaign)
    fo = sub.add_parser("folders", help="folders modules may read or write on nodes: list, map, sign (signing mode)")
    fo.add_argument("action", choices=["list", "map", "sign"])
    fo.add_argument("what", nargs="?", help="map: a folder id; sign: a node id")
    fo.add_argument("--access", choices=["read", "write"])
    fo.add_argument("--node", action="append", help="map: <node>=<path> (an empty path removes the node)")
    fo.add_argument("--key", help="sign: the owner's release key (default: the configured one)")
    fo.add_argument("--reason")
    fo.add_argument("--yes", "-y", action="store_true")
    fo.set_defaults(fn=cmd_folders)
    jc = sub.add_parser("join-code", help="a one-time join code for a new machine (it is approved when it enrolls)")
    jc.add_argument("--label", help="the new node's name; it keeps it whatever host name its agent reports "
                                    "(default: the name the agent reports)")
    jc.add_argument("--ttl", type=float, default=3600, help="seconds the code stays valid")
    jc.add_argument("--reason")
    jc.add_argument("--yes", action="store_true")
    jc.set_defaults(fn=cmd_join_code)
    mc = sub.add_parser("cli", help="run a module's own CLI on the coordinator, sandboxed: oarbank cli <module> [args...]")
    mc.add_argument("module")
    mc.add_argument("args", nargs=argparse.REMAINDER)
    mc.set_defaults(fn=cmd_cli)
    md = sub.add_parser("mod", help="run a module's own operation: oarbank mod <module> <verb> [target] -p k=v | --json FILE")
    md.add_argument("module")
    md.add_argument("verb")
    md.add_argument("target", nargs="?")
    md.add_argument("--param", "-p", action="append")
    md.add_argument("--json", help="params: a JSON object or a path to a JSON file")
    md.add_argument("--reason")
    md.add_argument("--yes", "-y", action="store_true")
    md.add_argument("--confirm")
    md.add_argument("--dry-run", action="store_true")
    md.set_defaults(fn=cmd_mod)
    ds = sub.add_parser("dataset", help="datasets: upload a folder, download one, list, show, or register from a JSON file")
    ds.add_argument("action", choices=["upload", "download", "list", "show", "register"])
    ds.add_argument("what", nargs="?", help="upload: a folder; download and show: a dataset id; register: a JSON file")
    ds.add_argument("dest", nargs="?", help="download: the directory to write into (default: the dataset id)")
    ds.add_argument("--kind")
    ds.add_argument("--id", help="upload: the dataset id (default: <kind>:<folder>-<digest>)")
    ds.add_argument("--module", help="upload: the module the dataset belongs to (its kinds; default: the operator's)")
    ds.add_argument("--meta", action="append", help="upload: key=value (JSON values allowed)")
    ds.set_defaults(fn=cmd_dataset)
    al = sub.add_parser("alerts", help="alerts: list, ack/snooze/resolve (with a useful/noise verdict), precision review")
    al.add_argument("action", choices=["list", "ack", "snooze", "resolve", "precision"])
    al.add_argument("id", nargs="?")
    al.add_argument("--state", default="open")
    al.add_argument("--days", type=float, default=7.0)
    al.add_argument("--minutes", type=float, default=60.0)
    al.add_argument("--useful", action="store_true")
    al.add_argument("--noise", action="store_true")
    al.add_argument("--reason")
    al.set_defaults(fn=cmd_alerts)
    mo = sub.add_parser("module", help="module lifecycle: install a bundle, enable, canary, promote, rollback, disable, pin")
    mo.add_argument("action", choices=["list", "show", "install", "verify", "check", "approve", "enable", "canary", "promote", "rollback", "disable",
                                       "pin", "unpin", "uninstall"])
    mo.add_argument("--deep", action="store_true", help="check: also re-hash every module file")
    mo.add_argument("what", nargs="?", help="a bundle file (install); <name>@<version> (canary, pin, uninstall, approve; enable "
                                            "takes either form); <name> or <name>@<its canary version> (promote); <name> "
                                            "(rollback, disable, verify, check, show: where it runs, per platform)")
    mo.add_argument("--node", action="append", help="canary or pin node (repeat for several canary nodes)")
    mo.add_argument("--reason")
    mo.add_argument("--yes", action="store_true")
    mo.add_argument("--dry-run", action="store_true")
    mo.set_defaults(fn=cmd_module)
    se = sub.add_parser("secret", help="module secrets, write-only: set (value from stdin or a no-echo prompt), clear, list")
    se.add_argument("action", choices=["set", "clear", "list"])
    se.add_argument("module")
    se.add_argument("name", nargs="?")
    se.add_argument("--node", help="a node's own value (hostname or id) instead of the module's")
    se.add_argument("--reason")
    se.add_argument("--yes", action="store_true")
    se.set_defaults(fn=cmd_secret)
    co = sub.add_parser("coordinator", help="move the coordinator to another machine: status, prepare, move, cancel, finalize")
    co.add_argument("action", choices=["status", "prepare", "move", "sign", "cancel", "finalize"])
    co.add_argument("--owner-key", help="move/sign: the owner key file that signs the move (signing mode)")
    co.add_argument("--to", help="prepare: an enrolled node (hostname or node id) or http://host:port of a standby")
    co.add_argument("--timelock", help="move: wait before the cutover (default 24h; at least 15m, with --reason)")
    co.add_argument("--reason")
    co.add_argument("--force", action="store_true", help="move: do not let module blockers or failed module checks stop the move")
    co.add_argument("--confirm", help="the T3 confirmation (defaults to the target, or 'move')")
    co.add_argument("--yes", action="store_true")
    co.add_argument("--dry-run", action="store_true")
    co.set_defaults(fn=cmd_coordinator)
    ow = sub.add_parser("owner", help="the owner key set (signing mode): show, set, disable, rescue-move")
    ow.add_argument("action", choices=["show", "set", "disable", "rescue-move"])
    ow.add_argument("--key", help=f"the primary owner key file (default {key})")
    ow.add_argument("--backup-key", help="set: the backup owner key file (created if missing; keep it offline)")
    ow.add_argument("--old-key", help="set: a key of the current set, when it is not in the new set")
    ow.add_argument("--rescue", action="append", help="set: a rescue location URL agents check when their coordinator is lost")
    ow.add_argument("--request", help="rescue-move: the new coordinator's rescue-request.json (rescue adopt)")
    ow.add_argument("--to-stable-id", help="rescue-move: the new coordinator's Tailscale stable node id (agents check it)")
    ow.add_argument("--out", help="rescue-move: the file to write")
    ow.add_argument("--reason"); ow.add_argument("--yes", action="store_true"); ow.add_argument("--dry-run", action="store_true")
    ow.set_defaults(fn=cmd_owner)
    vm = sub.add_parser("vendor-metadata", help="mirror the vendor's TUF metadata for agents: upload <dir>")
    vm.add_argument("action", choices=["upload"])
    vm.add_argument("dir")
    vm.add_argument("--reason")
    vm.add_argument("--yes", action="store_true")
    vm.set_defaults(fn=cmd_vendor_metadata)
    cb = sub.add_parser("coordinator-build", help="coordinator builds for moves: list, upload, sign (owner key)")
    cb.add_argument("action", choices=["list", "upload", "sign"])
    cb.add_argument("what", nargs="?")
    cb.add_argument("--key", help=f"sign: the owner key (default {key})")
    cb.add_argument("--seq", type=int)
    cb.add_argument("--reason")
    cb.add_argument("--yes", action="store_true")
    cb.add_argument("--dry-run", action="store_true")
    cb.set_defaults(fn=cmd_coordinator_build)
    ac = sub.add_parser("account", help="console accounts: list, create, disable, enable, role, reset-totp, password")
    ac.add_argument("action", choices=["list", "create", "disable", "enable", "role", "reset-totp", "password"])
    ac.add_argument("name", nargs="?")
    ac.add_argument("--role", choices=["admin", "operator", "viewer"])
    ac.add_argument("--password", action="store_true", help="create: also set a password (asked for)")
    ac.add_argument("--reason")
    ac.add_argument("--yes", action="store_true")
    ac.add_argument("--dry-run", action="store_true")
    ac.set_defaults(fn=cmd_account)
    tk = sub.add_parser("token", help="personal access tokens: create, revoke")
    tk.add_argument("action", choices=["create", "revoke"])
    tk.add_argument("id", nargs="?", help="revoke: the token id")
    tk.add_argument("--account", help="create: for this account (default: yours)")
    tk.add_argument("--label")
    tk.add_argument("--role", choices=["admin", "operator", "viewer"])
    tk.add_argument("--days", type=float, default=90)
    tk.add_argument("--reason")
    tk.add_argument("--yes", action="store_true")
    tk.add_argument("--dry-run", action="store_true")
    tk.set_defaults(fn=cmd_token)
    co = sub.add_parser("console", help="console sign-in: oarbank console login [--account NAME] [--open]")
    co.add_argument("action", choices=["login"])
    co.add_argument("--account")
    co.add_argument("--console", help="the console's base URL (default http://127.0.0.1:7400)")
    co.add_argument("--open", action="store_true", help="open the link in the browser")
    co.set_defaults(fn=cmd_console)
    ag = sub.add_parser("agent", help="agent self-update: upload an oarbank-agent build, canary, promote, rollback, sign (no ssh)")
    ag.add_argument("action", choices=["list", "upload", "canary", "promote", "rollback", "sign"])
    ag.add_argument("what", nargs="?", help="an oarbank-agent binary (upload) or a build: sha256, prefix or version")
    ag.add_argument("--node", action="append", help="canary node (repeat for several)")
    ag.add_argument("--platform", help="promote, rollback: only this platform's channel, e.g. linux-amd64 (default: every platform)")
    ag.add_argument("--key", help=f"signing key (sign; default {key})")
    ag.add_argument("--seq", type=int, help="statement seq (sign; default: one above the highest signed agent build)")
    ag.add_argument("--reason")
    ag.add_argument("--yes", action="store_true")
    ag.add_argument("--dry-run", action="store_true")
    ag.set_defaults(fn=cmd_agent)
    sub.add_parser("modules").set_defaults(fn=lambda a: [print(f"{m['name']:<12} v{m['version']} requires={m['requires']} "
                                                               f"{'enabled' if m['enabled'] else 'disabled'}") for m in api("GET", "/api/v1/modules")])
    pl = sub.add_parser("pipeline", help="run a module single-stage or as its stage chain (head on every node, tail where its pools are)")
    pl.add_argument("mode", choices=["single", "split"])
    pl.add_argument("--module", required=True)
    pl.add_argument("--reason")
    pl.add_argument("--yes", action="store_true")
    pl.set_defaults(fn=lambda a: print(json.dumps(run_op("modules.set_pipeline", a.module, {"mode": a.mode}, a.reason, a.yes),
                                                  indent=1, default=str)))
    v = sub.add_parser("verify", help="check protocol invariants and fleet health (exit 1 on violations)")
    v.add_argument("--strict", action="store_true", help="also fail on warnings")
    v.set_defaults(fn=cmd_verify)
    o = sub.add_parser("op", help="run any operation from the registry (see `oarbank ops`)")
    o.add_argument("op")
    o.add_argument("target", nargs="?")
    o.add_argument("--param", "-p", action="append", help="key=value (value parsed as JSON when possible)")
    o.add_argument("--json", help="params as a JSON object")
    o.add_argument("--reason", help="or OARBANK_REASON")
    o.add_argument("--yes", "-y", action="store_true")
    o.add_argument("--confirm", help="T3: the resource name")
    o.add_argument("--if-match", type=int)
    o.add_argument("--dry-run", action="store_true", help="preview only (exit 2 when there are changes)")
    o.set_defaults(fn=cmd_op)
    sub.add_parser("ops", help="list operations with their tier and reason policy").set_defaults(
        fn=lambda a: [print(f"{x['id']:<32} {x['tier']}  reason:{x['reason_policy']:<9} {x['summary']}")
                      for x in api("GET", "/api/v1/ops")])
    ex = sub.add_parser("explain", help="why is a job pending / a node not taking work (the claim path's own predicates)")
    ex.add_argument("kind", choices=["job", "node"])
    ex.add_argument("id")
    ex.add_argument("--json", action="store_true")
    ex.set_defaults(fn=cmd_explain)
    au = sub.add_parser("audit", help="audit log: list or verify the hash chain and signed digests")
    au.add_argument("action", choices=["log", "verify"], nargs="?", default="log")
    au.add_argument("--limit", type=int, default=50)
    au.add_argument("--op")
    au.add_argument("--target")
    au.add_argument("--against", help="verify against an off-host copy of audit/digests.jsonl")
    au.set_defaults(fn=cmd_audit)
    for name, opid in (("pause", "fleet.pause"), ("halt", "fleet.halt"), ("resume", "fleet.resume")):
        fp = sub.add_parser(name, help=f"{opid} (whole fleet)")
        fp.add_argument("--all", action="store_true", required=True)
        fp.add_argument("--reason")
        fp.add_argument("--yes", "-y", action="store_true")
        fp.set_defaults(fn=lambda a, opid=opid: print(json.dumps(run_op(opid, "fleet", reason=a.reason, yes=a.yes), indent=1)))
    return ap


def main():
    a = parser().parse_args()
    if a.cmd == "node" and a.action == "policy" and a.value:
        a.kv = [a.value] + a.kv
    a.fn(a)


if __name__ == "__main__":
    main()
