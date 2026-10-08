"""Portable, local-owner first-run wizard. No services are installed until POST /start.

The build root and installer are trusted command-line inputs, never HTTP inputs. A
private journal permits recovery; setup.complete.json is written only after TOTP.
"""
import argparse
import contextlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

from . import paths
from .coordinator import access
from .platform import files


class SetupError(Exception):
    def __init__(self, detail, status=400):
        super().__init__(detail)
        self.status = status


def agent_address(value):
    """An explicit unicast IP literal, including loopback for a single-computer setup."""
    if not isinstance(value, str) or '%' in value:
        raise SetupError("Choose an IPv4 or IPv6 address without a scope suffix.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise SetupError("Choose an IPv4 or IPv6 address, without a hostname, port or URL.") from None
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise SetupError("Choose a specific unicast coordinator address, not a wildcard or multicast address.")
    if address.version == 6 and (address.is_link_local or address.ipv4_mapped):
        raise SetupError("Choose a routable IPv6 address or an IPv4 address.")
    return str(address)


def check_local_address(address):
    try:
        with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((address, 0))
    except OSError:
        raise SetupError("That address is not assigned to this computer or cannot be bound locally.") from None


def local_addresses():
    """Read-only discovery, with fixed commands and a bind probe for every choice."""
    from .coordinator import config as C
    if sys.platform == "win32":
        commands = [["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-NetIPAddress | Select-Object -ExpandProperty IPAddress"]]
    elif sys.platform == "darwin":
        commands = [["/sbin/ifconfig"]]
    else:
        commands = [["hostname", "-I"]]
    commands.append([C.TAILSCALE, "ip", "-4"])
    found = {}
    for command in commands:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3,
                                    check=False)
            if result.returncode:
                continue
            for word in re.findall(r"[0-9a-fA-F:.]+(?:%[\w.-]+)?", result.stdout):
                try:
                    address = agent_address(word)
                    if ipaddress.ip_address(address).is_loopback:
                        continue
                    check_local_address(address)
                except SetupError:
                    continue
                found[address] = {"address": address, "label": f"{address} ({'Tailscale' if command[0] == C.TAILSCALE else 'local network'})"}
        except (OSError, subprocess.TimeoutExpired):
            continue
    return sorted(found.values(), key=lambda row: ("Tailscale" not in row["label"], row["address"]))


class Backend:
    """Calls the existing CLI in this process, using only this host's owner channel."""
    def __init__(self, root):
        from .coordinator import config as C
        from .cli import main as cli
        self.cli = cli
        # A desktop environment must not redirect setup credentials to a remote API.
        os.environ.pop("OARBANKD_URL", None)
        os.environ.pop("OARBANK_TOKEN", None)
        cli.URL = f"http://127.0.0.1:{C.ADMIN_PORT}"
        self.console = f"http://127.0.0.1:{C.CONSOLE_PORT}/login"
        self.home = C.HOME
        # CLI operations must also bypass environment proxies when the local
        # owner channel is temporarily unavailable during service startup.
        cli.http_request = self._request
        self._addresses = None

    def addresses(self):
        if self._addresses is None:
            self._addresses = local_addresses()
        return self._addresses

    def _request(self, method, url, **kwargs):
        import httpx
        from .platform import localchannel
        if not url.startswith(self.cli.URL + "/"):
            raise SetupError("Setup only uses the local coordinator API.")
        transport = localchannel.transport(self.home) if localchannel.reachable(self.home) else None
        with httpx.Client(transport=transport, trust_env=False) as client:
            return client.request(method, url, **kwargs)

    def snapshot(self):
        return {"accounts": self.cli.api("GET", "/api/v1/access", timeout=2)["accounts"],
                "owner": self.cli.api("GET", "/api/v1/owner", timeout=2),
                "fleet": self.cli.api("GET", "/api/v1/coordinator", timeout=2)["fleet_id"]}

    def ready(self):
        try:
            state = self.snapshot()
            import httpx
            with httpx.Client(trust_env=False) as client:
                r = client.get(self.console.rsplit("/", 1)[0] + "/healthz", timeout=2)
            if r.status_code == 200 and r.json().get("ok"):
                return state
        except (Exception, SystemExit):
            pass
        return None

    def install(self, root, address):
        if sys.platform == "win32":
            command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                       str(root / "install-oarbankd.ps1"), "-Installed", str(root), "-AgentBind", address]
        else:
            command = ["bash", str(root / "install-oarbankd.sh"), "--installed", str(root), "--agent-bind", address]
        # Nothing from a request except the validated IP reaches argv. No password
        # is in argv, stdin, environment or subprocess output logs.
        try:
            r = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=180, check=False)
        except subprocess.TimeoutExpired:
            raise SetupError("The service installer timed out. Retry setup to check readiness.", 503) from None
        if r.returncode:
            raise SetupError(f"The service installer failed (exit {r.returncode}). Retry after fixing the installation.", 503)

    def create_admin(self, name, password):
        return self.cli.run_op("access.accounts.create", name, {"role": "admin", "password": password},
                               yes=True, reason="First-run administrator setup", out=lambda *_: None)["result"]

    def signing(self, primary, backup):
        # cmd_owner reuses existing key files and proves possession of both keys.
        with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            self.cli.cmd_owner(SimpleNamespace(action="set", key=str(primary), backup_key=str(backup), old_key=None,
                                              rescue=[], reason="First-run setup", yes=True, dry_run=False))

    def confirm(self, name, password, code):
        # The existing access.password_login ceremony verifies both factors,
        # records replay protection and failures, and never changes credentials.
        secret = (self.home / "console.secret").read_text(encoding="utf-8").strip()
        import httpx
        # Sign-in ceremonies check the loopback TCP peer even when the owner
        # channel is available, so use TCP explicitly for this one ceremony.
        with httpx.Client(trust_env=False) as client:
            r = client.post(self.cli.URL + "/api/v1/access/login",
                            json={"name": name, "password": password, "code": code},
                            headers={"x-oarbank-console-secret": secret}, timeout=5)
            if r.status_code != 200:
                raise SetupError("Wrong password or authenticator code, or the account is locked.", 403)
            # This wizard does not retain or expose the session minted by the ceremony.
            client.post(self.cli.URL + "/api/v1/access/logout", json={"sid": r.json()["sid"]},
                        headers={"x-oarbank-console-secret": secret}, timeout=5)

    def login_url(self):
        try:
            return self.cli.run_op("access.login_link", params={"console": self.console.rsplit("/", 1)[0]},
                                   yes=True, out=lambda *_: None)["result"]["url"]
        except (Exception, SystemExit):
            return self.console


class Wizard:
    def __init__(self, root, backend=None, home=None, primary=None, ready_timeout=60):
        self.root = Path(root).resolve(strict=True)
        manifest = json.loads((self.root / "oarbank-coordinator.json").read_text(encoding="utf-8"))
        if manifest.get("format") != 1:
            raise SetupError("Unknown coordinator build format.")
        self.version = manifest.get("version")
        if not isinstance(self.version, str) or not self.version:
            raise SetupError("The coordinator build has no version.")
        helper = "install-oarbankd.ps1" if sys.platform == "win32" else "install-oarbankd.sh"
        if not (self.root / helper).is_file():
            raise SetupError(f"The build is missing {helper}.")
        self.home = Path(home or os.environ.get("OARBANKD_HOME") or paths.coordinator_home())
        self.primary = Path(primary or paths.release_key())
        self.backup = self.primary.with_name("release-ed25519-backup.key")
        self.pending_path = self.home / "setup.pending.json"
        self.marker = self.home / "setup.complete.json"
        self.backend = backend or Backend(self.root)
        self.ready_timeout = ready_timeout
        self.capability = secrets.token_urlsafe(32)
        self.pending = None
        if self.pending_path.exists():
            if not files.owner_only(self.pending_path):
                raise SetupError("The pending setup journal must be owner-only.")
            self.pending = json.loads(self.pending_path.read_text(encoding="utf-8"))
        self.password = None
        self.complete = self.marker.exists()
        self.failures = []

    def _save(self, exclusive=False):
        files.write_private(self.pending_path, json.dumps(self.pending), exclusive=exclusive)

    def _disk_configured(self):
        # Be conservative when services are stopped: do not reconfigure an old
        # installation simply because its readiness probe cannot connect.
        return any((self.home / n).exists() for n in ("oarbank.sqlite3", "admin.token", "console.secret"))

    def existing(self):
        if self.complete:
            return True
        if self.pending:
            return False
        if self._disk_configured():
            return True
        ready = self.backend.ready()
        return bool(ready and (ready["accounts"] or ready["owner"].get("keys")))

    def _wait(self):
        deadline = time.monotonic() + self.ready_timeout
        while True:
            state = self.backend.ready()
            if state:
                return state
            if time.monotonic() >= deadline:
                raise SetupError("Services are not ready. Retry setup once the coordinator and console are running.", 503)
            time.sleep(.25)

    def start(self, body):
        if set(body) != {"address", "name", "password", "confirmation"}:
            raise SetupError("Submit an address, admin name, password and password confirmation.")
        address = agent_address(body["address"])
        name, password = body["name"], body["password"]
        if not isinstance(name, str) or not access.ACCOUNT_RE.fullmatch(name):
            raise SetupError("Admin name: 2–32 lowercase letters, digits, '.', '_' or '-'; start with a letter.")
        if not isinstance(password, str) or len(password) < 12:
            raise SetupError("The password must have at least 12 characters.")
        if password != body["confirmation"]:
            raise SetupError("Passwords do not match.")
        if self.existing():
            return {"console": self.backend.console, "existing": True}
        check_local_address(address)
        if self.pending and (self.pending["address"] != address or self.pending["name"] != name):
            raise SetupError("Resume with the original coordinator address and admin name. Existing setup choices are preserved.", 409)
        if not self.pending:
            self.pending = {"format": 1, "address": address, "name": name}
            try:
                self._save(exclusive=True)
            except BaseException:
                self.pending = None
                raise
        state = self.backend.ready()
        if not state:
            self.backend.install(self.root, address)
            state = self._wait()
        if self.pending.get("fleet") and self.pending["fleet"] != state["fleet"]:
            raise SetupError("The coordinator fleet changed. Setup will not modify it.", 409)
        self.pending["fleet"] = state["fleet"]
        self._save()
        accounts = state["accounts"]
        enrollment = self.pending.get("enrollment")
        if accounts:
            # An account created between the API commit and journal save is not
            # overwritten or reset. The owner can recover through console login.
            if not enrollment or len(accounts) != 1 or accounts[0]["name"] != name or accounts[0]["role"] != "admin" or accounts[0].get("disabled"):
                raise SetupError("An existing account was found. Open the console; setup will not replace it.", 409)
        elif enrollment:
            raise SetupError("The pending admin account is missing. Setup will not recreate it.", 409)
        else:
            enrollment = self.backend.create_admin(name, password)
            self.pending["enrollment"] = enrollment
            self._save()
        owner = state["owner"]
        if not owner.get("signing"):
            raise SetupError("Release signing is disabled. Enable signing before finishing setup.", 409)
        if not owner.get("version"):
            self.backend.signing(self.primary, self.backup)
        self.password = password  # memory only, cleared after TOTP confirmation
        return {"account": name, "totp_secret": enrollment["totp_secret"], "otpauth": enrollment["otpauth"],
                "primary_key": str(self.primary), "backup_key": str(self.backup)}

    def finish(self, body):
        if set(body) != {"code"} or not isinstance(body["code"], str):
            raise SetupError("Enter the authenticator's six-digit code.")
        if self.complete:
            return {"console": self.backend.console}
        if not self.pending or not self.pending.get("enrollment"):
            raise SetupError("Submit the setup form first.", 409)
        if self.password is None:
            raise SetupError("Resume the setup form with your original password first.", 409)
        now = time.monotonic()
        self.failures = [t for t in self.failures if now - t < 60]
        if len(self.failures) >= 5:
            raise SetupError("Too many failed codes. Wait one minute and retry.", 429)
        state = self._wait()
        account = next((a for a in state["accounts"] if a["name"] == self.pending["name"]), None)
        if (state["fleet"] != self.pending["fleet"] or not account or account["role"] != "admin"
                or account.get("disabled") or not state["owner"].get("signing") or not state["owner"].get("version")):
            raise SetupError("The admin account or signing setup is incomplete or has changed.", 409)
        enrollment = self.pending["enrollment"]
        if access.totp_step(enrollment["totp_secret"], body["code"], self.pending.get("last_step", 0)) is None:
            self.failures.append(now)
            raise SetupError("Invalid authenticator code. Try the current six-digit code.")
        try:
            self.backend.confirm(self.pending["name"], self.password, body["code"])
        except SetupError:
            self.failures.append(now)
            raise
        files.write_private(self.marker, json.dumps({"format": 1, "account": self.pending["name"],
                                                    "fleet": state["fleet"], "address": self.pending["address"],
                                                    "root": str(self.root), "version": self.version,
                                                    "completed_at": time.time()}), exclusive=True)
        self.complete = True
        self.password = None
        self.pending_path.unlink(missing_ok=True)
        self.pending = None
        return {"console": self.backend.login_url()}

    def reopen(self):
        if self.complete:
            marker = json.loads(self.marker.read_text(encoding="utf-8"))
            address = agent_address(marker["address"])
            state = self.backend.ready()
            changed = marker.get("root") != str(self.root) or marker.get("version") != self.version
            if state and state["fleet"] != marker["fleet"]:
                raise SetupError("The coordinator fleet changed. Open the console to review it.", 409)
            if changed or not state:
                # Refresh only after an upgrade, relocation or stopped services.
                # Ordinary app openings must not interrupt active work.
                self.backend.install(self.root, address)
                state = self._wait()
            if state["fleet"] != marker["fleet"]:
                raise SetupError("The coordinator fleet changed. Open the console to review it.", 409)
            if changed:
                files.write_private(self.marker, json.dumps({**marker, "root": str(self.root), "version": self.version}))
            # A crash after the completion marker was written may have left the
            # enrollment journal. Erase it when reopening verified completion.
            self.pending_path.unlink(missing_ok=True)
            self.pending = None
        return self.backend.login_url()


class SetupServer(HTTPServer):
    def __init__(self, wizard, port=0, idle_timeout=180):
        self.wizard = wizard
        self.finished = False
        self.idle_timeout = idle_timeout
        self.last_activity = time.monotonic()
        super().__init__(("127.0.0.1", port), Handler)
        self.host = f"127.0.0.1:{self.server_port}"
        self.origin = f"http://{self.host}"

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(10)
        return sock, address

    def handle_error(self, request, client_address):
        pass  # never print requests, credentials, tokens or tracebacks


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _reply(self, status, data, content_type="application/json", nonce=None):
        payload = json.dumps(data).encode() if content_type == "application/json" else data.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        scripts = f"'nonce-{nonce}'" if nonce else "'none'"
        self.send_header("Content-Security-Policy", f"default-src 'none'; script-src {scripts}; style-src {scripts}; "
                         "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def send_error(self, code, message=None, explain=None):
        self._reply(code, {"error": "Invalid HTTP request."})

    def _guard(self, write=False):
        hosts = self.headers.get_all("Host", [])
        if hosts != [self.server.host]:
            raise SetupError("Invalid Host.", 421)
        origins = self.headers.get_all("Origin", [])
        if (origins and origins != [self.server.origin]) or (write and origins != [self.server.origin]):
            raise SetupError("Invalid Origin.", 403)
        if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            raise SetupError("Cross-origin requests are refused.", 403)
        if write:
            tokens = self.headers.get_all("X-Oarbank-Setup", [])
            if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode(), self.server.wizard.capability.encode()):
                raise SetupError("Invalid setup capability.", 403)

    def do_GET(self):
        try:
            self._guard()
            if self.path != "/":
                raise SetupError("Not found.", 404)
            nonce = secrets.token_urlsafe(24)
            page = Path(__file__).with_name("setup.html").read_text(encoding="utf-8")
            self._reply(200, page.replace("__NONCE__", nonce), "text/html", nonce)
        except SetupError as e:
            self._reply(e.status, {"error": str(e)})

    def do_POST(self):
        password = ""
        active = False
        try:
            self._guard(write=True)
            if self.path not in ("/state", "/start", "/finish", "/ping", "/close"):
                raise SetupError("Not found.", 404)
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise SetupError("A single Content-Length is required.")
            if self.headers.get("Content-Type") != "application/json":
                raise SetupError("Send application/json.", 415)
            try:
                length = int(self.headers["Content-Length"])
                if not 0 < length <= 16384:
                    raise ValueError()
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise SetupError("Invalid or oversized JSON request.") from None
            wizard = self.server.wizard
            self.server.last_activity = time.monotonic()
            active = True
            password = body.get("password") if isinstance(body.get("password"), str) else ""
            if self.path == "/state":
                if body:
                    raise SetupError("State takes no parameters.")
                result = {"existing": wizard.existing(), "console": wizard.backend.console,
                          "pending": {k: wizard.pending[k] for k in ("name", "address")} if wizard.pending else None,
                          "addresses": wizard.backend.addresses()}
            elif self.path in ("/ping", "/close"):
                if body:
                    raise SetupError("This request takes no parameters.")
                result = {"ok": True}
                if self.path == "/close":
                    self.server.finished = True
            elif self.path == "/start":
                result = wizard.start(body)
            else:
                result = wizard.finish(body)
                self.server.finished = True
            self._reply(200, result)
        except (SetupError, SystemExit) as e:
            # CLI errors preserve the operation/status/detail, without reflecting
            # a submitted password or a once-only enrollment secret.
            detail = str(e)
            for value in (password, self.server.wizard.password):
                if value:
                    detail = detail.replace(value, "[redacted]")
            pending = self.server.wizard.pending or {}
            for key in ("totp_secret", "otpauth"):
                secret = pending.get("enrollment", {}).get(key)
                if secret:
                    detail = detail.replace(secret, "[redacted]")
            self._reply(e.status if isinstance(e, SetupError) else 502, {"error": detail})
        except Exception:
            self._reply(503, {"error": "Setup could not continue. Retry; existing accounts, keys and setup choices are preserved."})
        finally:
            if active:
                # A slow installer/readiness wait must not consume the browser's
                # idle allowance before the authenticator screen appears.
                self.server.last_activity = time.monotonic()


@contextlib.contextmanager
def setup_lock(home):
    """Serialize wizard processes, including exclusive key creation in cmd_owner."""
    files.private_dir(home)
    lock = home / "setup.lock"
    if not lock.exists():
        try:
            files.write_private(lock, "0", exclusive=True)
        except FileExistsError:
            pass
    with lock.open("r+b") as stream:
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SetupError("Another setup wizard is already running.", 409) from None
        yield


def main(argv=None):
    parser = argparse.ArgumentParser(description="Set up the coordinator in a private loopback browser wizard.")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    try:
        wizard = Wizard(args.root)
        with setup_lock(wizard.home):
            if wizard.existing():
                url = wizard.reopen()
                if not args.no_browser:
                    webbrowser.open(url)
                print(f"Existing coordinator: {url}")
                return 0
            with SetupServer(wizard, args.port) as server:
                url = server.origin + "/#" + wizard.capability
                # The capability is a URL fragment: not in HTTP requests, referers
                # or access logs. Printing this local launch link permits no-browser use.
                print(f"Open this private setup link on this computer: {url}", flush=True)
                if not args.no_browser:
                    webbrowser.open(url)
                server.timeout = .5
                while not server.finished and time.monotonic() - server.last_activity < server.idle_timeout:
                    server.handle_request()
        return 0
    except KeyboardInterrupt:
        return 130
    except (SetupError, OSError, ValueError) as e:
        print(f"oarbank-setup: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
