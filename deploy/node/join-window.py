"""The node's join window: a private loopback page that joins this machine to a fleet (docs/design/node-enrollment.md,
"Join window" and "Join window: files and launch contract").

    python -I join-window.py [--launcher PATH] [--link URL | --code-file PATH] [--no-browser]

It runs on the node package's bundled CPython with the standard library only (the coordinator is not installed on a
node, so nothing here imports oarbank), and it follows the coordinator setup wizard's hardened pattern
(src/oarbank/setup.py): a server on 127.0.0.1 and a random port, the exact Host and Origin, Sec-Fetch-Site, a
capability in the URL fragment that every POST carries as a header (compared in constant time), a nonce CSP, no-store,
JSON bodies of bounded size, an idle timeout kept alive by /ping, and a private active record so a second launch
reopens the open window instead of starting another.

The window never joins anything itself. It checks a code unprivileged (`oarbank-node check --code-stdin --json`), then
runs `oarbank-node join --code-file F --no-input --no-wait --progress-file P` with the operating system's own
elevation (macOS: the administrator prompt for the system service, none for "only while I'm logged in"; Linux:
pkexec; Windows: UAC) and follows the status document the agent writes. The code reaches the launcher on standard
input or in a 0600 file inside a 0700 private directory, never on a command line, and the file is deleted as soon as
the launcher exits. A code that arrived by link or file is shown with its coordinator and fingerprint first and joins
only after the person confirms it (a code merely arriving must not hand the machine to whoever sent it).
"""
import argparse
import base64
import contextlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HEADER = "X-Oarbank-Join"
MAX_BODY = 16384
MAX_CODE = 4096
LABEL = "dev.codonic.oarbank.agent"
JOINED_STATES = ("joined", "connected", "offline")
# Windows: start helpers without flashing a console window (the tray runs this with pythonw.exe).
NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class WindowError(Exception):
    def __init__(self, detail, status=400, code=None):
        super().__init__(detail)
        self.status = status
        self.code = code


def platform_name(value=None):
    value = value or sys.platform
    return "macos" if value == "darwin" else "windows" if value.startswith("win") else "linux"


# ---------------------------------------------------------------- the join code (OB2), offline
# A copy of oarbank.coordinator.joincodes.decode (and of the page's decoder), tested against the same vectors: the
# window refuses a malformed or expired code before it asks for an administrator, and never logs or echoes one.
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE = {c: i for i, c in enumerate(ALPHABET)} | {"I": 1, "L": 1, "O": 0}


def decode_code(code):
    """The non-secret fields of an OB2 code, or WindowError(E_CODE_FORMAT) naming what is wrong."""
    s = "".join(code.split()).upper()
    if not s.startswith("OB2"):
        if s.startswith("OB1"):
            raise WindowError("That code is from an older coordinator. Make a new one in the console.",
                              code="E_CODE_FORMAT")
        raise WindowError("That is not an Oarbank join code (they start with OB2-).", code="E_CODE_FORMAT")
    out, buf, bits = bytearray(), 0, 0
    for c in s[3:].replace("-", ""):
        if c not in _DECODE:
            raise WindowError("The join code has a character that is not in it. Copy it again from the console.",
                              code="E_CODE_FORMAT")
        buf, bits = (buf << 5) | _DECODE[c], bits + 5
        if bits >= 8:
            bits -= 8
            out.append((buf >> bits) & 0xFF)
            buf &= (1 << bits) - 1
    raw = bytes(out)
    if len(raw) < 1 + 1 + 4 + 32 + 1 + 1 + 8 + 16 + 4:
        raise WindowError("The join code is incomplete. Copy it again from the console.", code="E_CODE_FORMAT")
    body, crc = raw[:-4], raw[-4:]
    if zlib.crc32(body).to_bytes(4, "big") != crc:
        raise WindowError("The join code is mistyped or incomplete. Copy it again from the console.",
                          code="E_CODE_FORMAT")
    if body[0] != 2:
        raise WindowError("This join code's format is not supported by this version.", code="E_CODE_FORMAT")
    try:
        i = 6
        cik = base64.b64encode(body[i:i + 32]).decode()
        i += 32
        n = body[i]
        pins = [body[i + 1 + 32 * k:i + 1 + 32 * (k + 1)].hex() for k in range(n)]
        i += 1 + 32 * n
        n = body[i]
        i += 1
        urls = []
        for _ in range(n):
            ln = body[i]
            urls.append(body[i + 1:i + 1 + ln].decode())
            i += 1 + ln
        if i + 24 != len(body) or not pins or not urls or any(len(p) != 64 for p in pins):
            raise IndexError
    except (IndexError, UnicodeDecodeError):
        raise WindowError("The join code is malformed. Copy it again from the console.", code="E_CODE_FORMAT") from None
    first = urls[0].split("://", 1)[-1]
    return {"flags": body[1], "expires_at": int.from_bytes(body[2:6], "big") * 60, "cik": cik, "pins": pins,
            "urls": urls, "id": body[i:i + 8].hex(), "host": first.split("/", 1)[0], "fingerprint": pins[0][:16],
            "approve": bool(body[1] & 1), "system": bool(body[1] & 2), "containers": bool(body[1] & 4),
            "multi": bool(body[1] & 8)}


def offline_check(code, now=None):
    c = decode_code(code)
    if c["expires_at"] <= (time.time() if now is None else now):
        raise WindowError("This code has expired. Make a new one in the console.", code="E_CODE_EXPIRED")
    return c


def clean_code(value):
    """A pasted code as text: bounded, printable, whitespace allowed (the decoder strips it)."""
    if not isinstance(value, str) or not value.strip() or len(value) > MAX_CODE:
        raise WindowError("Paste the join code from your Oarbank console.", code="E_CODE_FORMAT")
    if any(ord(ch) < 32 and ch not in "\t\r\n" or ord(ch) == 127 for ch in value):
        raise WindowError("The join code has characters that are not in it. Copy it again from the console.",
                          code="E_CODE_FORMAT")
    return value.strip()


def code_from_link(url):
    """The code in `oarbank://join?code=…` (or `oarbank:join?code=…`); anything else is refused."""
    if not isinstance(url, str) or len(url) > MAX_CODE + 64:
        raise WindowError("That link is not an Oarbank join link.")
    parts = urllib.parse.urlsplit(url.strip())
    target = parts.netloc or parts.path.strip("/")
    if parts.scheme.lower() != "oarbank" or target.lower() != "join" or (parts.netloc and parts.path.strip("/")):
        raise WindowError("That link is not an Oarbank join link.")
    values = urllib.parse.parse_qs(parts.query, keep_blank_values=True).get("code", [])
    if len(values) != 1:
        raise WindowError("That join link has no code in it.")
    return clean_code(values[0])


def code_from_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_CODE + 1)
    except OSError as e:
        raise WindowError(f"Can't read {path}: {e.strerror or e}") from None
    try:
        return clean_code(data.decode("utf-8"))
    except UnicodeDecodeError:
        raise WindowError("That file does not hold a join code.") from None


# ---------------------------------------------------------------- where things are
def launcher_candidates(script, platform, env):
    """`oarbank-node` (the launcher under its second name): the environment, then the paths the packages install
    relative to this script (node-enrollment.md, "Join window: files and launch contract"), then PATH."""
    here = Path(script).resolve().parent
    found = []
    if env.get("OARBANK_NODE_LAUNCHER"):
        found.append(Path(env["OARBANK_NODE_LAUNCHER"]))
    if platform == "macos":
        found += [here.parent.parent / "bin" / "oarbank-launcher", Path("/Library/Oarbank/bin/oarbank-launcher")]
    elif platform == "linux":
        found += [here.parent / "oarbank-launcher", Path("/usr/lib/oarbank/oarbank-launcher")]
    else:
        found += [here.parent / "oarbank-node.exe"]
    return found


def find_launcher(script=__file__, platform=None, env=None):
    platform = platform or platform_name()
    env = os.environ if env is None else env
    for p in launcher_candidates(script, platform, env):
        if p.is_file() and (platform == "windows" or os.access(p, os.X_OK)):
            return str(p)
    on_path = shutil.which("oarbank-node", path=env.get("PATH"))
    if on_path:
        return on_path
    raise WindowError("Can't find oarbank-node. Reinstall Oarbank Node, or pass --launcher.")


def status_paths(platform, env=None, home=None):
    """{scope: status document path} (node-enrollment.md: `<data root>/status/node.json`). macOS has two scopes: the
    system service and the logged-in user's own agent. OARBANK_NODE_STATUS (and OARBANK_NODE_STATUS_PERSONAL) name
    other files (tests)."""
    env = os.environ if env is None else env
    if env.get("OARBANK_NODE_STATUS"):
        paths = {"system": Path(env["OARBANK_NODE_STATUS"])}
        if platform == "macos" and env.get("OARBANK_NODE_STATUS_PERSONAL"):
            paths["personal"] = Path(env["OARBANK_NODE_STATUS_PERSONAL"])
        return paths
    if platform == "macos":
        home = Path(home or Path.home())
        return {"system": Path("/Library/Application Support/Oarbank/status/node.json"),
                "personal": home / "Library/Application Support/Oarbank/status/node.json"}
    if platform == "windows":
        return {"system": Path(env.get("ProgramData") or r"C:\ProgramData") / "Oarbank" / "status" / "node.json"}
    return {"system": Path("/var/lib/oarbank/status/node.json")}


def read_json_file(path, limit=65536):
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
        value = json.loads(data) if len(data) <= limit else None
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, UnicodeError):
        return None


def is_root():
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (OSError, AttributeError):
            return False
    return os.geteuid() == 0


# ---------------------------------------------------------------- elevation
def applescript_string(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def powershell_string(text):
    # PowerShell also ends a single-quoted string at the typographic single quotes; each is escaped by doubling it.
    for q in "'\u2018\u2019\u201a\u201b":
        text = text.replace(q, q + q)
    return "'" + text + "'"


def elevated_command(argv, platform, elevate, pkexec=None):
    """The command that runs `argv` (the launcher and its arguments) with the operating system's own elevation:
    `argv` unchanged when nothing needs to be elevated, the macOS administrator prompt, pkexec, or UAC. A pure function
    of its inputs (tested with string asserts); nothing a request sent reaches it except the validated options."""
    if not elevate:
        return list(argv)
    if platform == "macos":
        script = (f"do shell script {applescript_string(shlex.join(argv))} with prompt "
                  f"{applescript_string('Oarbank Node needs an administrator to change how this Mac runs jobs.')} "
                  "with administrator privileges")
        return ["/usr/bin/osascript", "-e", script]
    if platform == "linux":
        if not pkexec:
            raise WindowError("This computer has no graphical administrator prompt (pkexec). Open a terminal and run: "
                              "sudo oarbank-node join", 409, code="E_PRIVILEGE")
        return [pkexec, *argv]
    # Start-Process joins -ArgumentList without quoting; one string quoted the Windows way keeps each argument whole.
    script = (f"try {{ $p = Start-Process -FilePath {powershell_string(argv[0])} "
              f"-ArgumentList {powershell_string(subprocess.list2cmdline(argv[1:]))} "
              "-Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode } catch { exit 1223 }")
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]


def cancelled(platform, exit_code, stderr):
    """Whether the person dismissed the administrator prompt (osascript -128, pkexec 126, UAC 1223)."""
    if platform == "macos":
        return exit_code != 0 and b"-128" in (stderr or b"")
    if platform == "linux":
        return exit_code == 126
    return exit_code == 1223


# ---------------------------------------------------------------- one launcher run at a time
class Job:
    """One elevated launcher run (join or leave) in a background thread. The code file and the progress file live in
    a private directory; the code file goes as soon as the launcher exits."""

    def __init__(self, kind, scope, workdir, code=None):
        self.kind, self.scope = kind, scope
        self.dir = Path(tempfile.mkdtemp(prefix=f"oarbank-{kind}-", dir=workdir))
        if os.name == "posix":
            os.chmod(self.dir, 0o700)
        self.code_file = None
        if code is not None:
            self.code_file = self.dir / "code"
            fd = os.open(self.code_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(code)
        self.progress = self.dir / "progress.jsonl"
        fd = os.open(self.progress, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        self.started_at = time.time()
        self.exit = None
        self.cancelled = False
        self.failed = None
        self.thread = None

    def start(self, command, platform):
        def run():
            try:
                r = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, timeout=3600, check=False, creationflags=NO_WINDOW)
                self.cancelled = cancelled(platform, r.returncode, r.stderr)
                self.exit = r.returncode
            except subprocess.TimeoutExpired:
                self.failed, self.exit = "The join did not finish within an hour.", -1
            except OSError as e:
                self.failed, self.exit = f"Couldn't start {Path(command[0]).name}: {e.strerror or e}", -1
            except Exception:
                self.failed, self.exit = "Oarbank Node could not run the command.", -1
            finally:
                self.forget_code()
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def forget_code(self):
        if self.code_file:
            with contextlib.suppress(OSError):
                self.code_file.unlink()

    def lines(self, offset, limit=65536):
        """Whole JSON lines of the progress file from byte `offset`, and the next offset."""
        try:
            with open(self.progress, "rb") as f:
                f.seek(max(0, offset))
                data = f.read(limit)
        except OSError:
            return [], offset
        end = data.rfind(b"\n") + 1
        out = []
        for line in data[:end].splitlines():
            with contextlib.suppress(ValueError, UnicodeError):
                v = json.loads(line)
                if isinstance(v, dict) and v.get("type") in ("row", "state", "result"):
                    out.append(v)
        return out, offset + end

    def result(self):
        last = None
        offset = 0
        while True:
            batch, nxt = self.lines(offset)
            for v in batch:
                if v["type"] == "result":
                    last = v
            if nxt == offset:
                return last
            offset = nxt

    def close(self, wait=True):
        if wait and self.thread is not None:
            self.thread.join()
        self.forget_code()
        shutil.rmtree(self.dir, ignore_errors=True)


def scrub(value, secrets_):
    """`value` with every occurrence of the code (as typed, normalized, its token) replaced; the launcher never
    prints the code, and this keeps it that way whatever an error message quotes."""
    if isinstance(value, str):
        for s in secrets_:
            if s and len(s) >= 8:
                value = value.replace(s, "[redacted]")
        return value
    if isinstance(value, list):
        return [scrub(v, secrets_) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v, secrets_) for k, v in value.items()}
    return value


def code_secrets(code):
    normalized = "".join(code.split()).upper()
    return [code, normalized, normalized.replace("-", ""), normalized[4:].replace("-", "")]


class Window:
    """What the page can ask for. The launcher (an argv prefix) and the platform are trusted command-line inputs."""

    def __init__(self, launcher, platform=None, prefill=None, env=None, workdir=None, home=None, elevate_root=None):
        self.launcher = [launcher] if isinstance(launcher, (str, Path)) else list(launcher)
        self.launcher = [str(x) for x in self.launcher]
        self.platform = platform or platform_name()
        self.env = os.environ if env is None else env
        self.statuses = status_paths(self.platform, self.env, home)
        self.prefill = prefill  # {"code", "source": "link" | "file"}
        self.workdir = workdir
        self.capability = secrets.token_urlsafe(32)
        self.job = None
        self.root = is_root() if elevate_root is None else elevate_root
        self.lock = threading.Lock()

    # ---- facts
    def scopes(self):
        return ["system", "personal"] if self.platform == "macos" else ["system"]

    def status(self):
        return {scope: read_json_file(p) for scope, p in self.statuses.items()}

    def policy(self):
        """The two policy values the page may see. JoinCode and Coordinator are never read out of the agent's answer.
        OARBANK_POLICY_FILE replaces the operating system's policy, as it does for the agent."""
        if self.env.get("OARBANK_POLICY_FILE"):
            raw = read_json_file(self.env["OARBANK_POLICY_FILE"]) or {}
        else:
            raw = {}
            agent = self.agent()
            if agent:
                with contextlib.suppress(OSError, subprocess.TimeoutExpired, ValueError, UnicodeError):
                    r = subprocess.run([agent, "policy"], stdin=subprocess.DEVNULL, capture_output=True, timeout=15,
                                       check=False, creationflags=NO_WINDOW)
                    v = json.loads(r.stdout) if r.returncode == 0 else {}
                    raw = v if isinstance(v, dict) else {}
        allow = raw.get("AllowUserJoin")
        if isinstance(allow, str):
            allow = {"1": True, "true": True, "yes": True, "0": False, "false": False, "no": False}.get(allow.lower())
        elif isinstance(allow, (int, float)) and not isinstance(allow, bool):
            allow = allow != 0
        managed = raw.get("ManagedByOrganizationName")
        return {"allow_user_join": allow is not False,
                "managed_by": managed.strip()[:120] if isinstance(managed, str) and managed.strip() else None}

    def agent(self):
        """`oarbank-agent` beside the canonical launcher (what `oarbank-node` itself runs)."""
        if len(self.launcher) != 1:
            return None
        exe = Path(self.launcher[0])
        with contextlib.suppress(OSError):
            exe = exe.resolve(strict=True)
        agent = exe.with_name("oarbank-agent.exe" if self.platform == "windows" else "oarbank-agent")
        return str(agent) if agent.is_file() else None

    def needs_elevation(self, scope):
        if self.root:
            return False
        return not (self.platform == "macos" and scope == "personal")

    def command(self, args, scope):
        return elevated_command([*self.launcher, *args], self.platform, self.needs_elevation(scope),
                                pkexec=shutil.which("pkexec") if self.platform == "linux" else None)

    def joined_scope(self):
        """The scope whose status document says the node joined (or is pending, joining, or failed with a
        coordinator), system first; on macOS a system LaunchDaemon also means the system service."""
        docs = self.status()
        for scope in self.scopes():
            doc = docs.get(scope) or {}
            if doc.get("state") in JOINED_STATES or (doc.get("state") not in (None, "unjoined") and doc.get("coordinator")):
                return scope
        if self.platform == "macos" and Path(f"/Library/LaunchDaemons/{LABEL}.plist").exists():
            return "system"
        return None

    # ---- requests
    def state(self):
        job = self.job
        return {"platform": self.platform, "scopes": self.scopes(), "status": self.status(), "policy": self.policy(),
                "prefill": dict(self.prefill) if self.prefill else None,
                "job": {"kind": job.kind, "scope": job.scope, "running": job.running} if job else None}

    def check(self, body):
        if set(body) != {"code"}:
            raise WindowError("Send the join code to check.")
        code = clean_code(body["code"])
        try:
            r = subprocess.run([*self.launcher, "check", "--code-stdin", "--json"], input=code.encode(),
                               capture_output=True, timeout=180, check=False,
                               creationflags=NO_WINDOW)
        except subprocess.TimeoutExpired:
            raise WindowError("The checks took too long. Check the network and try again.", 504, code="E_TCP") from None
        except OSError:
            raise WindowError("Can't run oarbank-node. Reinstall Oarbank Node.", 500, code="E_LOCAL") from None
        rows, result = [], None
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            with contextlib.suppress(ValueError):
                v = json.loads(line)
                if isinstance(v, dict) and v.get("type") == "row":
                    rows.append({"row": str(v.get("row", "")), "ok": v.get("ok") is True, "detail": str(v.get("detail", ""))})
                elif isinstance(v, dict) and v.get("type") == "result":
                    result = v
        if result is None:
            result = {"type": "result", "ok": False, "exit": r.returncode, "code": "E_LOCAL",
                      "message": "The checks did not finish. Try again, or run: oarbank-node doctor"}
        return scrub({"rows": rows, "result": result}, code_secrets(code))

    def join(self, body):
        if set(body) != {"code", "scope", "containers", "name"}:
            raise WindowError("Send the code and the join options.")
        policy = self.policy()
        if not policy["allow_user_join"]:
            raise WindowError("Your organization manages how this machine joins a fleet.", 403, code="E_MANAGED")
        code = clean_code(body["code"])
        offline_check(code)
        scope = body["scope"]
        if scope not in self.scopes():
            raise WindowError("Choose how Oarbank runs on this machine.")
        if not isinstance(body["containers"], bool):
            raise WindowError("Choose whether to run container jobs.")
        name = body["name"]
        if not isinstance(name, str) or (name and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", name)):
            raise WindowError("Name: up to 63 letters, digits, '.', '_' or '-', starting with a letter or digit.")
        args = ["join"]
        return self._start("join", scope, args, code=code, extra=lambda job: [
            "--code-file", str(job.code_file), "--no-input", "--no-wait", "--progress-file", str(job.progress),
            *(["--scope", scope] if self.platform == "macos" else []),
            *(["--containers"] if body["containers"] and self.platform == "windows" else []),
            *(["--name", name] if name else [])])

    def leave(self, body):
        if body:
            raise WindowError("Leave takes no parameters.")
        if not self.policy()["allow_user_join"]:
            raise WindowError("Your organization manages this machine; it can't leave from here.", 403, code="E_MANAGED")
        scope = self.joined_scope() or "system"
        return self._start("leave", scope, ["leave"], extra=lambda job: ["--progress-file", str(job.progress)])

    def _start(self, kind, scope, args, code=None, extra=lambda job: []):
        with self.lock:
            if self.job and self.job.running:
                raise WindowError("Oarbank Node is already working on this machine. Wait for it to finish.", 409)
            command = None
            job = Job(kind, scope, self.workdir, code=code)
            try:
                command = self.command([*args, *extra(job)], scope)
            except WindowError:
                job.close(wait=False)
                raise
            if self.job:
                self.job.close(wait=False)
            self.job = job
            job.start(command, self.platform)
            return {"started": True, "kind": kind, "scope": scope, "elevated": self.needs_elevation(scope),
                    "started_at": job.started_at}

    def progress(self, body):
        if set(body) != {"offset"} or not isinstance(body["offset"], int) or isinstance(body["offset"], bool) \
                or body["offset"] < 0:
            raise WindowError("Send the progress offset.")
        job = self.job
        if not job:
            raise WindowError("Nothing is running.", 409)
        running = job.running
        lines, offset = job.lines(body["offset"])
        doc = read_json_file(self.statuses.get(job.scope, self.statuses["system"]))
        fresh = bool(doc) and isinstance(doc.get("updated_at"), (int, float)) and doc["updated_at"] >= job.started_at - 1
        return {"kind": job.kind, "lines": lines, "offset": offset, "done": not running,
                "exit": None if running else job.exit, "cancelled": False if running else job.cancelled,
                "failed": None if running else job.failed, "result": None if running else job.result(),
                "status": doc, "fresh": fresh, "started_at": job.started_at}

    def set_prefill(self, body):
        """A second launch with a new link or file hands its code to the open window (the capability holder only)."""
        if set(body) != {"code", "source"} or body["source"] not in ("link", "file"):
            raise WindowError("Send a code and where it came from.")
        self.prefill = {"code": clean_code(body["code"]), "source": body["source"]}
        return {"ok": True}

    def close(self):
        if self.job:
            self.job.close(wait=True)


# ---------------------------------------------------------------- the loopback server
class WindowServer(HTTPServer):
    def __init__(self, window, port=0, idle_timeout=180):
        self.window = window
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
        pass  # never print requests, codes or tracebacks

    def idle(self):
        """Time out only while nothing runs: the window stays until the launcher exits and the code file is gone."""
        job = self.window.job
        return not (job and job.running) and time.monotonic() - self.last_activity >= self.idle_timeout


class Handler(BaseHTTPRequestHandler):
    REJECT_BODY_TIMEOUT = 1.0
    ROUTES = ("/state", "/check", "/join", "/progress", "/leave", "/prefill", "/ping", "/close")

    def log_message(self, *_):
        pass

    def _body_length(self):
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get_all("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
            raise WindowError("A single valid Content-Length is required.")
        length = int(lengths[0])
        if not 0 <= length <= MAX_BODY:
            raise WindowError("Invalid or oversized JSON request.")
        return length

    def _discard_unread_body(self):
        """Bounded byte discard, never JSON parsing, before an early rejection (setup.py: closing with unread data can
        reset the connection on Windows and erase the HTTP error)."""
        self.close_connection = True
        try:
            remaining = self._body_length()
        except (WindowError, ValueError):
            return
        deadline = time.monotonic() + self.REJECT_BODY_TIMEOUT
        previous_timeout = self.connection.gettimeout()
        try:
            while remaining:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                self.connection.settimeout(timeout)
                chunk = self.rfile.read1(min(remaining, 4096))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass
        finally:
            self.connection.settimeout(previous_timeout)

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
                         "img-src data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def send_error(self, code, message=None, explain=None):
        self._reply(code, {"error": "Invalid HTTP request."})

    def _guard(self, write=False):
        hosts = self.headers.get_all("Host", [])
        if hosts != [self.server.host]:
            raise WindowError("Invalid Host.", 421)
        origins = self.headers.get_all("Origin", [])
        if (origins and origins != [self.server.origin]) or (write and origins != [self.server.origin]):
            raise WindowError("Invalid Origin.", 403)
        if self.headers.get("Sec-Fetch-Site") not in (None, "same-origin", "none"):
            raise WindowError("Cross-origin requests are refused.", 403)
        if write:
            tokens = self.headers.get_all(HEADER, [])
            if len(tokens) != 1 or not hmac.compare_digest(tokens[0].encode(), self.server.window.capability.encode()):
                raise WindowError("Invalid join window capability.", 403)

    def do_GET(self):
        try:
            self._guard()
            if self.path != "/":
                raise WindowError("Not found.", 404)
            nonce = secrets.token_urlsafe(24)
            page = Path(__file__).with_name("join-window.html").read_text(encoding="utf-8")
            self._reply(200, page.replace("__NONCE__", nonce), "text/html", nonce)
        except WindowError as e:
            self._reply(e.status, {"error": str(e)})
        except OSError:
            self._reply(500, {"error": "The join window's page is missing. Reinstall Oarbank Node."})

    def do_POST(self):
        code = ""
        active = False
        body_read_started = False
        try:
            self._guard(write=True)
            if self.path not in self.ROUTES:
                raise WindowError("Not found.", 404)
            length = self._body_length()
            if self.headers.get("Content-Type") != "application/json":
                raise WindowError("Send application/json.", 415)
            try:
                if not length:
                    raise ValueError()
                body_read_started = True
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise WindowError("Invalid or oversized JSON request.") from None
            window = self.server.window
            self.server.last_activity = time.monotonic()
            active = True
            code = body.get("code") if isinstance(body.get("code"), str) else ""
            if self.path in ("/state", "/ping", "/close"):
                if body:
                    raise WindowError("This request takes no parameters.")
                if self.path == "/state":
                    result = window.state()
                else:
                    result = {"ok": True}
                    if self.path == "/close":
                        self.server.finished = True
            elif self.path == "/check":
                result = window.check(body)
            elif self.path == "/join":
                result = window.join(body)
            elif self.path == "/leave":
                result = window.leave(body)
            elif self.path == "/prefill":
                result = window.set_prefill(body)
            else:
                result = window.progress(body)
            self._reply(200, result)
        except WindowError as e:
            if not body_read_started:
                self._discard_unread_body()
            data = {"error": str(e)}
            if e.code:
                data["code"] = e.code
            self._reply(e.status, scrub(data, code_secrets(code)) if code else data)
        except Exception:
            self._reply(503, {"error": "The join window could not continue. Try again; nothing on this machine changed."})
        finally:
            if active:
                self.server.last_activity = time.monotonic()


# ---------------------------------------------------------------- one window per user
def private_dir(base=None):
    """The user's own directory for the lock and the active record: inside the temporary directory (per user on macOS
    and Windows, shared on Linux), owned by this user and closed to everyone else, never a symlink."""
    base = Path(base or tempfile.gettempdir())
    who = os.getuid() if hasattr(os, "getuid") else re.sub(r"[^A-Za-z0-9_.-]", "_", os.environ.get("USERNAME", "user"))
    d = base / f"oarbank-join-{who}"
    with contextlib.suppress(FileExistsError):
        d.mkdir(mode=0o700)
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or (os.name == "posix" and (st.st_uid != os.getuid() or st.st_mode & 0o077)):
        raise WindowError(f"{d} is not this user's private directory. Remove it and open Oarbank Node again.")
    return d


def write_private(path, text):
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


@contextlib.contextmanager
def window_lock(directory):
    """One join window per user: a second one would race the first for the same machine."""
    lock = Path(directory) / "join.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "r+b") as stream:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise WindowError("Another join window is already starting. Try again in a moment.", 409) from None
        yield


def _post(origin, token, path, body, timeout=2):
    """A POST to an open window, never through a proxy."""
    data = json.dumps(body).encode()
    request = urllib.request.Request(origin + path, data=data, method="POST", headers={
        "Content-Type": "application/json", "Origin": origin, HEADER: token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        return response.status, json.loads(response.read(65536))


def running_window(directory, prefill=None):
    """Reopen only a private, authenticated loopback window, never a stale URL. A new link's code goes to it."""
    path = Path(directory) / "join.active.json"
    if not path.is_file() or path.is_symlink() or (os.name == "posix" and path.stat().st_mode & 0o077):
        return None
    try:
        active = json.loads(path.read_text(encoding="utf-8"))
        origin, token = active["origin"], active["capability"]
        if not isinstance(origin, str) or not re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", origin):
            return None
        if not 1 <= int(origin.rsplit(":", 1)[1]) <= 65535:
            return None
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        status, answer = _post(origin, token, "/ping", {})
        if status != 200 or answer != {"ok": True}:
            return None
        if prefill:
            with contextlib.suppress(OSError, ValueError):
                _post(origin, token, "/prefill", prefill)
        return origin + "/#" + token
    except (OSError, ValueError, KeyError, TypeError):
        return None


def say(text):
    # pythonw.exe (the Windows tray) has no stdout
    if sys.stdout is not None:
        with contextlib.suppress(OSError, ValueError):
            print(text, flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Join this machine to an Oarbank fleet in a private browser window.")
    parser.add_argument("--launcher", help="oarbank-node (the launcher); found automatically when left out")
    source = parser.add_mutually_exclusive_group()
    # The Linux desktop entry ends in `--link %u`: opened from the menu there is no URL, so a bare `--link` (or an
    # empty one) means no link.
    source.add_argument("--link", nargs="?", default=None, const="",
                        help="an oarbank://join?code=… link (shown for confirmation first)")
    source.add_argument("--code-file", type=Path, help="a file holding a join code (shown for confirmation first)")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--port", type=int, default=0, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    try:
        prefill = None
        if args.link and args.link.strip():
            prefill = {"code": code_from_link(args.link), "source": "link"}
        elif args.code_file:
            prefill = {"code": code_from_file(args.code_file), "source": "file"}
        directory = private_dir()
        url = running_window(directory, prefill)
        if url:
            say(f"Open this private link on this computer: {url}")
            if not args.no_browser:
                webbrowser.open(url)
            return 0
        if args.launcher and not Path(args.launcher).is_file():
            raise WindowError(f"Can't find oarbank-node at {args.launcher}. Reinstall Oarbank Node.")
        launcher = args.launcher or find_launcher()
        with window_lock(directory):
            # no window is open (running_window found none) and this one holds the lock: run folders left by a window
            # that was killed mid-run are stale, and one may still hold a code file
            for leftover in directory.glob("oarbank-*-*"):
                if leftover.is_dir() and not leftover.is_symlink():
                    shutil.rmtree(leftover, ignore_errors=True)
            window = Window(launcher, prefill=prefill, workdir=str(directory))
            active = directory / "join.active.json"
            try:
                with WindowServer(window, args.port) as server:
                    write_private(active, json.dumps({"origin": server.origin, "capability": window.capability}))
                    # The capability is a URL fragment: never in HTTP requests, referers or logs.
                    url = server.origin + "/#" + window.capability
                    say(f"Open this private link on this computer: {url}")
                    if not args.no_browser:
                        webbrowser.open(url)
                    server.timeout = .5
                    while not server.finished and not server.idle():
                        server.handle_request()
            finally:
                with contextlib.suppress(OSError):
                    active.unlink()
                window.close()
        return 0
    except KeyboardInterrupt:
        return 130
    except (WindowError, OSError, ValueError) as e:
        if sys.stderr is not None:
            print(f"oarbank join window: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
