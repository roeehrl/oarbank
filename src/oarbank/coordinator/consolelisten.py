"""Where the console listens (setting `console_listen`; docs/design/admin-console.md, "Listen addresses").

The console process (oarbank-console) serves two listeners, the console itself (CONSOLE_PORT, 7400) and the module
origin for sandboxed module frames (7402). Both bind every address the fleet setting `console_listen` names:

- `localhost`: 127.0.0.1, always (a value without it gets it; the desktop app and `oarbank console login` use it);
- `tailscale`: this machine's Tailscale addresses (IPv4 and IPv6), looked up when the console starts and again every
  little while, so a changed or late address is followed;
- an IP address of this machine (IPv4 or IPv6), as given;
- `all`: every interface (0.0.0.0 and ::). Anyone who can reach the machine reaches the sign-in page, so a change to it
  is confirmed by typing the key's name, and the plan warns.

`console_https` (tailscale) adds https://<this machine's MagicDNS name>/ through `tailscale serve`, for passkeys
(below; the console's supervisor manages it).

Nothing here grants access: every listener keeps its sign-in, sessions, CSRF checks and Host allowlist. Pure functions
(the console's supervisor is console/serve.py; the coordinator uses them for the sign-in links of
`oarbank console login`)."""
import ipaddress
import json
import subprocess

LOCALHOST, TAILSCALE, ALL = "localhost", "tailscale", "all"
WORDS = (LOCALHOST, TAILSCALE, ALL)
LOOPBACK = "127.0.0.1"
WILDCARDS = ("0.0.0.0", "::")
MAX_TARGETS = 16


class ListenError(ValueError):
    pass


def check_target(x) -> str:
    """One entry, normalized: a word (localhost, tailscale, all) or an IP address in its canonical form."""
    if not isinstance(x, str) or not x.strip():
        raise ListenError("an entry is localhost, tailscale, all or an IP address")
    s = x.strip().lower()
    if s in WORDS:
        return s
    try:
        ip = ipaddress.ip_address(s.strip("[]"))
    except ValueError:
        raise ListenError(f"{x.strip()!r} is not localhost, tailscale, all or an IP address")
    if ip.is_unspecified:
        raise ListenError(f"{x.strip()!r} is every interface: write all")
    if ip.is_multicast:
        raise ListenError(f"{x.strip()!r} is a multicast address")
    if ip.version == 6 and ip.is_link_local:
        raise ListenError(f"{x.strip()!r} is link-local (it needs an interface): use another address")
    return str(ip)


def normalize(v) -> list[str]:
    """The setting's value: entries checked and de-duplicated, `localhost` first (always present); `all` covers every
    address, so with it the value is [localhost, all]."""
    if v is None:
        v = []
    if isinstance(v, str):
        v = [x for x in v.split(",")]
    if not isinstance(v, list):
        raise ListenError("a list: localhost, tailscale, all or IP addresses")
    if len(v) > MAX_TARGETS:
        raise ListenError(f"at most {MAX_TARGETS} entries")
    out = [LOCALHOST]
    for x in v:
        t = check_target(x)
        if t not in out:
            out.append(t)
    return [LOCALHOST, ALL] if ALL in out else out


def exposes(v) -> str | None:
    """What a value opens beyond this machine, as a warning for the plan, or None for localhost only."""
    try:
        v = normalize(v)
    except ListenError:
        return None
    if ALL in v:
        return ("console_listen all: the console and the module origin listen on every interface of the coordinator, so "
                "anyone who can reach this machine (the local network, a public address) reaches the sign-in page. "
                "Prefer tailscale, or put a firewall in front")
    if len(v) > 1:
        return (f"console_listen {', '.join(v[1:])}: the console's sign-in page becomes reachable from other machines at "
                "these addresses (plain http: use it only on a private network such as your tailnet)")
    return None


def tailscale_ips(cli: str | None = None, socket_path: str | None = None, timeout: float = 3.0) -> list[str]:
    """This machine's Tailscale addresses (`tailscale ip`), IPv4 first; [] when Tailscale is not installed or not up."""
    from . import config as C
    cmd = [cli or C.TAILSCALE] + (["--socket", socket_path or C.TAILSCALE_SOCKET]
                                  if (socket_path or C.TAILSCALE_SOCKET) else []) + ["ip"]
    try:
        out = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode:
        return []
    return parse_ips(out.stdout)


def parse_ips(text: str) -> list[str]:
    """IP addresses from `tailscale ip` output (one per line; a JSON list too), IPv4 first, de-duplicated."""
    try:
        items = json.loads(text)
        items = items if isinstance(items, list) else []
    except ValueError:
        items = text.split()
    ips = []
    for x in items:
        try:
            ip = ipaddress.ip_address(str(x).strip())
        except ValueError:
            continue
        if not (ip.is_unspecified or ip.is_loopback) and str(ip) not in ips:
            ips.append(str(ip))
    return sorted(ips, key=lambda s: ipaddress.ip_address(s).version)


def resolve(value, tailscale: list[str] | None) -> tuple[list[str], list[str]]:
    """(addresses to bind, notes): 127.0.0.1 first, then the setting's addresses in order; `tailscale` expands to
    `tailscale` (this machine's Tailscale addresses, looked up by the caller; None or []: not up, noted); `all` is the
    two wildcards alone (a wildcard and a specific address on the same port collide on Linux)."""
    try:
        v = normalize(value)
    except ListenError as e:
        return [LOOPBACK], [f"console_listen is not valid ({e}): listening on localhost only"]
    if ALL in v:
        return list(WILDCARDS), []
    out, notes = [LOOPBACK], []
    for t in v[1:]:
        if t == TAILSCALE:
            if not tailscale:
                notes.append("tailscale: this machine has no Tailscale address now (is Tailscale running and signed in?); "
                             "it is looked up again every 30 s")
            out += [ip for ip in tailscale or [] if ip not in out]
        elif t not in out:
            out.append(t)
    return out, notes


def url_host(ip: str) -> str:
    """An address as a URL's host (IPv6 in brackets)."""
    return f"[{ip}]" if ":" in ip else ip


def link_hosts(value, tailscale: list[str] | None) -> list[str]:
    """The hosts a person can open the console at (sign-in links): localhost first, then the listen addresses; under `all`
    127.0.0.1 and the Tailscale addresses (every other interface works too)."""
    addrs, _ = resolve(value, tailscale)
    if addrs == list(WILDCARDS):
        addrs = [LOOPBACK, *(tailscale or [])]
    return [url_host(a) for a in dict.fromkeys(addrs)]


def split_host(host_header: str | None) -> tuple[str, int | None]:
    """(name, port) of a Host header: the name lower-cased (an IPv6 literal keeps its brackets), port None if absent."""
    h = (host_header or "").strip().lower()
    if h.startswith("["):
        name, _, rest = h.partition("]")
        name += "]"
        port = rest[1:] if rest.startswith(":") else ""
    elif h.count(":") == 1:
        name, port = h.split(":")
    else:
        name, port = h, ""
    return name, (int(port) if port.isdigit() else None)


def is_ip_literal(name: str) -> bool:
    try:
        ipaddress.ip_address(name.strip("[]"))
        return True
    except ValueError:
        return False


def other_origin(host_header: str | None, own_port: int | None, other_port: int, default: str) -> str:
    """The origin of the console's other listener as the browser sees it from this request: the same host name on the
    other port when the request reached this listener directly (its Host names this listener's port: the console
    opened at http://localhost:7400 has its frames at http://localhost:7402, at http://100.64.0.1:7400 at
    http://100.64.0.1:7402), else `default` (a proxy in front, such as `tailscale serve`, or no Host). The Host
    was already checked against the allowlist."""
    name, port = split_host(host_header)
    if name and own_port and port == own_port:
        return f"http://{name}:{other_port}"
    return default


# ------------------------------------------------------------------ https on this machine's Tailscale name (passkeys)
# Setting `console_https`: off, or tailscale: `tailscale serve` (this machine's tailscaled terminates TLS with a
# certificate for its MagicDNS name) proxies https://<name>/ to the console on localhost and https://<name>:8443/ to the
# module origin, so the console has a host name in a secure context and passkeys work from other devices of the
# tailnet. Never Funnel: tailscale serve answers on the tailnet only (and the console refuses Funnel requests).
HTTPS_OFF, HTTPS_TAILSCALE = "off", "tailscale"
CONSOLE_HTTPS_PORT, FRAMES_HTTPS_PORT = 443, 8443


def serve_wanted(console_port: int, frames_port: int) -> dict[int, str]:
    """{https port: the local target tailscale serve proxies it to}."""
    return {CONSOLE_HTTPS_PORT: f"http://127.0.0.1:{console_port}", FRAMES_HTTPS_PORT: f"http://127.0.0.1:{frames_port}"}


def magicdns_name(status: dict | None) -> str | None:
    """This machine's MagicDNS name from `tailscale status --json` (box.example.ts.net), or None."""
    name = str(((status or {}).get("Self") or {}).get("DNSName") or "").strip().rstrip(".").lower()
    return name or None


def same_target(a: str | None, b: str | None) -> bool:
    norm = lambda u: (u or "").strip().rstrip("/").lower().replace("://localhost:", "://127.0.0.1:")
    return bool(a) and norm(a) == norm(b)


def serve_targets(serve: dict | None, name: str | None) -> dict[int, str | None]:
    """{https port: what `tailscale serve status --json` proxies https://<name>:<port>/ to} (None: nothing)."""
    out: dict[int, str | None] = {}
    web = (serve or {}).get("Web") or {}
    for port in (CONSOLE_HTTPS_PORT, FRAMES_HTTPS_PORT):
        h = (((web.get(f"{name}:{port}") or {}).get("Handlers") or {}).get("/") or {}) if name else {}
        out[port] = h.get("Proxy") or (h.get("Path") and f"path {h['Path']}") or (h.get("Text") and "text") or None
    return out


def serve_commands(wanted: dict[int, str], on: bool) -> list[list[str]]:
    """The `tailscale` arguments that turn the console's https on (or off) for these ports."""
    return [["serve", "--bg", f"--https={port}", target] if on else ["serve", f"--https={port}", "off"]
            for port, target in wanted.items()]


def tailscale_status(timeout: float = 5.0) -> dict | None:
    """`tailscale status --json` of this machine, or None."""
    from . import config as C
    cmd = [C.TAILSCALE] + (["--socket", C.TAILSCALE_SOCKET] if C.TAILSCALE_SOCKET else []) + ["status", "--json"]
    try:
        out = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout, check=False)
        return json.loads(out.stdout) if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def https_origin(name: str, port: int) -> str:
    return f"https://{name}" if port == 443 else f"https://{name}:{port}"
