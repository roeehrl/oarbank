"""Advertising the coordinator on the local network (architecture.md, "Network and access": discovery is a hint, never trust).

An active coordinator announces `_oarbank._tcp` with its agent port and a TXT record naming its fleet id and CA pin
prefix. Agents use it only to find a URL: trust still comes from the owner approving the enrollment (or from a join
code, which carries the full CA pin). platform/dnssd.py announces it: the system responder on macOS, Avahi on Linux
when it is installed, the DNS-SD API on Windows.

`OARBANKD_DISCOVERY`: `auto` (default) advertises unless the agent listener is bound to loopback, `1` always, `0`
never. `OARBANK_DISCOVERY_TYPE` changes the service type (tests).
"""
import ipaddress
import os

SERVICE = "_oarbank._tcp"


def service_type() -> str:
    return os.environ.get("OARBANK_DISCOVERY_TYPE") or SERVICE


def wanted(bind: str) -> bool:
    mode = os.environ.get("OARBANKD_DISCOVERY", "auto")
    if mode == "0":
        return False
    if mode == "1":
        return True
    try:
        return not ipaddress.ip_address(bind.strip("[]")).is_loopback
    except ValueError:
        return bind != "localhost"


def advertise(fleet_id: str, port: int, ca_spki: str | None, bind: str):
    """Start the announcement; the caller terminates the returned object at exit."""
    if not wanted(bind):
        return None
    from ..platform import dnssd
    txt = [f"fleet={fleet_id}", f"ca={(ca_spki or '')[:16]}", "v=1"]
    try:
        return dnssd.announce(f"Oarbank {fleet_id[-8:]}", service_type(), port, txt)
    except OSError:
        return None
