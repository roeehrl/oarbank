"""The coordinator's internal CA and the agent listener's TLS (PLAN D29; architecture.md, "Network and access").

- **The CA** is a P-256 key and a self-signed certificate under `<home>/tls/` (key owner-only). It moves with the home
  in a coordinator move. Agents pin its SPKI SHA-256, learned from the CIK-signed identity payload, so the TLS pin is
  bound to the coordinator identity they already trust; `next` holds a successor during a CA rotation.
- **The server certificate** for the agent listener is issued by the CA for the listener's names and addresses, and
  re-issued when they change or within 30 days of expiry.
- **Agent client certificates** are issued from a CSR the agent makes at enrollment (its P-256 key never leaves the
  node), for 30 days, renewed in-band. The coordinator stores only each node's certificate fingerprint, so a database
  leak gives nobody a credential. Retiring a node clears it.

Certificates carry the extensions strict X.509 validators require (basic constraints, key usage, extended key usage,
subject and authority key identifiers).
"""
import datetime as dt
import hashlib
import ipaddress
import json
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DAYS = 3650
SERVER_DAYS = 365
CLIENT_DAYS = 30
RENEW_WITHIN_S = 10 * 86400
NODE_URI = "oarbank:node:"


class CAError(ValueError):
    pass


def tls_dir(home) -> Path:
    from ..platform import files
    return files.private_dir(Path(home) / "tls")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _write_key(path: Path, key):
    from ..platform import files
    files.write_private(path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))


def _load_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def spki_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_key().public_bytes(serialization.Encoding.DER,
                                                         serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def ensure_ca(home, fleet_id: str) -> x509.Certificate:
    d = tls_dir(home)
    if (d / "ca.pem").exists() and (d / "ca.key").exists():
        return x509.load_pem_x509_certificate((d / "ca.pem").read_bytes())
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Oarbank"),
                      x509.NameAttribute(NameOID.COMMON_NAME, f"Oarbank coordinator CA {fleet_id}")])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(_now() - dt.timedelta(minutes=5))
            .not_valid_after(_now() + dt.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(ski, critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
            .sign(key, hashes.SHA256()))
    _write_key(d / "ca.key", key)
    (d / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def _ca(home):
    d = tls_dir(home)
    return x509.load_pem_x509_certificate((d / "ca.pem").read_bytes()), _load_key(d / "ca.key")


def ca_pem(home) -> str:
    return (tls_dir(home) / "ca.pem").read_text(encoding="utf-8")


def pins(home) -> dict:
    """What the identity payload binds: the CA's SPKI hash (and a successor's during a rotation)."""
    d = tls_dir(home)
    ca = x509.load_pem_x509_certificate((d / "ca.pem").read_bytes())
    nxt = d / "ca-next.pem"
    return {"ca_spki_sha256": spki_sha256(ca),
            "ca_next_spki_sha256": spki_sha256(x509.load_pem_x509_certificate(nxt.read_bytes())) if nxt.exists() else None}


def _leaf(subject_cn: str, public_key, ca_cert, ca_key, days: int, san: list, eku) -> x509.Certificate:
    return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Oarbank"),
                                     x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
            .issuer_name(ca_cert.subject).public_key(public_key).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=5)).not_valid_after(_now() + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))


def _san_entries(names: list[str]) -> list:
    out, seen = [], set()
    for n in names:
        n = (n or "").strip().strip("[]")
        if not n or n in seen:
            continue
        seen.add(n)
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))
    return out


def ensure_server_cert(home, names: list[str]) -> tuple[Path, Path]:
    """(cert, key) paths for the agent listener, issued for `names` (host names and addresses)."""
    d = tls_dir(home)
    ca_cert, ca_key = _ca(home)
    want = sorted({n.strip().strip("[]") for n in names if n and n.strip()} | {"127.0.0.1", "localhost"})
    meta = d / "server.json"
    if (d / "server.pem").exists() and meta.exists():
        m = json.loads(meta.read_text(encoding="utf-8"))
        cert = x509.load_pem_x509_certificate((d / "server.pem").read_bytes())
        if m.get("names") == want and cert.not_valid_after_utc - _now() > dt.timedelta(days=30) \
                and m.get("ca") == spki_sha256(ca_cert):
            return d / "server.pem", d / "server.key"
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _leaf("oarbankd agent listener", key.public_key(), ca_cert, ca_key, SERVER_DAYS, _san_entries(want),
                 ExtendedKeyUsageOID.SERVER_AUTH)
    _write_key(d / "server.key", key)
    (d / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM))
    meta.write_text(json.dumps({"names": want, "ca": spki_sha256(ca_cert)}), encoding="utf-8", newline="\n")
    return d / "server.pem", d / "server.key"


def issue_client(home, csr_pem: str, node_id: str, days: int = CLIENT_DAYS) -> dict:
    """A client certificate for a node from its CSR: {cert_pem, fingerprint, not_after}. Only P-256 keys."""
    try:
        csr = x509.load_pem_x509_csr((csr_pem or "").encode())
    except ValueError as e:
        raise CAError(f"not a PEM certificate request: {e}")
    if not csr.is_signature_valid:
        raise CAError("the certificate request's signature does not verify")
    pk = csr.public_key()
    if not isinstance(pk, ec.EllipticCurvePublicKey) or pk.curve.name != "secp256r1":
        raise CAError("the node key must be ECDSA P-256 (Ed25519 TLS certificates fail in SChannel and Apple's TLS)")
    ca_cert, ca_key = _ca(home)
    cert = _leaf(node_id, pk, ca_cert, ca_key, days, [x509.UniformResourceIdentifier(NODE_URI + node_id)],
                 ExtendedKeyUsageOID.CLIENT_AUTH)
    der = cert.public_bytes(serialization.Encoding.DER)
    return {"cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode(), "fingerprint": fingerprint(der),
            "not_after": cert.not_valid_after_utc.timestamp(), "ca_pem": ca_pem(home)}


def node_of(der: bytes) -> str | None:
    """The node id a client certificate names (its SAN URI), or None."""
    try:
        cert = x509.load_der_x509_certificate(der)
        uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.UniformResourceIdentifier)
    except (ValueError, x509.ExtensionNotFound):
        return None
    ids = [u[len(NODE_URI):] for u in uris if u.startswith(NODE_URI)]
    return ids[0] if len(ids) == 1 else None


def client_context(ca_pem: str, pins: list[str]) -> ssl.SSLContext:
    """A TLS client context trusting only a coordinator CA whose SPKI hash is one of `pins` (host names are not
    checked: the private CA is the authentication, and coordinators are reached by changing addresses)."""
    ca = x509.load_pem_x509_certificate(ca_pem.encode())
    if spki_sha256(ca) not in [p.lower() for p in pins if p]:
        raise CAError("the peer's CA is not the pinned one")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=ca_pem)
    return ctx


def fetch_ca(url: str, pin: str) -> str:
    """The CA a coordinator at `url` offers (unverified TLS, a nonce only), accepted only if it matches `pin`."""
    import httpx
    import secrets
    r = httpx.get(f"{url.rstrip('/')}/v1/identity", params={"nonce": secrets.token_hex(8)}, verify=False, timeout=15)
    r.raise_for_status()
    ca_pem = r.json().get("ca_pem") or ""
    if not ca_pem or spki_sha256(x509.load_pem_x509_certificate(ca_pem.encode())) != (pin or "").lower():
        raise CAError(f"{url} offers a CA that does not match the pin {pin[:16]}")
    return ca_pem


def trust_adopted_ca(home, ca_pem: str):
    """A coordinator that took a fleet over in a rescue (rescue.py) keeps the old coordinator's CA certificate to
    verify the client certificates its nodes hold until they renew under this CA; it never issues with it, and a node
    is still its current certificate's fingerprint (core.auth_cert)."""
    x509.load_pem_x509_certificate(ca_pem.encode())
    (tls_dir(home) / "adopted-ca.pem").write_text(ca_pem, encoding="utf-8", newline="\n")


def client_cas(home) -> Path:
    """The CA certificates client certificates are verified against: this CA, and an adopted one (trust_adopted_ca)."""
    d = tls_dir(home)
    if not (d / "adopted-ca.pem").exists():
        return d / "ca.pem"
    (d / "client-cas.pem").write_text((d / "ca.pem").read_text(encoding="utf-8") + (d / "adopted-ca.pem").read_text(encoding="utf-8"),
                                      encoding="utf-8", newline="\n")
    return d / "client-cas.pem"


def server_context(home, names: list[str]) -> dict:
    """uvicorn ssl options: the server certificate, client certificates optional (enrollment has none) but verified
    against the CA (client_cas) when presented."""
    cert, key = ensure_server_cert(home, names)
    return {"ssl_certfile": str(cert), "ssl_keyfile": str(key), "ssl_ca_certs": str(client_cas(home)),
            "ssl_cert_reqs": ssl.CERT_OPTIONAL}
