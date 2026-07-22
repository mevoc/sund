"""Server-fingerprint pinning for a sund:// address.

This mirrors the client half of Sund's trust model (PRD, Server address): the
address carries the SHA-256 of the offline CA's public key, delivered out of band
(QR). The client connects, reads the presented certificate chain, and accepts the
server only if a presented certificate's SPKI fingerprint matches the pin — so a
first-connect MITM presenting a different cert is detected, not trusted.

Python 3.12's stdlib ssl cannot expose the peer chain, so this uses pyOpenSSL to
read it; once the CA is pinned, ordinary verification proceeds against it.
"""

from __future__ import annotations

import hashlib
import socket
import ssl

from OpenSSL import SSL, crypto


class PinError(Exception):
    """Raised when no presented certificate matches the pinned fingerprint."""


def parse_address(address: str) -> tuple[str, int, str]:
    """Split 'sund://host:port#fingerprint' into (host, port, fingerprint)."""
    if not address.startswith("sund://"):
        raise ValueError("not a sund:// address")
    rest = address[len("sund://"):]
    netloc, _, fingerprint = rest.partition("#")
    host, _, port = netloc.partition(":")
    if not host or not port or not fingerprint:
        raise ValueError(f"malformed sund:// address: {address!r}")
    return host, int(port), fingerprint


def _spki_fingerprint(cert) -> str:
    # DER of the SubjectPublicKeyInfo — matches Go's cert.RawSubjectPublicKeyInfo.
    spki_der = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())
    return hashlib.sha256(spki_der).hexdigest()


def _fetch_pinned_ca_pem(host: str, port: int, fingerprint: str, timeout: float = 5.0) -> str:
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *_: True)  # we pin manually below
    with socket.create_connection((host, port), timeout=timeout) as sock:
        # A timeout socket is non-blocking; switch to blocking for the handshake.
        sock.settimeout(None)
        conn = SSL.Connection(ctx, sock)
        conn.set_connect_state()
        try:
            conn.set_tlsext_host_name(host.encode())
        except Exception:
            pass
        conn.do_handshake()
        chain = conn.get_peer_cert_chain() or []
        try:
            conn.shutdown()
        except SSL.Error:
            pass
    for cert in chain:
        if _spki_fingerprint(cert) == fingerprint:
            return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
    raise PinError("no presented certificate matches the pinned fingerprint")


def pinned_context(host: str, port: int, fingerprint: str) -> ssl.SSLContext:
    """Return an SSLContext that trusts only the CA pinned by fingerprint."""
    ca_pem = _fetch_pinned_ca_pem(host, port, fingerprint)
    context = ssl.create_default_context(cadata=ca_pem)
    context.check_hostname = False  # identity is the pinned key, not the hostname
    return context


def connect(address: str) -> tuple[str, ssl.SSLContext]:
    """Resolve a sund:// address to (base_url, ssl_context) for pinned requests."""
    host, port, fingerprint = parse_address(address)
    return f"https://{host}:{port}", pinned_context(host, port, fingerprint)
