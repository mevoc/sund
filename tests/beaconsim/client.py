"""Client-side crypto and request signing for the Sund system suite.

Mirrors internal/sigauth: a device signs, with its Ed25519 identity key, the
newline-joined tuple METHOD, PATH, TIMESTAMP, NONCE, hex(sha256(BODY)). The
server verifies against the public key it stored at registration.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timezone

import httpx
from nacl.signing import SigningKey

HEADER_DEVICE_ID = "Sund-Device-Id"
HEADER_TIMESTAMP = "Sund-Timestamp"
HEADER_NONCE = "Sund-Nonce"
HEADER_SIGNATURE = "Sund-Signature"


def _now_rfc3339() -> str:
    # Second precision, always 'Z' — must match Go's time.RFC3339 in UTC.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def signing_string(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method, path, timestamp, nonce, body_hash]).encode()


class Client:
    """An enrolled device: its identity key plus signed-request helpers."""

    def __init__(self, base_url: str, device_id: str, signing_key: SigningKey):
        self.base_url = base_url.rstrip("/")
        self.device_id = device_id
        self.signing_key = signing_key

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(bytes(self.signing_key.verify_key)).decode()

    def _headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        ts = _now_rfc3339()
        nonce = secrets.token_hex(16)
        sig = self.signing_key.sign(signing_string(method, path, ts, nonce, body)).signature
        return {
            HEADER_DEVICE_ID: self.device_id,
            HEADER_TIMESTAMP: ts,
            HEADER_NONCE: nonce,
            HEADER_SIGNATURE: base64.b64encode(sig).decode(),
        }

    def _request(self, method: str, path: str, body: bytes = b"") -> httpx.Response:
        return httpx.request(
            method,
            self.base_url + path,
            headers=self._headers(method, path, body),
            content=body,
        )

    def get(self, path: str) -> httpx.Response:
        return self._request("GET", path)

    def list_devices(self) -> list[dict]:
        r = self.get("/v1/devices")
        r.raise_for_status()
        return r.json()["devices"]

    def create_invitation(self) -> str:
        """Mint a single-use token to pair another device into this account."""
        r = self._request("POST", "/v1/invitations")
        r.raise_for_status()
        return r.json()["invitation_token"]


def register_device(
    base_url: str,
    token: str,
    push_endpoint: str = "",
    capabilities: str = "",
) -> Client:
    """Generate a fresh identity and enroll it against a one-time token."""
    signing_key = SigningKey.generate()
    public_key = base64.b64encode(bytes(signing_key.verify_key)).decode()
    r = httpx.post(
        base_url.rstrip("/") + "/v1/devices/register",
        json={
            "token": token,
            "public_key": public_key,
            "push_endpoint": push_endpoint,
            "capabilities": capabilities,
        },
    )
    r.raise_for_status()
    return Client(base_url, r.json()["device_id"], signing_key)
