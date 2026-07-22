"""Client-side crypto and request signing for the Sund system suite.

Mirrors internal/sigauth: a device signs, with its Ed25519 identity key, the
newline-joined tuple METHOD, PATH, TIMESTAMP, NONCE, hex(sha256(BODY)). The
server verifies against the public key it stored at registration.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey


@dataclass
class Invitation:
    """A freshly minted invitation: the secret token, plus the non-secret id and
    expiry used to list or revoke it later."""

    token: str
    id: str
    expires: str

HEADER_DEVICE_ID = "Sund-Device-Id"
HEADER_TIMESTAMP = "Sund-Timestamp"
HEADER_NONCE = "Sund-Nonce"
HEADER_SIGNATURE = "Sund-Signature"
HEADER_SENDER_KEY = "Sund-Sender-Key"


def _now_rfc3339() -> str:
    # Second precision, always 'Z' — must match Go's time.RFC3339 in UTC.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def signing_string(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method, path, timestamp, nonce, body_hash]).encode()


def sign_headers(signing_key: SigningKey, method: str, path: str, body: bytes) -> dict[str, str]:
    """Build the timestamp/nonce/signature headers for a signed request.

    Used by both planes; the management plane adds a device-id header on top.
    """
    ts = _now_rfc3339()
    nonce = secrets.token_hex(16)
    sig = signing_key.sign(signing_string(method, path, ts, nonce, body)).signature
    return {
        HEADER_TIMESTAMP: ts,
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: base64.b64encode(sig).decode(),
    }


class Client:
    """An enrolled device: its identity key plus signed-request helpers."""

    def __init__(self, base_url: str, device_id: str, signing_key: SigningKey, verify=True):
        self.base_url = base_url.rstrip("/")
        self.device_id = device_id
        self.signing_key = signing_key
        # verify: True (default), or a pinned ssl.SSLContext for a TLS server.
        self._verify = verify

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(bytes(self.signing_key.verify_key)).decode()

    def _headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        return {
            HEADER_DEVICE_ID: self.device_id,
            **sign_headers(self.signing_key, method, path, body),
        }

    def _request(self, method: str, path: str, body: bytes = b"") -> httpx.Response:
        return httpx.request(
            method,
            self.base_url + path,
            headers=self._headers(method, path, body),
            content=body,
            verify=self._verify,
        )

    def get(self, path: str) -> httpx.Response:
        return self._request("GET", path)

    def list_devices(self) -> list[dict]:
        r = self.get("/v1/devices")
        r.raise_for_status()
        return r.json()["devices"]

    def create_invitation(self) -> Invitation:
        """Mint a single-use token to pair another device into this account."""
        r = self._request("POST", "/v1/invitations")
        r.raise_for_status()
        data = r.json()
        return Invitation(
            token=data["invitation_token"],
            id=data["invitation_id"],
            expires=data["expires"],
        )

    def list_invitations(self) -> list[dict]:
        """Return the account's outstanding invitations (ids and expiries)."""
        r = self._request("GET", "/v1/invitations")
        r.raise_for_status()
        return r.json()["invitations"]

    def revoke_invitation(self, invitation_id: str) -> None:
        """Kill a mis-shared invitation before it is used."""
        r = self._request("POST", f"/v1/invitations/{invitation_id}/revoke")
        r.raise_for_status()

    def set_push_endpoint(self, endpoint: str) -> None:
        """Register this device's wake-up endpoint (e.g. a UnifiedPush URL)."""
        body = json.dumps({"push_endpoint": endpoint}).encode()
        r = self._request("PUT", "/v1/me/push", body)
        r.raise_for_status()

    def revoke_device(self, device_id: str) -> None:
        """Revoke a device in this account (e.g. a lost or stolen phone)."""
        r = self._request("POST", f"/v1/devices/{device_id}/revoke")
        r.raise_for_status()

    def publish_bundle(self, blob: bytes) -> None:
        """Publish this device's opaque key bundle (a dead-drop for async pairing)."""
        body = json.dumps({"bundle": base64.b64encode(blob).decode()}).encode()
        r = self._request("PUT", "/v1/me/bundle", body)
        r.raise_for_status()

    def get_bundle(self, device_id: str) -> bytes:
        """Fetch a peer device's published key bundle, verbatim."""
        r = self._request("GET", f"/v1/devices/{device_id}/bundle")
        r.raise_for_status()
        return base64.b64decode(r.json()["bundle"])

    def create_queue(self) -> "Queue":
        """Create a blind queue owned by this device.

        Generates two fresh per-queue keys: an Ed25519 auth key that signs
        recv/ack/retire, and an X25519 key whose public half is handed to the
        sender out of band so it can encrypt payloads only this device can read.
        """
        auth_key = SigningKey.generate()
        enc_key = PrivateKey.generate()
        body = json.dumps(
            {"recipient_key": base64.b64encode(bytes(auth_key.verify_key)).decode()}
        ).encode()
        r = self._request("POST", "/v1/queues", body)
        r.raise_for_status()
        data = r.json()
        return Queue(self.base_url, data["recipient_id"], data["sender_id"],
                     auth_key, enc_key, verify=self._verify)


class Queue:
    """The owner (recipient) side of a blind queue."""

    def __init__(self, base_url: str, recipient_id: str, sender_id: str,
                 auth_key: SigningKey, enc_key: PrivateKey, verify=True):
        self.base_url = base_url.rstrip("/")
        self.recipient_id = recipient_id
        self.sender_id = sender_id
        self.auth_key = auth_key
        self.enc_key = enc_key
        self._verify = verify

    @property
    def encryption_public_key(self) -> bytes:
        """The X25519 public key a sender encrypts payloads to (shared out of band)."""
        return bytes(self.enc_key.public_key)

    def _request(self, method: str, path: str, body: bytes = b"") -> httpx.Response:
        return httpx.request(
            method,
            self.base_url + path,
            headers=sign_headers(self.auth_key, method, path, body),
            content=body,
            verify=self._verify,
        )

    def recv(self) -> list[dict]:
        """Drain the queue, decrypting each payload locally."""
        r = self._request("GET", f"/v1/recv/{self.recipient_id}")
        r.raise_for_status()
        box = SealedBox(self.enc_key)
        return [
            {"id": m["id"], "plaintext": box.decrypt(base64.b64decode(m["payload"]))}
            for m in r.json()["messages"]
        ]

    def ack(self, ids: list[str]) -> int:
        body = json.dumps({"ids": ids}).encode()
        r = self._request("POST", f"/v1/ack/{self.recipient_id}", body)
        r.raise_for_status()
        return r.json()["deleted"]

    def retire(self) -> None:
        r = self._request("POST", f"/v1/retire/{self.recipient_id}")
        r.raise_for_status()


class Sender:
    """The sending side of a blind queue: it knows only the sender id and the
    recipient's encryption public key, both handed over out of band. Its per-queue
    key is bound on the first send."""

    def __init__(self, base_url: str, sender_id: str, recipient_enc_pubkey: bytes, verify=True):
        self.base_url = base_url.rstrip("/")
        self.sender_id = sender_id
        self._box = SealedBox(PublicKey(recipient_enc_pubkey))
        self._key = SigningKey.generate()
        self._bound = False
        self._verify = verify

    def send(self, plaintext: bytes, ttl: int = 60, priority: bool = False) -> str:
        ciphertext = bytes(self._box.encrypt(plaintext))
        body = json.dumps(
            {"payload": base64.b64encode(ciphertext).decode(), "ttl": ttl, "priority": priority}
        ).encode()
        path = f"/v1/send/{self.sender_id}"
        headers = sign_headers(self._key, "POST", path, body)
        if not self._bound:
            headers[HEADER_SENDER_KEY] = base64.b64encode(bytes(self._key.verify_key)).decode()
        r = httpx.post(self.base_url + path, headers=headers, content=body, verify=self._verify)
        r.raise_for_status()
        self._bound = True
        return r.json()["message_id"]


def register_device(
    base_url: str,
    token: str,
    push_endpoint: str = "",
    capabilities: str = "",
    verify=True,
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
        verify=verify,
    )
    r.raise_for_status()
    return Client(base_url, r.json()["device_id"], signing_key, verify=verify)
