"""System scenario S11 — the three storage ceilings, and who may set each.

Account, device and queue ceilings are enforced together: a send is refused if
it would take any of them past its limit. The interesting properties are the
bulkheads (one channel filling leaves the others receiving) and the asymmetry in
who may write each level — the queue's owner may cap its own inbound channel,
but nobody may cap anyone else's over the API (PRD 0.10, decisions 13, 16, 17).
"""

import base64
import json

import httpx
from nacl.public import PublicKey, SealedBox
from nacl.signing import SigningKey

import beaconsim
from beaconsim.client import HEADER_SENDER_KEY, sign_headers

PAYLOAD = b"x" * 64


def _queue_and_sender(device):
    q = device.create_queue()
    return q, beaconsim.Sender(device.base_url, q.sender_id, q.encryption_public_key)


def test_queue_ceiling_is_a_bulkhead_between_peers(sund_server, new_account):
    """One peer filling its channel leaves the owner's other peers receiving."""
    _, token = new_account()
    device = beaconsim.register_device(sund_server.base_url, token)
    q1, peer1 = _queue_and_sender(device)
    q2, peer2 = _queue_and_sender(device)

    assert q1.set_quota(400).status_code == 200

    # Send until this channel is refused. Each payload stores more than 64 bytes
    # (SealedBox adds overhead), so a 400-byte ceiling takes a handful of sends.
    sent, refused = 0, None
    for _ in range(20):
        try:
            peer1.send(PAYLOAD)
            sent += 1
        except httpx.HTTPStatusError as exc:
            refused = exc.response
            break
    assert sent > 0, "the first send must fit under the ceiling"
    assert refused is not None, "the queue ceiling must eventually refuse"
    assert refused.status_code == 507

    # The bulkhead: the second peer's channel is untouched.
    peer2.send(PAYLOAD)
    assert len(q2.recv()) == 1


def test_refusal_does_not_name_the_level(sund_server, new_account):
    """A sender must not learn which of the three ceilings tripped."""
    _, token = new_account()
    device = beaconsim.register_device(sund_server.base_url, token)
    q, peer = _queue_and_sender(device)
    q.set_quota(1)

    try:
        peer.send(PAYLOAD)
        raise AssertionError("expected a refusal")
    except httpx.HTTPStatusError as exc:
        assert exc.response.status_code == 507
        body = exc.response.json()
        assert "account" not in json.dumps(body).lower(), (
            f"the refusal must not name a level: {body}"
        )


def test_only_the_owner_may_cap_a_queue(sund_server, new_account):
    """Not the sender, and not the owning device's identity key."""
    _, token = new_account()
    device = beaconsim.register_device(sund_server.base_url, token)
    q, _ = _queue_and_sender(device)
    path = f"/v1/quota/{q.recipient_id}"
    body = json.dumps({"quota_bytes": 1}).encode()

    # A freshly generated key is not the recipient key.
    stranger = SigningKey.generate()
    r = httpx.post(
        sund_server.base_url + path,
        headers=sign_headers(stranger, "POST", path, body),
        content=body,
    )
    assert r.status_code == 401

    # Nor is the owning device's identity key — this is a transport-plane route.
    r = httpx.post(
        sund_server.base_url + path,
        headers=sign_headers(device.signing_key, "POST", path, body),
        content=body,
    )
    assert r.status_code == 401, "a device signature must not authorize a queue write"


def test_own_quota_is_readable_and_peers_are_not(sund_server, new_account):
    """A device reads its own ceiling; the device list carries nobody's."""
    _, token = new_account()
    device = beaconsim.register_device(sund_server.base_url, token)
    q, peer = _queue_and_sender(device)
    peer.send(PAYLOAD)

    quota = device.get_quota()
    assert quota["quota_bytes"] == 0, "no device ceiling is set by default"
    assert quota["stored_bytes"] > 0, "the send should be counted"
    assert "account_stored_bytes" not in quota, (
        "account usage must never be exposed: it is a peer activity signal"
    )

    # Decision 16: no ceiling for any device appears in the list peers read.
    for entry in device.list_devices():
        assert "quota_bytes" not in entry, (
            f"a device ceiling must not be peer-readable: {entry}"
        )
