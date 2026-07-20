"""System tests for the transport plane: blind queues and E2E-encrypted payloads.

The server routes sealed envelopes it cannot open. These tests send real
SealedBox ciphertext through a queue, decrypt it only on the recipient, and
assert the server both delivers it and never holds the plaintext.
"""

import base64

import httpx
import pytest
from nacl.public import PrivateKey

import beaconsim

LOCATION = b'{"lat":55.6053,"lon":13.0038,"acc":8}'


def _pair(sund_server, new_account):
    """Register a device, create a queue, and return (queue, sender)."""
    _, token = new_account()
    device = beaconsim.register_device(sund_server.base_url, token)
    queue = device.create_queue()
    sender = beaconsim.Sender(sund_server.base_url, queue.sender_id, queue.encryption_public_key)
    return queue, sender


def test_send_recv_ack_roundtrip(sund_server, new_account):
    queue, sender = _pair(sund_server, new_account)

    sender.send(LOCATION, ttl=60)
    received = queue.recv()
    assert len(received) == 1
    assert received[0]["plaintext"] == LOCATION

    queue.ack([m["id"] for m in received])
    assert queue.recv() == []


def test_offline_receiver_gets_backlog(sund_server, new_account):
    # Messages queue while the receiver is "offline" and drain on return.
    queue, sender = _pair(sund_server, new_account)
    sender.send(b"first", ttl=60)
    sender.send(b"second", ttl=60)

    plaintexts = [m["plaintext"] for m in queue.recv()]
    assert plaintexts == [b"first", b"second"]


def test_first_send_binds_sender_key(sund_server, new_account):
    queue, sender = _pair(sund_server, new_account)
    sender.send(b"legit", ttl=60)

    # A different party cannot send into the now-bound queue.
    impostor = beaconsim.Sender(sund_server.base_url, queue.sender_id, queue.encryption_public_key)
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        impostor.send(b"forged", ttl=60)
    assert excinfo.value.response.status_code == 401


def test_send_to_unknown_queue_rejected(sund_server, new_account):
    # A syntactically valid but nonexistent sender id.
    enc_pub = bytes(PrivateKey.generate().public_key)
    sender = beaconsim.Sender(sund_server.base_url, "snd_deadbeef", enc_pub)
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        sender.send(b"x", ttl=60)
    assert excinfo.value.response.status_code == 404


def test_recv_requires_recipient_key(sund_server, new_account):
    queue, sender = _pair(sund_server, new_account)
    sender.send(LOCATION, ttl=60)

    # Tamper with the queue's auth key; the server must reject the drain.
    from nacl.signing import SigningKey

    queue.auth_key = SigningKey.generate()
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        queue.recv()
    assert excinfo.value.response.status_code == 401


def test_retire_stops_delivery(sund_server, new_account):
    queue, sender = _pair(sund_server, new_account)
    sender.send(b"before", ttl=60)
    queue.retire()

    # The queue is gone: a fresh sender to the same id is refused.
    late = beaconsim.Sender(sund_server.base_url, queue.sender_id, queue.encryption_public_key)
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        late.send(b"after", ttl=60)
    assert excinfo.value.response.status_code == 404


def test_server_stores_only_ciphertext(sund_server, new_account):
    # The blindness invariant, as an executable check (seed of S8).
    marker = b"TOPSECRET-LOCATION-55.60531-13.00382"
    queue, sender = _pair(sund_server, new_account)
    sender.send(marker, ttl=3600)

    # Leave the message unacked so it is still stored, then read the raw files.
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        path = sund_server.db_path.with_name(sund_server.db_path.name + suffix)
        if path.exists():
            blob += path.read_bytes()

    assert marker not in blob, "plaintext must never touch the server's storage"

    # And the ciphertext really is there to be delivered.
    received = queue.recv()
    assert received[0]["plaintext"] == marker
