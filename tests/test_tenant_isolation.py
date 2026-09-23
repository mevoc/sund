"""System scenario S7 — what an account isolates, and what it does not.

The management plane is account-scoped. The transport plane is not: neither a
send nor a receive consults an account, so a queue is protected by its keys
rather than by its tenancy (PRD 0.7, decision 15).

These assertions run in both directions on purpose. A future change that
introduced tenancy filtering on the transport plane would have to record a
sender-to-account link, which is exactly what the S8 blindness audit exists to
prove absent — so the positive assertion below is a blindness regression test,
not merely a description.
"""

import base64
import json

import httpx
from nacl.public import PublicKey, SealedBox
from nacl.signing import SigningKey

import beaconsim
from beaconsim.client import HEADER_DEVICE_ID, HEADER_SENDER_KEY, sign_headers

PAYLOAD = b'{"lat":55.6053,"lon":13.0038,"acc":8}'


def test_management_plane_is_account_scoped(sund_server, new_account):
    """Device lists and bundle fetches do not cross an account boundary."""
    _, token_a = new_account()
    _, token_b = new_account()
    device_a = beaconsim.register_device(sund_server.base_url, token_a)
    device_b = beaconsim.register_device(sund_server.base_url, token_b)

    assert [d["id"] for d in device_a.list_devices()] == [device_a.device_id]
    assert [d["id"] for d in device_b.list_devices()] == [device_b.device_id]

    device_b.publish_bundle(b"b-prekeys")
    r = device_a.get(f"/v1/devices/{device_b.device_id}/bundle")
    assert r.status_code == 404, "a bundle must not be fetchable across accounts"


def test_cross_account_send_succeeds(sund_server, new_account):
    """The transport plane consults no account: B sends into A's queue.

    This is asserted positively. If it ever starts failing, the server has begun
    checking a tenancy fact it must not be storing.
    """
    _, token_a = new_account()
    _, token_b = new_account()
    device_a = beaconsim.register_device(sund_server.base_url, token_a)
    beaconsim.register_device(sund_server.base_url, token_b)

    queue = device_a.create_queue()

    # Account B's side holds only what A handed over out of band: the sender id
    # and the encryption public key. It never presents a device id.
    sender = beaconsim.Sender(
        sund_server.base_url, queue.sender_id, queue.encryption_public_key
    )
    sender.send(PAYLOAD, ttl=60)

    received = queue.recv()
    assert len(received) == 1
    assert received[0]["plaintext"] == PAYLOAD


def test_send_needs_no_account_at_all(sund_server, new_account):
    """A sender that never enrolled can send. It holds a credential, not an identity."""
    _, token_a = new_account()
    device_a = beaconsim.register_device(sund_server.base_url, token_a)
    queue = device_a.create_queue()

    stranger = beaconsim.Sender(
        sund_server.base_url, queue.sender_id, queue.encryption_public_key
    )
    stranger.send(PAYLOAD, ttl=60)

    assert queue.recv()[0]["plaintext"] == PAYLOAD


def test_read_is_gated_by_the_key_not_the_account(sund_server, new_account):
    """A second device in the *same* account cannot read a queue it does not own.

    The mirror of the send case: reads fail for want of the recipient key, which
    is why "cross-account reads fail" was never a tenancy guarantee.
    """
    _, token_a = new_account()
    device_a = beaconsim.register_device(sund_server.base_url, token_a)
    queue = device_a.create_queue()

    # A second device, same account, with its own identity but not the queue's key.
    invitation = device_a.create_invitation()
    device_a2 = beaconsim.register_device(sund_server.base_url, invitation.token)
    assert len(device_a2.list_devices()) == 2, "both devices share one account"

    path = f"/v1/recv/{queue.recipient_id}"
    r = httpx.get(
        sund_server.base_url + path,
        headers=sign_headers(device_a2.signing_key, "GET", path, b""),
    )
    assert r.status_code == 401, "the recipient key gates the read, not the account"


def test_first_send_binds_and_a_second_key_is_refused(sund_server, new_account):
    """An unbound queue is claimed by whoever presents a key first."""
    _, token = new_account()
    device = beaconsim.register_device(sund_server.base_url, token)
    queue = device.create_queue()

    first = beaconsim.Sender(
        sund_server.base_url, queue.sender_id, queue.encryption_public_key
    )
    first.send(PAYLOAD, ttl=60)

    # An interloper with the same sender id but a different key is refused.
    path = f"/v1/send/{queue.sender_id}"
    body = json.dumps({"payload": base64.b64encode(b"x" * 32).decode(), "ttl": 60}).encode()
    other_key = SigningKey.generate()
    headers = sign_headers(other_key, "POST", path, body)
    headers[HEADER_SENDER_KEY] = base64.b64encode(bytes(other_key.verify_key)).decode()
    r = httpx.post(sund_server.base_url + path, headers=headers, content=body)
    assert r.status_code == 401, "a bound queue must refuse a second sender key"

    assert len(queue.recv()) == 1, "only the bound sender's message is stored"


def test_send_is_not_filtered_on_a_volunteered_device_id(sund_server, new_account):
    """A send that volunteers a device id is still authorized by the queue key alone.

    The two cases above are wire-identical — a Sender presents no identity either
    way — so on their own they pin only "an unidentified sender can send". This
    one closes the gap the other direction: a future filter that refused senders
    which *do* identify themselves would be building the sender-to-account link
    S8 forbids, and would fail here first.
    """
    _, token_a = new_account()
    _, token_b = new_account()
    device_a = beaconsim.register_device(sund_server.base_url, token_a)
    device_b = beaconsim.register_device(sund_server.base_url, token_b)
    queue = device_a.create_queue()

    ciphertext = SealedBox(PublicKey(queue.encryption_public_key)).encrypt(PAYLOAD)
    body = json.dumps(
        {"payload": base64.b64encode(bytes(ciphertext)).decode(), "ttl": 60}
    ).encode()
    path = f"/v1/send/{queue.sender_id}"

    sender_key = SigningKey.generate()
    headers = sign_headers(sender_key, "POST", path, body)
    headers[HEADER_SENDER_KEY] = base64.b64encode(bytes(sender_key.verify_key)).decode()
    # Volunteered, and from a different account than the queue's owner.
    headers[HEADER_DEVICE_ID] = device_b.device_id

    r = httpx.post(sund_server.base_url + path, headers=headers, content=body)
    assert r.status_code == 202, (
        "the server must ignore a volunteered device id on send, not filter on it"
    )
    assert queue.recv()[0]["plaintext"] == PAYLOAD
