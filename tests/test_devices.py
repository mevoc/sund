"""System tests for device registration and signed device listing.

This is where beaconsim starts doing real crypto against the real binary: each
device generates an Ed25519 identity, enrolls with a one-time token, and signs
its subsequent management-plane requests. The server can verify but never
decrypt — exactly the blindness the whole design turns on.
"""

import base64

import httpx
import pytest
from nacl.signing import SigningKey

import beaconsim


def test_register_and_list_self(sund_server, new_account):
    _, token = new_account()
    client = beaconsim.register_device(sund_server.base_url, token, push_endpoint="https://ntfy/x")

    devices = client.list_devices()
    assert len(devices) == 1
    assert devices[0]["id"] == client.device_id
    assert devices[0]["public_key"] == client.public_key_b64
    # A device reads back its own endpoint; a peer's is withheld (see below).
    assert devices[0]["push_endpoint"] == "https://ntfy/x"


def test_invitation_is_single_use(sund_server, new_account):
    _, token = new_account()
    beaconsim.register_device(sund_server.base_url, token)

    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        beaconsim.register_device(sund_server.base_url, token)
    assert excinfo.value.response.status_code == 401


def test_second_device_appears_in_list(sund_server, new_account):
    # One account; the first device invites a second (Walkthrough 2, step 1).
    _, token_a = new_account()
    client_a = beaconsim.register_device(sund_server.base_url, token_a)
    token_b = client_a.create_invitation().token
    client_b = beaconsim.register_device(sund_server.base_url, token_b)

    ids_seen_by_a = {d["id"] for d in client_a.list_devices()}
    assert ids_seen_by_a == {client_a.device_id, client_b.device_id}


def test_unsigned_request_is_rejected(sund_server, new_account):
    _, token = new_account()
    client = beaconsim.register_device(sund_server.base_url, token)

    # No signature headers at all.
    r = httpx.get(f"{client.base_url}/v1/devices")
    assert r.status_code == 401


def test_forged_signature_is_rejected(sund_server, new_account):
    _, token = new_account()
    client = beaconsim.register_device(sund_server.base_url, token)

    # Swap in a key the server never registered; the device id stays valid.
    client.signing_key = SigningKey.generate()
    r = client.get("/v1/devices")
    assert r.status_code == 401


def test_cross_account_isolation(sund_server, new_account):
    _, token_a = new_account()
    _, token_b = new_account()
    client_a = beaconsim.register_device(sund_server.base_url, token_a)
    beaconsim.register_device(sund_server.base_url, token_b)

    # Account A's device must see only account A (itself), not B's device.
    devices = client_a.list_devices()
    assert len(devices) == 1
    assert devices[0]["id"] == client_a.device_id


def test_push_endpoint_is_self_only(sund_server, new_account):
    """A peer's wake-up URL is a capability, not a fact about it.

    On a bearer-URL distributor — a default ntfy topic is one — holding a peer's
    endpoint is the ability to wake or spam that device, outside Sund entirely
    and beyond the reach of revocation or quota. No client needs a peer's
    endpoint, since pings are the server's to send, so it is returned only to the
    device that set it (PRD, decision 20).
    """
    _, token = new_account()
    a = beaconsim.register_device(
        sund_server.base_url, token, push_endpoint="https://ntfy.example/a"
    )
    b = beaconsim.register_device(
        sund_server.base_url,
        a.create_invitation().token,
        push_endpoint="https://ntfy.example/b",
    )

    by_id = {d["id"]: d for d in a.list_devices()}
    assert by_id[a.device_id].get("push_endpoint") == "https://ntfy.example/a", (
        "a device must still be able to read back its own endpoint"
    )
    assert not by_id[b.device_id].get("push_endpoint"), (
        "a peer's wake-up URL must not be readable"
    )

    # And symmetrically from B's side.
    by_id = {d["id"]: d for d in b.list_devices()}
    assert by_id[b.device_id].get("push_endpoint") == "https://ntfy.example/b"
    assert not by_id[a.device_id].get("push_endpoint")
