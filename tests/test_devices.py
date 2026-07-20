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
