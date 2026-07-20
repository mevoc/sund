"""System tests for key bundles — the per-device dead-drop for async pairing.

A device publishes an opaque prekey bundle; another device in the account fetches
it verbatim to establish a session with an offline peer. The server stores and
serves bytes and never interprets them.
"""

import httpx
import pytest
from nacl.public import PrivateKey
from nacl.signing import SigningKey

import beaconsim


def _fake_prekey_bundle() -> bytes:
    # Shape-of-a-real-bundle: an identity key, a signed prekey, and a signature.
    # The server never parses this — it is opaque bytes to Sund.
    identity = SigningKey.generate()
    signed_prekey = bytes(PrivateKey.generate().public_key)
    sig = identity.sign(signed_prekey).signature
    return bytes(identity.verify_key) + signed_prekey + sig


def test_publish_and_fetch_bundle(sund_server, new_account):
    _, token = new_account()
    alice = beaconsim.register_device(sund_server.base_url, token)
    bob = beaconsim.register_device(sund_server.base_url, alice.create_invitation().token)

    bundle = _fake_prekey_bundle()
    alice.publish_bundle(bundle)

    # Bob fetches Alice's bundle byte-for-byte (he could now pair while she's offline).
    assert bob.get_bundle(alice.device_id) == bundle


def test_bundle_is_replaced_on_republish(sund_server, new_account):
    _, token = new_account()
    alice = beaconsim.register_device(sund_server.base_url, token)

    alice.publish_bundle(b"first-bundle")
    alice.publish_bundle(b"second-bundle")
    assert alice.get_bundle(alice.device_id) == b"second-bundle"


def test_fetch_missing_bundle_404(sund_server, new_account):
    _, token = new_account()
    alice = beaconsim.register_device(sund_server.base_url, token)
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        alice.get_bundle(alice.device_id)
    assert excinfo.value.response.status_code == 404


def test_bundle_is_account_scoped(sund_server, new_account):
    _, token_a = new_account()
    alice = beaconsim.register_device(sund_server.base_url, token_a)
    alice.publish_bundle(_fake_prekey_bundle())

    _, token_other = new_account()
    stranger = beaconsim.register_device(sund_server.base_url, token_other)
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        stranger.get_bundle(alice.device_id)
    assert excinfo.value.response.status_code == 404


def test_revocation_clears_bundle(sund_server, new_account):
    _, token = new_account()
    alice = beaconsim.register_device(sund_server.base_url, token)
    bob = beaconsim.register_device(sund_server.base_url, alice.create_invitation().token)
    bob.publish_bundle(_fake_prekey_bundle())

    alice.revoke_device(bob.device_id)
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        alice.get_bundle(bob.device_id)
    assert excinfo.value.response.status_code == 404
