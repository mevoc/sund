"""System tests for device revocation (implementation guide, S5 — stolen phone).

Revoking a device kills its identity, retires its owned queues, and wakes the
account's peers to refetch. The revoked device's cached credentials open nothing.
"""

import httpx
import pytest

import beaconsim


def _account_with_two_devices(sund_server, new_account, push_sink):
    """A (with a push endpoint) and B, in one account. Returns (a, b)."""
    _, token = new_account()
    a = beaconsim.register_device(sund_server.base_url, token, push_endpoint=push_sink.url())
    token_b = a.create_invitation().token
    b = beaconsim.register_device(sund_server.base_url, token_b)
    # Drain the ping from B's registration so later assertions see only revoke.
    push_sink.wait_for(1)
    push_sink.received.clear()
    return a, b


def test_revoke_disables_device_and_queues(sund_server, new_account, push_sink):
    a, b = _account_with_two_devices(sund_server, new_account, push_sink)
    queue_b = b.create_queue()

    a.revoke_device(b.device_id)

    # B's signed management requests now fail.
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        b.list_devices()
    assert excinfo.value.response.status_code == 401

    # B's owned queue is gone: draining it 404s.
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        queue_b.recv()
    assert excinfo.value.response.status_code == 404


def test_revoke_pings_peers(sund_server, new_account, push_sink):
    a, b = _account_with_two_devices(sund_server, new_account, push_sink)

    a.revoke_device(b.device_id)

    assert push_sink.wait_for(1), "peers were not pinged on revocation"
    assert push_sink.received[-1]["body"] == b""


def test_revoked_device_shown_as_revoked_in_list(sund_server, new_account, push_sink):
    a, b = _account_with_two_devices(sund_server, new_account, push_sink)

    a.revoke_device(b.device_id)

    devices = {d["id"]: d for d in a.list_devices()}
    assert b.device_id in devices, "revoked device should stay visible in the list"
    assert devices[b.device_id]["revoked"] is True


def test_messages_to_revoked_queue_refused(sund_server, new_account, push_sink):
    a, b = _account_with_two_devices(sund_server, new_account, push_sink)
    queue_b = b.create_queue()
    sender = beaconsim.Sender(sund_server.base_url, queue_b.sender_id, queue_b.encryption_public_key)
    sender.send(b"before-revoke", ttl=60)

    a.revoke_device(b.device_id)

    # A fresh sender to the (now retired) queue is refused.
    late = beaconsim.Sender(sund_server.base_url, queue_b.sender_id, queue_b.encryption_public_key)
    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        late.send(b"after-revoke", ttl=60)
    assert excinfo.value.response.status_code == 404


def test_cross_account_revoke_forbidden(sund_server, new_account, push_sink):
    a, _ = _account_with_two_devices(sund_server, new_account, push_sink)

    # A device in a different account.
    _, other_token = new_account()
    stranger = beaconsim.register_device(sund_server.base_url, other_token)

    with pytest.raises(httpx.HTTPStatusError) as excinfo:
        a.revoke_device(stranger.device_id)
    assert excinfo.value.response.status_code == 404

    # The stranger is untouched: it can still make signed requests.
    assert stranger.list_devices()  # does not raise
