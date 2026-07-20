"""System tests for per-account storage quota.

Storage is capped per account and attributed to the queue owner's side. When the
cap is reached the server refuses new messages (507); draining and acking frees
space, and one account filling up never affects another.
"""

import httpx
import pytest

import beaconsim


def _sender_for_new_queue(server_url, token):
    recipient = beaconsim.register_device(server_url, token)
    queue = recipient.create_queue()
    sender = beaconsim.Sender(server_url, queue.sender_id, queue.encryption_public_key)
    return recipient, queue, sender


def test_quota_enforced_and_recovers(sund_server, new_account):
    # A small quota so a handful of messages hits the cap.
    _, token = new_account(quota_bytes=3000)
    _, queue, sender = _sender_for_new_queue(sund_server.base_url, token)

    payload = b"L" * 300
    accepted = 0
    for _ in range(50):
        try:
            sender.send(payload, ttl=3600)
            accepted += 1
        except httpx.HTTPStatusError as exc:
            assert exc.response.status_code == 507
            break
    else:
        pytest.fail("quota was never enforced")

    assert accepted >= 1, "no message was accepted before the cap"

    # Drain and ack everything, freeing the account's storage.
    stored = queue.recv()
    assert len(stored) == accepted
    queue.ack([m["id"] for m in stored])

    # A send succeeds again now that space is free.
    sender.send(payload, ttl=3600)  # must not raise


def test_quota_is_per_account(sund_server, provision_account):
    # Two accounts on the same server; filling one leaves the other untouched.
    _, token_full = provision_account(sund_server, quota_bytes=400)
    _, token_other = provision_account(sund_server, quota_bytes=400)

    _, _, sender_full = _sender_for_new_queue(sund_server.base_url, token_full)
    _, _, sender_other = _sender_for_new_queue(sund_server.base_url, token_other)

    payload = b"P" * 300
    sender_full.send(payload, ttl=3600)
    with pytest.raises(httpx.HTTPStatusError) as exc:
        sender_full.send(payload, ttl=3600)
    assert exc.value.response.status_code == 507

    # The second account has its own quota and is unaffected.
    sender_other.send(payload, ttl=3600)  # must not raise
