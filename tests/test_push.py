"""System tests for push wake-up (implementation guide, S4).

A ping must carry nothing — no payload, no queue id — only "check in". These
tests point the server at a stub UnifiedPush distributor and assert exactly that,
for both message-arrival fan-in and device-list changes.
"""

import beaconsim


def test_message_arrival_pings_owner_contentless(sund_server, new_account, push_sink):
    _, token = new_account()
    owner = beaconsim.register_device(sund_server.base_url, token, push_endpoint=push_sink.url())
    queue = owner.create_queue()
    sender = beaconsim.Sender(sund_server.base_url, queue.sender_id, queue.encryption_public_key)

    sender.send(b"a-location-update", ttl=60)

    assert push_sink.wait_for(1), "owner was not pinged on message arrival"
    ping = push_sink.received[-1]
    assert ping["body"] == b"", "wake-up ping must carry no payload"
    # The ping must not leak either queue id.
    assert queue.recipient_id not in ping["path"]
    assert queue.sender_id not in ping["path"]
    assert ping["priority"] is None


def test_sos_send_pings_high_priority(sund_server, new_account, push_sink):
    _, token = new_account()
    owner = beaconsim.register_device(sund_server.base_url, token, push_endpoint=push_sink.url())
    queue = owner.create_queue()
    sender = beaconsim.Sender(sund_server.base_url, queue.sender_id, queue.encryption_public_key)

    sender.send(b"an-sos", ttl=60, priority=True)

    assert push_sink.wait_for(1)
    ping = push_sink.received[-1]
    assert ping["body"] == b"", "even an SOS ping carries no content"
    assert ping["priority"] == "high"


def test_set_push_endpoint_then_wake(sund_server, new_account, push_sink):
    # Register without an endpoint, then set it via PUT /v1/me/push.
    _, token = new_account()
    owner = beaconsim.register_device(sund_server.base_url, token)
    owner.set_push_endpoint(push_sink.url())

    queue = owner.create_queue()
    sender = beaconsim.Sender(sund_server.base_url, queue.sender_id, queue.encryption_public_key)
    sender.send(b"hello", ttl=60)

    assert push_sink.wait_for(1)
    assert push_sink.received[-1]["body"] == b""


def test_device_list_change_pings_existing_device(sund_server, new_account, push_sink):
    _, token = new_account()
    a = beaconsim.register_device(sund_server.base_url, token, push_endpoint=push_sink.url())

    # A second device joins A's account; A must be woken to refetch the list.
    token_b = a.create_invitation().token
    beaconsim.register_device(sund_server.base_url, token_b)

    assert push_sink.wait_for(1), "existing device not pinged on new registration"
    assert push_sink.received[-1]["body"] == b""
