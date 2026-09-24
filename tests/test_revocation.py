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


def test_revoke_pings_peers_and_target_but_not_the_actor(sund_server, new_account, push_sink):
    """Three devices, because with two the only "peer" is the actor itself.

    The propagation rule is "every device in the account other than the one that
    performed it", plus the target. An earlier version of this test asserted the
    actor was pinged, which is what the code did and the PRD did not say.
    """
    _, token = new_account()
    actor = beaconsim.register_device(
        sund_server.base_url, token, push_endpoint=push_sink.url("/actor")
    )
    target = beaconsim.register_device(
        sund_server.base_url,
        actor.create_invitation().token,
        push_endpoint=push_sink.url("/target"),
    )
    peer = beaconsim.register_device(
        sund_server.base_url,
        actor.create_invitation().token,
        push_endpoint=push_sink.url("/peer"),
    )
    assert peer.device_id  # registered

    # Setup emits four pings: target's registration wakes actor; peer's
    # invitation mint wakes target; peer's registration wakes actor and target.
    # Wait for all four before clearing, or a straggler lands after the clear and
    # the assertions below read it as a revocation ping.
    assert push_sink.wait_for(4), "setup pings did not all arrive"
    push_sink.received.clear()

    actor.revoke_device(target.device_id)
    assert push_sink.wait_for(2), "the peer and the target should both be pinged"
    paths = {p["path"] for p in push_sink.received}
    assert "/peer" in paths, "the account's other devices must be woken"
    assert "/target" in paths, "the revoked device must be told"
    assert "/actor" not in paths, "a device must not be pinged by its own act"


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


def test_revoke_target_ping_survives_endpoint_clearing(sund_server, new_account, push_sink):
    """The removed device is told, which needs its endpoint captured pre-revoke.

    Revocation clears push_endpoint inside its transaction and wakeAccountDevices
    skips revoked devices, so without capturing it first there is nothing left to
    ping with (docs/deviations.md, 2026-09-23). family-beacon's roster spec
    requires that a removed device is told when it is reachable.
    """
    _, token = new_account()
    actor = beaconsim.register_device(
        sund_server.base_url, token, push_endpoint=push_sink.url("/actor")
    )
    target = beaconsim.register_device(
        sund_server.base_url,
        actor.create_invitation().token,
        push_endpoint=push_sink.url("/target"),
    )
    push_sink.wait_for(1)
    push_sink.received.clear()

    actor.revoke_device(target.device_id)
    assert push_sink.wait_for(1), "the revoked device was never told"
    assert {p["path"] for p in push_sink.received} == {"/target"}
    for ping in push_sink.received:
        assert ping["body"] == b"", "pings stay contentless"
        assert ping["priority"] is None, (
            "revocation must not spend the urgency hint (PRD decision 18)"
        )
