"""System tests for pinned TLS (PRD, Server address).

The client learns the server's fingerprint out of band (the sund:// address),
pins it on connect, and runs the full flow over HTTPS. A mismatching fingerprint
is rejected — the first-connect MITM defence.
"""

import pytest

import beaconsim
from beaconsim.pinning import PinError, connect, parse_address


def test_address_parse_roundtrip():
    host, port, fingerprint = parse_address("sund://example.test:5870#deadbeef")
    assert (host, port, fingerprint) == ("example.test", 5870, "deadbeef")


def test_pinned_client_runs_full_flow_over_tls(tls_sund, provision_account):
    base_url, ssl_ctx = connect(tls_sund.address)

    _, token = provision_account(tls_sund.server)
    alice = beaconsim.register_device(base_url, token, verify=ssl_ctx)

    # A signed management request works over pinned TLS.
    assert [d["id"] for d in alice.list_devices()] == [alice.device_id]

    # And the full transport plane, end to end, over HTTPS.
    queue = alice.create_queue()
    sender = beaconsim.Sender(base_url, queue.sender_id, queue.encryption_public_key, verify=ssl_ctx)
    sender.send(b"hello-over-pinned-tls", ttl=60)
    received = queue.recv()
    assert received[0]["plaintext"] == b"hello-over-pinned-tls"


def test_wrong_fingerprint_is_rejected(tls_sund):
    host, port, _ = parse_address(tls_sund.address)
    bad_address = f"sund://{host}:{port}#{'00' * 32}"

    # Connecting with a fingerprint the server can't present is a pin failure —
    # exactly what a MITM presenting its own certificate would trigger.
    with pytest.raises(PinError):
        connect(bad_address)


def test_fingerprint_matches_served_certificate(tls_sund):
    # The fingerprint in the address is the one the live server actually presents.
    base_url, ssl_ctx = connect(tls_sund.address)
    r = beaconsim_get(base_url, "/health", ssl_ctx)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def beaconsim_get(base_url, path, ssl_ctx):
    import httpx

    return httpx.get(base_url + path, verify=ssl_ctx)
