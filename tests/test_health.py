"""System smoke test: the real binary boots and answers /health.

This is the seed the S1-S9 scenarios (implementation guide) grow from — proving
the build/boot/HTTP loop works end to end before any real endpoint exists.
"""

import httpx

import beaconsim


def test_health_ok(sund_server):
    r = httpx.get(f"{sund_server.base_url}/health")
    assert r.status_code == 200

    body = r.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_beaconsim_importable():
    # The client-mockup package resolves from the source tree under uv/pytest.
    assert beaconsim.__version__
