"""Pinned TLS is what `sund serve` does when you do not choose.

The PRD has always said pinned mode "remains Sund's self-host-first default"
while the binary served plain HTTP unless told otherwise (docs/deviations.md,
2026-09-18). This asserts the flip: no flags, no setup, HTTPS with a CA the
server generated for itself.
"""

import socket
import ssl
import subprocess
import time

import httpx


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_serve_defaults_to_pinned_tls(sund_binary, tmp_path):
    port = _free_port()
    addr = f"127.0.0.1:{port}"
    log = open(tmp_path / "sund.log", "wb")
    proc = subprocess.Popen(
        # No --tls-dir, no --http: exactly what an operator gets by running it.
        [str(sund_binary), "serve", "--addr", addr, "--db", str(tmp_path / "sund.db")],
        cwd=tmp_path, stdout=log, stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 10
        ok = False
        while time.monotonic() < deadline:
            try:
                r = httpx.get(f"https://{addr}/health", verify=False, timeout=1)
                if r.status_code == 200:
                    ok = True
                    break
            except Exception:
                time.sleep(0.05)
        assert ok, "the server did not come up on HTTPS without being asked"

        # A plain-HTTP request must not get a healthy answer. Go's TLS server
        # replies 400 "Client sent an HTTP request to an HTTPS server" rather
        # than refusing the connection, so assert on the outcome, not an error.
        try:
            plain = httpx.get(f"http://{addr}/health", timeout=1)
            assert plain.status_code != 200, "plain HTTP served /health; TLS is not the default"
        except httpx.HTTPError:
            pass

        # The CA it generated for itself is what a client pins.
        assert (tmp_path / "tls" / "ca.crt").exists(), "no CA was created"
        cert = ssl.get_server_certificate((("127.0.0.1"), port))
        assert "BEGIN CERTIFICATE" in cert

        # And `sund health` follows the same default.
        probe = subprocess.run(
            [str(sund_binary), "health", "--addr", addr],
            capture_output=True, text=True,
        )
        assert probe.returncode == 0, f"health probe failed: {probe.stderr}"
    finally:
        proc.kill()
        proc.wait()
        log.close()
