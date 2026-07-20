"""Shared fixtures for the Sund system suite.

The unit under test is the real compiled binary: a session fixture builds it
once, and a per-test fixture starts it against a temp SQLite file on a random
loopback port. Startup is milliseconds, so per-test spawning is cheap — and if
it ever stops being cheap, that is itself a regression worth catching (see
docs/Sund-ImplementationGuide.md, Testing).
"""

import json
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class SundServer:
    base_url: str
    db_path: Path
    binary: Path


def _go_binary() -> str:
    """Locate the Go toolchain, tolerating a PATH that omits /usr/local/go/bin."""
    return shutil.which("go") or "/usr/local/go/bin/go"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def sund_binary(tmp_path_factory) -> Path:
    """Compile the real sund binary once per session (CGO off — pure-Go SQLite)."""
    out = tmp_path_factory.mktemp("bin") / "sund"
    subprocess.run(
        [_go_binary(), "build", "-o", str(out), "."],
        cwd=REPO_ROOT,
        check=True,
        env={**os.environ, "CGO_ENABLED": "0"},
    )
    return out


@pytest.fixture
def sund_server(sund_binary, tmp_path) -> SundServer:
    """Start the compiled binary on a random port; yield connection details."""
    port = _free_port()
    addr = f"127.0.0.1:{port}"
    db_path = tmp_path / "sund.db"

    proc = subprocess.Popen(
        [str(sund_binary), "serve", "--addr", addr, "--db", str(db_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    server = SundServer(base_url=f"http://{addr}", db_path=db_path, binary=sund_binary)
    try:
        _wait_until_ready(server.base_url, proc)
        yield server
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def new_account(sund_server):
    """Return a factory that provisions an account via the admin CLI.

    Exercises the real operator surface (`sund admin account create`) against
    the same database file the running server uses, and returns
    (account_id, invitation_token).
    """

    def _make(quota: str = "standard") -> tuple[str, str]:
        proc = subprocess.run(
            [
                str(sund_server.binary), "admin", "account", "create",
                "--db", str(sund_server.db_path),
                "--quota", quota,
                "--json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout)
        return data["account_id"], data["invitation_token"]

    return _make


def _wait_until_ready(base_url: str, proc: subprocess.Popen, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out = proc.stdout.read().decode() if proc.stdout else ""
            raise RuntimeError(f"sund exited before becoming ready:\n{out}")
        try:
            r = httpx.get(f"{base_url}/health", timeout=0.5)
            if r.status_code == 200:
                return
        except httpx.TransportError:
            time.sleep(0.05)
    raise TimeoutError(f"sund did not become ready within {timeout}s")
