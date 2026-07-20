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
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class SundServer:
    base_url: str
    db_path: Path
    binary: Path
    log_path: Path


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


def _start_server(binary: Path, db_path: Path, log_path: Path):
    """Launch sund against db_path, teeing its output to log_path. Returns
    (proc, log_file, SundServer) once the server answers /health."""
    port = _free_port()
    addr = f"127.0.0.1:{port}"
    log_file = open(log_path, "wb")
    proc = subprocess.Popen(
        [str(binary), "serve", "--addr", addr, "--db", str(db_path)],
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    server = SundServer(base_url=f"http://{addr}", db_path=db_path, binary=binary, log_path=log_path)
    try:
        _wait_until_ready(server.base_url, proc, log_path)
    except Exception:
        proc.kill()
        log_file.close()
        raise
    return proc, log_file, server


def _stop(proc, log_file):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    log_file.close()


@pytest.fixture
def sund_server(sund_binary, tmp_path) -> SundServer:
    """Start the compiled binary on a random port; yield connection details."""
    proc, log_file, server = _start_server(sund_binary, tmp_path / "sund.db", tmp_path / "sund.log")
    try:
        yield server
    finally:
        _stop(proc, log_file)


class SundLauncher:
    """Starts and stops sund servers on demand, for tests that need to kill and
    restart the binary (backup/restore, upgrade)."""

    def __init__(self, binary: Path):
        self.binary = binary
        self._running: list = []

    def start(self, db_path: Path) -> SundServer:
        log_path = db_path.with_name(f"{db_path.stem}-{len(self._running)}.log")
        proc, log_file, server = _start_server(self.binary, db_path, log_path)
        self._running.append((proc, log_file, server))
        return server

    def stop(self, server: SundServer) -> None:
        for i, (proc, log_file, s) in enumerate(self._running):
            if s is server:
                _stop(proc, log_file)
                self._running.pop(i)
                return

    def stop_all(self) -> None:
        for proc, log_file, _ in self._running:
            _stop(proc, log_file)
        self._running.clear()


@pytest.fixture
def sund_launcher(sund_binary):
    launcher = SundLauncher(sund_binary)
    try:
        yield launcher
    finally:
        launcher.stop_all()


@pytest.fixture
def provision_account():
    """Factory: provision an account on a given server via the admin CLI.

    Exercises the real operator surface (`sund admin account create`) against the
    server's database file, and returns (account_id, invitation_token).
    """

    def _provision(server: SundServer, quota: str = "standard") -> tuple[str, str]:
        proc = subprocess.run(
            [
                str(server.binary), "admin", "account", "create",
                "--db", str(server.db_path),
                "--quota", quota,
                "--json",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout)
        return data["account_id"], data["invitation_token"]

    return _provision


@pytest.fixture
def new_account(sund_server, provision_account):
    """Factory bound to the default sund_server fixture."""

    def _make(quota: str = "standard") -> tuple[str, str]:
        return provision_account(sund_server, quota)

    return _make


@dataclass
class PushSink:
    """A stub UnifiedPush distributor that records the pings it receives."""

    port: int
    received: list = field(default_factory=list)

    def url(self, path: str = "/UP") -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def wait_for(self, count: int = 1, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.received) >= count:
                return True
            time.sleep(0.02)
        return len(self.received) >= count


@pytest.fixture
def push_sink():
    received: list = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            received.append({
                "path": self.path,
                "body": body,
                "priority": self.headers.get("Priority"),
            })
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass  # keep the test output quiet

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sink = PushSink(port=server.server_address[1], received=received)
    try:
        yield sink
    finally:
        server.shutdown()


def _wait_until_ready(base_url: str, proc: subprocess.Popen, log_path: Path, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out = log_path.read_text(errors="replace") if log_path.exists() else ""
            raise RuntimeError(f"sund exited before becoming ready:\n{out}")
        try:
            r = httpx.get(f"{base_url}/health", timeout=0.5)
            if r.status_code == 200:
                return
        except httpx.TransportError:
            time.sleep(0.05)
    raise TimeoutError(f"sund did not become ready within {timeout}s")
