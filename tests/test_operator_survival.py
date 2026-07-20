"""S9 — the operator surface: install, deploy, backup, upgrade — tested, not hoped.

With undelivered messages in a queue, prove the data survives both a
backup-and-restore (copy the database, run a fresh binary against the copy) and a
kill-and-restart-in-place (the upgrade path). Everything is a file and a process.
"""

import shutil

import beaconsim


def _fill_queue(server, provision_account):
    """Register a recipient, create a queue, send undelivered messages, and
    return (queue, markers) — the queue object holds the client-side keys."""
    _, token = provision_account(server)
    recipient = beaconsim.register_device(server.base_url, token)
    queue = recipient.create_queue()
    sender = beaconsim.Sender(server.base_url, queue.sender_id, queue.encryption_public_key)

    markers = [f"undelivered-{i}".encode() for i in range(4)]
    for m in markers:
        sender.send(m, ttl=3600)
    return queue, markers


def _drain_plaintexts(server, queue) -> list[bytes]:
    """Reconnect a client to `server` with the queue's keys and drain it."""
    reconnected = beaconsim.Queue(
        server.base_url, queue.recipient_id, queue.sender_id, queue.auth_key, queue.enc_key
    )
    return [m["plaintext"] for m in reconnected.recv()]


def test_backup_and_restore_preserves_messages(sund_launcher, provision_account, tmp_path):
    live_dir = tmp_path / "live"
    live_dir.mkdir()
    server = sund_launcher.start(live_dir / "sund.db")

    queue, markers = _fill_queue(server, provision_account)

    # Back up by copying the database and its WAL sidecars (a consistent physical
    # snapshot: recent writes may still live in -wal until checkpoint).
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    for suffix in ("", "-wal", "-shm"):
        src = (live_dir / "sund.db").with_name("sund.db" + suffix)
        if src.exists():
            shutil.copy2(src, backup_dir / ("sund.db" + suffix))

    # Stop the original, bring up a fresh binary against the backup copy.
    sund_launcher.stop(server)
    restored = sund_launcher.start(backup_dir / "sund.db")

    drained = _drain_plaintexts(restored, queue)
    assert sorted(drained) == sorted(markers), "undelivered messages did not survive backup/restore"


def test_restart_in_place_preserves_messages(sund_launcher, provision_account, tmp_path):
    db_path = tmp_path / "sund.db"
    server = sund_launcher.start(db_path)

    queue, markers = _fill_queue(server, provision_account)

    # Kill and restart the binary against the same database file (upgrade path).
    sund_launcher.stop(server)
    restarted = sund_launcher.start(db_path)

    drained = _drain_plaintexts(restarted, queue)
    assert sorted(drained) == sorted(markers), "undelivered messages did not survive a restart"
