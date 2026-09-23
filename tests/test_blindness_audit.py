"""S8 — the blindness audit: the Architecture Principle as an executable test.

Exercise a broad slice of the surface with known plaintext markers, then open the
database and the server log directly and assert: no column links a sender device
to a queue, the who-talks-to-whom graph is not recorded, every stored payload is
ciphertext, and the plaintext markers appear nowhere on disk or in the log.
"""

import sqlite3

import beaconsim

COORDS = b'{"lat":55.60531,"lon":13.00382,"acc":6}'
SOS = b"SOS-HELP-ME-NOW"
BATTERY = b'{"battery":17,"charging":false}'
MARKERS = [COORDS, SOS, BATTERY]


def _read_all_db_bytes(db_path) -> bytes:
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        p = db_path.with_name(db_path.name + suffix)
        if p.exists():
            blob += p.read_bytes()
    return blob


def test_blindness_audit(sund_server, new_account, push_sink):
    base = sund_server.base_url

    # --- Exercise the surface (a compressed S1-S7) ---
    # Account with three devices; A carries a push endpoint.
    _, token_a = new_account()
    a = beaconsim.register_device(base, token_a, push_endpoint=push_sink.url())
    b = beaconsim.register_device(base, a.create_invitation().token)
    c = beaconsim.register_device(base, a.create_invitation().token)

    # Duplex-ish: A owns a queue B sends into; B owns a queue A sends into.
    q_a = a.create_queue()  # owner A, sender B
    q_b = b.create_queue()  # owner B, sender A
    b_to_a = beaconsim.Sender(base, q_a.sender_id, q_a.encryption_public_key)
    a_to_b = beaconsim.Sender(base, q_b.sender_id, q_b.encryption_public_key)

    # Real encrypted traffic carrying the known markers.
    b_to_a.send(COORDS, ttl=3600)
    a_to_b.send(SOS, ttl=3600, priority=True)
    b_to_a.send(BATTERY, ttl=3600)

    # Deliver and ack one message (touch the recv/ack path); leave the rest stored.
    delivered = q_a.recv()
    q_a.ack([m["id"] for m in delivered])

    # Touch revocation too.
    a.revoke_device(c.device_id)

    # --- Audit the database structure ---
    con = sqlite3.connect(f"file:{sund_server.db_path}?mode=ro", uri=True)
    try:
        queue_cols = [row[1] for row in con.execute("PRAGMA table_info(queues)")]
        device_cols = [c for c in queue_cols if c.endswith("_device")]
        assert device_cols == ["owner_device"], (
            f"queues must link only the owner device, found {device_cols}"
        )

        message_cols = [row[1] for row in con.execute("PRAGMA table_info(messages)")]
        assert not any("device" in c for c in message_cols), (
            f"messages must not reference any device, found {message_cols}"
        )

        # An account column would record the same forbidden link one level up:
        # sender -> account is as much a who-talks-to-whom edge as sender ->
        # device, and tenancy filtering on the transport plane could only be
        # built on one (PRD 0.7, decision 15).
        for table, cols in (("queues", queue_cols), ("messages", message_cols)):
            account_cols = [c for c in cols if "account" in c]
            assert not account_cols, (
                f"{table} must not reference an account, found {account_cols}"
            )

        # --- The who-talks-to-whom graph is not recorded ---
        # B sends into q_a (owned by A): B's device id must appear nowhere in that
        # queue's row. A sends into q_b (owned by B): A's id must be absent there.
        q_a_row = con.execute(
            "SELECT recipient_id, sender_id, owner_device FROM queues WHERE recipient_id=?",
            (q_a.recipient_id,),
        ).fetchone()
        assert q_a_row[2] == a.device_id
        assert b.device_id not in "".join(q_a_row), "sender device leaked into its queue"

        q_b_row = con.execute(
            "SELECT recipient_id, sender_id, owner_device FROM queues WHERE recipient_id=?",
            (q_b.recipient_id,),
        ).fetchone()
        assert q_b_row[2] == b.device_id
        assert a.device_id not in "".join(q_b_row), "sender device leaked into its queue"

        # No message row carries any device id.
        device_ids = [row[0] for row in con.execute("SELECT id FROM devices")]
        for queue_id, payload in con.execute("SELECT queue_id, payload FROM messages"):
            for did in device_ids:
                assert did != queue_id, "a queue is keyed by a device id"

        # --- Every stored payload is ciphertext ---
        stored = con.execute("SELECT payload FROM messages").fetchall()
        assert stored, "expected undelivered messages to still be stored"
        for (payload,) in stored:
            for marker in MARKERS:
                assert marker not in payload, "a payload was not encrypted"
    finally:
        con.close()

    # --- The markers appear nowhere on disk or in the log ---
    disk = _read_all_db_bytes(sund_server.db_path)
    for marker in MARKERS:
        assert marker not in disk, f"{marker!r} found in the database file"

    log = sund_server.log_path.read_bytes()
    for marker in MARKERS:
        assert marker not in log, f"{marker!r} found in the server log"
