"""Administrative statements — the log that lets a peer check an act itself.

Decision 12's role model binds the account's own devices and not the host, which
can still fabricate a revocation. An admin may write a signed, encrypted
statement of what it did; peers verify it against the device list. Sund stores
opaque bytes and serves them in order (PRD 0.13, decision 21).

The property this file exists to pin is the one the feature nearly got wrong: the
blob must be ciphertext, so the log cannot become the actor-to-target record the
data model refuses.
"""

import base64
import sqlite3

from nacl.public import PrivateKey, SealedBox

import beaconsim


def _sealed(plaintext: bytes, key: PrivateKey) -> bytes:
    """Stand-in for a real client's sign-then-encrypt. Sund parses neither."""
    return bytes(SealedBox(key.public_key).encrypt(plaintext))


def test_admin_writes_and_peers_read(sund_server, new_account):
    _, token = new_account(admin_mode="managed")
    admin = beaconsim.register_device(sund_server.base_url, token)
    member = beaconsim.register_device(
        sund_server.base_url, admin.create_invitation(grants_role="member").token
    )

    account_key = PrivateKey.generate()
    blob = _sealed(b'{"act":"revoke","target":"dev_x"}', account_key)
    r = admin.append_statement(blob)
    assert r.status_code == 201
    assert r.json()["seq"] == 1

    # Every device in the account reads the log, not just admins — the point is
    # that a peer can check an act for itself.
    entries = member.list_statements()
    assert len(entries) == 1
    assert base64.b64decode(entries[0]["statement"]) == blob

    # And polling from the highest seq held returns nothing new.
    assert member.list_statements(since=entries[0]["seq"]) == []


def test_members_cannot_write_statements(sund_server, new_account):
    """The acts a statement describes are admin-only, so the log that vouches
    for them is too — and a member cannot fill the account's bounded log."""
    _, token = new_account(admin_mode="managed")
    admin = beaconsim.register_device(sund_server.base_url, token)
    member = beaconsim.register_device(
        sund_server.base_url, admin.create_invitation(grants_role="member").token
    )
    assert member.append_statement(b"anything").status_code == 403
    assert admin.list_statements() == []


def test_the_log_is_opaque_to_the_server(sund_server, new_account):
    """The blindness property, and the reason encryption is required.

    A plaintext signed statement would be exactly the "X did A to Y" row the
    data model refuses. Written as ciphertext, the database holds no readable
    trace of who acted on whom.
    """
    _, token = new_account()
    admin = beaconsim.register_device(sund_server.base_url, token)
    account_key = PrivateKey.generate()

    secret = b'{"act":"revoke","actor":"dev_alice","target":"dev_bob"}'
    admin.append_statement(_sealed(secret, account_key))

    con = sqlite3.connect(f"file:{sund_server.db_path}?mode=ro", uri=True)
    try:
        rows = list(con.execute("SELECT account_id, seq, blob, created FROM statements"))
        assert len(rows) == 1
        stored = rows[0][2]
        assert secret not in stored, "the statement must not be readable in the database"
        for needle in (b"dev_alice", b"dev_bob", b"revoke"):
            assert needle not in stored, f"{needle!r} leaked into the stored statement"

        # The table carries no actor or target column either — the log is one
        # opaque blob per account, not a graph.
        cols = [r[1] for r in con.execute("PRAGMA table_info(statements)")]
        assert cols == ["account_id", "seq", "blob", "created"], cols
    finally:
        con.close()


def test_statements_are_account_scoped(sund_server, new_account):
    _, token_a = new_account()
    _, token_b = new_account()
    a = beaconsim.register_device(sund_server.base_url, token_a)
    b = beaconsim.register_device(sund_server.base_url, token_b)

    a.append_statement(b"a-only")
    assert len(a.list_statements()) == 1
    assert b.list_statements() == [], "an account must not see another's log"

    # B's own log starts at 1, so sequence numbers reveal nothing about A.
    assert b.append_statement(b"b-first").json()["seq"] == 1


def test_statement_http_boundaries(sund_server, new_account):
    """The edges the store tests cannot reach: sizes and bad bodies over the wire."""
    _, token = new_account()
    admin = beaconsim.register_device(sund_server.base_url, token)

    # Exactly at the 4 KiB cap is accepted; one byte more is refused.
    assert admin.append_statement(b"x" * 4096).status_code == 201
    assert admin.append_statement(b"x" * 4097).status_code == 413

    # An empty statement is not a statement.
    assert admin.append_statement(b"").status_code == 400

    # Neither is a body that is not base64.
    import json

    r = admin._request(
        "POST", "/v1/statements", json.dumps({"statement": "not!base64"}).encode()
    )
    assert r.status_code == 400


def test_revoked_device_cannot_read_the_log(sund_server, new_account):
    """The party a forged revocation harms is the one that cannot check it.

    Signed requests from a revoked device are refused, so the defence lives with
    its peers rather than with the target (PRD 0.14, Administrative statements).
    """
    _, token = new_account()
    admin = beaconsim.register_device(sund_server.base_url, token)
    other = beaconsim.register_device(
        sund_server.base_url, admin.create_invitation().token
    )
    admin.append_statement(b"opaque")

    assert len(other.list_statements()) == 1
    admin.revoke_device(other.device_id)
    assert other.get("/v1/statements/0").status_code == 401


def test_retention_cap_over_the_wire(sund_server, new_account):
    """Trimming leaves a head gap a client cannot tell from hostile truncation,
    which is why the cap is part of the contract."""
    _, token = new_account()
    admin = beaconsim.register_device(sund_server.base_url, token)

    for i in range(260):
        assert admin.append_statement(f"s{i}".encode()).status_code == 201

    log = admin.list_statements()
    assert len(log) == 256, f"the log should be capped at 256, got {len(log)}"
    assert base64.b64decode(log[-1]["statement"]) == b"s259", "the newest must survive"
    # The sequence number does not reset, so it reports the lifetime total.
    assert log[-1]["seq"] == 260
    assert log[0]["seq"] == 5, "the head gap is visible as a non-1 starting seq"
