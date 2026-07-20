Sund — Implementation Status

Status: v0.1 (snapshot, 2026-07-20) — describes the code, not the plan

This is a snapshot of what the Sund binary actually does as of the storage-quota
commit, written for the people who build on it — chiefly `../family-beacon`, the
first consumer — and for contributors. Where it and the PRD disagree, the PRD
(`Sund-PRD.md`) is the design intent and this document is the ground truth of the
implementation. Rationale lives in the PRD and `Sund-ImplementationGuide.md`; this
file is the "what exists today" reference.

---

At a glance

- Stack: Go + SQLite (pure-Go `modernc.org/sqlite`, `CGO_ENABLED=0`) — one static
  binary, one database file. Go 1.25+ (floor set by the driver).
- Both planes are implemented: a management plane (device identity) and a
  transport plane (pseudonymous blind queues).
- Also built: push wake-up, device revocation, per-account storage quota.
- Tests: a Go unit suite and a Python system suite (`beaconsim`) that drives the
  real compiled binary with real crypto. ~49 Go cases, ~29 system tests, both
  per-commit. Includes the blindness audit (S8) and operator-survival (S9).
- Not yet built: iOS push provider, in-binary TLS / fingerprint pinning, metrics.
  See "Not built yet".

---

Architecture (as built)

Two planes, meeting in exactly one place:

- Management plane — authenticated by a device's Ed25519 identity key. The server
  knows accounts, devices, public keys, push endpoints, quotas.
- Transport plane — authenticated by per-queue keys, addressed by random queue
  ids. The server does not record which device sends into a queue.

The single meeting point is queue ownership: a queue records its owner (recipient)
device, because quota attribution and wake-up need it. The sender side is
pseudonymous. The runtime form of that link — resolving queue → owner to send a
wake-up ping — is the only transport→management linkage, and it is behavioral, not
stored (no `sender_device` column exists anywhere).

The server transports sealed envelopes and never interprets them. All end-to-end
encryption is client-side; the server stores ciphertext and minimal routing
metadata.

---

Data model (actual SQLite schema)

    accounts     id, created, quota (class label), status, quota_bytes
    devices      id, account_id, public_key, push_endpoint, capabilities,
                 created, last_seen, revoked
    invitations  token_hash, account_id, created, expires, consumed
    queues       recipient_id (pk), sender_id, owner_device, recipient_key,
                 sender_key (null until bound), created, retired
    messages     seq (autoincrement), id, queue_id (= a queue's recipient_id),
                 payload (ciphertext), received_at, expires, status

Notes:
- There is deliberately no column linking a sender device to a queue.
- `capabilities` is stored, never interpreted (opaque to the server).
- Timestamps are RFC3339 UTC at second precision; `messages.seq` gives a stable
  per-queue delivery order independent of that precision.
- Migrations run on open: `CREATE TABLE IF NOT EXISTS` plus an idempotent
  add-column step (`quota_bytes` was added this way; 0 = unlimited, so upgrading
  an old database never retroactively caps its accounts).

---

HTTP API (implemented endpoints)

    Method & path                      Auth                    Purpose
    ---------------------------------------------------------------------------
    GET  /health                       none                    liveness
    POST /v1/devices/register          one-time token          enroll (bootstrap)
    GET  /v1/devices                   device signature        list account devices
    POST /v1/devices/{id}/revoke       device signature        revoke a device
    POST /v1/invitations               device signature        mint a pairing token
    GET  /v1/invitations               device signature        list outstanding invitations
    POST /v1/invitations/{id}/revoke   device signature        revoke before use
    PUT  /v1/me/push                   device signature        set wake-up endpoint
    PUT  /v1/me/bundle                 device signature        publish own key bundle
    GET  /v1/devices/{id}/bundle       device signature        fetch a peer's bundle
    POST /v1/queues                    device signature        create a blind queue
    POST /v1/send/{sender_id}          per-queue sender key     append a message
    GET  /v1/recv/{recipient_id}       per-queue recipient key  drain the queue
    POST /v1/ack/{recipient_id}        per-queue recipient key  delete acked messages
    POST /v1/retire/{recipient_id}     per-queue recipient key  retire (rotation)

Request/response shapes are JSON; payloads are base64 ciphertext. See
`Sund-ImplementationGuide.md` for the sketch and `tests/beaconsim/` for a working
client. The binary serves plain HTTP on its listen address (default `:5870`); TLS
termination and certificate-fingerprint pinning are deployment-layer (reverse
proxy) and not in the binary yet — see "Not built yet".

---

Authentication

Signed requests (both planes) carry four headers and sign a canonical string:

    Headers: Sund-Device-Id (management only), Sund-Timestamp, Sund-Nonce,
             Sund-Signature (base64 Ed25519 signature)
    Signed:  METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" hex(sha256(BODY))

- Timestamp is RFC3339 UTC; requests outside a ±5-minute window are rejected.
- Nonces are remembered in-memory for the skew window to reject replays.
- Management plane: signed by the device identity key; the server looks the key
  up by `Sund-Device-Id` and rejects unknown or revoked devices.
- Transport plane: no device id — the key is the queue's per-queue key, found via
  the recipient/sender id in the path. Sends use the sender key; recv/ack/retire
  use the recipient key.
- Sender-key binding (SimpleX pattern): a queue is created "open" (no sender key).
  The first SEND supplies `Sund-Sender-Key` and the server binds it; later sends
  verify against the bound key and cannot rebind.

The canonical string is the one cross-language contract (Go `internal/sigauth`
and Python `beaconsim`); it must be reproduced byte-for-byte.

---

Behavior details a consumer should know

- Messages: per-message payload cap 64 KiB. TTL is client-supplied seconds,
  clamped to [default 24h, max 7d]; ≤0 uses the default. Expired messages are
  purged unread on the next drain and do not count against quota.
- Push wake-up: a ping carries nothing (no payload, no queue id) — only "check
  in". Pings fire on message arrival (queue → owner) and on device-list changes
  (registration and revocation → the account's other devices), asynchronously so
  a slow distributor never blocks the API. A per-message `priority` flag is an
  opaque hint the server forwards to the pinger without reading the payload
  (used for SOS). Provider is pluggable (`internal/push`); UnifiedPush/ntfy is
  implemented, an iOS APNS gateway is not.
- Revocation: one atomic step kills the identity key, clears the push endpoint,
  and retires every queue the device owns (dropping their messages). The revoked
  device's signed requests then fail and its queues 404. The account's other
  devices are pinged to refetch and rotate. Any device in an account may revoke
  another (admin-only is app-level policy). A revoked device stays listed, flagged
  revoked.
- Quota: per account, counted on the owner (recipient) side. A send that would
  exceed `quota_bytes` is refused with 507; space frees as messages are acked or
  expire. Set via `sund admin account create --quota-bytes N` or a named class
  (standard = 64 MiB, large = 1 GiB). 0 = unlimited.
- Invitations: single-use, default 15-minute TTL, atomically consumed by the
  first registration. Minting returns a non-secret invitation id alongside the
  token; a device can list its account's outstanding (unconsumed, unrevoked,
  unexpired) invitations and revoke one by id before it is used — the stolen-QR
  mitigation. The token itself is never stored (only its hash) or returned by the
  listing.
- Key bundles: each device may publish one opaque, size-capped (8 KiB) blob of
  key material via `PUT /v1/me/bundle`; another device in the account fetches it
  verbatim via `GET /v1/devices/{id}/bundle` to pair with an offline peer. The
  server stores and serves bytes and never interprets them — it does not pop
  one-time prekeys, so managing prekey rotation/consumption is the client's
  concern (the prekey/opacity tension is documented in the PRD's Key bundles
  note). A revoked or cross-account target 404s; a device's bundle is cleared on
  revocation. Bundles are public key material, not secrets, and are distinct from
  blob/object storage (a Non-goal).
- Multi-tenancy: accounts are isolated. Cross-account reads/sends/revokes fail.

---

Guarantees and residual metadata (for privacy docs)

Defended: honest-but-curious and abusive host cannot read content, cannot
impersonate a device (signed requests), cannot inject (sender-key binding), and
cannot enumerate who-messages-whom from the schema (no stored sender↔recipient
link). First-connect MITM is addressed by fingerprint pinning at the deployment
layer (see caveat below). Replay is blocked by nonce+timestamp.

Not hidden (a host can observe): traffic timing and sizes; queue ownership
(recipient side); the push-ping fan-in (which device is woken when a queue
receives); on iOS, wake timing at the vendor gateway and Apple. In a small account
the anonymity set is small — Sund does not claim traffic-analysis resistance; it
guarantees the graph is not *recorded*. Consuming apps must state this honestly.

The blindness claim is enforced by an executable audit (S8): after exercising the
surface with known plaintext markers, the test opens the database and the server
log and asserts the markers appear nowhere and no column links a sender to a
queue.

---

What a client (sund-client) must implement

`tests/beaconsim/` is a working reference (Python). A production client
(family-beacon's Android/iOS/web) implements the same contract:

1. Device identity: generate an Ed25519 keypair; the private key never leaves the
   device.
2. Enrollment: obtain a one-time token (out of band / QR) and POST it with the
   base64 public key to `/v1/devices/register`.
3. Request signing: build the canonical string above and set the four headers, for
   every signed call.
4. Push: register a wake-up endpoint via `PUT /v1/me/push`; on a ping, drain
   queues over the API.
5. Queues: create with a fresh per-queue Ed25519 auth key (the recipient key);
   receive `recipient_id` + `sender_id`. Share the sender id and your payload
   encryption key with the peer out of band (the pairing message).
6. Sending: hold a per-queue Ed25519 sender key; include `Sund-Sender-Key` on the
   first send; encrypt the payload client-side and base64 it in
   `{payload, ttl, priority}`.
7. Receiving: sign with the recipient key; decrypt locally; ack by message id.
8. Rotation: periodically retire a queue and create a replacement.
9. Device list: `GET /v1/devices`; refetch on wake and before any new pairing.

Payload encryption is entirely the client's concern. beaconsim uses X25519
SealedBox as a stand-in; family-beacon's real session crypto (double-ratchet or
Noise, per `../family-beacon/docs/FamilyBeacon-Protocol-0_1.md`) rides inside the
same opaque payload — the server is indifferent to it.

---

Test coverage

- Unit suite (`go test ./...`): signature verification (good/forged/stale/replay),
  invitation single-use/TTL, queue id generation, sender-key binding, message
  TTL/ordering, quota (cap/free/expiry-excluded/per-account/zero-unlimited),
  revocation, tenant isolation, the push provider.
- System suite (`uv run pytest`, drives the real binary): onboarding + pairing,
  device-to-device invitation, send/recv/ack, offline backlog, sender-key binding,
  push wake-up (contentless, SOS priority, device-list change), revocation (S5),
  the blindness audit (S8), operator survival — backup/restore and restart (S9),
  and storage quota.

Run both with `make test-all`.

---

Not built yet (relative to the PRD / API sketch)

- In-binary TLS and the `sund://host:port#fingerprint` address / QR pinning: the
  binary serves plain HTTP; TLS + fingerprint pinning are expected at the reverse
  proxy and on the client, not yet produced or verified by Sund itself.
- iOS push: the provider interface exists; only UnifiedPush/ntfy is implemented.
- Metrics endpoint.
- Storage quota is enforced sequentially-correct; under heavy concurrent sends to
  one account a small overshoot is possible (self-correcting). Fine at the target
  scale; noted for honesty.

Open design decisions (PRD): only iOS gateway operations remains genuinely open.
Blob/object storage is a Non-goal (add when a consumer needs it), and queue
rotation is client-driven by design — the create/retire primitives plus a
fail-closed 404 for a stale sender suffice, and no server-assisted redirect is
wanted (it would reintroduce the sender↔recipient graph). Neither needs new
server API.

---

Code map

    main.go                 CLI: serve, admin account create, health, version;
                            env-var config (SUND_ADDR/SUND_DB)
    Dockerfile, compose.yaml, .env.example
                            container image (distroless static, multi-arch) and a
                            minimal single-service deployment
    internal/server/        HTTP handlers, signature middleware, wake dispatch
      server.go             routes, config
      auth.go               signature extract/verify, nonce cache
      devices.go            register, list, revoke
      transport.go          queues, send/recv/ack/retire, TTL/quota mapping
      push.go               wake helpers, PUT /v1/me/push
    internal/store/         SQLite persistence
      store.go              open/migrate, accounts, devices, invitations
      queue.go              queues, messages, quota-enforcing append
      quota.go              quota classes
    internal/sigauth/       canonical signing string + header names
    internal/push/          Pinger interface, UnifiedPush, Noop
    tests/beaconsim/        reference client (Python)
    tests/                  system suite (pytest)
