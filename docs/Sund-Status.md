Sund — Implementation Status

Status: v0.1 (snapshot of the code at the storage-quota commit, 2026-07-20;
"Not built yet", the schema block and multi-tenancy refreshed against PRD 0.10
on 2026-09-24, when the three quota levels were built) — describes the code, not
the plan

This is a snapshot of what the Sund binary actually does as of the three-level
quota commit, written for the people who build on it — chiefly family-beacon
(github.com/mevoc/family-beacon), the first consumer — and for contributors. Where it and the PRD disagree, the PRD
(`Sund-PRD.md`) is the design intent and this document is the ground truth of the
implementation. Rationale lives in the PRD and `Sund-ImplementationGuide.md`; this
file is the "what exists today" reference.

---

At a glance

- Stack: Go + SQLite (pure-Go `modernc.org/sqlite`, `CGO_ENABLED=0`) — one static
  binary, one database file. Go 1.25+ (floor set by the driver).
- Both planes are implemented: a management plane (device identity) and a
  transport plane (pseudonymous blind queues).
- Also built: push wake-up, device revocation, and storage quota at all three
  levels — account, device and queue (PRD 0.10, decisions 13, 16 and 17).
- Tests: a Go unit suite and a Python system suite (`beaconsim`) that drives the
  real compiled binary with real crypto. ~94 Go cases, 52 system tests, both
  per-commit. Includes the blindness audit (S8) and operator-survival (S9).
- Not yet built: the account administration model of PRD 0.4 (administration
  modes, device roles), iOS push provider, metrics. TLS/fingerprint pinning is
  implemented as an opt-in mode (`serve --tls-dir`); making it the default is a
  follow-up. See "Not built yet".

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
                 created, last_seen, revoked, quota_bytes
    bundles      device_id (pk), blob (opaque, size-capped), updated
    invitations  token_hash (pk), id, account_id, created, expires, consumed,
                 revoked
    queues       recipient_id (pk), sender_id, owner_device, recipient_key,
                 sender_key (null until bound), created, retired, quota_bytes
    messages     seq (autoincrement), id, queue_id (= a queue's recipient_id),
                 payload (ciphertext), received_at, expires

Notes:
- There is deliberately no column linking a sender device to a queue.
- `capabilities` is stored, never interpreted (opaque to the server).
- Timestamps are RFC3339 UTC at second precision; `messages.seq` gives a stable
  per-queue delivery order independent of that precision.
- Migrations run on open: `CREATE TABLE IF NOT EXISTS`, an idempotent
  add-column step (`quota_bytes` was added this way; 0 = unlimited, so upgrading
  an old database never retroactively caps its accounts), and — since PRD 0.6 —
  an idempotent drop-column step, currently used only to remove `messages.status`
  (see `docs/deviations.md`, 2026-09-21). The drop is destructive and one-way:
  an older binary's append still names `status`, so downgrading across it fails
  every send. Take the usual file copy before upgrading. A failed migration is
  fail-closed — `Open` returns the error and the server does not start.

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
    POST /v1/quota/{recipient_id}      per-queue recipient key  set queue ceiling
    GET  /v1/me/quota                  device signature        own ceiling + usage

Request/response shapes are JSON; payloads are base64 ciphertext. See
`Sund-ImplementationGuide.md` for the sketch and `tests/beaconsim/` for a working
client. The binary serves plain HTTP by default; `serve --tls-dir DIR` switches
it to HTTPS with fingerprint pinning (see Transport security). A reverse proxy
for WebPKI TLS also remains supported.

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
  devices are pinged to refetch and rotate. **Any device in an account may revoke
  any other, including itself** — the binary has no role model. PRD 0.4 adds an
  optional per-account administration model (flat/managed accounts,
  `admin`/`member` roles) on top of this; none of it is implemented, so a consumer
  must not rely on a revocation being gated today. As built, the behaviour is
  exactly PRD 0.4's `flat` mode, which is also what family-beacon's roster spec
  requires. A revoked device stays listed, flagged
  revoked.
- Quota: three ceilings, all counted on the owner (recipient) side — the
  account's, the owning device's, and the queue's. A send is refused with 507 if
  it would take *any* of them past its limit; the boundary is inclusive, so
  landing exactly on a ceiling succeeds. 0 at a level means no ceiling there, so
  a deployment that sets none behaves as it did before the levels existed.
  Expired-but-unpurged rows do not count, and space frees as messages are acked
  or expire. Ceilings are not retroactive: lowering one refuses further sends and
  deletes nothing.
  - The **refusal body is the same string at every level** ("storage quota
    exceeded"), so a sender cannot tell which tripped.
  - The **account** ceiling is set at provisioning:
    `sund admin account create --quota-bytes N` or a named class
    (standard = 64 MiB, large = 1 GiB).
  - The **device** ceiling is the operator's — `sund admin device quota <id>
    [<bytes>]`, which sets or shows it and pings the capped device. It has no API
    endpoint, because capping a device silences someone else, and it is
    deliberately absent from the device list a peer reads.
  - The **queue** ceiling is the owner's own: `POST /v1/quota/{recipient_id}`,
    authenticated by the queue's recipient key, so no device identity is
    involved. Capping your own inbound channel limits only what you receive.
  - `GET /v1/me/quota` returns the calling device's ceiling, its stored bytes and
    the account ceiling. It is self-scoped and never reports account *usage*.
    No response at any level carries remaining headroom.
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
- Transport security: `serve --tls-dir DIR` serves HTTPS with a two-layer cert —
  a long-lived offline CA (auto-generated in DIR) whose SPKI SHA-256 is the pin,
  signing a rotatable leaf. `sund cert fingerprint --tls-dir DIR [--host host:port]`
  prints the pin or a full `sund://host:port#fingerprint` address for the QR. The
  client pins the CA fingerprint from the address, disables WebPKI/hostname
  checks, and rejects any cert that doesn't match — first-connect MITM is
  detected. Deleting the leaf (server.crt/server.key) rotates it without changing
  the pin. `internal/tlsid` is the implementation; `tests/beaconsim/pinning.py` is
  the client reference; `Sund-Pinning-Contract.md` is the normative spec every
  real client must implement.
- Multi-tenancy: the **management plane** is isolated — cross-account device-list
  reads, bundle fetches and revokes all fail. The **transport plane** consults no
  account in either direction: `recv`/`ack`/`retire` are authorized by the
  per-queue recipient key, a send by the per-queue sender key. So a cross-account
  send succeeds, a sender need hold no account at all, and a cross-account read
  fails only because the caller lacks the recipient key — the same reason a
  same-account device without it fails. A queue is protected by its keys, not by
  its account (PRD 0.7, decision 15). First-send binding then fixes the
  counterparty: after it, a different sender key is refused.

---

Guarantees and residual metadata (for privacy docs)

Defended: honest-but-curious and abusive host cannot read content, cannot
impersonate a device (signed requests), cannot inject (sender-key binding), and
cannot enumerate who-messages-whom from the schema (no stored sender↔recipient
link). First-connect MITM is addressed by the pinned-TLS mode (see Transport
security). Replay is blocked by nonce+timestamp.

Not hidden, by observer. The PRD's threat model carries the full list with what
each item *enables*; this is the as-built subset, which is what a consumer's
privacy documentation has to describe today.

- **A host** observes: traffic timing and sizes; queue ownership (recipient
  side); the push-ping fan-in (which device is woken when a queue receives); who
  acted on whom in live management traffic; on iOS, wake timing additionally
  reaches the vendor gateway and Apple. In a small account the anonymity set is
  small — Sund does not claim traffic-analysis resistance; it guarantees the
  graph is not *recorded*.
- **Any device in the account** observes, from `GET /v1/devices`: every peer's
  `public_key`, `push_endpoint`, `capabilities`, `created`, `last_seen` and
  whether it is revoked. Two of those are worth naming to a privacy writer.
  `push_endpoint` is a peer's wake-up URL, which on a bearer-URL distributor such
  as a default ntfy topic is a capability to wake or spam that device, outside
  Sund and beyond revocation. `last_seen` updates on authenticated
  *management-plane* requests only — the transport plane leaves it alone — but
  since clients refetch the device list on every ping, and a ping fires on
  message arrival, it approximates when a peer's client last woke.
- **A sender**, who may hold no account at all, observes: whether a send is
  refused for storage (507), which is a coarse oracle on the recipient's
  headroom; and whether a queue is gone (404) versus live (401). The second needs
  no credential, because the queue is resolved before the signature is checked,
  so anyone who has ever seen a sender id can use it as a liveness monitor on
  that queue — and revocation retires a device's queues, so that includes
  learning that the owner was revoked.

Consuming apps must state this honestly.

Trust boundary: every non-revoked device in an account is trusted equally — as
built, that includes the administrative acts (revoking a device, minting an
invitation), which PRD 0.4 gates behind a role but the binary does not. The
device list is visible to all members, and the server enforces no "which member
may reach which" policy (nor will it — that one is the consumer's by design).
If a consumer publishes reachable key bundles, any member device can initiate to
any peer; since quota is charged to the recipient and senders are pseudonymous
(nothing to rate-limit), a hostile member can fill a victim's queues, and
revocation is the only server-side remedy. Consumers that
can't assume mutual trust use grant-only reachability (bundles without a self-serve
address) and enforce peer-acceptance client-side. See PRD → Threat model (Trust
boundary) and Devices → Key bundles (Reachability).

The blindness claim is enforced by an executable audit (S8): after exercising the
surface with known plaintext markers, the test opens the database and the server
log and asserts the markers appear nowhere and no column links a sender to a
queue.

---

What a client (sund-client) must implement

`client/` is the Go implementation of the contract (importable as
`github.com/mevoc/sund/client`; first consumer: Postiljon), and
`tests/beaconsim/` is the Python reference the system suite drives. A
production client (family-beacon's Android/iOS/web) implements the same
contract:

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
Noise, per
https://github.com/mevoc/family-beacon/blob/main/docs/FamilyBeacon-Protocol.md)
rides inside the same opaque payload — the server is indifferent to it.

---

Test coverage

- Unit suite (`go test ./...`): signature verification (good/forged/stale/replay),
  invitation single-use/TTL, queue id generation, sender-key binding, message
  TTL/ordering, quota (cap/free/expiry-excluded/per-account/zero-unlimited),
  revocation, tenant isolation, the push provider.
- System suite (`uv run pytest`, drives the real binary): onboarding + pairing,
  device-to-device invitation, send/recv/ack, offline backlog, sender-key binding,
  push wake-up (contentless, SOS priority, device-list change), revocation (S5),
  tenant isolation (S7 — management plane scoped, transport plane not, the
  cross-account send asserted positively), the three quota levels (S11 — the
  per-queue bulkhead, the refusal naming no level, and that only the owner may
  cap a queue), the blindness audit (S8), operator
  survival — backup/restore and restart (S9), and storage quota.

Run both with `make test-all`.

---

Not built yet (relative to the PRD / API sketch)

- Account administration (PRD 0.4, decision 12): `accounts.admin_mode`,
  `devices.role`, `invitations.grants_role`, `POST /v1/devices/{id}/role`, the
  admin-only checks on revoke and invitation minting, the last-admin invariant,
  `sund admin account create --admin-mode` and `sund admin device promote`, role
  in the device-list response, and the two new ping triggers (a role change and
  an invitation mint must wake the account's other devices; today only
  registration and revocation do). It also adds a client obligation Sund cannot
  verify — a client MUST render each device's role and surface administrative
  changes rather than absorbing the ping — which belongs in "What a client must
  implement" once roles exist. Nothing of it exists: today every device is
  effectively an admin, which is exactly PRD 0.4's `flat` mode, so implementing
  it should be additive rather than a behaviour change for existing deployments
  (an existing database migrates to `flat`).
- Pinned TLS is opt-in, not the default: plain HTTP remains the flagless default
  and the container/compose still serve HTTP. Making pinned TLS the self-host
  default (and enabling it in the image) is a follow-up. Client pinning is proven
  in beaconsim (Python); the real clients (Android/iOS/web) must each implement
  the same contract (now specified normatively in `Sund-Pinning-Contract.md`)
  with platform-specific trust evaluation.
- iOS push: the provider interface exists; only UnifiedPush/ntfy is implemented.
- Metrics endpoint.
- Storage quota is enforced sequentially-correct; under heavy concurrent sends to
  one account a small overshoot is possible (self-correcting). Fine at the target
  scale; noted for honesty.

Open design decisions (PRD): iOS gateway operations, and whether administrative
acts should be signed by the acting device so peers can verify them without
trusting the server (open decision 2, added in PRD 0.4).
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
    client/                 Go client: address parsing (both trust modes),
                            request signing, Device / Recipient / Sender
    internal/push/          Pinger interface, UnifiedPush, Noop
    tests/beaconsim/        reference client (Python)
    tests/                  system suite (pytest)
