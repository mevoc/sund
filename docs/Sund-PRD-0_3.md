Sund

«A blind strait between your devices.»

Status: PRD v0.3 (Draft) — supersedes PRD 0.2

> Working name: **Sund** (Swedish: a strait between islands — the channel between
> skerries; also "sound, healthy"). The kernel extracted from Skerry
> (`../skerry`). This revision folds in the three open items surfaced by
> `Sund-ImplementationGuide-0_1.md` (July 2026): push-ping fan-in made explicit in
> the threat model, invitation semantics specified, and device-list change
> propagation decided. It also adds the per-commit test strategy (decision 9)
> and locks the stack: Go + SQLite (decision 10). The changes are listed at the
> end under "Decisions in this revision"; PRD 0.2's five decisions carry over
> unchanged.

---

Vision

Sund is a minimal, self-hostable, blind store-and-forward relay for end-to-end
encrypted messages between a user's devices, plus the device management needed to
make that trustworthy: device identity, registration, revocation and push wake-up.

It is the smallest backend that Family Beacon — and many small apps like it —
actually needs. Nothing more.

---

Architecture Principle

«Sund transports data between authorized devices — it never interprets it.»

The server must never need to know:

- what a message means
- what application sent it
- what a family, group or session is
- who owns a location, photo or event

If a feature requires the server to understand payload content, the feature belongs
in a client or in Skerry — not in Sund.

---

The two planes

Sund separates what the server must know from what it must not:

Management plane — authenticated by device identity keys. The server knows the
account, its devices, their public keys, push endpoints and quotas. This is what
makes Sund an app substrate rather than an anonymous relay.

Transport plane — authenticated by per-queue keys, unlinked to device identity.
Message flow is addressed to queues, not devices. The server does not record which
device sends into a queue.

The planes meet in exactly one place: a queue has an owner (the recipient device),
because quota attribution and push wake-up require it. The sender side is
pseudonymous.

That single meeting point is exercised in two ways: statically for quota
(storage attributed to the owner's account) and at runtime for wake-up (a message
arriving in a queue makes the server resolve queue → owner device and ping it).
The runtime form — push-ping fan-in — links queue activity to a device in live
behavior, never in the schema; it is stated explicitly in the Threat model.

---

Principles

- Blind by construction. Public keys, encrypted payloads, minimal routing metadata.
  Nothing to leak, nothing for a host to covertly read.
- Infrastructure, not application. All business logic lives in clients.
- Multi-tenant by design. Accounts are fully isolated.
- Self-host first. One small static binary, one database file. Install. Deploy.
  Backup. Upgrade. (The Holm bar.)
- Adopt, don't build. Where sound self-hostable components exist (UnifiedPush/ntfy
  for Android wake-up), Sund integrates them instead of reinventing them.
- API-first. Everything reachable via a documented, signed API.
- Minimal metadata, honestly stated. What the server must store, it stores briefly
  (TTL) and legibly — documented here, auditable in the schema.

---

Scope — V1

Accounts
- Multi-tenant isolation, per-account quotas, root-admin provisioning.
- Quotas are attributed to the queue owner's account (the recipient side — the
  side the server knows). Senders stay pseudonymous without breaking accounting.

Devices
- Ed25519 keypair per device; the server stores the public key only.
- Bootstrap: QR code carrying the server address (including certificate
  fingerprint, see Server address) and a one-time token. Verification →
  registration → the new device appears in the account's device list.
- Invitations: enrollment tokens are single-use and short-lived (default TTL
  15 minutes, operator-configurable). A token is consumed atomically by the first
  successful registration; a second use, or use after expiry, fails closed.
  Outstanding invitations are listable and revocable from any authorized device —
  a mis-shared QR can be killed before it is used.
- Explicit device list: every device in an account can see all registered devices
  (id, created, last_seen, capabilities). Revocation is a first-class operation;
  a revoked device's identity key and queue access die immediately.
- Device-list change propagation: any change to the account's device list
  (registration, revocation) triggers a contentless ping to the account's other
  devices; on waking, a client refetches the device list. Pings are best-effort —
  clients MUST additionally refetch the device list before establishing any new
  session or pairing, so a missed ping costs latency, never security.
- Key bundles: each device may publish a small, size-capped, opaque blob of
  client-side key material (e.g. prekeys for X3DH-style async session setup),
  retrievable by other devices in the account. The server never interprets it —
  it is a dead-drop, not a crypto service.

Queues
- A queue is a unidirectional channel owned by one recipient device, created by
  that device. On creation the server issues two unrelated random IDs: a
  recipient ID (used by the owner to read/ack) and a sender ID (handed to the
  sending device out-of-band or via an invitation message). The server stores
  per-queue authentication keys supplied at creation; sender-side keys are
  per-queue, not device identity keys.
- Consequence: the server's records do not link a sender device to a queue. The
  who-talks-to-whom graph is not stored.
- Rotation: the owner can create a replacement queue and retire the old ID at any
  time; clients are expected to rotate periodically.
- V1 scope: queues connect devices within the same account.

Messages
- Send (by sender ID), receive/ack (by recipient ID), per-message TTL, delivery
  status. Queues survive offline receivers; expired messages are deleted unread.
- Payloads are opaque ciphertext, size-capped per quota.

Push wake-up
- A ping carries nothing — no payload, no queue ID. It only tells a device
  "check in"; the client then drains its queues over the API.
- Pings are sent on message arrival (transport plane, via queue ownership) and on
  device-list changes (management plane, see Devices).
- Delivery paths differ fundamentally per platform — see Push architecture.

Health and metrics endpoints.

---

Data model (the whole of it)

accounts     — id, created, quota, status
devices      — id, account_id, public_key, push_endpoint, capabilities, created,
               last_seen, revoked
bundles      — device_id, blob (opaque, size-capped), updated
invitations  — token_hash, account_id, created, expires, consumed
queues       — recipient_id, sender_id, owner_device, recipient_key, sender_key,
               created, retired
messages     — queue_id, payload, received_at, ttl, status

There is deliberately no sender_device column anywhere in the transport plane.

---

Server address

A Sund server address embeds the fingerprint of the server's offline certificate
(SimpleX pattern), e.g.:

sund://host:port#<certificate-fingerprint>

The QR bootstrap code carries this full address, so a new device pins the server
identity on first contact. A man-in-the-middle on first connect is detected, not
trusted.

---

Push architecture

Pings are payload-free by design (no content, no queue IDs — only "check in").
That decision is what makes the following delivery paths acceptable.

Android — fully self-hostable.

  Sund server → UnifiedPush distributor (e.g. self-hosted ntfy) → device

The device registers any UnifiedPush endpoint; a family can run ntfy next to Sund
on the same box. Because pings carry nothing, the distributor's lack of E2E is
irrelevant. No third party is required.

iOS — structurally Apple-only. The OS wakes background apps through APNS and
nothing else: apps cannot hold background connections, and no third-party app may
act as a push distributor (there is no iOS UnifiedPush). Two consequences:

1. The self-hoster cannot own this path. APNS credentials are bound to the app's
   bundle ID and belong to the app vendor; shipping the signing key with an
   open-source server would let anyone push to the app's users. A family's own
   Sund server therefore cannot deliver an iOS wake-up by itself.
2. The realistic architecture is a vendor-operated gateway:

   Sund server → push gateway (vendor holds APNS key) → APNS → device

Sund defines a pluggable push-provider interface; the APNS gateway is one
provider. An organization with its own Apple developer account can run its own
gateway; a family self-hosting the vendor's published app uses the vendor's.

Trust and availability implications — stated, not hidden:

- The gateway and Apple see: device push token, app identity, and wake timing.
  They never see content, queue IDs, or message counts per queue.
- The gateway is an availability dependency: if it is down, iOS devices stop
  being woken. Clients must degrade gracefully (fetch on foreground, Background
  App Refresh opportunistically) — and consuming apps must define what their
  critical path promises when wake-up is slow or unavailable. For a safety app
  this is the SOS question (family-beacon open decision #4); resolve it together
  with this section.
- Latency honesty: without a successful push, iOS delivery latency is unbounded.
  Background App Refresh is opportunistic (minutes to hours) and unreliable.

Outside Sund's scope but relevant to iOS consumers: the OS wakes apps for
geofence crossings and significant location changes without any push (covers
arrival/departure-type events at the source), and PushKit/VoIP offers
higher-priority delivery for call-like alerts (a possibly legitimate SOS
presentation) — both still app-level choices, and PushKit also transits APNS.

---

Threat model (summary)

Defended against:

- Honest-but-curious host: sees ciphertext, public keys, queue records and
  management metadata — no content, no stored sender↔recipient links.
- Abusive host (the Family Beacon scenario): cannot read content, cannot
  impersonate a device (signed requests), cannot inject (clients verify sender
  keys), cannot silently enumerate who messages whom from the schema.
- Stolen or leaked invitation QR: tokens are single-use with a short TTL and can
  be revoked before use; a consumed token registers a device that is immediately
  visible in every account member's device list — no silent enrollment.
- First-connect MITM: certificate fingerprint pinned via the server address.
- Replay: signed requests with nonces/timestamps.

Explicitly NOT hidden — residual metadata a host can observe:

- Traffic timing and sizes, per queue and per device connection.
- Queue ownership (recipient side) — required for quotas and wake-up.
- Push-ping fan-in: on every message arrival the server resolves queue → owner
  device in order to ping it. This is the same queue-ownership linkage as quota,
  exercised at runtime rather than stored: a host watching live behavior sees
  which device is woken when a given queue receives, even though the schema
  records no sender↔recipient link. It is the only transport→management linkage
  in the system, and it is inherent to offering wake-up at all.
- In a small account (a family), the anonymity set is small: a host correlating
  traffic timing can often guess the sender despite pseudonymous queues. The
  improvement over PRD 0.1 is that the graph is not *recorded*; it is not that
  traffic analysis is defeated.
- On iOS, wake timing (though nothing else) is additionally visible to the vendor
  push gateway and to Apple — see Push architecture.

Sund does not claim traffic-analysis resistance. Consuming apps must state this
honestly in their privacy documentation.

---

Non-goals

- No application logic, ever (see Architecture Principle).
- No server-side cryptography beyond verifying request signatures. Key bundles are
  stored, never interpreted. No key escrow, no recovery.
- No blob/object storage in V1. First candidate extension, deferred until a
  consumer demonstrates need; if added, a separate optional module with the same
  blindness guarantee.
- No cross-account or federated messaging in V1.
- No chat product: no UI, no contacts, no groups.
- No content moderation — structurally impossible, stated openly.

---

Prior art

See `Sund-PriorArt-0_1.md`. The queue design above adapts SimpleX's SMP addressing
to a substrate with accounts; the bootstrap ergonomics follow Signal's
device-management patterns; the push leg adopts UnifiedPush/ntfy; the address
format follows SimpleX's fingerprint pinning. The surveyed gap — blind transport
plus an account/device model — remains unoccupied as of July 2026.

---

Relationship to other projects

- family-beacon — first consumer and forcing function. Formally adopted Sund as
  its backend (July 2026), closing its open decisions #1 (E2EE) and #3 (Skerry
  coupling); #2 (push) is shared. Its ARCHITECTURE.md is rewritten around Sund.
- skerry — grows around Sund; references it as Layer 1.
- `Sund-ImplementationGuide-0_1.md` — companion: components, API sketch and
  end-to-end walkthroughs (first-device onboarding, second-device invitation),
  each step mapped to Family Beacon. This PRD is normative where they disagree.
- Lineage: supersedes the Layer-1 subset of
  `../skerry/docs/FamilyBeacon-MicroCloud-0_5.md` and all of Sund PRD 0.1
  and 0.2.

---

Decisions in this revision

The five decisions of PRD 0.2 (SimpleX queue addressing, UnifiedPush/ntfy push
leg, Signal-style device management, fingerprint-pinned server address,
one-binary stack requirement) carry over unchanged. New in 0.3 — the three items
surfaced by the implementation guide, plus the test strategy:

6. Push-ping fan-in made explicit. Confirmed: resolving queue → owner device at
   delivery time is the only transport→management linkage in the system, the
   runtime twin of quota attribution. Now stated in The two planes and listed as
   residual metadata in the Threat model instead of being implied by "queue
   ownership".
7. Invitation semantics specified. Enrollment tokens are single-use (atomically
   consumed by the first successful registration), short-lived (default TTL
   15 minutes, operator-configurable), and listable/revocable before use. An
   invitations table joins the data model; the stolen-QR case joins the threat
   model.
8. Device-list change propagation: push and verify. Registration and revocation
   trigger a contentless ping to the account's other devices (reusing the
   existing wake-up channel — nothing new to build), and clients must refetch
   the device list before establishing any new session. Push provides latency;
   the mandatory refetch provides correctness — a missed ping never lets a
   revoked device linger in a peer's world view past its next pairing.
9. Test strategy: two suites, both run on every commit. A unit suite (< 5 s)
   for isolated invariants, and a system suite (< 30 s) that starts the real
   compiled binary per test and drives it through a headless Family Beacon
   client mockup (beaconsim) doing real E2E crypto — the test suite is Sund's
   first consumer. It includes a blindness audit: after the scenarios run, the
   database file and logs are inspected directly and the known plaintexts must
   appear nowhere — the Architecture Principle as an executable regression
   test. Scenarios and suite details in the implementation guide (Testing).
10. Stack locked: Go + SQLite, signed off July 2026. The one-binary requirement
    of decision 5 (PRD 0.2) is now concrete rather than a leading candidate;
    family-beacon's ARCHITECTURE.md has been updated accordingly (its original
    Kotlin/Ktor + PostgreSQL sketch is superseded for the server). Clients
    remain free in their stacks.

Open decisions remaining

1. iOS push gateway operations (shared with family-beacon #2): who operates the
   vendor gateway, what availability it promises, and whether pings get
   batching/jitter to blunt timing analysis at the gateway. The architecture
   itself is settled in Push architecture; "no lock-in" is structurally
   unattainable on iOS — only containment is.
2. Blob module — revisit when a consumer needs it.
3. Queue rotation policy: client-driven only, or server-assisted hints?

---

Motto

«Own the strait. The cargo stays sealed.»
