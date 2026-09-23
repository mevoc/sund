# Sund — Blind Store-and-Forward Relay

> «Own the strait. The cargo stays sealed.»

A minimal, self-hostable, blind store-and-forward relay for end-to-end encrypted
messages between a user's devices, plus device management (Ed25519 identity, QR
bootstrap with pinned server fingerprint, device list + revocation, signed
requests) and payload-free push wake-up (UnifiedPush/ntfy on Android). Two planes:
a management plane that knows accounts/devices, and a transport plane of
pseudonymous per-queue IDs (SimpleX pattern) that never records who talks to whom.
The server transports sealed envelopes; it never interprets them.

**"Sund" is the working name** (Swedish: a strait between islands — the channel
between skerries; also "sound, healthy"). Extracted from Skerry (`../skerry`)
as its kernel: Sund is Skerry's Layer-1 identity/messaging service, and the actual
backend of [family-beacon](https://github.com/mevoc/family-beacon).

**Implemented and running.** Both planes work, plus push wake-up, device
revocation, key bundles and per-account quota, with a Go unit suite and a Python
system suite per commit and a container image published to GHCR. See
`docs/Sund-Status.md` for what the binary actually does; the PRD stays design
intent.

---

## Hard rules

- **Blind by construction.** The server stores only public keys, encrypted payloads
  and minimal routing metadata. If a feature requires the server to understand
  payload content, it belongs in a client or in Skerry — raise it, don't build it.
- **No server-side crypto** beyond verifying request signatures. No key escrow, no
  recovery.
- **Infrastructure, not application.** No UI, no contacts, no groups, no app logic.
- Be honest about residual metadata: timing, sizes and the device graph are visible
  to the host. Sund does not claim traffic-analysis resistance.
- Operational bar is Holm's (holmhq.com): aim for one small binary + one database
  file, not a service zoo.

## Relationships

- [family-beacon](https://github.com/mevoc/family-beacon) — first consumer;
  formally adopted Sund as its backend (July 2026), closing its decisions #1
  (E2EE) and #3 (Skerry coupling). Push-provider problem (#2) is shared.
- `../skerry` — grows around Sund; its PRD references Sund as Layer 1
  rather than respecifying it. (Not public.)
- The generic client library (`sund-client`: identity, pairing, sessions,
  queues, push) is scoped in
  [FamilyBeacon-Protocol.md](https://github.com/mevoc/family-beacon/blob/main/docs/FamilyBeacon-Protocol.md)
  (Layering). Family Beacon's is Rust; the **Go** implementation of the
  transport half (address modes, signing, both planes; no payload crypto) lives
  here in `client/` and is what `../postiljon` builds on.
- Supersedes the Layer-1 subset of
  `../skerry/docs/FamilyBeacon-MicroCloud-0_5.md`.

## Docs

- `docs/Sund-PRD.md` — **current (v0.7).** Two-plane architecture, pseudonymous
  queues, device list/revocation/key bundles, push architecture (UnifiedPush/ntfy
  on Android; vendor APNS gateway on iOS — pluggable provider interface),
  fingerprint-pinned server address, one-binary stack requirement. New in 0.7:
  multi-tenancy scoped to what it is (decision 15). The management plane is
  account-isolated; the **transport plane consults no account in either
  direction**, so a cross-account send succeeds, a sender may hold no account at
  all, and a cross-account read fails only for want of the recipient key. A queue
  is protected by its keys, not its account. Three sentences said otherwise and
  were wrong — the code was always right. From 0.6:
  the per-message delivery status is **removed** (decision 14) — an ack deletes
  the row, so the column only ever held one value and described no behaviour;
  Messages now states the model positively (stored until acked; no read receipt;
  no delivery or read signal to the sender — which is narrower than "a sender
  learns nothing", since a send still fails closed on a retired or full queue).
  The migration is destructive and one-way. From 0.5:
  a per-device storage ceiling beside the per-account one (decision 13) — a
  bulkhead so one device's backlog cannot exhaust the account's headroom. Needs
  no new linkage (the quota check already resolves queue → owner device).
  *Writing* a ceiling has no endpoint — it is an operator CLI act, because it is
  a denial-of-service primitive — but it must not therefore be silent: a change
  pings the account, `quota_bytes` is in the device list, and `GET /v1/me/quota`
  lets a device read its own ceiling and usage, so being capped is
  distinguishable from being full. Explicitly *not* a sender-side limit, since
  there is no sender_device, and it makes the refusal a cheaper oracle for a
  sender probing headroom — stated in the threat model rather than buried. 0.5
  also syncs the data-model table with the schema, closing a deviation. From 0.4:
  an optional per-account administration model — `flat` (default, unchanged) vs.
  `managed` accounts, an `admin`/`member` device role, and admin-only revocation
  and invitation minting. Self-revocation is unconditional, an account never
  loses its last admin to an act performed on another device, and no
  administrative act is invisible to a *conforming* client (Sund pings every
  other device and publishes role; whether a client surfaces either is the
  consumer's obligation and unverifiable server-side). **Opt-in and
  contested:** family-beacon's roster spec as written is incompatible with it on
  anti-stalkerware grounds (no privileged remover), and PRD 0.4 records the
  conflict rather than settling it — raise it, don't pick a winner. From
  0.3: push-ping fan-in in the threat model, invitation semantics (single-use,
  15-min TTL, revocable), device-list changes push + mandatory refetch, a
  per-commit test strategy (unit + system suites, blindness audit), and the
  stack lock, July 2026: Go + SQLite (family-beacon
  ARCHITECTURE.md updated to match). Remaining open: iOS gateway operations,
  signed administrative statements. (Blob storage and queue rotation are
  resolved — see the PRD's "Resolved since first listed as open".)
- `docs/Sund-ImplementationGuide.md` — companion to PRD 0.7: components, API
  sketch (two planes), walkthroughs for first-device onboarding and second-device
  invitation (SimpleX-style QR bootstrap), each step mapped to Family Beacon.
  Also the test strategy: unit + system suites (both per-commit), the beaconsim
  client mockup, scenarios S1–S10 (S5b/S5b2/S5b3/S5c administration, S10 quota).
  Its four surfaced open items are resolved in PRD 0.3 and 0.4.
- `docs/Sund-Status.md` — **implementation snapshot** (what the binary actually
  does, for consumers — chiefly family-beacon — and contributors): as-built data
  model, the implemented endpoints, auth/signing contract, push/revocation/quota
  behavior, transport security, the sund-client contract, test coverage, and an
  honest "not built yet" list. Ground truth of the code; the PRD stays design intent.
- `docs/Sund-Pinning-Contract.md` — **normative** transport-trust contract every
  client (sund-client; family-beacon's Android/iOS/web) MUST implement for
  pinned-TLS mode: the `sund://host:port#fingerprint` address, what is pinned
  (SPKI SHA-256 of the offline CA), the verification algorithm, rotation, and the
  MUST/MUST NOT rules. Keeps three client implementations from drifting.
- `docs/Sund-PriorArt.md` — survey (July 2026): SimpleX SMP is the closest
  incumbent; the gap Sund fills (blind transport + account/device model) is
  unoccupied. Its five design implications are incorporated in PRD 0.2.
- `docs/deviations.md` — where the code, the guide or an issue departs from the PRD
  or guide, one entry each, with status. Open entries are the agenda for the next
  spec revision (`~/projects/CLAUDE.md`, *Design flow*).
- Doc filenames are unversioned; the version lives in each doc's `Status:` line.
  Superseded PRD revisions (0.1, 0.2) live in git history, not as separate files.
