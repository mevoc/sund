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
backend of `../family-beacon`. **Spec only, no code yet.**

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

- `../family-beacon` — first consumer; formally adopted Sund as its backend
  (July 2026), closing its decisions #1 (E2EE) and #3 (Skerry coupling).
  Push-provider problem (#2) is shared.
- `../skerry` — grows around Sund; its PRD references Sund as Layer 1
  rather than respecifying it.
- The generic client library (`sund-client`: identity, pairing, sessions,
  queues, push) is scoped in `../family-beacon/docs/FamilyBeacon-Protocol-0_1.md`
  (Layering). It belongs conceptually to Sund and may move here when built.
- Supersedes the Layer-1 subset of
  `../skerry/docs/FamilyBeacon-MicroCloud-0_5.md`.

## Docs

- `docs/Sund-PRD-0_3.md` — **current.** Two-plane architecture, pseudonymous
  queues, device list/revocation/key bundles, push architecture (UnifiedPush/ntfy
  on Android; vendor APNS gateway on iOS — pluggable provider interface),
  fingerprint-pinned server address, one-binary stack requirement. New in 0.3:
  push-ping fan-in stated in the threat model, invitation semantics (single-use,
  15-min TTL, revocable), device-list changes push + mandatory refetch, and a
  per-commit test strategy (unit + system suites, blindness audit). Stack locked
  July 2026: Go + SQLite (family-beacon ARCHITECTURE.md updated to match).
  Remaining open: iOS gateway operations, blob module, rotation policy.
- `docs/Sund-ImplementationGuide-0_1.md` — companion to PRD 0.3: components, API
  sketch (two planes), walkthroughs for first-device onboarding and second-device
  invitation (SimpleX-style QR bootstrap), each step mapped to Family Beacon.
  Also the test strategy: unit + system suites (both per-commit), the beaconsim
  client mockup, scenarios S1–S9. Its three surfaced open items are resolved in
  PRD 0.3.
- `docs/Sund-PriorArt-0_1.md` — survey (July 2026): SimpleX SMP is the closest
  incumbent; the gap Sund fills (blind transport + account/device model) is
  unoccupied. Its five design implications are incorporated in PRD 0.2.
- `docs/Sund-PRD-0_2.md`, `docs/Sund-PRD-0_1.md` — superseded revisions; kept for
  history.
