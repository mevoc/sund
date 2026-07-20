Sund — Prior Art Survey

Status: v0.1, surveyed July 2026

Scope of the question: does anything already ship Sund's combination —
(a) blind-by-construction store-and-forward queues for E2E-encrypted payloads,
(b) an app-neutral substrate (REST/SDK) rather than a chat product,
(c) multi-tenant accounts + device management + quotas,
(d) payload-free push wake-up,
(e) trivial self-hosting (one small binary)?

Short answer: no single incumbent covers all five. The closest is SimpleX's SMP
server (a + e). Each entry below states what it is, where it overlaps, and where
it falls short of the combination.

---

Closest incumbents

SimpleX SMP server (simplexmq) — THE one to study before writing code.
- Blind store-and-forward relay of E2E-encrypted messages via unidirectional
  per-contact queues. The server cannot tell who talks to whom: each queue has two
  unrelated random IDs (sender-side and recipient-side) plus separate verification
  keys, and queue addresses rotate. No user identifiers at all. Runs on low-power
  devices; in-memory store with append-only log; server certificate fingerprint is
  embedded in the server address (MITM protection).
- Falls short of Sund on: app-neutrality (it is the substrate of the SimpleX chat
  network, with an agent protocol geared to social contacts), accounts/tenancy/
  quotas/device management (deliberately none — that is its privacy feature), push
  (iOS goes through SimpleX's notification infrastructure), and stack (Haskell).
- Why not just run smp-server: Sund's consumers (Family Beacon, small apps) need an
  account/device model, admin provisioning and quotas — the things SMP refuses to
  have. But its queue design is strictly better than Sund PRD 0.1's on metadata:
  per-queue pseudonymous IDs hide the device graph, which Sund currently concedes.
  See "Design implications" below.

XMPP + OMEMO (Prosody, ejabberd)
- Mature store-and-forward with offline message queues, self-hostable, E2E via the
  OMEMO extension, mobile push via XEP-0357. Two decades of production hardening.
- Falls short: not blind by construction — E2E is an optional app-layer add-on;
  the server sees rosters, presence and rich metadata; large protocol surface;
  push payloads and mobile behavior are notoriously fiddly. Sund is roughly "the
  10% of XMPP Family Beacon needs, blind by default."

Signal-server
- The gold standard for E2E store-and-forward plus real device management
  (registration, prekey bundles, multi-device). Sealed sender reduces even
  sender-metadata.
- Falls short: not meaningfully self-hostable (AWS-coupled, unsupported for third
  parties), phone-number identity, app-specific. Study its device-registration and
  multi-device patterns; do not try to run it.

Nostr relays
- Simple, self-hostable, store-and-forward of signed events; identity is a bare
  keypair (a pattern Sund shares). Dozens of small relay implementations prove the
  "tiny relay binary" form factor.
- Falls short: public-by-default; DMs (NIP-04/44) still leak sender/recipient
  metadata to relays; no tenancy, quotas or device management; no push story.

ntfy / UnifiedPush
- Self-hostable pub/sub push; the standard answer to Google-free push on Android
  (UnifiedPush distributor). Not a competitor but a candidate component: Sund's
  payload-free push wake-up can be delivered via ntfy/UnifiedPush instead of
  reinventing it. Note: ntfy itself does no E2E — UnifiedPush expects app-layer
  encryption (RFC 8291) and some apps fake it. Sund's payload-free design sidesteps
  this: a wake-up ping carries nothing to encrypt.
- iOS remains APNS-only regardless (family-beacon open decision #2, unchanged).

MQTT brokers (Mosquitto et al.)
- Tiny, battle-tested store-and-forward (QoS 1/2, retained messages), runs
  anywhere. The IoT default.
- Falls short: no E2E or identity model beyond TLS/certs, topics are not blind, no
  tenancy/quotas, no mobile push wake-up. Adopting it would mean building all of
  Sund's actual value on top of a broker that fights the blindness principle.

Matrix (Synapse / Dendrite / Conduit)
- Self-hostable, E2E (Megolm), federated, multi-device.
- Falls short: heavyweight by design (room state, federation), server sees
  considerable metadata, operationally the opposite of the one-binary bar.

---

Same shape, different purpose

- Syncthing relays (strelaysrv): blind encrypted relays run by volunteers — but
  transit-only (no storage) and for file sync, not message queues. Validates the
  "untrusted relay" trust model at scale.
- Magic Wormhole transit relay: blind relay for ephemeral transfers; no
  store-and-forward, no persistence.
- Delta Chat: uses ordinary email (SMTP/IMAP) as the store-and-forward substrate
  with Autocrypt E2E. Proof that "dumb store-and-forward + client-side crypto" is
  sufficient for a full product — but email servers are metadata-rich and
  operationally heavy; Sund is the purpose-built version of this idea.
- Paseo relay, CryptPeer (2025–26): new small entrants relaying NaCl-boxed bytes
  through an untrusted server for a single app. The pattern is spreading;
  none offers a multi-app substrate.
- Holm (holmhq.com): overlaps on operational bar and agent platform, already
  covered in Skerry's PRD (Prior Art & Positioning). No blind relay — Holm's
  server reads app data by design.

---

Gap analysis

The combination is open. Incumbents cluster at two poles: privacy-maximal chat
substrates with no account model (SimpleX, Nostr) and account-full platforms that
are not blind (XMPP, Matrix, MQTT, Holm). Sund sits deliberately between: blind
transport with just enough account/device structure for self-hosted apps to build
on. That middle position is the thesis — and the survey found it unoccupied.

---

Design implications for Sund (feed into PRD 0.2)

1. Steal SimpleX's queue addressing. PRD 0.1 concedes the device graph to the
   host. Per-queue pseudonymous IDs (distinct sender-side and recipient-side IDs,
   rotatable) would hide sender↔receiver correlation at modest cost. Read the SMP
   protocol document before freezing Sund's queue design. Open question: is this
   compatible with per-account quotas, which require attributing storage to an
   account? (Likely yes — quota on the recipient queue, blind to the sender.)
2. Adopt, don't build, the Android push leg: UnifiedPush/ntfy as the wake-up
   channel; payload-free pings make ntfy's lack of E2E irrelevant.
3. Copy Signal's device-registration ergonomics (prekey-style bootstrap, explicit
   device list with revocation) without adopting its infrastructure.
4. Embed the server certificate fingerprint in the server address (SimpleX
   pattern) for first-connect MITM protection — cheap and effective for the
   self-host audience.
5. Nostr's ecosystem shows demand for tiny relay binaries — reinforces the
   one-binary decision (open decision #1) over a JVM stack.

---

References

- SimpleX: github.com/simplex-chat/simplexmq (protocol/simplex-messaging.md),
  simplex.chat/docs/server.html
- UnifiedPush/ntfy: unifiedpush.org, docs.ntfy.sh
- Signal server: github.com/signalapp/Signal-Server
- Nostr: github.com/nostr-protocol/nips
- Syncthing relays: docs.syncthing.net (strelaysrv)
- Delta Chat: delta.chat (Autocrypt)
- Paseo relay: github.com/zenghongtu/paseo-relay; CryptPeer: cryptpeer.com
- Holm: holmhq.com (see also Skerry PRD, Prior Art & Positioning)
