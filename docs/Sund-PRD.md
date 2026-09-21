Sund

«A blind strait between your devices.»

Status: PRD v0.4 (Draft) — supersedes PRD 0.3

> Working name: **Sund** (Swedish: a strait between islands — the channel between
> skerries; also "sound, healthy"). The kernel extracted from Skerry
> (`../skerry`). This revision adds one thing: an optional per-account
> administration model (decision 12). An account may now restrict revoking a
> device, minting an invitation and changing a role to devices holding an admin
> role, instead of granting all three to every device equally. The flat account
> of PRD 0.3 remains the default and is unchanged in behaviour, and the mode is
> opt-in per account, and family-beacon's roster spec as written is incompatible
> with it on anti-stalkerware grounds — a conflict recorded under Threat model →
> Administration rather than settled here. The change is listed at the end under
> "Decisions in this revision"; the eleven decisions of PRD 0.2 and 0.3 carry
> over unchanged.

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
- Infrastructure, not application. All business logic lives in clients. The one
  class of rule Sund does enforce is authorization over its *own* operations, for
  the reason set out in Threat model → Trust boundary.
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
- Administration mode: an account is `flat` (default) or `managed`, chosen at
  provisioning and not changeable afterwards — there is no endpoint for it, and
  that refusal is the whole specification. It decides which role a device gets
  when it registers, and whether roles may be changed at all — see Devices →
  Roles and administration. A `flat` account behaves as PRD 0.3 did, with one
  addition that applies in both modes: minting an invitation now pings the
  account. Named *administration* mode to stay clear
  of the two **transport**-trust modes of decision 11, which are an unrelated
  axis.

Devices
- Ed25519 keypair per device; the server stores the public key only.
- Bootstrap: QR code carrying the server address (including certificate
  fingerprint in pinned mode, see Server address) and a one-time token.
  Verification → registration → the new device appears in the account's device
  list.
- Invitations: enrollment tokens are single-use and short-lived (default TTL
  15 minutes, operator-configurable). A token is consumed atomically by the first
  successful registration; a second use, or use after expiry, fails closed. A
  token also carries the role its bearer will hold, so a device never exists in
  an account before its role is settled, and minting one wakes the account's
  other devices like any other administrative act. Outstanding invitations are
  listable by
  every device and revocable by every device — including in a managed account,
  deliberately: killing an invitation is fail-safe (it denies an enrollment and
  destroys nothing), so the fastest possible response to a mis-shared QR is worth
  more than the ability of a hostile member to be obstructive.
- Explicit device list: every device in an account can see all registered devices
  (id, role, created, last_seen, capabilities). Revocation is a first-class
  operation; a revoked device's identity key and queue access die immediately,
  and its undelivered messages are dropped along with its queues. Revocation is
  destructive and has no undo — part of why an account may want it gated.
- Device-list change propagation: every administrative act — registration,
  revocation, role change and invitation minting — triggers a contentless ping to
  every device in the account other than the one that performed it, never only to
  the admins. This includes an operator-side `sund admin device promote`, which
  pings *every* device since no device performed it: the host is the one party
  the role model cannot bind, so it must not also hold the only silent role
  change. A revocation pings its target too — it is a device the act was
  performed on, and the one with most reason to be told — so the ping is
  attempted *before* the target's push endpoint is cleared, in the same step; an
  unreachable target learns instead from its next request, which fails closed, and
  a consumer that promises a removed device will be told cannot rely on the ping
  alone. Because a ping carries nothing, a woken client cannot know *which* act
  fired it: the rule is to refetch the device list and the invitation list on any
  ping, not to refetch selectively. Pings are best-effort — clients MUST
  additionally refetch the device list before establishing any new session or
  pairing, so a missed ping costs latency, never security.
- Roles and administration: each device holds a role, `admin` or `member`. The
  account's administration mode decides which role a *newly registered* device
  gets — in a `flat` account every device registers as an admin; in a `managed`
  account a device registers with the role its invitation granted, defaulting to
  `member`. The first device of an account is always an admin. Authorization is
  then one rule. Two of its three clauses are evaluated identically in both modes
  — flat is simply the case where every device is an admin, not a second code
  path — and the third is the one place the mode itself is consulted:

    - Admin only: revoking another device, minting an invitation.
    - Any device, always: listing devices and invitations, revoking an
      outstanding invitation, revoking *itself*, and the whole transport plane.
    - Changing a device's role: admin only, and refused outright in a `flat`
      account. Flat means "every device is an admin" as a property of the
      account, not as a coincidence of the current rows — so there is nothing to
      promote and nothing to demote, and a flat account cannot be walked into a
      managed one one demotion at a time.

  **A device may always revoke itself**, with no exception, including the last
  admin. Withholding self-revocation protects nothing — a device can discard its
  own key regardless — and it is the one act a device must always be able to
  perform on itself. It is also the only remedy a member has against an admin,
  which is why it is unconditional rather than merely usual.

  One invariant the server enforces: **an account never loses its last admin to
  an act performed on another device.** The last non-revoked admin cannot be
  demoted, and cannot be revoked by a different device; promoting a second admin
  first is the only way through. The check and the write are one transaction, so
  two admins revoking each other concurrently cannot both pass — one of them
  becomes the last admin and its revocation is refused. That is a requirement,
  not an implementation note: evaluated outside a transaction the invariant is
  merely usually true, which is the same as false. It deliberately does not
  extend to
  self-revocation, so one bad state stays reachable: the sole admin of a managed
  account can leave, stranding members who can then neither invite nor revoke.
  Sund makes that recoverable from outside rather than preventing it —
  `sund admin device promote <device-id>` is the operator's way back in — and a
  consumer SHOULD keep a second admin in any managed account. Promote is refused
  against a revoked device, and in a flat account, where every non-revoked device
  is already an admin and there is nothing to promote. A single-device
  account self-revoking is the degenerate case: an empty account, nobody
  stranded.

  **No silent administration** is the second requirement, and it splits by who
  can be held to it:

    - Sund's half, which is testable: role is a field of the device list every
      device reads, and every administrative act — registration, revocation, role
      change, invitation minting — pings every other device in the account, never
      only the admins.
    - The consumer's half, which Sund requires and cannot verify: a client MUST
      render each device's role, and MUST surface an administrative change to the
      user rather than silently absorbing the ping. A client that does neither is
      still contract-conformant and administers covertly; Sund has no way to
      know. This is an obligation of the same kind as "consuming apps must state
      the residual metadata honestly", and it is backed by the same thing —
      the consumer's own review, not the server.

  A refused attempt is invisible, and that is worth naming rather than leaving to
  be discovered: a member that probes for escalation — trying to revoke a peer,
  mint an invitation, promote itself — changes nothing, so nothing pings and
  nothing is stored. Recording the attempt would mean recording the actor and its
  target, which is the edge the model exists to avoid. Sund accepts unobserved
  probing as the price of storing no administration log; a consumer that wants
  failed attempts surfaced has to carry them client-side.

  What a member learns is bounded on purpose. It sees the account's current roles
  and is woken whenever they change; it does not learn *which* admin acted, or
  when. Sund records no actor and no history for an administrative act, because
  an "X revoked Y" row would be precisely the device→device edge the data model
  refuses. The transparency on offer is "you can always see the current
  distribution of power, and you are always told when it moved" — not an audit
  trail. A consumer that wants one builds it client-side, ledgered end-to-end,
  where it is not the host's to read.

  This is the first asymmetry of power Sund's substrate encodes, and it is
  deliberately the smallest one that closes the hole: a per-device attribute, not
  a relationship. It is not a permission system and does not grow into one. It
  says nothing about which device may reach which — that stays the consumer's,
  and stays unrecorded (Threat model → Trust boundary). It is also optional, and
  there is a serious argument that a family-shaped consumer should decline it —
  see Threat model → Administration.
- Key bundles: each device may publish a small, size-capped, opaque blob of
  client-side key material (e.g. prekeys for X3DH-style async session setup),
  retrievable by other devices in the account. The server never interprets it —
  it is a dead-drop, not a crypto service. This is what makes mesh pairing scale:
  a new device can pair with an *offline* peer by fetching its bundle, instead of
  needing a co-present QR ceremony with each one. Bundles are self-authenticating
  to clients — signed by the publishing device's identity key and verified by the
  fetcher against the device list — so a malicious host cannot substitute a forged
  bundle even though Sund serves it without checking.

  One-time prekeys create a tension worth stating. Strict X3DH forward secrecy
  wants each one-time prekey used once, which a classic prekey server enforces by
  *popping* a key per fetch — but popping requires understanding the blob's
  structure, which Sund refuses to do. Sund's stance follows the dead-drop rule:
  it returns the same bytes to every fetch and pops nothing; the client owns
  one-time-prekey management — by rotating its published bundle, or by using an
  X3DH variant without one-time prekeys (accepting slightly weaker
  initial-message forward secrecy). Which of those a consumer picks is a
  client-protocol decision, and it is why the exact bundle *format* is the
  consumer's to define; Sund only stores and serves it.

  Reachability is a consumer choice, not a Sund default. Knowing a device exists
  does not make it addressable: sending requires a queue sender ID — a per-queue
  secret the recipient minted — which the device list (device IDs only) never
  reveals. What can turn "I can see you" into "I can reach you" is a published
  bundle that carries an initiation address, the convenience that enables async
  mesh pairing. So consumers pick their own reachability topology on the same
  server:
    - Grant-only reachability: bundles carry no self-serve address; a device is
      reachable only by peers it has explicitly handed a sender ID (out of band
      or via a pairing message). The device list stays a harmless directory, the
      account is not a fully-connected mesh, and no server permission or stored
      graph is needed. This is how a consumer confines a newly invited device to
      its inviter until further introductions are made.
    - Published-bundle mesh: bundles carry a reachable address, so any member can
      initiate with any offline peer without ceremony. This scales pairing (the
      reason bundles exist) at the cost of making every member reachable — and
      spammable — by every other (see Threat model → Trust boundary).
  Neither needs a server change; the lever is entirely the consumer's bundle
  format, which is another reason Sund leaves that format to the consumer.

Queues
- A queue is a unidirectional channel owned by one recipient device, created by
  that device. On creation the server issues two unrelated random IDs: a
  recipient ID (used by the owner to read/ack) and a sender ID (handed to the
  sending device out-of-band or via an invitation message). The server stores
  per-queue authentication keys supplied at creation; sender-side keys are
  per-queue, not device identity keys.
- Consequence: the server's records do not link a sender device to a queue. The
  who-talks-to-whom graph is not stored.
- Rotation (client-driven — a security-hygiene practice, not an open question):
  the owner mints a replacement queue, hands the new sender ID to the peer over an
  existing encrypted channel, and retires the old one; clients rotate
  periodically. Rotation bounds how long any (recipient, sender) pair persists —
  shrinking the window a host has to profile a queue from timing — and it
  completes revocation on the sender side, since the server structurally cannot
  kill a sender's access to a queue (there is no stored sender↔queue link to
  revoke). The server assists exactly as far as it can while staying blind: a send
  to a retired queue fails closed, which is the stale sender's signal to fetch a
  new address. It deliberately offers no old→new redirect or forwarding — that
  would force the server to learn the very who-talks-to-whom graph it refuses to
  store. Caveat: retire drops the queue's undelivered messages, so a rotating
  owner drains the old queue before retiring it.
- V1 scope: queues connect devices within the same account.

Messages
- Send (by sender ID), receive/ack (by recipient ID), per-message TTL, delivery
  status. Queues survive offline receivers; expired messages are deleted unread.
- Payloads are opaque ciphertext, size-capped per quota.

Push wake-up
- A ping carries nothing — no payload, no queue ID. It only tells a device
  "check in"; the client then drains its queues over the API.
- Pings are sent on message arrival (transport plane, via queue ownership) and on
  every administrative act — registration, revocation, role change and invitation
  minting (management plane, see Devices). A mint changes no device list, which is
  why the trigger is the act and not the list.
- Delivery paths differ fundamentally per platform — see Push architecture.

Health and metrics endpoints.

---

Data model (the whole of it)

accounts     — id, created, quota, status, admin_mode
devices      — id, account_id, public_key, role, push_endpoint, capabilities,
               created, last_seen, revoked
bundles      — device_id, blob (opaque, size-capped), updated
invitations  — token_hash, account_id, created, expires, consumed, grants_role
queues       — recipient_id, sender_id, owner_device, recipient_key, sender_key,
               created, retired
messages     — queue_id, payload, received_at, ttl, status

There is deliberately no sender_device column anywhere in the transport plane.

The three columns added in 0.4 — admin_mode, role and grants_role — are
attributes of an account, a device and a token. None of them is an edge: nothing
here records a relationship between two devices, in either plane. Nor is one
created at runtime — an administrative act is evaluated and applied, never
recorded with its actor, so there is no "X revoked Y" row and no administration
log anywhere in the schema. That is the line the model is built to stay behind,
and it is why it offers current-state transparency rather than an audit trail.

---

Server address

A server address is what the QR bootstrap code carries, and it determines how the
client establishes transport trust. There are two modes, and the address states
which — it is never negotiated at connection time. Both are first-class; the
scheme is the discriminator. Normative client contract:
`Sund-Pinning-Contract.md` (v0.2).

Pinned mode — sund://host:port#<certificate-fingerprint>

The address embeds the fingerprint of the server's offline certificate (SimpleX
pattern), so a new device pins the server identity on first contact. A
man-in-the-middle on first connect is detected, not trusted.

WebPKI mode — sund+webpki://host[:port]

Sund runs as plain HTTP behind a TLS-terminating reverse proxy holding a
publicly trusted certificate. Identity is the domain name, verified by the
platform's ordinary TLS stack (chain to the system trust store, SAN hostname
check). No fingerprint travels in the address, and the absence of one is not how
the mode is signalled — a distinct scheme is, so that stripping a fragment
cannot silently downgrade a pinned deployment.

Two-layer certificates. The fingerprint is the SHA-256 of a long-lived offline
CA's SubjectPublicKeyInfo. That CA signs a shorter-lived online (leaf)
certificate used for the live TLS handshake, so the server can rotate the leaf
without changing the pin — clients keep trusting the same address. The client
disables WebPKI (no public CA, no hostname check) and accepts a connection only
if a presented certificate's SPKI fingerprint matches the pin and the leaf
validly chains to it. This needs no CA, no domain, and works on a bare IP or LAN;
trust is anchored in the QR ceremony, the same physical co-presence that
authenticates device pairing.

Choosing between them. Pinned mode is the stronger model and remains Sund's
self-host-first default: trust rests on one operator-held key delivered by
physical co-presence, rather than on the public CA ecosystem (any trusted CA can
issue for a domain) and on DNS. It also needs no CA, no domain and no correct
DNS, which is what makes "install and run it on your own box" true.

WebPKI mode is not a concession to operators who dislike certificates; two
things force it. A browser cannot pin — there is no API for it, and a request to
a self-signed origin fails — so any web client requires WebPKI. And pinned mode
is typically served on a non-standard port, which is blocked on many hotel,
school, guest and corporate networks; a consumer whose value depends on working
away from home may rationally weigh reachability above the trust-model
difference. Family Beacon does exactly that and recommends WebPKI mode for all
of its deployments. Sund takes no position on which a given consumer picks — it
specifies both so the choice is a deployment decision rather than a fork in the
client.

What does not change with the mode: payloads are end-to-end encrypted
independently of the transport, so message confidentiality is identical either
way, and the blindness model is untouched. What does: WebPKI mode publishes the
hostname in Certificate Transparency logs, and the proxy is one more component
inside the operator's trust boundary that can log request metadata. A mode
change on a running deployment re-pairs every device (contract §8.5), so the
choice belongs before onboarding, not after.

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
- Stolen or leaked invitation QR: tokens are single-use with a short TTL, can be
  revoked before use by any device, and minting one already pinged the account; a
  consumed token registers a device that is immediately visible in every member's
  device list — no silent enrollment. The blast radius varies with the role the
  token grants: a stolen admin-granting invitation enrolls a device that can then
  revoke and enroll, which is a reason to mint those sparingly and to prefer a
  short TTL still.
- Member device turned hostile, in a managed account: it cannot revoke another
  device, enroll one of its own, or change a role. In a flat account it can do
  all three — that is the mode's stated cost, not a defect. The converse case, an
  *admin* turned hostile, is not defended against and is the strongest argument
  against using the mode at all; both are argued under Administration.
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
- Who acted on whom, in live traffic: a revocation or role change carries the
  acting device's id in its signature headers and names its target in the path,
  so a host watching requests sees the pair even though nothing stores it. This
  is the management-plane twin of push-ping fan-in — runtime, not recorded — and
  the same honesty applies: the binary keeps no access log (it logs errors only),
  so the claim holds today at runtime as well as in the schema, but a host that
  chose to log would learn it.
- The account's administration shape, from all three columns 0.4 adds:
  `admin_mode` tells a host whether an account is flat or managed before any
  device has registered; `role` tells it which device administers a managed
  account; and `grants_role` tells it, at mint time, that an account is about to
  add an admin rather than a member. A flat account exposes only the first, and
  exposes it uniformly.
- On iOS, wake timing (though nothing else) is additionally visible to the vendor
  push gateway and to Apple — see Push architecture.

Trust boundary — the account. Sund has no notion of which member may see or talk
to which: the device list is visible to all members, and reachability between them
is governed entirely by the consumer's pairing protocol (see Devices → Key
bundles, Reachability). What 0.4 changes is narrower than it sounds — the account
is still the trust boundary, and every non-revoked device in it is still trusted
to read the device list and to use the transport plane. Only three acts are
gated — revoking another device, minting an invitation, changing a role — of the
four the propagation rule calls administrative; the fourth, registration, is
gated by holding a valid token instead. Consequences a consumer must weigh:

- A compromised or malicious member device can enumerate the account's device
  list and, if the consumer publishes reachable bundles, initiate to any peer
  unsolicited. A managed account does not change this.
- Because quota is attributed to the recipient and senders are pseudonymous (no
  sender_device to rate-limit), such a member can consume a victim's quota by
  filling its queues; the transport plane cannot throttle per sender. A managed
  account does not change this either — the remedy is still revocation, now by an
  admin rather than by anyone.
- In a flat account, revocation is the remedy against a member turned hostile and
  is equally available *to* that member: any device may revoke any other. A
  managed account is the answer to that symmetry.

Two kinds of restriction, and why only one of them belongs in the server. Sund's
rule is that a restriction lives wherever it can actually be enforced:

- Reachability is client-enforceable. A sender ID is a secret the recipient minted
  and handed over; the server never brokers one. A consumer that withholds it has
  enforced the restriction completely, without the server knowing a thing. So
  "who may talk to whom" stays out of Sund — a stored may-talk-to graph remains
  deliberately out of scope, because it is application policy *and* it would
  reintroduce exactly the relationship metadata Sund refuses to record.
- Administration is not. Revocation, enrollment and role changes are operations
  the *server* performs; only the server can refuse one. PRD 0.3 called an admin
  restriction "app-level policy", which does not hold up: a client-side rule that
  only the parent's phone may revoke is enforced solely by the device it
  restricts, and a member turned hostile just signs the request itself. That is
  the hole decision 12 closes, and it is closed with a per-device attribute
  rather than a graph, at the cost stated under Administration.

This remains the right boundary for Sund's consumers. Which mode an account runs
is the consumer's decision and is not a function of how family-shaped it is — a
family may rationally choose flat, and Sund's first consumer does; see
Administration. A consumer whose account may hold mutually-distrusting devices
must still not publish self-serve reachable bundles (use grant-only reachability)
and must still enforce peer-acceptance in the client; roles substitute for
neither.

Administration — what the role model binds, and what it does not. Roles are
enforced by the server, so they constrain the account's own devices and nothing
else. A hostile host can ignore a role bit, revoke any device it likes, invent an
enrollment or lie about who holds admin, exactly as it could before 0.4. The model
defends against two things and claims no more:

- Mistakes. Revocation is destructive and has no undo (it drops the target's
  undelivered messages along with its queues), and in a flat account every device
  can do it to every other. This is the common case the model is for.
- A member turned hostile. In a managed account a compromised member device can
  no longer wipe the account's other devices or enroll one of its own.

It does not defend against the host and must not be documented as if it does. The
upgrade that would partly bind the host — having the acting admin sign an
administrative statement so peers verify it instead of trusting the server — is
Open decision 2.

Nor does it defend against a hostile *admin*, and that is the serious argument
against the mode rather than a footnote to it. A member's only remedy against an
admin is to revoke itself and leave, which is exactly why self-revocation carries
no exception. Family Beacon, Sund's first consumer, has a roster rule that
predates this mode and is incompatible with it for exactly this reason. Its
wording is worth quoting rather than paraphrasing: `FamilyBeacon-Roster.md`
(Removal) is normative that "any active device may remove any other device —
there is no privileged remover", because "concentrating removal in an 'admin'
would hand exactly the wrong person a lock", and it judges the
permissive rule's failure mode (eviction: loud, ledgered, recoverable by
re-pairing) preferable to the restrictive rule's (a person trapped in a family
they cannot alter). Sund does not overrule that and is not in a position to: it
cannot see a family. `flat` is the default, `managed` is opt-in per account, and
a consumer is free never to offer it — which is where family-beacon's rule as
written leaves it. Whether any
family-shaped consumer should use managed mode is a cross-repo question this
revision raises and does not settle.

The anti-stalkerware note, since a consumer will ask: a managed account is the
first place where Sund's substrate lets one device act on another. What makes it
acceptable is the visibility requirement in Devices → Roles and administration —
power in an account is visible to the devices it is held over, and every
administrative act wakes them. The limit belongs in the same sentence: that makes
covert administration *detectable by a conforming client*, not impossible. Pings
are contentless, and Sund cannot see whether a client renders role or surfaces
the change, so a client that swallows both administers covertly and Sund will
never know. Devices that must not be subject to another's administration at all
do not belong in the same account: the account is the isolation boundary, and
always was.

Sund does not claim traffic-analysis resistance. Consuming apps must state this
honestly in their privacy documentation.

---

Non-goals

- No application logic, ever (see Architecture Principle). Decision 12's
  administration model is authorization over Sund's own operations, not
  application logic; the distinction is argued in Threat model → Trust boundary.
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

See `Sund-PriorArt.md`. The queue design above adapts SimpleX's SMP addressing
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
- `Sund-ImplementationGuide.md` — companion: components, API sketch and
  end-to-end walkthroughs (first-device onboarding, second-device invitation),
  each step mapped to Family Beacon. This PRD is normative where they disagree.
- Lineage: supersedes the Layer-1 subset of
  `../skerry/docs/FamilyBeacon-MicroCloud-0_5.md` and all of Sund PRD 0.1
  and 0.2.

---

Decisions in this revision

The five decisions of PRD 0.2 (SimpleX queue addressing, UnifiedPush/ntfy push
leg, Signal-style device management, fingerprint-pinned server address,
one-binary stack requirement) carry over unchanged. Items 6–11 were added in 0.3:
the three open items surfaced by the implementation guide, the test strategy, the
stack lock and the second transport-trust mode. Item 12 is new in 0.4:

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
11. Two transport-trust modes, both first-class. Decision 4 of PRD 0.2 chose the
    fingerprint-pinned address; it stands, and pinned mode remains the
    self-host-first default. What changes is that the WebPKI-proxy deployment is
    no longer an unspecified footnote: it has a normative address form
    (`sund+webpki://host[:port]`) and client algorithm in
    `Sund-Pinning-Contract.md` §8, because family-beacon adopted it as its
    recommended deployment for port-443 reachability and because a web client
    cannot pin at all. A distinct scheme rather than a fingerprint-less
    `sund://`, so that stripping a fragment fails closed instead of silently
    downgrading. Clients implement both; there is no fallback between them, and
    switching modes re-pairs every device.
12. Optional per-account administration. An account is `flat` (the default, and
    0.3's behaviour: every device registers as an admin and may do everything) or
    `managed` (devices register as members; revoking another device and minting
    an invitation become admin-only, and roles become changeable at all). The
    reason this is a server concern and not, as PRD 0.3 had it, app-level policy:
    revocation is a server operation, so a client-side rule restricting it is
    enforced only by the very device it restricts. Reachability, by contrast, is
    genuinely client-enforceable and therefore stays the consumer's. Costs,
    stated rather than designed away: the three new columns are readable by the
    host (Threat model, residual metadata); the model binds members, not the host
    (Administration); and it does not bind a hostile admin either, which is why
    self-revocation is unconditional and why family-beacon's roster rule, written
    before this mode existed, is incompatible with it on anti-stalkerware grounds
    — a conflict this revision records instead of resolving. One server-enforced
    invariant keeps an account administrable: it never loses its last admin to an
    act performed on another device (self-revocation excepted, with an operator
    recovery path). Scope discipline:
    two roles, one flag, no permission system, no actor recorded for any
    administrative act; the account stays the trust boundary and no may-talk-to
    graph is introduced.

Open decisions remaining

1. iOS push gateway operations (shared with family-beacon #2): who operates the
   vendor gateway, what availability it promises, and whether pings get
   batching/jitter to blunt timing analysis at the gateway. The architecture
   itself is settled in Push architecture; "no lock-in" is structurally
   unattainable on iOS — only containment is.
2. Signed administrative statements. A role change or revocation is a server-side
   fact, which a hostile host can fabricate — a forged revocation is enough to
   make honest peers drop a device's queues and re-key. The fix is for the acting
   admin to sign the statement, for Sund to store it opaquely, and for peers to
   verify it against the device list — exactly how key bundles are already stored
   and verified, so no server-side crypto is added and the dead-drop rule holds.
   The server would keep the liveness half: it must actually stop serving a
   revoked device, and it can deny service regardless. Open because the statement
   format is a client-protocol decision (as the bundle format is) and because no
   consumer has yet asked for administration that survives a hostile host.
   Deferred, not rejected: 0.4's model is a mistake-and-member defence and says
   so.

Resolved since first listed as open (no longer decisions):

- Blob/object storage — a Non-goal, not an open question: add it only when a
  consumer demonstrates need, as a separate optional module keeping the same
  blindness guarantee (see Non-goals). Distinct from key bundles, which are in
  scope and store opaque client key material.
- Queue rotation — client-driven by design; the existing primitives (create /
  retire, and a fail-closed 404 for a stale sender) are sufficient, and no
  server-assisted redirect is wanted because it would reintroduce the sender↔
  recipient graph. See Queues (Rotation).

---

Motto

«Own the strait. The cargo stays sealed.»
