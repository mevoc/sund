Sund

«A blind strait between your devices.»

Status: PRD v0.13 (Draft) — supersedes PRD 0.12

> Working name: **Sund** (Swedish: a strait between islands — the channel between
> skerries; also "sound, healthy"). The kernel extracted from Skerry
> (`../skerry`). This revision adds the third and last level of the storage
> quota: a ceiling on a single queue (decision 17). It is the sender bound the
> threat model has always said it lacked, reached from the other side — a
> recipient mints one queue per peer, so *which peer* is already *which queue*,
> and capping the queue caps the peer without the server ever learning who it is.
> Unlike the device ceiling it is set by the queue's own owner, which makes it
> nobody's weapon and so needs none of decision 13's machinery. The rate-shaped
> variant that would also stop ping-spam is deferred, because its counter would
> be the first state here that outlives the data it describes.
>
> PRD 0.8 did three things, for context: decision 16 (a device's ceiling is
> read by the device it caps and nobody else), the residual-metadata list
> restructured by observer *and by what observing enables*, and what sharing an
> account costs two co-located server components.
>
> Decisions 12, 13, 16 and 17 were unimplemented while 0.4 through 0.9 were
> written, which is why each cost nothing to revise as the next exposed a flaw in
> the last. They are built as of 2026-09-24; `Sund-Status.md` is the ground truth
> for what the binary does.

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

That single meeting point is exercised in three ways: statically for quota
(storage attributed to the owner device and its account), at runtime for wake-up
(a message arriving in a queue makes the server resolve queue → owner device and
ping it), and on demand when a device reads its own stored bytes
(`GET /v1/me/quota`, PRD 0.5) — the same resolution, asked for by the device the
answer is about.
The runtime form — push-ping fan-in — links queue activity to a device in live
behavior, never in the schema; it is stated explicitly in the Threat model.

---

Principles

- Blind by construction. Public keys, encrypted payloads, minimal routing metadata.
  Nothing to leak, nothing for a host to covertly read.
- Infrastructure, not application. All business logic lives in clients. The one
  class of rule Sund does enforce is authorization over its *own* operations, for
  the reason set out in Threat model → Trust boundary.
- Multi-tenant by design. The management plane is account-isolated: a device
  sees only its own account's devices, bundles and invitations, and can revoke
  only within it. The transport plane is not a tenancy boundary at all — it is
  authenticated by per-queue keys, which is the point of it (see Queues, and
  Threat model → What an account is and is not).
- Self-host first. One small static binary, one database file. Install. Deploy.
  Backup. Upgrade. (The Holm bar.)
- Adopt, don't build. Where sound self-hostable components exist (UnifiedPush/ntfy
  for Android wake-up), Sund integrates them instead of reinventing them.
- API-first. Everything reachable via a documented, signed API.
- Minimal metadata, honestly stated. What the server must store, it stores briefly
  (TTL) and legibly — documented here, auditable in the schema. "Briefly" is a
  promise about the server, not about client behaviour: expiry is enforced by a
  background sweep as well as on drain, so a queue whose owner never returns does
  not become indefinite storage.

---

Scope — V1

Accounts
- Multi-tenant isolation **on the management plane**, per-account quotas,
  root-admin provisioning. The transport plane is not account-scoped; see
  Threat model → What an account is, and is not.
- Quotas are attributed to the queue owner's account (the recipient side — the
  side the server knows). Senders stay pseudonymous without breaking accounting.
- Storage quota has three levels, all recipient-side and all optional: a ceiling
  on the account's stored bytes, one on an individual device's, and one on a
  single queue's (decision 17). A send is refused if it would take *any* of them
  past its ceiling. Device ceilings need not
  sum to the account ceiling — over-committing is normal and correct, exactly as
  it is for disk quotas — and a device with no ceiling of its own is bounded only
  by the account's, which is PRD 0.4 behaviour. "Stored bytes", the boundary rule
  and what a ceiling does when lowered are defined in Devices → Storage quota,
  which is also where the second level's costs are stated.
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
  (id, public_key, role, capabilities, created, last_seen and whether it is
  revoked). Two per-device fields are deliberately *not* in it: `quota_bytes`,
  which is read by the device it caps and nobody else (decision 16), and
  `push_endpoint`, which is returned only to the device that set it
  (decision 20). What the list does expose between peers is enumerated under
  Threat model → residual metadata. Revocation is a first-class
  operation; a revoked device's identity key and queue access die immediately,
  and its undelivered messages are dropped along with its queues. Revocation is
  destructive and has no undo — part of why an account may want it gated.
- Device-list change propagation: every administrative act that changes what the
  account's devices see — registration, revocation, role change and invitation
  minting — triggers a contentless ping to every device in the account other than
  the one that performed it, never only to the admins. `sund admin device
  promote` is performed by the operator rather than by a device, so it pings
  *every* device, there being no actor to exclude. The fifth administrative act,
  a storage-ceiling change, is the exception that proves the rule: it changes
  nothing any other device can read, so it pings only the device it affects (see
  Storage quota). That is not a courtesy: the host is the one party none of this
  binds, so it must not also hold the only silent act. A
  revocation pings its target too — it is a device the act was
  performed on, and the one with most reason to be told — so its endpoint is
  captured before revocation clears it and the ping is dispatched once the
  revocation commits, rather than before, so a failed revocation never tells a
  device it was removed; an
  unreachable target learns instead from its next request, which fails closed, and
  a consumer that promises a removed device will be told cannot rely on the ping
  alone. Because a ping carries nothing, a woken client cannot know *which* act
  fired it: the rule is to refetch the device list, the invitation list **and
  `GET /v1/me/quota`** on any ping, not to refetch selectively. The quota read
  joined that rule in 0.8 and is load-bearing, not tidiness: once a ceiling left
  the device list (decision 16), a ceiling change became the one administrative
  act a conforming client could not otherwise detect — it would refetch both
  lists, find nothing changed, and learn nothing. Pings are best-effort —
  clients MUST additionally refetch the device list before establishing any new
  session or
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
      change and invitation minting — pings the account's other devices, never
      only the admins; `promote`, performed by the operator rather than by a
      device, pings every device, there being no actor to exclude. A
      storage-ceiling change pings only the device it affects, which is the same
      rule rather than an exception to it: the party a ceiling is held over is
      that one device (Storage quota, decision 16).
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
- Storage quota: a device may carry its own ceiling beside the account's. This
  costs no new linkage. Quota is already attributed by resolving queue → owner
  device → account, so counting to the device instead of to the account uses a
  join the server already performs — one join fewer, in fact; it learns nothing
  it was not already computing, and queue ownership is already disclosed as the
  one sanctioned transport→management link (Threat model).

  **Stored bytes**, defined once and used everywhere below: the summed length of
  the ciphertext payloads a device's queues are holding — messages accepted, not
  yet acked, and not yet expired. Expired-but-unpurged rows do not count (they
  are unreachable and are dropped on the next drain; see the lazy-purge entry in
  `docs/deviations.md`), and nothing outside the payload counts — no envelope,
  no transport framing, no base64 expansion.

  Enforcement, stated tightly enough to become acceptance criteria:

    - A send is refused when it would take the owning device's stored bytes past
      its ceiling, or the owning account's past the account ceiling. Whichever
      trips, the refusal is the same.
    - The boundary is inclusive: a send landing *exactly* on a ceiling succeeds.
      Only exceeding it fails. (This matches the account check as built.)
    - `0` at either level means no ceiling there, which is why both levels are
      additive: an account or device that has never been given one behaves
      exactly as it did before the column existed.
    - Ceilings are not retroactive. Lowering one below a device's current stored
      bytes drops nothing and deletes nothing; it refuses further sends until
      acks or expiry bring the device back under. Sund never discards a stored
      payload to satisfy a ceiling that moved.

  What the second level buys is containment, and it lands on a case the threat
  model otherwise leaves open. With a single account-wide ceiling, a device whose
  queues fill up does not merely stop receiving — it exhausts the ceiling every
  other device in the account shares, so one flooded device can silence the whole
  family. A per-device ceiling turns "one member's queues take the account down"
  into "one member's queues fill up", which is the difference between a
  family-wide outage and one person's backlog. It is a bulkhead, not a defence.

  What it is **not**, and the misreading to head off: it is not a sender-side
  rate limit. There is no sender_device and there will not be one, so the server
  cannot charge a sender, throttle one, or tell two senders apart. A device
  ceiling bounds what a recipient can *absorb*, never what a sender can *emit*.
  A hostile member with a valid sender ID can still fill its victim's queues to
  that victim's ceiling; what changed is that it can no longer reach past the
  victim into everyone else's headroom. Bounding the sender would require the
  sender↔queue link the whole design refuses (see Queues).

  Setting is the operator's (`sund admin device quota`); there is deliberately no
  endpoint that *sets* a ceiling. A per-device ceiling is a denial-of-service
  primitive — setting a peer's to one byte silences it — so keeping the write out
  of band means it raises no authorization question, does not interact with
  decision 12, and puts it beyond any member's reach. There is also no derived
  default: dividing the account ceiling by the device count would silently re-cap
  every existing device whenever a new one enrolled.

  Keeping the write out of band does not put the primitive beyond the *host's*
  reach, and the rest of this section exists because it must not be silent there
  either. The same argument the propagation rule makes about
  `sund admin device promote` applies unchanged: the host is the one party none
  of this binds, so it must not also hold the only invisible act. Therefore:

    - A ceiling change pings **the device it affects**, and only that device.
      That is enough to satisfy the rule, because the rule is that power is
      visible to the party it is held over — and a ceiling is held over exactly
      one device.
    - `GET /v1/me/quota` returns the calling device's own ceiling and its own
      stored bytes. Self-scoped, like the rest of `/v1/me/*`: a device reads its
      own quota and no one else's. This is the one *read* the no-endpoint rule
      does not cover, and it is what lets a device tell "I am full" from "someone
      capped me" — without it, a one-byte ceiling would be indistinguishable
      client-side from honest fullness, which is precisely the silent power this
      PRD refuses elsewhere. It may also carry the *account* ceiling, a static
      figure that binds every device equally and reveals nothing about any of
      them, so that a device can explain a refusal it hits while still under its
      own ceiling. Account *stored bytes* MUST NOT appear: a number every member
      could read would be a coarse activity signal about all of its peers
      combined. Be precise about what that withholds, though — a member holding
      one sender id can probe the account ceiling's boundary and subtract, so the
      MUST NOT denies a convenient read rather than an unreachable fact. It is
      worth keeping for the same reason a locked door is worth keeping next to an
      openable window: the cost of the alternative route is the point. Postiljon
      has an open request for exactly this read (its `docs/deviations.md`,
      "Quota headroom cannot be reported").

  Quota is **not** in the device list, and the contrast with `role` is the whole
  reason (decision 16). A role is authority *over other devices*, so the devices
  it is held over must be able to see who holds it — that is what makes a managed
  account non-covert. A ceiling is a constraint on *one device's own storage*. It
  confers nothing over anyone, so no peer needs it to protect itself, and no peer
  gains a remedy from seeing it: ceilings are operator-written, so a member who
  disapproves of a peer's ceiling can do nothing about it anyway. Publishing it
  would have sold a real capability: a member who reads a peer's ceiling knows
  the silencing cost with *no* probes at all, can rank peers by how cheap each is
  to silence, and with a single probe learns the target's absolute stored bytes
  rather than only whether it moved (Threat model → residual metadata).

  The trade, stated rather than waved through, because publishing did buy one
  thing: a *third-party witness*. Under 0.5 any peer could see that a device had
  been capped to one byte; under 0.8 only that device can, and only if its client
  implements the self-read — an obligation Sund cannot verify, the same caveat
  the role model carries. In the deployment this is aimed at, the operator is
  often a household member, so the witness was not worthless. It is given up
  because a witness who cannot act is worth less than the targeting capability it
  costs: a peer can no more change a ceiling than the capped device can, so
  seeing one produced awareness without recourse, while the capability it handed
  over was real and one-sided.

  A consumer SHOULD surface a ceiling change and a persistent refusal to the
  user rather than retrying quietly; as with the administration model, Sund can
  publish the fact and cannot make a client show it.
- Administrative statements (optional, decision 21). An account has an
  append-only log of opaque, size-capped blobs, written by admins and readable by
  every device in the account. Sund never parses one: it stores bytes and serves
  them back in order, exactly as it does a key bundle.

  It exists because decision 12's model binds the account's own devices and not
  the host. A hostile host can fabricate a revocation, and a forged one is enough
  to make honest peers drop a device's queues and re-key. If the acting admin
  signs a statement describing what it did, and peers verify that signature
  against the device list, the host can no longer *invent* an administrative act
  — it can only refuse to serve the statements, which is denial of service, a
  thing it could always do.

  **The blob must be encrypted by the client, not merely signed**, and this is
  the whole reason the feature took three revisions to arrive. A plaintext signed
  statement says "device X did A to device Y", which is precisely the
  device→device edge the data model refuses and the blindness audit exists to
  prove absent — storing one would hand the host the administration graph the
  rest of the design is built to withhold. Encrypted to the account's devices, it
  is one more opaque payload, and the only parties who can verify it are the
  parties who need to.

  What it does not do, stated because signing invites the assumption that it
  does: it defeats *forgery*, not *suppression*. The host serves the log, so it
  can withhold entries or truncate the tail, and a client cannot distinguish that
  from an account where nothing happened. Chaining statements client-side makes a
  gap in the middle detectable; truncation at the end is not, and no
  server-stored log can fix that. This is the same limit key bundles have, and it
  is why the server keeps the liveness half regardless: it must actually stop
  serving a revoked device.

  The cost, which is new: a durable record of administrative *activity* — how
  many statements an account has and when they were written — where the model
  previously kept none. Bounded rather than unbounded: an account retains its
  most recent statements up to a cap, oldest dropped, so the window a host can
  observe is finite and the store cannot grow without limit. Sequence numbers are
  per account, not global, so one account's log never reveals another's volume.
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
  sending device out-of-band or via an invitation message). The recipient key is
  supplied at creation, by the owner. The **sender key is not**, and cannot be:
  the recipient mints the queue before it knows anything about its peer, so a
  queue is created open and the first valid SEND binds the key it carries
  (`Sund-Sender-Key`). Later sends verify against the bound key and cannot
  rebind. Both keys are per-queue, never device identity keys.

  The consequence is the one the bearer-credential bullet below turns on: until a
  queue is bound, its sender ID is a bearer secret — whoever first presents it
  with a key claims the channel. That is what makes the QR ceremony and the first
  message through a new queue load-bearing, and why a sender ID handed to the
  wrong party is worth retiring rather than reusing.
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
- A sender ID is a bearer credential, and the server treats it as one. A send is
  authorized by the per-queue sender key and nothing else: the server does not
  ask, and cannot ask, which account the sender belongs to, because no column
  links a sender to a device or an account. Consequences worth stating plainly:
    - Until a queue is bound, whoever first presents its sender ID with a key
      claims it. Binding is what turns the bearer claim into a fixed
      counterparty, which is why the QR ceremony and the first message through a
      new queue matter.
    - After binding, only the holder of the bound key can send. A leaked sender
      ID buys nothing on a bound queue.
    - Neither check involves an account. A sender may hold no account on the
      server, and a send into a queue owned by a different account succeeds.
- Per-queue storage ceiling — the third and last level of the quota, and the one
  that bounds a *sender* (decision 17). A queue may carry its own ceiling on the
  stored bytes held in it, set by the queue's owner. It reuses no new linkage at
  all: the count is `SUM(LENGTH(payload))` over one queue's own rows, with none
  of the joins the account and device levels need.

  What makes it the sender bound the design was said to lack: a recipient mints
  one queue per peer and hands that sender ID to exactly one party, which
  first-send binding then fixes. So *which peer is sending* is already expressed,
  exactly, as *which queue* — the server simply never learns the peer's name.
  Capping a queue therefore caps a peer, with no sender↔identity record and no
  new metadata. Earlier revisions said flatly that bounding a sender would
  require the link Sund refuses; that is true of bounding a sender *identity* and
  false of bounding a *channel*, and in this model the two coincide.

  The owner sets it, with the queue's own recipient key — the same credential
  that reads, acks and retires — so no device identity enters, and it is a
  transport-plane operation like the rest. This is the reason it needs none of
  decision 13's machinery: capping your own inbound channel limits only what you
  receive. It harms no third party, so it is not a denial-of-service primitive,
  so it raises no authorization question, needs no operator, and carries no
  visibility requirement.

  Two boundaries worth being exact about, since they cut opposite ways:
    - The *limit* is harmless to disclose. Knowing a channel is capped at 1 MiB
      enables nothing against anyone else, so a recipient may tell its peer the
      budget out of band, in the same pairing message that carries the sender ID.
      The server never discloses it, because it has no reason to.
    - The *remaining headroom* MUST NOT be disclosed, and in particular a send
      response MUST NOT carry it. It would hand the sender, for free and
      precisely, the drain-timing signal the refused-send oracle currently makes
      it probe for (Threat model → residual metadata). A sender learns from the
      refusal and nothing else, exactly as at the other two levels.

  What it does not solve: every send wakes the recipient, so a peer can sit
  inside a small budget and still ping-spam by sending, waiting to be acked, and
  sending again. Bounding *that* means counting sends per window regardless of
  ack, which is a rate rather than a quota and is deliberately not in V1 —
  decision 17 states why. The unilateral remedy already exists and is unchanged:
  the owner retires the queue. A budget is the dial between "unlimited" and
  "gone", worth having because retiring costs a re-pair.
- V1 scope: Sund offers no cross-account *addressing, routing or discovery* —
  there is no way to name another account, enumerate it, or reach a device
  through it, and the management plane is isolated. What it does not do is
  *refuse a send* on account grounds, which is a different claim and was
  previously stated as though it were the same one (decision 15).

Messages
- Send (by sender ID), receive/ack (by recipient ID), per-message TTL. Queues
  survive offline receivers; expired messages are deleted unread — on the next
  drain of that queue, and for queues nobody drains by a background sweep, so the
  promise holds for abandoned queues too and not only for attended ones. There is
  no
  per-message delivery status and no read receipt: a message is stored until it
  is acked, at which point its row is deleted, so "delivered" is not a state the
  server keeps. A recipient learns what arrived by draining. Sund gives a sender
  no delivery or read signal at all — that is the design rather than a gap
  (decision 14) — which is narrower than saying a sender learns nothing: a send
  can still fail closed against a retired queue (404) or a full one (507), and
  the latter is a coarse oracle on the recipient's storage and drain timing. What
  a sender can infer anyway is in Threat model → residual metadata; what Sund
  deliberately does not tell it is delivery.
- Payloads are opaque ciphertext, bounded by both quota levels (Accounts).

Push wake-up
- A ping carries no payload and no queue ID. It tells a device "check in"; the
  client then drains its queues over the API.
- A ping does carry one bit, and 0.10 states it because the code has sent it
  since the beginning: a **priority hint**. A send may set `priority: true`,
  which the server forwards to the pinger as an opaque high/normal flag without
  reading the payload — on UnifiedPush it becomes ntfy's `Priority: high` header.
  It exists because an Android device in Doze will not wake for a normal-priority
  push, so without it an SOS is not deliverable at all. The body stays empty and
  no queue ID travels, but "a ping carries nothing" was never true, and what the
  bit discloses is listed under Threat model → residual metadata.
- Pings are sent on message arrival (transport plane, via queue ownership) and on
  every administrative act — registration, revocation, role change, invitation
  minting, and a storage-ceiling change (management plane, see Devices). A mint
  changes no device list and a ceiling change is not made by a device at all,
  which is why the trigger is the act and not the list. The ceiling change is
  also the one act whose ping goes to a single device rather than the account,
  since it is the only one whose effect no other device can observe.
- Delivery paths differ fundamentally per platform — see Push architecture.

Health and metrics endpoints.

---

Data model (the whole of it)

accounts     — id, created, quota (class label), quota_bytes, status, admin_mode
devices      — id, account_id, public_key, role, push_endpoint, capabilities,
               quota_bytes, created, last_seen, revoked
bundles      — device_id, blob (opaque, size-capped), updated
statements   — account_id, seq (per account), blob (opaque, size-capped),
               created
invitations  — id, token_hash, account_id, created, expires, consumed, revoked,
               grants_role
queues       — recipient_id, sender_id, owner_device, recipient_key, sender_key,
               quota_bytes, created, retired
messages     — seq, id, queue_id, payload, received_at, expires

There is deliberately no sender_device column anywhere in the transport plane.

A `quota_bytes` of 0 means "no ceiling at this level", so an account, device or
queue that has never been given one behaves exactly as it did before the column
existed — which is what makes all three quota levels additive rather than a
migration.

This table is design intent, and the promise attached to it runs one way: every
column the implementation actually has appears here. Not the converse: a column
may be specified before it is built, and `Sund-Status.md` is where that gap is
tracked. (As of 2026-09-24 there is no gap — `admin_mode`, `role`, `grants_role`
and both `quota_bytes` columns are all in the schema.) The one-way promise
had lapsed and is repaired here: the accounts, invitations and messages rows were
out of step with `internal/store/store.go` (recorded in `docs/deviations.md`,
2026-09-18). `seq` gives a stable per-queue delivery order at second-precision
timestamps, `expires` is the absolute form of the per-message TTL that the purge
query needs, and `invitations.id`/`revoked` are what decision 7's listable and
revocable invitations actually require. The `messages.status` column that 0.5
left carved out as an open question is gone in 0.6 — see decision 14.

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

Pings are payload-free by design (no content, no queue IDs — only "check in",
plus the one-bit priority hint of Scope → Push wake-up). That decision is what
makes the following delivery paths acceptable, and the hint is the one part of it
a consumer must weigh rather than assume away.

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

Explicitly NOT hidden — residual metadata. Each item below is stated with two
things, where earlier revisions stated only the first: **who can observe it**,
and **what observing it enables**. The distinction earns its place because the
two need different treatment. A pure disclosure is documented and lived with —
someone learns a fact and gains no new capability from it. An enabler is a
design question, because it makes an attack cheaper, quieter or better aimed,
and the right answer is sometimes not to expose the datum at all. Decision 16 is
one such answer.

Observable by the **host** (which can also deny service outright, so nothing
here enables anything it could not already do):

- Traffic timing and sizes, per queue and per device connection.
- Queue ownership on the recipient side — required for quotas and wake-up.
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
  so a host watching requests sees the pair even though nothing stores it. The
  management-plane twin of push-ping fan-in — runtime, not recorded. The binary
  keeps no access log (it logs errors only), so the claim holds today at runtime
  as well as in the schema, but a host that chose to log would learn it. One
  error path is not content-free: a failed push ping logs the transport error,
  which carries the device's push endpoint URL. Host-observable only, so it
  enables nothing the host did not already hold.
- The priority hint on a ping. A send may mark itself urgent, and the server
  forwards that as an opaque flag. So a host sees, per wake-up, whether the
  sender called it urgent — and in a consumer that reserves urgency for one thing,
  that is a label on the event. In family-beacon's shape, timing plus the flag
  distinguishes an SOS from a location update without reading a byte of either.
  *Enables:* nothing a host can act on beyond what selective delay already gives
  it, but it is the single most content-revealing bit in the system and the one a
  consumer's privacy documentation most needs to name.
- Per-queue ceilings: `queues.quota_bytes` tells a host what tolerance a
  recipient has configured for each channel it owns. Owner-written, tiny, and it
  says nothing the host could not infer from watching that queue refuse.
- The account's shape: `admin_mode` says whether an account is flat or managed
  before any device has registered, `role` says which device administers a
  managed account, `grants_role` says at mint time that an account is about to
  add an admin, and `devices.quota_bytes` says which device has been capped and
  how far. The host wrote the first and the last itself, so it learns nothing
  from them. A flat account exposes only `admin_mode`, and uniformly.

Observable by an **account member**, from the device list every member reads.
These are the items the anti-stalkerware argument turns on, because the observer
is someone the subject lives with:

- **Not** a peer's `push_endpoint`, since 0.12. It used to be here and it was
  the sharpest item in the section: on a bearer-URL distributor such as a default
  ntfy topic, a peer's wake-up URL is the ability to wake or spam that device,
  outside Sund entirely and beyond the reach of revocation or quota. It was the
  only *capability* a member held over a peer, and no client needed it — pings
  are the server's to send — so decision 20 withholds it. A device still reads
  back its own.
- **`last_seen` for every peer** — when each device last made an authenticated
  *management-plane* request. The transport plane does not touch it: draining,
  acking and sending leave it unchanged. But because clients MUST refetch the
  device list on every ping, and a ping fires on every message arrival, a peer's
  `last_seen` approximates *when a message last arrived for that device and its
  client woke* — a sharper presence signal than "last checked in", and a side
  effect of the mandatory-refetch rule rather than a deliberate feature.
  *Enables:* timing — knowing when a peer's client last woke is knowing when it
  is not watching, which is when an administrative act or a flood goes longest
  unnoticed.
- **Every peer's `public_key` and whether it is `revoked`** — the first is public
  key material and is the point of the list; the second, with `last_seen`, tells
  every member exactly when a peer was removed and when it was last active before
  that. *Enables:* little beyond what the removal itself already broadcasts.
- **`role` for every peer** — who may revoke, invite and promote in a managed
  account. Published deliberately: authority over other devices must be visible
  to the devices it is held over (Administration). *Enables:* target selection —
  revoke the admin first. In a flat account every device holds the same role, so
  it distinguishes nobody.
- **The device list itself** — how many devices an account holds and when each
  enrolled. *Enables:* little on its own.
- **Not** a peer's storage ceiling, and **not** a peer's stored bytes. Both were
  candidates and both are withheld; see decision 16 and the refused-send item
  below for what publishing the ceiling would have enabled.

Observable by a **sender** holding a queue's credentials — who may be an account
member, or may hold no account on the server at all (decision 15):

- **A refused send (507).** Mechanically: the refusal says storage is full on the
  recipient side at one of the three levels and does not say which, which it MUST
  NOT: a sender able to tell "account full" from "device full" would learn about
  account-wide state it otherwise cannot see, and one able to pick out "queue
  full" would learn that the recipient had singled this channel out. It does not
  mean "this queue
  is full": a device ceiling covers that device's stored bytes across every queue
  it owns, including queues the sender holds no ID for and cannot enumerate. And
  where the device ceiling is the lower of the two — the usual reason to set one,
  though nothing requires it — refusals fire more often than under an account
  ceiling alone.

  *Enables:* a coarse oracle, and confirmation of a flood. A sender holding a
  queue's live send credential — its sender ID, and on a bound queue the bound
  key — can send minimum-size payloads to binary-search the remaining headroom,
  and poll to watch headroom return, learning roughly when the recipient *acked*
  (headroom returns on ack, not on drain — a drain removes only expired rows) or
  when its messages expired. Sizes and timing are listed above as visible to the
  host; this exposes a coarse version of them to a sender too. Against the 64 MiB
  account ceiling the search was expensive and noisy; against a small device
  ceiling it is cheap.

  Three things sharpen or blunt that, all worth stating. The account ceiling is
  one of the two tripwires and sums across *every* device in the account, so a
  probe that trips it reports aggregate state about the recipient's peers, not
  just the recipient — the reason the refusal must not name which level tripped
  is to stop a sender resolving which of the two it hit, not to hide that account
  state is involved at all. Probing is self-consuming: each probe stores the
  bytes it measures, so it is indistinguishable from a small flood and cannot be
  repeated indefinitely without becoming one. And it remains a *search*
  deliberately: publishing a ceiling in the device list would have given a member
  the silencing cost with zero probes and let it rank peers by how cheap each is
  to silence, which is why decision 16 withholds it. Nothing here reveals payload
  content, another queue, or who else is in the account.
- **A 404 on a queue that is gone** — retired by its owner, or belonging to a
  device that was revoked, since revocation retires that device's queues. The
  first is a designed signal: a stale sender must learn to fetch a new address
  (Queues → Rotation). The second is the awkward one — a management-plane fact
  becomes visible outside the account. Note the scope precisely, because it is
  wider than "a sender holding credentials": the queue is resolved *before* the
  signature is checked, so an unsigned request already distinguishes 404 (gone)
  from 401 (live, wrong key). *Enables:* a permanent, credential-free liveness
  monitor for anyone who has ever seen the sender id — including a peer whose
  access was revoked, who can from then on tell whether the owner device is
  still enrolled. It is the one place a management event reaches a party the
  account has ejected, and a consumer reasoning about what a departed member can
  infer should know it.

Observable by the **push distributor**, and on iOS additionally by the **vendor
gateway and Apple**:

- Wake timing per endpoint, and the priority hint. No content, no queue ids, no
  message counts per queue. On Android the distributor may be self-hosted next to
  Sund, in which case this observer collapses into the host; a consumer using a
  third-party distributor should count it separately. On iOS it cannot collapse —
  the gateway and Apple are always distinct parties, and they see the same two
  things. See Push architecture.
- *Enables:* for a consumer that reserves the urgent flag for one event type,
  a party who sees only timing and priority can still tell that event apart from
  ordinary traffic. Sund cannot prevent this — the flag is what makes the event
  deliverable through Doze at all — so it is the consumer's to weigh: reserve
  urgency for a class of events rather than one, or accept that the class is
  visible to its push path.

What an account is, and is not. An account bounds the management plane — a
device lists, fetches bundles from and revokes only within its own account — plus
queue *ownership*, and therefore quota attribution and wake-up, plus billing.
It bounds nothing on the transport plane, in **either** direction. Neither a send
nor a receive consults an account *to authorize it*: `recv`/`ack`/`retire` are
authorized by the per-queue recipient key and a send by the per-queue sender key,
and no column anywhere links either to a device or an account. The one place a
send touches account state at all is the recipient-side quota check, which is
ownership again and is why a refusal can reach a sender who has no account of
their own — see the refused-send bullet under residual metadata. The server has
no tenancy fact to test for authorization, and could only acquire one by
recording the sender↔account link the blindness audit exists to prove absent.

This matters for how the guarantee is stated. It is not that cross-account reads
fail and cross-account sends succeed — a cross-account *read* fails for the same
reason a same-account read by the wrong device fails: the caller does not hold
the queue's recipient key. **A queue is protected by its keys, not by its
account.** What protects it is that the recipient minted both ids, that the
sender id went to one peer out of band, that the first send binds a key and a
second key is then refused, and that the owner can retire the queue at will.

So the honest statement of multi-tenancy is: accounts are isolated on the
management plane, and a queue is reachable by whoever holds its credentials.
A consumer must not treat the account as a spam or abuse boundary on the
transport plane. This is the SimpleX model working as intended, not a gap in it —
but PRD 0.6 and earlier described it as though the account also filtered sends,
which it never did (decision 15).

Sharing an account, for a stack rather than a family. The account model was
designed for a person's devices or a household, and its first non-family
consumers — Postiljon and Brygga — run two unequal server-side components as two
devices in one account. That is a sound choice, and it is what they chose, but
it costs three things that are easy to miss because each is documented elsewhere
as a mechanism rather than as a consequence. Stated here so a consumer designing
a multi-client stack meets them in one place:

- **Revocation reaches every device.** In a flat account any device may revoke
  any other, and revocation atomically retires every queue the target owns and
  drops their messages. For a stack where one component receives alarms and
  another holds every outbound credential, compromise of the credential-holder is
  one API call away from retiring the queues the alarms arrive on. A `managed`
  account (decision 12) narrows this to admins, which is one of the few cases
  where managed mode is clearly the right choice — the components are not people
  and there is no one to trap.
- **The storage quota is shared, and shared failure is not the same as shared
  billing.** Traffic into one component's queues consumes the account ceiling the
  other's senders draw on, so a flood aimed at one silences the other. Per-device
  ceilings (decision 13) are the containment for exactly this, and a multi-client
  account is the deployment that most needs them set.
- **Enrolment reaches every device too, and this is the worst of the four.** In a
  flat account any device may mint an invitation, so compromise of an
  internet-facing component enrols an attacker's device into the account —
  permanently, and with all the powers above. Revocation is loud and recoverable;
  a quietly enrolled peer is neither. A component that terminates untrusted input
  is exactly the one that should not be able to invite.
- **Every non-revoked device is trusted equally**, and the device list is visible
  to all of them — including, today, every peer's push endpoint. This is stated
  for peers in a family account; it applies just as much to a service account
  holding two components of unequal privilege. Neither the platform nor the
  account boundary makes the credential-holder more trusted than its neighbour,
  or less.

Two caveats on the remedies, so this section does not recommend what does not
exist. `managed` mode (decision 12) narrows revocation and minting to admins and
is the right shape for a service account — the components are not people and
there is nobody to trap — but the mode is fixed at provisioning, so it is a
choice at account creation and not a fix an existing deployment can adopt.
Per-device ceilings (decision 13) are the containment for the shared-quota cost,
and a per-queue ceiling (decision 17) bounds one peer within that. All are
implemented as of 2026-09-24, so a stack deploying today can take the first cost
off the table at provisioning and contain the second — but the mode is still a
choice made once, at account creation.

The honest answer to "should two components share an account?" is "yes, with
those four costs, and provision the account managed if you can" — and a consumer
that cannot accept them should run separate accounts, which the transport plane
permits (decision 15) at the price of losing the shared device list and shared
revocation that made one account attractive.

Trust boundary — the account. Sund has no notion of which member may see or talk
to which: the device list is visible to all members, and reachability between them
is governed entirely by the consumer's pairing protocol (see Devices → Key
bundles, Reachability). What 0.4 changes is narrower than it sounds — the account
is still the trust boundary, and every non-revoked device in it is still trusted
to read the device list and to use the transport plane. Of the five acts the
propagation rule calls administrative, three are gated by role — revoking another
device, minting an invitation, changing a role — while registration is gated by
holding a valid token, and a storage-ceiling change is not available to a device
at all, being the operator's — and is also the one whose effect is visible to a
single device rather than to the account (Devices → Storage quota).
Consequences a consumer must weigh:

- A compromised or malicious member device can enumerate the account's device
  list and, if the consumer publishes reachable bundles, initiate to any peer
  unsolicited. A managed account does not change this.
- Because quota is attributed to the recipient and senders are pseudonymous (no
  sender_device to rate-limit), such a member can consume a victim's quota by
  filling its queues; the transport plane cannot throttle a sender *by identity*.
  It can now bound one by channel: a per-queue ceiling (decision 17) caps what a
  given peer can leave in the queue the victim minted for it, which is as good as
  per-sender wherever the recipient keeps one queue per peer. Neither the
  administration model nor the quota levels prevents the flood itself — the
  remedy for a member turned hostile is still revocation. What per-device quota
  (decision 13) changes is the blast radius: a
  victim with its own ceiling absorbs the flood alone instead of exhausting the
  headroom every other device in the account shares. Containment, not defence,
  and worth having only because the undefended case is otherwise account-wide.
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
- No cross-account or federated *addressing* in V1: no directory, no routing
  between accounts, no way to reach a device except through a queue whose sender
  ID you were given. This is not the same as refusing a send that arrives with a
  valid sender credential from outside the account — see Queues and decision 15
  for why the transport plane cannot make that distinction without storing the
  link it exists not to store.
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
- postiljon — a headless Sund subscriber, and the consumer `client/` exists for.
  It asked for both halves of decision 13: per-device quota, and a way to read
  headroom so a digest can report it.
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
stack lock and the second transport-trust mode. Item 12 came in 0.4, item 13 in
0.5; item 14 is new in 0.6:

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
13. Per-device storage quota. A device may carry its own ceiling on its stored
    bytes, enforced alongside the account ceiling; a send is refused if it would
    take either past its ceiling, the boundary is inclusive, and 0 at either
    level means no ceiling there, so both are additive and a deployment that sets
    none is unaffected. Ceilings are not retroactive: lowering one refuses
    further sends and discards nothing. Cheap by construction — the quota check
    already resolves queue → owner device → account, so counting to the device
    reuses a join the server performs anyway (one join fewer) and discloses
    nothing new to the host; `devices.quota_bytes` is a per-device attribute, not
    an edge, the same test decision 12's `role` had to pass. What it is for: with
    only an account ceiling, one device's flooded queues exhaust the headroom
    every other device shares, so a single member can silence the family by being
    filled up. Per-device ceilings make that a bulkhead. What it is **not**: a
    sender-side limit — there is no sender_device, so the ceiling bounds
    absorption, never emission, and the flood itself remains undefended (Threat
    model → Trust boundary). Writing a ceiling is the operator's alone
    (`sund admin device quota`, no endpoint, no derived default), because it is a
    denial-of-service primitive and keeping the write out of band puts it beyond
    every member's reach. But it is not beyond the host's, so by the rule 0.4
    already applied to `sund admin device promote` it must not be silent either:
    a ceiling change pings the device it affects and `GET /v1/me/quota` lets that
    device read its own ceiling and stored bytes — which is also the headroom
    read Postiljon has an open request for. (0.5 also put the ceiling in the
    device list; decision 16 takes it out again.) Cost
    accepted and recorded: a lower ceiling makes the refusal a cheap oracle for a
    sender probing a recipient's headroom and drain timing (Threat model,
    residual metadata).
14. No per-message delivery status. The `messages.status` column existed from
    the first schema, was written as `'stored'` and never updated, and was read
    by nothing: an ack deletes the row and an expired message is purged, so
    there was never a second state to be in. It is dropped — from the schema,
    from the `Message` struct and from the append and drain queries — rather than
    given real statuses. The load-bearing reason is retention: a status worth
    reading has to outlive the ack, and keeping rows past ack contradicts "it
    stores briefly (TTL)" in Principles. It would also turn a timing observation
    the host can already make live into a durable per-message record of when a
    recipient collected what — the difference between seeing traffic and keeping
    a history of it. A second reason applies only if such a status were ever
    exposed to senders, which this column never was: a read receipt is a
    per-message timing signal about the recipient, and the transport plane exists
    not to produce those. The Messages section now states the model positively
    instead of promising a feature: stored until acked, then gone, no read
    receipt, and no delivery signal to the sender — stated there with the
    failure modes a sender *can* still observe, so the claim stays as narrow as
    it is true. Migration drops the column from databases written by an older
    binary, and it is one-way: an older binary's append names `status` in its
    INSERT, so a rollback across this change fails every send. Since the column
    never appeared in a response body, no client contract changes.
15. Multi-tenancy scoped to what it is. Three statements — Principles ("Accounts
    are fully isolated"), the V1 non-goal ("No cross-account or federated
    messaging") and the guide's scenario S7 ("cross-account queue reads, sends,
    bundle fetches and device-list reads all fail") — asserted that a send from
    another account is refused. It is not, and cannot be: `handleSend` resolves
    the queue by sender ID and verifies the per-queue sender key, and no column
    anywhere links a sender to a device or an account, so there is no tenancy
    fact to test. Enforcing it would mean storing that link, contradicting the
    Architecture Principle and the S8 audit, and buying nothing — a queue is
    already protected by its sender ID being secret and by first-send binding.
    The code was right and the spec was wrong, so the spec moves: the management
    plane and the recipient side of a queue are account-isolated, the transport
    plane is authorized by bearer credential, and the non-goal is restated as the
    absence of cross-account *addressing, routing and discovery*, which is true
    and is what a consumer actually relies on. S7 now asserts the guarantee that
    exists, including positively that a cross-account send succeeds, so the suite
    would catch a future change that quietly introduced tenancy filtering.
16. A device's storage ceiling is self-scoped. PRD 0.5 put `quota_bytes` in the
    device list, reasoning by analogy with `role`. The analogy does not hold, and
    this corrects it: a *role* is authority over other devices, so the devices it
    is held over must see who holds it — that is what makes a managed account
    non-covert. A *ceiling* is a constraint on one device's own storage. It
    confers nothing over anyone, so no peer needs it to protect itself; ceilings
    are operator-written, so no peer gains a remedy from seeing one; and the
    accountability that publishing was meant to buy — a capped device knowing it
    was capped — is delivered entirely by `GET /v1/me/quota`. What publishing did
    buy was a capability: a member who reads a peer's ceiling knows the silencing
    cost with no probes at all, can compare peers for the cheapest to silence,
    and with one probe learns the target's absolute stored bytes. It also bought
    a third-party witness to an operator's capping act, which is a real loss and
    is argued as a trade under Storage quota rather than dismissed. So the
    ceiling leaves the
    device list, a ceiling change pings only the device it affects, and
    `/v1/me/quota` stays self-scoped — it may carry the account ceiling, a
    constant that binds everyone equally, and never account stored bytes.
    Generalised, the rule this follows: publish what a party needs to hold power
    to account, withhold what only makes it easier to act on someone. The
    restructured residual-metadata list exists to make that judgement visible per
    item rather than buried in prose.
17. A per-queue storage ceiling — the sender bound, arrived at from the other
    side. The threat model has always conceded that a peer can fill a victim's
    queues and that the transport plane cannot throttle a sender, and earlier
    revisions said flatly that bounding one would need the sender↔identity link
    Sund refuses. That is true of bounding a sender *identity* and false of
    bounding a *channel*: a recipient mints one queue per peer and binds it to
    one sender key, so *which peer* is already expressed as *which queue*, and
    capping the queue caps the peer without the server learning who it is. It is
    also the cheapest of the three levels to enforce — one queue's own rows, no
    joins.

    Set by the owner with the queue's recipient key, on the transport plane, with
    no device identity involved. None of decision 13's machinery applies, and the
    reason is worth keeping in view: capping your own inbound channel limits only
    what you receive, so it is not a denial-of-service primitive, so there is no
    authorization question, no operator-only write, and no visibility
    requirement. Two adjacent quota values, opposite answers — the device ceiling
    is withheld from peers (decision 16) because knowing it helps you act on
    someone else; a queue's own limit is harmless for its sender to know, and may
    be shared out of band with the sender ID. Its *remaining headroom* is not,
    and MUST NOT appear in a send response: that would hand over, precisely and
    for free, the drain-timing signal the refused-send oracle makes a prober work
    for.

    Deferred, and named so it is not mistaken for an oversight: the *rate*-shaped
    variant, counting sends per window regardless of ack, which is what would
    stop a peer ping-spamming inside a small budget by sending, being acked, and
    sending again. It is out of V1 because it needs a counter that outlives the
    messages it describes — the first state in Sund that would — and that cuts
    against "it stores briefly (TTL)" for a threat the owner can already end by
    retiring the queue. Revisit if a consumer shows the annoyance case matters
    more than the retained metadata costs.
18. The priority hint is stated, not removed. A ping has always carried one bit
    beyond "check in": a send may mark itself urgent and the server forwards that
    to the pinger as an opaque flag, becoming ntfy's `Priority: high`. The PRD
    said "a ping carries nothing" and the guide's S4 has been testing the flag
    since the test strategy was written, so the spec was the only thing that did
    not know. Kept, because without it an Android device in Doze does not wake and
    an SOS is not deliverable at all — the feature is load-bearing for the
    consumer the whole design is aimed at. Now disclosed instead: it is the single
    most content-revealing bit in the system, because a consumer that reserves
    urgency for one event type has, in effect, labelled that event to its host and
    its push path. The mitigation is the consumer's and is stated as such —
    reserve urgency for a class of events rather than one — because Sund cannot
    fix it without making the event undeliverable. Closes the 2026-09-18
    deviation.
19. Two sentences made true, one by wording and one by code. Both were recorded
    on 2026-09-18 and both were the same shape as decision 18: a claim the code
    did not support.

    *The sender key is bound, not supplied.* Queues said "the server stores
    per-queue authentication keys supplied at creation". The recipient key is;
    the sender key is not and cannot be, since the recipient mints the queue
    before it knows anything about its peer. The queue is created open and the
    first valid SEND binds the key it carries. The guide has described this since
    0.2 and the PRD declares itself normative where they disagree, so the PRD was
    the wrong one. Stated now, with the consequence the bearer-credential bullet
    already depends on: until a queue is bound its sender ID is a bearer secret.

    *Expired means expired, including in queues nobody visits.* "Expired messages
    are deleted unread" and "it stores briefly (TTL)" were true of any queue a
    client drains, because a drain purges its own queue first. They were false of
    an abandoned one, which held expired ciphertext until its owner was revoked
    or the queue retired. This is closed by building rather than by qualifying,
    because it is a privacy promise and retracting one should be the last resort:
    an hourly background sweep now deletes expired rows everywhere. A goroutine,
    not a service — no new process, nothing to configure, the Holm bar intact.
20. A peer's wake-up endpoint is withheld. `push_endpoint` was in the device
    list from the first schema and came out in 0.12: it is returned to the device
    that set it and omitted for everyone else. It was the one *capability* in the
    member-visible set rather than a disclosure — on a bearer-URL distributor,
    which a default ntfy topic is, holding a peer's endpoint is the ability to
    wake or spam that device, outside Sund entirely and beyond the reach of
    revocation, quota or anything else here. Nothing needed it: pings are the
    server's to send, and pairing carries what a peer needs out of band, so
    publishing it bought no accountability and sold a capability — the same test
    decision 16 applied to a storage ceiling, reaching the same answer for a
    field that had been there far longer. Self-read stays, because reading back
    what you registered is a diagnostic and confers nothing over anyone. This
    closes what 0.8 raised as an open decision rather than folding it in quietly,
    since it is a wire-format change: a client that displayed a peer's endpoint
    will now see it empty.
21. Administrative statements, and why they are encrypted rather than merely
    signed. Decision 12 binds an account's own devices and not the host, which
    can still fabricate a revocation — and a forged one makes honest peers drop a
    device's queues and re-key. An acting admin may now write a statement of what
    it did into a per-account append-only log, which peers read and verify
    against the device list; the host can no longer invent an act.

    The part that took three revisions to get right: the blob is **encrypted by
    the client**, not just signed. A plaintext signed statement is literally the
    "X did A to Y" record the data model refuses and the S8 audit exists to prove
    absent, so storing one would have handed the host the administration graph
    the whole design withholds — a feature meant to constrain the host, paid for
    by telling it more. Encrypted, it is one more opaque payload, and the only
    parties who can verify it are the ones who need to.

    Sund defines no statement format, for the reason it defines no bundle format:
    what an act means is the consumer's protocol, and Sund storing bytes is what
    keeps it out of that. Optional throughout — an account that writes no
    statements is unaffected, and decision 12's gates do not depend on it.

    Honest limits. It defeats forgery, not suppression: the host serves the log
    and can withhold or truncate it, and a client cannot tell that from an
    account where nothing happened. Chaining makes a mid-log gap detectable;
    tail truncation is not, by any server-stored log. And the cost is real — a
    durable record of administrative *activity*, count and timing, where the
    model previously kept none. Bounded by a per-account retention cap so the
    observable window is finite, with per-account sequence numbers so one
    account's log never reveals another's volume.

Open decisions remaining

1. iOS push gateway operations (shared with family-beacon #2): who operates the
   vendor gateway, what availability it promises, and whether pings get
   batching/jitter to blunt timing analysis at the gateway. The architecture
   itself is settled in Push architecture; "no lock-in" is structurally
   unattainable on iOS — only containment is.

Resolved since first listed as open (no longer decisions):

- Signed administrative statements — closed in 0.13 by decision 21. Sund stores
  and serves an opaque per-account log; the statement format stays the
  consumer's, as the bundle format is. The one thing the original framing got
  wrong: "signed" is not enough, because a plaintext signed statement is the
  actor→target record the data model refuses. It must be encrypted too.

- Whether `push_endpoint` belongs in the device-list response — closed in 0.12
  by decision 20: it does not, except for the device that set it.

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
